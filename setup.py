#!/usr/bin/env python3
"""Strata setup: installs Strata on this machine and registers it as a background service.

    python setup.py                 interactive setup; asks before it changes anything, safe to run again
    python setup.py --home <dir>    set up another site in its own instance folder
    python setup.py --check         report what is installed and running, change nothing
    python setup.py --no-service    configure everything but don't register or start the service
    python setup.py --uninstall     remove the service (configuration and data stay)

Steps: Python packages into vendor/, the site (domain, files folder, ports), Caddy (Caddyfile backup + import of the
config Strata renders), the Cloudflare Tunnel (config backup + ingress rule for the CDN host), API keys and the owner
account, strata.json (backup first) and data/.env (every secret), then the service: a Task Scheduler task on Windows, a systemd unit on Linux.
Standard library only, so it runs before anything is installed.
"""
import argparse
import getpass
import glob
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from xml.sax.saxutils import escape

CODE = os.path.dirname(os.path.abspath(__file__))
WIN = os.name == "nt"
STAMP = time.strftime("%Y%m%d-%H%M%S")
BASE_PORTS = {"listen": 8090, "feed_listen": 8081, "transform_listen": 8083, "gate_listen": 8085, "media": 8084,
              "cdn": 8080, "lan": 8091}
CF_PERMISSIONS = ["Zone > Zone > Read", "Zone > DNS > Edit", "Zone > Cache Purge > Purge",
                  "Zone > Zone Settings > Edit", "Zone > Zone WAF > Edit", "Zone > Cache Rules > Edit",
                  "Account > Account Filter Lists > Edit"]


# ---------------------------------------------------------------- console

def say(*a):
    print(*a, flush=True)


def step(n, total, title):
    say("\n[%d/%d] %s" % (n, total, title))


def ask(q, default=""):
    try:
        s = input("  %s%s: " % (q, " [%s]" % default if default else "")).strip()
    except EOFError:
        s = ""
    return s or default


def yes(q, default=True):
    a = ask(q + (" (Y/n)" if default else " (y/N)")).lower()
    return default if not a else a.startswith("y")


def secret(q):
    if not sys.stdin.isatty():
        return ask(q)
    return getpass.getpass("  %s: " % q).strip()


def run(cmd, capture=True, timeout=120):
    try:
        r = subprocess.run(cmd, capture_output=capture, text=True, timeout=timeout)
        return r.returncode, ((r.stdout or "") + (r.stderr or "")).strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, str(e)


def backup(path):
    """Copy path to <dir>/backups/<name>.<timestamp>.bak and return the copy's path."""
    d = os.path.join(os.path.dirname(path), "backups")
    os.makedirs(d, exist_ok=True)
    dst = os.path.join(d, "%s.%s.bak" % (os.path.basename(path), STAMP))
    shutil.copy2(path, dst)
    return dst


def write(path, text):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    os.replace(tmp, path)


def merge(base, over):
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            merge(base[k], v)
        else:
            base[k] = v
    return base


# ---------------------------------------------------------------- platform

def is_admin():
    if WIN:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def relaunch_elevated():
    """Windows: start this script again in an elevated console (UAC prompt) and let this one exit."""
    import ctypes
    args = " ".join('"%s"' % a for a in [os.path.abspath(__file__)] + sys.argv[1:] + ["--elevated"])
    return ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, args, CODE, 1) > 32


def find_exe(name, configured="", extra=()):
    for c in [configured, shutil.which(name)] + list(extra):
        if c and os.path.isfile(c):
            return os.path.abspath(c)
        if c and not os.path.dirname(c) and shutil.which(c):
            return shutil.which(c)
    return ""


def win_candidates(exe, *more):
    local = os.environ.get("LOCALAPPDATA", "")
    pf, pf86 = os.environ.get("ProgramFiles", r"C:\Program Files"), os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    out = [os.path.join(local, "Microsoft", "WinGet", "Links", exe)]
    out += glob.glob(os.path.join(local, "Microsoft", "WinGet", "Packages", "*", exe))
    out += [os.path.join(p, d, exe) for p in (pf, pf86) for d in more]
    out += [os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "chocolatey", "bin", exe)]
    return out


def winget_install(package):
    if not shutil.which("winget"):
        say("  winget is not available. Install %s by hand, then run setup again." % package)
        return False
    say("  running: winget install -e --id %s" % package)
    code, _ = run(["winget", "install", "-e", "--id", package], capture=False, timeout=900)
    return code == 0


def port_free(port):
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def pick_ports(caddyfile_text):
    """The default ports, or the first block of them shifted by 100s where every port is free (second site)."""
    for k in range(10):
        ports = {n: p + 100 * k for n, p in BASE_PORTS.items()}
        if all(port_free(p) and not re.search(r"(?m)^\s*:%d\s*\{" % p, caddyfile_text) for p in ports.values()):
            return ports
    sys.exit("  no free block of ports found between 8080 and 9091")


def http_get(url, headers=None, timeout=10):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except (OSError, ValueError):
        return 0, b""


# ---------------------------------------------------------------- services

def task_xml(description, command, arguments, workdir):
    return """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>%s</Description></RegistrationInfo>
  <Triggers><BootTrigger><Enabled>true</Enabled><Delay>PT20S</Delay></BootTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>
    <Priority>5</Priority>
  </Settings>
  <Actions Context="Author"><Exec><Command>%s</Command><Arguments>%s</Arguments><WorkingDirectory>%s</WorkingDirectory></Exec></Actions>
</Task>
""" % (escape(description), escape(command), escape(arguments), escape(workdir))


def install_task(name, description, command, arguments, workdir):
    """A Task Scheduler task that starts at boot as SYSTEM, never times out, and restarts after a failure.
    (schtasks /SC ONSTART alone would stop it after 72 hours.)"""
    path = os.path.join(tempfile.gettempdir(), "strata-task-%s.xml" % STAMP)
    with open(path, "w", encoding="utf-16") as f:
        f.write(task_xml(description, command, arguments, workdir))
    try:
        code, out = run(["schtasks", "/Create", "/TN", name, "/XML", path, "/F"])
    finally:
        os.remove(path)
    if code != 0:
        raise RuntimeError("schtasks: " + out)
    run(["schtasks", "/End", "/TN", name])
    code, out = run(["schtasks", "/Run", "/TN", name])
    if code != 0:
        raise RuntimeError("schtasks: " + out)


def install_unit(name, description, command, workdir, after="network-online.target"):
    path = "/etc/systemd/system/%s.service" % name
    write(path, "[Unit]\nDescription=%s\nAfter=%s\nWants=network-online.target\n\n[Service]\nExecStart=%s\n"
                "WorkingDirectory=%s\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n"
          % (description, after, command, workdir))
    for cmd in (["systemctl", "daemon-reload"], ["systemctl", "enable", "--now", name], ["systemctl", "restart", name]):
        code, out = run(cmd)
        if code != 0:
            raise RuntimeError(" ".join(cmd) + ": " + out)


def task_exists(name):
    return run(["schtasks", "/Query", "/TN", name])[0] == 0


def service_exists(name):
    return run(["sc", "query", name])[0] == 0 if WIN else run(["systemctl", "cat", name])[0] == 0


def service_names(home, iid):
    """(Strata service, tunnel service) names: plain for the instance in the code folder, suffixed for the others."""
    default = os.path.normcase(home) == os.path.normcase(CODE) or not iid
    if WIN:
        return "Strata" if default else "Strata %s" % iid, "Strata Tunnel" if default else "Strata Tunnel %s" % iid
    return "strata" if default else "strata-%s" % iid, "strata-tunnel" if default else "strata-tunnel-%s" % iid


# ---------------------------------------------------------------- steps

def package_problems():
    """Installed modules must meet requirements.txt, including security updates in existing vendor folders."""
    import importlib.metadata
    import importlib.util
    vendor = os.path.join(CODE, "vendor")
    sys.path.insert(0, vendor)
    problems = []
    try:
        with open(os.path.join(CODE, "requirements.txt"), encoding="utf-8") as f:
            requirements = [re.fullmatch(r"([A-Za-z0-9_-]+)>=(\d+(?:\.\d+)*)", line.strip()) for line in f]
        for req in filter(None, requirements):
            name, minimum = req.groups()
            module = "PIL" if name.lower() == "pillow" else name
            if not importlib.util.find_spec(module):
                problems.append(name + " (missing)")
                continue
            try:
                installed = importlib.metadata.version(name)
            except importlib.metadata.PackageNotFoundError:
                problems.append(name + " (version unavailable)")
                continue
            actual = re.match(r"\d+(?:\.\d+)*", installed)
            numbers = lambda v: tuple(int(n) for n in v.split(".")) + (0,) * (4 - len(v.split(".")))
            if not actual or numbers(actual[0]) < numbers(minimum) or (
                    numbers(actual[0]) == numbers(minimum) and re.search(r"(?:dev|rc|a|b)\d", installed)):
                problems.append("%s %s (need >=%s)" % (name, installed, minimum))
    finally:
        sys.path.remove(vendor)
    return problems


def step_packages():
    vendor = os.path.join(CODE, "vendor")
    missing = package_problems()
    if not missing:
        say("  brotli, zstandard, Pillow and qrcode meet the required versions")
        return
    say("  packages to install or update: %s" % ", ".join(missing))
    if not yes("Install or update them in %s with pip?" % vendor):
        say("  skipped. Strata runs without them, but loses Brotli, image previews and 2FA QR codes.")
        return
    if run([sys.executable, "-m", "pip", "--version"])[0] != 0:
        run([sys.executable, "-m", "ensurepip", "--upgrade"], capture=False)
    code, _ = run([sys.executable, "-m", "pip", "install", "--upgrade", "--target", vendor, "-r",
                   os.path.join(CODE, "requirements.txt")], capture=False, timeout=900)
    say("  done" if code == 0 else "  pip failed (see above); continuing without the missing packages")


def step_site(cfg, raw, home):
    inst = raw.get("instance") or {}
    domain = ""
    while not re.fullmatch(r"(?i)[a-z0-9-]+(\.[a-z0-9-]+)+", domain):
        domain = ask("Your domain", inst.get("name") or "example.com").lower().strip().rstrip(".")
    hosts = raw.get("public", {}).get("hosts") or []
    cdn = ask("Hostname for the CDN", hosts[0] if hosts else "cdn." + domain).lower()
    iid = inst.get("id") or re.sub(r"[^a-z0-9]", "", domain.split(".")[0])[:16] or "site"
    default_home = os.path.normcase(home) == os.path.normcase(CODE)
    files = (raw.get("storage_paths") or [""])[0] or os.path.join(home, "files")
    files = os.path.abspath(ask("Folder with the files to serve", files))
    os.makedirs(files, exist_ok=True)
    cfg["site"] = {"domain": domain, "cdn": cdn, "files": files}
    merge(cfg["update"], {
        "instance": {"id": iid, "name": domain, "prefix": inst.get("prefix") or ("strata" if default_home else iid + "_strata")},
        "public": {"hosts": [cdn] if cdn == domain else [cdn, domain]},
        "public_base_url": "https://" + cdn,
        "storage_paths": [files] + [p for p in raw.get("storage_paths") or [] if p != files],
    })


def ports_for(raw, caddyfile_text):
    if raw.get("listen"):  # already set up: keep what the running instance uses
        p = lambda v, d: int(str(v or d).rsplit(":", 1)[-1])
        listen = p(raw.get("listen"), 8090)
        return {"listen": listen, "feed_listen": p(raw.get("feed_listen"), 8081),
                "transform_listen": p(raw.get("transform_listen"), 8083), "gate_listen": p(raw.get("gate_listen"), 8085),
                "media": p((raw.get("media") or {}).get("listen"), 8084),
                "cdn": p((raw.get("instance") or {}).get("cdn_listen"), 8080), "lan": listen + 1}
    return pick_ports(caddyfile_text)


def step_caddy(cfg, raw, home):
    extra = win_candidates("caddy.exe", "Caddy") + [r"C:\caddy\caddy.exe"] if WIN else ["/usr/bin/caddy", "/usr/local/bin/caddy"]
    exe = find_exe("caddy", raw.get("caddy_exe", ""), extra)
    if not exe:
        say("  Caddy was not found.")
        if WIN and yes("Install it with winget?"):
            winget_install("CaddyServer.Caddy")
            exe = find_exe("caddy", "", extra)
        if not exe:
            exe = ask("Path to caddy%s (or Enter to stop here)" % (".exe" if WIN else ""))
            if not os.path.isfile(exe):
                sys.exit("  Caddy is required: https://caddyserver.com/docs/install")
    say("  found %s (%s)" % (exe, run([exe, "version"])[1].split("\n")[0][:60]))

    default_cf = raw.get("caddyfile") or (os.path.join(os.path.dirname(exe), "Caddyfile") if WIN else "/etc/caddy/Caddyfile")
    caddyfile = os.path.abspath(ask("Caddyfile", default_cf))
    text = open(caddyfile, encoding="utf-8-sig").read() if os.path.exists(caddyfile) else ""
    ports = ports_for(raw, text)
    cfg["ports"] = ports
    gen = os.path.join(home, "generated", "cdn.caddy")
    import_line = "import " + gen.replace("\\", "/")  # the exact line rules.py looks for
    if not os.path.exists(gen):
        write(gen, "# Placeholder written by setup.py. Strata replaces it with the CDN site within a minute of starting.\n")

    if import_line in text:
        say("  the Caddyfile already imports Strata's config")
        new = text
    else:
        new = text or "# Caddyfile written by Strata setup on %s\n{\n\tadmin localhost:2019\n}\n" % time.strftime("%Y-%m-%d")
        if yes("Let other devices on your network open the dashboard on port %d?" % ports["lan"], False):
            new += "\n# Strata dashboard for your local network\n:%d {\n\treverse_proxy 127.0.0.1:%d\n}\n" % (ports["lan"], ports["listen"])
        new += "\n# CDN site on :%d, rendered by Strata from its database (Strata > Serving)\n%s\n" % (ports["cdn"], import_line)
    if new != text:
        if text:
            say("  backup: %s" % backup(caddyfile))
        write(caddyfile, new)
        say("  updated %s" % caddyfile)
    code, out = run([exe, "validate", "--config", caddyfile, "--adapter", "caddyfile"])
    if code != 0:
        say("  Caddy rejects the Caddyfile:\n    " + out.splitlines()[-1][:300] if out else "  Caddy rejects the Caddyfile")
        if text and new != text and yes("Restore the previous Caddyfile?"):
            write(caddyfile, text)
        sys.exit("  fix the Caddyfile and run setup again")
    say("  Caddy accepts the configuration")

    log_dir = os.path.join(os.path.dirname(caddyfile), "logs") if WIN else "/var/log/caddy"
    access_log = raw.get("access_log") or os.path.join(log_dir, "%s-access.log" % cfg["update"]["instance"]["id"])
    os.makedirs(os.path.dirname(access_log), exist_ok=True)
    merge(cfg["update"], {"caddy_exe": exe, "caddyfile": caddyfile, "access_log": access_log,
                          "listen": "127.0.0.1:%d" % ports["listen"], "feed_listen": "127.0.0.1:%d" % ports["feed_listen"],
                          "transform_listen": "127.0.0.1:%d" % ports["transform_listen"],
                          "gate_listen": "127.0.0.1:%d" % ports["gate_listen"],
                          "media": {"listen": "127.0.0.1:%d" % ports["media"]},
                          "instance": {"cdn_listen": ":%d" % ports["cdn"]}})
    cfg["caddy"] = {"exe": exe, "caddyfile": caddyfile}


def step_caddy_running(cfg, service):
    exe, caddyfile = cfg["caddy"]["exe"], cfg["caddy"]["caddyfile"]
    if http_get("http://localhost:2019/config/")[0] == 200:
        code, out = run([exe, "reload", "--config", caddyfile, "--adapter", "caddyfile"])
        say("  Caddy reloaded" if code == 0 else "  caddy reload failed: " + out[-300:])
        return
    if not service:
        return say("  Caddy is not running. Start it with: %s run --config \"%s\"" % (exe, caddyfile))
    say("  Caddy is not running.")
    if WIN and yes("Start Caddy at boot (Task Scheduler task \"Caddy\")?"):
        install_task("Caddy", "Caddy web server (installed by Strata setup)", exe,
                     'run --config "%s" --adapter caddyfile' % caddyfile, os.path.dirname(caddyfile))
        say("  task \"Caddy\" registered and started")
    elif not WIN:
        say("  start it with: systemctl enable --now caddy")


def find_cloudflared_config(raw):
    cands = [raw.get("cloudflared_config", ""), os.path.expanduser("~/.cloudflared/config.yml"),
             os.path.expanduser("~/.cloudflared/config.yaml")]
    if WIN:
        cands.append(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "config", "systemprofile",
                                  ".cloudflared", "config.yml"))
    else:
        cands += ["/etc/cloudflared/config.yml", "/usr/local/etc/cloudflared/config.yml"]
    return next((c for c in cands if c and os.path.isfile(c)), "")


def add_ingress(text, host, port):
    """Insert `host -> localhost:port` before the catch-all rule. Returns the new text, or None if it can't."""
    if re.search(r"(?m)^\s*-?\s*hostname:\s*['\"]?%s['\"]?\s*$" % re.escape(host), text):
        return text
    m = re.search(r"(?m)^(\s*)-\s*service:\s*http_status:\d+\s*$", text)
    if not m or "ingress:" not in text[:m.start()]:
        return None
    ind = m.group(1)
    rule = "%s- hostname: %s\n%s  service: http://localhost:%d\n" % (ind, host, ind, port)
    return text[:m.start()] + rule + text[m.start():]


def step_tunnel(cfg, raw, service):
    extra = win_candidates("cloudflared.exe", "cloudflared") if WIN else ["/usr/bin/cloudflared", "/usr/local/bin/cloudflared"]
    exe = find_exe("cloudflared", raw.get("cloudflared_exe", ""), extra)
    if not yes("Publish the CDN through a Cloudflare Tunnel?"):
        return
    if not exe:
        say("  cloudflared was not found.")
        if WIN and yes("Install it with winget?"):
            winget_install("Cloudflare.cloudflared")
            exe = find_exe("cloudflared", "", extra)
        if not exe:
            say("  skipped. Install cloudflared and run setup again to connect the tunnel.")
            return
    say("  found %s (%s)" % (exe, run([exe, "--version"])[1].split("\n")[0][:60]))
    host, port = cfg["site"]["cdn"], cfg["ports"]["cdn"]
    path = find_cloudflared_config(raw)
    tunnel = ""
    if path:
        say("  tunnel config: %s" % path)
        text = open(path, encoding="utf-8-sig").read()
        tunnel = (re.search(r"(?m)^tunnel:\s*['\"]?([^'\"\s]+)", text) or [None, ""])[1]
        new = add_ingress(text, host, port)
        if new is None:
            say("  couldn't find the ingress catch-all rule. Add this rule to the ingress list by hand:\n"
                "    - hostname: %s\n      service: http://localhost:%d" % (host, port))
        elif new != text:
            say("  backup: %s" % backup(path))
            write(path, new)
            code, out = run([exe, "tunnel", "--config", path, "ingress", "validate"])
            if code != 0:
                write(path, text)
                say("  cloudflared rejected the change, restored the old config: " + out[-300:])
            else:
                say("  added %s -> localhost:%d" % (host, port))
        else:
            say("  %s is already routed" % host)
    elif yes("No tunnel config found. Create a tunnel now? (opens a browser to sign in to Cloudflare)"):
        cert = os.path.expanduser("~/.cloudflared/cert.pem")
        if not os.path.exists(cert):
            run([exe, "tunnel", "login"], capture=False, timeout=600)
        name = "strata-" + cfg["update"]["instance"]["id"]
        code, out = run([exe, "tunnel", "create", name])
        m = re.search(r"with id ([0-9a-f-]{36})", out)
        creds = re.search(r"written to (.+?\.json)", out)
        if code != 0 or not m or not creds:
            say("  tunnel create failed: " + out[-400:])
            return
        tunnel = m.group(1)
        path = os.path.expanduser("~/.cloudflared/config.yml")
        write(path, "tunnel: %s\ncredentials-file: %s\n\ningress:\n  - hostname: %s\n    service: http://localhost:%d\n"
                    "  - service: http_status:404\n" % (tunnel, creds.group(1).strip(), host, port))
        say("  created tunnel %s, config %s" % (name, path))
    else:
        return
    if tunnel and yes("Point the DNS record for %s at this tunnel?" % host):
        code, out = run([exe, "tunnel", "--config", path, "route", "dns", tunnel, host])
        say("  " + (out.splitlines()[-1] if out else "done") if code == 0 else "  route dns failed: " + out[-300:])
    merge(cfg["update"], {"cloudflared_exe": exe, "cloudflared_config": path})

    restart = (raw.get("instance") or {}).get("tunnel_restart") or {}
    if restart.get("name"):
        say("  the tunnel runs as %s \"%s\"" % (restart.get("kind"), restart["name"]))
    elif WIN and service_exists("cloudflared"):
        say("  the tunnel runs as the Windows service \"cloudflared\"")
        merge(cfg["update"], {"instance": {"tunnel_restart": {"kind": "service", "name": "cloudflared"}}})
    elif service and yes("Run the tunnel in the background, started at boot?"):
        name = service_names(cfg["_home"], cfg["update"]["instance"]["id"])[1]
        args = 'tunnel --config "%s" run' % path
        if WIN:
            install_task(name, "Cloudflare Tunnel for Strata", exe, args, os.path.dirname(path))
            merge(cfg["update"], {"instance": {"tunnel_restart": {"kind": "task", "name": name}}})
        else:
            install_unit(name, "Cloudflare Tunnel for Strata", '%s %s' % (exe, args), os.path.dirname(path))
        say("  %s registered and started" % name)


def step_tokens(cfg, raw):
    cf = raw.get("cloudflare") or {}
    say("  Cloudflare API token: lets Strata manage DNS, purge the cache and block addresses at the edge.")
    say("  Create one at https://dash.cloudflare.com/profile/api-tokens with: " + ", ".join(CF_PERMISSIONS))
    token = secret("Cloudflare API token (Enter to %s)" % ("keep the current one" if cf.get("api_token") else "skip"))
    if token:
        st, body = http_get("https://api.cloudflare.com/client/v4/user/tokens/verify", {"Authorization": "Bearer " + token})
        if st != 200:
            say("  Cloudflare refused this token (HTTP %s); saved anyway, check it under Network in the dashboard" % st)
        zone_name, zone_id = cfg["site"]["domain"], cf.get("zone_id", "")
        st, body = http_get("https://api.cloudflare.com/client/v4/zones?name=" + zone_name, {"Authorization": "Bearer " + token})
        try:
            zone_id = json.loads(body)["result"][0]["id"]
            say("  zone %s: %s" % (zone_name, zone_id))
        except (ValueError, KeyError, IndexError, TypeError):
            zone_id = ask("Zone ID of %s (Cloudflare dashboard > Overview)" % zone_name, zone_id)
        merge(cfg["update"], {"cloudflare": {"api_token": token, "zone_id": zone_id, "zone_name": zone_name}})

    alerts = raw.get("alerts") or {}
    say("\n  Every sign-in asks for a code after the password. The owner can use an authenticator app; other")
    say("  accounts get it by e-mail, through any SMTP server (your mail provider's or your own) or through")
    say("  Resend (https://resend.com, the free tier is enough).")
    smtp = alerts.get("smtp") or {}
    sender = ask("Send e-mail from", alerts.get("from") or "strata@" + cfg["site"]["domain"])
    host = ask("SMTP server (Enter to use Resend instead)", smtp.get("host") or "").strip().lower()
    if host:
        port = int(ask("SMTP port (587 = STARTTLS, 465 = TLS)", str(smtp.get("port") or 587)) or 587)
        user = ask("SMTP user name", smtp.get("user") or sender)
        pw = secret("SMTP password (Enter to %s)" % ("keep the current one" if smtp.get("password") else "send none"))
        merge(cfg["update"], {"alerts": {"from": sender, "provider": "smtp", "smtp": {
            "host": host, "port": port, "security": "tls" if port == 465 else "starttls", "user": user,
            "password": pw or smtp.get("password") or ""}}})
    else:
        key = secret("Resend API key (Enter to %s)" % ("keep the current one" if alerts.get("resend_api_key") else "skip"))
        if key:
            merge(cfg["update"], {"alerts": {"resend_api_key": key, "from": sender, "provider": "resend"}})
    mail = bool(host or key or alerts.get("resend_api_key") or smtp.get("host"))

    auth = raw.get("auth") or {}
    if auth.get("password_hash") and yes("Keep the owner account \"%s\"?" % auth.get("user")):
        if not mail and not auth.get("totp_secret"):
            say("  The owner has no way to get a sign-in code. Add an authenticator app with: python auth.py --totp")
        return
    say("\n  The owner account can change everything. Leave the name empty to create it later at /setup.")
    user = ask("Owner username", auth.get("user") or "")
    if not user:
        return
    while not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{1,59}", user):
        user = ask("Usernames are 2-60 letters, digits, dots, dashes or underscores. Owner username")
    while True:
        pw = secret("Password (12 characters or more)")
        if len(pw) < 12:
            say("  too short")
        elif secret("Repeat password") != pw:
            say("  the passwords don't match")
        else:
            break
    os.environ["STRATA_HOME"] = cfg["_home"]
    sys.path.insert(0, CODE)
    import auth as strata_auth  # same hash and TOTP format the server checks
    update = {"auth": {"user": user, "password_hash": strata_auth.hash_password(pw)}}
    app = owner_app(strata_auth, user) if yes("Use an authenticator app for the owner's sign-in code?", not mail) else None
    if app:
        update["auth"].update(app)
    email_ok = lambda e: re.fullmatch(r"[^\s@]+@[^\s@.]+(\.[^\s@.]{2,})+", e)
    email = (alerts.get("to") or [""])[0]
    if app:
        email = ask("Owner e-mail for alerts (Enter to skip)", email).lower() if mail else ""
        while email and not email_ok(email):
            email = ask("Owner e-mail for alerts (Enter to skip)").lower()
    else:
        for _ in range(3):  # bounded: with input piped in, an empty answer would otherwise repeat forever
            email = ask("Owner e-mail (sign-in codes go here)", email).lower()
            if email_ok(email):
                break
            email = ""
        if not email:
            say("  No e-mail address, so the owner can't sign in yet. Add an authenticator app with: python auth.py --totp")
        elif not mail:
            say("  Without a Resend key the owner can't sign in yet. Add one with: python auth.py --resend <key> <from>, "
                "or an authenticator app with: python auth.py --totp")
    if email:
        update["alerts"] = {"to": [email] + [t for t in alerts.get("to") or [] if t != email]}
    merge(cfg["update"], update)


def owner_app(strata_auth, user):
    """Shows a new authenticator key and checks a code from the app. Returns the auth settings to store, or None."""
    secret = strata_auth.totp_secret()
    qr = strata_auth.qr_text(strata_auth.totp_uri(secret, user))
    try:
        if qr:
            say(qr)
    except UnicodeEncodeError:  # a console that can't draw the block characters: the key below still works
        pass
    say("  Scan this with your authenticator app, or enter the key: %s" % strata_auth.spaced(secret))
    for _ in range(3):
        matched = strata_auth.totp_verify(secret, ask("Code from the app"))
        if matched:
            codes, hashes = strata_auth.recovery_codes()
            say("  Recovery codes. If you lose your phone, each works once instead of a code from the app.")
            say("  They are shown only now:\n    " + "\n    ".join("  ".join(codes[i:i + 2]) for i in range(0, len(codes), 2)))
            return {"totp_secret": secret, "totp_last": matched, "recovery": hashes}
        say("  That code didn't match. Check that the time on your phone is correct.")
    say("  skipped the authenticator app")
    return None


def secrets_mod():
    sys.path.insert(0, CODE)
    import instance  # data/.env helpers, no side effects beyond resolving the home
    return instance


def step_save(cfg, raw, path):
    """strata.json without secrets (its backup too); every secret goes to <home>/data/.env, locked down."""
    inst = secrets_mod()
    if os.path.exists(path):
        bak = backup(path)
        with open(bak, encoding="utf-8-sig") as f:
            old = json.load(f)
        inst.split_secrets(old, old)  # an older strata.json may still hold secrets: never keep a copy of them
        write(bak, json.dumps(old, indent=2) + "\n")
        say("  backup: %s" % bak)
    merged = merge(raw, cfg["update"])
    found = inst.split_secrets(merged, merged)
    if found:
        env = inst.env_path(os.path.dirname(path))
        inst.env_write(found, env)
        say("  wrote %d secret(s) to %s (this account, SYSTEM and Administrators only)" % (sum(1 for v in found.values() if v), env))
    write(path, json.dumps(merged, indent=2) + "\n")
    say("  wrote %s" % path)


def step_service(cfg, raw):
    name = service_names(cfg["_home"], raw["instance"]["id"])[0]
    script = os.path.join(CODE, "strata.py")
    home = cfg["_home"]
    if WIN:
        pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
        install_task(name, "Strata dashboard for %s" % raw["instance"]["name"], pyw if os.path.exists(pyw) else sys.executable,
                     '"%s" --home "%s"' % (script, home), CODE)
        say("  Task Scheduler task \"%s\" registered (starts at boot, runs as SYSTEM) and started" % name)
    else:
        install_unit(name, "Strata dashboard for %s" % raw["instance"]["name"],
                     '%s %s --home %s' % (sys.executable, script, home), CODE, "network-online.target caddy.service")
        say("  systemd unit %s enabled and started" % name)
    url = "http://%s/login" % raw["listen"]
    for _ in range(40):
        st, _ = http_get(url, timeout=3)
        if st == 200:
            say("  Strata answers on http://%s" % raw["listen"])
            return True
        time.sleep(1)
    say("  Strata did not answer within 40 seconds. Its log: %s" % os.path.join(home, "data", "strata.log"))
    return False


# ---------------------------------------------------------------- commands

def load(home):
    """strata.json with the secrets of <home>/data/.env put back in, so every prompt can offer to keep them."""
    path = os.path.join(home, "strata.json")
    raw = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8-sig") as f:
            raw = json.load(f)
    inst = secrets_mod()
    return path, inst.overlay_secrets(raw, inst.env_path(home))


def check(home):
    path, raw = load(home)
    say("Python      %s (%s)" % (sys.version.split()[0], sys.executable))
    sys.path.insert(0, os.path.join(CODE, "vendor"))
    import importlib.util
    for m in ("brotli", "zstandard", "PIL", "qrcode"):
        say("%-11s %s" % (m, "ok" if importlib.util.find_spec(m) else "missing"))
    say("config      %s" % (path if raw else "none yet"))
    caddy = find_exe("caddy", raw.get("caddy_exe", ""))
    say("caddy       %s" % (caddy or "not found"))
    say("caddy admin %s" % ("running" if http_get("http://localhost:2019/config/")[0] == 200 else "not running"))
    say("cloudflared %s" % (find_exe("cloudflared", raw.get("cloudflared_exe", "")) or "not found"))
    if raw:
        name = service_names(home, raw.get("instance", {}).get("id"))[0]
        say("service     %s: %s" % (name, "registered" if (task_exists(name) if WIN else service_exists(name)) else "not registered"))
        say("dashboard   %s" % ("up" if http_get("http://%s/login" % raw.get("listen", "127.0.0.1:8090"), timeout=3)[0] == 200 else "down"))


def uninstall(home):
    _, raw = load(home)
    name = service_names(home, raw.get("instance", {}).get("id"))[0]
    if WIN:
        run(["schtasks", "/End", "/TN", name])
        code, out = run(["schtasks", "/Delete", "/TN", name, "/F"])
    else:
        run(["systemctl", "disable", "--now", name])
        code, out = (0, "") if not os.path.exists("/etc/systemd/system/%s.service" % name) else run(
            ["rm", "/etc/systemd/system/%s.service" % name])
        run(["systemctl", "daemon-reload"])
    say("removed %s" % name if code == 0 else "could not remove %s: %s" % (name, out))
    say("Configuration and data in %s are untouched. Caddy and the tunnel keep running." % home)


def main():
    ap = argparse.ArgumentParser(description="Install Strata on this machine.")
    ap.add_argument("--home", default=CODE, help="instance folder (default: this folder)")
    ap.add_argument("--check", action="store_true", help="report the current state and exit")
    ap.add_argument("--no-service", action="store_true", help="don't register or start the background service")
    ap.add_argument("--uninstall", action="store_true", help="remove the background service")
    ap.add_argument("--elevated", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args()
    home = os.path.abspath(a.home)
    if a.check:
        return check(home)
    if sys.version_info < (3, 10):
        sys.exit("Strata needs Python 3.10 or newer (this is %s)" % sys.version.split()[0])
    if not a.no_service and not is_admin():
        if WIN and relaunch_elevated():
            return say("Continuing in a new window with administrator rights.")
        sys.exit("Registering the service needs %s. Run again %s, or use --no-service."
                 % (("administrator rights", "from an administrator terminal") if WIN else ("root", "with sudo")))
    if a.uninstall:
        return uninstall(home)
    if WIN and "WindowsApps" in sys.executable and not a.no_service:
        sys.exit("The Microsoft Store Python can't run as a service. Install Python from https://python.org and run "
                 "setup with that one.")

    os.makedirs(home, exist_ok=True)
    path, raw = load(home)
    say("Strata setup  (code: %s, instance folder: %s)" % (CODE, home))
    if raw:
        say("Existing configuration found. Values in brackets are the current ones; press Enter to keep them.")
    cfg = {"_home": home, "update": {}}
    total = 6 if a.no_service else 7
    step(1, total, "Python packages")
    step_packages()
    step(2, total, "Site")
    step_site(cfg, raw, home)
    step(3, total, "Caddy")
    step_caddy(cfg, raw, home)
    step(4, total, "Cloudflare Tunnel")
    step_tunnel(cfg, raw, not a.no_service)
    step(5, total, "Keys and owner account")
    step_tokens(cfg, raw)
    step(6, total, "Configuration")
    step_save(cfg, raw, path)
    if a.no_service:
        step_caddy_running(cfg, False)
        say("\nDone. Start Strata with:  python strata.py --home \"%s\"" % home)
        return
    step(7, total, "Service")
    step_caddy_running(cfg, True)
    ok = step_service(cfg, raw)
    if ok:
        say("\nDone. Open http://%s on this machine%s." % (
            raw["listen"], "" if raw.get("auth", {}).get("password_hash") else " to create the owner account"))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        say("\ncancelled; files changed so far have backups in the backups folders listed above")
    finally:
        if "--elevated" in sys.argv:
            input("\nPress Enter to close this window.")
