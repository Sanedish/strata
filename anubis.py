"""Bot protection with Anubis (https://anubis.techaro.lol, https://github.com/TecharoHQ/anubis, MIT licence).

Anubis makes a browser solve a small proof-of-work puzzle before it gets a page, which slows scrapers down. Strata
does not bundle it. The dashboard's Challenger page can fetch the release Strata was tested with from github.com (one
click, checked against the SHA-256 GitHub publishes for that file), register it as a start-up task and switch it on.
Nothing here runs until someone clicks, and with `anubis.enabled` false (the default) the generated Caddy config is
unchanged.

How it is wired (rules.render_challenge):
    Caddy `forward_auth` -> Anubis /.within.website/x/cmd/anubis/api/check   (Anubis in "auth request" mode)
        200  the browser holds a valid pass cookie: the request carries on to the file
        401  no cookie (307 when Anubis has a --public-url, which its puzzle page needs): Caddy redirects to
             /.within.website/?redir=<url>, which is also proxied to Anubis
    so Anubis never proxies the files itself (--target is blank) and there is no proxy loop.

Per instance (a second site started with --home gets its own port, key, cookie and policy):
    <home>/.private/anubis.key           64 hex characters, ed25519 signing key, passed as a *file* so it is never on
                                         a command line, in strata.json or in a log
    <home>/generated/anubis-policy.yaml  rewritten by rules.apply() and when the settings are saved
"""
import hashlib
import hmac
import json
import os
import platform
import re
import secrets
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

import core
from core import CFG

# the release Strata is tested with (tests/anubis_test.py); a newer one is a one-line change here
TESTED = "1.28.1"
RELEASE_API = "https://api.github.com/repos/TecharoHQ/anubis/releases/tags/v" + TESTED
DOWNLOAD_HOSTS = ("github.com", "api.github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com")
MAX_DOWNLOAD = 100 << 20
BUSY = threading.Lock()  # one install or set-up at a time
CHECK_PATH = "/.within.website/x/cmd/anubis/api/check"
POLICY_NAME = "anubis-policy.yaml"
AUTO_RULE_NAME = "Automatic bot challenge"
LOOPBACK_RE = re.compile(r"^(127\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[::1\]|localhost):(\d{4,5})$")
NOWIN = getattr(subprocess, "CREATE_NO_WINDOW", 0)
# Anubis' shipped lists (anubis docs: configuration/import). Not (data)/meta/default-config.yaml as a whole: it also holds
# GeoIP/ASN rules that need a GeoIP database Strata does not set up.
DEFAULT_IMPORTS = ("(data)/bots/_deny-pathological.yaml", "(data)/meta/ai-block-aggressive.yaml",
                   "(data)/crawlers/_allow-good.yaml", "(data)/common/keep-internet-working.yaml")


class BotError(Exception):
    pass


def port_offset():
    """Strata's own port against the default 8090: the second instance (8190) gets Anubis on 9023 and so on."""
    try:
        return int(str(CFG["listen"]).rsplit(":", 1)[1]) - 8090
    except (ValueError, IndexError):
        return 0


def settings():
    a = dict(CFG["anubis"])
    a["bind"] = a.get("bind") or "127.0.0.1:%d" % (8923 + port_offset())
    a["metrics"] = a.get("metrics") or "127.0.0.1:%d" % (9923 + port_offset())
    if under_attack():
        # Under Attack Mode: everyone solves a harder puzzle, direct downloads included (the auto rule's flag).
        # Resting difficulty comes back on its own when the window lapses; the flag is cleared lazily below.
        a["difficulty"] = max(int(a["difficulty"]), UNDER_ATTACK_DIFFICULTY)
    return a


UNDER_ATTACK_DIFFICULTY = 6   # 4 is Anubis' default; 6 is ~256x the work - slow for a browser, slower for a scraper farm
UNDER_ATTACK_STRETCH = 3600   # default window: one hour, adjustable after it is on


def under_attack_left():
    """Seconds of Under Attack Mode left (0 = off); a lapsed window is cleared from the config here."""
    until = float(CFG["anubis"].get("under_attack_until") or 0)
    left = until - time.time()
    if left <= 0 and until:
        core.save_config({"anubis": {"under_attack_until": 0}})
        if enabled():
            import rules  # the downloads overlay and the difficulty are in the Caddy config: re-render (local: circular)
            rules.mutate("", "under attack mode expired", lambda db: None)
            rules.EDGE_SYNC.set()
            # difficulty is back down: Anubis reads the policy only at start, so restart it (off the request thread)
            if write_policy() and not CFG["instance"].get("dry_run") and task_installed():
                threading.Thread(target=_restart_quietly, daemon=True).start()
        return 0
    return max(0, int(left))


def _restart_quietly():
    try:
        restart("under attack mode expired")
    except Exception as e:
        core.log("anubis: restart after Under Attack Mode failed: %s" % e)


def under_attack():
    return under_attack_left() > 0


def auto_rule(db):
    """The challenge rule Strata manages for the one-switch experience (None if the user deleted it)."""
    import rules  # rules.py imports anubis at module level, so keep this local (same as ensure_auto_rule)
    for r in rules.load(db)["rules"]:
        if r.get("name") == AUTO_RULE_NAME and r["action"] == "challenge":
            return r
    return None


def ensure_auto_rule(user, downloads=None):
    """Make sure the global challenge rule exists. Custom rules are never touched: the auto rule is an ordinary row
    the user can see and edit under Serving › Rules like any other. Direct downloads are covered while Under Attack
    Mode is on by an overlay in rules.render_challenge - the rule's own downloads flag is the user's resting choice."""
    import rules as rules_mod
    db = core.connect()
    try:
        if auto_rule(db):
            return "kept"
        rules_mod.save_rule(user, {"name": AUTO_RULE_NAME, "action": "challenge", "patterns": ["/*"],
                                   "params": {"downloads": bool(downloads)}})
        return "created"
    finally:
        db.close()


def enabled():
    return bool(CFG["anubis"].get("enabled"))


def policy_path():
    return os.path.join(core.HOME, "generated", POLICY_NAME)


def key_path():
    return os.path.join(core.HOME, ".private", "anubis.key")


def ensure_key():
    """Create the signing key once. Every Anubis on one base domain must share it, so an existing file is kept."""
    p = key_path()
    if not os.path.exists(p):
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="ascii") as f:
            f.write(secrets.token_hex(32))
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
    return p


def program_dir():
    return os.path.join(core.HOME, ".private", "anubis")


def asset_name():
    """The release file for this machine: anubis-<version>-<os>-<arch>.zip (Windows) or .tar.gz (Linux)."""
    arch = {"amd64": "amd64", "x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64", "riscv64": "riscv64",
            "ppc64le": "ppc64le"}.get(platform.machine().lower())
    if os.name == "nt" and arch in ("amd64", "arm64"):
        return "anubis-%s-windows-%s.zip" % (TESTED, arch)
    if sys.platform.startswith("linux") and arch:
        return "anubis-%s-linux-%s.tar.gz" % (TESTED, arch)
    raise BotError("There is no Anubis download for this system (%s, %s). Install it yourself and set its path under Settings."
                   % (sys.platform, platform.machine()))


class Pinned(urllib.request.HTTPRedirectHandler):
    """GitHub redirects release files to its own storage; anything else (or plain http) is refused."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        u = urllib.parse.urlsplit(newurl)
        if u.scheme != "https" or u.hostname not in DOWNLOAD_HOSTS:
            raise BotError("The download was sent to %s, which Strata doesn't trust" % u.hostname)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url):
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" or u.hostname not in DOWNLOAD_HOSTS:
        raise BotError("Refusing to fetch " + url)
    req = urllib.request.Request(url, headers={"User-Agent": "Strata", "Accept": "application/vnd.github+json, */*"})
    try:
        return urllib.request.build_opener(Pinned).open(req, timeout=30)
    except urllib.error.HTTPError as e:
        raise BotError("github.com answered %d for %s" % (e.code, u.path))
    except (urllib.error.URLError, OSError) as e:
        raise BotError("Couldn't reach github.com: %s" % (getattr(e, "reason", None) or e))


def install(user=""):
    """Download the tested release, check it against GitHub's SHA-256 for the file, and unpack only anubis(.exe) and its
    licence into <home>/.private/anubis/. Nothing else from the archive is written. GitHub vouches for both the file
    and its checksum: this catches a damaged or swapped download, not a compromised release."""
    if not BUSY.acquire(blocking=False):
        raise BotError("Another Anubis install or set-up is running")
    try:
        return install_locked(user)
    finally:
        BUSY.release()


def install_locked(user):
    name = asset_name()
    with fetch(RELEASE_API) as r:
        rel = json.loads(r.read(2 << 20))
    asset = next((a for a in rel.get("assets", []) if a.get("name") == name), None)
    if not asset:
        raise BotError("Release %s has no file called %s" % (TESTED, name))
    want = str(asset.get("digest") or "")
    if not want.startswith("sha256:") or not 0 < int(asset.get("size") or 0) <= MAX_DOWNLOAD:
        raise BotError("GitHub gave no checksum (or an odd size) for %s; not installing it" % name)
    out = program_dir()
    os.makedirs(out, exist_ok=True)
    sha, got = hashlib.sha256(), 0
    fd, tmp = tempfile.mkstemp(dir=out, suffix=".download")
    try:
        with os.fdopen(fd, "wb") as f, fetch(asset["browser_download_url"]) as r:
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                got += len(chunk)
                if got > MAX_DOWNLOAD:
                    raise BotError("The download is bigger than expected; stopped")
                sha.update(chunk)
                f.write(chunk)
        if not hmac.compare_digest("sha256:" + sha.hexdigest(), want):
            raise BotError("The downloaded file does not match GitHub's checksum; nothing was installed")
        exe = unpack(tmp, out)
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    if not version(exe):
        raise BotError("The downloaded program doesn't start on this machine")
    core.save_config({"anubis": {"exe": exe}})
    core.audit("", user, "anubis-install", "%s %s" % (TESTED, name))
    return exe


def unpack(archive, out):
    """Only bin/anubis(.exe) and doc/LICENSE, read by name: no path from the archive is ever used to write."""
    exe_key = "bin/anubis.exe" if os.name == "nt" else "bin/anubis"
    want = {exe_key: os.path.basename(exe_key), "doc/LICENSE": "LICENSE"}
    found = {}
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as z:
            for info in z.infolist():
                key = "/".join(info.filename.split("/")[1:])
                if key in want and not info.is_dir() and info.file_size <= MAX_DOWNLOAD:
                    found[key] = z.read(info)
    else:
        with tarfile.open(archive) as t:
            for m in t.getmembers():
                key = "/".join(m.name.split("/")[1:])
                if key in want and m.isreg() and m.size <= MAX_DOWNLOAD:
                    found[key] = t.extractfile(m).read()
    if len(found) < 2:
        raise BotError("The archive doesn't hold the files Strata expects (%s, doc/LICENSE)" % exe_key)
    for key, data in found.items():
        dest = os.path.join(out, want[key])
        with open(dest + ".new", "wb") as f:
            f.write(data)
        try:
            os.replace(dest + ".new", dest)
        except OSError:
            os.remove(dest + ".new")
            raise BotError("Anubis is running from %s. Stop it first (Stop), then install again." % dest)
    exe = os.path.join(out, want[exe_key])
    if os.name != "nt":
        os.chmod(exe, 0o755)
    return exe


def policy_text():
    s = settings()
    out = ["# Generated by Strata (instance %s) - do not edit by hand: use Settings > Bot protection." %
           re.sub(r"[\r\n]", " ", core.HOME),
           "# Caddy decides which requests are sent here (Serving > rules > challenge); this file decides what Anubis does with them.",
           "bots:"]
    if s["defaults"]:
        out += ["  - import: " + i for i in DEFAULT_IMPORTS]
    out += ["  - name: strata-challenge", "    path_regex: .*", "    action: CHALLENGE",
            "    challenge:", "      difficulty: %d" % int(s["difficulty"]), "      algorithm: fast",
            # forward_auth treats any 2xx as 'pass': a denied request must not be a 200 (docs: subrequest-auth)
            "status_codes:", "  CHALLENGE: 200", "  DENY: 403",
            "metrics:", '  bind: "%s"' % s["metrics"], '  network: "tcp"']
    return "\n".join(out) + "\n"


def write_policy(force=False):
    """Keep generated/anubis-policy.yaml current. Does nothing (and creates nothing) while bot protection is off,
    unless force: the start-up task needs the file before it is switched on."""
    if not (enabled() or force):
        return False
    text, p = policy_text(), policy_path()
    try:  # closed before os.replace below: an open handle makes that fail with WinError 32 on Windows
        with open(p, encoding="utf-8") as f:
            if f.read() == text:
                return False
    except OSError:
        pass
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p + ".tmp", "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    os.replace(p + ".tmp", p)
    return True


def redirect_domains():
    """Hosts Anubis may send a visitor back to after the puzzle (REDIRECT_DOMAINS: stops it being an open redirect)."""
    hosts = list(CFG["public"]["hosts"])
    for m in core.mounts():
        hosts += m.get("hosts") or []
    return ",".join(dict.fromkeys(h for h in hosts if h))


def command():
    """Anubis' command line for this instance. --target is blank on purpose: auth-request mode, nothing is proxied."""
    s = settings()
    argv = [s["exe"], "--bind", s["bind"], "--target", " ", "--policy-fname", policy_path(),
            "--ed25519-private-key-hex-file", key_path(), "--difficulty", str(int(s["difficulty"])),
            "--redirect-domains", redirect_domains(), "--slog-level", "WARN"]
    if s["cookie_domain"]:
        argv += ["--cookie-domain", s["cookie_domain"]]
    # without a public URL the puzzle page sends the browser back to itself instead of to the file (found with a real
    # browser); a bare scheme is enough for its script to read ?redir=, and works for every host of the instance
    argv += ["--public-url", s["public_url"]]
    if s["public_url"] == "http://":  # no TLS: browsers drop Secure / Partitioned cookies, which are Anubis' default
        argv += ["--cookie-secure=false", "--cookie-partitioned=false"]
    return argv


def clean(d):
    """Validated settings from the dashboard (anything missing keeps its value)."""
    a = {}
    if "enabled" in d:
        a["enabled"] = bool(d["enabled"])
    for k in ("bind", "metrics"):
        if k in d:
            v = str(d[k] or "").strip().lower()
            if v and not LOOPBACK_RE.match(v):
                raise BotError("%s: Anubis must run on this PC, e.g. 127.0.0.1:8923" % k)
            a[k] = v
    if "exe" in d:
        v = str(d["exe"] or "").strip().strip('"')
        if v and (not os.path.isfile(v) or os.path.basename(v).lower() not in ("anubis", "anubis.exe")):
            raise BotError("Executable: pick the file called anubis.exe (anubis on Linux)")
        a["exe"] = v
    if "difficulty" in d:
        a["difficulty"] = int(d["difficulty"])
        if not 1 <= a["difficulty"] <= 8:
            raise BotError("Difficulty: 1 to 8 (4 is Anubis' default; each step is about 16 times more work)")
    if "defaults" in d:
        a["defaults"] = bool(d["defaults"])
    if "public_url" in d:
        a["public_url"] = str(d["public_url"] or "https://").strip().lower()
        if a["public_url"] not in ("http://", "https://"):
            raise BotError("public_url: http:// or https:// (just the scheme)")
    if "cookie_domain" in d:
        v = str(d["cookie_domain"] or "").strip().lower()
        if v and not re.match(r"^(?:[a-z0-9-]+\.)+[a-z]{2,63}$", v):
            raise BotError("Cookie domain: a domain like example.com, without a port")
        a["cookie_domain"] = v
    if "under_attack_until" in d:  # internal only - written by set_under_attack, never by the settings sheet
        try:
            a["under_attack_until"] = max(0.0, float(d["under_attack_until"] or 0))
        except (TypeError, ValueError):
            raise BotError("under_attack_until: a timestamp or 0")
    return a


def save(d):
    a = clean(d)
    if a.get("enabled") and not enabled() and not CFG["instance"].get("dry_run"):
        # Caddy fails closed: while Anubis is down, every challenged path answers 502. Don't let one click do that.
        up, answers = probe(a.get("bind") or settings()["bind"])
        if not answers:
            raise BotError("Anubis doesn't answer on %s yet. Start it (register the start-up task below, or run it yourself), "
                           "then switch bot protection on." % (a.get("bind") or settings()["bind"]))
    core.save_config({"anubis": a})
    if enabled():
        ensure_key()
        write_policy()


def version(exe):
    if not exe or not os.path.isfile(exe):
        return ""
    try:
        p = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=10, creationflags=NOWIN)
        return (p.stdout or p.stderr or "").strip()[:60]
    except (OSError, subprocess.TimeoutExpired):
        return ""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def probe(bind=None):
    """(reachable, answers) - a TCP connect, then the check URL as Anubis itself would get it from Caddy: 401 (it wants
    a puzzle solved) or 200 means the policy loaded; 500 means a header it needs is missing; anything else is not Anubis."""
    s = {"bind": bind or settings()["bind"]}
    host, _, port = s["bind"].rpartition(":")
    try:
        socket.create_connection((host.strip("[]"), int(port)), timeout=2).close()
    except OSError:
        return False, False
    # the host must be one Anubis may redirect to (--redirect-domains), or it answers 400 instead of asking for a puzzle
    host_h = (redirect_domains().split(",")[0] or "localhost")
    req = urllib.request.Request("http://%s%s" % (s["bind"], CHECK_PATH), headers={
        "X-Real-IP": "127.0.0.1", "X-Forwarded-Proto": "http", "X-Forwarded-Host": host_h,
        "X-Forwarded-Uri": "/", "User-Agent": core.PROBE_UA})
    try:
        return True, urllib.request.build_opener(NoRedirect).open(req, timeout=5).status == 200
    except urllib.error.HTTPError as e:
        return True, e.code in (401, 307)  # 307: with a --public-url Anubis redirects to its puzzle page itself
    except OSError:
        return True, False


def task_name():
    import setup
    return setup.service_names(core.HOME, CFG["instance"].get("id") or "")[0] + (" Anubis" if setup.WIN else "-anubis")


def task_installed():
    import setup
    return setup.task_exists(task_name()) if setup.WIN else os.path.exists("/etc/systemd/system/%s.service" % task_name())


def state():
    s = settings()
    up, answers = probe()  # also while switched off: "Check" tells you whether it is safe to switch on
    try:
        asset = asset_name()
    except BotError:
        asset = ""
    rest = CFG["anubis"].get("difficulty", 4)
    db = core.connect()
    try:
        auto = auto_rule(db)
    finally:
        db.close()
    return {"enabled": s["enabled"], "bind": s["bind"], "metrics": s["metrics"], "exe": s["exe"], "difficulty": s["difficulty"],
            "rest_difficulty": int(rest), "under_attack": under_attack(),
            "under_attack_left": under_attack_left(),
            "auto_rule": auto["id"] if auto else None,
            # what is in force now: the row's flag, or Under Attack Mode's overlay over every challenge rule
            "auto_downloads": bool((auto["params"] or {}).get("downloads")) or under_attack() if auto else under_attack(),
            "defaults": s["defaults"], "cookie_domain": s["cookie_domain"], "version": version(s["exe"]),
            "reachable": up, "answers": answers, "policy": policy_path(), "key": key_path(),
            "key_exists": os.path.exists(key_path()), "policy_exists": os.path.exists(policy_path()),
            "task": task_name(), "task_installed": task_installed(), "tested": TESTED, "asset": asset,
            "dry_run": bool(CFG["instance"].get("dry_run")), "counts": counts(s["metrics"]) if up else None,
            "prometheus": "http://%s/metrics" % s["metrics"]}


def set_under_attack(user, seconds):
    """Turn Under Attack Mode on for `seconds` (0 = off). While it is on, rules.render_challenge and
    cloudflare.challenge_expression overlay downloads onto every challenge rule, whatever its resting flag. A
    restart of Anubis (it reads the policy only at start) is the caller's job - the API endpoint does it after the
    policy file is rewritten."""
    if seconds and not enabled():
        raise BotError("Bot protection is off: switch it on before Under Attack Mode.")
    core.save_config({"anubis": {"under_attack_until": (time.time() + seconds) if seconds else 0}})
    write_policy(force=True)
    if seconds:  # expire on time even when nobody has the dashboard open (housekeeping is the hourly backstop)
        t = threading.Timer(seconds + 1, under_attack_left)
        t.daemon = True
        t.start()
    core.audit("", user, "anubis-under-attack", "%ds" % seconds)
    return state()


def counts(metrics):
    """Requests Anubis has judged since it started, by result (CHALLENGE / ALLOW / DENY), from its Prometheus page."""
    out = {}
    try:
        text = urllib.request.urlopen("http://%s/metrics" % metrics, timeout=2).read(2 << 20).decode("utf-8", "replace")
    except (OSError, ValueError):
        return None
    for m in re.finditer(r'^anubis_policy_results\{[^}]*action="([A-Z]+)"[^}]*\}\s+([0-9.e+]+)', text, re.M):
        out[m.group(1)] = out.get(m.group(1), 0) + int(float(m.group(2)))
    return out


def install_task(user=""):
    """Registers Anubis to start with the PC (Task Scheduler / systemd), as the other Strata services do, and starts it."""
    import setup
    s = settings()
    if not s["exe"]:
        raise BotError("Install Anubis first (the Install button), or set the path of an Anubis you installed yourself")
    if CFG["instance"].get("dry_run"):
        return {"installed": False, "note": "dry run instance: no start-up task registered"}
    ensure_key()
    write_policy(force=True)
    argv = command()
    name = task_name()
    try:
        if setup.WIN:
            setup.install_task(name, "Anubis bot protection for %s" % CFG["instance"]["name"], argv[0],
                               subprocess.list2cmdline(argv[1:]), os.path.dirname(argv[0]))
        else:
            setup.install_unit(name, "Anubis bot protection for %s" % CFG["instance"]["name"],
                               " ".join(subprocess.list2cmdline([a]) if " " in a else a for a in argv),
                               os.path.dirname(argv[0]))
    except RuntimeError as e:
        raise BotError(str(e))
    core.audit("", user, "anubis-task", name)
    return {"installed": True, "task": name}


def restart(user=""):
    """Stop, then start the task: Anubis reads its settings (hosts, difficulty, key) only at start."""
    import setup
    name = task_name()
    if CFG["instance"].get("dry_run") or not task_installed():
        raise BotError("No start-up task for this instance yet. Register it first.")
    if setup.WIN:
        subprocess.run(["schtasks", "/End", "/TN", name], capture_output=True, creationflags=NOWIN, timeout=30)
        p = subprocess.run(["schtasks", "/Run", "/TN", name], capture_output=True, text=True, creationflags=NOWIN, timeout=30)
    else:
        p = subprocess.run(["systemctl", "restart", name], capture_output=True, text=True, timeout=60)
    if p.returncode != 0:
        raise BotError("Restart failed: %s" % ((p.stderr or p.stdout or "").strip()[-300:]))
    core.audit("", user, "anubis-restart", name)
    return {"restarted": True}


def guard_down():
    if enabled():
        raise BotError("Switch bot protection off first: while Anubis is down, every challenged path answers 502.")


def stop(user=""):
    import setup
    name = task_name()
    guard_down()
    if CFG["instance"].get("dry_run") or not task_installed():
        raise BotError("No start-up task for this instance, so there is nothing for Strata to stop.")
    if setup.WIN:
        p = subprocess.run(["schtasks", "/End", "/TN", name], capture_output=True, text=True, creationflags=NOWIN, timeout=30)
    else:
        p = subprocess.run(["systemctl", "stop", name], capture_output=True, text=True, timeout=60)
    if p.returncode != 0:
        raise BotError("Stop failed: %s" % ((p.stderr or p.stdout or "").strip()[-300:]))
    core.audit("", user, "anubis-stop", name)
    return {"stopped": True}


def remove_task(user=""):
    """Stop Anubis and take it out of Task Scheduler / systemd. Program, key, policy and settings stay."""
    import setup
    name = task_name()
    guard_down()
    if CFG["instance"].get("dry_run") or not task_installed():
        raise BotError("No start-up task for this instance.")
    if setup.WIN:
        setup.run(["schtasks", "/End", "/TN", name])
        code, out = setup.run(["schtasks", "/Delete", "/TN", name, "/F"])
    else:
        setup.run(["systemctl", "disable", "--now", name])
        code, out = setup.run(["rm", "/etc/systemd/system/%s.service" % name])
        setup.run(["systemctl", "daemon-reload"])
    if code != 0:
        raise BotError("Couldn't remove the task: %s" % out[-300:])
    core.audit("", user, "anubis-task-remove", name)
    return {"removed": True}


def setup_all(user=""):
    """Everything between 'nothing installed' and 'protection on', stopping at the first thing that fails: program,
    key and policy, start-up task (which also starts it), a wait until it answers, then the switch. Safe to run again.
    Returns what it did, one line per step. A demo (dry-run) instance still downloads into its own folder but registers
    and starts nothing."""
    log = []
    if not BUSY.acquire(blocking=False):
        raise BotError("Another Anubis install or set-up is running")
    try:
        s = settings()
        if s["exe"] and os.path.isfile(s["exe"]):
            log.append("Program: using %s" % s["exe"])
        else:
            exe = install_locked(user)
            log.append("Program: downloaded Anubis %s, checksum matched, into %s" % (TESTED, os.path.dirname(exe)))
    finally:
        BUSY.release()
    ensure_key()
    write_policy(force=True)
    log.append("Signing key and policy file are in place")
    if CFG["instance"].get("dry_run"):
        log.append("Demo instance: the start-up task was not registered and Anubis was not started")
        return log
    install_task(user)
    log.append("Start-up task registered and started")
    for _ in range(40):  # a cold start takes a few seconds (it reads the policy lists first)
        if probe()[1]:
            break
        time.sleep(0.5)
    else:
        raise BotError("The task is registered, but Anubis doesn't answer on %s yet. Check again in a moment, or look at "
                       "the program's output in Task Scheduler / journalctl." % settings()["bind"])
    log.append("Anubis answers on %s" % settings()["bind"])
    return log
