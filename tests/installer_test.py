"""setup.py end to end, non-interactive: answers piped in, a temp instance folder, the stub Caddy, no service, no
tunnel (so the machine's real cloudflared config is never read or written). Then checks what it wrote, runs it a
second time to check it keeps the existing values, and starts Strata on the result."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request

TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TESTS)
import run_all as ra  # noqa: E402

sys.path.insert(0, ra.CODE)
import setup  # noqa: E402

ok = True


def check(name, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else "  -> %s" % (detail,)))


# ---- ingress editing on sample configs
base = "tunnel: abc\ncredentials-file: x.json\n\ningress:\n  - hostname: old.example.org\n    service: http://localhost:1\n  - service: http_status:404\n"
new = setup.add_ingress(base, "cdn.example.org", 8080)
check("ingress rule goes before the catch-all", new.index("cdn.example.org") < new.index("http_status:404")
      and "  - hostname: cdn.example.org\n    service: http://localhost:8080\n  - service: http_status:404" in new, new)
check("an existing rule is left alone", setup.add_ingress(new, "cdn.example.org", 9999) == new)
check("no catch-all: refuses to guess", setup.add_ingress("tunnel: abc\n", "cdn.example.org", 8080) is None)

# ---- full run
root = tempfile.mkdtemp(prefix="strata-installer-")
home = os.path.join(root, "home")
caddy = ra.stub_caddy(os.path.join(root, "bin"))
caddyfile = os.path.join(root, "caddy", "Caddyfile")
os.makedirs(os.path.dirname(caddyfile))
with open(caddyfile, "w") as f:
    f.write("{\n\tadmin localhost:2019\n}\n\nsomething.example.org {\n\trespond hi\n}\n")
answers = [
    "example.org", "", "",                      # domain, CDN host (default cdn.example.org), files folder (default)
    "n", caddy, caddyfile, "y",                 # no winget, caddy path, Caddyfile, LAN dashboard: yes
    "n",                                        # no tunnel
    "", "", "", "",                             # no Cloudflare token, default sender, no SMTP server, no Resend key
    "owner", "a long enough passphrase", "a long enough passphrase", "owner@example.org",
]
env = dict(os.environ, PATH=os.environ.get("PATH", ""), PYTHONIOENCODING="utf-8")
env.pop("STRATA_HOME", None)


def install(lines):
    return subprocess.run([sys.executable, os.path.join(ra.CODE, "setup.py"), "--home", home, "--no-service"],
                          input="\n".join(lines) + "\n", capture_output=True, text=True, env=env, timeout=120)


proc = None
try:
    r = install(answers)
    out = r.stdout + r.stderr
    check("setup.py exits cleanly", r.returncode == 0, out[-1500:])
    cfg = json.load(open(os.path.join(home, "strata.json")))
    check("site written", cfg["instance"]["name"] == "example.org" and cfg["public"]["hosts"] == ["cdn.example.org", "example.org"]
          and cfg["public_base_url"] == "https://cdn.example.org", cfg.get("instance"))
    check("caddy paths written", cfg["caddy_exe"] == caddy and cfg["caddyfile"] == caddyfile, (cfg.get("caddy_exe"), cfg.get("caddyfile")))
    check("owner written", cfg["auth"]["user"] == "owner" and cfg["auth"]["password_hash"].startswith("pbkdf2_sha256$")
          and cfg["alerts"]["to"] == ["owner@example.org"], cfg.get("auth", {}).get("user"))
    check("no secrets asked for were stored", "cloudflare" not in cfg and "resend_api_key" not in cfg["alerts"]
          and "smtp" not in cfg["alerts"], cfg.get("alerts"))
    check("files folder created", os.path.isdir(cfg["storage_paths"][0]), cfg.get("storage_paths"))
    text = open(caddyfile).read()
    imp = "import " + os.path.join(home, "generated", "cdn.caddy").replace("\\", "/")
    check("Caddyfile keeps the old site and imports Strata's", "something.example.org {" in text and imp in text, text)
    check("LAN dashboard block added", ":%s {" % (int(cfg["listen"].rsplit(":", 1)[1]) + 1) in text, text)
    backups = os.listdir(os.path.join(root, "caddy", "backups"))
    check("Caddyfile backed up first", len(backups) == 1 and "something.example.org" in
          open(os.path.join(root, "caddy", "backups", backups[0])).read(), backups)
    check("placeholder for the generated config", os.path.exists(os.path.join(home, "generated", "cdn.caddy")))

    # second run: Enter everywhere keeps what is there (caddy found from strata.json this time, so no winget question)
    r2 = install(["", "", "", "", "n", "", "", "", "", "y"])
    cfg2 = json.load(open(os.path.join(home, "strata.json")))
    check("re-run exits cleanly", r2.returncode == 0, (r2.stdout + r2.stderr)[-1500:])
    check("re-run keeps owner, ports and site", cfg2["auth"] == cfg["auth"] and cfg2["listen"] == cfg["listen"]
          and cfg2["instance"] == cfg["instance"], (cfg2.get("listen"), cfg2.get("instance")))
    check("re-run doesn't add the import twice", open(caddyfile).read().count(imp) == 1)
    check("strata.json backed up on re-run", any(n.startswith("strata.json.") for n in os.listdir(os.path.join(home, "backups"))))

    # the result starts
    proc = subprocess.Popen([sys.executable, os.path.join(ra.CODE, "strata.py"), "--home", home], cwd=ra.CODE,
                            env=dict(env, STRATA_HOME=home), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = "http://%s/login" % cfg["listen"]
    up = False
    for _ in range(120):
        try:
            up = urllib.request.urlopen(url, timeout=2).status == 200
            break
        except OSError:
            if proc.poll() is not None:
                break
            import time
            time.sleep(0.25)
    check("Strata starts on the installed config and shows the sign-in page", up, url)
finally:
    if proc:
        proc.terminate()
        proc.wait(10)
    shutil.rmtree(root, ignore_errors=True)
sys.exit(0 if ok else 1)
