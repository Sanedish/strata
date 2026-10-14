"""Run every Strata test suite against a fresh, throwaway instance. Nothing outside a temp folder is touched.

    python tests/run_all.py            all suites
    python tests/run_all.py --keep     leave the temp instance (and its server) running afterwards for poking around
    python tests/run_all.py --offline  skip the check that needs the internet (ssrf_test fetches https://example.com)

Builds a dev home under a temp folder named *scratchpad* (the HTTP suites refuse any other database), with a stub
`caddy` that accepts every config, `instance.dry_run` on, and the dashboard on 127.0.0.1:8190. Seeds the accounts
the suites expect (dev = owner, mara, lena, one pending invite), then runs the suites in a fixed order. Exit code 1
if any suite fails.
"""
import hashlib
import json
import os
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

TESTS = os.path.dirname(os.path.abspath(__file__))
CODE = os.path.dirname(TESTS)
BASE = "http://127.0.0.1:8190"
PASSWORD = "correct horse battery staple 42"  # test value, also used by login_test.py and the suites
STUB = '''import sys
args = sys.argv[1:]
if args[:1] == ["hash-password"]:
    sys.stdin.read()
    print("$2a$11$" + "x" * 53)
elif args[:1] == ["version"]:
    print("v2.10.2 h1:stub")
else:
    print("Valid configuration")
'''


def stub_caddy(bindir):
    os.makedirs(bindir, exist_ok=True)
    with open(os.path.join(bindir, "caddy_stub.py"), "w") as f:
        f.write(STUB)
    if os.name == "nt":
        exe = os.path.join(bindir, "caddy.cmd")
        with open(exe, "w") as f:
            f.write('@"%s" "%s" %%*\r\n' % (sys.executable, os.path.join(bindir, "caddy_stub.py")))
    else:
        exe = os.path.join(bindir, "caddy")
        with open(exe, "w") as f:
            f.write("#!%s\n%s" % (sys.executable, STUB))
        os.chmod(exe, 0o755)
    return exe


def make_home(root, owner=True):
    home = os.path.join(root, "home")
    files = os.path.join(home, "files")
    os.makedirs(os.path.join(home, "generated"), exist_ok=True)
    os.makedirs(files, exist_ok=True)
    caddyfile = os.path.join(home, "Caddyfile")
    with open(caddyfile, "w") as f:
        f.write("import %s\n" % os.path.join(home, "generated", "cdn.caddy").replace("\\", "/"))
    with open(os.path.join(home, "generated", "cdn.caddy"), "w") as f:
        f.write("# placeholder\n")
    sys.path.insert(0, CODE)
    os.environ["STRATA_HOME"] = home
    import auth  # noqa: E402  (hash format the server checks)
    cfg = {
        "instance": {"id": "dev", "name": "dev.example.com", "prefix": "dev_strata", "dry_run": True,
                     "cdn_listen": ":18180"},
        "listen": "127.0.0.1:8190", "feed_listen": "127.0.0.1:18181", "transform_listen": "127.0.0.1:18183",
        "gate_listen": "127.0.0.1:18185", "media": {"listen": "127.0.0.1:18184"},
        "caddy_exe": stub_caddy(os.path.join(root, "bin")), "caddyfile": caddyfile,
        "caddy_metrics": "http://127.0.0.1:1/metrics", "cloudflared_metrics": "http://127.0.0.1:1/metrics",
        "cloudflared_config": os.path.join(home, "cloudflared.yml"),
        "access_log": os.path.join(home, "data", "access.log"),
        "storage_paths": [files], "public": {"hosts": ["cdn.dev.example.com"]},
        "auth": {"user": "dev", "password_hash": auth.hash_password(PASSWORD)},
        "alerts": {"to": ["dev@example.test"]},
    }
    if not owner:  # a fresh install: no owner, no mail sender yet
        del cfg["auth"], cfg["alerts"]
    with open(os.path.join(home, "strata.json"), "w") as f:
        json.dump(cfg, f, indent=2)
    return home, files


def wait_up(proc, seconds=60):
    for _ in range(seconds * 4):
        if proc.poll() is not None:
            return False
        try:
            urllib.request.urlopen(BASE + "/login", timeout=2)
            return True
        except urllib.error.HTTPError:
            return True
        except OSError:
            time.sleep(0.25)
    return False


def session(db, user):
    tok = secrets.token_urlsafe(32)
    c = sqlite3.connect(db)
    c.execute("INSERT OR REPLACE INTO session VALUES(?,?,?,?,?,?)",
              [hashlib.sha256(tok.encode()).hexdigest(), user, time.time() + 3600, "127.0.0.1", time.time(), 3600])
    c.commit()
    c.close()
    return tok


def post(tok, path, body, form=False):
    h = {"X-Strata": "1", "Origin": BASE, "Cookie": "dev_strata_session=" + tok,
         "Content-Type": "application/x-www-form-urlencoded" if form else "application/json"}
    data = urllib.parse.urlencode(body).encode() if form else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read()
            return json.loads(raw) if raw[:1] == b"{" else {}
    except urllib.error.HTTPError as e:
        return {"error": e.code, "body": e.read()[:200].decode("utf-8", "replace")}


def seed(db, files):
    c = sqlite3.connect(db)
    c.execute("UPDATE account SET privacy_version=? WHERE user='dev'", [privacy_version()])
    c.commit()
    c.close()
    root = session(db, "dev")
    r = post(root, "/api/accounts/invite", {"user": "lena", "email": "lena@example.test", "preset": "read_only"})
    if not r.get("token"):
        raise SystemExit("seeding lena failed: %s" % r)
    post(root, "/enroll", {"token": r["token"], "password": PASSWORD, "privacy": "yes"}, form=True)
    r = post(root, "/api/accounts/invite", {"user": "alexandra.konstantinopoulou-wellington_contractor-2026-team",
                                            "email": "alexandra@example.test", "preset": "read_only"})
    if not r.get("token"):
        raise SystemExit("seeding the pending account failed: %s" % r)


def privacy_version():
    sys.path.insert(0, CODE)
    import accounts  # noqa: E402
    return accounts.PRIVACY_VERSION


def main():
    keep, offline = "--keep" in sys.argv, "--offline" in sys.argv
    root = tempfile.mkdtemp(prefix="strata-scratchpad-")
    home, files = make_home(root)
    db = os.path.join(home, "data", "strata.db")
    log = open(os.path.join(root, "server.log"), "w")
    env = dict(os.environ, STRATA_HOME=home, PYTHONIOENCODING="utf-8")
    # the media unit tests expect default settings and a database as Strata leaves it after its first start
    # (one production drive on its own hostname, the built-in rules): they copy it and add their own test drive
    media_home = os.path.join(root, "media-home")
    os.makedirs(os.path.join(media_home, "files"))
    with open(os.path.join(media_home, "strata.json"), "w") as f:
        json.dump({"storage_paths": [os.path.join(media_home, "files")], "public": {"hosts": ["cdn.example.com"]}}, f)
    media_env = dict(env, STRATA_HOME=media_home)
    subprocess.run([sys.executable, "-c", "import core, rules; core.init_db(); db = core.connect(); rules.seed(db); "
                    "db.commit()"], cwd=CODE, env=media_env, check=True, capture_output=True)
    py = [sys.executable]

    def start():
        try:
            urllib.request.urlopen(BASE + "/login", timeout=2)
            raise SystemExit("something is already listening on 127.0.0.1:8190; stop it first")
        except urllib.error.HTTPError:
            raise SystemExit("something is already listening on 127.0.0.1:8190; stop it first")
        except OSError:
            pass
        p = subprocess.Popen(py + [os.path.join(CODE, "strata.py"), "--home", home], cwd=CODE, env=env,
                             stdout=log, stderr=subprocess.STDOUT)
        if not wait_up(p):
            log.flush()
            print(open(os.path.join(root, "server.log")).read()[-3000:])
            raise SystemExit("the test server did not start (is something else on 127.0.0.1:8190?)")
        return p

    def stop(p):
        p.terminate()
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()

    results = []
    t = time.time()
    p = subprocess.run(py + [os.path.join(TESTS, "setup_test.py")], cwd=CODE, env=env, capture_output=True, text=True)
    results.append(("first-run setup", p.returncode == 0, time.time() - t))
    print("== first-run setup: %s (%.1f s)" % ("ok" if p.returncode == 0 else "FAILED", time.time() - t))
    print("\n".join(l for l in (p.stdout + p.stderr).splitlines() if not l.startswith("PASS")) or "   (no output)")
    proc = start()
    try:
        print("test instance: %s" % home)
        seed(db, files)
        r = subprocess.run(py + [os.path.join(TESTS, "seed_granular.py"), db, files], cwd=CODE, env=env,
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit("seeding mara failed:\n" + r.stdout + r.stderr)
        # restart as after an upgrade from before the team feature: its one-time migration (accounts.office_migrate)
        # then runs over the seeded accounts, which office_regress.py checks
        stop(proc)
        c = sqlite3.connect(db)
        c.execute("DELETE FROM meta WHERE k='office_v1'")
        c.commit()
        c.close()
        proc = start()
        suites = [
            ("smtp sender", py + [os.path.join(TESTS, "smtp_test.py")]),
            ("security", py + [os.path.join(TESTS, "sec_regress.py"), db]),
            ("caddy config", py + [os.path.join(TESTS, "caddy_test.py"), db]),
            ("bot protection", py + [os.path.join(TESTS, "anubis_test.py")]),
            ("permissions", py + [os.path.join(TESTS, "granular_regress.py"), db, files]),
            ("team", py + [os.path.join(TESTS, "office_regress.py"), db]),
            ("sign-in", py + [os.path.join(TESTS, "login_test.py")]),
            ("installer", py + [os.path.join(TESTS, "installer_test.py")]),
            ("auto-ban ranges", py + [os.path.join(TESTS, "autoban_test.py")]),
        ]
        if not offline:
            suites.append(("remote upload SSRF", py + [os.path.join(TESTS, "ssrf_test.py"), home]))
        media = os.path.join(CODE, "media", "tests")
        suites.append(("media unit tests", py + ["-m", "unittest", "discover", "-s", media, "-t", media, "-p", "test_*.py"]))
        for name, cmd in suites:
            t = time.time()
            p = subprocess.run(cmd, cwd=CODE, env=media_env if name.startswith("media") else env, capture_output=True, text=True, encoding="utf-8", errors="replace")
            out = (p.stdout or "") + (p.stderr or "")
            results.append((name, p.returncode == 0, time.time() - t))
            print("\n== %s: %s (%.1f s)" % (name, "ok" if p.returncode == 0 else "FAILED", time.time() - t))
            lines = out.strip().splitlines()
            shown = [l for l in lines if l.startswith("FAIL")] if p.returncode == 0 else lines
            print("\n".join(shown[-60:]) or "   (no output)")
    finally:
        if keep:
            print("\nkept: %s (server pid %d)" % (root, proc.pid))
        else:
            stop(proc)
            log.close()
            shutil.rmtree(root, ignore_errors=True)
    print("\n" + "\n".join("%-20s %s  %.1f s" % (n, "ok" if ok else "FAILED", s) for n, ok, s in results))
    sys.exit(0 if results and all(ok for _, ok, _ in results) else 1)


if __name__ == "__main__":
    main()
