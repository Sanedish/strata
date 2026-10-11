"""First-run owner setup (/setup) on a fresh instance with no owner: loopback only, validation, one-time.
Starts its own server on 127.0.0.1:8190 in a temp folder; run_all.py runs it before the other suites."""
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_all as ra  # noqa: E402

BASE = ra.BASE
ok = True


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def call(path, form=None, headers=None):
    h = {"Origin": BASE}
    h.update(headers or {})
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    if data:
        h["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(BASE + path, data=data, headers=h)
    try:
        r = urllib.request.build_opener(NoRedirect).open(req, timeout=20)
    except urllib.error.HTTPError as e:
        r = e
    return r.status, r.headers.get("Location"), r.read().decode("utf-8", "replace")


def check(name, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else "  -> %s" % (detail,)))


root = tempfile.mkdtemp(prefix="strata-scratchpad-setup-")
home, _ = ra.make_home(root, owner=False)
proc = subprocess.Popen([sys.executable, os.path.join(ra.CODE, "strata.py"), "--home", home], cwd=ra.CODE,
                        env=dict(os.environ, STRATA_HOME=home), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    if not ra.wait_up(proc):
        sys.exit("FAIL server did not start")
    good = {"user": "owner", "password": "a long enough passphrase", "password2": "a long enough passphrase",
            "email": "owner@example.test", "resend_key": "re_test_key", "mail_from": "strata@example.test"}

    st, loc, _ = call("/login")
    check("/login sends a local browser to /setup", st == 303 and loc == "/setup", (st, loc))
    st, loc, _ = call("/login", headers={"X-Forwarded-For": "203.0.113.9"})
    check("/login from outside explains instead", st == 303 and loc == "/login?e=setup_local", (st, loc))
    st, loc, _ = call("/login?e=setup_local")
    check("the explanation page renders", st == 200, st)
    st, _, body = call("/setup")
    check("/setup shows the form with mail fields", st == 200 and 'name="resend_key"' in body, st)
    st, loc, _ = call("/setup", headers={"X-Forwarded-For": "203.0.113.9"})
    check("/setup refuses requests forwarded from outside", st == 303 and loc == "/login?e=setup_local", (st, loc))
    st, loc, _ = call("/api/me")
    check("API answers 503 until there is an owner", st == 503, st)

    for field, value, err in (("user", "x", "user"), ("password", "short", "password"), ("password2", "different!!!!", "repeat"),
                              ("email", "nope", "email"), ("resend_key", "", "mail")):
        st, loc, _ = call("/setup", dict(good, **{field: value}))
        check("rejects bad %s" % field, st == 303 and loc == "/setup?e=" + err, (st, loc))
    st, loc, _ = call("/setup", good, headers={"X-Forwarded-For": "203.0.113.9"})
    check("POST from outside creates nothing", loc == "/login?e=setup_local", (st, loc))
    st, loc, _ = call("/setup", good, headers={"Origin": "https://evil.example"})
    check("cross-site POST refused", st == 403, st)

    st, loc, _ = call("/setup", good)
    check("valid form creates the owner", st == 303 and loc == "/login?e=owner", (st, loc))
    cfg = json.load(open(os.path.join(home, "strata.json")))
    check("strata.json has the owner and mail sender", cfg["auth"]["user"] == "owner" and cfg["alerts"]["from"] ==
          "strata@example.test" and cfg["alerts"]["to"][0] == "owner@example.test", cfg.get("auth", {}).get("user"))
    db = sqlite3.connect(os.path.join(home, "data", "strata.db"))
    row = db.execute("SELECT role, email FROM account WHERE user='owner'").fetchone()
    db.close()
    check("owner is the root account", row == ("root", "owner@example.test"), row)
    st, loc, _ = call("/setup")
    check("/setup is gone afterwards", st == 303 and loc == "/login", (st, loc))
    st, loc, _ = call("/setup", dict(good, user="second"))
    cfg = json.load(open(os.path.join(home, "strata.json")))
    check("a second POST changes nothing", loc == "/login" and cfg["auth"]["user"] == "owner", (loc, cfg["auth"]["user"]))
    import auth  # noqa: E402  (signing in would e-mail a code through Resend: check the stored hash instead)
    check("stored password hash verifies", auth.verify_password(good["password"], cfg["auth"]["password_hash"]))
finally:
    proc.terminate()
    proc.wait(10)
    shutil.rmtree(root, ignore_errors=True)
sys.exit(0 if ok else 1)
