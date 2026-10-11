"""First-run owner setup (/setup) on a fresh instance with no owner: loopback only, validation, one-time.
Then a second fresh instance whose owner picks an authenticator app instead of e-mail, and signs in with it.
Starts its own server on 127.0.0.1:8190 in a temp folder; run_all.py runs it before the other suites."""
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
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
    return r.status, r.headers.get("Location"), r.read().decode("utf-8", "replace"), r.headers.get_all("Set-Cookie") or []


def check(name, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else "  -> %s" % (detail,)))


def fresh():
    """A new instance with no owner and no mail sender, and its server."""
    root = tempfile.mkdtemp(prefix="strata-scratchpad-setup-")
    home, _ = ra.make_home(root, owner=False)
    proc = subprocess.Popen([sys.executable, os.path.join(ra.CODE, "strata.py"), "--home", home], cwd=ra.CODE,
                            env=dict(os.environ, STRATA_HOME=home), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not ra.wait_up(proc):
        proc.terminate()
        sys.exit("FAIL server did not start")
    return root, home, proc


def stop(root, proc):
    proc.terminate()
    proc.wait(10)
    shutil.rmtree(root, ignore_errors=True)


def cookie(set_cookies, name):
    for c in set_cookies:
        k, _, v = c.split(";", 1)[0].partition("=")
        if k == name:
            return v
    return None


# ---- e-mailed codes
root, home, proc = fresh()
import auth  # noqa: E402  (after make_home: core reads the instance folder when it is imported)
try:
    good = {"user": "owner", "password": "a long enough passphrase", "password2": "a long enough passphrase",
            "factor": "email", "email": "owner@example.test", "resend_key": "re_test_key", "mail_from": "strata@example.test"}

    st, loc, _, _ = call("/login")
    check("/login sends a local browser to /setup", st == 303 and loc == "/setup", (st, loc))
    st, loc, _, _ = call("/login", headers={"X-Forwarded-For": "203.0.113.9"})
    check("/login from outside explains instead", st == 303 and loc == "/login?e=setup_local", (st, loc))
    st, loc, _, _ = call("/login?e=setup_local")
    check("the explanation page renders", st == 200, st)
    st, _, body, _ = call("/setup")
    check("/setup offers the app and e-mail", st == 200 and 'value="app" checked' in body and 'name="resend_key"' in body
          and 'name="totp_code"' in body, st)
    key1 = re.search(r"<code>([A-Z2-7 ]+)</code>", body)
    st, _, body2, _ = call("/setup")
    check("the key stays the same on reload", key1 and key1.group(1) in body2, key1)
    st, loc, _, _ = call("/setup", headers={"X-Forwarded-For": "203.0.113.9"})
    check("/setup refuses requests forwarded from outside", st == 303 and loc == "/login?e=setup_local", (st, loc))
    st, loc, _, _ = call("/api/me")
    check("API answers 503 until there is an owner", st == 503, st)

    for field, value, err in (("user", "x", "user"), ("password", "short", "password"), ("password2", "different!!!!", "repeat"),
                              ("factor", "", "factor"), ("email", "nope", "email"), ("resend_key", "", "mail")):
        st, loc, _, _ = call("/setup", dict(good, **{field: value}))
        check("rejects bad %s" % field, st == 303 and loc == "/setup?e=" + err, (st, loc))
    st, loc, _, _ = call("/setup", dict(good, factor="app", totp_code="000000"))
    check("rejects a wrong app code", st == 303 and loc == "/setup?e=totp", (st, loc))
    st, loc, _, _ = call("/setup", good, headers={"X-Forwarded-For": "203.0.113.9"})
    check("POST from outside creates nothing", loc == "/login?e=setup_local", (st, loc))
    st, loc, _, _ = call("/setup", good, headers={"Origin": "https://evil.example"})
    check("cross-site POST refused", st == 403, st)

    st, loc, _, _ = call("/setup", good)
    check("valid form creates the owner", st == 303 and loc == "/login?e=owner", (st, loc))
    cfg = json.load(open(os.path.join(home, "strata.json")))
    check("strata.json has the owner and mail sender", cfg["auth"]["user"] == "owner" and cfg["alerts"]["from"] ==
          "strata@example.test" and cfg["alerts"]["to"][0] == "owner@example.test", cfg.get("auth", {}).get("user"))
    check("no authenticator app was stored", not cfg["auth"].get("totp_secret"), cfg["auth"].keys())
    db = sqlite3.connect(os.path.join(home, "data", "strata.db"))
    row = db.execute("SELECT role, email FROM account WHERE user='owner'").fetchone()
    db.close()
    check("owner is the root account", row == ("root", "owner@example.test"), row)
    st, loc, _, _ = call("/setup")
    check("/setup is gone afterwards", st == 303 and loc == "/login", (st, loc))
    st, loc, _, _ = call("/setup", dict(good, user="second"))
    cfg = json.load(open(os.path.join(home, "strata.json")))
    check("a second POST changes nothing", loc == "/login" and cfg["auth"]["user"] == "owner", (loc, cfg["auth"]["user"]))
    # signing in would e-mail a code through Resend: check the stored hash instead
    check("stored password hash verifies", auth.verify_password(good["password"], cfg["auth"]["password_hash"]))
finally:
    stop(root, proc)

# ---- an authenticator app, no e-mail at all
root, home, proc = fresh()
try:
    st, _, body, _ = call("/setup")
    m = re.search(r"<code>([A-Z2-7 ]+)</code>", body)
    key = m.group(1).replace(" ", "") if m else ""
    check("the app key is shown with a QR code", len(key) == 32 and '<div class="qr"><svg' in body, (key, body[:200]))
    now = int(time.time() // 30)
    form = {"user": "solo", "password": "a long enough passphrase", "password2": "a long enough passphrase",
            "factor": "app", "totp_code": auth._totp(key, now)}
    st, loc, body, _ = call("/setup", form)
    codes = re.findall(r"<li>([0-9a-f]{6}-[0-9a-f]{6})</li>", body)
    check("creates the owner and shows ten recovery codes", st == 200 and len(codes) == 10, (st, loc, body[:300]))
    cfg = json.load(open(os.path.join(home, "strata.json")))
    check("strata.json has the app key and no mail", cfg["auth"].get("totp_secret") == key and len(cfg["auth"]["recovery"]) == 10
          and not cfg.get("alerts", {}).get("resend_api_key"), cfg.get("alerts"))

    st, loc, _, cookies = call("/login", {"user": "solo", "password": form["password"]})
    pending = cookie(cookies, "dev_strata_2fa")
    check("the password leads straight to the app code", st == 303 and loc == "/login/2fa" and pending, (st, loc))
    jar = {"Cookie": "dev_strata_2fa=%s" % pending}
    st, loc, _, _ = call("/login/otp", headers=jar)
    check("the e-mail code page refuses an app sign-in", st == 303 and loc == "/login?e=expired", (st, loc))
    st, loc, _, _ = call("/login/otp", {"code": "123456"}, headers=jar)
    check("and so does posting an e-mail code", st == 303 and loc == "/login?e=expired", (st, loc))
    st, loc, _, _ = call("/login/2fa", {"code": auth._totp(key, now)}, headers=jar)
    check("the code used at setup can't be replayed", st == 303 and loc == "/login/2fa?e=1", (st, loc))
    st, loc, _, cookies = call("/login/2fa", {"code": auth._totp(key, now + 1)}, headers=jar)
    session = cookie(cookies, "dev_strata_session")
    check("the next app code signs in", st == 303 and loc in ("/", "/privacy") and session, (st, loc))
    st, loc, body, _ = call("/api/me", headers={"Cookie": "dev_strata_session=%s" % session, "X-Strata": "1"})
    me = json.loads(body) if st == 200 else {}
    check("signed in as the owner with the app on", me.get("role") == "root" and me.get("totp") is True, (st, body[:200]))
    def api(path, body):
        h = {"Cookie": "dev_strata_session=%s" % session, "X-Strata": "1", "Content-Type": "application/json", "Origin": BASE}
        try:
            return urllib.request.urlopen(urllib.request.Request(BASE + path, data=json.dumps(body).encode(), headers=h),
                                          timeout=20).status
        except urllib.error.HTTPError as e:
            return e.code

    st, loc, _, _ = call("/privacy/accept", {"accept": "yes"}, headers={"Cookie": "dev_strata_session=%s" % session})
    check("the privacy note can be accepted", st == 303 and loc == "/", (st, loc))
    st = api("/api/2fa/disable", {"code": codes[0]})
    cfg = json.load(open(os.path.join(home, "strata.json")))
    check("the app can't be turned off without e-mail", st == 400 and cfg["auth"].get("totp_secret") == key, st)
    check("the refused request didn't use up a recovery code", len(cfg["auth"]["recovery"]) == 10, len(cfg["auth"]["recovery"]))

    st, loc, _, cookies = call("/login", {"user": "solo", "password": form["password"]})
    jar = {"Cookie": "dev_strata_2fa=%s" % cookie(cookies, "dev_strata_2fa")}
    st, loc, _, cookies = call("/login/2fa", {"code": codes[1]}, headers=jar)
    check("a recovery code works instead of the app", st == 303 and cookie(cookies, "dev_strata_session"), (st, loc))
    cfg = json.load(open(os.path.join(home, "strata.json")))
    check("and works only once", len(cfg["auth"]["recovery"]) == 9, len(cfg["auth"]["recovery"]))
finally:
    stop(root, proc)
sys.exit(0 if ok else 1)
