"""Security regression suite for the Strata DEV instance (127.0.0.1:8190, scratchpad home only).

Creates an admin and an employee through root's API, activates them through /enroll, then checks that the
escalation paths found in the 2026-10-10 audit are closed. Exit code 1 if any check fails."""
import hashlib
import json
import secrets
import socket
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8190"
DB = sys.argv[1]
COOKIE = "dev_strata_session"
assert "scratchpad" in DB.replace("\\", "/"), "dev databases only"
results = []


def session(user):
    tok = secrets.token_urlsafe(32)
    c = sqlite3.connect(DB)
    c.execute("INSERT OR REPLACE INTO session VALUES(?,?,?,?,?,?)",
              [hashlib.sha256(tok.encode()).hexdigest(), user, time.time() + 3600, "127.0.0.1", time.time(), 3600])
    c.commit()
    return tok


def call(method, path, tok=None, body=None, headers=None, form=False):
    h = {"X-Strata": "1", "Host": "127.0.0.1:8190"}
    if tok:
        h["Cookie"] = "%s=%s" % (COOKIE, tok)
    data = None
    if body is not None:
        if form:
            data = urllib.parse.urlencode(body).encode()
            h["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
    h.update(headers or {})
    req = urllib.request.Request(BASE + path, data=data, headers=h, method=method)

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    try:
        with urllib.request.build_opener(NoRedirect).open(req, timeout=20) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw[:1] in (b"{", b"[") else raw.decode("utf-8", "replace")), r.headers
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw), e.headers
        except ValueError:
            return e.code, raw.decode("utf-8", "replace"), e.headers


def raw(method, path, tok, body=b"", hold=0):
    """Every byte the server sends back (urllib hides a second response written after the first). With hold, the
    last `hold` bytes of the body follow a second later, and whatever the server sent before them is marked <early>."""
    s = socket.create_connection(("127.0.0.1", 8190), timeout=20)
    s.sendall(("%s %s HTTP/1.1\r\nHost: 127.0.0.1:8190\r\nX-Strata: 1\r\nCookie: %s=%s\r\nContent-Type: application/json\r\n"
               "Content-Length: %d\r\nConnection: close\r\n\r\n" % (method, path, COOKIE, tok, len(body))).encode()
              + body[:len(body) - hold])
    out = b""
    try:
        if hold:
            s.settimeout(1)
            try:
                out = b"<early>" + s.recv(65536)
            except TimeoutError:
                pass
            s.settimeout(20)
            s.sendall(body[len(body) - hold:])
        while True:
            buf = s.recv(65536)
            if not buf:
                break
            out += buf
    except (ConnectionResetError, BrokenPipeError):
        out += b"<connection reset>"
    s.close()
    return out


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else "  -> " + str(detail)[:300]))


def enroll(token):
    return call("POST", "/enroll", body={"token": token, "password": "correct horse battery staple 42", "privacy": "yes"},
                form=True, headers={"Origin": BASE})


root = session("dev")
st, me, _ = call("GET", "/api/me", root)
check("root /api/me has root-only caps", st == 200 and "accounts.manage" in me["capabilities"] and "code.write" in me["capabilities"], me)

suffix = secrets.token_hex(3)
adm, emp = "adm" + suffix, "emp" + suffix
st, r, _ = call("POST", "/api/accounts/invite", root, {"user": adm, "email": adm + "@example.test", "preset": "admin"})
check("root can invite an admin", st == 200 and r.get("token"), r)
adm_token = r.get("token")
check("activation link is not the public CDN", st == 200 and r["link"].startswith("http://127.0.0.1:8190/enroll"), r.get("link"))
st, r, _ = call("POST", "/api/accounts/invite", root, {"user": emp, "email": emp + "@example.test", "preset": "uploader"})
emp_token = r.get("token")
check("root can invite an employee", st == 200 and emp_token, r)

st, r, _ = call("POST", "/api/accounts/status", root, {"user": emp, "enabled": True})
check("pending (password-less) account cannot be enabled", st == 400, (st, r))

st, r, _ = call("POST", "/enroll", body={"token": adm_token, "password": "x" * 20, "privacy": "yes"}, form=True,
                headers={"Origin": "https://evil.example"})
check("cross-site /enroll post refused", st == 403, (st, r))
st, r, _ = call("POST", "/login", body={"user": "dev", "password": "nope"}, form=True, headers={"Origin": "https://evil.example"})
check("cross-site /login post refused", st == 403, (st, r))

st, _, h = enroll(adm_token)
check("admin activation works", st == 303 and "enrolled" in (h.get("Location") or ""), (st, h.get("Location")))
st, _, h = enroll(emp_token)
check("employee activation works", st == 303 and "enrolled" in (h.get("Location") or ""), (st, h.get("Location")))
st, _, h = enroll(emp_token)
check("activation token is single-use", st == 200 or "enrolled" not in (h.get("Location") or ""), st)

a, e = session(adm), session(emp)
st, me, _ = call("GET", "/api/me", a)
check("admin capabilities exclude root-only ones", st == 200 and "accounts.manage" not in me["capabilities"]
      and "code.write" not in me["capabilities"] and "system.retention" in me["capabilities"], me)

# --- the takeover paths ChatGPT's implementation allowed
st, r, _ = call("POST", "/api/accounts/password-reset", a, {"user": "dev"})
check("admin cannot issue a root password-reset link", st == 403, (st, r))
st, r, _ = call("POST", "/api/accounts/password-reset", root, {"user": "dev"})
check("nobody can issue a root reset link over the API", st == 400, (st, r))
st, r, _ = call("GET", "/api/accounts", a)
check("admin cannot list/manage accounts", st == 403, (st, r))
st, r, _ = call("POST", "/api/accounts/invite", a, {"user": "evil" + suffix, "preset": "admin"})
check("admin cannot create admins", st == 403, (st, r))
st, r, _ = call("POST", "/api/accounts/zone", a, {"user": emp, "mount": 1, "path": "/", "access": "write"})
check("admin cannot assign storage zones", st == 403, (st, r))
st, r, _ = call("POST", "/api/accounts/status", a, {"user": emp, "enabled": False})
check("admin cannot disable accounts", st == 403, (st, r))
st, r, _ = call("POST", "/api/ide/save", a, {"path": "x.py", "text": "print(1)", "expect_sha": ""})
check("admin cannot write code through the web IDE", st == 403, (st, r))
st, r, _ = call("POST", "/api/alerts/config", a, {"resend_api_key": "re_attackerattacker1"})
check("admin cannot swap the OTP e-mail sender key", st == 403, (st, r))
st, r, _ = call("POST", "/api/2fa/begin", a, {})
check("admin cannot touch root 2FA", st == 403, (st, r))
st, r, _ = call("POST", "/api/settings/signups", a, {"allowed": True})
check("admin cannot open registration", st == 403, (st, r))
st, r, _ = call("GET", "/api/system", a)
check("admin keeps normal admin access (system)", st == 200, (st, r))

st, r, _ = call("GET", "/api/accounts", e)
check("employee cannot reach account management", st == 403, (st, r))
st, r, _ = call("POST", "/api/accounts/permissions", e, {"user": emp, "role": "admin", "preset": "admin"})
check("employee cannot raise own permissions", st == 403, (st, r))
st, r, _ = call("POST", "/api/accounts/zone", e, {"user": emp, "mount": 1, "path": "/", "access": "write"})
check("employee cannot grant itself storage", st == 403, (st, r))
st, r, _ = call("GET", "/api/files?mount=1&path=/", e)
check("employee cannot browse outside its zone", st == 403, (st, r))
st, r, _ = call("GET", "/api/files?mount=1&path=/users/" + emp, e)
check("employee can browse its own zone", st == 200, (st, r))
st, r, _ = call("GET", "/api/system", e)
check("employee without system.read is refused", st == 403, (st, r))
st, r, _ = call("POST", "/api/compress/run", e, {})
check("unmapped admin routes refuse employees", st == 403, (st, r))
st, r, _ = call("POST", "/api/upload/url", e, {"mount": 1, "dest": "/users/" + emp, "url": "http://127.0.0.1:8190/login"})
check("remote upload refuses loopback (SSRF)", st == 400 and "non-public" in str(r), (st, r))
st, r, _ = call("POST", "/api/upload/url", e, {"mount": 1, "dest": "/users/" + emp, "url": "http://192.168.1.50/"})
check("remote upload refuses LAN (SSRF)", st == 400 and "non-public" in str(r), (st, r))

# an account that hasn't accepted the current privacy note gets one answer: 428 from the API, a redirect for pages
c = sqlite3.connect(DB)
accepted = c.execute("SELECT privacy_version FROM account WHERE user=?", [emp]).fetchone()[0]
c.execute("UPDATE account SET privacy_version='' WHERE user=?", [emp])
c.commit()
st, r, _ = call("GET", "/api/files?mount=1&path=/users/" + emp, e)
check("API before the privacy note answers 428", st == 428 and r.get("privacy_required"), (st, r))
st, _, h = call("GET", "/", e)
check("page before the privacy note redirects to it", st == 303 and h.get("Location") == "/privacy", (st, h.get("Location")))
out = raw("GET", "/api/prefs", e)
check("428 is the only response on the wire", out.startswith(b"HTTP/1.0 428") and out.count(b"HTTP/1.") == 1, out[:300])
out = raw("POST", "/api/upload/url", e, b'{"mount": 1, "pad": "' + b"x" * 60000 + b'"}', hold=1000)
check("a refused POST is answered once its body is read", out.startswith(b"HTTP/1.0 428") and out.count(b"HTTP/1.") == 1, out[:120])
c.execute("UPDATE account SET privacy_version=? WHERE user=?", [accepted, emp])
c.commit()
c.close()
st, r, _ = call("GET", "/api/files?mount=1&path=/users/" + emp, e)
check("accepting again restores access", st == 200, (st, r))

# a reset never re-enables a disabled account
call("POST", "/api/accounts/status", root, {"user": emp, "enabled": False})
st, r, _ = call("POST", "/api/accounts/password-reset", root, {"user": emp})
check("root can issue an employee reset link", st == 200 and r.get("token"), (st, r))
enroll(r.get("token"))
c = sqlite3.connect(DB)
enabled = c.execute("SELECT enabled FROM account WHERE user=?", [emp]).fetchone()[0]
check("password reset keeps a disabled account disabled", enabled == 0, enabled)
st, r, _ = call("GET", "/api/me", e)
check("disabled employee's session is dead", st == 401, (st, r))

# security headers
st, _, h = call("GET", "/login")
check("pages send CSP + COOP + Permissions-Policy", "frame-ancestors 'none'" in (h.get("Content-Security-Policy") or "")
      and h.get("Cross-Origin-Opener-Policy") == "same-origin" and h.get("Permissions-Policy"), dict(h))

# clean up the test accounts
for u in (adm, emp):
    call("POST", "/api/accounts/delete", root, {"user": u, "storage_action": "delete"})

failed = [n for n, ok in results if not ok]
print("\n%d checks, %d failed" % (len(results), len(failed)))
sys.exit(1 if failed else 0)
