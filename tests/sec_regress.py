"""Security regression suite for the Strata DEV instance (127.0.0.1:8190, scratchpad home only).

Creates an admin and an employee through root's API, activates them through /enroll, then checks that the
escalation paths found in the 2026-10-10 audit are closed. Exit code 1 if any check fails."""
import hashlib
import io
import json
import os
import secrets
import socket
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

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
st, r, _ = call("POST", "/api/alerts/config", a, {"smtp": {"host": "smtp.attacker.example", "user": "x", "password": "y"}})
check("admin cannot point OTP mail at their own SMTP server", st == 403, (st, r))
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

# branding: administrators only, PNG logos only, custom.css and the name reach the sign-in page
st, r, _ = call("POST", "/api/branding", e, {"css": "body { display: none }"})
check("employee cannot change the branding", st == 403, (st, r))
st, r, _ = call("POST", "/api/branding", root, {"logo": "PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+"})  # an SVG
check("branding refuses a logo that isn't a PNG", st == 415, (st, r))
st, r, _ = call("POST", "/api/branding", root, {"brand": "Acme <b>", "login_text": "Staff only", "css": ".lock { outline: 1px }"})
st2, css, _ = call("GET", "/custom.css")
st3, page, _ = call("GET", "/login")
check("branding reaches custom.css and the sign-in page", st == 200 and ".lock" in css and "Acme &lt;b&gt;" in page
      and "Staff only" in page, (st, r, css[:80]))
call("POST", "/api/branding", root, {"brand": "", "login_text": "", "css": ""})
st, css, _ = call("GET", "/custom.css")
check("empty custom CSS falls back to the built-in file", st == 200 and ".lock" not in css, css[:80])

# a 502 page is written into the Caddy config only when one is set
st, r, _ = call("POST", "/api/serving/site", root, {"error_page_502": "/404/502.html"})
cdn = open(os.path.join(os.path.dirname(os.path.dirname(DB)), "generated", "cdn.caddy"), encoding="utf-8").read()
check("502 page adds handle_errors 502 503 504", st == 200 and "handle_errors 502 503 504" in cdn and "/404/502.html" in cdn, (st, r))
call("POST", "/api/serving/site", root, {"error_page_502": ""})

# link previews sit after the access rules and the scan gate and before the drives, so a hidden, protected or held
# file never gets one; the page goes to crawlers only and must not be stored at the edge
pv, drives = cdn.find("# link previews"), cdn.find("# drives")
check("link previews come after the access rules and before the drives", 0 < pv < drives and cdn.find("# access rules") < pv
      and "header_up X-Strata-Embed 1" in cdn[pv:drives] and "header_regexp" in cdn[pv:drives], (pv, drives))

# config preview: a diff, and nothing saved or applied
st, r, _ = call("POST", "/api/serving/site", root, {"error_page_502": "/404/502.html", "preview": True})
site = json.loads(sqlite3.connect(DB).execute("SELECT v FROM meta WHERE k='site'").fetchone()[0])
cdn2 = open(os.path.join(os.path.dirname(os.path.dirname(DB)), "generated", "cdn.caddy"), encoding="utf-8").read()
check("config preview shows the diff and saves nothing", st == 200 and "+" in r.get("diff", "") and "/404/502.html" in r["diff"]
      and not site.get("error_page_502") and "/404/502.html" not in cdn2, (st, r))
st, r, _ = call("POST", "/api/serving/site", e, {"error_page_502": "/x.html", "preview": True})
check("config preview needs the same permission as saving", st == 403, (st, r))

# alert webhooks: owner only, http(s) only, the URL (it carries a secret) is never sent back
st, r, _ = call("POST", "/api/alerts/config", a, {"webhooks": "https://example.test/hook"})
check("admin cannot set alert webhooks", st == 403, (st, r))
st, r, _ = call("POST", "/api/alerts/config", root, {"webhooks": "file:///etc/passwd"})
check("webhooks must be http or https", st == 400, (st, r))
st, r, _ = call("POST", "/api/alerts/config", root, {"webhooks": "https://ntfy.example.test/SECRET-topic"})
st2, r2, _ = call("GET", "/api/alerts", a)
check("webhook URLs stay on the server", st == 200 and r["config"]["webhooks"] == [{"host": "ntfy.example.test", "kind": "ntfy"}]
      and "SECRET" not in json.dumps(r) + json.dumps(r2), (st, r))
call("POST", "/api/alerts/config", root, {"webhooks": ""})

# backup and restore: owner only, no secrets in the zip, a round trip works, junk is refused
st, r, _ = call("GET", "/api/backup", a)
check("admin cannot download a backup", st == 403, (st, r))
st, r, _ = call("POST", "/api/backup/restore", a, {})
check("admin cannot restore a backup", st == 403, (st, r))
with urllib.request.urlopen(urllib.request.Request(BASE + "/api/backup", headers={
        "X-Strata": "1", "Cookie": "%s=%s" % (COOKIE, root)}), timeout=60) as resp:
    blob = resp.read()
z = zipfile.ZipFile(io.BytesIO(blob))
conf = z.read("strata.json").decode()
check("backup holds the database and settings without secrets", {"strata.db", "strata.json"} <= set(z.namelist())
      and "cookie_secret" not in conf and "sign_secret" not in conf and "password_hash" not in conf, z.namelist())
req = urllib.request.Request(BASE + "/api/backup/restore", data=blob, method="POST", headers={
    "X-Strata": "1", "Cookie": "%s=%s" % (COOKIE, root), "Content-Type": "application/zip"})
with urllib.request.urlopen(req, timeout=60) as resp:
    st, r = resp.status, json.loads(resp.read())
st2, me2, _ = call("GET", "/api/me", root)
check("owner can restore a backup and stays signed in", st == 200 and r.get("restored") and st2 == 200, (st, r, st2))
try:
    urllib.request.urlopen(urllib.request.Request(BASE + "/api/backup/restore", data=b"not a zip", method="POST", headers={
        "X-Strata": "1", "Cookie": "%s=%s" % (COOKIE, root), "Content-Type": "application/zip"}), timeout=20)
    st = 200
except urllib.error.HTTPError as ex:
    st = ex.code
check("restore refuses a file that isn't a backup", st == 400, st)
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
