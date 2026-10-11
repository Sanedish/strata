"""Strata gate: the login in front of proxied services (proxy drives with access = "login").

rules.render_service() puts this inside the drive's own `handle` block, before its reverse_proxy:
    <prefix>/__strata_gate/*  -> this server (login form, logout)
    forward_auth              -> this server, uri /__strata_gate/check (every other request of the drive)
so nothing reaches the upstream without a valid session for exactly that drive and hostname. Fail-closed: if this
server is down, forward_auth answers 502, and a drive that is not (or no longer) gated here answers 403.

Caddy sets X-Strata-Gate-Mount (the drive id) and X-Strata-Client-Ip ({client_ip}: Cloudflare's address is only
trusted from loopback peers), overwriting anything a client sent; this server only listens on loopback.

  * users per drive (table gate_user): PBKDF2-SHA256 passwords (auth.py), optional TOTP; unknown users still cost a
    full KDF run, and the error never says which part was wrong
  * session = 32 random bytes in a __Host- cookie (Secure, HttpOnly, SameSite=Lax, Path=/, exact host only); only
    sha256(token) is stored (gate_session), bound to drive + host + user, fixed lifetime (no sliding renewal); removing
    a user or changing their password ends their sessions at once (the check joins gate_user)
  * login form: double-submit CSRF token + Origin / Sec-Fetch-Site checks, lockouts per address (8 / 15 min) and per
    user (10 / hour), audit + alerts, `next` must stay inside the drive
  * every answer: no-store (browsers and Cloudflare), no framing, strict CSP; Caddy removes the gate cookies before
    the request is proxied, so the service never sees them
"""
import html
import json
import re
import secrets
import threading
import time
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import auth
import core
from core import CFG, log

PATH = "/__strata_gate"
BASE = auth.COOKIE[:-len("_session")] if auth.COOKIE.endswith("_session") else "strata"   # strata / site2_strata
COOKIE_RX = r"__Host-%s_g(?:ate|csrf)_\d+=[^;]*;?\s*" % BASE   # rules.py strips these before the upstream
HOURS = (1, 168)
# public exceptions of a gated drive (e.g. a radio's /listen/*): Caddy path patterns, nothing that could break out
PUBLIC_RE = re.compile(r"^/[A-Za-z0-9._~*/-]{0,200}$")
# a raw request path with dot-segments, encoded / . \ or // could match a public pattern in Caddy and then be
# normalised by the service into a protected path - such requests are refused when a drive has public exceptions
RAW_BAD = r"(?i)^[^?#]*(?:/\.\.?(?:[/?#]|$)|%2e|%2f|%5c|\\|//)"
HOOKS = {"failed": None, "alert": None}   # strata.py: alerts.login_failed(ip, user), alerts.raise_(...)
IP_LIMIT = auth.Limiter(8, 900)
USER_LIMIT = auth.Limiter(10, 3600)
TOTP_LAST = {}                             # (drive, user) -> last accepted time step: a code works only once
_TOTP_LOCK = threading.Lock()
_DUMMY = []                                # a real hash for unknown users (same KDF cost), made on first use
CSP = ("default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")


def session_cookie(mid):
    return "__Host-%s_gate_%d" % (BASE, int(mid))


def csrf_cookie(mid):
    return "__Host-%s_gcsrf_%d" % (BASE, int(mid))


def conf(m):
    """Access settings of a drive row: {"mode": "login" | "public", "hours": n}. Proxies saved before the gate
    existed have none and stay public; everything saved since has an explicit mode."""
    try:
        g = json.loads(m.get("gate") or "{}") if isinstance(m.get("gate"), (str, type(None))) else dict(m["gate"])
    except ValueError:
        g = {}
    mode = g.get("mode") if g.get("mode") in ("login", "public") else "public"
    try:
        hours = min(HOURS[1], max(HOURS[0], int(g.get("hours") or 12)))
    except (TypeError, ValueError):
        hours = 12
    public = [p for p in (g.get("public") or []) if isinstance(p, str) and PUBLIC_RE.match(p)]
    return {"mode": mode, "hours": hours, "public": public if mode == "login" else []}


def drive(mid):
    """The enabled, gated proxy drive `mid`, read from the DB (never a stale cache), else None."""
    db = core.connect()
    try:
        row = db.execute("SELECT id, name, kind, prefix, hosts, gate, enabled FROM mount WHERE id=?", [mid]).fetchone()
        totp = bool(row) and bool(db.execute("SELECT 1 FROM gate_user WHERE mount=? AND coalesce(totp,'')!='' LIMIT 1",
                                             [mid]).fetchone())
    finally:
        db.close()
    if not row:
        return None
    m = dict(zip(("id", "name", "kind", "prefix", "hosts", "gate", "enabled"), row))
    c = conf(m)
    if m["kind"] != "proxy" or not m["enabled"] or c["mode"] != "login":
        return None
    m.update(hosts=json.loads(m["hosts"] or "[]"), hours=c["hours"], totp=totp,
             pre="" if m["prefix"] == "/" else m["prefix"])
    return m


def session_user(m, host, token):
    if not token or len(token) > 100:
        return None
    db = core.connect()
    try:
        row = db.execute("SELECT s.user FROM gate_session s JOIN gate_user u ON u.mount = s.mount AND u.user = s.user "
                         "WHERE s.hash=? AND s.mount=? AND s.host=? AND s.exp > ?",
                         [auth.token_hash(token), m["id"], host, time.time()]).fetchone()
    finally:
        db.close()
    return row[0] if row else None


def safe_next(n, pre):
    """Where to go after the login: a path inside this drive, never another site or the gate itself."""
    n = str(n or "")
    home = pre + "/"
    if (not n.startswith("/") or n.startswith("//") or "\\" in n or len(n) > 2000
            or any(c in n for c in "\r\n\t\x00")):
        return home
    p = urllib.parse.urlsplit(n).path.lower()
    if pre and not (p == pre.lower() or p.startswith(pre.lower() + "/")):
        return home
    if p.startswith(pre.lower() + PATH.lower()):
        return home
    return n


def set_cookie(name, value, max_age, samesite="Lax"):
    return "%s=%s; Path=/; Secure; HttpOnly; SameSite=%s; Max-Age=%d" % (name, value, samesite, max_age)


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><meta name="referrer" content="no-referrer"><title>%(title)s</title><style>
:root{color-scheme:light dark;--bg:#f4f3f7;--card:#fff;--text:#1d1b22;--dim:#6b6875;--line:#d9d6e0;--acc:#6d4aff;--err:#c62a3d}
@media (prefers-color-scheme:dark){:root{--bg:#141318;--card:#1e1c24;--text:#ece9f2;--dim:#9a96a6;--line:#34313d;--acc:#9b85ff;--err:#ff6b7d}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--text);
font:15px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;padding:16px}
form,.card{width:100%%;max-width:360px;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:26px}
h1{font-size:19px;margin:0 0 4px}p{margin:0 0 18px;color:var(--dim);font-size:13.5px}
label{display:block;font-size:12.5px;font-weight:600;margin:12px 0 5px}
input{width:100%%;padding:10px 12px;border:1px solid var(--line);border-radius:9px;background:transparent;color:inherit;font:inherit}
input:focus{outline:2px solid var(--acc);outline-offset:1px}
button{width:100%%;margin-top:18px;padding:11px;border:0;border-radius:9px;background:var(--acc);color:#fff;font:inherit;font-weight:650;cursor:pointer}
.err{background:color-mix(in srgb,var(--err) 14%%,transparent);color:var(--err);border-radius:9px;padding:9px 12px;font-size:13.5px;margin-bottom:6px}
</style></head><body>%(body)s</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "Strata"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 20

    def log_message(self, *a):
        pass

    # -- plumbing
    def send(self, code, body=b"", headers=(), ctype="text/html; charset=utf-8"):
        self.send_response(code)
        if self.headers.get("Content-Length") not in (None, "0") or self.headers.get("Transfer-Encoding"):
            self.close_connection = True   # a request body we may not have read must never become the next request
            self.send_header("Connection", "close")
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, private")
        self.send_header("Cloudflare-CDN-Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", CSP)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def page(self, code, title, inner, headers=()):
        self.send(code, (PAGE % {"title": html.escape(title), "body": inner}).encode("utf-8"), headers)

    def ctx(self):
        """(drive, host, client ip) for a request Caddy forwarded for a gated drive, else None."""
        if self.client_address[0] not in ("127.0.0.1", "::1"):
            return None
        mid = (self.headers.get("X-Strata-Gate-Mount") or "").strip()
        if not (mid.isascii() and mid.isdigit() and len(mid) < 10):
            return None
        m = drive(int(mid))
        host = (self.headers.get("Host") or "").strip().lower().rsplit(":", 1)[0] if "]" not in (
            self.headers.get("Host") or "") else ""
        if not m or host not in m["hosts"]:
            return None
        return m, host, (self.headers.get("X-Strata-Client-Ip") or "").strip()[:64] or self.client_address[0]

    def cookie(self, name):
        return auth.cookie_value(self.headers.get("Cookie"), name)

    def same_origin(self, host):
        site = (self.headers.get("Sec-Fetch-Site") or "").lower()
        if site and site not in ("same-origin", "none"):
            return False
        origin = self.headers.get("Origin")
        if origin and origin != "null":
            return (urllib.parse.urlsplit(origin).hostname or "").lower() == host
        return origin != "null"

    def form(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 4096 or "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            self.close_connection = True
            return None
        raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        return {k: v[-1] for k, v in urllib.parse.parse_qs(raw, keep_blank_values=True).items()}

    # -- routes
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        try:
            self.route()
        except Exception:
            log("gate error:\n" + traceback.format_exc())
            self.send(500, b"gate error", ctype="text/plain; charset=utf-8")

    do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_GET

    def route(self):
        c = self.ctx()
        if not c:   # not a gated drive (any more), wrong host, or not from Caddy: never let anything through
            return self.send(403, b"Forbidden", ctype="text/plain; charset=utf-8")
        m, host, ip = c
        path = urllib.parse.urlsplit(self.path).path
        if path == PATH + "/check" and self.command == "GET":
            return self.check(m, host)
        sub = path[len(m["pre"]):] if path.lower().startswith(m["pre"].lower()) else ""
        if sub.lower() == PATH + "/login":
            if self.command == "POST":
                return self.login(m, host, ip)
            if self.command in ("GET", "HEAD"):
                return self.login_form(m, host)
        if sub.lower() == PATH + "/logout":
            if self.command == "POST":
                return self.logout(m, host, ip)
            if self.command in ("GET", "HEAD"):
                return self.logout_form(m)
        return self.send(404, b"Not Found", ctype="text/plain; charset=utf-8")

    def check(self, m, host):
        """forward_auth: 200 lets the request through to the upstream; anything else is sent to the visitor."""
        if session_user(m, host, self.cookie(session_cookie(m["id"]))):
            return self.send(200, ctype="text/plain; charset=utf-8")
        method = (self.headers.get("X-Forwarded-Method") or "GET").upper()
        uri = self.headers.get("X-Forwarded-Uri") or m["pre"] + "/"
        if method in ("GET", "HEAD") and "text/html" in (self.headers.get("Accept") or ""):
            to = m["pre"] + PATH + "/login?next=" + urllib.parse.quote(safe_next(uri, m["pre"]), safe="")
            return self.send(302, b"", [("Location", to)])
        return self.send(401, b"Login required", ctype="text/plain; charset=utf-8")

    def login_form(self, m, host, error="", code=200, nxt=None):
        if not error and session_user(m, host, self.cookie(session_cookie(m["id"]))):
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            return self.send(303, b"", [("Location", safe_next((q.get("next") or [""])[-1], m["pre"]))])
        if nxt is None:
            nxt = (urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("next") or [""])[-1]
        tok = secrets.token_urlsafe(24)
        e = lambda s: html.escape(str(s), quote=True)
        body = """<form method="post" action="%(action)s" autocomplete="on">
<h1>%(name)s</h1><p>Sign in to continue to %(host)s%(pre)s</p>%(err)s
<input type="hidden" name="csrf" value="%(tok)s"><input type="hidden" name="next" value="%(next)s">
<label for="u">User</label><input id="u" name="user" autocomplete="username" required autofocus maxlength="40">
<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required maxlength="200">
%(totp)s<button type="submit">Sign in</button></form>""" % {
            "action": e(m["pre"] + PATH + "/login"), "name": e(m["name"]), "host": e(host), "pre": e(m["pre"] or ""),
            "err": '<div class="err">%s</div>' % e(error) if error else "", "tok": e(tok),
            "next": e(safe_next(nxt, m["pre"])),
            "totp": '<label for="c">2FA code</label><input id="c" name="code" inputmode="numeric" autocomplete="one-time-code" '
                    'maxlength="8" pattern="[0-9 ]*">' if m["totp"] else ""}
        self.page(code, "Sign in · " + m["name"], body, [("Set-Cookie", set_cookie(csrf_cookie(m["id"]), tok, 1800, "Strict"))])

    def login(self, m, host, ip):
        f = self.form()
        if f is None:
            return self.send(413, b"Request too large", ctype="text/plain; charset=utf-8")
        nxt = f.get("next", "")
        want = self.cookie(csrf_cookie(m["id"])) or ""
        if not (want and auth.hmac.compare_digest(want, f.get("csrf", "")) and self.same_origin(host)):
            return self.login_form(m, host, "The form expired - please sign in again.", 400, nxt)
        user = f.get("user", "").strip()[:40]
        key = "%d:%s" % (m["id"], user.lower())
        if IP_LIMIT.blocked(ip) or USER_LIMIT.blocked(key):
            core.audit(ip, "gate:" + user, "gate-login", "%d:%s" % (m["id"], host), ok=False, note="locked out")
            return self.login_form(m, host, "Too many attempts - try again later.", 429, nxt)
        db = core.connect()
        try:
            row = db.execute("SELECT hash, totp FROM gate_user WHERE mount=? AND user=?", [m["id"], user]).fetchone()
        finally:
            db.close()
        if not _DUMMY:
            _DUMMY.append(auth.hash_password(secrets.token_urlsafe(16)))
        ok = auth.verify_password(f.get("password", ""), row[0] if row else _DUMMY[0]) and bool(row)
        if ok and row[1]:
            with _TOTP_LOCK:
                step = auth.totp_verify(row[1], f.get("code", ""), TOTP_LAST.get((m["id"], user), 0))
                if step:
                    TOTP_LAST[(m["id"], user)] = step
            ok = bool(step)
        if not ok:
            IP_LIMIT.fail(ip)
            USER_LIMIT.fail(key)
            core.audit(ip, "gate:" + user, "gate-login", "%d:%s" % (m["id"], host), ok=False)
            if HOOKS["failed"]:
                HOOKS["failed"](ip, "gate:%s@%s" % (user, m["name"]))
            if USER_LIMIT.blocked(key) and HOOKS["alert"]:
                HOOKS["alert"]("login", "warning", "Gate login for %s on %s locked" % (user or "?", m["name"]),
                               "10 wrong passwords or codes within an hour (last from %s). The account is locked for "
                               "up to an hour; nothing reached the service." % ip, "gate-lock:%s" % key)
            time.sleep(0.5)
            return self.login_form(m, host, "Wrong user, password or code.", 401, nxt)
        # failures are NOT cleared by a success: one valid account must not reset the guessing budget of an address
        tok = secrets.token_urlsafe(32)
        t = time.time()
        db = core.connect()
        try:
            with db:
                db.execute("DELETE FROM gate_session WHERE exp < ?", [t])
                db.execute("INSERT INTO gate_session(hash, mount, user, host, exp, created, ip) VALUES(?,?,?,?,?,?,?)",
                           [auth.token_hash(tok), m["id"], user, host, t + m["hours"] * 3600, t, ip])
        finally:
            db.close()
        core.audit(ip, "gate:" + user, "gate-login", "%d:%s" % (m["id"], host))
        self.send(303, b"", [("Location", safe_next(nxt, m["pre"])),
                             ("Set-Cookie", set_cookie(session_cookie(m["id"]), tok, m["hours"] * 3600)),
                             ("Set-Cookie", set_cookie(csrf_cookie(m["id"]), "", 0, "Strict"))])

    def logout_form(self, m):
        tok = secrets.token_urlsafe(24)
        body = """<form method="post" action="%s"><h1>Sign out</h1><p>End your session for %s.</p>
<input type="hidden" name="csrf" value="%s"><button type="submit">Sign out</button></form>""" % (
            html.escape(m["pre"] + PATH + "/logout"), html.escape(m["name"]), tok)
        self.page(200, "Sign out · " + m["name"], body, [("Set-Cookie", set_cookie(csrf_cookie(m["id"]), tok, 1800, "Strict"))])

    def logout(self, m, host, ip):
        f = self.form() or {}
        want = self.cookie(csrf_cookie(m["id"])) or ""
        if not (want and auth.hmac.compare_digest(want, f.get("csrf", "")) and self.same_origin(host)):
            return self.logout_form(m)
        tok = self.cookie(session_cookie(m["id"]))
        if tok:
            db = core.connect()
            try:
                with db:
                    db.execute("DELETE FROM gate_session WHERE hash=?", [auth.token_hash(tok)])
            finally:
                db.close()
            core.audit(ip, "gate", "gate-logout", "%d:%s" % (m["id"], host))
        self.send(303, b"", [("Location", m["pre"] + PATH + "/login"),
                             ("Set-Cookie", set_cookie(session_cookie(m["id"]), "", 0)),
                             ("Set-Cookie", set_cookie(csrf_cookie(m["id"]), "", 0, "Strict"))])


class Server(ThreadingHTTPServer):
    daemon_threads = True


def start():
    host, _, port = CFG["gate_listen"].rpartition(":")
    if host not in ("127.0.0.1", "localhost", "[::1]"):
        log("gate: refusing to listen on %s - loopback only" % CFG["gate_listen"])
        return None
    srv = Server((host.strip("[]"), int(port)), Handler)
    threading.Thread(target=srv.serve_forever, name="gate", daemon=True).start()
    log("gate: login for proxied services on %s" % CFG["gate_listen"])
    return srv
