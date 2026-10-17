#!/usr/bin/env python3
"""Strata - CDN analytics, storage manager, serving control and precompression for Caddy + cloudflared.

One code folder serves several sites; each runs as its own process with its own instance home (instance.py):

    pythonw strata.py --home D:\\sites\\example.com
    pythonw strata.py --home D:\\sites\\example.net

Processes / ports per instance (everything here is loopback or LAN - never published), with the default ports:
    listen            127.0.0.1:8090  admin UI + API (login + optional TOTP)   <- Caddy exposes it to the LAN on :8091
    feed_listen       127.0.0.1:8081  redacted feed for Strata Telemetry (loopback + bearer token, see feed.py)
    transform_listen  127.0.0.1:8083  Strata Transform (transform/transform.py): resize / versions / signed links
    telemetry.json    127.0.0.1:8082  Strata Telemetry (telemetry/telemetry.py): the public stats page

Config: <home>/strata.json (see core.DEFAULTS). First run: `python setup.py`, or open /setup from this machine.
"""
import json
import base64
import hashlib
import ipaddress
import os
import re
import secrets
import shutil
import sys
import threading
import tempfile
import time
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import alerts
import analyze
import anubis
import backup
import accounts
import auth
import cloudflare
import compress
import core
import feed
import files
import gate
import media_bridge
import network
import office
import rollup
import rules
from core import CFG, log

try:  # dev-only extensions in the git-ignored local/ folder: production has none
    import local
except ModuleNotFoundError as e:
    if e.name != "local":
        raise
    local = None

STATIC = os.path.join(core.ROOT, "static")
LOCAL_STATIC = os.path.join(core.ROOT, "local", "static")  # its .css / .js join index.html (<!--LOCAL-->)
PUBLIC_STATIC = {"/styles.css", "/favicon.ico", "/login.js", "/boot.js", "/custom.css"}
BRAND_FILES = ("custom.css", "brand.png")  # Settings › Branding: a copy in the instance home replaces the built-in file
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src https://fonts.gstatic.com; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
RAW_CSP = "sandbox; default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'"
TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
         ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".ico": "image/x-icon", ".png": "image/png",
         ".webp": "image/webp", ".jpg": "image/jpeg", ".json": "application/json"}
DUMMY_HASH = auth.hash_password(secrets.token_urlsafe(24))  # login timing for accounts without a password
IDE_LOCK = threading.RLock()
IDE_EXTS = {".py", ".js", ".mjs", ".cjs", ".css", ".html", ".htm", ".json", ".md", ".svg", ".txt", ".xml"}
IDE_SKIP = {".git", ".hg", ".svn", "__pycache__", "vendor", "node_modules", "generated", "data", ".strata"}
# first-run owner setup (/setup): loopback only, gone once strata.json has an owner
SETUP_LOCK = threading.Lock()
SETUP_TOTP = {}  # "secret": the authenticator key /setup shows until the owner exists (one per process)
SETUP_ERRORS = {"user": "Usernames are 2 to 60 letters, digits, dots, dashes or underscores.",
                "password": "Use at least 12 characters for the password.",
                "repeat": "The two passwords don't match.",
                "email": "Enter a valid e-mail address.",
                "mail": "Enter a sender address and an SMTP server or a Resend API key, or use an authenticator app instead.",
                "totp": "That code didn't match. Enter the code your app shows now.",
                "factor": "Choose how you get your sign-in code."}
SETUP_FACTOR = '''<fieldset class="factor"><legend>Sign-in code</legend>
  <label><input type="radio" name="factor" value="app"%(app)s><span>Authenticator app</span></label>
  <label><input type="radio" name="factor" value="email"%(email)s><span>E-mail</span></label>
</fieldset>
<div class="if-app">
  %(qr)s<p class="note">Scan this with your authenticator app, or enter the key <code>%(key)s</code></p>
  <label>Code from the app<input name="totp_code" inputmode="numeric" autocomplete="one-time-code" maxlength="7" spellcheck="false"></label>
</div>
<div class="if-email">
  <label>E-mail<input name="email" type="email" autocomplete="email"></label>%(mail)s
</div>'''
SETUP_MAIL = ('\n  <p class="note">Codes are sent through the SMTP server of any mail provider or your own mail server, or through '
              '<a href="https://resend.com" target="_blank" rel="noopener">Resend</a>.</p>'
              '\n  <label>Send codes from<input name="mail_from" type="email" placeholder="strata@example.com"></label>'
              '\n  <label>SMTP server<input name="smtp_host" placeholder="smtp.example.com" autocomplete="off" spellcheck="false"></label>'
              '\n  <label>SMTP port<input name="smtp_port" inputmode="numeric" placeholder="587 (STARTTLS) or 465 (TLS)"></label>'
              '\n  <label>SMTP user name<input name="smtp_user" autocomplete="off" spellcheck="false"></label>'
              '\n  <label>SMTP password<input name="smtp_password" type="password" autocomplete="off"></label>'
              '\n  <label>Or: Resend API key<input name="resend_key" autocomplete="off" spellcheck="false"></label>')


def mail_configured():
    return alerts.mail_ready()


def owner_mail_ready():
    """True when an e-mailed sign-in code can reach the owner."""
    owner = accounts.get(str(CFG["auth"].get("user") or "")) or {}
    return mail_configured() and bool(accounts.EMAIL_RE.fullmatch(str(owner.get("email") or "")))


def trust_bind(acct):
    """What a trusted browser stays bound to: a new owner password or a new authenticator app ends the trust."""
    return "%s|%s" % (acct.get("password_hash") or "", CFG["auth"].get("totp_secret") or "")


def setup_secret():
    """The key /setup offers stays the same across reloads, so a mistyped code doesn't mean scanning again."""
    with SETUP_LOCK:
        if not SETUP_TOTP.get("secret"):
            SETUP_TOTP["secret"] = auth.totp_secret()
        return SETUP_TOTP["secret"]


def setup_factor():
    secret = setup_secret()
    svg = auth.qr_svg(auth.totp_uri(secret, CFG["instance"].get("name") or "owner"))
    app = not mail_configured()  # the app is the default unless e-mail is already set up
    return SETUP_FACTOR % {"app": " checked" if app else "", "email": "" if app else " checked",
                           "qr": '<div class="qr">%s</div>' % svg if svg else "", "key": auth.spaced(secret),
                           "mail": "" if mail_configured() else SETUP_MAIL}


class DBSessions(auth.Sessions):
    """Sessions that survive a restart: only sha256(token) is stored, the token itself stays in the cookie."""

    def load(self):
        db = core.connect()
        try:
            with db:
                db.execute("DELETE FROM session WHERE exp < ?", [time.time()])
            for h, user, exp, ip, created, ttl in db.execute("SELECT hash, user, exp, ip, created, ttl FROM session"):
                self.by_hash[h] = {"user": user, "exp": exp, "ip": ip, "created": created, "ttl": ttl, "attempts": 0, "saved": exp}
        finally:
            db.close()

    def _write(self, sql, args):
        db = core.connect()
        try:
            with db:
                db.execute(sql, args)
        except Exception:
            log("session store error:\n" + traceback.format_exc())
        finally:
            db.close()

    def create(self, user, ip, ttl=None):
        tok = super().create(user, ip, ttl)
        s = self.by_hash[auth.token_hash(tok)]
        s["saved"] = s["exp"]
        self._write("INSERT OR REPLACE INTO session VALUES(?,?,?,?,?,?)",
                    [auth.token_hash(tok), user, s["exp"], ip, s["created"], s["ttl"]])
        return tok

    def get(self, token):
        s = super().get(token)
        if s:
            return s
        if not token:
            return None
        h = auth.token_hash(token)
        db = core.connect()
        try:
            row = db.execute("SELECT user, exp, ip, created, ttl FROM session WHERE hash=? AND exp > ?",
                             [h, time.time()]).fetchone()
            if row:
                user, exp, ip, created, ttl = row
                with self.lock:
                    s = {"user": user, "exp": exp, "ip": ip, "created": created, "ttl": ttl, "attempts": 0, "saved": exp}
                    self.by_hash[h] = s
                return s
        finally:
            db.close()
        return None

    def check(self, token):
        user = super().check(token)
        if user:
            h = auth.token_hash(token)
            s = self.by_hash.get(h)
            if s and s["exp"] - s.get("saved", 0) > 600:  # persist the sliding expiry at most every 10 min
                s["saved"] = s["exp"]
                self._write("UPDATE session SET exp=? WHERE hash=?", [s["exp"], h])
        return user

    def drop(self, token):
        super().drop(token)
        if token:
            self._write("DELETE FROM session WHERE hash=?", [auth.token_hash(token)])

    def drop_user(self, user):
        super().drop_user(user)
        self._write("DELETE FROM session WHERE user=? COLLATE NOCASE", [user])


class App:
    live = metrics = probes = compressor = alerts = None
    started = time.time()
    sessions = DBSessions(CFG["auth"]["session_hours"])
    pending = auth.Sessions(0.1)  # half-authenticated logins waiting for the 2FA code (6 minutes)
    enrol = {}                    # user -> (secret, expires) while setting up 2FA
    limiter = auth.Limiter()


class CountingReader:
    """Wraps rfile so we know how much of a request body is still unread when we answer early."""

    def __init__(self, raw):
        self.raw, self.count = raw, 0

    def read(self, n=-1):
        b = self.raw.read(n)
        self.count += len(b)
        return b

    def readline(self, n=-1):
        b = self.raw.readline(n)
        self.count += len(b)
        return b

    def close(self):
        if hasattr(self.raw, "close"):
            self.raw.close()

    def __getattr__(self, name):
        return getattr(self.raw, name)



def instance_info():
    """What the dashboard needs to know about the site it manages (no secrets)."""
    inst = CFG["instance"]
    hosts = CFG["public"]["hosts"]
    try:
        cdn = rules.preferred_host(rules.cdn_hosts(core.mounts())) if core.mounts() else ""
    except Exception:
        cdn = ""
    return {"id": inst.get("id") or "", "name": inst.get("name") or CFG["cloudflare"].get("zone_name") or "Strata",
            "brand": inst.get("brand") or "Strata", "login_text": inst.get("login_text") or "",
            "accent": inst.get("accent") or "", "siblings": inst.get("siblings") or [],
            "zone": CFG["cloudflare"].get("zone_name") or "", "hosts": hosts,
            "cdn_host": cdn or next((h for h in hosts if h.startswith("cdn.")), hosts[0] if hosts else ""),
            "stats_host": rules.stats_host(), "cdn_listen": inst.get("cdn_listen") or ":8080",
            "home": core.HOME, "code": core.ROOT, "config": core.CONFIG_PATH,
            "token_env": inst.get("token_env") or "CF_API_TOKEN", "cloudflared_config": CFG["cloudflared_config"],
            "cloudflared_metrics": CFG["cloudflared_metrics"], "dry_run": bool(inst.get("dry_run")),
            "tunnel_restart": inst.get("tunnel_restart") or {}, "version": core.VERSION, "update": newer_release()}


def newer_release():
    """{"tag", "url"} of a GitHub release newer than this code, else None."""
    db = core.connect()
    try:
        rel = core.get_meta(db, "latest_release") or {}
    finally:
        db.close()
    newer = core.version_tuple(rel.get("tag")) > core.version_tuple(core.VERSION)
    return {"tag": rel["tag"], "url": rel["url"]} if newer else None


def icon_sprite():
    """static/icons.svg inlined into the dashboard: an external <use href="icons.svg#..."> stays blank until that file
    has been fetched again, which left icons missing from freshly rendered buttons."""
    with open(os.path.join(STATIC, "icons.svg"), encoding="utf-8") as f:
        return f.read().replace('style="display:none"', 'aria-hidden="true" style="position:absolute;width:0;height:0;overflow:hidden"', 1)


def local_assets():
    """<link> / <script> tags for the dev-only files in local/static/ ("" in production)."""
    if not local or not os.path.isdir(LOCAL_STATIC):
        return ""
    names = sorted(os.listdir(LOCAL_STATIC))
    return "".join(['<link rel="stylesheet" href="/%s">' % n for n in names if n.endswith(".css")] +
                   ['<script src="/%s"></script>' % n for n in names if n.endswith(".js")])


def page_vars():
    """Placeholders filled into the HTML pages (index.html carries the instance info for the scripts)."""
    import html
    info = instance_info()
    return {"{{SITE}}": html.escape(info["name"]), "{{INSTANCE}}": html.escape(json.dumps(info), quote=True),
            "{{ACCENT}}": html.escape(info["accent"] or ""), "{{BRAND}}": html.escape(info["brand"]),
            "<!--LOCAL-->": local_assets(),
            "<!--LOGIN_TEXT-->": '<p class="foot">%s</p>' % html.escape(info["login_text"]) if info["login_text"] else "",
            "<!--VERSION-->": "Strata %s%s" % (html.escape(info["version"]), ' · <a href="%s" target="_blank" rel="noopener">%s available</a>' % (
                html.escape(info["update"]["url"]), html.escape(info["update"]["tag"])) if info["update"] else "")}


def read_file(path, mode="rb", encoding=None):
    """Whole file, handle closed at once: an open one makes os.replace() fail on Windows (WinError 32)."""
    with open(path, mode, encoding=encoding) as f:
        return f.read()


def branding():
    """Settings › Branding: what the editor shows (name and sign-in text live in strata.json, files in the home)."""
    css = core.home_path("custom.css")
    return {"brand": CFG["instance"].get("brand") or "", "login_text": CFG["instance"].get("login_text") or "",
            "css": read_file(css, "r", "utf-8") if os.path.isfile(css) else "",
            "logo": os.path.isfile(core.home_path("brand.png"))}


def save_branding(b):
    inst = {k: str(b[k] or "").strip()[:n] for k, n in (("brand", 40), ("login_text", 300)) if k in b}
    if inst:
        core.save_config({"instance": inst})
    files_ = {}
    if "css" in b:
        files_["custom.css"] = str(b["css"] or "").encode("utf-8")
    if "logo" in b:
        files_["brand.png"] = base64.b64decode(b["logo"] or "", validate=True)
        if files_["brand.png"] and files_["brand.png"][:8] != bytes.fromhex("89504e470d0a1a0a"):  # PNG signature
            raise files.FileError(415, "the logo has to be a PNG")
    for name, data in files_.items():
        if len(data) > 256 << 10:
            raise files.FileError(413, "%s is larger than 256 KB" % ("the logo" if name == "brand.png" else "the CSS"))
        full = core.home_path(name)
        if not data:  # empty: back to the built-in logo / no custom CSS
            if os.path.isfile(full):
                os.remove(full)
            continue
        with open(full + ".tmp", "wb") as f:
            f.write(data)
        os.replace(full + ".tmp", full)
    return branding()


def smart_home(user):
    """Where this user's uploads at a drive root land (Smart-Sorting): {"mount", "path"} or None."""
    raw = next((v for k, v in (CFG["smartsort"].get("homes") or {}).items() if k.lower() == (user or "").lower()), "")
    mid, _, path = str(raw or "").partition(":")
    m = core.mount(mid)
    if not m or m["kind"] != "files" or not path.startswith("/"):
        return None
    try:
        return {"mount": m["id"], "path": files.rel_of(files.parts_of(path))}
    except files.FileError:
        return None


def purge_later(result):
    """Queue a result's Cloudflare purges: its `purge` prefixes (every URL form and ?variant), else its `urls`."""
    if isinstance(result, dict):
        cloudflare.enqueue(result.get("purge") or result.get("urls") or [])


def purge_now(result):
    """Delete / empty trash: send the purges before answering and report how it went (the UI warns if they failed)."""
    result["cdn"] = cloudflare.purge_now(result.pop("purge", None) or [])
    return result


# ---------------------------------------------------------------- which capability each API route needs
# Deny by default: a route missing here needs "*" (administrators only). Pseudo-capabilities: "account.self" (any
# signed-in account), "files.any" (some file capability + a zone), "serving.view" (serving.read or files.share).
ROUTE_CAPS = {
    # analytics and monitoring
    "/api/live": "analytics.read", "/api/stats": "analytics.read", "/api/insights": "analytics.read",
    "/api/history": "analytics.read", "/api/edge": "analytics.read", "/api/compression": "analytics.read",
    "/api/requests": "analytics.visitors", "/api/ip": "analytics.visitors",
    "/api/alerts": "alerts.read", "/api/alerts/ack": "alerts.ack", "/api/alerts/test": "alerts.config",
    "/api/system": "system.read", "/api/settings/retention": "system.retention", "/api/system/optimize": "system.optimize",
    "/api/settings/links": "system.settings", "/api/settings/smartsort": "system.settings",
    "/api/settings/upload": "system.settings", "/api/compress/run": "system.compression",
    "/api/settings/autoban": "security.autoban",
    "/api/bots": "security.bots", "/api/settings/bots": "security.bots", "/api/bots/task": "security.bots",  # Anubis: runs a program here
    "/api/bots/restart": "security.bots", "/api/bots/stop": "security.bots", "/api/bots/task/remove": "security.bots",
    "/api/bots/install": "security.bots", "/api/bots/setup": "security.bots",  # the last two download from github.com
    "/api/bots/under-attack": "security.bots", "/api/bots/auto-downloads": "security.bots",
    "/api/backup": "system.backup", "/api/backup/restore": "system.backup",  # the whole database: owner only
    # own account
    "/api/me": "account.self", "/api/instance": "account.self", "/api/prefs": "account.self", "/api/password": "account.self",
    "/api/privacy/accept": "account.self", "/api/audit": "account.self", "/api/audit/events": "account.self",
    "/api/avatar": "account.self",
    # files
    "/api/drives": "files.any", "/api/jobs": "files.any", "/api/uploads": "files.upload",
    "/api/files/mkdir": "files.mkdir", "/api/files/rename": "files.rename", "/api/files/move": "files.move",
    "/api/files/copy": "files.copy", "/api/files/version/restore": "files.edit", "/api/files/delete": "files.delete",
    "/api/files/restore": "files.restore", "/api/files/empty-trash": "files.purge", "/api/files/trash/delete": "files.purge",
    "/api/files/version/delete": "files.purge", "/api/files/purge": "files.purge", "/api/files/hash": "files.read",
    "/api/files/zip": "files.download", "/api/files/upload": "files.upload",
    # serving
    "/api/serving": "serving.view", "/api/serving/test": "serving.read", "/api/fs": "serving.drives",
    "/api/serving/link": "files.share", "/api/serving/link/delete": "files.share", "/api/serving/link/alias": "files.share",
    "/api/serving/sign": "files.share",
    "/api/serving/mount": "serving.drives", "/api/serving/mount/delete": "serving.drives",
    "/api/serving/rule": "serving.rules", "/api/serving/rule/delete": "serving.rules", "/api/serving/rule/move": "serving.rules",
    "/api/serving/bl": "serving.blacklist", "/api/serving/bl/bulk": "serving.blacklist",
    "/api/serving/bl/delete": "serving.blacklist", "/api/serving/bl/toggle": "serving.blacklist",
    "/api/serving/site": "serving.site", "/api/serving/rollback": "serving.apply", "/api/serving/apply": "serving.apply",
    # network and CDN
    "/api/cloudflare": "network.read", "/api/network/setting": "network.zone", "/api/network/dns/delete": "network.dns",
    "/api/network/ingress/add": "network.ingress", "/api/network/ingress/delete": "network.ingress",
    "/api/network/ingress/move": "network.ingress", "/api/network/ingress/test": "network.ingress",
    "/api/network/restart": "network.tunnel", "/api/network/expose": "network.expose",
    # the office (office.py): own profile and presence for every account; posting / notes in route_cap
    "/api/presence": "account.self", "/api/office/profile": "account.self",
    "/api/office": "office.view", "/api/office/board": "office.view", "/api/office/notes": "office.view",
    "/api/office/seen": "office.view", "/api/office/post/edit": "office.view", "/api/office/post/delete": "office.view",
    "/api/office/post/pin": "office.admin", "/api/office/member": "office.admin",
}
if local:
    ROUTE_CAPS.update(local.CAPS)


def route_cap(path, method, q, body):
    """The capability a request needs (see ROUTE_CAPS), "*" for administrator-only, None for never."""
    write = method in ("POST", "PUT", "PATCH")
    if path.startswith("/api/accounts") or path == "/api/settings/signups" or path.startswith("/api/2fa/"):
        return "accounts.manage"
    if path.startswith("/api/ide/"):
        return "code.write" if write and path.endswith("/save") else "code.read"
    if path == "/api/alerts/config":  # the sender that delivers sign-in codes: whoever controls it can read them
        # webhooks too: a URL of the owner's choosing receives every security alert
        return "mail.manage" if any(k in body for k in ("resend_api_key", "clear_key", "from", "webhooks", "smtp", "provider")) else "alerts.config"
    if path == "/api/logs":
        return {"access": "logs.access", "activity": "audit.read"}.get(q.get("source"), "logs.runtime")
    if path.startswith("/api/audit/"):
        return "audit.read"
    if path.startswith("/api/account/"):
        return "account.self"
    if path.startswith("/api/media/"):
        return "media.manage" if write else "media.read"
    if path.startswith("/api/upload"):
        return "files.upload"
    if path.startswith("/api/analyze/"):
        return "files.analyze"
    if path.startswith("/api/files/zip/"):
        return "files.download"
    if path == "/api/files/text":
        return "files.edit" if write else "files.read"
    if path == "/api/files/raw" and q.get("download") == "1":
        return "files.download"
    if path == "/api/network/dns":
        return "network.dns" if write else "network.read"
    if path == "/api/office/post":  # a noticeboard post, or a note on a colleague's profile
        return "office.notes" if str(body.get("target") or "").strip() else "office.post"
    if path.startswith("/api/cloudflare/"):
        return "cdn.manage"
    if path in ROUTE_CAPS:
        return ROUTE_CAPS[path]
    if path.startswith("/api/serving/history/"):
        return "serving.read"
    if path.startswith("/api/network/") and not write:
        return "network.read"
    if (path == "/api/files" or path.startswith("/api/files/")) and not write:
        return "files.read"
    return "*"



# settings fields as the forms label them, for "<field>: enter a number from <lo> to <hi>"
FIELD_LABELS = {"raw_retention_days": "Raw request days", "retention_days": "Aggregate days", "digest_hour": "Summary hour",
                "max_per_hour": "Alerts per hour", "default_days": "Link lifetime in days", "seconds": "Link lifetime",
                "per_ip_10m": "Clicks per address in 10 minutes", "clicks_10m": "Clicks in 10 minutes",
                "countries_1h": "Countries in an hour", "bot_min": "Minimum bot clicks", "bot_share": "Bot share",
                "chunk_mb": "Chunk size in MB", "parallel": "Parallel uploads", "versions_keep": "Versions to keep"}


def num(b, key, lo, hi, cast=int, default=None):
    """A number from a settings form, kept within lo..hi. Anything else is a 400 that names the field, instead of
    Python's own message ("invalid literal for int()...")."""
    v = b.get(key)
    if v in (None, "") and default is not None:
        v = default
    try:
        n = float(str(v).strip())
        if n != n or n in (float("inf"), float("-inf")):
            raise ValueError
    except (TypeError, ValueError):
        raise files.FileError(400, "%s: enter a number from %s to %s" % (FIELD_LABELS.get(key, key.replace("_", " ")), lo, hi))
    return max(lo, min(hi, cast(n) if cast is float else int(round(n))))


class Handler(BaseHTTPRequestHandler):
    server_version = "Strata"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(60)

    def log_message(self, *a):
        pass

    # -- helpers
    def client_ip(self):
        peer = self.client_address[0]
        xff = self.headers.get("X-Forwarded-For")
        if peer in ("127.0.0.1", "::1") and xff:  # set by Caddy (it discards client-supplied values)
            return xff.split(",")[-1].strip()
        return peer

    via_key = False

    def user(self):
        self.via_key = False
        bearer = self.headers.get("Authorization") or ""
        if bearer[:7].lower() == "bearer ":  # API key: acts as "api:<name>"; a bad key is never a cookie fallback
            if App.limiter.blocked(self.client_ip()):
                return None
            name = auth.api_key_name(CFG["auth"].get("api_keys"), bearer[7:].strip())
            self.via_key = bool(name)
            return "api:" + name if name else None
        cv = auth.cookie_value(self.headers.get("Cookie"))
        user = App.sessions.check(cv)
        if user:
            a = accounts.get(user)
            problem = accounts.access_problem(a, self.client_ip())
            s = App.sessions.get(cv)
            if not problem and s and a.get("role") != "root" and a.get("session_hours") and \
                    time.time() - (s.get("created") or 0) > float(a["session_hours"]) * 3600:
                problem = "session-length"  # absolute limit: activity does not extend it
            if problem:  # disabled, past its end date, outside its networks, or too long signed in: it ends here
                App.sessions.drop(cv)
                if problem != "disabled":
                    core.audit(self.client_ip(), user, "session-refused", problem, ok=False)
                return None
        return user

    def csrf_ok(self, path=""):
        if self.via_key:  # no ambient credential: a browser cannot attach the Authorization header cross-site
            return True
        if path in ("/privacy/accept", "/enroll"):  # plain form posts: no X-Strata header, so the origin is the check
            return self.form_origin_ok()
        if self.headers.get("X-Strata") != "1":
            return False
        origin = self.headers.get("Origin")
        if origin:
            return urllib.parse.urlsplit(origin).netloc.lower() == (self.headers.get("Host") or "").lower()
        return True

    def form_origin_ok(self):
        """Sign-in forms carry no session yet, so SameSite cannot protect them: refuse cross-site posts (login CSRF)."""
        host = (self.headers.get("Host") or "").lower()
        src = self.headers.get("Origin") or self.headers.get("Referer")
        if not src:
            return True  # browsers always send Origin on POST; non-browser clients cannot ride a victim's cookies
        return urllib.parse.urlsplit(src).netloc.lower() == host

    def common_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")

    def json(self, obj, code=200):
        body = json.dumps(obj, separators=(",", ":"), default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.common_headers()
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, to, cookies=()):
        self.send_response(303)
        self.send_header("Location", to)
        for c in cookies:
            self.send_header("Set-Cookie", c)
        self.send_header("Content-Length", "0")
        self.common_headers()
        self.end_headers()

    def html_page(self, name, replace=None):
        with open(os.path.join(STATIC, name), encoding="utf-8") as f:
            page = f.read()
        for k, v in (replace or {}).items():
            page = page.replace(k, v)
        body = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.common_headers()
        self.end_headers()
        self.wfile.write(body)

    def static(self, path):
        name = "index.html" if path in ("/", "/index.html") else path.lstrip("/")
        if not path.startswith("/api/") and "." not in name.rsplit("/", 1)[-1] and not os.path.isfile(os.path.join(STATIC, name)):
            name = "index.html"   # a view's address (/truenas/connection): app.js opens that view
        full = os.path.normpath(os.path.join(STATIC, name))
        if local and not os.path.isfile(full):
            full = os.path.normpath(os.path.join(LOCAL_STATIC, name))
        if name in BRAND_FILES and os.path.isfile(core.home_path(name)):
            full = core.home_path(name)
        elif not full.startswith((STATIC + os.sep, LOCAL_STATIC + os.sep)) or not os.path.isfile(full) or re.match(r"login.*\.html$", name):
            return self.json({"error": "not found"}, 404)
        if name == "index.html":
            return self.html_page(name, dict(page_vars(), **{"<!--ICONS-->": icon_sprite()}))
        with open(full, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", TYPES.get(os.path.splitext(full)[1], "application/octet-stream"))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(body)))
        self.common_headers()
        self.end_headers()
        self.wfile.write(body)

    def query(self):
        u = urllib.parse.urlsplit(self.path)
        return u.path, {k: v[-1] for k, v in urllib.parse.parse_qs(u.query).items()}

    def body_json(self, limit=4 << 20):
        n = files.content_length(self.headers, limit)
        body = json.loads(self.rfile.read(n) or b"{}")
        if not isinstance(body, dict):
            raise files.FileError(400, "request body must be a JSON object")
        return body

    def body_form(self, limit=8192):
        n = files.content_length(self.headers, limit)
        values = urllib.parse.parse_qs(self.rfile.read(n).decode("utf-8", "replace"), keep_blank_values=True)
        return {k: v[-1] for k, v in values.items()}

    def drain(self, cap=100 << 20):
        """Read (and discard) whatever is left of the request body before answering early.
        Otherwise the socket closes with unread data, the OS sends a RST, and Caddy turns our 401/403/409
        into a 502 (reported by the stats-page session)."""
        try:
            total = files.content_length(self.headers)
        except files.FileError:
            self.close_connection = True
            return
        done = getattr(self.rfile, "count", 0)
        left = total - done
        if left <= 0:
            return
        if left > cap or "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            self.close_connection = True
            return
        try:
            self.connection.settimeout(30)
            while left > 0:
                buf = self.rfile.read(min(left, 65536))
                if not buf:
                    break
                left -= len(buf)
        except OSError:
            pass
        self.close_connection = True

    def local_network(self):
        """Administrative authentication is accepted only from loopback/LAN/VPN address ranges."""
        try:
            addr = ipaddress.ip_address(self.client_ip())
            if getattr(addr, "ipv4_mapped", None):
                addr = addr.ipv4_mapped
            nets = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
                    "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10")
            return any(addr in ipaddress.ip_network(n) for n in nets)
        except ValueError:
            return False

    @staticmethod
    def administrative_account(acct):
        """Accounts that can change anything beyond files sign in only from the local network."""
        operate = {p for p, _, g, _ in accounts.PERMISSIONS if g == "operate"}
        return bool(acct and (acct.get("role") in ("root", "admin") or accounts.capabilities(acct) & operate))

    def guard(self, path=""):
        if not CFG["auth"].get("password_hash"):
            self.drain()
            if path.startswith("/api/"):
                self.json({"error": "no owner account yet: open /setup on this machine or run python setup.py"}, 503)
            else:
                self.redirect("/setup")
            return None
        user = self.user()
        if not user:
            self.drain()
            path, _ = self.query()
            if (self.headers.get("Authorization") or "")[:7].lower() == "bearer ":
                ip = self.client_ip()
                App.limiter.fail(ip)
                core.audit(ip, "", "api-key", path[:200], ok=False)
                return self.json({"error": "invalid API key"}, 401)
            if path.startswith("/api/"):
                self.json({"error": "login required"}, 401)
            else:
                self.redirect("/login")
            return None
        if user.startswith("api:"):
            if not self.local_network():
                self.drain()
                core.audit(self.client_ip(), user, "admin-network-denied", path[:200], ok=False)
                self.json({"error": "administrative access is available only from the local network"}, 403)
                return None
            return user
        acct = accounts.get(user)
        if acct:
            if self.administrative_account(acct) and not self.local_network():
                self.drain()
                core.audit(self.client_ip(), user, "admin-network-denied", path[:200], ok=False)
                self.json({"error": "administrative access is available only from the local network"}, 403)
                return None
            if acct.get("privacy_version") != accounts.PRIVACY_VERSION:
                if path == "/api/me" or path == "/api/privacy/accept" or path in ("/privacy", "/privacy/accept") or path.startswith("/") and path.rsplit("/", 1)[-1] in (
                        "styles.css", "favicon.ico"):
                    return user
                self.drain()
                if path.startswith("/api/"):
                    self.json({"error": "privacy notice acceptance required", "privacy_required": True}, 428)
                else:
                    self.redirect("/privacy")
                return None
        return user

    def authorize(self, user, path, method, q=None, body=None):
        """Enforce capability permissions on every API route before dispatch (deny by default)."""
        q, body = q or {}, body or {}
        if user.startswith("api:"):
            return True
        acct = accounts.get(user)
        if accounts.access_problem(acct, self.client_ip()):
            return False
        if acct.get("role") == "root":
            return True
        cap = route_cap(path, method, q, body)
        if cap in accounts.ROOT_ONLY or cap is None:
            return False
        if cap == "office.admin":  # office moderation: the administrative flag, not the administrator role
            return accounts.is_administrative(acct)
        if acct.get("role") == "admin":
            return True
        held = accounts.capabilities(acct)
        if cap == "account.self":
            return True
        if cap == "files.any":  # drive list / own jobs: any file capability plus at least one zone
            return bool(held & accounts.FILE_CAPS) and bool(accounts.zones(user))
        if cap == "serving.view":  # the serving state: full with serving.read, own links only with files.share
            return bool(held & {"serving.read", "files.share"})
        if cap not in held:
            return False
        if cap in accounts.FILE_CAPS and not path.startswith(("/api/serving/link/delete", "/api/serving/link/alias")):
            return self.authorize_zone(user, acct, path, method, q, body, cap)
        return True

    def authorize_zone(self, user, acct, path, method, q, body, cap):
        """File routes: every path the request touches must lie in a zone that allows the needed capability."""
        z_list = accounts.zones(user)
        if not z_list:
            return False

        def ok(mount, rel, need):
            if mount is None or str(mount) in ("", "all"):
                return False
            rel = files.rel_of(files.parts_of(str(rel or "/")))
            if need not in accounts.file_caps_at(user, mount, rel, acct, z_list):
                return False
            m = files.get_mount(mount)
            full, _ = files.resolve(m, rel)
            actual = files.rel_of(os.path.relpath(os.path.realpath(full), os.path.realpath(files.root_of(m))).split(os.sep))
            return need in accounts.file_caps_at(user, mount, actual, acct, z_list)

        def whole_drive(mount, need):  # trash, recent files and analysis span a whole drive
            return ok(mount, "/", need) and any(str(z["mount"]) == str(mount) and z["path"].rstrip("/") == ""
                                                and need in z["caps"] for z in z_list)
        try:
            zip_match = re.fullmatch(r"/api/files/zip/([A-Za-z0-9_-]+)", path)
            if zip_match:
                z = files.ZIPS.get(zip_match.group(1))
                return bool(z and z.get("exp", 0) >= time.time()) and all(
                    ok(z["mount"], files.rel_of(parts), "files.download") for _, parts in z["items"])
            mount = body.get("mount", q.get("mount"))
            if re.match(r"^/api/upload/[0-9a-f]{24}/", path):  # chunks / finish: bound to the stored destination
                db = core.connect()
                try:
                    row = db.execute("SELECT mount,path FROM upload WHERE id=? AND user=?", [path.split("/")[3], user]).fetchone()
                finally:
                    db.close()
                return bool(row) and ok(row[0], row[1], "files.upload")
            if path in ("/api/files/recent", "/api/files/trash", "/api/files/restore", "/api/files/empty-trash",
                        "/api/files/trash/delete") or path.startswith("/api/analyze/"):
                return whole_drive(mount, cap)
            if path == "/api/uploads":
                return True  # upload sessions are bound to their owner
            paths = [p.get("path") if isinstance(p, dict) else p for p in body.get("paths") or []]
            if path == "/api/files/rename":
                return ok(mount, body.get("from"), cap) and ok(mount, body.get("to"), cap)
            if path in ("/api/files/move", "/api/files/copy"):
                src_need = "files.move" if path.endswith("move") else "files.read"
                return bool(paths) and all(ok(mount, p, src_need) for p in paths) and \
                    ok(body.get("dest_mount") or mount, body.get("dest"), cap)
            if path == "/api/upload/url":
                return ok(mount, body.get("dest"), cap)
            if path in ("/api/files/delete", "/api/files/zip", "/api/files/purge", "/api/upload/check"):
                return bool(paths) and all(ok(mount, p, cap) for p in paths)
            if path == "/api/files/search":
                return ok(mount, q.get("within", "/"), cap)
            target = body.get("path") if method == "POST" else q.get("path", "/")
            return ok(mount, target if target is not None else "/", cap)
        except Exception:
            return False

    def fail(self, e):
        if isinstance(e, files.FileError):
            return self.json({"error": str(e)}, e.code)
        if isinstance(e, network.NetError):
            return self.json({"error": str(e)}, 400)
        if isinstance(e, (rules.ServeError, anubis.BotError)):
            return self.json({"error": str(e)}, 400)
        if local and isinstance(e, local.ERRORS):
            return self.json({"error": str(e)}, 400)
        if isinstance(e, cloudflare.CFError):
            return self.json({"error": "Cloudflare: %s" % e, "status": e.status}, 502)
        if isinstance(e, (ValueError, KeyError, TypeError)):
            return self.json({"error": "bad request: %s" % e}, 400)
        if isinstance(e, (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)):
            return None
        log("api error:\n" + traceback.format_exc())
        return self.json({"error": str(e)[:300]}, 500)

    def secure(self):
        return (self.headers.get("X-Forwarded-Proto") or "").lower() == "https"

    def dashboard_base(self):
        """Where activation / reset links point: strata.json "dashboard_url" if set, else the address root is using
        right now (that request already passed the Origin == Host check). Not public_base_url - that is the CDN, which
        does not serve the dashboard."""
        base = str(CFG.get("dashboard_url") or "").rstrip("/")
        if base:
            return base
        host = (self.headers.get("Host") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9.\-\[\]:]{1,255}", host):
            host = "localhost"
        return ("https" if self.secure() else "http") + "://" + host

    def cookie(self, name, value, max_age, path="/"):
        return "%s=%s; Path=%s; HttpOnly; SameSite=Strict; Max-Age=%d%s" % (
            name, value, path, max_age, "; Secure" if self.secure() else "")

    # -- GET
    def loopback(self):
        try:
            host = urllib.parse.urlsplit("//" + (self.headers.get("Host") or ""))
            if host.username or host.password or host.path or host.query or host.fragment:
                return False
            local_host = host.hostname == "localhost" or ipaddress.ip_address(host.hostname or "").is_loopback
            return local_host and ipaddress.ip_address(self.client_ip()).is_loopback
        except ValueError:
            return False

    def do_GET(self):
        path, q = self.query()
        if path == "/setup":
            if CFG["auth"].get("password_hash"):
                return self.redirect("/login")
            if not self.loopback():
                return self.redirect("/login?e=setup_local")
            msg = SETUP_ERRORS.get(q.get("e"))
            return self.html_page("setup.html", dict(page_vars(), **{
                "<!--ERROR-->": '<div class="err">%s</div>' % msg if msg else "", "<!--FACTOR-->": setup_factor()}))
        if path == "/login":
            if not CFG["auth"].get("password_hash") and q.get("e") != "setup_local":
                return self.redirect("/setup" if self.loopback() else "/login?e=setup_local")
            if self.user():
                return self.redirect("/")
            msg = {"1": "Wrong username or password.", "locked": "Too many attempts. Try again in 15 minutes.",
                   "expired": "That took too long. Sign in again.",
                   "local": "Administrators can sign in only from the local network.",
                   "email": "Couldn't send your sign-in code. Ask the owner to check the e-mail setup.",
                   "setup_required": "The owner has no way to get a sign-in code. On the server, run: python auth.py --totp",
                   "signups_disabled": "Sign-ups are turned off on this site.",
                   "enrolled": "Account set up. Sign in with your new password.",
                   "owner": "Owner created. Sign in to continue.",
                   "setup_local": "No owner yet. Open /setup in a browser on the machine Strata runs on, "
                                  "or run python setup.py there.",
                   "acct_expired": "Your access has ended. Ask an administrator to extend it.",
                   "acct_network": "This account can't sign in from this network."}.get(q.get("e"))
            return self.html_page("login.html", dict(page_vars(), **{"<!--ERROR-->": '<div class="err">%s</div>' % msg if msg else ""}))
        if path == "/login/2fa":
            if (App.pending.get(auth.cookie_value(self.headers.get("Cookie"), auth.PENDING_COOKIE)) or {}).get("step") != "app":
                return self.redirect("/login?e=expired")
            msg = {"1": "That code didn't match. Codes change every 30 seconds.",
                   "locked": "Too many attempts. Try again in 15 minutes."}.get(q.get("e"))
            return self.html_page("login2fa.html", dict(page_vars(), **{"<!--ERROR-->": '<div class="err">%s</div>' % msg if msg else ""}))
        if path == "/login/otp":
            if (App.pending.get(auth.cookie_value(self.headers.get("Cookie"), auth.PENDING_COOKIE)) or {}).get("step") != "email":
                return self.redirect("/login?e=expired")
            msg = {"1": "That code didn't match or has expired.", "locked": "Too many attempts. Try again in 15 minutes."}.get(q.get("e"))
            return self.html_page("loginotp.html", dict(page_vars(), **{"<!--ERROR-->": '<div class="err">%s</div>' % msg if msg else ""}))
        if path == "/privacy":
            user = self.user()
            if user and (accounts.get(user) or {}).get("privacy_version") == accounts.PRIVACY_VERSION:
                return self.redirect("/")
            return self.html_page("privacy.html", page_vars())
        if path in ("/signup", "/register"):
            if not accounts.signups_allowed():
                return self.redirect("/login?e=signups_disabled")
            return self.redirect("/enroll")
        if path == "/enroll":
            tok = q.get("token", "")
            if not tok and not accounts.signups_allowed():
                return self.redirect("/login?e=signups_disabled")
            return self.html_page("enroll.html", dict(page_vars(), **{"{{INVITE}}": urllib.parse.quote(tok)}))
        if path in ("/login.html", "/login2fa.html", "/loginsetup.html", "/login/setup"):
            return self.redirect("/login")
        if path in PUBLIC_STATIC:
            return self.static(path)
        user = self.guard(path)
        if not user:
            return
        if path.startswith("/api/") and not self.authorize(user, path, "GET", q):
            core.audit(self.client_ip(), user, "access-denied", path[:200], ok=False)
            return self.json({"error": "this account can't open this. Ask an administrator for access."}, 403)
        try:
            return self.get_routes(user, path, q)
        except Exception as e:
            return self.fail(e)

    def send_avatar(self, user, q):
        """Profile picture (re-encoded WebP). Own picture for everyone; colleagues' with office access (only accounts
        that appear in the office); any with account management."""
        target = str(q.get("user") or user)
        t_acct = accounts.get(target)
        if target.lower() != user.lower() and not accounts.has(user, "accounts.manage") and not (
                accounts.has(user, "office.view") and t_acct and target.lower() in office.member_names()):
            return self.json({"error": "not your profile picture"}, 403)
        p = accounts.avatar_file(t_acct)
        if not p:
            return self.json({"error": "no profile picture"}, 404)
        with open(p, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "image/webp")
        self.send_header("Content-Security-Policy", RAW_CSP)
        self.send_header("Cache-Control", "private, max-age=31536000, immutable")  # the URL carries ?v=<version>
        self.send_header("Content-Length", str(len(body)))
        self.common_headers()
        self.end_headers()
        self.wfile.write(body)

    def get_routes(self, user, path, q):
        if path == "/api/avatar":
            return self.send_avatar(user, q)
        if path.startswith("/api/media/"):  # Strata Media admin API (media_bridge, DESIGN 13.2)
            r = media_bridge.api_get(user, path, q)
            return self.json(r) if r is not None else self.json({"error": "not found"}, 404)
        if path == "/api/live":
            snap = App.metrics.snapshot()
            snap.update(App.probes.snapshot())
            db = core.connect()
            try:
                open_alerts = dict(db.execute("SELECT severity, count(*) FROM alert WHERE ack=0 GROUP BY severity").fetchall())
                bl = db.execute("SELECT count(*) FROM blacklist WHERE enabled=1 AND (expires IS NULL OR expires > ?)",
                                [time.time()]).fetchone()[0]
            finally:
                db.close()
            snap.update(now=time.time(), series=App.live.series(300), win=App.live.window(60),
                        win5=App.live.window(300), recent=App.live.tail(40) if accounts.has(user, "analytics.visitors") else [], db=core.db_info(),
                        compress=App.compressor.status(), user=user, sessions=App.sessions.count(),
                        alerts=open_alerts, blacklist=bl, totp=bool(CFG["auth"].get("totp_secret")))
            return self.json(snap)
        if path == "/api/backup":
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", "attachment; filename=%s" % backup.name())
            self.send_header("Cache-Control", "no-store")
            self.common_headers()
            self.end_headers()
            self.close_connection = True
            backup.write(self.wfile)
            core.audit(self.client_ip(), user, "backup", "")
            return None
        if path.startswith("/api/files/zip/"):
            z = files.zip_take(path.rsplit("/", 1)[-1])
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", "attachment; filename*=UTF-8''%s" % urllib.parse.quote(z["name"]))
            self.send_header("Cache-Control", "no-store")
            self.common_headers()
            self.end_headers()
            self.close_connection = True
            files.zip_write(z, self.wfile)
            core.audit(self.client_ip(), user, "zip", z["name"])
            return None
        if path == "/api/files/raw":
            return self.send_raw(*files.raw_info(q.get("mount"), q.get("path", ""), q.get("ver")), q.get("download") == "1")
        if path == "/api/files/preview":
            return self.file_preview(q)
        if path == "/api/files/thumb":
            p = files.thumbnail(q.get("mount"), q.get("path", ""), q.get("w"))
            with open(p, "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "image/webp")
            self.send_header("Cache-Control", "private, max-age=86400")
            self.send_header("Content-Length", str(len(body)))
            self.common_headers()
            self.end_headers()
            self.wfile.write(body)
            return None
        if path.startswith("/api/serving/history/"):
            db = core.connect()
            try:
                row = db.execute("SELECT content FROM confhist WHERE id=?", [int(path.rsplit("/", 1)[-1])]).fetchone()
            finally:
                db.close()
            return self.json({"content": row[0] if row else ""})
        routes = {
            "/api/stats": lambda: self.analytics(user, core.q_stats(q)),
            "/api/insights": lambda: self.analytics(user, core.q_insights(q)),
            "/api/requests": lambda: core.q_requests(q),
            "/api/ip": lambda: core.q_ip(q),
            "/api/history": lambda: core.q_history(q),
            "/api/edge": lambda: core.q_edge(q),
            "/api/compression": lambda: compress.q_compression(q, App.compressor),
            "/api/audit": lambda: self.account_activity(user, q),
            "/api/files": lambda: files.listdir(q.get("mount"), q.get("path", "/"), q.get("sort", "name"),
                                                q.get("desc") == "1", q.get("q", ""), q.get("cat", ""),
                                                int(q.get("offset") or 0), int(q.get("limit") or 0) or None,
                                                q.get("hidden", "1") != "0", q.get("focus", "")),
            "/api/files/tree": lambda: files.tree(q.get("mount"), q.get("path", "/")),
            "/api/files/recent": lambda: files.recent(q.get("mount"), q.get("limit", 60)),
            "/api/analyze/find": lambda: analyze.find(q),
            "/api/analyze/growth": lambda: analyze.growth(q),
            "/api/analyze/folders": lambda: analyze.hot_folders(q),
            "/api/network/status": network.status,
            "/api/network/settings": lambda: network.settings(q.get("force") == "1"),
            "/api/network/dns": lambda: network.dns_list(q.get("force") == "1"),
            "/api/network/ingress": network.ingress,
            "/api/network/listening": lambda: {"ports": network.listening(), "reserved": sorted(network.reserved_ports())},
            "/api/system": self.system,
            "/api/logs": lambda: self.logs(q),
            "/api/files/search": lambda: files.search(q.get("mount"), q.get("q"), q.get("within", "/")),
            "/api/files/info": lambda: files.info(q.get("mount"), q.get("path", ""), self.dup_filter(user)),
            "/api/files/versions": lambda: files.versions(q.get("mount"), q.get("path", "")),
            "/api/files/text": lambda: files.read_text(q.get("mount"), q.get("path", "")),
            "/api/files/trash": lambda: dict(files.trash_list(q.get("mount"), sync=True), cdn=cloudflare.purge_status()),
            "/api/uploads": lambda: files.up_list(user),
            "/api/jobs": lambda: self.scoped_jobs(user),
            "/api/drives": lambda: self.scoped_drives(user) if (accounts.get(user) or {}).get("role") not in ("root", "admin") else files.drives(),
            "/api/fs": lambda: files.browse_dirs(q.get("path")),
            "/api/analyze/overview": lambda: analyze.overview(q),
            "/api/analyze/tree": lambda: analyze.tree(q),
            "/api/analyze/dupes": lambda: analyze.duplicates(q),
            "/api/analyze/list": lambda: analyze.listing(q),
            "/api/serving": lambda: self.serving_state(user),
            "/api/prefs": lambda: {"prefs": accounts.get_prefs(user)},
            "/api/serving/test": lambda: rules.test_url(q.get("url", ""), q.get("ip", ""), q.get("ua", ""),
                                                        q.get("country", ""), q.get("referer", "")),
            "/api/cloudflare": self.cf_state,
            "/api/bots": anubis.state,
            "/api/alerts": lambda: alerts.q_alerts(q),
            "/api/me": lambda: self.me(user),
            "/api/instance": instance_info,
            "/api/branding": branding,  # not in ROUTE_CAPS: administrators only
            "/api/settings/signups": lambda: {"allowed": accounts.signups_allowed(), "locked_by_env": bool(__import__("os").environ.get("ALLOW_SIGNUPS") is not None or __import__("os").environ.get("STRATA_ALLOW_SIGNUPS") is not None)},
            "/api/accounts": lambda: self.accounts_list(user),
            "/api/office": lambda: self.office_state(user),
            "/api/office/board": lambda: office.board(accounts.get(user), q.get("before") or None),
            "/api/office/notes": lambda: office.notes_for(accounts.get(user), q.get("user", "")),
            "/api/ide/tree": self.ide_tree,
            "/api/ide/read": lambda: self.ide_read(q),
        }
        if local:
            routes.update(local.get_routes(q))
        if path in routes:
            return self.json(routes[path]())
        return self.static(path)

    def analytics(self, user, data):
        if not accounts.has(user, "analytics.visitors"):
            for key in ("ips", "scanners", "clients"):
                if key in data:
                    data[key] = []
        return data

    def cf_state(self):
        db = core.connect()
        try:
            st = {"sync": core.get_meta(db, "cf_sync"), "purge": core.get_meta(db, "cf_purge"),
                  "edge_enabled": core.get_meta(db, "cf_edge_enabled", True),
                  "autopurge": core.get_meta(db, "cf_autopurge", True)}
        finally:
            db.close()
        st["queue"] = cloudflare.purge_status()
        st["caps"] = cloudflare.capabilities()
        st["perms"] = cloudflare.PERMS
        return st

    def office_state(self, user):
        acct = accounts.get(user)
        return {"people": office.people(acct), "unread": office.unread(user),
                "administrative": accounts.is_administrative(acct),
                "caps": sorted(accounts.capabilities(acct) & accounts.OFFICE_CAPS),
                "office_permissions": [{"id": p, "label": l, "description": d}
                                       for p, l, g, d in accounts.PERMISSIONS if g == "office"]}

    def presence_beat(self, user, b):
        """Heartbeat from an open dashboard: records this tab's state and answers with what the account may see -
        everyone's presence with office access, otherwise only its own - plus unread office counts."""
        if user.startswith("api:"):
            return {"presence": {}}
        if b.get("leave"):
            office.PRESENCE.leave(user, b.get("tab"))
            return {"left": True}
        office.PRESENCE.beat(user, b.get("tab"), b.get("state"))
        acct = accounts.get(user)
        if accounts.has(user, "office.view"):
            return {"presence": office.presence_map(office._members()), "unread": office.unread(user)}
        return {"presence": office.presence_map([acct])}

    def me(self, user):
        a = CFG["auth"]
        acct = accounts.get(user) or {}
        if user.startswith("api:"):
            permissions = sorted(accounts.PERMISSION_IDS | accounts.ROOT_ONLY)
        else:
            permissions = sorted(accounts.capabilities(acct))
        return {"user": user, "email": acct.get("email", ""), "role": acct.get("role", "employee"),
                "capabilities": permissions, "zones": accounts.effective_zones(user, acct) if acct else [],
                "administrative": accounts.is_administrative(acct) if acct else False,
                "profile": office.profile_of(acct),
                "avatar": (acct.get("avatar") or "")[:8], "expires": acct.get("expires"),
                "session_hours": acct.get("session_hours"),
                "email_verified": bool(acct.get("email_verified")),
                "privacy_accepted": acct.get("privacy_version") == accounts.PRIVACY_VERSION,
                "totp": bool(a.get("totp_secret")) if acct.get("role") == "root" else False,
                "recovery_left": len(a.get("recovery") or []) if acct.get("role") == "root" else 0,
                "sessions": App.sessions.count(), "autoban": CFG["autoban"], "bots": bool(CFG["anubis"]["enabled"]), "upload": CFG["upload"],
                "versions_keep": CFG.get("versions_keep"), "links": CFG["links"],
                "smartsort": dict(CFG["smartsort"], home=smart_home(user))}

    def system(self):
        """Health of this instance: its processes / ports, database tables, rollups, retention."""
        import socket
        info = instance_info()

        def up(addr):
            try:
                host, port = str(addr).rsplit(":", 1)
                with socket.create_connection((host or "127.0.0.1", int(port)), timeout=0.5):
                    return True
            except (OSError, ValueError):
                return False
        tele = {}
        try:
            with open(os.path.join(core.HOME, "telemetry", "telemetry.json"), encoding="utf-8-sig") as f:
                tele = json.load(f)
        except (OSError, ValueError):
            pass
        procs = [{"name": "Strata admin", "addr": CFG["listen"], "up": True},
                 {"name": "Telemetry feed", "addr": CFG["feed_listen"], "up": up(CFG["feed_listen"])},
                 {"name": "Public stats page", "addr": tele.get("listen", ""), "up": up(tele.get("listen", ""))},
                 {"name": "Strata Transform", "addr": CFG["transform_listen"], "up": up(CFG["transform_listen"])},
                 {"name": "Service gate", "addr": CFG["gate_listen"], "up": up(CFG["gate_listen"])}]
        if CFG["media"].get("enabled"):
            procs.append({"name": "Strata Media", "addr": CFG["media"]["listen"], "up": up(CFG["media"]["listen"])})
        db = core.connect()
        try:
            try:
                tables = [{"name": n, "bytes": b} for n, b in db.execute(
                    "SELECT name, sum(pgsize) FROM dbstat GROUP BY name ORDER BY 2 DESC LIMIT 30")]
            except Exception:
                tables = []
            counts = {t: db.execute("SELECT count(*) FROM %s" % t).fetchone()[0]
                      for t in ("req", "agg_m", "agg_h", "agg_pd", "visitor", "fidx", "alert", "audit",
                                "audit_event", "account", "account_zone")}
            roll = core.get_meta(db, "rollup_v1") or {}
        finally:
            db.close()
        return {"instance": info, "processes": procs, "tables": tables, "counts": counts, "rollup": roll,
                "raw_max": rollup.RAW_MAX, "retention_days": CFG["retention_days"],
                "raw_retention_days": CFG.get("raw_retention_days"), "db": core.db_info(), "pid": os.getpid(),
                "started": App.started, "python": __import__("sys").version.split()[0],
                "runtime_log": {"path": core.RUNTIME_LOG_PATH, "bytes": os.path.getsize(core.RUNTIME_LOG_PATH)
                                if os.path.exists(core.RUNTIME_LOG_PATH) else 0}}

    def logs(self, q):
        source = q.get("source", "runtime")
        if source == "activity":
            user = self.user()
            if not user or not accounts.has(user, "audit.read"):
                raise files.FileError(403, "account activity access requires the audit.read permission")
            return dict(source=source, **core.q_audit(q))
        if source == "access":
            params = dict(q)
            params.setdefault("limit", 250)
            params.setdefault("since", 86400)
            return dict(source=source, **core.q_requests(params))
        return core.q_runtime_logs(q)

    def account_activity(self, user, q):
        if accounts.has(user, "audit.read"):
            return core.q_audit(q)
        return core.q_audit(dict(q, user=user))

    def dup_filter(self, user):
        """Scoped accounts only learn about duplicates that sit inside their own zones."""
        if (accounts.get(user) or {}).get("role") in ("root", "admin"):
            return None
        zl = accounts.zones(user)
        return lambda mount, path: bool(accounts.file_caps_at(user, mount, path, z_list=zl))

    def scoped_drives(self, user):
        # Employees see assigned file mounts only, with their own grant roots instead of host paths.
        allowed = {}
        for zone in accounts.effective_zones(user):
            allowed.setdefault(int(zone["mount"]), []).append(zone)
        served = []
        for drive in files.served():
            grants = allowed.get(int(drive["mount"]), [])
            if not grants:
                continue
            item = {k: v for k, v in drive.items() if k != "path"}
            item["zone_roots"] = [{"path": z["path"], "access": z["access"], "caps": z["effective"]} for z in grants]
            item["zone_path"] = grants[0]["path"]
            item["zone_access"] = "write" if any(z["access"] == "write" for z in grants) else "read"
            served.append(item)
        return {"drives": [], "served": served}

    def scoped_jobs(self, user):
        jobs = files.job_list().get("jobs", [])
        return {"jobs": [job for job in jobs if job.get("user") == user]}

    def serving_state(self, user):
        """Serving configuration: complete with serving.read; with only files.share, the account's own links and the
        drives it may share from (the share editor needs mounts + links; rules, blacklist and gate users stay hidden)."""
        st = rules.state()
        if user.startswith("api:") or accounts.has(user, "serving.read"):
            return st
        shareable = {str(z["mount"]) for z in accounts.effective_zones(user) if "files.share" in z["effective"]}
        db = core.connect()
        try:
            mine = {r[0] for r in db.execute("SELECT code FROM link WHERE owner=? COLLATE NOCASE", [user])}
        finally:
            db.close()
        keep = ("id", "name", "kind", "prefix", "enabled")
        return {"mounts": [{k: m.get(k) for k in keep} for m in st.get("mounts", []) if str(m.get("id")) in shareable],
                "links": [l for l in st.get("links", []) if l.get("code") in mine and not l.get("url")],
                "rules": [], "blacklist": [], "history": [], "actions": st.get("actions"), "bl_kinds": st.get("bl_kinds"),
                "site": {"link_prefix": (st.get("site") or {}).get("link_prefix", "/l/")},
                "scoped": True}

    def link_allowed(self, user, code):
        """May `user` change the share link `code`? Its creator may; so may anyone holding serving.links."""
        if user.startswith("api:") or accounts.has(user, "serving.links"):
            return True
        db = core.connect()
        try:
            row = db.execute("SELECT owner FROM link WHERE code=?", [str(code or "")]).fetchone()
        finally:
            db.close()
        return bool(row and row[0] and row[0].lower() == user.lower())

    def accounts_list(self, user):
        return {"accounts": accounts.all_accounts(),
                "permissions": [{"id": p, "label": label, "group": g, "description": d} for p, label, g, d in accounts.PERMISSIONS],
                "groups": accounts.GROUPS, "file_caps": sorted(accounts.FILE_CAPS), "presets": list(accounts.PRESETS.values()),
                "drives": files.drives()}

    def ide_path(self, rel):
        rel = str(rel or "").replace("\\", "/").strip("/")
        parts = rel.split("/") if rel else []
        if not parts or any(p in ("", ".", "..") or p.startswith(".") for p in parts):
            raise files.FileError(400, "choose a source file inside the Strata code folder")
        if any(p.lower() in IDE_SKIP for p in parts) or os.path.splitext(parts[-1])[1].lower() not in IDE_EXTS:
            raise files.FileError(403, "this file is outside the web IDE scope")
        root = os.path.realpath(core.ROOT)
        full = os.path.realpath(os.path.join(root, *parts))
        try:
            if os.path.commonpath([root, full]) != root:
                raise files.FileError(403, "path outside the Strata code folder")
        except ValueError:
            raise files.FileError(403, "path outside the Strata code folder")
        return full, "/".join(parts)

    def ide_tree(self):
        root = os.path.realpath(core.ROOT)
        entries, seen = [], 0
        for base, dirs, names in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs if d.lower() not in IDE_SKIP and not d.startswith(".")
                       and not os.path.islink(os.path.join(base, d))]
            rel_dir = os.path.relpath(base, root)
            for name in dirs:
                rel = os.path.join(rel_dir, name).replace(os.sep, "/") if rel_dir != "." else name
                entries.append({"path": rel, "name": name, "dir": True})
            for name in names:
                if name.startswith(".") or os.path.splitext(name)[1].lower() not in IDE_EXTS:
                    continue
                full = os.path.join(base, name)
                try:
                    if os.path.islink(full) or os.path.getsize(full) > (2 << 20):
                        continue
                except OSError:
                    continue
                rel = os.path.join(rel_dir, name).replace(os.sep, "/") if rel_dir != "." else name
                entries.append({"path": rel, "name": name, "dir": False, "bytes": os.path.getsize(full)})
                seen += 1
                if seen >= 4000:
                    break
            if seen >= 4000:
                break
        entries.sort(key=lambda e: (not e["dir"], e["path"].lower()))
        return {"files": entries}

    def ide_read(self, q):
        full, rel = self.ide_path(q.get("path"))
        if not os.path.isfile(full) or os.path.islink(full):
            raise files.FileError(404, "source file not found")
        size = os.path.getsize(full)
        if size > (2 << 20):
            raise files.FileError(413, "web IDE file limit is 2 MiB")
        raw = read_file(full)
        if b"\x00" in raw[:8192]:
            raise files.FileError(415, "binary file")
        try:
            source = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            raise files.FileError(415, "source file is not valid UTF-8")
        return {"path": rel, "text": source, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": size,
                "modified": os.path.getmtime(full)}

    def ide_save(self, user, ip, body):
        full, rel = self.ide_path(body.get("path"))
        source = body.get("text")
        if not isinstance(source, str) or len(source.encode("utf-8")) > (2 << 20):
            raise files.FileError(413, "source must be text no larger than 2 MiB")
        if rel.lower().endswith(".py"):
            try:
                compile(source, rel, "exec")
            except SyntaxError as e:
                raise files.FileError(400, "Python syntax error at line %s: %s" % (e.lineno, e.msg))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with IDE_LOCK:
            exists = os.path.isfile(full)
            old = read_file(full) if exists else b""
            old_hash = hashlib.sha256(old).hexdigest() if exists else ""
            if body.get("expect_sha") != old_hash:
                raise files.FileError(409, "file changed since it was opened; reload before saving")
            backup = ""
            if exists:
                backup_dir = os.path.join(core.HOME, "data", "ide-backups", hashlib.sha256(rel.encode()).hexdigest()[:24])
                os.makedirs(backup_dir, exist_ok=True)
                backup = os.path.join(backup_dir, "%d-%s" % (int(time.time() * 1000), os.path.basename(rel)))
                shutil.copy2(full, backup)
                old_backups = sorted((os.path.join(backup_dir, n) for n in os.listdir(backup_dir)),
                                     key=os.path.getmtime, reverse=True)
                for stale in old_backups[20:]:
                    try:
                        os.remove(stale)
                    except OSError:
                        pass
            fd, temp = tempfile.mkstemp(prefix=".strata-ide-", suffix=".tmp", dir=os.path.dirname(full))
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(source.encode("utf-8"))
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(temp, full)
            except BaseException:
                try:
                    os.remove(temp)
                except OSError:
                    pass
                raise
        digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
        core.audit(ip, user, "ide-save", rel, note="%d bytes · sha256 %s" % (len(source.encode("utf-8")), digest[:16]))
        return {"saved": True, "path": rel, "sha256": digest, "backup": bool(backup), "restart_required": True}

    def file_preview(self, q):
        """The link preview of a file or folder as crawlers would get it, for the Files inspector: the card (JPEG) or,
        with ?meta=1, its title / description / colour and the rule that names this path. ?draft= (JSON) previews
        unsaved settings on top of the other rules; ?skip= leaves out the rule being edited."""
        m = files.get_mount(q.get("mount"))
        full, parts = files.resolve(m, q.get("path", ""))
        if not os.path.exists(full):
            raise files.FileError(404, "not found")
        is_dir = os.path.isdir(full)
        rel = "/" + "/".join(parts)
        url_path = ("" if m["prefix"] == "/" else m["prefix"]) + rel + ("/" if is_dir and parts else "")
        skip = int(q["skip"]) if str(q.get("skip") or "").isdigit() else None
        ov, exact = rules.preview_settings(m["id"], url_path, is_dir, skip)
        if q.get("draft"):
            try:
                draft = json.loads(q["draft"])
            except ValueError:
                raise files.FileError(400, "draft is not JSON")
            draft = rules.clean_rule({"action": "preview", "patterns": ["/x"], "params": draft})["params"]
            ov = {k: v for k, v in ov.items() if k in ("color", "kind", "off")}  # the draft is this path's own rule
            ov.update(draft)
        tdir = os.path.join(core.ROOT, "transform")
        if tdir not in sys.path:
            sys.path.insert(0, tdir)
        import audiocard
        import cards
        cache_dir = os.path.join(core.HOME, "data", "tcache")
        kind = ov.get("kind", "")
        st = None if is_dir else os.stat(full)
        audio = not is_dir and (kind == "audio" or (not kind and os.path.splitext(full)[1].lower() in audiocard.AUDIO_EXT))
        native = not is_dir and re.search(rules.PREVIEW_NATIVE_RX, full) is not None
        gallery = False
        if is_dir:
            db = core.connect()
            try:
                galleries = [r for r in rules.load(db)["rules"] if r["action"] == "gallery" and rules.active(r)
                             and (not r["mount"] or r["mount"] == m["id"])]
            finally:
                db.close()
            gallery = any(rules.rule_matches(dict(r, patterns=rules.gallery_patterns(r["patterns"])), url_path.rstrip("/"))
                          for r in galleries)
        if native or (is_dir and not gallery):  # crawlers never get a Strata card here
            if q.get("meta"):
                return self.json({"native": native, "folder_without_gallery": is_dir and not gallery, "url_path": url_path})
            raise files.FileError(404, "no link preview here")
        where = url_path.rstrip("/").rsplit("/", 1)[0] + "/"
        if audio:
            data, info = audiocard.card(full, st, cache_dir, ov)
        else:
            data, info = cards.card(full, st, cache_dir, is_dir, where, ov)
        if q.get("meta"):
            return self.json({"title": info.get("title"), "description": info.get("description") or "", "color": info.get("color"),
                    "kind": info.get("kind") or ("audio" if audio else ""), "url_path": url_path, "host": (m["hosts"] or [""])[0],
                    "settings": ov, "rule": {"id": exact["id"], "params": exact["params"]} if exact else None,
                    "native": native, "folder_without_gallery": False})
        self.send_response(200)
        self.send_header("Content-Type", "image/jpeg")
        self.send_header("Cache-Control", "private, no-store")
        self.send_header("Content-Length", str(len(data)))
        self.common_headers()
        self.end_headers()
        self.wfile.write(data)
        return None

    def send_raw(self, full, size, ctype, name, download):
        start, end, code = 0, max(0, size - 1), 200
        m = re.fullmatch(r"bytes=(\d*)-(\d*)", self.headers.get("Range") or "")
        if m and size and (m.group(1) or m.group(2)):
            if m.group(1):
                start = int(m.group(1))
                end = min(int(m.group(2)), size - 1) if m.group(2) else size - 1
            else:
                start = max(0, size - int(m.group(2)))
            if start > end:
                self.send_response(416)
                self.send_header("Content-Range", "bytes */%d" % size)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            code = 206
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Security-Policy", RAW_CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Cache-Control", "private, max-age=60")
        self.send_header("Content-Length", str(end - start + 1 if size else 0))
        if code == 206:
            self.send_header("Content-Range", "bytes %d-%d/%d" % (start, end, size))
        self.send_header("Content-Disposition", "%s; filename*=UTF-8''%s" % ("attachment" if download else "inline",
                                                                          urllib.parse.quote(name)))
        self.common_headers()
        self.end_headers()
        if not size:
            return
        with open(full, "rb") as f:
            f.seek(start)
            left = end - start + 1
            while left:
                buf = f.read(min(left, 1 << 20))
                if not buf:
                    break
                self.wfile.write(buf)
                left -= len(buf)

    # -- POST
    def do_POST(self):
        try:
            return self._do_POST()
        except Exception as e:
            self.drain()
            return self.fail(e)

    def _do_POST(self):
        self.rfile = CountingReader(self.rfile)
        path, q = self.query()
        if path in ("/login", "/login/otp", "/enroll", "/login/2fa", "/setup") and not self.form_origin_ok():
            self.drain()
            return self.json({"error": "cross-site request refused"}, 403)
        if path == "/login":
            return self.login()
        if path == "/setup":
            return self.owner_setup()
        if path == "/login/otp":
            return self.login_otp()
        if path == "/enroll":
            return self.enroll()
        if path == "/login/2fa":
            return self.login_2fa()
        user = self.guard(path)
        if not user:
            return
        if not self.csrf_ok(path):
            self.drain()
            return self.json({"error": "cross-site request refused"}, 403)
        ip = self.client_ip()
        try:
            if path == "/logout":
                App.sessions.drop(auth.cookie_value(self.headers.get("Cookie")))
                core.audit(ip, user, "logout", "")
                self.send_response(204)
                self.send_header("Set-Cookie", self.cookie(auth.COOKIE, "", 0))
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if path == "/api/account/avatar":  # raw image body; decoded and re-encoded by accounts.set_avatar
                n = files.content_length(self.headers, accounts.AVATAR_MAX_BYTES)
                if user.startswith("api:"):
                    raise files.FileError(400, "API keys have no profile")
                try:
                    accounts.set_avatar(user, self.rfile.read(n))
                except ValueError as e:
                    raise files.FileError(400, str(e))
                core.audit(ip, user, "account.avatar.set", "")
                return self.json({"avatar": ((accounts.get(user) or {}).get("avatar") or "")[:8]})
            if path == "/api/backup/restore":  # raw zip body, streamed to disk
                if not self.authorize(user, path, "POST", q):
                    self.drain()
                    return self.json({"error": "only the owner can restore a backup"}, 403)
                left = files.content_length(self.headers)
                if not left:
                    raise files.FileError(400, "choose a backup zip")
                fd, tmp = tempfile.mkstemp(prefix=".strata-upload-", suffix=".zip", dir=os.path.dirname(core.DB_PATH))
                try:
                    with os.fdopen(fd, "wb") as f:
                        while left > 0:
                            buf = self.rfile.read(min(left, 1 << 20))
                            if not buf:
                                raise files.FileError(400, "the upload stopped early")
                            f.write(buf)
                            left -= len(buf)
                    backup.restore(tmp)
                except ValueError as e:
                    raise files.FileError(400, str(e))
                finally:
                    os.remove(tmp)
                rules.APPLY_SOON.set()  # Caddy config from the restored drives and rules
                core.audit(ip, user, "backup.restore", "")
                return self.json({"restored": True})
            m = re.fullmatch(r"/api/upload/([0-9a-f]{24})/(complete|abort)", path)
            if m:
                if not self.authorize(user, path, "POST", q):
                    return self.json({"error": "this account does not have access to this storage area"}, 403)
                if m.group(2) == "abort":
                    return self.json(files.up_abort(user, m.group(1)))
                r = files.up_complete(user, m.group(1))
                self.after_upload(ip, user, r)
                return self.json(r)
            body = self.body_form() if path == "/privacy/accept" else self.body_json()
            if path.startswith("/api/") and not self.authorize(user, path, "POST", q, body):
                return self.json({"error": "this account can't do this. Ask an administrator for access."}, 403)
            if path == "/privacy/accept":
                if body.get("accept") != "yes":
                    raise files.FileError(400, "privacy notice acceptance is required")
                accounts.accept_privacy(user, ip)
                self.redirect("/")
                return
            r = self.post_routes(user, ip, path, body)
            if r is None:
                return self.json({"error": "not found"}, 404)
            return self.json(r)
        except Exception as e:
            core.audit(ip, user, path.rsplit("/", 1)[-1], "", ok=False, note=str(e)[:200])
            self.drain()
            return self.fail(e)

    def office_post(self, user, ip, path, b):
        """Office writes. Capability checks already ran (ROUTE_CAPS / route_cap); ownership and moderation rules are
        enforced in office.py. Audit entries name posts by id only - their text is not copied into the ledger."""
        if user.startswith("api:"):
            raise files.FileError(400, "API keys can’t use Team")
        acct = accounts.get(user)
        try:
            if path == "/api/office/profile":
                p = office.save_profile(user, b if isinstance(b, dict) else {}, own=True)
                core.audit(ip, user, "office.profile", user)
                return {"profile": p}
            if path == "/api/office/seen":
                office.mark_seen(user, str(b.get("what") or ""))
                return {"unread": office.unread(user)}
            if path == "/api/office/post":
                n = office.create(acct, b.get("body"), b.get("target") or "", bool(b.get("private")))
                core.audit(ip, user, "office.note" if n["target"] else "office.post", n["target"] or "board",
                           note="id=%d%s" % (n["id"], " private" if n["private"] else ""))
                return {"note": n}
            if path == "/api/office/post/edit":
                n = office.edit(acct, b.get("id"), b.get("body"))
                core.audit(ip, user, "office.edit", n["target"] or "board", note="id=%d" % n["id"])
                return {"note": n}
            if path == "/api/office/post/delete":
                r = office.delete(acct, b.get("id"))
                core.audit(ip, user, "office.delete", r["target"] or "board",
                           note="id=%d by %s" % (r["id"], "author" if r["author"].lower() == user.lower() else "moderation"))
                return {"deleted": r["id"]}
            if path == "/api/office/post/pin":
                r = office.pin(acct, b.get("id"), bool(b.get("pinned")))
                core.audit(ip, user, "office.pin" if b.get("pinned") else "office.unpin", "board", note="id=%d" % r["id"])
                return {"pinned": bool(b.get("pinned"))}
            if path == "/api/office/member":
                target = str(b.get("user") or "")
                out = {}
                if "caps" in b:
                    out["caps"] = office.set_member_caps(acct, target, b.get("caps") or [])
                    core.audit(ip, user, "office.member.caps", target, note=",".join(out["caps"]))
                if "title" in b or "department" in b:
                    t = accounts.get(target)
                    if not t or t["user"].lower() == user.lower() or acct.get("role") != "root" and (
                            t.get("role") in ("root", "admin") or accounts.is_administrative(t)):
                        raise PermissionError("You cannot change this colleague's profile")
                    out["profile"] = office.save_profile(target, {k: b[k] for k in ("title", "department") if k in b}, own=False)
                    core.audit(ip, user, "office.member.profile", target)
                return out
        except PermissionError as e:
            raise files.FileError(403, str(e))
        except LookupError as e:
            raise files.FileError(404, str(e))
        return None

    def after_upload(self, ip, user, r):
        if r.get("skipped"):
            return
        full = r.pop("full", None)
        core.audit(ip, user, "upload", "%s:%s" % (r["mount"], r["path"]), note="%d bytes%s" % (
            r["size"], " (replaced; old version kept)" if r.get("replaced") else ""))
        if full:
            App.compressor.enqueue(full)
            media_bridge.on_upload(r["mount"], r["path"], full)  # scan / prewarm only if configured (both off)
        purge_later(r)

    def reindex(self, mid, *paths):
        for p in paths:
            App.compressor.reindex(mid, (p or "/").rsplit("/", 1)[0] or "/")

    def post_routes(self, user, ip, path, b):
        if path.startswith("/api/media/"):  # Strata Media admin API (validates and audits itself)
            return media_bridge.api_post(user, ip, path, b)
        A = lambda action, target, note="": core.audit(ip, user, action, target, note=note)
        if local and path in local.POST:
            return local.POST[path](user, b, A)
        mid = b.get("mount")
        if path == "/api/ide/save":
            return self.ide_save(user, ip, b)
        if path.startswith("/api/2fa/") and (accounts.get(user) or {}).get("role") != "root":
            raise files.FileError(403, "only the owner can set up the authenticator app")
        if path == "/api/audit/events":
            events = b.get("events")
            if not isinstance(events, list) or len(events) > 100:
                raise files.FileError(400, "send up to 100 audit events at a time")
            allowed = {"view", "click", "change", "overlay", "view-duration", "client-error"}
            for evt in events:
                if not isinstance(evt, dict) or evt.get("kind") not in allowed:
                    continue
                target = str(evt.get("target") or "")
                if not re.fullmatch(r"[A-Za-z0-9:_./-]{1,120}", target):
                    continue
                action = "ui." + evt["kind"]
                note = ""
                if evt["kind"] == "view-duration":
                    try:
                        note = "seconds=%d" % max(0, min(86400, int(evt.get("seconds") or 0)))
                    except (TypeError, ValueError):
                        note = ""
                core.audit_event(ip, user, action, target, note=note)
            return {"accepted": True}
        if path == "/api/prefs":  # dashboard preferences synced to the account (Settings > Sync to my account)
            if user.startswith("api:"):
                raise files.FileError(400, "API keys have no preferences")
            accounts.set_prefs(user, b.get("prefs") or {})
            return {"saved": True}
        if path == "/api/account/avatar/delete":
            accounts.clear_avatar(user)
            A("account.avatar.remove", user)
            return {"removed": True}
        if path == "/api/account/email/begin":
            acct = accounts.get(user) or {}
            if not auth.verify_password(str(b.get("current") or ""), acct.get("password_hash") or ""):
                raise files.FileError(400, "current password is incorrect")
            email = str(b.get("email") or "").strip().lower()
            accounts.send_code(user, email, App.alerts, ip, "email-change")
            return {"sent": True, "email": email}
        if path == "/api/account/email/verify":
            email = accounts.verify_code(user, b.get("code"), "email-change")
            if not email:
                raise files.FileError(400, "verification code is invalid or expired")
            accounts.confirm_email(user, email)
            A("account.email-verified", "address updated")
            return {"verified": True, "email": email}
        if path == "/api/presence":
            return self.presence_beat(user, b)
        if path.startswith("/api/office/"):
            return self.office_post(user, ip, path, b)
        if path == "/api/accounts/administrative":  # root (accounts.manage via route_cap) marks office administrators
            target = str(b.get("user") or "")
            if target.lower() == user.lower():
                raise files.FileError(400, "you cannot change your own administrative flag")
            accounts.set_administrative(target, bool(b.get("administrative")))
            A("account.administrative", target, "on" if b.get("administrative") else "off")
            return {"account": accounts.public(accounts.get(target))}
        if path in ("/api/accounts/invite", "/api/accounts/create"):
            if not accounts.has(user, "accounts.manage"):
                raise files.FileError(403, "account management requires administrator access")
            actor = accounts.get(user) or {}
            invited_role = str(b.get("role") or "employee")
            preset = str(b.get("preset") or "")
            if preset and preset in accounts.PRESETS and preset != "custom":
                invited_role = accounts.PRESETS[preset]["role"]
                grants = list(accounts.PRESETS[preset]["permissions"])
            else:
                grants = b.get("permissions") or []
            if invited_role == "root":
                raise files.FileError(403, "there is only one owner: invite an administrator or a member instead")
            if invited_role == "admin" and actor.get("role") not in ("root", "admin"):
                raise files.FileError(403, "only the owner or an administrator can invite administrators")
            if actor.get("role") not in ("root", "admin") and any(
                    p not in (actor.get("permissions") or []) for p in grants):
                raise files.FileError(403, "you may only delegate permissions already assigned to your account")
            target_user = str(b.get("user") or b.get("username") or "").strip()
            token, expiry = accounts.issue_invite(target_user, b.get("email"), invited_role,
                                                  grants, user, preset=preset,
                                                  mount=b.get("mount"), storage_path=b.get("storage_path"))
            link = self.dashboard_base() + "/enroll?token=" + urllib.parse.quote(token)
            email_sent = False
            target_email = str(b.get("email") or "").strip().lower()
            if target_email and App.alerts and mail_configured():
                import html
                body = "Complete your Strata account setup within 24 hours: " + link
                html_body = "<p>An administrator invited you to Strata.</p><p><a href=\"%s\">Set your password and review the privacy note</a>. The invite expires in 24 hours.</p>" % html.escape(link, quote=True)
                try:
                    App.alerts.send_to([target_email], "Your Strata account invitation", body, html_body)
                    email_sent = True
                except Exception:
                    pass
            A("account.create" if path == "/api/accounts/create" else "account.invite", target_user, str(b.get("email") or ""))
            return {"invited": True, "created": True, "user": target_user, "token": token, "link": link, "expires": expiry, "email_sent": email_sent}
        if path == "/api/accounts/permissions":
            target = str(b.get("user") or b.get("username") or "")
            actor = accounts.get(user) or {}
            if target.lower() == user.lower():
                raise files.FileError(403, "you cannot modify your own permissions or role")
            acct = accounts.get(target)
            if not acct:
                raise files.FileError(404, "account not found")
            if acct.get("role") == "root":
                raise files.FileError(403, "the owner's permissions can't be changed")
            target_role = str(b.get("role", "employee"))
            preset = str(b.get("preset") or "")
            if preset and preset in accounts.PRESETS and preset != "custom":
                target_role = accounts.PRESETS[preset]["role"]
                grants = list(accounts.PRESETS[preset]["permissions"])
            else:
                grants = b.get("permissions") or []
            if target_role == "root":
                raise files.FileError(403, "an account can't become the owner")
            if target_role == "admin" and actor.get("role") not in ("root", "admin"):
                raise files.FileError(403, "only the owner or an administrator can grant administrator access")
            if actor.get("role") not in ("root", "admin") and any(
                    p not in (actor.get("permissions") or []) for p in grants):
                raise files.FileError(403, "you may only delegate permissions already assigned to your account")
            accounts.set_permissions(target, target_role, grants, preset=preset)
            A("account.permissions", target, str(target_role))
            App.sessions.drop_user(target)
            return {"account": accounts.public(accounts.get(target))}
        if path == "/api/accounts/status":
            target, enabled = str(b.get("user") or b.get("username") or ""), bool(b.get("enabled"))
            acct = accounts.get(target)
            if not acct:
                raise files.FileError(404, "account not found")
            if acct.get("role") == "root" and not enabled:
                db = core.connect()
                try:
                    root_count = db.execute("SELECT COUNT(*) FROM account WHERE role='root' AND enabled=1").fetchone()[0]
                    if root_count <= 1:
                        raise files.FileError(400, "the owner can't be disabled")
                finally:
                    db.close()
            if target.lower() == user.lower() and not enabled:
                raise files.FileError(400, "you cannot disable your own active account")
            if enabled and not acct.get("password_hash"):
                raise files.FileError(400, "this account has not set a password yet - send it a new activation link")
            db = core.connect()
            try:
                with db:
                    db.execute("UPDATE account SET enabled=?,updated=? WHERE user=? COLLATE NOCASE",
                               (int(enabled), time.time(), target))
            finally:
                db.close()
            if not enabled:
                App.sessions.drop_user(target)
            A("account." + ("enabled" if enabled else "disabled"), target)
            return {"user": target, "enabled": enabled}
        if path == "/api/accounts/sessions/revoke":
            target = str(b.get("user") or b.get("username") or "")
            if not target:
                raise files.FileError(400, "username required")
            if target.lower() != user.lower() and not accounts.has(user, "accounts.manage"):
                raise files.FileError(403, "account management requires administrator access")
            App.sessions.drop_user(target)
            A("account.sessions.revoke", target, "by " + user)
            return {"user": target, "revoked": True}
        if path == "/api/accounts/password-reset":
            if not accounts.has(user, "accounts.manage"):
                raise files.FileError(403, "account management requires administrator access")
            target = str(b.get("user") or b.get("username") or "")
            acct = accounts.get(target)
            if not acct:
                raise files.FileError(404, "account not found")
            token, expiry = accounts.issue_password_reset(target, user)
            link = self.dashboard_base() + "/enroll?token=" + urllib.parse.quote(token)
            email_sent = False
            target_email = str(acct.get("email") or "").strip().lower()
            if target_email and App.alerts and mail_configured():
                import html
                body = "Reset your Strata account password: " + link
                html_body = "<p>An administrator initiated a password reset for your Strata account.</p><p><a href=\"%s\">Set your new password</a>. The link expires in 24 hours.</p>" % html.escape(link, quote=True)
                try:
                    App.alerts.send_to([target_email], "Strata password reset link", body, html_body)
                    email_sent = True
                except Exception:
                    pass
            A("account.password-reset", target, "token generated")
            return {"user": target, "token": token, "link": link, "expires": expiry, "email_sent": email_sent}
        if path == "/api/accounts/delete":
            if not accounts.has(user, "accounts.manage"):
                raise files.FileError(403, "account management requires administrator access")
            target = str(b.get("user") or b.get("username") or "")
            if target.lower() == user.lower():
                raise files.FileError(400, "you cannot delete your own active account")
            storage_action = str(b.get("storage_action") or "retain").lower()
            if storage_action not in ("retain", "delete", "archive"):
                storage_action = "retain"
            accounts.delete_account(target, storage_action=storage_action)
            App.sessions.drop_user(target)
            A("account.delete", target, "storage=" + storage_action)
            return {"user": target, "deleted": True, "storage_action": storage_action}
        if path == "/api/accounts/zone":
            target = str(b.get("user") or b.get("username") or "")
            acct = accounts.get(target)
            if not acct or acct.get("role") in ("root", "admin"):
                raise files.FileError(400, "assign zones to employee accounts")
            caps = b.get("caps")
            if caps is None:  # older clients: read / write
                caps = sorted(accounts.FILE_CAPS) if b.get("access") == "write" else sorted(accounts.ZONE_READ)
            zones = accounts.zone_save(target, b.get("mount"), b.get("path", "/"), caps, b.get("expires"), user)
            A("account.zone.assign", "%s %s:%s" % (target, b.get("mount"), b.get("path")), note=",".join(caps)[:280])
            App.sessions.drop_user(target)
            return {"zones": zones}
        if path == "/api/accounts/zone/update":
            zid = int(b.get("id") or 0)
            db = core.connect()
            try:
                row = db.execute("SELECT user,mount,path FROM account_zone WHERE id=?", [zid]).fetchone()
            finally:
                db.close()
            if not row:
                raise files.FileError(404, "storage zone not found")
            accounts.zone_update(zid, b.get("caps") or [], b.get("expires"))
            A("account.zone.update", "%s %s:%s" % (row[0], row[1], row[2]), note=",".join(b.get("caps") or [])[:280])
            App.sessions.drop_user(row[0])
            return {"zones": accounts.zones(row[0], include_expired=True)}
        if path == "/api/accounts/constraints":
            target = str(b.get("user") or "")
            accounts.set_constraints(target, b.get("expires"), b.get("allowed_ips") or "", b.get("session_hours"), b.get("note") or "")
            A("account.constraints", target, "expires=%s ips=%s session_h=%s" % (b.get("expires"), str(b.get("allowed_ips") or "")[:120],
                                                                             b.get("session_hours")))
            App.sessions.drop_user(target)  # new limits apply from the next sign-in
            return {"account": accounts.public(accounts.get(target))}
        if path == "/api/accounts/avatar/delete":
            target = str(b.get("user") or "")
            if not accounts.get(target):
                raise files.FileError(404, "account not found")
            accounts.clear_avatar(target)
            A("account.avatar.remove", target, "by root")
            return {"removed": True}
        if path == "/api/accounts/zone/delete":
            zid = int(b.get("id") or 0)
            db = core.connect()
            try:
                row = db.execute("SELECT user,mount,path FROM account_zone WHERE id=?", [zid]).fetchone()
            finally:
                db.close()
            if not row:
                raise files.FileError(404, "storage zone not found")
            accounts.zone_delete(zid)
            A("account.zone.remove", row[0], "%s:%s" % (row[1], row[2]))
            return {"removed": zid}
        if path == "/api/upload/init":
            return files.up_init(user, b)
        if path == "/api/upload/check":
            return files.up_check(mid, b.get("paths") or [])
        if path == "/api/upload/url":
            r = files.fetch_url(user, mid, b.get("dest", "/"), b.get("url"), b.get("name") or None, b.get("policy") or "rename")
            A("fetch-url", "%s:%s" % (mid, b.get("dest")), str(b.get("url"))[:200])
            return r
        if path == "/api/files/trash/delete":
            r = files.trash_delete(mid, b.get("items") or [])
            A("trash-delete", "%s: %d items" % (mid, r["deleted"]), "%d bytes" % r["freed"])
            return purge_now(r)
        # network: Cloudflare zone settings, DNS, tunnel ingress, expose a service
        if path == "/api/network/setting":
            r = network.set_setting(b.get("id"), b.get("value"))
            A("cf-setting", "%s=%s" % (r["id"], r["value"]))
            return r
        if path == "/api/network/dns":
            r = network.dns_save(b)
            A("dns-save", "%s %s" % (r.get("type"), r.get("name")), str(r.get("content"))[:120])
            return r
        if path == "/api/network/dns/delete":
            A("dns-delete", str(b.get("id")), str(b.get("name") or ""))
            return network.dns_delete(b.get("id"))
        if path == "/api/network/ingress/add":
            return network.ingress_add(user, b.get("hostname", ""), b.get("service") or "", b.get("path") or "")
        if path == "/api/network/ingress/delete":
            return network.ingress_delete(user, b.get("index"))
        if path == "/api/network/ingress/move":
            return network.ingress_move(user, b.get("index"), b.get("delta"))
        if path == "/api/network/ingress/test":
            return network.ingress_test(b.get("url", ""))
        if path == "/api/network/restart":
            return network.restart_tunnel(user)
        if path == "/api/network/expose":
            r = network.expose(user, b)
            A("expose", r.get("url", ""), "; ".join("%s:%s" % (s["step"], "ok" if s["ok"] else "failed") for s in r["steps"]))
            App.compressor.request_scan()
            return r
        if path == "/api/settings/retention":
            upd = {}
            if "raw_retention_days" in b:
                upd["raw_retention_days"] = num(b, "raw_retention_days", 1, 3650)
            if "retention_days" in b:
                upd["retention_days"] = num(b, "retention_days", 7, 3650)
            core.save_config(upd)
            A("retention", json.dumps(upd))
            return self.system()
        if path == "/api/system/optimize":
            db = core.connect()
            try:
                db.execute("PRAGMA optimize")
                db.execute("ANALYZE")
                db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                db.close()
            A("db-optimize", "")
            return self.system()
        if path == "/api/files/mkdir":
            r = files.mkdir(mid, b.get("path", ""))
            A("mkdir", "%s:%s" % (mid, r["path"]))
            self.reindex(mid, r["path"] + "/x")
            return r
        if path == "/api/files/rename":
            r = files.rename(mid, b.get("from", ""), b.get("to", ""))
            A("rename", "%s:%s -> %s" % (mid, r["from"], r["to"]))
            media_bridge.on_rename(mid, r["from"], r["to"])  # verdicts (and queued jobs) follow the file / folder
            self.reindex(mid, r["from"], r["to"])
            App.compressor.reload_map()
            purge_later(r)
            if b.get("redirect") and r["urls"]:
                rules.save_rule(user, {"name": "Moved: %s" % r["from"][-60:], "mount": mid, "action": "redirect",
                                       "patterns": [files.url_path(files.get_mount(mid), r["from"])],
                                       "params": {"to": files.url_path(files.get_mount(mid), r["to"]), "code": 301}})
            return r
        if path == "/api/files/delete":
            paths = b.get("paths") or []
            if not isinstance(paths, list) or not paths or len(paths) > 2000:
                raise files.FileError(400, "nothing to delete")
            r = files.delete(user, mid, paths)
            A("delete", "%s:%s" % (mid, ", ".join(x["path"] for x in r["moved"])[:500]), "batch " + r["batch"])
            self.reindex(mid, *[x["path"] for x in r["moved"]])
            App.compressor.reload_map()
            return purge_now(r)
        if path == "/api/files/restore":
            r = files.restore(mid, b.get("batch", ""), b.get("path", ""))
            A("restore", "%s:%s" % (mid, r["path"]))
            self.reindex(mid, r["path"])
            App.compressor.reload_map()
            return r
        if path == "/api/files/empty-trash":
            r = files.empty_trash(mid)
            A("empty-trash", str(mid), "%d items, %d bytes" % (r["items"], r["freed"]))
            return purge_now(r)
        if path in ("/api/files/copy", "/api/files/move"):
            move = path.endswith("move")
            r = files.copy_items(user, mid, b.get("paths") or [], b.get("dest_mount") or mid, b.get("dest", "/"), move)
            A("move" if move else "copy", "%s:%s -> %s:%s" % (mid, ", ".join(b.get("paths") or [])[:300],
                                                              b.get("dest_mount") or mid, b.get("dest")))
            if r.get("instant"):
                for x in r["moved"]:
                    self.reindex(mid, x["from"], x["to"])
                    purge_later(x)
            return r
        if path == "/api/files/text":
            r = files.write_text(user, mid, b.get("path", ""), b.get("text", ""), b.get("expect_mtime"), b.get("create"))
            full = r.pop("full")
            A("edit", "%s:%s" % (mid, r["path"]), "%d bytes" % r["size"])
            App.compressor.enqueue(full)
            purge_later(r)
            return r
        if path == "/api/files/version/restore":
            r = files.restore_version(user, mid, b.get("path", ""), b.get("n"))
            A("version-restore", "%s:%s v%s" % (mid, r["path"], r["restored"]))
            full, _ = files.resolve(files.get_mount(mid), r["path"])
            App.compressor.enqueue(full)
            purge_later(r)
            return r
        if path == "/api/files/version/delete":
            r = files.delete_version(mid, b.get("path", ""), b.get("n"))
            A("version-delete", "%s:%s v%s" % (mid, b.get("path"), b.get("n")))
            return r
        if path == "/api/files/hash":
            return files.sha256_of(mid, b.get("path", ""))
        if path == "/api/files/zip":
            return files.zip_prepare(mid, b.get("paths") or [])
        if path == "/api/files/purge":
            m = files.get_mount(mid)
            items = []
            for p in b.get("paths") or []:
                full, parts = files.resolve(m, p)
                items.append((files.rel_of(parts), os.path.isdir(full)))
            r = cloudflare.purge_now(files.purge_targets(m, items))
            A("purge", "%s: %d targets" % (mid, r["queued"]), r.get("error", "") if not r.get("ok", True) else "")
            return dict(r, purged=r["queued"] if r.get("ok", True) and not r.get("pending") else 0)
        if path == "/api/compress/run":
            App.compressor.request_scan()
            A("scan", "all drives")
            return {"queued": True}
        # serving control
        if b.get("preview") and path in ("/api/serving/mount", "/api/serving/rule", "/api/serving/site"):
            # the diff of the Caddy config the change would produce; nothing is saved, applied or audited
            save = {"mount": rules.save_mount, "rule": rules.save_rule, "site": rules.save_site}[path.rsplit("/", 1)[1]]
            return {"diff": save(user, b)["diff"]}
        if path == "/api/serving/mount":
            r = rules.save_mount(user, b)
            A("drive-save", b.get("name", ""))
            App.compressor.request_scan()
            return r
        if path == "/api/serving/mount/delete":
            A("drive-delete", str(b.get("id")))
            return rules.delete_mount(user, b.get("id"))
        if path == "/api/serving/rule":
            A("rule-save", b.get("name", ""), b.get("action", ""))
            r = rules.save_rule(user, b)
            if b.get("purge"):
                self.purge_rule_paths(b)
            return r
        if path == "/api/serving/rule/delete":
            A("rule-delete", str(b.get("id")))
            return rules.delete_rule(user, b.get("id"))
        if path == "/api/serving/rule/move":
            return rules.move_rule(user, b.get("id"), b.get("delta"))
        if path == "/api/serving/bl":
            A("blacklist-add", "%s %s" % (b.get("kind"), b.get("value")), b.get("note", ""))
            return rules.save_bl(user, b)
        if path == "/api/serving/bl/bulk":
            A("blacklist-import", b.get("kind", ""))
            return rules.bulk_bl(user, b.get("text"), b.get("kind"), b.get("note"), b.get("expires"), b.get("scope"))
        if path == "/api/serving/bl/delete":
            A("blacklist-remove", str(b.get("ids")))
            return rules.delete_bl(user, b.get("ids"))
        if path == "/api/serving/bl/toggle":
            return rules.toggle_bl(user, b.get("id"), b.get("enabled"))
        if path in ("/api/serving/link", "/api/serving/link/delete", "/api/serving/link/alias"):
            code = b.get("original_code") if path.endswith("/link") else b.get("code")
            if code and not self.link_allowed(user, code):
                raise files.FileError(403, "only the creator of this link (or a link administrator) can change it")
            if path.endswith("/link") and b.get("url") and not accounts.has(user, "serving.links"):
                raise files.FileError(403, "links to external addresses need the 'All share links' capability")
        if path == "/api/serving/link":
            A("link-save", b.get("code") or "(new)")
            return rules.save_link(user, b)
        if path == "/api/serving/link/delete":
            A("link-delete", b.get("code", ""))
            return rules.delete_link(user, b.get("code"))
        if path == "/api/serving/link/alias":
            A("link-alias", b.get("code", ""))
            return rules.alias_link(user, b.get("code"))
        if path == "/api/serving/site":
            A("site-save", "")
            return rules.save_site(user, b)
        if path == "/api/serving/rollback":
            A("config-rollback", str(b.get("id")))
            return rules.rollback(user, b.get("id"))
        if path == "/api/serving/apply":
            db = core.connect()
            try:
                with db:
                    return rules.apply(db, user, "manual", force=True)
            finally:
                db.close()
        if path == "/api/serving/sign":
            m = files.get_mount(mid)
            secs = num(b, "seconds", 60, 365 * 86400, default=(CFG["links"].get("default_days") or 7) * 86400)
            url, exp = rules.signed_url(m, b.get("path", "/"), secs, rules.clean_mods(b.get("mods")))
            A("sign", "%s:%s" % (mid, b.get("path")), "valid %ds" % secs)
            return {"url": url, "expires": exp}
        # cloudflare
        if path == "/api/cloudflare/sync":
            rules.EDGE_SYNC.set()
            return {"queued": True}
        if path == "/api/cloudflare/purge":
            urls = [u.strip() for u in (b.get("urls") or []) if isinstance(u, str) and u.strip()]
            A("purge", "%d urls" % len(urls))
            return cloudflare.purge(urls)
        if path == "/api/cloudflare/purge-all":
            A("purge-everything", "zone")
            return cloudflare.purge_everything()
        if path == "/api/cloudflare/purge-retry":  # e.g. right after the token got the Cache Purge permission
            cloudflare.drain(wait=10, max_calls=10)
            return self.cf_state()
        if path == "/api/cloudflare/settings":
            db = core.connect()
            try:
                with db:
                    for k in ("edge_enabled", "autopurge"):
                        if k in b:
                            core.set_meta(db, "cf_" + k, bool(b[k]))
            finally:
                db.close()
            if b.get("edge_enabled") is not None:
                rules.EDGE_SYNC.set()
            return self.cf_state()
        # alerts
        if path == "/api/alerts/ack":
            return alerts.ack(b.get("ids") or "all")
        if path == "/api/alerts/config":
            upd = {}
            if b.get("resend_api_key"):
                if not re.match(r"^re_[A-Za-z0-9_]{10,}$", b["resend_api_key"]):
                    raise files.FileError(400, "Resend keys start with re_")
                upd["resend_api_key"] = b["resend_api_key"]
            if b.get("clear_key"):
                upd["resend_api_key"] = ""
            if "from" in b:
                upd["from"] = str(b["from"]).strip()[:120]
            if "provider" in b:
                if b["provider"] not in ("smtp", "resend"):
                    raise files.FileError(400, "provider is smtp or resend")
                upd["provider"] = b["provider"]
            if isinstance(b.get("smtp"), dict):  # any SMTP server: a provider's relay or a self-hosted one
                sm, old = b["smtp"], CFG["alerts"].get("smtp") or {}
                host = str(sm.get("host") or "").strip().lower()
                if host and not re.fullmatch(r"[a-z0-9.-]{1,253}|\[[0-9a-f:.]+\]", host):
                    raise files.FileError(400, "SMTP host: a host name or address, without port or scheme")
                if str(sm.get("security") or "starttls") not in alerts.SMTP_SECURITY:
                    raise files.FileError(400, "SMTP security is starttls, tls or none")
                port = int(sm.get("port") or 0)
                if not 0 <= port <= 65535:
                    raise files.FileError(400, "SMTP port is 1 to 65535")
                upd["smtp"] = {"host": host, "port": port, "security": str(sm.get("security") or "starttls"),
                               "user": str(sm.get("user") or "").strip()[:200],
                               # empty keeps the stored password, like the Resend key
                               "password": "" if not host else str(sm["password"])[:500] if sm.get("password") else old.get("password", "")}
            # the merged settings, so switching provider or clearing the SMTP host counts as removing e-mail too
            removes_mail = mail_configured() and not alerts.mail_ready(dict(CFG["alerts"], **upd))
            if removes_mail and not CFG["auth"].get("totp_secret"):
                raise files.FileError(400, "Can't remove e-mail: the owner gets sign-in codes by e-mail. "
                                           "Set up an authenticator app in Settings first.")
            if "to" in b:
                to = [t.strip() for t in re.split(r"[,\s;]+", str(b["to"])) if t.strip()]
                if any(not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", t) for t in to):
                    raise files.FileError(400, "invalid e-mail address")
                upd["to"] = to[:10]
            if "webhooks" in b:  # the owner's own LAN (a self-hosted ntfy) is a fine target, so no public-address check
                hooks = [u.strip() for u in re.split(r"[\s,]+", str(b["webhooks"] or "")) if u.strip()]
                if any(not re.match(r"^https?://[^\s/]+", u) or len(u) > 500 for u in hooks):
                    raise files.FileError(400, "webhooks must be http:// or https:// addresses")
                upd["webhooks"] = hooks[:5]
            for k in ("min_severity", "digest"):
                if k in b:
                    upd[k] = str(b[k])
            for k, lo, hi in (("digest_hour", 0, 23), ("max_per_hour", 1, 10000)):
                if k in b:
                    upd[k] = num(b, k, lo, hi)
            core.save_config({"alerts": upd})
            A("alerts-config", ", ".join(k for k in upd))
            return alerts.q_alerts({})
        if path == "/api/alerts/test":
            try:
                n = App.alerts.notify("[Strata] Test message", "This is a test from Strata.",
                                      "<p>This is a test from <b>Strata</b>.</p>", "info")
            except RuntimeError as e:
                raise files.FileError(502, str(e))
            if not n:
                raise files.FileError(400, "set up e-mail delivery or add a webhook first")
            return {"sent": n}
        # account + security
        if path == "/api/2fa/begin":
            secret = auth.totp_secret()
            App.enrol[user] = (secret, time.time() + 600)
            uri = auth.totp_uri(secret, user)
            return {"secret": secret, "uri": uri, "qr": auth.qr_svg(uri)}
        if path == "/api/2fa/enable":
            secret, exp = App.enrol.get(user, (None, 0))
            if not secret or exp < time.time():
                raise files.FileError(400, "start the setup again")
            step = auth.totp_verify(secret, b.get("code"))
            if not step:
                raise files.FileError(400, "code did not match - check the time on your phone")
            codes, hashes = auth.recovery_codes()
            core.save_config({"auth": {"totp_secret": secret, "totp_last": step, "recovery": hashes}})
            App.enrol.pop(user, None)
            A("2fa-enable", user)
            return {"enabled": True, "recovery": codes}
        if path in ("/api/2fa/disable", "/api/2fa/recovery"):
            # checked before the code, so a recovery code isn't used up by a request that is refused anyway
            if path.endswith("disable") and not owner_mail_ready():
                raise files.FileError(400, "Can't turn off the app: e-mail isn't set up, so you couldn't sign in. "
                                           "Set up e-mail in Settings first.")
            if not self.second_factor_ok(b.get("code")):
                raise files.FileError(400, "That code didn't match. Enter the current code or a recovery code.")
            if path.endswith("disable"):
                core.save_config({"auth": {"totp_secret": "", "recovery": [], "totp_last": 0}})
                A("2fa-disable", user)
                return {"enabled": False}
            codes, hashes = auth.recovery_codes()
            core.save_config({"auth": {"recovery": hashes}})
            A("2fa-recovery-regenerated", user)
            return {"recovery": codes}
        if path == "/api/password":
            acct = accounts.get(user) or {}
            if not auth.verify_password(b.get("current", ""), acct.get("password_hash") or ""):
                raise files.FileError(400, "current password is wrong")
            new = b.get("new", "")
            if len(new) < 12:
                raise files.FileError(400, "use at least 12 characters")
            hashed = auth.hash_password(new)
            db = core.connect()
            try:
                with db:
                    db.execute("UPDATE account SET password_hash=?,updated=? WHERE user=? COLLATE NOCASE",
                               (hashed, time.time(), user))
            finally:
                db.close()
            if acct.get("role") == "root":
                core.save_config({"auth": {"password_hash": hashed}})
            App.sessions.drop_user(user)
            A("password-change", user)
            return {"changed": True, "note": "all sessions were signed out"}
        if path == "/api/branding":
            r = save_branding(b)
            A("branding", ", ".join(sorted(b))[:200])
            return r
        if path == "/api/settings/bots":
            old = dict(CFG["anubis"])
            try:
                anubis.save(b)
                rules.mutate(user, "bot protection settings", lambda db: None)  # re-render, check with Caddy, reload
            except Exception:  # Caddy (or the checks) refused: back to what ran before
                core.save_config({"anubis": old})
                anubis.write_policy()
                raise
            rules.EDGE_SYNC.set()
            A("bots-settings", json.dumps({k: v for k, v in b.items() if k != "exe"})[:300])
            return anubis.state()
        if path == "/api/bots/task":
            return anubis.install_task(user)
        if path == "/api/bots/restart":
            return anubis.restart(user)
        if path == "/api/bots/stop":
            return anubis.stop(user)
        if path == "/api/bots/task/remove":
            return anubis.remove_task(user)
        if path == "/api/bots/install":
            A("bots-install", anubis.TESTED)
            anubis.install(user)
            return anubis.state()
        if path == "/api/bots/setup":  # program, key, policy, start-up task, start, switch on - and the auto challenge rule
            was_on = anubis.enabled()
            try:
                log = anubis.setup_all(user)
                anubis.ensure_auto_rule(user, downloads=bool(b.get("downloads")))
                anubis.save({"enabled": True})
                rules.mutate(user, "bot protection set up", lambda db: None)
            except Exception:  # keep what was downloaded, but not a half-working switch
                core.save_config({"anubis": {"enabled": was_on}})
                anubis.write_policy()
                raise
            rules.EDGE_SYNC.set()
            A("bots-setup", anubis.TESTED)
            return dict(anubis.state(), log=log + ["Bot protection is on"])
        if path == "/api/bots/auto-downloads":  # the checkbox under Activate: direct download tools challenged too
            rule = anubis.auto_rule(core.connect())
            if rule:
                rules.save_rule(user, dict(rule, params={"downloads": bool(b.get("downloads"))}))
            rules.mutate(user, "bot challenge covers direct downloads" if b.get("downloads") else "bot challenge browsers only",
                         lambda db: None)
            A("bots-downloads", "1" if b.get("downloads") else "0")
            return anubis.state()
        if path == "/api/bots/under-attack":  # red button: hardest puzzle + downloads challenged, for a while
            seconds = max(0, min(7 * 24 * 3600, int(b.get("seconds") or 0)))
            st = anubis.set_under_attack(user, seconds)
            rules.mutate(user, "under attack mode %s" % ("on" if seconds else "off"), lambda db: None)  # overlay + policy in the Caddy config
            rules.EDGE_SYNC.set()
            if anubis.enabled() and anubis.task_installed() and not CFG["instance"].get("dry_run"):
                try:
                    anubis.restart(user)  # Anubis reads the policy (difficulty) only at start
                except anubis.BotError as e:
                    return dict(st, note=str(e))
            return st
        if path == "/api/settings/autoban":
            ab = {k: b[k] for k in ("enabled", "probes", "window_minutes", "ban_hours") if k in b}
            for k in ("probes", "window_minutes", "ban_hours"):
                if k in ab:
                    ab[k] = max(1, min(100000, int(ab[k])))
            core.save_config({"autoban": ab})
            A("autoban-settings", json.dumps(ab))
            return {"autoban": CFG["autoban"]}
        if path == "/api/settings/smartsort":
            ss = {}
            if "home" in b:  # {"mount": 1, "path": "/share/eric"}, or null to switch it off for this user
                h = b["home"] or {}
                ss["homes"] = {user.lower(): ""}
                if h.get("path"):
                    m = files.get_mount(h.get("mount"))
                    ss["homes"][user.lower()] = "%d:%s" % (m["id"], files.rel_of(files.resolve(m, h["path"])[1]))
            if "root_to_home" in b:
                ss["root_to_home"] = bool(b["root_to_home"])
            if "assets" in b:
                ss["assets"] = "/".join(files.parts_of(str(b["assets"] or "assets")))
            if isinstance(b.get("folders"), dict):
                ss["folders"] = {k: "/".join(files.parts_of(str(v))) or k for k, v in b["folders"].items()
                                 if k in CFG["smartsort"]["folders"]}
            core.save_config({"smartsort": ss})
            A("smartsort-settings", json.dumps(ss)[:500])
            return self.me(user)
        if path == "/api/settings/links":
            lk = {"abuse": {}}
            if "default_days" in b:
                lk["default_days"] = num(b, "default_days", 0, 365, float, default=0)
            for k, lo, hi in (("per_ip_10m", 5, 100000), ("clicks_10m", 20, 1000000), ("countries_1h", 3, 250),
                              ("bot_min", 5, 100000)):
                if k in b:
                    lk["abuse"][k] = num(b, k, lo, hi)
            if "bot_share" in b:
                lk["abuse"]["bot_share"] = num(b, "bot_share", 0.5, 1.0, float)
            if "abuse_enabled" in b:
                lk["abuse"]["enabled"] = bool(b["abuse_enabled"])
            core.save_config({"links": lk})
            A("link-settings", json.dumps(lk))
            return self.me(user)
        if path == "/api/settings/upload":
            up = {}
            if "chunk_mb" in b:
                up["chunk_mb"] = num(b, "chunk_mb", 1, 95)
            if "parallel" in b:
                up["parallel"] = num(b, "parallel", 1, 8)
            core.save_config({"upload": up})
            if "versions_keep" in b:
                core.save_config({"versions_keep": num(b, "versions_keep", 1, 100)})
            return self.me(user)
        if path == "/api/settings/signups":
            if not accounts.has(user, "accounts.manage") and (accounts.get(user) or {}).get("role") not in ("root", "admin"):
                raise files.FileError(403, "administrative privileges required")
            val = bool(b.get("allowed", True))
            accounts.set_signups_allowed(val)
            A("settings.signups", "enabled" if val else "disabled")
            return {"allowed": accounts.signups_allowed()}
        return None

    def purge_rule_paths(self, b):
        """Purge the files a new protective rule covers, so Cloudflare stops serving cached public copies."""
        urls = []
        for m in core.file_mounts():
            if b.get("mount") and str(m["id"]) != str(b.get("mount")):
                continue
            db = core.connect()
            try:
                paths = [r[0] for r in db.execute("SELECT path FROM fidx WHERE mount=? LIMIT 20000", [m["id"]])]
            finally:
                db.close()
            fake = {"patterns": b.get("patterns") if isinstance(b.get("patterns"), list) else str(b.get("patterns") or "").splitlines()}
            for p in paths:
                if rules.rule_matches(fake, files.url_path(m, p)):
                    urls += files.urls_for(m, p)
        cloudflare.purge_async(urls[:6000])

    def second_factor_ok(self, code):
        with SETUP_LOCK:
            return self._second_factor_ok(code)

    def _second_factor_ok(self, code):
        a = CFG["auth"]
        step = auth.totp_verify(a.get("totp_secret"), code, a.get("totp_last") or 0)
        if step:
            core.save_config({"auth": {"totp_last": step}})
            return True
        rc = auth.normalize_recovery(code)
        if rc and auth.token_hash(rc) in (a.get("recovery") or []):
            core.save_config({"auth": {"recovery": [h for h in a["recovery"] if h != auth.token_hash(rc)]}})
            return True
        return False

    # -- PUT (uploads, streamed straight to the drive)
    def do_PUT(self):
        path, q = self.query()
        self.rfile = CountingReader(self.rfile)
        user = self.guard(path)
        if not user:
            return
        if path.startswith("/api/") and not self.authorize(user, path, "PUT", q):
            self.drain()
            core.audit(self.client_ip(), user, "access-denied", path[:200], ok=False)
            return self.json({"error": "this account does not have permission for this upload"}, 403)
        if not self.csrf_ok(path):
            self.drain()
            return self.json({"error": "cross-site request refused"}, 403)
        ip = self.client_ip()
        try:
            m = re.fullmatch(r"/api/upload/([0-9a-f]{24})/(\d{1,7})", path)
            if m:
                return self.json(files.up_chunk(user, m.group(1), m.group(2), self.rfile, self.headers))
            if path == "/api/files/upload":
                r = files.upload_single(user, q.get("mount"), q.get("path", ""), self.rfile, self.headers,
                                        q.get("policy", "ask"))
                self.after_upload(ip, user, r)
                return self.json(r)
            self.drain()
            return self.json({"error": "not found"}, 404)
        except Exception as e:
            if not isinstance(e, files.FileError) or e.code != 409:
                core.audit(ip, user, "upload", q.get("path", path)[:200], ok=False, note=str(e)[:200])
            self.drain()  # e.g. "exists" is decided before the body is read
            return self.fail(e)

    def do_DELETE(self):
        self.json({"error": "method not allowed"}, 405)

    # -- login
    def owner_setup(self):
        """Create the owner (root) account on a fresh install. Same storage as `python setup.py`: strata.json
        auth.user / auth.password_hash, imported into the account table by accounts.bootstrap()."""
        if not self.loopback():
            self.drain()
            return self.redirect("/login?e=setup_local")
        form = self.body_form(4096)
        user = str(form.get("user") or "").strip()
        password = form.get("password") or ""
        factor = form.get("factor")
        email = str(form.get("email") or "").strip().lower()
        key, sender = str(form.get("resend_key") or "").strip(), str(form.get("mail_from") or "").strip()
        smtp_host = str(form.get("smtp_host") or "").strip().lower()
        smtp_port = int(form.get("smtp_port")) if str(form.get("smtp_port") or "").isdigit() else 0
        if smtp_host and not re.fullmatch(r"[a-z0-9.-]{1,253}", smtp_host):
            smtp_host = ""
        secret = setup_secret()
        step = auth.totp_verify(secret, form.get("totp_code")) if factor == "app" else None
        problem = ("user" if not accounts.USER_RE.fullmatch(user) else
                   "password" if len(password) < 12 else
                   "repeat" if password != form.get("password2") else
                   "factor" if factor not in ("app", "email") else
                   "totp" if factor == "app" and not step else
                   "email" if factor == "email" and not accounts.EMAIL_RE.fullmatch(email) else
                   "mail" if factor == "email" and not mail_configured() and not ((key or smtp_host) and accounts.EMAIL_RE.fullmatch(sender))
                   else "")
        if problem:
            return self.redirect("/setup?e=" + problem)
        with SETUP_LOCK:
            if CFG["auth"].get("password_hash"):  # someone finished first
                return self.redirect("/login")
            update = {"auth": {"user": user, "password_hash": auth.hash_password(password)}}
            codes = []
            if factor == "app":
                codes, hashes = auth.recovery_codes()
                update["auth"].update(totp_secret=secret, totp_last=step, recovery=hashes)
            else:
                update["alerts"] = {"to": [email] + [t for t in CFG["alerts"].get("to") or [] if t != email]}
                if smtp_host:
                    update["alerts"].update({"from": sender, "provider": "smtp", "smtp": {
                        "host": smtp_host, "port": smtp_port, "security": "tls" if smtp_port == 465 else "starttls",
                        "user": str(form.get("smtp_user") or "").strip()[:200], "password": str(form.get("smtp_password") or "")[:500]}})
                elif key:
                    update["alerts"].update(resend_api_key=key, provider="resend", **{"from": sender})
            core.save_config(update)
            accounts.bootstrap()
            SETUP_TOTP.clear()
        core.audit(self.client_ip(), user, "owner-setup", factor)
        log("setup: owner account %s created from %s (sign-in code: %s)" % (user, self.client_ip(), factor))
        if not codes:
            return self.redirect("/login?e=owner")
        return self.html_page("setupdone.html", dict(page_vars(), **{
            "<!--CODES-->": "".join("<li>%s</li>" % c for c in codes)}))

    def login(self):
        ip = self.client_ip()
        if App.limiter.blocked(ip):
            core.audit(ip, "", "login", "", ok=False, note="rate limited")
            return self.redirect("/login?e=locked")
        form = self.body_form(4096)
        username = str(form.get("user") or "").strip()
        password = form.get("password") or ""
        acct = accounts.get(username)
        # run the KDF even for unknown / not yet activated accounts (same timing), but never against another
        # account's hash: falling back to root's hash let a password-less account sign in with root's password
        stored = (acct or {}).get("password_hash") or DUMMY_HASH
        valid_password = auth.verify_password(password, stored) and stored is not DUMMY_HASH
        if not acct or not acct.get("enabled") or not valid_password:
            App.limiter.fail(ip)
            core.audit(ip, username[:60], "login", "", ok=False)
            App.alerts.login_failed(ip, username)
            time.sleep(0.5)
            return self.redirect("/login?e=1")
        username = acct["user"]  # account and session identities use the same spelling
        if self.administrative_account(acct) and not self.local_network():
            App.limiter.fail(ip)
            core.audit(ip, username, "admin-network-denied", "login", ok=False)
            return self.redirect("/login?e=local")
        problem = accounts.access_problem(acct, ip)  # told only after a correct password: no account probing
        if problem:
            App.limiter.fail(ip)
            core.audit(ip, username, "login", "", ok=False, note="refused: " + problem)
            return self.redirect("/login?e=" + {"expired": "acct_expired", "network": "acct_network"}.get(problem, "1"))
        # the pending login remembers which second step it waits for: each code page accepts only its own
        if acct.get("role") == "root" and CFG["auth"].get("totp_secret"):  # the app replaces the e-mailed code
            trusted = auth.cookie_value(self.headers.get("Cookie"), auth.TRUST_COOKIE)
            if trusted and auth.trust_ok(CFG["auth"]["cookie_secret"], trusted, username, trust_bind(acct)):
                core.audit(ip, username, "login-2fa", "", note="trusted browser")
                return self.finish_login(ip, username, [])
            tok = App.pending.create(username, ip, ttl=600, step="app")
            cookies = [self.cookie(auth.PENDING_COOKIE, tok, 600)]
            if trusted:  # expired, or ended by a new password or a new authenticator app
                cookies.append(self.cookie(auth.TRUST_COOKIE, "", 0, "/login"))
            return self.redirect("/login/2fa", cookies)
        email = str(acct.get("email") or "").strip().lower()
        mail_ready = mail_configured()
        if acct.get("role") == "root" and (not accounts.EMAIL_RE.fullmatch(email) or not mail_ready):
            App.limiter.fail(ip)
            core.audit(ip, username, "email-otp.unavailable", "login", ok=False, note="owner has no authenticator app or e-mail")
            return self.redirect("/login?e=setup_required")
        if not accounts.EMAIL_RE.fullmatch(email) or not mail_ready:
            App.limiter.fail(ip)
            core.audit(ip, username, "email-otp.unavailable", "login", ok=False)
            return self.redirect("/login?e=email")
        tok = App.pending.create(username, ip, ttl=600, step="email")
        pending_cookie = self.cookie(auth.PENDING_COOKIE, tok, 600)
        try:
            accounts.send_code(username, email, App.alerts, ip, "login")
        except Exception:
            App.pending.drop(tok)
            App.limiter.fail(ip)
            core.audit(ip, username, "email-otp.send", "login", ok=False, note="delivery failed")
            return self.redirect("/login?e=email")
        return self.redirect("/login/otp", [pending_cookie])

    def login_otp(self):
        ip = self.client_ip()
        tok = auth.cookie_value(self.headers.get("Cookie"), auth.PENDING_COOKIE)
        pending = App.pending.get(tok)
        if not pending or pending.get("step") != "email":
            return self.redirect("/login?e=expired")
        if App.limiter.blocked(ip):
            return self.redirect("/login/otp?e=locked")
        form = self.body_form(2048)
        user = pending["user"]
        email = accounts.verify_code(user, form.get("code"), "login")
        if not email:
            App.limiter.fail(ip)
            core.audit(ip, user, "email-otp.verify", "login", ok=False)
            App.alerts.raise_("login", "warning", "Wrong e-mail code for %s from %s" % (user, ip),
                              "The password was correct. Ignore if this was expected.", "emailotp:%s" % ip)
            time.sleep(0.4)
            return self.redirect("/login/otp?e=1")
        accounts.confirm_email(user, email)
        core.audit(ip, user, "email-otp.verify", "login")
        App.pending.drop(tok)
        return self.finish_login(ip, user, [self.cookie(auth.PENDING_COOKIE, "", 0)])

    def login_2fa(self):
        ip = self.client_ip()
        ptok = auth.cookie_value(self.headers.get("Cookie"), auth.PENDING_COOKIE)
        pend = App.pending.get(ptok)
        if not pend or pend.get("step") != "app":
            return self.redirect("/login?e=expired")
        if App.limiter.blocked(ip):
            return self.redirect("/login/2fa?e=locked")
        form = self.body_form(2048)
        code = form.get("code") or ""
        if not self.second_factor_ok(code):
            App.limiter.fail(ip)
            core.audit(ip, pend["user"], "login-2fa", "", ok=False)
            App.alerts.raise_("login", "warning", "Wrong 2FA code for %s from %s" % (pend["user"], ip),
                              "The password was correct - if this was not you, change it.", "2fa:%s" % ip)
            time.sleep(0.5)
            return self.redirect("/login/2fa?e=1")
        App.pending.drop(ptok)
        cookies = [self.cookie(auth.PENDING_COOKIE, "", 0)]
        if form.get("trust") == "1":  # the next sign-in from this browser skips the code (sent to /login only)
            trust = auth.trust_token(CFG["auth"]["cookie_secret"], pend["user"], trust_bind(accounts.get(pend["user"]) or {}))
            cookies.append(self.cookie(auth.TRUST_COOKIE, trust, auth.TRUST_DAYS * 86400, "/login"))
            core.audit(ip, pend["user"], "trust-browser", "", note="%d days" % auth.TRUST_DAYS)
        return self.finish_login(ip, pend["user"], cookies)

    def finish_login(self, ip, user, cookies):
        App.limiter.ok(ip)
        ttl = accounts.session_seconds(accounts.get(user), CFG["auth"]["session_hours"])
        tok = App.sessions.create(user, ip, ttl)
        core.audit(ip, user, "login", "")
        App.alerts.login_ok(ip, user)
        db = core.connect()
        try:
            with db:
                db.execute("UPDATE account SET last_login=?,updated=? WHERE user=? COLLATE NOCASE",
                           (time.time(), time.time(), user))
        finally:
            db.close()
        acct = accounts.get(user) or {}
        dest = "/" if acct.get("privacy_version") == accounts.PRIVACY_VERSION else "/privacy"
        return self.redirect(dest, cookies + [self.cookie(auth.COOKIE, tok, int(ttl))])

    def enroll(self):
        ip = self.client_ip()
        if App.limiter.blocked(ip):
            return self.redirect("/login?e=locked")
        form = self.body_form(8192)
        tok = form.get("token") or ""
        if not tok and not accounts.signups_allowed():
            return self.redirect("/login?e=signups_disabled")
        if not self.csrf_ok("/enroll"):
            return self.json({"error": "cross-site request refused"}, 403)
        try:
            user = accounts.use_invite(tok, form.get("password"), form.get("privacy") == "yes", ip)
            App.sessions.drop_user(user)  # a reset link signs out every existing session of that account
            return self.redirect("/login?e=enrolled")
        except Exception as e:
            App.limiter.fail(ip)  # invite tokens are guessable by brute force otherwise
            return self.html_page("enroll.html", dict(page_vars(), **{"{{INVITE}}": urllib.parse.quote(tok),
                                       "<!--ERROR-->": '<div class="err">%s</div>' % __import__("html").escape(str(e))}))


class Housekeeping(threading.Thread):
    daemon = True

    def run(self):
        hours = 0
        while True:
            try:
                files.up_gc()
                files.sync_all_bins()  # trash edited by hand, expired 404 tombstones
                anubis.under_attack_left()  # lapsed Under Attack Mode (e.g. across a restart) goes back to rest
            except Exception:
                log("housekeeping error:\n" + traceback.format_exc())
            if hours % 24 == 0:
                try:
                    core.check_update()
                except Exception as e:
                    log("update check failed: %s" % e)
            try:
                rules.warm_previews()  # link-preview cards of popular files, drawn ahead of time (skipped when busy)
            except Exception:
                log("preview warm-up error:\n" + traceback.format_exc())
            hours += 1
            time.sleep(3600)


def main():
    core.init_db()
    accounts.bootstrap()
    accounts.office_migrate()
    feed.ensure_token()
    rules.ensure_secret()
    if not CFG["auth"].get("cookie_secret"):
        core.save_config({"auth": {"cookie_secret": secrets.token_urlsafe(32)}})
    if not CFG["auth"].get("password_hash"):
        log("WARNING: no admin login configured - the admin UI refuses everything until you run: python auth.py <user>")
    db = core.connect()
    try:
        with db:
            if rules.seed(db):
                log("serving: imported drives and rules from the old Caddyfile")
            if rules.upgrade_cache_policy(db):
                rules.APPLY_SOON.set()
    finally:
        db.close()
    core.mounts(refresh=True)
    App.sessions.load()
    App.live = core.Live()
    App.metrics = core.Metrics()
    App.probes = core.Probes(App.metrics)
    App.compressor = compress.Compressor()
    App.alerts = alerts.Alerts(App.metrics, App.probes, App.live)
    rules.ALERT_HOOK.append(App.alerts.hook)
    gate.HOOKS.update(failed=App.alerts.login_failed, alert=App.alerts.raise_)
    gate.start()  # login in front of proxied services; Caddy's forward_auth fails closed (502) until it is up
    core.ROW_HOOKS.append(rules.on_rows)
    core.STORED_HOOKS.append(rollup.on_rows)  # aggregated statistics (rollup.py): dashboard cost independent of traffic
    files.JOB_HOOKS.append(lambda job: job.get("mount") and App.compressor.reindex(job["mount"], job.get("dest", "/")))
    files.JOB_HOOKS.append(lambda job: cloudflare.enqueue(job.get("purge") or []))  # cross-drive move: old URLs
    for t in (rollup.Worker(), core.Tailer(App.live), App.metrics, App.probes, core.Pruner(), App.compressor, rules.Scheduler(),
              cloudflare.EdgeSync(), cloudflare.Purger(), App.alerts, Housekeeping()):
        t.start()
    media_bridge.start()  # Strata Media: supervisor, discovery, purges, alerts; no-op while media.enabled is off
    feed.serve(App.live, App.metrics, App.probes)
    with open(rules.CFG["caddyfile"], encoding="utf-8-sig") as f:
        if rules.IMPORT_LINE not in f.read():
            log("WARNING: the Caddyfile does not import %s yet - serving changes are validated but cannot apply" % rules.GEN_FILE)
    host, port = CFG["listen"].rsplit(":", 1)
    srv = ThreadingHTTPServer((host, int(port)), Handler)
    srv.daemon_threads = True
    log("strata admin on http://%s:%s  (log: %s, db: %s)" % (host, port, CFG["access_log"], core.DB_PATH))
    srv.serve_forever()


if __name__ == "__main__":
    main()
