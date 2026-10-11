"""Serving control: drives (mounts), access rules, blacklist and short links -> the CDN Caddy site.

Everything lives in SQLite. render() turns it into generated/cdn.caddy, apply() validates the *whole*
Caddyfile with the candidate swapped in and only then reloads Caddy (the old file is restored if the reload
fails). Every applied revision is stored in `confhist`, so any earlier state can be put back.

Order inside the generated `route` (literal, Caddy does not re-sort inside route):
  1 blacklist  2 access rules (in their order, `allow` rules carve exceptions out of the others)
  3 short links  3b gallery folders  4 link modifiers (download, resize/format, versions)  5 drives
  6 unknown-host fallback
Error handling: a missing file whose path is in the recycle bin (table binpath, see files.sync_bin) gets the 403
page, a recently deleted one the 404 page - both with Clear-Site-Data so browsers drop cached copies.
Caching: a drive's `cache` goes to browsers as Cache-Control, its `edge_cache` to Cloudflare only (as
Cloudflare-CDN-Cache-Control). Browsers revalidate, Cloudflare keeps files long and is purged on every change.
"""
import base64
import collections
import concurrent.futures
import difflib
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import subprocess
import threading
import time
import traceback
import urllib.parse

import auth
import core
import gate
from core import CFG, connect, get_meta, log, rows_of, set_meta

try:  # Strata Media (media_rules.py, media/DESIGN.md): optional - while it is off or missing, render() is unchanged
    import media_rules
except Exception:
    media_rules = None

GEN_DIR = os.path.join(core.HOME, "generated")
GEN_FILE = os.path.join(GEN_DIR, "cdn.caddy")
IMPORT_LINE = "import " + GEN_FILE.replace("\\", "/")
TRANSFORM_CONFIG = os.path.join(core.HOME, "transform", "transform.json")
NOWIN = getattr(subprocess, "CREATE_NO_WINDOW", 0)

ACTIONS = {
    "allow": "Always serve (exception to the other rules)",
    "hide": "Hide (answer 404, like a missing file)",
    "deny": "Forbid (answer 403)",
    "password": "Password protect (browser login)",
    "signed": "Signed, expiring links only",
    "ip_allow": "Only these IPs / ranges",
    "geo_allow": "Only these countries",
    "geo_deny": "Block these countries",
    "hotlink": "Only when linked from these sites",
    "download": "Force download",
    "cache": "Custom Cache-Control",
    "redirect": "Redirect elsewhere",
    "gallery": "Gallery view (folders as a thumbnail grid)",
    "player": "Audio player (visualizer page for audio files)",
}
PRIVATE_ACTIONS = {"password", "signed", "ip_allow", "geo_allow", "geo_deny", "hotlink"}
BL_KINDS = {
    "ip": "IP address", "cidr": "IP range (CIDR)", "country": "Country", "asn": "Network / ASN (edge only)",
    "ua_contains": "User agent contains", "ua_regex": "User agent regex (origin only)", "agent": "Client class",
    "browser": "Browser family", "os": "Operating system", "referer": "Referring site", "path": "Path pattern",
}
AGENT_CLASSES = {
    "bots": core.BOT_RE.pattern, "previews": core.EMBED_RE.pattern, "players": core.PLAYER_RE.pattern,
    "empty": None,
}
BROWSER_RE = {"Edge": r"Edg[AeiO]?/", "Opera": r"OPR/|Opera", "Samsung": r"SamsungBrowser", "Yandex": r"YaBrowser",
              "Vivaldi": r"Vivaldi", "Firefox": r"Firefox/|FxiOS", "Discord app": r"discord/", "Electron": r"Electron/",
              "Chrome (all Chromium)": r"Chrome/|CriOS", "Safari": r"Version/.*Safari/"}
OS_RE = {"Windows": r"Windows", "Android": r"Android", "iOS": r"iPhone|iPad|iOS", "macOS": r"Mac OS X|Macintosh",
         "ChromeOS": r"CrOS", "Linux": r"Linux"}
IMAGE_RX = r"(?i)\.(jpe?g|png|webp|gif|bmp|tiff?|avif)$"
OLD_MEDIA_CACHE = "public, max-age=31536000, immutable"
BROWSER_REVALIDATE = "public, no-cache"   # browsers keep the file but ask (a cheap 304) before every use
EDGE_LONG = "public, max-age=31536000"    # Cloudflare keeps it a year; purged on replace / rename / delete
EDGE_HEADER = "Cloudflare-CDN-Cache-Control"  # read by Cloudflare only, never forwarded to browsers
RE2_META = set("\\.+*?()|[]{}^$")
GALLERY_TEMPLATE = os.path.join(core.ROOT, "gallery", "gallery.html").replace("\\", "/")  # Caddy browse template
GALLERY_CACHE = "private, no-cache"  # listings change without a purge: never at the edge, browsers revalidate
PLAYER_DIR = os.path.join(core.ROOT, "player").replace("\\", "/")  # player.html, a Caddy template
AUDIO_EXT = "mp3|m4a|aac|flac|ogg|oga|opus|wav|aiff?|weba|alac|wma|amr|wv|ape"
PHONE_UA = r"(?i)Mobi|iPhone|iPod|Android.+Mobile|Windows Phone|BlackBerry|Opera Mini"
# a browser opening the URL (or a frame showing it) - not an <audio> element, fetch(), crawler or download tool
NAV_EXPR = ('{http.request.header.Sec-Fetch-Dest} in ["document", "iframe"] || ({http.request.header.Sec-Fetch-Dest} == ""'
            ' && {http.request.header.Accept}.contains("text/html"))')
PLAYER_HEADERS = ("X-Strata-Player-Dir", "X-Strata-Player-Bg", "X-Strata-Player-Bg-Url")
PREVIEW_UA = "(?i)" + core.EMBED_RE.pattern  # link-preview crawlers (Discord, Slack, Telegram, X, WhatsApp...)
# file types the platforms embed themselves (pictures, videos, web pages): every other file gets a Strata card
PREVIEW_NATIVE = ("jpg", "jpeg", "png", "webp", "gif", "bmp", "tif", "tiff", "avif", "svg", "ico", "heic", "mp4",
                  "webm", "mov", "m4v", "mkv", "avi", "ogv", "html", "htm", "xhtml")
PREVIEW_NATIVE_RX = r"(?i)\.(%s)$" % "|".join(PREVIEW_NATIVE)

HOST_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$|^localhost$")
PATH_PAT_RE = re.compile(r"^/[^\x00-\x1f{}`\\]*$")
PREFIX_RE = re.compile(r"^/(?:[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*)?$")
CODE_RE = re.compile(r"^[A-Za-z0-9_-]{2,40}$")
CC_RE = re.compile(r"^(?:[A-Z]{2}|T1|XX)$")
CACHE_RE = re.compile(r"^[A-Za-z0-9=,\- ]{1,160}$")
UPSTREAM_RE = re.compile(r"^(?:[a-z0-9.-]+|\[[0-9a-f:]+\]):\d{2,5}$")
RE2_BAD = re.compile(r"\(\?[=!]|\(\?<[=!]|\\[1-9]|\(\?>|[*+?}]\+")
NEVER_NETS = [ipaddress.ip_network(n) for n in ("127.0.0.0/8", "::1/128")]
# exactly Caddy's `private_ranges` (what the generated blacklist exempts) - Python's is_private is broader
CADDY_PRIVATE = [ipaddress.ip_network(n) for n in ("192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8", "127.0.0.0/8",
                                                   "fd00::/8", "::1/128")]
# proxy drives (services) may only point into the LAN / VPN (Tailscale 100.64/10) or loopback
SERVICE_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                                  "127.0.0.0/8", "::1/128", "fc00::/7")]
UPSTREAM_IP_RE = re.compile(r"^(?:(\d{1,3}(?:\.\d{1,3}){3})|\[([0-9A-Fa-f:]+)\]|(localhost)):(\d{1,5})$")
GATE_USER_RE = re.compile(r"^[A-Za-z0-9._@-]{1,40}$")


class ServeError(Exception):
    pass


def bq(s):
    """Backtick-quoted raw Caddyfile token (no escapes inside, so we refuse the few chars that could break out)."""
    s = str(s)
    if re.search(r"[`\r\n\x00]", s) or "{$" in s:
        raise ServeError("unsupported character in %r" % s[:60])
    return "`%s`" % s


def check_regex(p):
    if not p or len(p) > 400 or RE2_BAD.search(p) or "{$" in p or "`" in p:
        raise ServeError("regex not supported (no look-arounds, back-references or possessive quantifiers; max 400 chars)")
    try:
        re.compile(p)
    except re.error as e:
        raise ServeError("invalid regex: %s" % e)
    return p


def glob_rx(pat):
    if pat.startswith("re:"):
        return re.compile(pat[3:])
    return re.compile("^" + ".*".join(re.escape(p) for p in pat.lower().split("*")) + "$")


def now():
    return time.time()


def active(row):
    return row.get("enabled") and not (row.get("expires") and row["expires"] < now())


# ---------------------------------------------------------------- validation

def clean_hosts(v):
    hosts = [h.strip().lower() for h in (v if isinstance(v, list) else str(v or "").replace(",", " ").split()) if h.strip()]
    if not hosts:
        raise ServeError("at least one hostname is required")
    for h in hosts:
        if not HOST_RE.match(h):
            raise ServeError("invalid hostname: %s" % h)
    return list(dict.fromkeys(hosts))


def own_addresses():
    """Every address of this PC: a service there could be Strata's or Caddy's own admin side."""
    addrs = {"127.0.0.1", "::1"}
    for fn in (lambda: [a[4][0] for a in socket.getaddrinfo(socket.gethostname(), None)],
               lambda: socket.gethostbyname_ex(socket.gethostname())[2]):
        try:
            addrs.update(a.split("%")[0].lower() for a in fn())
        except OSError:
            pass
    return addrs


def clean_upstream(v):
    """`ip:port` of a LAN / VPN / loopback service - never a hostname (DNS could later point it elsewhere), never
    a public, link-local (cloud metadata) or multicast address, and never this PC itself unless the exact address is
    in proxy_local_allow (strata.json only): exposing e.g. 127.0.0.1:8090 would publish the admin API."""
    s = str(v or "").strip()
    m = UPSTREAM_IP_RE.match(s)
    if not m:
        raise ServeError("upstream must be an IP address and port, e.g. 192.168.1.35:8080 (no hostnames)")
    try:
        ip = ipaddress.ip_address("127.0.0.1" if m.group(3) else m.group(1) or m.group(2))
    except ValueError:
        raise ServeError("not an IP address: %s" % s[:60])
    port = int(m.group(4))
    if not 1 <= port <= 65535:
        raise ServeError("port must be 1-65535")
    if ip.is_unspecified or ip.is_multicast or ip.is_link_local or not any(ip in n for n in SERVICE_NETS):
        raise ServeError("only LAN, VPN or loopback services can be exposed (10/8, 172.16/12, 192.168/16, 100.64/10, "
                         "127/8, fc00::/7) - not %s" % ip)
    canon = ("[%s]" % ip if ip.version == 6 else str(ip)) + ":%d" % port
    if ip.is_loopback or str(ip) in own_addresses():
        # services on this PC (e.g. localhost:1234) are fine - except the reserved ports where Strata, Caddy, the
        # tunnel's metrics, monitoring or remote access live (network.reserved_ports); those only with an explicit
        # proxy_local_allow entry in strata.json, deliberately not settable from the UI or the API
        import network
        allowed = set()
        for a in CFG.get("proxy_local_allow") or []:
            am = UPSTREAM_IP_RE.match(str(a).strip())
            if am:
                allowed.add(int(am.group(4)))
        if port in network.reserved_ports() and port not in allowed:
            raise ServeError("%s is reserved on this PC (Strata, Caddy, tunnel metrics, monitoring or remote access "
                             "listen there) - refused. If you really mean it, add \"127.0.0.1:%d\" to proxy_local_allow "
                             "in strata.json (on purpose not possible from the UI or the API) and restart Strata."
                             % (canon, port))
    return canon


def clean_gate(d):
    """Access of a proxy drive: login (default, the gate) or public (anyone on the internet)."""
    g = d.get("gate") if isinstance(d.get("gate"), dict) else {}
    mode = g.get("mode") or "login"
    if mode not in ("login", "public"):
        raise ServeError("access must be login or public")
    try:
        hours = int(g.get("hours") or 12)
    except (TypeError, ValueError):
        raise ServeError("session length must be a number of hours")
    if not gate.HOURS[0] <= hours <= gate.HOURS[1]:
        raise ServeError("session length: 1 to 168 hours")
    users = []
    for u in g.get("users") or []:
        name = str(u.get("user") or "").strip()
        if not name:
            continue
        if not GATE_USER_RE.match(name):
            raise ServeError("user names: letters, digits and . _ @ - only (max 40)")
        pw = str(u.get("password") or "")
        if pw and (len(pw) < 12 or pw.lower() == name.lower() or len(pw) > 200):
            raise ServeError("passwords for %s: 12 to 200 characters, not the user name" % name)
        users.append({"user": name, "password": pw, "totp": bool(u.get("totp"))})
    if len({u["user"].lower() for u in users}) != len(users):
        raise ServeError("user names must be unique")
    raw = g.get("public") or []
    public = [p.strip() for p in (raw if isinstance(raw, list) else str(raw).splitlines()) if p.strip()]
    for p in public:
        if (not gate.PUBLIC_RE.match(p) or gate.PATH.lower() in p.lower() or p in ("/", "/*", "*")
                or re.search(r"(?:^|/)\.\.?(?:/|$)|//", p)):
            raise ServeError("public paths start with / and use letters, digits, . _ ~ - / and * only "
                             "(the whole service cannot be an exception): %s" % p[:60])
    if len(public) > 40:
        raise ServeError("at most 40 public paths")
    return {"mode": mode, "hours": hours, "users": users, "public": list(dict.fromkeys(public))}


def clean_mount(d):
    kind = d.get("kind") or "files"
    if kind not in ("files", "page", "proxy"):
        raise ServeError("unknown drive type")
    name = str(d.get("name") or "").strip()[:60] or "Drive"
    hosts = clean_hosts(d.get("hosts"))
    path = str(d.get("path") or "").strip()
    if kind == "proxy":
        path = clean_upstream(path)
    else:
        if not path or not os.path.isdir(path):
            raise ServeError("folder not found or not readable: %s" % path)
        try:
            os.listdir(path)
        except OSError as e:
            raise ServeError("cannot read %s: %s" % (path, e.strerror or e))
        path = path.replace("\\", "/")
        if re.search(r"[`{}\x00-\x1f]", path):
            raise ServeError("unsupported character in path")
    prefix = "/" if kind == "page" else "/" + str(d.get("prefix") or "/").strip().strip("/")
    if prefix != "/" and not PREFIX_RE.match(prefix):
        raise ServeError("URL prefix may only contain letters, digits and . _ ~ -")
    if kind == "proxy" and prefix != "/" and (any(p.startswith(".") for p in prefix.split("/")[1:])
                                              or gate.PATH.lower() in prefix.lower()):
        raise ServeError("a service prefix may not start with a dot or contain %s" % gate.PATH)
    if kind == "proxy" and prefix != "/":
        for p in clean_gate(d)["public"]:
            if not p.lower().startswith(prefix.lower() + "/"):
                raise ServeError("public paths are full URL paths inside the prefix, e.g. %s/listen/*" % prefix)
    cache = str(d.get("cache") or (BROWSER_REVALIDATE if kind == "files" else "public, max-age=300")).strip()
    if not CACHE_RE.match(cache):
        raise ServeError("invalid Cache-Control value")
    if "edge_cache" in d:
        edge = str(d["edge_cache"] or "").strip()
    else:  # older clients: long at the edge only for public file drives
        edge = EDGE_LONG if kind == "files" and not re.search(r"no-store|private", cache) else ""
    if kind == "proxy":
        edge = ""
    if edge and not CACHE_RE.match(edge):
        raise ServeError("invalid Cloudflare cache value")
    return {"name": name, "kind": kind, "path": path, "prefix": prefix, "hosts": hosts, "cache": cache, "edge_cache": edge,
            "precompress": 1 if d.get("precompress", True) and kind != "proxy" else 0,
            "browse": 1 if d.get("browse") and kind == "files" else 0,
            "transforms": 1 if d.get("transforms", True) and kind == "files" else 0,
            "enabled": 1 if d.get("enabled", True) else 0, "note": str(d.get("note") or "")[:300],
            "strip": 0 if kind == "proxy" and d.get("strip") is False else 1,
            "gate": clean_gate(d) if kind == "proxy" else None}


def clean_patterns(v):
    pats = [p.strip() for p in (v if isinstance(v, list) else str(v or "").splitlines()) if p.strip()]
    if not pats:
        raise ServeError("at least one path pattern is required (e.g. /private/*)")
    rx = [p for p in pats if p.startswith("re:")]
    if rx and len(pats) > 1:
        raise ServeError("a regex pattern (re:...) must be the only pattern of its rule")
    for p in pats:
        if p.startswith("re:"):
            check_regex(p[3:])
        elif not PATH_PAT_RE.match(p):
            raise ServeError("patterns start with / and may not contain { } ` or \\ : %s" % p[:60])
    return pats


def clean_ips(v, allow_private=True):
    out = []
    for s in (v if isinstance(v, list) else re.split(r"[\s,;]+", str(v or ""))):
        s = s.strip()
        if not s:
            continue
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError:
            raise ServeError("not an IP or CIDR range: %s" % s)
        if not allow_private and any(net.overlaps(n) for n in NEVER_NETS):
            raise ServeError("refusing to block loopback addresses (%s) - Strata's own health checks use them" % s)
        out.append(str(net.network_address) if net.num_addresses == 1 else str(net))
    return list(dict.fromkeys(out))


def clean_countries(v):
    ccs = [c.strip().upper() for c in (v if isinstance(v, list) else re.split(r"[\s,;]+", str(v or ""))) if c.strip()]
    for c in ccs:
        if not CC_RE.match(c):
            raise ServeError("country codes are two letters (DE, US, ...; T1 = Tor, XX = unknown): %s" % c)
    if not ccs:
        raise ServeError("at least one country is required")
    return list(dict.fromkeys(ccs))


def clean_domains(v):
    ds = [d.strip().lower().lstrip("*.") for d in (v if isinstance(v, list) else re.split(r"[\s,;]+", str(v or ""))) if d.strip()]
    for d in ds:
        if not HOST_RE.match(d):
            raise ServeError("invalid domain: %s" % d)
    return list(dict.fromkeys(ds))


def bcrypt_hash(pw):
    if len(pw) < 6:
        raise ServeError("passwords need at least 6 characters")
    # caddy reads one line from stdin (EOF without a newline) - never pass the password as an argument.
    # Bytes, not text=True: on Windows text mode writes "\r\n" and caddy would hash the trailing "\r" too.
    r = subprocess.run([CFG["caddy_exe"], "hash-password", "--bcrypt-cost", "11"], input=(pw + "\n").encode("utf-8"),
                       capture_output=True, timeout=60, creationflags=NOWIN)
    out = (r.stdout or b"").decode("utf-8", "replace").strip().splitlines()
    h = out[-1].strip() if out else ""
    if not h.startswith("$2"):
        raise ServeError("caddy hash-password failed: %s" % (r.stderr or b"").decode("utf-8", "replace")[:200])
    return h


def clean_rule(d, old=None):
    action = d.get("action")
    if action not in ACTIONS:
        raise ServeError("unknown action")
    mount = d.get("mount")
    mount = int(mount) if mount not in (None, "", "all", 0, "0") else None
    if mount is not None and not core.mount(mount):
        raise ServeError("unknown drive")
    p = d.get("params") or {}
    params = {}
    if action == "password":
        users = []
        oldusers = {u["user"]: u for u in ((old or {}).get("params") or {}).get("users", [])}
        for u in p.get("users") or []:
            name = str(u.get("user") or "").strip()
            if not re.match(r"^[A-Za-z0-9._@-]{1,40}$", name):
                raise ServeError("user names: letters, digits and . _ @ - only")
            if u.get("password"):
                users.append({"user": name, "hash": bcrypt_hash(str(u["password"]))})
            elif name in oldusers:
                users.append(oldusers[name])
            else:
                raise ServeError("password required for new user %s" % name)
        if not users:
            raise ServeError("add at least one user")
        params = {"users": users, "realm": re.sub(r"[^A-Za-z0-9 ._-]", "", str(p.get("realm") or "Protected"))[:40] or "Protected"}
    elif action == "ip_allow":
        params = {"ips": clean_ips(p.get("ips"))}
        if not params["ips"]:
            raise ServeError("add at least one IP or range")
    elif action in ("geo_allow", "geo_deny"):
        params = {"countries": clean_countries(p.get("countries"))}
    elif action == "hotlink":
        params = {"domains": clean_domains(p.get("domains"))}
    elif action == "cache":
        v = str(p.get("value") or "").strip()
        if not CACHE_RE.match(v):
            raise ServeError("invalid Cache-Control value")
        params = {"value": v}
    elif action == "redirect":
        to = str(p.get("to") or "").strip()
        if not re.match(r"^(https?://[^\s`{}]+|/[^\s`{}]*)$", to):
            raise ServeError("redirect target must be a URL or a path")
        params = {"to": to, "code": 301 if str(p.get("code")) == "301" else 302}
    elif action == "player":
        bg = str(p.get("placeholders") or "").strip().rstrip("/")
        if bg and (not bg.startswith("/") or "*" in bg or not PATH_PAT_RE.match(bg) or "/../" in bg + "/"):
            raise ServeError("placeholder folder must be a URL path like /share/placeholders")
        params = {"placeholders": bg}
    exp = d.get("expires")
    return {"name": str(d.get("name") or ACTIONS[action]).strip()[:80], "mount": mount,
            "patterns": clean_patterns(d.get("patterns")), "action": action, "params": params,
            "enabled": 1 if d.get("enabled", True) else 0, "expires": float(exp) if exp else None,
            "note": str(d.get("note") or "")[:300]}


def clean_bl(d):
    kind = d.get("kind")
    if kind not in BL_KINDS:
        raise ServeError("unknown blacklist type")
    raw = str(d.get("value") or "").strip()
    if kind in ("ip", "cidr"):
        vals = clean_ips(raw, allow_private=False)
        if len(vals) != 1:
            raise ServeError("one address or range per entry (use bulk import for lists)")
        value = vals[0]
        kind = "cidr" if "/" in value else "ip"
    elif kind == "country":
        value = clean_countries(raw)[0]
    elif kind == "asn":
        if not raw.upper().lstrip("AS").isdigit():
            raise ServeError("ASN is a number, e.g. 14061 or AS14061")
        value = str(int(raw.upper().lstrip("AS")))
    elif kind == "ua_contains":
        if not 1 <= len(raw) <= 120 or re.search(r"[`\r\n]", raw) or "{$" in raw:
            raise ServeError("1-120 characters, no backticks")
        value = raw
    elif kind == "ua_regex":
        value = check_regex(raw)
    elif kind == "agent":
        if raw not in AGENT_CLASSES:
            raise ServeError("client class must be one of: " + ", ".join(AGENT_CLASSES))
        value = raw
    elif kind == "browser":
        if raw not in BROWSER_RE:
            raise ServeError("unknown browser family")
        value = raw
    elif kind == "os":
        if raw not in OS_RE:
            raise ServeError("unknown operating system")
        value = raw
    elif kind == "referer":
        value = clean_domains(raw)[0]
    else:
        value = clean_patterns([raw])[0]
        if value.startswith("re:"):
            raise ServeError("use a glob for paths, e.g. *.php or /wp-*")
    action = "challenge" if d.get("action") == "challenge" else "block"
    scope = d.get("scope") if d.get("scope") in ("origin", "edge", "both") else "both"
    if kind == "asn" or action == "challenge":
        scope = "edge"
    if kind in ("ua_regex", "path") and scope == "edge":
        scope = "origin"
    exp = d.get("expires")
    return {"kind": kind, "value": value, "action": action, "scope": scope,
            "enabled": 1 if d.get("enabled", True) else 0, "expires": float(exp) if exp else None,
            "note": str(d.get("note") or "")[:300], "source": str(d.get("source") or "manual")[:20]}


MOD_ALLOWED = {"w": r"^\d{1,4}$", "h": r"^\d{1,4}$", "fit": r"^(cover|contain|inside|fill)$",
               "fm": r"^(webp|avif|jpeg|jpg|png|auto)$", "q": r"^\d{1,3}$", "dl": r"^1$", "ver": r"^\d{1,6}$",
               "v": r"^[A-Za-z0-9._-]{1,20}$", "t": r"^[A-Za-z0-9._-]{1,40}$"}


def clean_mods(m):
    out = {}
    for k, v in (m or {}).items():
        v = str(v).strip()
        if v == "" or k not in MOD_ALLOWED:
            continue
        if not re.match(MOD_ALLOWED[k], v):
            raise ServeError("invalid value for %s" % k)
        out[k] = v
    return out


def clean_link(d, is_new):
    code = str(d.get("code") or "").strip() or secrets.token_urlsafe(5).replace("-", "x").replace("_", "y")
    if not CODE_RE.match(code):
        raise ServeError("link codes: 2-40 letters, digits, - or _")
    url = str(d.get("url") or "").strip()
    mount = d.get("mount")
    path = str(d.get("path") or "").strip()
    if url:
        if not re.match(r"^https?://[^\s`{}]+$", url):
            raise ServeError("external targets must be http(s) URLs")
        mount, path = None, ""
    else:
        if not core.mount(mount):
            raise ServeError("pick a drive and file for the link target")
        if not path.startswith("/") or re.search(r"[`{}\x00-\x1f]", path):
            raise ServeError("invalid target path")
        mount = int(mount)
    exp, mx = d.get("expires"), d.get("max_clicks")
    days = float((CFG.get("links") or {}).get("default_days") or 0)
    if is_new and "expires" not in d and days > 0:  # share links expire by default; an explicit null means never
        exp = now() + days * 86400
    return {"code": code, "mount": mount, "path": path, "url": url, "mods": clean_mods(d.get("mods")),
            "expires": float(exp) if exp else None, "max_clicks": int(mx) if mx not in (None, "", 0, "0") else None,
            "enabled": 1 if d.get("enabled", True) else 0, "note": str(d.get("note") or "")[:300]}


# ---------------------------------------------------------------- site settings + seeding

def stats_host():
    """The public statistics hostname of this instance (stats.<zone>), if it has one."""
    return next((h for h in CFG["public"]["hosts"] if h.startswith("stats.")), "")


def site_default():
    """Site settings before anything was saved in the database - derived from this instance's strata.json."""
    sh = stats_host()
    return {
        "listen": CFG["instance"].get("cdn_listen") or ":8080", "log_file": CFG["access_log"], "roll_size": "50MiB",
        "roll_keep": 10, "roll_keep_for": "720h", "encode": ["gzip", "zstd"], "nosniff": True, "hide_server": True,
        "error_mount": 1, "error_page": "/404/404.html", "error_page_403": "/404/403.html", "error_page_502": "",
        "unknown_host": "404 - Unknown host",
        "quiet": [{"host": sh, "paths": ["/api/live", "/api/stats"]}] if sh else [],
        "link_prefix": "/l/",
    }


def site(db):
    s = site_default()
    s.update(get_meta(db, "site", {}) or {})
    return s


def seed(db):
    """First run of an instance: a files drive on the first storage path for the CDN hostnames, the public
    statistics page (Strata Telemetry) on stats.<zone>, and the built-in hiding rules."""
    if db.execute("SELECT count(*) FROM mount").fetchone()[0]:
        return False
    t = now()
    sh = stats_host()
    cdn = [h for h in CFG["public"]["hosts"] if h != sh] or ["localhost"]
    tele = "127.0.0.1:8082"
    try:
        with open(os.path.join(core.HOME, "telemetry", "telemetry.json"), encoding="utf-8-sig") as f:
            tele = json.load(f).get("listen") or tele
    except (OSError, ValueError):
        pass
    rows = []
    if CFG["storage_paths"]:
        rows.append((1, "Storage", "files", CFG["storage_paths"][0], "/", cdn, BROWSER_REVALIDATE, 1, 0, 1, 10,
                     "first storage path of this instance"))
    if sh:
        rows.append((3, "Public statistics", "proxy", tele, "/", [sh], "", 0, 0, 0, 20, "Strata Telemetry"))
    for mid, name, kind, path, prefix, hosts, cache, pre, browse, tf, sort, note in rows:
        db.execute("INSERT INTO mount(id,name,kind,path,prefix,hosts,cache,edge_cache,precompress,browse,transforms,"
                   "enabled,sort,note,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,1,?,?,?,?)",
                   [mid, name, kind, path, prefix, json.dumps(hosts), cache, EDGE_LONG if kind == "files" else "",
                    pre, browse, tf, sort, note, t, t])
    for sort, name, pats, action, note in [
            (0, "Hide dot-files", ["re:/\\."], "hide", "built in: .env, .git, Strata's own .strata-* folders"),
            (1, "Hide Windows system folders", ["/System*", "/$RECYCLE.BIN*"], "hide", "built in")]:
        db.execute("INSERT INTO rule(name,mount,patterns,action,params,enabled,sort,note,builtin,created,updated) "
                   "VALUES(?,?,?,?,?,1,?,?,1,?,?)", [name, None, json.dumps(pats), action, "{}", sort, note, t, t])
    set_meta(db, "site", site_default())
    set_meta(db, "cache_policy_v2", {"ts": t, "mounts": 0})
    core.mounts(refresh=True)
    return True


def upgrade_cache_policy(db):
    """One-time: drives still on the old default (immutable for a year, in browsers too) move to browser revalidation
    plus a year at Cloudflare. With `immutable`, a browser that has a file never asks again, so deleting it cannot
    take it back from anyone who already loaded it; with revalidation the next view gets the 403/404."""
    if get_meta(db, "cache_policy_v2"):
        return 0
    n = db.execute("UPDATE mount SET cache=?, edge_cache=?, updated=? WHERE kind='files' AND cache=? "
                   "AND coalesce(edge_cache, '')=''", [BROWSER_REVALIDATE, EDGE_LONG, now(), OLD_MEDIA_CACHE]).rowcount
    set_meta(db, "cache_policy_v2", {"ts": now(), "mounts": n})
    if n:
        core.mounts(refresh=True)
        log("serving: %d drive(s) moved from '%s' to browser '%s' + Cloudflare '%s'" % (
            n, OLD_MEDIA_CACHE, BROWSER_REVALIDATE, EDGE_LONG))
    return n


def ensure_secret():
    if not CFG.get("sign_secret"):
        core.save_config({"sign_secret": secrets.token_urlsafe(32)})


# ---------------------------------------------------------------- data access

def load(db):
    def js(rows, *cols):
        for r in rows:
            for c in cols:
                r[c] = json.loads(r[c]) if r.get(c) else ([] if c in ("hosts", "patterns") else {})
        return rows
    return {
        "mounts": js(rows_of(db.execute("SELECT * FROM mount ORDER BY sort, id")), "hosts"),
        "rules": js(rows_of(db.execute("SELECT * FROM rule ORDER BY sort, id")), "patterns", "params"),
        "blacklist": rows_of(db.execute("SELECT * FROM blacklist ORDER BY id DESC")),
        "links": js(rows_of(db.execute("SELECT * FROM link ORDER BY created DESC")), "mods"),
        "site": site(db),
    }


def link_status(l):
    if not l["enabled"]:
        return "disabled"
    if l.get("expires") and l["expires"] < now():
        return "expired"
    if l.get("max_clicks") and (l.get("clicks") or 0) >= l["max_clicks"]:
        return "exhausted"
    return "active"


def cdn_hosts(mounts):
    return list(dict.fromkeys(h for m in mounts if m["kind"] in ("files", "page") and m["enabled"] for h in m["hosts"]))


def preferred_host(hosts):
    return next((h for h in hosts if h.startswith("cdn.")), hosts[0] if hosts else "localhost")


def public_url(m, path, mods=None):
    """Absolute public URL for a file inside mount m (path is relative to the drive, starting with /)."""
    prefix = "" if m["prefix"] == "/" else m["prefix"]
    url = "https://" + preferred_host(m["hosts"]) + urllib.parse.quote(prefix + path)
    if mods:
        url += "?" + urllib.parse.urlencode(mods)
    return url


def link_target(l, mounts):
    if l.get("url"):
        u = l["url"]
        if l.get("mods"):
            u += ("&" if "?" in u else "?") + urllib.parse.urlencode(l["mods"])
        return u
    m = next((x for x in mounts if x["id"] == l["mount"]), None)
    if not m:
        return None
    return public_url(m, l["path"], l.get("mods"))


# ---------------------------------------------------------------- signed links

def sign(path, exp):
    msg = "%s\n%d" % (urllib.parse.unquote(path), int(exp))
    mac = hmac.new(CFG["sign_secret"].encode(), msg.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode().rstrip("=")[:32]


def signed_url(m, path, seconds, mods=None):
    exp = int(now() + seconds)
    prefix = "" if m["prefix"] == "/" else m["prefix"]
    q = dict(mods or {})
    q.update(exp=exp, sig=sign(prefix + path, exp))
    return public_url(m, path) + "?" + urllib.parse.urlencode(q), exp


# ---------------------------------------------------------------- rendering

class Out:
    def __init__(self):
        self.lines = []
        self.n = collections.Counter()

    def add(self, depth, text):
        self.lines.append("\t" * depth + text)

    def name(self, base):
        self.n[base] += 1
        return "%s_%d" % (base, self.n[base])

    def matcher(self, depth, name, conds):
        if len(conds) == 1 and "\n" not in conds[0]:
            self.add(depth, "@%s %s" % (name, conds[0]))
            return
        self.add(depth, "@%s {" % name)
        for c in conds:
            self.add(depth + 1, c)
        self.add(depth, "}")


def host_cond(hosts):
    return "host " + " ".join(bq(h) for h in hosts)


def path_conds(pats, out, prefix="p"):
    rx = [p[3:] for p in pats if p.startswith("re:")]
    if rx:
        return ["path_regexp %s %s" % (out.name(prefix + "rx"), bq(rx[0]))]
    return ["path " + " ".join(bq(p) for p in pats)]


def exception_conds(allows, out):
    conds = []
    for a in allows:
        if any(p.startswith("re:") for p in a["patterns"]):
            conds.append("not path_regexp %s %s" % (out.name("ex"), bq(a["patterns"][0][3:])))
        else:
            conds.append("not path " + " ".join(bq(p) for p in a["patterns"]))
    return conds


def render_service(o, m, n, depth):
    """`handle @n` for a proxy drive. With access = login the gate sits inside this same handle, in a literal
    `route`, before the reverse_proxy: no access rule, `allow` exception or path trick can reach the upstream without
    a session for this drive, and if the gate is down forward_auth answers 502 (fail-closed)."""
    g = gate.conf(m)
    pre = "" if m["prefix"] == "/" else m["prefix"]
    d = depth + 2
    o.add(depth, "handle @%s {" % n)
    o.add(depth + 1, "route {")
    if g["mode"] == "login":
        def gate_headers(k):  # set by Caddy - whatever a client sent under these names is overwritten
            o.add(k, "header_up X-Strata-Gate-Mount %d" % m["id"])
            o.add(k, "header_up X-Strata-Client-Ip {client_ip}")
        at = ""
        if g["public"]:  # explicit exceptions; raw paths that could be normalised into something else are refused
            rb = o.name("raw%d" % m["id"])
            o.add(d, "@%s vars_regexp %s {http.request.orig_uri} %s" % (rb, rb, bq(gate.RAW_BAD)))
            o.add(d, "respond @%s `Bad Request` 400" % rb)
            at = "@%s " % o.name("auth%d" % m["id"])
            o.add(d, "%snot path %s" % (at, " ".join(bq(p) for p in g["public"])))
        gl = o.name("gate%d" % m["id"])
        o.add(d, "@%s path %s" % (gl, bq(pre + gate.PATH + "/*")))
        o.add(d, "handle @%s {" % gl)
        o.add(d + 1, "reverse_proxy %s {" % CFG["gate_listen"])
        gate_headers(d + 2)
        o.add(d + 1, "}")
        o.add(d, "}")
        o.add(d, "forward_auth %s%s {" % (at, CFG["gate_listen"]))
        o.add(d + 1, "uri %s/check" % gate.PATH)
        gate_headers(d + 1)
        o.add(d, "}")
        # signed-in pages are per person: never at Cloudflare, never in a shared cache
        o.add(d, "header %s>Cache-Control `private, no-store`" % at)
        o.add(d, "header %s-%s" % (at, EDGE_HEADER))
        o.add(d, "header %s-CDN-Cache-Control" % at)
    if pre:
        ex = o.name("svc%d" % m["id"])
        o.add(d, "@%s path %s" % (ex, bq(pre)))
        o.add(d, "redir @%s %s 308" % (ex, bq(pre + "/")))
        if m.get("strip", 1):
            o.add(d, "uri strip_prefix %s" % bq(pre))
    o.add(d, "reverse_proxy %s {" % m["path"])
    o.add(d + 1, "header_down -Via")  # don't advertise the proxy chain
    if g["mode"] == "login":  # the service never sees the gate's cookies
        o.add(d + 1, "header_up Cookie %s %s" % (bq(gate.COOKIE_RX), '""'))
    o.add(d, "}")
    o.add(depth + 1, "}")
    o.add(depth, "}")


def ua_alternatives(entries):
    parts = []
    for e in entries:
        k, v = e["kind"], e["value"]
        if k == "ua_contains":
            parts.append(re.escape(v))
        elif k == "ua_regex":
            parts.append("(?:%s)" % v)
        elif k == "agent" and AGENT_CLASSES.get(v):
            parts.append("(?:%s)" % AGENT_CLASSES[v])
        elif k == "browser":
            parts.append("(?:%s)" % BROWSER_RE[v])
        elif k == "os":
            parts.append("(?:%s)" % OS_RE[v])
    return parts


def re2_literal(s):
    """s as a literal inside an RE2 regex in a backtick Caddyfile token: metacharacters escaped, backtick as \\x60
    (so bq() accepts it), and braces escaped, which also keeps `{$` and Caddyfile placeholder shorthands out."""
    return "".join("\\" + c if c in RE2_META else r"\x60" if c == "`" else c for c in s)


def bin_rows(db):
    """{(mount id, 'bin'|'gone'): [row]} - binned paths, and deleted ones still inside the gone_days window."""
    gone_after = now() - float(CFG.get("gone_days") or 30) * 86400
    out = collections.defaultdict(list)
    for r in rows_of(db.execute("SELECT mount, path, dir, state, ts FROM binpath ORDER BY mount, state, path")):
        if r["state"] == "bin" or (r["state"] == "gone" and (r["ts"] or 0) >= gone_after):
            out[(r["mount"], r["state"])].append(r)
    return out


def bin_state(db, m, rel):
    """'bin' / 'gone' / None for a drive-relative path, mirroring the generated matchers (folders cover their content)."""
    rows = bin_rows(db)
    low = rel.lower()
    for state in ("bin", "gone"):
        for r in rows.get((m["id"], state), []):
            p = r["path"].lower()
            if low == p or (r["dir"] and low.startswith(p + "/")):
                return state
    return None


MEDIA_ERRORS = set()


def media(name, *a):
    """Strata Media hook (media_rules.hook): None while media is off or media_rules is missing. A failure is logged
    (once per message) and never raised, so render() / apply() then behave exactly as without media."""
    if media_rules is None:
        return None
    try:
        return media_rules.hook(name, *a)
    except Exception as e:
        msg = "media hook %s failed: %s" % (name, e)
        if msg not in MEDIA_ERRORS:
            MEDIA_ERRORS.add(msg)
            log(msg + "\n" + traceback.format_exc())
        return None


def gallery_patterns(pats):
    """`/folder/*` also covers `/folder` itself, so the bare folder URL gets file_server's redirect to `/folder/`."""
    out = []
    for p in pats:
        if not p.startswith("re:") and p.endswith("/*") and len(p) > 2:
            out.append(p[:-2])
        out.append(p)
    return list(dict.fromkeys(out))


def render_galleries(o, rules, mounts):
    """Step 3b: `gallery` rules list matching *folders* with the gallery browse template. Only existing directories
    are taken (a nested file matcher, evaluated after the outer set has captured the drive-relative path); files,
    and folders without a rule, fall through to the normal steps (link modifiers, drive -> 404 for folders)."""
    gals = [r for r in rules if r["action"] == "gallery"]
    if gals:
        o.add(2, "# gallery folders (file_server browse with %s)" % GALLERY_TEMPLATE)
    for r in gals:
        for m in mounts:
            if m["kind"] != "files" or (r["mount"] and r["mount"] != m["id"]):
                continue
            pre = "" if m["prefix"] == "/" else m["prefix"]
            n = o.name("gal%d" % r["id"])
            conds = [host_cond(m["hosts"])] + path_conds(gallery_patterns(r["patterns"]), o, "gal")
            if pre:  # the drive's own URL space, and its drive-relative path as {re.<n>.1}
                conds.append("vars_regexp %s {path} %s" % (n, bq("(?i)^%s(/.*)?$" % re2_literal(pre))))
            o.add(2, "# %s" % re.sub(r"[\r\n]", " ", r["name"]))
            o.matcher(2, n, conds)
            o.add(2, "route @%s {" % n)
            o.add(3, "@%s_dir file {" % n)
            o.add(4, "root %s" % bq(m["path"]))
            o.add(4, "try_files %s/" % ("{re.%s.1}" % n if pre else "{path}"))
            o.add(3, "}")
            o.add(3, "handle @%s_dir {" % n)
            if pre:
                o.add(4, "uri strip_prefix %s" % bq(pre))
            o.add(4, "root * %s" % bq(m["path"]))
            o.add(4, "header Cache-Control %s" % bq(GALLERY_CACHE))
            o.add(4, "header -%s" % EDGE_HEADER)
            o.add(4, "header -Last-Modified")  # Caddy's is the newest *remaining* file: a delete would 304
            o.add(4, "file_server {")
            o.add(5, "browse %s" % bq(GALLERY_TEMPLATE))
            o.add(4, "}")
            o.add(3, "}")
            o.add(2, "}")


def player_bg(r, m):
    """The rule's placeholder folder as (drive-relative path, URL path) for drive m - None when it is not on m."""
    url = (r["params"] or {}).get("placeholders") or ""
    pre = "" if m["prefix"] == "/" else m["prefix"]
    if not url or (pre and url.lower() != pre.lower() and not url.lower().startswith(pre.lower() + "/")):
        return None
    return url[len(pre):] or "/", url


def render_players(o, rules, mounts):
    """Step 3c: `player` rules answer a browser *opening* an existing audio file (bare URL, no query) with the
    player page (player/player.html through `templates`); the page plays `?raw=1`. Phones, <audio> elements,
    fetch(), crawlers, ?dl=1 and every other query fall through to the normal steps and get the file. The bare URL
    is never cached by Cloudflare (it answers differently per client); `?raw=1` keeps the drive's edge TTL and is
    covered by the prefix purges, like every other query variant."""
    pls = [r for r in rules if r["action"] == "player"]
    if pls:
        o.add(2, "# audio player (%s/player.html for browsers opening an audio file; ?raw=1 is the file)" % PLAYER_DIR)
    for r in pls:
        for m in mounts:
            if m["kind"] != "files" or (r["mount"] and r["mount"] != m["id"]):
                continue
            pre = "" if m["prefix"] == "/" else m["prefix"]
            n = o.name("pl%d" % r["id"])
            conds = [host_cond(m["hosts"])] + path_conds(r["patterns"], o, "pl") + [
                "path_regexp %s %s" % (o.name("plx"), bq(r"(?i)\.(%s)$" % AUDIO_EXT)),
                'expression `{http.request.uri.query} == ""`']
            if pre:  # the drive's own URL space, and its drive-relative path as {re.<n>.1}
                conds.append("vars_regexp %s {path} %s" % (n, bq("(?i)^%s(/.*)?$" % re2_literal(pre))))
            o.add(2, "# %s" % re.sub(r"[\r\n]", " ", r["name"]))
            o.matcher(2, n, conds)
            o.add(2, "route @%s {" % n)
            o.add(3, "header >%s `no-store`" % EDGE_HEADER)
            o.add(3, "header +Vary `Sec-Fetch-Dest, Accept`")
            o.add(3, "@%s_page {" % n)
            o.add(4, "file {")
            o.add(5, "root %s" % bq(m["path"]))
            o.add(5, "try_files %s" % ("{re.%s.1}" % n if pre else "{path}"))
            o.add(4, "}")
            o.add(4, "expression %s" % bq(NAV_EXPR))
            o.add(4, "not header_regexp %s User-Agent %s" % (o.name("plua"), bq(PHONE_UA)))
            o.add(4, "not header_regexp %s User-Agent %s" % (o.name("plbot"), bq(PREVIEW_UA)))
            o.add(4, "not header Sec-Ch-Ua-Mobile ?1")
            o.add(3, "}")
            o.add(3, "handle @%s_page {" % n)
            o.add(4, "route {")
            if pre:
                o.add(5, "uri strip_prefix %s" % bq(pre))
            # set by Caddy only: player.html lists these folders, so a client must never choose them
            o.add(5, "request_header %s {http.request.uri.path.dir}" % PLAYER_HEADERS[0])
            bg = player_bg(r, m)
            if bg:
                o.add(5, "request_header %s %s" % (PLAYER_HEADERS[1], bq(bg[0])))
                o.add(5, "request_header %s %s" % (PLAYER_HEADERS[2], bq(bg[1])))
            else:
                o.add(5, "request_header -%s" % PLAYER_HEADERS[1])
                o.add(5, "request_header -%s" % PLAYER_HEADERS[2])
            o.add(5, "rewrite * /player.html")
            o.add(5, "root * %s" % bq(PLAYER_DIR))
            o.add(5, "header Cache-Control `private, no-store`")
            o.add(5, "header -%s" % EDGE_HEADER)
            o.add(5, "header -Last-Modified")
            o.add(5, "templates {")
            o.add(6, "root %s" % bq(m["path"]))
            o.add(5, "}")
            o.add(5, "file_server")
            o.add(4, "}")
            o.add(3, "}")
            o.add(2, "}")


def render_previews(o, mounts, rules):
    """Step 4b: link previews. A crawler on the bare URL of a file gets Open Graph tags from Transform; ?card=1 is
    the image they point at. After the access rules and the scan gate, so hidden, protected and held files never
    get one. Pictures, videos and web pages keep the platforms' own embeds. Folders get a preview only inside a
    gallery rule (anywhere else a folder URL is a 404, and a preview would list what people can't open).
    Transform answers 404 for a file that isn't there, which becomes the normal 404 page."""
    if not mounts:
        return
    o.add(2, "# link previews: Open Graph page for crawlers on the bare URL, ?card=1 is its image")

    def proxy(n, mid, page, gallery):
        o.add(2, "reverse_proxy @%s %s {" % (n, CFG["transform_listen"]))
        o.add(3, "header_up X-Strata-Mount %d" % mid)
        o.add(3, "header_up X-Strata-Embed 1" if page else "header_up -X-Strata-Embed")
        o.add(3, "header_up X-Strata-Gallery 1" if gallery else "header_up -X-Strata-Gallery")
        o.add(3, "@%s_missing status 404" % n)
        o.add(3, "handle_response @%s_missing {" % n)
        o.add(4, "error 404")
        o.add(3, "}")
        o.add(2, "}")

    ua = "header_regexp %s User-Agent %s" % (o.name("pvua"), bq(PREVIEW_UA))
    crawler = [ua, 'expression `{http.request.uri.query} == ""`']
    folder = '{http.request.uri.path}.matches("(/|/[^./]+)$")'  # a folder URL (with or without the slash)
    for r in [r for r in rules if r["action"] == "gallery"]:
        for m in mounts:
            if r["mount"] and r["mount"] != m["id"]:
                continue
            for page in (True, False):
                n = o.name("pvg%d" % r["id"])
                # one expression per matcher: the folder test joins the query test instead of being a second line
                extra = ([ua, 'expression `{http.request.uri.query} == "" && %s`' % folder] if page
                         else ["query card=1", "expression `%s`" % folder])
                o.matcher(2, n, [host_cond(m["hosts"])] + path_conds(gallery_patterns(r["patterns"]), o, "pvg") + extra)
                proxy(n, m["id"], page, True)
    for m in mounts:
        pc = [] if m["prefix"] == "/" else ["path " + bq(m["prefix"] + "/*")]
        for page in (True, False):
            n = o.name("pv%s%d" % ("p" if page else "c", m["id"]))
            conds = [host_cond(m["hosts"])] + pc + ["path_regexp %s %s" % (n, bq(r"\.[A-Za-z0-9]{1,10}$")),
                                                    "not path_regexp %s %s" % (o.name("pvn"), bq(PREVIEW_NATIVE_RX))]
            o.matcher(2, n, conds + (crawler if page else ["query card=1"]))
            proxy(n, m["id"], page, False)


def render(db):
    D = load(db)
    S = D["site"]
    mounts = [m for m in D["mounts"] if m["enabled"]]
    rules = [r for r in D["rules"] if active(r)]
    bl = [b for b in D["blacklist"] if active(b) and b["scope"] in ("origin", "both") and b["action"] == "block"]
    hosts_all = cdn_hosts(mounts)
    o = Out()
    o.add(0, "# Generated by Strata (instance %s, code %s) - do not edit by hand: use Strata > Serving."
          % (re.sub(r"[\r\n]", " ", core.HOME), re.sub(r"[\r\n]", " ", core.ROOT)))
    o.add(0, "# The previous revisions are kept in Strata's database and can be restored from the Config tab.")
    o.add(0, S["listen"] + " {")
    o.add(1, "log {")
    o.add(2, "output file %s {" % bq(S["log_file"]))
    o.add(3, "roll_size %s" % S["roll_size"])
    o.add(3, "roll_keep %d" % int(S["roll_keep"]))
    o.add(3, "roll_keep_for %s" % S["roll_keep_for"])
    o.add(2, "}")
    o.add(2, "format json")
    o.add(1, "}")
    for q in S.get("quiet") or []:
        n = o.name("quiet")
        o.matcher(1, n, [host_cond([q["host"]]), "path " + " ".join(bq(p) for p in q["paths"])])
        o.add(1, "log_skip @%s" % n)
    if S.get("encode"):
        o.add(1, "encode " + " ".join(e for e in S["encode"] if e in ("gzip", "zstd")))
    if S.get("nosniff") or S.get("hide_server"):
        o.add(1, "header {")
        if S.get("nosniff"):
            o.add(2, "X-Content-Type-Options nosniff")
        if S.get("hide_server"):
            o.add(2, "-Server")
        o.add(1, "}")
    o.add(1, "route {")
    media("prologue", o)  # Strata Media: clients cannot inject internal X-Strata-* request headers

    # 1 blacklist (LAN / loopback are never blocked, so Strata's probes and your own network keep working)
    safe = "not client_ip private_ranges"
    ips = [b["value"] for b in bl if b["kind"] in ("ip", "cidr")]
    if ips:
        o.add(2, "# blacklist")
        for i in range(0, len(ips), 400):
            n = o.name("bl_ip")
            o.matcher(2, n, ["client_ip " + " ".join(ips[i:i + 400]), safe])
            o.add(2, "respond @%s `Forbidden` 403" % n)
    ccs = [b["value"] for b in bl if b["kind"] == "country"]
    if ccs:
        n = o.name("bl_cc")
        o.matcher(2, n, ["header_regexp %s Cf-Ipcountry %s" % (n, bq("^(%s)$" % "|".join(ccs))), safe])
        o.add(2, "respond @%s `Forbidden` 403" % n)
    parts = ua_alternatives(bl)
    if parts:
        n = o.name("bl_ua")
        o.matcher(2, n, ["header_regexp %s User-Agent %s" % (n, bq("(?i)(?:%s)" % "|".join(parts))), safe])
        o.add(2, "respond @%s `Forbidden` 403" % n)
    if any(b["kind"] == "agent" and b["value"] == "empty" for b in bl):
        n = o.name("bl_noua")
        o.matcher(2, n, ["expression `{http.request.header.User-Agent} == \"\"`", safe])
        o.add(2, "respond @%s `Forbidden` 403" % n)
    refs = [b["value"] for b in bl if b["kind"] == "referer"]
    if refs:
        n = o.name("bl_ref")
        rx = r"(?i)^https?://([^/:]+\.)?(%s)(?::\d+)?(?:/|$)" % "|".join(re.escape(r) for r in refs)
        o.matcher(2, n, ["header_regexp %s Referer %s" % (n, bq(rx)), safe])
        o.add(2, "respond @%s `Forbidden` 403" % n)
    bpaths = [b["value"] for b in bl if b["kind"] == "path"]
    if bpaths:
        n = o.name("bl_path")
        o.matcher(2, n, ["path " + " ".join(bq(p) for p in bpaths), safe])
        o.add(2, "respond @%s `Forbidden` 403" % n)

    # 2 access rules
    allows = [r for r in rules if r["action"] == "allow"]
    if rules:
        o.add(2, "# access rules")
    for r in rules:
        if r["action"] in ("allow", "gallery", "player"):
            continue
        scope = None
        if r["mount"]:
            m = next((x for x in mounts if x["id"] == r["mount"]), None)
            if not m:
                continue
            scope = m["hosts"]
        mine = [a for a in allows if not a["mount"] or a["mount"] == r["mount"]]
        base = ([host_cond(scope)] if scope else []) + path_conds(r["patterns"], o) + exception_conds(mine, o)
        n = o.name("r%d" % r["id"])
        o.add(2, "# %s" % re.sub(r"[\r\n]", " ", r["name"]))
        o.matcher(2, n, base)
        a, p = r["action"], r["params"]
        if a in PRIVATE_ACTIONS:  # never let Cloudflare cache what the origin restricts
            o.add(2, "header @%s >Cache-Control `private, no-store`" % n)
            o.add(2, "header @%s -%s" % (n, EDGE_HEADER))  # else the drive's edge TTL would still cache it
        if a == "hide":
            o.add(2, "error @%s 404" % n)
        elif a == "deny":
            o.add(2, "error @%s 403" % n)
        elif a == "password":
            o.add(2, "basic_auth @%s bcrypt %s {" % (n, bq(p.get("realm") or "Protected")))
            for u in p["users"]:
                o.add(3, "%s %s" % (bq(u["user"]), u["hash"]))
            o.add(2, "}")
        elif a == "signed":
            o.add(2, "forward_auth @%s %s {" % (n, CFG["transform_listen"]))
            o.add(3, "uri /_gate")
            o.add(2, "}")
        elif a in ("ip_allow", "geo_allow", "geo_deny", "hotlink"):
            d = o.name("r%dd" % r["id"])
            extra = []
            if a == "ip_allow":
                extra = ["not client_ip " + " ".join(p["ips"])]
            elif a == "geo_allow":
                extra = ["not header_regexp %s Cf-Ipcountry %s" % (o.name("g"), bq("^(%s)$" % "|".join(p["countries"])))]
            elif a == "geo_deny":
                extra = ["header_regexp %s Cf-Ipcountry %s" % (o.name("g"), bq("^(%s)$" % "|".join(p["countries"])))]
            else:
                doms = list(dict.fromkeys(p["domains"] + hosts_all))
                rx = r"(?i)^https?://([^/:]+\.)?(%s)(?::\d+)?(?:/|$)" % "|".join(re.escape(x) for x in doms)
                extra = ["header Referer *", "not header_regexp %s Referer %s" % (o.name("hl"), bq(rx))]
            o.matcher(2, d, base + extra)
            o.add(2, "error @%s 403" % d)
        elif a == "download":
            o.add(2, "header @%s >Content-Disposition `attachment`" % n)
        elif a == "cache":  # governs Cloudflare too: without the edge header it follows Cache-Control
            o.add(2, "header @%s >Cache-Control %s" % (n, bq(p["value"])))
            o.add(2, "header @%s -%s" % (n, EDGE_HEADER))
        elif a == "redirect":
            o.add(2, "redir @%s %s %d" % (n, bq(p["to"]), p.get("code", 302)))

    # 2b services at a URL prefix: right after the blacklist and access rules, so short links, galleries, link
    # modifiers and Strata Media (all meant for folder drives) never answer inside a service's prefix
    for m in sorted([m for m in mounts if m["kind"] == "proxy" and m["prefix"] != "/"], key=lambda m: -len(m["prefix"])):
        n = o.name("m%d" % m["id"])
        o.add(2, "# service %s" % re.sub(r"[\r\n]", " ", m["name"]))
        o.matcher(2, n, [host_cond(m["hosts"]), "path " + bq(m["prefix"]) + " " + bq(m["prefix"] + "/*")])
        render_service(o, m, n, 2)

    # 3 short links (tracked: each click is a logged 302 that Cloudflare does not cache)
    if D["links"] and hosts_all:
        o.add(2, "# short links")
        lp = S.get("link_prefix") or "/l/"
        for l in D["links"]:
            n = o.name("l")
            o.matcher(2, n, [host_cond(hosts_all), "path " + bq(lp + l["code"])])
            o.add(2, "header @%s >Cache-Control `no-store`" % n)
            target = link_target(l, D["mounts"]) if link_status(l) == "active" else None
            if target:
                o.add(2, "redir @%s %s 302" % (n, bq(target)))
            else:
                o.add(2, "respond @%s `This link has expired.` 410" % n)

    render_galleries(o, rules, mounts)
    render_players(o, rules, mounts)

    media("file_policy", o, mounts, allows)  # Strata Media: dangerous -> 404, unknown type -> 403, SVG CSP

    # 4 link modifiers
    fmounts = [m for m in mounts if m["kind"] == "files"]
    if fmounts:
        o.add(2, "# link modifiers: ?dl=1  ?w= ?h= ?fit= ?fm= ?q=  ?ver=")
    for m in fmounts:
        pc = [] if m["prefix"] == "/" else ["path " + bq(m["prefix"] + "/*")]
        n = o.name("dl%d" % m["id"])
        o.matcher(2, n, [host_cond(m["hosts"])] + pc + ["query dl=1"])
        o.add(2, "header @%s >Content-Disposition `attachment; filename=\"{http.request.uri.path.file}\"`" % n)
        if not m["transforms"]:
            continue
        up = ["header_up X-Strata-Mount %d" % m["id"], "header_up X-Strata-Cache %s" % bq(m["cache"])]
        if m.get("edge_cache"):
            up.append("header_up X-Strata-Edge-Cache %s" % bq(m["edge_cache"]))

        def transform_proxy(n):
            o.add(2, "reverse_proxy @%s %s {" % (n, CFG["transform_listen"]))
            for u in up:
                o.add(3, u)
            # Transform's 404 becomes a real error, so a binned / deleted file's ?w= or ?ver= gets the 403 / 404 page
            o.add(3, "@%s_missing status 404" % n)
            o.add(3, "handle_response @%s_missing {" % n)
            o.add(4, "error 404")
            o.add(3, "}")
            o.add(2, "}")
        if not media("media_routes", o, m, up, db):  # Strata Media takes ?_v= ?w= ... (not ?ver=) when it is on
            n = o.name("tf%d" % m["id"])
            o.matcher(2, n, [host_cond(m["hosts"])] + pc + [
                "path_regexp %s %s" % (n, bq(IMAGE_RX)),
                "expression `{query.w} != \"\" || {query.h} != \"\" || {query.fm} != \"\" || {query.q} != \"\" || {query.fit} != \"\"`"])
            transform_proxy(n)
        n = o.name("ver%d" % m["id"])
        o.matcher(2, n, [host_cond(m["hosts"])] + pc + ["expression `{query.ver} != \"\"`"])
        transform_proxy(n)
    media("gate", o, fmounts)  # Strata Media: scan gate (forward_auth) + large-file lane
    render_previews(o, fmounts, rules)

    # 5 drives
    o.add(2, "# drives")
    order = sorted(mounts, key=lambda m: ({"page": 0, "files": 1, "proxy": 2}[m["kind"]], -len(m["prefix"]), m["sort"]))
    for m in order:
        if m["kind"] == "proxy" and m["prefix"] != "/":
            continue  # rendered in 2b
        n = o.name("m%d" % m["id"])
        o.add(2, "# %s" % re.sub(r"[\r\n]", " ", m["name"]))
        if m["kind"] == "page":
            o.matcher(2, n, [host_cond(m["hosts"]), "path /"])
        elif m["kind"] == "files" and m["prefix"] != "/":
            o.matcher(2, n, [host_cond(m["hosts"]), "path " + bq(m["prefix"]) + " " + bq(m["prefix"] + "/*")])
        else:
            o.matcher(2, n, [host_cond(m["hosts"])])
        if m["kind"] == "proxy":
            render_service(o, m, n, 2)
            continue
        o.add(2, "handle @%s {" % n)
        if m["kind"] == "files" and m["prefix"] != "/":
            o.add(3, "uri strip_prefix %s" % bq(m["prefix"]))
        o.add(3, "root * %s" % bq(m["path"]))
        if m["cache"]:
            o.add(3, "header Cache-Control %s" % bq(m["cache"]))
        if m.get("edge_cache"):
            o.add(3, "header %s %s" % (EDGE_HEADER, bq(m["edge_cache"])))
        opts = (["precompressed br"] if m["precompress"] else []) + (["browse"] if m["browse"] else [])
        if opts:
            o.add(3, "file_server {")
            for x in opts:
                o.add(4, x)
            o.add(3, "}")
        else:
            o.add(3, "file_server")
        o.add(2, "}")
    o.add(2, "handle {")
    o.add(3, "respond %s 404" % bq(S["unknown_host"]))
    o.add(2, "}")
    o.add(1, "}")

    # errors: never cacheable (headers the failed route already set - the drive's Cache-Control and edge TTL - are
    # still on the response, so both are overridden here)
    em = next((m for m in mounts if m["id"] == S.get("error_mount") and m["kind"] in ("files", "page")), None)

    def no_store(depth):
        o.add(depth, "header Cache-Control `no-store`")
        o.add(depth, "header -%s" % EDGE_HEADER)

    def error_page(depth, page, status, text):
        if em and page:
            o.add(depth, "root * %s" % bq(em["path"]))
            o.add(depth, "rewrite * %s" % bq(page))
            o.add(depth, "file_server {")
            o.add(depth + 1, "status %s" % status)
            o.add(depth, "}")
        else:
            o.add(depth, "respond %s %s" % (bq(text), status))

    # recycle bin: only reached when the file is missing, so a new upload or a restore at the path is never blocked.
    # Matched on the original path (before strip_prefix), case-insensitively like the share; folders cover their content.
    bins = bin_rows(db)
    wipe = "header Clear-Site-Data %s" % bq('"cache"')  # visitors' browsers drop what they cached from this origin
    o.add(1, "handle_errors 404 {")
    no_store(2)
    for state, page, status, what in (("bin", S.get("error_page_403"), 403, "in the trash: 403 until restored"),
                                      ("gone", S.get("error_page"), 404, "deleted permanently: 404 + cache wipe")):
        for m in [x for x in mounts if x["kind"] == "files"]:
            pre = "" if m["prefix"] == "/" else m["prefix"]
            alts = [re2_literal(pre + r["path"]) + ("(?:/.*)?" if r["dir"] else "") for r in bins.get((m["id"], state), [])]
            for i in range(0, len(alts), 200):
                n = o.name(state + str(m["id"]))
                if i == 0:
                    o.add(2, "# %s - %s" % (re.sub(r"[\r\n]", " ", m["name"]), what))
                o.matcher(2, n, [host_cond(m["hosts"]), "vars_regexp %s {http.request.orig_uri.path} %s" % (
                    n, bq("(?i)^(?:%s)$" % "|".join(alts[i:i + 200])))])
                o.add(2, "handle @%s {" % n)
                o.add(3, wipe)
                error_page(3, page, status, "Forbidden" if status == 403 else "Not Found")
                o.add(2, "}")
    o.add(2, "handle {")
    error_page(3, S.get("error_page"), "{err.status_code}", "{err.status_code} {err.status_text}")
    o.add(2, "}")
    o.add(1, "}")
    if em and S.get("error_page_403"):
        o.add(1, "handle_errors 403 {")
        no_store(2)
        error_page(2, S["error_page_403"], 403, "Forbidden")
        o.add(1, "}")
    if em and S.get("error_page_502"):  # a proxied service (or Transform, or the gate) is down or too slow
        o.add(1, "handle_errors 502 503 504 {")
        no_store(2)
        error_page(2, S["error_page_502"], "{err.status_code}", "")
        o.add(1, "}")
    o.add(1, "handle_errors {")
    no_store(2)
    o.add(2, "respond `{err.status_code} {err.status_text}`")
    o.add(1, "}")
    o.add(0, "}")
    return "\n".join(o.lines) + "\n"


# ---------------------------------------------------------------- apply / history

APPLY_LOCK = threading.Lock()


def caddy(*args, timeout=90):
    if args and args[0] == "reload" and CFG["instance"].get("dry_run"):
        return 0, ""  # test instance: configs are validated, the running Caddy is never touched
    r = subprocess.run([CFG["caddy_exe"], *args], capture_output=True, text=True, timeout=timeout, creationflags=NOWIN)
    msg = ""
    for line in (r.stderr or "").splitlines() + (r.stdout or "").splitlines():
        if line.startswith("Error:") or '"level":"error"' in line:
            msg = line
    return r.returncode, msg or (r.stderr or r.stdout or "")[-400:]


def validate(text):
    os.makedirs(GEN_DIR, exist_ok=True)
    main_path = CFG["caddyfile"]
    with open(main_path, encoding="utf-8-sig") as f:
        main = f.read()
    if IMPORT_LINE not in main:
        raise ServeError("the Caddyfile does not import %s" % GEN_FILE)
    cand = os.path.join(GEN_DIR, "cdn.candidate.caddy")
    with open(cand, "w", encoding="utf-8") as f:
        f.write(text)
    tmp_main = os.path.join(GEN_DIR, "Caddyfile.validate")
    with open(tmp_main, "w", encoding="utf-8") as f:
        f.write(main.replace(IMPORT_LINE, "import " + cand.replace("\\", "/")))
    code, msg = caddy("validate", "--config", tmp_main, "--adapter", "caddyfile")
    if code != 0:
        raise ServeError("Caddy rejected the configuration: " + msg.replace(cand.replace("\\", "/"), "cdn.caddy")[:600])


def write_transform_config(mounts):
    os.makedirs(os.path.dirname(TRANSFORM_CONFIG), exist_ok=True)
    conf = {"listen": CFG["transform_listen"], "sign_secret": CFG["sign_secret"],
            "cache_dir": os.path.join(core.HOME, "data", "tcache"), "cache_max_mb": 2048, "max_dim": 4096,
            "mounts": {str(m["id"]): {"path": m["path"], "prefix": m["prefix"]} for m in mounts
                       if m["kind"] == "files" and m["enabled"]}}
    tmp = TRANSFORM_CONFIG + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(conf, f, indent=2)
    os.replace(tmp, TRANSFORM_CONFIG)


def apply(db, user="", reason="", force=False):
    """Render -> validate -> swap -> reload. Raises ServeError (and leaves Caddy untouched) on any failure."""
    with APPLY_LOCK:
        text = render(db)
        cur = open(GEN_FILE, encoding="utf-8").read() if os.path.exists(GEN_FILE) else None
        if cur == text and not force:
            return {"changed": False}
        sha = hashlib.sha256(text.encode()).hexdigest()[:16]
        try:
            validate(text)
        except ServeError as e:
            db.execute("INSERT INTO confhist(ts,user,reason,content,sha,ok,error) VALUES(?,?,?,?,?,0,?)",
                       [now(), user, reason, text, sha, str(e)])
            raise
        write_transform_config(core.mounts(refresh=True))
        media("config", core.mounts(), db)  # Strata Media: media/media.json (no-op while media is off)
        tmp = GEN_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, GEN_FILE)
        code, msg = caddy("reload", "--config", CFG["caddyfile"], "--adapter", "caddyfile")
        if code != 0:
            if cur is not None:
                with open(GEN_FILE, "w", encoding="utf-8") as f:
                    f.write(cur)
                caddy("reload", "--config", CFG["caddyfile"], "--adapter", "caddyfile")
            raise ServeError("Caddy reload failed (previous config restored): " + msg[:400])
        db.execute("INSERT INTO confhist(ts,user,reason,content,sha,ok,error) VALUES(?,?,?,?,?,1,'')",
                   [now(), user, reason, text, sha])
        db.execute("DELETE FROM confhist WHERE id NOT IN (SELECT id FROM confhist ORDER BY id DESC LIMIT 200)")
        set_meta(db, "serving", {"ts": now(), "sha": sha, "user": user, "reason": reason})
        log("serving: applied %s (%s)" % (sha, reason))
        MATCH.dirty = True
        return {"changed": True, "sha": sha}


def mutate(user, reason, fn, preview=False):
    """Run fn(db) in a transaction, then apply. If Caddy refuses the result, the DB change is rolled back.
    preview: render the change and return its diff against the live config; nothing is committed."""
    db = connect()
    try:
        if preview:
            try:
                fn(db)
                text = render(db)
            finally:
                db.rollback()
            cur = open(GEN_FILE, encoding="utf-8").read() if os.path.exists(GEN_FILE) else ""
            return {"diff": "".join(difflib.unified_diff(cur.splitlines(True), text.splitlines(True), "live", "new", n=2))}
        with db:
            out = fn(db)
            res = apply(db, user, reason)
        core.mounts(refresh=True)
        return {"result": out, "apply": res}
    finally:
        db.close()
        core.mounts(refresh=True)


# ---------------------------------------------------------------- CRUD (called by the HTTP layer)

def gate_users(mid, g, old):
    """New gate_user rows for drive `mid` from the cleaned users (new passwords hashed here, outside the DB
    transaction - PBKDF2 is slow on purpose) + 2FA enrolments to show once. `old`: user -> (hash, totp)."""
    rows, enrol = [], []
    for u in g["users"]:
        prev = old.get(u["user"])
        if u["password"]:
            h = auth.hash_password(u["password"])
        elif prev:
            h = prev[0]
        else:
            raise ServeError("a password is required for the new user %s" % u["user"])
        totp = ""
        if u["totp"]:
            totp = prev[1] if prev and prev[1] else auth.totp_secret()
            if not (prev and prev[1]):
                uri = auth.totp_uri(totp, u["user"], issuer="Strata gate")
                enrol.append({"user": u["user"], "secret": totp, "uri": uri, "qr": auth.qr_svg(uri)})
        rows.append((mid, u["user"], h, totp))
    if g["mode"] == "login" and not rows:
        raise ServeError("a service behind a login needs at least one user")
    return rows, enrol


def save_mount(user, d):
    c = clean_mount(d)
    mid0 = int(d["id"]) if d.get("id") else None
    db0 = connect()
    try:
        old = {u: (h, t) for u, h, t in db0.execute("SELECT user, hash, coalesce(totp,'') FROM gate_user WHERE mount=?",
                                                       [mid0 or -1])}
        prev = db0.execute("SELECT kind, prefix, hosts, path, gate FROM mount WHERE id=?", [mid0 or -1]).fetchone()
        others = [x for x in load(db0)["mounts"] if x["id"] != mid0 and x["enabled"]]
        lp = (site(db0).get("link_prefix") or "/l/").rstrip("/")
    finally:
        db0.close()
    if c["kind"] == "proxy" and c["enabled"]:
        clash = [x["name"] for x in others if set(x["hosts"]) & set(c["hosts"]) and (
            c["prefix"] == "/" and x["kind"] in ("files", "page")
            or x["kind"] == "proxy" and x["prefix"].lower() == c["prefix"].lower())]
        if clash:
            raise ServeError("that hostname / prefix is already served by %s - give the service its own hostname or a "
                             "URL prefix" % ", ".join(clash))
        if c["prefix"] != "/" and lp and (c["prefix"].lower() == lp.lower() or c["prefix"].lower().startswith(lp.lower() + "/")):
            raise ServeError("%s is the short-link prefix" % c["prefix"])
    rows, enrol = gate_users(mid0, c["gate"], old) if c["kind"] == "proxy" else ([], [])
    gconf = json.dumps({"mode": c["gate"]["mode"], "hours": c["gate"]["hours"], "public": c["gate"]["public"]}
                       ) if c["kind"] == "proxy" else None

    def fn(db):
        t = now()
        if mid0:
            db.execute("UPDATE mount SET name=?,kind=?,path=?,prefix=?,hosts=?,cache=?,edge_cache=?,precompress=?,"
                       "browse=?,transforms=?,enabled=?,note=?,strip=?,gate=?,updated=? WHERE id=?",
                       [c["name"], c["kind"], c["path"], c["prefix"], json.dumps(c["hosts"]), c["cache"],
                        c["edge_cache"], c["precompress"], c["browse"], c["transforms"], c["enabled"], c["note"],
                        c["strip"], gconf, t, mid0])
            mid = mid0
        else:
            sort = (db.execute("SELECT max(sort) FROM mount").fetchone()[0] or 0) + 10
            mid = db.execute("INSERT INTO mount(name,kind,path,prefix,hosts,cache,edge_cache,precompress,browse,transforms,"
                             "enabled,sort,note,strip,gate,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                             [c["name"], c["kind"], c["path"], c["prefix"], json.dumps(c["hosts"]), c["cache"],
                              c["edge_cache"], c["precompress"], c["browse"], c["transforms"], c["enabled"], sort,
                              c["note"], c["strip"], gconf, t, t]).lastrowid
        # sessions end when what they were granted for changes: the whole drive (address, hosts, access) or a user
        # (removed, new password, 2FA changed)
        moved = not prev or (prev[0], prev[1], json.loads(prev[2] or "[]"), prev[3],
                             gate.conf({"gate": prev[4]})) != (c["kind"], c["prefix"], c["hosts"], c["path"],
                                                               gate.conf({"gate": gconf}))
        keep = {r[1]: (r[2], r[3]) for r in rows}
        if moved:
            db.execute("DELETE FROM gate_session WHERE mount=?", [mid])
        else:
            for u, v in old.items():
                if keep.get(u) != v:
                    db.execute("DELETE FROM gate_session WHERE mount=? AND user=?", [mid, u])
        db.execute("DELETE FROM gate_user WHERE mount=?", [mid])
        db.executemany("INSERT INTO gate_user(mount, user, hash, totp, created) VALUES(?,?,?,?,?)",
                       [(mid, u, h, tp, t) for _, u, h, tp in rows])
        return mid
    res = mutate(user, "drive %s saved" % c["name"], fn, d.get("preview"))
    res["enrol"] = enrol
    return res


def delete_mount(user, mid):
    def fn(db):
        n = db.execute("SELECT count(*) FROM mount").fetchone()[0]
        if n <= 1:
            raise ServeError("keep at least one drive")
        db.execute("DELETE FROM mount WHERE id=?", [int(mid)])
        db.execute("DELETE FROM rule WHERE mount=?", [int(mid)])
        db.execute("DELETE FROM gate_user WHERE mount=?", [int(mid)])
        db.execute("DELETE FROM gate_session WHERE mount=?", [int(mid)])
        return int(mid)
    return mutate(user, "drive %s deleted" % mid, fn)


def save_rule(user, d):
    db0 = connect()
    try:
        old = None
        if d.get("id"):
            old = next((r for r in load(db0)["rules"] if r["id"] == int(d["id"])), None)
    finally:
        db0.close()
    c = clean_rule(d, old)

    def fn(db):
        t = now()
        vals = [c["name"], c["mount"], json.dumps(c["patterns"]), c["action"], json.dumps(c["params"]), c["enabled"],
                c["expires"], c["note"], t]
        if d.get("id"):
            db.execute("UPDATE rule SET name=?,mount=?,patterns=?,action=?,params=?,enabled=?,expires=?,note=?,updated=? "
                       "WHERE id=?", vals + [int(d["id"])])
            return int(d["id"])
        sort = (db.execute("SELECT max(sort) FROM rule").fetchone()[0] or 0) + 1
        cur = db.execute("INSERT INTO rule(name,mount,patterns,action,params,enabled,expires,note,updated,sort,created) "
                         "VALUES(?,?,?,?,?,?,?,?,?,?,?)", vals + [sort, t])
        return cur.lastrowid
    return mutate(user, "rule %s saved" % c["name"], fn, d.get("preview"))


def delete_rule(user, rid):
    return mutate(user, "rule %s deleted" % rid, lambda db: db.execute("DELETE FROM rule WHERE id=?", [int(rid)]).rowcount)


def move_rule(user, rid, delta):
    def fn(db):
        ids = [r[0] for r in db.execute("SELECT id FROM rule ORDER BY sort, id")]
        i = ids.index(int(rid))
        j = max(0, min(len(ids) - 1, i + (1 if int(delta) > 0 else -1)))
        ids[i], ids[j] = ids[j], ids[i]
        for n, x in enumerate(ids):
            db.execute("UPDATE rule SET sort=? WHERE id=?", [n, x])
        return ids
    return mutate(user, "rule %s moved" % rid, fn)


def save_bl(user, d):
    c = clean_bl(d)

    def fn(db):
        t = now()
        if d.get("id"):
            db.execute("UPDATE blacklist SET kind=?,value=?,action=?,scope=?,enabled=?,expires=?,note=? WHERE id=?",
                       [c["kind"], c["value"], c["action"], c["scope"], c["enabled"], c["expires"], c["note"], int(d["id"])])
            return int(d["id"])
        dup = db.execute("SELECT id FROM blacklist WHERE kind=? AND value=?", [c["kind"], c["value"]]).fetchone()
        if dup:
            db.execute("UPDATE blacklist SET enabled=1, expires=?, note=?, action=?, scope=? WHERE id=?",
                       [c["expires"], c["note"] or None, c["action"], c["scope"], dup[0]])
            return dup[0]
        cur = db.execute("INSERT INTO blacklist(kind,value,action,scope,enabled,expires,note,source,created) "
                         "VALUES(?,?,?,?,?,?,?,?,?)", [c["kind"], c["value"], c["action"], c["scope"], c["enabled"],
                                                       c["expires"], c["note"], c["source"], t])
        return cur.lastrowid
    r = mutate(user, "blacklist %s %s" % (c["kind"], c["value"]), fn)
    EDGE_SYNC.set()
    return r


def bulk_bl(user, text, kind, note, expires, scope):
    added, errors = 0, []
    entries = []
    for line in str(text or "").splitlines():
        v = line.split("#", 1)[0].strip()
        if not v:
            continue
        try:
            entries.append(clean_bl({"kind": kind, "value": v, "note": note, "expires": expires, "scope": scope}))
        except ServeError as e:
            errors.append("%s: %s" % (v[:40], e))
    if len(entries) > 5000:
        raise ServeError("at most 5000 entries per import")

    def fn(db):
        n = 0
        for c in entries:
            if db.execute("SELECT 1 FROM blacklist WHERE kind=? AND value=?", [c["kind"], c["value"]]).fetchone():
                continue
            db.execute("INSERT INTO blacklist(kind,value,action,scope,enabled,expires,note,source,created) "
                       "VALUES(?,?,?,?,1,?,?,'import',?)", [c["kind"], c["value"], c["action"], c["scope"],
                                                            c["expires"], c["note"], now()])
            n += 1
        return n
    r = mutate(user, "blacklist import (%d)" % len(entries), fn)
    EDGE_SYNC.set()
    added = r["result"]
    return {"added": added, "errors": errors[:50], "apply": r["apply"]}


def delete_bl(user, ids):
    ids = [int(i) for i in (ids if isinstance(ids, list) else [ids])]

    def fn(db):
        return sum(db.execute("DELETE FROM blacklist WHERE id=?", [i]).rowcount for i in ids)
    r = mutate(user, "blacklist %d removed" % len(ids), fn)
    EDGE_SYNC.set()
    return r


def toggle_bl(user, bid, enabled):
    r = mutate(user, "blacklist %s %s" % (bid, "enabled" if enabled else "disabled"),
               lambda db: db.execute("UPDATE blacklist SET enabled=? WHERE id=?", [1 if enabled else 0, int(bid)]).rowcount)
    EDGE_SYNC.set()
    return r


def save_link(user, d):
    is_new = not d.get("original_code")
    c = clean_link(d, is_new)

    def fn(db):
        if not is_new:
            db.execute("UPDATE link SET code=?,mount=?,path=?,url=?,mods=?,expires=?,max_clicks=?,enabled=?,note=? "
                       "WHERE code=?", [c["code"], c["mount"], c["path"], c["url"], json.dumps(c["mods"]), c["expires"],
                                        c["max_clicks"], c["enabled"], c["note"], d["original_code"]])
        else:
            if db.execute("SELECT 1 FROM link WHERE code=?", [c["code"]]).fetchone():
                raise ServeError("that code is already in use")
            db.execute("INSERT INTO link(code,mount,path,url,mods,expires,max_clicks,enabled,note,created,owner) "
                       "VALUES(?,?,?,?,?,?,?,?,?,?,?)", [c["code"], c["mount"], c["path"], c["url"], json.dumps(c["mods"]),
                                                       c["expires"], c["max_clicks"], c["enabled"], c["note"], now(),
                                                       str(user or "")])  # the creator may change it later
        for k in (c["code"], d.get("original_code")):  # re-saved (e.g. re-enabled after the guard): watch it afresh
            GUARD.done.discard(k)
            GUARD.win.pop(k, None)
        return c["code"]
    return mutate(user, "link %s saved" % c["code"], fn)


def alias_link(user, code):
    """Another short code (random) for the same target and modifiers, expiring after the default share period."""
    db = connect()
    try:
        rows = rows_of(db.execute("SELECT * FROM link WHERE code=?", [code]))
    finally:
        db.close()
    if not rows:
        raise ServeError("no such link")
    src = rows[0]
    d = {"mount": src["mount"], "path": src["path"], "url": src["url"], "mods": json.loads(src["mods"] or "{}"),
         "max_clicks": src["max_clicks"], "note": ("alias of %s %s" % (code, src.get("note") or "")).strip()}
    return save_link(user, d)


def delete_link(user, code):
    return mutate(user, "link %s deleted" % code, lambda db: db.execute("DELETE FROM link WHERE code=?", [code]).rowcount)


def save_site(user, d):
    def fn(db):
        s = site(db)
        if "encode" in d:
            s["encode"] = [e for e in d["encode"] if e in ("gzip", "zstd")]
        for k in ("nosniff", "hide_server"):
            if k in d:
                s[k] = bool(d[k])
        if "unknown_host" in d:
            v = str(d["unknown_host"])[:120]
            bq(v)
            s["unknown_host"] = v
        for k in ("error_page", "error_page_403", "error_page_502"):
            if k in d:
                v = str(d[k] or "")
                if v and not PATH_PAT_RE.match(v):
                    raise ServeError("error page must be a path like /404/404.html")
                s[k] = v
        if "error_mount" in d:
            s["error_mount"] = int(d["error_mount"]) if d["error_mount"] else None
        set_meta(db, "site", s)
        return s
    return mutate(user, "site settings", fn, d.get("preview"))


def rollback(user, hid):
    db = connect()
    try:
        row = db.execute("SELECT content, sha FROM confhist WHERE id=? AND ok=1", [int(hid)]).fetchone()
        if not row:
            raise ServeError("unknown revision")
        with APPLY_LOCK:
            validate(row[0])
            cur = open(GEN_FILE, encoding="utf-8").read() if os.path.exists(GEN_FILE) else None
            with open(GEN_FILE, "w", encoding="utf-8") as f:
                f.write(row[0])
            code, msg = caddy("reload", "--config", CFG["caddyfile"], "--adapter", "caddyfile")
            if code != 0:
                if cur is not None:
                    with open(GEN_FILE, "w", encoding="utf-8") as f:
                        f.write(cur)
                    caddy("reload", "--config", CFG["caddyfile"], "--adapter", "caddyfile")
                raise ServeError("reload failed: " + msg[:300])
            with db:
                db.execute("INSERT INTO confhist(ts,user,reason,content,sha,ok,error) VALUES(?,?,?,?,?,1,'')",
                           [now(), user, "rollback to #%s" % hid, row[0], row[1]])
                set_meta(db, "serving", {"ts": now(), "sha": row[1], "user": user, "reason": "rollback",
                                         "pinned": True})
        return {"sha": row[1], "note": "Caddy now runs revision #%s. The database still holds the current rules - "
                                       "the next change re-renders from them." % hid}
    finally:
        db.close()


def state():
    db = connect()
    try:
        D = load(db)
        for l in D["links"]:
            l["status"] = link_status(l)
            l["target"] = link_target(l, D["mounts"])
            l["short"] = "https://%s%s%s" % (preferred_host(cdn_hosts(D["mounts"])), D["site"]["link_prefix"], l["code"])
        for r in D["rules"]:
            if r["action"] == "password":  # never ship hashes to the browser
                r["params"] = {"realm": r["params"].get("realm"), "users": [{"user": u["user"]} for u in r["params"].get("users", [])]}
            r["active"] = bool(active(r))
        for m in D["mounts"]:
            if m["kind"] == "proxy":  # user names and 2FA state only - hashes and TOTP secrets never leave the DB
                g = gate.conf(m)
                g["users"] = [{"user": u, "totp": bool(tp)} for u, tp in db.execute(
                    "SELECT user, coalesce(totp,'') FROM gate_user WHERE mount=? ORDER BY user", [m["id"]])]
                g["sessions"] = db.execute("SELECT count(*) FROM gate_session WHERE mount=? AND exp > ?",
                                           [m["id"], now()]).fetchone()[0]
                m["gate"] = g
            else:
                m.pop("gate", None)
            if m["kind"] != "proxy":
                try:
                    import shutil
                    du = shutil.disk_usage(m["path"])
                    m["disk"] = {"total": du.total, "used": du.used, "free": du.free}
                except OSError as e:
                    m["disk"] = None
                    m["error"] = e.strerror or str(e)
                row = db.execute("SELECT files, dirs, bytes FROM fdir WHERE mount=? AND path='/'", [m["id"]]).fetchone()
                m["index"] = {"files": row[0], "dirs": row[1], "bytes": row[2]} if row else None
        hist = rows_of(db.execute("SELECT id, ts, user, reason, sha, ok, error FROM confhist ORDER BY id DESC LIMIT 40"))
        return {"mounts": D["mounts"], "rules": D["rules"], "blacklist": D["blacklist"], "links": D["links"],
                "site": D["site"], "history": hist, "serving": get_meta(db, "serving"),
                "actions": ACTIONS, "bl_kinds": BL_KINDS, "agent_classes": list(AGENT_CLASSES),
                "browsers": list(BROWSER_RE), "oses": list(OS_RE), "generated": open(GEN_FILE, encoding="utf-8").read()
                if os.path.exists(GEN_FILE) else "", "edge": get_meta(db, "cf_sync")}
    finally:
        db.close()


# ---------------------------------------------------------------- evaluation (mirrors the generated config)

def rule_matches(r, path):
    p = path if any(x.startswith("re:") for x in r["patterns"]) else path.lower()
    return any(glob_rx(x).search(p) if x.startswith("re:") else glob_rx(x).match(p) for x in r["patterns"])


def effective(mount_id, url_path, rules=None):
    """Which rules apply to a file of a drive, as the generated Caddy config would decide."""
    if rules is None:
        db = connect()
        try:
            rules = [r for r in load(db)["rules"] if active(r)]
        finally:
            db.close()
    allows = [a for a in rules if a["action"] == "allow" and (not a["mount"] or a["mount"] == mount_id)
              and rule_matches(a, url_path)]
    hits = []
    for r in rules:
        if r["action"] == "allow" or (r["mount"] and r["mount"] != mount_id):
            continue
        # same scoping as render(): an allow rule only carves exceptions out of rules of its own scope
        exempt = any(not a["mount"] or a["mount"] == r["mount"] for a in allows)
        if rule_matches(r, url_path) and not exempt:
            hits.append({"id": r["id"], "name": r["name"], "action": r["action"]})
    state = "public"
    for h in hits:
        if h["action"] in ("hide", "deny") or h["action"] in PRIVATE_ACTIONS:
            state = h["action"]
            break
    return {"state": state, "rules": hits, "allowed_by": [a["id"] for a in allows]}


class Matcher:
    """Python mirror of the blacklist, used to attribute blocked requests and to count link clicks."""

    def __init__(self):
        self.dirty = True
        self.lock = threading.Lock()

    def build(self):
        db = connect()
        try:
            D = load(db)
        finally:
            db.close()
        self.nets, self.ccs, self.uas, self.refs, self.paths, self.noua = [], {}, [], [], [], None
        for b in D["blacklist"]:
            if not active(b) or b["scope"] == "edge":
                continue
            k, v = b["kind"], b["value"]
            if k in ("ip", "cidr"):
                self.nets.append((ipaddress.ip_network(v, strict=False), b["id"]))
            elif k == "country":
                self.ccs[v] = b["id"]
            elif k == "referer":
                self.refs.append((v, b["id"]))
            elif k == "path":
                self.paths.append((glob_rx(v), b["id"]))
            elif k == "agent" and v == "empty":
                self.noua = b["id"]
            else:
                parts = ua_alternatives([b])
                if parts:
                    self.uas.append((re.compile(parts[0], re.I), b["id"]))
        self.rules = [r for r in D["rules"] if active(r) and r["action"] in ("deny", "ip_allow", "geo_allow", "geo_deny",
                                                                              "hotlink", "password", "signed")]
        self.links = {l["code"]: l for l in D["links"]}
        self.prefix = D["site"]["link_prefix"]
        self.dirty = False

    def blacklisted(self, r):
        ip = r.get("ip") or ""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            addr = None
        if addr and any(addr in n for n in CADDY_PRIVATE):
            return None
        if addr:
            for net, bid in self.nets:
                if addr in net:
                    return bid
        if r.get("country") in self.ccs:
            return self.ccs[r["country"]]
        ua = r.get("ua") or ""
        if not ua and self.noua:
            return self.noua
        for rx, bid in self.uas:
            if rx.search(ua):
                return bid
        ref = (r.get("ref") or "").lower()
        for d, bid in self.refs:
            if ref == d or ref.endswith("." + d):
                return bid
        p = urllib.parse.unquote(r.get("path") or "").lower()
        for rx, bid in self.paths:
            if rx.match(p):
                return bid
        return None


class LinkGuard:
    """Expires a short link early at strong signs of abuse (thresholds: CFG['links']['abuse']): one address
    hammering it, a click flood, clicks from a wide spread of countries, or traffic that is mostly bots/scanners.
    Link previews (Discord, Telegram...) and your own LAN never count against a link."""

    def __init__(self):
        self.win = collections.defaultdict(collections.deque)  # code -> (ts, ip or '', country, bot?)
        self.done = set()

    def feed(self, code, r, link):
        if code in self.done or r["ts"] < (link.get("created") or 0) or r.get("kind") == "embed":
            return
        ip = r.get("ip") or ""
        try:
            if ipaddress.ip_address(ip).is_private:
                ip = ""
        except ValueError:
            pass
        q = self.win[code]
        q.append((r["ts"], ip, r.get("country") or "", r.get("kind") == "bot" or bool(r.get("scan"))))
        while q and q[0][0] < r["ts"] - 3600:
            q.popleft()

    def verdicts(self, codes):
        a = (CFG.get("links") or {}).get("abuse") or {}
        if not a.get("enabled"):
            return []
        out = []
        for code in codes:
            q = self.win.get(code)
            if code in self.done or not q:
                continue
            last10 = [x for x in q if x[0] >= q[-1][0] - 600]
            ip, n_ip = max(collections.Counter(x[1] for x in last10 if x[1]).items(), key=lambda kv: kv[1], default=("", 0))
            countries = {x[2] for x in q if x[2] and x[2] not in ("XX", "T1")}
            bots = sum(1 for x in q if x[3])
            reason = None
            if n_ip >= a.get("per_ip_10m", 60):
                reason = "%d clicks from %s within 10 min" % (n_ip, ip)
            elif len(last10) >= a.get("clicks_10m", 500):
                reason = "%d clicks within 10 min" % len(last10)
            elif len(countries) >= a.get("countries_1h", 25):
                reason = "clicks from %d countries within an hour" % len(countries)
            elif len(q) >= a.get("bot_min", 30) and bots >= a.get("bot_share", 0.8) * len(q):
                reason = "%d of %d clicks within an hour from bots / scanners" % (bots, len(q))
            if reason:
                self.done.add(code)
                out.append((code, reason))
        return out


# search / security crawlers: user agent claim -> domains its forward-confirmed reverse DNS must end in
CRAWLERS = [
    (re.compile(r"googlebot|google-inspectiontool|googleother|adsbot-google|mediapartners-google|feedfetcher-google|"
                r"apis-google|storebot-google|google-safety|google-read-aloud|google-site-verification", re.I),
     ("googlebot.com", "google.com", "gae.googleusercontent.com")),
    (re.compile(r"bingbot|bingpreview|msnbot|adidxbot", re.I), ("search.msn.com",)),
    (re.compile(r"applebot", re.I), ("applebot.apple.com",)),
    (re.compile(r"yahoo! slurp", re.I), ("crawl.yahoo.net",)),
    (re.compile(r"yandex(bot|images|mobilebot|video|media|metrika)", re.I), ("yandex.ru", "yandex.net", "yandex.com")),
    (re.compile(r"baiduspider", re.I), ("baidu.com", "baidu.jp")),
    (re.compile(r"petalbot", re.I), ("petalsearch.com", "aspiegel.com")),
    (re.compile(r"seznambot", re.I), ("seznam.cz",)),
]
# 4xx that browsers and crawlers produce on their own - never part of an error spray
BENIGN_RE = re.compile(r"(^|/)(favicon[\w.-]*|apple-touch-icon[\w.-]*|robots\.txt|sitemap[\w.-]*|ads\.txt|"
                       r"manifest\.json|site\.webmanifest|browserconfig\.xml|[\w.-]+\.map)$|^/\.well-known/", re.I)


def domain_in(host, domains):
    return bool(host) and any(host == d or host.endswith("." + d) for d in domains)


def push(q, t, span):
    q.append(t)
    while q and q[0] < t - span:
        q.popleft()


class Verifier:
    """Forward-confirmed reverse DNS - the check Google, Bing and Apple document for their crawlers - cached a day.
    Lookups run on a small pool, so the tailer only ever waits for them when it is about to ban someone."""
    TTL = 86400

    def __init__(self):
        self.pool = concurrent.futures.ThreadPoolExecutor(4, thread_name_prefix="rdns")
        self.lock = threading.Lock()
        self.cache = {}  # ip -> (started, future of the verified host name or "")

    @staticmethod
    def resolve(ip):
        try:
            host = socket.gethostbyaddr(ip)[0].lower().rstrip(".")
            want = ipaddress.ip_address(ip)
            if any(ipaddress.ip_address(a[4][0].split("%")[0]) == want for a in socket.getaddrinfo(host, None)):
                return host
        except (OSError, UnicodeError, ValueError):
            pass
        return ""

    def start(self, ip):
        with self.lock:
            hit = self.cache.get(ip)
            if hit and time.time() - hit[0] < self.TTL:
                return hit[1]
            if len(self.cache) > 50000:
                self.cache.clear()
            f = self.pool.submit(self.resolve, ip)
            self.cache[ip] = (time.time(), f)
            return f

    def host(self, ip):
        """Verified host name, "" when the address does not verify, None while the lookup still runs."""
        f = self.start(ip)
        return f.result() if f.done() else None

    def wait(self, ips, timeout=4.0):
        concurrent.futures.wait([self.start(ip) for ip in ips], timeout=timeout)
        return {ip: self.host(ip) for ip in ips}


class Crackdown:
    """Scores client addresses from the access log (thresholds: CFG['autoban']). Probes, credential grabs, 4xx
    sprays over many paths, rotating user agents and fake search-engine crawlers make an address a *suspect*: its
    traffic leaves the error rates (core.SUSPECT, req.sus). Clear cases are banned - blacklist, so origin and
    Cloudflare - for ban_hours, longer for repeat offenders. Verified crawlers (forward-confirmed reverse DNS under
    autoban.safe_domains) and the autoban.safe / never ranges are never flagged or banned."""

    def __init__(self):
        self.probes = collections.defaultdict(collections.deque)  # ip -> ts of probe requests
        self.creds = collections.defaultdict(collections.deque)   # ip -> ts of credential / secret grabs
        self.fakes = collections.defaultdict(collections.deque)   # ip -> ts of requests posing as a crawler
        self.recent = collections.defaultdict(lambda: collections.deque(maxlen=2000))  # ip -> (ts, err, path, ua)
        self.claims = {}      # ip -> [claimed crawler domains, requests] while its reverse DNS is pending
        self.safe_seen = set()
        self.last_gc = 0

    def observe(self, r, ab):
        """Record one request; returns (level, reason, detail) for its address or None (level: ban | suspect)."""
        ip, t, ua = r["ip"], r["ts"], r["ua"] or ""
        win = ab["window_minutes"] * 60
        if r["scan"]:
            push(self.probes[ip], t, win)
            if r.get("cred"):
                push(self.creds[ip], t, win)
            VERIFY.start(ip)  # usually answered before a ban decision has to wait for it
        claim = next((d for rx, d in CRAWLERS if rx.search(ua)), None)
        if claim:
            host = VERIFY.host(ip)
            if host is None:
                self.claims.setdefault(ip, [claim, 0])[1] += 1
            elif not domain_in(host, claim):
                push(self.fakes[ip], t, win)
        ref = r.get("ref") or ""
        err = (r["status"] >= 400 and not r["blocked"].startswith("rule:") and not BENIGN_RE.search(r["path"] or "")
               and not (ref == r["host"] or domain_in(ref, CFG["public"]["hosts"])))
        rec = self.recent[ip]
        changed = not rec or rec[-1][3] != ua
        rec.append((t, err, r["path"] or "", ua))
        while rec and rec[0][0] < t - ab["spray_minutes"] * 60:
            rec.popleft()
        return self.verdict(ip, ab, err or changed)

    def verdict(self, ip, ab, deep=True):
        n_cred, n_probe = len(self.creds.get(ip) or ()), len(self.probes.get(ip) or ())
        n_fake, mins = len(self.fakes.get(ip) or ()), ab["window_minutes"]
        if n_cred >= ab["credential_probes"]:
            return "ban", "credentials", "%d requests for credentials or secrets within %d min" % (n_cred, mins)
        if n_probe >= ab["probes"]:
            return "ban", "scanner", "%d probe requests within %d min" % (n_probe, mins)
        if n_fake >= ab["fake_crawler_hits"]:
            return "ban", "fake-crawler", "%d requests posing as a search-engine crawler (reverse DNS disagrees)" % n_fake
        rec = self.recent.get(ip) or ()
        uas = 0
        if deep and rec:  # only on errors and user-agent changes: busy honest clients stay cheap
            errs = [e for e in rec if e[1]]
            paths, uas, share = len({e[2] for e in errs}), len({e[3] for e in rec}), len(errs) / len(rec)
            if len(errs) >= ab["spray_errors"] and paths >= ab["spray_paths"] and share >= 0.8:
                return "ban", "error-spray", "%d errors on %d different paths within %d min" % (
                    len(errs), paths, ab["spray_minutes"])
            if uas >= ab["ua_rotation"] and share >= 0.5:
                return "ban", "rotating-ua", "%d different user agents and %d %% errors within %d min" % (
                    uas, share * 100, ab["spray_minutes"])
        if n_cred or n_probe >= ab["suspect_probes"]:
            return "suspect", "scanner", ""
        if n_fake:
            return "suspect", "fake-crawler", ""
        if uas >= ab["ua_rotation"]:
            return "suspect", "rotating-ua", ""
        return None

    def settle_claims(self, ab):
        """Crawler claims whose reverse DNS has come back since the last batch."""
        out = {}
        for ip, (claim, n) in list(self.claims.items()):
            host = VERIFY.host(ip)
            if host is None:
                continue
            del self.claims[ip]
            if not domain_in(host, claim):
                for _ in range(n):
                    push(self.fakes[ip], now(), ab["window_minutes"] * 60)
                v = self.verdict(ip, ab, False)
                if v:
                    out[ip] = v + ("", "")
        return out

    def forget(self, ip):
        for d in (self.probes, self.creds, self.fakes, self.recent, self.claims):
            d.pop(ip, None)

    def gc(self, ab):
        t = now()
        if t - self.last_gc < 300:
            return
        self.last_gc = t
        edge = t - max(ab["window_minutes"], ab["spray_minutes"]) * 60
        for d in (self.probes, self.creds, self.fakes):
            for ip in [ip for ip, q in d.items() if not q or q[-1] < edge]:
                del d[ip]
        for ip in [ip for ip, q in self.recent.items() if not q or q[-1][0] < edge]:
            del self.recent[ip]
        for ip in [ip for ip, (until, _) in list(core.SUSPECT.items()) if until < t]:
            core.SUSPECT.pop(ip, None)


MATCH = Matcher()
GUARD = LinkGuard()
VERIFY = Verifier()
CRACK = Crackdown()
EDGE_SYNC = threading.Event()
APPLY_SOON = threading.Event()
ALERT_HOOK = []  # f(kind, severity, title, detail, key) - set by alerts.py


def on_rows(rows):
    """Tailer hook: attribute blocks, count link clicks, flag suspicious clients (left out of error rates) and
    auto-ban the clear cases (see Crackdown)."""
    ab = CFG["autoban"]
    with MATCH.lock:
        if MATCH.dirty:
            MATCH.build()
        bl_hits, rule_hits, clicks = collections.Counter(), collections.Counter(), collections.Counter()
        skip = exempt_nets(ab, core.own_ips())
        flagged = CRACK.settle_claims(ab)  # ip -> (level, reason, detail, sample path, country)
        CRACK.gc(ab)
        for r in rows:
            st = r["status"]
            if st == 403:
                bid = MATCH.blacklisted(r)
                if bid:
                    r["blocked"] = "bl:%d" % bid
                    bl_hits[bid] += 1
            if st in (401, 403) and not r["blocked"]:
                p = urllib.parse.unquote(r["path"] or "")
                for rule in MATCH.rules:
                    if rule_matches(rule, p):
                        r["blocked"] = "rule:%d" % rule["id"]
                        rule_hits[rule["id"]] += 1
                        break
            path = r["path"] or ""
            if st == 302 and path.startswith(MATCH.prefix):
                code = path[len(MATCH.prefix):]
                if code in MATCH.links:
                    clicks[code] += 1
                    GUARD.feed(code, r, MATCH.links[code])
            if r["blocked"].startswith("bl:"):
                r["sus"] = "blacklist"
                continue
            if not r["ip"] or r.get("sus") == "internal":
                continue
            try:
                addr = ipaddress.ip_address(r["ip"])
            except ValueError:
                continue
            if any(addr in n for n in skip) or any(addr in n for n, _ in MATCH.nets):
                continue
            v = CRACK.observe(r, ab)
            if v and (r["ip"] not in flagged or v[0] == "ban"):
                flagged[r["ip"]] = v + (r["path"] or "", r.get("country") or "")
        abused = GUARD.verdicts(list(clicks))
    t = now()
    # verified crawlers are left alone; reverse DNS is only waited for when someone is about to be banned
    hosts = VERIFY.wait([ip for ip, v in flagged.items() if v[0] == "ban"]) if flagged else {}
    if any(v[0] == "ban" for v in flagged.values()):  # dynamic own address: make sure it did not just change
        mine = exempt_nets(ab, core.own_ips(60))
        flagged = {ip: v for ip, v in flagged.items() if not any(ipaddress.ip_address(ip) in n for n in mine)}
    new_suspects, bans = [], []
    for ip, (level, why, detail, path, cc) in flagged.items():
        host = hosts[ip] if ip in hosts else VERIFY.host(ip)
        if domain_in(host, ab["safe_domains"]):
            if ip not in CRACK.safe_seen:
                CRACK.safe_seen.add(ip)
                log("crackdown: %s left alone, verified crawler %s (%s)" % (ip, host, why))
            continue
        old = core.SUSPECT.get(ip)
        if not old or old[0] < t:
            new_suspects.append((why, ip, t - ab["suspect_hours"] * 3600))
        core.SUSPECT[ip] = (max(t + ab["suspect_hours"] * 3600, old[0] if old else 0), why)
        if level == "ban" and ab["enabled"]:
            bans.append((ip, why, detail, path, cc, host))
            CRACK.forget(ip)
    for r in rows:
        s = core.SUSPECT.get(r["ip"])
        if s and not r.get("sus") and s[0] > t:
            r["sus"] = s[1]
    if not (bl_hits or rule_hits or clicks or abused or bans or new_suspects):
        return
    notes = []  # alerts go out after the commit: alerts.raise_ writes through its own connection (deadlock otherwise)
    db = connect()
    try:
        with db:
            for bid, n in bl_hits.items():
                db.execute("UPDATE blacklist SET hits=coalesce(hits,0)+?, last_hit=? WHERE id=?", [n, t, bid])
            for rid, n in rule_hits.items():
                db.execute("UPDATE rule SET hits=coalesce(hits,0)+?, last_hit=? WHERE id=?", [n, t, rid])
            for code, n in clicks.items():
                db.execute("UPDATE link SET clicks=coalesce(clicks,0)+?, last_click=? WHERE code=?", [n, t, code])
                l = MATCH.links.get(code)
                if l and l.get("max_clicks") and (l.get("clicks") or 0) + n >= l["max_clicks"]:
                    APPLY_SOON.set()
                if l:
                    l["clicks"] = (l.get("clicks") or 0) + n
            for code, reason in abused:  # expire now: the short URL answers 410 once the config is re-applied
                l = MATCH.links.get(code) or {}
                db.execute("UPDATE link SET expires=?, note=? WHERE code=? AND (expires IS NULL OR expires > ?)",
                           [t, ("auto-expired %s: %s. %s" % (time.strftime("%Y-%m-%d %H:%M"), reason, l.get("note") or ""))[:300],
                            code, t])
                log("link guard: %s%s expired (%s)" % (MATCH.prefix, code, reason))
                APPLY_SOON.set()
                notes.append(("links", "warning", "Short link %s%s expired early" % (MATCH.prefix, code),
                              "Strong signs of abuse: %s. Target: %s. Re-enable it from Serving > Links if this was expected." % (
                                  reason, l.get("url") or l.get("path") or "?"), "link-abuse:" + code))
            # earlier requests of a new suspect leave the stored error rates too (and the rollups, rollup.py)
            if new_suspects:
                import rollup
                rollup.on_reclass(db, new_suspects)
            db.executemany("UPDATE req SET sus=? WHERE ip=? AND ts>=? AND " + core.CLEAN, new_suspects)
            banned = ban_all(db, bans, ab, t, notes)
        if banned:
            MATCH.dirty = True
            APPLY_SOON.set()
            EDGE_SYNC.set()
    finally:
        db.close()
    for note in notes:
        for h in ALERT_HOOK:
            try:
                h(*note)
            except Exception:
                log("alert hook error:\n" + traceback.format_exc())


def exempt_nets(ab, own):
    """Never flagged or banned: Caddy's private ranges, autoban.never / safe, and the site's own public addresses."""
    return CADDY_PRIVATE + [ipaddress.ip_network(n, strict=False) for n in list(ab["never"]) + list(ab["safe"])] + [
        ipaddress.ip_network(ip + ("/64" if ":" in ip else "/32"), strict=False) for ip in own]


def active_ban(db, value, t):
    return db.execute("SELECT 1 FROM blacklist WHERE kind IN ('ip','cidr') AND value=? AND enabled=1 AND "
                      "(expires IS NULL OR expires > ?)", [value, t]).fetchone()


def ban_all(db, bans, ab, t, notes):
    """Insert the autobans (repeat offenders stay out longer) and widen to the /24 (/64) when a range keeps
    producing them. Runs inside the caller's transaction; alerts are only queued in `notes`."""
    edge = " and Cloudflare" if (get_meta(db, "cf_sync", {}) or {}).get("ok") else ""
    banned = []
    for ip, why, detail, path, cc, host in bans:
        if active_ban(db, ip, t):
            continue
        prior = db.execute("SELECT count(*) FROM blacklist WHERE value=? AND source='autoban'", [ip]).fetchone()[0]
        hours = min(ab["ban_hours"] * ab["repeat_factor"] ** prior, ab["max_ban_days"] * 24)
        note = "%s: %s, e.g. %s%s" % (why, detail, path[:80], " (rDNS %s)" % host if host else "")
        db.execute("INSERT INTO blacklist(kind,value,action,scope,enabled,expires,note,source,created) "
                   "VALUES('ip',?,'block','both',1,?,?,'autoban',?)", [ip, t + hours * 3600, note[:300], t])
        banned.append(ip)
        log("autoban: %s %s (%s)" % (ip, why, detail))
        notes.append(("autoban", "warning", "Auto-banned %s%s" % (ip, " (%s)" % cc if cc else ""),
                      "%s, e.g. %s. Banned for %s at origin%s%s." % (
                          detail[:1].upper() + detail[1:], path[:120], "%d h" % hours if hours < 48 else "%d days" % (hours // 24),
                          edge, ", repeat offence #%d" % (prior + 1) if prior else ""), "autoban:" + ip))
    if not banned or not ab.get("subnet_after"):
        return banned
    skip = exempt_nets(ab, core.own_ips())
    recent = [v for (v,) in db.execute("SELECT value FROM blacklist WHERE source='autoban' AND kind='ip' AND created > ?",
                                       [t - 7 * 86400])]
    for ip in list(banned):  # copy: range bans are appended below and must not be widened again
        net = ipaddress.ip_network(ip + ("/64" if ":" in ip else "/24"), strict=False)
        same = set()
        for v in recent:
            try:
                if ipaddress.ip_address(v) in net:
                    same.add(v)
            except ValueError:
                pass
        if (len(same) < ab["subnet_after"] or active_ban(db, str(net), t) or any(net.overlaps(n) for n in skip)
                or any(ipaddress.ip_address(s) in net for s in CRACK.safe_seen)):
            continue
        db.execute("INSERT INTO blacklist(kind,value,action,scope,enabled,expires,note,source,created) "
                   "VALUES('cidr',?,'block','both',1,?,?,'autoban',?)",
                   [str(net), t + ab["ban_hours"] * 3600, "%d auto-banned addresses in this range within 7 days" % len(same), t])
        banned.append(str(net))
        log("autoban: range %s (%d addresses)" % (net, len(same)))
        notes.append(("autoban", "warning", "Auto-banned range %s" % net,
                      "%d addresses from this range were auto-banned within 7 days (%s). The whole range is banned for "
                      "%d h at origin%s." % (len(same), ", ".join(sorted(same)[:6]), ab["ban_hours"], edge), "autoban:" + str(net)))
    return banned


class Scheduler(threading.Thread):
    """Re-applies when something time-based changes (expiring bans/rules/links, exhausted links, auto-bans)."""
    daemon = True

    def run(self):
        last = 0
        while True:
            APPLY_SOON.wait(timeout=30)
            fast = APPLY_SOON.is_set()
            APPLY_SOON.clear()
            if fast:
                time.sleep(2)  # coalesce bursts
            try:
                db = connect()
                try:
                    pinned = (get_meta(db, "serving", {}) or {}).get("pinned")
                    if not pinned or fast:
                        with db:
                            res = apply(db, "strata", "scheduled" if not fast else "auto")
                        if res.get("changed"):
                            EDGE_SYNC.set()
                finally:
                    db.close()
            except Exception as e:
                if time.time() - last > 600:
                    last = time.time()
                    log("scheduler apply failed: %s" % e)
                    for h in ALERT_HOOK:
                        h("config", "warning", "Serving config could not be applied", str(e)[:400], "apply-fail")


# ---------------------------------------------------------------- one-time migration of the hand-written site

def migrate_caddyfile(user="strata"):
    """Replace the hand-written CDN site block (instance.cdn_listen, e.g. :8080) of the Caddyfile with an import of
    the generated file. Backup first; validate the complete result; restore the backup if the reload fails."""
    path = CFG["caddyfile"]
    listen = CFG["instance"].get("cdn_listen") or ":8080"
    with open(path, encoding="utf-8-sig") as f:
        text = f.read()
    if IMPORT_LINE in text:
        return {"migrated": False, "note": "already imports the generated file"}
    lines = text.splitlines(keepends=True)
    start = next((i for i, l in enumerate(lines) if re.match(r"^%s\s*\{" % re.escape(listen), l)), None)
    if start is None:
        raise ServeError("no %s site block found in the Caddyfile" % listen)
    depth, end = 0, None
    for j in range(start, len(lines)):
        depth += lines[j].count("{") - lines[j].count("}")
        if depth == 0:
            end = j
            break
    if end is None:
        raise ServeError("could not find the end of the %s block" % listen)
    new = ("".join(lines[:start]) + "# %s CDN site - rendered by Strata from its database (Strata > Serving).\n"
           "# The hand-written original is in the backups folder next to the Caddyfile.\n" % listen
           + IMPORT_LINE + "\n" + "".join(lines[end + 1:]))
    bdir = os.path.join(os.path.dirname(path), "backups")
    os.makedirs(bdir, exist_ok=True)
    backup = os.path.join(bdir, "Caddyfile.%s.pre-strata.bak" % time.strftime("%Y%m%d-%H%M%S"))
    with open(backup, "w", encoding="utf-8") as f:
        f.write(text)
    db = connect()
    try:
        gen = render(db)
        os.makedirs(GEN_DIR, exist_ok=True)
        with open(GEN_FILE, "w", encoding="utf-8") as f:
            f.write(gen)
        tmp_main = os.path.join(GEN_DIR, "Caddyfile.migrate")
        with open(tmp_main, "w", encoding="utf-8") as f:
            f.write(new)
        code, msg = caddy("validate", "--config", tmp_main, "--adapter", "caddyfile")
        if code != 0:
            raise ServeError("migration aborted, Caddy rejected the result: " + msg[:500])
        with open(path, "w", encoding="utf-8") as f:
            f.write(new)
        code, msg = caddy("reload", "--config", path, "--adapter", "caddyfile")
        if code != 0:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            caddy("reload", "--config", path, "--adapter", "caddyfile")
            raise ServeError("reload failed, original Caddyfile restored: " + msg[:400])
        write_transform_config(core.mounts(refresh=True))
        media("config", core.mounts(), db)
        with db:
            sha = hashlib.sha256(gen.encode()).hexdigest()[:16]
            db.execute("INSERT INTO confhist(ts,user,reason,content,sha,ok,error) VALUES(?,?,?,?,?,1,'')",
                       [now(), user, "migrated hand-written %s site" % listen, gen, sha])
            set_meta(db, "serving", {"ts": now(), "sha": sha, "user": user, "reason": "migration"})
    finally:
        db.close()
    return {"migrated": True, "backup": backup}


# ---------------------------------------------------------------- URL tester

def test_url(url, ip="", ua="", country="", referer=""):
    u = urllib.parse.urlsplit(url if "://" in url else "https://" + url.lstrip("/"))
    host, path, query = (u.hostname or "").lower(), urllib.parse.unquote(u.path or "/"), urllib.parse.parse_qs(u.query)
    db = connect()
    try:
        D = load(db)
    finally:
        db.close()
    steps = []
    fake = {"ip": ip, "ua": ua, "country": country.upper(), "ref": urllib.parse.urlsplit(referer).hostname or "",
            "path": u.path}
    with MATCH.lock:
        if MATCH.dirty:
            MATCH.build()
        bid = MATCH.blacklisted(fake)
    if bid:
        b = next((x for x in D["blacklist"] if x["id"] == bid), {})
        return {"result": "403 Forbidden (blacklist)", "steps": ["Blacklist #%d matches: %s = %s" % (bid, b.get("kind"), b.get("value"))]}
    mounts = [m for m in D["mounts"] if m["enabled"]]
    rules = [r for r in D["rules"] if active(r)]
    m_hit = None
    lpath = path.lower()
    services = [m for m in mounts if m["kind"] == "proxy" and m["prefix"] != "/"]  # 2b: before every other drive
    for m in sorted(services, key=lambda m: -len(m["prefix"])) + sorted(
            [m for m in mounts if m not in services], key=lambda m: ({"page": 0, "files": 1, "proxy": 2}[m["kind"]], -len(m["prefix"]))):
        pre = m["prefix"].lower()
        if host in m["hosts"] and (m["kind"] != "page" or path == "/") and (
                m["kind"] == "page" or pre == "/" or lpath == pre or lpath.startswith(pre + "/")):
            m_hit = m
            break
    gallery = player = None
    for r in rules:
        if r["action"] == "allow":
            continue
        if r["mount"] and (not m_hit or r["mount"] != m_hit["id"]):
            continue
        if r["action"] == "gallery":
            if not gallery and rule_matches(dict(r, patterns=gallery_patterns(r["patterns"])), path):
                gallery = r
            continue
        if r["action"] == "player":
            if not player and rule_matches(r, path):
                player = r
            continue
        if not rule_matches(r, path):
            continue
        allows = [a for a in rules if a["action"] == "allow" and (not a["mount"] or a["mount"] == r["mount"]) and rule_matches(a, path)]
        if allows:
            steps.append("Rule “%s” matches but allow rule “%s” exempts this path" % (r["name"], allows[0]["name"]))
            continue
        a, p = r["action"], r["params"]
        steps.append("Rule “%s” (%s) matches" % (r["name"], ACTIONS[a]))
        if a == "hide":
            return {"result": "404 Not Found (hidden)", "steps": steps}
        if a == "deny":
            return {"result": "403 Forbidden", "steps": steps}
        if a == "password":
            return {"result": "401 - browser asks for a login (%d user(s))" % len(p.get("users", [])), "steps": steps}
        if a == "signed":
            ok = "exp" in query and "sig" in query
            return {"result": "needs a valid signature (?exp=&sig=)" + (" - one is present, checked by the gate" if ok else " - missing: 403"), "steps": steps}
        if a == "ip_allow":
            try:
                inside = any(ipaddress.ip_address(ip) in ipaddress.ip_network(n, strict=False) for n in p["ips"]) if ip else False
            except ValueError:
                inside = False
            if not inside:
                return {"result": "403 Forbidden (IP not on the allow list)", "steps": steps}
        if a == "geo_allow" and fake["country"] not in p["countries"]:
            return {"result": "403 Forbidden (country %s not allowed)" % (fake["country"] or "unknown"), "steps": steps}
        if a == "geo_deny" and fake["country"] in p["countries"]:
            return {"result": "403 Forbidden (country %s blocked)" % fake["country"], "steps": steps}
        if a == "hotlink" and referer:
            rh = fake["ref"]
            doms = p["domains"] + cdn_hosts(mounts)
            if not any(rh == d or rh.endswith("." + d) for d in doms):
                return {"result": "403 Forbidden (hotlinked from %s)" % rh, "steps": steps}
        if a == "redirect":
            return {"result": "%d redirect to %s" % (p.get("code", 302), p["to"]), "steps": steps}
        if a in PRIVATE_ACTIONS:
            steps.append("→ response is sent with Cache-Control: private, no-store")
    if m_hit and m_hit["kind"] == "proxy":
        g = gate.conf(m_hit)
        steps.append("Service “%s” → %s%s" % (m_hit["name"], m_hit["path"], "" if m_hit["prefix"] == "/" else
                                             " (prefix %s %s)" % (m_hit["prefix"], "stripped" if m_hit.get("strip", 1) else "kept")))
        if g["mode"] == "login" and any(glob_rx(p).match(lpath) for p in g["public"]):
            return {"result": "proxied to %s (public exception of the login)" % m_hit["path"],
                    "steps": steps + ["→ path matches a public path of this service: no login"]}
        if g["mode"] == "login":
            return {"result": "302 → %s%s/login unless signed in, then proxied to %s" % (
                "" if m_hit["prefix"] == "/" else m_hit["prefix"], gate.PATH, m_hit["path"]),
                "steps": steps + ["→ Strata gate: login required (session cookie for this service and hostname, %d h)"
                                  % g["hours"], "→ response is sent with Cache-Control: private, no-store"]}
        return {"result": "proxied to %s (public)" % m_hit["path"], "steps": steps}
    lp = D["site"]["link_prefix"]
    if path.startswith(lp) and host in cdn_hosts(mounts):
        l = next((x for x in D["links"] if x["code"] == path[len(lp):]), None)
        if l:
            st = link_status(l)
            if st != "active":
                return {"result": "410 Gone (link %s)" % st, "steps": steps}
            return {"result": "302 → %s" % link_target(l, D["mounts"]), "steps": steps + ["Short link %s" % l["code"]]}
    if not m_hit:
        return {"result": "404 Unknown host" if not any(host in m["hosts"] for m in mounts) else "404 Not Found", "steps": steps}
    if m_hit["kind"] == "proxy":
        return {"result": "proxied to %s" % m_hit["path"], "steps": steps + ["Drive “%s”" % m_hit["name"]]}
    rel = path if m_hit["prefix"] == "/" else path[len(m_hit["prefix"]):] or "/"
    full = os.path.normpath(os.path.join(m_hit["path"], *[p for p in rel.split("/") if p]))
    steps.append("Drive “%s” → %s" % (m_hit["name"], full))
    if gallery and m_hit["kind"] == "files" and os.path.isdir(full):
        steps.append("Rule “%s” (%s) matches this folder" % (gallery["name"], ACTIONS["gallery"]))
        return {"result": "200 OK (gallery view)" if path.endswith("/") else "308 → %s/ (then gallery view)" % path,
                "steps": steps + ["→ listing sent with Cache-Control: %s, never cached by Cloudflare" % GALLERY_CACHE]}
    if player and m_hit["kind"] == "files" and not u.query and re.search(r"(?i)\.(%s)$" % AUDIO_EXT, path) \
            and os.path.isfile(full):
        steps.append("Rule “%s” (%s) matches this file" % (player["name"], ACTIONS["player"]))
        return {"result": "200 OK (player page for desktop / tablet browsers; the file itself for phones, <audio>, "
                          "link previews and ?raw=1)",
                "steps": steps + ["→ the bare URL is never cached by Cloudflare; ?raw=1 keeps the drive's edge cache"]}
    if query.get("ver"):
        steps.append("?ver=%s → served from the version store by Strata Transform" % query["ver"][0])
    elif re.search(IMAGE_RX, path) and any(k in query for k in ("w", "h", "fm", "q", "fit")):
        steps.append("image modifiers → resized/converted by Strata Transform")
    if query.get("dl") == ["1"]:
        steps.append("?dl=1 → Content-Disposition: attachment")
    exists = os.path.isfile(full) if m_hit["kind"] == "files" else os.path.isfile(os.path.join(m_hit["path"], "index.html"))
    if not exists and m_hit["kind"] == "files":
        db = connect()
        try:
            state = bin_state(db, m_hit, rel)
        finally:
            db.close()
        if state:
            steps.append("in binpath (%s) → answered with Clear-Site-Data: \"cache\", so the visitor's browser drops its "
                         "cached copies" % state)
            return {"result": "403 Forbidden (in the trash - restore it to serve it again)" if state == "bin"
                    else "404 Not Found (deleted permanently)", "steps": steps}
    return {"result": ("200 OK" if exists else "404 Not Found (custom 404 page)"), "steps": steps}
