#!/usr/bin/env python3
"""Strata Telemetry - the public statistics page (stats.<zone>) of one Strata instance.

    pythonw telemetry.py --home <instance home>     (config: <home>/telemetry/telemetry.json, see instance.py)

What this process can do, by construction:
  * read its own four static files once at start-up (kept in memory; no file access afterwards)
  * make GET requests to exactly two fixed URLs on the loopback feed (feed_url/feed/{stats,live})
  * answer GET/HEAD for a fixed set of routes
What it cannot do: it has no database handle, no storage path, no Caddy/cloudflared access, no upload or
download route, and it never forwards a client-controlled URL, header or path to the feed.
Everything received from the feed is re-validated against SCHEMA below; unknown keys are dropped and any
string that looks like an IP address, a filesystem path or a URL is replaced before it is served.
"""
import ipaddress
import json
import os
import re
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import instance  # noqa: E402  (the instance home: --home / STRATA_HOME)
with open(instance.home("telemetry", "telemetry.json"), encoding="utf-8-sig") as _f:
    CONF = json.load(_f)
SITE_NAME = re.sub(r"[^A-Za-z0-9.\- ]", "", str(CONF.get("site_name") or "Strata"))[:60]

FEED = urllib.parse.urlsplit(CONF.get("feed_url", "http://127.0.0.1:8081"))
if FEED.scheme != "http" or FEED.hostname not in ("127.0.0.1", "::1", "localhost"):
    sys.exit("telemetry: feed_url must point at the loopback feed")
FEED_BASE = "http://%s:%d" % (FEED.hostname, FEED.port or 80)
TOKEN = CONF["feed_token"]
RANGES = ("24h", "7d", "30d")

# static assets are loaded exactly once. The page and favicon are fixed here; the content-hashed CSS/JS/font files of
# the build (site/build.py) are listed in static/manifest.json. That is still a fixed list, read once at start-up:
# names must match ASSET_NAME (no "..", no absolute paths, at most one "fonts/" folder), and nothing else in static/
# is ever reachable.
STATIC_FILES = {"/": ("index.html", "text/html; charset=utf-8"), "/favicon.ico": ("favicon.ico", "image/x-icon")}
ASSET_TYPES = {".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".woff2": "font/woff2"}
ASSET_NAME = re.compile(r"^(?:fonts/)?[a-z0-9][a-z0-9_-]*(?:\.[a-z0-9_-]+)*\.(?:js|css|woff2)$")
IMMUTABLE = set()  # hashed names never change content, so they can be cached for a year
with open(os.path.join(HERE, "static", "manifest.json"), encoding="utf-8") as _f:
    for _name in json.load(_f)["assets"]:
        if not isinstance(_name, str) or not ASSET_NAME.match(_name):
            sys.exit("telemetry: refusing asset name from manifest: %r" % (_name,))
        STATIC_FILES["/" + _name] = (_name, ASSET_TYPES[os.path.splitext(_name)[1]])
        IMMUTABLE.add("/" + _name)
STATIC = {}
for route, (name, ctype) in STATIC_FILES.items():
    with open(os.path.join(HERE, "static", name), "rb") as _f:
        _body = _f.read()
    if name == "index.html":  # the page is shared by every instance; only the site's name differs
        _body = _body.replace(b"{{SITE}}", SITE_NAME.encode())
    STATIC[route] = (_body, ctype)
STATIC["/robots.txt"] = (b"User-agent: *\nAllow: /\n", "text/plain; charset=utf-8")
del _f

# ---------------------------------------------------------------- schema re-validation

IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
IPV6 = re.compile(r"\b[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}\b")
PATHY = re.compile(r"[\\]|^[A-Za-z]:|//|/[^\s]|@|https?:", re.I)


def clean_str(s, max_len=48):
    if not isinstance(s, str):
        return None
    if len(s) > max_len or IPV4.search(s) or PATHY.search(s):
        return "[redacted]"
    if IPV6.search(s):
        try:
            ipaddress.ip_address(IPV6.search(s).group(0))
            return "[redacted]"
        except ValueError:
            pass
    return s


NUM = "num"
STR = "str"
BOOL = "bool"
KV = {"k": STR, "c": NUM, "b": NUM, "u": NUM}
SITE = {"k": STR, "ok": BOOL, "ms": NUM}
LIVE = {"generated": NUM, "rps": NUM, "bps": NUM, "visitors_5m": NUM, "caddy": BOOL, "tunnel": BOOL,
        "tunnel_connections": NUM, "tunnel_rtt": NUM, "sites": [SITE], "services_up": NUM, "services_total": NUM,
        "storage_online": BOOL, "storage_used_pct": NUM}
SCHEMA_STATS = {
    "range": STR, "generated": NUM, "k_anon": NUM,
    "totals": {k: NUM for k in ("reqs", "bytes", "visitors", "e4", "e5", "bots", "probes", "saved", "encoded",
                                "p50", "p95", "p99")},
    "series": {"t0": NUM, "step": NUM, "reqs": [NUM], "bytes": [NUM], "visitors": [NUM], "errors": [NUM],
               "saved": [NUM]},
    "countries": [KV], "colos": [KV], "agents": [KV], "os": [KV], "categories": [KV], "extensions": [KV],
    "collections": [KV], "threats": [KV], "scanners": NUM, "latency": [NUM], "heat": [[NUM]],
    "kinds": {k: NUM for k in ("people", "players", "previews", "bots")},
    "classes": {k: NUM for k in ("1xx", "2xx", "3xx", "4xx", "5xx")},
    "encodings": {k: {"c": NUM, "b": NUM, "saved": NUM} for k in ("identity", "br", "zstd", "gzip")},
    "precompressed": {k: {"files": NUM, "orig": NUM, "size": NUM} for k in ("br", "zstd", "gzip")},
    "inventory": {"files": NUM, "bytes": NUM, "variants": NUM, "variant_bytes": NUM, "cats": [KV]},
    "uptime": {k: {"pct": NUM, "minutes": NUM} for k in ("caddy_up", "tunnel_up", "origins_up")},
    "monitoring_since": NUM,
    "edge": {"requests": NUM, "cached": NUM, "bytes": NUM, "cached_bytes": NUM, "threats": NUM, "fetched": NUM,
             "hours": [{"t": STR, "r": NUM, "c": NUM}], "days": [{"d": STR, "r": NUM, "c": NUM, "b": NUM}],
             "countries": [KV]},
    "live": LIVE,
}
ISO = re.compile(r"^\d{4}-\d\d-\d\d(T\d\d:\d\d:\d\dZ)?$")


def validate(v, schema, depth=0):
    if depth > 6:
        return None
    if isinstance(schema, dict):
        if not isinstance(v, dict):
            return None
        return {k: validate(v.get(k), s, depth + 1) for k, s in schema.items() if k in v}
    if isinstance(schema, list):
        if not isinstance(v, list):
            return None
        return [validate(x, schema[0], depth + 1) for x in v[:400]]
    if schema == NUM:
        return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None
    if schema == BOOL:
        return v if isinstance(v, bool) else None
    if schema == STR:
        if isinstance(v, str) and ISO.match(v):
            return v
        return clean_str(v)
    return None


# ---------------------------------------------------------------- feed client (fixed URLs only)

class Cache:
    def __init__(self):
        self.lock = threading.Lock()
        self.v = {}

    def get(self, key, ttl, fn):
        with self.lock:  # single flight: public traffic can't multiply load on the feed
            hit = self.v.get(key)
            if hit and time.time() - hit[0] < ttl:
                return hit[1]
            try:
                val = fn()
            except Exception:
                if hit:
                    return hit[1]  # serve stale rather than error
                raise
            self.v[key] = (time.time(), val)
            return val


CACHE = Cache()


def pull(endpoint, schema):
    req = urllib.request.Request(FEED_BASE + endpoint, headers={"Authorization": "Bearer " + TOKEN})
    with urllib.request.urlopen(req, timeout=15) as r:
        raw = json.loads(r.read(4 * 1024 * 1024))
    return json.dumps(validate(raw, schema), separators=(",", ":")).encode()


def stats(rng):
    return CACHE.get("stats:" + rng, 20, lambda: pull("/feed/stats?range=" + rng, SCHEMA_STATS))


def live():
    return CACHE.get("live", 3, lambda: pull("/feed/live", LIVE))


# ---------------------------------------------------------------- HTTP

# Sent on every response. Kept a plain literal dict: site/dev/serve.py reads it with ast.literal_eval so the local
# test server enforces exactly what production sends. The page has no inline script/style, loads nothing third-party
# and never touches an HTML sink, so the policy can be this tight (Trusted Types with no policy allowed).
SECURITY_HEADERS = {
    "Content-Security-Policy": ("default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; "
                                "img-src 'self'; connect-src 'self'; manifest-src 'none'; object-src 'none'; "
                                "frame-ancestors 'none'; base-uri 'none'; form-action 'none'; "
                                "upgrade-insecure-requests; require-trusted-types-for 'script'; trusted-types 'none'"),
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": ("accelerometer=(), autoplay=(), browsing-topics=(), camera=(), display-capture=(), "
                           "encrypted-media=(), fullscreen=(self), geolocation=(), gyroscope=(), hid=(), "
                           "magnetometer=(), microphone=(), midi=(), payment=(), publickey-credentials-get=(), "
                           "screen-wake-lock=(self), serial=(), usb=(), xr-spatial-tracking=()"),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Permitted-Cross-Domain-Policies": "none",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "StrataTelemetry"
    sys_version = ""

    def log_message(self, *a):
        pass  # no access logging here: Caddy already counts these requests (without us storing anything)

    def send(self, code, body, ctype, cache):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # no-transform on the HTML page only: Cloudflare must not rewrite it (it injects inline scripts the CSP forbids).
        # Not on assets or JSON: no-transform also stops Caddy's gzip/zstd, which matters on the tunnel link.
        self.send_header("Cache-Control", cache + ", no-transform" if ctype.startswith("text/html") else cache)
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        if int(self.headers.get("Content-Length") or 0) or self.headers.get("Transfer-Encoding"):
            return self.send(400, b"", "text/plain", "no-store")
        u = urllib.parse.urlsplit(self.path)
        try:
            if u.path in STATIC:
                body, ctype = STATIC[u.path]
                return self.send(200, body, ctype,
                                 "public, max-age=31536000, immutable" if u.path in IMMUTABLE else "public, max-age=300")
            if u.path == "/api/stats":
                rng = urllib.parse.parse_qs(u.query).get("range", ["24h"])[-1]
                return self.send(200, stats(rng if rng in RANGES else "24h"), "application/json",
                                 "public, max-age=20")
            if u.path == "/api/live":
                return self.send(200, live(), "application/json", "public, max-age=3")
        except Exception:
            return self.send(503, b'{"error":"statistics temporarily unavailable"}', "application/json", "no-store")
        return self.send(404, b"not found", "text/plain; charset=utf-8", "public, max-age=60")

    do_HEAD = do_GET

    def refuse(self):
        self.send(405, b"method not allowed", "text/plain; charset=utf-8", "no-store")

    do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = refuse


def main():
    host, port = CONF.get("listen", "127.0.0.1:8082").rsplit(":", 1)
    srv = ThreadingHTTPServer((host, int(port)), Handler)
    srv.daemon_threads = True
    print(time.strftime("%H:%M:%S"), "strata telemetry on http://%s:%s (feed %s)" % (host, port, FEED_BASE), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
