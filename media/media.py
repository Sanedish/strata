#!/usr/bin/env python3
"""Strata Media - the hot path on 127.0.0.1:8084 (media/DESIGN.md sections 2, 4.2, 4.3, 5, 6.1, 6.3, 7.6, 8, 14).

Caddy (media_rules.py) sends it, always from loopback:
  GET /_scan                        forward_auth gate: 200 (+ X-Strata-Lane: throttle) | 403 held | 503 pending
  <path>?_v=avif|webp|webm, ?w ?h ?fit ?fm ?q   variants: an empty 200 telling Caddy what to serve (X-Strata-Accel =
                                    a file under <cache_root>/cache, X-Strata-Orig = the untouched original), or a
                                    302 / 403 / 503 that passes through
  <path> + X-Strata-Negotiate: 1    redirect-mode negotiation: 302 ?_v=avif|webp|orig by Accept
  <path> + X-Strata-Throttle: 1     large-file lane: streams the original through token buckets (Range works)
Compatibility with transform/transform.py (which keeps 8083 for these): /_gate (signed links), ?ver=N (Range).
Admin: GET /_stats (JSON), POST /_admin/breaker (X-Strata-Admin-Token).

Why it looks like this:
  * Heavy bytes never go through Python on the hot path: a variant is written to the cache once and Caddy's
    file_server serves it (Range, ETag, sendfile); originals are served by Caddy straight from the mount.
  * The gate never waits for the database on the common path: verdicts live in memory (refreshed every 2 s,
    fully reloaded every 10 min) and scans are enqueued by a background thread. Only a verdict miss reads the db
    (quick-hash lookup, so a renamed copy of a held file stays held).
  * Encoding is optional work: the cost model defers what does not fit the sync budget to the worker, the breaker
    sheds load while the VM is busy, and every refusal is an event (bypass.<kind>) plus the original under a
    short CDN TTL so Cloudflare asks again soon.
  * Cache headers (DESIGN 4.2): the mount's browser value (X-Strata-Cache) and CDN value (X-Strata-Edge-Cache)
    are echoed as X-Strata-Cache-Control / X-Strata-CDN-Cache-Control and Caddy copies them onto the served
    file. Short-TTL answers keep the browser value and shorten only the CDN one (the zone's Browser Cache TTL
    would rewrite a browser max-age anyway); 302 / 403 / 503 are no-store and never carry a CDN header.
Least privilege: no strata.db, no Cloudflare token; reads mounts and media.db, writes <cache_root> and media.db.
"""
import pathfix  # noqa: F401  (vendored Pillow / user site before anything imports PIL)

import argparse
import base64
import collections
import contextlib
import hashlib
import hmac
import ipaddress
import json
import mimetypes
import os
import queue
import re
import socket
import stat
import sys
import threading
import time
import traceback
import types
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import breaker
import cache as cache_mod
import config
import events as events_mod
import imaging
import store as store_mod
import video

VERSION = "1.0"
PROC = "media"
FALLBACK_CC = "public, max-age=31536000, immutable"   # transform.py's value when Caddy sends no X-Strata-Cache
SHORT_CC = "public, max-age=60"                       # image.short_ttl default
TF_KEYS = ("w", "h", "fit", "fm", "q")
HELD_MSG = "This file is being held for review."
PENDING_MSG = "This file is being checked. Please try again in a moment."
TICK_S = 2.0                  # verdict refresh + meta.breaker
FULL_RELOAD_S = 600           # full verdict reload (sees deleted rows)
MODEL_SAVE_S = 300            # cost model -> meta.cost_model
USAGE_EVERY_S = 60            # cache usage walk for /_stats
ENQUEUE_TTL = 30.0            # in-memory dedupe before the store's own dedupe
HASH_TTL = 30.0               # quick-hash verdict lookups are remembered this long
BYPASS_EVERY = 10.0           # at most one bypass.<kind> event per file and kind per 10 s (counters count all)
MTIME_EPS = 5e-4
MAX_TF_BYTES = 150 << 20      # transform.py: 413 above this
STREAM_CHUNK = 1 << 20
LANE_CHUNK = 64 << 10
MAX_BODY = 16 << 10
RANGE_RE = re.compile(r"bytes=(\d*)-(\d*)")
PATH_SAFE = "/!$&'()*+,;=:@-._~"   # RFC 3986 pchar minus '%': a literal % in a name is re-escaped
ATTR_SAFE = "!#$&+^`|~"             # RFC 5987 attr-char besides alnum and -._
EXT_OUT = {"jpeg": "jpg"}
_CRLF = re.compile(r"[\r\n]+")
MOUNT_RE = re.compile(r"[0-9]{1,9}")      # X-Strata-Mount (str.isdigit would also accept superscripts)


def log(*a):
    try:
        if sys.stdout is not None:
            print(time.strftime("%Y-%m-%d %H:%M:%S"), "media:", *a, flush=True)
    except Exception:
        pass


# ---------------------------------------------------------------- small pure helpers (unit-tested)

def spec_auto(want, width=None, profile=None):
    """Variant identity of an automatic encode: format + output width + quality/encoder profile (DESIGN 6.3).
    The source identity (mount, path, size, mtime) is added by cache.key(). width None = source size.
    Without a profile (old callers, tests) the v1 spelling is kept."""
    if profile is None and not width:
        return "auto:%s:v1" % want
    return "auto:%s:w=%s:%s:v2" % (want, int(width) if width else "full", profile or "-")   # = imaging.auto_spec


def parse_spec(spec):
    """{"want", "width"} of an auto spec (worker jobs carry the spec, not the request)."""
    m = re.fullmatch(r"auto:(avif|webp):(?:w=(\d+|full):[^:]*:v2|v1)", spec or "")
    if not m:
        return None
    return {"want": m.group(1), "width": int(m.group(2)) if m.group(2) and m.group(2) != "full" else None}


TRUTHY = ("", "1", "true", "yes", "on")
# bypass answers that only mean "busy right now" (a retry soon gets the variant); decode errors etc. keep the original
WAIT_KINDS = ("deferred",) + tuple("bypass;kind=" + k for k in
                                   ("inflight", "queue_full", "queue_timeout", "breaker_open", "backoff"))


def bypass_reason(q, headers):
    """Why this request must get the untouched original, or None:
      nocompress   ?nocompress=1 (also true/yes/on, or the bare flag) - part of the URL, so caches keep it apart
      no-transform Cache-Control: no-transform request directive (RFC 9111 5.2.1.6) - NOT part of the cache key, so
                   such answers are never stored by Cloudflare (see Ctx.cc) and never poison the normal entry."""
    v = q.get("nocompress")
    if v is not None and str(v).strip().lower() in TRUTHY:
        return "nocompress"
    cc = ",".join(headers.get_all("Cache-Control") or []) if hasattr(headers, "get_all") else (headers.get("Cache-Control") or "")
    if any(d.strip().lower() == "no-transform" for d in cc.split(",")):
        return "no-transform"
    return None


def etag_matches(inm, etag):
    """If-None-Match weak comparison (RFC 9110 13.1.2): '*' or any listed tag equal to etag, W/ ignored."""
    if not inm or not etag:
        return False
    if inm.strip() == "*":
        return True
    want = etag[2:] if etag.startswith("W/") else etag
    return any((t.strip()[2:] if t.strip().startswith("W/") else t.strip()) == want for t in inm.split(","))


def prom_name(s):
    return re.sub(r"[^a-zA-Z0-9_]", "_", s)


def prom_labels(d):
    return "{%s}" % ",".join('%s="%s"' % (k, str(v).replace("\\", "\\\\").replace('"', '\\"'))
                             for k, v in sorted(d.items())) if d else ""


def spec_tf(p, ver=None):
    """Cache spec of an explicit transform (validated params); a stored version gets its own spec."""
    s = "tf:w=%s,h=%s,fit=%s,fm=%s,q=%d" % (p["w"] or "", p["h"] or "", p["fit"], p["fm"], int(p["q"]))
    return s + (",ver=%d" % ver if ver is not None else "") + ":v1"


def spec_video(fmt):
    """The video variant's spec - the same string the worker stores it under (worker.AUTO_SPEC). These two once
    differed ("webm:<codec>:v1" here), so every finished WebM was looked up under a key nothing ever wrote."""
    return "auto:%s:v1" % fmt


def is_loopback(host):
    try:
        ip = ipaddress.ip_address(str(host).split("%", 1)[0])
    except ValueError:
        return False
    return ip.is_loopback or bool(getattr(ip, "ipv4_mapped", None) and ip.ipv4_mapped.is_loopback)


def split_target(target):
    """(raw path, raw query) of a request target. Not urlsplit: '//host/x.png' is a path here, never a netloc."""
    t = target or "/"
    if t[:7].lower() == "http://" or t[:8].lower() == "https://":
        u = urllib.parse.urlsplit(t)
        return u.path or "/", u.query
    path, _, query = t.split("#", 1)[0].partition("?")
    return path or "/", query


def parse_accept(value):
    """{media type: q} from an Accept header; malformed q counts as 0 (never claim support we are unsure of)."""
    out = {}
    for part in (value or "").split(","):
        bits = part.strip().split(";")
        t = bits[0].strip().lower()
        if not t:
            continue
        q = 1.0
        for b in bits[1:]:
            k, _, v = b.strip().partition("=")
            if k.strip().lower() == "q":
                try:
                    q = float(v.strip())
                except ValueError:
                    q = 0.0
        out[t] = max(q, out.get(t, 0.0)) if t in out else q
    return out


def negotiate_format(accept):
    """avif | webp | orig. Only explicit types count (like the edge rules): */* and image/* do not promise AVIF."""
    a = parse_accept(accept)
    if a.get("image/avif", 0) > 0:
        return "avif"
    if a.get("image/webp", 0) > 0:
        return "webp"
    return "orig"


def disposition(rel, ext):
    """inline; filename*=UTF-8''<base name with the variant's extension> (RFC 5987)."""
    base = (rel or "").rsplit("/", 1)[-1] or "file"
    stem = base.rsplit(".", 1)[0] if "." in base.strip(".") else base
    return "inline; filename*=UTF-8''" + urllib.parse.quote("%s.%s" % (stem, ext), safe=ATTR_SAFE)


def location(mount, rel, v, query=None):
    """Relative 302 target: the canonical (prefix + mount-relative) path, re-escaped, plus ?_v= (or a full,
    already-encoded query). Built from the resolved path, never from the raw request, so '//evil.example/x.png'
    cannot become an open redirect."""
    prefix = "/" + (mount.get("prefix") or "/").strip("/")
    path = ("" if prefix == "/" else prefix) + rel
    return urllib.parse.quote(path, safe=PATH_SAFE) + "?" + (query if query else "_v=" + v)


def version_file(mount, rel, n):
    """transform.py's stored-version layout: <mount>/.strata-versions/<h[:2]>/<h>/v<n>, h = sha1(rel)."""
    h = hashlib.sha1(rel.encode("utf-8")).hexdigest()
    return os.path.join(os.path.normpath(mount["path"]), ".strata-versions", h[:2], h, "v%d" % n)


def sign(secret, path, exp):
    """transform.py's signed-link MAC (HMAC-SHA256 of the decoded path and the expiry, 32 url-safe chars)."""
    msg = "%s\n%d" % (urllib.parse.unquote(path), int(exp))
    mac = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode().rstrip("=")[:32]


def _same_mtime(a, b):
    try:
        return abs(float(a) - float(b)) < MTIME_EPS
    except (TypeError, ValueError):
        return False


def _hv(v):
    return _CRLF.sub(" ", str(v)).strip()


class Bucket:
    """Token bucket in bytes/s with reservation: take(n) books n bytes now and returns how long to wait before
    sending them, so concurrent streams queue fairly and the long-run rate never exceeds the limit. mbps <= 0 =
    unlimited."""

    def __init__(self, mbps, burst):
        self.lock = threading.Lock()
        self.rate, self.burst = None, float(burst)
        self.set(mbps)
        self.tokens = self.burst
        self.at = time.perf_counter()

    def set(self, mbps):
        try:
            mbps = float(mbps or 0)
        except (TypeError, ValueError):
            mbps = 0.0
        self.rate = mbps * 1e6 / 8 if mbps > 0 else None

    def take(self, n):
        with self.lock:
            if self.rate is None:
                return 0.0
            now = time.perf_counter()
            self.tokens = min(self.burst, self.tokens + (now - self.at) * self.rate)
            self.at = now
            self.tokens -= n
            return 0.0 if self.tokens >= 0 else -self.tokens / self.rate


class Ctx:
    """One media request: mount, paths, stat, query, the cache values Caddy passed in and the request facts the
    optimizer needs (method, validators, bypass)."""
    __slots__ = ("conf", "mid", "mount", "rel", "full", "src", "st", "q", "browser", "edge", "ver", "method", "inm",
                 "conditional", "bypass", "negotiated")

    def __init__(self, conf, mid, mount, rel, full, q, browser, edge, method="GET", inm="", conditional=False,
                 bypass=None):
        self.conf, self.mid, self.mount, self.rel, self.full, self.q = conf, mid, mount, rel, full, q
        self.src, self.st, self.ver = full, None, None
        self.browser = _hv(browser or "") or FALLBACK_CC
        self.edge = _hv(edge or "")          # "" = older rules.py: single-header behaviour
        self.method, self.inm, self.conditional, self.bypass = method, inm or "", conditional, bypass
        self.negotiated = False              # the answer depends on Accept (-> Vary: Accept)

    def cc(self, short=False):
        """(browser value, CDN value) for an accel/orig answer; both always non-empty.
        short=True: the CDN keeps it briefly (deferred / bypassed encode). short="nostore": nobody stores it - an
        answer that depends on a request header which is not part of the cache key (Cache-Control: no-transform)."""
        if short == "nostore":
            return "private, no-store", "no-store"
        if not short:
            return self.browser, self.edge or self.browser
        s = _hv((self.conf.get("image") or {}).get("short_ttl") or SHORT_CC)
        return (self.browser, s) if self.edge else (s, s)


# ---------------------------------------------------------------- the service (state shared by all requests)

class Service:
    def __init__(self, conf_path=None, monitor=None):
        self.conf_path = conf_path or config.CONF_PATH
        self.started = time.time()
        c = config.load(self.conf_path)
        self._conf = c
        self.store = store_mod.Store(c["db"]).init()
        self.events = events_mod.Events(self.store, c["event_log"], PROC)
        self.own_monitor = monitor is None
        self.monitor = monitor or breaker.Monitor()
        self.breaker = breaker.Breaker("media", self.monitor, c, self.events)
        self.cache = cache_mod.Cache(c["cache_root"], self._cache_max(c), self.store)
        self.lane_total = Bucket((c.get("lane") or {}).get("total_mbps", 25), LANE_CHUNK * 4)
        self.model = imaging.CostModel()
        self.model_base = {}
        self.halt = threading.Event()
        self.threads = []
        self.stat_lock = threading.Lock()
        self.counters = collections.Counter()
        self.win = collections.Counter()           # per-minute counters (sample row)
        self.win_cpu, self.win_mem = [], None
        self.minute = int(time.time() // 60)
        self.v_lock = threading.Lock()
        self.verdicts, self.verdicts_ci = {}, {}
        self.v_seen, self.v_at, self.v_full_ts, self.v_full_at = 0.0, None, None, float("-inf")
        self.jobs = queue.Queue(maxsize=2000)
        self.q_lock = threading.Lock()
        self.recent = {}                           # enqueue dedupe key -> monotonic ts
        self.hashes = {}                           # (mount, rel, size, mtime) -> (monotonic ts, verdict | None)
        self.fl_lock = threading.Lock()
        self.inflight = {}                         # cache key -> Event (one encode per variant at a time)
        # image optimizer (tiers, hotness, failure backoff, metrics)
        self.h_lock = threading.Lock()
        self.hits = {}                             # key -> [requests, served bytes, saved bytes] (flushed to the db)
        self.failures = {}                         # key -> (monotonic retry-at, failures so far): negative cache
        self.dims = collections.OrderedDict()      # (mount, rel, size, mtime) -> (w, h): no probe per ?w= request
        self.retiring = []                         # (monotonic due, rel_url): old names of moved variants
        self.metrics = collections.Counter()       # (name, labels tuple) -> value  (Prometheus counters)
        self.enc_hist = collections.Counter()      # encode seconds histogram buckets (sync encodes)
        self.queued_images = 0
        self.tier_at = self.sweep_at = time.monotonic()
        self.tier_last = {}
        self.lane_active = 0
        self.cache_usage = {}
        self.errors = collections.deque(maxlen=20)
        self.model_at = self.usage_at = self.prune_at = time.monotonic()
        self._load_model()

    # ------------------------------------------------------------ config
    @staticmethod
    def _cache_max(c):
        try:
            return int(float(c.get("cache_max_gb") or 30) * (1 << 30))
        except (TypeError, ValueError):
            return 30 << 30

    def conf(self):
        """config.load() is cheap (stat of media.json); a changed file is re-applied to breaker, lane and cache."""
        c = config.load(self.conf_path)
        if c is not self._conf:
            self._conf = c
            try:
                self.breaker.configure(c)
                self.lane_total.set((c.get("lane") or {}).get("total_mbps", 25))
                self.cache.max_bytes = self._cache_max(c)
            except Exception as e:
                self.fail("config", e)
        return c

    def cutover(self, c):
        """Files born before this are legacy. Unset (0) = this process' start: until the bridge records the real
        switch-on time, the existing library must not turn into a wall of 503s."""
        try:
            return float(c.get("cutover") or 0) or self.started
        except (TypeError, ValueError):
            return self.started

    def mem(self):
        try:
            return self.monitor.snapshot().get("mem_avail_mb")
        except Exception:
            return None

    # ------------------------------------------------------------ bookkeeping
    def count(self, name, n=1):
        with self.stat_lock:
            self.counters[name] += n
            self.win[name] += n

    # ------------------------------------------------------------ image optimizer: metrics + hotness
    def metric(self, name, n=1, **labels):
        with self.stat_lock:
            self.metrics[(name, tuple(sorted(labels.items())))] += n

    ENC_BUCKETS = (0.1, 0.25, 0.5, 1, 2, 4, 8, 16, 32)

    def observe_encode(self, fmt, secs):
        self.metric("image_optimizer_encode_count_total", format=fmt, path="sync")
        self.metric("image_optimizer_encode_duration_seconds_sum", float(secs or 0))
        with self.stat_lock:
            self.enc_hist["count"] += 1
            for b in self.ENC_BUCKETS:
                if (secs or 0) <= b:
                    self.enc_hist[b] += 1

    def account(self, ctx, ans):
        """Bytes and hotness of one answer. Only GETs without validators are counted as bytes on the wire (a HEAD
        sends none, a conditional request is most likely a 304); every request counts towards hotness."""
        kind = ans[0]
        meta = ans[-1] if isinstance(ans[-1], dict) else {}
        body = ctx.method == "GET" and not ctx.conditional and ctx.st is not None
        src = ctx.st.st_size if ctx.st is not None else 0
        if kind == "accel":
            fmt = meta.get("fmt") or ans[2]
            self.metric("image_optimizer_requests_total", result="variant", format=fmt, cache=meta.get("cache", "?"))
            key = meta.get("key")
            sent = int(meta.get("bytes") or 0) if body else 0
            saved = max(0, src - sent) if body and sent else 0
            if body:
                self.metric("image_optimizer_original_bytes_total", src)
                self.metric("image_optimizer_served_bytes_total", sent, format=fmt, source="variant")
                self.metric("image_optimizer_bytes_saved_total", saved, format=fmt)
                self.count("opt_bytes.original", src)
                self.count("opt_bytes.served", sent)
                self.count("opt_bytes.saved", saved)
            if key:
                with self.h_lock:
                    h = self.hits.setdefault(key, [0, 0, 0])
                    h[0], h[1], h[2] = h[0] + 1, h[1] + sent, h[2] + saved
        elif kind == "orig":
            cache = meta.get("cache") or ("deferred" if "deferred" in ans[1] else
                                          "bypass" if ans[1].startswith("bypass") else "original")
            self.metric("image_optimizer_requests_total", result="original", format="original", cache=cache)
            if body:
                self.metric("image_optimizer_original_bytes_total", src)
                self.metric("image_optimizer_served_bytes_total", src, format="original", source="original")
                self.count("opt_bytes.original", src)
                self.count("opt_bytes.served", src)
        elif kind == "notmod":
            self.metric("image_optimizer_requests_total", result="not_modified", format=meta.get("fmt") or "?",
                        cache="validator")
            key = meta.get("key")
            if key:
                with self.h_lock:
                    self.hits.setdefault(key, [0, 0, 0])[0] += 1
        elif kind == "redirect":
            self.metric("image_optimizer_requests_total", result="redirect", format=ans[1], cache="none")

    def tiers(self, c):
        d = {"interval_s": 300, "half_life_h": 72, "promote_min_hits": 4, "promote_rate_per_day": 2.0,
             "promote_min_value_mb": 32, "horizon_days": 30, "storage_weight": 0.02, "cpu_mb_per_s": 4,
             "demote_rate_per_day": 0.2, "demote_idle_days": 21, "persistent_max_gb": 100,
             "ephemeral_max_age_days": 30, "tombstone_days": 30, "failure_retry_h": 24, "upgrade_on_promote": True}
        d.update(((c or {}).get("image") or {}).get("tiers") or {})
        return d

    def flush_hits(self):
        with self.h_lock:
            hits, self.hits = self.hits, {}
        if not hits:
            return 0
        tc = self.tiers(self._conf)
        try:
            return self.store.add_hits({k: tuple(v) for k, v in hits.items()}, float(tc["half_life_h"]) * 3600)
        except Exception:
            with self.h_lock:   # keep them for the next pass
                for k, v in hits.items():
                    h = self.hits.setdefault(k, [0, 0, 0])
                    for i in range(3):
                        h[i] += v[i]
            raise

    @staticmethod
    def value_of(row, now, tc):
        """(requests/day, value in bytes) of keeping a variant persistent.

        value = projected bandwidth saved over the horizon (rate x horizon x bytes saved per request)
              + the re-encode it avoids after an eviction (encode seconds x cpu_mb_per_s, i.e. CPU priced in MB)
              - its disk space x storage_weight (disk is cheap here, uplink is not)."""
        hl = float(tc["half_life_h"]) * 3600
        score = store_mod.Store.decayed(row, now, hl)
        rate = score * 0.6931 / (hl / 86400.0)
        per_req = max(0, int(row.get("src_bytes") or 0) - int(row.get("bytes") or 0))
        value = (rate * float(tc["horizon_days"]) * per_req + float(row.get("secs") or 0) * float(tc["cpu_mb_per_s"]) * 1e6
                 - float(row.get("bytes") or 0) * float(tc["storage_weight"]))
        return rate, value

    def tier_pass(self):
        """Every image.tiers.interval_s: fold hits into the db, promote demonstrably hot variants to the persistent
        tier, demote long-cold ones (hysteresis: promote >= promote_rate, demote only < demote_rate AND idle for
        demote_idle_days), keep the persistent tier under its cap (lowest value first), forget old tombstones and
        failure decisions."""
        c, now = self._conf, time.time()
        tc = self.tiers(c)
        self.flush_hits()
        res = {"promoted": 0, "demoted": 0, "upgrades": 0}
        persistent = self.store.variants_in_tier("persistent")
        p_bytes = sum(int(r.get("bytes") or 0) for r in persistent)
        cap = float(tc["persistent_max_gb"]) * (1 << 30)
        for r in persistent:
            rate, _ = self.value_of(r, now, tc)
            idle = now - float(r.get("last_used") or 0)
            if rate < float(tc["demote_rate_per_day"]) and idle > float(tc["demote_idle_days"]) * 86400:
                if self.move(r, "ephemeral"):
                    res["demoted"] += 1
                    p_bytes -= int(r.get("bytes") or 0)
        if p_bytes > cap:   # over the cap: demote the least valuable first
            rows = sorted(self.store.variants_in_tier("persistent"), key=lambda r: self.value_of(r, now, tc)[1])
            for r in rows:
                if p_bytes <= cap:
                    break
                if self.move(r, "ephemeral"):
                    res["demoted"] += 1
                    p_bytes -= int(r.get("bytes") or 0)
        cands = []
        for r in self.store.variants_in_tier("ephemeral", min_hits=int(tc["promote_min_hits"])):
            if not r.get("file"):
                continue
            rate, value = self.value_of(r, now, tc)
            if rate >= float(tc["promote_rate_per_day"]) and value >= float(tc["promote_min_value_mb"]) * 1e6:
                cands.append((value, r))
        for value, r in sorted(cands, key=lambda x: -x[0]):
            if p_bytes + int(r.get("bytes") or 0) > cap:
                break
            if self.move(r, "persistent"):
                res["promoted"] += 1
                p_bytes += int(r.get("bytes") or 0)
                self.events.emit("variant.promoted", "info", r.get("mount"), r.get("path"), fmt=r.get("fmt"),
                                 width=r.get("width"), bytes=r.get("bytes"), value_mb=round(value / 1e6, 1))
                ic = imaging.image_conf(c)
                spec = parse_spec(r.get("spec"))
                if tc.get("upgrade_on_promote") and spec and r.get("fmt") == "avif" and int(ic["speed_bg"]) < int(ic["speed_sync"]):
                    st = types.SimpleNamespace(st_size=r.get("src_size") or 0, st_mtime=r.get("src_mtime") or 0)
                    if self.enqueue("image", r["mount"], r["path"], st,
                                    {"want": spec["want"], "width": spec["width"], "spec": r["spec"], "upgrade": True}, 50):
                        res["upgrades"] += 1
        res.update(self.store.prune_variants(now - float(tc["tombstone_days"]) * 86400,
                                             now - float(tc["failure_retry_h"]) * 3600))
        self.tier_last = dict(res, ts=now, persistent_bytes=p_bytes)
        return res

    def move(self, row, tier):
        """Move one variant between tiers: new name first, then the row, old name retired 2 min later (a request
        that already got the old name from lookup() can still open it)."""
        old = row.get("file") or ""
        try:
            new = self.cache.move_tier(old, row["key"], tier)
        except (OSError, ValueError) as e:
            self.fail("tier", e)
            return False
        if new == old:
            return False
        self.store.set_tier(row["key"], tier, new, promoted=time.time())
        self.retiring.append((time.monotonic() + 120, old))
        self.metric("image_optimizer_hot_promotions_total" if tier == "persistent" else "image_optimizer_demotions_total")
        return True

    def retire(self, mono):
        due = [r for t, r in self.retiring if t <= mono]
        if due:
            self.retiring = [(t, r) for t, r in self.retiring if t > mono]
            for rel in due:
                if not self.cache.remove(rel):
                    self.retiring.append((mono + 300, rel))   # still open (being served): try again later

    def sweep(self):
        """Hourly: orphaned cache files (crash between write and row, old names of moved variants)."""
        n, freed, _ = self.cache.sweep_orphans()
        if n:
            self.metric("image_optimizer_evictions_total", n, reason="orphan")
        return n

    def optimizer_stats(self):
        """Answer "how much bandwidth did the optimizer save?": since start (this process) and lifetime (the
        variant rows: bytes the origin served from variants and what that saved against the originals)."""
        with self.stat_lock:
            m = dict(self.metrics)

        def total(name, **want):
            return sum(v for (n, lb), v in m.items() if n == name and all(dict(lb).get(k) == x for k, x in want.items()))
        orig, served, saved = (total("image_optimizer_original_bytes_total"), total("image_optimizer_served_bytes_total"),
                               total("image_optimizer_bytes_saved_total"))
        try:
            life = self.store.variant_totals()
        except Exception as e:
            self.fail("store", e)
            life = {}
        return {"since": self.started, "original_bytes": orig, "served_bytes": served, "bytes_saved": saved,
                "saved_pct": round(100.0 * (orig - served) / orig, 1) if orig else None,
                "requests": {"variant": total("image_optimizer_requests_total", result="variant"),
                             "original": total("image_optimizer_requests_total", result="original"),
                             "not_modified": total("image_optimizer_requests_total", result="not_modified"),
                             "redirect": total("image_optimizer_requests_total", result="redirect")},
                "cache_hits": {t: total("image_optimizer_cache_hits_total", tier=t)
                               for t in ("persistent", "ephemeral", "validator", "decision")},
                "cache_misses": total("image_optimizer_cache_misses_total"),
                "encodes": total("image_optimizer_encode_count_total"),
                "encode_failures": total("image_optimizer_encode_failures_total"),
                "promotions": total("image_optimizer_hot_promotions_total"),
                "demotions": total("image_optimizer_demotions_total"),
                "evictions": self.cache.evicted, "queue_depth": self.queued_images, "tier_pass": self.tier_last,
                "lifetime": life}

    def prometheus(self):
        """/_metrics: the optimizer's counters in the Prometheus text format (loopback only, like /_stats)."""
        lines, seen = [], set()
        with self.stat_lock:
            items = sorted(self.metrics.items())
            hist = dict(self.enc_hist)
        for (name, labels), v in items:
            if name not in seen:
                seen.add(name)
                lines.append("# TYPE %s %s" % (name, "counter"))
            lines.append("%s%s %s" % (prom_name(name), prom_labels(dict(labels)), v))
        lines.append("# TYPE image_optimizer_encode_duration_seconds_bucket counter")
        for b in self.ENC_BUCKETS:
            lines.append('image_optimizer_encode_duration_seconds_bucket{le="%s"} %d' % (b, hist.get(b, 0)))
        lines.append('image_optimizer_encode_duration_seconds_bucket{le="+Inf"} %d' % hist.get("count", 0))
        lines.append("image_optimizer_encode_duration_seconds_count %d" % hist.get("count", 0))
        u = self.cache_usage or {}
        ev = self.cache.evicted
        gauges = [("image_optimizer_queue_depth", {}, self.queued_images),
                  ("image_optimizer_inflight_encodes", {}, len(self.inflight)),
                  ("image_optimizer_cache_bytes", {"tier": "ephemeral"}, u.get("bytes") or 0),
                  ("image_optimizer_cache_bytes", {"tier": "persistent"}, u.get("static_bytes") or 0),
                  ("image_optimizer_cache_files", {"tier": "ephemeral"}, u.get("files") or 0),
                  ("image_optimizer_cache_files", {"tier": "persistent"}, u.get("static_files") or 0),
                  ("image_optimizer_breaker_open", {}, 1 if self.breaker.status().get("state") == "open" else 0)]
        lines.append("# TYPE image_optimizer_evictions_total counter")
        lines.append('image_optimizer_evictions_total{reason="lru_or_age"} %d' % ev)
        try:
            bg = self.store.get_meta("optimizer_worker") or {}
        except Exception:
            bg = {}
        for k in ("encodes", "failures", "upgrades"):
            name = {"encodes": "image_optimizer_encode_count_total", "failures": "image_optimizer_encode_failures_total",
                    "upgrades": "image_optimizer_upgrades_total"}[k]
            lines.append('%s{path="background"} %d' % (name, int(bg.get(k) or 0)))
        for name, labels, v in gauges:
            if name not in seen:
                seen.add(name)
                lines.append("# TYPE %s gauge" % name)
            lines.append("%s%s %s" % (name, prom_labels(labels), v))
        return "\n".join(lines) + "\n"

    def fail(self, where, e, tb=False):
        """Internal error: counted, remembered for /_stats, logged, and an event at most once a minute per place."""
        msg = "%s: %s" % (e.__class__.__name__, str(e)[:300])
        self.count("error." + where)
        self.errors.append({"ts": time.time(), "where": where, "error": msg})
        self.events.emit_every(60, "media.error", "warning", key=where, where=where, error=msg)
        log("%s failed: %s" % (where, msg))
        if tb:
            log(traceback.format_exc(limit=6))

    def bypass(self, ctx, kind, severity="warning", **detail):
        """Log a failure + kind and bypass it: event bypass.<kind>, original under the short CDN TTL."""
        self.count("bypass." + kind)
        self.events.emit_every(BYPASS_EVERY, "bypass." + kind, severity, ctx.mid, ctx.rel,
                               key=(ctx.mid, ctx.rel), **detail)
        return ("orig", "deferred" if kind == "deferred" else "bypass;kind=%s" % kind, True)

    # ------------------------------------------------------------ lifecycle
    def start(self):
        try:
            self.refresh_verdicts(full=True)
        except Exception as e:  # db busy at boot: the housekeeping loop retries every 2 s
            self.fail("verdicts", e)
        self.events.start()
        if self.own_monitor and not self.monitor.is_alive():
            self.monitor.start()
        for name, fn in (("media-enqueue", self._enqueuer), ("media-housekeeping", self._housekeeping)):
            t = threading.Thread(target=fn, name=name, daemon=True)
            t.start()
            self.threads.append(t)
        self.events.emit("media.start", "info", version=VERSION, pid=os.getpid())
        return self

    def stop(self):
        self.halt.set()
        for t in self.threads:
            t.join(5)
        for step in (self.save_model, self.cache.flush_touches, self.flush_hits):
            try:
                step()
            except Exception as e:
                self.fail("stop", e)
        if self.own_monitor:
            self.monitor.stop()
        self.events.stop()
        try:
            self.store.close()
        except Exception:
            pass

    def _housekeeping(self):
        while not self.halt.wait(TICK_S):
            self.tick()

    def tick(self):
        """Every 2 s: verdict refresh (full every 10 min), meta.breaker, monitor window; then the per-minute sample,
        cost-model save, cache usage and pruning of the in-memory dedupe tables when due."""
        mono, now = time.monotonic(), time.time()
        self.conf()
        self._step("verdicts", lambda: self.refresh_verdicts(full=mono - self.v_full_at >= FULL_RELOAD_S))
        self._step("breaker", self.publish_breaker)
        snap = self.monitor.snapshot()
        with self.stat_lock:
            if snap.get("cpu") is not None:
                self.win_cpu.append(snap["cpu"])
            m = snap.get("mem_avail_mb")
            if m is not None:
                self.win_mem = m if self.win_mem is None else min(self.win_mem, m)
        minute = int(now // 60)
        if minute != self.minute:
            ts, self.minute = self.minute * 60, minute
            self._step("sample", lambda: self.write_sample(ts))
        if mono - self.model_at >= MODEL_SAVE_S:
            self.model_at = mono
            self._step("model", self.save_model)
        if mono - self.usage_at >= USAGE_EVERY_S or not self.cache_usage:
            self.usage_at = mono
            self._step("cache", self._usage)
        if mono - self.prune_at >= 60:
            self.prune_at = mono
            self._prune(mono)
        self._step("retire", lambda: self.retire(mono))
        tc = self.tiers(self._conf)
        if mono - self.tier_at >= float(tc["interval_s"]):
            self.tier_at = mono
            self._step("tiers", self.tier_pass)
        if mono - self.sweep_at >= 3600:
            self.sweep_at = mono
            self._step("sweep", self.sweep)

    def _step(self, name, fn):
        try:
            fn()
        except Exception as e:
            self.fail(name, e)

    def _usage(self):
        self.cache.max_age_s = float(self.tiers(self._conf)["ephemeral_max_age_days"]) * 86400
        self.cache_usage = self.cache.usage()
        self.cache.maybe_evict()
        try:
            self.queued_images = int((self.store.job_counts().get("image") or {}).get("queued", 0))
        except Exception as e:
            self.fail("store", e)

    def _prune(self, mono):
        with self.q_lock:
            for k in [k for k, t in self.recent.items() if mono - t >= ENQUEUE_TTL]:
                del self.recent[k]
        for k in [k for k, v in list(self.hashes.items()) if mono - v[0] >= HASH_TTL]:
            self.hashes.pop(k, None)

    def publish_breaker(self):
        """meta.breaker for the worker (pauses while open) and the admin UI."""
        st = self.breaker.status()
        st.update(ts=time.time(), pid=os.getpid(), proc=PROC)
        self.store.set_meta("breaker", st)

    def write_sample(self, ts):
        """One row per minute (DESIGN 8): cpu avg/max, mem min, breaker window, bypass counts by kind, gate counts."""
        w = self.breaker.window(reset=True)
        with self.stat_lock:
            wc, self.win = self.win, collections.Counter()
            cpu, self.win_cpu = self.win_cpu, []
            mem, self.win_mem = self.win_mem, None
        data = {"cpu_avg": round(sum(cpu) / len(cpu), 1) if cpu else None,
                "cpu_max": round(max(cpu), 1) if cpu else None, "mem_min_mb": round(mem) if mem is not None else None, "open_s": w.get("open_s"),
                "trips": w.get("trips"), "waiters_max": w.get("waiters_max"), "wait_p90_ms": w.get("wait_p90_ms"),
                "encodes": w.get("encodes"), "encode_p95_s": w.get("encode_p95_s"),
                "bypass": {k[7:]: v for k, v in wc.items() if k.startswith("bypass.")},
                "gate": {k[5:]: v for k, v in wc.items() if k.startswith("gate.")},
                "answers": {k[7:]: v for k, v in wc.items() if k.startswith("answer.")},
                "optimizer": {k[10:]: v for k, v in wc.items() if k.startswith("opt_bytes.")},
                "requests": wc.get("requests", 0)}
        self.store.add_sample(ts, PROC, data)

    # ------------------------------------------------------------ cost model (shared with the worker via meta)
    def _load_model(self):
        try:
            d = self.store.get_meta("cost_model")
            if isinstance(d, dict):
                self.model = imaging.CostModel.from_dict(d)
        except Exception as e:
            self.fail("model", e)
        self.model_base = dict(self.model.samples)

    def save_model(self):
        """Merge the rates this process measured into meta.cost_model (the worker measures other speeds)."""
        d = self.model.to_dict()
        mine = [k for k, n in d["samples"].items() if n > self.model_base.get(k, 0)]
        if not mine:
            return
        cur = self.store.get_meta("cost_model")
        cur = cur if isinstance(cur, dict) else {}
        rates, samples = dict(cur.get("rates") or {}), dict(cur.get("samples") or {})
        for k in mine:
            rates[k], samples[k] = d["rates"][k], d["samples"][k]
        self.store.set_meta("cost_model", {"rates": rates, "samples": samples, "ts": time.time(), "by": PROC})
        self.model_base = dict(d["samples"])

    # ------------------------------------------------------------ job queue (fire and forget)
    def enqueue(self, kind, mid, rel, st, params, priority):
        """Queue a store.enqueue on the background thread; the hot path never waits for the database."""
        pj = params if isinstance(params, str) else json.dumps(params, sort_keys=True, separators=(",", ":"))
        key = (kind, mid, rel, pj, st.st_size, st.st_mtime)
        now = time.monotonic()
        with self.q_lock:
            last = self.recent.get(key)
            if last is not None and now - last < ENQUEUE_TTL:
                return False
            self.recent[key] = now
        try:
            self.jobs.put_nowait((key, kind, mid, rel, params, st.st_size, st.st_mtime, priority))
        except queue.Full:
            with self.q_lock:
                self.recent.pop(key, None)
            self.count("enqueue.dropped")
            return False
        return True

    def _enqueuer(self):
        while True:
            try:
                item = self.jobs.get(timeout=0.5)
            except queue.Empty:
                if self.halt.is_set():
                    return
                continue
            key, kind, mid, rel, params, size, mtime, prio = item
            try:
                self.store.enqueue(kind, mid, rel, size=size, mtime=mtime, params=params, priority=prio)
                self.count("enqueue." + kind)
            except Exception as e:
                with self.q_lock:
                    self.recent.pop(key, None)   # the next request retries
                self.fail("enqueue", e)

    # ------------------------------------------------------------ gate (DESIGN 5.2)
    def refresh_verdicts(self, full=False):
        rows = self.store.verdicts_since(0 if full else max(0.0, self.v_seen - 5))
        slim = {}
        for r in rows:
            try:
                slim[(int(r["mount"]), r["path"])] = {"state": r.get("state"), "size": r.get("size"),
                                                      "mtime": r.get("mtime"), "updated": r.get("updated")}
            except (TypeError, ValueError, KeyError):
                continue
        with self.v_lock:
            if full:
                self.verdicts = slim
                self.verdicts_ci = {(k[0], k[1].lower()): v for k, v in slim.items()}
            else:
                for k, v in slim.items():
                    self.verdicts[k] = v
                    self.verdicts_ci[(k[0], k[1].lower())] = v
            if rows:
                self.v_seen = max(self.v_seen, max(float(r.get("updated") or 0) for r in rows))
        self.v_at = time.time()
        if full:
            self.v_full_at, self.v_full_ts = time.monotonic(), self.v_at
        return len(rows)

    def verdict_for(self, mid, rel):
        v = self.verdicts.get((mid, rel))
        return v if v is not None else self.verdicts_ci.get((mid, rel.lower()))   # SMB/NTFS names are case-blind

    def hash_verdict(self, mid, rel, full, st):
        """Most severe verdict of any file with this size + quick hash (renamed / re-uploaded copies)."""
        k = (mid, rel, st.st_size, st.st_mtime)
        now = time.monotonic()
        hit = self.hashes.get(k)
        if hit is not None and now - hit[0] < HASH_TTL:
            return hit[1]
        try:
            v = self.store.verdict_by_hash(st.st_size, config.quick_hash(full, st.st_size))
        except Exception as e:
            self.fail("gate_hash", e)
            return None
        self.hashes[k] = (now, v)
        return v

    def decide(self, c, mid, rel, full, st):
        """(action allow|held|pending, reason, lane "throttle"|""). Reads memory; only a miss reads the db."""
        g, ln = c.get("gate") or {}, c.get("lane") or {}
        try:
            big = st.st_size >= int(ln.get("min_bytes") or (512 << 20))
        except (TypeError, ValueError):
            big = False
        lane = "throttle" if ln.get("enabled", True) and big else ""
        if not config.gated(rel, c):
            return "allow", "exempt", lane
        legacy = config.birth_time(st) < self.cutover(c)
        v = self.verdict_for(mid, rel)
        if v is not None and v.get("size") == st.st_size and _same_mtime(v.get("mtime"), st.st_mtime):
            s = v.get("state")
            if s in ("clean", "released", "skipped"):
                return "allow", "clean", lane
            if s in ("flagged", "held"):
                return "held", s, ""
            if s == "error":   # unscannable: legacy content stays up, new content never goes out unscanned
                return ("allow", "legacy", lane) if legacy else ("held", "error", "")
        else:  # no verdict, or one for other content: a held copy anywhere keeps this one held
            h = self.hash_verdict(mid, rel, full, st)
            if h is not None and h.get("state") in ("flagged", "held"):
                return "held", "copy", ""
        self.enqueue("scan", mid, rel, st, "", 60 if legacy else 10)
        if legacy and g.get("legacy_while_pending", True):
            return "allow", "legacy", lane
        return "pending", "new", ""

    def gate_check(self, ctx):
        """None when the file may be served, else the held / pending answer (DESIGN 6.3 step 2)."""
        action = self.decide(ctx.conf, ctx.mid, ctx.rel, ctx.full, ctx.st)[0]
        self.count("gate." + action)
        return None if action == "allow" else (action,)

    # ------------------------------------------------------------ variants (DESIGN 6.3, 7.6)
    def variant(self, ctx):
        """Route one variant request. Format selection (_v, negotiated by Accept at the edge or by negotiate()) and
        dimension selection (?w= snapped to the width ladder) are independent inputs of one variant identity;
        ?h ?fit ?fm ?q keep transform.py's exact legacy semantics."""
        q = ctx.q
        fm, v = (q.get("fm") or "").lower(), (q.get("_v") or "").lower()
        if fm == "webm":
            return self.video_variant(ctx, "webm", explicit=True)
        if v in video.FORMATS and not ctx.bypass:
            return self.video_variant(ctx, v, explicit=False)
        if v not in ("", "orig", "avif", "webp") + video.FORMATS:
            return ("text", 400, "_v must be avif, webp, webm, mp4 or orig")
        ctx.negotiated = v in ("avif", "webp")
        explicit = any(q.get(k) for k in ("h", "fit", "fm", "q"))
        if ctx.bypass:   # the untouched original, never generated / promoted / stored under this request
            return self.gate_check(ctx) or self.bypass_orig(ctx)
        if explicit:
            return self.explicit(ctx)
        width = None
        if q.get("w"):
            if config.ext_of(ctx.rel) not in config.TRANSFORMABLE:
                return ("text", 415, "image modifiers only apply to images")
            try:
                width = self.width_rung(ctx)
            except ValueError as e:
                return ("text", 400, str(e))
        if v in ("avif", "webp"):
            return self.auto(ctx, v, width)
        if width:
            return self.family(ctx, width)
        return self.gate_check(ctx) or ("orig", "orig;reason=requested", False)

    def width_rung(self, ctx):
        """?w= -> ladder rung (image.widths), or the exact width when image.snap_widths is off."""
        ic = imaging.image_conf(ctx.conf)
        if (ctx.conf.get("image") or {}).get("snap_widths", True):
            return imaging.snap_width(ctx.q["w"], ic)
        s = str(ctx.q["w"]).strip()
        if not re.fullmatch(r"[0-9]{1,6}", s) or not 1 <= int(s) <= int(ic["max_width"]):
            raise ValueError("w must be a whole number of pixels (1-%d)" % int(ic["max_width"]))
        return int(s)

    def bypass_orig(self, ctx):
        """?nocompress / Cache-Control: no-transform. A URL bypass is cacheable like the original itself (its URL
        is its own cache key); a header bypass is never stored, so it cannot take the place of the optimized entry."""
        self.metric("image_optimizer_bypass_total", reason=ctx.bypass)
        self.count("bypass_request." + ctx.bypass)
        return ("orig", "orig;reason=" + ctx.bypass, "nostore" if ctx.bypass == "no-transform" else False,
                {"cache": "bypass", "source": "original"})

    def negotiate(self, ctx, accept):
        """Redirect mode (DESIGN 6.1) and ?w= in any mode: gate first, then 302 to the canonical variant URL
        (?w=<rung>&_v=avif|webp|orig, other query parameters kept) by Accept. Answers vary by Accept and are
        private + no-store, so no cache can hand one client's choice to another."""
        g = self.gate_check(ctx)
        if g:
            return g
        ctx.negotiated = True
        if ctx.bypass:
            return self.bypass_orig(ctx)
        ext = config.ext_of(ctx.rel)
        width = None
        if ctx.q.get("w"):
            if ext not in config.TRANSFORMABLE:
                return ("text", 415, "image modifiers only apply to images")
            try:
                width = self.width_rung(ctx)
            except ValueError as e:
                return ("text", 400, str(e))
        # a video only gets here from Caddy's video matcher (redirect mode): its WebM / MP4, once there is one
        want = (video.video_conf(ctx.conf)["format"] if ext in config.VIDEO_EXT and not width else
                negotiate_format(accept) if ext in config.NEGOTIABLE or width else "orig")
        self.count("negotiate." + want)
        self.metric("image_optimizer_negotiations_total", format=want)
        keep = [(k, v) for k, v in ctx.q.items() if k not in ("w", "_v")]
        extra = urllib.parse.urlencode(keep + ([("w", str(width))] if width else []) + [("_v", want)])
        return ("redirect", want, True, extra)

    @contextlib.contextmanager
    def flight(self, key, wait_s):
        """One encode per variant: later requests wait for the first (True = this request encodes).

        In-process an Event; across processes (the worker, a second media.py during a restart) an OS lock file per
        key (cache.KeyLock). If another process holds it, this request waits up to wait_s for its result and then
        yields False - it never starts a second encode of the same variant."""
        with self.fl_lock:
            ev = self.inflight.get(key)
            first = ev is None
            if first:
                ev = self.inflight[key] = threading.Event()
        if not first:
            self.metric("image_optimizer_singleflight_waits_total")
            ev.wait(wait_s)
            yield False
            return
        lk = self.cache.lock(key)
        try:
            got = lk.acquire(blocking=False)
            if not got:
                self.metric("image_optimizer_singleflight_waits_total")
                got = lk.acquire(blocking=True, timeout=wait_s)   # the other process finishes, then we re-check
                if got:
                    lk.release()
                yield False
                return
            try:
                yield True
            finally:
                lk.release()
        finally:
            with self.fl_lock:
                self.inflight.pop(key, None)
            ev.set()

    def lookup(self, key, ctx=None):
        """Answer from a variant row: accel hit (with its tier), orig for a recorded decision, 304 for a conditional
        request whose ETag still names this variant (also after eviction: no encode just to say "not modified"),
        None = encode needed."""
        try:
            row = self.store.variant(key)
        except Exception as e:
            self.fail("store", e)
            return None
        if not row:
            return None
        if not row.get("beneficial"):
            reason = row.get("reason") or "not_beneficial"
            return ("orig", "orig;reason=%s" % reason, False, {"cache": "decision", "source": "original"})
        f = row.get("file") or ""
        tier = row.get("tier") or "ephemeral"
        meta = {"key": key, "tier": tier, "width": row.get("width"), "fmt": row.get("fmt"),
                "bytes": row.get("bytes") or 0, "src_bytes": row.get("src_bytes") or 0, "etag": row.get("etag")}
        if f and self.cache.exists(f):
            self.cache.touch(key)
            meta["cache"] = tier
            return ("accel", f, f.rsplit(".", 1)[-1], "hit", meta)   # tier: X-CDN-Image-Cache
        if ctx is not None and ctx.conditional and etag_matches(ctx.inm, row.get("etag")):
            meta["cache"] = "validator"
            return ("notmod", row["etag"], meta)
        return None   # evicted or deleted behind our back: encode again

    def put_variant(self, key, ctx, spec, fmt, file, nbytes, secs, beneficial, width=None, reason=None, etag=None):
        try:
            self.store.put_variant(key, mount=ctx.mid, path=ctx.rel, src_size=ctx.st.st_size,
                                   src_mtime=ctx.st.st_mtime, kind="img", fmt=fmt, spec=spec, file=file,
                                   bytes=int(nbytes or 0), src_bytes=ctx.st.st_size, secs=round(secs or 0.0, 4),
                                   beneficial=beneficial, width=width, reason=reason, etag=etag)
        except Exception as e:
            self.fail("store", e)

    def defer(self, ctx, params, why, **detail):
        """Serve the original now (short CDN TTL), build the variant in the background. A full job queue refuses
        new work instead of growing without bound (image.max_queue_depth)."""
        depth = int(imaging.image_conf(ctx.conf)["max_queue_depth"])
        if ctx.ver is None:    # the worker knows no stored versions
            if self.queued_images >= depth:
                self.metric("image_optimizer_queue_rejections_total")
                return self.bypass(ctx, "queue_full", "info", why=why, depth=self.queued_images)
            if self.enqueue("image", ctx.mid, ctx.rel, ctx.st, params, 30):
                self.queued_images += 1
        self.metric("image_optimizer_deferred_total", why=why)
        return self.bypass(ctx, "deferred", "info", why=why, **detail)

    def backoff(self, key):
        """Negative cache: (seconds left) while a recent failure of this variant forbids another sync attempt."""
        f = self.failures.get(key)
        if not f:
            return 0.0
        left = f[0] - time.monotonic()
        if left <= 0:
            return 0.0
        return left

    def record_failure(self, ctx, key, spec, kind, params):
        """A sync encode failed: no sync retry for 1 min, 10 min, 1 h ... (per process) and one background job
        whose own retries end in a permanent 'failed:<kind>' decision row (retried after image.tiers.failure_retry_h)."""
        n = (self.failures.get(key) or (0, 0))[1] + 1
        self.failures[key] = (time.monotonic() + (60, 600, 3600, 6 * 3600)[min(n, 4) - 1], n)
        if len(self.failures) > 20000:
            for k in list(self.failures)[:5000]:
                self.failures.pop(k, None)
        self.metric("image_optimizer_encode_failures_total", kind=kind, path="sync")
        if ctx.ver is None:
            self.enqueue("image", ctx.mid, ctx.rel, ctx.st, dict(params, spec=spec), 60)

    def source_dims(self, ctx):
        """(w, h, info|None) of the source; cached per (mount, path, size, mtime) so ?w= requests probe once."""
        k = (ctx.mid, ctx.rel, ctx.st.st_size, ctx.st.st_mtime)
        hit = self.dims.get(k)
        if hit is not None:
            self.dims.move_to_end(k)
            return hit[0], hit[1], None
        info = imaging.probe(ctx.full, ctx.conf)
        if info.get("w"):
            self.dims[k] = (info["w"], info["h"])
            if len(self.dims) > 50000:
                self.dims.popitem(last=False)
        return info.get("w"), info.get("h"), info

    def auto(self, ctx, want, width=None):
        """_v=avif|webp (optionally at a width rung): persistent / ephemeral hit, recorded decision, 304, or a miss
        that is encoded now (cheap enough), deferred to the worker (expensive, HEAD, overloaded) or bypassed."""
        if config.ext_of(ctx.rel) not in config.TRANSFORMABLE:
            return self.gate_check(ctx) or ("orig", "orig;reason=not_image", False)
        g = self.gate_check(ctx)
        if g:
            return g
        ic = imaging.image_conf(ctx.conf)
        if ctx.st.st_size > int(ic["max_source_bytes"]):
            self.metric("image_optimizer_skipped_total", reason="source_bytes")
            return ("orig", "orig;reason=too_large", False, {"cache": "decision", "source": "original"})
        info, target = None, None
        if width:
            try:
                sw, sh, info = self.source_dims(ctx)
            except imaging.ImagingError as e:
                return self.bypass(ctx, e.kind, error=str(e)[:200])
            except Exception as e:
                return self.bypass(ctx, "decode_error", error="%s: %s" % (e.__class__.__name__, str(e)[:200]))
            if sw and width < sw:
                target = width   # else the rung is not smaller than the source: same variant as full size
        spec = imaging.auto_spec(want, target, ctx.conf)
        key = self.cache.key(ctx.mid, ctx.rel, ctx.st.st_size, ctx.st.st_mtime, spec)
        ans = self.lookup(key, ctx)
        if ans:
            self.metric("image_optimizer_cache_hits_total", tier=(ans[-1] or {}).get("cache", "decision")
                        if isinstance(ans[-1], dict) else "decision")
            return ans
        self.metric("image_optimizer_cache_misses_total")
        params = {"want": want, "width": target, "spec": spec}
        if ctx.method == "HEAD" or ctx.conditional:
            # metadata-only / revalidation requests never pay for an encode on the request path
            return self.defer(ctx, params, "head" if ctx.method == "HEAD" else "conditional")
        left = self.backoff(key)
        if left:
            self.metric("image_optimizer_backoff_total")
            return self.bypass(ctx, "backoff", "info", retry_in=round(left))
        with self.flight(key, float(ic["sync_budget_s"]) * 2 + 1) as first:
            if not first:
                ans = self.lookup(key, ctx)
                return ans or self.bypass(ctx, "inflight", "info")
            return self._auto_miss(ctx, want, spec, key, ic, target, info, params)

    def sync_budget(self, ic, src_bytes):
        """Seconds a first request may spend encoding: image.sync_budget_s, raised up to sync_budget_max_s when
        sending the original through the uplink would take longer than the encode (then encoding is the faster
        answer for the client *and* saves the bandwidth)."""
        budget = float(ic["sync_budget_s"])
        cap = float(ic["sync_budget_max_s"] or budget)
        mbps = float((self._conf.get("capacity") or {}).get("uplink_mbps") or 0)
        if mbps > 0 and cap > budget:
            budget = max(budget, min(cap, 0.5 * src_bytes / (mbps * 1e6 / 8)))
        return budget

    def _auto_miss(self, ctx, want, spec, key, ic, target, info, params):
        c = ctx.conf
        try:
            info = info or imaging.probe(ctx.full, c)
        except imaging.ImagingError as e:
            self.record_failure(ctx, key, spec, e.kind, params)
            return self.bypass(ctx, e.kind, error=str(e)[:200])
        except Exception as e:
            self.record_failure(ctx, key, spec, "decode_error", params)
            return self.bypass(ctx, "decode_error", error="%s: %s" % (e.__class__.__name__, str(e)[:200]))
        plan = imaging.choose(info, want, c, target)
        if plan.fmt == "orig":   # deterministic: remember it, cache it long
            self.put_variant(key, ctx, spec, "orig", "", 0, 0.0, False, reason=plan.reason)
            self.metric("image_optimizer_skipped_total", reason=plan.reason)
            return ("orig", "orig;reason=%s" % plan.reason, False, {"cache": "decision", "source": "original"})
        out = plan.opts.get("resize")
        est = self.model.estimate(info, plan.fmt, imaging.speed_for(plan.fmt, c, True),
                                  out_mp=(out[0] * out[1] / 1e6) if out else None)
        mp, frames = float(info.get("mp") or 0), int(info.get("frames") or 1)
        budget = self.sync_budget(ic, ctx.st.st_size)
        why = ("mp" if mp > float(ic["sync_max_mp"]) or mp > float(ic["max_mp"]) else
               "bytes" if ctx.st.st_size > int(ic["sync_max_bytes"]) else
               "budget" if est > budget else
               "animated" if plan.animated and frames * mp > 8 else "")
        if why:
            return self.defer(ctx, params, why, est=round(est, 3), mp=mp)

        def run():
            return imaging.encode_auto(ctx.full, info, plan, c, sync=True, model=self.model, mem_avail_mb=self.mem())
        return self.encode(ctx, key, spec, est, run, check_benefit=not out, width=out[0] if out else None,
                           params=params)

    def _est_explicit(self, info, p, c):
        """Seconds for an explicit transform: NAS read + decode of the source + encode of the (smaller) output."""
        cm = imaging.CostModel
        mp = float(info.get("mp") or 0)
        w, h = info.get("w") or 1, info.get("h") or 1
        tw, th = p["w"], p["h"]
        if tw and th and p["fit"] in ("fill", "contain"):
            out = tw * th / 1e6
        elif tw or th:
            s = min(tw / w if tw else 1.0, th / h if th else 1.0, 1.0)
            out = mp * s * s
        else:
            out = mp
        fm = p["fm"] if p["fm"] != "auto" else {"JPEG": "jpeg", "MPO": "jpeg", "WEBP": "webp", "AVIF": "avif"}.get(
            (info.get("format") or "").upper(), "png")
        enc = fm if fm in ("avif", "webp") else "webp"   # jpeg/png: webp method 4 is a fair proxy
        speed = imaging.speed_for(enc, c, True)
        decode = cm.DECODE.get((info.get("format") or "").upper(), 0.03) * mp
        read = (info.get("bytes") or 0) / cm.NAS_BPS
        return round(cm.OVERHEAD_S + read + decode + self.model.rate(enc, speed) * max(out, cm.MIN_MP), 4), fm, out

    def explicit(self, ctx):
        """?w ?h ?fit ?fm ?q with transform.py's exact semantics, now cached, cost-checked and breaker-admitted."""
        c = ctx.conf
        if config.ext_of(ctx.rel) not in config.TRANSFORMABLE:
            return ("text", 415, "image modifiers only apply to images")
        try:
            p = imaging.validate_explicit(ctx.q, c)
        except ValueError as e:
            return ("text", 400, str(e))
        if ctx.st.st_size > MAX_TF_BYTES:
            return ("text", 413, "image too large to transform")
        if ctx.ver is None:
            g = self.gate_check(ctx)
            if g:
                return g
        spec = spec_tf(p, ctx.ver)
        key = self.cache.key(ctx.mid, ctx.rel, ctx.st.st_size, ctx.st.st_mtime, spec)
        ans = self.lookup(key)
        if ans:
            return ans
        ic = imaging.image_conf(c)
        with self.flight(key, float(ic["sync_budget_s"]) * 2 + 1) as first:
            if not first:
                ans = self.lookup(key)
                if ans:
                    return ans
            try:
                info = imaging.probe(ctx.src, c)
            except imaging.ImagingError as e:
                return self.bypass(ctx, e.kind, error=str(e)[:200])
            except Exception as e:
                return self.bypass(ctx, "decode_error", error="%s: %s" % (e.__class__.__name__, str(e)[:200]))
            if info.get("too_large"):
                return self.bypass(ctx, "too_large", mp=info.get("mp"))
            est, fm, out_mp = self._est_explicit(info, p, c)
            mp = float(info.get("mp") or 0)
            why = ("mp" if mp > float(ic["sync_max_mp"]) or mp > float(ic["max_mp"]) else
                   "budget" if est > float(ic["sync_budget_s"]) else "")
            if why:
                return self.defer(ctx, {"tf": p}, why, est=est, mp=mp)

            def run():
                data, fmt = imaging.encode_explicit(ctx.src, ctx.q, c)
                if fmt in ("avif", "webp"):
                    t = imaging.last_timing()
                    self.model.observe(fmt, imaging.speed_for(fmt, c, True), out_mp, t.get("encode_s"))
                return data, fmt
            return self.encode(ctx, key, spec, est, run, check_benefit=False)

    def family(self, ctx, width):
        """?w= without a negotiated format (edge mode for clients without AVIF/WebP, _v=orig): resize to the rung in
        the source's own format family, so every client can decode it. Same tiers and single-flight as auto()."""
        g = self.gate_check(ctx)
        if g:
            return g
        ic = imaging.image_conf(ctx.conf)
        if ctx.st.st_size > int(ic["max_source_bytes"]):
            return ("orig", "orig;reason=too_large", False, {"cache": "decision", "source": "original"})
        try:
            sw, sh, info = self.source_dims(ctx)
        except imaging.ImagingError as e:
            return self.bypass(ctx, e.kind, error=str(e)[:200])
        except Exception as e:
            return self.bypass(ctx, "decode_error", error="%s: %s" % (e.__class__.__name__, str(e)[:200]))
        if not sw or width >= sw:   # never upscale: the rung covers the whole source -> the original itself
            return ("orig", "orig;reason=width_covers_source", False, {"cache": "decision", "source": "original"})
        spec = "fam:w=%d:%s:v2" % (width, imaging.profile_token(ctx.conf))
        key = self.cache.key(ctx.mid, ctx.rel, ctx.st.st_size, ctx.st.st_mtime, spec)
        ans = self.lookup(key, ctx)
        if ans:
            return ans
        params = {"family": True, "width": width, "spec": spec}
        if ctx.method == "HEAD" or ctx.conditional:
            return self.defer(ctx, params, "head" if ctx.method == "HEAD" else "conditional")
        if self.backoff(key):
            return self.bypass(ctx, "backoff", "info")
        with self.flight(key, float(ic["sync_budget_s"]) * 2 + 1) as first:
            if not first:
                return self.lookup(key, ctx) or self.bypass(ctx, "inflight", "info")
            info = info or imaging.probe(ctx.full, ctx.conf)
            if int(info.get("frames") or 1) > 1:   # a resized single frame would silently drop the animation
                self.put_variant(key, ctx, spec, "orig", "", 0, 0.0, False, reason="animated")
                return ("orig", "orig;reason=animated", False, {"cache": "decision", "source": "original"})
            tw, th = imaging.target_size(sw, sh, width)
            est = self._est_explicit(info, {"w": tw, "h": None, "fit": "inside",
                                            "fm": imaging.family_format(info)}, ctx.conf)[0]
            if float(info.get("mp") or 0) > float(ic["sync_max_mp"]) or est > self.sync_budget(ic, ctx.st.st_size):
                return self.defer(ctx, params, "budget", est=est)

            def run():
                return imaging.encode_family(ctx.full, info, width, ctx.conf)
            return self.encode(ctx, key, spec, est, run, check_benefit=False, width=tw, params=params)

    def encode(self, ctx, key, spec, est, fn, check_benefit, width=None, params=None):
        """Breaker-admitted encode at below-normal thread priority -> cache file + variant row -> accel.
        The file gets the source's mtime, so Caddy's ETag for it is stable and recorded in the row."""
        err = out = None
        try:
            with self.breaker.admit(est) as t:
                try:
                    with breaker.below_normal_thread():
                        out = fn()
                except imaging.ImagingError as e:
                    err = e
                    t.ok = not isinstance(e, imaging.EncodeError)   # a corrupt source is not the machine's fault
                except Exception as e:                               # MemoryError, NAS read errors, Pillow internals
                    err = e
                    t.ok = False
        except breaker.Bypass as b:
            return self.bypass(ctx, b.kind, detail=b.detail)
        if t.slow:
            self.count("encode.slow")
            self.events.emit("encode.slow", "warning", ctx.mid, ctx.rel, secs=round(t.secs, 3), est=round(est, 3),
                             spec=spec)
        if err is not None:
            kind = getattr(err, "kind", None) or "encode_error"
            if params is not None:
                self.record_failure(ctx, key, spec, kind, params)
            return self.bypass(ctx, kind, error="%s: %s" % (err.__class__.__name__, str(err)[:200]))
        data, fmt = out
        self.count("encode.ok")
        self.failures.pop(key, None)
        self.observe_encode(fmt, t.secs)
        if check_benefit and not imaging.beneficial(ctx.st.st_size, len(data), ctx.conf):
            self.put_variant(key, ctx, spec, fmt, "", len(data), t.secs, False, width=width, reason="not_beneficial")
            self.metric("image_optimizer_skipped_total", reason="not_beneficial")
            return ("orig", "orig;reason=not_beneficial", False, {"cache": "decision", "source": "original"})
        ext = EXT_OUT.get(fmt, fmt)
        try:
            rel_url = self.cache.write_bytes(key, ext, "img", data, mtime=ctx.st.st_mtime)
        except (OSError, ValueError) as e:
            self.fail("cache", e)
            return self.bypass(ctx, "cache_error", error="%s: %s" % (e.__class__.__name__, str(e)[:200]))
        etag = self.cache.etag_for(rel_url)
        self.put_variant(key, ctx, spec, fmt, rel_url, len(data), t.secs, True, width=width, etag=etag)
        self.cache.maybe_evict()
        return ("accel", rel_url, ext, "miss", {"key": key, "tier": "ephemeral", "cache": "live", "width": width,
                                                 "fmt": fmt, "bytes": len(data), "src_bytes": ctx.st.st_size,
                                                 "etag": etag})

    def video_variant(self, ctx, fmt, explicit):
        """_v=webm|mp4 / fm=webm: a ready, beneficial variant -> accel; otherwise queue it (only the configured
        video.format is ever built) and 302 ?_v=orig - never the original's bytes under the variant URL: a playback
        spanning the variant's arrival would mix two files' byte ranges."""
        ext = config.ext_of(ctx.rel)
        if ext not in config.VIDEO_EXT:
            if explicit and ext != "webm":
                return ("text", 400, "fm must be webp, avif, jpeg or png")
            g = self.gate_check(ctx)
            if g:
                return g
            return ("orig", "orig;reason=" + fmt, False) if ext == fmt else ("redirect", "orig", False)
        g = self.gate_check(ctx)
        if g:
            return g
        key = self.cache.key(ctx.mid, ctx.rel, ctx.st.st_size, ctx.st.st_mtime, spec_video(fmt))
        try:
            row = self.store.variant(key)
        except Exception as e:
            self.fail("store", e)
            row = None
        if row and not row.get("beneficial"):
            return ("redirect", "orig", False)       # decided: the original stays the only copy
        if row and row.get("file") and self.cache.exists(row["file"]):
            self.cache.touch(key)
            return ("accel", row["file"], fmt, "hit")
        vc = video.video_conf(ctx.conf)
        if vc["enabled"] and fmt == vc["format"]:
            self.enqueue("video", ctx.mid, ctx.rel, ctx.st, {"want": fmt}, 40)
        return ("redirect", "orig", False)

    # ------------------------------------------------------------ /_stats
    def stats(self):
        c = self.conf()
        with self.stat_lock:
            counters = dict(self.counters)
        ln = c.get("lane") or {}
        return {"service": "strata-media", "version": VERSION, "pid": os.getpid(), "started": self.started,
                "uptime": round(time.time() - self.started, 1), "listen": c.get("listen"),
                "enabled": bool(c.get("enabled")), "negotiation": c.get("negotiation"), "cutover": self.cutover(c),
                "breaker": self.breaker.status(), "monitor": self.monitor.snapshot(), "counters": counters,
                "cache": self.cache_usage,
                "gate": {"verdicts": len(self.verdicts), "refreshed": self.v_at, "full_reload": self.v_full_ts,
                         "queue": self.jobs.qsize(), "inflight": len(self.inflight)},
                "lane": {"active": self.lane_active, "total_mbps": ln.get("total_mbps"),
                         "per_conn_mbps": ln.get("per_conn_mbps")},
                "cost_model": self.model.to_dict(),
                "optimizer": self.optimizer_stats(),
                "events": {"counts": self.events.counts(), "recent": self.events.recent(20),
                           "log": self.events.stats()},
                "errors": list(self.errors)}


# ---------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = "StrataMedia"
    sys_version = ""
    protocol_version = "HTTP/1.1"   # keep-alive with Caddy; every answer has an exact Content-Length
    timeout = 300

    def log_message(self, *a):
        pass

    @property
    def svc(self):
        return self.server.svc

    def end_headers(self):
        self._sent = True
        super().end_headers()

    # ------------------------------------------------------------ answer primitives
    def _empty(self, code, headers=()):
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def text(self, code, msg, extra=()):
        body = msg.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_json(self, code, obj):
        body = json.dumps(obj, default=str, separators=(",", ":")).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def held(self):
        self.text(403, HELD_MSG)

    def pending(self, c):
        try:
            ra = int((c.get("gate") or {}).get("pending_retry_after") or 30)
        except (TypeError, ValueError):
            ra = 30
        self.text(503, PENDING_MSG, [("Retry-After", str(max(1, ra)))])

    def debug(self, ctx, ans):
        """X-CDN-Image-* (image.debug_headers): what was served and from where - format, cache tier, source, width.
        Never paths, keys, queue details or anything from the file's metadata."""
        if not (ctx.conf.get("image") or {}).get("debug_headers", True):
            return []
        meta = ans[-1] if isinstance(ans[-1], dict) else {}
        if ans[0] == "accel":
            fmt, src, w = meta.get("fmt") or ans[2], "variant", meta.get("width") or "full"
            cache = meta.get("cache") or meta.get("tier") or "ephemeral"
        elif ans[0] == "notmod":
            fmt, src, w, cache = meta.get("fmt") or "", "variant", meta.get("width") or "full", "validator"
        else:
            fmt, src, w = config.ext_of(ctx.rel) or "original", "original", "full"
            cache = meta.get("cache") or ("deferred" if "deferred" in ans[1] else
                                          "bypass" if ans[1].startswith("bypass") else "original")
        return [("X-CDN-Image-Format", "jpeg" if fmt == "jpg" else fmt), ("X-CDN-Image-Cache", cache),
                ("X-CDN-Image-Source", src), ("X-CDN-Image-Width", str(w))]

    def render(self, ctx, ans):
        """accel / orig (empty 200s for Caddy's handle_response), 304, redirect, held, pending or a text error."""
        kind = ans[0]
        # ?_wait=1 (the gallery's thumbnails): load shedding answers 503 instead of the original, so a folder of
        # 640 px tiles never turns into the whole library at source size; the page retries, the variant gets built
        if kind == "orig" and ctx.q.get("_wait") and ans[1] in WAIT_KINDS:
            self.svc.count("answer.wait")
            return self.text(503, "variant not ready, try again shortly", [("Retry-After", "3")])
        self.svc.count("answer." + (kind if kind != "text" else str(ans[1])))
        if kind in ("accel", "orig", "notmod", "redirect"):
            try:
                self.svc.account(ctx, ans)
            except Exception as e:
                self.svc.fail("account", e)
        vary = [("X-Strata-Vary", "Accept")] if ctx.negotiated else []
        if kind == "accel":
            rel_url, ext, media = ans[1], ans[2], ans[3]
            b, e = ctx.cc()
            return self._empty(200, [("X-Strata-Accel", rel_url), ("X-Strata-Cache-Control", b),
                                     ("X-Strata-CDN-Cache-Control", e),
                                     ("X-Strata-Disposition", disposition(ctx.rel, ext)),
                                     ("X-Strata-Media", media), ("Cache-Control", "no-store")]
                               + vary + self.debug(ctx, ans))
        if kind == "orig":
            media, short = ans[1], ans[2]
            if ctx.ver is not None:   # a stored version has no "original" Caddy could serve: stream it
                return self.stream_file(ctx.src, ctx.st, ctx, short)
            b, e = ctx.cc(short)
            return self._empty(200, [("X-Strata-Orig", "1"), ("X-Strata-Cache-Control", b),
                                     ("X-Strata-CDN-Cache-Control", e), ("X-Strata-Media", media),
                                     ("Cache-Control", "no-store")] + vary + self.debug(ctx, ans))
        if kind == "notmod":   # the client's copy is this variant: say so without re-encoding an evicted file
            b, e = ctx.cc()
            hdrs = [("ETag", ans[1]), ("Cache-Control", b), ("X-Strata-Media", "notmod")]
            if ctx.edge:
                hdrs.append(("Cloudflare-CDN-Cache-Control", e))
            if ctx.negotiated:
                hdrs.append(("Vary", "Accept"))
            return self._empty(304, hdrs + self.debug(ctx, ans))
        if kind == "redirect":
            v, vary = ans[1], ans[2]
            query = ans[3] if len(ans) > 3 else None
            hdrs = [("Location", location(ctx.mount, ctx.rel, v, query)), ("Cache-Control", "private, no-store")]
            return self._empty(302, hdrs + ([("Vary", "Accept")] if vary else []))
        if kind == "held":
            return self.held()
        if kind == "pending":
            return self.pending(ctx.conf)
        return self.text(ans[1], ans[2])

    # ------------------------------------------------------------ dispatch
    def do_GET(self):
        self._dispatch(False)

    do_HEAD = do_GET

    def do_POST(self):
        self._dispatch(True)

    def _refuse(self):
        self._sent = False
        self.close_connection = True   # a body we did not read must not be parsed as the next request
        try:
            self.text(405, "method not allowed")
        except OSError:
            pass

    do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_TRACE = do_CONNECT = _refuse

    def _dispatch(self, post):
        self._sent = False
        svc = self.svc
        try:
            if not is_loopback(self.client_address[0]):
                self.close_connection = True
                return self.text(403, "forbidden")
            svc.count("requests")
            path, query = split_target(self.path)
            if post:
                if path == "/_admin/breaker":
                    return self.admin_breaker()
                self.close_connection = True
                return self.text(405, "method not allowed")
            if path == "/_stats":
                return self.send_json(200, svc.stats())
            if path == "/_metrics":
                body = svc.prometheus().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)
                return None
            if path == "/_scan":
                return self.scan()
            if path == "/_gate":
                return self.gate()
            if path.startswith("/_admin/"):
                return self.text(405, "method not allowed")
            return self.media(path, query)
        except (ConnectionError, TimeoutError):
            self.close_connection = True       # client (Caddy) went away: nothing to answer
        except Exception as e:
            self.close_connection = True
            svc.fail("request", e, tb=True)
            if not self._sent:
                try:
                    self.text(500, "internal error")
                except OSError:
                    pass

    def _stat(self, full):
        """os.stat -> st, or answers 404 (missing / not a file) / 502 (storage error) and returns None."""
        try:
            st = os.stat(full)
        except (FileNotFoundError, NotADirectoryError):
            self.text(404, "not found")
            return None
        except OSError as e:
            self.svc.fail("nas", e)
            self.text(502, "storage unavailable")
            return None
        if not stat.S_ISREG(st.st_mode):
            self.text(404, "not found")
            return None
        return st

    def media(self, path, query):
        svc = self.svc
        c = svc.conf()
        hdr = (self.headers.get("X-Strata-Mount") or "").strip()
        m = config.mount(c, hdr) if MOUNT_RE.fullmatch(hdr) else None
        if m is None:
            return self.text(404, "not found")
        full, rel = config.resolve(m, path)
        if not full:
            return self.text(404, "not found")
        q = {k: v[-1] for k, v in urllib.parse.parse_qs(query, keep_blank_values=True).items()}
        inm = self.headers.get("If-None-Match") or ""
        ctx = Ctx(c, int(hdr), m, rel, full, q, self.headers.get("X-Strata-Cache"),
                  self.headers.get("X-Strata-Edge-Cache"), method=self.command, inm=inm,
                  conditional=bool(inm or self.headers.get("If-Modified-Since")),
                  bypass=bypass_reason(q, self.headers))
        if self.headers.get("X-Strata-Throttle") == "1":
            ctx.st = self._stat(full)
            return None if ctx.st is None else self.lane(ctx)
        if q.get("ver"):
            return self.version(ctx)
        ctx.st = self._stat(full)
        if ctx.st is None:
            return None
        # redirect-mode negotiation: Caddy only sends query-less (or ?w= only + unrelated parameters) images, and
        # query-less videos requested by a <video> player, here
        if self.headers.get("X-Strata-Negotiate") == "1" and not any(q.get(k) for k in ("_v",) + TF_KEYS[1:]):
            return self.render(ctx, svc.negotiate(ctx, self.headers.get("Accept")))
        return self.render(ctx, svc.variant(ctx))

    # ------------------------------------------------------------ /_scan (forward_auth)
    def scan(self):
        svc = self.svc
        c = svc.conf()
        hdr = (self.headers.get("X-Strata-Mount") or "").strip()
        m = config.mount(c, hdr) if MOUNT_RE.fullmatch(hdr) else None
        uri = self.headers.get("X-Forwarded-Uri")
        if m is None or not uri:
            return self.text(403, "forbidden")   # fail closed: the gate never says yes to what it cannot check
        path, _ = split_target(uri)
        full, rel = config.resolve(m, path)
        if not full:   # dot segments, ADS, device names ...: file_server must not serve what we cannot gate
            svc.count("gate.refused")
            return self.text(403, "forbidden")
        try:
            st = os.stat(full)
        except (FileNotFoundError, NotADirectoryError):
            return self._empty(200)              # file_server produces the normal 404 page
        except OSError as e:
            svc.fail("nas", e)
            return self.text(502, "storage unavailable")
        if not stat.S_ISREG(st.st_mode):
            return self._empty(200)
        action, _, lane = svc.decide(c, int(hdr), rel, full, st)
        svc.count("gate." + action)
        if action == "held":
            return self.held()
        if action == "pending":
            return self.pending(c)
        return self._empty(200, [("X-Strata-Lane", "throttle")] if lane else [])

    # ------------------------------------------------------------ /_gate (signed links, transform.py semantics)
    def gate(self):
        c = self.svc.conf()
        path, query = split_target(self.headers.get("X-Forwarded-Uri") or "")
        q = {k: v[-1] for k, v in urllib.parse.parse_qs(query).items()}
        try:
            exp = int(q.get("exp", "0"))
        except ValueError:
            exp = 0
        sig, secret = q.get("sig", ""), c.get("sign_secret") or ""
        if not secret or not sig or exp < time.time():
            return self.text(403, "This link has expired or is not valid." if sig else "A signed link is required.")
        if not hmac.compare_digest(sign(secret, path, exp), sig):
            return self.text(403, "This link is not valid.")
        return self._empty(200)

    # ------------------------------------------------------------ POST /_admin/breaker
    def admin_breaker(self):
        svc = self.svc
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if n < 0 or n > MAX_BODY:
            self.close_connection = True
            return self.text(413 if n > MAX_BODY else 400, "bad request body")
        body = self.rfile.read(n) if n else b""
        want = str(svc.conf().get("admin_token") or "")
        got = self.headers.get("X-Strata-Admin-Token") or ""
        if not want or not hmac.compare_digest(got.encode("utf-8", "replace"), want.encode("utf-8")):
            return self.text(403, "forbidden")
        try:
            d = json.loads(body.decode("utf-8") or "{}")
            state = d.get("state")
            seconds = d.get("seconds")
            seconds = float(seconds) if seconds not in (None, "", 0) else None
            if seconds is not None and not 0 < seconds <= 7 * 86400:
                raise ValueError("seconds must be 0-604800")
            svc.breaker.force(state, seconds)
        except (ValueError, TypeError, AttributeError, UnicodeDecodeError) as e:
            return self.text(400, "bad request: %s" % e)
        svc.events.emit("breaker.admin", "info", state=state, seconds=seconds)
        try:
            svc.publish_breaker()   # the worker pauses on meta.breaker: tell it now, not in 2 s
        except Exception as e:
            svc.fail("breaker", e)
        return self.send_json(200, {"ok": True, "breaker": svc.breaker.status()})

    # ------------------------------------------------------------ streaming: ?ver= and the lane
    def version(self, ctx):
        n = ctx.q["ver"]
        if not re.fullmatch(r"\d{1,6}", n):
            return self.text(400, "ver must be a number")
        src = version_file(ctx.mount, ctx.rel, int(n))
        st = self._stat(src)
        if st is None:
            return None
        ctx.ver, ctx.src, ctx.st = int(n), src, st
        if any(ctx.q.get(k) for k in TF_KEYS):
            return self.render(ctx, self.svc.explicit(ctx))
        return self.stream_file(src, st, ctx, False)

    def stream_file(self, src, st, ctx, short, throttle=None):
        b, e = ctx.cc(short)
        headers = [("Cache-Control", b)] + ([("Cloudflare-CDN-Cache-Control", e)] if ctx.edge else [])
        ctype = mimetypes.guess_type(ctx.full)[0] or "application/octet-stream"
        return self.stream(src, st, ctype, headers, throttle)

    def lane(self, ctx):
        """Large-file lane (DESIGN 4.3): lane total + per-connection token buckets, Range supported."""
        svc = self.svc
        per = Bucket((ctx.conf.get("lane") or {}).get("per_conn_mbps", 10), LANE_CHUNK * 2)
        glob = svc.lane_total

        def throttle(n):
            w = max(per.take(n), glob.take(n))
            if w > 0:
                time.sleep(w)
        with svc.stat_lock:
            svc.lane_active += 1
        try:
            svc.count("lane.requests")
            return self.stream_file(ctx.full, ctx.st, ctx, False, throttle)
        finally:
            with svc.stat_lock:
                svc.lane_active -= 1

    def stream(self, path, st, ctype, headers, throttle=None):
        """transform.py's Range streaming (single range, 416, If-Range) with an optional throttle."""
        size = st.st_size
        start, end, code = 0, max(0, size - 1), 200
        last_mod = self.date_time_string(st.st_mtime)
        etag = '"%x-%x"' % (int(st.st_mtime * 1e6), size)
        rng = (self.headers.get("Range") or "").strip()
        if_range = (self.headers.get("If-Range") or "").strip()
        if if_range and if_range not in (last_mod, etag):
            rng = ""
        m = RANGE_RE.fullmatch(rng)
        if m and size and (m.group(1) or m.group(2)):
            if m.group(1):
                start = int(m.group(1))
                end = min(int(m.group(2)), size - 1) if m.group(2) else size - 1
            else:
                start = max(0, size - int(m.group(2)))
            if start > end or start >= size:
                return self._empty(416, [("Content-Range", "bytes */%d" % size), ("Cache-Control", "no-store")])
            code = 206
        try:
            f = open(path, "rb")
        except FileNotFoundError:
            return self.text(404, "not found")
        except OSError as e:
            self.svc.fail("nas", e)
            return self.text(502, "storage unavailable")
        with f:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(end - start + 1 if size else 0))
            self.send_header("Accept-Ranges", "bytes")
            for k, v in headers:
                self.send_header(k, v)
            self.send_header("Last-Modified", last_mod)
            self.send_header("ETag", etag)
            if code == 206:
                self.send_header("Content-Range", "bytes %d-%d/%d" % (start, end, size))
            self.end_headers()
            if self.command == "HEAD" or not size:
                return None
            f.seek(start)
            left, chunk = end - start + 1, LANE_CHUNK if throttle else STREAM_CHUNK
            while left > 0:
                try:
                    buf = f.read(min(left, chunk))
                except OSError as e:
                    self.svc.fail("nas", e)
                    buf = b""
                if not buf:   # storage error or the file shrank: the client got less than promised
                    self.close_connection = True
                    return None
                if throttle:
                    throttle(len(buf))
                try:
                    self.wfile.write(buf)
                except OSError:
                    self.close_connection = True
                    return None
                left -= len(buf)
        return None


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64
    allow_reuse_address = False   # single instance: on Windows SO_REUSEADDR would let a second copy bind too
    allow_reuse_port = False
    svc = None

    def server_bind(self):
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            except OSError:
                pass
        super().server_bind()

    def handle_error(self, request, client_address):
        e = sys.exc_info()[1]
        if isinstance(e, (ConnectionError, TimeoutError)):
            return
        log("unhandled %s from %s: %s" % (e.__class__.__name__, client_address, e))


def parse_listen(listen):
    host, _, port = str(listen).rpartition(":")
    return host.strip("[]") or "127.0.0.1", int(port)


def make_server(listen, svc):
    host, port = parse_listen(listen)
    cls = Server
    if ":" in host:
        cls = type("Server6", (Server,), {"address_family": socket.AF_INET6})
    srv = cls((host, port), Handler)
    srv.svc = svc
    return srv


def main(argv=None):
    ap = argparse.ArgumentParser(description="Strata Media hot path (media/DESIGN.md)")
    ap.add_argument("--config", help="media.json (default: %s)" % config.CONF_PATH)
    ap.add_argument("--listen", help="host:port (default: the config's listen)")
    args = ap.parse_args(argv)
    path = args.config or config.CONF_PATH
    c = config.load(path)
    if not c.get("enabled"):
        log("media.enabled is off in %s - not starting" % path)
        return 0
    listen = args.listen or c.get("listen") or "127.0.0.1:8084"
    try:
        srv = make_server(listen, None)   # bind first: a second instance exits before touching anything
    except (OSError, ValueError) as e:
        log("cannot listen on %s: %s (another instance running?)" % (listen, e))
        return 2
    svc = Service(path)
    srv.svc = svc
    svc.start()
    log("strata media %s on http://%s (pid %d)" % (VERSION, listen, os.getpid()))
    try:
        srv.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        svc.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
