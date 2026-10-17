"""Strata Media bridge - the part of the media pipeline that runs inside strata.py (media/DESIGN.md 2, 9, 13).

media.py and worker.py hold neither strata.db nor the Cloudflare token (least privilege), so everything that needs
one of them lives here, in one daemon thread with independent timers:
    10 s   Supervisor.ensure(): start, health-check and restart media.py / worker.py (DESIGN 2)
     5 s   verdict watcher: newly flagged | held | error -> Cloudflare purge + "Held for review" alert
     2 min discovery: fidx vs verdicts -> scan jobs; files gone from index and disk -> verdict + variants dropped;
           prewarm (new images 70, popular images 85)
    60 s   events watcher: tool.missing, supervisor.restart, job.failed bursts -> alerts
     5 min capacity advisor (13.1) -> strata.db meta media_capacity + alerts (coalesced 24 h)
     6 h   negotiation (also at start and after a settings change): edge rules via media_edge, effective mode in
           strata.db meta media_negotiation_effective, rules.APPLY_SOON on change
plus the admin API of 13.2 (api_get / api_post) and the hooks strata.py calls (on_upload, on_rename).

Rule (DESIGN 13): never call rules.ALERT_HOOK - or anything that opens a strata.db connection - while a strata.db
transaction is open; alerts.raise_ opens its own connection and would deadlock into "database is locked". Every step
collects its alerts, commits and closes, then raises them (_raise_all refuses while a transaction is open).
With media.enabled off, start() does nothing and media.db is never opened; status and the policy preview still answer.
"""
import collections
import contextlib
import http.client
import importlib
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse

import core

MEDIA_DIR = os.path.join(core.ROOT, "media")
if MEDIA_DIR not in sys.path:
    sys.path.insert(0, MEDIA_DIR)  # media/*.py import each other as plain modules (store, config, cache, sandbox)

VERSION = "1"
NEG_META, CAP_META, CURSOR_META = "media_negotiation_effective", "media_capacity", "media_verdict_cursor"
BAD_STATES = ("flagged", "held", "error")
VERDICT_STATES = ("pending", "clean", "flagged", "held", "released", "error", "skipped")
JOB_KINDS = ("scan", "image", "video")
JOB_STATES = ("queued", "running", "done", "failed", "cancelled")
NEG_MODES = ("auto", "edge", "redirect", "off")
SEVERITIES = ("low", "medium", "high")
PRIO = {"upload": 20, "new": 60, "prewarm_upload": 70, "legacy": 80, "popular": 85}
PREWARM_PARAMS = {"want": "avif"}          # image job params (worker.py reads "want")
EVERY = {"supervise": 10, "verdicts": 5, "discovery": 120, "events": 60, "capacity": 300,
         "negotiation": 6 * 3600, "prune": 86400}
NEG_RETRY_S = 600                          # transient Cloudflare trouble: try again in 10 min, not 6 h
MAX_ENQUEUE = 5000                         # discovery: scan jobs queued per pass (the rest come next pass)
MAX_PREWARM = 1000
MAX_ALERTS = 20                            # "Held for review" alerts per watcher tick; the rest are summarised
JOB_FAILED_PER_H = 10
CAPACITY_COALESCE_MIN = 24 * 60
BACKOFF = (10, 30, 60, 120, 300)           # supervisor restart delays (s), max 5 min
HEALTHY_RESET_S = 600                      # a child healthy this long starts from the shortest backoff again
WORKER_HEARTBEAT_S = 30
CAPACITY = {"uplink_mbps": 50, "cpu_p95": 85, "mem_p95": 90, "backlog_hours": 6, "open_ratio": 0.10,
            "cache_free_pct": 10}

NOWIN = getattr(subprocess, "CREATE_NO_WINDOW", 0)
BELOW_NORMAL = getattr(subprocess, "BELOW_NORMAL_PRIORITY_CLASS", 0)

BRIDGE = None
_bridge_lock = threading.Lock()
_log_last = {}


def log(msg, key=None, every=600):
    """core.log, at most once per `every` seconds per key (a failing timer must not flood run.out)."""
    if key is not None:
        now = time.time()
        if now - _log_last.get(key, 0) < every:
            return
        _log_last[key] = now
    core.log("media: " + msg)


def _mod(name):
    """Lazily imported module (strata's rules / cloudflare / files / media_rules / media_edge, or a media/ module):
    a broken pipeline module can never keep Strata from starting."""
    return importlib.import_module(name)


def _file_error_base():
    try:
        return _mod("files").FileError        # strata.fail() answers these with their own status code
    except Exception:
        class _Base(Exception):
            def __init__(self, code, msg):
                super().__init__(msg)
                self.code = code
        return _Base


class MediaError(_file_error_base()):
    """An API refusal with an HTTP status (409 pipeline disabled, 404 unknown file, 503 media down ...)."""


def conf():
    return core.CFG.get("media") or {}


def enabled():
    return bool(conf().get("enabled"))


def db_path(c=None):
    p = (c or conf()).get("db") or "data/media.db"
    return p if os.path.isabs(p) else os.path.join(core.HOME, p)


def _hostport(listen):
    host, _, port = (listen or "127.0.0.1:8084").rpartition(":")
    return host.strip("[]") or "127.0.0.1", int(port)


def http_json(listen, method, path, body=None, headers=None, timeout=2.0):
    """(status, parsed JSON or text) from a loopback service (media.py); raises OSError on connect / timeout."""
    host, port = _hostport(listen)
    c = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        data = json.dumps(body).encode() if body is not None else None
        h = dict(headers or {})
        if data is not None:
            h["Content-Type"] = "application/json"
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        raw = r.read(1 << 20)
        try:
            return r.status, json.loads(raw or b"{}")
        except ValueError:
            return r.status, raw.decode("utf-8", "replace")[:500]
    finally:
        c.close()


def p95(vals):
    v = sorted(x for x in vals if x is not None)
    return v[min(len(v) - 1, int(round(0.95 * (len(v) - 1))))] if v else None


def _num(d, key):
    """A sample value: top level or inside the "breaker" section (media.py's per-minute sample layout)."""
    if not isinstance(d, dict):
        return 0
    v = d.get(key)
    if v is None and isinstance(d.get("breaker"), dict):
        v = d["breaker"].get(key)
    return v if isinstance(v, (int, float)) else 0


def _same_mtime(a, b):
    return a is not None and b is not None and abs(float(a) - float(b)) < 1e-3


def _fmt_age(s):
    return "%.1f h" % (s / 3600) if s >= 3600 else "%d min" % (s // 60)


# ---------------------------------------------------------------- capacity advisor (13.1), pure

def advise(inputs, cap=None, ncpu=None):
    """Advice rows {resource, level: watch|upgrade, evidence, recommendation} from measured inputs:
    cpu_p95 / mem_p95 (host %, 1 h), tx_p95_mbps (tunnel, 1 h), open_ratio (breaker open share, 1 h), trips_24h,
    mem_bypass_1h (bypass.breaker_open with detail mem), oldest_job_s, oldest_scan_s, queued_scans, disk_free,
    disk_total. Missing inputs (None) never produce advice."""
    c = dict(CAPACITY, **(cap or {}))
    i = inputs or {}
    n = int(ncpu or core.NCPU or 6)
    out = []

    def row(resource, level, evidence, rec):
        out.append({"resource": resource, "level": level, "evidence": ", ".join(evidence), "recommendation": rec})

    cpu, opr, oldest = i.get("cpu_p95"), i.get("open_ratio"), i.get("oldest_job_s")
    trips = i.get("trips_24h") or 0
    if cpu is not None and cpu > c["cpu_p95"]:
        ev = ["host_cpu p95 %.0f %% (1 h)" % cpu]
        if opr is not None and opr > c["open_ratio"]:
            ev.append("breaker open %.0f %% (1 h)" % (opr * 100))
        if oldest is not None and oldest > 7200:
            ev.append("oldest queued job %s" % _fmt_age(oldest))
        if len(ev) > 1:
            row("cpu", "upgrade", ev, "add 2 vCPU (%d -> %d)" % (n, n + 2))
    if not any(r["resource"] == "cpu" for r in out) and trips > 20:
        row("cpu", "watch", ["breaker tripped %d times in 24 h" % trips],
            "watch CPU: encodes are bypassed often; add 2 vCPU if it keeps happening")
    mem, mb = i.get("mem_p95"), i.get("mem_bypass_1h") or 0
    if (mem is not None and mem > c["mem_p95"]) or mb > 0:
        ev = (["host_mem p95 %.0f %% (1 h)" % mem] if mem is not None else []) + (
            ["%d memory bypasses (1 h)" % mb] if mb else [])
        row("memory", "upgrade", ev, "add 4 GB RAM")
    scan_age, queued = i.get("oldest_scan_s"), i.get("queued_scans") or 0
    if (scan_age is not None and scan_age > c["backlog_hours"] * 3600) or queued > 500:
        ev = (["oldest queued scan %s" % _fmt_age(scan_age)] if scan_age is not None else []) + (
            ["%d scans queued" % queued] if queued else [])
        row("backlog", "watch", ev, "background pipeline behind (scans)")
    tx = i.get("tx_p95_mbps")
    if tx is not None and tx > 0.8 * c["uplink_mbps"]:
        row("uplink", "upgrade", ["tunnel tx p95 %.1f of %s Mbps (1 h)" % (tx, c["uplink_mbps"])],
            "uplink saturated: turn on Smart Tiered Cache, give the token Cache Purge, keep the large-file lane on")
    free, total = i.get("disk_free"), i.get("disk_total")
    if free is not None and total:
        pct = free * 100.0 / total
        if pct < c["cache_free_pct"]:
            row("disk", "upgrade", ["cache disk %.1f %% free (%.1f GB)" % (pct, free / 1e9)],
                "cache disk: free space or move cache_root to a larger disk")
    return out


# ---------------------------------------------------------------- supervisor (DESIGN 2)

def media_health(listen, timeout=2.0):
    """media.py is healthy when GET /_stats answers 200 within 2 s. -> (ok, stats dict or error text)."""
    try:
        status, body = http_json(listen, "GET", "/_stats", timeout=timeout)
    except (OSError, http.client.HTTPException) as e:
        return False, "%s: %s" % (e.__class__.__name__, e)
    return (True, body if isinstance(body, dict) else {}) if status == 200 else (False, "HTTP %d" % status)


def heartbeat_health(store, max_age=WORKER_HEARTBEAT_S, clock=time.time):
    """worker.py is healthy while media.db meta worker_heartbeat.ts is younger than 30 s."""
    try:
        hb = store.get_meta("worker_heartbeat")
    except Exception as e:
        return False, "media.db: %s" % e
    ts = hb.get("ts") if isinstance(hb, dict) else hb
    if not isinstance(ts, (int, float)):
        return False, "no heartbeat"
    age = clock() - ts
    info = dict(hb) if isinstance(hb, dict) else {"ts": ts}
    info["age"] = age
    return (age < max_age), (info if age < max_age else "heartbeat %.0f s old" % age)


class Child:
    """One supervised process. health() -> (ok, info); info may carry "pid" (an instance we did not start)."""

    def __init__(self, name, argv, out, err, health, grace=20, priority=None, cwd=None, env=None):
        self.name, self.argv, self.out, self.err, self.health = name, list(argv), out, err, health
        self.grace, self.priority, self.cwd, self.env = grace, priority, cwd, env
        self.proc = self.pid = self.started = self.healthy_since = self.last_exit = None
        self.pending_reason = self.error = self.info = self.last_pid = None
        self.state, self.restarts, self.streak, self.fails, self.next_start = "stopped", 0, 0, 0, 0.0


class Supervisor:
    """Starts media.py / worker.py with Strata's own interpreter (pythonw under the scheduled task), keeps them
    healthy, restarts with backoff 10 s, 30 s, 60 s ... 5 min and records supervisor.* events. A healthy instance it
    did not start (e.g. left running across a Strata restart) is adopted as "external" and never touched: only
    processes this object spawned are ever killed."""

    def __init__(self, children, emit=None, backoff=BACKOFF, clock=time.time, max_fails=3,
                 healthy_reset=HEALTHY_RESET_S):
        self.children = list(children)
        self.emit = emit or (lambda kind, severity, **detail: None)
        self.backoff, self.clock, self.max_fails, self.healthy_reset = tuple(backoff), clock, max_fails, healthy_reset
        self.lock = threading.Lock()

    def child(self, name):
        return next((c for c in self.children if c.name == name), None)

    def ensure(self):
        with self.lock:
            for c in self.children:
                try:
                    self._ensure(c)
                except Exception as e:
                    c.error = "%s: %s" % (e.__class__.__name__, e)
                    log("supervisor %s: %s" % (c.name, c.error), key="sup-" + c.name)

    def _check(self, c):
        try:
            ok, info = c.health()
        except Exception as e:
            ok, info = False, "%s: %s" % (e.__class__.__name__, e)
        c.info, c.error = (info, None) if ok else (c.info, str(info)[:300])
        return ok, info

    def _ensure(self, c):
        now = self.clock()
        if c.proc is not None:
            rc = c.proc.poll()
            if rc is None:
                ok, _ = self._check(c)
                if ok:
                    c.fails, c.state = 0, "up"
                    c.healthy_since = c.healthy_since or now
                    if c.streak and now - c.healthy_since >= self.healthy_reset:
                        c.streak = 0
                    return
                c.healthy_since = None
                if now - c.started < c.grace:
                    c.state = "starting"
                    return
                c.fails += 1
                c.state = "unhealthy"
                if c.fails < self.max_fails:
                    return
                reason = "unhealthy (%s)" % c.error
                self._kill(c)
                rc = c.proc.returncode
            else:
                reason = "exited (rc=%s)" % rc
            delay = self.backoff[min(c.streak, len(self.backoff) - 1)]
            c.streak += 1
            c.last_exit = {"ts": now, "rc": rc, "reason": reason, "pid": c.pid}
            c.last_pid, c.proc, c.pid, c.healthy_since = c.pid, None, None, None
            c.pending_reason, c.next_start, c.state = reason, now + delay, "backoff"
            log("%s %s - restart in %g s" % (c.name, reason, delay))
        ok, info = self._check(c)
        pid = info.get("pid") if ok and isinstance(info, dict) else None
        if ok and not (c.last_pid and pid == c.last_pid):
            c.state = "external"  # someone else's instance answers: adopt, never start a second one
            return
        if now < c.next_start:
            c.state = "backoff"
            return
        self._start(c, now)

    def _start(self, c, now):
        script = next((a for a in c.argv[1:] if a.endswith(".py")), None)
        if script and not os.path.isfile(script):
            c.state, c.error, c.next_start = "missing", "script not found: %s" % script, now + 300
            return
        for p in (c.out, c.err):
            os.makedirs(os.path.dirname(os.path.abspath(p)), exist_ok=True)
        env = dict(os.environ if c.env is None else c.env)
        env.setdefault("PYTHONUNBUFFERED", "1")
        env.setdefault("PYTHONIOENCODING", "utf-8")
        flags = NOWIN | (BELOW_NORMAL if c.priority == "below_normal" else 0)
        with open(c.out, "ab") as out, open(c.err, "ab") as err:
            out.write(("\n--- %s started by the Strata supervisor ---\n" % time.strftime("%Y-%m-%d %H:%M:%S")).encode())
            out.flush()
            c.proc = subprocess.Popen(c.argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err, cwd=c.cwd, env=env,
                                      creationflags=flags, close_fds=True)
        core.tie_to_me(c.proc)  # ends with Strata (a task stop no longer orphans media.py / worker.py)
        c.pid, c.started, c.fails, c.state, c.healthy_since = c.proc.pid, now, 0, "starting", None
        if c.pending_reason is not None:
            c.restarts += 1
            self.emit("supervisor.restart", "warning", child=c.name, reason=c.pending_reason, pid=c.pid,
                      restarts=c.restarts)
            log("%s restarted (pid %d)" % (c.name, c.pid))
        else:
            self.emit("supervisor.start", "info", child=c.name, pid=c.pid)
            log("%s started (pid %d)" % (c.name, c.pid))
        c.pending_reason = None

    @staticmethod
    def _kill(c):
        """Only ever called with a Popen this supervisor created."""
        try:
            c.proc.kill()
            c.proc.wait(10)
        except Exception:
            pass

    def stop(self):
        """Terminate the children this supervisor started (tests / shutdown); adopted ones are left alone."""
        with self.lock:
            for c in self.children:
                if c.proc is not None and c.proc.poll() is None:
                    try:
                        c.proc.terminate()
                        c.proc.wait(5)
                    except Exception:
                        self._kill(c)
                c.proc, c.pid, c.state = None, None, "stopped"

    def status(self):
        now = self.clock()
        out = {}
        for c in self.children:
            out[c.name] = {"state": c.state, "up": c.state in ("up", "external"), "managed": c.proc is not None,
                           "pid": c.pid, "restarts": c.restarts, "uptime": now - c.started if c.proc and c.started else None,
                           "last_exit": c.last_exit, "error": c.error,
                           "next_start": c.next_start if c.state == "backoff" else None}
        return out


def default_children(c, store, python=None, media_dir=MEDIA_DIR, data_dir=None):
    """media.py (hot path) and worker.py (BELOW_NORMAL). The interpreter is Strata's own: pythonw under the
    scheduled task, python in a console. Output is appended to data/media.out|err and data/worker.out|err."""
    py = python or sys.executable or "python"
    data_dir = data_dir or os.path.join(core.HOME, "data")
    listen = c.get("listen") or "127.0.0.1:8084"
    return [Child("media", [py, os.path.join(media_dir, "media.py")], os.path.join(data_dir, "media.out"),
                  os.path.join(data_dir, "media.err"), lambda: media_health(listen), grace=20, cwd=media_dir),
            Child("worker", [py, os.path.join(media_dir, "worker.py")], os.path.join(data_dir, "worker.out"),
                  os.path.join(data_dir, "worker.err"), lambda: heartbeat_health(store), grace=45,
                  priority="below_normal", cwd=media_dir)]


# ---------------------------------------------------------------- default integrations (getattr fallbacks)

def _default_alert(kind, severity, title, detail="", key=None, coalesce_minutes=None):
    for h in list(getattr(_mod("rules"), "ALERT_HOOK", None) or []):
        try:
            if coalesce_minutes:
                try:
                    h(kind, severity, title, detail, key, coalesce_minutes=coalesce_minutes)
                    continue
                except TypeError as e:
                    if "coalesce_minutes" not in str(e):
                        raise
            h(kind, severity, title, detail, key)
        except Exception:
            log("alert hook failed:\n" + traceback.format_exc(), key="alert-hook")


def _default_purge(urls):
    cf = _mod("cloudflare")
    fn = getattr(cf, "purge_async", None) or getattr(cf, "enqueue", None)
    if fn:
        fn(urls)


def _default_apply_soon():
    ev = getattr(_mod("rules"), "APPLY_SOON", None)
    if ev is not None:
        ev.set()


def _default_apply(user, reason):
    """rules.apply() in a transaction of its own (what /api/serving/apply does); returns its result."""
    rules = _mod("rules")
    db = core.connect()
    try:
        with db:
            return rules.apply(db, user, reason)
    finally:
        db.close()


def urls_for(m, rel):
    try:
        return _mod("files").urls_for(m, rel)
    except Exception:
        up = urllib.parse.quote(rel if m["prefix"] == "/" else m["prefix"] + rel)
        return ["https://%s%s" % (h, up) for h in m["hosts"]]


def url_path(m, rel):
    return rel if m.get("prefix", "/") == "/" else m["prefix"] + rel


def finding_summary(v):
    """One line for an alert: state, severity and the (already redacted) findings - never raw file content."""
    head = "%s%s" % (v.get("state"), ", severity %s" % v["severity"] if v.get("severity") else "")
    f = v.get("findings") if isinstance(v.get("findings"), list) else []
    parts = []
    for x in f[:5]:
        if isinstance(x, dict):
            s = "%s (%s)" % (x.get("type") or "finding", x.get("severity") or "?")
            if x.get("where"):
                s += " in %s" % str(x["where"])[:60]
            if x.get("sample"):
                s += ": %s" % str(x["sample"])[:40]
            parts.append(s)
    if len(f) > 5:
        parts.append("+%d more" % (len(f) - 5))
    if not parts:
        parts.append({"held": "held by an admin", "error": "the file could not be scanned"}.get(v.get("state"), "flagged"))
    if v.get("review_note"):
        parts.append("note: %s" % str(v["review_note"])[:120])
    return (head + " - " + "; ".join(parts))[:900]


# ---------------------------------------------------------------- the bridge

class Bridge(threading.Thread):
    """Runs every timer of DESIGN 13 in one daemon thread. Every dependency is injectable (tests never touch the
    production strata.db, media.db, Cloudflare or ports): connect (strata.db), store, cache, supervisor, edge
    (media_edge), purge(urls), alert(kind, severity, title, detail, key, coalesce_minutes=None), hits() (files.hits_by_path),
    mounts() (core.file_mounts), apply_soon(), apply(user, reason), clock."""
    daemon = True

    def __init__(self, connect=None, store=None, cache=None, supervisor=None, edge=None, purge=None, alert=None,
                 hits=None, mounts=None, apply_soon=None, apply=None, clock=time.time, python=None, data_dir=None):
        super().__init__(name="media-bridge")
        self.connect = connect or (lambda: core.connect())
        self._store, self._cache, self.supervisor, self._edge = store, cache, supervisor, edge
        self.purge = purge or _default_purge
        self.alert = alert or _default_alert
        self.hits = hits or (lambda: _mod("files").hits_by_path())
        self.mounts = mounts or (lambda: core.file_mounts())
        self.apply_soon = apply_soon or _default_apply_soon
        self.apply = apply or _default_apply
        self.clock, self.python, self.data_dir = clock, python, data_dir
        self._stop_ev, self._wake = threading.Event(), threading.Event()
        self._tl = threading.local()
        self._mylock = threading.Lock()
        self._launched = False
        self._cursor = None
        self._seen_bad = None               # (mount, path) -> (state, size, mtime) of files known to be held
        self._prewarmed = set()
        self._event_since = None
        self._event_ids = {}
        self._neg_request = False
        self._alerted = {}                  # capacity alert key -> ts (24 h coalescing across hooks)
        self._stats = (0.0, None)           # (ts, media /_stats) cache for status()
        self.capacity = None
        self.paused = False                 # media.enabled switched off while running
        self.last = {}                      # timer -> {"ts", "ok"} or {"ts", "ok": False, "error"}

    # ------------------------------------------------------------ plumbing
    @property
    def conf(self):
        return conf()

    def st(self):
        """media.db (created on first use; never while the pipeline is off, except through tests)."""
        if self._store is None:
            with self._mylock:
                if self._store is None:
                    self._store = _mod("store").Store(db_path(self.conf)).init()
        return self._store

    def cache(self):
        if self._cache is None:
            with self._mylock:
                if self._cache is None:
                    c = self.conf
                    self._cache = _mod("cache").Cache(c.get("cache_root") or os.path.join(core.HOME, "data", "media-cache"),
                                                      float(c.get("cache_max_gb") or 30) * (1 << 30), self.st())
        return self._cache

    @property
    def edge(self):
        return self._edge or _mod("media_edge")

    def tx_open(self):
        return getattr(self._tl, "depth", 0) > 0

    @contextlib.contextmanager
    def strata(self, write=False):
        """A strata.db connection; write=True wraps it in one transaction. Closed on exit, before any alert."""
        db = self.connect()
        self._tl.depth = getattr(self._tl, "depth", 0) + 1
        try:
            if write:
                with db:
                    yield db
            else:
                yield db
        finally:
            self._tl.depth -= 1
            db.close()

    def _meta(self, k, default=None):
        with self.strata() as db:
            return core.get_meta(db, k, default)

    def _set_meta(self, k, v):
        with self.strata(write=True) as db:
            core.set_meta(db, k, v)

    def _raise_all(self, alerts, coalesce_minutes=None):
        """Raise collected alerts - only outside a strata.db transaction (DESIGN 13)."""
        if self.tx_open():
            raise RuntimeError("alert raised inside an open strata.db transaction")
        for a in alerts:
            try:
                self.alert(*a, coalesce_minutes=coalesce_minutes) if coalesce_minutes else self.alert(*a)
            except Exception:
                log("alert failed:\n" + traceback.format_exc(), key="alert")

    def _emit(self, kind, severity="warning", **detail):
        """A bridge event straight into media.db (the events watcher and the admin UI read it there)."""
        try:
            self.st().add_events([{"ts": self.clock(), "proc": "bridge", "kind": kind, "severity": severity,
                                   "detail": detail}])
        except Exception as e:
            log("event %s not stored: %s" % (kind, e), key="emit")

    def _mounts(self):
        return {int(m["id"]): m for m in self.mounts() if m.get("kind") == "files"}

    # ------------------------------------------------------------ thread
    def start(self):
        """No-op while media.enabled is off (and idempotent): the pipeline stays completely cold."""
        if not enabled():
            log("disabled (media.enabled is off) - bridge not started")
            return self
        with self._mylock:
            if self._launched:
                return self
            self._launched = True
        super().start()
        return self

    def stop(self, children=True):
        self._stop_ev.set()
        self._wake.set()
        if children and self.supervisor is not None:
            self.supervisor.stop()

    def request_negotiation(self):
        """Settings changed: re-run the negotiation step on the next loop turn."""
        self._neg_request = True
        self._wake.set()

    def _safe(self, name, fn):
        try:
            res = fn()
            self.last[name] = {"ts": self.clock(), "ok": True}
            return res
        except Exception as e:
            self.last[name] = {"ts": self.clock(), "ok": False, "error": "%s: %s" % (e.__class__.__name__, e)}
            log("%s failed:\n%s" % (name, traceback.format_exc()), key="timer-" + name)
            return None

    def run(self):
        self._safe("init", self.first_start)
        if self.supervisor is None:
            self.supervisor = Supervisor(default_children(self.conf, self.st(), self.python, data_dir=self.data_dir),
                                         emit=self._emit, clock=self.clock)
        steps = {"supervise": self.supervisor.ensure, "verdicts": self.watch_verdicts, "discovery": self.discover,
                 "events": self.watch_events, "capacity": self.check_capacity, "negotiation": self.negotiate,
                 "prune": lambda: self.st().prune()}
        now = self.clock()
        due = {"supervise": now, "verdicts": now + 5, "negotiation": now + 15, "discovery": now + 60,
               "events": now + 60, "capacity": now + 90, "prune": now + 600}
        while not self._stop_ev.is_set():
            if not enabled():  # kill switch flipped at runtime: stop our own children, idle until it is back on
                if not self.paused:
                    self.paused = True
                    log("media.enabled switched off - bridge paused, stopping the processes it started")
                    self._safe("pause", self.supervisor.stop)
                self._wake.wait(30)
                self._wake.clear()
                continue
            if self.paused:
                self.paused = False
                log("media.enabled back on - bridge resumed")
                due["supervise"] = due["negotiation"] = self.clock()
            if self._neg_request:
                self._neg_request = False
                due["negotiation"] = self.clock()
            for name in sorted(due, key=due.get):
                if due[name] <= self.clock() and not self._stop_ev.is_set():
                    res = self._safe(name, steps[name])
                    every = res if name == "negotiation" and isinstance(res, (int, float)) else EVERY[name]
                    due[name] = self.clock() + every
            self._wake.wait(max(0.5, min(due.values()) - self.clock()))
            self._wake.clear()

    # ------------------------------------------------------------ first start
    def first_start(self):
        """cutover = now (files born before it are legacy) and the /_admin token, saved once to strata.json; the
        next apply copies both into media.json."""
        c, upd = self.conf, {}
        if not c.get("cutover"):
            upd["cutover"] = round(self.clock(), 3)
        if not c.get("admin_token"):
            upd["admin_token"] = secrets.token_urlsafe(32)
        if upd:
            core.save_config({"media": upd})
            log("first start: %s set" % " and ".join(sorted(upd)))
            self.apply_soon()
        return sorted(upd)

    # ------------------------------------------------------------ verdict watcher (5 s)
    def watch_verdicts(self):
        st = self.st()
        if self._cursor is None:
            self._cursor = float(self._meta(CURSOR_META, 0) or 0)
        cursor = self._cursor
        if self._seen_bad is None:  # files already held before this start: no second purge / alert for them
            self._seen_bad = {(v["mount"], v["path"]): (v["state"], v["size"], v["mtime"])
                              for v in st.list_verdicts(BAD_STATES, limit=10 ** 7) if (v["updated"] or 0) <= cursor}
        rows = st.verdicts_since(max(0.0, cursor - 5))  # other processes' clocks: overlap, re-applying is idempotent
        mounts = self._mounts()
        urls, alerts, newest = [], [], cursor
        for v in rows:
            newest = max(newest, v["updated"] or 0)
            k, sig = (v["mount"], v["path"]), (v["state"], v["size"], v["mtime"])
            if v["state"] not in BAD_STATES:
                self._seen_bad.pop(k, None)
                continue
            prev = self._seen_bad.get(k)
            self._seen_bad[k] = sig
            if prev is not None and prev[1:] == sig[1:]:
                continue  # same content already held (re-read row, or flagged -> held by an admin)
            m = mounts.get(v["mount"])
            if m is not None:
                urls += urls_for(m, v["path"])
            if v["state"] == "held" and v.get("reviewed_by"):
                continue  # an admin's own hold: purge, but no alert
            label = url_path(m, v["path"]) if m else "%s:%s" % (v["mount"], v["path"])
            alerts.append(("media", "warning", "Held for review: %s" % label, finding_summary(v),
                           "media-hold:%s:%s" % (v["mount"], v["path"])))
        if urls:
            self.purge(list(dict.fromkeys(urls)))
        if newest > cursor:
            self._set_meta(CURSOR_META, newest)
            self._cursor = newest
        if len(alerts) > MAX_ALERTS:
            extra = len(alerts) - MAX_ALERTS
            alerts = alerts[:MAX_ALERTS] + [("media", "warning", "%d more files held for review" % extra,
                                             "See the Media view for the full list.", "media-hold:many")]
        self._raise_all(alerts)
        return {"rows": len(rows), "purged": len(urls), "alerts": len(alerts)}

    # ------------------------------------------------------------ discovery + prewarm (2 min)
    def discover(self):
        c, st = self.conf, self.st()
        mcfg = _mod("config")
        gate = c.get("gate") or {}
        cats = set(gate.get("categories") or ()) if gate.get("enabled", True) else set()
        cutover = float(c.get("cutover") or 0)
        backfill = (c.get("worker") or {}).get("backfill", True)
        mounts = self._mounts()
        if not mounts:
            return {"mounts": 0}
        with self.strata() as db:  # read only, closed before anything else happens
            rows = db.execute("SELECT mount, path, size, mtime FROM fidx WHERE mount IN (%s)"
                              % ",".join("?" * len(mounts)), list(mounts)).fetchall()
        fidx, per_mount = {}, collections.Counter()
        for mid, path, size, mtime in rows:
            fidx[(mid, path)] = (size, mtime)
            per_mount[mid] += 1
        verdicts = {(v["mount"], v["path"]): v for v in st.list_verdicts(limit=10 ** 7)}
        busy = {(j["mount"], j["path"]) for s in ("queued", "running") for j in st.jobs(s, "scan", limit=10 ** 7)}
        failed = {(j["mount"], j["path"]): (j["size"], j["mtime"]) for j in st.jobs("failed", "scan", limit=10 ** 7)}
        res = {"files": len(fidx), "new": 0, "legacy": 0, "dropped": 0, "prewarm": 0, "popular": 0}
        for (mid, path), (size, mtime) in fidx.items():
            if not cats or mcfg.category(path) not in cats:
                continue
            v = verdicts.get((mid, path))
            if v and v["size"] == size and _same_mtime(v["mtime"], mtime) and v["state"] != "pending":
                continue
            if (mid, path) in busy or failed.get((mid, path)) == (size, mtime):
                continue
            legacy = bool(cutover) and (mtime or 0) < cutover   # fidx has no birth time: mtime approximates it
            if legacy and not backfill:
                continue
            if res["new"] + res["legacy"] >= MAX_ENQUEUE:
                break
            if st.enqueue("scan", mid, path, size=size, mtime=mtime,
                          priority=PRIO["legacy"] if legacy else PRIO["new"]) is not None:
                res["legacy" if legacy else "new"] += 1
        # verdicts of files that left both the index and the disk (never for an offline or unindexed drive)
        for (mid, path), v in verdicts.items():
            m = mounts.get(mid)
            if (mid, path) in fidx or m is None or not per_mount.get(mid) or not os.path.isdir(m["path"]):
                continue
            full = self._full(m, path)
            if full is not None and not os.path.exists(full):
                self.drop(mid, path)
                res["dropped"] += 1
        self._variant_sources(mounts, fidx, per_mount, res)
        self._prewarm_pass(c, mcfg, mounts, fidx, cutover, res)
        return res

    def _variant_sources(self, mounts, fidx, per_mount, res):
        """Derived images follow their source: deleted source -> all its variants go; changed source (new size or
        mtime) -> the variants of the old content go. Variant keys embed the source identity, so stale variants are
        already unreachable; this only reclaims their disk. Decided on a real stat, never on the (possibly older)
        file index alone, and never while a drive is offline."""
        stale, gone, cache = [], set(), None
        stats = {}
        for mid, path, size, mtime, key, f in self.st().variant_sources():
            m = mounts.get(mid)
            if m is None or not per_mount.get(mid):
                continue
            ix = fidx.get((mid, path))
            if ix is not None and ix[0] == size and _same_mtime(ix[1], mtime):
                continue
            if (mid, path) not in stats:
                full = self._full(m, path)
                try:
                    st = os.stat(full) if full else None
                except FileNotFoundError:
                    st = None
                except OSError:
                    st = "error"
                if st is None and not os.path.isdir(m["path"]):
                    st = "error"   # unreachable share: decide nothing
                stats[(mid, path)] = st
            st = stats[(mid, path)]
            if st == "error":
                continue
            if st is None:
                gone.add((mid, path))
            elif not (st.st_size == size and _same_mtime(st.st_mtime, mtime)):
                stale.append(key)
        for mid, path in gone:
            self.drop(mid, path)
        if stale:
            cache = self.cache()
            for r in self.st().drop_variant_keys(stale):
                if r.get("file"):
                    cache.remove(r["file"])
        res["variants_gone"], res["variants_stale"] = len(gone), len(stale)

    def _prewarm_pass(self, c, mcfg, mounts, fidx, cutover, res):
        img = c.get("image") or {}
        min_bytes = int(img.get("min_bytes") or 0)
        tm = sorted((m for m in mounts.values() if m.get("transforms")), key=lambda m: -len(m.get("prefix") or "/"))
        tids = {int(m["id"]) for m in tm}
        if not tids:
            return
        if img.get("prewarm_uploads", True) and cutover:  # images born after the cutover
            for (mid, path), (size, mtime) in fidx.items():
                if (mid in tids and (mtime or 0) >= cutover and (size or 0) >= min_bytes
                        and mcfg.ext_of(path) in mcfg.NEGOTIABLE and res["prewarm"] < MAX_PREWARM):
                    res["prewarm"] += self._prewarm(mid, path, size, mtime, PRIO["prewarm_upload"])
        n = int(img.get("prewarm_popular") or 0)
        if n <= 0:
            return
        cand = []
        for up, h in (self.hits() or {}).items():
            if mcfg.ext_of(up) not in mcfg.NEGOTIABLE:
                continue
            for m in tm:
                pre = m.get("prefix") or "/"
                rel = up if pre == "/" else (up[len(pre):] if up.startswith(pre + "/") else None)
                if rel and (int(m["id"]), rel) in fidx:
                    cand.append((h[0] if isinstance(h, (list, tuple)) else h, int(m["id"]), rel))
                    break
        cand.sort(key=lambda x: -x[0])
        for _, mid, rel in cand[:n]:
            size, mtime = fidx[(mid, rel)]
            if (size or 0) >= min_bytes:
                res["popular"] += self._prewarm(mid, rel, size, mtime, PRIO["popular"])

    def _prewarm(self, mid, path, size, mtime, prio):
        key = (mid, path, size, mtime)
        if key in self._prewarmed:
            return 0
        self._prewarmed.add(key)
        return 1 if self.st().enqueue("image", mid, path, size=size, mtime=mtime, params=PREWARM_PARAMS,
                                      priority=prio) is not None else 0

    @staticmethod
    def _full(m, rel):
        full, _ = _mod("config").resolve({"path": m["path"], "prefix": "/"}, urllib.parse.quote(rel))
        return full

    def drop(self, mid, path):
        """A file is gone for good: its verdict, queued jobs, variant rows and cache files go too."""
        st = self.st()
        rows = st.drop_variants(mid, path)
        if rows:
            cache = self.cache()
            for r in rows:
                f = r.get("file") or ""
                if f and not cache.remove(f) and os.path.isabs(f):
                    try:  # an absolute path inside the cache (older rows)
                        if os.path.commonpath([os.path.abspath(f).lower(), cache.dir.lower()]) == cache.dir.lower():
                            os.remove(f)
                    except (OSError, ValueError):
                        pass
        st.cancel(None, mid, path)
        st.drop_verdict(mid, path)
        if self._seen_bad is not None:
            self._seen_bad.pop((mid, path), None)

    # ------------------------------------------------------------ events watcher (60 s)
    def watch_events(self):
        st, now = self.st(), self.clock()
        since = self._event_since if self._event_since is not None else now - 120
        rows = [r for r in st.events(since=since - 30, limit=2000) if r["id"] not in self._event_ids]
        for r in rows:
            self._event_ids[r["id"]] = r["ts"]
        self._event_ids = {i: t for i, t in self._event_ids.items() if t > now - 600}
        self._event_since = now
        alerts = []
        for r in sorted(rows, key=lambda r: r["ts"]):
            d = r.get("detail") if isinstance(r.get("detail"), dict) else {}
            if r["kind"] == "tool.missing":
                tool = str(d.get("tool") or d.get("name") or "?")[:40]
                alerts.append(("media", "warning", "Media tool missing: %s" % tool,
                               str(d.get("need") or d.get("detail") or d.get("error") or
                                   "Install it with media/install.ps1; affected files stay held or unscanned.")[:400],
                               "media-tool:%s" % tool))
            elif r["kind"] == "supervisor.restart":
                child = str(d.get("child") or "?")[:40]
                alerts.append(("media", "warning", "Media process restarted: %s" % child,
                               str(d.get("reason") or "")[:400], "media-restart:%s" % child))
        failed = st.event_counts(now - 3600).get("job.failed", 0)
        if failed > JOB_FAILED_PER_H:
            alerts.append(("media", "warning", "Media jobs failing: %d in the last hour" % failed,
                           "See Media > Jobs (failed) for the errors.", "media-jobs-failed"))
        self._raise_all(alerts)
        return {"events": len(rows), "alerts": len(alerts)}

    # ------------------------------------------------------------ capacity advisor (5 min)
    def capacity_inputs(self):
        now, st = self.clock(), self.st()
        with self.strata() as db:
            def vals(key):
                return [r[0] for r in db.execute("SELECT val FROM metric WHERE key=? AND ts>=? AND val IS NOT NULL",
                                                 (key, int(now - 3600)))]
            cpu, mem, tx = vals("host_cpu"), vals("host_mem"), vals("tunnel_tx")
        s1 = [s.get("data") for s in st.samples(now - 3600, proc="media")]
        s24 = [s.get("data") for s in st.samples(now - 86400, proc="media")]
        secs = sum(_num(d, "secs") or 60 for d in s1)
        ev24 = st.event_counts(now - 86400)
        mem_bypass = 0
        for e in st.events(since=now - 3600, kind="bypass.breaker_open", limit=5000):
            d = e.get("detail") if isinstance(e.get("detail"), dict) else {}
            if "mem" in str(d.get("detail") or d.get("reason") or ""):
                mem_bypass += 1
        try:
            usage = self.cache().usage()
        except Exception:
            usage = {}
        txp = p95(tx)
        return {"cpu_p95": p95(cpu), "mem_p95": p95(mem), "tx_p95_mbps": txp * 8 / 1e6 if txp is not None else None,
                "open_ratio": (sum(_num(d, "open_s") for d in s1) / secs) if s1 and secs else None,
                "trips_24h": max(sum(_num(d, "trips") for d in s24), ev24.get("breaker.trip", 0)),
                "mem_bypass_1h": mem_bypass, "oldest_job_s": st.oldest_queued_age(),
                "oldest_scan_s": st.oldest_queued_age("scan"),
                "queued_scans": (st.job_counts().get("scan") or {}).get("queued", 0),
                "disk_free": usage.get("disk_free"), "disk_total": usage.get("disk_total"),
                "metric_minutes": len(cpu)}

    def check_capacity(self):
        inputs = self.capacity_inputs()
        rows = advise(inputs, self.conf.get("capacity"), core.NCPU)
        now = self.clock()
        self.capacity = {"ts": now, "advice": rows, "inputs": inputs}
        self._set_meta(CAP_META, self.capacity)
        alerts = []
        for a in rows:
            key = "capacity:%s" % a["resource"]
            if now - self._alerted.get(key, 0) < CAPACITY_COALESCE_MIN * 60:
                continue
            self._alerted[key] = now
            alerts.append(("media", "warning" if a["level"] == "upgrade" else "info",
                           "Capacity: %s" % a["recommendation"], a["evidence"], key))
        self._raise_all(alerts, coalesce_minutes=CAPACITY_COALESCE_MIN)
        return self.capacity

    # ------------------------------------------------------------ negotiation (start, 6 h, settings change)
    def _video_exts(self):
        c = self.conf
        if not (c.get("video") or {}).get("enabled", True):
            return ()
        try:  # without ffmpeg `_v=webm` would only ever answer 302 ?_v=orig - not worth a rewrite
            if not _mod("sandbox").which("ffmpeg", c):
                return ()
        except Exception:
            return ()
        return ("mp4", "m4v", "mov")

    def negotiate(self):
        """Configured auto/edge -> install the edge rules; success = effective edge. A permission error (401/403, no
        token) means redirect for auto, and "keep trying + warning" for edge. redirect/off remove the rules (best
        effort). The effective mode is stored in strata.db meta; a change triggers rules.APPLY_SOON."""
        c = self.conf
        mode = c.get("negotiation") or "auto"
        mode = mode if mode in NEG_MODES else "auto"
        prev = self._meta(NEG_META)
        prev_mode = prev.get("mode") if isinstance(prev, dict) else prev
        now, edge = self.clock(), self.edge
        rec = {"configured": mode, "checked": now, "error": "", "edge": {"state": "unchecked", "rules": {}, "error": ""}}
        eff, retry, alerts = prev_mode, EVERY["negotiation"], []
        if mode in ("auto", "edge"):
            try:
                r = edge.sync_media_rules(True, vid_exts=self._video_exts()) or {}
                eff = "edge"
                rec["edge"] = {"state": "installed", "rules": r.get("rules") or {}, "error": "",
                               "changed": bool(r.get("created") or r.get("updated") or r.get("deleted"))}
            except Exception as e:
                status = getattr(e, "status", None)
                perm = status in (401, 403) or (status == 0 and "token" in str(e).lower())
                rec["error"] = "%s" % e
                rec["edge"] = {"state": "no permission" if perm else "error", "rules": {}, "error": str(e)[:300]}
                need = getattr(edge, "PERMS", {}).get("transform", "Zone › Transform Rules › Edit")
                if perm and mode == "auto":
                    eff = "redirect"
                else:
                    retry = NEG_RETRY_S
                    if mode == "edge":
                        alerts.append(("media", "warning", "Edge negotiation rules could not be installed",
                                       "%s%s" % (str(e)[:300], " - add %s to the token" % need if perm else ""),
                                       "media-edge"))
        else:
            try:
                r = edge.sync_media_rules(False) or {}
                rec["edge"] = {"state": "removed", "rules": r.get("rules") or {}, "error": ""}
            except Exception as e:
                rec["edge"] = {"state": "error", "rules": {}, "error": str(e)[:300]}
            eff = mode
        try:
            rec["caps"] = edge.capabilities()
        except Exception as e:
            rec["caps"] = {"error": str(e)[:300]}
        rec["mode"] = eff if eff in ("edge", "redirect", "off") else None
        self._set_meta(NEG_META, rec)
        if rec["mode"] != prev_mode:
            log("negotiation: %s -> %s (configured %s)" % (prev_mode, rec["mode"], mode))
            self.apply_soon()
        self._raise_all(alerts)
        return retry

    # ------------------------------------------------------------ hooks
    def upload(self, mount, rel, full):
        c, st = self.conf, self.st()
        mcfg = _mod("config")
        s = os.stat(full)
        out = {"scan": None, "prewarm": None}
        if mcfg.gated(rel, c):
            out["scan"] = st.enqueue("scan", mount, rel, size=s.st_size, mtime=s.st_mtime, priority=PRIO["upload"])
        img = c.get("image") or {}
        m = self._mounts().get(int(mount))
        if (img.get("prewarm_uploads", True) and m and m.get("transforms") and mcfg.ext_of(rel) in mcfg.NEGOTIABLE
                and s.st_size >= int(img.get("min_bytes") or 0)):
            out["prewarm"] = st.enqueue("image", mount, rel, size=s.st_size, mtime=s.st_mtime,
                                        params=PREWARM_PARAMS, priority=PRIO["prewarm_upload"])
        return out

    # ------------------------------------------------------------ admin API helpers
    def need_enabled(self):
        if not enabled():
            raise MediaError(409, "media pipeline disabled")

    def media_stats(self, max_age=2.0):
        ts, val = self._stats
        if val is not None and self.clock() - ts < max_age:
            return val
        ok, info = media_health(self.conf.get("listen"))
        val = {"ok": ok, "stats": info if ok else None, "error": None if ok else info}
        self._stats = (self.clock(), val)
        return val

    def settings(self):
        c = self.conf
        v = c.get("video") or {}
        img = c.get("image") or {}
        return {"negotiation": c.get("negotiation") or "auto",
                "gate_legacy": bool((c.get("gate") or {}).get("legacy_while_pending", True)),
                "hold_threshold": (c.get("scan") or {}).get("hold_threshold") or "medium",
                "video_format": "mp4" if v.get("format") == "mp4" else "webm",
                "image": {k: img.get(k) for k in ("avif_quality_lossy", "avif_quality_lossless",
                                                  "avif_alpha_quality", "webp_quality", "jpeg_quality",
                                                  "speed_sync", "speed_bg", "min_saving", "sync_budget_s",
                                                  "min_bytes", "threads", "prewarm_uploads", "prewarm_popular")},
                "video": {k: v.get(k) for k in ("enabled", "codec", "encoder", "crf_av1", "preset_av1",
                                                "crf_vp9", "crf_h264", "preset_h264", "nvenc_cq",
                                                "nvenc_preset", "audio_kbps", "threads", "cpu_pct",
                                                "max_seconds", "max_bytes", "min_saving", "timeout_factor")}}

    def config_summary(self):
        """What the UI may show - never the admin token or anything secret."""
        c = self.conf
        b, g, img, v = c.get("breaker") or {}, c.get("gate") or {}, c.get("image") or {}, c.get("video") or {}
        return {"listen": c.get("listen"), "cutover": c.get("cutover") or 0, "cache_root": c.get("cache_root"),
                "cache_max_gb": c.get("cache_max_gb"),
                "breaker": {k: b.get(k) for k in ("slots", "max_waiters", "cpu_trip", "cpu_resume", "mem_min_mb")},
                "capacity": dict(CAPACITY, **(c.get("capacity") or {})),
                "gate": {"enabled": g.get("enabled", True), "categories": list(g.get("categories") or ()),
                         "legacy_while_pending": g.get("legacy_while_pending", True)},
                "lane": dict(c.get("lane") or {}),
                "image": {k: img.get(k) for k in ("sync_budget_s", "sync_max_mp", "prewarm_uploads", "prewarm_popular")},
                "video": {k: v.get(k) for k in ("enabled", "codec", "format", "encoder", "crf_av1",
                                                 "preset_av1", "crf_vp9", "crf_h264", "preset_h264",
                                                 "nvenc_cq", "nvenc_preset", "audio_kbps", "threads",
                                                 "cpu_pct", "max_seconds", "max_bytes", "min_saving")},
                "file_policy": {"enabled": bool((c.get("file_policy") or {}).get("enabled"))}}

    def tools(self):
        out = {}
        try:
            out = dict(_mod("sandbox").tools(self.conf))
        except Exception as e:
            out = {"error": str(e)[:200]}
        try:
            import importlib.metadata
            import importlib.util
            out["pypdfium2"] = (importlib.metadata.version("pypdfium2")
                                if importlib.util.find_spec("pypdfium2") else None)
        except Exception:
            out["pypdfium2"] = None
        return out

    def status(self):
        now = self.clock()
        out = {"enabled": enabled(), "now": now, "version": VERSION, "error": None, "settings": self.settings(),
               "config": self.config_summary()}
        if not out["enabled"]:
            out.update(reason="media pipeline disabled", tools=self.tools(), policy="/api/media/policy")
            return out
        errors = []
        c = self.conf
        st = self.st()
        ms = self.media_stats()
        stats = ms.get("stats") or {}
        sup = self.supervisor.status() if self.supervisor is not None else {}
        smed, swrk = sup.get("media") or {}, sup.get("worker") or {}
        try:
            hb = st.get_meta("worker_heartbeat")
        except Exception as e:
            hb, _ = None, errors.append("media.db: %s" % e)
        hb = hb if isinstance(hb, dict) else ({"ts": hb} if isinstance(hb, (int, float)) else {})
        age = now - hb["ts"] if isinstance(hb.get("ts"), (int, float)) else None
        hb_ok = age is not None and age < WORKER_HEARTBEAT_S
        out["processes"] = {
            "media": {"up": bool(ms.get("ok")), "pid": stats.get("pid") or smed.get("pid"),
                      "uptime": stats.get("uptime"), "restarts": smed.get("restarts", 0), "listen": c.get("listen"),
                      "state": smed.get("state"), "managed": smed.get("managed", False), "error": ms.get("error")},
            "worker": {"up": hb_ok, "pid": hb.get("pid") or swrk.get("pid"), "heartbeat": hb.get("ts"),
                       "heartbeat_age": age, "paused": hb.get("paused"), "restarts": swrk.get("restarts", 0),
                       "state": swrk.get("state"), "managed": swrk.get("managed", False),
                       "error": None if hb_ok else ("no heartbeat" if age is None else "heartbeat %.0f s old" % age)}}
        br = stats.get("breaker")
        if not isinstance(br, dict):
            try:
                br = st.get_meta("breaker")
            except Exception:
                br = None
        out["breaker"] = br if isinstance(br, dict) else None
        out["optimizer"] = stats.get("optimizer") if isinstance(stats.get("optimizer"), dict) else None
        mon = stats.get("monitor")
        out["monitor"] = mon if isinstance(mon, dict) else (br or {}).get("monitor") if isinstance(br, dict) else None
        out["tools"] = self.tools()
        out["cache"] = None
        try:
            out["cache"] = self.cache().usage()
        except Exception as e:
            errors.append("cache: %s" % e)
        neg = {}
        try:
            neg = self._meta(NEG_META) or {}
        except Exception as e:
            errors.append("strata.db: %s" % e)
        neg = neg if isinstance(neg, dict) else {"mode": neg}
        configured = c.get("negotiation") or "auto"
        # same rule as media_rules.effective_negotiation(): what rules.render() puts into the Caddy config
        eff = configured if configured in ("redirect", "off") else (
            neg.get("mode") if neg.get("mode") in ("edge", "redirect", "off") else "redirect")
        out["negotiation"] = {"configured": configured, "effective": eff,
                              "checked": neg.get("checked"), "error": neg.get("error") or "",
                              "edge": neg.get("edge") or {"state": "unchecked", "rules": {}, "error": ""},
                              "caps": neg.get("caps")}
        try:
            out["counts"] = {"verdicts": st.verdict_counts(), "jobs": st.job_counts(),
                             "oldest": {k: st.oldest_queued_age(k) for k in JOB_KINDS}}
            out["events_24h"] = st.event_counts(now - 86400)
            out["savings"] = st.variant_totals()
        except Exception as e:
            errors.append("media.db: %s" % e)
        cap = self.capacity
        if cap is None:
            try:
                cap = self._meta(CAP_META)
            except Exception:
                cap = None
        out["capacity"] = {"ts": cap.get("ts"), "advice": cap.get("advice") or []} if isinstance(cap, dict) else None
        out["bridge"] = {"running": self.is_alive(), "timers": self.last}
        out["error"] = "; ".join(errors) or None
        return out

    def policy(self):
        with self.strata() as db:
            r = _mod("media_rules").file_policy_preview(db)
        if isinstance(r, dict):
            r.pop("blocked", None)  # can list thousands of paths; the view never draws it
        return r


# ---------------------------------------------------------------- module API (strata.py hooks)

def get_bridge():
    """The process-wide Bridge (created passive on first use: the API works even if the thread never started)."""
    global BRIDGE
    with _bridge_lock:
        if BRIDGE is None:
            BRIDGE = Bridge()
        return BRIDGE


def start(**kw):
    """strata.main() hook. No-op while media.enabled is off."""
    global BRIDGE
    with _bridge_lock:
        if BRIDGE is None or kw:
            BRIDGE = Bridge(**kw)
    return BRIDGE.start()


def on_upload(mount, rel, full):
    """strata.after_upload() hook: scan the new file first (priority 20) and prewarm its AVIF (70). Never raises."""
    if not enabled() or not full:
        return None
    try:
        return get_bridge().upload(mount, rel, full)
    except OSError as e:  # moved / deleted right after the upload: the gate and discovery catch up later
        log("on_upload %s:%s: %s" % (mount, rel, e), key="on_upload", every=60)
    except Exception:
        log("on_upload failed:\n" + traceback.format_exc(), key="on_upload", every=60)
    return None


def on_rename(mount, old, new):
    """files.rename hook: verdicts (and queued jobs / variant rows) follow the file. Never raises."""
    if not enabled():
        return None
    try:
        get_bridge().st().move_verdict(mount, old, new)
        return True
    except Exception:
        log("on_rename failed:\n" + traceback.format_exc(), key="on_rename", every=60)
        return None


def _int(v, name, lo, hi, default=None):
    if v is None or v == "":
        if default is None:
            raise ValueError("%s is required" % name)
        return default
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise ValueError("%s must be a number" % name)
    if not lo <= n <= hi:
        raise ValueError("%s must be between %d and %d" % (name, lo, hi))
    return n


def _path(v):
    if not isinstance(v, str) or not v.startswith("/") or len(v) > 2048 or "\x00" in v or "\\" in v:
        raise ValueError("path must be a drive-relative path starting with /")
    if any(p in (".", "..") for p in v.split("/")):
        raise ValueError("path must not contain . or .. segments")
    return v


def _note(v, need=0):
    v = "" if v is None else v
    if not isinstance(v, str):
        raise ValueError("note must be text")
    v = v.strip()
    if len(v) < need:
        raise ValueError("a note of at least %d characters is required" % need)
    return v[:500]


def _csv(v, allowed, name):
    items = [s.strip() for s in str(v or "").split(",") if s.strip()]
    bad = [s for s in items if s not in allowed]
    if bad:
        raise ValueError("unknown %s: %s" % (name, ", ".join(bad)[:80]))
    return items


def api_get(user, path, q):
    """GET /api/media/* (DESIGN 13.2). Returns a dict, or None for an unknown path (strata answers 404)."""
    b, q = get_bridge(), q or {}
    try:
        if path == "/api/media/status":
            return b.status()
        if path == "/api/media/policy":
            return b.policy()
        if path not in ("/api/media/holds", "/api/media/events", "/api/media/jobs"):
            return None
        b.need_enabled()
        st = b.st()
        if path == "/api/media/holds":
            states = _csv(q.get("state") or "flagged,held,error", VERDICT_STATES, "state")
            limit, offset = _int(q.get("limit"), "limit", 1, 1000, 200), _int(q.get("offset"), "offset", 0, 10 ** 9, 0)
            text = str(q.get("q") or "")[:200]
            total = None
            if not text:
                counts = st.verdict_counts()
                total = sum(n for s, n in counts.items() if not states or s in states)
            return {"rows": st.list_verdicts(states or None, limit, offset, text or None), "total": total}
        if path == "/api/media/events":
            kind = str(q.get("kind") or "")
            if kind and (len(kind) > 64 or not all(ch.isalnum() or ch in "._-" for ch in kind)):
                raise ValueError("bad event kind")
            try:
                since = float(q.get("since") or 0)
            except ValueError:
                raise ValueError("since must be an epoch timestamp")
            return {"rows": st.events(since, kind or None, _int(q.get("limit"), "limit", 1, 2000, 200))}
        state = q.get("state") or None
        kind = q.get("kind") or None
        if state and state not in JOB_STATES:
            raise ValueError("unknown job state")
        if kind and kind not in JOB_KINDS:
            raise ValueError("unknown job kind")
        return {"rows": st.jobs(state, kind, _int(q.get("limit"), "limit", 1, 2000, 200))}
    finally:
        if b._store is not None:
            b._store.close()   # this request thread's media.db connection


def api_post(user, ip, path, body):
    """POST /api/media/* (DESIGN 13.2): validated (ValueError -> 400), audited with core.audit, dicts back."""
    b, body = get_bridge(), body if isinstance(body, dict) else {}
    A = lambda action, target, note="": core.audit(ip, user, action, target, note=note)
    try:
        if path == "/api/media/settings":
            return _post_settings(b, user, body, A)
        if path not in ("/api/media/release", "/api/media/hold", "/api/media/rescan", "/api/media/retry",
                        "/api/media/breaker"):
            return None
        b.need_enabled()
        st = b.st()
        if path in ("/api/media/release", "/api/media/hold"):
            mid, rel = _int(body.get("mount"), "mount", 1, 10 ** 9), _path(body.get("path"))
            state = "released" if path.endswith("release") else "held"
            note = _note(body.get("note"), 3 if state == "released" else 0)
            ok = st.review(mid, rel, state, user, note)
            if not ok and state == "held":  # not scanned yet: create the verdict so the hold sticks
                m = b._mounts().get(mid)
                full = b._full(m, rel) if m else None
                if not full or not os.path.isfile(full):
                    raise MediaError(404, "file not found")
                s = os.stat(full)
                st.set_verdict(mid, rel, size=s.st_size, mtime=s.st_mtime, state="pending")
                ok = st.review(mid, rel, state, user, note)
            if not ok:
                raise MediaError(404, "no scan verdict for that file")
            A("media-" + ("release" if state == "released" else "hold"), "%d:%s" % (mid, rel), note)
            b._wake.set()  # a hold is purged by the verdict watcher right away
            return {"ok": True, "state": state}
        if path == "/api/media/rescan":
            mid, rel = _int(body.get("mount"), "mount", 1, 10 ** 9), _path(body.get("path"))
            m = b._mounts().get(mid)
            if m is None:
                raise MediaError(404, "unknown drive")
            full = b._full(m, rel)
            if not full or not os.path.isfile(full):
                raise MediaError(404, "file not found")
            s = os.stat(full)
            jid = st.enqueue("scan", mid, rel, size=s.st_size, mtime=s.st_mtime, priority=PRIO["upload"], force=True)
            A("media-rescan", "%d:%s" % (mid, rel))
            return {"ok": True, "job": jid}
        if path == "/api/media/retry":
            kind = body.get("kind") or None
            if kind is not None and kind not in JOB_KINDS:
                raise ValueError("kind must be one of %s" % ", ".join(JOB_KINDS))
            n = st.retry_failed(kind)
            A("media-retry", kind or "all", "%d jobs" % n)
            return {"ok": True, "retried": n}
        state = body.get("state")
        if state not in ("open", "closed", "auto"):
            raise ValueError("state must be open, closed or auto")
        secs = 0 if state == "auto" else _int(body.get("seconds"), "seconds", 60, 86400)
        token = b.conf.get("admin_token") or ""
        if not token:
            raise MediaError(409, "no admin token yet (the bridge sets it on first start)")
        try:
            code, resp = http_json(b.conf.get("listen"), "POST", "/_admin/breaker", {"state": state, "seconds": secs},
                                   headers={"X-Strata-Admin-Token": token}, timeout=2.0)
        except (OSError, http.client.HTTPException) as e:
            raise MediaError(503, "media service not reachable: %s" % e)
        if code != 200:
            raise MediaError(502, "media answered %d: %s" % (code, str(resp)[:200]))
        A("media-breaker", state, "%d s" % secs)
        b._stats = (0.0, None)
        return {"ok": True, "breaker": resp.get("breaker", resp) if isinstance(resp, dict) else resp}
    finally:
        if b._store is not None:
            b._store.close()


def _post_settings(b, user, body, A):
    upd, media = {}, {}
    if "negotiation" in body:
        if body["negotiation"] not in NEG_MODES:
            raise ValueError("negotiation must be one of %s" % ", ".join(NEG_MODES))
        media["negotiation"] = upd["negotiation"] = body["negotiation"]
    if "gate_legacy" in body:
        if not isinstance(body["gate_legacy"], bool):
            raise ValueError("gate_legacy must be true or false")
        media["gate"] = {"legacy_while_pending": body["gate_legacy"]}
        upd["gate_legacy"] = body["gate_legacy"]
    if "hold_threshold" in body:
        if body["hold_threshold"] not in SEVERITIES:
            raise ValueError("hold_threshold must be low, medium or high")
        media["scan"] = {"hold_threshold": body["hold_threshold"]}
        upd["hold_threshold"] = body["hold_threshold"]
    if "video_format" in body:
        if body["video_format"] not in ("webm", "mp4"):
            raise ValueError("video_format must be webm or mp4")
        media.setdefault("video", {})["format"] = body["video_format"]
        upd["video_format"] = body["video_format"]
    if "image" in body:
        raw = body["image"]
        if not isinstance(raw, dict) or not raw:
            raise ValueError("image must be a non-empty object")
        ints = {"avif_quality_lossy": (1, 100), "avif_quality_lossless": (1, 100),
                "avif_alpha_quality": (1, 100), "webp_quality": (1, 100), "jpeg_quality": (1, 100),
                "speed_sync": (0, 10), "speed_bg": (0, 10), "min_bytes": (0, 1 << 20),
                "threads": (1, 16), "prewarm_popular": (0, 100000)}
        checked = {}
        for k, val in raw.items():
            if k == "prewarm_uploads":
                if not isinstance(val, bool):
                    raise ValueError("image.prewarm_uploads must be true or false")
            elif k in ints:
                lo, hi = ints[k]
                if isinstance(val, bool) or not isinstance(val, int) or not lo <= val <= hi:
                    raise ValueError("image.%s must be an integer from %s to %s" % (k, lo, hi))
            elif k == "min_saving":
                if isinstance(val, bool) or not isinstance(val, (int, float)) or not 0 <= val <= 0.75:
                    raise ValueError("image.min_saving must be between 0 and 0.75")
            elif k == "sync_budget_s":
                if isinstance(val, bool) or not isinstance(val, (int, float)) or not 0.1 <= val <= 10:
                    raise ValueError("image.sync_budget_s must be between 0.1 and 10")
            else:
                raise ValueError("unsupported image setting: %s" % k)
            checked[k] = val
        media["image"] = checked
        upd["image"] = checked
    if "video" in body:
        raw = body["video"]
        if not isinstance(raw, dict) or not raw:
            raise ValueError("video must be a non-empty object")
        enums = {"codec": ("av1", "vp9"), "encoder": ("cpu", "auto", "nvenc"),
                 "preset_h264": ("ultrafast", "superfast", "veryfast", "faster", "fast", "medium",
                                 "slow", "slower", "veryslow"),
                 "nvenc_preset": tuple("p%d" % n for n in range(1, 8))}
        ints = {"crf_av1": (0, 63), "preset_av1": (0, 13), "crf_vp9": (0, 63),
                "crf_h264": (0, 51), "nvenc_cq": (0, 51), "audio_kbps": (32, 320),
                "threads": (1, 32), "cpu_pct": (10, 100), "max_seconds": (60, 86400),
                "max_bytes": (1 << 20, 64 << 30), "timeout_factor": (1, 60)}
        checked = {}
        for k, val in raw.items():
            if k == "enabled":
                if not isinstance(val, bool):
                    raise ValueError("video.enabled must be true or false")
            elif k in enums:
                if val not in enums[k]:
                    raise ValueError("video.%s must be one of %s" % (k, ", ".join(enums[k])))
            elif k in ints:
                lo, hi = ints[k]
                if isinstance(val, bool) or not isinstance(val, int) or not lo <= val <= hi:
                    raise ValueError("video.%s must be an integer from %s to %s" % (k, lo, hi))
            elif k == "min_saving":
                if isinstance(val, bool) or not isinstance(val, (int, float)) or not 0 <= val <= 0.75:
                    raise ValueError("video.min_saving must be between 0 and 0.75")
            else:
                raise ValueError("unsupported video setting: %s" % k)
            checked[k] = val
        media.setdefault("video", {}).update(checked)
        upd["video"] = checked
    effective_video = dict((b.conf.get("video") or {}), **media.get("video", {}))
    if effective_video.get("format") == "webm" and effective_video.get("encoder") == "nvenc":
        raise ValueError("NVENC requires MP4; choose CPU or Auto for WebM")
    if not media:
        raise ValueError("nothing to change")
    core.save_config({"media": media})
    A("media-settings", ", ".join("%s=%s" % kv for kv in sorted(upd.items())))
    res = None
    if enabled():
        try:  # media.json (hold threshold, legacy gate) and the Caddy routes (negotiation) follow at once
            res = b.apply(user, "media settings")
        except Exception as e:
            res = {"error": str(e)[:300]}
            b.apply_soon()
        if "negotiation" in upd or "video_format" in upd or "video" in upd:
            b.request_negotiation()
    return {"ok": True, "settings": b.settings(), "apply": res}
