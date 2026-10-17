"""Strata Media Worker - background scans, deferred image encodes and WebM transcodes (DESIGN.md section 7).

Started by media_bridge.Supervisor (pythonw, BELOW_NORMAL priority); `--once` drains the claimable jobs and exits
(tests, manual backfills). Why it looks like this:
  * Two lanes (threads). Scans gate what may be published, so they get their own lane and never wait behind an
    hour-long transcode; the encode lane takes image and video jobs in priority order.
  * Before every claim a lane checks the machine (cpu_ewma, free RAM) and media.py's breaker (meta 'breaker'):
    the CDN hot path always wins, the worker only uses what is left (7.2).
  * Jobs are leased (store.claim). A heartbeat thread extends the leases of running jobs, so a crashed or hung
    worker's jobs come back via requeue_expired(), and a job the bridge cancelled is noticed (lease lost).
  * Failures retry with backoff (store.fail: 60 s, 10 min, 1 h, then failed); a missing tool is not retried until
    the tools change (7.4). A final decode/encode failure records a not-beneficial variant so the hot path stops
    deferring that file and serves the original.
  * Writes only go below cache_root (variants via cache.py, scratch dirs <cache_root>/sandbox/<job id> that are
    always deleted) and into media.db; originals are only read. No strata.db, no Cloudflare token.

Job params (job.params, written by media.py / the bridge):
  image  JSON {"want": "avif"|"webp", "spec": <cache spec, default "auto:<want>:v1">,
               "tf": {w, h, fit, fm, q} for a deferred explicit transform (then pass the hot path's "spec")};
         a bare "avif" / "webp" or "want=webp" works too.
  video  optional JSON {"want": "webm"|"mp4", "spec"} (default: video.format, policy-versioned spec).
  scan   none.
Meta written: worker_heartbeat (every 5 s), tools (every 10 min), cost_model (CostModel.to_dict after every automatic
encode, read back at start), worker_prune (last prune).
"""
import pathfix  # noqa: F401  (vendored Pillow / real user site before anything imports PIL)

import argparse
import json
import os
import signal
import stat
import sys
import threading
import time
import traceback
import urllib.parse

import breaker
import cache
import config
import events
import imaging
import sandbox
import scan
import store
import video

try:
    import msvcrt
    fcntl = None
except ImportError:  # not Windows (tests elsewhere)
    msvcrt = None
    import fcntl

LANES = {"scan": ("scan",), "encode": ("image", "video")}
LOCK_NAME = "media-worker.lock"     # next to media.db (DESIGN 2: data/media-worker.lock)
IDLE_S = 2.0                        # queue empty: claim again after this
PAUSE_S = 5.0                       # paused: re-check after this (7.2)
PAUSED_EVERY = 300                  # worker.paused at most once per 5 min per reason
HEARTBEAT_S = 5                     # meta worker_heartbeat; the bridge calls us healthy while it is < 30 s old
TOOLS_EVERY = 600                   # tool discovery + tool.missing events
REQUEUE_EVERY = 60
EVICT_EVERY = 60
PRUNE_EVERY = 86400
HOUSEKEEP_S = 5.0
BREAKER_STALE_S = 60                # a breaker state with a 'ts' older than this is ignored (media.py died open)
ONCE_PAUSE_MAX = 300                # --once gives up after this long paused and leaves the jobs queued
STOP_WAIT_S = 10.0
AUTO_SPEC = "auto:%s:v1"
QUIET = False                       # tests silence the log


def log(msg):
    """stdout -> data/worker.out (the supervisor redirects it); print() is a no-op under pythonw without one."""
    if QUIET:
        return
    try:
        print("%s [worker %d] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), os.getpid(), msg), flush=True)
    except Exception:
        pass


def _job_params(raw):
    """job.params -> dict: JSON object, "k=v&..." or a bare format name ("avif")."""
    raw = (raw or "").strip()
    if not raw:
        return {}
    if raw.startswith("{"):
        try:
            d = json.loads(raw)
            return d if isinstance(d, dict) else {}
        except ValueError:
            return {}
    if "=" in raw:
        return dict(urllib.parse.parse_qsl(raw, keep_blank_values=True))
    return {"want": raw}


def _tf_spec(p):
    """Cache spec of an explicit transform (DESIGN 6.3) - only used when the job does not carry the hot path's."""
    return "tf:w=%s,h=%s,fit=%s,fm=%s,q=%s:v1" % (p["w"] or "", p["h"] or "", p["fit"], p["fm"], p["q"])


def _summary(findings, n=4):
    """Short, already redacted description of the worst findings for events / alerts (never raw content)."""
    parts = []
    for f in findings[:n]:
        s = "%s (%s)" % (f.get("type") or "?", f.get("severity") or "?")
        if f.get("sample"):
            s += " " + str(f["sample"])[:40]
        parts.append(s)
    if len(findings) > n:
        parts.append("+%d more" % (len(findings) - n))
    return "; ".join(parts)[:400]


def _rm(path):
    try:
        os.remove(path)
    except OSError:
        pass


def _pdfium_version():
    try:
        import importlib
        importlib.invalidate_caches()        # pick up an install made while we run
        import pypdfium2
        return str(getattr(pypdfium2, "V_PYPDFIUM2", "") or getattr(pypdfium2, "__version__", "") or "yes")
    except Exception:
        return None


def _pillow():
    out = {"version": None, "avif": False, "webp": False}
    try:
        import PIL
        from PIL import features
        out["version"] = PIL.__version__
        for f in ("avif", "webp"):
            try:
                out[f] = bool(features.check(f))
            except Exception:
                pass
    except Exception:
        pass
    return out


class InstanceLock:
    """Single instance (DESIGN 2): an exclusive byte-range lock on data/media-worker.lock. The OS drops it when the
    process dies, so a crashed worker never leaves a stale lock behind."""

    def __init__(self, path):
        self.path, self._f = os.path.abspath(path), None

    def acquire(self):
        if self._f is not None:
            return True
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            f = open(self.path, "a+b")
        except OSError:
            return False
        try:
            f.seek(0)
            if msvcrt is not None:
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            f.close()
            return False
        self._f = f
        return True

    def release(self):
        f, self._f = self._f, None
        if f is None:
            return
        try:
            f.seek(0)
            if msvcrt is not None:
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        f.close()


class _Lane:
    def __init__(self, name, kinds, wid):
        self.name, self.kinds, self.wid = name, tuple(kinds), wid
        self.paused = None               # reason while paused
        self.paused_since = None
        self.job = None                  # _Run while a job runs
        self.done = self.failed = 0
        self.thread = None


class _Run:
    """A claimed job while it runs: lease bookkeeping and the cancel flag scan.scan_file polls."""

    def __init__(self, job, lane):
        self.job, self.lane, self.id = job, lane, job["id"]
        self.started = time.time()
        self.beat = time.monotonic()
        self.lost = False                # lease gone: cancelled by the bridge or re-leased after expiry

    def info(self):
        j = self.job
        return {"id": self.id, "kind": j.get("kind"), "mount": j.get("mount"), "path": j.get("path"),
                "attempts": j.get("attempts"), "started": self.started}


class Worker:
    """The job runner. conf: a media.json path (None = config.CONF_PATH, re-read when it changes) or a config dict
    (tests). db / ev / vcache / monitor replace the Store, Events, Cache and breaker.Monitor it would create."""

    def __init__(self, conf=None, *, db=None, ev=None, vcache=None, monitor=None, lanes=("scan", "encode"),
                 once=False):
        self._conf = conf
        c = self.conf
        self.store = db or store.Store(c["db"]).init()
        self.events = ev or events.Events(self.store, c.get("event_log"), "worker")
        self.cache = vcache or cache.Cache(c["cache_root"], int(float(c.get("cache_max_gb") or 30) * (1 << 30)),
                                           self.store)
        self.monitor = monitor or breaker.Monitor()
        self._own_monitor = monitor is None
        self.once = once
        pid = os.getpid()
        self.lanes = {n: _Lane(n, LANES[n], "worker-%d-%s" % (pid, n)) for n in lanes}
        self.started = time.time()
        self._stop = threading.Event()
        self._tools = None
        self._timers = {}
        self._threads = []
        self._running = False
        try:
            self.model = imaging.CostModel.from_dict(self.store.get_meta("cost_model"))
        except Exception:
            self.model = imaging.CostModel()
        self._handlers = {"scan": self.do_scan, "image": self.do_image, "video": self.do_video}

    @property
    def conf(self):
        return self._conf if isinstance(self._conf, dict) else config.load(self._conf)

    @property
    def lease_s(self):
        return max(1, int((self.conf.get("worker") or {}).get("lease_s") or 900))

    # ------------------------------------------------------------ lifecycle
    def start(self):
        if self._running:
            return self
        self._running = True
        if self._own_monitor and not self.monitor.is_alive():
            self.monitor.start()
        self.events.start()
        self.clean_sandbox()
        self.housekeeping(force=True)     # tools, expired leases (a crashed predecessor's jobs), eviction
        self.heartbeat()
        self._spawn("media-worker-keeper", self._keeper)
        if not self.once:
            self._spawn("media-worker-housekeeping", self._housekeeper)
        for lane in self.lanes.values():
            lane.thread = self._spawn("media-worker-" + lane.name, self._lane_loop, lane)
        return self

    def _spawn(self, name, fn, *args):
        t = threading.Thread(target=fn, args=args, name=name, daemon=True)
        t.start()
        self._threads.append(t)
        return t

    def request_stop(self):
        self._stop.set()

    def run(self):
        """Start, then wait until stopped (with once: until every lane drained). Returns the exit code."""
        self.start()
        rc = 0
        try:
            while not self._stop.is_set():
                alive = [ln for ln in self.lanes.values() if ln.thread is not None and ln.thread.is_alive()]
                if self.once and not alive:
                    break
                if not self.once and len(alive) < len(self.lanes):
                    log("a lane thread died - exiting so the supervisor restarts the worker")
                    rc = 1
                    break
                self._stop.wait(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
        return rc

    def stop(self, timeout=STOP_WAIT_S):
        """Graceful stop: no new claims, scans are cancelled (scan_file polls), jobs still running after `timeout`
        (a transcode cannot be interrupted) go back to the queue - our exit then kills their sandboxed tool."""
        self._stop.set()
        deadline = time.monotonic() + timeout
        for lane in self.lanes.values():
            if lane.thread is not None:
                lane.thread.join(max(0.0, deadline - time.monotonic()))
        for lane in self.lanes.values():
            run = lane.job
            if run is not None and not run.lost:
                self._requeue(run)
        if self._running:
            try:
                self.heartbeat(stopping=True)
            except Exception:
                pass
        self._running = False
        try:
            self.cache.flush_touches()
        except Exception:
            pass
        self.events.stop()
        if self._own_monitor:
            self.monitor.stop()

    # ------------------------------------------------------------ lanes
    def pause_reason(self):
        """cpu | mem | breaker | None - checked before every claim (7.2)."""
        wc = self.conf.get("worker") or {}
        try:
            snap = self.monitor.snapshot() or {}
        except Exception:
            snap = {}
        cpu, mem = snap.get("cpu_ewma"), snap.get("mem_avail_mb")
        if cpu is not None and cpu >= float(wc.get("cpu_max", 65)):
            return "cpu"
        if mem is not None and mem < float(wc.get("mem_min_mb", 1024)):
            return "mem"
        try:
            b = self.store.get_meta("breaker")
        except Exception:
            b = None
        if isinstance(b, dict) and b.get("state") == "open":
            ts = b.get("ts")
            if not isinstance(ts, (int, float)) or time.time() - ts < BREAKER_STALE_S:
                return "breaker"
        return None

    def lane_step(self, lane):
        """One iteration: pause check, claim, run. Returns "paused", "idle" or "ran"."""
        reason = self.pause_reason()
        if reason:
            if lane.paused != reason:
                lane.paused, lane.paused_since = reason, time.monotonic()
            snap = {}
            try:
                snap = self.monitor.snapshot() or {}
            except Exception:
                pass
            if self.events.emit_every(PAUSED_EVERY, "worker.paused", "info", key=reason, reason=reason,
                                      lane=lane.name, cpu_ewma=snap.get("cpu_ewma"),
                                      mem_avail_mb=snap.get("mem_avail_mb")):
                log("%s lane paused (%s)" % (lane.name, reason))
            return "paused"
        lane.paused = lane.paused_since = None
        job = self.store.claim(lane.wid, lane.kinds, lease_s=self.lease_s)
        if job is None:
            return "idle"
        self.run_job(lane, job)
        return "ran"

    def _lane_loop(self, lane):
        while not self._stop.is_set():
            try:
                r = self.lane_step(lane)
            except Exception as e:   # e.g. media.db locked for longer than the busy timeout: the lane must not die
                log("%s lane: %s: %s" % (lane.name, e.__class__.__name__, e))
                r = "error"
            if r == "ran":
                continue
            if self.once:
                if r in ("idle", "error"):
                    break
                if r == "paused" and time.monotonic() - (lane.paused_since or 0) > ONCE_PAUSE_MAX:
                    log("--once: %s lane paused too long (%s), leaving its jobs queued" % (lane.name, lane.paused))
                    break
            self._stop.wait(IDLE_S if r == "idle" else PAUSE_S)

    def run_job(self, lane, job):
        run = _Run(job, lane.name)
        lane.job = run
        try:
            handler = self._handlers.get(job.get("kind"))
            if handler is None:
                self._fail(run, "unknown job kind %r" % job.get("kind"), "bad_job", final=True)
            else:
                handler(run)
        except Exception as e:           # a bug or unexpected I/O trouble: retry with backoff, then failed
            log("job %s (%s %s): %s" % (run.id, job.get("kind"), job.get("path"),
                                        traceback.format_exc(limit=4).strip().replace("\n", " | ")))
            self._fail(run, "%s: %s" % (e.__class__.__name__, e), "exception")
        finally:
            lane.job = None

    # ------------------------------------------------------------ job bookkeeping
    def _finish(self, run, result=None):
        ok = self.store.finish(run.id, result)
        if ok:
            self.lanes[run.lane].done += 1
        else:
            log("job %s: lease lost before finish (cancelled or re-leased)" % run.id)
        return ok

    def _fail(self, run, error, kind, retry_in=None, final=False):
        """store.fail with the configured attempts; returns the new state. A final failure is an event."""
        max_attempts = 1 if final else int((self.conf.get("worker") or {}).get("max_attempts") or 3)
        state = self.store.fail(run.id, error, kind, retry_in=retry_in, max_attempts=max_attempts)
        if state == "failed":
            j = run.job
            self.lanes[run.lane].failed += 1
            self.events.emit("job.failed", "warning", j.get("mount"), j.get("path"), job=run.id,
                             job_kind=j.get("kind"), error_kind=kind, error=str(error)[:300],
                             attempts=j.get("attempts"))
        return state

    def _requeue(self, run):
        """Back to the queue right away (stop / cancelled scan); the attempt this claim cost stays counted."""
        return self.store.fail(run.id, "worker stopped", "stopped", retry_in=0,
                               max_attempts=int(run.job.get("attempts") or 0) + 1)

    def _source(self, run, on_missing=None):
        """(mount, full path, stat) of the job's file, or None when the job was settled here: mount gone or unsafe
        path (finished), file missing (on_missing(), finished), NAS unreachable (retry)."""
        j = run.job
        m = config.mount(self.conf, j.get("mount")) if j.get("mount") is not None else None
        full = None
        if m and j.get("path"):
            try:  # the job path is decoded and mount-relative (no prefix): resolve() wants it URL-encoded
                full, _rel = config.resolve({"path": m.get("path"), "prefix": "/"},
                                            urllib.parse.quote(j["path"], safe="/"))
            except (TypeError, ValueError, UnicodeError):
                full = None
        if not full:
            self._finish(run, {"skipped": "no_mount" if not m else "bad_path"})
            return None
        try:
            st = os.stat(full)
        except (FileNotFoundError, NotADirectoryError):
            st = None
        except OSError as e:
            self._fail(run, "stat: %s" % e, "io_error")
            return None
        if st is None or not stat.S_ISREG(st.st_mode):
            if not os.path.isdir(m.get("path") or ""):
                # an unreachable share looks like "file not found" (WinError 53 -> ENOENT): never drop verdicts then
                self._fail(run, "mount root unreachable", "io_error")
                return None
            if on_missing is not None:
                on_missing()
            self._finish(run, {"missing": True})
            return None
        return m, full, st

    # ------------------------------------------------------------ scan jobs (7.3)
    def _sandbox_root(self):
        return os.path.join(self.conf["cache_root"], "sandbox")

    def clean_sandbox(self):
        """Remove scratch dirs a crashed run left behind (single instance: none of them is in use)."""
        root = self._sandbox_root()
        try:
            names = os.listdir(root)
        except OSError:
            return 0
        n = 0
        for name in names:
            if name.isdigit() or name.startswith("strata-scan-"):
                if self._drop_sandbox(os.path.join(root, name)):
                    n += 1
        return n

    def _drop_sandbox(self, box):
        try:
            if os.path.lexists(box):
                sandbox.rmtree(box)
            return True
        except OSError as e:
            log("sandbox cleanup failed: %s: %s" % (box, e))
            self.events.emit_every(600, "sandbox.cleanup_failed", "warning", key="cleanup", dir=box, error=str(e)[:200])
            return False

    def do_scan(self, run):
        j = run.job
        src = self._source(run, on_missing=lambda: self.store.drop_verdict(j["mount"], j["path"]))
        if src is None:
            return
        m, full, st = src
        conf = self.conf
        try:
            qhash = config.quick_hash(full, st.st_size)
        except OSError as e:
            self._fail(run, "read: %s" % e, "io_error")
            return
        legacy = config.birth_time(st) < float(conf.get("cutover") or 0)
        root = self._sandbox_root()
        os.makedirs(root, exist_ok=True)
        box = sandbox.safe_join(root, str(int(run.id)))
        self._drop_sandbox(box)                          # left over by a crashed attempt
        try:
            res = scan.scan_file(full, j["path"], conf, self.tools(),
                                 cancel=lambda: self._stop.is_set() or run.lost, sandbox_dir=box)
        finally:
            self._drop_sandbox(box)                      # scan_file removes it too; this covers exceptions
        if res.error_kind == "not_found" and res.state != "flagged":
            if not os.path.isdir(m.get("path") or ""):
                self._fail(run, "mount root unreachable", "io_error")
                return
            self.store.drop_verdict(j["mount"], j["path"])
            self._finish(run, {"missing": True})
            return
        sev = "" if res.severity in (None, "none") else res.severity
        if res.state in ("clean", "flagged"):
            if run.lost:                                 # cancelled meanwhile (file deleted / renamed): no verdict
                return
            self.store.set_verdict(j["mount"], j["path"], size=st.st_size, mtime=st.st_mtime, state=res.state,
                                   qhash=qhash, severity=sev, findings=res.findings, engines=res.engines,
                                   legacy=int(legacy))
            if res.state == "flagged":
                types = {}
                for f in res.findings:
                    types[f.get("type")] = types.get(f.get("type"), 0) + 1
                self.events.emit("scan.flagged", "warning", j["mount"], j["path"], finding_severity=res.severity,
                                 legacy=bool(legacy), findings=len(res.findings), types=types,
                                 summary=_summary(res.findings))
            self._finish(run, {"state": res.state, "severity": res.severity, "findings": len(res.findings),
                               "legacy": bool(legacy), "secs": res.secs})
            return
        if res.error_kind == "cancelled":
            if not run.lost:
                self._requeue(run)
            return
        detail = (res.engines or {}).get("error") or res.error_kind or "scan error"
        if self._fail(run, detail, res.error_kind or "exception") == "failed":
            # out of retries: an unscannable file is held unless legacy (gate 5.2)
            self.store.set_verdict(j["mount"], j["path"], size=st.st_size, mtime=st.st_mtime, state="error",
                                   qhash=qhash, severity=sev, findings=res.findings, engines=res.engines,
                                   legacy=int(legacy))

    # ------------------------------------------------------------ image jobs (6.2 / 6.3 step 5)
    def _not_beneficial(self, key, j, st, spec, kind, fmt="orig", out_bytes=None, secs=0.0, reason=None):
        self.store.put_variant(key, mount=j["mount"], path=j["path"], src_size=st.st_size, src_mtime=st.st_mtime,
                               kind=kind, fmt=fmt, spec=spec, file=None, bytes=out_bytes, src_bytes=st.st_size,
                               secs=round(secs, 3), beneficial=0, reason=reason)

    def _cached(self, key):
        row = self.store.variant(key)
        return bool(row) and (not row.get("beneficial") or self.cache.exists(row.get("file")))

    def _bg_count(self, **inc):
        """Background encode counters for media.py's /_metrics (meta optimizer_worker; single worker process)."""
        try:
            cur = self.store.get_meta("optimizer_worker") or {}
            for k, v in inc.items():
                cur[k] = (cur.get(k) or 0) + v
            self.store.set_meta("optimizer_worker", cur)
        except Exception as e:
            log("optimizer counters not saved: %s" % e)

    def do_image(self, run):
        j = run.job
        src = self._source(run)
        if src is None:
            return
        _m, full, st = src
        conf = self.conf
        if imaging.Image is None:
            self._fail(run, "Pillow is not available", "tool_missing")
            return
        p = _job_params(j.get("params"))
        want = str(p.get("want") or "avif").lower()
        want = want if want in ("avif", "webp") else "avif"
        tf = p.get("tf") if isinstance(p.get("tf"), dict) else None
        family = bool(p.get("family"))
        upgrade = bool(p.get("upgrade"))
        try:
            width = int(p["width"]) if p.get("width") else None
        except (TypeError, ValueError):
            width = None
        try:
            spec = p.get("spec") or (_tf_spec(imaging.validate_explicit(tf, conf)) if tf
                                     else imaging.auto_spec(want, width, conf))
        except ValueError as e:
            self._fail(run, "bad transform params: %s" % e, "bad_params", final=True)
            return
        key = self.cache.key(j["mount"], j["path"], st.st_size, st.st_mtime, spec)
        row = self.store.variant(key)
        if upgrade:   # promoted hot variant: re-encode at speed_bg, keep whichever file is smaller
            if not row or not row.get("beneficial") or not row.get("file") or not self.cache.exists(row["file"]):
                self._finish(run, {"upgrade": "gone"})
                return
        elif self._cached(key):
            self._finish(run, {"cached": True})
            return
        lk = self.cache.lock(key)   # the same per-variant lock as media.py's single-flight
        if not lk.acquire(blocking=False):
            self._fail(run, "variant is being encoded by another process", "busy", retry_in=30)
            return
        try:
            self._image(run, j, full, st, conf, p, want, tf, family, upgrade, width, spec, key, row)
        finally:
            lk.release()

    def _image(self, run, j, full, st, conf, p, want, tf, family, upgrade, width, spec, key, row):
        try:
            mem = (self.monitor.snapshot() or {}).get("mem_avail_mb")
        except Exception:
            mem = None
        t0 = time.monotonic()
        out_w = None
        try:
            with breaker.below_normal_thread():
                if tf:
                    data, fmt = imaging.encode_explicit(full, tf, conf)
                    good = True                           # explicit ?fm= is honoured exactly
                elif family:                              # ?w= in the source's own format family
                    info = imaging.probe(full, conf)
                    if int(info.get("frames") or 1) > 1:
                        self._not_beneficial(key, j, st, spec, "img", reason="animated")
                        self._finish(run, {"variant": "orig", "reason": "animated"})
                        return
                    data, fmt = imaging.encode_family(full, info, width, conf)
                    out_w = imaging.target_size(info["w"], info["h"], width)[0]
                    good = True
                else:
                    info = imaging.probe(full, conf)
                    plan = imaging.choose(info, want, conf, width)
                    if plan.fmt == "orig":
                        self._not_beneficial(key, j, st, spec, "img", reason=plan.reason)
                        if plan.reason == "too_large":
                            self.events.emit("image.skipped", "info", j["mount"], j["path"], reason="too_large",
                                             mp=info.get("mp"))
                        self._finish(run, {"variant": "orig", "reason": plan.reason})
                        return
                    out_w = (plan.opts.get("resize") or [None])[0]
                    data, fmt = imaging.encode_auto(full, info, plan, conf, sync=False, model=self.model,
                                                    mem_avail_mb=mem)
                    # a resized variant is used regardless (dimension correctness wins); full size must pay off
                    good = bool(out_w) or imaging.beneficial(st.st_size, len(data), conf)
                    self._save_model()
        except imaging.TooLarge as e:
            used = imaging.mp_limit(conf, sync=bool(tf), mem_avail_mb=mem)
            best = imaging.mp_limit(conf, sync=bool(tf), mem_avail_mb=None)
            if used < best and e.mp <= best:
                # within the configured limit, only too large for the RAM free right now: try again later
                self.events.emit_every(PAUSED_EVERY, "image.skipped", "info", j["mount"], j["path"], key="low_memory",
                                       reason="low_memory", mp=e.mp, mem_avail_mb=mem)
                self._fail(run, str(e), "low_memory")
                return
            if not upgrade:
                self._not_beneficial(key, j, st, spec, "img", reason="too_large")
            self.events.emit("image.skipped", "info", j["mount"], j["path"], reason="too_large", mp=e.mp,
                             limit=e.limit)
            self._finish(run, {"variant": "orig", "reason": "too_large"})
            return
        except (imaging.DecodeError, imaging.EncodeError) as e:
            self._bg_count(failures=1)
            if self._fail(run, str(e), e.kind) == "failed" and not upgrade:
                # out of retries: a decision row, so the hot path serves the original instead of retrying forever
                self._not_beneficial(key, j, st, spec, "img", secs=time.monotonic() - t0, reason="failed:" + e.kind)
            return
        except MemoryError:
            self._bg_count(failures=1)
            self._fail(run, "out of memory", "memory")
            return
        secs = time.monotonic() - t0
        self._bg_count(encodes=1, secs=round(secs, 3))
        if run.lost:
            return
        if upgrade:
            return self._upgrade(run, j, st, key, row, data, fmt, secs)
        if not good:
            self._not_beneficial(key, j, st, spec, "img", fmt=fmt, out_bytes=len(data), secs=secs,
                                 reason="not_beneficial")
            self._finish(run, {"variant": "orig", "reason": "not_beneficial", "fmt": fmt, "bytes": len(data),
                               "src_bytes": st.st_size, "secs": round(secs, 3)})
            return
        ext = "jpg" if fmt == "jpeg" else fmt
        rel = self.cache.write_bytes(key, ext, "img", data, mtime=st.st_mtime)   # the fmt encode_* returned
        self.store.put_variant(key, mount=j["mount"], path=j["path"], src_size=st.st_size, src_mtime=st.st_mtime,
                               kind="img", fmt=fmt, spec=spec, file=rel, bytes=len(data), src_bytes=st.st_size,
                               secs=round(secs, 3), beneficial=1, width=out_w, etag=self.cache.etag_for(rel))
        self._finish(run, {"variant": fmt, "file": rel, "bytes": len(data), "src_bytes": st.st_size,
                           "secs": round(secs, 3), "timing": imaging.last_timing()})

    def _upgrade(self, run, j, st, key, row, data, fmt, secs):
        """Replace a promoted variant's file with the slower, smaller encode - in place (same name, same tier), so
        Caddy keeps serving one complete file or the other. Only if it is really smaller and the same format."""
        old = int(row.get("bytes") or 0)
        if fmt != row.get("fmt") or not old or len(data) >= old * 0.98:
            self._finish(run, {"upgrade": "kept", "bytes": len(data), "old": old})
            return
        tier = self.cache.tier_of(row["file"]) or "ephemeral"
        ext = row["file"].rsplit(".", 1)[-1]
        try:
            rel = self.cache.write_bytes(key, ext, "img", data, mtime=st.st_mtime, tier=tier)
        except OSError as e:   # Windows: the file is being served right now (open without FILE_SHARE_DELETE)
            self._fail(run, "replace: %s" % e, "busy", retry_in=120)
            return
        self.store.put_variant(key, mount=j["mount"], path=j["path"], src_size=st.st_size, src_mtime=st.st_mtime,
                               kind="img", fmt=fmt, spec=row["spec"], file=rel, bytes=len(data), src_bytes=st.st_size,
                               secs=round((row.get("secs") or 0) + secs, 3), beneficial=1, width=row.get("width"),
                               etag=self.cache.etag_for(rel), tier=tier)
        self._bg_count(upgrades=1)
        self.events.emit("variant.upgraded", "info", j["mount"], j["path"], old=old, new=len(data))
        self._finish(run, {"upgrade": "replaced", "bytes": len(data), "old": old})

    def _save_model(self):
        try:
            self.store.set_meta("cost_model", self.model.to_dict())
        except Exception as e:
            log("cost model not saved: %s" % e)

    # ------------------------------------------------------------ video jobs (7.6)
    def do_video(self, run):
        j = run.job
        src = self._source(run)
        if src is None:
            return
        _m, full, st = src
        conf = self.conf
        if not video.video_conf(conf)["enabled"]:
            self._finish(run, {"skipped": "disabled"})
            return
        jp = _job_params(j.get("params"))
        fmt = jp.get("want") if jp.get("want") in video.FORMATS else video.video_conf(conf)["format"]
        spec = jp.get("spec") or video.spec(fmt, conf)
        key = self.cache.key(j["mount"], j["path"], st.st_size, st.st_mtime, spec)
        if self._cached(key):
            self._finish(run, {"cached": True})
            return
        t0 = time.monotonic()
        tmp = None
        plan = None
        try:
            avail = video.available(conf, fmt)
            if not avail.get("ok"):
                raise video.VideoError("tool_missing", avail.get("error") or "ffmpeg missing")
            info = video.probe(full, conf)
            plan = video.plan(info, conf, avail, fmt)
            if plan is None:
                reason = video.skip_reason(info, conf, fmt)
                self._not_beneficial(key, j, st, spec, "vid")
                self._finish(run, {"variant": "orig", "reason": reason})
                return
            tmp = self.cache.tmp_path("." + fmt)
            r = video.transcode(full, tmp, plan, conf)
            kind = video.result_kind(r)
            if (kind == "encode_error" and plan.get("codec") == "h264_nvenc"
                    and video.video_conf(conf).get("encoder") == "auto" and avail.get("h264")):
                # A build may list NVENC even when the driver/GPU is unavailable at runtime.
                # Auto mode falls back to software instead of permanently failing the variant.
                cpu_avail = dict(avail, codec="h264")
                plan = video.plan(info, conf, cpu_avail, fmt)
                r = video.transcode(full, tmp, plan, conf)
                kind = video.result_kind(r)
            if kind:
                raise video.VideoError(kind, ((r.err or "").strip() if r is not None else "")[-300:])
            if not os.path.isfile(tmp):
                raise video.VideoError("encode_error", "ffmpeg produced no output")
            out = os.path.getsize(tmp)
            secs = time.monotonic() - t0
            if run.lost:
                return
            if not video.beneficial(st.st_size, out, conf):
                self._not_beneficial(key, j, st, spec, "vid", fmt=fmt, out_bytes=out, secs=secs)
                self._finish(run, {"variant": "orig", "reason": "not_beneficial", "bytes": out,
                                   "src_bytes": st.st_size, "secs": round(secs, 1)})
                return
            rel = self.cache.adopt(key, fmt, "vid", tmp)
            self.store.put_variant(key, mount=j["mount"], path=j["path"], src_size=st.st_size, src_mtime=st.st_mtime,
                                   kind="vid", fmt=fmt, spec=spec, file=rel, bytes=out, src_bytes=st.st_size,
                                   secs=round(secs, 3), beneficial=1)
            self._finish(run, {"variant": fmt, "file": rel, "bytes": out, "src_bytes": st.st_size,
                               "secs": round(secs, 1), "codec": plan.get("codec")})
        except video.VideoError as e:
            if e.kind == "tool_missing":   # no retry until the tools change (store.NO_RETRY / retry_failed)
                self.events.emit_every(TOOLS_EVERY, "tool.missing", "warning", key="ffmpeg", tool="ffmpeg",
                                       needed_for="video transcodes (%s variants)" % fmt.upper(), detail=e.detail[:200])
            # A driver/GPU can become available later. Do not record a permanent original-only
            # decision for a hardware initialization failure; retry_failed should be able to recover.
            hardware_failure = e.kind == "encode_error" and plan is not None and plan.get("codec") == "h264_nvenc"
            if self._fail(run, str(e), e.kind) == "failed" and e.kind in ("probe_error", "encode_error") and not hardware_failure:
                self._not_beneficial(key, j, st, spec, "vid", secs=time.monotonic() - t0)
        finally:
            if tmp:
                _rm(tmp)
                _rm(tmp + ".part")

    # ------------------------------------------------------------ keeper: leases + heartbeat
    def lease_beat(self, force=False):
        """Extend the leases of running jobs (every lease_s/3, at most 60 s); a refused beat marks the job lost."""
        lease_s = self.lease_s
        every = max(1.0, min(60.0, lease_s / 3.0))
        now = time.monotonic()
        for lane in self.lanes.values():
            run = lane.job
            if run is None or run.lost or (not force and now - run.beat < every):
                continue
            run.beat = now
            if not self.store.heartbeat(run.id, lease_s):
                run.lost = True
                log("job %s lost its lease (cancelled or re-leased)" % run.id)

    def heartbeat(self, stopping=False):
        lanes = {}
        for name, ln in self.lanes.items():
            run = ln.job
            lanes[name] = {"kinds": list(ln.kinds), "job": run.info() if run else None, "paused": ln.paused,
                           "done": ln.done, "failed": ln.failed}
        paused = next((v["paused"] for v in lanes.values() if v["paused"]), None)
        self.store.set_meta("worker_heartbeat", {"ts": time.time(), "pid": os.getpid(), "started": self.started,
                                                 "lanes": lanes, "paused": paused, "once": self.once,
                                                 "stopping": bool(stopping)})

    def _keeper(self):
        next_hb = time.monotonic() + HEARTBEAT_S
        while not self._stop.wait(1.0):
            try:
                self.lease_beat()
            except Exception as e:
                log("lease heartbeat: %s" % e)
            if time.monotonic() >= next_hb:
                next_hb = time.monotonic() + HEARTBEAT_S
                try:
                    self.heartbeat()
                except Exception as e:
                    log("heartbeat: %s" % e)

    # ------------------------------------------------------------ housekeeping
    def housekeeping(self, force=False):
        """Independent timers; each task is isolated so one failure cannot stop the others."""
        now = time.monotonic()
        for name, every, fn in (("tools", TOOLS_EVERY, self.check_tools),
                                ("requeue", REQUEUE_EVERY, self._requeue_expired),
                                ("evict", EVICT_EVERY, self.cache.maybe_evict),
                                ("prune", 3600, self._maybe_prune)):
            last = self._timers.get(name)
            if not force and last is not None and now - last < every:
                continue
            self._timers[name] = now
            try:
                fn()
            except Exception as e:
                log("housekeeping %s: %s: %s" % (name, e.__class__.__name__, e))

    def _housekeeper(self):
        while not self._stop.wait(HOUSEKEEP_S):
            self.housekeeping()

    def _requeue_expired(self):
        n = self.store.requeue_expired(int((self.conf.get("worker") or {}).get("max_attempts") or 3))
        if n:
            log("requeued %d job(s) with an expired lease" % n)
            self.events.emit("worker.requeued", "info", n=n)
        return n

    def _maybe_prune(self):
        last = self.store.get_meta("worker_prune")
        if isinstance(last, (int, float)) and time.time() - last < PRUNE_EVERY:
            return False
        self.store.prune()
        self.store.set_meta("worker_prune", time.time())
        return True

    def tools(self):
        if self._tools is None:
            self.check_tools()
        return self._tools

    def check_tools(self):
        """Discover the external tools (7.4), publish them in meta 'tools' and report missing ones (tool.missing,
        at most once per 10 min each)."""
        conf = self.conf
        found = sandbox.tools(conf, fresh=True)
        self._tools = found
        pdfium, pil = _pdfium_version(), _pillow()
        vc = video.video_conf(conf)
        vid = None
        if vc["enabled"] and found.get("ffmpeg") and found.get("ffprobe"):
            v = video.available(conf)
            vid = {k: v.get(k) for k in ("ok", "codec", "av1", "vp9", "opus", "h264", "h264_nvenc",
                                         "aac", "error")}
        sc, oc = conf.get("scan") or {}, conf.get("ocr") or {}
        engines = {"defender": ("mpcmdrun",), "clamav": ("clamscan", "clamdscan")}
        av = [e for e in sc.get("av_engines") or () if any(found.get(t) for t in engines.get(e, ()))]
        missing = {}
        if vc["enabled"]:
            for t in ("ffmpeg", "ffprobe"):
                if not found.get(t):
                    missing[t] = "video transcodes (WebM variants)"
            if vid is not None and not vid["ok"]:
                missing["ffmpeg-encoders"] = "video transcodes: %s" % (vid.get("error") or "no encoder")
        if not found.get("tesseract"):
            missing["tesseract"] = "OCR of images / scanned PDF pages" + (
                " (required: held as unscannable)" if oc.get("required", True) else " (skipped)")
        if not found.get("7z"):
            missing["7z"] = "rar / 7z / zst archives (held as unscannable)"
        if not av:
            missing["av"] = "antivirus scan (%s)" % ("required: held as unscannable" if sc.get("require_av", True)
                                                      else "skipped")
        if not pdfium:
            missing["pypdfium2"] = "PDF text (PDFs held as unscannable)"
        if not pil["avif"]:
            missing["pillow-avif"] = "AVIF variants"
        for name, why in missing.items():
            self.events.emit_every(TOOLS_EVERY, "tool.missing", "warning", key=name, tool=name, needed_for=why)
        info = {"ts": time.time(), "tools": found, "av": av, "pypdfium2": pdfium, "pillow": pil, "video": vid,
                "missing": sorted(missing)}
        prev = self.store.get_meta("tools")
        self.store.set_meta("tools", info)
        if vid is not None and vid["ok"] and not (isinstance(prev, dict) and (prev.get("video") or {}).get("ok")):
            # "no retry until the tools change" (7.4): ffmpeg just became usable, give failed transcodes a new chance
            n = self.store.retry_failed("video")
            if n:
                log("ffmpeg is available now: requeued %d failed video job(s)" % n)
                self.events.emit("worker.retry", "info", job_kind="video", n=n, reason="tools changed")
        return info


def main(argv=None):
    ap = argparse.ArgumentParser(prog="worker.py", description="Strata Media background worker (DESIGN.md 7)")
    ap.add_argument("--config", help="media.json to use (default: %s)" % config.CONF_PATH)
    ap.add_argument("--once", action="store_true", help="drain the claimable jobs, then exit")
    ap.add_argument("--lanes", default="scan,encode", help="comma-separated lanes to run (scan, encode)")
    a = ap.parse_args(argv)
    lanes = [x.strip().lower() for x in (a.lanes or "").split(",") if x.strip()]
    if not lanes or any(x not in LANES for x in lanes):
        ap.error("--lanes takes a comma-separated list of: %s" % ", ".join(LANES))
    conf = config.load(a.config)
    if not conf.get("enabled"):
        log("media.enabled is off - nothing to do")
        return 0
    lock = InstanceLock(os.path.join(os.path.dirname(conf["db"]), LOCK_NAME))
    if not lock.acquire():
        log("another worker holds %s - exiting" % lock.path)
        return 0
    try:
        if not breaker.set_process_priority("below_normal"):
            log("could not lower the process priority")
        w = Worker(a.config, lanes=tuple(dict.fromkeys(lanes)), once=a.once)

        def _sig(signum, frame):
            w.request_stop()
        for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
            sig = getattr(signal, name, None)
            if sig is not None:
                try:
                    signal.signal(sig, _sig)
                except (OSError, ValueError):
                    pass
        log("started (lanes %s%s, db %s)" % (",".join(w.lanes), ", once" if a.once else "", conf["db"]))
        rc = w.run()
        log("stopped")
        return rc
    finally:
        lock.release()


if __name__ == "__main__":
    sys.exit(main())
