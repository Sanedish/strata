"""Resource monitor, circuit breaker and admission control for Strata Media (DESIGN.md section 8).

The VM is small (6 vCPU, 8 GB) and also runs Caddy and cloudflared, which must always win. On-the-fly encoding
is optional work: a Breaker admits it only while the machine has headroom and one of a few slots is free, and
otherwise raises Bypass(kind, detail) so the caller logs "bypass.<kind>" and serves the untouched original.

  closed    -> open       cpu_ewma >= cpu_trip for cpu_trip_seconds | mem < mem_min_mb | waiters >= max_waiters |
                          p90 of the last 20 slot waits >= wait_trip_ms | error_trip failures or slow_trip slow
                          encodes in a row
  open      -> half_open  cooldown over AND cpu_ewma < cpu_resume AND memory fine (hysteresis)
  half_open -> closed     the single trial request succeeds (cooldown resets)
  half_open -> open       the trial fails or is slow (cooldown doubles, up to cooldown_max_s)

Everything time-based uses the injectable `clock`, so tests drive the state machine with a fake clock and a
fake monitor. Slot waits are real waits (threading.Condition) measured with perf_counter: on Python 3.12 /
Windows time.monotonic is GetTickCount64 (15.6 ms steps), too coarse for a p90 of millisecond waits.
"""
import collections
import contextlib
import ctypes
import math
import os
import sys
import threading
import time

DEFAULTS = {"cpu_trip": 85, "cpu_resume": 70, "cpu_trip_seconds": 3, "mem_min_mb": 768, "slots": 2,
            "max_waiters": 6, "wait_timeout_ms": 1500, "wait_trip_ms": 1200, "error_trip": 5, "slow_trip": 3,
            "cooldown_s": 15, "cooldown_max_s": 300}
WAIT_SAMPLES = 20        # slot waits kept for the p90
WAIT_MIN_SAMPLES = 5     # no p90 trip on fewer samples than this

if sys.platform == "win32":
    from ctypes import wintypes
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)   # private instance: our argtypes never leak elsewhere
    _k32.GetCurrentThread.restype = wintypes.HANDLE
    _k32.GetThreadPriority.argtypes = [wintypes.HANDLE]
    _k32.GetThreadPriority.restype = ctypes.c_int
    _k32.SetThreadPriority.argtypes = [wintypes.HANDLE, ctypes.c_int]
    _k32.SetThreadPriority.restype = wintypes.BOOL
    _k32.GetCurrentProcess.restype = wintypes.HANDLE
    _k32.SetPriorityClass.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _k32.SetPriorityClass.restype = wintypes.BOOL
    _k32.GetSystemTimes.argtypes = [ctypes.c_void_p] * 3
    _k32.GetSystemTimes.restype = wintypes.BOOL
    _k32.GlobalMemoryStatusEx.argtypes = [ctypes.c_void_p]
    _k32.GlobalMemoryStatusEx.restype = wintypes.BOOL
else:
    _k32 = None

THREAD_PRIORITY_BELOW_NORMAL = -1
THREAD_PRIORITY_ERROR_RETURN = 0x7FFFFFFF
PRIORITY_CLASS = {"idle": 0x40, "below_normal": 0x4000, "normal": 0x20}


# ---------------------------------------------------------------- sampling

class _FILETIME(ctypes.Structure):
    _fields_ = [("lo", ctypes.c_uint32), ("hi", ctypes.c_uint32)]


class _MEMSTAT(ctypes.Structure):
    _fields_ = [("dwLength", ctypes.c_uint32), ("dwMemoryLoad", ctypes.c_uint32),
                ("ullTotalPhys", ctypes.c_uint64), ("ullAvailPhys", ctypes.c_uint64),
                ("ullTotalPageFile", ctypes.c_uint64), ("ullAvailPageFile", ctypes.c_uint64),
                ("ullTotalVirtual", ctypes.c_uint64), ("ullAvailVirtual", ctypes.c_uint64),
                ("ullAvailExtendedVirtual", ctypes.c_uint64)]


class SystemSampler:
    """() -> (cpu % since the previous call or None, available MB or None, memory load % or None).
    Windows: GetSystemTimes (kernel time includes idle, as in core.host_sample) + GlobalMemoryStatusEx.
    Elsewhere a psutil-free fallback: load average per CPU and /proc/meminfo."""

    def __init__(self):
        self.prev = None

    def __call__(self):
        if _k32 is None:
            return self._posix()
        idle, kern, user = _FILETIME(), _FILETIME(), _FILETIME()
        cpu = None
        if _k32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kern), ctypes.byref(user)):
            ft = lambda f: (f.hi << 32) | f.lo
            cur = (ft(idle), ft(kern) + ft(user))
            if self.prev and cur[1] > self.prev[1]:
                cpu = max(0.0, min(100.0, 100.0 * (1 - (cur[0] - self.prev[0]) / (cur[1] - self.prev[1]))))
            self.prev = cur
        m = _MEMSTAT()
        m.dwLength = ctypes.sizeof(_MEMSTAT)
        if not _k32.GlobalMemoryStatusEx(ctypes.byref(m)):
            return cpu, None, None
        return cpu, m.ullAvailPhys / 1048576.0, float(m.dwMemoryLoad)

    @staticmethod
    def _posix():
        try:
            cpu = min(100.0, os.getloadavg()[0] / (os.cpu_count() or 1) * 100.0)
        except (AttributeError, OSError):
            cpu = 0.0
        avail = pct = None
        try:
            info = {}
            with open("/proc/meminfo") as f:
                for line in f:
                    k, v = line.split(":", 1)
                    info[k] = int(v.split()[0]) / 1024.0
            avail = info.get("MemAvailable")
            if avail is not None and info.get("MemTotal"):
                pct = 100.0 * (1 - avail / info["MemTotal"])
        except (OSError, ValueError):
            pass
        return cpu, avail, pct


class Monitor(threading.Thread):
    """Samples the machine every `interval` s; cpu_ewma is an exponential average with time constant `tau` s."""
    daemon = True

    def __init__(self, interval=1.0, tau=5.0, sampler=None, clock=time.monotonic):
        super().__init__(name="media-monitor")
        self.interval, self.tau, self.clock = interval, tau, clock
        self.sampler = sampler or SystemSampler()
        self._lock = threading.Lock()
        self._snap = {"cpu": None, "cpu_ewma": None, "mem_avail_mb": None, "mem_pct": None, "ts": None}
        self._at = None
        self._listeners = []
        self._halt = threading.Event()

    def add_listener(self, fn):
        """fn(snapshot) after every sample (the Breaker uses it so 'sustained' CPU is judged every second)."""
        self._listeners.append(fn)

    def snapshot(self):
        with self._lock:
            return dict(self._snap)

    def tick(self):
        """Take one sample now (the thread calls this every interval; tests call it directly)."""
        try:
            cpu, avail, pct = self.sampler()
        except Exception:
            cpu = avail = pct = None
        now = self.clock()
        with self._lock:
            s = self._snap
            if cpu is not None:
                if s["cpu_ewma"] is None or self._at is None:
                    s["cpu_ewma"] = float(cpu)
                else:
                    a = 1.0 - math.exp(-max(0.0, now - self._at) / self.tau) if self.tau > 0 else 1.0
                    s["cpu_ewma"] += a * (cpu - s["cpu_ewma"])
                self._at = now
            elif self._at is None:
                self._at = now
            s.update(cpu=cpu, mem_avail_mb=avail, mem_pct=pct, ts=time.time())
            snap = dict(s)
        for fn in list(self._listeners):
            try:
                fn(snap)
            except Exception:
                pass
        return snap

    def run(self):
        while not self._halt.is_set():
            self.tick()
            self._halt.wait(self.interval)

    def stop(self):
        self._halt.set()


# ---------------------------------------------------------------- breaker

class Bypass(Exception):
    """Admission refused: kind is breaker_open (detail cpu|mem|queue|wait|errors|slow|forced), queue_full or
    queue_timeout. The caller emits event bypass.<kind> and serves the original."""

    def __init__(self, kind, detail=""):
        super().__init__("%s%s" % (kind, "(%s)" % detail if detail else ""))
        self.kind, self.detail = kind, detail


class Ticket:
    """Yielded by admit(). Set ok=False to record a failure without raising, or slow=True/False to override the
    automatic slow rule (secs > 2 x est and > 3 s). After the block: secs, slow, wait_ms are filled in."""

    def __init__(self, est, wait_ms, trial):
        self.est, self.wait_ms, self.trial = est, wait_ms, trial
        self.ok, self.slow, self.secs = True, None, None


def _p(values, q):
    if not values:
        return None
    s = sorted(values)
    return s[max(0, min(len(s) - 1, int(math.ceil(q * len(s))) - 1))]


class Breaker:
    def __init__(self, name, monitor, conf, events=None, clock=time.monotonic):
        self.name, self.monitor, self.events, self.clock = name, monitor, events, clock
        self.c = dict(DEFAULTS)
        self.configure(conf)
        self._cond = threading.Condition(threading.Lock())
        self.state, self.reason = "closed", ""
        self.open_until = 0.0
        self.cooldown = self.c["cooldown_s"]
        self.consecutive = 0          # trips since the last successful close (drives the cooldown doubling)
        self.trips = 0
        self.forced, self.forced_until = None, None
        self.hot_since = None
        self.trial = False            # half-open trial in flight
        self.busy = self.waiting = 0
        self.waits = collections.deque(maxlen=WAIT_SAMPLES)
        self.error_streak = self.slow_streak = 0
        self.bypasses = collections.Counter()
        self.encodes = self.failures = 0
        self._left_closed_at = None   # for open-seconds accounting
        self._win = self._new_window()
        if hasattr(monitor, "add_listener"):
            monitor.add_listener(self._observe)

    def configure(self, conf):
        """Apply thresholds (the media "breaker" section, or the whole media config). Safe to call live."""
        conf = conf or {}
        if isinstance(conf.get("breaker"), dict):
            conf = conf["breaker"]
        self.c.update({k: v for k, v in conf.items() if k in DEFAULTS})

    # ------------------------------------------------------------ state machine (lock held)
    def _new_window(self):
        return {"since": self.clock(), "open_s": 0.0, "trips": 0, "waiters_max": 0, "waits": [], "encodes": 0,
                "secs": [], "bypass": collections.Counter()}

    def _emit(self, kind, severity="warning", **detail):
        if self.events is not None:
            try:
                self.events.emit(kind, severity, breaker=self.name, **detail)
            except Exception:
                pass

    def _set(self, state, reason, now):
        if state == self.state:
            self.reason = reason
            return
        if self.state == "closed":
            self._left_closed_at = now
        elif state == "closed" and self._left_closed_at is not None:
            self._win["open_s"] += max(0.0, now - max(self._left_closed_at, self._win["since"]))
            self._left_closed_at = None
        self.state, self.reason = state, reason

    def _trip(self, reason, now):
        if self.state == "open" or self.forced == "closed":
            return
        self.consecutive += 1
        self.trips += 1
        self._win["trips"] += 1
        self.cooldown = min(self.c["cooldown_s"] * 2 ** min(self.consecutive - 1, 20), self.c["cooldown_max_s"])
        self.open_until = now + self.cooldown
        self.trial = False
        self._set("open", reason, now)
        self._emit("breaker.trip", "warning", reason=reason, cooldown=self.cooldown, consecutive=self.consecutive)

    def _close(self, now):
        self._set("closed", "", now)
        self.consecutive = 0
        self.cooldown = self.c["cooldown_s"]
        self.error_streak = self.slow_streak = 0
        self.waits.clear()
        self.trial = False
        self._emit("breaker.close", "info")

    def _evaluate(self, now, snap=None):
        c = self.c
        if self.forced and self.forced_until is not None and now >= self.forced_until:
            was, self.forced, self.forced_until = self.forced, None, None
            if was == "open":
                self._close(now)
        if snap is None:
            try:
                snap = self.monitor.snapshot() if self.monitor is not None else {}
            except Exception:
                snap = {}
        ewma, mem = snap.get("cpu_ewma"), snap.get("mem_avail_mb")
        if ewma is not None and ewma >= c["cpu_trip"]:
            if self.hot_since is None:
                self.hot_since = now
        else:
            self.hot_since = None
        mem_low = mem is not None and mem < c["mem_min_mb"]
        if self.forced:
            return
        if self.state in ("closed", "half_open"):
            if mem_low:
                self._trip("mem", now)
            elif self.hot_since is not None and now - self.hot_since >= c["cpu_trip_seconds"]:
                self._trip("cpu", now)
        if self.state == "open" and now >= self.open_until:
            if not mem_low and (ewma is None or ewma < c["cpu_resume"]):
                self.trial = False
                self._set("half_open", self.reason, now)
                self._emit("breaker.half_open", "info", reason=self.reason)

    def _observe(self, snap):
        with self._cond:
            self._evaluate(self.clock(), snap)

    def _bypass(self, kind, detail=""):
        self.bypasses[kind] += 1
        self._win["bypass"][kind] += 1
        return Bypass(kind, detail)

    def _note_wait(self, ms, now):
        self.waits.append(ms)
        self._win["waits"].append(ms)
        # only a closed breaker trips on queueing: in half_open the single trial decides (the waits that caused
        # the last trip are still in the window and would re-open it before the trial could prove anything)
        if (self.state == "closed" and len(self.waits) >= WAIT_MIN_SAMPLES
                and _p(self.waits, 0.9) >= self.c["wait_trip_ms"]):
            self._trip("wait", now)

    # ------------------------------------------------------------ public API
    def check(self):
        """Advance the state machine; returns the state ("closed" | "open" | "half_open")."""
        with self._cond:
            self._evaluate(self.clock())
            return self.state

    def trip(self, reason):
        with self._cond:
            self._trip(reason, self.clock())

    @contextlib.contextmanager
    def admit(self, est_seconds=0.0):
        """Reserve a slot for one encode, or raise Bypass. Records duration and outcome on exit."""
        c = self.c
        with self._cond:
            now = self.clock()
            self._evaluate(now)
            if self.state == "open":
                raise self._bypass("breaker_open", self.reason)
            trial = False
            if self.state == "half_open":
                if self.trial:
                    raise self._bypass("breaker_open", self.reason)
                self.trial = trial = True
            t0 = time.perf_counter()
            if self.busy >= c["slots"]:
                if self.waiting >= c["max_waiters"]:
                    if trial:
                        self.trial = False
                    self._trip("queue", now)
                    raise self._bypass("queue_full", "%d waiting" % self.waiting)
                self.waiting += 1
                self._win["waiters_max"] = max(self._win["waiters_max"], self.waiting)
                deadline = t0 + c["wait_timeout_ms"] / 1000.0
                try:
                    while self.busy >= c["slots"]:
                        left = deadline - time.perf_counter()
                        if left <= 0:
                            break
                        self._cond.wait(left)
                finally:
                    self.waiting -= 1
                waited = (time.perf_counter() - t0) * 1000.0
                if self.busy >= c["slots"]:
                    if trial:
                        self.trial = False
                    self._note_wait(waited, self.clock())
                    raise self._bypass("queue_timeout", "%d ms" % waited)
                if self.state == "open" and self.reason in ("cpu", "mem", "forced"):
                    self._note_wait(waited, self.clock())   # the machine got hot while we queued: shed it
                    raise self._bypass("breaker_open", self.reason)
            else:
                waited = (time.perf_counter() - t0) * 1000.0
            self.busy += 1
            self._note_wait(waited, self.clock())
            start = self.clock()
        ticket = Ticket(est_seconds, waited, trial)
        outcome = True
        try:
            yield ticket
        except Bypass:
            outcome = None                 # nested refusal: not an encode failure
            raise
        except BaseException:
            outcome = False
            raise
        finally:
            secs = max(0.0, self.clock() - start)
            with self._cond:
                self.busy -= 1
                self._cond.notify()
            est = float(est_seconds or 0)
            if ticket.slow is None:
                ticket.slow = bool(est > 0 and secs > 2 * est and secs > 3)
            ticket.secs = secs
            if outcome is None:
                if trial:
                    with self._cond:
                        self.trial = False
            else:
                self._record(outcome and ticket.ok, secs, ticket.slow, trial)

    def record(self, ok, secs, slow=False):
        """Outcome of work not run under admit() (admit() records its own)."""
        self._record(ok, secs, slow, False)

    def _record(self, ok, secs, slow, trial):
        with self._cond:
            now = self.clock()
            self.encodes += 1
            self._win["encodes"] += 1
            self._win["secs"].append(secs)
            if ok:
                self.error_streak = 0
            else:
                self.error_streak += 1
                self.failures += 1
            if slow:
                self.slow_streak += 1
            elif ok:
                self.slow_streak = 0
            if trial:
                self.trial = False
                if self.state == "half_open" and not self.forced:
                    if ok and not slow:
                        self._close(now)
                    else:
                        self._trip("errors" if not ok else "slow", now)   # consecutive + 1: cooldown doubles
                    return
            if self.state == "closed":
                if self.error_streak >= self.c["error_trip"]:
                    self._trip("errors", now)
                elif self.slow_streak >= self.c["slow_trip"]:
                    self._trip("slow", now)

    def force(self, state, seconds=None):
        """Maintenance switch. "open": bypass everything (for `seconds`, else until "auto"); "closed": reset now
        and, with `seconds`, ignore trips for that long; "auto": back to automatic."""
        with self._cond:
            now = self.clock()
            until = now + float(seconds) if seconds else None
            if state == "open":
                self.forced, self.forced_until = "open", until
                self.open_until = until if until is not None else float("inf")
                self.trial = False
                self._set("open", "forced", now)
            elif state == "closed":
                self.forced, self.forced_until = ("closed", until) if until is not None else (None, None)
                self._close(now)
            elif state == "auto":
                was, self.forced, self.forced_until = self.forced, None, None
                if was == "open" or self.reason == "forced":
                    self._close(now)
            else:
                raise ValueError("state must be open, closed or auto")
            self._emit("breaker.force", "info", state=state, seconds=seconds)

    def status(self):
        with self._cond:
            now = self.clock()
            self._evaluate(now)
            try:
                snap = self.monitor.snapshot() if self.monitor is not None else {}
            except Exception:
                snap = {}
            open_for = 0.0
            if self.state == "open":   # None = open until someone says "auto"
                open_for = None if self.open_until == float("inf") else max(0.0, self.open_until - now)
            return {"name": self.name, "state": self.state, "reason": self.reason, "forced": self.forced,
                    "forced_for": None if self.forced_until is None else max(0.0, self.forced_until - now),
                    "open_for": open_for,
                    "cooldown": self.cooldown, "consecutive_trips": self.consecutive, "trips": self.trips,
                    "slots": self.c["slots"], "busy": self.busy, "waiters": self.waiting,
                    "wait_p90_ms": _p(self.waits, 0.9), "error_streak": self.error_streak,
                    "slow_streak": self.slow_streak, "encodes": self.encodes, "failures": self.failures,
                    "bypass": dict(self.bypasses), "monitor": snap}

    def window(self, reset=True):
        """Aggregates since the last call, for the per-minute sample: open_s, trips, waiters_max, wait_p90_ms,
        encodes, encode_p95_s, bypass {kind: n}."""
        with self._cond:
            now = self.clock()
            w = self._win
            open_s = w["open_s"]
            if self.state != "closed" and self._left_closed_at is not None:
                open_s += max(0.0, now - max(self._left_closed_at, w["since"]))
            out = {"secs": max(0.0, now - w["since"]), "open_s": round(open_s, 3), "trips": w["trips"],
                   "waiters_max": w["waiters_max"], "wait_p90_ms": _p(w["waits"], 0.9), "encodes": w["encodes"],
                   "encode_p95_s": _p(w["secs"], 0.95), "bypass": dict(w["bypass"])}
            if reset:
                self._win = self._new_window()
                self._win["since"] = now
            return out


# ---------------------------------------------------------------- priorities

@contextlib.contextmanager
def below_normal_thread(level=THREAD_PRIORITY_BELOW_NORMAL):
    """Run the block at THREAD_PRIORITY_BELOW_NORMAL so Caddy and cloudflared win the CPU; restores after.
    (Only this thread: encoder worker threads a codec library starts get the process' normal priority.)"""
    h = old = None
    if _k32 is not None:
        try:
            h = _k32.GetCurrentThread()
            old = _k32.GetThreadPriority(h)
            if old == THREAD_PRIORITY_ERROR_RETURN or not _k32.SetThreadPriority(h, level):
                old = None
        except Exception:
            old = None
    try:
        yield
    finally:
        if old is not None:
            try:
                _k32.SetThreadPriority(h, old)
            except Exception:
                pass


def set_process_priority(level):
    """"below_normal" | "idle" | "normal" for the whole process. Returns True on success."""
    if level not in PRIORITY_CLASS:
        raise ValueError("level must be one of %s" % ", ".join(PRIORITY_CLASS))
    try:
        if _k32 is not None:
            return bool(_k32.SetPriorityClass(_k32.GetCurrentProcess(), PRIORITY_CLASS[level]))
        target = {"idle": 19, "below_normal": 10, "normal": 0}[level]
        os.setpriority(os.PRIO_PROCESS, 0, target)
        return True
    except Exception:
        return False
