"""Event log for Strata Media: bypasses, breaker trips, holds, missing tools, job failures ("log a failure + kind").

emit() runs on the hot path, so it never blocks on I/O and never raises: it appends to an in-memory deque and bumps
counters. A flusher thread drains the deque once a second into a JSONL file (event_log, rotated at 20 MB, 5 kept -
readable without the database) and into media.db (store.add_events) for the admin UI and the bridge's alerts.
If the database is busy the rows are retried on the next tick (bounded); the JSONL line is written once.
media.py and worker.py share the JSONL file: each flush opens, appends and closes it, and rotation first renames
the live file to a per-process name, so a concurrent rotation by the other process simply loses the race.
"""
import collections
import json
import os
import threading
import time

ROTATE_BYTES = 20 << 20
KEEP = 5
MAX_QUEUE = 20000     # unflushed events kept in memory; beyond that the oldest are dropped (and counted)
MAX_RETRY = 5000      # rows waiting for the database
RING = 200            # recent() buffer


class Events:
    def __init__(self, store, log_path, proc):
        self.store, self.log_path, self.proc = store, log_path, proc
        self._q = collections.deque(maxlen=MAX_QUEUE)
        self._ring = collections.deque(maxlen=RING)
        self._counts = collections.Counter()
        self._lock = threading.Lock()          # counters only, held for microseconds
        self._flush_lock = threading.Lock()
        self._retry = []
        self._last = {}                        # emit_every() throttle
        self._stop = threading.Event()
        self._thread = None
        self.dropped = self.written = self.errors = 0
        self.last_error = ""

    # ------------------------------------------------------------ producer side (any thread)
    def emit(self, kind, severity="warning", mount=None, path=None, **detail):
        try:
            row = {"ts": time.time(), "proc": self.proc, "kind": str(kind), "severity": severity,
                   "mount": mount, "path": path, "detail": detail}
            if len(self._q) >= MAX_QUEUE:
                self.dropped += 1
            self._q.append(row)
            self._ring.append(row)
            with self._lock:
                self._counts[row["kind"]] += 1
        except Exception:
            pass

    def emit_every(self, interval_s, kind, severity="warning", mount=None, path=None, key=None, **detail):
        """emit() at most once per interval_s for (kind, key) - e.g. tool.missing every 10 min. True if emitted."""
        try:
            k, now = (kind, key), time.monotonic()
            last = self._last.get(k)
            if last is not None and now - last < interval_s:
                return False
            self._last[k] = now
            self.emit(kind, severity, mount, path, **detail)
            return True
        except Exception:
            return False

    def counts(self):
        """Events emitted by this process since start, by kind."""
        with self._lock:
            return dict(self._counts)

    def recent(self, n=50):
        """The last n events, newest first."""
        rows = list(self._ring)[-max(0, int(n)):]
        return [dict(r) for r in reversed(rows)]

    def stats(self):
        return {"queued": len(self._q), "retry": len(self._retry), "dropped": self.dropped,
                "written": self.written, "errors": self.errors, "last_error": self.last_error}

    # ------------------------------------------------------------ flusher
    def start(self):
        if self._thread is None or not self._thread.is_alive():
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, name="media-events", daemon=True)
            self._thread.start()
        return self

    def stop(self, timeout=5):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)
        self.flush()

    def _run(self):
        while not self._stop.wait(1.0):
            self.flush()

    def flush(self):
        """Drain the queue now (the flusher calls this every second; also used at shutdown and in tests)."""
        with self._flush_lock:
            rows = []
            while True:
                try:
                    rows.append(self._q.popleft())
                except IndexError:
                    break
            if rows:
                self._write_jsonl(rows)
            pending, self._retry = self._retry + rows, []
            if not pending or self.store is None:
                return
            done = 0
            try:
                for i in range(0, len(pending), 500):
                    self.store.add_events(pending[i:i + 500])
                    done = i + 500
                self.written += len(pending)
            except Exception as e:
                self._fail("db", e)
                self.written += min(done, len(pending))
                self._retry = pending[done:][-MAX_RETRY:]

    def _fail(self, where, e):
        self.errors += 1
        self.last_error = "%s: %s: %s" % (where, e.__class__.__name__, e)

    def _write_jsonl(self, rows):
        if not self.log_path:
            return
        try:
            data = "".join(json.dumps(r, ensure_ascii=False, default=str, separators=(",", ":")) + "\n"
                           for r in rows).encode("utf-8", "replace")
            os.makedirs(os.path.dirname(os.path.abspath(self.log_path)), exist_ok=True)
            try:
                size = os.path.getsize(self.log_path)
            except OSError:
                size = 0
            if size and size + len(data) > ROTATE_BYTES:
                self._rotate()
            with open(self.log_path, "ab") as f:
                f.write(data)
        except Exception as e:
            self._fail("jsonl", e)

    def _rotate(self):
        p = self.log_path
        tmp = "%s.rot-%d" % (p, os.getpid())
        try:
            os.replace(p, tmp)       # fails if the other process rotated first or has the file open: retry later
        except OSError:
            return
        for i in range(KEEP - 1, 0, -1):
            try:
                os.replace("%s.%d" % (p, i), "%s.%d" % (p, i + 1))
            except OSError:
                pass
        try:
            os.replace(tmp, p + ".1")
        except OSError as e:
            self._fail("rotate", e)
