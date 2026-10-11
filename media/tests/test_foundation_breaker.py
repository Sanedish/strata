"""breaker.py: state machine with a fake clock + fake monitor (no multi-second sleeps), admission, Monitor EWMA,
thread priority helper."""
import ctypes
import math
import os
import sys
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
MEDIA = os.path.dirname(HERE)
if MEDIA not in sys.path:
    sys.path.insert(0, MEDIA)

import breaker  # noqa: E402
from breaker import Breaker, Bypass, Monitor  # noqa: E402


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


class FakeMonitor:
    def __init__(self):
        self.snap = {"cpu": 10.0, "cpu_ewma": 10.0, "mem_avail_mb": 4000.0, "mem_pct": 50.0, "ts": 0}

    def snapshot(self):
        return dict(self.snap)

    def set(self, cpu=None, mem=None):
        if cpu is not None:
            self.snap.update(cpu=cpu, cpu_ewma=cpu)
        if mem is not None:
            self.snap["mem_avail_mb"] = mem


class FakeEvents:
    def __init__(self):
        self.rows = []

    def emit(self, kind, severity="warning", mount=None, path=None, **detail):
        self.rows.append((kind, detail))

    def kinds(self):
        return [k for k, _ in self.rows]


class BreakerCase(unittest.TestCase):
    conf = {}

    def setUp(self):
        self.clock = Clock()
        self.mon = FakeMonitor()
        self.ev = FakeEvents()
        self.b = Breaker("encode", self.mon, dict(breaker.DEFAULTS, **self.conf), self.ev, clock=self.clock)

    def at(self, cpu=None, mem=None, advance=0.0):
        self.clock.advance(advance)
        self.mon.set(cpu, mem)
        return self.b.check()

    def assertBypass(self, kind, detail=None):
        with self.assertRaises(Bypass) as cm:
            with self.b.admit(0.5):
                self.fail("admitted")
        self.assertEqual(cm.exception.kind, kind)
        if detail is not None:
            self.assertEqual(cm.exception.detail, detail)
        return cm.exception

    def succeed(self, secs=0.1, est=1.0):
        with self.b.admit(est) as t:
            self.clock.advance(secs)
        return t

    def failing(self):
        with self.assertRaises(RuntimeError):
            with self.b.admit(1.0):
                raise RuntimeError("decode error")


class StateMachineTest(BreakerCase):
    def test_cpu_sustained_trips(self):
        self.assertEqual(self.at(cpu=90), "closed")
        self.assertEqual(self.at(advance=1), "closed")
        self.assertEqual(self.at(advance=1), "closed")
        self.assertEqual(self.at(advance=0.99), "closed")
        self.assertEqual(self.at(advance=0.01), "open")                     # 3 s continuously >= 85
        self.assertEqual(self.b.reason, "cpu")
        e = self.assertBypass("breaker_open", "cpu")
        self.assertEqual(str(e), "breaker_open(cpu)")
        self.assertIn("breaker.trip", self.ev.kinds())
        self.assertEqual(self.b.status()["bypass"], {"breaker_open": 1})

    def test_short_spike_does_not_trip(self):
        for _ in range(3):
            self.assertEqual(self.at(cpu=95, advance=1), "closed")          # 0, 1, 2 s hot
        self.assertEqual(self.at(cpu=50, advance=0.5), "closed")            # dips below: streak resets
        for _ in range(3):
            self.assertEqual(self.at(cpu=95, advance=0.9), "closed")        # hot again for only 2.7 s
        self.assertEqual(self.at(cpu=84.9, advance=1), "closed")
        self.succeed()
        self.assertEqual(self.b.trips, 0)

    def test_memory_trip_and_recovery(self):
        self.assertEqual(self.at(mem=700), "open")
        self.assertEqual(self.b.reason, "mem")
        self.assertEqual(self.at(advance=60), "open")                       # cooldown over, memory still low
        self.assertEqual(self.at(mem=900), "half_open")
        self.succeed()
        self.assertEqual(self.b.state, "closed")

    def test_cooldown_doubling_half_open_and_reset(self):
        self.b.trip("cpu")
        self.assertEqual((self.b.state, self.b.cooldown), ("open", 15))
        self.mon.set(cpu=40)
        self.assertEqual(self.at(advance=14.9), "open")
        self.assertEqual(self.at(advance=0.1), "half_open")
        self.assertIn("breaker.half_open", self.ev.kinds())
        self.failing()                                                      # trial fails: re-open, x2
        self.assertEqual((self.b.state, self.b.cooldown, self.b.consecutive), ("open", 30, 2))
        self.assertEqual(self.at(advance=29), "open")
        self.assertEqual(self.at(advance=1), "half_open")
        with self.b.admit(1.0):                                             # slow trial (5 s > 2 x 1 s, > 3 s)
            self.clock.advance(5)
        self.assertEqual((self.b.state, self.b.cooldown, self.b.reason), ("open", 60, "slow"))
        self.assertEqual(self.at(advance=60), "half_open")
        t = self.succeed()
        self.assertFalse(t.slow)
        self.assertEqual((self.b.state, self.b.cooldown, self.b.consecutive), ("closed", 15, 0))
        self.assertIn("breaker.close", self.ev.kinds())
        self.b.trip("errors")                                               # after a good close: 15 s again
        self.assertEqual(self.b.cooldown, 15)

    def test_cooldown_is_capped(self):
        for _ in range(12):
            self.b.trip("cpu")
            self.mon.set(cpu=10)
            self.at(advance=self.b.cooldown)
            self.assertEqual(self.b.state, "half_open")
            self.failing()
        self.assertEqual(self.b.cooldown, 300)

    def test_half_open_admits_exactly_one(self):
        self.b.trip("wait")
        self.at(cpu=10, advance=15)
        self.assertEqual(self.b.state, "half_open")
        trial = self.b.admit(1.0)
        ticket = trial.__enter__()
        self.assertTrue(ticket.trial)
        self.assertBypass("breaker_open", "wait")                          # a second request meanwhile
        self.assertBypass("breaker_open", "wait")
        self.clock.advance(0.2)
        trial.__exit__(None, None, None)
        self.assertEqual(self.b.state, "closed")
        self.succeed()                                                      # and now everyone again
        self.succeed()

    def test_resume_hysteresis(self):
        self.at(cpu=90)
        self.at(advance=3)
        self.assertEqual(self.b.state, "open")
        self.assertEqual(self.at(cpu=80, advance=15), "open")               # below trip, above resume
        self.assertEqual(self.at(cpu=70, advance=100), "open")              # resume needs < 70
        self.assertEqual(self.at(cpu=69.9, advance=1), "half_open")

    def test_hot_half_open_trips_again(self):
        self.b.trip("cpu")
        self.at(cpu=10, advance=15)
        self.assertEqual(self.b.state, "half_open")
        self.at(cpu=95)
        self.assertEqual(self.at(advance=3), "open")
        self.assertEqual(self.b.cooldown, 30)

    def test_error_streak(self):
        for _ in range(4):
            self.failing()
        self.succeed()                                                      # a success resets the streak
        for _ in range(4):
            self.failing()
        self.assertEqual(self.b.state, "closed")
        self.failing()
        self.assertEqual((self.b.state, self.b.reason), ("open", "errors"))
        self.assertBypass("breaker_open", "errors")

    def test_ticket_ok_false_counts_as_failure(self):
        for _ in range(5):
            with self.b.admit(1.0) as t:
                t.ok = False
        self.assertEqual((self.b.state, self.b.reason), ("open", "errors"))

    def test_slow_streak_and_override(self):
        for _ in range(2):
            t = self.succeed(secs=4.0, est=1.0)
            self.assertTrue(t.slow)
        with self.b.admit(1.0) as t:                                        # caller knows better
            self.clock.advance(10)
            t.slow = False
        self.assertEqual(self.b.slow_streak, 0)
        for _ in range(2):
            self.succeed(secs=2.5, est=1.0)                                 # > 2 x est but not > 3 s: fine
        self.assertEqual(self.b.slow_streak, 0)
        for _ in range(2):
            self.succeed(secs=10, est=0)                                    # no estimate: never "slow"
        for _ in range(3):
            self.succeed(secs=7, est=3.0)
        self.assertEqual((self.b.state, self.b.reason), ("open", "slow"))

    def test_record_outside_admit(self):
        for _ in range(3):
            self.b.record(True, 9.0, slow=True)
        self.assertEqual((self.b.state, self.b.reason), ("open", "slow"))

    def test_force(self):
        self.b.force("open", 60)
        self.assertBypass("breaker_open", "forced")
        st = self.b.status()
        self.assertEqual((st["forced"], st["open_for"], st["forced_for"]), ("open", 60, 60))
        self.assertEqual(self.at(advance=59), "open")
        self.assertEqual(self.at(advance=2), "closed")
        self.b.force("open")                                                # until "auto"
        self.assertEqual(self.at(advance=10_000), "open")
        self.assertIsNone(self.b.status()["open_for"])
        self.b.force("auto")
        self.assertEqual(self.b.check(), "closed")
        self.succeed()
        self.b.force("closed", 30)                                          # maintenance: ignore trips
        self.at(cpu=99)
        self.assertEqual(self.at(advance=10), "closed")
        self.assertEqual(self.at(mem=100), "closed")
        self.assertEqual(self.at(advance=19), "closed")                     # t+29: still inside the window
        self.assertEqual(self.at(advance=2), "open")                        # t+31: over, low memory trips at once
        self.assertEqual(self.b.reason, "mem")                              # (mem has no sustain rule, DESIGN 8)
        with self.assertRaises(ValueError):
            self.b.force("half_open")
        self.assertIn("breaker.force", self.ev.kinds())

    def test_status_and_window(self):
        st = self.b.status()
        for k in ("name", "state", "reason", "forced", "open_for", "cooldown", "consecutive_trips", "trips", "slots",
                  "busy", "waiters", "wait_p90_ms", "error_streak", "slow_streak", "encodes", "bypass", "monitor"):
            self.assertIn(k, st)
        self.assertEqual(st["monitor"]["cpu_ewma"], 10.0)
        self.succeed(secs=1.0)
        self.succeed(secs=3.0)
        self.b.trip("cpu")
        self.assertBypass("breaker_open")
        self.clock.advance(10)
        self.assertEqual(self.b.status()["open_for"], 5)
        w = self.b.window()
        self.assertEqual((w["trips"], w["encodes"], w["open_s"], w["bypass"]), (1, 2, 10, {"breaker_open": 1}))
        self.assertEqual(w["encode_p95_s"], 3.0)
        self.clock.advance(5)
        self.mon.set(cpu=10)
        self.b.check()                                                      # half_open (still not closed)
        self.succeed(secs=0.5)                                              # trial closes it
        self.clock.advance(100)
        w = self.b.window()
        self.assertEqual((w["trips"], w["open_s"], w["encodes"]), (0, 5.5, 1))


class AdmissionTest(BreakerCase):
    conf = {"slots": 1, "max_waiters": 1, "wait_timeout_ms": 5000}

    def hold_slot(self):
        """A thread that owns the only slot until release is set."""
        entered, release = threading.Event(), threading.Event()

        def run():
            with self.b.admit(1.0):
                entered.set()
                release.wait(20)
        t = threading.Thread(target=run, daemon=True)
        t.start()
        self.assertTrue(entered.wait(5))
        return t, release

    def wait_for(self, cond, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if cond():
                return True
            time.sleep(0.005)
        return False

    def test_queue_full_trips(self):
        holder, release = self.hold_slot()
        waited = []

        def waiter():
            with self.b.admit(1.0) as t:
                waited.append(t.wait_ms)
        w = threading.Thread(target=waiter, daemon=True)
        w.start()
        self.assertTrue(self.wait_for(lambda: self.b.waiting == 1))
        self.assertBypass("queue_full")                                     # 1 waiting = max_waiters
        self.assertEqual((self.b.state, self.b.reason), ("open", "queue"))
        self.assertBypass("breaker_open", "queue")
        release.set()                                                       # the queued one still runs
        holder.join(5)
        w.join(5)
        self.assertEqual(len(waited), 1)
        self.assertGreater(waited[0], 0)
        self.assertEqual(self.b.busy, 0)
        self.assertEqual(self.b.status()["bypass"], {"queue_full": 1, "breaker_open": 1})


class TimeoutTest(BreakerCase):
    conf = {"slots": 1, "max_waiters": 10, "wait_timeout_ms": 40, "wait_trip_ms": 30}

    def test_queue_timeout_then_wait_p90_trip(self):
        entered, release = threading.Event(), threading.Event()

        def run():
            with self.b.admit(1.0):
                entered.set()
                release.wait(20)
        t = threading.Thread(target=run, daemon=True)
        t.start()
        self.assertTrue(entered.wait(5))
        t0 = time.perf_counter()                                           # monotonic ticks 15.6 ms on 3.12/Win
        e = self.assertBypass("queue_timeout")
        self.assertGreaterEqual(time.perf_counter() - t0, 0.035)
        self.assertTrue(e.detail.endswith("ms"))
        n = 1
        while self.b.state == "closed" and n < 10:                         # every timeout is a >= 40 ms wait
            self.assertBypass("queue_timeout")
            n += 1
        self.assertEqual((self.b.state, self.b.reason), ("open", "wait"))
        self.assertLessEqual(n, breaker.WAIT_MIN_SAMPLES)
        self.assertGreaterEqual(self.b.status()["wait_p90_ms"], 30)
        self.assertBypass("breaker_open", "wait")
        release.set()
        t.join(5)

    def test_p90_ignores_rare_waits(self):
        for _ in range(19):
            self.b._note_wait(0.0, self.clock())
        self.b._note_wait(5000.0, self.clock())                            # one slow wait out of 20
        self.assertEqual(self.b.check(), "closed")
        self.b._note_wait(5000.0, self.clock())
        self.assertEqual(self.b.state, "closed")                            # 2/20 = p90 still 0 ...
        self.b._note_wait(5000.0, self.clock())
        self.assertEqual((self.b.state, self.b.reason), ("open", "wait"))  # ... 3/20 is not

    def test_close_clears_old_waits(self):
        for _ in range(5):
            self.b._note_wait(100.0, self.clock())
        self.assertEqual(self.b.state, "open")
        self.at(cpu=10, advance=15)
        self.succeed()
        self.assertEqual(self.b.state, "closed")
        self.succeed()                                                      # its 0 ms wait alone must not trip
        self.assertEqual(self.b.state, "closed")


class MonitorTest(unittest.TestCase):
    def test_ewma_and_listeners(self):
        clock = Clock(0.0)
        seq = iter([(None, 3000.0, 60.0), (10.0, 3000.0, 60.0), (90.0, 2500.0, 70.0), (90.0, 2500.0, 70.0)])
        m = Monitor(interval=1.0, tau=5.0, sampler=lambda: next(seq), clock=clock)
        seen = []
        m.add_listener(seen.append)
        m.add_listener(lambda s: 1 / 0)                                   # a broken listener is ignored
        s = m.tick()
        self.assertIsNone(s["cpu_ewma"])
        self.assertEqual(s["mem_avail_mb"], 3000.0)
        clock.advance(1)
        self.assertEqual(m.tick()["cpu_ewma"], 10.0)                        # first real sample seeds the EWMA
        clock.advance(5)
        s = m.tick()
        self.assertAlmostEqual(s["cpu_ewma"], 10 + (1 - math.exp(-1)) * 80, places=6)
        self.assertEqual((s["cpu"], s["mem_avail_mb"], s["mem_pct"]), (90.0, 2500.0, 70.0))
        self.assertEqual(set(s), {"cpu", "cpu_ewma", "mem_avail_mb", "mem_pct", "ts"})
        self.assertEqual(len(seen), 3)
        self.assertEqual(m.snapshot(), seen[-1])
        m.sampler = lambda: 1 / 0                                           # sampler failure: no crash
        clock.advance(1)
        self.assertIsNone(m.tick()["cpu"])

    def test_breaker_follows_monitor_listener(self):
        clock = Clock(0.0)
        cpu = [95.0]
        m = Monitor(interval=1.0, tau=0.001, sampler=lambda: (cpu[0], 4000.0, 40.0), clock=clock)
        b = Breaker("encode", m, {"breaker": dict(breaker.DEFAULTS)}, clock=clock)
        for _ in range(3):
            m.tick()
            clock.advance(1)
        self.assertEqual(b.state, "closed")
        m.tick()                                                            # 3 s hot, judged by the listener
        self.assertEqual((b.state, b.reason), ("open", "cpu"))

    def test_thread_runs_with_real_sampler(self):
        m = Monitor(interval=0.05)
        m.start()
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and m.snapshot()["cpu_ewma"] is None:
                time.sleep(0.02)
            s = m.snapshot()
        finally:
            m.stop()
            m.join(2)
        self.assertIsNotNone(s["cpu_ewma"])
        self.assertTrue(0.0 <= s["cpu_ewma"] <= 100.0)
        if sys.platform == "win32":
            self.assertGreater(s["mem_avail_mb"], 0)
            self.assertTrue(0 <= s["mem_pct"] <= 100)


class PriorityTest(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "win32", "Windows thread priorities")
    def test_below_normal_thread(self):
        k32 = ctypes.WinDLL("kernel32")
        k32.GetCurrentThread.restype = ctypes.c_void_p
        k32.GetThreadPriority.argtypes = [ctypes.c_void_p]
        h = k32.GetCurrentThread()
        before = k32.GetThreadPriority(h)
        with breaker.below_normal_thread():
            self.assertEqual(k32.GetThreadPriority(h), -1)
        self.assertEqual(k32.GetThreadPriority(h), before)
        with self.assertRaises(KeyError):
            with breaker.below_normal_thread():
                raise KeyError("x")
        self.assertEqual(k32.GetThreadPriority(h), before)                  # restored on exceptions too

    def test_set_process_priority_validates(self):
        with self.assertRaises(ValueError):
            breaker.set_process_priority("realtime")
        self.assertTrue(breaker.set_process_priority("normal"))


if __name__ == "__main__":
    unittest.main()
