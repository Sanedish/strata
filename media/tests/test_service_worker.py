"""worker.py: lanes, pause rules, leases, retries, scan / image / video jobs, single instance (DESIGN.md 7).

Run: python -m unittest discover -s media/tests -t media/tests -p "test_service_worker*.py"
Every test gets its own temp media.db, cache_root, event log and mount dir (tempfile.mkdtemp, removed afterwards).
scan.scan_file, imaging.encode_auto and video.* are faked where the real tool is slow, missing on this box or
nondeterministic; a fake monitor drives the pause rules and a fake store clock the retry backoff. Real runs at the
end: PNG -> AVIF variant file, and a text file with a synthetic GitHub token -> flagged. No ports, no production paths.
"""
import copy
import gc
import io
import json
import os
import random
import shutil
import string
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
MEDIA = os.path.dirname(HERE)
for p in (MEDIA, HERE):
    if p not in sys.path:
        sys.path.insert(0, p)
try:
    import pathfix  # noqa: F401
except Exception:
    pass

import config  # noqa: E402
import detect  # noqa: E402
import imaging  # noqa: E402
import sandbox  # noqa: E402
import scan  # noqa: E402
import store  # noqa: E402
import video  # noqa: E402
import worker  # noqa: E402

worker.QUIET = True
WORKER_PY = os.path.join(MEDIA, "worker.py")
VIDEO_OK = {"ffmpeg": r"C:\fake\ffmpeg.exe", "ffprobe": r"C:\fake\ffprobe.exe", "av1": True, "vp9": True,
            "opus": True, "codec": "av1", "ok": True, "error": ""}
VIDEO_MISSING = {"ffmpeg": None, "ffprobe": None, "av1": False, "vp9": False, "opus": False, "codec": None,
                 "ok": False, "error": "ffmpeg missing"}


class FakeMonitor:
    def __init__(self, cpu=10.0, mem=6000.0):
        self.cpu, self.mem = cpu, mem

    def snapshot(self):
        return {"cpu": self.cpu, "cpu_ewma": self.cpu, "mem_avail_mb": self.mem, "mem_pct": 20.0, "ts": time.time()}


def make_conf(tmp, mount):
    conf = copy.deepcopy(config.DEFAULTS)
    conf.update(enabled=True, db=os.path.join(tmp, "data", "media.db"), cache_root=os.path.join(tmp, "media-cache"),
                event_log=os.path.join(tmp, "logs", "media-events.jsonl"), cutover=0,
                mounts={"1": {"path": mount, "prefix": "/", "hosts": ["test.local"],
                              "cache": "public, max-age=31536000, immutable", "edge_cache": ""}})
    return conf


def fake_scan(state="clean", severity="none", findings=None, error_kind=None, engines=None):
    def f(full, name, conf, tools, cancel=None, sandbox_dir=None):
        return scan.ScanResult(state, severity, list(findings or []),
                               dict(engines or {"category": config.category(name)}), 0.01, error_kind)
    return f


def png(w, h, fill=None, noise=0, seed=1):
    """PNG bytes: a flat colour, or a smooth gradient with +-noise (compresses badly as PNG, well as AVIF)."""
    from PIL import Image
    if fill is not None:
        im = Image.new("RGB", (w, h), fill)
    else:
        rnd = random.Random(seed)
        px = bytearray()
        for y in range(h):
            for x in range(w):
                n = rnd.randint(-noise, noise) if noise else 0
                px += bytes((max(0, min(255, x * 255 // w + n)), max(0, min(255, y * 255 // h + n)),
                             max(0, min(255, 128 + n))))
        im = Image.frombytes("RGB", (w, h), bytes(px))
    buf = io.BytesIO()
    im.save(buf, "PNG")
    return buf.getvalue()


def noise_png(w=64, h=64):
    from PIL import Image
    buf = io.BytesIO()
    Image.frombytes("RGB", (w, h), os.urandom(w * h * 3)).save(buf, "PNG")
    return buf.getvalue()


def video_info(full, size):
    return {"path": full, "ext": "mp4", "container": "mov,mp4,m4a,3gp,3g2,mj2", "duration": 10.0, "size": size,
            "bit_rate": 0, "video": {"index": 0, "codec": "h264", "width": 640, "height": 360, "fps": 30.0,
                                     "pix_fmt": "yuv420p", "bit_rate": 0, "rotation": 0},
            "audio": [{"codec": "aac", "channels": 2, "channel_layout": "stereo", "sample_rate": 48000}]}


def sresult(rc=0, killed=None, err=""):
    r = sandbox.Result()
    r.rc, r.killed, r.timed_out, r.err = rc, killed, killed == "timeout", err
    return r


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="strata-worker-test-")
        self.mount = os.path.join(self.tmp, "mount")
        os.makedirs(self.mount)
        self.conf = make_conf(self.tmp, self.mount)
        self.db = store.Store(self.conf["db"]).init()
        self.mon = FakeMonitor()
        self.workers = []

    def tearDown(self):
        for w in self.workers:
            w.stop(timeout=5)
        self.db.close()
        gc.collect()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def make_worker(self, **kw):
        w = worker.Worker(self.conf, db=self.db, monitor=self.mon, **kw)
        self.workers.append(w)
        return w

    def put(self, rel, data):
        full = os.path.join(self.mount, *rel.strip("/").split("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
        return full

    def enqueue(self, kind, rel, params="", priority=50):
        st = os.stat(os.path.join(self.mount, *rel.strip("/").split("/")))
        return self.db.enqueue(kind, 1, rel, size=st.st_size, mtime=st.st_mtime, params=params, priority=priority)

    def job(self, jid):
        return next(j for j in self.db.jobs(limit=1000) if j["id"] == jid)

    def step(self, w, lane):
        return w.lane_step(w.lanes[lane])

    def events(self, w, kind):
        w.events.flush()
        return self.db.events(kind=kind)

    def key(self, w, rel, spec):
        """spec "auto:<fmt>:v1" = the default spec of an automatic job (imaging.auto_spec: profile-versioned)."""
        st = os.stat(os.path.join(self.mount, *rel.strip("/").split("/")))
        return w.cache.key(1, rel, st.st_size, st.st_mtime, self.spec(w, spec))

    @staticmethod
    def spec(w, spec):
        m = spec.split(":")
        if len(m) == 3 and m[0] == "auto" and m[1] in ("avif", "webp") and m[2] == "v1":
            return imaging.auto_spec(m[1], None, w.conf)
        return spec


# ---------------------------------------------------------------------------------------------------- drain / lanes

class TestDrain(Base):
    def test_once_drains_both_lanes(self):
        texts = ["/docs/a%d.txt" % i for i in range(3)]
        for rel in texts:
            self.put(rel, "hello %s\n" % rel)
            self.enqueue("scan", rel, priority=10)
        pics = ["/img/p%d.png" % i for i in range(2)]
        for rel in pics:
            self.put(rel, noise_png())
            self.enqueue("image", rel, params=json.dumps({"want": "avif"}), priority=30)
        with mock.patch.object(scan, "scan_file", fake_scan()), \
                mock.patch.object(imaging, "encode_auto", return_value=(b"\x00" * 300, "avif")):
            w = self.make_worker(once=True)
            self.assertEqual(w.run(), 0)
        counts = self.db.job_counts()
        self.assertEqual(counts, {"scan": {"done": 3}, "image": {"done": 2}})
        for rel in texts:
            v = self.db.verdict(1, rel)
            full = os.path.join(self.mount, *rel.strip("/").split("/"))
            self.assertEqual(v["state"], "clean")
            self.assertEqual(v["legacy"], 0)
            self.assertEqual(v["qhash"], config.quick_hash(full, os.path.getsize(full)))
        for rel in pics:
            row = self.db.variant(self.key(w, rel, "auto:avif:v1"))
            self.assertEqual((row["beneficial"], row["fmt"], row["kind"]), (1, "avif", "img"))
            self.assertTrue(w.cache.exists(row["file"]))
        for j in self.db.jobs(state="done", limit=100):
            self.assertTrue(j["worker"].endswith("-scan" if j["kind"] == "scan" else "-encode"), j["worker"])
        hb = self.db.get_meta("worker_heartbeat")
        self.assertEqual(hb["pid"], os.getpid())
        self.assertEqual(set(hb["lanes"]), {"scan", "encode"})
        self.assertTrue(hb["stopping"])
        self.assertEqual(hb["lanes"]["scan"]["done"], 3)

    def test_lanes_option_runs_only_that_lane(self):
        self.put("/a.txt", "a")
        self.put("/b.png", noise_png())
        sj = self.enqueue("scan", "/a.txt")
        ij = self.enqueue("image", "/b.png")
        with mock.patch.object(scan, "scan_file", fake_scan()):
            self.assertEqual(self.make_worker(lanes=("scan",), once=True).run(), 0)
        self.assertEqual(self.job(sj)["state"], "done")
        self.assertEqual(self.job(ij)["state"], "queued")

    def test_unknown_kind_fails_without_retry(self):
        jid = self.db.enqueue("image", 1, "/x.png")
        self.db._db().execute("UPDATE job SET kind='bogus' WHERE id=?", (jid,))
        w = self.make_worker()
        job = self.db.claim("t", ["bogus"])
        w.run_job(w.lanes["encode"], job)
        self.assertEqual((self.job(jid)["state"], self.job(jid)["error_kind"]), ("failed", "bad_job"))

    def test_params_parsing(self):
        self.assertEqual(worker._job_params(""), {})
        self.assertEqual(worker._job_params("webp"), {"want": "webp"})
        self.assertEqual(worker._job_params("want=webp&spec=x"), {"want": "webp", "spec": "x"})
        self.assertEqual(worker._job_params('{"want": "avif"}'), {"want": "avif"})
        self.assertEqual(worker._job_params("{broken"), {})


# ---------------------------------------------------------------------------------------------------- scan jobs

class TestScanJobs(Base):
    def test_verdict_and_legacy_flag(self):
        self.put("/old.txt", "old file")
        self.put("/new.txt", "new file")
        w = self.make_worker()
        with mock.patch.object(scan, "scan_file", fake_scan()):
            self.conf["cutover"] = time.time() + 3600      # born before the cutover -> legacy
            jid = self.enqueue("scan", "/old.txt")
            self.assertEqual(self.step(w, "scan"), "ran")
            self.conf["cutover"] = 1.0                     # born after it -> new
            self.enqueue("scan", "/new.txt")
            self.assertEqual(self.step(w, "scan"), "ran")
        old, new = self.db.verdict(1, "/old.txt"), self.db.verdict(1, "/new.txt")
        self.assertEqual((old["state"], old["legacy"]), ("clean", 1))
        self.assertEqual((new["state"], new["legacy"]), ("clean", 0))
        st = os.stat(os.path.join(self.mount, "old.txt"))
        self.assertEqual((old["size"], old["mtime"]), (st.st_size, st.st_mtime))
        self.assertEqual(old["engines"], {"category": "text"})
        self.assertEqual(old["severity"], "")
        self.assertTrue(self.job(jid)["result"]["legacy"])

    def test_flagged_event_is_redacted(self):
        self.put("/secret.txt", "whatever")
        f = detect.finding("github_token", "high", detect.redact("ghp_" + "Ab3" * 12), "/secret.txt", "high")
        w = self.make_worker()
        with mock.patch.object(scan, "scan_file", fake_scan("flagged", "high", [f])):
            self.enqueue("scan", "/secret.txt")
            self.step(w, "scan")
        v = self.db.verdict(1, "/secret.txt")
        self.assertEqual((v["state"], v["severity"]), ("flagged", "high"))
        self.assertEqual(v["findings"][0]["type"], "github_token")
        ev = self.events(w, "scan.flagged")
        self.assertEqual(len(ev), 1)
        d = ev[0]["detail"]
        self.assertEqual((ev[0]["mount"], ev[0]["path"], ev[0]["severity"]), (1, "/secret.txt", "warning"))
        self.assertEqual((d["finding_severity"], d["legacy"], d["findings"]), ("high", False, 1))
        self.assertIn("github_token (high)", d["summary"])
        self.assertNotIn("Ab3Ab3Ab3", json.dumps(ev[0]))

    def test_missing_file_drops_verdict(self):
        self.db.set_verdict(1, "/gone.txt", size=5, mtime=1.0, state="clean")
        jid = self.db.enqueue("scan", 1, "/gone.txt", size=5, mtime=1.0)
        w = self.make_worker()
        with mock.patch.object(scan, "scan_file", side_effect=AssertionError("must not scan")):
            self.step(w, "scan")
        self.assertIsNone(self.db.verdict(1, "/gone.txt"))
        self.assertEqual((self.job(jid)["state"], self.job(jid)["result"]), ("done", {"missing": True}))

    def test_unreachable_mount_keeps_verdict(self):
        self.conf["mounts"]["1"]["path"] = os.path.join(self.tmp, "offline-share")
        self.db.set_verdict(1, "/gone.txt", size=5, mtime=1.0, state="flagged")
        jid = self.db.enqueue("scan", 1, "/gone.txt", size=5, mtime=1.0)
        self.step(self.make_worker(), "scan")
        self.assertEqual(self.db.verdict(1, "/gone.txt")["state"], "flagged")
        self.assertEqual((self.job(jid)["state"], self.job(jid)["error_kind"]), ("queued", "io_error"))

    def test_unknown_mount_is_skipped(self):
        jid = self.db.enqueue("scan", 7, "/a.txt")
        self.step(self.make_worker(), "scan")
        self.assertEqual(self.job(jid)["result"], {"skipped": "no_mount"})

    def test_retry_backoff_then_failed(self):
        now = [1_000_000.0]
        self.db.clock = lambda: now[0]
        self.put("/flaky.txt", "x")
        jid = self.enqueue("scan", "/flaky.txt")
        w = self.make_worker()
        with mock.patch.object(scan, "scan_file", fake_scan("error", error_kind="av_error",
                                                            engines={"error": "MpCmdRun failed"})):
            self.assertEqual(self.step(w, "scan"), "ran")
            j = self.job(jid)
            self.assertEqual((j["state"], j["attempts"], j["error_kind"], j["error"]),
                             ("queued", 1, "av_error", "MpCmdRun failed"))
            self.assertEqual(j["not_before"], now[0] + 60)
            self.assertEqual(self.step(w, "scan"), "idle")          # backoff: not claimable yet
            now[0] += 61
            self.assertEqual(self.step(w, "scan"), "ran")
            j = self.job(jid)
            self.assertEqual((j["state"], j["attempts"], j["not_before"]), ("queued", 2, now[0] + 600))
            self.assertIsNone(self.db.verdict(1, "/flaky.txt"))
            now[0] += 601
            self.assertEqual(self.step(w, "scan"), "ran")
        j = self.job(jid)
        self.assertEqual((j["state"], j["attempts"]), ("failed", 3))
        v = self.db.verdict(1, "/flaky.txt")
        self.assertEqual(v["state"], "error")               # unscannable: held unless legacy
        ev = self.events(w, "job.failed")
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0]["detail"]["error_kind"], ev[0]["detail"]["job_kind"]), ("av_error", "scan"))

    def test_sandbox_removed_on_exception(self):
        self.put("/a.zip", b"PK\x05\x06" + b"\0" * 18)
        seen = []

        def boom(full, name, conf, tools, cancel=None, sandbox_dir=None):
            seen.append(sandbox_dir)
            os.makedirs(os.path.join(sandbox_dir, "deep", "er"))
            with open(os.path.join(sandbox_dir, "deep", "er", "x.bin"), "wb") as f:
                f.write(b"123")
            raise RuntimeError("scanner crashed")
        jid = self.enqueue("scan", "/a.zip")
        w = self.make_worker()
        with mock.patch.object(scan, "scan_file", boom):
            self.step(w, "scan")
        box = seen[0]
        self.assertEqual(os.path.dirname(box), os.path.join(self.conf["cache_root"], "sandbox"))
        self.assertEqual(os.path.basename(box), str(jid))
        self.assertFalse(os.path.exists(box))
        j = self.job(jid)
        self.assertEqual((j["state"], j["error_kind"]), ("queued", "exception"))
        self.assertIn("scanner crashed", j["error"])

    def test_sandbox_removed_when_scan_leaves_files(self):
        self.put("/b.zip", b"PK\x05\x06" + b"\0" * 18)
        seen = []

        def messy(full, name, conf, tools, cancel=None, sandbox_dir=None):
            seen.append(sandbox_dir)
            os.makedirs(sandbox_dir)
            open(os.path.join(sandbox_dir, "left.txt"), "w").close()
            return scan.ScanResult("clean")
        self.enqueue("scan", "/b.zip")
        with mock.patch.object(scan, "scan_file", messy):
            self.step(self.make_worker(), "scan")
        self.assertFalse(os.path.exists(seen[0]))
        self.assertEqual(self.db.verdict(1, "/b.zip")["state"], "clean")

    def test_stale_sandbox_dirs_cleaned(self):
        root = os.path.join(self.conf["cache_root"], "sandbox")
        os.makedirs(os.path.join(root, "77", "sub"))
        os.makedirs(os.path.join(root, "strata-scan-abc"))
        open(os.path.join(root, "keep.txt"), "w").close()
        self.assertEqual(self.make_worker().clean_sandbox(), 2)
        self.assertEqual(os.listdir(root), ["keep.txt"])


# ---------------------------------------------------------------------------------------------------- pause rules

class TestPause(Base):
    def test_pause_on_high_cpu_then_resume(self):
        self.put("/a.txt", "a")
        jid = self.enqueue("scan", "/a.txt")
        w = self.make_worker()
        self.mon.cpu = 90.0
        with mock.patch.object(scan, "scan_file", fake_scan()):
            self.assertEqual(self.step(w, "scan"), "paused")
            self.assertEqual(self.step(w, "scan"), "paused")
            self.assertEqual(self.job(jid)["state"], "queued")
            self.assertEqual(w.lanes["scan"].paused, "cpu")
            w.heartbeat()
            hb = self.db.get_meta("worker_heartbeat")
            self.assertEqual((hb["paused"], hb["lanes"]["scan"]["paused"]), ("cpu", "cpu"))
            ev = self.events(w, "worker.paused")
            self.assertEqual(len(ev), 1)                     # rate-limited per reason
            self.assertEqual((ev[0]["detail"]["reason"], ev[0]["detail"]["cpu_ewma"]), ("cpu", 90.0))
            self.mon.cpu = 20.0
            self.assertEqual(self.step(w, "scan"), "ran")
        self.assertIsNone(w.lanes["scan"].paused)
        self.assertEqual(self.job(jid)["state"], "done")

    def test_pause_on_low_memory(self):
        w = self.make_worker()
        self.mon.mem = 500.0
        self.assertEqual(w.pause_reason(), "mem")
        self.mon.mem, self.mon.cpu = 6000.0, None        # cpu_ewma unknown (first second): no pause
        self.assertIsNone(w.pause_reason())

    def test_pause_on_breaker_open_then_resume(self):
        self.put("/a.png", noise_png())
        jid = self.enqueue("image", "/a.png")
        w = self.make_worker()
        self.db.set_meta("breaker", {"state": "open", "reason": "cpu", "ts": time.time()})
        self.assertEqual(self.step(w, "encode"), "paused")
        self.assertEqual(w.lanes["encode"].paused, "breaker")
        self.db.set_meta("breaker", {"state": "open"})              # no timestamp: trusted
        self.assertEqual(w.pause_reason(), "breaker")
        self.db.set_meta("breaker", {"state": "open", "ts": time.time() - 3600})   # media.py died open
        self.assertIsNone(w.pause_reason())
        self.db.set_meta("breaker", {"state": "closed", "ts": time.time()})
        self.assertEqual(self.job(jid)["state"], "queued")
        with mock.patch.object(imaging, "encode_auto", return_value=(b"\0" * 100, "avif")):
            self.assertEqual(self.step(w, "encode"), "ran")
        self.assertEqual(self.job(jid)["state"], "done")
        ev = self.events(w, "worker.paused")
        self.assertEqual([e["detail"]["reason"] for e in ev], ["breaker"])


# ---------------------------------------------------------------------------------------------------- leases / stop

class TestLeases(Base):
    def slow_scan(self):
        self.started, self.release = threading.Event(), threading.Event()

        def slow(full, name, conf, tools, cancel=None, sandbox_dir=None):
            self.started.set()
            while not self.release.wait(0.05):
                if cancel():
                    return scan.ScanResult("error", error_kind="cancelled")
            return scan.ScanResult("clean")
        return slow

    def wait_for(self, cond, timeout=8.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if cond():
                return True
            time.sleep(0.05)
        return False

    def test_lease_heartbeat_and_cancel(self):
        self.conf["worker"]["lease_s"] = 3                # beat every 1 s
        self.put("/big.txt", "x")
        jid = self.enqueue("scan", "/big.txt")
        with mock.patch.object(scan, "scan_file", self.slow_scan()):
            w = self.make_worker(lanes=("scan",)).start()
            self.assertTrue(self.started.wait(10))
            l0 = self.job(jid)["lease_until"]
            self.assertTrue(self.wait_for(lambda: self.job(jid)["lease_until"] > l0 + 0.5), "lease not extended")
            self.assertEqual(self.job(jid)["state"], "running")
            w.heartbeat()
            self.assertEqual(self.db.get_meta("worker_heartbeat")["lanes"]["scan"]["job"]["id"], jid)
            self.db.cancel("scan", 1, "/big.txt")           # e.g. the bridge saw the file deleted
            self.assertTrue(self.wait_for(lambda: w.lanes["scan"].job is None), "cancel not noticed")
            w.stop()
        self.assertEqual(self.job(jid)["state"], "cancelled")
        self.assertIsNone(self.db.verdict(1, "/big.txt"))

    def test_graceful_stop_requeues_running_job(self):
        self.put("/big.txt", "x")
        jid = self.enqueue("scan", "/big.txt")
        with mock.patch.object(scan, "scan_file", self.slow_scan()):
            w = self.make_worker(lanes=("scan",)).start()
            self.assertTrue(self.started.wait(10))
            w.stop(timeout=5)
        j = self.job(jid)
        self.assertEqual((j["state"], j["error_kind"]), ("queued", "stopped"))
        self.assertLessEqual(j["not_before"], time.time())
        self.assertIsNone(self.db.verdict(1, "/big.txt"))
        self.assertTrue(self.db.get_meta("worker_heartbeat")["stopping"])

    def test_expired_leases_requeued(self):
        jid = self.db.enqueue("scan", 1, "/a.txt")
        self.db.claim("dead-worker", ["scan"], lease_s=-5)
        self.make_worker().housekeeping(force=True)
        self.assertEqual((self.job(jid)["state"], self.job(jid)["error_kind"]), ("queued", "lease_expired"))


# ---------------------------------------------------------------------------------------------------- image jobs

class TestImageJobs(Base):
    def test_small_image_recorded_not_beneficial(self):
        self.put("/tiny.png", png(8, 8, fill=(200, 10, 10)))
        jid = self.enqueue("image", "/tiny.png", params="avif")
        w = self.make_worker()
        self.step(w, "encode")
        row = self.db.variant(self.key(w, "/tiny.png", "auto:avif:v1"))
        self.assertEqual((row["beneficial"], row["fmt"], row["file"]), (0, "orig", None))
        self.assertEqual(self.job(jid)["result"], {"variant": "orig", "reason": "small"})

    def test_cache_written_with_returned_format(self):
        self.put("/ui.png", noise_png())
        self.enqueue("image", "/ui.png", params=json.dumps({"want": "avif"}))
        w = self.make_worker()
        with mock.patch.object(imaging, "encode_auto", return_value=(b"RIFF" + b"\0" * 60, "webp")):
            self.step(w, "encode")
        row = self.db.variant(self.key(w, "/ui.png", "auto:avif:v1"))
        self.assertEqual((row["fmt"], row["beneficial"], row["spec"]), ("webp", 1, self.spec(w, "auto:avif:v1")))
        self.assertTrue(row["file"].endswith(".webp") and row["file"].startswith("/img/"))
        self.assertTrue(w.cache.exists(row["file"]))

    def test_not_beneficial_encode(self):
        data = noise_png()
        self.put("/n.png", data)
        self.enqueue("image", "/n.png", params="webp")
        w = self.make_worker()
        with mock.patch.object(imaging, "encode_auto", return_value=(b"\0" * len(data), "webp")):
            self.step(w, "encode")
        row = self.db.variant(self.key(w, "/n.png", "auto:webp:v1"))
        self.assertEqual((row["beneficial"], row["file"], row["bytes"]), (0, None, len(data)))
        self.assertEqual(os.listdir(os.path.join(self.conf["cache_root"], "cache")), [])

    def test_too_large_vs_low_memory(self):
        self.put("/huge.png", noise_png())
        self.put("/big.png", noise_png())
        w = self.make_worker()
        j1 = self.enqueue("image", "/huge.png")
        with mock.patch.object(imaging, "encode_auto", side_effect=imaging.TooLarge(300.0, 280.0)):
            self.step(w, "encode")
        row = self.db.variant(self.key(w, "/huge.png", "auto:avif:v1"))
        self.assertEqual((row["beneficial"], row["fmt"]), (0, "orig"))
        self.assertEqual(self.job(j1)["state"], "done")
        self.mon.mem = 2000.0                       # above worker.mem_min_mb, below imaging.LOW_MEM_MB
        j2 = self.enqueue("image", "/big.png")
        with mock.patch.object(imaging, "encode_auto", side_effect=imaging.TooLarge(200.0, 150.0)):
            self.step(w, "encode")
        self.assertIsNone(self.db.variant(self.key(w, "/big.png", "auto:avif:v1")))
        self.assertEqual((self.job(j2)["state"], self.job(j2)["error_kind"]), ("queued", "low_memory"))
        reasons = sorted(e["detail"]["reason"] for e in self.events(w, "image.skipped"))
        self.assertEqual(reasons, ["low_memory", "too_large"])

    def test_decode_error_retries_then_not_beneficial(self):
        now = [2_000_000.0]
        self.db.clock = lambda: now[0]
        self.put("/bad.png", b"\x89PNG\r\n\x1a\n" + b"garbage" * 1000)
        jid = self.enqueue("image", "/bad.png")
        w = self.make_worker()
        for _ in range(3):
            self.assertEqual(self.step(w, "encode"), "ran")
            now[0] += 3601
        j = self.job(jid)
        self.assertEqual((j["state"], j["error_kind"], j["attempts"]), ("failed", "decode_error", 3))
        row = self.db.variant(self.key(w, "/bad.png", "auto:avif:v1"))
        self.assertEqual((row["beneficial"], row["fmt"]), (0, "orig"))

    def test_existing_variant_skips_encode(self):
        self.put("/c.png", noise_png())
        w = self.make_worker()
        st = os.stat(os.path.join(self.mount, "c.png"))
        self.db.put_variant(self.key(w, "/c.png", "auto:avif:v1"), mount=1, path="/c.png", src_size=st.st_size,
                            src_mtime=st.st_mtime, kind="img", fmt="orig", spec="auto:avif:v1", file=None,
                            bytes=None, src_bytes=st.st_size, secs=0, beneficial=0)
        jid = self.enqueue("image", "/c.png")
        with mock.patch.object(imaging, "encode_auto", side_effect=AssertionError("must not encode")):
            self.step(w, "encode")
        self.assertEqual(self.job(jid)["result"], {"cached": True})

    def test_explicit_transform_job(self):
        self.put("/t.png", png(128, 96, noise=4))
        spec = "tf:w=32,h=,fit=inside,fm=webp,q=82:v1"
        self.enqueue("image", "/t.png", params=json.dumps({"tf": {"w": "32", "fm": "webp"}, "spec": spec}))
        w = self.make_worker()
        self.step(w, "encode")
        row = self.db.variant(self.key(w, "/t.png", spec))
        self.assertEqual((row["fmt"], row["beneficial"], row["spec"]), ("webp", 1, spec))
        from PIL import Image
        with Image.open(os.path.join(w.cache.dir, *row["file"].strip("/").split("/"))) as im:
            self.assertEqual(im.size, (32, 24))
        bad = self.enqueue("image", "/t.png", params=json.dumps({"tf": {"w": "99999"}}))
        self.step(w, "encode")
        self.assertEqual((self.job(bad)["state"], self.job(bad)["error_kind"]), ("failed", "bad_params"))


# ---------------------------------------------------------------------------------------------------- video jobs

class TestVideoJobs(Base):
    def test_tool_missing_fails_without_retry(self):
        self.put("/clip.mp4", b"\0" * 4096)
        jid = self.enqueue("video", "/clip.mp4", priority=40)
        w = self.make_worker()
        with mock.patch.object(video, "available", return_value=dict(VIDEO_MISSING)):
            self.step(w, "encode")
        j = self.job(jid)
        self.assertEqual((j["state"], j["error_kind"], j["attempts"]), ("failed", "tool_missing", 1))
        self.assertIsNone(self.enqueue("video", "/clip.mp4"))        # no retry until the tools change
        ev = self.events(w, "tool.missing")
        self.assertEqual([e["detail"]["tool"] for e in ev], ["ffmpeg"])

    def test_timeout_retries(self):
        full = self.put("/clip.mp4", b"\0" * 4096)
        jid = self.enqueue("video", "/clip.mp4")
        w = self.make_worker()
        with mock.patch.object(video, "available", return_value=dict(VIDEO_OK)), \
                mock.patch.object(video, "probe", return_value=video_info(full, 4096)), \
                mock.patch.object(video, "transcode", return_value=sresult(1, "timeout")):
            self.step(w, "encode")
        j = self.job(jid)
        self.assertEqual((j["state"], j["error_kind"]), ("queued", "timeout"))
        self.assertEqual(os.listdir(w.cache.tmp_dir), [])

    def fake_transcode(self, nbytes):
        def tc(src, dst, plan, conf):
            with open(dst, "wb") as f:
                f.write(b"\x1a\x45\xdf\xa3" + b"\0" * (nbytes - 4))
            self.assertTrue(os.path.dirname(dst) == os.path.join(self.conf["cache_root"], "tmp"))
            return sresult(0)
        return tc

    def test_transcode_adopted_into_cache(self):
        full = self.put("/clip.mp4", b"\0" * 4096)
        jid = self.enqueue("video", "/clip.mp4")
        w = self.make_worker()
        with mock.patch.object(video, "available", return_value=dict(VIDEO_OK)), \
                mock.patch.object(video, "probe", return_value=video_info(full, 4096)), \
                mock.patch.object(video, "transcode", self.fake_transcode(1000)):
            self.step(w, "encode")
        row = self.db.variant(self.key(w, "/clip.mp4", "auto:webm:v1"))
        self.assertEqual((row["beneficial"], row["fmt"], row["kind"], row["bytes"]), (1, "webm", "vid", 1000))
        self.assertTrue(row["file"].startswith("/vid/") and w.cache.exists(row["file"]))
        self.assertEqual(self.job(jid)["state"], "done")
        self.assertEqual(os.listdir(w.cache.tmp_dir), [])

    def test_mp4_job(self):
        """{"want": "mp4"}: planned, transcoded and stored as MP4 under auto:mp4:v1 (the key media.py looks up)."""
        full = self.put("/clip.mov", b"\0" * 4096)
        jid = self.enqueue("video", "/clip.mov", params='{"want":"mp4"}')
        w = self.make_worker()
        seen = {}

        def tc(src, dst, plan, conf):
            seen.update(plan=plan, dst=dst)
            with open(dst, "wb") as f:
                f.write(b"\0\0\0\x18ftypisom" + b"\0" * 988)
            return sresult(0)
        with mock.patch.object(video, "available", return_value=dict(VIDEO_OK, codec="h264", format="mp4")),                 mock.patch.object(video, "probe", return_value=video_info(full, 4096)),                 mock.patch.object(video, "transcode", tc):
            self.step(w, "encode")
        self.assertEqual((seen["plan"]["format"], seen["plan"]["codec"]), ("mp4", "h264"))
        self.assertTrue(seen["dst"].endswith(".mp4"))
        row = self.db.variant(self.key(w, "/clip.mov", "auto:mp4:v1"))
        self.assertEqual((row["beneficial"], row["fmt"], row["file"].rsplit(".", 1)[-1]), (1, "mp4", "mp4"))
        self.assertEqual(self.job(jid)["result"]["variant"], "mp4")

    def test_not_beneficial_and_skipped_sources(self):
        full = self.put("/clip.mp4", b"\0" * 4096)
        self.enqueue("video", "/clip.mp4")
        w = self.make_worker()
        with mock.patch.object(video, "available", return_value=dict(VIDEO_OK)), \
                mock.patch.object(video, "probe", return_value=video_info(full, 4096)), \
                mock.patch.object(video, "transcode", self.fake_transcode(3900)):
            self.step(w, "encode")
        row = self.db.variant(self.key(w, "/clip.mp4", "auto:webm:v1"))
        self.assertEqual((row["beneficial"], row["file"], row["bytes"]), (0, None, 3900))
        self.assertEqual(os.listdir(w.cache.tmp_dir), [])
        full2 = self.put("/av1.mkv", b"\0" * 4096)
        info = video_info(full2, 4096)
        info["video"]["codec"] = "av1"
        jid = self.enqueue("video", "/av1.mkv")
        with mock.patch.object(video, "available", return_value=dict(VIDEO_OK)), \
                mock.patch.object(video, "probe", return_value=info), \
                mock.patch.object(video, "transcode", side_effect=AssertionError("must not transcode")):
            self.step(w, "encode")
        self.assertEqual(self.job(jid)["result"], {"variant": "orig", "reason": "already_av1"})
        self.assertEqual(self.db.variant(self.key(w, "/av1.mkv", "auto:webm:v1"))["beneficial"], 0)


# ---------------------------------------------------------------------------------------------------- housekeeping

class TestHousekeeping(Base):
    def test_tools_meta_and_missing_events(self):
        w = self.make_worker()
        with mock.patch.object(sandbox, "tools", return_value={n: None for n in sandbox.TOOL_NAMES}), \
                mock.patch.object(worker, "_pdfium_version", return_value=None):
            info = w.check_tools()
            w.check_tools()                                   # second run: rate-limited, no new events
        meta = self.db.get_meta("tools")
        self.assertEqual(meta["missing"], info["missing"])
        for t in ("ffmpeg", "ffprobe", "tesseract", "7z", "av", "pypdfium2"):
            self.assertIn(t, meta["missing"])
        self.assertIsNone(meta["pypdfium2"])
        self.assertTrue(meta["pillow"]["avif"])                 # Pillow 12.3 on this box
        self.assertNotIn("pillow-avif", meta["missing"])
        ev = self.events(w, "tool.missing")
        self.assertEqual(sorted(e["detail"]["tool"] for e in ev), sorted(meta["missing"]))

    def test_failed_video_jobs_requeued_when_ffmpeg_appears(self):
        self.put("/clip.mp4", b"\0" * 4096)
        jid = self.enqueue("video", "/clip.mp4")
        w = self.make_worker()
        with mock.patch.object(video, "available", return_value=dict(VIDEO_MISSING)):
            self.step(w, "encode")
        self.assertEqual(self.job(jid)["state"], "failed")
        with mock.patch.object(sandbox, "tools", return_value={n: None for n in sandbox.TOOL_NAMES}):
            w.check_tools()                                   # still missing: stays failed
        self.assertEqual(self.job(jid)["state"], "failed")
        found = dict({n: None for n in sandbox.TOOL_NAMES}, ffmpeg=VIDEO_OK["ffmpeg"], ffprobe=VIDEO_OK["ffprobe"])
        with mock.patch.object(sandbox, "tools", return_value=found), \
                mock.patch.object(video, "available", return_value=dict(VIDEO_OK)):
            w.check_tools()
            self.assertEqual(self.job(jid)["state"], "queued")
            self.db.retry_failed = mock.Mock(side_effect=AssertionError("only on the missing -> ok transition"))
            w.check_tools()
        self.assertEqual([e["detail"]["n"] for e in self.events(w, "worker.retry")], [1])

    def test_heartbeat_meta(self):
        w = self.make_worker()
        w.heartbeat()
        hb = self.db.get_meta("worker_heartbeat")
        self.assertLess(abs(hb["ts"] - time.time()), 5)
        self.assertEqual((hb["pid"], hb["paused"], hb["stopping"]), (os.getpid(), None, False))
        self.assertEqual(hb["lanes"]["scan"], {"kinds": ["scan"], "job": None, "paused": None, "done": 0,
                                               "failed": 0})
        self.assertEqual(hb["lanes"]["encode"]["kinds"], ["image", "video"])

    def test_prune_at_most_daily(self):
        w = self.make_worker()
        self.assertTrue(w._maybe_prune())
        self.assertFalse(w._maybe_prune())
        self.assertIsInstance(self.db.get_meta("worker_prune"), float)

    def test_cost_model_persisted_and_reloaded(self):
        self.put("/m.png", png(128, 96, noise=5))
        self.enqueue("image", "/m.png")
        w = self.make_worker()
        self.step(w, "encode")
        saved = self.db.get_meta("cost_model")
        self.assertTrue(saved["samples"])
        w2 = self.make_worker()
        self.assertEqual(w2.model.to_dict()["samples"], saved["samples"])


# ---------------------------------------------------------------------------------------------------- single instance

class TestSingleInstance(Base):
    def lock_path(self):
        return os.path.join(os.path.dirname(self.conf["db"]), worker.LOCK_NAME)

    def cli(self, *args):
        path = os.path.join(self.tmp, "media.json")
        conf = copy.deepcopy(self.conf)
        conf["worker"].update(cpu_max=101, mem_min_mb=0)      # a real monitor runs: never pause on a busy box
        with open(path, "w", encoding="utf-8") as f:
            json.dump(conf, f)
        return subprocess.run([sys.executable, WORKER_PY, "--config", path] + list(args), cwd=MEDIA,
                              capture_output=True, text=True, timeout=180)

    def test_lock_is_exclusive(self):
        a, b = worker.InstanceLock(self.lock_path()), worker.InstanceLock(self.lock_path())
        self.assertTrue(a.acquire())
        self.assertFalse(b.acquire())
        a.release()
        self.assertTrue(b.acquire())
        b.release()

    def test_cli_exits_quietly_when_locked_then_drains(self):
        self.put("/hello.txt", "hello world\n")
        jid = self.enqueue("scan", "/hello.txt")
        lock = worker.InstanceLock(self.lock_path())
        self.assertTrue(lock.acquire())
        try:
            r = self.cli("--once")
            self.assertEqual(r.returncode, 0, r.stderr[-500:])
            self.assertIn("another worker", r.stdout)
            self.assertIsNone(self.db.get_meta("worker_heartbeat"))
            self.assertEqual(self.job(jid)["state"], "queued")
        finally:
            lock.release()
        r = self.cli("--once", "--lanes", "scan")
        self.assertEqual(r.returncode, 0, r.stderr[-500:])
        self.assertEqual(self.job(jid)["state"], "done")
        self.assertEqual(self.db.verdict(1, "/hello.txt")["state"], "clean")
        hb = self.db.get_meta("worker_heartbeat")
        self.assertNotEqual(hb["pid"], os.getpid())
        self.assertEqual(list(hb["lanes"]), ["scan"])
        self.assertIsNotNone(self.db.get_meta("tools"))

    def test_cli_disabled_and_bad_lanes(self):
        self.conf["enabled"] = False
        r = self.cli("--once")
        self.assertEqual(r.returncode, 0)
        self.assertIn("media.enabled is off", r.stdout)
        self.conf["enabled"] = True
        self.assertEqual(self.cli("--lanes", "nope").returncode, 2)


# ---------------------------------------------------------------------------------------------------- real runs

class TestReal(Base):
    def test_real_png_to_avif(self):
        data = png(320, 240, noise=6)
        self.put("/photos/grad.png", data)
        jid = self.enqueue("image", "/photos/grad.png", params=json.dumps({"want": "avif"}), priority=30)
        w = self.make_worker()
        self.assertEqual(self.step(w, "encode"), "ran")
        j = self.job(jid)
        self.assertEqual(j["state"], "done", j)
        row = self.db.variant(self.key(w, "/photos/grad.png", "auto:avif:v1"))
        self.assertEqual((row["fmt"], row["beneficial"]), ("avif", 1))
        path = os.path.join(w.cache.dir, *row["file"].strip("/").split("/"))
        self.assertTrue(path.startswith(self.conf["cache_root"]))
        with open(path, "rb") as f:
            head = f.read(12)
        self.assertEqual(head[4:12], b"ftypavif")
        self.assertEqual(os.path.getsize(path), row["bytes"])
        self.assertLess(row["bytes"], len(data) * 0.9)
        self.assertIn("avif:%d" % imaging.image_conf(self.conf)["speed_bg"],
                      self.db.get_meta("cost_model")["samples"])   # worker speed (speed_bg)

    def test_real_scan_github_token_flagged(self):
        rnd = random.Random(20260929)
        token = "ghp_" + "".join(rnd.choice(string.ascii_letters + string.digits) for _ in range(36))
        self.put("/notes/deploy.txt", "deploy notes\nexport GITHUB_TOKEN=%s\nthanks\n" % token)
        jid = self.enqueue("scan", "/notes/deploy.txt", priority=10)
        w = self.make_worker()
        self.assertEqual(self.step(w, "scan"), "ran")
        v = self.db.verdict(1, "/notes/deploy.txt")
        self.assertEqual((v["state"], v["severity"]), ("flagged", "high"), v)
        self.assertTrue(any("github" in (f.get("type") or "") for f in v["findings"]), v["findings"])
        self.assertNotIn(token, json.dumps(v))
        self.assertNotIn(token[4:], json.dumps(v))
        ev = self.events(w, "scan.flagged")
        self.assertEqual(len(ev), 1)
        self.assertNotIn(token[4:], json.dumps(ev[0]))
        self.assertEqual(self.job(jid)["state"], "done")
        self.assertFalse(os.path.exists(os.path.join(self.conf["cache_root"], "sandbox", str(jid))))


if __name__ == "__main__":
    unittest.main()
