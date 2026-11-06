"""worker.py on several GPUs: the video lane's GPU slots, video.gpu_jobs, benching and failover between slots, the
CPU slot, headroom for the scan lane, and lease tokens with several running jobs (DESIGN.md 7.1, 7.2, 7.6).

Run: python -m unittest discover -s media/tests -t media/tests -p "test_service_worker_gpu*.py"
The GPUs are fakes: video.available answers from a device list (leaving out what gpu.bench benched, as the real
gpu.select does), video.transcode is an Encoder that counts parallel runs per device and holds them until released.
Real worker threads run against a temp media.db; no ffmpeg, no GPU, no ports.
"""
import contextlib
import os
import sqlite3
import sys
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
MEDIA = os.path.dirname(HERE)
for p in (MEDIA, HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

import gpu  # noqa: E402
import imaging  # noqa: E402
import scan  # noqa: E402
import store  # noqa: E402
import video  # noqa: E402
import worker  # noqa: E402
from test_service_worker import VIDEO_OK, Base, fake_scan, noise_png, sresult, video_info  # noqa: E402

worker.QUIET = True
G0 = {"id": "nvenc:0", "backend": "nvenc", "index": 0, "name": "A", "ok": True}
G1 = {"id": "nvenc:1", "backend": "nvenc", "index": 1, "name": "B", "ok": True}
SESSION_CAP = "[h264_nvenc @ 0x1] OpenEncodeSessionEx failed: out of memory (10): (no details)"


def gpus_only(slots):
    """_Slots counts without "cpu" (the encode lane holds it for a moment each time it looks for image jobs)."""
    return {k: v for k, v in slots.items() if k != "cpu"}


def wait_for(cond, timeout=10.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


class Encoder:
    """Fake video.transcode: records (device, file), counts runs per device, holds every run until `gate` is set.
    fail(device, running) -> stderr text makes that run fail (encode_error)."""

    def __init__(self, fail=None, hold=True):
        self.lock = threading.Lock()
        self.gate = threading.Event()
        if not hold:
            self.gate.set()
        self.fail = fail or (lambda dev, running: None)
        self.running, self.max_per, self.log = {}, {}, []
        self.max_total = 0

    @contextlib.contextmanager
    def track(self, dev, name=""):
        with self.lock:
            self.running[dev] = self.running.get(dev, 0) + 1
            self.max_per[dev] = max(self.max_per.get(dev, 0), self.running[dev])
            self.max_total = max(self.max_total, self.total(locked=True))
            self.log.append((dev, name))
            n = self.running[dev]
        try:
            yield n
        finally:
            with self.lock:
                self.running[dev] -= 1

    def total(self, locked=False):
        if locked:
            return sum(self.running.values())
        with self.lock:
            return sum(self.running.values())

    def on(self, dev):
        with self.lock:
            return self.running.get(dev, 0)

    def __call__(self, src, dst, plan, conf):
        with self.track(plan.get("device") or "cpu", os.path.basename(src)) as n:
            err = self.fail(plan.get("device"), n)
            if err:
                return sresult(1, err=err)
            self.gate.wait(15)
            with open(dst, "wb") as f:
                f.write(b"\0\0\0\x18ftypisom" + b"\0" * 988)
            return sresult(0)


def fail_once_busy(enc, dev, err, busy):
    """Encoder fail hook: runs on `dev` fail with `err`, but only once the other job holds `busy` - a run that fails
    before the other job is placed takes the still-free `busy` card itself, and the other job never gets it."""
    def fail(d, running):
        if d == dev:
            wait_for(lambda: enc.on(busy) == 1)
            return err
    return fail


class GpuBase(Base):
    def setUp(self):
        super().setUp()
        gpu.reset()
        self.conf["video"].update(format="mp4", encoder="nvenc")
        self.devs = [G0, G1]

    def tearDown(self):
        super().tearDown()
        gpu.reset()

    def available(self, conf, fmt=None):
        """video.available as the real one answers it: usable GPUs minus the benched ones (gpu.select)."""
        vc = video.video_conf(conf)
        fmt = fmt if fmt in video.FORMATS else vc["format"]
        if fmt != "mp4":
            return dict(VIDEO_OK, format=fmt, h264=True, aac=True)
        out = dict(VIDEO_OK, format="mp4", h264=True, aac=True, h264_nvenc=True, devices=[])
        devs = [dict(d) for d in self.devs if d["id"] not in gpu.benched()]
        if vc["encoder"] != "cpu" and devs:
            return dict(out, codec="h264_nvenc", devices=devs)
        cpu_ok = vc["encoder"] in ("cpu", "auto")
        return dict(out, codec="h264" if cpu_ok else None, ok=cpu_ok, error="" if cpu_ok else "h264_nvenc unusable")

    @contextlib.contextmanager
    def gpus(self, enc):
        with mock.patch.object(video, "available", side_effect=self.available), \
                mock.patch.object(video, "probe", side_effect=lambda full, conf: video_info(full, 4096)), \
                mock.patch.object(video, "transcode", side_effect=enc), \
                mock.patch.object(worker.Worker, "check_tools", return_value={}):
            yield

    def videos(self, n, prefix="v"):
        out = []
        for i in range(n):
            rel = "/%s%d.mp4" % (prefix, i)
            self.put(rel, b"\0" * 4096)
            out.append(self.enqueue("video", rel, priority=40 + i))
        return out

    def done(self, ids):
        return all(self.job(j)["state"] == "done" for j in ids)

    def started(self, **kw):
        return self.make_worker(**kw).start()


# ---------------------------------------------------------------------------------------------------- GPU slots

class TestGpuSlots(GpuBase):
    def test_two_gpus_encode_at_the_same_time(self):
        ids = self.videos(2)
        enc = Encoder()
        with self.gpus(enc):
            w = self.started()
            self.assertTrue(wait_for(lambda: enc.total() == 2), enc.log)
            self.assertEqual(sorted(d for d, _ in enc.log), ["nvenc:0", "nvenc:1"])
            self.assertEqual(gpus_only(w.slots.snapshot()), {"nvenc:0": 1, "nvenc:1": 1})
            w.heartbeat()
            hb = self.db.get_meta("worker_heartbeat")
            self.assertEqual(sorted(n for n in hb["lanes"] if n.startswith("video-")), ["video-0", "video-1"])
            self.assertEqual(sorted(hb["lanes"][n]["job"]["on"] for n in ("video-0", "video-1")),
                             ["nvenc:0", "nvenc:1"])
            self.assertEqual(gpus_only(hb["slots"]), {"nvenc:0": 1, "nvenc:1": 1})
            enc.gate.set()
            self.assertTrue(wait_for(lambda: self.done(ids)))
            w.stop()
        self.assertEqual(sorted(self.job(j)["result"]["device"] for j in ids), ["nvenc:0", "nvenc:1"])
        for j in ids:
            self.assertTrue(self.job(j)["worker"].endswith(("-video-0", "-video-1")), self.job(j)["worker"])
        self.assertEqual(enc.max_per, {"nvenc:0": 1, "nvenc:1": 1})
        self.assertEqual(w.slots.snapshot(), {})

    def test_gpu_jobs_runs_that_many_per_device(self):
        self.devs = [G0]
        self.conf["video"]["gpu_jobs"] = 2
        ids = self.videos(3)
        enc = Encoder()
        with self.gpus(enc):
            w = self.started()
            self.assertTrue(wait_for(lambda: enc.total() == 2))
            time.sleep(0.4)
            self.assertEqual((enc.total(), enc.on("nvenc:0")), (2, 2))     # the third waits for a free session
            self.assertEqual(len(w._video_slots()), 2)
            self.assertEqual([self.job(j)["state"] for j in ids].count("queued"), 1)
            enc.gate.set()
            self.assertTrue(wait_for(lambda: self.done(ids)))
            w.stop()
        self.assertEqual(enc.max_per, {"nvenc:0": 2})

    def test_slot_count_follows_gpus_and_gpu_jobs(self):
        self.conf["video"]["gpu_jobs"] = {"nvenc:1": 3, "*": 1}
        with self.gpus(Encoder()):
            w = self.started()
            self.assertEqual(len(w._video_slots()), 4)                       # 1 + 3
            self.conf["video"]["gpu_jobs"] = 1
            self.assertEqual(w.ensure_video_slots(), 4)                      # never shrinks: surplus slots idle
            w.stop()
        self.conf["video"]["format"] = "webm"                                # WebM: CPU only, no GPU slots
        with self.gpus(Encoder()):
            w2 = self.started()
            self.assertEqual(w2._video_slots(), [])
            w2.stop()
        self.conf["video"].update(format="mp4", encoder="nvenc")
        with self.gpus(Encoder()):                                           # --lanes scan,encode: no video lane
            w3 = self.started(lanes=("scan", "encode"))
            self.assertEqual(w3._video_slots(), [])
            w3.stop()

    def test_capacity_setting(self):
        vc = video.video_conf(self.conf)
        self.assertEqual(gpu.capacity(G0, vc), 1)
        for val, want0, want1 in ((3, 3, 3), ({"nvenc:1": 2}, 1, 2), ({"nvenc": 4, "nvenc:0": 2}, 2, 4),
                                  ({"*": 2}, 2, 2), (99, gpu.MAX_JOBS, gpu.MAX_JOBS), (0, 1, 1), ("x", 1, 1),
                                  (None, 1, 1)):
            vc = dict(vc, gpu_jobs=val)
            self.assertEqual((gpu.capacity(G0, vc), gpu.capacity(G1, vc)), (want0, want1), val)
        # where a job runs is not policy: video.gpu_jobs never changes the variant spec
        self.assertEqual(video.spec("mp4", self.conf), video.spec("mp4", dict(self.conf, video=dict(
            self.conf["video"], gpu_jobs={"nvenc:0": 4}))))
        self.assertEqual(gpu.summary({"devices": [dict(G1, error="", hint="")]}, dict(vc, gpu_jobs=2))["devices"][0]
                         ["jobs"], 2)

    def test_encode_lane_leaves_video_to_gpu_slots(self):
        self.devs = [G0]
        self.put("/p.png", noise_png())
        img = self.enqueue("image", "/p.png", priority=60)
        vid = self.videos(1)[0]                                              # more urgent than the image
        enc = Encoder(hold=False)
        with self.gpus(enc), mock.patch.object(imaging, "encode_auto", return_value=(b"\0" * 300, "avif")):
            w = self.make_worker()
            w.lanes["video-0"] = worker._Lane("video-0", ("video",), "w-video-0", "gpu")
            self.assertEqual(self.step(w, "encode"), "ran")
            self.assertEqual((self.job(img)["state"], self.job(vid)["state"]), ("done", "queued"))
            self.assertEqual(self.step(w, "video-0"), "ran")
        self.assertEqual(self.job(vid)["result"]["device"], "nvenc:0")
        self.assertEqual(w.slots.snapshot(), {})


class TestDiscoverySingleFlight(unittest.TestCase):
    def tearDown(self):
        gpu.reset()

    def test_parallel_callers_share_one_round_of_test_encodes(self):
        """Every slot asks video.available() when the 10-minute cache runs out: one discovery answers them all."""
        gpu.reset()
        calls = []

        class R:
            rc, timed_out, err, out = 0, False, "", ""

        def run(cmd, *a, **kw):
            calls.append(cmd)
            time.sleep(0.3)
            return R()
        res = []
        with mock.patch.object(gpu, "devices", side_effect=lambda names, run: [dict(G0)]):
            ts = [threading.Thread(target=lambda: res.append(gpu.discover(["ff"], {}, run, lambda ff: {"h264_nvenc"})))
                  for _ in range(4)]
            for t in ts:
                t.start()
            for t in ts:
                t.join(10)
            self.assertEqual(len(calls), 1)                                  # one test encode, not four
            self.assertEqual(len(res), 4)
            self.assertTrue(all(r is res[0] for r in res))
            gpu.discover(["ff"], {}, run, lambda ff: {"h264_nvenc"}, fresh=True)
            self.assertEqual(len(calls), 2)                                  # fresh still re-tests


# ---------------------------------------------------------------------------------------------------- CPU slot

class TestCpuSlot(GpuBase):
    def test_cpu_video_and_images_stay_one_at_a_time(self):
        self.conf["video"].update(format="webm", encoder="cpu")
        ids = self.videos(3)
        for i in range(2):
            self.put("/p%d.png" % i, noise_png())
            ids.append(self.enqueue("image", "/p%d.png" % i, priority=45))
        enc = Encoder(hold=False)

        def slow_img(*a, **kw):
            with enc.track("img"):
                time.sleep(0.15)
            return b"\0" * 300, "avif"

        def slow_tc(src, dst, plan, conf):
            time.sleep(0.15)
            r = enc(src, dst, plan, conf)
            return r
        with self.gpus(slow_tc), mock.patch.object(imaging, "encode_auto", side_effect=slow_img):
            w = self.started()
            self.assertTrue(wait_for(lambda: self.done(ids)))
            w.stop()
        self.assertEqual(w._video_slots(), [])
        self.assertEqual(enc.max_total, 1)                                   # one CPU encode at a time, as before
        self.assertEqual(len(enc.log), 5)
        for j in ids[:3]:
            self.assertTrue(self.job(j)["worker"].endswith("-encode"))
            self.assertEqual(self.job(j)["result"]["codec"], "av1")

    def test_gpu_video_runs_next_to_images(self):
        self.devs = [G0]
        vid = self.videos(1)[0]
        self.put("/p.png", noise_png())
        img = self.enqueue("image", "/p.png", priority=60)
        enc = Encoder()
        with self.gpus(enc), mock.patch.object(imaging, "encode_auto", return_value=(b"\0" * 300, "avif")):
            w = self.started()
            self.assertTrue(wait_for(lambda: enc.on("nvenc:0") == 1))
            self.assertTrue(wait_for(lambda: self.job(img)["state"] == "done"), "image waited for the GPU job")
            enc.gate.set()
            self.assertTrue(wait_for(lambda: self.done([vid])))
            w.stop()


# ---------------------------------------------------------------------------------------------------- bench / failover

class TestBenchAndFailover(GpuBase):
    def test_benched_gpu_gets_no_job_and_failover_waits_for_a_free_gpu(self):
        ids = self.videos(2)
        enc = Encoder()
        enc.fail = fail_once_busy(enc, "nvenc:0", "CUDA_ERROR_LAUNCH_FAILED", busy="nvenc:1")
        with self.gpus(enc):
            w = self.started()
            # one job fails on nvenc:0, the other holds nvenc:1: the failed one waits for nvenc:1 (explicit NVENC:
            # no CPU), and nothing new is started on the benched card
            self.assertTrue(wait_for(lambda: "nvenc:0" in gpu.benched() and enc.on("nvenc:1") == 1
                                     and w.slots.waiting == {"nvenc:1": 1}), (enc.log, w.slots.waiting))
            time.sleep(0.4)
            self.assertEqual([d for d, _ in enc.log].count("nvenc:0"), 1)
            self.assertEqual(enc.on("nvenc:1"), 1)
            self.assertEqual([self.job(j)["state"] for j in ids], ["running", "running"])
            enc.gate.set()
            self.assertTrue(wait_for(lambda: self.done(ids)))
            w.stop()
        self.assertEqual([d for d, _ in enc.log].count("nvenc:0"), 1)
        self.assertEqual(enc.max_per["nvenc:1"], 1)                          # never two jobs on one card
        self.assertEqual(sorted(self.job(j)["result"]["device"] for j in ids), ["nvenc:1", "nvenc:1"])
        ev = self.events(w, "video.gpu_fallback")
        self.assertEqual([(e["detail"]["device"], e["detail"]["next"]) for e in ev], [("nvenc:0", "nvenc:1")])

    def test_auto_failover_takes_the_free_cpu_slot(self):
        self.conf["video"]["encoder"] = "auto"
        ids = self.videos(2)
        enc = Encoder()
        enc.fail = fail_once_busy(enc, "nvenc:0", "GPU gone", busy="nvenc:1")
        with self.gpus(enc):
            w = self.started()
            self.assertTrue(wait_for(lambda: enc.on("cpu") == 1 and enc.on("nvenc:1") == 1), enc.log)
            self.assertEqual(w.slots.snapshot(), {"cpu": 1, "nvenc:1": 1})
            enc.gate.set()
            self.assertTrue(wait_for(lambda: self.done(ids)))
            w.stop()
        self.assertEqual(sorted(self.job(j)["result"]["codec"] for j in ids), ["h264", "h264_nvenc"])

    def test_session_cap_lowers_capacity_instead_of_benching(self):
        self.conf["video"].update(encoder="auto", gpu_jobs=2)
        self.devs = [G0]
        ids = self.videos(2)
        enc = Encoder(fail=lambda dev, n: SESSION_CAP if dev == "nvenc:0" and n == 2 else None)
        with self.gpus(enc):
            w = self.started()
            self.assertTrue(wait_for(lambda: enc.on("nvenc:0") == 1 and enc.on("cpu") == 1), enc.log)
            self.assertEqual(gpu.benched(), {})                              # full, not broken
            self.assertEqual(w.capacity(G0, video.video_conf(self.conf)), 1)
            enc.gate.set()
            self.assertTrue(wait_for(lambda: self.done(ids)))
            w.stop()
        ev = self.events(w, "video.gpu_fallback")
        self.assertEqual([(e["detail"]["next"], e["detail"]["reason"]) for e in ev], [("cpu", "session_limit")])
        with mock.patch.object(time, "monotonic", return_value=time.monotonic() + gpu.BENCH_S + 1):
            self.assertEqual(w.capacity(G0, video.video_conf(self.conf)), 2)   # back after the cut runs out

    def test_lone_session_cap_still_benches(self):
        """No other job of ours on that GPU: another program holds the sessions, so it rests like any failure."""
        self.conf["video"]["encoder"] = "auto"
        self.devs = [G0]
        ids = self.videos(1)
        enc = Encoder(fail=lambda dev, n: SESSION_CAP if dev == "nvenc:0" else None, hold=False)
        with self.gpus(enc):
            w = self.started()
            self.assertTrue(wait_for(lambda: self.done(ids)))
            w.stop()
        self.assertIn("nvenc:0", gpu.benched())
        self.assertEqual(self.job(ids[0])["result"]["codec"], "h264")


# ---------------------------------------------------------------------------------------------------- headroom

class TestHeadroom(GpuBase):
    def test_parallel_encodes_leave_headroom_for_scans(self):
        self.mon.cpu = 60                     # below cpu_max 65 (nothing pauses), within the 10-point headroom
        ids = self.videos(2)
        self.put("/a.txt", "hello")
        sj = self.enqueue("scan", "/a.txt", priority=10)
        enc = Encoder()
        with self.gpus(enc), mock.patch.object(scan, "scan_file", fake_scan()):
            w = self.started()
            self.assertTrue(wait_for(lambda: enc.total() == 1))
            self.assertTrue(wait_for(lambda: self.job(sj)["state"] == "done"), "scan lane starved")
            time.sleep(0.5)
            self.assertEqual(enc.total(), 1)                                 # no second parallel transcode
            self.assertIsNone(w.lanes["scan"].paused)
            self.mon.cpu = 10
            self.assertTrue(wait_for(lambda: enc.total() == 2))
            enc.gate.set()
            self.assertTrue(wait_for(lambda: self.done(ids)))
            w.stop()

    def test_parallel_needs_extra_memory(self):
        w = self.make_worker()
        self.mon.mem = self.conf["worker"]["mem_min_mb"] + worker.PARALLEL_MEM_MB - 1
        self.assertIsNone(w.pause_reason())
        self.assertFalse(w.parallel_ok())
        self.mon.mem += 2
        self.assertTrue(w.parallel_ok())


# ---------------------------------------------------------------------------------------------------- leases

class TestLeaseTokens(GpuBase):
    def test_store_token_guards_a_reclaimed_job(self):
        jid = self.db.enqueue("video", 1, "/x.mp4")
        a = self.db.claim("A", ["video"], lease_s=-1)
        self.assertTrue(a["lease"])
        self.assertNotIn("lease", self.job(jid))                             # never shown by the admin API
        self.assertTrue(self.db.heartbeat(jid, -1, token=a["lease"]))
        self.assertEqual(self.db.requeue_expired(3), 1)                      # A hung: its lease ran out
        b = self.db.claim("B", ["video"])
        self.assertNotEqual(a["lease"], b["lease"])
        self.assertFalse(self.db.heartbeat(jid, 900, token=a["lease"]))
        self.assertFalse(self.db.finish(jid, {"by": "A"}, token=a["lease"]))
        self.assertEqual(self.db.fail(jid, "late", "encode_error", token=a["lease"]), "lost")
        self.assertEqual((self.job(jid)["state"], self.job(jid)["worker"]), ("running", "B"))
        self.assertTrue(self.db.heartbeat(jid, 900, token=b["lease"]))
        self.assertTrue(self.db.finish(jid, {"by": "B"}, token=b["lease"]))
        self.assertEqual(self.job(jid)["result"], {"by": "B"})
        self.assertIsNone(self.db._db().execute("SELECT lease FROM job WHERE id=?", (jid,)).fetchone()[0])
        self.assertFalse(self.db.heartbeat(jid, 900))                        # done: nothing left to extend

    def test_worker_run_with_a_stale_claim_cannot_settle_the_new_one(self):
        jid = self.db.enqueue("video", 1, "/x.mp4")
        w = self.make_worker()
        stale = worker._Run(self.db.claim("w-video-0", ["video"], lease_s=-1), "encode")
        w.lanes["encode"].job = stale
        self.db.requeue_expired(3)
        fresh = worker._Run(self.db.claim("w-video-1", ["video"]), "scan")
        w.lease_beat(force=True)
        self.assertTrue(stale.lost)                                          # its beat is refused
        self.assertFalse(w._finish(stale, {"by": "stale"}))
        self.assertEqual(w._requeue(stale), "lost")
        self.assertEqual(self.job(jid)["state"], "running")
        self.assertTrue(w._finish(fresh, {"by": "fresh"}))
        self.assertEqual(self.job(jid)["result"], {"by": "fresh"})
        w.lanes["encode"].job = None

    def test_lease_column_added_to_an_old_db(self):
        path = os.path.join(self.tmp, "old", "media.db")
        os.makedirs(os.path.dirname(path))
        db = sqlite3.connect(path)
        db.execute("CREATE TABLE job(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, mount INTEGER, path TEXT, "
                   "params TEXT NOT NULL DEFAULT '', size INTEGER, mtime REAL, priority INTEGER NOT NULL, "
                   "state TEXT NOT NULL, attempts INTEGER DEFAULT 0, lease_until REAL, not_before REAL DEFAULT 0, "
                   "worker TEXT, created REAL, started REAL, finished REAL, error TEXT, error_kind TEXT, result TEXT, "
                   "UNIQUE(kind, mount, path, params))")
        db.execute("INSERT INTO job(kind, mount, path, priority, state, created) VALUES('video', 1, '/a', 40, "
                   "'queued', 0)")
        db.commit()
        db.close()
        st = store.Store(path).init()
        try:
            job = st.claim("w", ["video"])
            self.assertTrue(job["lease"])
            self.assertTrue(st.finish(job["id"], None, token=job["lease"]))
        finally:
            st.close()

    def test_running_video_slots_keep_their_leases(self):
        self.conf["worker"]["lease_s"] = 3                                   # beat every 1 s
        ids = self.videos(2)
        enc = Encoder()
        with self.gpus(enc):
            w = self.started()
            self.assertTrue(wait_for(lambda: enc.total() == 2))
            l0 = {j: self.job(j)["lease_until"] for j in ids}
            self.assertTrue(wait_for(lambda: all(self.job(j)["lease_until"] > l0[j] + 0.5 for j in ids)),
                            "leases not extended")
            self.db.cancel("video", 1, "/v1.mp4")                            # e.g. the file was deleted
            self.assertTrue(wait_for(lambda: any(ln.job is not None and ln.job.lost for ln in w._video_slots())))
            enc.gate.set()
            self.assertTrue(wait_for(lambda: self.job(ids[0])["state"] == "done"))
            self.assertTrue(wait_for(lambda: w.slots.snapshot() == {}))
            w.stop()
        self.assertEqual(self.job(ids[1])["state"], "cancelled")
        self.assertIsNone(self.db.variant(self.key(w, "/v1.mp4", video.spec("mp4", self.conf))))

    def test_stop_requeues_every_running_slot(self):
        ids = self.videos(2)
        enc = Encoder()
        with self.gpus(enc):
            w = self.started()
            self.assertTrue(wait_for(lambda: enc.total() == 2))
            w.stop(timeout=0.5)                                              # transcodes cannot be interrupted
            states = [(self.job(j)["state"], self.job(j)["error_kind"]) for j in ids]
            enc.gate.set()                                                   # ... and finish late: no effect
            time.sleep(0.3)
        self.assertEqual(states, [("queued", "stopped")] * 2)
        self.assertEqual([self.job(j)["state"] for j in ids], ["queued", "queued"])


if __name__ == "__main__":
    unittest.main()
