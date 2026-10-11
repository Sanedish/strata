"""events.py (JSONL + db flush, rotation, never raises) and cache.py (keys, atomic writes, adopt, LRU eviction)."""
import gc
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
MEDIA = os.path.dirname(HERE)
if MEDIA not in sys.path:
    sys.path.insert(0, MEDIA)

import cache as cache_mod  # noqa: E402
import events as events_mod  # noqa: E402
from cache import Cache  # noqa: E402
from events import Events  # noqa: E402
from store import Store  # noqa: E402


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


class FlakyStore:
    def __init__(self):
        self.fail, self.rows = True, []

    def add_events(self, rows):
        if self.fail:
            raise RuntimeError("database is locked")
        self.rows.extend(rows)


class TmpCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        gc.collect()
        shutil.rmtree(self.tmp, ignore_errors=True)


class EventsTest(TmpCase):
    def lines(self, path):
        with open(path, encoding="utf-8") as f:
            return [json.loads(line) for line in f]

    def test_emit_flush_jsonl_and_store(self):
        st = Store(os.path.join(self.tmp, "m.db")).init()
        log = os.path.join(self.tmp, "logs", "media-events.jsonl")
        ev = Events(st, log, "media")
        ev.emit("bypass.breaker_open", mount=1, path="/a.png", detail="cpu")
        ev.emit("bypass.queue_full", "warning", "1", "/b.png")
        ev.emit("tool.missing", "warning", tool="7z", obj=object())          # not JSON-serialisable: str()
        self.assertEqual(ev.counts(), {"bypass.breaker_open": 1, "bypass.queue_full": 1, "tool.missing": 1})
        self.assertEqual([e["kind"] for e in ev.recent(2)], ["tool.missing", "bypass.queue_full"])
        self.assertFalse(os.path.exists(log))                                 # nothing written on emit
        ev.flush()
        rows = self.lines(log)
        self.assertEqual([r["kind"] for r in rows], ["bypass.breaker_open", "bypass.queue_full", "tool.missing"])
        self.assertEqual(rows[0]["detail"], {"detail": "cpu"})
        self.assertEqual((rows[0]["proc"], rows[0]["mount"], rows[0]["path"]), ("media", 1, "/a.png"))
        self.assertTrue(rows[2]["detail"]["obj"].startswith("<object"))
        db = st.events()
        self.assertEqual(len(db), 3)
        self.assertEqual(db[-1]["detail"], {"detail": "cpu"})
        self.assertEqual({e["mount"] for e in db}, {1, None})
        ev.flush()
        self.assertEqual(len(self.lines(log)), 3)                             # nothing twice
        self.assertEqual(ev.stats()["written"], 3)
        st.close()

    def test_flusher_thread(self):
        log = os.path.join(self.tmp, "e.jsonl")
        ev = Events(None, log, "worker").start()
        try:
            ev.emit("job.failed", "warning", 1, "/x.pdf", error_kind="timeout")
            deadline = time.time() + 5
            while time.time() < deadline and not os.path.exists(log):
                time.sleep(0.05)
            self.assertEqual(self.lines(log)[0]["kind"], "job.failed")
        finally:
            ev.stop()

    def test_rotation(self):
        old = events_mod.ROTATE_BYTES
        events_mod.ROTATE_BYTES = 4000
        try:
            log = os.path.join(self.tmp, "r.jsonl")
            ev = Events(None, log, "media")
            for i in range(40):
                for _ in range(10):
                    ev.emit("encode.slow", secs=i, pad="x" * 60)
                ev.flush()
            self.assertLessEqual(os.path.getsize(log), 4000)
            rotated = sorted(n for n in os.listdir(self.tmp) if n.startswith("r.jsonl."))
            self.assertEqual(rotated, ["r.jsonl.%d" % i for i in range(1, events_mod.KEEP + 1)])
            for n in rotated:
                self.assertLessEqual(os.path.getsize(os.path.join(self.tmp, n)), 4000)
                self.lines(os.path.join(self.tmp, n))                         # every line intact JSON
            newest = self.lines(log)[-1]["detail"]["secs"]
            self.assertEqual(newest, 39)
            self.assertGreater(self.lines(os.path.join(self.tmp, "r.jsonl.1"))[-1]["detail"]["secs"],
                               self.lines(os.path.join(self.tmp, "r.jsonl.2"))[-1]["detail"]["secs"])
        finally:
            events_mod.ROTATE_BYTES = old

    def test_never_raises_and_retries_db(self):
        flaky = FlakyStore()
        bad_log = os.path.join(self.tmp, "is_a_dir")
        os.makedirs(bad_log)                                                  # the log path is a directory
        ev = Events(flaky, bad_log, "media")
        ev.emit("a")
        ev.emit(None, severity=None, mount=object(), path=b"\xff")
        ev.flush()                                                            # db down, JSONL impossible
        self.assertGreaterEqual(ev.stats()["errors"], 2)
        self.assertEqual(ev.stats()["retry"], 2)
        flaky.fail = False
        ev.flush()
        self.assertEqual([r["kind"] for r in flaky.rows], ["a", "None"])
        self.assertEqual(ev.stats()["retry"], 0)

    def test_queue_is_bounded(self):
        old = events_mod.MAX_QUEUE
        events_mod.MAX_QUEUE = 50
        try:
            ev = Events(None, None, "media")
            ev._q = type(ev._q)(maxlen=50)
            for i in range(80):
                ev.emit("k", n=i)
            self.assertEqual(len(ev._q), 50)
            self.assertEqual(ev.stats()["dropped"], 30)
            self.assertEqual(ev.counts()["k"], 80)
        finally:
            events_mod.MAX_QUEUE = old

    def test_emit_every(self):
        ev = Events(None, None, "worker")
        self.assertTrue(ev.emit_every(600, "tool.missing", key="7z", tool="7z"))
        self.assertFalse(ev.emit_every(600, "tool.missing", key="7z", tool="7z"))
        self.assertTrue(ev.emit_every(600, "tool.missing", key="tesseract", tool="tesseract"))
        self.assertEqual(ev.counts()["tool.missing"], 2)


class CacheTest(TmpCase):
    def setUp(self):
        super().setUp()
        self.store = Store(os.path.join(self.tmp, "m.db")).init()
        self.clock = Clock()
        self.store.clock = self.clock
        self.root = os.path.join(self.tmp, "media-cache")

    def tearDown(self):
        self.store.close()
        super().tearDown()

    def test_keys_and_paths(self):
        c = Cache(self.root, 1 << 20, self.store)
        k = c.key(1, "/general/photo.png", 29400000, 1727600000.25, "auto:avif:v1")
        self.assertRegex(k, r"^[0-9a-f]{40}$")
        self.assertEqual(k, c.key("1", "/general/photo.png", 29400000, 1727600000.25, "auto:avif:v1"))
        for other in [(2, "/general/photo.png", 29400000, 1727600000.25, "auto:avif:v1"),
                      (1, "/general/photo2.png", 29400000, 1727600000.25, "auto:avif:v1"),
                      (1, "/general/photo.png", 29400001, 1727600000.25, "auto:avif:v1"),
                      (1, "/general/photo.png", 29400000, 1727600000.5, "auto:avif:v1"),
                      (1, "/general/photo.png", 29400000, 1727600000.25, "auto:webp:v1")]:
            self.assertNotEqual(c.key(*other), k)
        # two shard levels (65 536 directories), the persistent tier under static/
        self.assertEqual(c.rel_url(k, "AVIF", "img"), "/img/%s/%s/%s.avif" % (k[:2], k[2:4], k))
        self.assertEqual(c.rel_url(k, ".webm", "video"), "/vid/%s/%s/%s.webm" % (k[:2], k[2:4], k))
        self.assertEqual(c.rel_url(k, "avif", "img", "persistent"), "/static/img/%s/%s/%s.avif" % (k[:2], k[2:4], k))
        self.assertEqual(c.path_for(k, "avif", "image"),
                         os.path.join(self.root, "cache", "img", k[:2], k[2:4], k + ".avif"))
        self.assertEqual(c.path_for(k, "avif", "image", "persistent"),
                         os.path.join(self.root, "cache", "static", "img", k[:2], k[2:4], k + ".avif"))
        self.assertEqual((c.tier_of(c.rel_url(k, "avif", "img")), c.tier_of(c.rel_url(k, "avif", "img", "persistent"))),
                         ("ephemeral", "persistent"))
        for bad in [(k, "avif", "doc"), (k, "av/if", "img"), (k, "", "img"), ("../" + k[3:], "avif", "img"),
                    (k.upper(), "avif", "img")]:
            with self.assertRaises(ValueError):
                c.rel_url(*bad)
        for bad in ("/img/../../x.avif", "/img/ab/cd/%s.avif" % k, "img/%s/%s/%s.avif" % (k[:2], k[2:4], k),
                    "/img/%s/%s.avif" % (k[:2], k), "/img/%s/%s/%s" % (k[:2], k[2:4], k),
                    "/static/../img/%s/%s/%s.avif" % (k[:2], k[2:4], k), "/tmp/%s/%s/%s.avif" % (k[:2], k[2:4], k),
                    "", None):
            self.assertFalse(c.exists(bad), bad)

    def test_atomic_write_and_adopt(self):
        c = Cache(self.root, 1 << 20, self.store)
        k = c.key(1, "/a.png", 10, 1.0, "auto:avif:v1")
        rel = c.write_bytes(k, "avif", "img", b"AVIFDATA")
        self.assertEqual(rel, c.rel_url(k, "avif", "img"))
        self.assertTrue(c.exists(rel))
        with open(c.path_for(k, "avif", "img"), "rb") as f:
            self.assertEqual(f.read(), b"AVIFDATA")
        self.assertEqual(os.listdir(c.tmp_dir), [])
        rel2 = c.write_bytes(k, "avif", "img", b"NEWER")                     # replace in place
        self.assertEqual(rel2, rel)
        with open(c.path_for(k, "avif", "img"), "rb") as f:
            self.assertEqual(f.read(), b"NEWER")
        with self.assertRaises(TypeError):
            c.write_bytes(k, "avif", "img", "not bytes")
        self.assertEqual(os.listdir(c.tmp_dir), [])                           # failed write leaves nothing
        with open(c.path_for(k, "avif", "img"), "rb") as f:
            self.assertEqual(f.read(), b"NEWER")                              # and the old variant intact
        tmp = c.tmp_path(".webm")
        self.assertEqual(os.path.dirname(tmp), c.tmp_dir)
        with open(tmp, "wb") as f:
            f.write(b"WEBM" * 100)
        kv = c.key(1, "/v.mp4", 10, 1.0, "webm:av1:v1")
        relv = c.adopt(kv, "webm", "vid", tmp)
        self.assertTrue(relv.startswith("/vid/"))
        self.assertFalse(os.path.exists(tmp))
        self.assertEqual(os.path.getsize(c.path_for(kv, "webm", "vid")), 400)
        self.assertTrue(c.remove(relv))
        self.assertFalse(c.exists(relv))
        u = c.usage(fresh=True)
        self.assertEqual((u["bytes"], u["files"], u["max_bytes"]), (5, 1, 1 << 20))
        self.assertGreater(u["disk_free"], 0)

    def fill(self, c, n, size=1000):
        keys = []
        for i in range(n):
            k = c.key(1, "/f%02d.png" % i, size, 1.0, "auto:avif:v1")
            rel = c.write_bytes(k, "avif", "img", b"x" * size)
            self.store.put_variant(k, mount=1, path="/f%02d.png" % i, src_size=size * 10, src_mtime=1.0, kind="img",
                                   fmt="avif", spec="auto:avif:v1", file=rel, bytes=size, src_bytes=size * 10,
                                   secs=0.1, beneficial=1)
            self.clock.advance(1)
            keys.append(k)
        return keys

    def test_evict_lru_to_90_percent(self):
        c = Cache(self.root, 10_000, self.store)
        keys = self.fill(c, 20)                                # 20 000 bytes, cap 10 000
        self.store.put_variant("n" * 40, mount=1, path="/small.png", src_size=10, src_mtime=1.0, kind="img",
                               fmt="avif", spec="auto:avif:v1", file=None, bytes=12, src_bytes=10, secs=0.1,
                               beneficial=0)
        self.clock.advance(1)
        self.store.touch_variants([keys[0]])                   # recently used: must survive
        stats = c.evict()
        self.assertLessEqual(stats["bytes"], 9000)
        self.assertEqual(stats["removed"], 11)
        u = c.usage(fresh=True)
        self.assertEqual(u["bytes"], 9000)
        left = {r["key"] for r in self.store.lru_variants(100)}
        self.assertIn(keys[0], left)
        self.assertEqual(left, {keys[0]} | set(keys[12:]))
        for k in keys[1:12]:
            self.assertFalse(os.path.exists(c.path_for(k, "avif", "img")))
            row = self.store.variant(k)                         # a tombstone: hotness + ETag survive eviction
            self.assertEqual((row["tier"], row["file"]), ("evicted", None))
        self.assertIsNotNone(self.store.variant("n" * 40))   # not-beneficial decisions are kept
        self.assertEqual(c.evict()["removed"], 0)               # under the cap: nothing to do

    def test_evict_orphans_and_stale_tmp(self):
        c = Cache(self.root, 3000, self.store)
        old = time.time() - 2 * cache_mod.ORPHAN_MIN_AGE
        orphans = []
        for i in range(5):                                      # files without variant rows (crash, lost rows)
            k = c.key(9, "/o%d.png" % i, 1000, 1.0, "x")
            orphans.append(c.write_bytes(k, "webp", "img", b"o" * 1000))
            os.utime(c._path(orphans[-1]), (old + i, old + i))
        fresh = c.write_bytes(c.key(9, "/new.png", 1000, 1.0, "x"), "webp", "img", b"n" * 1000)
        stale = c.tmp_path(".part")
        with open(stale, "wb") as f:
            f.write(b"t")
        os.utime(stale, (time.time() - cache_mod.TMP_MAX_AGE - 10,) * 2)
        live = c.tmp_path(".part")
        with open(live, "wb") as f:
            f.write(b"t")
        # orphan age is the file's creation time (variant files carry their *source's* mtime), which utime cannot
        # backdate: let mtime stand in for it here
        with mock.patch.object(cache_mod, "_created", lambda st: st.st_mtime):
            stats = c.evict()
        self.assertEqual(stats["tmp_removed"], 1)
        self.assertFalse(os.path.exists(stale))
        self.assertTrue(os.path.exists(live))
        self.assertLessEqual(stats["bytes"], 2700)
        self.assertTrue(c.exists(fresh))                        # younger than ORPHAN_MIN_AGE: kept
        self.assertEqual([c.exists(r) for r in orphans], [False, False, False, False, True])   # oldest first

    def test_fresh_file_with_old_source_mtime_is_not_an_old_orphan(self):
        c = Cache(self.root, 1000, self.store)
        rel = c.write_bytes(c.key(9, "/x.png", 5000, 1.0, "x"), "avif", "img", b"v" * 3000, mtime=1_000_000.0)
        self.assertEqual(os.stat(c._path(rel)).st_mtime, 1_000_000.0)   # deterministic mtime (stable ETag)
        c.evict()                                                         # over the cap, row not written yet
        self.assertTrue(c.exists(rel))                                    # created just now: not an orphan yet

    def test_maybe_evict_throttle_and_touch(self):
        c = Cache(self.root, 10_000, self.store)
        mono = Clock(500.0)
        c.clock = mono
        keys = self.fill(c, 3)

        def wait_idle():
            self.assertTrue(c._evict_lock.acquire(timeout=10))
            c._evict_lock.release()
        self.assertTrue(c.maybe_evict())
        wait_idle()
        self.assertIn("removed", c.last_evict)
        self.assertFalse(c.maybe_evict())                       # within 60 s
        mono.advance(59)
        self.assertFalse(c.maybe_evict())
        mono.advance(2)
        self.assertTrue(c.maybe_evict())
        wait_idle()
        self.clock.advance(100)
        c.touch(keys[1])
        c.flush_touches()
        self.assertEqual(self.store.variant(keys[1])["last_used"], self.clock())
        self.assertEqual(self.store.lru_variants(1)[0]["key"], keys[0])


if __name__ == "__main__":
    unittest.main()
