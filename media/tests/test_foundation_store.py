"""store.py: schema, job dedupe/claim/leases/backoff, verdicts incl. review fields, variants LRU, events, meta."""
import gc
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
MEDIA = os.path.dirname(HERE)
if MEDIA not in sys.path:
    sys.path.insert(0, MEDIA)

import store as store_mod  # noqa: E402
from store import Store  # noqa: E402


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


class StoreCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "sub", "media.db")
        self.s = Store(self.path).init()
        self.clock = Clock()
        self.s.clock = self.clock

    def tearDown(self):
        self.s.close()
        gc.collect()
        shutil.rmtree(self.tmp, ignore_errors=True)


class SchemaTest(StoreCase):
    def test_schema_idempotent_and_wal(self):
        self.s.init()
        db = sqlite3.connect(self.path)
        try:
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertEqual(tables, {"verdict", "job", "variant", "event", "sample", "meta"})
            idx = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'")}
            self.assertTrue({"verdict_updated", "verdict_state", "verdict_hash", "job_pick", "variant_src",
                             "variant_used", "event_ts", "event_kind"} <= idx)
            self.assertEqual(db.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")
        finally:
            db.close()
        self.assertEqual(self.s._db().execute("PRAGMA busy_timeout").fetchone()[0], 15000)

    def test_readonly(self):
        self.s.set_meta("x", 1)
        ro = Store(self.path, readonly=True)
        try:
            self.assertEqual(ro.get_meta("x"), 1)
            with self.assertRaises(sqlite3.OperationalError):
                ro.set_meta("x", 2)
        finally:
            ro.close()


class JobTest(StoreCase):
    def test_enqueue_dedupe(self):
        s = self.s
        a = s.enqueue("scan", 1, "/a.png", size=10, mtime=1.5, priority=60)
        self.assertIsInstance(a, int)
        self.assertEqual(s.enqueue("scan", "1", "/a.png", size=10, mtime=1.5, priority=10), a)
        self.assertEqual(s.jobs()[0]["priority"], 10)
        self.assertEqual(s.enqueue("scan", 1, "/a.png", size=10, mtime=1.5, priority=80), a)
        self.assertEqual(s.jobs()[0]["priority"], 10)                    # only ever lowered
        job = s.claim("w1", ["scan"])
        self.assertEqual(job["id"], a)
        self.assertEqual(s.enqueue("scan", 1, "/a.png", size=10, mtime=1.5, priority=5), a)
        j = s.jobs()[0]
        self.assertEqual((j["state"], j["priority"]), ("running", 5))
        self.assertTrue(s.finish(a, {"verdict": "clean"}))
        self.assertEqual(s.jobs(state="done")[0]["result"], {"verdict": "clean"})
        self.assertIsNone(s.enqueue("scan", 1, "/a.png", size=10, mtime=1.5, priority=10))   # done, unchanged
        self.assertEqual(s.enqueue("scan", 1, "/a.png", size=10, mtime=2.5, priority=60), a)  # content changed
        j = s.jobs()[0]
        self.assertEqual((j["state"], j["attempts"], j["mtime"], j["result"]), ("queued", 0, 2.5, None))
        s.finish(s.claim("w1", "scan")["id"])
        self.assertEqual(s.enqueue("scan", 1, "/a.png", size=10, mtime=2.5, force=True), a)   # force
        self.assertEqual(s.jobs()[0]["state"], "queued")
        self.assertEqual(len(s.jobs()), 1)

    def test_params_are_part_of_the_key(self):
        s = self.s
        a = s.enqueue("image", 1, "/a.png", params={"want": "avif", "b": 1})
        b = s.enqueue("image", 1, "/a.png", params={"b": 1, "want": "avif"})
        c = s.enqueue("image", 1, "/a.png", params={"want": "webp"})
        d = s.enqueue("scan", 1, "/a.png")
        self.assertEqual(a, b)
        self.assertEqual(len({a, c, d}), 3)
        self.assertEqual(s.jobs(kind="image")[0]["params"], '{"b":1,"want":"avif"}')

    def test_failed_requeue(self):
        s = self.s
        a = s.enqueue("image", 1, "/x.png", size=1, mtime=1.0)
        s.claim("w", ["image"])
        self.assertEqual(s.fail(a, "boom", "encode_error", max_attempts=1), "failed")
        self.assertEqual(s.enqueue("image", 1, "/x.png", size=1, mtime=1.0), a)     # failed -> requeue ...
        j = s.jobs()[0]
        self.assertEqual(j["state"], "queued")
        self.assertGreaterEqual(j["not_before"], self.clock() + store_mod.FAILED_REQUEUE_S - 1)  # ... not in a loop
        self.assertIsNone(s.claim("w", ["image"]))
        self.assertEqual(s.enqueue("image", 1, "/x.png", size=1, mtime=1.0, force=True), a)
        self.assertEqual(s.jobs()[0]["not_before"], 0)
        self.assertEqual(s.claim("w", ["image"])["id"], a)
        self.assertEqual(s.fail(a, "no ffmpeg", "tool_missing"), "failed")               # never retried
        self.assertIsNone(s.enqueue("image", 1, "/x.png", size=1, mtime=1.0))
        self.assertEqual(s.jobs()[0]["state"], "failed")
        self.assertEqual(s.enqueue("image", 1, "/x.png", size=2, mtime=1.0), a)         # new content: requeued
        s.claim("w", ["image"])
        s.fail(a, "no ffmpeg", "tool_missing")
        self.assertEqual(s.retry_failed("image"), 1)
        j = s.jobs()[0]
        self.assertEqual((j["state"], j["attempts"], j["error"]), ("queued", 0, None))

    def test_claim_order_kinds_and_not_before(self):
        s = self.s
        s.enqueue("video", 1, "/v.mp4", priority=40)
        s.enqueue("scan", 1, "/late.png", priority=10, not_before=self.clock() + 100)
        b = s.enqueue("scan", 1, "/b.png", priority=60)
        self.clock.advance(1)
        c = s.enqueue("scan", 1, "/c.png", priority=20)
        self.clock.advance(1)
        d = s.enqueue("scan", 1, "/d.png", priority=20)
        self.assertEqual([s.claim("w", ["scan"])["id"] for _ in range(3)], [c, d, b])   # priority, then age
        self.assertIsNone(s.claim("w", ["scan"]))                                        # /late not yet
        self.assertIsNone(s.claim("w", []))
        self.assertEqual(s.claim("w", ["image", "video"])["path"], "/v.mp4")
        self.clock.advance(100)
        job = s.claim("w", ("scan",), lease_s=30)
        self.assertEqual((job["path"], job["state"], job["worker"], job["attempts"]), ("/late.png", "running", "w", 1))
        self.assertEqual(job["lease_until"], self.clock() + 30)

    def test_claim_race_never_double_claims(self):
        s = self.s
        n = 240
        for i in range(n):
            s.enqueue("scan", 1, "/f%03d.png" % i, priority=i % 7)
        got, errors = [], []
        lock = threading.Lock()
        start = threading.Barrier(8)

        def worker(name):
            try:
                start.wait()
                while True:
                    job = s.claim(name, ["scan"])
                    if job is None:
                        break
                    with lock:
                        got.append(job["id"])
            except Exception as e:  # pragma: no cover - reported below
                errors.append(e)
            finally:
                s.close()

        threads = [threading.Thread(target=worker, args=("w%d" % i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(120)
        self.assertEqual(errors, [])
        self.assertEqual(len(got), n)
        self.assertEqual(len(set(got)), n)
        self.assertEqual(s.job_counts(), {"scan": {"running": n}})

    def test_leases_heartbeat_and_requeue(self):
        s = self.s
        a = s.enqueue("scan", 1, "/a.png")
        s.claim("w1", ["scan"], lease_s=10)
        self.clock.advance(5)
        self.assertTrue(s.heartbeat(a, lease_s=10))
        self.clock.advance(8)
        self.assertEqual(s.requeue_expired(), 0)
        self.clock.advance(3)
        self.assertEqual(s.requeue_expired(), 1)                  # worker died: back in the queue
        j = s.jobs()[0]
        self.assertEqual((j["state"], j["worker"], j["lease_until"]), ("queued", None, None))
        self.assertFalse(s.heartbeat(a))
        self.assertFalse(s.finish(a))                             # a stale worker cannot finish it
        s.claim("w2", ["scan"], lease_s=10)
        self.clock.advance(11)
        s.requeue_expired(max_attempts=3)
        s.claim("w3", ["scan"], lease_s=10)
        self.clock.advance(11)
        self.assertEqual(s.requeue_expired(max_attempts=3), 1)   # third claim expired: poison file, give up
        j = s.jobs()[0]
        self.assertEqual((j["state"], j["error_kind"], j["attempts"]), ("failed", "lease_expired", 3))

    def test_fail_backoff(self):
        s = self.s
        a = s.enqueue("scan", 1, "/a.png")
        s.claim("w", ["scan"])
        self.assertEqual(s.fail(a, "x" * 5000, "io"), "queued")
        j = s.jobs()[0]
        self.assertEqual(j["not_before"], self.clock() + 60)
        self.assertEqual(len(j["error"]), 2000)
        self.assertEqual(j["error_kind"], "io")
        self.assertIsNone(s.claim("w", ["scan"]))
        self.clock.advance(61)
        s.claim("w", ["scan"])
        self.assertEqual(s.fail(a, "again", "io"), "queued")
        self.assertEqual(s.jobs()[0]["not_before"], self.clock() + 600)
        self.clock.advance(601)
        s.claim("w", ["scan"])
        self.assertEqual(s.fail(a, "third", "io"), "failed")        # 3 attempts = max_attempts
        j = s.jobs(state="failed")[0]
        self.assertEqual((j["attempts"], j["error"]), (3, "third"))
        self.assertEqual(s.fail(a, "late", "io"), "failed")         # not running: unchanged
        # a longer max_attempts reaches the 1 h step; retry_in overrides
        b = s.enqueue("scan", 1, "/b.png")
        for _ in range(3):
            self.clock.advance(4000)
            s.claim("w", ["scan"])
            state = s.fail(b, "e", "io", max_attempts=5)
        self.assertEqual(state, "queued")
        self.assertEqual(s.jobs(kind="scan", state="queued")[0]["not_before"], self.clock() + 3600)
        self.clock.advance(4000)
        s.claim("w", ["scan"])
        s.fail(b, "e", "io", retry_in=7, max_attempts=5)
        self.assertEqual(s.jobs(state="queued")[0]["not_before"], self.clock() + 7)
        self.assertEqual(s.fail(999, "e", "io"), "missing")

    def test_cancel_counts_and_ages(self):
        s = self.s
        a = s.enqueue("scan", 1, "/a.png")
        b = s.enqueue("image", 1, "/a.png", params="avif")
        s.enqueue("scan", 1, "/other.png")
        self.clock.advance(50)
        self.assertAlmostEqual(s.oldest_queued_age(), 50)
        self.assertAlmostEqual(s.oldest_queued_age("image"), 50)
        self.assertIsNone(s.oldest_queued_age("video"))
        s.claim("w", ["image"])
        self.assertEqual(s.job_counts(), {"scan": {"queued": 2}, "image": {"running": 1}})
        self.assertEqual(s.cancel(None, 1, "/a.png"), 2)
        self.assertFalse(s.heartbeat(b))
        self.assertFalse(s.finish(b))
        self.assertEqual(s.jobs(state="cancelled")[0]["id"], b)
        self.assertEqual(s.enqueue("image", 1, "/a.png", params="avif"), b)     # cancelled -> requeued
        self.assertNotEqual(s.enqueue("scan", 1, "/a.png"), a)                  # deleted -> new row
        self.assertEqual(s.cancel("scan", 1, "/nothing"), 0)


class VerdictTest(StoreCase):
    def test_upsert_read_and_json(self):
        s = self.s
        self.assertIsNone(s.verdict(1, "/a.png"))
        s.set_verdict(1, "/a.png", size=10, mtime=1.5, state="pending", legacy=1)
        v = s.verdict("1", "/a.png")
        self.assertEqual((v["state"], v["legacy"], v["scanned"], v["updated"]), ("pending", 1, None, self.clock()))
        self.clock.advance(10)
        findings = [{"type": "github_token", "severity": "high", "sample": "ghp_…Xy3Q", "where": "ocr",
                     "confidence": 0.9}]
        s.set_verdict(1, "/a.png", size=10, mtime=1.5, state="flagged", qhash="h1", severity="high",
                      findings=findings, engines={"ocr": "tesseract 5.4", "av": ["defender"]}, legacy=1)
        v = s.verdict(1, "/a.png")
        self.assertEqual(v["findings"], findings)
        self.assertEqual(v["engines"]["av"], ["defender"])
        self.assertEqual(v["scanned"], self.clock())
        self.assertEqual(v["qhash"], "h1")
        with self.assertRaises(ValueError):
            s.set_verdict(1, "/a.png", size=10, mtime=1.5, state="bogus")

    def test_verdicts_since_counts_list(self):
        s = self.s
        s.set_verdict(1, "/a.png", size=1, mtime=1, state="clean")
        self.clock.advance(1)
        t = self.clock()
        self.clock.advance(1)
        s.set_verdict(1, "/b 100%_x.png", size=1, mtime=1, state="flagged", severity="medium")
        self.clock.advance(1)
        s.set_verdict(2, "/c.pdf", size=1, mtime=1, state="error")
        self.assertEqual([v["path"] for v in s.verdicts_since(t)], ["/b 100%_x.png", "/c.pdf"])
        self.assertEqual(len(s.verdicts_since(0)), 3)
        self.assertEqual(s.verdict_counts(), {"clean": 1, "flagged": 1, "error": 1})
        self.assertEqual([v["path"] for v in s.list_verdicts("flagged,error")], ["/c.pdf", "/b 100%_x.png"])
        self.assertEqual([v["path"] for v in s.list_verdicts(["clean"])], ["/a.png"])
        self.assertEqual([v["path"] for v in s.list_verdicts(q="100%_")], ["/b 100%_x.png"])
        self.assertEqual(s.list_verdicts(q="0%x"), [])
        self.assertEqual(len(s.list_verdicts(limit=1, offset=1)), 1)

    def test_verdict_by_hash_most_severe(self):
        s = self.s
        s.set_verdict(1, "/a.png", size=5, mtime=1, state="clean", qhash="q")
        s.set_verdict(1, "/b.png", size=5, mtime=1, state="pending", qhash="q")
        self.assertEqual(s.verdict_by_hash(5, "q")["path"], "/a.png")
        s.set_verdict(1, "/c.png", size=5, mtime=1, state="error", qhash="q")
        self.assertEqual(s.verdict_by_hash(5, "q")["path"], "/c.png")
        s.set_verdict(2, "/d.png", size=5, mtime=1, state="flagged", qhash="q", severity="medium")
        s.set_verdict(2, "/e.png", size=5, mtime=1, state="flagged", qhash="q", severity="high")
        self.assertEqual(s.verdict_by_hash(5, "q")["path"], "/e.png")
        self.assertIsNone(s.verdict_by_hash(6, "q"))
        self.assertIsNone(s.verdict_by_hash(5, None))

    def test_review_fields_survive_rescan_of_same_content(self):
        s = self.s
        s.set_verdict(1, "/a.png", size=10, mtime=1.0, qhash="q", state="flagged", severity="medium")
        self.assertTrue(s.review(1, "/a.png", "released", "alice", "screenshot of a public IP"))
        self.assertFalse(s.review(1, "/missing.png", "released", "alice"))
        with self.assertRaises(ValueError):
            s.review(1, "/a.png", "clean", "alice")
        s.set_verdict(1, "/a.png", size=10, mtime=1.0, qhash="q", state="flagged", severity="medium")
        v = s.verdict(1, "/a.png")
        self.assertEqual((v["state"], v["reviewed_by"], v["review_note"]),
                         ("released", "alice", "screenshot of a public IP"))
        s.set_verdict(1, "/a.png", size=10, mtime=1.0, state="flagged", severity="high")   # new evidence
        v = s.verdict(1, "/a.png")
        self.assertEqual((v["state"], v["reviewed_by"], v["qhash"]), ("flagged", "alice", "q"))
        s.review(1, "/a.png", "held", "bob")
        s.set_verdict(1, "/a.png", size=10, mtime=1.0, state="clean")                      # hold sticks
        self.assertEqual(s.verdict(1, "/a.png")["state"], "held")
        s.set_verdict(1, "/a.png", size=11, mtime=2.0, state="clean")                      # content changed
        v = s.verdict(1, "/a.png")
        self.assertEqual((v["state"], v["reviewed_by"], v["review_note"]), ("clean", None, None))
        s.review(1, "/a.png", "held", "bob")
        s.set_verdict(1, "/a.png", size=11, mtime=2.0, state="pending")                    # explicit rescan
        v = s.verdict(1, "/a.png")
        self.assertEqual((v["state"], v["reviewed_by"]), ("pending", None))
        s.set_verdict(1, "/a.png", size=11, mtime=2.0, qhash="h11", state="clean")
        s.review(1, "/a.png", "held", "bob")
        s.set_verdict(1, "/a.png", size=11, mtime=2.0, qhash="other", state="clean")       # hash differs
        v = s.verdict(1, "/a.png")
        self.assertEqual((v["state"], v["reviewed_by"], v["qhash"]), ("clean", None, "other"))

    def test_move_and_drop(self):
        s = self.s
        s.set_verdict(1, "/dir/a.png", size=1, mtime=1, state="flagged")
        s.set_verdict(1, "/dir/sub/b.png", size=1, mtime=1, state="clean")
        s.set_verdict(1, "/dirx/c.png", size=1, mtime=1, state="clean")
        s.set_verdict(1, "/new/a.png", size=9, mtime=9, state="clean")        # overwritten by the move
        s.put_variant("k1", mount=1, path="/dir/a.png", src_size=1, src_mtime=1, kind="img", fmt="avif",
                      spec="auto:avif:v1", file="/img/k1.avif", bytes=1, src_bytes=2, secs=0.1, beneficial=1)
        s.enqueue("scan", 1, "/dir/sub/b.png")
        s.move_verdict(1, "/dir", "/new")
        self.assertIsNone(s.verdict(1, "/dir/a.png"))
        self.assertEqual(s.verdict(1, "/new/a.png")["state"], "flagged")
        self.assertEqual(s.verdict(1, "/new/sub/b.png")["state"], "clean")
        self.assertEqual(s.verdict(1, "/dirx/c.png")["state"], "clean")        # sibling prefix untouched
        self.assertEqual(s.variants_for(1, "/new/a.png")[0]["key"], "k1")
        self.assertEqual(s.jobs()[0]["path"], "/new/sub/b.png")
        s.move_verdict(1, "/new/a.png", "/renamed.png")                         # single file
        self.assertEqual(s.verdict(1, "/renamed.png")["state"], "flagged")
        self.assertEqual(s.variants_for(1, "/renamed.png")[0]["key"], "k1")
        s.move_verdict(2, "/renamed.png", "/elsewhere.png")                     # other mount: no-op
        self.assertIsNotNone(s.verdict(1, "/renamed.png"))
        s.drop_verdict(1, "/renamed.png")
        self.assertIsNone(s.verdict(1, "/renamed.png"))


class VariantTest(StoreCase):
    def put(self, key, beneficial=1, path="/a.png", size=100):
        self.s.put_variant(key, mount=1, path=path, src_size=1000, src_mtime=1.0, kind="img", fmt="avif",
                           spec="auto:avif:v1", file=("/img/%s/%s.avif" % (key[:2], key)) if beneficial else None,
                           bytes=size, src_bytes=1000, secs=0.5, beneficial=beneficial)

    def test_lru_totals_drop(self):
        s = self.s
        for i, k in enumerate(["k1", "k2", "k3"]):
            self.put(k)
            self.clock.advance(10)
        self.put("n1", beneficial=0)
        self.assertEqual([r["key"] for r in s.lru_variants()], ["k1", "k2", "k3"])
        self.assertEqual([r["key"] for r in s.lru_variants(with_file=False)][:1], ["k1"])
        s.touch_variants(["k1", "k1", None])
        self.assertEqual([r["key"] for r in s.lru_variants(2)], ["k2", "k3"])
        self.assertEqual(s.variant("k1")["last_used"], self.clock())
        t = s.variant_totals()
        self.assertEqual({k: t[k] for k in ("count", "beneficial", "bytes", "src_bytes", "saved")},
                         {"count": 4, "beneficial": 3, "bytes": 300, "src_bytes": 3000, "saved": 2700})
        self.assertEqual(t["tiers"]["ephemeral"]["count"], 3)
        self.assertEqual(len(s.variants_for(1, "/a.png")), 4)
        self.assertEqual(s.drop_variant("k2")["key"], "k2")
        self.assertIsNone(s.drop_variant("k2"))
        rows = s.drop_variants(1, "/a.png")
        self.assertEqual(sorted(r["key"] for r in rows), ["k1", "k3", "n1"])
        self.assertEqual(s.variants_for(1, "/a.png"), [])
        self.assertEqual(s.variant_totals()["count"], 0)

    def test_hotness_survives_reencode_and_decays(self):
        s = self.s
        self.put("h1")
        hl = 3600.0
        s.add_hits({"h1": (4, 400, 3600), "missing": (9, 9, 9)}, hl)
        r = s.variant("h1")
        self.assertEqual((r["hits"], r["served"], r["saved"]), (4, 400, 3600))
        self.assertAlmostEqual(r["score"], 4.0)
        self.clock.advance(hl)                                   # one half-life later
        self.assertAlmostEqual(s.decayed(s.variant("h1"), self.clock(), hl), 2.0)
        s.add_hits({"h1": (1, 0, 0)}, hl)
        self.assertAlmostEqual(s.variant("h1")["score"], 3.0)
        self.put("h1", size=80)                                  # re-encode (upsert): counters are kept
        r = s.variant("h1")
        self.assertEqual((r["hits"], r["bytes"], r["tier"]), (5, 80, "ephemeral"))

    def test_tiers_tombstones_and_prune(self):
        s = self.s
        self.put("p1")
        self.assertTrue(s.set_tier("p1", "persistent", "/static/img/p1.avif", promoted=self.clock()))
        self.assertEqual([r["key"] for r in s.lru_variants()], [])          # persistent: never LRU-evicted
        self.assertEqual([r["key"] for r in s.variants_in_tier("persistent")], ["p1"])
        with self.assertRaises(ValueError):
            s.set_tier("p1", "bogus")
        self.put("e1")
        self.assertTrue(s.evict_variant("e1"))
        self.assertEqual((s.variant("e1")["tier"], s.variant("e1")["file"]), ("evicted", None))
        s.put_variant("f1", mount=1, path="/b.png", src_size=1, src_mtime=1.0, kind="img", fmt="orig", spec="x",
                      file=None, bytes=0, src_bytes=1, secs=0, beneficial=0, reason="failed:decode_error")
        self.put("e1")   # (a re-encode would revive a tombstone)
        s.evict_variant("e1")
        self.clock.advance(100)
        self.assertEqual(s.prune_variants(self.clock() - 50, self.clock() - 50), {"tombstones": 1, "failures": 1})
        self.assertIsNone(s.variant("e1"))
        self.assertIsNone(s.variant("f1"))
        self.assertIsNotNone(s.variant("p1"))
        self.assertEqual(sorted(x[4] for x in s.variant_sources()), ["p1"])
        self.assertEqual([r["key"] for r in s.drop_variant_keys(["p1"])], ["p1"])

    def test_migrates_v1_variant_table(self):
        import sqlite3
        path = os.path.join(self.tmp, "old.db")
        db = sqlite3.connect(path)
        db.execute("CREATE TABLE variant(key TEXT PRIMARY KEY, mount INTEGER, path TEXT, src_size INTEGER, "
                   "src_mtime REAL, kind TEXT, fmt TEXT, spec TEXT, file TEXT, bytes INTEGER, src_bytes INTEGER, "
                   "secs REAL, beneficial INTEGER, created REAL, last_used REAL)")
        db.execute("INSERT INTO variant(key, beneficial, file) VALUES('old', 1, '/img/x.avif')")
        db.commit()
        db.close()
        st = store_mod.Store(path).init()
        try:
            self.assertEqual((st.variant("old")["tier"], st.variant("old")["hits"]), ("ephemeral", 0))
            st.init()   # idempotent
        finally:
            st.close()


class EventMetaTest(StoreCase):
    def test_events(self):
        s = self.s
        s.add_events([{"ts": 100.0, "proc": "media", "kind": "bypass.breaker_open", "severity": "warning",
                       "mount": "1", "path": "/a.png", "detail": {"detail": "cpu"}},
                      {"ts": 101.0, "proc": "media", "kind": "bypass.queue_full", "mount": None},
                      {"ts": 102.0, "proc": "worker", "kind": "bypassx", "mount": "bad"},
                      {"ts": 103.0, "proc": "worker", "kind": "tool.missing", "detail": {"tool": "7z"}}])
        s.add_events([])
        ev = s.events()
        self.assertEqual([e["kind"] for e in ev], ["tool.missing", "bypassx", "bypass.queue_full",
                                                   "bypass.breaker_open"])
        self.assertEqual(ev[-1]["detail"], {"detail": "cpu"})
        self.assertEqual(ev[-1]["mount"], 1)
        self.assertIsNone(ev[1]["mount"])
        self.assertEqual([e["kind"] for e in s.events(kind="bypass")], ["bypass.queue_full", "bypass.breaker_open"])
        self.assertEqual(len(s.events(since=101.0)), 2)
        self.assertEqual(len(s.events(limit=1)), 1)
        self.assertEqual(s.event_counts(100.5), {"bypass.queue_full": 1, "bypassx": 1, "tool.missing": 1})

    def test_samples_meta_prune(self):
        s = self.s
        s.add_sample(60, "media", {"cpu_avg": 12.5})
        s.add_sample(60, "media", {"cpu_avg": 13.5})          # replace
        s.add_sample(120, "worker", {"jobs": 3})
        self.assertEqual([r["data"] for r in s.samples(0)], [{"cpu_avg": 13.5}, {"jobs": 3}])
        self.assertEqual(len(s.samples(0, proc="worker")), 1)
        self.assertEqual(len(s.samples(100)), 1)
        self.assertIsNone(s.get_meta("nope"))
        self.assertEqual(s.get_meta("nope", 5), 5)
        s.set_meta("breaker", {"state": "open", "ts": 1.5})
        s.set_meta("s", "text")
        s.set_meta("n", 3)
        self.assertEqual(s.get_meta("breaker"), {"state": "open", "ts": 1.5})
        self.assertEqual((s.get_meta("s"), s.get_meta("n")), ("text", 3))
        s._db().execute("INSERT INTO meta(k, v) VALUES('raw', 'not json')")
        self.assertEqual(s.get_meta("raw"), "not json")
        # prune: old events / finished jobs / samples go, fresh ones stay
        now = self.clock()
        s.add_events([{"ts": now - 40 * 86400, "kind": "old"}, {"ts": now - 86400, "kind": "new"}])
        a = s.enqueue("scan", 1, "/old.png")
        s.claim("w", ["scan"])
        s.finish(a)
        self.clock.advance(20 * 86400)
        b = s.enqueue("scan", 1, "/new.png")
        s.claim("w", ["scan"])
        s.finish(b)
        s.enqueue("scan", 1, "/queued.png")
        s.add_sample(int(self.clock() - 60), "media", {})
        s.prune(event_days=30, job_days=14, sample_days=30)
        self.assertEqual({e["kind"] for e in s.events()}, {"new"})      # 40 d + 20 d old goes, 1 d + 20 d stays
        self.assertEqual(sorted(j["path"] for j in s.jobs()), ["/new.png", "/queued.png"])
        self.assertEqual(len(s.samples(0)), 1)


if __name__ == "__main__":
    unittest.main()
