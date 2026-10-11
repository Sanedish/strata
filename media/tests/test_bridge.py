"""media_bridge.py (DESIGN 2, 13, 13.1, 13.2): capacity advice, discovery, verdict watcher, events watcher,
negotiation, admin API, upload / rename hooks and the process supervisor.

Never touches production: a synthetic strata-like sqlite (meta, metric, fidx, audit) and media.db live in a temp dir,
core.connect / core.save_config / CFG["media"] are swapped in memory and restored, Cloudflare, purges, alerts and
rules.apply are fakes, and every process / server uses the test ports 18283-18289.
"""
import copy
import http.server
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
MEDIA_DIR = os.path.dirname(HERE)
STRATA = os.path.dirname(MEDIA_DIR)
for _p in (MEDIA_DIR, STRATA):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import core  # noqa: E402

# tests follow the design defaults, never whatever the live strata.json currently says (e.g. the deployed profile)
core.CFG["media"].clear()
core.CFG["media"].update(copy.deepcopy(core.DEFAULTS["media"]))
import cloudflare  # noqa: E402
import media_bridge as mb  # noqa: E402
import media_rules  # noqa: E402
import store as mstore  # noqa: E402
import cache as mcache  # noqa: E402

P_MEDIA, P_BREAKER, P_SUP, P_EXT, P_SICK, P_PRIO = 18283, 18284, 18285, 18286, 18287, 18288
HOST = "cdn.example.test"
TOKEN = "unit-test-admin-token"

DUMMY = r'''
import json, os, sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
port, mode = int(sys.argv[1]), (sys.argv[2] if len(sys.argv) > 2 else "ok")
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/_exit":
            self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers(); self.wfile.flush()
            threading.Timer(0.1, lambda: os._exit(3)).start()
            return
        body = json.dumps({"pid": os.getpid()}).encode()
        self.send_response(200 if mode == "ok" else 500)
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *a):
        pass
HTTPServer(("127.0.0.1", port), H).serve_forever()
'''


def wait_for(pred, timeout=20.0, tick=None, step=0.1):
    end = time.time() + timeout
    while time.time() < end:
        if tick:
            tick()
        if pred():
            return True
        time.sleep(step)
    return False


def make_strata_db(path):
    db = sqlite3.connect(path)
    db.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT);
        CREATE TABLE metric(key TEXT NOT NULL, ts INTEGER NOT NULL, val REAL, PRIMARY KEY(key, ts)) WITHOUT ROWID;
        CREATE TABLE fidx(mount INTEGER NOT NULL, path TEXT NOT NULL, parent TEXT, name TEXT, ext TEXT, cat TEXT,
          size INTEGER, mtime REAL, depth INTEGER, qhash TEXT, hash TEXT, PRIMARY KEY(mount, path)) WITHOUT ROWID;
        CREATE TABLE audit(ts REAL, ip TEXT, user TEXT, action TEXT, target TEXT, ok INTEGER, note TEXT);
        CREATE TABLE audit_event(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, ip TEXT, user TEXT, action TEXT,
          target TEXT, ok INTEGER, note TEXT);
    """)
    db.commit()
    db.close()


class FakeEdge:
    PERMS = {"transform": "Zone › Transform Rules › Edit"}

    def __init__(self):
        self.fail, self.calls = None, []

    def sync_media_rules(self, enable, hosts=None, img_exts=None, vid_exts=None):
        self.calls.append(enable)
        if self.fail:
            raise self.fail
        return {"rules": {r: bool(enable) for r in ("strata_media_avif", "strata_media_webp", "strata_media_webm")},
                "created": [], "updated": [], "deleted": []}

    def capabilities(self):
        return {"transform": {"ok": self.fail is None, "error": str(self.fail or "")}, "purge": {"ok": None}}


class Base(unittest.TestCase):
    """Temp strata-like DB + media.db + a drive dir; a Bridge wired to fakes only."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="strata-media-bridge-")
        self.saved = (copy.deepcopy(core.CFG["media"]), core.connect, core.save_config, mb.BRIDGE,
                      media_rules.file_policy_preview)
        self.strata_db = os.path.join(self.tmp, "strata-test.db")
        make_strata_db(self.strata_db)
        core.connect = self.connect
        self.saves = []
        core.save_config = self.fake_save
        self.drive = os.path.join(self.tmp, "drive")
        os.makedirs(self.drive)
        self.t0 = time.time() - 1000
        m = core.CFG["media"]
        m.update(enabled=True, db=os.path.join(self.tmp, "media.db"), cache_root=os.path.join(self.tmp, "mcache"),
                 listen="127.0.0.1:%d" % P_MEDIA, admin_token=TOKEN, cutover=self.t0, negotiation="auto")
        m["image"]["min_bytes"] = 16
        self.store = mstore.Store(m["db"]).init()
        self.cache = mcache.Cache(m["cache_root"], 1 << 30, self.store)
        self.mounts = [{"id": 1, "name": "T", "kind": "files", "path": self.drive, "prefix": "/", "hosts": [HOST],
                        "cache": "public, no-cache", "edge_cache": "", "transforms": 1, "enabled": 1}]
        self.purged, self.alerts, self.applied, self.soon, self.hits = [], [], [], [], {}
        self.edge = FakeEdge()
        self.bridge = self.make_bridge()
        mb.BRIDGE = self.bridge

    def tearDown(self):
        try:
            self.bridge.stop()
        except Exception:
            pass
        self.store.close()
        m, core.connect, core.save_config, mb.BRIDGE, media_rules.file_policy_preview = self.saved
        core.CFG["media"].clear()
        core.CFG["media"].update(m)
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- fakes
    def connect(self):
        db = sqlite3.connect(self.strata_db, timeout=15, check_same_thread=False)
        db.execute("PRAGMA busy_timeout=15000")
        return db

    def fake_save(self, updates):
        self.saves.append(copy.deepcopy(updates))
        core._merge(core.CFG, copy.deepcopy(updates))

    def alert(self, kind, severity, title, detail="", key=None, coalesce_minutes=None):
        probe = sqlite3.connect(self.strata_db, timeout=0)
        try:
            probe.execute("BEGIN IMMEDIATE")
            probe.execute("ROLLBACK")
            locked = False
        except sqlite3.OperationalError:
            locked = True
        finally:
            probe.close()
        self.alerts.append({"kind": kind, "severity": severity, "title": title, "detail": detail, "key": key,
                            "coalesce": coalesce_minutes, "locked": locked, "tx_open": self.bridge.tx_open()})

    def make_bridge(self, **kw):
        args = dict(connect=self.connect, store=self.store, cache=self.cache, supervisor=mb.Supervisor([]),
                    edge=self.edge, purge=self.purged.extend, alert=self.alert, hits=lambda: self.hits,
                    mounts=lambda: self.mounts, apply_soon=lambda: self.soon.append(1),
                    apply=lambda user, reason: self.applied.append((user, reason)) or {"changed": False})
        args.update(kw)
        return mb.Bridge(**args)

    # -- helpers
    def put(self, rel, size=5000, mtime=None, index=True):
        full = os.path.join(self.drive, *rel.strip("/").split("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as f:
            f.write(b"x" * size)
        t = self.t0 + 100 if mtime is None else mtime
        os.utime(full, (t, t))
        st = os.stat(full)
        if index:
            self.index(1, rel, st.st_size, st.st_mtime)
        return st

    def index(self, mid, rel, size, mtime):
        db = self.connect()
        with db:
            db.execute("INSERT OR REPLACE INTO fidx(mount, path, name, size, mtime) VALUES(?,?,?,?,?)",
                       [mid, rel, rel.rsplit("/", 1)[-1], size, mtime])
        db.close()

    def meta(self, k):
        db = self.connect()
        try:
            return core.get_meta(db, k)
        finally:
            db.close()

    def jobs(self):
        return {(j["kind"], j["mount"], j["path"]): j for j in self.store.jobs(limit=10000)}

    def assert_alerts_clean(self):
        for a in self.alerts:
            self.assertFalse(a["locked"], "alert raised while strata.db had an open write transaction: %s" % a)
            self.assertFalse(a["tx_open"], "alert raised inside Bridge.strata(): %s" % a)


# ---------------------------------------------------------------- capacity advisor (pure)

class Advise(unittest.TestCase):
    def res(self, **inputs):
        return {r["resource"]: r for r in mb.advise(inputs, None, ncpu=6)}

    def test_quiet_and_missing_inputs(self):
        self.assertEqual(mb.advise({}, None, 6), [])
        self.assertEqual(mb.advise({"cpu_p95": 40, "mem_p95": 60, "tx_p95_mbps": 10, "open_ratio": 0.0,
                                    "trips_24h": 2, "mem_bypass_1h": 0, "oldest_job_s": 30, "oldest_scan_s": 30,
                                    "queued_scans": 3, "disk_free": 50e9, "disk_total": 100e9}, None, 6), [])

    def test_cpu(self):
        r = self.res(cpu_p95=92, open_ratio=0.14)["cpu"]
        self.assertEqual((r["level"], r["recommendation"]), ("upgrade", "add 2 vCPU (6 -> 8)"))
        self.assertIn("92", r["evidence"])
        self.assertEqual(self.res(cpu_p95=92, oldest_job_s=3 * 3600)["cpu"]["level"], "upgrade")
        self.assertNotIn("cpu", self.res(cpu_p95=92, open_ratio=0.05, oldest_job_s=600))  # busy but coping
        self.assertNotIn("cpu", self.res(cpu_p95=50, open_ratio=0.5))
        self.assertEqual(self.res(cpu_p95=50, trips_24h=21)["cpu"]["level"], "watch")
        self.assertNotIn("cpu", self.res(trips_24h=20))

    def test_memory_backlog_uplink_disk(self):
        self.assertEqual(self.res(mem_p95=95)["memory"]["recommendation"], "add 4 GB RAM")
        self.assertEqual(self.res(mem_p95=50, mem_bypass_1h=1)["memory"]["level"], "upgrade")
        self.assertNotIn("memory", self.res(mem_p95=90))
        self.assertEqual(self.res(oldest_scan_s=7 * 3600)["backlog"]["recommendation"], "background pipeline behind (scans)")
        self.assertIn("backlog", self.res(queued_scans=501))
        self.assertNotIn("backlog", self.res(queued_scans=500, oldest_scan_s=5 * 3600))
        self.assertIn("uplink saturated", self.res(tx_p95_mbps=41)["uplink"]["recommendation"])
        self.assertNotIn("uplink", self.res(tx_p95_mbps=39))
        self.assertEqual(self.res(disk_free=5e9, disk_total=100e9)["disk"]["level"], "upgrade")
        self.assertNotIn("disk", self.res(disk_free=20e9, disk_total=100e9))

    def test_thresholds_from_config(self):
        cap = {"cpu_p95": 50, "open_ratio": 0.01, "uplink_mbps": 100, "cache_free_pct": 30}
        rows = {r["resource"]: r for r in mb.advise({"cpu_p95": 60, "open_ratio": 0.02, "tx_p95_mbps": 50,
                                                     "disk_free": 20, "disk_total": 100}, cap, 8)}
        self.assertEqual(rows["cpu"]["recommendation"], "add 2 vCPU (8 -> 10)")
        self.assertNotIn("uplink", rows)
        self.assertIn("disk", rows)


# ---------------------------------------------------------------- discovery

class Discovery(Base):
    def test_discovery_enqueues_drops_and_prewarms(self):
        core.CFG["media"]["worker"]["backfill"] = True          # both default off (demand-driven optimizer)
        core.CFG["media"]["image"]["prewarm_uploads"] = True
        old = self.t0 - 10000
        st_new = self.put("/img/new.png")
        self.put("/docs/old.pdf", mtime=old)
        st_clean = self.put("/docs/clean.txt", mtime=old)
        self.store.set_verdict(1, "/docs/clean.txt", size=st_clean.st_size, mtime=st_clean.st_mtime, state="clean")
        st_ch = self.put("/docs/changed.txt", mtime=old)
        self.store.set_verdict(1, "/docs/changed.txt", size=st_ch.st_size + 1, mtime=st_ch.st_mtime, state="clean")
        self.put("/music/song.mp3")
        self.put("/video/clip.mp4")
        st_svg = self.put("/pending.svg")
        self.store.set_verdict(1, "/pending.svg", size=st_svg.st_size, mtime=st_svg.st_mtime, state="pending")
        self.store.enqueue("scan", 1, "/pending.svg", size=st_svg.st_size, mtime=st_svg.st_mtime, priority=10)
        self.put("/img/pop.jpg", mtime=old)
        self.hits = {"/img/pop.jpg": [50, 1000, time.time()], "/music/song.mp3": [99, 1, 1]}
        # a file deleted from index and disk, with a variant in the cache
        self.store.set_verdict(1, "/deleted.png", size=10, mtime=1.0, state="flagged", severity="high")
        key = self.cache.key(1, "/deleted.png", 10, 1.0, "auto:avif:v1")
        rel = self.cache.write_bytes(key, "avif", "img", b"avif-bytes")
        self.store.put_variant(key, mount=1, path="/deleted.png", src_size=10, src_mtime=1.0, kind="img", fmt="avif",
                               spec="auto:avif:v1", file=rel, bytes=10, src_bytes=10, secs=0.1, beneficial=1)
        self.assertTrue(self.cache.exists(rel))
        # on disk but not (yet) indexed: kept
        st_ni = self.put("/notindexed.png", index=False)
        self.store.set_verdict(1, "/notindexed.png", size=st_ni.st_size, mtime=st_ni.st_mtime, state="clean")

        res = self.bridge.discover()
        jobs = self.jobs()
        prio = {(k, p): j["priority"] for (k, _, p), j in jobs.items()}
        self.assertEqual(prio[("scan", "/img/new.png")], 60)
        self.assertEqual(prio[("scan", "/docs/old.pdf")], 80)
        self.assertEqual(prio[("scan", "/docs/changed.txt")], 80)
        self.assertEqual(prio[("scan", "/img/pop.jpg")], 80)
        self.assertEqual(prio[("scan", "/pending.svg")], 10)       # already queued: left alone
        self.assertEqual(prio[("image", "/img/new.png")], 70)      # new image prewarm
        self.assertEqual(prio[("image", "/img/pop.jpg")], 85)      # popular prewarm
        for p in ("/docs/clean.txt", "/music/song.mp3", "/video/clip.mp4"):
            self.assertNotIn(("scan", p), prio)
        self.assertNotIn(("image", "/music/song.mp3"), prio)
        self.assertEqual(jobs[("image", 1, "/img/new.png")]["params"], '{"want":"avif"}')
        self.assertEqual(jobs[("scan", 1, "/img/new.png")]["size"], st_new.st_size)
        self.assertEqual((res["new"], res["legacy"], res["dropped"], res["prewarm"], res["popular"]), (1, 3, 1, 1, 1))
        self.assertIsNone(self.store.verdict(1, "/deleted.png"))
        self.assertEqual(self.store.variants_for(1, "/deleted.png"), [])
        self.assertFalse(self.cache.exists(rel))
        self.assertIsNotNone(self.store.verdict(1, "/notindexed.png"))
        # a second pass finds nothing new to do
        res = self.bridge.discover()
        self.assertEqual((res["new"], res["legacy"], res["dropped"], res["prewarm"], res["popular"]), (0, 0, 0, 0, 0))
        self.assertEqual(len(self.jobs()), len(jobs))

    def variant(self, rel, size, mtime, spec="auto:avif:w=full:p:v2", tier="ephemeral"):
        key = self.cache.key(1, rel, size, mtime, spec)
        f = self.cache.write_bytes(key, "avif", "img", b"v" * 10, tier=tier)
        self.store.put_variant(key, mount=1, path=rel, src_size=size, src_mtime=mtime, kind="img", fmt="avif",
                               spec=spec, file=f, bytes=10, src_bytes=size, secs=0.1, beneficial=1, tier=tier)
        return key, f

    def test_derivatives_follow_their_source_without_verdicts(self):
        """Images-only profile (no scan gate, so no verdicts): a deleted source loses every variant (ephemeral and
        persistent), a changed source loses the old content's variants, an unchanged one keeps its own."""
        core.CFG["media"]["gate"]["enabled"] = False
        st = self.put("/keep.png")
        k_keep, f_keep = self.variant("/keep.png", st.st_size, st.st_mtime)
        st_ch = self.put("/changed.png")
        k_old, f_old = self.variant("/changed.png", st_ch.st_size, st_ch.st_mtime, tier="persistent")
        self.put("/changed.png", size=6000, mtime=self.t0 + 500)          # replaced: new size + mtime (index lags)
        st_gone = self.put("/gone.png")
        k_gone, f_gone = self.variant("/gone.png", st_gone.st_size, st_gone.st_mtime, tier="persistent")
        os.remove(os.path.join(self.drive, "gone.png"))
        res = self.bridge.discover()          # the index still lists it (no SMB stat for indexed, matching files)
        self.assertEqual(res["variants_gone"], 0)
        db = self.connect()
        with db:
            db.execute("DELETE FROM fidx WHERE path='/gone.png'")     # ... until the indexer notices
        db.close()
        res = self.bridge.discover()
        self.assertEqual(res["variants_gone"], 1)
        self.assertIsNotNone(self.store.variant(k_keep))
        self.assertTrue(self.cache.exists(f_keep))
        for k, f in ((k_old, f_old), (k_gone, f_gone)):
            self.assertIsNone(self.store.variant(k))
            self.assertFalse(self.cache.exists(f))
        # an offline drive decides nothing
        k2, f2 = self.variant("/keep.png", st.st_size, st.st_mtime + 1)
        self.mounts[0]["path"] = os.path.join(self.tmp, "offline")
        self.bridge.discover()
        self.assertIsNotNone(self.store.variant(k2))

    def test_no_backfill_and_categories(self):
        core.CFG["media"]["worker"]["backfill"] = False
        core.CFG["media"]["gate"]["categories"] = ["pdf"]
        self.put("/a/new.pdf")
        self.put("/a/old.pdf", mtime=self.t0 - 5000)
        self.put("/a/new.txt")
        self.bridge.discover()
        scans = {p for (k, _, p) in self.jobs() if k == "scan"}
        self.assertEqual(scans, {"/a/new.pdf"})

    def test_never_drops_for_offline_or_unindexed_drives(self):
        self.mounts.append(dict(self.mounts[0], id=2, path=os.path.join(self.tmp, "offline")))
        empty = os.path.join(self.tmp, "empty")
        os.makedirs(empty)
        self.mounts.append(dict(self.mounts[0], id=3, path=empty))
        self.index(2, "/x.png", 5, 1.0)
        for mid in (2, 3):
            self.store.set_verdict(mid, "/gone.png", size=5, mtime=1.0, state="clean")
        self.bridge.discover()
        self.assertIsNotNone(self.store.verdict(2, "/gone.png"))  # drive offline
        self.assertIsNotNone(self.store.verdict(3, "/gone.png"))  # nothing indexed for that drive


# ---------------------------------------------------------------- verdict watcher

class VerdictWatcher(Base):
    FIND = [{"type": "github_token", "severity": "high", "sample": "ghp_…abcd", "where": "ocr", "confidence": 0.9}]

    def keys(self):
        return [a["key"] for a in self.alerts]

    def test_purge_and_alert_outside_transactions(self):
        s = self.store
        s.set_verdict(1, "/a.png", size=10, mtime=1.0, state="flagged", severity="high", findings=self.FIND)
        s.set_verdict(1, "/b.txt", size=10, mtime=1.0, state="clean")
        s.set_verdict(1, "/c.pdf", size=10, mtime=1.0, state="pending")
        s.review(1, "/c.pdf", "held", "admin", "checking")
        s.set_verdict(1, "/d d.txt", size=10, mtime=1.0, state="error")
        self.bridge.watch_verdicts()
        self.assertEqual(sorted(self.purged), sorted(["https://%s/a.png" % HOST, "https://%s/c.pdf" % HOST,
                                                      "https://%s/d%%20d.txt" % HOST]))
        self.assertEqual(sorted(self.keys()), ["media-hold:1:/a.png", "media-hold:1:/d d.txt"])
        a = next(x for x in self.alerts if x["key"] == "media-hold:1:/a.png")
        self.assertEqual((a["kind"], a["severity"], a["title"]), ("media", "warning", "Held for review: /a.png"))
        self.assertIn("github_token (high) in ocr: ghp_…abcd", a["detail"])
        self.assert_alerts_clean()
        cursor = self.meta(mb.CURSOR_META)
        self.assertAlmostEqual(cursor, max(v["updated"] for v in s.verdicts_since(0)), places=3)

        # re-reading the overlap window changes nothing
        n_p, n_a = len(self.purged), len(self.alerts)
        self.bridge.watch_verdicts()
        self.assertEqual((len(self.purged), len(self.alerts)), (n_p, n_a))
        # flagged -> held by an admin: same content, nothing new
        s.review(1, "/a.png", "held", "admin", "confirmed")
        self.bridge.watch_verdicts()
        self.assertEqual((len(self.purged), len(self.alerts)), (n_p, n_a))
        # a clean file becomes flagged: purge + alert
        s.set_verdict(1, "/b.txt", size=10, mtime=1.0, state="flagged", severity="medium")
        self.bridge.watch_verdicts()
        self.assertEqual(self.purged[n_p:], ["https://%s/b.txt" % HOST])
        self.assertEqual(self.keys()[n_a:], ["media-hold:1:/b.txt"])
        # new content of a held file is flagged again: purge + alert again
        s.set_verdict(1, "/a.png", size=11, mtime=2.0, state="flagged", severity="high", findings=self.FIND)
        self.bridge.watch_verdicts()
        self.assertEqual(self.keys()[-1], "media-hold:1:/a.png")
        self.assert_alerts_clean()

        # a restarted bridge does not repeat what the last one already handled
        n_p, n_a = len(self.purged), len(self.alerts)
        self.bridge = self.make_bridge()
        self.bridge.watch_verdicts()
        self.assertEqual((len(self.purged), len(self.alerts)), (n_p, n_a))

    def test_raise_refused_inside_transaction(self):
        with self.bridge.strata(write=True) as db:
            core.set_meta(db, "probe", 1)
            with self.assertRaises(RuntimeError):
                self.bridge._raise_all([("media", "warning", "t", "d", "k")])
        self.assertEqual(self.alerts, [])
        self.bridge._raise_all([("media", "warning", "t", "d", "k")])
        self.assertEqual(len(self.alerts), 1)
        self.assert_alerts_clean()


# ---------------------------------------------------------------- events watcher + capacity + first start

class Watchers(Base):
    def test_events_watcher(self):
        now = time.time()
        rows = [{"ts": now - 5, "proc": "worker", "kind": "tool.missing", "severity": "warning",
                 "detail": {"tool": "tesseract"}},
                {"ts": now - 4, "proc": "bridge", "kind": "supervisor.restart", "severity": "warning",
                 "detail": {"child": "worker", "reason": "exited (rc=1)"}},
                {"ts": now - 3, "proc": "media", "kind": "bypass.breaker_open", "severity": "warning", "detail": {}}]
        rows += [{"ts": now - 60 - i, "proc": "worker", "kind": "job.failed", "severity": "warning", "detail": {}}
                 for i in range(11)]
        self.store.add_events(rows)
        self.bridge.watch_events()
        keys = [a["key"] for a in self.alerts]
        self.assertEqual(sorted(keys), ["media-jobs-failed", "media-restart:worker", "media-tool:tesseract"])
        self.assertIn("exited (rc=1)", next(a["detail"] for a in self.alerts if a["key"] == "media-restart:worker"))
        self.alerts.clear()
        self.bridge.watch_events()  # the same events are not alerted twice
        self.assertEqual([a["key"] for a in self.alerts], ["media-jobs-failed"])
        self.assert_alerts_clean()

    def test_capacity_meta_and_coalesced_alerts(self):
        now = int(time.time() // 60 * 60)
        db = self.connect()
        with db:
            for i in range(60):
                ts = now - i * 60
                db.execute("INSERT INTO metric VALUES('host_cpu', ?, 95)", [ts])
                db.execute("INSERT INTO metric VALUES('host_mem', ?, 50)", [ts])
                db.execute("INSERT INTO metric VALUES('tunnel_tx', ?, 1000000)", [ts])
                db.execute("INSERT INTO metric VALUES('host_cpu', ?, 5)", [ts - 7200])  # older than 1 h: ignored
        db.close()
        for i in range(30):
            self.store.add_sample(now - i * 60, "media", {"secs": 60, "open_s": 30, "trips": 1})
        res = self.bridge.check_capacity()
        adv = {r["resource"]: r for r in res["advice"]}
        self.assertEqual(adv["cpu"]["level"], "upgrade")
        self.assertAlmostEqual(res["inputs"]["cpu_p95"], 95)
        self.assertAlmostEqual(res["inputs"]["tx_p95_mbps"], 8.0)
        self.assertAlmostEqual(res["inputs"]["open_ratio"], 0.5)
        self.assertEqual(res["inputs"]["trips_24h"], 30)
        self.assertNotIn("uplink", adv)
        stored = self.meta(mb.CAP_META)
        self.assertEqual(stored["advice"], res["advice"])
        a = next(x for x in self.alerts if x["key"] == "capacity:cpu")
        self.assertEqual((a["severity"], a["coalesce"]), ("warning", 24 * 60))
        self.assertIn("add 2 vCPU", a["title"])
        n = len(self.alerts)
        self.bridge.check_capacity()
        self.assertEqual(len(self.alerts), n)  # coalesced for 24 h
        self.assert_alerts_clean()

    def test_first_start(self):
        core.CFG["media"].update(cutover=0, admin_token="")
        done = self.bridge.first_start()
        self.assertEqual(done, ["admin_token", "cutover"])
        self.assertEqual(len(self.saves), 1)
        self.assertGreater(core.CFG["media"]["cutover"], 0)
        self.assertGreaterEqual(len(core.CFG["media"]["admin_token"]), 32)
        self.assertEqual(self.soon, [1])
        self.assertEqual(self.bridge.first_start(), [])
        self.assertEqual(len(self.saves), 1)


# ---------------------------------------------------------------- negotiation

class Negotiation(Base):
    def mode(self):
        return (self.meta(mb.NEG_META) or {}).get("mode")

    def test_auto_redirect_on_403_then_edge(self):
        self.edge.fail = cloudflare.CFError(403, "Authentication error (code 10000)")
        self.assertEqual(self.bridge.negotiate(), mb.EVERY["negotiation"])
        rec = self.meta(mb.NEG_META)
        self.assertEqual((rec["mode"], rec["configured"], rec["edge"]["state"]), ("redirect", "auto", "no permission"))
        self.assertEqual(self.soon, [1])
        db = self.connect()
        self.assertEqual(media_rules.effective_negotiation(db), "redirect")
        self.bridge.negotiate()
        self.assertEqual(self.soon, [1])  # unchanged: no apply
        self.edge.fail = None
        self.bridge.negotiate()
        self.assertEqual(self.mode(), "edge")
        self.assertEqual(self.soon, [1, 1])
        self.assertEqual(media_rules.effective_negotiation(db), "edge")
        db.close()
        self.bridge.negotiate()
        self.assertEqual(self.soon, [1, 1])
        self.assertEqual(self.edge.calls, [True, True, True, True])
        self.assertEqual(self.alerts, [])

    def test_edge_mode_keeps_trying_and_transient_errors(self):
        self.bridge.negotiate()
        self.assertEqual(self.mode(), "edge")
        core.CFG["media"]["negotiation"] = "edge"
        self.edge.fail = cloudflare.CFError(403, "Authentication error (code 10000)")
        self.assertEqual(self.bridge.negotiate(), mb.NEG_RETRY_S)
        self.assertEqual(self.mode(), "edge")
        self.assertEqual([a["key"] for a in self.alerts], ["media-edge"])
        self.assertIn("Transform Rules", self.alerts[0]["detail"])
        core.CFG["media"]["negotiation"] = "auto"
        self.edge.fail = cloudflare.CFError(0, "network: timed out")
        self.assertEqual(self.bridge.negotiate(), mb.NEG_RETRY_S)
        self.assertEqual(self.mode(), "edge")  # rules probably still live: keep the mode
        self.assertEqual(len(self.soon), 1)
        self.assert_alerts_clean()

    def test_redirect_and_off_remove_rules(self):
        core.CFG["media"]["negotiation"] = "redirect"
        self.edge.fail = cloudflare.CFError(403, "nope")  # best effort
        self.bridge.negotiate()
        self.assertEqual((self.mode(), self.edge.calls), ("redirect", [False]))
        core.CFG["media"]["negotiation"] = "off"
        self.edge.fail = None
        self.bridge.negotiate()
        self.assertEqual(self.mode(), "off")
        self.assertEqual(self.meta(mb.NEG_META)["edge"]["state"], "removed")
        self.assertEqual(len(self.soon), 2)


# ---------------------------------------------------------------- admin API + hooks

class BreakerStub(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        ok = self.headers.get("X-Strata-Admin-Token") == TOKEN and self.path == "/_admin/breaker"
        out = json.dumps({"ok": True, "breaker": {"state": body.get("state"), "forced_for": body.get("seconds")}}
                         if ok else {"error": "forbidden"}).encode()
        self.send_response(200 if ok else 403)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


class Api(Base):
    def audits(self):
        db = self.connect()
        try:
            return [r[0] for r in db.execute("SELECT action FROM audit ORDER BY ts")]
        finally:
            db.close()

    def test_disabled_mode(self):
        core.CFG["media"]["enabled"] = False
        dbp = os.path.join(self.tmp, "never", "media.db")
        core.CFG["media"]["db"] = dbp
        mb.BRIDGE = passive = mb.Bridge(connect=self.connect, mounts=lambda: self.mounts,
                                        apply=lambda u, r: self.applied.append(r))
        passive.start()
        self.assertFalse(passive.is_alive())
        st = mb.api_get("admin", "/api/media/status", {})
        self.assertIs(st["enabled"], False)
        self.assertEqual(st["reason"], "media pipeline disabled")
        self.assertIn("tesseract", st["tools"])
        self.assertEqual(st["settings"]["negotiation"], "auto")
        self.assertNotIn(TOKEN, json.dumps(st))
        self.assertIn("breaker", st["config"])
        media_rules.file_policy_preview = lambda db, limit=200: {"total": 1, "blocked": ["/x.env"], "counts": {}}
        pol = mb.api_get("admin", "/api/media/policy", {})
        self.assertEqual(pol, {"total": 1, "counts": {}})
        for call in (lambda: mb.api_get("admin", "/api/media/holds", {}),
                     lambda: mb.api_post("admin", "1.2.3.4", "/api/media/release", {"mount": 1, "path": "/a", "note": "fine"}),
                     lambda: mb.api_post("admin", "1.2.3.4", "/api/media/breaker", {"state": "auto"})):
            with self.assertRaises(mb.MediaError) as cm:
                call()
            self.assertEqual(cm.exception.code, 409)
        r = mb.api_post("admin", "1.2.3.4", "/api/media/settings", {"hold_threshold": "high"})
        self.assertEqual((r["ok"], r["apply"]), (True, None))
        self.assertEqual(self.applied, [])
        self.assertFalse(os.path.exists(dbp))  # media.db never opened while off
        self.assertIsNone(mb.on_upload(1, "/a.png", __file__))
        self.assertIsNone(mb.on_rename(1, "/a.png", "/b.png"))

    def test_status_enabled(self):
        self.store.set_verdict(1, "/a.pdf", size=1, mtime=1.0, state="flagged")
        self.store.set_meta("worker_heartbeat", {"ts": time.time() - 3, "pid": 4242, "paused": None})
        st = mb.api_get("admin", "/api/media/status", {})
        self.assertIs(st["enabled"], True)
        self.assertFalse(st["processes"]["media"]["up"])  # nothing listens on the test port
        self.assertTrue(st["processes"]["worker"]["up"])
        self.assertEqual(st["processes"]["worker"]["pid"], 4242)
        self.assertEqual(st["counts"]["verdicts"], {"flagged": 1})
        self.assertEqual(st["negotiation"]["effective"], "redirect")
        self.assertIn("savings", st)
        self.assertIsNone(st["error"])
        self.assertNotIn(TOKEN, json.dumps(st, default=str))

    def test_lists_and_validation(self):
        self.store.set_verdict(1, "/a.pdf", size=1, mtime=1.0, state="flagged")
        self.store.set_verdict(1, "/b.pdf", size=1, mtime=1.0, state="clean")
        r = mb.api_get("admin", "/api/media/holds", {"state": "flagged,held,error"})
        self.assertEqual(([x["path"] for x in r["rows"]], r["total"]), (["/a.pdf"], 1))
        self.assertIsNone(mb.api_get("admin", "/api/media/holds", {"q": "a"})["total"])
        self.store.add_events([{"ts": time.time(), "proc": "media", "kind": "bypass.queue_full", "detail": {}}])
        self.assertEqual(len(mb.api_get("admin", "/api/media/events", {"kind": "bypass", "since": "0"})["rows"]), 1)
        self.store.enqueue("scan", 1, "/a.pdf", priority=10)
        self.assertEqual(len(mb.api_get("admin", "/api/media/jobs", {"state": "queued", "kind": "scan"})["rows"]), 1)
        bad = [("/api/media/holds", {"state": "bogus"}), ("/api/media/holds", {"limit": "0"}),
               ("/api/media/holds", {"offset": "-1"}), ("/api/media/events", {"kind": "a b"}),
               ("/api/media/events", {"since": "yesterday"}), ("/api/media/jobs", {"state": "x"}),
               ("/api/media/jobs", {"kind": "x"})]
        for path, q in bad:
            with self.assertRaises(ValueError, msg=(path, q)):
                mb.api_get("admin", path, q)
        self.assertIsNone(mb.api_get("admin", "/api/media/nope", {}))
        self.assertIsNone(mb.api_post("admin", "ip", "/api/media/nope", {}))

    def test_post_actions(self):
        ip = "192.0.2.1"
        st = self.put("/docs/x.pdf")
        self.store.set_verdict(1, "/docs/x.pdf", size=st.st_size, mtime=st.st_mtime, state="flagged", severity="medium")
        for body in ({"mount": 1, "path": "/docs/x.pdf"}, {"mount": 1, "path": "/docs/x.pdf", "note": "ok"},
                     {"mount": "x", "path": "/docs/x.pdf", "note": "fine"}, {"mount": 1, "path": "docs", "note": "fine"},
                     {"mount": 1, "path": "/../x", "note": "fine"}):
            with self.assertRaises(ValueError):
                mb.api_post("admin", ip, "/api/media/release", body)
        self.assertEqual(mb.api_post("admin", ip, "/api/media/release",
                                     {"mount": 1, "path": "/docs/x.pdf", "note": "reviewed, harmless"}),
                         {"ok": True, "state": "released"})
        v = self.store.verdict(1, "/docs/x.pdf")
        self.assertEqual((v["state"], v["reviewed_by"], v["review_note"]), ("released", "admin", "reviewed, harmless"))
        with self.assertRaises(mb.MediaError) as cm:
            mb.api_post("admin", ip, "/api/media/release", {"mount": 1, "path": "/nope.pdf", "note": "fine"})
        self.assertEqual(cm.exception.code, 404)
        # hold of a file that was never scanned creates the verdict
        self.put("/docs/new.pdf")
        mb.api_post("admin", ip, "/api/media/hold", {"mount": 1, "path": "/docs/new.pdf"})
        self.assertEqual(self.store.verdict(1, "/docs/new.pdf")["state"], "held")
        with self.assertRaises(mb.MediaError):
            mb.api_post("admin", ip, "/api/media/hold", {"mount": 1, "path": "/docs/missing.pdf"})
        r = mb.api_post("admin", ip, "/api/media/rescan", {"mount": 1, "path": "/docs/x.pdf"})
        job = self.jobs()[("scan", 1, "/docs/x.pdf")]
        self.assertEqual((r["job"], job["priority"], job["size"]), (job["id"], 20, st.st_size))
        with self.assertRaises(mb.MediaError):
            mb.api_post("admin", ip, "/api/media/rescan", {"mount": 9, "path": "/docs/x.pdf"})
        c = self.store.claim("w", ["scan"])
        self.store.fail(c["id"], "boom", "crash", max_attempts=1)
        self.assertEqual(mb.api_post("admin", ip, "/api/media/retry", {"kind": "scan"}), {"ok": True, "retried": 1})
        with self.assertRaises(ValueError):
            mb.api_post("admin", ip, "/api/media/retry", {"kind": "bogus"})
        self.assertEqual(self.audits(), ["media-release", "media-hold", "media-rescan", "media-retry"])

    def test_settings(self):
        for body in ({}, {"negotiation": "sometimes"}, {"gate_legacy": "yes"}, {"hold_threshold": "extreme"}):
            with self.assertRaises(ValueError):
                mb.api_post("admin", "ip", "/api/media/settings", body)
        r = mb.api_post("admin", "ip", "/api/media/settings",
                        {"negotiation": "redirect", "gate_legacy": False, "hold_threshold": "high"})
        self.assertEqual(r["settings"], {"negotiation": "redirect", "gate_legacy": False, "hold_threshold": "high",
                                         "video_format": "webm"})
        self.assertEqual(self.saves, [{"media": {"negotiation": "redirect", "gate": {"legacy_while_pending": False},
                                                 "scan": {"hold_threshold": "high"}}}])
        self.assertEqual(self.applied, [("admin", "media settings")])
        self.assertEqual(r["apply"], {"changed": False})
        self.assertTrue(self.bridge._neg_request)
        self.assertEqual(self.audits(), ["media-settings"])
        with self.assertRaises(ValueError):
            mb.api_post("admin", "ip", "/api/media/settings", {"video_format": "mkv"})
        self.bridge._neg_request = False
        mb.api_post("admin", "ip", "/api/media/settings", {"video_format": "mp4"})
        self.assertEqual(self.saves[-1], {"media": {"video": {"format": "mp4"}}})
        self.assertTrue(self.bridge._neg_request)        # the edge video rule switches to _v=mp4

    def test_breaker(self):
        for body in ({"state": "half"}, {"state": "open"}, {"state": "open", "seconds": 5},
                     {"state": "closed", "seconds": 90000}):
            with self.assertRaises(ValueError):
                mb.api_post("admin", "ip", "/api/media/breaker", body)
        with self.assertRaises(mb.MediaError) as cm:  # media not running
            mb.api_post("admin", "ip", "/api/media/breaker", {"state": "auto"})
        self.assertEqual(cm.exception.code, 503)
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", P_BREAKER), BreakerStub)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            core.CFG["media"]["listen"] = "127.0.0.1:%d" % P_BREAKER
            r = mb.api_post("admin", "ip", "/api/media/breaker", {"state": "open", "seconds": 600})
            self.assertEqual(r, {"ok": True, "breaker": {"state": "open", "forced_for": 600}})
            core.CFG["media"]["admin_token"] = "wrong-token"
            with self.assertRaises(mb.MediaError) as cm:
                mb.api_post("admin", "ip", "/api/media/breaker", {"state": "auto"})
            self.assertEqual(cm.exception.code, 502)
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(self.audits(), ["media-breaker"])

    def test_upload_and_rename_hooks(self):
        # default: demand driven - an upload alone never encodes anything
        self.put("/up/quiet.png")
        self.assertIsNone(mb.on_upload(1, "/up/quiet.png", os.path.join(self.drive, "up", "quiet.png"))["prewarm"])
        core.CFG["media"]["image"]["prewarm_uploads"] = True
        st = self.put("/up/pic.png")
        full = os.path.join(self.drive, "up", "pic.png")
        r = mb.on_upload(1, "/up/pic.png", full)
        jobs = self.jobs()
        self.assertEqual(jobs[("scan", 1, "/up/pic.png")]["priority"], 20)
        self.assertEqual(jobs[("image", 1, "/up/pic.png")]["priority"], 70)
        self.assertEqual(r, {"scan": jobs[("scan", 1, "/up/pic.png")]["id"], "prewarm": jobs[("image", 1, "/up/pic.png")]["id"]})
        self.put("/up/song.mp3")
        self.assertEqual(mb.on_upload(1, "/up/song.mp3", os.path.join(self.drive, "up", "song.mp3")),
                         {"scan": None, "prewarm": None})
        self.assertIsNone(mb.on_upload(1, "/up/missing.png", os.path.join(self.drive, "nope.png")))  # never raises
        self.store.set_verdict(1, "/up/pic.png", size=st.st_size, mtime=st.st_mtime, state="held")
        self.assertTrue(mb.on_rename(1, "/up", "/moved"))
        self.assertIsNone(self.store.verdict(1, "/up/pic.png"))
        self.assertEqual(self.store.verdict(1, "/moved/pic.png")["state"], "held")


class BridgeThread(Base):
    def test_loop_runs_and_stops(self):
        self.assertIs(self.bridge.start(), self.bridge)
        self.assertTrue(wait_for(lambda: "supervise" in self.bridge.last and "init" in self.bridge.last, 10))
        self.assertTrue(self.bridge.last["init"]["ok"])
        self.bridge.start()  # idempotent
        self.bridge.stop()
        self.bridge.join(10)
        self.assertFalse(self.bridge.is_alive())

    def test_pauses_and_stops_own_children_when_switched_off(self):
        class Sup:
            stopped = ensured = 0

            def ensure(self):
                Sup.ensured += 1

            def stop(self):
                Sup.stopped += 1

            def status(self):
                return {}
        self.bridge = self.make_bridge(supervisor=Sup())
        self.bridge.start()
        self.assertTrue(wait_for(lambda: Sup.ensured >= 1, 10))
        core.CFG["media"]["enabled"] = False
        self.bridge._wake.set()
        self.assertTrue(wait_for(lambda: self.bridge.paused and Sup.stopped == 1, 10))
        n = Sup.ensured
        core.CFG["media"]["enabled"] = True
        self.bridge._wake.set()
        self.assertTrue(wait_for(lambda: not self.bridge.paused and Sup.ensured > n, 10))
        self.bridge.stop(children=False)
        self.bridge.join(10)
        self.assertFalse(self.bridge.is_alive())

    def test_start_is_noop_when_disabled(self):
        core.CFG["media"]["enabled"] = False
        b = mb.start(connect=self.connect, store=self.store, mounts=lambda: self.mounts)
        self.assertIs(mb.BRIDGE, b)
        self.assertFalse(b.is_alive())


# ---------------------------------------------------------------- supervisor

class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="strata-media-sup-")
        self.script = os.path.join(self.tmp, "dummy_media.py")
        with open(self.script, "w", encoding="utf-8") as f:
            f.write(DUMMY)
        self.events = []
        self.sups = []

    def tearDown(self):
        for s in self.sups:
            s.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def sup(self, port, mode="ok", grace=10, **kw):
        c = mb.Child("media", [sys.executable, self.script, str(port), mode], os.path.join(self.tmp, "m.out"),
                     os.path.join(self.tmp, "m.err"), lambda: mb.media_health("127.0.0.1:%d" % port, 1.0),
                     grace=grace, cwd=self.tmp, priority=kw.pop("priority", None))
        s = mb.Supervisor([c], emit=lambda kind, severity, **d: self.events.append((kind, severity, d)), **kw)
        self.sups.append(s)
        return s, c

    def test_start_and_restart_after_death(self):
        s, c = self.sup(P_SUP, backoff=(0.3, 0.6))
        s.ensure()
        self.assertIsNotNone(c.proc)
        self.assertTrue(wait_for(lambda: c.state == "up", tick=s.ensure), (c.state, c.error))
        pid1 = c.pid
        mb.http_json("127.0.0.1:%d" % P_SUP, "GET", "/_exit")
        self.assertTrue(wait_for(lambda: c.restarts == 1 and c.state == "up", tick=s.ensure), (c.state, c.error))
        self.assertNotEqual(c.pid, pid1)
        self.assertEqual(c.last_exit["rc"], 3)
        self.assertEqual([e[0] for e in self.events], ["supervisor.start", "supervisor.restart"])
        self.assertEqual(self.events[1][2]["reason"], "exited (rc=3)")
        self.assertEqual(s.status()["media"]["restarts"], 1)
        with open(os.path.join(self.tmp, "m.out"), encoding="utf-8") as f:
            self.assertEqual(f.read().count("started by the Strata supervisor"), 2)
        proc = c.proc
        s.stop()
        self.assertIsNotNone(proc.poll())

    def test_unhealthy_child_is_killed_and_restarted(self):
        s, c = self.sup(P_SICK, mode="sick", grace=0.5, backoff=(0.2,), max_fails=2)
        s.ensure()
        self.assertTrue(wait_for(lambda: c.last_exit is not None, tick=s.ensure), (c.state, c.error))
        self.assertTrue(c.last_exit["reason"].startswith("unhealthy"), c.last_exit)
        self.assertTrue(wait_for(lambda: c.restarts >= 1, tick=s.ensure))

    def test_adopts_external_instance_and_never_touches_it(self):
        class Stats(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *a):
                pass
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", P_EXT), Stats)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            s, c = self.sup(P_EXT)
            s.ensure()
            s.ensure()
            self.assertEqual((c.state, c.proc, self.events), ("external", None, []))
            self.assertTrue(s.status()["media"]["up"])
        finally:
            srv.shutdown()
            srv.server_close()

    def test_missing_script(self):
        c = mb.Child("worker", [sys.executable, os.path.join(self.tmp, "nope.py")], os.path.join(self.tmp, "w.out"),
                     os.path.join(self.tmp, "w.err"), lambda: (False, "down"))
        s = mb.Supervisor([c], emit=lambda *a, **k: self.events.append(a))
        s.ensure()
        self.assertEqual((c.state, c.proc, self.events), ("missing", None, []))

    @unittest.skipUnless(os.name == "nt", "Windows priority classes")
    def test_below_normal_priority(self):
        import ctypes
        s, c = self.sup(P_PRIO, priority="below_normal")
        s.ensure()
        k32 = ctypes.WinDLL("kernel32")
        k32.GetPriorityClass.argtypes = [ctypes.c_void_p]
        self.assertEqual(k32.GetPriorityClass(int(c.proc._handle)), 0x4000)

    def test_worker_heartbeat_health(self):
        st = mstore.Store(os.path.join(self.tmp, "media.db")).init()
        try:
            self.assertEqual(mb.heartbeat_health(st), (False, "no heartbeat"))
            st.set_meta("worker_heartbeat", {"ts": time.time() - 2, "pid": 7})
            ok, info = mb.heartbeat_health(st)
            self.assertTrue(ok)
            self.assertEqual(info["pid"], 7)
            st.set_meta("worker_heartbeat", {"ts": time.time() - 31})
            self.assertFalse(mb.heartbeat_health(st)[0])
        finally:
            st.close()


if __name__ == "__main__":
    unittest.main()
