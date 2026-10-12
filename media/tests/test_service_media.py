"""media.py over real HTTP: variants (accel / hit / not beneficial / deferred / breaker bypass), redirect negotiation,
the /_scan gate matrix, the throttled lane, /_gate, ?ver= Range, explicit ?w= transforms, webm redirects, the admin
breaker switch and the cache-header rules. In-process server on a free port in 18183-18189 with a temp media.json,
media.db, cache and mount; a fake monitor keeps the breaker independent of this (busy) production box."""
import copy
import gc
import hashlib
import http.client
import importlib.util
import json
import os
import re
import secrets
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
MEDIA = os.path.dirname(HERE)
STRATA = os.path.dirname(MEDIA)
if MEDIA not in sys.path:
    sys.path.insert(0, MEDIA)

import media  # noqa: E402  (imports pathfix first)
import breaker  # noqa: E402
import config  # noqa: E402
import imaging  # noqa: E402
import worker  # noqa: E402

try:
    from PIL import Image
except ImportError:  # pragma: no cover
    Image = None

PORTS = range(18183, 18190)
BROWSER = "public, no-cache"
EDGE = "public, max-age=31536000"
IMMUTABLE = "public, max-age=31536000, immutable"
SHORT = "public, max-age=60"
SECRET = "test-sign-secret-not-real"
ACCEL_RX = re.compile(r"^(/static)?/img/[0-9a-f]{2}/[0-9a-f]{2}/[0-9a-f]{40}\.(avif|webp|png|jpg)$")


def free_port():
    for p in PORTS:
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", p))
            return p
        except OSError:
            continue
        finally:
            s.close()
    raise unittest.SkipTest("no free test port in 18183-18189")


def merge(base, over):
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            merge(base[k], v)
        else:
            base[k] = v
    return base


def photo(path, size=(640, 480)):
    """Photo-like PNG (gradient + fractal + noise): big as PNG, small as AVIF/WebP."""
    base = Image.linear_gradient("L").resize(size)
    mand = Image.effect_mandelbrot(size, (-2.0, -1.25, 1.0, 1.25), 60)
    noise = Image.effect_noise(size, 12)
    Image.merge("RGB", (base, mand, noise)).save(path, "PNG")


@unittest.skipIf(Image is None or imaging.Image is None, "Pillow missing")
class MediaServiceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="strata-media-svc-")
        cls.mnt = os.path.join(cls.tmp, "mount")
        os.makedirs(os.path.join(cls.mnt, "sub"))
        cls.conf_path = os.path.join(cls.tmp, "media.json")
        cls.token = secrets.token_hex(16)
        cls.port = free_port()
        cls.base = {
            "enabled": True, "listen": "127.0.0.1:%d" % cls.port, "db": os.path.join(cls.tmp, "media.db"),
            "cache_root": os.path.join(cls.tmp, "mc"), "event_log": os.path.join(cls.tmp, "events.jsonl"),
            "negotiation": "redirect", "cutover": time.time() + 10 * 86400,   # default: every fixture is legacy
            "sign_secret": SECRET, "admin_token": cls.token,
            "lane": {"enabled": True, "min_bytes": 1 << 20, "total_mbps": 25, "per_conn_mbps": 8},
            "mounts": {"1": {"path": cls.mnt, "prefix": "/", "hosts": ["cdn.test"], "cache": BROWSER,
                             "edge_cache": EDGE, "transforms": 1},
                       "2": {"path": cls.mnt, "prefix": "/pre", "hosts": ["cdn.test"], "cache": BROWSER,
                             "edge_cache": EDGE, "transforms": 1}}}
        cls.write_conf()
        m = cls.mnt
        photo(os.path.join(m, "photo.png"))
        for n in ("bypass.png", "defer.png", "held.png", "fresh.png", "nohdr.png", "my photo.png"):
            shutil.copyfile(os.path.join(m, "photo.png"), os.path.join(m, n))
        shutil.copyfile(os.path.join(m, "photo.png"), os.path.join(m, "sub", "p.png"))
        Image.new("RGB", (8, 8), (10, 20, 30)).save(os.path.join(m, "tiny.png"))
        for n, data in (("clip.mp4", os.urandom(20000)), ("clip2.mp4", os.urandom(20000)),
                        ("clip3.mp4", os.urandom(20000)), ("clip4.mp4", os.urandom(20000)), ("movie.webm", os.urandom(5000)),
                        ("big.bin", os.urandom(2_000_000)), ("big.zip", os.urandom((1 << 20) + 50000)),
                        ("clean.txt", b"hello clean\n"), ("flagged.txt", b"pretend finding inside\n" * 50),
                        ("new.txt", b"brand new\n"), ("stale.txt", b"stale content\n"), ("legacy.txt", b"old\n"),
                        ("broken.txt", b"unscannable\n")):
            with open(os.path.join(m, n), "wb") as f:
                f.write(data)
        cls.monitor = breaker.Monitor(sampler=lambda: (5.0, 6000.0, 30.0))
        cls.monitor.tick()
        cls.monitor.tick()
        cls.svc = media.Service(cls.conf_path, monitor=cls.monitor)
        cls.srv = media.make_server("127.0.0.1:%d" % cls.port, cls.svc)
        cls.svc.start()
        cls.thread = threading.Thread(target=cls.srv.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.svc.stop()
        cls.thread.join(5)
        for _ in range(20):
            gc.collect()
            try:
                shutil.rmtree(cls.tmp)
                break
            except OSError:
                time.sleep(0.3)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def write_conf(cls, **over):
        conf = merge(copy.deepcopy(cls.base), copy.deepcopy(over))
        with open(cls.conf_path, "w", encoding="utf-8") as f:
            json.dump(conf, f)
        config._cache.pop(cls.conf_path, None)   # mtime granularity must not hide a rewrite from the test

    def restore_conf(self):
        self.write_conf()

    # ------------------------------------------------------------ helpers
    def req(self, path, headers=None, method="GET", body=None, mount="1", cache=BROWSER, edge=EDGE):
        h = {}
        if mount:
            h["X-Strata-Mount"] = mount
        if cache is not None:
            h["X-Strata-Cache"] = cache
        if edge is not None:
            h["X-Strata-Edge-Cache"] = edge
        h.update(headers or {})
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        try:
            c.request(method, path, body=body, headers=h)
            r = c.getresponse()
            data = r.read()
            return r.status, {k.lower(): v for k, v in r.getheaders()}, data
        finally:
            c.close()

    def scan(self, uri, mount="1"):
        h = {"X-Forwarded-Uri": uri, "X-Forwarded-Method": "GET"}
        return self.req("/_scan", h, mount=mount, cache=None, edge=None)

    def admin(self, obj, token=None):
        body = json.dumps(obj).encode()
        h = {"Content-Type": "application/json", "Content-Length": str(len(body))}
        if token is not False:
            h["X-Strata-Admin-Token"] = token or self.token
        return self.req("/_admin/breaker", h, method="POST", body=body, mount=None, cache=None, edge=None)

    def wait_for(self, fn, timeout=5.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            v = fn()
            if v:
                return v
            time.sleep(0.05)
        return fn()

    def job(self, kind, path):
        return self.wait_for(lambda: [j for j in self.svc.store.jobs(kind=kind) if j["path"] == path])

    def verdict(self, name, state, qhash=False, mount=1):
        full = os.path.join(self.mnt, name.lstrip("/"))
        st = os.stat(full)
        qh = config.quick_hash(full, st.st_size) if qhash else None
        self.svc.store.set_verdict(mount, "/" + name.lstrip("/"), size=st.st_size, mtime=st.st_mtime, state=state,
                                   qhash=qh, severity="high" if state == "flagged" else "")
        self.svc.refresh_verdicts(full=True)

    def event_kinds(self, path=None):
        return [e["kind"] for e in self.svc.events.recent(200) if path is None or e.get("path") == path]

    def assert_no_cdn(self, h):
        self.assertNotIn("x-strata-cdn-cache-control", h)
        self.assertNotIn("cloudflare-cdn-cache-control", h)
        self.assertNotIn("x-strata-accel", h)
        self.assertNotIn("x-strata-orig", h)

    def cache_file(self, accel):
        return os.path.join(self.tmp, "mc", "cache", *accel.lstrip("/").split("/"))

    # ------------------------------------------------------------ variants
    def test_avif_accel_then_hit(self):
        st, h, body = self.req("/photo.png?_v=avif")
        self.assertEqual((st, body), (200, b""))
        self.assertEqual(h["x-strata-media"], "miss")
        accel = h["x-strata-accel"]
        self.assertRegex(accel, ACCEL_RX)
        self.assertTrue(accel.endswith(".avif"))
        self.assertEqual(h["x-strata-cache-control"], BROWSER)
        self.assertEqual(h["x-strata-cdn-cache-control"], EDGE)
        self.assertEqual(h["x-strata-disposition"], "inline; filename*=UTF-8''photo.avif")
        self.assertNotIn("x-strata-orig", h)
        with Image.open(self.cache_file(accel)) as im:
            self.assertEqual((im.format, im.size), ("AVIF", (640, 480)))
        self.assertLess(os.path.getsize(self.cache_file(accel)), os.path.getsize(os.path.join(self.mnt, "photo.png")))
        rows = [r for r in self.svc.store.variants_for(1, "/photo.png")
                if r["spec"] == imaging.auto_spec("avif", None, self.svc.conf())]
        self.assertEqual((len(rows), rows[0]["beneficial"], rows[0]["file"]), (1, 1, accel))
        self.assertEqual(rows[0]["etag"], media.cache_mod.caddy_etag(os.stat(self.cache_file(accel)).st_mtime_ns,
                                                                     os.path.getsize(self.cache_file(accel))))
        self.assertAlmostEqual(os.stat(self.cache_file(accel)).st_mtime,               # the source's (to the us)
                               os.stat(os.path.join(self.mnt, "photo.png")).st_mtime, places=5)
        st, h, _ = self.req("/photo.png?_v=avif")
        self.assertEqual((st, h["x-strata-media"], h["x-strata-accel"]), (200, "hit", accel))
        st, h, body = self.req("/photo.png?_v=avif", method="HEAD")
        self.assertEqual((st, h["x-strata-media"], body), (200, "hit", b""))

    def test_webp_and_prefixed_mount(self):
        st, h, _ = self.req("/pre/photo.png?_v=webp", mount="2")
        self.assertEqual(st, 200)
        self.assertTrue(h["x-strata-accel"].endswith(".webp"), h)
        with Image.open(self.cache_file(h["x-strata-accel"])) as im:
            self.assertEqual(im.format, "WEBP")
        st, h, _ = self.req("/pre/photo.png", {"X-Strata-Negotiate": "1", "Accept": "image/avif,*/*"}, mount="2")
        self.assertEqual((st, h["location"]), (302, "/pre/photo.png?_v=avif"))
        st, _, _ = self.req("/photo.png?_v=webp", mount="2")    # outside the mount prefix
        self.assertEqual(st, 404)

    def test_not_beneficial_tiny_png(self):
        st, h, body = self.req("/tiny.png?_v=avif")
        self.assertEqual((st, body, h.get("x-strata-orig")), (200, b"", "1"))
        self.assertEqual(h["x-strata-media"], "orig;reason=small")
        self.assertEqual((h["x-strata-cache-control"], h["x-strata-cdn-cache-control"]), (BROWSER, EDGE))
        self.assertNotIn("x-strata-accel", h)
        rows = self.svc.store.variants_for(1, "/tiny.png")
        self.assertEqual([(r["beneficial"], r["file"]) for r in rows], [(0, "")])
        st, h, _ = self.req("/tiny.png?_v=avif")
        # the cached decision keeps its real reason (and its long CDN TTL: it is deterministic)
        self.assertEqual((h["x-strata-media"], h["x-strata-cdn-cache-control"]), ("orig;reason=small", EDGE))

    def test_breaker_forced_open_bypass(self):
        st, h, body = self.admin({"state": "open", "seconds": 120})
        self.addCleanup(self.admin, {"state": "auto"})
        self.assertEqual(st, 200, body)
        self.assertEqual(json.loads(body)["breaker"]["state"], "open")
        self.assertEqual(self.svc.store.get_meta("breaker")["state"], "open")   # published at once for the worker
        st, h, _ = self.req("/bypass.png?_v=avif")
        self.assertEqual((st, h.get("x-strata-orig")), (200, "1"))
        self.assertEqual(h["x-strata-media"], "bypass;kind=breaker_open")
        self.assertEqual((h["x-strata-cache-control"], h["x-strata-cdn-cache-control"]), (BROWSER, SHORT))
        # the gallery's ?_wait=1: busy means 503 (retry), never the original
        st, h, _ = self.req("/bypass.png?_v=avif&_wait=1")
        self.assertEqual((st, h.get("x-strata-orig"), h.get("retry-after")), (503, None, "3"))
        self.assertIn("bypass.breaker_open", self.event_kinds("/bypass.png"))
        ev = [e for e in self.svc.events.recent(200) if e["kind"] == "bypass.breaker_open"][0]
        self.assertEqual((ev["mount"], ev["detail"].get("detail")), (1, "forced"))
        self.svc.events.flush()
        self.assertTrue(self.svc.store.events(kind="bypass.breaker_open"))
        # older rules.py (no X-Strata-Edge-Cache): single-header behaviour, short TTL for both
        st, h, _ = self.req("/bypass.png?_v=avif", cache=IMMUTABLE, edge=None)
        self.assertEqual((h["x-strata-cache-control"], h["x-strata-cdn-cache-control"]), (SHORT, SHORT))
        st, _, body = self.admin({"state": "auto"})
        self.assertEqual((st, json.loads(body)["breaker"]["state"]), (200, "closed"))
        st, h, _ = self.req("/bypass.png?_v=avif")
        self.assertEqual(h["x-strata-media"], "miss")

    def test_admin_token_and_methods(self):
        self.assertEqual(self.admin({"state": "open"}, token=False)[0], 403)
        self.assertEqual(self.admin({"state": "open"}, token="wrong")[0], 403)
        self.assertEqual(self.svc.breaker.state, "closed")
        self.assertEqual(self.admin({"state": "sideways"})[0], 400)
        self.assertEqual(self.admin({"state": "open", "seconds": -5})[0], 400)
        self.assertEqual(self.req("/_admin/breaker", mount=None)[0], 405)
        self.assertEqual(self.req("/_stats", method="POST", body=b"", mount=None)[0], 405)
        self.assertEqual(self.req("/photo.png", method="PUT", body=b"x")[0], 405)
        self.assertEqual(self.req("/photo.png?_v=avif", mount=None)[0], 404)
        self.assertEqual(self.req("/photo.png?_v=avif", mount="9")[0], 404)
        self.assertEqual(self.req("/nope.png?_v=avif")[0], 404)
        self.assertEqual(self.req("/../media.json?_v=avif")[0], 404)

    def test_deferral_enqueues_image_job(self):
        self.write_conf(image={"sync_max_mp": 0.001})
        self.addCleanup(self.restore_conf)
        st, h, _ = self.req("/defer.png?_v=avif")
        self.assertEqual((st, h.get("x-strata-orig"), h["x-strata-media"]), (200, "1", "deferred"))
        self.assertEqual((h["x-strata-cache-control"], h["x-strata-cdn-cache-control"]), (BROWSER, SHORT))
        jobs = self.job("image", "/defer.png")
        self.assertEqual([(json.loads(j["params"]), j["priority"], j["state"]) for j in jobs],
                         [({"want": "avif", "width": None, "spec": imaging.auto_spec("avif", None, self.svc.conf())},
                           30, "queued")])
        self.assertIn("bypass.deferred", self.event_kinds("/defer.png"))
        self.assertEqual(self.svc.store.variants_for(1, "/defer.png"), [])
        st, h, _ = self.req("/defer.png?w=100&fm=png")       # explicit transforms defer too
        self.assertEqual(h["x-strata-media"], "deferred")
        self.assertTrue(self.wait_for(lambda: [j for j in self.job("image", "/defer.png") if '"tf"' in j["params"]]))
        st, h, _ = self.req("/defer.png?w=100")              # and so does a width-ladder resize (rung 320)
        self.assertEqual(h["x-strata-media"], "deferred")
        self.assertTrue(self.wait_for(lambda: [j for j in self.job("image", "/defer.png")
                                               if json.loads(j["params"]).get("family") and
                                               json.loads(j["params"])["width"] == 320]))

    def test_negotiation_redirects(self):
        for accept, want in (("image/avif,image/webp,image/apng,*/*;q=0.8", "avif"), ("image/webp,*/*", "webp"),
                             ("*/*", "orig"), ("image/avif;q=0, image/webp;q=0.5", "webp"),
                             ("image/avif;q=0,image/webp;q=0", "orig"), ("image/*", "orig"), (None, "orig")):
            h = {"X-Strata-Negotiate": "1"}
            if accept is not None:
                h["Accept"] = accept
            st, rh, body = self.req("/photo.png", h)
            self.assertEqual((st, rh["location"], body), (302, "/photo.png?_v=" + want, b""), accept)
            self.assertEqual((rh["cache-control"], rh["vary"]), ("private, no-store", "Accept"))
            self.assert_no_cdn(rh)
        st, rh, _ = self.req("/my%20photo.png", {"X-Strata-Negotiate": "1", "Accept": "image/avif"})
        self.assertEqual(rh["location"], "/my%20photo.png?_v=avif")
        st, rh, _ = self.req("//sub/p.png", {"X-Strata-Negotiate": "1", "Accept": "image/webp"})
        self.assertEqual(rh["location"], "/sub/p.png?_v=webp")        # never a protocol-relative open redirect
        self.assertEqual(self.req("/missing.png", {"X-Strata-Negotiate": "1"})[0], 404)

    def test_held_and_pending_variants(self):
        self.verdict("held.png", "flagged")
        for path, extra in (("/held.png?_v=avif", {}), ("/held.png?w=10", {}),
                            ("/held.png", {"X-Strata-Negotiate": "1", "Accept": "image/avif"})):
            st, h, body = self.req(path, extra)
            self.assertEqual((st, body), (403, b"This file is being held for review."), path)
            self.assertEqual(h["cache-control"], "no-store")
            self.assert_no_cdn(h)
        self.write_conf(cutover=1)
        self.addCleanup(self.restore_conf)
        st, h, _ = self.req("/fresh.png?_v=avif")
        self.assertEqual((st, h["retry-after"], h["cache-control"]), (503, "30", "no-store"))
        self.assert_no_cdn(h)
        self.assertEqual([j["priority"] for j in self.job("scan", "/fresh.png")], [10])

    # ------------------------------------------------------------ gate
    def test_scan_matrix(self):
        self.write_conf(cutover=1)                    # everything below is "new" content
        self.addCleanup(self.restore_conf)
        self.verdict("clean.txt", "clean")
        self.verdict("flagged.txt", "flagged", qhash=True)
        self.verdict("stale.txt", "clean")
        self.verdict("broken.txt", "error")
        st, h, body = self.scan("/clip.mp4")
        self.assertEqual((st, body, h.get("x-strata-lane")), (200, b"", None))           # exempt (video)
        self.assertEqual(self.scan("/clean.txt?x=1")[0], 200)
        st, h, body = self.scan("/flagged.txt")
        self.assertEqual((st, body, h["cache-control"]), (403, b"This file is being held for review.", "no-store"))
        self.assert_no_cdn(h)
        shutil.copyfile(os.path.join(self.mnt, "flagged.txt"), os.path.join(self.mnt, "renamed.txt"))
        self.assertEqual(self.scan("/renamed.txt")[0], 403)                             # copy inherits the hold
        st, h, _ = self.scan("/new.txt")
        self.assertEqual((st, h["retry-after"], h["cache-control"]), (503, "30", "no-store"))
        self.assertEqual([(j["priority"], j["params"]) for j in self.job("scan", "/new.txt")], [(10, "")])
        self.assertEqual(self.scan("/broken.txt")[0], 403)                              # error + new = held
        self.assertEqual(self.scan("/stale.txt")[0], 200)
        t = time.time() + 60
        os.utime(os.path.join(self.mnt, "stale.txt"), (t, t))
        self.assertEqual(self.scan("/stale.txt")[0], 503)                               # verdict is for old content
        self.assertEqual(self.scan("/missing.txt")[0], 200)                             # file_server renders the 404
        self.assertEqual(self.scan("/../outside.txt")[0], 403)
        self.assertEqual(self.scan("/.hidden/a.txt")[0], 403)
        self.assertEqual(self.scan("/clean.txt", mount="9")[0], 403)
        self.assertEqual(self.req("/_scan", mount="1", cache=None, edge=None)[0], 403)  # no X-Forwarded-Uri
        self.assertEqual(self.scan("/pre/clean.txt", mount="2")[0], 503)                # verdict belongs to mount 1
        # legacy content: served while pending, scan queued at priority 60; unscannable legacy stays up
        self.write_conf()
        st, h, _ = self.scan("/legacy.txt")
        self.assertEqual(st, 200)
        self.assertEqual([j["priority"] for j in self.job("scan", "/legacy.txt")], [60])
        self.assertEqual(self.scan("/broken.txt")[0], 200)
        self.assertEqual(self.scan("/flagged.txt")[0], 403)                             # but a flag always holds
        st, h, _ = self.scan("/big.zip")
        self.assertEqual((st, h.get("x-strata-lane")), (200, "throttle"))
        self.assertIsNone(self.scan("/legacy.txt")[1].get("x-strata-lane"))

    def test_lane_throttle(self):
        t0 = time.perf_counter()
        st, h, body = self.req("/big.bin", {"X-Strata-Throttle": "1"})
        secs = time.perf_counter() - t0
        self.assertEqual((st, len(body)), (200, 2_000_000))
        self.assertGreater(secs, 1.4)                  # 2 MB at 8 Mbps = 2.0 s (minus a 128 KiB burst)
        self.assertLess(secs, 4.5)
        self.assertEqual((h["cache-control"], h["cloudflare-cdn-cache-control"]), (BROWSER, EDGE))
        self.assertEqual(h["accept-ranges"], "bytes")
        with open(os.path.join(self.mnt, "big.bin"), "rb") as f:
            self.assertEqual(hashlib.sha1(body).hexdigest(), hashlib.sha1(f.read()).hexdigest())
        st, h, body = self.req("/big.bin", {"X-Strata-Throttle": "1", "Range": "bytes=100-199"})
        self.assertEqual((st, len(body), h["content-range"]), (206, 100, "bytes 100-199/2000000"))
        st, h, body = self.req("/big.bin", {"X-Strata-Throttle": "1"}, method="HEAD")
        self.assertEqual((st, body, h["content-length"]), (200, b"", "2000000"))
        self.assertEqual(self.req("/nope.bin", {"X-Strata-Throttle": "1"})[0], 404)

    # ------------------------------------------------------------ transform.py compatibility
    def test_gate_signed_links(self):
        exp = int(time.time()) + 600
        good = "/f/x.png?exp=%d&sig=%s" % (exp, media.sign(SECRET, "/f/x.png", exp))
        g = lambda uri: self.req("/_gate", {"X-Forwarded-Uri": uri}, mount=None, cache=None, edge=None)  # noqa: E731
        self.assertEqual(g(good)[0], 200)
        self.assertEqual(g(good.replace("/f/x.png", "/f/y.png"))[0], 403)
        old = int(time.time()) - 5
        self.assertEqual(g("/f/x.png?exp=%d&sig=%s" % (old, media.sign(SECRET, "/f/x.png", old)))[0], 403)
        st, _, body = g("/f/x.png")
        self.assertEqual((st, body), (403, b"A signed link is required."))
        tf = os.path.join(STRATA, "transform", "transform.py")
        if os.path.isfile(tf):   # byte-identical MAC to Strata Transform
            spec = importlib.util.spec_from_file_location("strata_transform_under_test", tf)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            self.assertEqual(mod.sign(SECRET, "/a%20b/c.png", exp), media.sign(SECRET, "/a%20b/c.png", exp))

    def test_ver_streaming_with_range(self):
        rel = "/doc.txt"
        vf = media.version_file({"path": self.mnt}, rel, 2)
        os.makedirs(os.path.dirname(vf), exist_ok=True)
        with open(vf, "wb") as f:
            f.write(b"0123456789abcdef")
        st, h, body = self.req("/doc.txt?ver=2", {"Range": "bytes=2-5"})
        self.assertEqual((st, body, h["content-range"]), (206, b"2345", "bytes 2-5/16"))
        st, h, body = self.req("/doc.txt?ver=2")
        self.assertEqual((st, body, h["cache-control"], h["cloudflare-cdn-cache-control"]),
                         (200, b"0123456789abcdef", BROWSER, EDGE))
        self.assertEqual(self.req("/doc.txt?ver=2", {"Range": "bytes=20-30"})[0], 416)
        self.assertEqual(self.req("/doc.txt?ver=abc")[0], 400)
        self.assertEqual(self.req("/doc.txt?ver=7")[0], 404)
        # ?ver= + ?w= transforms the stored version
        v1 = media.version_file({"path": self.mnt}, "/photo.png", 1)
        os.makedirs(os.path.dirname(v1), exist_ok=True)
        shutil.copyfile(os.path.join(self.mnt, "tiny.png"), v1)
        st, h, _ = self.req("/photo.png?ver=1&w=4&fm=png")
        self.assertEqual(st, 200)
        with Image.open(self.cache_file(h["x-strata-accel"])) as im:
            self.assertEqual(im.size, (4, 4))

    def test_explicit_resize(self):
        st, h, _ = self.req("/photo.png?w=100&fm=png")
        self.assertEqual((st, h["x-strata-media"]), (200, "miss"))
        self.assertRegex(h["x-strata-accel"], ACCEL_RX)
        self.assertEqual(h["x-strata-disposition"], "inline; filename*=UTF-8''photo.png")
        self.assertEqual((h["x-strata-cache-control"], h["x-strata-cdn-cache-control"]), (BROWSER, EDGE))
        with Image.open(self.cache_file(h["x-strata-accel"])) as im:
            self.assertEqual((im.format, im.size), ("PNG", (100, 75)))
        self.assertEqual(self.req("/photo.png?w=100&fm=png")[1]["x-strata-media"], "hit")
        st, h, _ = self.req("/photo.png?w=120&fm=jpeg&q=70")
        self.assertTrue(h["x-strata-accel"].endswith(".jpg"))
        self.assertEqual(h["x-strata-disposition"], "inline; filename*=UTF-8''photo.jpg")
        with Image.open(self.cache_file(h["x-strata-accel"])) as im:
            self.assertEqual((im.format, im.size), ("JPEG", (120, 90)))
        st, h, _ = self.req("/photo.png?w=2000&fm=png")             # never upscales
        with Image.open(self.cache_file(h["x-strata-accel"])) as im:
            self.assertEqual(im.size, (640, 480))
        st, h, _ = self.req("/photo.png?w=2000")   # ladder rung covers the source: the original itself, no copy
        self.assertEqual((h.get("x-strata-orig"), h["x-strata-media"]), ("1", "orig;reason=width_covers_source"))

    def test_bad_params(self):
        # bare ?w= is the width ladder (1-7680, snapped); with fm/h/fit/q it keeps transform.py's exact rules
        for path, msg in (("/photo.png?w=abc", "w must be a whole number of pixels (1-7680)"),
                          ("/photo.png?w=0", "w must be a whole number of pixels (1-7680)"),
                          ("/photo.png?w=abc&fm=webp", "w/h must be 1-4096"),
                          ("/photo.png?w=5000&fm=webp", "w/h must be 1-4096"),
                          ("/photo.png?fit=nope", "fit must be inside, cover, contain or fill"),
                          ("/photo.png?q=0", "q must be 1-100"),
                          ("/photo.png?fm=gif", "fm must be webp, avif, jpeg or png"),
                          ("/photo.png?fm=webm", "fm must be webp, avif, jpeg or png"),
                          ("/photo.png?_v=bogus", "_v must be avif, webp, webm, mp4 or orig")):
            st, h, body = self.req(path)
            self.assertEqual((st, body.decode()), (400, msg), path)
            self.assertEqual(h["cache-control"], "no-store")
            self.assert_no_cdn(h)
        self.assertEqual(self.req("/clip.mp4?w=100")[0], 415)

    def test_mp4_variants(self):
        """?_v=mp4: queued only while video.format is mp4; a ready MP4 is served from the vid cache as clip.mp4."""
        st, h, _ = self.req("/clip4.mp4?_v=mp4")                    # format webm: no MP4 job behind your back
        self.assertEqual((st, h["location"]), (302, "/clip4.mp4?_v=orig"))
        time.sleep(0.3)
        self.assertEqual([j for j in self.svc.store.jobs(kind="video") if j["path"] == "/clip4.mp4"], [])
        self.write_conf(video={"format": "mp4"})
        self.addCleanup(self.restore_conf)
        st, h, _ = self.req("/clip4.mp4?_v=mp4")
        self.assertEqual((st, h["location"]), (302, "/clip4.mp4?_v=orig"))
        self.assertEqual([(j["priority"], j["params"]) for j in self.job("video", "/clip4.mp4")], [(40, '{"want":"mp4"}')])
        s = os.stat(os.path.join(self.mnt, "clip4.mp4"))
        key = self.svc.cache.key(1, "/clip4.mp4", s.st_size, s.st_mtime, worker.AUTO_SPEC % "mp4")
        f = self.svc.cache.write_bytes(key, "mp4", "vid", b"fake mp4 bytes")
        self.svc.store.put_variant(key, mount=1, path="/clip4.mp4", src_size=s.st_size, src_mtime=s.st_mtime, kind="vid",
                                   fmt="mp4", spec=worker.AUTO_SPEC % "mp4", file=f, bytes=14, src_bytes=s.st_size,
                                   secs=1.0, beneficial=1)
        st, h, _ = self.req("/clip4.mp4?_v=mp4")
        self.assertEqual((st, h["x-strata-media"], h["x-strata-disposition"]), (200, "hit", "inline; filename*=UTF-8''clip4.mp4"))
        self.assertTrue(h["x-strata-accel"].endswith(".mp4"))

    def test_webm_variants(self):
        st, h, body = self.req("/clip.mp4?_v=webm")
        self.assertEqual((st, h["location"], h["cache-control"], body),
                         (302, "/clip.mp4?_v=orig", "private, no-store", b""))
        self.assert_no_cdn(h)
        self.assertEqual([(j["priority"], j["params"]) for j in self.job("video", "/clip.mp4")],
                         [(40, '{"want":"webm"}')])
        self.assertEqual(self.req("/clip.mp4?fm=webm")[0], 302)
        # a ready variant, stored under the very spec the worker uses -> accel from the vid cache
        for name, ok in (("/clip2.mp4", 1), ("/clip3.mp4", 0)):
            s = os.stat(os.path.join(self.mnt, name.lstrip("/")))
            spec = worker.AUTO_SPEC % "webm"
            key = self.svc.cache.key(1, name, s.st_size, s.st_mtime, spec)
            f = self.svc.cache.write_bytes(key, "webm", "vid", b"fake webm bytes") if ok else ""
            self.svc.store.put_variant(key, mount=1, path=name, src_size=s.st_size, src_mtime=s.st_mtime, kind="vid",
                                       fmt="webm", spec=spec, file=f, bytes=15, src_bytes=s.st_size,
                                       secs=1.0, beneficial=ok)
        st, h, _ = self.req("/clip2.mp4?_v=webm")
        self.assertEqual((st, h["x-strata-media"], h["x-strata-disposition"]),
                         (200, "hit", "inline; filename*=UTF-8''clip2.webm"))
        self.assertTrue(h["x-strata-accel"].startswith("/vid/") and h["x-strata-accel"].endswith(".webm"))
        self.assertEqual((h["x-strata-cache-control"], h["x-strata-cdn-cache-control"]), (BROWSER, EDGE))
        st, h, _ = self.req("/clip3.mp4?_v=webm")                  # not beneficial: original, no new job
        self.assertEqual((st, h["location"]), (302, "/clip3.mp4?_v=orig"))
        time.sleep(0.3)
        self.assertEqual([j for j in self.svc.store.jobs(kind="video") if j["path"] == "/clip3.mp4"], [])
        st, h, _ = self.req("/movie.webm?_v=webm")
        self.assertEqual((st, h.get("x-strata-orig"), h["x-strata-media"]), (200, "1", "orig;reason=webm"))
        self.assertEqual(self.req("/photo.png?_v=webm")[1]["location"], "/photo.png?_v=orig")

    def test_cache_header_fallbacks(self):
        st, h, _ = self.req("/nohdr.png?_v=webp", cache=IMMUTABLE, edge=None)          # older rules.py
        self.assertEqual((h["x-strata-cache-control"], h["x-strata-cdn-cache-control"]), (IMMUTABLE, IMMUTABLE))
        st, h, _ = self.req("/nohdr.png?_v=webp", cache=None, edge=None)               # nothing at all
        self.assertEqual((h["x-strata-cache-control"], h["x-strata-cdn-cache-control"]), (media.FALLBACK_CC,) * 2)
        st, h, _ = self.req("/photo.png?_v=orig")
        self.assertEqual((h.get("x-strata-orig"), h["x-strata-cdn-cache-control"]), ("1", EDGE))

    # ------------------------------------------------------------ stats / housekeeping
    def test_stats_and_housekeeping(self):
        st, h, body = self.req("/_stats", mount=None)
        self.assertEqual((st, h["content-type"], h["cache-control"]), (200, "application/json", "no-store"))
        d = json.loads(body)
        self.assertEqual((d["service"], d["version"]), ("strata-media", media.VERSION))
        self.assertIn(d["breaker"]["state"], ("closed", "open", "half_open"))
        self.assertIsInstance(d["gate"]["verdicts"], int)
        self.svc.tick()
        meta = self.svc.store.get_meta("breaker")
        self.assertEqual((meta["name"], meta["proc"]), ("media", "media"))
        self.svc.write_sample(60 * 1000)
        rows = self.svc.store.samples(0, "media")
        self.assertTrue(rows and {"cpu_avg", "open_s", "bypass", "gate", "encodes"} <= set(rows[-1]["data"]))
        self.svc.model.observe("avif", 7, 1.0, 0.4)
        self.svc.save_model()
        self.assertIn("avif:7", self.svc.store.get_meta("cost_model")["rates"])

    def test_single_instance(self):
        with self.assertRaises(OSError):   # a second media.py cannot bind the same port (no SO_REUSEADDR)
            media.make_server("127.0.0.1:%d" % self.port, None)
        self.assertEqual(self.req("/photo.png?_v=avif", mount="¹")[0], 404)   # superscript one is no mount id


class HelperTest(unittest.TestCase):
    def test_loopback(self):
        for host, ok in (("127.0.0.1", True), ("127.8.9.1", True), ("::1", True), ("::ffff:127.0.0.1", True),
                         ("10.0.0.1", False), ("192.168.1.55", False), ("::ffff:10.0.0.1", False), ("garbage", False)):
            self.assertEqual(media.is_loopback(host), ok, host)

    def test_split_target_and_location(self):
        self.assertEqual(media.split_target("//evil.example/x.png?_v=avif"), ("//evil.example/x.png", "_v=avif"))
        self.assertEqual(media.split_target("http://h/a.png?q=1"), ("/a.png", "q=1"))
        self.assertEqual(media.location({"prefix": "/pre"}, "/a%b c.png", "avif"), "/pre/a%25b%20c.png?_v=avif")
        self.assertEqual(media.location({"prefix": "/"}, "/d/é.png", "orig"), "/d/%C3%A9.png?_v=orig")

    def test_accept_and_disposition(self):
        self.assertEqual(media.negotiate_format("image/avif;q=0.1"), "avif")
        self.assertEqual(media.negotiate_format("image/AVIF;q=x, image/webp"), "webp")
        self.assertEqual(media.negotiate_format(""), "orig")
        self.assertEqual(media.disposition("/a/b cé.png", "avif"), "inline; filename*=UTF-8''b%20c%C3%A9.avif")
        self.assertEqual(media.disposition("/noext", "webp"), "inline; filename*=UTF-8''noext.webp")

    def test_specs(self):
        p = {"w": 100, "h": None, "fit": "inside", "q": 82, "fm": "auto"}
        self.assertEqual(media.spec_tf(p), "tf:w=100,h=,fit=inside,fm=auto,q=82:v1")
        self.assertEqual(media.spec_tf(p, 3), "tf:w=100,h=,fit=inside,fm=auto,q=82,ver=3:v1")
        self.assertEqual((media.spec_auto("avif"), media.spec_video("webm")), ("auto:avif:v1", "auto:webm:v1"))
        for fmt in ("webm", "mp4"):   # media.py looks a video variant up under the key the worker writes it to
            self.assertEqual(media.spec_video(fmt), worker.AUTO_SPEC % fmt)

    def test_bucket_rate(self):
        b = media.Bucket(8, 0)                 # 1 MB/s, no burst
        self.assertAlmostEqual(b.take(500_000), 0.5, delta=0.05)
        self.assertAlmostEqual(b.take(500_000), 1.0, delta=0.05)   # reservations queue up
        self.assertEqual(media.Bucket(0, 0).take(10 ** 9), 0.0)    # 0 = unlimited


if __name__ == "__main__":
    unittest.main()
