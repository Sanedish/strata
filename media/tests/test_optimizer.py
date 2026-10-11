"""Image optimizer (media/OPTIMIZER.md): negotiation, width ladder, bypass, tiers, single-flight, failures, limits and
the HTTP semantics as a client sees them - through a private Caddy rendered by media_rules in front of a real
media.py, both on test ports (production ports, strata.db and the NAS are never touched).

Runs the deployed images-only profile: scan gate, file policy, lane and video off.
"""
import copy
import gc
import http.client
import io
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zlib
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
MEDIA_DIR = os.path.dirname(HERE)
STRATA = os.path.dirname(MEDIA_DIR)
for _p in (MEDIA_DIR, STRATA):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import media  # noqa: E402  (imports pathfix first)
import breaker  # noqa: E402
import config  # noqa: E402
import imaging  # noqa: E402

try:
    from PIL import Image, ImageDraw, features
except ImportError:  # pragma: no cover
    Image = None

MEDIA_PORT, SITE_PORT, ADMIN = 18290, 18291, "localhost:2097"
BROWSER, EDGE = "public, no-cache", "public, max-age=31536000"
SHORT = "public, max-age=60"
AVIF_ACCEPT = "image/avif,image/webp,image/apng,image/*,*/*;q=0.8"
WEBP_ACCEPT = "image/webp,image/*,*/*;q=0.8"
OLD_ACCEPT = "image/png,image/*;q=0.8,*/*;q=0.5"
CADDY = None
TMP = None


def setUpModule():
    global TMP, CADDY
    TMP = tempfile.mkdtemp(prefix="strata-optimizer-")
    for c in (os.environ.get("STRATA_CADDY"), shutil.which("caddy")):
        if c and os.path.exists(c):
            CADDY = c
            break


def tearDownModule():
    for _ in range(20):
        gc.collect()
        try:
            shutil.rmtree(TMP)
            return
        except OSError:
            time.sleep(0.3)
    shutil.rmtree(TMP, ignore_errors=True)


def port_free(port):
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def listening(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
        return True
    except OSError:
        return False


# ---------------------------------------------------------------- fixtures

def photo(size):
    base = Image.linear_gradient("L").resize(size)
    mand = Image.effect_mandelbrot(size, (-2.0, -1.25, 1.0, 1.25), 60)
    return Image.merge("RGB", (base, mand, Image.effect_noise(size, 12)))


def screenshot(size):
    im = Image.new("RGB", size, (245, 245, 247))
    d = ImageDraw.Draw(im)
    for y in range(40, size[1] - 40, 28):
        d.rectangle([60, y, size[0] - 60, y + 14], fill=(30 + y % 90, 60, 120))
        d.text((70, y), "Strata optimizer fixture line %d" % y, fill=(255, 255, 255))
    return im


def bomb_png(w, h):
    """A valid PNG header claiming w x h pixels (no real pixel data): a decompression-bomb probe."""
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(b"\0" * 64)) + chunk(b"IEND", b"")


def make_fixtures(m):
    os.makedirs(os.path.join(m, "sub"), exist_ok=True)
    photo((2400, 1350)).save(os.path.join(m, "big.png"))
    photo((1600, 1200)).save(os.path.join(m, "photo.jpg"), "JPEG", quality=95)
    a = photo((800, 600)).convert("RGBA")
    a.putalpha(Image.linear_gradient("L").resize((800, 600)))
    a.save(os.path.join(m, "alpha.png"))
    screenshot((1600, 900)).save(os.path.join(m, "shot.png"))
    photo((800, 600)).save(os.path.join(m, "pic.webp"), "WEBP", quality=95)
    if features.check("avif"):
        photo((600, 400)).save(os.path.join(m, "pic.avif"), "AVIF", quality=60)
    Image.new("RGB", (8, 8), (10, 20, 30)).save(os.path.join(m, "tiny.png"))
    frames = [photo((200, 150)).rotate(i * 20) for i in range(5)]
    frames[0].save(os.path.join(m, "anim.gif"), save_all=True, append_images=frames[1:], duration=80, loop=0)
    with open(os.path.join(m, "garbage.png"), "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n" + b"not really a png" * 500)
    with open(os.path.join(m, "bomb.png"), "wb") as f:
        f.write(bomb_png(60000, 60000))
    with open(os.path.join(m, "notes.txt"), "wb") as f:
        f.write(b"plain text that compresses well. " * 400)
    for n in ("hot.png", "cold.png", "conc.png", "fail.png", "mut.png", "head.png", "cond.png", "lock.png",
              "nt.png", "dbg.png", "lim.png"):
        shutil.copyfile(os.path.join(m, "big.png"), os.path.join(m, n))
    shutil.copyfile(os.path.join(m, "anim.gif"), os.path.join(m, "anim2.gif"))


def conf_for(tmp, mnt, **over):
    c = {"enabled": True, "listen": "127.0.0.1:%d" % MEDIA_PORT, "db": os.path.join(tmp, "media.db"),
         "cache_root": os.path.join(tmp, "mc"), "event_log": os.path.join(tmp, "events.jsonl"),
         "negotiation": "redirect", "cutover": 1.0, "admin_token": "t", "sign_secret": "s",
         # the deployed images-only profile
         "gate": {"enabled": False}, "lane": {"enabled": False}, "video": {"enabled": False},
         "file_policy": {"enabled": False, "svg_csp": False}, "worker": {"backfill": False},
         "image": {"min_bytes": 1024, "prewarm_uploads": False,
                   "tiers": {"interval_s": 86400, "promote_min_hits": 3, "promote_rate_per_day": 0.5,
                             "promote_min_value_mb": 0.01}},
         "mounts": {"1": {"path": mnt, "prefix": "/", "hosts": ["localhost"], "cache": BROWSER, "edge_cache": EDGE,
                          "transforms": 1}}}
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(c.get(k), dict):
            c[k] = dict(c[k], **v)
        else:
            c[k] = v
    return c


@unittest.skipIf(Image is None or imaging.Image is None, "Pillow missing")
class Base(unittest.TestCase):
    """A real media.py Service (own media.db, cache, mount) on MEDIA_PORT."""

    @classmethod
    def setUpClass(cls):
        if not port_free(MEDIA_PORT):
            raise unittest.SkipTest("media test port %d busy" % MEDIA_PORT)
        cls.tmp = tempfile.mkdtemp(prefix="opt-", dir=TMP)
        cls.mnt = os.path.join(cls.tmp, "mount")
        make_fixtures(cls.mnt)
        cls.conf_path = os.path.join(cls.tmp, "media.json")
        cls.write_conf()
        cls.monitor = breaker.Monitor(sampler=lambda: (5.0, 6000.0, 30.0))
        cls.monitor.tick()
        cls.monitor.tick()
        cls.svc = media.Service(cls.conf_path, monitor=cls.monitor)
        cls.srv = media.make_server("127.0.0.1:%d" % MEDIA_PORT, cls.svc)
        cls.svc.start()
        cls.thread = threading.Thread(target=cls.srv.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.svc.stop()
        cls.thread.join(5)

    @classmethod
    def write_conf(cls, **over):
        with open(cls.conf_path, "w", encoding="utf-8") as f:
            json.dump(conf_for(cls.tmp, cls.mnt, **over), f)
        config._cache.pop(cls.conf_path, None)

    def media_req(self, path, headers=None, method="GET"):
        """Straight to media.py, as Caddy would call it (mount + cache headers)."""
        h = {"X-Strata-Mount": "1", "X-Strata-Cache": BROWSER, "X-Strata-Edge-Cache": EDGE}
        h.update(headers or {})
        c = http.client.HTTPConnection("127.0.0.1", MEDIA_PORT, timeout=120)
        try:
            c.request(method, path, headers=h)
            r = c.getresponse()
            return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()
        finally:
            c.close()

    def cache_path(self, accel):
        return os.path.join(self.tmp, "mc", "cache", *accel.lstrip("/").split("/"))

    def rows(self, rel):
        return self.svc.store.variants_for(1, rel)

    def metric(self, name, **labels):
        with self.svc.stat_lock:
            return sum(v for (n, lb), v in self.svc.metrics.items()
                       if n == name and all(dict(lb).get(k) == x for k, x in labels.items()))


# ================================================================ HTTP through a real Caddy

class ThroughCaddy(Base):
    proc = None

    @classmethod
    def setUpClass(cls):
        if not CADDY:
            raise unittest.SkipTest("caddy.exe not found")
        if listening(SITE_PORT) or not port_free(SITE_PORT):
            raise unittest.SkipTest("site test port %d busy" % SITE_PORT)
        super().setUpClass()
        cls.main = os.path.join(cls.tmp, "Caddyfile")
        cls.render("redirect")
        cls.proc = subprocess.Popen([CADDY, "run", "--config", cls.main, "--adapter", "caddyfile"],
                                    stdout=subprocess.DEVNULL, stderr=open(os.path.join(cls.tmp, "caddy.err"), "wb"),
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        end = time.monotonic() + 30
        while time.monotonic() < end and not listening(SITE_PORT):   # Caddy binds [::]: a bind test can't see it
            time.sleep(0.2)
        if not listening(SITE_PORT):
            cls.tearDownClass()
            raise unittest.SkipTest("private caddy did not start")

    @classmethod
    def tearDownClass(cls):
        if cls.proc is not None:
            cls.proc.terminate()
            try:
                cls.proc.wait(15)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
        super().tearDownClass()

    @classmethod
    def render(cls, mode):
        """The CDN site exactly as media_rules renders it for a files mount (+ the drive's own handle)."""
        import core
        import media_rules
        import rules
        m = {"id": 1, "kind": "files", "enabled": 1, "prefix": "/", "hosts": ["localhost"], "path": cls.mnt,
             "cache": BROWSER, "edge_cache": EDGE, "precompress": 1, "browse": 0, "transforms": 1, "sort": 1}
        saved = copy.deepcopy(core.CFG["media"])
        try:
            core.CFG["media"].update(enabled=True, listen="127.0.0.1:%d" % MEDIA_PORT,
                                     cache_root=os.path.join(cls.tmp, "mc").replace("\\", "/"))
            o = rules.Out()
            media_rules.render_prologue(o)
            up = ["header_up X-Strata-Mount 1", "header_up X-Strata-Cache %s" % rules.bq(BROWSER),
                  "header_up X-Strata-Edge-Cache %s" % rules.bq(EDGE)]
            media_rules.render_media_routes(o, m, up, negotiation=mode)
        finally:
            core.CFG["media"].clear()
            core.CFG["media"].update(saved)
        body = "\n".join(o.lines)
        mnt = cls.mnt.replace("\\", "/")
        text = """{
\tadmin %s
\tauto_https off
\tpersist_config off
\tstorage file_system %s
}
http://localhost:%d {
\tencode gzip zstd
\troute {
%s
\t\thandle {
\t\t\troot * `%s`
\t\t\theader Cache-Control `%s`
\t\t\theader Cloudflare-CDN-Cache-Control `%s`
\t\t\tfile_server {
\t\t\t\tprecompressed br
\t\t\t}
\t\t}
\t}
}
""" % (ADMIN, os.path.join(cls.tmp, "caddy-storage").replace("\\", "/"), SITE_PORT, body, mnt, BROWSER, EDGE)
        with open(cls.main, "w", encoding="utf-8") as f:
            f.write(text)
        return text

    def reload(self, mode):
        self.render(mode)
        r = subprocess.run([CADDY, "reload", "--config", self.main, "--adapter", "caddyfile", "--address", ADMIN],
                           capture_output=True, text=True, timeout=60,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.assertEqual(r.returncode, 0, r.stderr[-800:])

    def get(self, path, headers=None, method="GET"):
        h = {"Host": "localhost:%d" % SITE_PORT, "Accept-Encoding": "identity"}
        h.update(headers or {})
        c = http.client.HTTPConnection("127.0.0.1", SITE_PORT, timeout=120)
        try:
            c.request(method, path, headers=h)
            r = c.getresponse()
            out = {}
            for k, v in r.getheaders():                      # repeated fields (Vary) joined like a client would
                out[k.lower()] = out[k.lower()] + ", " + v if k.lower() in out else v
            return r.status, out, r.read()
        finally:
            c.close()

    def follow(self, path, accept, headers=None, method="GET"):
        """GET the canonical URL with an Accept header and follow the negotiation redirect once."""
        h = dict(headers or {}, Accept=accept)
        st, hd, body = self.get(path, h, method)
        if st == 302:
            self.assertEqual(hd["cache-control"], "private, no-store")   # nobody may cache a negotiation answer
            self.assertIn("Accept", hd.get("vary", ""))
            return (hd["location"],) + self.get(hd["location"], h, method)
        return (path, st, hd, body)

    # ------------------------------------------------------------ negotiation + cache semantics
    def test_negotiation_per_client(self):
        loc, st, h, body = self.follow("/big.png", AVIF_ACCEPT)
        self.assertEqual((loc, st, h["content-type"]), ("/big.png?_v=avif", 200, "image/avif"))
        self.assertEqual(int(h["content-length"]), len(body))
        self.assertIn("Accept", h["vary"])
        self.assertEqual((h["cache-control"], h["cloudflare-cdn-cache-control"]), (BROWSER, EDGE))
        self.assertTrue(h["etag"].startswith('"'))
        self.assertIn("last-modified", h)
        self.assertEqual(Image.open(io.BytesIO(body)).size, (2400, 1350))       # same dimensions, other format
        avif_bytes = body
        loc, st, h, body = self.follow("/big.png", WEBP_ACCEPT)
        self.assertEqual((loc, h["content-type"]), ("/big.png?_v=webp", "image/webp"))
        # a client without AVIF/WebP never gets AVIF, even right after an AVIF client asked for the same URL
        for accept in (OLD_ACCEPT, "*/*", "image/avif;q=0, image/png", ""):
            loc, st, h, body = self.follow("/big.png", accept)
            self.assertEqual((loc, st, h["content-type"]), ("/big.png?_v=orig", 200, "image/png"), accept)
            with open(os.path.join(self.mnt, "big.png"), "rb") as f:
                self.assertEqual(body, f.read())
        self.assertNotEqual(avif_bytes[:16], body[:16])
        # the canonical URL itself never answers 200 in redirect mode (nothing format-specific to cache there)
        self.assertEqual(self.get("/big.png", {"Accept": AVIF_ACCEPT})[0], 302)

    def test_width_ladder_and_collisions(self):
        seen = {}
        for w, rung, size in ((1000, 1080, (1080, 608)), (1080, 1080, (1080, 608)), (1500, 1920, (1920, 1080)),
                              (2160, 2160, (2160, 1215)), (4000, None, (2400, 1350)), (99999, None, (2400, 1350))):
            loc, st, h, body = self.follow("/big.png?w=%d" % w, AVIF_ACCEPT)
            want = "/big.png?w=%d&_v=avif" % (rung or (7680 if w > 4320 else 4320))
            self.assertEqual((loc, st, h["content-type"]), (want, 200, "image/avif"), w)
            got = Image.open(io.BytesIO(body)).size
            self.assertEqual(got, size, w)                            # never larger than asked, never upscaled
            self.assertEqual(h["x-cdn-image-width"], str(size[0]) if size[0] < 2400 else "full")
            seen.setdefault(size, set()).add(h["etag"])
        self.assertEqual({k: len(v) for k, v in seen.items()}, {k: 1 for k in seen})   # one variant per size
        self.assertEqual(len({e for v in seen.values() for e in v}), 4)                # and no two sizes collide
        _, _, full_h, _ = self.follow("/big.png", AVIF_ACCEPT)
        self.assertIn(full_h["etag"], seen[(2400, 1350)])           # rung >= source == the full-size variant
        # without a modern format: a resize in the source's own format family
        loc, st, h, body = self.follow("/big.png?w=1080", OLD_ACCEPT)
        self.assertEqual((loc, h["content-type"], Image.open(io.BytesIO(body)).size),
                         ("/big.png?w=1080&_v=orig", "image/png", (1080, 608)))

    def test_bypass_nocompress_and_no_transform(self):
        with open(os.path.join(self.mnt, "nt.png"), "rb") as f:
            orig = f.read()
        before = len(self.rows("/nt.png"))
        for q in ("nocompress=1", "nocompress=true", "nocompress"):
            st, h, body = self.get("/nt.png?" + q, {"Accept": AVIF_ACCEPT})
            self.assertEqual((st, h["content-type"], body), (200, "image/png", orig), q)
            self.assertEqual(h["cloudflare-cdn-cache-control"], EDGE)   # its own URL: cacheable like the original
        st, h, body = self.get("/nt.png?_v=avif&nocompress=1", {"Accept": AVIF_ACCEPT})
        self.assertEqual((st, h["content-type"], body), (200, "image/png", orig))
        # header bypass: original, but nobody may store it (the URL is the normal one)
        loc, st, h, body = self.follow("/nt.png", AVIF_ACCEPT, {"Cache-Control": "no-transform"})
        self.assertEqual((loc, st, h["content-type"], body), ("/nt.png", 200, "image/png", orig))
        self.assertEqual((h["cache-control"], h["cloudflare-cdn-cache-control"]), ("private, no-store", "no-store"))
        st, h, body = self.get("/nt.png?_v=avif", {"Accept": AVIF_ACCEPT, "Cache-Control": "max-age=0, no-transform"})
        self.assertEqual((h["content-type"], h["cache-control"], body), ("image/png", "private, no-store", orig))
        self.assertEqual(h["cloudflare-cdn-cache-control"], "no-store")
        self.assertEqual(len(self.rows("/nt.png")), before)          # nothing generated, nothing stored
        # ... and the normal entry is untouched
        loc, st, h, body = self.follow("/nt.png", AVIF_ACCEPT)
        self.assertEqual((loc, h["content-type"]), ("/nt.png?_v=avif", "image/avif"))

    def test_head_and_conditional_never_encode(self):
        st, h, body = self.get("/head.png?_v=avif", {"Accept": AVIF_ACCEPT}, method="HEAD")
        self.assertEqual((st, body, h["content-type"], h["x-cdn-image-cache"]), (200, b"", "image/png", "deferred"))
        self.assertEqual(h["cloudflare-cdn-cache-control"], SHORT)      # Cloudflare asks again soon
        self.assertEqual([r for r in self.rows("/head.png") if r["beneficial"]], [])   # no encode for HEAD
        loc, st, h, body = self.follow("/head.png", AVIF_ACCEPT)        # GET encodes
        etag, size = h["etag"], len(body)
        st, h, body = self.get(loc, {"Accept": AVIF_ACCEPT}, method="HEAD")
        self.assertEqual((st, int(h["content-length"]), body, h["etag"]), (200, size, b"", etag))
        st, h, body = self.get(loc, {"Accept": AVIF_ACCEPT, "If-None-Match": etag})
        self.assertEqual((st, body), (304, b""))
        self.assertEqual(h["etag"], etag)
        # evict the file: a conditional request is answered from the recorded validator, without re-encoding
        row = next(r for r in self.rows("/head.png") if r["beneficial"] and r["fmt"] == "avif" and not r["width"])
        os.remove(self.cache_path(row["file"]))
        self.svc.store.evict_variant(row["key"])
        n = self.metric("image_optimizer_encode_count_total")
        st, h, body = self.get(loc, {"Accept": AVIF_ACCEPT, "If-None-Match": etag})
        self.assertEqual((st, body, h["etag"], h["x-cdn-image-cache"]), (304, b"", etag, "validator"))
        self.assertIn("Accept", h.get("vary", ""))
        self.assertEqual(self.metric("image_optimizer_encode_count_total"), n)
        self.assertFalse(os.path.exists(self.cache_path(row["file"])))
        # a stale validator is not a 304 (and never triggers a sync encode either)
        st, h, body = self.get(loc, {"Accept": AVIF_ACCEPT, "If-None-Match": '"nope"'})
        self.assertEqual((st, h["content-type"], h["x-cdn-image-cache"]), (200, "image/png", "deferred"))
        # the next plain GET re-encodes; same source mtime + same settings -> the same ETag as before
        loc2, st, h, body = self.follow("/head.png", AVIF_ACCEPT)
        self.assertEqual((st, h["content-type"]), (200, "image/avif"))
        self.assertEqual(self.get(loc, {"If-None-Match": h["etag"]})[0], 304)

    def test_non_images_untouched(self):
        st, h, body = self.get("/notes.txt", {"Range": "bytes=0-9"})
        self.assertEqual((st, body, h.get("content-range")), (206, b"plain text", "bytes 0-9/13200"))
        st, h, body = self.get("/notes.txt", {"Accept-Encoding": "gzip"})
        self.assertEqual(h.get("content-encoding"), "gzip")             # text still gets transfer compression
        self.assertNotIn("Accept", [v.strip() for v in h.get("vary", "").split(",")])
        loc, st, h, body = self.follow("/big.png", AVIF_ACCEPT, {"Accept-Encoding": "gzip, br, zstd"})
        self.assertNotIn("content-encoding", h)                          # never AVIF -> gzip/br
        st, h, body = self.get(loc, {"Range": "bytes=0-11", "Accept": AVIF_ACCEPT})
        self.assertEqual((st, body[4:12]), (206, b"ftypavif"))           # Range works on the variant file too
        st, h, _ = self.get("/big.png?dl=1", {"Accept": AVIF_ACCEPT})   # a download is always the original
        self.assertEqual((st, h["content-type"]), (200, "image/png"))
        st, h, _ = self.get("/big.png?fm=webp&w=640&q=70", {"Accept": AVIF_ACCEPT})   # legacy explicit transform
        self.assertEqual((st, h["content-type"]), (200, "image/webp"))
        self.assertNotIn("accept", [v.strip().lower() for v in h.get("vary", "").split(",")])   # explicit: no Vary

    def test_debug_headers_and_switch(self):
        loc, st, h, _ = self.follow("/dbg.png", AVIF_ACCEPT)
        self.assertEqual((h["x-cdn-image-format"], h["x-cdn-image-source"], h["x-cdn-image-width"]),
                         ("avif", "variant", "full"))
        self.assertIn(h["x-cdn-image-cache"], ("live", "ephemeral"))
        for v in h.values():                                             # no paths / keys leak
            self.assertNotIn(self.mnt.replace("\\", "/").lower(), v.lower())
        self.assertNotIn("x-strata-accel", h)
        self.write_conf(image={"debug_headers": False})
        self.addCleanup(self.write_conf)
        loc, st, h, _ = self.follow("/dbg.png", AVIF_ACCEPT)
        self.assertFalse([k for k in h if k.startswith("x-cdn-image")])

    def test_zz_edge_mode(self):
        """Edge mode: Cloudflare rewrites query-less requests by Accept (simulated here by asking for ?_v= the way the
        rule would); the origin still negotiates ?w= itself, and the canonical original says Vary: Accept."""
        self.reload("edge")
        try:
            st, h, body = self.get("/big.png", {"Accept": OLD_ACCEPT})
            self.assertEqual((st, h["content-type"]), (200, "image/png"))     # no redirect at the origin
            self.assertIn("Accept", h["vary"])
            st, h, body = self.get("/big.png?_v=avif", {"Accept": AVIF_ACCEPT})   # what the edge rule produces
            self.assertEqual((st, h["content-type"]), (200, "image/avif"))
            self.assertIn("Accept", h["vary"])
            loc, st, h, body = self.follow("/big.png?w=1080", AVIF_ACCEPT)
            self.assertEqual((loc, Image.open(io.BytesIO(body)).size), ("/big.png?w=1080&_v=avif", (1080, 608)))
        finally:
            self.reload("redirect")


# ================================================================ service level

class Service(Base):
    def test_negotiate_format_q_values(self):
        cases = {"image/avif": "avif", "image/webp": "webp", "image/png": "orig", "*/*": "orig", "": "orig",
                 None: "orig", "image/*": "orig", AVIF_ACCEPT: "avif", "image/avif;q=0,image/webp": "webp",
                 "image/avif;q=0.0, image/webp;q=0": "orig", "image/AVIF;Q=0.5": "avif", "image/avif;q=bogus": "orig",
                 "image/webp;q=0.9, image/avif;q=0.1": "avif"}   # any acceptable AVIF wins: it is the smaller one
        for accept, want in cases.items():
            self.assertEqual(media.negotiate_format(accept), want, accept)

    def test_video_player_negotiates_webm(self):
        """Redirect mode sends query-less videos from <video> players here: 302 ?_v=webm (never AVIF/WebP by Accept);
        while no WebM exists that URL answers 302 ?_v=orig. ?nocompress keeps the original."""
        with open(os.path.join(self.mnt, "clip.mp4"), "wb") as f:
            f.write(b"\0\0\0\x18ftypmp42" + b"\0" * 2048)
        st, h, _ = self.media_req("/clip.mp4", {"X-Strata-Negotiate": "1", "Accept": AVIF_ACCEPT})
        self.assertEqual((st, h["location"].rsplit("?", 1)[-1]), (302, "_v=webm"))
        self.assertEqual(h["cache-control"], "private, no-store")
        st, h, _ = self.media_req("/clip.mp4?_v=webm")
        self.assertEqual((st, h["location"].rsplit("?", 1)[-1]), (302, "_v=orig"))
        st, h, _ = self.media_req("/clip.mp4?nocompress=1", {"X-Strata-Negotiate": "1"})
        self.assertNotEqual(st, 302)

    def test_bypass_reason(self):
        from email.message import Message
        def hdrs(**kw):
            m = Message()
            for k, v in kw.items():
                m[k.replace("_", "-")] = v
            return m
        self.assertEqual(media.bypass_reason({"nocompress": "1"}, hdrs()), "nocompress")
        self.assertEqual(media.bypass_reason({"nocompress": "Yes"}, hdrs()), "nocompress")
        self.assertEqual(media.bypass_reason({"nocompress": ""}, hdrs()), "nocompress")
        self.assertIsNone(media.bypass_reason({"nocompress": "0"}, hdrs()))
        self.assertIsNone(media.bypass_reason({"nocompress": "false"}, hdrs()))
        self.assertEqual(media.bypass_reason({}, hdrs(Cache_Control="max-age=0, No-Transform")), "no-transform")
        self.assertIsNone(media.bypass_reason({}, hdrs(Cache_Control="no-cache")))

    def test_single_flight_100_requests_one_encode(self):
        calls = []
        real = imaging.encode_auto

        def slow(*a, **kw):
            calls.append(1)
            time.sleep(0.8)                         # make sure every request arrives while the encode runs
            return real(*a, **kw)
        results = []
        with mock.patch.object(imaging, "encode_auto", slow):
            def one():
                results.append(self.media_req("/conc.png?_v=avif"))
            ts = [threading.Thread(target=one) for _ in range(100)]
            for t in ts:
                t.start()
            for t in ts:
                t.join(120)
        self.assertEqual(len(calls), 1)
        accels = {h.get("x-strata-accel") for st, h, _ in results}
        self.assertEqual(len(accels), 1, accels)                        # all 100 got the one variant
        self.assertIsNotNone(accels.pop())
        files = [f for dp, dn, fn in os.walk(os.path.join(self.tmp, "mc", "cache")) for f in fn
                 if self.svc.cache.key(1, "/conc.png", os.path.getsize(os.path.join(self.mnt, "conc.png")),
                                       os.stat(os.path.join(self.mnt, "conc.png")).st_mtime,
                                       imaging.auto_spec("avif", None, self.svc.conf())) in f]
        self.assertEqual(len(files), 1)                                 # one writer, one file
        self.assertEqual(os.listdir(os.path.join(self.tmp, "mc", "tmp")), [])   # no partial files left

    def test_cross_process_lock_blocks_second_encoder(self):
        st = os.stat(os.path.join(self.mnt, "lock.png"))
        key = self.svc.cache.key(1, "/lock.png", st.st_size, st.st_mtime,
                                 imaging.auto_spec("avif", None, self.svc.conf()))
        other = self.svc.cache.lock(key)              # a second handle = what the worker process would hold
        self.assertTrue(other.acquire())
        try:
            with mock.patch.object(imaging, "encode_auto", side_effect=AssertionError("must not encode")):
                self.write_conf(image={"sync_budget_s": 0.3, "sync_budget_max_s": 0.3})
                try:
                    stt, h, _ = self.media_req("/lock.png?_v=avif")
                finally:
                    self.write_conf()
            self.assertEqual((stt, h.get("x-strata-orig"), h["x-strata-media"]), (200, "1", "bypass;kind=inflight"))
            self.assertEqual(h["x-strata-cdn-cache-control"], SHORT)
        finally:
            other.release()
        stt, h, _ = self.media_req("/lock.png?_v=avif")
        self.assertEqual(h["x-strata-media"], "miss")

    def test_promotion_cold_ephemeral_persistent_and_back(self):
        st, h, _ = self.media_req("/hot.png?_v=avif")
        self.assertEqual((h["x-strata-media"], h["x-cdn-image-cache"]), ("miss", "live"))
        eph = h["x-strata-accel"]
        self.assertFalse(eph.startswith("/static/"))
        for _ in range(5):
            st, h, _ = self.media_req("/hot.png?_v=avif")
            self.assertEqual((h["x-strata-accel"], h["x-cdn-image-cache"]), (eph, "ephemeral"))
        self.media_req("/cold.png?_v=avif")                             # requested once: stays ephemeral
        res = self.svc.tier_pass()
        self.assertGreaterEqual(res["promoted"], 1, res)                # (other tests' hot variants may join)
        row = next(r for r in self.rows("/hot.png") if r["beneficial"])
        self.assertEqual((row["tier"], row["hits"]), ("persistent", 6))
        self.assertTrue(row["file"].startswith("/static/img/"))
        self.assertEqual(next(r for r in self.rows("/cold.png") if r["beneficial"])["tier"], "ephemeral")
        with mock.patch.object(imaging, "encode_auto", side_effect=AssertionError("hot path must not encode")):
            for _ in range(3):
                st, h, _ = self.media_req("/hot.png?_v=avif")
                self.assertEqual((h["x-strata-accel"], h["x-cdn-image-cache"], h["x-strata-media"]),
                                 (row["file"], "persistent", "hit"))
        self.assertEqual(self.svc.tier_pass()["promoted"], 0)          # idempotent: no second copy
        # the old ephemeral name is retired after the grace period, never twice the bytes for long
        self.assertTrue(os.path.exists(self.cache_path(eph)))
        self.svc.retire(time.monotonic() + 3600)
        self.assertFalse(os.path.exists(self.cache_path(eph)))
        self.assertTrue(os.path.exists(self.cache_path(row["file"])))
        # the promotion asked the worker for the slower, smaller encode
        self.assertTrue(self.wait(lambda: [j for j in self.svc.store.jobs(kind="image")
                                           if j["path"] == "/hot.png" and '"upgrade":true' in j["params"]]))
        # long cold -> demoted back to the ephemeral tier (hysteresis: rate AND idle time)
        self.svc.store._db().execute("UPDATE variant SET score_at=?, last_used=? WHERE key=?",
                                     (time.time() - 90 * 86400, time.time() - 90 * 86400, row["key"]))
        res = self.svc.tier_pass()
        self.assertEqual(res["demoted"], 1, res)
        row2 = self.svc.store.variant(row["key"])
        self.assertEqual(row2["tier"], "ephemeral")
        self.assertFalse(row2["file"].startswith("/static/"))
        self.assertTrue(os.path.exists(self.cache_path(row2["file"])))
        self.assertGreaterEqual(self.metric("image_optimizer_hot_promotions_total"), 1)
        self.assertGreaterEqual(self.metric("image_optimizer_demotions_total"), 1)

    def wait(self, fn, timeout=5.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            v = fn()
            if v:
                return v
            time.sleep(0.05)
        return fn()

    def test_source_mutation_never_serves_stale_variant(self):
        p = os.path.join(self.mnt, "mut.png")
        st, h, _ = self.media_req("/mut.png?_v=avif")
        old = h["x-strata-accel"]
        photo((1200, 700)).rotate(90, expand=True).save(p)            # new content, new size and mtime
        os.utime(p, (time.time() + 5, time.time() + 5))
        st, h, body = self.media_req("/mut.png?_v=avif")
        self.assertEqual(h["x-strata-media"], "miss")
        self.assertNotEqual(h["x-strata-accel"], old)
        with Image.open(self.cache_path(h["x-strata-accel"])) as im:
            self.assertEqual(im.size, (700, 1200))
        stt, h2, _ = self.media_req("/mut.png?_v=avif")
        self.assertEqual(h2["x-strata-accel"], h["x-strata-accel"])

    def test_encoder_failure_serves_original_with_backoff(self):
        boom = imaging.EncodeError("synthetic encoder crash")
        with mock.patch.object(imaging, "encode_auto", side_effect=boom) as enc:
            st, h, _ = self.media_req("/fail.png?_v=avif")
            self.assertEqual((st, h.get("x-strata-orig"), h["x-strata-media"]), (200, "1", "bypass;kind=encode_error"))
            self.assertEqual(h["x-strata-cdn-cache-control"], SHORT)
            st, h, _ = self.media_req("/fail.png?_v=avif")
            self.assertEqual(h["x-strata-media"], "bypass;kind=backoff")   # no second attempt on the hot path
            self.assertEqual(enc.call_count, 1)
        jobs = self.wait(lambda: [j for j in self.svc.store.jobs(kind="image") if j["path"] == "/fail.png"])
        self.assertEqual(json.loads(jobs[0]["params"])["spec"], imaging.auto_spec("avif", None, self.svc.conf()))
        self.assertGreaterEqual(self.metric("image_optimizer_encode_failures_total", kind="encode_error"), 1)
        # once the worker gave up for good, the decision row makes it a cheap, long-cached original
        stt = os.stat(os.path.join(self.mnt, "fail.png"))
        key = self.svc.cache.key(1, "/fail.png", stt.st_size, stt.st_mtime, jobs[0] and json.loads(jobs[0]["params"])["spec"])
        self.svc.store.put_variant(key, mount=1, path="/fail.png", src_size=stt.st_size, src_mtime=stt.st_mtime,
                                   kind="img", fmt="orig", spec="x", file=None, bytes=None, src_bytes=stt.st_size,
                                   secs=0, beneficial=0, reason="failed:encode_error")
        self.svc.failures.clear()
        st, h, _ = self.media_req("/fail.png?_v=avif")
        self.assertEqual((h["x-strata-media"], h["x-strata-cdn-cache-control"]), ("orig;reason=failed:encode_error", EDGE))

    def test_resource_limits(self):
        n = self.metric("image_optimizer_encode_count_total")
        st, h, _ = self.media_req("/bomb.png?_v=avif")                 # 3.6 gigapixels claimed in 100 bytes
        self.assertEqual((st, h.get("x-strata-orig")), (200, "1"))
        self.assertIn(h["x-strata-media"], ("orig;reason=too_large", "bypass;kind=too_large"))
        st, h, _ = self.media_req("/garbage.png?_v=avif")               # not decodable
        self.assertEqual((h.get("x-strata-orig"), h["x-strata-media"]), ("1", "bypass;kind=decode_error"))
        self.write_conf(image={"max_source_bytes": 1000})
        try:
            st, h, _ = self.media_req("/photo.jpg?_v=avif")
            self.assertEqual(h["x-strata-media"], "orig;reason=too_large")
            self.write_conf(image={"max_frames": 2})
            st, h, _ = self.media_req("/anim2.gif?_v=avif")
            self.assertEqual(h["x-strata-media"], "orig;reason=too_many_frames")
            self.write_conf(image={"max_queue_depth": 0, "sync_max_mp": 0.0001})
            st, h, _ = self.media_req("/lim.png?_v=avif")
            self.assertEqual(h["x-strata-media"], "bypass;kind=queue_full")
        finally:
            self.write_conf()
        self.assertEqual(self.metric("image_optimizer_encode_count_total"), n)   # none of this encoded anything

    def test_categories(self):
        """JPEG, PNG with alpha, PNG screenshot, WebP, large, small, already-AVIF, animated, unsupported."""
        got = {}
        for name in ("photo.jpg", "alpha.png", "shot.png", "pic.webp", "big.png", "tiny.png", "pic.avif", "anim.gif"):
            if not os.path.exists(os.path.join(self.mnt, name)):
                continue
            st, h, _ = self.media_req("/%s?_v=avif" % name)
            got[name] = h["x-strata-media"] if "x-strata-orig" in h else h["x-strata-accel"].rsplit(".", 1)[1]
            if "x-strata-accel" in h:
                path = self.cache_path(h["x-strata-accel"])
                self.assertLess(os.path.getsize(path), os.path.getsize(os.path.join(self.mnt, name)) * 0.9, name)
                with Image.open(path) as im, Image.open(os.path.join(self.mnt, name)) as src:
                    self.assertEqual(im.size, src.size, name)
                    if name == "alpha.png":
                        self.assertEqual(im.mode, "RGBA")                 # transparency kept
                        self.assertLess(im.getpixel((5, 5))[3], 30)
                    if name == "anim.gif":
                        self.assertEqual(getattr(im, "n_frames", 1), 5)   # all frames, not just the first
        self.assertEqual(got["tiny.png"], "orig;reason=small")
        if "pic.avif" in got:
            self.assertEqual(got["pic.avif"], "orig;reason=already_avif")
        for name in ("photo.jpg", "alpha.png", "shot.png", "big.png", "pic.webp"):
            self.assertIn(got[name], ("avif", "webp"), name)
        self.assertEqual(got["anim.gif"], "webp")                         # animation -> animated WebP

    def test_not_beneficial_is_declined(self):
        with open(os.path.join(self.mnt, "dense.jpg"), "wb") as f:
            photo((900, 600)).save(f, "JPEG", quality=20)                 # already tiny: AVIF cannot win by 10 %
        with mock.patch.object(imaging, "encode_auto",
                               lambda *a, **k: (b"\0" * int(os.path.getsize(os.path.join(self.mnt, "dense.jpg")) * 0.95),
                                                "avif")):
            st, h, _ = self.media_req("/dense.jpg?_v=avif")
        self.assertEqual((h.get("x-strata-orig"), h["x-strata-media"]), ("1", "orig;reason=not_beneficial"))
        self.assertEqual(h["x-strata-cdn-cache-control"], EDGE)            # deterministic: cache it long
        row = next(r for r in self.rows("/dense.jpg"))
        self.assertEqual((row["beneficial"], row["reason"], row["file"]), (0, "not_beneficial", ""))

    def test_metrics_endpoint_and_savings(self):
        self.media_req("/shot.png?_v=avif")
        st, h, _ = self.media_req("/shot.png?_v=avif")
        self.assertIn("x-strata-accel", h)
        c = http.client.HTTPConnection("127.0.0.1", MEDIA_PORT, timeout=30)
        c.request("GET", "/_metrics")
        r = c.getresponse()
        text = r.read().decode()
        c.close()
        self.assertEqual(r.status, 200)
        for name in ("image_optimizer_requests_total", "image_optimizer_original_bytes_total",
                     "image_optimizer_served_bytes_total", "image_optimizer_bytes_saved_total",
                     "image_optimizer_encode_count_total", "image_optimizer_encode_duration_seconds_bucket",
                     "image_optimizer_cache_hits_total", "image_optimizer_cache_misses_total",
                     "image_optimizer_evictions_total", "image_optimizer_queue_depth", "image_optimizer_cache_bytes"):
            self.assertIn(name, text)
        s = self.svc.optimizer_stats()
        self.assertGreater(s["bytes_saved"], 0)
        self.assertGreater(s["original_bytes"], s["served_bytes"])
        # every byte not served was saved by a variant (originals, HEADs and 304s count on neither side)
        self.assertEqual(s["original_bytes"] - s["served_bytes"], s["bytes_saved"])
        self.svc.flush_hits()
        life = self.svc.store.variant_totals()
        self.assertGreater(life["bytes_saved_served"], 0)


if __name__ == "__main__":
    unittest.main()
