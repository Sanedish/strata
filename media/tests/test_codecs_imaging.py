"""imaging.py: probe, format choice matrix, AVIF/WebP output, metadata scrubbing, cost model, legacy transforms.

Run: python -m unittest discover -s media/tests -t media/tests -p "test_codecs_imaging*.py"
Fixtures are generated into a temp dir. The explicit-transform parity tests load transform/transform.py
read-only (its disk cache is pointed at the temp dir). One calibration test reads a large
real photo named by STRATA_SAMPLE_PHOTO, read-only, and is skipped when that is not set.
"""
import importlib.util
import io
import json
import os
import random
import shutil
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
MEDIA = os.path.dirname(HERE)
STRATA = os.path.dirname(MEDIA)
if MEDIA not in sys.path:
    sys.path.insert(0, MEDIA)
try:
    import pathfix  # noqa: F401  (vendored Pillow first, exactly like media.py / worker.py)
except Exception:
    pass

from PIL import Image, ImageCms, ImageDraw, ImageStat  # noqa: E402

import imaging  # noqa: E402

SAMPLE = os.environ.get("STRATA_SAMPLE_PHOTO", "")
CONF = {"image": dict(imaging.IMAGE_DEFAULTS)}
CONF0 = {"image": dict(imaging.IMAGE_DEFAULTS, min_bytes=0)}   # tiny synthetic fixtures still get encoded
SRGB = ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB")).tobytes()
XMP = (b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
       b'<rdf:Description StrataXmpMarker="1"/></rdf:RDF></x:xmpmeta>')
MARKERS = (b"StrataTestCam", b"StrataXmpMarker", b"x:xmpmeta", b"Exif\x00\x00")


def _load_transform():
    path = os.path.join(STRATA, "transform", "transform.py")
    if not os.path.isfile(path):
        return None
    spec = importlib.util.spec_from_file_location("strata_transform_legacy", path)
    mod = importlib.util.module_from_spec(spec)
    old, sys.dont_write_bytecode = sys.dont_write_bytecode, True   # read-only: no .pyc into transform/
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = old
    return mod


def _exif(orientation=1):
    ex = Image.Exif()
    ex[0x010F] = "StrataTestCam"          # Make
    ex[0x0112] = orientation              # Orientation
    gps = ex.get_ifd(0x8825)              # GPS IFD
    gps[1], gps[2], gps[3], gps[4] = "N", (52.0, 31.0, 12.0), "E", (13.0, 24.0, 0.0)
    return ex


def _photo(w, h, seed=1):
    base = Image.radial_gradient("L").resize((w, h))
    noise = Image.effect_noise((w, h), 40)
    g = Image.linear_gradient("L").resize((w, h))
    return Image.merge("RGB", (Image.blend(base, noise, 0.35), g, Image.blend(noise, g, 0.5)))


def _ui(w, h, mode="RGB"):
    im = Image.new(mode, (w, h), (245, 245, 245) if mode == "RGB" else (245, 245, 245, 255))
    d = ImageDraw.Draw(im)
    for y in range(0, h, 40):
        d.rectangle([20, y + 5, w - 20, y + 30], fill=((y * 7) % 255, 120, 200))
        d.text((30, y + 10), "Strata media %d" % y, fill=(0, 0, 0))
    return im


def _open(data):
    im = Image.open(io.BytesIO(data))
    im.load()
    return im


class Fixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="strata-imaging-")
        j = lambda n: os.path.join(cls.dir, n)  # noqa: E731
        cls.f = {}
        # photo JPEG with EXIF (incl. GPS), XMP, a comment and an ICC profile
        cls.f["jpg"] = j("photo.jpg")
        _photo(640, 480).save(cls.f["jpg"], "JPEG", quality=92, exif=_exif().tobytes(), icc_profile=SRGB, xmp=XMP,
                              comment=b"StrataTestCam comment")
        # EXIF orientation 6 (rotate 90): stored 64x32, displayed 32x64
        cls.f["orient"] = j("orient.jpg")
        _photo(64, 32).save(cls.f["orient"], "JPEG", quality=90, exif=_exif(6).tobytes())
        # lossless UI screenshot with alpha, ICC and EXIF
        cls.f["png"] = j("ui.png")
        ui = _ui(640, 480, "RGBA")
        ui.paste(Image.effect_noise((200, 200), 60).convert("RGBA"), (400, 200))
        ui.putalpha(Image.linear_gradient("L").resize((640, 480)).point(lambda v: 128 + v // 2))
        ui.save(cls.f["png"], "PNG", icc_profile=SRGB, exif=_exif().tobytes())
        # palette image: crisp text on flat colours (the case lossless WebP exists for)
        cls.f["palette"] = j("palette.png")
        pal = _ui(600, 400).quantize(16, dither=Image.Dither.NONE)
        pal.save(cls.f["palette"], "PNG")
        # animated GIF (3 frames, durations 50/120/0 ms, infinite loop) and a static transparent GIF
        cls.f["anim"] = j("anim.gif")
        frames = [Image.new("RGB", (64, 64), c) for c in ((255, 0, 0), (0, 255, 0), (0, 0, 255))]
        for i, fr in enumerate(frames):
            ImageDraw.Draw(fr).rectangle([i * 10, i * 10, i * 10 + 20, i * 10 + 20], fill=(255, 255, 255))
        frames[0].save(cls.f["anim"], "GIF", save_all=True, append_images=frames[1:], duration=[50, 120, 0], loop=0)
        cls.f["gif"] = j("static.gif")
        g = Image.new("P", (200, 120), 0)
        g.putpalette([0, 0, 0, 255, 255, 255, 200, 30, 30] + [0] * (253 * 3))
        ImageDraw.Draw(g).ellipse([20, 10, 180, 110], fill=2)
        g.save(cls.f["gif"], "GIF", transparency=0)
        # modern sources
        cls.f["webp"] = j("src.webp")
        _photo(320, 240).save(cls.f["webp"], "WEBP", quality=80)
        cls.f["webp_ll"] = j("src_ll.webp")
        _ui(320, 240).save(cls.f["webp_ll"], "WEBP", lossless=True)
        cls.f["avif"] = j("src.avif")
        _photo(320, 240).save(cls.f["avif"], "AVIF", quality=60, speed=9, max_threads=1)
        # awkward modes
        cls.f["la"] = j("la.png")
        Image.merge("LA", (Image.linear_gradient("L").resize((200, 100)),
                           Image.new("L", (200, 100), 90))).save(cls.f["la"])
        cls.f["i16"] = j("i16.png")
        Image.linear_gradient("L").resize((300, 200)).convert("I").point(lambda v: v * 257).convert("I;16").save(cls.f["i16"])
        cls.f["cmyk"] = j("cmyk.jpg")
        _photo(200, 150).convert("CMYK").save(cls.f["cmyk"], "JPEG", quality=90)
        cls.f["bw"] = j("bw.png")
        _ui(160, 120).convert("1").save(cls.f["bw"])
        cls.f["garbage"] = j("garbage.png")
        with open(cls.f["garbage"], "wb") as fh:
            fh.write(b"\x89PNG\r\n\x1a\n" + os.urandom(2048))

    @classmethod
    def tearDownClass(cls):
        imaging._bomb_guard(imaging.IMAGE_DEFAULTS)   # transform.py sets its own global limit
        shutil.rmtree(cls.dir, ignore_errors=True)


class TestProbe(Fixtures):
    def test_fixture_metadata_present(self):
        with Image.open(self.f["jpg"]) as im:  # sanity: the source really carries what we must strip
            self.assertEqual(im.getexif().get_ifd(0x8825).get(1), "N")
            self.assertIn("xmp", im.info)
            self.assertEqual(im.info.get("icc_profile"), SRGB)

    def test_probe_fields(self):
        p = imaging.probe(self.f["png"])
        for k in ("format", "mode", "w", "h", "frames", "lossless", "alpha", "mp"):
            self.assertIn(k, p)
        self.assertEqual((p["format"], p["w"], p["h"], p["frames"]), ("PNG", 640, 480, 1))
        self.assertTrue(p["lossless"] and p["alpha"] and p["icc"])
        self.assertAlmostEqual(p["mp"], 0.3072, places=4)
        self.assertEqual(p["bytes"], os.path.getsize(self.f["png"]))
        j = imaging.probe(self.f["jpg"])
        self.assertEqual((j["format"], j["lossless"], j["alpha"]), ("JPEG", False, False))
        self.assertEqual(imaging.probe(self.f["anim"])["frames"], 3)
        self.assertTrue(imaging.probe(self.f["anim"])["animated"])
        self.assertTrue(imaging.probe(self.f["gif"])["alpha"])
        self.assertTrue(imaging.probe(self.f["palette"])["palette_like"])
        self.assertIsNone(imaging.probe(self.f["jpg"])["palette_like"])

    def test_probe_webp_lossless_flag(self):
        self.assertTrue(imaging.probe(self.f["webp_ll"])["lossless"])
        self.assertFalse(imaging.probe(self.f["webp"])["lossless"])
        self.assertFalse(imaging.probe(self.f["avif"])["lossless"])

    def test_probe_garbage_raises_decode_error(self):
        with self.assertRaises(imaging.DecodeError) as cm:
            imaging.probe(self.f["garbage"])
        self.assertEqual(cm.exception.kind, "decode_error")

    def test_palette_like(self):
        self.assertTrue(imaging.palette_like(self.f["palette"]))
        self.assertTrue(imaging.palette_like(self.f["bw"]))
        self.assertFalse(imaging.palette_like(self.f["jpg"]))
        flat = Image.new("RGB", (1200, 900), (250, 250, 250))  # flat UI in RGB mode is still <= 256 colours
        ImageDraw.Draw(flat).rectangle([100, 100, 700, 300], fill=(30, 90, 200), outline=(0, 0, 0), width=3)
        self.assertTrue(imaging.palette_like(flat))


class TestChoose(Fixtures):
    def test_choice_matrix(self):
        ic = CONF["image"]
        j = imaging.choose(imaging.probe(self.f["jpg"]), "avif", CONF)
        self.assertEqual((j.fmt, j.opts["subsampling"], j.opts["quality"], j.reason),
                         ("avif", "4:2:0", ic["avif_quality_lossy"], "lossy"))
        self.assertNotIn("lossless_candidate", j.opts)
        p = imaging.choose(imaging.probe(self.f["png"]), "avif", CONF)
        self.assertEqual((p.fmt, p.opts["subsampling"], p.opts["quality"], p.reason),
                         ("avif", "4:4:4", ic["avif_quality_lossless"], "lossless"))
        w = imaging.choose(imaging.probe(self.f["png"]), "webp", CONF)
        self.assertEqual((w.fmt, w.opts["quality"], w.opts["alpha_quality"]), ("webp", ic["webp_quality"], 100))
        jw = imaging.choose(imaging.probe(self.f["jpg"]), "webp", CONF)
        self.assertEqual((jw.fmt, jw.opts["quality"]), ("webp", ic["webp_quality"]))
        # same format at the same size: never re-encoded; WebP -> AVIF is tried (min_saving decides afterwards)
        for src, want in (("webp", "webp"), ("webp_ll", "webp"), ("avif", "avif"), ("avif", "webp")):
            self.assertEqual(imaging.choose(imaging.probe(self.f[src]), want, CONF).fmt, "orig", (src, want))
        wa = imaging.choose(imaging.probe(self.f["webp"]), "avif", CONF)
        self.assertEqual((wa.fmt, wa.reason, wa.opts["subsampling"]), ("avif", "lossy", "4:2:0"))
        self.assertEqual(imaging.choose(imaging.probe(self.f["webp_ll"]), "avif", CONF).reason, "small")  # 3.4 KB
        wl = imaging.choose(dict(imaging.probe(self.f["webp_ll"]), bytes=50000), "avif", CONF)
        self.assertEqual((wl.fmt, wl.reason, wl.opts["subsampling"]), ("avif", "lossless", "4:4:4"))
        for want in ("avif", "webp"):
            a = imaging.choose(imaging.probe(self.f["anim"]), want, CONF0)
            self.assertEqual((a.fmt, a.animated, a.opts.get("minimize_size"), a.opts["quality"]),
                             ("webp", True, True, ic["webp_quality"]))
        g = imaging.choose(imaging.probe(self.f["gif"]), "avif", CONF0)   # static GIF counts as lossless
        self.assertEqual((g.fmt, g.opts["subsampling"]), ("avif", "4:4:4"))

    def test_palette_candidate_only_small_lossless(self):
        info = {"format": "PNG", "w": 1000, "h": 1000, "mp": 1.0, "frames": 1, "lossless": True, "bytes": 10 ** 6}
        self.assertTrue(imaging.choose(info, "webp", CONF).opts.get("lossless_candidate"))
        self.assertTrue(imaging.choose(info, "avif", CONF).opts.get("lossless_candidate"))
        big = dict(info, w=3000, h=2000, mp=6.0)
        self.assertNotIn("lossless_candidate", imaging.choose(big, "webp", CONF).opts)
        known_not = dict(info, palette_like=False)
        self.assertNotIn("lossless_candidate", imaging.choose(known_not, "webp", CONF).opts)
        jpeg = dict(info, format="JPEG", lossless=False)
        self.assertNotIn("lossless_candidate", imaging.choose(jpeg, "webp", CONF).opts)

    def test_width_is_separate_from_format(self):
        info = {"format": "PNG", "w": 7680, "h": 4320, "mp": 33.2, "frames": 1, "lossless": True, "bytes": 6 * 10 ** 7}
        full = imaging.choose(info, "avif", CONF)
        self.assertNotIn("resize", full.opts)
        r = imaging.choose(info, "avif", CONF, 1080)
        self.assertEqual((r.fmt, r.opts["resize"]), ("avif", [1080, 608]))   # aspect kept
        self.assertNotIn("resize", imaging.choose(info, "avif", CONF, 7680).opts)   # rung >= source: no resize
        self.assertNotIn("resize", imaging.choose(info, "avif", CONF, 9000).opts)   # never upscales
        # a modern source is re-encoded only to resize it
        av = dict(info, format="AVIF", lossless=False)
        self.assertEqual(imaging.choose(av, "avif", CONF).fmt, "orig")
        self.assertEqual(imaging.choose(av, "avif", CONF, 1440).opts["resize"], [1440, 810])
        # animations: total output megapixels are capped (the measured 127-frame 1080p GIF), a rung can fit under it
        gif = {"format": "GIF", "w": 1920, "h": 1080, "mp": 2.07, "frames": 127, "lossless": True,
               "bytes": 15_580_125}
        self.assertEqual(imaging.choose(gif, "avif", CONF).reason, "animation_too_large")
        small = imaging.choose(gif, "avif", CONF, 1080)
        self.assertEqual((small.fmt, small.animated, small.opts["resize"]), ("webp", True, [1080, 608]))
        # a small source that needs no resize stays as it is
        tiny = dict(info, w=800, h=600, mp=0.48, bytes=1000)
        self.assertEqual(imaging.choose(tiny, "avif", CONF, 1080).reason, "small")

    def test_snap_width_and_spec(self):
        snap = lambda w: imaging.snap_width(w, CONF)   # noqa: E731
        self.assertEqual([snap(x) for x in (1, 320, 321, 1000, 1080, 1081, 1920, 3000, 7680, 99999)],
                         [320, 320, 640, 1080, 1080, 1440, 1920, 3840, 7680, 7680])
        for bad in ("0", "-5", "abc", "1e3", "", "1234567"):
            with self.assertRaises(ValueError):
                snap(bad)
        a, b = imaging.auto_spec("avif", 1080, CONF), imaging.auto_spec("avif", None, CONF)
        self.assertNotEqual(a, b)
        self.assertNotEqual(a, imaging.auto_spec("webp", 1080, CONF))
        tweaked = json.loads(json.dumps(CONF))
        tweaked["image"]["avif_quality_lossy"] = 50
        self.assertNotEqual(imaging.auto_spec("avif", 1080, tweaked), a)    # quality is part of the identity
        tweaked = json.loads(json.dumps(CONF))
        tweaked["image"]["speed_sync"] = 4
        self.assertEqual(imaging.auto_spec("avif", 1080, tweaked), a)       # speed is not

    def test_resize_encodes_target_size_and_alpha(self):
        im = Image.new("RGBA", (1600, 900), (255, 0, 0, 0))
        ImageDraw.Draw(im).rectangle([200, 200, 1400, 700], fill=(20, 200, 40, 255))
        buf = io.BytesIO()
        im.save(buf, "PNG")
        path = os.path.join(self.dir, "alpha_resize.png")
        with open(path, "wb") as f:
            f.write(buf.getvalue())
        info = imaging.probe(path)
        plan = imaging.choose(info, "avif", CONF, 640)
        data, fmt = imaging.encode_auto(path, info, plan, CONF)
        out = Image.open(io.BytesIO(data))
        out.load()
        # flat 2-colour art: the lossless WebP candidate may legitimately win - the resize is what matters here
        self.assertIn(fmt, ("avif", "webp"))
        self.assertEqual((out.size, out.mode), ((640, 360), "RGBA"))
        self.assertEqual(out.getpixel((10, 10))[3], 0)            # transparent stays transparent
        r, g, b, a = out.getpixel((320, 180))
        self.assertGreater(a, 240)
        self.assertGreater(g, 150)                                # no dark premultiply fringe in the middle

    def test_orig_reasons(self):
        small = imaging.choose(dict(imaging.probe(self.f["png"]), bytes=100), "avif", CONF)
        self.assertEqual((small.fmt, small.reason), ("orig", "small"))
        huge = {"format": "PNG", "w": 20000, "h": 20000, "mp": 400.0, "frames": 1, "lossless": True, "bytes": 10 ** 8}
        self.assertEqual(imaging.choose(huge, "avif", CONF).reason, "too_large")
        self.assertEqual(imaging.choose({"too_large": True, "mp": 900}, "avif", CONF).fmt, "orig")
        wide = {"format": "PNG", "w": 20000, "h": 500, "mp": 10.0, "frames": 1, "lossless": True, "bytes": 10 ** 7}
        self.assertEqual(imaging.choose(wide, "avif", CONF).fmt, "avif")       # AVIF takes 20000 px wide
        self.assertEqual(imaging.choose(wide, "webp", CONF).reason, "too_large")  # WebP stops at 16383
        with self.assertRaises(ValueError):
            imaging.choose(huge, "jxl", CONF)

    def test_plan_is_json_friendly(self):
        p = imaging.choose(imaging.probe(self.f["png"]), "avif", CONF)
        self.assertEqual(p.as_dict()["fmt"], "avif")
        self.assertEqual(p, imaging.Plan(*p))
        self.assertEqual(imaging.Plan.from_dict(json.loads(json.dumps(p.as_dict()))), p)


class TestEncodeAuto(Fixtures):
    def _auto(self, key, want, conf=CONF0, **kw):
        info = imaging.probe(self.f[key])
        plan = imaging.choose(info, want, conf)
        data, fmt = imaging.encode_auto(self.f[key], info, plan, conf, **kw)
        return info, plan, data, fmt, _open(data)

    def test_outputs_decode(self):
        for key in ("jpg", "png", "palette", "gif", "la", "i16", "cmyk", "bw"):
            for want in ("avif", "webp"):
                info, plan, data, fmt, out = self._auto(key, want)
                self.assertEqual(out.format, fmt.upper(), (key, want))
                self.assertEqual(out.size, (info["w"], info["h"]), (key, want))
                self.assertIn(fmt, imaging.CONTENT_TYPE)

    def test_alpha_kept_and_opaque_alpha_dropped(self):
        _, _, _, _, out = self._auto("png", "avif")
        self.assertEqual(out.mode, "RGBA")
        _, _, _, _, out = self._auto("gif", "webp")
        self.assertEqual(out.mode, "RGBA")
        self.assertEqual(out.getpixel((0, 0))[3], 0)       # transparent GIF background stays transparent
        _, _, _, _, out = self._auto("jpg", "webp")
        self.assertEqual(out.mode, "RGB")

    def test_16bit_scaled_not_clipped(self):
        _, _, _, _, out = self._auto("i16", "avif")
        mean = ImageStat.Stat(out.convert("L")).mean[0]
        self.assertTrue(90 < mean < 170, mean)             # a plain convert() would clip to ~255

    def test_icc_preserved(self):
        for key in ("jpg", "png"):
            for want in ("avif", "webp"):
                *_, out = self._auto(key, want)
                self.assertEqual(out.info.get("icc_profile"), SRGB, (key, want))

    def test_exif_gps_xmp_absent(self):
        for key in ("jpg", "png"):
            for want in ("avif", "webp"):
                _, _, data, _, out = self._auto(key, want)
                self.assertFalse(out.info.get("exif"), (key, want))
                self.assertFalse(out.info.get("xmp"), (key, want))
                self.assertEqual(len(out.getexif()), 0, (key, want))
                for m in MARKERS:
                    self.assertNotIn(m, data, (key, want, m))

    def test_exif_orientation_applied(self):
        _, _, _, _, out = self._auto("orient", "avif")
        self.assertEqual(out.size, (32, 64))

    def test_animated_gif_to_animated_webp(self):
        info, plan, data, fmt, out = self._auto("anim", "avif")
        self.assertEqual((fmt, plan.animated), ("webp", True))
        self.assertEqual(out.n_frames, 3)
        durations = []
        for i in range(out.n_frames):
            out.seek(i)
            out.load()                                      # the WebP reader sets duration on load
            durations.append(out.info.get("duration"))
        self.assertEqual(durations, [50, 120, 100])        # 0 ms frames are shown for 100 ms, like browsers do
        self.assertEqual(out.info.get("loop"), 0)
        out.seek(1)
        r, g, b = out.convert("RGB").getpixel((50, 50))[:3]    # lossy: close to pure green, not exact
        self.assertTrue(r < 12 and g > 240 and b < 12, (r, g, b))
        self.assertEqual(imaging.last_timing()["candidates"][0]["kind"], "animated")

    def test_apng_tiff_pages_mpo(self):
        apng = os.path.join(self.dir, "anim.png")
        frames = [Image.new("RGBA", (48, 48), c) for c in ((255, 0, 0, 255), (0, 0, 255, 128))]
        frames[0].save(apng, "PNG", save_all=True, append_images=frames[1:], duration=[80, 160], loop=2)
        info = imaging.probe(apng)
        self.assertEqual((info["frames"], info["animated"]), (2, True))
        plan = imaging.choose(info, "avif", CONF0)
        data, fmt = imaging.encode_auto(apng, info, plan, CONF0)
        out = _open(data)
        self.assertEqual((fmt, out.n_frames, out.info.get("loop")), ("webp", 2, 2))
        tif = os.path.join(self.dir, "pages.tif")
        _photo(120, 80).save(tif, "TIFF", save_all=True, append_images=[_photo(120, 80, 2)])
        t = imaging.probe(tif)
        self.assertEqual((t["format"], t["frames"], t["lossless"]), ("TIFF", 1, True))  # pages are not an animation
        self.assertEqual(imaging.choose(t, "avif", CONF0).opts["subsampling"], "4:4:4")
        mpo = os.path.join(self.dir, "camera.jpg")
        _photo(160, 120).save(mpo, "MPO", save_all=True, append_images=[_photo(160, 120)], quality=90)
        m = imaging.probe(mpo)
        self.assertEqual((m["format"], m["frames"], m["lossless"]), ("MPO", 1, False))
        self.assertEqual(imaging.choose(m, "avif", CONF0).opts["subsampling"], "4:2:0")
        self.assertEqual(imaging.encode_explicit(mpo, {"w": "80"}, CONF)[1], "jpeg")   # transform.py said png

    def test_palette_lossless_pick(self):
        info, plan, data, fmt, out = self._auto("palette", "webp")
        t = imaging.last_timing()
        kinds = {c["kind"]: c["bytes"] for c in t["candidates"]}
        self.assertEqual(set(kinds), {"lossy", "lossless"})
        self.assertEqual(len(data), min(kinds.values()))
        self.assertEqual(t["chosen"], "lossless")          # crisp text on flat colours: lossless is smaller
        self.assertIn(b"VP8L", data[:64])
        self.assertEqual(out.convert("RGB").tobytes(), Image.open(self.f["palette"]).convert("RGB").tobytes())
        # with an AVIF plan both are tried and the smaller wins, whichever format that is
        info, plan, data, fmt, out = self._auto("palette", "avif")
        t = imaging.last_timing()
        self.assertEqual(len(t["candidates"]), 2)
        self.assertEqual(len(data), min(c["bytes"] for c in t["candidates"]))
        self.assertEqual(fmt, "webp" if t["chosen"] == "lossless" else "avif")

    def test_no_palette_try_for_photos(self):
        self._auto("jpg", "webp")
        self.assertEqual([c["kind"] for c in imaging.last_timing()["candidates"]], ["lossy"])

    def test_model_fed_with_encode_seconds(self):
        m = imaging.CostModel()
        self._auto("jpg", "avif", model=m)
        self.assertEqual(m.samples.get("avif:%d" % CONF["image"]["speed_sync"]), 1)
        self._auto("png", "webp", conf=dict(CONF0), model=m, sync=False)
        self.assertEqual(m.samples.get("webp:5"), 1)

    def test_orig_plan_rejected(self):
        with self.assertRaises(ValueError):
            imaging.encode_auto(self.f["webp"], {}, imaging.Plan("orig"), CONF)

    def test_decode_error_kind(self):
        plan = imaging.Plan("avif", {"quality": 60, "subsampling": "4:2:0"})
        with self.assertRaises(imaging.DecodeError) as cm:
            imaging.encode_auto(self.f["garbage"], {}, plan, CONF)
        self.assertEqual(cm.exception.kind, "decode_error")

    def test_bomb_guard_limits(self):
        conf = {"image": dict(imaging.IMAGE_DEFAULTS, max_mp=0.1, bg_max_mp=0.5, min_bytes=0)}
        info = imaging.probe(self.f["png"])            # 0.31 MP
        plan = imaging.choose(info, "webp", conf)
        with self.assertRaises(imaging.TooLarge) as cm:
            imaging.encode_auto(self.f["png"], info, plan, conf, sync=True)
        self.assertEqual(cm.exception.kind, "too_large")
        with self.assertRaises(imaging.TooLarge):    # worker, but < 3 GB RAM free -> hot-path limit
            imaging.encode_auto(self.f["png"], info, plan, conf, sync=False, mem_avail_mb=1000)
        data, fmt = imaging.encode_auto(self.f["png"], info, plan, conf, sync=False, mem_avail_mb=6000)
        self.assertEqual(_open(data).size, (640, 480))
        # a lying info dict does not help: the real header is checked before decoding
        with self.assertRaises(imaging.TooLarge):
            imaging.encode_auto(self.f["png"], dict(info, mp=0.01), plan, conf, sync=True)
        self.assertEqual(imaging.mp_limit(CONF, True), 150)
        self.assertEqual(imaging.mp_limit(CONF, False), 280)
        # memory-aware: never more than the available RAM can hold (45 MB/MP measured, 768 MB kept back)
        self.assertAlmostEqual(imaging.mp_limit(CONF, False, mem_avail_mb=2000), (2000 - 768) / 45.0)
        self.assertAlmostEqual(imaging.mp_limit(CONF, True, mem_avail_mb=3000), (3000 - 768) / 45.0)
        self.assertEqual(imaging.mp_limit(CONF, False, mem_avail_mb=16000), 280)
        self.assertEqual(imaging.mp_limit(CONF, True, mem_avail_mb=500), imaging.MIN_MEM_MP)
        # Pillow's global backstop follows the larger configured limit (here the tiny test values) ...
        self.assertEqual(Image.MAX_IMAGE_PIXELS, int(0.5e6))
        imaging.probe(self.f["png"], CONF)                   # ... and the real config restores it
        self.assertEqual(Image.MAX_IMAGE_PIXELS, int(280e6))


class TestHelpers(unittest.TestCase):
    def test_beneficial(self):
        self.assertFalse(imaging.beneficial(1000, 950, CONF))
        self.assertTrue(imaging.beneficial(1000, 900, CONF))     # exactly 10 % smaller is "at least 10 %"
        self.assertTrue(imaging.beneficial(1000, 100, CONF))
        self.assertFalse(imaging.beneficial(1000, 1200, CONF))
        self.assertFalse(imaging.beneficial(0, 0, CONF))
        self.assertFalse(imaging.beneficial(1000, 850, {"image": {"min_saving": 0.2}}))

    def test_speed_for(self):
        # measured 2026-10-03: speed 8 on the hot path (latency), 6 in the background (bytes)
        self.assertEqual(imaging.speed_for("avif", CONF, True), 8)
        self.assertEqual(imaging.speed_for("avif", CONF, False), 6)
        self.assertEqual((imaging.speed_for("webp", CONF, True), imaging.speed_for("webp", CONF, False)), (4, 5))

    def test_image_conf_accepts_shapes(self):
        self.assertEqual(imaging.image_conf(None)["max_mp"], 150)
        self.assertEqual(imaging.image_conf({"image": {"max_mp": 9}})["max_mp"], 9)
        self.assertEqual(imaging.image_conf({"max_mp": 8})["max_mp"], 8)


class TestCostModel(unittest.TestCase):
    INFO = {"format": "PNG", "w": 2000, "h": 2000, "mp": 4.0, "frames": 1, "lossless": True, "palette_like": False}

    def test_monotonic(self):
        m = imaging.CostModel()
        est = lambda mp, **kw: m.estimate(dict(self.INFO, mp=mp), kw.get("fmt", "avif"), kw.get("speed", 7),  # noqa
                                          kw.get("src", 1 << 20))
        seq = [est(mp) for mp in (0.5, 1, 2, 4, 8, 16, 33)]
        self.assertEqual(seq, sorted(seq))
        self.assertLess(est(4, src=1 << 20), est(4, src=100 << 20))           # NAS read counts
        self.assertAlmostEqual(est(4, src=80_000_000) - est(4, src=0), 1.0, places=2)
        self.assertGreater(est(4, speed=5), est(4, speed=6))
        self.assertGreater(est(4, speed=6), est(4, speed=7))
        self.assertGreater(est(4, speed=7), est(4, speed=8))
        self.assertGreater(est(4, speed=3), est(4, speed=4))                   # extrapolated below the seeds
        self.assertGreater(est(4, speed=5) / est(4, speed=7), 5)               # speed 5 is ~10x slower here
        self.assertGreaterEqual(est(4, fmt="webp", speed=5), est(4, fmt="webp", speed=4))
        self.assertEqual(est(4, fmt="webp", speed=7), est(4, fmt="webp", speed=4))   # AVIF-style speed -> m4
        self.assertEqual(m.estimate(self.INFO, "orig", 7, 0), 0.0)

    def test_animation_and_palette_cost(self):
        m = imaging.CostModel()
        one = m.estimate(dict(self.INFO, format="GIF", mp=0.25), "webp", 4, 0)
        many = m.estimate(dict(self.INFO, format="GIF", mp=0.25, frames=40), "webp", 4, 0)
        self.assertGreater(many, one * 20)
        pal = m.estimate(dict(self.INFO, palette_like=None), "avif", 7, 0)
        self.assertGreater(pal, m.estimate(self.INFO, "avif", 7, 0))           # lossless WebP candidate counted
        jpeg = dict(self.INFO, format="JPEG", lossless=False)
        self.assertLess(m.estimate(jpeg, "avif", 7, 0), m.estimate(self.INFO, "avif", 7, 0))  # cheaper decode

    def test_observe_ewma_and_clamp(self):
        m = imaging.CostModel()
        r0 = m.rate("avif", 7)
        m.observe("avif", 7, 4.0, 4.0 * r0 * 2 + m.OVERHEAD_S)
        r1 = m.rate("avif", 7)
        self.assertAlmostEqual(r1, r0 + m.ALPHA * r0, places=6)
        for _ in range(40):
            m.observe("avif", 7, 4.0, 4.0 * 0.1 + m.OVERHEAD_S)
        self.assertAlmostEqual(m.rate("avif", 7), 0.1, places=3)                # converges to the measurements
        m.observe("avif", 7, 4.0, 10_000)                                         # absurd outlier: clamped to 5x
        self.assertLessEqual(m.rate("avif", 7), 0.1 + m.ALPHA * 0.4 + 1e-5)
        m.observe("avif", 7, 0, 1.0)                                              # ignored
        m.observe("avif", 7, 4, 0)
        m2 = imaging.CostModel.from_dict(m.to_dict())
        self.assertAlmostEqual(m2.rate("avif", 7), m.rate("avif", 7), places=4)
        self.assertEqual(m2.samples["avif:7"], m.samples["avif:7"])
        self.assertEqual(imaging.CostModel().rate("jxl", 7), 1.0)                # unknown format: pessimistic


class TestExplicit(Fixtures):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.tf = _load_transform()
        cls.cache = tempfile.mkdtemp(prefix="strata-tfcache-")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.cache, ignore_errors=True)
        super().tearDownClass()

    CASES = [("jpg", {"w": "100"}), ("jpg", {"w": "100", "h": "100", "fit": "cover"}),
             ("png", {"w": "300", "h": "200", "fit": "cover"}), ("png", {"w": "300", "h": "300", "fit": "contain", "fm": "webp"}),
             ("jpg", {"w": "300", "h": "300", "fit": "contain"}), ("png", {"w": "900", "h": "100", "fit": "fill", "fm": "avif"}),
             ("gif", {"h": "50"}), ("orient", {"w": "16"}), ("png", {"w": "2000"}), ("jpg", {"fm": "jpg", "q": "50"}),
             ("png", {"w": "0", "fm": "png"}), ("palette", {"w": "123", "h": "77", "fit": "inside", "fm": "jpeg"}),
             ("webp", {"h": "60"}), ("avif", {"w": "50", "fm": "webp"}), ("la", {"w": "33", "fm": "jpeg"}),
             ("png", {"h": "479", "fit": "cover"})]

    @unittest.skipUnless(os.path.isfile(os.path.join(STRATA, "transform", "transform.py")), "transform.py missing")
    def test_parity_with_transform_py(self):
        for key, params in self.CASES:
            src = self.f[key]
            tdata, tctype, _ = self.tf.transform(src, os.stat(src), dict(params), {"cache_dir": self.cache, "max_dim": 4096})
            data, fmt = imaging.encode_explicit(src, dict(params), CONF)
            self.assertEqual(imaging.CONTENT_TYPE[fmt], tctype, (key, params))
            self.assertEqual(_open(data).size, _open(tdata).size, (key, params))
            self.assertEqual(_open(data).format, fmt.upper(), (key, params))

    @unittest.skipUnless(os.path.isfile(os.path.join(STRATA, "transform", "transform.py")), "transform.py missing")
    def test_invalid_params_same_messages(self):
        bad = [{"w": "5000"}, {"h": "4097"}, {"w": "-5"}, {"fit": "stretch"}, {"q": "0"}, {"q": "101"},
               {"fm": "gif"}, {"fm": "heic", "w": "10"}, {"w": "10", "fit": "crop"}]
        for params in bad:
            with self.assertRaises(ValueError) as mine:
                imaging.validate_explicit(params, CONF)
            with self.assertRaises(ValueError) as theirs:
                self.tf.transform(self.f["png"], os.stat(self.f["png"]), dict(params), {"cache_dir": self.cache})
            self.assertEqual(str(mine.exception), str(theirs.exception), params)
            with self.assertRaises(ValueError):
                imaging.encode_explicit(self.f["png"], params, CONF)

    def test_invalid_non_numeric(self):
        for params, msg in (({"w": "abc"}, "w/h must be 1-4096"), ({"h": "1.5"}, "w/h must be 1-4096"),
                            ({"w": "\uff15"}, "w/h must be 1-4096"), ({"q": "high"}, "q must be 1-100"),
                            ({"w": "99999999999"}, "w/h must be 1-4096")):
            with self.assertRaises(ValueError) as cm:
                imaging.validate_explicit(params, CONF)
            self.assertEqual(str(cm.exception), msg)
        self.assertIn("1-512", str(self._raises({"w": "600"}, {"image": {"max_dim": 512}})))

    def _raises(self, params, conf):
        try:
            imaging.validate_explicit(params, conf)
        except ValueError as e:
            return e
        self.fail("no ValueError")

    def test_validate_normalises(self):
        v = imaging.validate_explicit({"w": " 120 ", "fm": "JPG"}, CONF)
        self.assertEqual(v, {"w": 120, "h": None, "fit": "inside", "q": 82, "fm": "jpg"})
        self.assertEqual(imaging.validate_explicit({"w": "0", "h": ""}, CONF)["w"], None)

    def test_explicit_strips_metadata_keeps_icc(self):
        for fm in ("jpeg", "png", "webp", "avif"):
            data, fmt = imaging.encode_explicit(self.f["jpg"], {"w": "200", "fm": fm}, CONF)
            out = _open(data)
            self.assertEqual(fmt, fm)
            self.assertEqual(out.info.get("icc_profile"), SRGB, fm)
            self.assertFalse(out.info.get("exif"), fm)
            self.assertFalse(out.info.get("xmp"), fm)
            for m in MARKERS:
                self.assertNotIn(m, data, (fm, m))

    def test_contain_jpeg_pads_white(self):
        data, fmt = imaging.encode_explicit(self.f["la"], {"w": "300", "h": "300", "fit": "contain", "fm": "jpeg"}, CONF)
        out = _open(data).convert("RGB")
        self.assertEqual(out.size, (300, 300))
        self.assertGreater(min(out.getpixel((150, 5))), 240)   # padding is white

    def test_explicit_errors(self):
        with self.assertRaises(imaging.DecodeError):
            imaging.encode_explicit(self.f["garbage"], {"w": "10"}, CONF)
        with self.assertRaises(imaging.TooLarge):
            imaging.encode_explicit(self.f["png"], {"w": "10"}, {"image": {"max_mp": 0.1}})


@unittest.skipIf(os.environ.get("STRATA_MEDIA_NO_NAS"), "STRATA_MEDIA_NO_NAS set")
@unittest.skipUnless(os.path.exists(SAMPLE), "set STRATA_SAMPLE_PHOTO to a large photo")
class TestCalibration(unittest.TestCase):
    """The user's example (29 MB, 4320x7680 PNG) on the hot-path settings; read-only, one encode."""

    def test_sample_photo(self):
        info = imaging.probe(SAMPLE)
        self.assertEqual((info["format"], info["w"], info["h"]), ("PNG", 4320, 7680))
        plan = imaging.choose(info, "avif", CONF)
        self.assertEqual((plan.fmt, plan.opts["subsampling"]), ("avif", "4:4:4"))
        m = imaging.CostModel()
        est = m.estimate(info, "avif", imaging.speed_for("avif", CONF, True), info["bytes"])
        t = time.perf_counter()
        data, fmt = imaging.encode_auto(SAMPLE, info, plan, CONF, model=m)
        wall = time.perf_counter() - t
        with Image.open(io.BytesIO(data)) as out:
            self.assertEqual((out.format, out.size), ("AVIF", (4320, 7680)))
        self.assertTrue(imaging.beneficial(info["bytes"], len(data), CONF))
        self.assertLess(len(data), info["bytes"] * 0.02)
        ratio = est / wall
        self.assertTrue(0.3 < ratio < 4, "estimate %.1f s vs measured %.1f s" % (est, wall))
        print("\n  photo.png: %d -> %d bytes (%.2f %%), wall %.1f s, seed estimate %.1f s, learned %.3f s/MP"
              % (info["bytes"], len(data), 100.0 * len(data) / info["bytes"], wall, est, m.rate("avif", 7)))


if __name__ == "__main__":
    unittest.main()
