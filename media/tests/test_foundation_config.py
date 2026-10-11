"""config.py: defaults parity with core.DEFAULTS["media"], load/merge/cache, categories, resolve(), birth_time()."""
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import time
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
MEDIA = os.path.dirname(HERE)
if MEDIA not in sys.path:
    sys.path.insert(0, MEDIA)

import config  # noqa: E402


def _import_strata(name):
    """Import a Strata module (core / compress) read-only: they only read strata.json at import."""
    root = config.STRATA_ROOT
    added = root not in sys.path
    if added:
        sys.path.append(root)
    try:
        return __import__(name)
    finally:
        if added and root in sys.path:
            sys.path.remove(root)


class DefaultsTest(unittest.TestCase):
    def test_media_block_is_a_literal_copy_of_core(self):
        core = _import_strata("core")
        self.assertEqual(config.MEDIA, core.DEFAULTS["media"])

    def test_defaults_have_every_core_key_plus_runtime_keys(self):
        core = _import_strata("core")
        for k, v in core.DEFAULTS["media"].items():
            self.assertIn(k, config.DEFAULTS)
            if k not in config.RUNTIME:
                self.assertEqual(config.DEFAULTS[k], v, k)
        for k in ("listen", "sign_secret", "admin_token", "db", "cache_root", "event_log", "negotiation",
                  "cutover", "mounts"):
            self.assertIn(k, config.DEFAULTS)
        self.assertEqual(config.DEFAULTS["listen"], core.DEFAULTS["media"]["listen"])   # 8084 (DESIGN 4.2)
        self.assertNotIn(config.DEFAULTS["listen"].rsplit(":", 1)[1], ("8080", "8081", "8082", "8083", "8090"))
        self.assertEqual(config.DEFAULTS["negotiation"], "redirect")
        self.assertEqual(config.DEFAULTS["mounts"], {})
        self.assertTrue(os.path.isabs(config.DEFAULTS["db"]))
        self.assertTrue(config.DEFAULTS["db"].endswith("media.db"))

    def test_defaults_are_not_shared_with_media_block(self):
        self.assertIsNot(config.DEFAULTS["breaker"], config.MEDIA["breaker"])


class LoadTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "media.json")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, obj, raw=None):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(raw if raw is not None else json.dumps(obj))
        os.replace(tmp, self.path)

    def test_missing_file_gives_defaults(self):
        conf = config.load(self.path)
        self.assertEqual(conf["breaker"], config.DEFAULTS["breaker"])
        self.assertEqual(conf["negotiation"], "redirect")
        self.assertEqual(conf["mounts"], {})

    def test_deep_merge_and_normalisation(self):
        self.write({"breaker": {"slots": 3}, "negotiation": "edge", "db": "data/other.db",
                    "mounts": {1: {"path": "//nas/share", "prefix": "/", "hosts": ["a"], "cache": "x"}},
                    "file_policy": {"deny_ext": ["env"]}})
        conf = config.load(self.path)
        self.assertEqual(conf["breaker"]["slots"], 3)
        self.assertEqual(conf["breaker"]["cpu_trip"], 85)              # untouched siblings survive
        self.assertEqual(conf["negotiation"], "edge")
        self.assertEqual(conf["file_policy"]["deny_ext"], ["env"])     # lists replace, not merge
        self.assertEqual(conf["file_policy"]["safe_names"], config.MEDIA["file_policy"]["safe_names"])
        self.assertEqual(conf["db"], os.path.normpath(os.path.join(config.STRATA_ROOT, "data", "other.db")))
        self.assertIn("1", conf["mounts"])
        self.assertEqual(config.mount(conf, 1)["path"], "//nas/share")
        self.assertEqual(config.mount(conf, " 1 ")["path"], "//nas/share")
        self.assertIsNone(config.mount(conf, 2))
        self.assertEqual(config.DEFAULTS["breaker"]["slots"], 2)        # DEFAULTS never mutated

    def test_cached_until_the_file_changes(self):
        self.write({"breaker": {"slots": 3}})
        a = config.load(self.path)
        self.assertIs(config.load(self.path), a)
        self.write({"breaker": {"slots": 4}, "cutover": 123})           # different size -> reload
        b = config.load(self.path)
        self.assertIsNot(b, a)
        self.assertEqual(b["breaker"]["slots"], 4)

    def test_broken_file_keeps_last_good(self):
        self.write({"breaker": {"slots": 5}})
        self.assertEqual(config.load(self.path)["breaker"]["slots"], 5)
        self.write(None, raw='{"breaker": {"slots": ')
        self.assertEqual(config.load(self.path)["breaker"]["slots"], 5)

    def test_broken_file_without_history_gives_defaults(self):
        self.write(None, raw="[1, 2")
        self.assertEqual(config.load(self.path)["breaker"]["slots"], 2)

    def test_env_override(self):
        self.write({"listen": "127.0.0.1:18083"})
        old = os.environ.get("STRATA_MEDIA_CONFIG")
        os.environ["STRATA_MEDIA_CONFIG"] = self.path
        try:
            spec = importlib.util.spec_from_file_location("config_env_copy", os.path.join(MEDIA, "config.py"))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
        finally:
            if old is None:
                os.environ.pop("STRATA_MEDIA_CONFIG", None)
            else:
                os.environ["STRATA_MEDIA_CONFIG"] = old
        self.assertEqual(mod.CONF_PATH, self.path)
        self.assertEqual(mod.load()["listen"], "127.0.0.1:18083")


class CategoryTest(unittest.TestCase):
    def test_ext_of(self):
        self.assertEqual(config.ext_of("a/b/Photo.PNG"), "png")
        self.assertEqual(config.ext_of("x.tar.gz"), "gz")
        self.assertEqual(config.ext_of(".env"), "")
        self.assertEqual(config.ext_of("dir.v2/README"), "")
        self.assertEqual(config.ext_of("file."), "")
        self.assertEqual(config.ext_of(r"C:\x\y.PDF"), "pdf")
        self.assertEqual(config.ext_of(""), "")

    def test_categories(self):
        cases = {"a.PNG": "image", "b.jfif": "image", "c.svg": "svg", "d.pdf": "pdf", "e.tar.gz": "archive",
                 "f.mrpack": "archive", "g.docx": "document", "h.rtf": "document", "i.webmanifest": "text",
                 "j.yml": "text", "k.PS1": "exec", "l.appimage": "exec", "m.webm": "video", "n.m3u8": "video",
                 "o.opus": "audio", "p.woff2": "font", "q.blend1": "3d", "r.xyz": "other", ".env": "other",
                 "LICENSE": "other"}
        for name, cat in cases.items():
            self.assertEqual(config.category(name), cat, name)

    def test_every_extension_has_exactly_one_category(self):
        seen = {}
        for cat, exts in config.CATEGORIES.items():
            for e in exts.split():
                self.assertNotIn(e, seen, "%s in %s and %s" % (e, seen.get(e), cat))
                seen[e] = cat

    def test_extension_sets(self):
        self.assertIn("png", config.NEGOTIABLE)
        self.assertIn("webp", config.NEGOTIABLE)        # measured: lossy WebP -> AVIF often 80 % smaller
        self.assertNotIn("avif", config.NEGOTIABLE)     # never re-encoded at its own size
        self.assertTrue(config.NEGOTIABLE < config.TRANSFORMABLE)
        self.assertIn("avif", config.TRANSFORMABLE)
        self.assertIn("mov", config.VIDEO_EXT)
        self.assertNotIn("webm", config.VIDEO_EXT)
        self.assertEqual(set(config.NEGOTIABLE), set("png jpg jpeg jfif gif bmp tif tiff webp".split()))

    def test_gated(self):
        conf = config.DEFAULTS
        for name in ("a.png", "b.svg", "c.pdf", "d.zip", "e.docx", "f.txt", "g.exe"):
            self.assertTrue(config.gated(name, conf), name)
        for name in ("a.mp4", "b.mp3", "c.woff2", "d.glb", "e.xyz"):
            self.assertFalse(config.gated(name, conf), name)
        off = {"gate": dict(conf["gate"], enabled=False)}
        self.assertFalse(config.gated("a.png", off))


class ResolveTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.root = os.path.normpath(self.tmp)
        self.mount = {"path": self.tmp, "prefix": "/"}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_plain_paths(self):
        full, rel = config.resolve(self.mount, "/general/photo.png")
        self.assertEqual(rel, "/general/photo.png")
        self.assertEqual(full, os.path.join(self.root, "general", "photo.png"))
        full, rel = config.resolve(self.mount, "/a%20b//c%2Epng")
        self.assertEqual(rel, "/a b/c.png")
        full, rel = config.resolve(self.mount, "/")
        self.assertEqual((full, rel), (self.root, "/"))
        full, rel = config.resolve(self.mount, "/%E2%9C%93/%C3%BC.png")
        self.assertEqual(rel, "/\u2713/\u00fc.png")

    def test_rejects_traversal_and_windows_tricks(self):
        bad = ["/../x.png", "/a/../../x.png", "/%2e%2e/x.png", "/..%2fx.png", "/a/%2e%2e%5c..%5cx.png",
               "/a\\..\\x.png", "/.env", "/a/.git/config", "/.well-known/x", "/C:/Windows/win.ini",
               "/a/b.png::$DATA", "/a/b.png:stream", "/a/CON", "/a/con.txt", "/a/Com1.png", "/a/LPT9", "/a/nul .png",
               "/a/b.png.", "/a/b.png ", "/a/%00b.png", "/a/b%3F.png", "/a/b*.png", "/a/b%3C.png", "/a/b%7C.png",
               "/a/%01.png", "/a/%ff.png", "relative.png", "", "/a/.", "/a/..", "/a/b/...png."]
        for p in bad:
            self.assertEqual(config.resolve(self.mount, p), (None, None), p)

    def test_allowed_lookalikes(self):
        for p in ("/a/b..png", "/a/console.png", "/a/COM10.png", "/a/con-fig.png", "/a/b.c.d.png", "/a/~b.png"):
            full, rel = config.resolve(self.mount, p)
            self.assertIsNotNone(full, p)

    def test_prefix(self):
        for prefix in ("/disk2", "/disk2/", "disk2"):
            m = {"path": self.tmp, "prefix": prefix}
            full, rel = config.resolve(m, "/disk2/a/b.png")
            self.assertEqual(rel, "/a/b.png", prefix)
            self.assertEqual(full, os.path.join(self.root, "a", "b.png"))
            self.assertEqual(config.resolve(m, "/disk2"), (self.root, "/"))
            self.assertEqual(config.resolve(m, "/disk2X/a.png"), (None, None))
            self.assertEqual(config.resolve(m, "/other/a.png"), (None, None))
            self.assertEqual(config.resolve(m, "/a.png"), (None, None))
            self.assertEqual(config.resolve(m, "/disk2/../a.png"), (None, None))

    def test_unc_root(self):
        m = {"path": "//192.168.1.55/data2/storage", "prefix": "/"}
        full, rel = config.resolve(m, "/general/photo.png")
        self.assertEqual(rel, "/general/photo.png")
        self.assertEqual(os.path.normcase(full),
                         os.path.normcase(os.path.join(os.path.normpath("//192.168.1.55/data2/storage"),
                                                       "general", "photo.png")))

    def test_bad_mounts(self):
        self.assertEqual(config.resolve(None, "/a.png"), (None, None))
        self.assertEqual(config.resolve({}, "/a.png"), (None, None))
        self.assertEqual(config.resolve({"path": ""}, "/a.png"), (None, None))
        self.assertEqual(config.resolve(self.mount, None), (None, None))


class FileFactsTest(unittest.TestCase):
    def test_birth_time(self):
        st = types.SimpleNamespace(st_mtime=100.0, st_birthtime=200.0, st_ctime=50.0)
        self.assertEqual(config.birth_time(st), 200.0)              # copied today: new
        st = types.SimpleNamespace(st_mtime=300.0, st_birthtime=200.0, st_ctime=50.0)
        self.assertEqual(config.birth_time(st), 300.0)              # overwritten: new
        st = types.SimpleNamespace(st_mtime=100.0, st_ctime=150.0)
        self.assertEqual(config.birth_time(st), 150.0)              # no st_birthtime: st_ctime
        st = types.SimpleNamespace(st_mtime=100.0, st_birthtime=0, st_ctime=120.0)
        self.assertEqual(config.birth_time(st), 120.0)

    def test_birth_time_real_file(self):
        fd, p = tempfile.mkstemp()
        os.close(fd)
        try:
            os.utime(p, (1000000000, 1000000000))                   # an "old" mtime on a file created now
            st = os.stat(p)
            self.assertGreater(config.birth_time(st), time.time() - 3600)
        finally:
            os.remove(p)

    def test_quick_hash(self):
        tmp = tempfile.mkdtemp()
        try:
            small, big = os.path.join(tmp, "s.bin"), os.path.join(tmp, "b.bin")
            with open(small, "wb") as f:
                f.write(b"abc" * 100)
            data = bytes(range(256)) * 1024 + b"tail"
            with open(big, "wb") as f:
                f.write(data)
            h = hashlib.sha1(str(300).encode())
            h.update(b"abc" * 100)
            self.assertEqual(config.quick_hash(small, 300), h.hexdigest())
            h = hashlib.sha1(str(len(data)).encode())
            h.update(data[:65536])
            h.update(data[-65536:])
            self.assertEqual(config.quick_hash(big, len(data)), h.hexdigest())
            try:
                compress = _import_strata("compress")
            except Exception as e:  # pragma: no cover - only if Strata itself cannot be imported here
                self.skipTest("compress not importable: %s" % e)
            self.assertEqual(config.quick_hash(big, len(data)), compress.quick_hash(big, len(data)))
            self.assertEqual(config.quick_hash(small, 300), compress.quick_hash(small, 300))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
