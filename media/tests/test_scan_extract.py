"""extract.py: traversal / link / bomb / encryption / nesting limits, normal archives, 7-Zip paths.

Run: python -m unittest discover -s media/tests -t media/tests -p "test_scan_extract*.py"
Archives are built in temp dirs with the stdlib; limits are lowered through conf so the bombs stay a few KB. 7-Zip
is not installed: the 7z/rar paths are tested for their "unscannable" fallback and, with a scripted fake 7z
(sandbox.run mocked), for listing checks and the post-extraction walk.
"""
import bz2
import gzip
import io
import lzma
import os
import shutil
import stat
import struct
import sys
import tarfile
import tempfile
import time
import unittest
import zipfile
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
MEDIA = os.path.dirname(HERE)
if MEDIA not in sys.path:
    sys.path.insert(0, MEDIA)
try:
    import pathfix  # noqa: F401
except Exception:
    pass

import extract  # noqa: E402
import sandbox  # noqa: E402

NO_TOOLS = {"7z": None}


def conf_with(**archive):
    return {"scan": {"timeout_s": 120, "archive": archive}}


def zip_bytes(entries, compression=zipfile.ZIP_DEFLATED):
    """entries: [(name_or_ZipInfo, data)]."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


def tar_bytes(members, mode="w"):
    """members: [(TarInfo, data or None)]."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for ti, data in members:
            if data is not None:
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
            else:
                tf.addfile(ti)
    return buf.getvalue()


def ti(name, type_=tarfile.REGTYPE, **kw):
    t = tarfile.TarInfo(name)
    t.type = type_
    t.mode = 0o644
    for k, v in kw.items():
        setattr(t, k, v)
    return t


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="strata-test-extract-")
        self.dest = os.path.join(self.tmp, "sandbox", "job1")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def write(self, name, data):
        p = os.path.join(self.tmp, name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def run_extract(self, name, data, conf=None, tools=NO_TOOLS, **kw):
        shutil.rmtree(self.dest, ignore_errors=True)      # a fresh sandbox per call, like one worker job
        return extract.extract(self.write(name, data), self.dest, conf or {}, tools, **kw)

    def assert_finding(self, res, type_, severity, where=None, contains=None):
        hits = [f for f in res["findings"] if f["type"] == type_ and f["severity"] == severity
                and (where is None or f["where"] == where) and (contains is None or contains in f["sample"])]
        self.assertTrue(hits, "no %s/%s finding (where=%r, %r) in %r" % (type_, severity, where, contains,
                                                                         res["findings"]))
        return hits[0]

    def files(self, res):
        return {rel: size for rel, _abs, size in res["files"]}

    def all_paths(self):
        out = []
        for dp, dns, fns in os.walk(self.tmp):
            out += [os.path.join(dp, n) for n in dns + fns]
        return out


class CheckName(unittest.TestCase):
    def test_ok(self):
        self.assertEqual(extract.check_name("a.txt"), (["a.txt"], None))
        self.assertEqual(extract.check_name("dir/sub/b.png"), (["dir", "sub", "b.png"], None))
        self.assertEqual(extract.check_name("./x//y"), (["x", "y"], None))
        self.assertEqual(extract.check_name("docs\\a.txt"), (["docs", "a.txt"], None))

    def test_rejected(self):
        cases = {"../x": "traversal", "a/../../x": "traversal", "..\\..\\evil.txt": "traversal",
                 "/etc/passwd": "absolute", "\\\\server\\share\\x": "absolute", "\\Windows\\x": "absolute",
                 "C:/Windows/x.dll": "drive", "C:x.txt": "drive", "d:\\x": "drive",
                 "a\x00b": "control", "a\x1fb": "control", "a\nb": "control",
                 "CON": "device", "aux.txt": "device", "sub/LPT1.log": "device", "nul": "device",
                 "ab:c": "colon", "file.txt:stream": "colon", "x.": "trailing", "x ": "trailing",
                 "a<b": "reserved", "q?.txt": "reserved", "": "empty", ".": "empty", "a" * 256: "too long"}
        for name, why in cases.items():
            with self.subTest(name=name):
                parts, reason = extract.check_name(name)
                self.assertIsNone(parts)
                self.assertIn(why, reason.lower().replace("-", " ").replace("nul or control", "control"))

    def test_root_entry(self):
        self.assertTrue(extract._root_entry("./"))
        self.assertTrue(extract._root_entry("."))
        self.assertFalse(extract._root_entry("/"))
        self.assertFalse(extract._root_entry("./a"))


class Zip(Base):
    def test_normal_archive(self):
        data = zip_bytes([("readme.txt", b"hello"), ("img/", b""), ("img/cat.png", b"\x89PNG" + b"x" * 100),
                          ("deep/a/b/c.txt", b"abc" * 1000)])
        res = self.run_extract("ok.zip", data)
        self.assertEqual(res["tool"], "zipfile")
        self.assertEqual(res["findings"], [])
        self.assertEqual(self.files(res), {"readme.txt": 5, "img/cat.png": 104, "deep/a/b/c.txt": 3000})
        for rel, full, size in res["files"]:
            self.assertTrue(os.path.abspath(full).startswith(os.path.abspath(self.dest)))
            self.assertEqual(os.path.getsize(full), size)
        with open(dict((r, a) for r, a, _ in res["files"])["readme.txt"], "rb") as f:
            self.assertEqual(f.read(), b"hello")

    def test_zip_slip(self):
        res = self.run_extract("slip.zip", zip_bytes([("../evil.txt", b"x"), ("a/../../../evil2.txt", b"x"),
                                                      ("ok.txt", b"fine")]))
        self.assert_finding(res, "archive_bomb", "high", "../evil.txt", "traversal")
        self.assert_finding(res, "archive_bomb", "high", "a/../../../evil2.txt", "traversal")
        self.assertEqual(list(self.files(res)), ["ok.txt"])
        self.assertFalse([p for p in self.all_paths() if "evil" in os.path.basename(p)])

    def test_absolute_and_drive_paths(self):
        res = self.run_extract("abs.zip", zip_bytes([("/abs.txt", b"x"), ("C:/drive.txt", b"x"),
                                                     ("D:rel.txt", b"x"), ("ok.txt", b"y")]))
        self.assert_finding(res, "archive_bomb", "high", "/abs.txt", "absolute")
        self.assert_finding(res, "archive_bomb", "high", "C:/drive.txt", "drive")
        self.assert_finding(res, "archive_bomb", "high", "D:rel.txt", "drive")
        self.assertEqual(list(self.files(res)), ["ok.txt"])
        self.assertFalse(os.path.exists(os.path.join(self.dest, "..", "abs.txt")))

    def test_backslash_traversal(self):
        zi = zipfile.ZipInfo("placeholder")
        zi.filename = "..\\..\\bs.txt"          # raw backslashes (ZipInfo() itself would normalise them)
        zi2 = zipfile.ZipInfo("x")
        zi2.filename = "\\\\srv\\share\\unc.txt"
        res = self.run_extract("bs.zip", zip_bytes([(zi, b"x"), (zi2, b"x"), ("ok.txt", b"y")]))
        bad = [f for f in res["findings"] if f["type"] == "archive_bomb"]
        self.assertEqual(len(bad), 2, res["findings"])
        self.assertTrue(all(f["severity"] == "high" for f in bad))
        self.assertEqual(list(self.files(res)), ["ok.txt"])
        self.assertFalse([p for p in self.all_paths() if p.endswith(("bs.txt", "unc.txt"))])

    def test_unix_symlink_entry(self):
        zi = zipfile.ZipInfo("link")
        zi.create_system = 3
        zi.external_attr = (stat.S_IFLNK | 0o777) << 16
        res = self.run_extract("sym.zip", zip_bytes([(zi, b"../../../Windows/win.ini"), ("ok.txt", b"y")]))
        self.assert_finding(res, "archive_bomb", "high", "link", "symlink")
        self.assertEqual(list(self.files(res)), ["ok.txt"])

    def test_encrypted_flag_bit(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("secret.txt", b"not really encrypted")
            zf.writestr("plain.txt", b"plain")
            zf.getinfo("secret.txt").flag_bits |= 0x1      # lands in the central directory on close
        res = self.run_extract("enc.zip", buf.getvalue())
        self.assert_finding(res, "unscannable", "medium", "secret.txt", "encrypted")
        self.assertEqual(list(self.files(res)), ["plain.txt"])

    def test_ratio_bomb_lowered_limits(self):
        data = zip_bytes([("zeros.bin", b"\0" * (256 << 10))])
        with self.assertRaises(extract.BombError) as cm:
            self.run_extract("bomb.zip", data, conf_with(max_ratio=20, ratio_min_bytes=64 << 10))
        self.assertIn("ratio", str(cm.exception))
        self.assertFalse([p for p in self.all_paths() if p.endswith("zeros.bin")])   # partial file removed

    def test_ratio_bomb_default_limits(self):
        with self.assertRaises(extract.BombError):
            self.run_extract("bomb.zip", zip_bytes([("zeros.bin", b"\0" * (3 << 20))]))

    def test_small_or_incompressible_entries_pass(self):
        res = self.run_extract("ok.zip", zip_bytes([("small.bin", b"\0" * (512 << 10)),       # below 1 MiB
                                                    ("rand.bin", os.urandom(2 << 20))]))
        self.assertEqual(self.files(res), {"small.bin": 512 << 10, "rand.bin": 2 << 20})

    def test_entry_and_total_limits(self):
        data = zip_bytes([("a.bin", os.urandom(2000)), ("b.bin", os.urandom(2000))], zipfile.ZIP_STORED)
        with self.assertRaises(extract.BombError) as cm:
            self.run_extract("e.zip", data, conf_with(max_entry_bytes=1000))
        self.assertIn("entry", str(cm.exception))
        with self.assertRaises(extract.BombError) as cm:
            self.run_extract("t.zip", data, conf_with(max_total_bytes=3000))
        self.assertIn("archive expands", str(cm.exception))

    def test_too_many_entries(self):
        data = zip_bytes([("f%02d.txt" % i, b"x") for i in range(10)])
        with self.assertRaises(extract.BombError) as cm:
            self.run_extract("many.zip", data, conf_with(max_entries=5))
        self.assertIn("more than 5 entries", str(cm.exception))
        self.assertEqual(len(self.files(self.run_extract("many2.zip", data, conf_with(max_entries=10)))), 10)

    def test_overlapping_entries(self):
        data = bytearray(zip_bytes([("a.txt", b"A" * 5000), ("b.txt", b"B" * 5000)]))
        cd = data.find(b"PK\x01\x02")
        cd2 = data.find(b"PK\x01\x02", cd + 4)
        data[cd2 + 42:cd2 + 46] = data[cd + 42:cd + 46]     # second entry points at the first one's data
        with self.assertRaises(extract.BombError) as cm:
            self.run_extract("overlap.zip", bytes(data))
        self.assertIn("overlapping", str(cm.exception))

    def test_duplicate_names_and_corrupt_member(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("dup.txt", b"one")
            with self.assertWarns(UserWarning):
                zf.writestr("dup.txt", b"two")
        res = self.run_extract("dup.zip", buf.getvalue())
        self.assert_finding(res, "unscannable", "medium", "dup.txt", "duplicate")
        data = bytearray(zip_bytes([("c.txt", b"hello world " * 200)]))
        data[40] ^= 0xFF                                     # inside the deflate stream
        res = self.run_extract("crc.zip", bytes(data))
        self.assert_finding(res, "unscannable", "medium", "c.txt", "corrupt")
        self.assertEqual(res["files"], [])

    def test_unsupported_method_without_7z(self):
        data = bytearray(zip_bytes([("a.txt", b"x" * 100)]))
        cd = data.find(b"PK\x01\x02")
        data[cd + 10:cd + 12] = struct.pack("<H", 9)       # Deflate64 in the central directory
        res = self.run_extract("d64.zip", bytes(data))
        self.assert_finding(res, "unscannable", "medium", "a.txt", "compression method 9")

    def test_reserved_names_and_root_dir_entry(self):
        res = self.run_extract("r.zip", zip_bytes([("./", b""), ("CON.txt", b"x"), ("sub/aux", b"x"),
                                                   ("fine.txt", b"y")]))
        self.assertEqual(len([f for f in res["findings"] if "device" in f["sample"]]), 2)
        self.assertEqual(list(self.files(res)), ["fine.txt"])


class Tar(Base):
    def test_normal_targz_with_root_entry(self):
        data = tar_bytes([(ti("./", tarfile.DIRTYPE), None), (ti("./docs", tarfile.DIRTYPE), None),
                          (ti("./docs/a.txt"), b"alpha"), (ti("b.txt"), b"beta")], "w:gz")
        res = self.run_extract("ok.tar.gz", data)
        self.assertEqual(res["tool"], "tarfile")
        self.assertEqual(res["findings"], [])                  # "./" is the root, not an "empty name" bomb
        self.assertEqual(self.files(res), {"docs/a.txt": 5, "b.txt": 4})

    def test_plain_tar_and_xz(self):
        members = [(ti("a.txt"), b"alpha"), (ti("d/b.txt"), b"beta")]
        self.assertEqual(self.files(self.run_extract("p.tar", tar_bytes(members))), {"a.txt": 5, "d/b.txt": 4})
        self.assertEqual(self.files(self.run_extract("p.tar.xz", tar_bytes(members, "w:xz"))),
                         {"a.txt": 5, "d/b.txt": 4})
        self.assertEqual(self.files(self.run_extract("p.tbz2", tar_bytes(members, "w:bz2"))),
                         {"a.txt": 5, "d/b.txt": 4})

    def test_traversal_and_absolute(self):
        data = tar_bytes([(ti("../up.txt"), b"x"), (ti("/etc/abs.txt"), b"x"), (ti("C:/drive.txt"), b"x"),
                          (ti("ok.txt"), b"y")])
        res = self.run_extract("t.tar", data)
        self.assert_finding(res, "archive_bomb", "high", "../up.txt", "traversal")
        self.assert_finding(res, "archive_bomb", "high", "/etc/abs.txt", "absolute")
        self.assert_finding(res, "archive_bomb", "high", "C:/drive.txt", "drive")
        self.assertEqual(list(self.files(res)), ["ok.txt"])
        self.assertFalse([p for p in self.all_paths() if p.endswith(("up.txt", "abs.txt", "drive.txt"))])

    def test_links_and_devices_never_created(self):
        data = tar_bytes([(ti("a.txt"), b"alpha"),
                          (ti("sym", tarfile.SYMTYPE, linkname="../../../Windows/win.ini"), None),
                          (ti("hard", tarfile.LNKTYPE, linkname="a.txt"), None),
                          (ti("dev", tarfile.CHRTYPE, devmajor=1, devminor=3), None),
                          (ti("fifo", tarfile.FIFOTYPE), None)])
        res = self.run_extract("links.tar", data)
        self.assert_finding(res, "archive_bomb", "high", "sym", "symlink")
        self.assert_finding(res, "archive_bomb", "high", "hard", "hard link")
        self.assert_finding(res, "archive_bomb", "high", "dev", "device")
        self.assert_finding(res, "archive_bomb", "high", "fifo", "device")
        self.assertEqual(list(self.files(res)), ["a.txt"])
        for name in ("sym", "hard", "dev", "fifo"):
            self.assertFalse([p for p in self.all_paths() if os.path.basename(p) == name])

    def test_ratio_bomb(self):
        data = tar_bytes([(ti("zeros.bin"), b"\0" * (512 << 10))], "w:gz")
        with self.assertRaises(extract.BombError) as cm:
            self.run_extract("bomb.tar.gz", data, conf_with(max_ratio=20, ratio_min_bytes=64 << 10))
        self.assertIn("ratio", str(cm.exception))

    def test_declared_size_of_skipped_member(self):
        # the member is refused by name, but tarfile would still inflate its data to reach the next header
        data = tar_bytes([(ti("../big.bin"), b"\0" * 5000), (ti("ok.txt"), b"y")], "w:gz")
        with self.assertRaises(extract.BombError) as cm:
            self.run_extract("decl.tar.gz", data, conf_with(max_entry_bytes=1000))
        self.assertIn("declares", str(cm.exception))

    def test_too_many_entries(self):
        data = tar_bytes([(ti("f%02d.txt" % i), b"x") for i in range(10)])
        with self.assertRaises(extract.BombError):
            self.run_extract("many.tar", data, conf_with(max_entries=5))

    def test_truncated_tar(self):
        data = tar_bytes([(ti("a.txt"), b"alpha" * 100), (ti("b.txt"), os.urandom(4000))])
        res = self.run_extract("trunc.tar", data[:2048])
        self.assertIn("a.txt", self.files(res))
        self.assert_finding(res, "unscannable", "medium", contains="truncated")


class Compressed(Base):
    def test_single_streams(self):
        payload = b"log line\n" * 100
        for name, blob, tool in (("app.log.gz", gzip.compress(payload), "gzip"),
                                 ("app.log.bz2", bz2.compress(payload), "bz2"),
                                 ("app.log.xz", lzma.compress(payload), "lzma")):
            with self.subTest(name):
                res = self.run_extract(name, blob)
                self.assertEqual(res["tool"], tool)
                self.assertEqual(self.files(res), {"app.log": len(payload)})
                self.assertEqual(res["findings"], [])

    def test_single_gz_bomb(self):
        # all zeros: tarfile alone would call this an empty tar and never inflate it
        with self.assertRaises(extract.BombError):
            self.run_extract("z.bin.gz", gzip.compress(b"\0" * (3 << 20)))
        with self.assertRaises(extract.BombError):
            self.run_extract("z.tar.gz", gzip.compress(b"\0" * (64 << 10)), conf_with(max_ratio=20,
                                                                                      ratio_min_bytes=16 << 10))

    def test_content_starting_with_zeros_is_scanned(self):
        payload = b"\0" * 1024 + b"password=hunter2xyz\n"
        res = self.run_extract("disk.img.gz", gzip.compress(payload))
        self.assertEqual((res["tool"], self.files(res)), ("gzip", {"disk.img": len(payload)}))

    def test_empty_tar_gz(self):
        res = self.run_extract("empty.tar.gz", tar_bytes([], "w:gz"))
        self.assertEqual(res["findings"], [])
        self.assertEqual([r for r in self.files(res) if not r.endswith(".tar")], [])

    @unittest.skipIf(extract.zstandard is None, "zstandard not importable")
    def test_zstd(self):
        cctx = extract.zstandard.ZstdCompressor()
        tarred = tar_bytes([(ti("a.txt"), b"alpha"), (ti("b/c.txt"), b"gamma")])
        res = self.run_extract("x.tar.zst", cctx.compress(tarred))
        self.assertEqual((res["tool"], self.files(res)), ("tarfile", {"a.txt": 5, "b/c.txt": 5}))
        res = self.run_extract("notes.txt.zst", cctx.compress(b"hello zstd\n" * 10))
        self.assertEqual((res["tool"], self.files(res)), ("zstandard", {"notes.txt": 110}))
        res = self.run_extract("bad.zst", b"\x28\xb5\x2f\xfd" + b"\xff" * 64)    # corrupt frame: no ZstdError leak
        self.assertEqual(res["files"], [])
        self.assert_finding(res, "unscannable", "medium", contains="corrupt")

    def test_corrupt_gzip(self):
        res = self.run_extract("bad.gz", b"\x1f\x8b\x08\x00" + b"\x00" * 6 + b"garbage" * 10)
        self.assertEqual(res["files"], [])
        self.assert_finding(res, "unscannable", "medium", contains="corrupt")


class Nested(Base):
    def chain(self, levels, leaf=("deep.txt", b"deep")):
        data = zip_bytes([leaf])
        for i in range(levels, 0, -1):
            data = zip_bytes([("l%d.zip" % i, data), ("n%d.txt" % i, b"level")])
        return data

    def test_nested_ok_within_depth(self):
        res = self.run_extract("outer.zip", self.chain(3))
        files = self.files(res)
        self.assertIn("l1.zip/l2.zip/l3.zip/deep.txt", files)
        self.assertIn("l1.zip/n2.txt", files)
        self.assertEqual(res["findings"], [])

    def test_depth_limit(self):
        res = self.run_extract("outer.zip", self.chain(3), conf_with(max_depth=1))
        f = self.assert_finding(res, "archive_bomb", "high", "l1.zip/l2.zip", "nested deeper")
        self.assertIn("1 levels", f["sample"])
        self.assertNotIn("l1.zip/l2.zip/l3.zip/deep.txt", self.files(res))
        with self.assertRaises(extract.BombError):
            extract.extract(self.write("x.zip", self.chain(1)), self.dest, conf_with(max_depth=1), NO_TOOLS, depth=2,
                            budget={"bytes": 0, "entries": 0, "seq": 0, "root": self.dest, "checked": 0, "tick": 0,
                                    "cancel": None, "deadline": time.monotonic() + 60})

    def test_nested_bomb_names_the_member(self):
        inner = zip_bytes([("zeros.bin", b"\0" * (256 << 10))])
        with self.assertRaises(extract.BombError) as cm:
            self.run_extract("outer.zip", zip_bytes([("inner.zip", inner)]),
                             conf_with(max_ratio=20, ratio_min_bytes=64 << 10))
        self.assertTrue(str(cm.exception).startswith("inner.zip:"), str(cm.exception))

    def test_nested_findings_are_prefixed(self):
        inner = zip_bytes([("../evil.txt", b"x"), ("a.txt", b"a")])
        res = self.run_extract("outer.zip", zip_bytes([("sub/inner.zip", inner)]))
        self.assert_finding(res, "archive_bomb", "high", "sub/inner.zip/../evil.txt")
        self.assertIn("sub/inner.zip/a.txt", self.files(res))

    def test_nested_unreadable_and_7z(self):
        res = self.run_extract("outer.zip", zip_bytes([("broken.zip", b"PK\x03\x04garbage"),
                                                       ("inner.7z", b"7z\xbc\xaf\x27\x1c" + b"\0" * 64)]))
        self.assert_finding(res, "unscannable", "medium", "broken.zip", "unreadable")
        self.assert_finding(res, "unscannable", "medium", "inner.7z", "7-Zip missing")


class SevenZip(Base):
    def test_missing_7z_is_unscannable(self):
        for name, magic in (("a.7z", b"7z\xbc\xaf\x27\x1c"), ("a.rar", b"Rar!\x1a\x07\x00"),
                            ("b.rar", b"Rar!\x1a\x07\x01\x00")):
            with self.subTest(name):
                res = self.run_extract(name, magic + os.urandom(128))
                self.assertEqual(res["tool"], "missing")
                self.assertEqual(res["files"], [])
                f = self.assert_finding(res, "unscannable", "medium", contains="7-Zip missing")
                self.assertIn(extract.sniff(os.path.join(self.tmp, name)), f["sample"])

    def test_parse_slt(self):
        entries = extract.parse_slt(SLT_OK)
        self.assertEqual([e["Path"] for e in entries], ["docs\\a.txt", "docs"])
        self.assertEqual(entries[0]["Size"], "12")
        self.assertEqual(extract.parse_slt("no listing"), [])

    def fake_7z(self, listing, make_files=(), rc_list=0, rc_x=0):
        calls = []

        def run(cmd, timeout, **kw):
            calls.append(cmd)
            r = sandbox.Result()
            if cmd[1] == "l":
                r.rc, r.out = rc_list, listing
            else:
                out = next(a[2:] for a in cmd if a.startswith("-o"))
                for rel, data in make_files:
                    p = os.path.join(out, *rel.split("/"))
                    os.makedirs(os.path.dirname(p), exist_ok=True)
                    with open(p, "wb") as f:
                        f.write(data)
                r.rc = rc_x
            return r
        return run, calls

    def test_fake_7z_listing_and_post_walk(self):
        run, calls = self.fake_7z(SLT_OK, [("docs/a.txt", b"hello world!")])
        with mock.patch.object(extract.sandbox, "run", run):
            res = self.run_extract("a.7z", b"7z\xbc\xaf\x27\x1c" + b"\0" * 64, tools={"7z": r"C:\fake\7z.exe"})
        self.assertEqual(res["tool"], "7z")
        self.assertEqual(self.files(res), {"docs/a.txt": 12})
        self.assertEqual(res["findings"], [])
        self.assertEqual([c[1] for c in calls], ["l", "x"])
        x = calls[1]
        self.assertIn("-snl-", x)
        self.assertIn("-p-", x)
        self.assertTrue(any(a.startswith("-o") for a in x))

    @unittest.skipUnless(os.name == "nt", "junctions are Windows-only")
    def test_post_walk_removes_junctions_without_following(self):
        import _winapi
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(outside)
        with open(os.path.join(outside, "keep.txt"), "wb") as f:
            f.write(b"must survive")
        base_run, _ = self.fake_7z(SLT_OK, [("docs/a.txt", b"hello world!")])

        def run(cmd, timeout, **kw):
            r = base_run(cmd, timeout, **kw)
            if cmd[1] == "x":     # what a hostile archive + extractor bug could leave behind
                out = next(a[2:] for a in cmd if a.startswith("-o"))
                _winapi.CreateJunction(outside, os.path.join(out, "docs", "jn"))
            return r
        with mock.patch.object(extract.sandbox, "run", run):
            res = self.run_extract("a.7z", b"7z\xbc\xaf\x27\x1c" + b"\0" * 64, tools={"7z": "7z.exe"})
        self.assert_finding(res, "archive_bomb", "high", "docs/jn", "junction")
        self.assertEqual(self.files(res), {"docs/a.txt": 12})
        self.assertTrue(os.path.isfile(os.path.join(outside, "keep.txt")))
        self.assertFalse(os.path.lexists(os.path.join(self.dest, "a0", "docs", "jn")))

    def test_fake_7z_listing_bombs(self):
        big = SLT_OK.replace("Size = 12", "Size = %d" % (20 << 30))
        run, calls = self.fake_7z(big)
        with mock.patch.object(extract.sandbox, "run", run), self.assertRaises(extract.BombError):
            self.run_extract("a.7z", b"7z\xbc\xaf\x27\x1c" + b"\0" * 64, tools={"7z": "7z.exe"})
        self.assertEqual([c[1] for c in calls], ["l"])        # never extracted

    def test_fake_7z_encrypted_and_links(self):
        listing = SLT_OK.replace("Encrypted = -", "Encrypted = +", 1) + (
            "Path = link\nSize = 10\nAttributes = A_ lrwxrwxrwx\nEncrypted = -\n\n"
            "Path = ..\\up.txt\nSize = 1\nAttributes = A\nEncrypted = -\n\n")
        run, _ = self.fake_7z(listing)
        with mock.patch.object(extract.sandbox, "run", run):
            res = self.run_extract("a.7z", b"7z\xbc\xaf\x27\x1c" + b"\0" * 64, tools={"7z": "7z.exe"})
        self.assert_finding(res, "unscannable", "medium", "docs\\a.txt", "encrypted")
        self.assert_finding(res, "archive_bomb", "high", "link", "symlink")
        self.assert_finding(res, "archive_bomb", "high", "..\\up.txt", "traversal")

    def test_fake_7z_header_encryption(self):
        run, _ = self.fake_7z("ERROR: Cannot open encrypted archive. Wrong password?", rc_list=2)
        with mock.patch.object(extract.sandbox, "run", run), self.assertRaises(extract.EncryptedError):
            self.run_extract("a.7z", b"7z\xbc\xaf\x27\x1c" + b"\0" * 64, tools={"7z": "7z.exe"})


class BudgetAndErrors(Base):
    def test_cancel(self):
        with self.assertRaises(extract.Cancelled):
            self.run_extract("c.zip", zip_bytes([("a.txt", b"a")]), cancel=lambda: True)

    def test_timeout(self):
        with self.assertRaises(extract.Timeout):
            self.run_extract("t.zip", zip_bytes([("a.txt", b"a")]), deadline=time.monotonic() - 1)

    def test_low_disk(self):
        with self.assertRaises(extract.SpaceError):
            self.run_extract("s.zip", zip_bytes([("a.txt", b"a")]), conf_with(min_free_bytes=1 << 60))

    def test_unknown_format(self):
        with self.assertRaises(extract.ArchiveError):
            self.run_extract("x.zip", b"this is not an archive at all" * 20)
        self.assertIsNone(extract.sniff(self.write("n.bin", b"plain")))
        self.assertEqual(extract.sniff(self.write("z.bin", zip_bytes([("a", b"b")]))), "zip")
        self.assertEqual(extract.sniff(self.write("sfx.exe", b"MZ" + b"\0" * 200 + zip_bytes([("a", b"b")]))), "zip")
        self.assertEqual(extract.sniff(self.write("t.bin", tar_bytes([(ti("a"), b"b")]))), "tar")

    def test_limits_from_conf(self):
        lim = extract.limits({"scan": {"timeout_s": 60, "archive": {"max_ratio": 5, "ocr_images": 3}}})
        self.assertEqual((lim["max_ratio"], lim["timeout_s"], lim["max_depth"]), (5, 60.0, 3))
        self.assertNotIn("ocr_images", lim)
        self.assertEqual(extract.limits(None)["max_entries"], 50000)


SLT_OK = """
7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20

Scanning the drive for archives:
1 file, 1234 bytes (2 KiB)

Listing archive: C:\\x\\a.7z

--
Path = C:\\x\\a.7z
Type = 7z
Physical Size = 1234
Headers Size = 200
Method = LZMA2:24
Solid = +
Blocks = 1

----------
Path = docs\\a.txt
Size = 12
Packed Size = 100
Modified = 2024-01-01 00:00:00
Attributes = A
CRC = 12345678
Encrypted = -
Method = LZMA2:24
Block = 0

Path = docs
Size = 0
Packed Size = 0
Attributes = D
Encrypted = -

"""


if __name__ == "__main__":
    unittest.main()
