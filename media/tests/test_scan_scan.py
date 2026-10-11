"""scan.py: verdicts per category, missing-tool fallbacks (7.4), AV engines, OCR path, robustness and cleanup.

Run: python -m unittest discover -s media/tests -t media/tests -p "test_scan_scan*.py"
Tools are passed explicitly: most tests use none (require_av off) so they are deterministic; tesseract, pypdfium2,
MpCmdRun and ClamAV are replaced by fakes where their behaviour matters. The real-Defender tests run only when
MpCmdRun is found and scan harmless temp files. Every scan gets its own sandbox dir, which must be gone afterwards.
"""
import copy
import io
import os
import shutil
import sys
import tempfile
import unittest
import zipfile
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
import sandbox  # noqa: E402
import scan  # noqa: E402
from test_scan_detect import AN, Gen, PDF_HARMLESS, PDF_JS  # noqa: E402

NO_TOOLS = {n: None for n in sandbox.TOOL_NAMES}
FAKE_TESS = r"C:\fake\Tesseract-OCR\tesseract.exe"
FAKE_MPCMD = r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.99-0\MpCmdRun.exe"
DEFENDER_THREAT_OUT = """Scan starting...
Scan finished.
Scanning C:\\x\\sample.bin found 2 threats.

<===========================LIST OF DETECTED THREATS==========================>
----------------------------- Threat information ------------------------------
Threat                  : Trojan:Win32/Synthetic.A!test
Resources               : 1 total
    file                : C:\\x\\sample.bin
-------------------------------------------------------------------------------
----------------------------- Threat information ------------------------------
Threat                  : HackTool:Win32/Synthetic.B
Resources               : 1 total
    file                : C:\\x\\sample.bin
-------------------------------------------------------------------------------
"""
REAL_MPCMD = sandbox.which("mpcmdrun", {})


def result(rc=0, out="", err="", killed=None):
    r = sandbox.Result()
    r.rc, r.out, r.err, r.killed, r.timed_out = rc, out, err, killed, killed == "timeout"
    return r


def png_bytes(size=(300, 120), mode="RGB", **info):
    from PIL import Image, PngImagePlugin
    img = Image.new(mode, size, "white")
    meta = PngImagePlugin.PngInfo()
    for k, v in info.items():
        meta.add_text(k, v)
    buf = io.BytesIO()
    img.save(buf, "PNG", pnginfo=meta)
    return buf.getvalue()


def zip_bytes(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


class FakeOcr:
    """Stands in for tesseract behind sandbox.run: checks the tile list it is given, answers with canned text."""

    def __init__(self, text="", killed=None, rc=0):
        self.text, self.killed, self.rc = text, killed, rc
        self.tiles, self.calls = [], []

    def __call__(self, cmd, timeout, **kw):
        self.calls.append((cmd, kw))
        if "--version" in cmd:
            return result(out="tesseract v5.3.0.20221214\n leptonica-1.83.0\n")
        from PIL import Image
        with open(cmd[1], encoding="utf-8") as f:
            paths = [ln for ln in f.read().splitlines() if ln]
        for p in paths:
            with Image.open(p) as im:
                self.tiles.append((p, im.mode, im.size))
        assert kw.get("env", {}).get("OMP_THREAD_LIMIT") == "1"
        return result(rc=self.rc, out=self.text if not self.killed else "", killed=self.killed)


class FakePdfium:
    """Enough of pypdfium2 for scan._scan_pdf: pages with text, optional render, or a load error."""
    V_PYPDFIUM2 = "4.30.0"

    def __init__(self, pages=(), error=None):
        self.pages, self.error, self.closed = list(pages), error, []

    def PdfDocument(self, path):
        if self.error:
            raise Exception(self.error)
        outer = self

        class Doc:
            def __len__(self):
                return len(outer.pages)

            def __getitem__(self, i):
                return Page(outer.pages[i])

            def close(self):
                outer.closed.append("doc")

        class TextPage:
            def __init__(self, t):
                self.t = t

            def get_text_range(self):
                return self.t

            def close(self):
                pass

        class Bitmap:
            def to_pil(self):
                from PIL import Image
                return Image.new("RGB", (200, 260), "white")

        class Page:
            def __init__(self, t):
                self.t = t

            def get_textpage(self):
                return TextPage(self.t)

            def render(self, scale):
                return Bitmap()

            def close(self):
                outer.closed.append("page")
        return Doc()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="strata-test-scan-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.cache = os.path.join(self.tmp, "cache")
        os.makedirs(os.path.join(self.cache, "sandbox"))
        self.conf = copy.deepcopy(config.DEFAULTS)
        self.conf.update(enabled=True, cache_root=self.cache)      # media.enabled defaults to False
        self.conf["scan"]["require_av"] = False
        self.jobs = 0
        scan._versions.clear()
        self.g = Gen(4242)

    def put(self, name, data):
        p = os.path.join(self.tmp, "mount", *name.strip("/").split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data.encode() if isinstance(data, str) else data)
        return p

    def scan(self, name, data, tools=None, conf=None, **kw):
        full = self.put(name, data)
        self.jobs += 1
        box = os.path.join(self.cache, "sandbox", "job%d" % self.jobs)
        res = scan.scan_file(full, name, conf or self.conf, NO_TOOLS if tools is None else tools,
                             sandbox_dir=box, **kw)
        self.assertFalse(os.path.lexists(box), "sandbox dir left behind")
        self.assertEqual(os.listdir(os.path.join(self.cache, "sandbox")), [], "temp dirs left behind")
        return res

    def finding(self, res, type_, severity=None, contains=None):
        hits = [f for f in res.findings if f["type"] == type_ and (severity is None or f["severity"] == severity)
                and (contains is None or contains in f["sample"] or contains in f["where"])]
        self.assertTrue(hits, "no %s/%s (%r) in %r" % (type_, severity, contains, res.findings))
        return hits[0]

    def token(self):
        return "ghp_" + self.g.s(36)


class TextAndWeb(Base):
    def test_text_with_token_flagged(self):
        tok = self.token()
        res = self.scan("/docs/config.txt", "hello\ntoken %s\n" % tok)
        self.assertEqual((res.state, res.severity, res.error_kind), ("flagged", "high", None))
        f = self.finding(res, "github_token", "high")
        self.assertEqual(f["where"], "/docs/config.txt:2")
        self.assertNotIn(tok, repr(res.as_dict()))
        self.assertEqual(res.engines["category"], "text")

    def test_clean_text(self):
        res = self.scan("/docs/readme.md", "# Title\n\nJust some notes, version 1.2.3.4, see https://example.org\n")
        self.assertEqual((res.state, res.severity, res.findings, res.error_kind), ("clean", "none", [], None))
        self.assertGreaterEqual(res.secs, 0)

    def test_low_findings_stay_clean(self):
        res = self.scan("/docs/contacts.csv", "name,mail\nalice,alice.smith@corp.io\n")
        self.assertEqual((res.state, res.severity), ("clean", "low"))

    def test_medium_holds(self):
        res = self.scan("/docs/notes.txt", "db server 93.184.216.34\n")
        self.assertEqual((res.state, res.severity), ("flagged", "medium"))
        conf = copy.deepcopy(self.conf)
        conf["scan"]["hold_threshold"] = "high"
        self.assertEqual(self.scan("/docs/notes2.txt", "db server 93.184.216.34\n", conf=conf).state, "clean")

    def test_web_asset_with_aiza_only_is_clean_low(self):
        res = self.scan("/site/app.js", 'const maps = new Loader({apiKey: "AIza%s"});\n' % self.g.s(35))
        self.assertEqual((res.state, res.severity), ("clean", "low"))
        self.finding(res, "google_api_key", "low")
        res = self.scan("/site/app.txt", 'apiKey: "AIza%s"\n' % self.g.s(35))           # not a web asset
        self.assertEqual((res.state, res.severity), ("flagged", "high"))

    def test_web_asset_medium_is_not_held_but_high_is(self):
        res = self.scan("/site/config.json", '{"password": "c0rrect-h0rse", "host": "93.184.216.34"}')
        self.assertEqual((res.state, res.severity), ("clean", "low"))
        res = self.scan("/site/bundle.js", "const k = `%s`;" % ("sk_live_" + self.g.s(24)))
        self.assertEqual((res.state, res.severity), ("flagged", "high"))

    def test_text_limit(self):
        conf = copy.deepcopy(self.conf)
        conf["scan"]["text_max_bytes"] = 1000
        res = self.scan("/big.log", "x" * 2000 + "\ntoken %s\n" % self.token(), conf=conf)
        self.assertEqual(res.state, "clean")
        self.assertIn("first 1000", res.engines["text"])

    def test_utf16_text(self):
        res = self.scan("/w.txt", ("\ufefftoken %s\r\n" % self.token()).encode("utf-16-le"))
        self.assertEqual(res.state, "flagged")


class Svg(Base):
    def test_script_flagged(self):
        res = self.scan("/img/logo.svg", '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>')
        self.assertEqual((res.state, res.severity), ("flagged", "medium"))
        self.finding(res, "svg_active", "medium", "<script>")

    def test_clean_svg_with_path_data(self):
        svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><path d="M 10 10 L 93.18.21.34 '
               'l 172.16.0.5 Z" transform="matrix(1.0 0.0 0.0 1.0 93.184.216.34)"/><text x="1" y="2">Hi</text></svg>')
        res = self.scan("/img/clean.svg", svg)
        self.assertEqual((res.state, res.findings), ("clean", []))

    def test_token_in_comment(self):
        res = self.scan("/img/t.svg", "<svg><!-- deploy token %s --><rect/></svg>" % self.token())
        self.finding(res, "github_token", "high")


class Pdf(Base):
    def pdfium(self, fake):
        return mock.patch.object(scan, "_pdfium", return_value=fake)

    def test_javascript_pdf_flagged(self):
        with self.pdfium(FakePdfium(["Hello, this page has more than twenty characters."])):
            res = self.scan("/docs/a.pdf", PDF_JS)
        self.assertEqual((res.state, res.severity), ("flagged", "medium"))
        self.assertTrue({"/JavaScript", "/JS", "/OpenAction+JS"} <= {f["sample"] for f in res.findings
                                                                  if f["type"] == "pdf_active"})
        self.assertEqual(res.engines["pdf"], "pypdfium2 4.30.0")

    def test_harmless_pdf_mentioning_javascript_is_clean(self):
        fake = FakePdfium(["Learning JavaScript: /JS and /Launch explained in plain text."])
        with self.pdfium(fake):
            res = self.scan("/docs/book.pdf", PDF_HARMLESS)
        self.assertEqual((res.state, res.findings), ("clean", []))
        self.assertIn("doc", fake.closed)

    def test_pypdfium2_missing_is_unscannable(self):
        with self.pdfium(None):
            res = self.scan("/docs/book.pdf", PDF_HARMLESS)
        self.assertEqual((res.state, res.severity), ("flagged", "medium"))
        self.finding(res, "unscannable", "medium", "pypdfium2 missing")
        self.assertEqual(res.engines["pdf"], "missing")
        self.assertFalse([f for f in res.findings if f["type"] == "pdf_active"])
        with self.pdfium(None):
            res = self.scan("/docs/a.pdf", PDF_JS)         # active content is still reported without pdfium
        self.finding(res, "pdf_active", "medium", "/JavaScript")

    def test_page_text_detectors(self):
        with self.pdfium(FakePdfium(["intro page with enough text to count", "token %s" % self.token()])):
            res = self.scan("/docs/leak.pdf", PDF_HARMLESS)
        self.assertEqual(self.finding(res, "github_token", "high")["where"], "/docs/leak.pdf p2:1")

    def test_scanned_page_needs_ocr(self):
        with self.pdfium(FakePdfium([""])):
            res = self.scan("/docs/scan.pdf", PDF_HARMLESS)
        self.finding(res, "unscannable", "medium", "tesseract is missing")
        fake = FakeOcr("Password: hunter2xyz")
        tools = dict(NO_TOOLS, tesseract=FAKE_TESS)
        with self.pdfium(FakePdfium(["", "short"])), mock.patch.object(sandbox, "run", fake):
            res = self.scan("/docs/scan.pdf", PDF_HARMLESS, tools=tools)
        self.assertEqual(res.state, "flagged")
        self.assertEqual({f["where"] for f in res.findings}, {"/docs/scan.pdf p1", "/docs/scan.pdf p2"})
        self.assertEqual(len(fake.tiles), 2)

    def test_password_protected(self):
        with self.pdfium(FakePdfium(error="Failed to load document (PDFium: Incorrect password error)")):
            res = self.scan("/docs/locked.pdf", PDF_HARMLESS)
        self.finding(res, "unscannable", "medium", "password-protected")
        self.assertEqual(res.state, "flagged")

    def test_page_limit(self):
        conf = copy.deepcopy(self.conf)
        conf["scan"]["pdf"]["max_pages"] = 2
        with self.pdfium(FakePdfium(["enough text on this page to count"] * 2 + ["token " + self.token()])):
            res = self.scan("/docs/long.pdf", PDF_HARMLESS, conf=conf)
        self.assertEqual((res.state, res.engines["pdf_pages"]), ("clean", "2 of 3"))


class Ocr(Base):
    def test_image_ocr_with_mocked_tesseract(self):
        fake = FakeOcr("Login\nUsername: admin\nPassword: hunter2xyz\n")
        with mock.patch.object(sandbox, "run", fake):
            res = self.scan("/shots/login.png", png_bytes((300, 120)), tools=dict(NO_TOOLS, tesseract=FAKE_TESS))
        self.assertEqual((res.state, res.severity), ("flagged", "medium"))
        f = self.finding(res, "password", "medium")
        self.assertNotIn("hunter2xyz", f["sample"])
        self.assertEqual(f["where"], "/shots/login.png")
        self.assertEqual(res.engines["ocr"], "tesseract 5.3.0.20221214")
        self.assertEqual(fake.tiles and [t[1:] for t in fake.tiles], [("L", (600, 240))])   # gray, upscaled x2
        box = os.path.join(self.cache, "sandbox", "job1")
        self.assertTrue(all(os.path.normcase(t[0]).startswith(os.path.normcase(box)) for t in fake.tiles))
        cmd, kw = [c for c in fake.calls if "--version" not in c[0]][0]
        self.assertEqual(cmd[2:], ["stdout", "-l", "eng", "--psm", "3"])
        self.assertEqual((kw["priority"], kw["cpu_pct"]), ("idle", 35))

    def test_tall_image_is_tiled(self):
        fake = FakeOcr("nothing here")
        with mock.patch.object(sandbox, "run", fake):
            res = self.scan("/shots/tall.png", png_bytes((200, 6000)), tools=dict(NO_TOOLS, tesseract=FAKE_TESS))
        self.assertEqual(res.state, "clean")
        self.assertEqual(len(fake.tiles), 3)
        self.assertTrue(all(max(size) <= 2400 for _p, _m, size in fake.tiles))
        self.assertEqual(scan._tiles(__import__("PIL.Image", fromlist=["Image"]).new("L", (5000, 5000)), 2400)
                         .__len__(), 9)

    def test_animated_gif_frames(self):
        from PIL import Image
        # distinct RGB colours: Pillow merges frames that look identical (same-palette P frames collapse to one)
        frames = [Image.new("RGB", (120, 80), (i * 25, 0, 0)) for i in range(10)]
        buf = io.BytesIO()
        frames[0].save(buf, "GIF", save_all=True, append_images=frames[1:], duration=50)
        fake = FakeOcr("")
        with mock.patch.object(sandbox, "run", fake):
            res = self.scan("/anim.gif", buf.getvalue(), tools=dict(NO_TOOLS, tesseract=FAKE_TESS))
        self.assertEqual(res.state, "clean")
        self.assertEqual(len(fake.tiles), 5)            # first frame + 4 evenly spaced

    def test_tesseract_missing_required(self):
        res = self.scan("/shots/a.png", png_bytes())
        self.assertEqual((res.state, res.severity), ("flagged", "medium"))
        self.finding(res, "unscannable", "medium", "tesseract is missing")
        self.assertEqual(res.engines["ocr"], "missing")

    def test_tesseract_missing_not_required(self):
        conf = copy.deepcopy(self.conf)
        conf["ocr"]["required"] = False
        res = self.scan("/shots/a.png", png_bytes(), conf=conf)
        self.assertEqual((res.state, res.findings, res.engines["ocr"]), ("clean", [], "skipped"))

    def test_ocr_timeout_is_transient(self):
        with mock.patch.object(sandbox, "run", FakeOcr(killed="timeout")):
            res = self.scan("/shots/a.png", png_bytes(), tools=dict(NO_TOOLS, tesseract=FAKE_TESS))
        self.assertEqual((res.state, res.error_kind), ("error", "ocr_timeout"))

    def test_tiny_image_skipped(self):
        with mock.patch.object(sandbox, "run", FakeOcr("Password: hunter2xyz")) as fake:
            res = self.scan("/icons/fav.png", png_bytes((32, 32)), tools=dict(NO_TOOLS, tesseract=FAKE_TESS))
        self.assertEqual((res.state, res.engines.get("ocr")), ("clean", "skipped"))
        self.assertEqual(fake.tiles, [])

    def test_exif_gps_low(self):
        from PIL import Image
        img = Image.new("RGB", (64, 64), "white")
        exif = Image.Exif()
        exif.get_ifd(0x8825).update({1: "N", 2: (48.0, 51.0, 29.0), 3: "E", 4: (2.0, 17.0, 40.0)})
        buf = io.BytesIO()
        img.save(buf, "JPEG", exif=exif)
        conf = copy.deepcopy(self.conf)
        conf["ocr"]["required"] = False
        res = self.scan("/photos/trip.jpg", buf.getvalue(), conf=conf)
        self.assertEqual((res.state, res.severity), ("clean", "low"))
        self.assertEqual(self.finding(res, "gps", "low")["where"], "/photos/trip.jpg")

    def test_png_text_metadata(self):
        conf = copy.deepcopy(self.conf)
        conf["ocr"]["required"] = False
        res = self.scan("/gen/a.png", png_bytes(parameters="prompt: cat, api token %s" % self.token()), conf=conf)
        self.assertEqual(res.state, "flagged")
        self.assertEqual(self.finding(res, "github_token")["where"], "/gen/a.png (metadata):1")

    def test_corrupt_image_is_unscannable(self):
        res = self.scan("/broken.png", b"\x89PNG\r\n\x1a\n" + b"\0" * 50)
        self.assertEqual(res.state, "flagged")
        self.finding(res, "unscannable", "medium", "cannot be decoded")


class Archive(Base):
    def test_inner_env_flagged(self):
        res = self.scan("/dl/site.zip", zip_bytes([("app/.env", "DB_PASSWORD=%s\n" % self.g.s(12)),
                                                   ("app/index.html", "<h1>hi</h1>")]))
        self.assertEqual((res.state, res.severity), ("flagged", "high"))
        self.assertEqual(self.finding(res, "dangerous_name", "high")["where"], "/dl/site.zip!/app/.env")
        self.finding(res, "password", "medium")
        self.assertEqual((res.engines["archive"], res.engines["archive_files"]), ("zipfile", 2))

    def test_inner_ps1_flagged_medium(self):
        res = self.scan("/dl/tools.zip", zip_bytes([("run.ps1", "Write-Host hi"), ("readme.txt", "hello")]))
        self.assertEqual((res.state, res.severity), ("flagged", "medium"))
        self.finding(res, "risky_file", "medium", ".ps1")

    def test_inner_exe_low_only(self):
        res = self.scan("/dl/app.zip", zip_bytes([("bin/app.exe", b"MZ" + os.urandom(2000)), ("readme.txt", "hi")]))
        self.assertEqual((res.state, res.severity), ("clean", "low"))
        self.finding(res, "executable", "low", ".exe")

    def test_inner_text_detectors_and_nesting(self):
        inner = zip_bytes([("conf/app.txt", "token %s\n" % self.token())])
        res = self.scan("/dl/outer.zip", zip_bytes([("inner.zip", inner)]))
        self.assertEqual(self.finding(res, "github_token", "high")["where"], "/dl/outer.zip!/inner.zip/conf/app.txt:1")

    def test_zip_slip_and_bomb_flagged(self):
        res = self.scan("/dl/slip.zip", zip_bytes([("../../evil.txt", "x"), ("ok.txt", "y")]))
        self.assertEqual(res.state, "flagged")
        self.assertEqual(self.finding(res, "archive_bomb", "high")["where"], "/dl/slip.zip!/../../evil.txt")
        res = self.scan("/dl/bomb.zip", zip_bytes([("zeros.bin", b"\0" * (3 << 20))]))
        self.assertEqual((res.state, res.severity), ("flagged", "high"))
        self.finding(res, "archive_bomb", "high", "ratio")

    def test_rar_without_7z_unscannable(self):
        res = self.scan("/dl/x.rar", b"Rar!\x1a\x07\x00" + os.urandom(100))
        self.assertEqual((res.state, res.severity), ("flagged", "medium"))
        self.finding(res, "unscannable", "medium", "7-Zip missing")
        self.assertEqual(res.engines["archive"], "missing")

    def test_encrypted_member(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("secret.docx", b"x")
            zf.getinfo("secret.docx").flag_bits |= 1
        res = self.scan("/dl/enc.zip", buf.getvalue())
        self.assertEqual(res.state, "flagged")
        self.finding(res, "unscannable", "medium", "encrypted")

    def test_unreadable_archive(self):
        res = self.scan("/dl/fake.zip", b"PK\x03\x04 definitely not a zip")
        self.assertEqual(res.state, "flagged")
        self.finding(res, "unscannable", "medium", "unreadable")

    def test_inner_image_ocr_budget(self):
        conf = copy.deepcopy(self.conf)
        conf["scan"]["archive"]["ocr_images"] = 1
        fake = FakeOcr("nothing")
        with mock.patch.object(sandbox, "run", fake):
            res = self.scan("/dl/pics.zip", zip_bytes([("a.png", png_bytes()), ("b.png", png_bytes()),
                                                       ("c.png", png_bytes())]),
                            tools=dict(NO_TOOLS, tesseract=FAKE_TESS), conf=conf)
        self.assertEqual((res.state, res.engines["ocr_images_skipped"], len(fake.tiles)), ("clean", 2, 1))

    def test_temp_dir_without_sandbox_dir(self):
        full = self.put("/dl/a.zip", zip_bytes([("a.txt", "hello")]))
        res = scan.scan_file(full, "/dl/a.zip", self.conf, NO_TOOLS)
        self.assertEqual(res.state, "clean")
        self.assertEqual(os.listdir(os.path.join(self.cache, "sandbox")), [])

    def test_vanished_member(self):
        real = scan._scan_one

        def flaky(ctx, path, where, cat, size, inner):
            if inner:
                raise FileNotFoundError(path)
            return real(ctx, path, where, cat, size, inner)
        with mock.patch.object(scan, "_scan_one", flaky):
            res = self.scan("/dl/v.zip", zip_bytes([("a.txt", "hello")]))
        self.assertEqual(res.state, "flagged")
        self.finding(res, "unscannable", "medium", "vanished")


class Document(Base):
    def docx(self, body, extra=()):
        xml = ('<?xml version="1.0"?><w:document xmlns:w="x"><w:body><w:p><w:r><w:t>%s</w:t></w:r></w:p>'
               '</w:body></w:document>' % body)
        return zip_bytes([("[Content_Types].xml", "<Types/>"), ("word/document.xml", xml)] + list(extra))

    def test_clean_docx(self):
        res = self.scan("/docs/letter.docx", self.docx("Dear reader, nothing secret in here."))
        self.assertEqual((res.state, res.findings), ("clean", []))

    def test_token_in_docx(self):
        res = self.scan("/docs/notes.docx", self.docx("deploy key: %s" % self.token()))
        self.assertEqual(self.finding(res, "github_token", "high")["where"], "/docs/notes.docx:word/document.xml:1")

    def test_macros(self):
        res = self.scan("/docs/m.docx", self.docx("hi", [("word/vbaProject.bin", b"\xd0\xcf\x11\xe0junk")]))
        self.assertEqual((res.state, res.severity), ("flagged", "medium"))
        self.finding(res, "document_active", "medium", "macros")

    def test_legacy_doc_strings(self):
        data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 500 + b"Password: hunter2xyz\0\0" + b"\0" * 100
        res = self.scan("/docs/old.doc", data)
        self.finding(res, "password", "medium")


class Antivirus(Base):
    def test_parse_defender(self):
        self.assertEqual(scan.parse_defender(DEFENDER_THREAT_OUT),
                         ["Trojan:Win32/Synthetic.A!test", "HackTool:Win32/Synthetic.B"])
        self.assertEqual(scan.parse_defender("Scan starting...\nScan finished.\nfound no threats.\n"), [])
        self.assertEqual(scan.parse_defender(None), [])

    def test_defender_threat_flags(self):
        calls = []

        def run(cmd, timeout, **kw):
            calls.append(cmd)
            return result(rc=2, out=DEFENDER_THREAT_OUT)
        with mock.patch.object(sandbox, "run", run):
            res = self.scan("/bin/setup.exe", b"MZ" + b"\0" * 100, tools=dict(NO_TOOLS, mpcmdrun=FAKE_MPCMD))
        self.assertEqual((res.state, res.severity), ("flagged", "high"))
        self.finding(res, "av_threat", "high", "Trojan:Win32/Synthetic.A!test")
        self.assertEqual(res.engines["av"], ["defender 4.18.99-0"])
        self.assertEqual(calls[0][1:5], ["-Scan", "-ScanType", "3", "-File"])
        self.assertEqual(calls[0][-1], "-DisableRemediation")

    def test_clamav_parsing(self):
        def run(cmd, timeout, **kw):
            if "--version" in cmd:
                return result(out="ClamAV 1.3.1/27000/Mon Jan  1 2024\n")
            return result(rc=1, out="C:\\x\\a.bin: Win.Test.Synthetic-1 FOUND\n")
        tools = dict(NO_TOOLS, clamscan=r"C:\ClamAV\clamscan.exe")
        with mock.patch.object(sandbox, "run", run):
            r = scan.av_scan(self.put("/a.bin", b"x"), self.conf, tools)
        self.assertEqual((r["ok"], r["threats"], r["engine"]), (True, ["Win.Test.Synthetic-1"], "clamav 1.3.1"))

    def test_av_error_is_transient(self):
        with mock.patch.object(sandbox, "run", lambda cmd, timeout, **kw: result(rc=5, out="Error 0x80508023")):
            res = self.scan("/bin/tool.exe", b"MZ", tools=dict(NO_TOOLS, mpcmdrun=FAKE_MPCMD))
        self.assertEqual((res.state, res.error_kind), ("error", "av_error"))
        self.assertIn("rc=5", res.engines["error"])

    def test_no_engine_required(self):
        conf = copy.deepcopy(self.conf)
        conf["scan"]["require_av"] = True
        res = self.scan("/bin/tool.exe", b"MZ", conf=conf)
        self.assertEqual((res.state, res.engines["av"]), ("flagged", "missing"))
        self.finding(res, "unscannable", "medium", "no engine")
        self.assertEqual(self.scan("/bin/tool2.exe", b"MZ").state, "clean")      # require_av off

    def test_no_engine_result(self):
        r = scan.av_scan(self.put("/a.bin", b"x"), self.conf, NO_TOOLS)
        self.assertEqual((r["engine"], r["ok"], r["threats"]), (None, False, []))

    @unittest.skipUnless(REAL_MPCMD, "Microsoft Defender (MpCmdRun) not found")
    def test_real_defender_clean_file(self):
        p = self.put("/clean.txt", "An ordinary text file with nothing in it.\n")
        r = scan.av_scan(p, self.conf, dict(NO_TOOLS, mpcmdrun=REAL_MPCMD))
        self.assertEqual((r["ok"], r["threats"], r["error"]), (True, [], None), r)
        self.assertTrue(r["engine"].startswith("defender"))

    @unittest.skipUnless(REAL_MPCMD, "Microsoft Defender (MpCmdRun) not found")
    def test_real_defender_clean_archive(self):
        conf = copy.deepcopy(self.conf)
        conf["scan"]["require_av"] = True
        res = self.scan("/dl/ok.zip", zip_bytes([("a.txt", "hello"), ("b/c.md", "# notes")]), conf=conf,
                        tools=dict(NO_TOOLS, mpcmdrun=REAL_MPCMD))
        self.assertEqual((res.state, res.findings, res.error_kind), ("clean", [], None), res.engines)
        self.assertTrue(res.engines["av"][0].startswith("defender"))


class Robustness(Base):
    def test_missing_file_and_directory(self):
        res = scan.scan_file(os.path.join(self.tmp, "nope.txt"), "/nope.txt", self.conf, NO_TOOLS)
        self.assertEqual((res.state, res.error_kind), ("error", "not_found"))
        res = scan.scan_file(self.tmp, "/dir.txt", self.conf, NO_TOOLS)
        self.assertEqual((res.state, res.error_kind), ("error", "not_found"))

    def test_bad_inputs_never_raise(self):
        box = os.path.join(self.cache, "sandbox", "bad")
        os.makedirs(box)
        for full, name, conf in ((None, "/x.txt", self.conf), (12345, None, self.conf),
                                 (self.put("/a.txt", "x"), "/a.txt", "not a dict"),
                                 (self.put("/b.txt", "x"), "/b.txt", {"scan": "broken"})):
            with self.subTest(full=full, conf=type(conf).__name__):
                res = scan.scan_file(full, name, conf, NO_TOOLS, sandbox_dir=box)
                self.assertEqual((res.state, res.error_kind), ("error", "exception"))
                self.assertIsInstance(res.as_dict(), dict)
                self.assertFalse(os.path.exists(box))
                os.makedirs(box)

    def test_sandbox_removed_after_crash(self):
        with mock.patch.object(scan, "_scan_one", side_effect=RuntimeError("boom")):
            res = self.scan("/a.txt", "hello")
        self.assertEqual((res.state, res.error_kind), ("error", "exception"))
        self.assertIn("RuntimeError: boom", res.engines["error"])
        with mock.patch.object(scan, "_scan_one", side_effect=MemoryError()):
            self.assertEqual(self.scan("/b.txt", "hello").error_kind, "memory")

    def test_sandbox_created_early_is_removed(self):
        box = os.path.join(self.cache, "sandbox", "pre")
        os.makedirs(os.path.join(box, "leftover"))
        res = scan.scan_file(self.put("/c.txt", "hello"), "/c.txt", self.conf, NO_TOOLS, sandbox_dir=box)
        self.assertEqual(res.state, "clean")
        self.assertFalse(os.path.exists(box))

    def test_never_deletes_a_root(self):
        with mock.patch.object(sandbox, "rmtree") as rm:
            note = scan._drop_sandbox(os.path.abspath(os.sep))
        rm.assert_not_called()
        self.assertIn("refused", note)

    def test_cancel(self):
        res = self.scan("/a.txt", "hello", cancel=lambda: True)
        self.assertEqual((res.state, res.error_kind), ("error", "cancelled"))
        calls = []

        def later():
            calls.append(1)
            return len(calls) > 2
        res = self.scan("/dl/many.zip", zip_bytes([("f%02d.txt" % i, "x") for i in range(20)]), cancel=later)
        self.assertEqual((res.state, res.error_kind), ("error", "cancelled"))

    def test_cancel_keeps_a_hold(self):
        calls = []

        def later():
            calls.append(1)
            return len(calls) > 3
        res = self.scan("/dl/m.zip", zip_bytes([("a/.env", "x=1")] + [("f%02d.txt" % i, "x") for i in range(20)]),
                        cancel=later)
        self.assertEqual((res.state, res.error_kind), ("flagged", "cancelled"))      # enough found to hold

    def test_timeout(self):
        conf = copy.deepcopy(self.conf)
        conf["scan"]["timeout_s"] = -1            # deadline already passed
        res = self.scan("/a.txt", "hello", conf=conf)
        self.assertEqual((res.state, res.error_kind), ("error", "timeout"))
        res = self.scan("/dl/a.zip", zip_bytes([("a.txt", "x")]), conf=conf)
        self.assertEqual((res.state, res.error_kind), ("error", "timeout"))

    def test_low_disk_is_retryable(self):
        conf = copy.deepcopy(self.conf)
        conf["scan"]["archive"]["min_free_bytes"] = 1 << 60
        res = self.scan("/dl/a.zip", zip_bytes([("a.txt", "x")]), conf=conf)
        self.assertEqual((res.state, res.error_kind), ("error", "disk_low"))

    def test_result_shape(self):
        res = self.scan("/a.txt", "hello")
        self.assertEqual(set(res.as_dict()), {"state", "severity", "findings", "engines", "secs", "error_kind"})
        self.assertIn("ScanResult(clean", repr(res))

    def test_findings_capped(self):
        text = "\n".join("token ghp_%s mail u%d@corp%d.io" % (self.g.s(36), i, i) for i in range(400))
        res = self.scan("/many.txt", text)
        self.assertLessEqual(len(res.findings), scan.MAX_FINDINGS)
        self.assertEqual(res.findings[0]["severity"], "high")


if __name__ == "__main__":
    unittest.main()
