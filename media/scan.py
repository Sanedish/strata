"""Strata Media scan dispatcher: OCR, PDF, archives, documents, text and AV engines (DESIGN.md 7.3, 7.4).

The worker calls scan_file() for every gated file before it may be published (new files) or while it keeps being
served (legacy files); the verdict decides whether the gate holds it back from the CDN. Principles:
  * nothing unscanned is published silently: when a category needs a tool that is missing (tesseract with
    ocr.required, an AV engine with scan.require_av, pypdfium2, 7-Zip for rar/7z) the file gets an "unscannable"
    medium finding, i.e. it is held, and `engines` records what did and did not run;
  * transient trouble (AV or OCR failure, timeout, cancel, low sandbox disk) gives state "error" so the worker
    retries - unless what was already found is enough to hold the file, then it is "flagged" right away;
  * every external tool runs through sandbox.run (Job Object, idle priority, CPU and memory caps, timeouts
    bounded by scan.timeout_s); archives are unpacked only inside the per-job sandbox dir, which is always
    deleted afterwards; documents are read part by part from the zip container, never extracted;
  * findings are redacted by detect.py; this module never logs or returns file content.
"""
import codecs
import html
import mmap
import os
import re
import tempfile
import time
import zipfile

import config
import detect
import extract
import sandbox

WEB_EXT = frozenset("html htm js mjs css map json webmanifest".split())   # hold only on high findings
MAX_FINDINGS = 200                 # stored per verdict; the most severe are kept
DOC_PART_MAX = 32 << 20            # decompressed bytes read from one OOXML/ODF/EPUB part
DOC_MAX_PARTS = 20000
_DOC_TEXT = re.compile(r"\.(?:xml|rels|xhtml|html?|opf|ncx|txt|vml|svg)$", re.I)
_DOC_BREAK = re.compile(r"</(?:w:p|a:p|text:p|text:h|p|div|li|tr|td|h[1-6]|si|row|c|title)>"
                        r"|<(?:w:br|w:tab|w:cr|text:line-break|text:tab|text:s|br)\b[^>]*>", re.I)
_TAG = re.compile(r"<[^>]*>")
_EXT_REL = re.compile(rb"<Relationship\b[^>]*>", re.I)
_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_U16 = lambda s: s.encode("utf-16-le")          # noqa: E731
_VBA_MARKERS = (_U16("_VBA_PROJECT"), b"_VBA_PROJECT", b"vbaProject.bin")     # OLE stream names of macros
_ENCRYPTED_OOXML = _U16("EncryptionInfo")
_SVG_GEOM = re.compile(r"""\s(?:d|points|transform|viewBox|[xy][12]?|[cdf][xy]|rx?|ry|width|height|offset|values"""
                       r"""|path|stroke-dash(?:array|offset)|key(?:Times|Splines|Points)|gradientTransform"""
                       r"""|patternTransform)\s*=\s*(?:"[^"]*"|'[^']*')""", re.I)
_SVG_DATA = re.compile(r"data:[\w/+.-]+;base64,[A-Za-z0-9+/=\s]{64,}")
_DEFENDER_THREAT = re.compile(r"(?mi)^\s*Threat\s*:\s*(\S.*?)\s*$")
_CLAM_FOUND = re.compile(r"(?m)^.*?:\s+(\S.*?)\s+FOUND\s*$")
_versions = {}


class ScanResult:
    """state: clean | flagged | error; severity: none|low|medium|high; findings: redacted dicts; engines: what ran
    ({"ocr": "tesseract 5.x"|"missing"|"skipped", "av": [...]|"missing", "pdf": ..., "archive": ...});
    secs; error_kind: None | not_found | timeout | cancelled | av_error | ocr_error | ocr_timeout | disk_low |
    memory | exception."""
    __slots__ = ("state", "severity", "findings", "engines", "secs", "error_kind")

    def __init__(self, state, severity="none", findings=None, engines=None, secs=0.0, error_kind=None):
        self.state, self.severity, self.findings = state, severity, findings or []
        self.engines, self.secs, self.error_kind = engines or {}, secs, error_kind

    def as_dict(self):
        return {k: getattr(self, k) for k in self.__slots__}

    def __repr__(self):
        return "ScanResult(%s, %s, %d findings, %.2fs, %s)" % (self.state, self.severity, len(self.findings),
                                                              self.secs, self.error_kind)


class _Stop(Exception):
    def __init__(self, kind, detail=""):
        super().__init__(kind)
        self.kind, self.detail = kind, detail


class _Ctx:
    def __init__(self, conf, tools, cancel, t0, sandbox_dir=None):
        self.conf, self.tools, self.cancel, self.sandbox_dir = conf, tools or {}, cancel, sandbox_dir
        self.s = conf.get("scan") or {}
        self.o = conf.get("ocr") or {}
        self.arc = self.s.get("archive") or {}
        self.deadline = t0 + float(self.s.get("timeout_s") or 1800)
        self.findings, self.engines, self.retry = [], {}, None
        self.ocr_images, self.text_budget = 0, int(self.arc.get("text_bytes") or 64 << 20)
        self.ocr_missing_noted = False

    def add(self, fs):
        self.findings.extend(fs)

    def check(self):
        if self.cancel is not None and self.cancel():
            raise _Stop("cancelled")
        if time.monotonic() > self.deadline:
            raise _Stop("timeout")

    def left(self, cap=None):
        left = self.deadline - time.monotonic()
        if left <= 1:
            raise _Stop("timeout")
        return min(left, cap) if cap else left

    def transient(self, kind, detail=""):
        if self.retry is None:
            self.retry = (kind, detail)

    def count(self, key, n=1):
        self.engines[key] = self.engines.get(key, 0) + n

    def tmp_dir(self):
        """Where OCR tiles go: inside the job's sandbox dir when there is one (deleted with it)."""
        if self.sandbox_dir:
            os.makedirs(self.sandbox_dir, exist_ok=True)
            return self.sandbox_dir
        return None


def _unscannable(why, where):
    return detect.finding("unscannable", "medium", why, where, "high")


def _tmp_root(conf):
    d = os.path.join(conf.get("cache_root") or "", "sandbox")
    return d if conf.get("cache_root") and os.path.isdir(d) else None


# ---------------------------------------------------------------- AV

def _tool_version(key, exe, args, rx, label):
    v = _versions.get((key, exe))
    if v is None:
        v = label
        if key == "defender":      # the platform dir carries the version: ...\Platform\4.18.x-0\MpCmdRun.exe
            m = re.search(r"[\\/]Platform[\\/]([\d.]+(?:-\d+)?)[\\/]", exe, re.I)
            v = "%s %s" % (label, m.group(1)) if m else label
        else:
            r = sandbox.run([exe] + args, timeout=20, mem_mb=256, cpu_pct=35)
            m = re.search(rx, (r.out or "") + (r.err or ""), re.I)
            v = "%s %s" % (label, m.group(1)) if m else label
        _versions[(key, exe)] = v
    return v


def parse_defender(text):
    """Threat names from MpCmdRun -Scan output ("Threat                  : Trojan:Win32/Foo")."""
    return list(dict.fromkeys(_DEFENDER_THREAT.findall(text or "")))


def _defender(exe, path, timeout):
    eng = _tool_version("defender", exe, None, None, "defender")
    r = sandbox.run([exe, "-Scan", "-ScanType", "3", "-File", os.path.abspath(path), "-DisableRemediation"],
                    timeout=timeout, mem_mb=512, cpu_pct=35, priority="idle")
    out = (r.out or "") + "\n" + (r.err or "")
    res = {"engine": eng, "ok": False, "threats": [], "error": None}
    if r.timed_out:
        res["error"] = "defender: timeout"
    elif r.killed:
        res["error"] = "defender: %s" % r.killed
    elif r.rc == 0:
        res["ok"] = True
    elif r.rc == 2:
        res["ok"], res["threats"] = True, parse_defender(out) or ["Defender: unnamed threat"]
    else:
        tail = [ln.strip() for ln in out.splitlines() if ln.strip()][-2:]
        res["error"] = "defender rc=%s: %s" % (r.rc, " / ".join(tail)[:200])
    return res


def _clamav(tools, path, timeout):
    res = {"engine": "clamav", "ok": False, "threats": [], "error": None}
    attempts = []
    if tools.get("clamdscan"):
        attempts.append([tools["clamdscan"], "--no-summary", "--infected", "--multiscan", "--fdpass", path])
    if tools.get("clamscan"):
        attempts.append([tools["clamscan"], "--no-summary", "--infected", "--recursive", "--max-filesize=4000M",
                         "--max-scansize=4000M", path])
    for cmd in attempts:
        res["engine"] = _tool_version("clamav", cmd[0], ["--version"], r"ClamAV\s+([\d.]+)", "clamav")
        r = sandbox.run(cmd, timeout=timeout, mem_mb=3072, cpu_pct=35, priority="idle")
        if r.timed_out or r.killed:
            res["error"] = "clamav: %s" % (r.killed or "timeout")
        elif r.rc == 0:
            res.update(ok=True, error=None)
            return res
        elif r.rc == 1:
            res.update(ok=True, error=None, threats=list(dict.fromkeys(_CLAM_FOUND.findall(r.out or ""))) or
                       ["ClamAV: unnamed threat"])
            return res
        else:  # 2 = error (e.g. clamd not running): fall back to clamscan if we have it
            res["error"] = "clamav rc=%s: %s" % (r.rc, ((r.err or r.out or "").strip().splitlines() or [""])[-1][:160])
    return res


def av_scan(path, conf, tools, timeout=None):
    """Scan a file or a directory with every configured, available engine (scan.av_engines: defender, clamav).
    {"engine": "defender 4.18..., clamav 1.x" | None, "ok": at least one engine completed, "threats": [...],
    "error": str | None, "engines": [per-engine results]}. engine None = no engine available."""
    conf = conf or {}
    s = conf.get("scan") or {}
    tools = tools if tools is not None else sandbox.tools(conf)
    timeout = float(timeout or min(900.0, float(s.get("timeout_s") or 1800)))
    runs = []
    for eng in s.get("av_engines") or ("defender", "clamav"):
        if eng == "defender" and tools.get("mpcmdrun"):
            runs.append(_defender(tools["mpcmdrun"], path, timeout))
        elif eng == "clamav" and (tools.get("clamdscan") or tools.get("clamscan")):
            runs.append(_clamav(tools, path, timeout))
    if not runs:
        return {"engine": None, "ok": False, "threats": [], "error": "no antivirus engine available", "engines": []}
    errors = [r["error"] for r in runs if r["error"]]
    return {"engine": ", ".join(r["engine"] for r in runs), "ok": any(r["ok"] for r in runs),
            "threats": list(dict.fromkeys(t for r in runs for t in r["threats"])),
            "error": "; ".join(errors) if errors else None, "engines": runs}


def _av(ctx, path, where):
    res = av_scan(path, ctx.conf, ctx.tools, timeout=ctx.left(900.0))
    if res["engine"] is None:
        ctx.engines["av"] = "missing"
        if ctx.s.get("require_av", True):
            ctx.add([_unscannable("antivirus scan required but no engine is available", where)])
        return
    names = [r["engine"] for r in res["engines"]]
    prev = ctx.engines.get("av")
    ctx.engines["av"] = list(dict.fromkeys((prev if isinstance(prev, list) else []) + names))
    ctx.add([detect.finding("av_threat", "high", t, where, "high") for t in res["threats"]])
    if not res["ok"]:
        ctx.transient("av_error", res["error"])


# ---------------------------------------------------------------- OCR

def _prep(im, o):
    """Grayscale (transparency flattened onto a background that contrasts with the content), downscaled beyond
    ocr.max_mp, upscaled x2 when small (tesseract wants ~30 px glyphs)."""
    from PIL import Image, ImageStat
    if im.mode in ("RGBA", "LA", "PA") or (im.mode == "P" and "transparency" in im.info):
        rgba = im.convert("RGBA")
        alpha = rgba.getchannel("A")
        gray = rgba.convert("L")
        mean = ImageStat.Stat(gray, mask=alpha).mean[0] if alpha.getbbox() else 0.0
        g = Image.new("L", rgba.size, 0 if mean > 160 else 255)   # light text on transparency -> dark background
        g.paste(gray, mask=alpha)
    else:
        g = im.convert("L")
    w, h = g.size
    max_px = float(o.get("max_mp") or 60) * 1e6
    if w * h > max_px:
        s = (max_px / (w * h)) ** 0.5
        g = g.resize((max(1, int(w * s)), max(1, int(h * s))), Image.BILINEAR)
    elif max(w, h) < 1000:
        g = g.resize((w * 2, h * 2), Image.BICUBIC)
    return g


def _tiles(g, tile_px, overlap=120):
    w, h = g.size
    if w <= tile_px and h <= tile_px:
        return [g]

    def starts(n):
        return [0] if n <= tile_px else list(range(0, n - tile_px, tile_px - overlap)) + [n - tile_px]
    return [g.crop((x, y, min(x + tile_px, w), min(y + tile_px, h))) for y in starts(h) for x in starts(w)]


def _frames(img):
    """Animated images: the first frame plus up to 4 evenly spaced ones."""
    n = int(getattr(img, "n_frames", 1) or 1)
    if n <= 1:
        return [img]
    out = []
    for i in sorted({0} | {round(k * (n - 1) / 4) for k in range(1, 5)}):
        img.seek(i)
        out.append(img.convert("RGBA"))
    img.seek(0)
    return out


def ocr_image(img_or_path, conf, tools, where="", timeout=None, tmp_dir=None):
    """OCR text of an image (PIL image or path) with tesseract inside sandbox.run (OMP_THREAD_LIMIT=1, idle).
    Returns (text, info) with info {"engine", "status": ok|missing|skipped|timeout|error, "tiles", "frames",
    "secs"}; all tiles go through one tesseract process (list file), so traineddata is loaded once. Tiles are
    written to a private temp dir (under tmp_dir, else <cache_root>/sandbox) that is always removed."""
    conf = conf or {}
    o = conf.get("ocr") or {}
    exe = (tools or {}).get("tesseract")
    info = {"engine": "missing", "status": "missing", "tiles": 0, "frames": 0, "secs": 0.0}
    if not exe:
        return "", info
    from PIL import Image
    t0 = time.monotonic()
    info["engine"] = _tool_version("tesseract", exe, ["--version"], r"tesseract\s+v?(\d[\w.\-]*)", "tesseract")
    own = None
    img = img_or_path
    if not hasattr(img, "size"):
        img = own = Image.open(img_or_path)
    tmp = None
    try:
        if min(img.size) < int(o.get("min_side") or 48):
            info["status"] = "skipped"
            return "", info
        tmp = tempfile.mkdtemp(prefix="strata-ocr-", dir=tmp_dir or _tmp_root(conf))
        paths = []
        frames = _frames(img)
        info["frames"] = len(frames)
        for fr in frames:
            for tile in _tiles(_prep(fr, o), int(o.get("tile_px") or 2400)):
                p = os.path.join(tmp, "t%03d.png" % len(paths))
                tile.save(p, "PNG", compress_level=1)
                paths.append(p)
        info["tiles"] = len(paths)
        listing = os.path.join(tmp, "tiles.txt")
        with open(listing, "w", encoding="utf-8") as f:
            f.write("\n".join(paths) + "\n")
        env = dict(os.environ)
        env["OMP_THREAD_LIMIT"] = "1"
        cmd = [exe, listing, "stdout", "-l", str(o.get("langs") or "eng"), "--psm", str(int(o.get("psm") or 3))]
        r = sandbox.run(cmd, timeout=float(timeout or o.get("timeout_s") or 180), mem_mb=1024, cpu_pct=35,
                        priority="idle", cwd=tmp, env=env)
        info["secs"] = round(time.monotonic() - t0, 2)
        if r.timed_out:
            info["status"] = "timeout"
            return "", info
        if r.rc != 0 or r.killed:
            info["status"], info["error"] = "error", ((r.err or "").strip()[-200:] or "rc=%s" % r.rc)
            return "", info
        info["status"] = "ok"
        return r.out or "", info
    finally:
        if tmp:
            try:
                sandbox.rmtree(tmp)
            except OSError:
                pass
        if own is not None:
            own.close()


def _ocr_into(ctx, img, where):
    """OCR one image/page into findings; handles missing tesseract (7.4) and transient failures."""
    required = bool(ctx.o.get("required", True))
    if not ctx.tools.get("tesseract"):
        ctx.engines["ocr"] = "missing" if required else "skipped"
        if required and not ctx.ocr_missing_noted:
            ctx.ocr_missing_noted = True
            ctx.add([_unscannable("OCR required but tesseract is missing", where)])
        return
    text, info = ocr_image(img, ctx.conf, ctx.tools, where, timeout=ctx.left(float(ctx.o.get("timeout_s") or 180)),
                           tmp_dir=ctx.tmp_dir())
    if info["status"] == "skipped":
        ctx.engines.setdefault("ocr", "skipped")
        return
    ctx.engines["ocr"] = info["engine"]
    if info["status"] in ("timeout", "error"):
        ctx.transient("ocr_" + info["status"], info.get("error", ""))
        return
    ctx.add(detect.scan_text(text, where, ctx.conf, ocr=True))


# ---------------------------------------------------------------- per category

def _decode(data):
    if data.startswith(codecs.BOM_UTF8):
        return data[3:].decode("utf-8", "replace")
    if data[:2] in (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE):
        return data.decode("utf-16", "replace")
    if len(data) >= 64 and data.count(b"\x00") > len(data) // 3:
        return _strings(data)     # UTF-16 without BOM, or binary: printable runs cover both
    return data.decode("utf-8", "replace")


def _strings(data, min_len=6):
    """Printable ASCII and UTF-16LE runs (legacy Office / RTF / binary files)."""
    a = re.findall(rb"[\x20-\x7e\t]{%d,}" % min_len, data)
    u = re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, data)
    return "\n".join([s.decode("ascii") for s in a] + [s.decode("utf-16-le", "replace") for s in u])


def _read(path, limit):
    with open(extract.long_path(path), "rb") as f:
        return f.read(max(0, int(limit)))


def _looks_text(path):
    try:
        head = _read(path, 8192)
    except OSError:
        return False
    if not head or b"\x00" in head:
        return False
    bad = sum(1 for b in head if b < 32 and b not in (9, 10, 12, 13))
    return bad * 50 < len(head)


def _image_meta_text(img):
    """Text people hide in image metadata: PNG tEXt/iTXt (e.g. generation parameters), comments, XMP, EXIF
    description / user comment / XP* fields."""
    parts = []
    for k, v in (img.info or {}).items():
        if isinstance(v, bytes) and k in ("xmp", "XML:com.adobe.xmp", "comment", "Comment"):
            v = v.decode("utf-8", "replace")
        if isinstance(v, str) and len(v) >= 8:
            parts.append(v)
    try:
        exif = img.getexif()
        tags = [exif.get(t) for t in (0x010E, 0x013B, 0x8298, 0x9C9B, 0x9C9C, 0x9C9D, 0x9C9E, 0x9C9F)]
        tags.append(exif.get_ifd(0x8769).get(0x9286))           # UserComment lives in the Exif sub-IFD
        for v in tags:
            if isinstance(v, bytes):
                v = v.decode("utf-16-le" if v[1:2] == b"\x00" else "utf-8", "replace").strip("\x00")
            if isinstance(v, str) and len(v.strip()) >= 8:
                parts.append(v)
    except Exception:
        pass
    return "\n".join(parts)[:1 << 20]


def _scan_image(ctx, path, where, inner=False):
    from PIL import Image
    try:
        img = Image.open(extract.long_path(path))
    except Exception as e:  # unknown format (heic/jxl without plugin), truncated, decompression bomb
        ctx.add([_unscannable("image cannot be decoded by the scanner (%s)" % e.__class__.__name__, where)])
        return
    with img:
        ctx.add(detect.exif_findings(img, ctx.conf, where))
        meta = _image_meta_text(img)
        if meta:
            ctx.add(detect.scan_text(meta, where + " (metadata)", ctx.conf))
        if inner:
            if ctx.ocr_images >= int(ctx.arc.get("ocr_images") or 25):
                ctx.count("ocr_images_skipped")
                return
            ctx.ocr_images += 1
        try:
            _ocr_into(ctx, img, where)
        except (OSError, ValueError, SyntaxError) as e:   # decode errors surface on first pixel access
            ctx.add([_unscannable("image cannot be decoded by the scanner (%s)" % e.__class__.__name__, where)])


def _scan_svg(ctx, path, where):
    text = _decode(_read(path, int(ctx.s.get("text_max_bytes") or 8 << 20)))
    ctx.add(detect.svg_findings(text, where))
    # geometry ("L 93.18.21.34" = three numbers, not an IP) and inline data: blobs are not text anyone reads
    ctx.add(detect.scan_text(_SVG_DATA.sub(" ", _SVG_GEOM.sub(" ", text)), where, ctx.conf))


def _scan_text(ctx, path, where, web, limit):
    size = os.path.getsize(extract.long_path(path))
    if size > limit:
        ctx.engines["text"] = "first %d of %d bytes" % (limit, size)
    ctx.add(detect.scan_text(_decode(_read(path, limit)), where, ctx.conf, web_asset=web))


def _pdfium():
    try:
        import pypdfium2
        return pypdfium2
    except Exception:
        return None


def _scan_pdf(ctx, path, where):
    names = set()
    if os.path.getsize(extract.long_path(path)):
        with open(extract.long_path(path), "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            names = detect.pdf_names(mm)
    ctx.add(detect.pdf_active_findings(None, where, names=names))
    pdfium = _pdfium()
    if pdfium is None:
        ctx.engines["pdf"] = "missing"
        ctx.add([_unscannable("PDF text not scanned: pypdfium2 missing", where)])
        if detect.pdf_encrypted(names=names):
            ctx.add([_unscannable("encrypted PDF", where)])
        return
    ctx.engines["pdf"] = "pypdfium2 %s" % (getattr(pdfium, "V_PYPDFIUM2", "") or getattr(pdfium, "__version__", ""))
    try:
        doc = pdfium.PdfDocument(extract.long_path(path))
    except Exception as e:
        msg = str(e)
        why = "password-protected PDF" if "password" in msg.lower() else "PDF cannot be parsed (%s)" % msg[:100]
        ctx.add([_unscannable(why, where)])
        return
    p = ctx.s.get("pdf") or {}
    max_pages, ocr_left, dpi = int(p.get("max_pages") or 300), int(p.get("ocr_pages") or 30), float(p.get("dpi") or 170)
    try:
        n = len(doc)
        if n > max_pages:
            ctx.engines["pdf_pages"] = "%d of %d" % (max_pages, n)
        for i in range(min(n, max_pages)):
            ctx.check()
            page = doc[i]
            pw = "%s p%d" % (where, i + 1)
            try:
                tp = page.get_textpage()
                try:
                    text = (getattr(tp, "get_text_range", None) or tp.get_text_bounded)()
                finally:
                    tp.close()
                if len(text.strip()) >= 20:
                    ctx.add(detect.scan_text(text, pw, ctx.conf))
                elif ocr_left > 0:        # scanned page: render and OCR it
                    ocr_left -= 1
                    if not ctx.tools.get("tesseract"):
                        _ocr_into(ctx, None, pw)
                        continue
                    bitmap = page.render(scale=dpi / 72.0)
                    try:
                        img = bitmap.to_pil()
                    finally:
                        getattr(bitmap, "close", lambda: None)()
                    _ocr_into(ctx, img, pw)
                else:
                    ctx.count("pdf_ocr_pages_skipped")
            finally:
                page.close()
    finally:
        doc.close()


def _read_member(zf, info, cap):
    out = bytearray()
    with zf.open(info) as f:
        while len(out) < cap:
            b = f.read(min(1 << 20, cap - len(out)))
            if not b:
                break
            out += b
    return bytes(out)


def _xml_text(data):
    s = data.decode("utf-8", "replace")
    return html.unescape(_TAG.sub("", _DOC_BREAK.sub("\n", s)))


def _scan_zipdoc(ctx, path, where):
    """OOXML / ODF / EPUB: XML parts read straight from the zip (bounded), tags stripped, detectors; macros,
    remote templates and embedded objects reported."""
    budget = int(ctx.s.get("text_max_bytes") or 8 << 20)
    try:
        zf = zipfile.ZipFile(extract.long_path(path))
    except (zipfile.BadZipFile, OSError, ValueError, NotImplementedError) as e:
        ctx.add([_unscannable("document container unreadable (%s)" % e.__class__.__name__, where)])
        return
    with zf:
        infos = zf.infolist()
        if len(infos) > DOC_MAX_PARTS:
            ctx.add([_unscannable("document has %d parts" % len(infos), where)])
            return
        macros = embedded = False
        for info in infos:
            ctx.check()
            name, low = info.filename, info.filename.lower()
            base = low.rsplit("/", 1)[-1]
            if base.startswith("vbaproject") or (low.startswith("basic/") and base not in ("script-lc.xml",
                                                                                         "script-lb.xml")):
                macros = True
            if "/embeddings/" in low or low.startswith("embeddings/") or base.startswith("oleobject"):
                embedded = True
            if not _DOC_TEXT.search(low) or budget <= 0:
                continue
            if info.flag_bits & 1:
                ctx.add([_unscannable("encrypted document part", "%s:%s" % (where, name))])
                continue
            try:
                data = _read_member(zf, info, min(DOC_PART_MAX, budget))
            except (zipfile.BadZipFile, EOFError, ValueError, NotImplementedError, RuntimeError, OSError) as e:
                ctx.add([_unscannable("corrupt document part (%s)" % e.__class__.__name__, "%s:%s" % (where, name))])
                continue
            budget -= len(data)
            pw = "%s:%s" % (where, name)
            if low.endswith(".rels"):
                for rel in _EXT_REL.findall(data):
                    if b'TargetMode="External"' in rel and re.search(rb"/(attachedTemplate|oleObject|subDocument|frame)\"",
                                                                      rel):
                        ctx.add([detect.finding("document_active", "medium", "remote template or object", pw)])
                ctx.add(detect.scan_text(data.decode("utf-8", "replace"), pw, ctx.conf))   # targets live in attributes
                continue
            ctx.add(detect.scan_text(_xml_text(data), pw, ctx.conf))
        if macros:
            ctx.add([detect.finding("document_active", "medium", "macros (VBA/Basic)", where, "high")])
        if embedded:
            ctx.add([detect.finding("document_active", "low", "embedded OLE object", where, "high")])
        if budget <= 0:
            ctx.engines["document"] = "text budget exhausted"


def _scan_document(ctx, path, where):
    with open(extract.long_path(path), "rb") as f:
        head = f.read(8)
    if head.startswith(b"PK"):
        _scan_zipdoc(ctx, path, where)
        return
    data = _read(path, int(ctx.s.get("text_max_bytes") or 8 << 20))
    if head == _OLE and _ENCRYPTED_OOXML in data:
        ctx.add([_unscannable("encrypted Office document", where)])
        return
    if any(m in data for m in _VBA_MARKERS):
        ctx.add([detect.finding("document_active", "medium", "macros (VBA)", where, "high")])
    if data[:5] == b"{\\rtf" and re.search(rb"\\objdata|\\object(?:emb|link|ocx|autlink)", data):
        ctx.add([detect.finding("document_active", "medium", "embedded RTF object", where, "high")])
    ctx.add(detect.scan_text(_strings(data), where, ctx.conf))


def _scan_one(ctx, path, where, cat, size, inner):
    """Content checks for one file (no AV: the caller decides where AV runs)."""
    limit = int(ctx.s.get("text_max_bytes") or 8 << 20)
    if cat == "image":
        _scan_image(ctx, path, where, inner)
    elif cat == "svg":
        _scan_svg(ctx, path, where)
    elif cat == "pdf":
        _scan_pdf(ctx, path, where)
    elif cat == "document":
        _scan_document(ctx, path, where)
    elif cat == "text" or (inner and cat == "other" and _looks_text(path)):
        if inner:
            limit = min(limit, ctx.text_budget)
            if limit <= 0:
                ctx.count("archive_text_skipped")
                return
            ctx.text_budget -= min(limit, size)
        _scan_text(ctx, path, where, config.ext_of(where) in WEB_EXT, limit)


def _scan_archive(ctx, full, name, sandbox_dir):
    root = sandbox_dir or tempfile.mkdtemp(prefix="strata-scan-", dir=_tmp_root(ctx.conf))
    av = "archive" in (ctx.s.get("av_categories") or ())
    try:
        os.makedirs(root, exist_ok=True)
        if av:
            _av(ctx, full, name)          # engines unpack archives themselves, too
        try:
            res = extract.extract(full, root, ctx.conf, ctx.tools, cancel=ctx.cancel, deadline=ctx.deadline)
        except extract.BombError as e:
            ctx.add([detect.finding("archive_bomb", "high", str(e)[:200], name, "high")])
            return
        except extract.EncryptedError:
            ctx.add([_unscannable("encrypted archive", name)])
            return
        except extract.SpaceError as e:
            raise _Stop("disk_low", str(e))
        except extract.Timeout:
            raise _Stop("timeout")
        except extract.Cancelled:
            raise _Stop("cancelled")
        except extract.ArchiveError as e:
            ctx.add([_unscannable("archive unreadable: %s" % str(e)[:160], name)])
            return
        ctx.engines["archive"] = res["tool"]
        ctx.engines["archive_files"] = len(res["files"])
        for f in res["findings"]:
            ctx.add([dict(f, where="%s!/%s" % (name, f["where"]) if f["where"] else name)])
        for rel, _abs, _size in res["files"]:
            ctx.add(detect.name_findings(rel, ctx.conf, where="%s!/%s" % (name, rel)))
        if av and res["files"]:
            _av(ctx, root, name + " (extracted)")
        for rel, ab, size in res["files"]:
            ctx.check()
            cat = config.category(rel)
            if cat == "archive":          # nested archives were unpacked by extract (their members are listed)
                continue
            where = "%s!/%s" % (name, rel)
            try:
                _scan_one(ctx, ab, where, cat, size, inner=True)
            except OSError as e:          # e.g. real-time AV quarantined the member after extraction
                ctx.add([_unscannable("member vanished or unreadable (%s)" % e.__class__.__name__, where)])
    finally:
        try:
            sandbox.rmtree(root)
        except OSError as e:
            ctx.engines["sandbox_cleanup"] = "failed: %s" % str(e)[:120]


# ---------------------------------------------------------------- entry point

def scan_file(full, name, conf, tools, cancel=None, sandbox_dir=None):
    """Scan one file for the gate. name: the mount-relative path ("/general/photo.png") used for the category and
    as `where` in findings. tools: sandbox.tools(conf) (None = discover). cancel: callable, true = stop.
    sandbox_dir: the job's scratch dir (archives are unpacked and OCR tiles written there); it is deleted before
    this returns, whatever happened. Never raises: bad input or a crash gives state "error" with error_kind."""
    t0 = time.monotonic()
    ctx, web, error_kind, detail = None, False, None, None
    try:
        conf = conf if conf is not None else config.load()
        if not isinstance(conf, dict):
            raise TypeError("conf must be a dict")
        tools = tools if tools is not None else sandbox.tools(conf)
        ctx = _Ctx(conf, tools, cancel, t0, sandbox_dir)
        full = os.fspath(full)
        name = str(name or os.path.basename(full))
        cat = config.category(name)
        web = cat == "text" and config.ext_of(name) in WEB_EXT
        ctx.engines["category"] = cat
        ctx.check()
        if not os.path.isfile(extract.long_path(full)):
            raise _Stop("not_found")
        if cat == "archive":
            _scan_archive(ctx, full, name, sandbox_dir)
        else:
            _scan_one(ctx, full, name, cat, os.path.getsize(extract.long_path(full)), inner=False)
            if cat in (ctx.s.get("av_categories") or ()):
                _av(ctx, full, name)
    except _Stop as e:
        error_kind, detail = e.kind, e.detail
    except MemoryError:
        error_kind = "memory"
    except Exception as e:  # the worker retries, then records error (= held for new files)
        error_kind, detail = "exception", "%s: %s" % (e.__class__.__name__, str(e)[:200])
    finally:
        cleanup = _drop_sandbox(sandbox_dir)
    if ctx is None:
        engines = {"error": str(detail or error_kind)[:240]}
        return ScanResult("error", engines=engines, secs=round(time.monotonic() - t0, 3), error_kind=error_kind)
    if cleanup:
        ctx.engines["sandbox_cleanup"] = cleanup
    return _verdict(ctx, web, error_kind, detail, t0)


def _drop_sandbox(path):
    """Delete the job's sandbox dir; returns an error note or None. Never a drive or share root."""
    if not path:
        return None
    try:
        p = os.path.abspath(os.fspath(path))
        if os.path.dirname(p) == p:
            return "refused to delete %s" % p
        if os.path.lexists(p):
            sandbox.rmtree(p)
    except (OSError, TypeError, ValueError) as e:
        return "failed: %s" % str(e)[:120]
    return None


def _verdict(ctx, web, error_kind, detail, t0):
    fs = detect.dedupe(ctx.findings)
    fs.sort(key=lambda f: -detect.SEVERITY.get(f.get("severity"), 0))
    if len(fs) > MAX_FINDINGS:
        ctx.engines["findings_dropped"] = len(fs) - MAX_FINDINGS
        fs = fs[:MAX_FINDINGS]
    sev = detect.max_severity(fs)
    threshold = ctx.s.get("hold_threshold") or "medium"
    if web:  # public web assets often embed public keys: hold only on high
        threshold = "high"
    hold = (any(f.get("type") == "av_threat" for f in fs)
            or detect.SEVERITY.get(sev, 0) >= detect.SEVERITY.get(threshold, 2))
    if error_kind is None and ctx.retry:
        error_kind, detail = ctx.retry
    if detail:
        ctx.engines["error"] = str(detail)[:240]
    state = "flagged" if hold else ("error" if error_kind else "clean")
    return ScanResult(state, sev, fs, ctx.engines, round(time.monotonic() - t0, 3), error_kind)
