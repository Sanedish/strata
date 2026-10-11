"""Strata link-preview cards for everything that isn't audio (audio cards live in audiocard.py, which this reuses).

    folder     a gallery folder: a mosaic of its pictures, file count, size, last update
    archive    zip / tar: entry count, unpacked size and the top-level entries; 7z / rar: size only
    pdf        page count and title (read from the file, no renderer needed), a page drawn on the tile
    text       code and plain text: language, line count and the first lines on a dark tile
    warning    programs, scripts and installers: a red card with the file's SHA-256
    file       anything else: type, size and date

Images, videos and web pages never get here: the platforms embed those themselves (rules.PREVIEW_NATIVE).
Every card is drawn once per file version (folders: per listing) and cached next to the audio cards.
"""
import datetime
import hashlib
import html
import json
import mimetypes
import os
import re
import tarfile
import threading
import zipfile

import audiocard as A

VERSION = 1
S = A.S
_LOCK = threading.Semaphore(2)
IMAGE_EXT = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".avif"}
ARCHIVE_EXT = {".zip": "ZIP", ".tar": "TAR", ".tgz": "TAR.GZ", ".tbz2": "TAR.BZ2", ".txz": "TAR.XZ", ".7z": "7-ZIP",
               ".rar": "RAR"}
RISKY = {".exe": "Windows program", ".msi": "Windows installer", ".com": "Windows program", ".scr": "Screen saver program",
         ".bat": "Windows script", ".cmd": "Windows script", ".ps1": "PowerShell script", ".vbs": "VBScript",
         ".hta": "HTML application", ".jar": "Java program", ".apk": "Android app", ".dmg": "macOS disk image",
         ".pkg": "macOS installer", ".lnk": "Windows shortcut", ".reg": "Registry file", ".dll": "Windows library",
         ".sys": "Windows driver", ".appimage": "Linux program", ".deb": "Linux package", ".rpm": "Linux package"}
TEXT_EXT = {".txt": "Plain text", ".md": "Markdown", ".log": "Log file", ".csv": "CSV", ".tsv": "TSV", ".json": "JSON",
            ".yml": "YAML", ".yaml": "YAML", ".toml": "TOML", ".ini": "INI", ".cfg": "Config", ".conf": "Config",
            ".py": "Python", ".js": "JavaScript", ".mjs": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
            ".jsx": "JavaScript", ".css": "CSS", ".scss": "SCSS", ".c": "C", ".h": "C header", ".cpp": "C++",
            ".hpp": "C++ header", ".cs": "C#", ".java": "Java", ".kt": "Kotlin", ".go": "Go", ".rs": "Rust",
            ".rb": "Ruby", ".php": "PHP", ".lua": "Lua", ".sh": "Shell script", ".sql": "SQL", ".srt": "Subtitles",
            ".vtt": "Subtitles", ".gitignore": "Git ignore", ".dockerfile": "Dockerfile", ".swift": "Swift"}
PROSE = {".txt", ".md", ".log", ".srt", ".vtt"}
COMMENT = re.compile(r"^\s*(#|//|--|;|/\*|\*)")
RED_COLS = [(150, 22, 26), (64, 8, 12), (196, 44, 32)]
MONO = ["consola.ttf", "DejaVuSansMono.ttf"]


def human(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1000 or unit == "TB":
            return ("%d %s" % (n, unit)) if unit == "B" or n >= 100 else ("%.1f %s" % (n, unit))
        n /= 1000


def day(ts):
    return datetime.datetime.fromtimestamp(ts).strftime("%d %b %Y").lstrip("0") if ts else ""


def kind_of(path, is_dir=False):
    if is_dir:
        return "folder"
    ext = os.path.splitext(path)[1].lower() or os.path.basename(path).lower()
    if ext in RISKY:
        return "warning"
    if ext in ARCHIVE_EXT:
        return "archive"
    if ext == ".pdf":
        return "pdf"
    if ext in TEXT_EXT:
        return "text"
    return "file"


# ---------------------------------------------------------------- reading the files


def listing(path):
    """Top level of a folder: (files [(name, size, mtime)], folder names). Hidden entries are skipped."""
    files, dirs = [], []
    with os.scandir(path) as it:
        for e in it:
            if e.name.startswith("."):
                continue
            try:
                if e.is_dir():
                    dirs.append(e.name)
                elif e.is_file():
                    st = e.stat()
                    files.append((e.name, st.st_size, st.st_mtime))
            except OSError:
                continue
    files.sort(key=lambda f: f[0].lower())
    return files, sorted(dirs, key=str.lower)


def archive_info(path, ext):
    """{files, unpacked, top: [(name, size, is_dir)], encrypted} - None when the archive can't be read here."""
    top, second, files, unpacked, encrypted = {}, {}, 0, 0, False

    def add(name, size, is_dir):
        nonlocal files, unpacked
        name = name.replace("\\", "/").lstrip("/")
        if not name:
            return
        head, _, rest = name.partition("/")
        folder = bool(rest) or is_dir
        cur = top.setdefault(head, [0, folder])
        cur[1] = cur[1] or folder
        if rest.strip("/"):  # one level down, for archives that wrap everything in a single folder
            h2, _, r2 = rest.partition("/")
            c2 = second.setdefault(head, {}).setdefault(h2, [0, bool(r2) or is_dir])
            c2[1] = c2[1] or bool(r2) or is_dir
            if not is_dir:
                c2[0] += size
        if not is_dir:
            files += 1
            unpacked += size
            cur[0] += size

    if ext == ".zip":
        with zipfile.ZipFile(path) as z:
            for i in z.infolist():
                add(i.filename, i.file_size, i.is_dir())
                encrypted = encrypted or bool(i.flag_bits & 1)
    elif ext in (".tar", ".tgz", ".tbz2", ".txz"):
        with tarfile.open(path, "r:*") as t:
            for n, m in enumerate(t):
                if n > 50000:  # a huge tarball: count what was read, don't walk the rest of the drive
                    break
                add(m.name, m.size, m.isdir())
    else:
        return None
    items = sorted(((k, v[0], v[1]) for k, v in top.items()), key=lambda x: (not x[2], x[0].lower()))
    return {"files": files, "unpacked": unpacked, "top": items, "encrypted": encrypted, "second": second}


def pdf_info(path, size):
    """{pages, title} from the PDF's own structure (best effort: compressed object streams hide both)."""
    with open(path, "rb") as f:
        head = f.read(2 << 20)
        if size > 3 << 20:
            f.seek(max(0, size - (1 << 20)))
            head += f.read()
    counts = [int(c) for c in re.findall(rb"/Type\s*/Pages\b[^>]*?/Count\s+(\d+)", head)]
    counts += [int(c) for c in re.findall(rb"/Count\s+(\d+)[^>]*?/Type\s*/Pages\b", head)]
    pages = max(counts) if counts else len(re.findall(rb"/Type\s*/Page\b", head))
    title = ""
    m = re.search(rb"/Title\s*\(((?:\\.|[^\\)])*)\)", head)
    if m:
        raw = re.sub(rb"\\([nrt()\\])", lambda x: {b"n": b"\n", b"r": b"", b"t": b" "}.get(x.group(1), x.group(1)), m.group(1))
        title = raw[2:].decode("utf-16-be", "replace") if raw.startswith(b"\xfe\xff") else raw.decode("latin-1")
    else:
        m = re.search(rb"/Title\s*<([0-9A-Fa-f\s]+)>", head)
        if m:
            raw = bytes.fromhex(re.sub(rb"\s", b"", m.group(1)).decode())
            title = raw[2:].decode("utf-16-be", "replace") if raw.startswith(b"\xfe\xff") else raw.decode("latin-1")
    return {"pages": pages, "title": " ".join(title.split())[:200]}


def text_info(path, size):
    """{lines, sample, binary}. Line count is exact up to 16 MB, estimated from the sample beyond."""
    with open(path, "rb") as f:
        sample = f.read(256 << 10)
        if b"\0" in sample[:8192]:
            return {"binary": True}
        if size <= 16 << 20:
            lines = sample.count(b"\n")
            for chunk in iter(lambda: f.read(1 << 20), b""):
                lines += chunk.count(b"\n")
        else:
            lines = int(sample.count(b"\n") * size / max(1, len(sample)))
    text = sample.decode("utf-8", "replace").replace("\r\n", "\n").replace("\t", "    ")
    return {"lines": lines + (0 if sample.endswith(b"\n") else 1), "sample": text.split("\n")[:40], "binary": False}


def sha256(path, size):
    if size > 512 << 20:  # a big download: don't read half a gigabyte off the drive for a preview
        return ""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------- drawing


def stats(d, items, ink, soft):
    """Big numbers in the band the audio card uses for its waveform: value in Bahnschrift, label in dot type."""
    x0, x1 = A.column()
    vy = A.H * A.SS - S(48) - S(44) - S(34) - S(18)
    x = x0
    for value, label in items:
        if not value:
            continue
        size = S(54)
        vw = A.text_width(value, size, "Bold")
        lw = A.dot_width(label, S(3.6))
        if x + max(vw, lw) > x1:
            break
        A.draw_text(d, x, vy - S(16), value, size, "Bold", ink)
        A.dot_text(d, x, vy, label, S(3.6), S(3.6) * 0.38, soft)
        x += max(vw, lw) + S(56)



def mono(size):
    return A.font(MONO, size)


def code_tile(lines, numbered=True, dim_comments=True, base=(13, 15, 18)):
    """A dark tile with lines of monospace text (and line numbers)."""
    from PIL import Image, ImageDraw
    _, side, _, _, _ = A.geometry()
    tile = Image.new("RGB", (side, side), base)
    td = ImageDraw.Draw(tile, "RGBA")
    size = S(17)
    f = mono(size)
    lh = int(size * 1.55)
    gutter = int(f.getlength("000")) + S(18) if numbered else 0
    x, y = S(26), S(28)
    room = side - x - gutter - S(22)
    for i, line in enumerate(lines):
        if y + lh > side - S(20):
            break
        if numbered:
            td.text((x + gutter - S(14), y), str(i + 1), font=f, fill=(255, 255, 255, 70), anchor="ra")
        txt = line.rstrip()
        while txt and f.getlength(txt) > room:
            txt = txt[:-2]
            if f.getlength(txt + "…") <= room:
                txt += "…"
                break
        fill = (255, 255, 255, 110) if dim_comments and COMMENT.match(line) else (236, 238, 242, 235)
        td.text((x + gutter, y), txt, font=f, fill=fill)
        y += lh
    return tile


def list_tile(rows, more=0):
    """Archive contents: name on the left, size on the right, folders first."""
    from PIL import Image, ImageDraw
    _, side, _, _, _ = A.geometry()
    tile = Image.new("RGB", (side, side), (13, 15, 18))
    td = ImageDraw.Draw(tile, "RGBA")
    size = S(18)
    f = mono(size)
    lh = int(size * 1.7)
    x, y, right = S(28), S(30), side - S(28)
    for name, sz, is_dir in rows:
        if y + lh * (2 if more else 1) > side - S(20):
            more += 1
            continue
        label = name + ("/" if is_dir else "")
        meta = human(sz) if sz or not is_dir else ""
        room = right - x - (f.getlength(meta) + S(20) if meta else 0)
        while label and f.getlength(label) > room:
            label = label[:-2]
            if f.getlength(label + "…") <= room:
                label += "…"
                break
        td.text((x, y), label, font=f, fill=(236, 238, 242, 235) if not is_dir else (255, 214, 120, 240))
        if meta:
            td.text((right, y), meta, font=f, fill=(255, 255, 255, 90), anchor="ra")
        y += lh
    if more:
        td.text((x, y), "+ %d more" % more, font=f, fill=(255, 255, 255, 110))
    return tile


def page_tile(title, pages):
    """A sheet of paper on the dark tile: the title set on it, grey lines for text, more sheets behind for long PDFs."""
    from PIL import Image, ImageDraw
    _, side, _, _, _ = A.geometry()
    tile = Image.new("RGB", (side, side), (20, 22, 26))
    td = ImageDraw.Draw(tile, "RGBA")
    pw = int(side * 0.62)
    ph = int(pw * 1.414)
    if ph > side - S(60):
        ph = side - S(60)
        pw = int(ph / 1.414)
    px, py = (side - pw) // 2, (side - ph) // 2
    for k in range(min(2, max(0, pages - 1)), 0, -1):  # the sheets behind
        o = S(10) * k
        td.rectangle((px + o, py - o, px + pw + o, py + ph - o), fill=(225 - 25 * k, 225 - 25 * k, 228 - 25 * k))
    td.rectangle((px, py, px + pw, py + ph), fill=(246, 246, 243))
    m = S(26)
    y = py + m
    lines, _ = A.wrap(title or "Untitled", S(30), "Bold", pw - 2 * m, 3)
    for line in lines:
        A.draw_text(td, px + m, y + S(28), line, S(30), "Bold", (20, 20, 24))
        y += S(36)
    y += S(18)
    import random
    rnd = random.Random(title)
    while y < py + ph - m - S(10):
        width = (pw - 2 * m) * (rnd.uniform(0.55, 1.0) if rnd.random() > 0.15 else rnd.uniform(0.2, 0.45))
        td.rounded_rectangle((px + m, y, px + m + width, y + S(7)), S(3), fill=(20, 20, 24, 46))
        y += S(19) if rnd.random() > 0.12 else S(34)
    A.dot_text(td, px + pw - m - A.dot_width("PDF", S(5)), py + ph - m - 7 * S(5), "PDF", S(5), S(5) * 0.38, (215, 25, 33, 255))
    return tile


def mosaic(path, files, side):
    """Up to 9 pictures of the folder in a square grid (3x3, 2x2 or one), or None without pictures."""
    from PIL import Image, ImageOps
    pics = [f for f in files if os.path.splitext(f[0])[1].lower() in IMAGE_EXT and f[1] < 60 << 20]
    n = 9 if len(pics) >= 9 else 4 if len(pics) >= 4 else 1 if pics else 0
    if not n:
        return None
    grid = int(n ** 0.5)
    gap = S(6)
    cell = (side - gap * (grid - 1)) // grid
    tile = Image.new("RGB", (side, side), (11, 11, 11))
    Image.MAX_IMAGE_PIXELS = 60_000_000
    placed = 0
    for name, _, _ in pics:
        if placed == n:
            break
        try:
            im = Image.open(os.path.join(path, name))
            im.draft("RGB", (cell, cell))  # JPEG: decode at a fraction of the size, far less work for big photos
            im = ImageOps.fit(ImageOps.exif_transpose(im).convert("RGB"), (cell, cell))
        except Exception:
            continue
        r, c = divmod(placed, grid)
        tile.paste(im, (c * (cell + gap), r * (cell + gap)))
        placed += 1
    return tile if placed else None


def draw(kind, path, st, files=None, dirs=None, where=""):
    """-> (jpeg bytes, info) for one card."""
    from PIL import ImageOps
    name = os.path.basename(path.rstrip("/\\")) or "/"
    ext = os.path.splitext(name)[1].lower()
    key = hashlib.sha1(path.encode("utf-8")).hexdigest()
    cols, ring, blur = A.hash_palette(key), (255, 255, 255), None
    _, side, _, _, _ = A.geometry()
    info = {"kind": kind, "title": name, "name": name}
    kicker_fill = None

    if kind == "folder":
        total = sum(f[1] for f in files)
        newest = max([f[2] for f in files] or [0])
        tile = mosaic(path, files, side)
        if tile is not None:
            dominant, cols = A.palette(tile)
            ring = (0, 0, 0) if A.luminance(dominant) > 0.36 else (255, 255, 255)
            blur = tile
        else:
            tile = A.dotted_tile("DIR")
        kicker, sub = "OPEN GALLERY", where or "Gallery"
        nums = [(str(len(files)), "FILES"), (human(total), "TOTAL"), (str(len(dirs)) if dirs else "", "FOLDERS")]
        foot = ("UPDATED " + day(newest).upper()) if newest else ""
        info["description"] = " · ".join(x for x in ("%d files" % len(files), "%d folders" % len(dirs) if dirs else "",
                                                     human(total)) if x)
    elif kind == "archive":
        fmt = ARCHIVE_EXT.get(ext, ext.lstrip(".").upper())
        try:
            ai = archive_info(path, ext)
        except Exception:
            ai = None
        if ai:
            rows = [(n, s, d) for n, s, d in ai["top"]]
            if len(rows) == 1 and rows[0][2] and ai["second"].get(rows[0][0]):
                inner = sorted(((rows[0][0] + "/" + k, v[0], v[1]) for k, v in ai["second"][rows[0][0]].items()),
                               key=lambda x: (not x[2], x[0].lower()))
                rows = inner
            tile = list_tile(rows)
            kicker, sub = "ARCHIVE", "%s archive · %d files" % (fmt, ai["files"]) + (" · encrypted" if ai["encrypted"] else "")
            nums = [(str(ai["files"]), "FILES"), (human(ai["unpacked"]), "UNPACKED"), (human(st.st_size), "DOWNLOAD")]
            info["description"] = "%s archive · %d files · %s unpacked · %s download" % (
                fmt, ai["files"], human(ai["unpacked"]), human(st.st_size))
        else:
            tile = A.dotted_tile(fmt.split(".")[0])
            kicker, sub = "ARCHIVE", "%s archive" % fmt
            nums = [(human(st.st_size), "DOWNLOAD"), (day(st.st_mtime), "UPDATED")]
            info["description"] = "%s archive · %s" % (fmt, human(st.st_size))
        foot = "UPDATED " + day(st.st_mtime).upper()
    elif kind == "pdf":
        try:
            pi = pdf_info(path, st.st_size)
        except Exception:
            pi = {"pages": 0, "title": ""}
        title = pi["title"] if len(pi["title"]) > 3 else ""
        if title:
            info["title"] = title
        tile = page_tile(title or os.path.splitext(name)[0], pi["pages"])
        kicker, sub = "READ", name if title else "PDF document"
        nums = [(str(pi["pages"]) if pi["pages"] else "", "PAGES"), (human(st.st_size), "SIZE")]
        foot = "UPDATED " + day(st.st_mtime).upper()
        info["description"] = " · ".join(x for x in ("PDF", "%d pages" % pi["pages"] if pi["pages"] else "", human(st.st_size)) if x)
    elif kind == "text":
        lang = TEXT_EXT.get(ext) or TEXT_EXT.get(name.lower(), "Text")
        ti = text_info(path, st.st_size)
        if ti["binary"]:
            return draw("file", path, st, where=where)
        if ext == ".md":
            h1 = next((l.lstrip("# ").strip() for l in ti["sample"] if l.startswith("# ")), "")
            if h1:
                info["title"] = h1
        tile = code_tile(ti["sample"], numbered=ext not in PROSE, dim_comments=ext not in PROSE)
        kicker = "READ" if ext in PROSE else "VIEW CODE"
        sub = name if info["title"] != name else lang
        nums = [("{:,}".format(ti["lines"]), "LINES"), (human(st.st_size), "SIZE")]
        foot = "UPDATED " + day(st.st_mtime).upper()
        info["description"] = "%s · %s lines · %s" % (lang, "{:,}".format(ti["lines"]), human(st.st_size))
    elif kind == "warning":
        what = RISKY.get(ext, "Program")
        digest = sha256(path, st.st_size)
        cols, ring, kicker_fill = RED_COLS, (255, 255, 255), (255, 214, 120)
        tile = A.dotted_tile("!", base=(16, 4, 6), label_fill=(235, 40, 40, 255), max_pitch=46)
        kicker, sub = "CAUTION", "%s · runs code on your computer" % what
        nums = [(human(st.st_size), "SIZE"), (digest[:12] if digest else "", "SHA-256")]
        foot = "ONLY OPEN IT IF YOU TRUST THE SOURCE"
        info["sha256"] = digest
        info["description"] = "%s · %s%s. Only open it if you trust the source." % (
            what, human(st.st_size), " · SHA-256 " + digest[:16] if digest else "")
        info["color"] = "#c62828"
    else:
        label = ext.lstrip(".").upper() or "FILE"
        tile = A.dotted_tile(label)
        what = (mimetypes.guess_type(name)[0] or "").split("/")[0]
        kicker, sub = "DOWNLOAD", "%s file" % label if label != "FILE" else "File"
        nums = [(human(st.st_size), "SIZE"), (day(st.st_mtime), "UPDATED")]
        foot = {"font": "FONT", "application": "", "text": "TEXT", "model": "3D MODEL"}.get(what, what.upper())
        info["description"] = "%s · %s · updated %s" % (sub, human(st.st_size), day(st.st_mtime))

    img, d, ink, soft, _ = A.canvas(cols, blur)
    A.place_tile(img, d, ImageOps.fit(tile, (side, side)) if tile.size != (side, side) else tile, ring)
    A.heading(d, kicker, info["title"], sub, ink, soft, kicker_fill)
    stats(d, nums, ink, soft)
    A.footer(d, foot, "", ink, soft)
    info.setdefault("color", "#%02x%02x%02x" % cols[0])
    return A.finish(img), info


def card(path, st, cache_dir, is_dir=False, where=""):
    """(jpeg bytes, info), drawn once per file version - for a folder, once per listing. where: the folder's URL
    path shown under its name."""
    kind = kind_of(path, is_dir)
    files = dirs = None
    if is_dir:
        files, dirs = listing(path)
        ident = [path, files, dirs, where]
    else:
        ident = [path, st.st_size, st.st_mtime]
    k = hashlib.sha1(json.dumps(ident + [VERSION, A.VERSION]).encode()).hexdigest()
    cdir = os.path.join(cache_dir, "cards", k[:2])
    cp, jp = os.path.join(cdir, k + ".jpg"), os.path.join(cdir, k + ".json")
    if os.path.isfile(cp) and os.path.isfile(jp):
        try:
            with open(cp, "rb") as f, open(jp, encoding="utf-8") as g:
                return f.read(), json.load(g)
        except (OSError, ValueError):
            pass
    with _LOCK:
        data, info = draw(kind, path, st, files, dirs, where)
        info["key"] = k
        os.makedirs(cdir, exist_ok=True)
        for p, blob in ((cp, data), (jp, json.dumps(info).encode("utf-8"))):
            tmp = p + ".tmp"
            with open(tmp, "wb") as f:
                f.write(blob)
            os.replace(tmp, p)
        return data, info


def embed_html(info, page_url, card_url, host):
    e = lambda v: html.escape(str(v or ""), quote=True)  # noqa: E731
    tags = [
        ("property", "og:type", "website"), ("property", "og:site_name", host),
        ("property", "og:title", info["title"]), ("property", "og:description", info.get("description", "")),
        ("property", "og:url", page_url), ("property", "og:image", card_url),
        ("property", "og:image:secure_url", card_url), ("property", "og:image:type", "image/jpeg"),
        ("property", "og:image:width", A.W), ("property", "og:image:height", A.H),
        ("property", "og:image:alt", info["title"]),
        ("name", "twitter:card", "summary_large_image"), ("name", "twitter:title", info["title"]),
        ("name", "twitter:description", info.get("description", "")), ("name", "twitter:image", card_url),
        ("name", "theme-color", info.get("color") or "#111111"),
    ]
    head = "\n".join('<meta %s="%s" content="%s">' % (a, e(k), e(v)) for a, k, v in tags)
    return ("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n<title>%s</title>\n%s\n"
            "<link rel=\"canonical\" href=\"%s\">\n</head><body><p><a href=\"%s\">%s</a></p></body></html>\n"
            % (e(info["title"]), head, e(page_url), e(page_url), e(info["title"]))).encode("utf-8")
