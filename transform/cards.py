"""Strata link-preview cards for everything that isn't audio (audiocard.py draws those, and lends its fonts here).

Each kind has its own look, so a link says what it is before anyone reads it:

    text       code and plain text: a clean light card like a repository's (path, a line from the file itself,
               stats, the site's logo) with the language's colour along the bottom
    archive    a terminal: `unzip -l` and a tree of what's inside, the contents' types as a bar along the bottom
    pdf        a document cover: serif title, author, pages, on paper, with the pages stacked beside it
    folder     a gallery folder: its pictures edge to edge, name and counts over a dark fade
    warning    programs, scripts and installers: hazard stripes, a warning sign and the file's SHA-256
    file       anything else: a file icon with its extension, size and date

Images, videos and web pages never get here: the platforms embed those themselves (rules.PREVIEW_NATIVE).
Every card is drawn once per file version (folders: per listing) and cached next to the audio cards.
"""
import datetime
import hashlib
import html
import json
import os
import random
import re
import tarfile
import threading
import zipfile

import audiocard as A

VERSION = 2
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
            ".rb": "Ruby", ".php": "PHP", ".lua": "Lua", ".sh": "Shell", ".sql": "SQL", ".srt": "Subtitles",
            ".vtt": "Subtitles", ".gitignore": "Git ignore", ".dockerfile": "Dockerfile", ".swift": "Swift"}
# GitHub's language colours, so a card reads like the repository page people know
LANG_COLOR = {".py": "#3572A5", ".js": "#f1e05a", ".mjs": "#f1e05a", ".jsx": "#f1e05a", ".ts": "#3178c6", ".tsx": "#3178c6",
              ".css": "#563d7c", ".scss": "#c6538c", ".html": "#e34c26", ".htm": "#e34c26", ".c": "#555555", ".h": "#555555",
              ".cpp": "#f34b7d", ".hpp": "#f34b7d", ".cs": "#178600", ".java": "#b07219", ".kt": "#A97BFF", ".go": "#00ADD8",
              ".rs": "#dea584", ".rb": "#701516", ".php": "#4F5D95", ".lua": "#000080", ".sh": "#89e051", ".sql": "#e38c00",
              ".md": "#083fa1", ".json": "#292929", ".yml": "#cb171e", ".yaml": "#cb171e", ".toml": "#9c4221",
              ".swift": "#F05138", ".svg": "#ff9900", ".png": "#a371f7", ".jpg": "#a371f7", ".jpeg": "#a371f7",
              ".webp": "#a371f7", ".mp3": "#2ea043", ".flac": "#2ea043", ".mp4": "#db61a2", ".pdf": "#b3261e"}
PROSE = {".txt", ".md", ".log", ".srt", ".vtt", ".csv", ".tsv"}
SANS, SANS_B = ["segoeui.ttf", "DejaVuSans.ttf"], ["segoeuib.ttf", "DejaVuSans-Bold.ttf"]
SERIF_B, SERIF_I = ["georgiab.ttf", "DejaVuSerif-Bold.ttf"], ["georgiai.ttf", "DejaVuSerif-Italic.ttf"]
MONO, MONO_B = ["consola.ttf", "DejaVuSansMono.ttf"], ["consolab.ttf", "DejaVuSansMono-Bold.ttf"]


def human(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1000 or unit == "TB":
            return ("%d %s" % (n, unit)) if unit == "B" or n >= 100 else ("%.1f %s" % (n, unit))
        n /= 1000


def day(ts):
    return datetime.datetime.fromtimestamp(ts).strftime("%d %b %Y").lstrip("0") if ts else ""


def rgb(hexcol):
    h = hexcol.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


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
    """{files, unpacked, top, second, exts, encrypted} - None when the archive can't be read here (7z, rar)."""
    top, second, exts, files, unpacked, encrypted = {}, {}, {}, 0, 0, False

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
            e = os.path.splitext(name)[1].lower()
            exts[e] = exts.get(e, 0) + size

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
    order = lambda x: (not x[2], x[0].lower())  # noqa: E731  folders first
    rows = sorted(((k, v[0], v[1]) for k, v in top.items()), key=order)
    prefix = ""
    if len(rows) == 1 and rows[0][2] and second.get(rows[0][0]):
        prefix = rows[0][0] + "/"
        rows = sorted(((k, v[0], v[1]) for k, v in second[rows[0][0]].items()), key=order)
    return {"files": files, "unpacked": unpacked, "rows": rows, "prefix": prefix, "exts": exts, "encrypted": encrypted}


def _pdf_string(head, key):
    m = re.search(rb"/" + key + rb"\s*\(((?:\\.|[^\\)])*)\)", head)
    if m:
        raw = re.sub(rb"\\([nrt()\\])", lambda x: {b"n": b"\n", b"r": b"", b"t": b" "}.get(x.group(1), x.group(1)), m.group(1))
    else:
        m = re.search(rb"/" + key + rb"\s*<([0-9A-Fa-f\s]+)>", head)
        if not m:
            return ""
        raw = bytes.fromhex(re.sub(rb"\s", b"", m.group(1)).decode())
    text = raw[2:].decode("utf-16-be", "replace") if raw.startswith(b"\xfe\xff") else raw.decode("latin-1")
    return " ".join(text.split())[:200]


def pdf_info(path, size):
    """{pages, title, author} from the PDF's own structure (best effort: compressed object streams hide them)."""
    with open(path, "rb") as f:
        head = f.read(2 << 20)
        if size > 3 << 20:
            f.seek(max(0, size - (1 << 20)))
            head += f.read()
    counts = [int(c) for c in re.findall(rb"/Type\s*/Pages\b[^>]*?/Count\s+(\d+)", head)]
    counts += [int(c) for c in re.findall(rb"/Count\s+(\d+)[^>]*?/Type\s*/Pages\b", head)]
    pages = max(counts) if counts else len(re.findall(rb"/Type\s*/Page\b", head))
    return {"pages": pages, "title": _pdf_string(head, b"Title"), "author": _pdf_string(head, b"Author")}


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
    return {"lines": lines + (0 if sample.endswith(b"\n") else 1), "sample": text.split("\n")[:200], "binary": False}


def summary(lines, ext):
    """One sentence from the file itself: a module docstring, the first comment, or the first line of prose."""
    clean = lambda s: re.sub(r"\s+", " ", re.sub(r"[*_`#>\[\]]|\(http[^)]*\)|<[^>]+>", "", s)).strip()  # noqa: E731
    if ext in PROSE:  # the first paragraph of prose, cut after a sentence when it runs long
        para = []
        for l in lines:
            skip = l.lstrip().startswith(("#", "<", "|", "---", "```", "![", "[!"))
            t = "" if skip else clean(l)
            if t:
                para.append(t)
            elif para and (skip or not l.strip()):
                if len(" ".join(para)) > 12:
                    break
                para = []
        text = " ".join(para)
        if len(text) > 220:
            cut = max(text.rfind(". ", 0, 220), text.rfind("! ", 0, 220), text.rfind("? ", 0, 220))
            text = text[:cut + 1] if cut > 60 else text[:219].rstrip() + "…"
        return text.rstrip(",;:")
    for i, l in enumerate(lines[:60]):
        s = l.strip()
        if not s or s.startswith("#!") or re.match(r"(?i)^(#|//|/\*|\*)\s*-\*-|^(#|//)\s*(type|eslint|noqa|pylint)", s):
            continue
        m = re.match(r'^[rRbBuU]?("""|\'\'\')(.*)', s)
        if m:
            t = m.group(2).split(m.group(1))[0].strip() or (lines[i + 1].strip() if i + 1 < len(lines) else "")
            return clean(t)[:220]
        m = re.match(r"^(#|//|--|;|/\*+|\*)\s?(.*)", s)
        if m and len(clean(m.group(2))) > 12 and not re.match(r"(?i)copyright|licen[cs]e|spdx", m.group(2)):
            return clean(m.group(2).rstrip("*/"))[:220]
        if not m:
            return ""
    return ""


def sha256(path, size):
    if size > 512 << 20:  # a big download: don't read half a gigabyte off the drive for a preview
        return ""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------- drawing helpers (text with per-script fallback)


def _runs(text, size, names):
    out, cur, idx = [], "", None
    for ch in text:
        s = A._script_of(ch)
        if s == -1 and idx not in (None, -1) and ch == " ":
            s = idx
        if s != idx and cur:
            out.append((idx, cur))
            cur = ""
        idx, cur = s, cur + ch
    if cur:
        out.append((idx, cur))
    return [(A.font(names if s == -1 else A.SCRIPTS[s][1] + names, size), seg) for s, seg in out]


def tw(text, size, names, tracking=0):
    return sum(f.getlength(seg) for f, seg in _runs(text, size, names)) + tracking * max(0, len(text) - 1)


def put(d, x, baseline, text, size, names, fill, tracking=0):
    """Draw text on a baseline; returns the x after it."""
    for f, seg in _runs(text, size, names):
        if tracking:
            for ch in seg:
                d.text((x, baseline), ch, font=f, fill=fill, anchor="ls")
                x += f.getlength(ch) + tracking
        else:
            d.text((x, baseline), seg, font=f, fill=fill, anchor="ls")
            x += f.getlength(seg)
    return x


def fit(text, size, names, width, tracking=0):
    if tw(text, size, names, tracking) <= width:
        return text
    while text and tw(text + "…", size, names, tracking) > width:
        text = text[:-1]
    return text.rstrip() + "…"


def wrapn(text, size, names, width, max_lines):
    lines, cur = [], ""
    for t in A._tokens(text):
        if tw((cur + t).rstrip(), size, names) <= width or not cur:
            cur += t
        else:
            lines.append(cur.rstrip())
            cur = t.lstrip()
    if cur.strip():
        lines.append(cur.rstrip())
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        lines[-1] = fit(lines[-1] + "…", size, names, width)
    return [fit(l, size, names, width) for l in lines]


def new(bg):
    from PIL import Image, ImageDraw
    img = Image.new("RGB", (A.W * A.SS, A.H * A.SS), bg)
    return img, ImageDraw.Draw(img, "RGBA")


def logo(side):
    """The site's logo as a rounded square: <home>/brand.png (Settings › Appearance › Branding), else Strata's."""
    from PIL import Image, ImageOps
    import instance
    for p in (instance.home("brand.png"), os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "brand-icon.png")):
        try:
            im = Image.open(p)
            im.draft("RGB", (side, side))
            im = ImageOps.fit(im.convert("RGBA"), (side, side))
            mask = A._rounded_mask((side, side), side // 6)
            alpha = Image.composite(im.getchannel("A"), Image.new("L", (side, side), 0), mask)
            im.putalpha(alpha)
            return im
        except Exception:
            continue
    return None


def bar(d, segments, height):
    """A strip along the bottom edge: [(colour, weight)] side by side, like GitHub's language bar."""
    w, h = A.W * A.SS, A.H * A.SS
    total = sum(x for _, x in segments) or 1
    x = 0
    for i, (col, weight) in enumerate(segments):
        x2 = w if i == len(segments) - 1 else x + int(w * weight / total)
        d.rectangle((x, h - height, x2, h), fill=col)
        x = x2


def ext_segments(exts, limit=6):
    """Contents by type for the bottom bar: the biggest types in their colours, the rest grey."""
    if not exts:
        return [((139, 148, 158), 1)]
    top = sorted(exts.items(), key=lambda kv: -kv[1])
    segs = [(rgb(LANG_COLOR.get(e, "#8b949e")), n) for e, n in top[:limit] if n]
    rest = sum(n for _, n in top[limit:])
    return segs + ([(rgb("#8b949e"), rest)] if rest else []) or [((139, 148, 158), 1)]


# icons, drawn at a given top-left in a box of `s` pixels
def icon_lines(d, x, y, s, col):
    for k in range(3):
        d.rounded_rectangle((x, y + s * (0.18 + 0.3 * k), x + s * (1 if k < 2 else 0.6), y + s * (0.18 + 0.3 * k) + s * 0.1), s * 0.05, fill=col)


def icon_disk(d, x, y, s, col):
    w = max(2, int(s * 0.1))
    d.rounded_rectangle((x + s * 0.05, y + s * 0.1, x + s * 0.95, y + s * 0.9), s * 0.12, outline=col, width=w)
    d.line((x + s * 0.05, y + s * 0.62, x + s * 0.95, y + s * 0.62), fill=col, width=w)
    d.ellipse((x + s * 0.68, y + s * 0.7, x + s * 0.8, y + s * 0.82), fill=col)


def icon_clock(d, x, y, s, col):
    w = max(2, int(s * 0.1))
    d.ellipse((x + s * 0.05, y + s * 0.05, x + s * 0.95, y + s * 0.95), outline=col, width=w)
    d.line((x + s * 0.5, y + s * 0.5, x + s * 0.5, y + s * 0.22), fill=col, width=w)
    d.line((x + s * 0.5, y + s * 0.5, x + s * 0.72, y + s * 0.6), fill=col, width=w)


def icon_dot(d, x, y, s, col):
    d.ellipse((x + s * 0.15, y + s * 0.15, x + s * 0.85, y + s * 0.85), fill=col)


def icon_pages(d, x, y, s, col):
    w = max(2, int(s * 0.1))
    d.rectangle((x + s * 0.3, y + s * 0.05, x + s * 0.95, y + s * 0.75), outline=col, width=w)
    d.rectangle((x + s * 0.05, y + s * 0.25, x + s * 0.7, y + s * 0.95), outline=col, width=w)


def stat_row(d, x, y, items, value_fill, label_fill, gap):
    """[(icon, value, label)] - icon and value on one line, label under it."""
    vs, ls = S(40), S(28)
    for icon, value, label in items:
        if not value:
            continue
        icon(d, x, y - vs * 0.82, vs * 0.86, value_fill)
        vx = x + vs * 1.2
        put(d, vx, y, value, vs, SANS_B, value_fill)
        put(d, x, y + S(46), label, ls, SANS, label_fill)
        x += max(vs * 1.2 + tw(value, vs, SANS_B), tw(label, ls, SANS)) + gap


# ---------------------------------------------------------------- the cards


def card_text(path, st, where, info):
    name = info["name"]
    ext = os.path.splitext(name)[1].lower()
    lang = TEXT_EXT.get(ext) or TEXT_EXT.get(name.lower(), "Text")
    ti = text_info(path, st.st_size)
    if ti["binary"]:
        return card_file(path, st, where, info)
    ov = info["ov"]
    desc = ov.get("description") or summary(ti["sample"], ext)
    if ext == ".md":
        h1 = next((l.lstrip("# ").strip() for l in ti["sample"] if l.startswith("# ")), "")
        if h1 and not desc:
            desc = h1
    col = ov.get("color") or LANG_COLOR.get(ext, "#8b949e")
    ink, dim = (31, 35, 40), (87, 96, 106)
    img, d = new((255, 255, 255))
    if ov.get("title"):
        name, where = ov["title"], ""
    side = S(200)
    lg = logo(side)
    right = A.W * A.SS - S(80)
    if lg is not None:
        img.paste(lg, (right - side, S(110)), lg)
        right -= side + S(60)
    x0 = S(80)
    parent = (where.strip("/").rsplit("/", 1)[-1] + "/") if where.strip("/") else ""
    size = S(84)
    while size > S(52) and tw(parent, size, SANS) + tw(name, size, SANS_B) > right - x0:
        size -= S(4)
    if tw(parent, size, SANS) + tw(name, size, SANS_B) > right - x0:
        parent = ""
    x = put(d, x0, S(200), parent, size, SANS, ink) if parent else x0
    put(d, x, S(200), fit(name, size, SANS_B, right - x), size, SANS_B, ink)
    y = S(290)
    for line in wrapn(desc or "%s file, %s lines." % (lang, "{:,}".format(ti["lines"])), S(36), SANS, right - x0, 2):
        put(d, x0, y, line, S(36), SANS, dim)
        y += S(52)
    stat_row(d, x0, S(500), [(icon_lines, "{:,}".format(ti["lines"]), "Lines"), (icon_disk, human(st.st_size), "Size"),
                             (lambda d_, x_, y_, s_, c_: icon_dot(d_, x_, y_, s_, rgb(col)), lang, "Language"),
                             (icon_clock, day(st.st_mtime), "Updated")], ink, dim, S(70))
    bar(d, [(rgb(col), 1)], S(24))
    info.update(title=name, color=col,
                description=(desc + " · " if desc else "") + "%s · %s lines · %s" % (lang, "{:,}".format(ti["lines"]), human(st.st_size)))
    return img


def card_archive(path, st, where, info):
    name = info["name"]
    ext = os.path.splitext(name)[1].lower()
    fmt = ARCHIVE_EXT.get(ext, ext.lstrip(".").upper())
    try:
        ai = archive_info(path, ext)
    except Exception:
        ai = None
    green, fg, blue, dim = (63, 185, 80), (201, 209, 217), (88, 166, 255), (139, 148, 158)
    img, d = new((13, 17, 23))
    ov = info["ov"]
    shown_name = ov.get("title") or name
    x0, y = S(70), S(100)
    ms = S(29)
    cmd = {"ZIP": "unzip -l", "7-ZIP": "7z l", "RAR": "unrar l"}.get(fmt, "tar -tvf")
    x = put(d, x0, y, "$ ", ms, MONO_B, green)
    put(d, x, y, fit("%s %s" % (cmd, name), ms, MONO, S(840) - x), ms, MONO, fg)
    y += S(60)
    col_right = S(880)
    if ai:
        rows, n = ai["rows"], 9
        if ai["prefix"]:
            put(d, x0, y, ai["prefix"], ms, MONO_B, blue)
            y += S(44)
            n -= 1
        shown = rows[:n] if len(rows) <= n else rows[:n - 1]
        for i, (nm, sz, is_dir) in enumerate(shown):
            last = i == len(shown) - 1 and len(shown) == len(rows)
            branch = "└── " if last else "├── "
            x = put(d, x0, y, branch, ms, MONO, dim)
            label = nm + ("/" if is_dir else "")
            meta = human(sz)
            put(d, x, y, fit(label, ms, MONO_B if is_dir else MONO, col_right - x - tw(meta, ms, MONO) - S(30)), ms,
                MONO_B if is_dir else MONO, blue if is_dir else fg)
            put(d, col_right - tw(meta, ms, MONO), y, meta, ms, MONO, dim)
            y += S(44)
        if len(shown) < len(rows):
            put(d, x0, y, "└── … %d more" % (len(rows) - len(shown)), ms, MONO, dim)
    else:
        put(d, x0, y, "(%s archives are listed after download)" % fmt, ms, MONO, dim)
    # the right column: what it is and how big
    rx, rw = S(980), A.W * A.SS - S(980) - S(70)
    size = S(58)
    lines = wrapn(shown_name, size, SANS_B, rw, 2)
    ty = S(150)
    for line in lines:
        put(d, rx, ty, line, size, SANS_B, (240, 246, 252))
        ty += S(66)
    put(d, rx, ty - S(10), fit("%s archive" % fmt + (" · encrypted" if ai and ai["encrypted"] else ""), S(28), MONO, rw),
        S(28), MONO, dim)
    sy = S(400)
    nums = [("{:,}".format(ai["files"]), "files"), (human(ai["unpacked"]), "unpacked")] if ai else []
    nums.append((human(st.st_size), "download"))
    cx = rx
    for value, label in nums:
        put(d, cx, sy, value, S(44), SANS_B, (240, 246, 252))
        put(d, cx, sy + S(40), label, S(26), MONO, dim)
        cx += max(tw(value, S(44), SANS_B), tw(label, S(26), MONO)) + S(44)
    bar(d, [(rgb(ov["color"]), 1)] if ov.get("color") else ext_segments(ai["exts"]) if ai else [((139, 148, 158), 1)], S(18))
    info.update(title=name, color="#0d1117", description=(
        "%s archive · %s files · %s unpacked · %s download" % (fmt, "{:,}".format(ai["files"]), human(ai["unpacked"]), human(st.st_size))
        if ai else "%s archive · %s" % (fmt, human(st.st_size))))
    return img


def card_pdf(path, st, where, info):
    from PIL import Image, ImageDraw, ImageFilter
    name = info["name"]
    try:
        pi = pdf_info(path, st.st_size)
    except Exception:
        pi = {"pages": 0, "title": "", "author": ""}
    ov = info["ov"]
    title = ov.get("title") or (pi["title"] if len(pi["title"]) > 3 else os.path.splitext(name)[0].replace("_", " ").replace("-", " "))
    paper, ink, dim, red = (243, 239, 230), (27, 27, 27), (98, 91, 84), rgb(ov["color"]) if ov.get("color") else (179, 38, 30)
    img, d = new(paper)
    x0, tx1 = S(90), S(900)
    put(d, x0, S(120), "PDF DOCUMENT", S(24), SANS_B, red, S(5))
    size = S(74)
    while True:
        lines = wrapn(title, size, SERIF_B, tx1 - x0, 3)
        if all(tw(l, size, SERIF_B) <= tx1 - x0 for l in lines) and (len(lines) < 3 or size <= S(50)) or size <= S(50):
            break
        size -= S(4)
    y = S(120) + int(size * 1.35)
    for line in lines:
        put(d, x0, y, line, size, SERIF_B, ink)
        y += int(size * 1.18)
    if ov.get("description") or pi["author"]:
        put(d, x0, y + S(14), fit(ov.get("description") or pi["author"], S(36), SERIF_I, tx1 - x0), S(36), SERIF_I, dim)
    meta = " · ".join(x for x in ("%d pages" % pi["pages"] if pi["pages"] else "", human(st.st_size),
                                  "updated " + day(st.st_mtime)) if x)
    d.line((x0, S(500), x0 + S(80), S(500)), fill=red, width=S(4))
    put(d, x0, S(552), fit(meta, S(30), SANS, tx1 - x0), S(30), SANS, dim)
    # the pages, stacked and turned a little, with the title set on the top one
    pw, ph = S(330), S(440)
    sheet = Image.new("RGBA", (pw + S(120), ph + S(120)), (0, 0, 0, 0))
    sd = ImageDraw.Draw(sheet, "RGBA")
    ox, oy = S(60), S(60)
    for k in range(min(2, max(0, pi["pages"] - 1)), 0, -1):
        sd.rectangle((ox + S(12) * k, oy - S(12) * k, ox + pw + S(12) * k, oy + ph - S(12) * k), fill=(232 - 18 * k, 228 - 18 * k, 220 - 18 * k, 255))
    sd.rectangle((ox, oy, ox + pw, oy + ph), fill=(255, 255, 255, 255))
    m, py = S(30), oy + S(34)
    for line in wrapn(title, S(28), SERIF_B, pw - 2 * m, 3):
        put(sd, ox + m, py + S(24), line, S(28), SERIF_B, ink)
        py += S(34)
    rnd = random.Random(title)
    py += S(20)
    while py < oy + ph - S(40):
        width = (pw - 2 * m) * (rnd.uniform(0.6, 1.0) if rnd.random() > 0.15 else rnd.uniform(0.2, 0.45))
        sd.rounded_rectangle((ox + m, py, ox + m + width, py + S(6)), S(3), fill=(27, 27, 27, 40))
        py += S(17) if rnd.random() > 0.12 else S(30)
    sheet = sheet.rotate(-4, resample=Image.BICUBIC, expand=False)
    shadow = Image.new("RGBA", sheet.size, (0, 0, 0, 0))
    shadow.putalpha(sheet.getchannel("A").point(lambda a: int(a * 0.28)).filter(ImageFilter.GaussianBlur(S(18))))
    px, py0 = A.W * A.SS - pw - S(190), (A.H * A.SS - sheet.size[1]) // 2
    img.paste((40, 30, 20), (px + S(10), py0 + S(18)), shadow)
    img.paste(sheet, (px, py0), sheet)
    info.update(title=title, color="#b3261e",
                description=" · ".join(x for x in (pi["author"], "PDF", "%d pages" % pi["pages"] if pi["pages"] else "",
                                                   human(st.st_size)) if x))
    return img


def justified(path, pics, w, h):
    """Pictures edge to edge: one row for up to 3, else two rows, each scaled to the full width."""
    from PIL import Image, ImageOps
    Image.MAX_IMAGE_PIXELS = 60_000_000
    ims = []
    for name, _, _ in pics[:8]:
        try:
            im = Image.open(os.path.join(path, name))
            im.draft("RGB", (w // 2, h // 2))  # JPEG: decode at a fraction of the size, far less work for big photos
            ims.append(ImageOps.exif_transpose(im).convert("RGB"))
        except Exception:
            continue
    if not ims:
        return None
    rows = [ims] if len(ims) <= 3 else [ims[:(len(ims) + 1) // 2], ims[(len(ims) + 1) // 2:]]
    canvas = Image.new("RGB", (w, h), (0, 0, 0))
    gap, y = S(4), 0
    rh = (h - gap * (len(rows) - 1)) // len(rows)
    for row in rows:
        ratios = [im.width / im.height for im in row]
        avail = w - gap * (len(row) - 1)
        x = 0
        for i, (im, r) in enumerate(zip(row, ratios)):
            cw = avail - x + gap * i if i == len(row) - 1 else int(avail * r / sum(ratios))
            canvas.paste(ImageOps.fit(im, (max(1, cw), rh)), (x, y))
            x += cw + gap
        y += rh + gap
    return canvas


def card_folder(path, st, where, info, files, dirs):
    from PIL import Image
    name = info["name"]
    w, h = A.W * A.SS, A.H * A.SS
    pics = [f for f in files if os.path.splitext(f[0])[1].lower() in IMAGE_EXT and f[1] < 60 << 20]
    photo = justified(path, pics, w, h)
    total = sum(f[1] for f in files)
    if photo is None:
        img, d = new((22, 24, 28))
    else:
        img = photo
        # dark toward the bottom and the left, where the text sits, so it reads over any picture
        down = Image.linear_gradient("L").resize((w, h)).point(lambda v: int(min(235, max(0, v - 70) * 1.3)))
        left = Image.linear_gradient("L").rotate(90, expand=True).resize((w, h)).point(lambda v: int(v * 0.55))
        from PIL import ImageChops
        img = Image.composite(Image.new("RGB", (w, h), (0, 0, 0)), img, ImageChops.lighter(down, left))
        from PIL import ImageDraw
        d = ImageDraw.Draw(img, "RGBA")
    x0 = S(70)
    ov = info["ov"]
    put(d, x0, h - S(200), "GALLERY", S(26), SANS_B, rgb(ov["color"]) if ov.get("color") else (255, 255, 255, 190), S(6))
    put(d, x0, h - S(108), fit(ov.get("title") or name, S(84), SANS_B, w - 2 * x0), S(84), SANS_B, (255, 255, 255))
    meta = ov.get("description") or " · ".join(
        x for x in ("%d files" % len(files), "%d folders" % len(dirs) if dirs else "", human(total), where) if x)
    put(d, x0, h - S(52), fit(meta, S(30), SANS, w - 2 * x0), S(30), SANS, (255, 255, 255, 200))
    col = "#%02x%02x%02x" % A.palette(photo)[0] if photo is not None else "#16181c"
    info.update(title=name, color=col, description=" · ".join(
        x for x in ("%d files" % len(files), "%d folders" % len(dirs) if dirs else "", human(total)) if x))
    return img


def card_warning(path, st, where, info):
    name = info["name"]
    ext = os.path.splitext(name)[1].lower()
    what = RISKY.get(ext, "Program")
    digest = sha256(path, st.st_size)
    yellow, black = (245, 196, 0), (11, 11, 11)
    img, d = new(black)
    w, h = A.W * A.SS, A.H * A.SS
    band = S(34)
    for top in (0, h - band):  # hazard stripes along the top and bottom edges
        d.rectangle((0, top, w, top + band), fill=yellow)
        for x in range(-band * 2, w + band * 2, S(56)):
            d.polygon([(x, top + band), (x + S(28), top + band), (x + S(28) + band, top), (x + band, top)], fill=black)
    x0, tx1 = S(80), S(1040)
    name = info["ov"].get("title") or name  # the warning itself can't be overridden
    put(d, x0, S(150), fit("CAUTION · " + what.upper(), S(28), SANS_B, tx1 - x0, S(4)), S(28), SANS_B, yellow, S(4))
    size = S(76)
    while size > S(48) and tw(name, size, SANS_B) > tx1 - x0:
        size -= S(4)
    put(d, x0, S(150) + int(size * 1.25), fit(name, size, SANS_B, tx1 - x0), size, SANS_B, (255, 255, 255))
    y = S(150) + int(size * 1.25) + S(64)
    for line in wrapn("This file runs code on your computer. Only open it if you trust the source.", S(34), SANS, tx1 - x0, 2):
        put(d, x0, y, line, S(34), SANS, (210, 210, 210))
        y += S(48)
    put(d, x0, S(500), human(st.st_size) + "  ·  SHA-256", S(24), SANS_B, (150, 150, 150), S(2))
    if digest:
        put(d, x0, S(540), digest[:32], S(26), MONO, (190, 190, 190))
        put(d, x0, S(572), digest[32:], S(26), MONO, (190, 190, 190))
    else:
        put(d, x0, S(540), "not computed for files over 512 MB", S(26), MONO, (150, 150, 150))
    # the warning sign
    cx, cy, r = S(1260), S(320), S(150)
    tri = [(cx, cy - r), (cx + r * 1.12, cy + r * 0.82), (cx - r * 1.12, cy + r * 0.82)]
    d.polygon(tri, fill=yellow)
    d.line(tri + [tri[0]], fill=yellow, width=S(22), joint="curve")
    d.rounded_rectangle((cx - S(14), cy - S(62), cx + S(14), cy + S(42)), S(10), fill=black)
    d.ellipse((cx - S(16), cy + S(62), cx + S(16), cy + S(94)), fill=black)
    info.update(title=name, color="#f5c400", sha256=digest, description="%s · %s%s. Only open it if you trust the source." % (
        what, human(st.st_size), " · SHA-256 " + digest[:16] if digest else ""))
    return img


def card_file(path, st, where, info):
    from PIL import Image, ImageDraw, ImageFilter
    name = info["name"]
    ext = os.path.splitext(name)[1].lstrip(".").upper() or "FILE"
    ov = info["ov"]
    c1 = rgb(ov["color"]) if ov.get("color") else A.hash_palette(ext)[2]
    name = ov.get("title") or name
    ink, dim = (31, 35, 40), (87, 96, 106)
    img, d = new((246, 247, 249))
    # the file: a sheet with a folded corner, the extension on a coloured band
    fx, fy, fw, fh, fold = S(120), S(110), S(300), S(400), S(80)
    shadow = Image.new("L", img.size, 0)
    ImageDraw.Draw(shadow).rectangle((fx + S(8), fy + S(14), fx + fw + S(8), fy + fh + S(14)), fill=70)
    img.paste((0, 0, 0), (0, 0), shadow.filter(ImageFilter.GaussianBlur(S(18))))
    d = ImageDraw.Draw(img, "RGBA")
    d.polygon([(fx, fy), (fx + fw - fold, fy), (fx + fw, fy + fold), (fx + fw, fy + fh), (fx, fy + fh)], fill=(255, 255, 255))
    d.polygon([(fx + fw - fold, fy), (fx + fw - fold, fy + fold), (fx + fw, fy + fold)], fill=(222, 226, 231))
    d.rectangle((fx, fy + fh - S(150), fx + fw, fy + fh - S(60)), fill=c1)
    ls = S(52)
    while tw(ext, ls, SANS_B) > fw - S(40) and ls > S(20):
        ls -= S(4)
    put(d, fx + (fw - tw(ext, ls, SANS_B)) / 2, fy + fh - S(105) + ls * 0.36, ext, ls, SANS_B, (255, 255, 255))
    x0, x1 = S(520), A.W * A.SS - S(80)
    size = S(72)
    while size > S(46) and tw(name, size, SANS_B) > x1 - x0:
        size -= S(4)
    lines = wrapn(name, size, SANS_B, x1 - x0, 2)
    y = S(210)
    for line in lines:
        put(d, x0, y, line, size, SANS_B, ink)
        y += int(size * 1.15)
    put(d, x0, y + S(6), fit(ov.get("description") or ("%s file" % ext if ext != "FILE" else "File"), S(36), SANS, x1 - x0),
        S(36), SANS, dim)
    stat_row(d, x0, S(500), [(icon_disk, human(st.st_size), "Size"), (icon_clock, day(st.st_mtime), "Updated")], ink, dim, S(80))
    bar(d, [(c1, 1)], S(16))
    info.update(title=name, color="#%02x%02x%02x" % c1,
                description="%s file · %s · updated %s" % (ext, human(st.st_size), day(st.st_mtime)))
    return img


def draw(kind, path, st, files=None, dirs=None, where="", ov=None):
    """-> (jpeg bytes, info) for one card."""
    name = os.path.basename(path.rstrip("/\\")) or "/"
    info = {"kind": kind, "title": name, "name": name, "ov": ov or {}}
    if kind == "folder":
        img = card_folder(path, st, where, info, files, dirs)
    else:
        img = {"archive": card_archive, "pdf": card_pdf, "text": card_text, "warning": card_warning}.get(kind, card_file)(
            path, st, where, info)
    o = info.pop("ov")
    for k in ("title", "description"):
        if o.get(k):
            info[k] = o[k]
    if o.get("color") and kind != "warning":
        info["color"] = o["color"]
    return A.finish(img), info


def card(path, st, cache_dir, is_dir=False, where="", ov=None):
    """(jpeg bytes, info), drawn once per file version - for a folder, once per listing. where: the URL path of the
    folder the file (or folder) sits in, shown on some cards. ov: link-preview rule settings (title, description,
    color, kind)."""
    ov = {k: v for k, v in (ov or {}).items() if k in ("title", "description", "color", "kind")}
    kind = kind_of(path, is_dir)
    if ov.get("kind") and (ov["kind"] == "folder") == is_dir and ov["kind"] != "audio":
        kind = ov["kind"]
    files = dirs = None
    if is_dir:
        files, dirs = listing(path)
        ident = [path, files, dirs, where]
    else:
        ident = [path, st.st_size, st.st_mtime, where]
    k = hashlib.sha1(json.dumps(ident + [VERSION, A.VERSION, ov], sort_keys=True).encode()).hexdigest()
    cdir = os.path.join(cache_dir, "cards", k[:2])
    cp, jp = os.path.join(cdir, k + ".jpg"), os.path.join(cdir, k + ".json")
    if os.path.isfile(cp) and os.path.isfile(jp):
        try:
            with open(cp, "rb") as f, open(jp, encoding="utf-8") as g:
                hit = f.read(), json.load(g)
            A.touch(cp, jp)
            return hit
        except (OSError, ValueError):
            pass
    with _LOCK:
        data, info = draw(kind, path, st, files, dirs, where, ov)
        info["key"] = k
        os.makedirs(cdir, exist_ok=True)
        for p, blob in ((cp, data), (jp, json.dumps(info).encode("utf-8"))):
            tmp = p + ".tmp"
            with open(tmp, "wb") as f:
                f.write(blob)
            os.replace(tmp, p)
        return data, info


def embed_html(info, page_url, card_url, host, custom_image=False):
    e = lambda v: html.escape(str(v or ""), quote=True)  # noqa: E731
    tags = [
        ("property", "og:type", "website"), ("property", "og:site_name", host),
        ("property", "og:title", info["title"]), ("property", "og:description", info.get("description", "")),
        ("property", "og:url", page_url), ("property", "og:image", card_url),
        ("property", "og:image:secure_url", card_url),
    ] + ([] if custom_image else [("property", "og:image:type", "image/jpeg"),
                                   ("property", "og:image:width", A.W), ("property", "og:image:height", A.H)]) + [
        ("property", "og:image:alt", info["title"]),
        ("name", "twitter:card", "summary_large_image"), ("name", "twitter:title", info["title"]),
        ("name", "twitter:description", info.get("description", "")), ("name", "twitter:image", card_url),
        ("name", "theme-color", info.get("color") or "#111111"),
    ]
    head = "\n".join('<meta %s="%s" content="%s">' % (a, e(k), e(v)) for a, k, v in tags)
    return ("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n<title>%s</title>\n%s\n"
            "<link rel=\"canonical\" href=\"%s\">\n</head><body><p><a href=\"%s\">%s</a></p></body></html>\n"
            % (e(info["title"]), head, e(page_url), e(page_url), e(info["title"]))).encode("utf-8")
