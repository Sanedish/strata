"""Strata audio cards - what a shared link to an audio file looks like in Discord, Slack, Telegram, X, iMessage...

Used by transform.py, reached only through the generated audio-player rules (rules.render_players):

    link-preview crawler on the bare URL (X-Strata-Embed: 1)  ->  embed_html(): Open Graph / Twitter tags
    <file>?card=1                                             ->  card(): the 1200x600 card image (JPEG)

The card: a soft mesh gradient from the cover's three dominant colours with the cover itself blurred into it, the
cover in a rounded square with a black / white outline (same rule as the player), "LISTEN TO" in dot-matrix
type, title and artist, the track's real loudness envelope as a dot-matrix waveform, duration and format. A static
image: nothing on it suggests a control, the link under it is what people click.

Tags are read here, in pure Python (ID3v2.2-2.4, FLAC, Ogg Vorbis / Opus / FLAC, MP4 / M4A, RIFF / AIFF), with
durations. The waveform needs ffmpeg; it runs boxed through media/sandbox.py (job object, memory / CPU caps,
file protocol only, audio demuxers only) and the card falls back to a plain dotted track without it.
Everything is cached on disk by file identity, so each file is parsed and drawn once.
"""
import array
import colorsys
import hashlib
import html
import importlib.util
import io
import json
import os
import re
import struct
import threading
import zlib

VERSION = 5                     # bump to redraw every cached card
AUDIO_EXT = {".mp3", ".m4a", ".aac", ".flac", ".ogg", ".oga", ".opus", ".wav", ".aif", ".aiff", ".weba", ".alac", ".wma", ".amr", ".wv", ".ape"}
W, H, SS = 1500, 630, 2         # output size (wide, at the Open Graph height), supersampling factor
MAX_TAG = 24 << 20
RED = (215, 25, 33)
DEMUXERS = "mp3,flac,ogg,mov,wav,w64,aiff,aac,matroska,asf"
_LOCK = threading.Semaphore(2)

# ---------------------------------------------------------------- tag reader


class Reader:
    def __init__(self, f, size):
        self.f, self.size = f, size

    def read(self, off, n):
        if off < 0 or off >= self.size or n <= 0:
            return b""
        self.f.seek(off)
        return self.f.read(min(n, self.size - off))


def _u32(b, i):
    return struct.unpack_from(">I", b, i)[0]


def _u32le(b, i):
    return struct.unpack_from("<I", b, i)[0]


def _syncsafe(b, i):
    return ((b[i] & 0x7f) << 21) | ((b[i + 1] & 0x7f) << 14) | ((b[i + 2] & 0x7f) << 7) | (b[i + 3] & 0x7f)


def _clean(s):
    return ", ".join(x.strip() for x in s.replace("\ufeff", "").split("\x00") if x.strip())


def _unsync(b):
    return b.replace(b"\xff\x00", b"\xff")


def _sniff(b):
    if b[:2] == b"\xff\xd8":
        return "image/jpeg"
    if b[:4] == b"\x89PNG":
        return "image/png"
    if b[:4] == b"RIFF" and b[8:12] == b"WEBP":
        return "image/webp"
    if b[:3] == b"GIF":
        return "image/gif"
    return ""


def _pic(meta, data, ptype):
    if len(data) > 64 and _sniff(data):
        meta["pics"].append((ptype, bytes(data)))


def _set(meta, key, v):
    v = (v or "").strip()
    if not v:
        return
    if key == "artist":
        if v not in meta["artists"]:
            meta["artists"].append(v)
    elif not meta.get(key):
        meta[key] = v


def _id3_text(enc, b):
    try:
        if enc == 0:
            return _clean(b.decode("latin-1"))
        if enc == 3:
            return _clean(b.decode("utf-8", "replace"))
        if enc == 2:
            return _clean(b.decode("utf-16-be", "replace"))
        return _clean(b.decode("utf-16", "replace"))          # BOM decides
    except Exception:
        return ""


def _str_end(b, i, enc):
    if enc in (1, 2):
        while i + 1 < len(b):
            if b[i] == 0 and b[i + 1] == 0:
                return i
            i += 2
        return len(b)
    j = b.find(b"\x00", i)
    return len(b) if j < 0 else j


ID3_TEXT = {"TIT2": "title", "TT2": "title", "TPE1": "artist", "TP1": "artist", "TPE2": "album_artist",
            "TP2": "album_artist", "TALB": "album", "TAL": "album"}


def id3_at(R, off, meta):
    h = R.read(off, 10)
    if len(h) < 10 or h[:3] != b"ID3":
        return 0
    ver, flags, size = h[3], h[5], _syncsafe(h, 6)
    total = 10 + size + (10 if flags & 0x10 else 0)
    if ver < 2 or ver > 4 or size > MAX_TAG:
        return total
    b = R.read(off + 10, size)
    if ver < 4 and flags & 0x80:
        b = _unsync(b)
    p = 0
    if ver == 3 and flags & 0x40 and len(b) >= 4:
        p = 4 + _u32(b, 0)
    elif ver == 4 and flags & 0x40 and len(b) >= 4:
        p = _syncsafe(b, 0)
    id_len, hdr = (3, 6) if ver == 2 else (4, 10)
    while p + hdr <= len(b):
        fid = b[p:p + id_len]
        if not re.fullmatch(rb"[A-Z0-9]+", fid):
            break
        fid = fid.decode()
        if ver == 2:
            fsz = (b[p + 3] << 16) | (b[p + 4] << 8) | b[p + 5]
        elif ver == 4:
            fsz = _syncsafe(b, p + 4)
        else:
            fsz = _u32(b, p + 4)
        ff = 0 if ver == 2 else b[p + 9]
        d = b[p + hdr:p + hdr + fsz]
        p += hdr + fsz
        if ver == 4:
            if ff & 0x0c:
                continue
            if ff & 0x40:
                d = d[1:]
            if ff & 0x01:
                d = d[4:]
            if ff & 0x02:
                d = _unsync(d)
        elif ver == 3:
            if ff & 0xc0:
                continue
            if ff & 0x20:
                d = d[1:]
        if not d:
            continue
        if fid in ID3_TEXT:
            _set(meta, ID3_TEXT[fid], _id3_text(d[0], d[1:]))
        elif fid in ("APIC", "PIC") and len(d) > 4:
            enc = d[0]
            i = _str_end(d, 1, 0) + 1 if fid == "APIC" else 4
            if i >= len(d):
                continue
            ptype = d[i]
            i = _str_end(d, i + 1, enc) + (2 if enc in (1, 2) else 1)
            _pic(meta, d[i:], ptype)
    return total


def _flac_picture(d, meta):
    try:
        i = 4
        i += 4 + _u32(d, i)
        i += 4 + _u32(d, i)
        i += 16
        n = _u32(d, i)
        _pic(meta, d[i + 4:i + 4 + n], _u32(d, 0))
    except struct.error:
        pass


def _b64(b):
    import base64
    try:
        return base64.b64decode(re.sub(rb"\s+", b"", bytes(b)), validate=False)
    except Exception:
        return b""


VORBIS_KEYS = {"TITLE": "title", "ARTIST": "artist", "ALBUMARTIST": "album_artist", "ALBUM ARTIST": "album_artist",
               "ALBUM": "album"}


def _vorbis_comment(d, i, meta):
    try:
        i += 4 + _u32le(d, i)
        n = _u32le(d, i)
        i += 4
        for _ in range(min(n, 10000)):
            if i + 4 > len(d):
                break
            ln = _u32le(d, i)
            s = d[i + 4:i + 4 + ln]
            i += 4 + ln
            eq = s.find(b"=")
            if eq < 0:
                continue
            key = s[:eq].decode("utf-8", "replace").upper()
            v = s[eq + 1:]
            if key == "METADATA_BLOCK_PICTURE":
                _flac_picture(_b64(v), meta)
            elif key == "COVERART":
                _pic(meta, _b64(v), 3)
            elif key in VORBIS_KEYS:
                _set(meta, VORBIS_KEYS[key], v.decode("utf-8", "replace"))
    except struct.error:
        pass


def _streaminfo(d):
    """(sample rate, total samples) from a FLAC STREAMINFO body."""
    if len(d) < 18:
        return 0, 0
    sr = (d[10] << 12) | (d[11] << 4) | (d[12] >> 4)
    total = ((d[13] & 0x0f) << 32) | (d[14] << 24) | (d[15] << 16) | (d[16] << 8) | d[17]
    return sr, total


def flac_at(R, off, meta):
    p = off + 4
    for _ in range(128):
        h = R.read(p, 4)
        if len(h) < 4:
            break
        last, kind, ln = h[0] & 0x80, h[0] & 0x7f, (h[1] << 16) | (h[2] << 8) | h[3]
        if kind in (0, 4, 6) and ln <= MAX_TAG:
            d = R.read(p + 4, ln)
            if kind == 0:
                sr, total = _streaminfo(d)
                if sr and total:
                    meta["duration"] = total / sr
            elif kind == 4:
                _vorbis_comment(d, 0, meta)
            else:
                _flac_picture(d, meta)
        p += 4 + ln
        if last:
            break


def ogg(R, meta):
    p, packets, cur = 0, [], []
    for _ in range(4000):
        if len(packets) >= 2:
            break
        h = R.read(p, 27)
        if len(h) < 27 or h[:4] != b"OggS":
            break
        segs = R.read(p + 27, h[26])
        body = p + 27 + h[26]
        data = R.read(body, sum(segs))
        q = 0
        for s in segs:
            cur.append(data[q:q + s])
            q += s
            if sum(len(x) for x in cur) > MAX_TAG:
                return
            if s < 255:
                packets.append(b"".join(cur))
                cur = []
                if len(packets) >= 2:
                    break
        p = body + sum(segs)
    if not packets:
        return
    head = packets[0]
    rate, skip = 0, 0
    if head[:7] == b"\x01vorbis" and len(head) >= 16:
        rate = _u32le(head, 12)
    elif head[:8] == b"OpusHead" and len(head) >= 12:
        rate, skip = 48000, struct.unpack_from("<H", head, 10)[0]
    elif head[:5] == b"\x7fFLAC" and len(head) >= 13 + 4 + 18:
        rate = _streaminfo(head[13 + 4:])[0]
    if len(packets) > 1:
        c = packets[1]
        if c[:7] == b"\x03vorbis":
            _vorbis_comment(c, 7, meta)
        elif c[:8] == b"OpusTags":
            _vorbis_comment(c, 8, meta)
        elif c and (c[0] & 0x7f) == 4:
            _vorbis_comment(c, 4, meta)
    if rate:   # duration: granule position of the last page
        tail = R.read(max(0, R.size - 65536), 65536)
        k = tail.rfind(b"OggS")
        if k >= 0 and k + 14 <= len(tail):
            gran = struct.unpack_from("<q", tail, k + 6)[0]
            if gran > 0:
                meta["duration"] = max(0, gran - skip) / rate


def _boxes(d, start, end):
    p = start
    while p + 8 <= end:
        size, kind, hl = _u32(d, p), d[p + 4:p + 8], 8
        if size == 1 and p + 16 <= end:
            size, hl = struct.unpack_from(">Q", d, p + 8)[0], 16
        elif size == 0:
            size = end - p
        if size < hl or p + size > end:
            break
        yield kind, p + hl, p + size
        p += size


MP4_KEYS = {b"\xa9nam": "title", b"\xa9ART": "artist", b"aART": "album_artist", b"\xa9alb": "album"}


def _ilst(d, s, e, meta):
    for key, s1, e1 in _boxes(d, s, e):
        for kind, s2, e2 in _boxes(d, s1, e1):
            if kind != b"data" or e2 - s2 < 8:
                continue
            v = d[s2 + 8:e2]
            if key == b"covr":
                _pic(meta, v, 3)
            elif key in MP4_KEYS:
                _set(meta, MP4_KEYS[key], v.decode("utf-8", "replace"))


def _meta_box(d, s, e, meta):
    off = s if d[s + 4:s + 8] == b"hdlr" else s + 4    # QuickTime's meta has no version / flags
    for kind, s1, e1 in _boxes(d, off, e):
        if kind == b"ilst":
            _ilst(d, s1, e1, meta)


def mp4(R, meta):
    p = 0
    for _ in range(64):
        h = R.read(p, 16)
        if len(h) < 8:
            break
        size, kind = _u32(h, 0), h[4:8]
        if size == 1 and len(h) >= 16:
            size = struct.unpack_from(">Q", h, 8)[0]
        elif size == 0:
            size = R.size - p
        if size < 8:
            break
        if kind == b"moov":
            if size > MAX_TAG:
                return
            d = R.read(p, size)
            for k, s, e in _boxes(d, 8, len(d)):
                if k == b"mvhd" and e - s >= 20:
                    if d[s] == 1 and e - s >= 32:
                        scale, dur = _u32(d, s + 20), struct.unpack_from(">Q", d, s + 24)[0]
                    else:
                        scale, dur = _u32(d, s + 12), _u32(d, s + 16)
                    if scale:
                        meta["duration"] = dur / scale
                elif k == b"meta":
                    _meta_box(d, s, e, meta)
                elif k == b"udta":
                    for k2, s2, e2 in _boxes(d, s, e):
                        if k2 == b"meta":
                            _meta_box(d, s2, e2, meta)
            return
        p += size


def _ext80(b):
    """IEEE 754 80-bit extended (AIFF sample rate) -> float."""
    exp = ((b[0] & 0x7f) << 8) | b[1]
    mant = struct.unpack_from(">Q", b, 2)[0]
    return 0.0 if not mant else mant * 2.0 ** (exp - 16383 - 63)


INFO_KEYS = {b"INAM": "title", b"IART": "artist", b"IPRD": "album"}


def iff(R, meta, le):
    p, byte_rate, data_size, frames, rate = 12, 0, 0, 0, 0.0
    for _ in range(256):
        c = R.read(p, 8)
        if len(c) < 8:
            break
        cid, size = c[:4], (_u32le(c, 4) if le else _u32(c, 4))
        if cid in (b"id3 ", b"ID3 "):
            id3_at(R, p + 8, meta)
        elif le and cid == b"fmt " and size >= 16:
            byte_rate = _u32le(R.read(p + 8, 16), 8)
        elif le and cid == b"data":
            data_size = size
        elif not le and cid == b"COMM" and size >= 18:
            d = R.read(p + 8, 18)
            frames, rate = _u32(d, 2), _ext80(d[8:18])
        elif le and cid == b"LIST" and size < (1 << 20):
            d = R.read(p + 8, size)
            if d[:4] == b"INFO":
                i = 4
                while i + 8 <= len(d):
                    k, ln = d[i:i + 4], _u32le(d, i + 4)
                    if k in INFO_KEYS:
                        _set(meta, INFO_KEYS[k], _clean(d[i + 8:i + 8 + ln].decode("utf-8", "replace")))
                    i += 8 + ln + (ln & 1)
        p += 8 + size + (size & 1)
        if p >= R.size:
            break
    if byte_rate and data_size:
        meta["duration"] = data_size / byte_rate
    elif frames and rate:
        meta["duration"] = frames / rate


MP3_BR = {1: [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320],
          2: [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160]}


def mp3_duration(R, off):
    """Xing / Info / VBRI frame count, else constant bitrate over the audio bytes."""
    buf = R.read(off, 65536)
    for i in range(len(buf) - 4):
        if buf[i] != 0xff or (buf[i + 1] & 0xe0) != 0xe0:
            continue
        b1, b2, b3 = buf[i + 1], buf[i + 2], buf[i + 3]
        ver_bits, layer = (b1 >> 3) & 3, (b1 >> 1) & 3
        br_i, sr_i = b2 >> 4, (b2 >> 2) & 3
        if ver_bits == 1 or layer != 1 or br_i in (0, 15) or sr_i == 3:   # Layer III only
            continue
        mpeg1 = ver_bits == 3
        sr = [44100, 48000, 32000][sr_i] // (1 if mpeg1 else 2 if ver_bits == 2 else 4)
        spf = 1152 if mpeg1 else 576
        mono = (b3 >> 6) == 3
        side = (17 if mono else 32) if mpeg1 else (9 if mono else 17)
        x = buf[i + 4 + side:i + 4 + side + 16]
        if x[:4] in (b"Xing", b"Info") and len(x) >= 12 and _u32(x, 4) & 1:
            return _u32(x, 8) * spf / sr
        v = buf[i + 36:i + 36 + 18]
        if v[:4] == b"VBRI" and len(v) >= 18:
            return _u32(v, 14) * spf / sr
        kbps = MP3_BR[1 if mpeg1 else 2][br_i]
        audio = R.size - off - i - (128 if R.read(R.size - 128, 3) == b"TAG" else 0)
        return audio * 8 / (kbps * 1000)
    return 0


def read_tags(path):
    meta = {"title": "", "artists": [], "album_artist": "", "album": "", "pics": [], "duration": 0.0}
    with open(path, "rb") as f:
        R = Reader(f, os.fstat(f.fileno()).st_size)
        h, off = R.read(0, 12), 0
        if h[:3] == b"ID3":
            off = id3_at(R, 0, meta)
            h = R.read(off, 12)
        if h[:4] == b"fLaC":
            flac_at(R, off, meta)
        elif h[:4] == b"OggS" and not off:
            ogg(R, meta)
        elif h[4:8] == b"ftyp":
            mp4(R, meta)
        elif h[:4] == b"RIFF" and h[8:12] == b"WAVE":
            iff(R, meta, True)
        elif h[:4] == b"FORM":
            iff(R, meta, False)
        elif os.path.splitext(path)[1].lower() == ".mp3" or (len(h) > 1 and h[0] == 0xff and h[1] & 0xe0 == 0xe0):
            meta["duration"] = mp3_duration(R, off)
    return meta


def name_guess(path):
    base = os.path.splitext(os.path.basename(path))[0].replace("_", " ").strip()
    m = re.match(r"^(.+?)\s+[-\u2013\u2014]\s+(.+)$", base)
    return (m.group(2), m.group(1)) if m else (base or "Untitled", "")


# ---------------------------------------------------------------- loudness envelope (ffmpeg, boxed)

_SB = {}


def _sandbox():
    if "m" not in _SB:
        try:
            p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "media", "sandbox.py")
            spec = importlib.util.spec_from_file_location("strata_media_sandbox", p)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            _SB["m"] = mod
        except Exception:
            _SB["m"] = None
    return _SB["m"]


def envelope(path, duration, n):
    """n loudness values 0..1 across the track, or None (no ffmpeg / undecodable)."""
    sb = _sandbox()
    exe = sb and sb.which("ffmpeg")
    if not exe:
        return None
    dur = duration if duration and duration > 0 else 600
    rate = int(max(200, min(8000, 2_000_000 / dur)))       # ~2 M samples whatever the length
    cmd = [exe, "-nostdin", "-hide_banner", "-loglevel", "error", "-protocol_whitelist", "file",
           "-format_whitelist", DEMUXERS, "-i", "file:" + path, "-map", "0:a:0", "-vn", "-sn", "-dn",
           "-ac", "1", "-ar", str(rate), "-t", "10800", "-f", "s16le", "pipe:1"]
    r = sb.run(cmd, timeout=45, mem_mb=512, cpu_pct=50, priority="below_normal", max_output=24 << 20)
    raw = r.out_bytes or b""
    if len(raw) < n * 8:
        return None
    a = array.array("h")
    a.frombytes(raw[:len(raw) // 2 * 2])
    step = len(a) / n
    vals = []
    for i in range(n):
        sl = a[int(i * step):int((i + 1) * step)]
        vals.append(sum(map(abs, sl)) / max(1, len(sl)))
    top = max(vals) or 1
    return [round((v / top) ** 0.75, 3) for v in vals]


# ---------------------------------------------------------------- colours


def _lin(v):
    v /= 255.0
    return v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4


def luminance(c):
    return 0.2126 * _lin(c[0]) + 0.7152 * _lin(c[1]) + 0.0722 * _lin(c[2])


def palette(img):
    """(dominant colour, three distinct colours) - most common buckets, nudged towards saturated ones."""
    from PIL import Image
    small = img.convert("RGB").resize((64, 64))
    q = small.quantize(colors=10, method=Image.Quantize.MEDIANCUT)
    pal = q.getpalette()
    counts = sorted(q.getcolors(), reverse=True)
    dominant = tuple(pal[counts[0][1] * 3:counts[0][1] * 3 + 3])
    scored = []
    for n, idx in counts:
        c = tuple(pal[idx * 3:idx * 3 + 3])
        s = colorsys.rgb_to_hsv(*(x / 255 for x in c))[1]
        scored.append((n * (0.55 + s), c))
    scored.sort(reverse=True)
    picks = []
    for _, c in scored:
        if all(sum((a - b) ** 2 for a, b in zip(c, d)) > 46 ** 2 for d in picks):
            picks.append(c)
        if len(picks) == 3:
            break
    while len(picks) < 3:
        h, l, s = colorsys.rgb_to_hls(*(x / 255 for x in (picks[-1] if picks else dominant)))
        picks.append(tuple(int(x * 255) for x in colorsys.hls_to_rgb((h + 0.08) % 1, max(0.1, l * 0.7), s)))
    return dominant, picks


def hash_palette(key):
    """A pleasant, stable triad for files without a cover."""
    h = (zlib.crc32(key.encode("utf-8")) % 360) / 360.0
    return [tuple(int(x * 255) for x in colorsys.hls_to_rgb((h + d) % 1, l, 0.55))
            for d, l in ((0, 0.32), (0.09, 0.22), (-0.07, 0.42))]


# ---------------------------------------------------------------- dot-matrix type (5x7, drawn as round dots)

GLYPHS = {
    "A": [" ### ", "#   #", "#   #", "#####", "#   #", "#   #", "#   #"],
    "B": ["#### ", "#   #", "#   #", "#### ", "#   #", "#   #", "#### "],
    "C": [" ### ", "#   #", "#    ", "#    ", "#    ", "#   #", " ### "],
    "D": ["#### ", "#   #", "#   #", "#   #", "#   #", "#   #", "#### "],
    "E": ["#####", "#    ", "#    ", "#### ", "#    ", "#    ", "#####"],
    "F": ["#####", "#    ", "#    ", "#### ", "#    ", "#    ", "#    "],
    "G": [" ### ", "#   #", "#    ", "# ###", "#   #", "#   #", " ####"],
    "H": ["#   #", "#   #", "#   #", "#####", "#   #", "#   #", "#   #"],
    "I": ["###", " # ", " # ", " # ", " # ", " # ", "###"],
    "J": ["  ###", "   # ", "   # ", "   # ", "   # ", "#  # ", " ##  "],
    "K": ["#   #", "#  # ", "# #  ", "##   ", "# #  ", "#  # ", "#   #"],
    "L": ["#    ", "#    ", "#    ", "#    ", "#    ", "#    ", "#####"],
    "M": ["#   #", "## ##", "# # #", "# # #", "#   #", "#   #", "#   #"],
    "N": ["#   #", "#   #", "##  #", "# # #", "#  ##", "#   #", "#   #"],
    "O": [" ### ", "#   #", "#   #", "#   #", "#   #", "#   #", " ### "],
    "P": ["#### ", "#   #", "#   #", "#### ", "#    ", "#    ", "#    "],
    "Q": [" ### ", "#   #", "#   #", "#   #", "# # #", "#  # ", " ## #"],
    "R": ["#### ", "#   #", "#   #", "#### ", "# #  ", "#  # ", "#   #"],
    "S": [" ####", "#    ", "#    ", " ### ", "    #", "    #", "#### "],
    "T": ["#####", "  #  ", "  #  ", "  #  ", "  #  ", "  #  ", "  #  "],
    "U": ["#   #", "#   #", "#   #", "#   #", "#   #", "#   #", " ### "],
    "V": ["#   #", "#   #", "#   #", "#   #", "#   #", " # # ", "  #  "],
    "W": ["#   #", "#   #", "#   #", "# # #", "# # #", "# # #", " # # "],
    "X": ["#   #", "#   #", " # # ", "  #  ", " # # ", "#   #", "#   #"],
    "Y": ["#   #", "#   #", " # # ", "  #  ", "  #  ", "  #  ", "  #  "],
    "Z": ["#####", "    #", "   # ", "  #  ", " #   ", "#    ", "#####"],
    "0": [" ### ", "#   #", "#  ##", "# # #", "##  #", "#   #", " ### "],
    "1": [" # ", "## ", " # ", " # ", " # ", " # ", "###"],
    "2": [" ### ", "#   #", "    #", "   # ", "  #  ", " #   ", "#####"],
    "3": ["#####", "   # ", "  #  ", "   # ", "    #", "#   #", " ### "],
    "4": ["   # ", "  ## ", " # # ", "#  # ", "#####", "   # ", "   # "],
    "5": ["#####", "#    ", "#### ", "    #", "    #", "#   #", " ### "],
    "6": ["  ## ", " #   ", "#    ", "#### ", "#   #", "#   #", " ### "],
    "7": ["#####", "    #", "   # ", "  #  ", " #   ", " #   ", " #   "],
    "8": [" ### ", "#   #", "#   #", " ### ", "#   #", "#   #", " ### "],
    "9": [" ### ", "#   #", "#   #", " ####", "    #", "   # ", " ##  "],
    ":": [" ", "#", " ", " ", " ", "#", " "],
    ".": [" ", " ", " ", " ", " ", " ", "#"],
    "-": ["   ", "   ", "   ", "###", "   ", "   ", "   "],
    "·": [" ", " ", " ", "#", " ", " ", " "],
    "/": ["    #", "    #", "   # ", "  #  ", " #   ", "#    ", "#    "],
    "!": ["#", "#", "#", "#", "#", " ", "#"],
    "+": ["     ", "  #  ", "  #  ", "#####", "  #  ", "  #  ", "     "],
    " ": ["  ", "  ", "  ", "  ", "  ", "  ", "  "],
}


def dot_width(text, pitch):
    cols = sum(len(GLYPHS.get(ch, GLYPHS[" "])[0]) + 1 for ch in text) - 1
    return max(0, cols) * pitch


def dot_text(draw, x, y, text, pitch, r, fill):
    """Draw text in the 5x7 dot font with its top-left at (x, y); returns the width."""
    cx = x
    for ch in text.upper():
        g = GLYPHS.get(ch, GLYPHS[" "])
        for row, line in enumerate(g):
            for col, on in enumerate(line):
                if on == "#":
                    px, py = cx + col * pitch + pitch / 2, y + row * pitch + pitch / 2
                    draw.ellipse((px - r, py - r, px + r, py + r), fill=fill)
        cx += (len(g[0]) + 1) * pitch
    return cx - pitch - x


# ---------------------------------------------------------------- fonts (system fonts, per-script fallback)

FONT_DIRS = [os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts"), "/usr/share/fonts/truetype/dejavu",
             "/usr/share/fonts/TTF", "/usr/share/fonts"]
LATIN = ["bahnschrift.ttf", "segoeui.ttf", "DejaVuSans.ttf"]
SCRIPTS = [  # (codepoint ranges, candidates)
    (((0x3040, 0x30ff), (0x31f0, 0x31ff), (0xff00, 0xffef), (0x3000, 0x303f)), ["YuGothB.ttc", "msyhbd.ttc"]),
    (((0x4e00, 0x9fff), (0x3400, 0x4dbf)), ["YuGothB.ttc", "msyhbd.ttc"]),
    (((0xac00, 0xd7af), (0x1100, 0x11ff), (0x3130, 0x318f)), ["malgunbd.ttf"]),
    (((0x0900, 0x0dff),), ["Nirmala.ttc"]),
    (((0x2190, 0x2bff), (0x2600, 0x27bf)), ["seguisym.ttf"]),
]
_fonts = {}


def _find(names):
    for n in names:
        for d in FONT_DIRS:
            p = os.path.join(d, n)
            if os.path.isfile(p):
                return p
    return None


def font(names, size, weight=None):
    key = (tuple(names), size, weight)
    if key not in _fonts:
        from PIL import ImageFont
        p = _find(names)
        f = None
        if p:
            try:
                f = ImageFont.truetype(p, size)
                if weight and p.lower().endswith("bahnschrift.ttf"):
                    try:
                        f.set_variation_by_name(weight)
                    except Exception:
                        pass
            except OSError:
                f = None
        if f is None:
            try:
                f = ImageFont.load_default(size)
            except TypeError:
                f = ImageFont.load_default()
        _fonts[key] = f
    return _fonts[key]


def _script_of(ch):
    o = ord(ch)
    for i, (ranges, _) in enumerate(SCRIPTS):
        if any(a <= o <= b for a, b in ranges):
            return i
    return -1


def runs(text, size, weight):
    """[(font, segment)] - consecutive characters of one script share a font."""
    out, cur, idx = [], "", None
    for ch in text:
        s = _script_of(ch)
        if s == -1 and idx is not None and idx != -1 and ch == " ":
            s = idx                       # keep spaces inside a CJK run
        if s != idx and cur:
            out.append((idx, cur))
            cur = ""
        idx = s
        cur += ch
    if cur:
        out.append((idx, cur))
    res = []
    for s, seg in out:
        names = LATIN if s == -1 else (SCRIPTS[s][1] + LATIN)
        res.append((font(names, size, weight if s == -1 else None), seg))
    return res


def text_width(text, size, weight, tracking=0):
    return sum(f.getlength(seg) for f, seg in runs(text, size, weight)) + tracking * max(0, len(text) - 1)


def draw_text(draw, x, baseline, text, size, weight, fill, tracking=0):
    for f, seg in runs(text, size, weight):
        if tracking:
            for ch in seg:
                draw.text((x, baseline), ch, font=f, fill=fill, anchor="ls")
                x += f.getlength(ch) + tracking
        else:
            draw.text((x, baseline), seg, font=f, fill=fill, anchor="ls")
            x += f.getlength(seg)


def _tokens(text):
    return re.findall(r"[\u3000-\u9fff\uac00-\ud7af\uff00-\uffef]|[^\s\u3000-\u9fff\uac00-\ud7af\uff00-\uffef]+\s*|\s+", text)


def wrap(text, size, weight, width, max_lines):
    """Greedy word wrap; returns (lines, fits) - the last line gets an ellipsis when the text does not fit."""
    lines, cur = [], ""
    for t in _tokens(text):
        if text_width((cur + t).rstrip(), size, weight) <= width or not cur:
            cur += t
        else:
            lines.append(cur.rstrip())
            cur = t.lstrip()
    if cur.strip():
        lines.append(cur.rstrip())
    fits = len(lines) <= max_lines and all(text_width(l, size, weight) <= width for l in lines)
    if not fits:
        lines = lines[:max_lines]
        last = lines[-1]
        while last and text_width(last + "…", size, weight) > width:
            last = last[:-1]
        lines[-1] = last.rstrip() + "…"
    return lines, fits


# ---------------------------------------------------------------- the card


def clock(s):
    s = int(round(s or 0))
    h, m, x = s // 3600, s // 60 % 60, s % 60
    return "%d:%02d:%02d" % (h, m, x) if h else "%d:%02d" % (m, x)


def _rounded_mask(size, radius):
    from PIL import Image, ImageDraw
    m = Image.new("L", size, 0)
    ImageDraw.Draw(m).rounded_rectangle((0, 0, size[0] - 1, size[1] - 1), radius, fill=255)
    return m


def S(v):
    """Card units (designed at 1x) -> supersampled pixels."""
    return int(round(v * SS))


def geometry():
    """(pad, side, tile x, tile y, radius) of the square tile on the right, in supersampled pixels."""
    pad = S(48)
    side = H * SS - 2 * pad
    return pad, side, W * SS - pad - side, pad, S(34)


def canvas(cols, blur=None):
    """The backdrop every card shares: a 3x2 colour mesh blown up (smooth by construction), an optional image blurred
    into it, film grain, a scrim behind the text column and a faint dot grid. -> (img, draw, ink, soft, dark_text)"""
    from PIL import Image, ImageDraw, ImageFilter, ImageOps
    w, h = W * SS, H * SS
    mix = lambda a, b, t: tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))  # noqa: E731
    c1, c2, c3 = cols
    mesh = Image.new("RGB", (3, 2))
    mesh.putdata([c1, mix(c1, c2, 0.5), c2, mix(c3, c1, 0.3), c3, mix(c2, c3, 0.5)])
    bg = mesh.resize((w, h), Image.BICUBIC).filter(ImageFilter.GaussianBlur(S(60)))
    if blur is not None:
        soft_img = ImageOps.fit(blur.convert("RGB"), (120, 50)).filter(ImageFilter.GaussianBlur(3)).resize((w, h), Image.BICUBIC)
        bg = Image.blend(bg, soft_img, 0.42)
    noise = Image.effect_noise((w // 2, h // 2), 40).resize((w, h)).convert("RGB")
    bg = Image.blend(bg, noise, 0.035)
    # text colour from what actually sits behind the text column, then a soft scrim for contrast
    _, _, ax, _, _ = geometry()
    left = bg.crop((0, 0, ax, h)).resize((1, 1), Image.BOX).getpixel((0, 0))
    dark_text = luminance(left) > 0.42
    ink = (14, 14, 16) if dark_text else (255, 255, 255)
    grad = Image.linear_gradient("L").rotate(-90).resize((w, h))     # 255 left -> 0 right
    grad = grad.point(lambda v: int(v * (0.22 if dark_text else 0.38)))
    img = Image.composite(Image.new("RGB", (w, h), (255, 255, 255) if dark_text else (0, 0, 0)), bg, grad)
    d = ImageDraw.Draw(img, "RGBA")       # RGBA mode: translucent fills blend into the card
    gp, gr = S(16), S(1.1)
    for yy in range(gp // 2, h, gp):
        for xx in range(gp // 2, w, gp):
            d.ellipse((xx - gr, yy - gr, xx + gr, yy + gr), fill=ink + (16,))
    return img, d, ink, ink + (205,), dark_text


def dotted_tile(label, base=(11, 11, 11), label_fill=(255, 255, 255, 255), max_pitch=22):
    """A dark tile with a dot grid and a centred dot-matrix label (files without a picture)."""
    from PIL import Image, ImageDraw
    _, side, _, _, _ = geometry()
    tile = Image.new("RGB", (side, side), base)
    td = ImageDraw.Draw(tile, "RGBA")
    tp, tr = S(14), S(1.6)
    for yy in range(tp // 2, side, tp):
        for xx in range(tp // 2, side, tp):
            td.ellipse((xx - tr, yy - tr, xx + tr, yy + tr), fill=(255, 255, 255, 40))
    label = label[:5]
    lp = S(max_pitch)
    while (dot_width(label, lp) > side * 0.8 or 7 * lp > side * 0.8) and lp > S(8):
        lp -= S(2)
    dot_text(td, (side - dot_width(label, lp)) / 2, (side - 7 * lp) / 2, label, lp, lp * 0.36, label_fill)
    return tile


def place_tile(img, d, tile, ring):
    """The rounded square on the right: soft shadow, the tile, a black / white outline."""
    from PIL import Image, ImageDraw, ImageFilter
    w, h = img.size
    pad, side, ax, ay, radius = geometry()
    shadow = Image.new("L", (w, h), 0)
    ImageDraw.Draw(shadow).rounded_rectangle((ax, ay + S(14), ax + side, ay + side + S(14)), radius, fill=120)
    img.paste((0, 0, 0), (0, 0), shadow.filter(ImageFilter.GaussianBlur(S(26))))
    img.paste(tile, (ax, ay), _rounded_mask((side, side), radius))
    rw = S(8)
    d.rounded_rectangle((ax - rw // 2, ay - rw // 2, ax + side + rw // 2, ay + side + rw // 2), radius + rw // 2,
                        outline=ring, width=rw)


def column():
    """(x0, x1) of the text column, in supersampled pixels."""
    _, _, ax, _, _ = geometry()
    return S(56), ax - S(56)


def heading(d, kicker, title, subtitle, ink, soft, kicker_fill=None):
    """Kicker in dot type, the title (up to two lines, shrinking to fit) and an upper-case subtitle. -> y below it"""
    x0, x1 = column()
    colw = x1 - x0
    pitch = S(9)
    dot_text(d, x0, S(52), kicker, pitch, pitch * 0.36, kicker_fill or ink)
    y = S(52) + 7 * pitch + S(30)
    size = S(76)
    while True:
        lines, fits = wrap(title or "Untitled", size, "Bold", colw, 2)
        if fits or size <= S(46):
            break
        size -= S(4)
    lh = int(size * 1.06)
    for i, line in enumerate(lines):
        draw_text(d, x0, y + int(size * 0.92) + i * lh, line, size, "Bold", ink)
    y += int(size * 0.92) + (len(lines) - 1) * lh + S(22)
    sub = (subtitle or "").upper()
    asz, track = S(26), S(3)
    while sub and text_width(sub, asz, "SemiBold", track) > colw and len(sub) > 1:
        sub = sub[:-2].rstrip() + "…"
    if sub:
        draw_text(d, x0, y + int(asz * 0.9), sub, asz, "SemiBold", soft, track)
    return y + int(asz * 0.9)


def footer(d, left, right, ink, soft):
    """One line of dot type at the bottom of the column: left-aligned, and right-aligned when it fits."""
    x0, x1 = column()
    fp = S(4.2)
    y = H * SS - S(48) - S(44) + S(22) - 3.5 * fp
    if left:
        dot_text(d, x0, y, left, fp, fp * 0.38, ink)
    room = (x1 - x0) - (dot_width(left, fp) if left else 0) - S(40)
    right = (right or "").upper()
    while right and dot_width(right, fp) > room:
        right = right[:-2].rstrip()
    if right and len(right) > 2:
        dot_text(d, x1 - dot_width(right, fp), y, right, fp, fp * 0.38, soft)


def finish(img):
    from PIL import Image
    out = img.resize((W, H), Image.LANCZOS)
    buf = io.BytesIO()
    out.save(buf, "JPEG", quality=90, optimize=True, progressive=True)
    return buf.getvalue()


def render(info, art, wave):
    """info: title, artist, duration, ext, key. art: PIL image or None. wave: list 0..1 or None. -> JPEG bytes."""
    from PIL import ImageOps
    if art is not None:
        art = ImageOps.exif_transpose(art).convert("RGB")
        dominant, cols = palette(art)
        ring = (0, 0, 0) if luminance(dominant) > 0.36 else (255, 255, 255)
    else:
        cols = hash_palette(info["key"])
        ring = (255, 255, 255)
    img, d, ink, soft, _ = canvas(cols, art)
    _, side, _, _, _ = geometry()
    tile = ImageOps.fit(art, (side, side)) if art is not None else dotted_tile(info.get("ext") or "AUDIO")
    place_tile(img, d, tile, ring)
    heading(d, "LISTEN TO", info["title"], info["artist"] or "Unknown artist", ink, soft)

    # waveform: the track's loudness as a dot matrix, mirrored around its middle row; first column red
    x0, x1 = column()
    wp, wr = S(10), S(3.1)
    rows = 7
    cols_n = int((x1 - x0) // wp)
    wy = H * SS - S(48) - S(44) - S(34) - rows * wp
    half = rows // 2
    vals = [wave[min(len(wave) - 1, int(i * len(wave) / cols_n))] for i in range(cols_n)] if wave else None
    for c in range(cols_n):
        cx = x0 + c * wp + wp / 2
        k = round(vals[c] * half) if vals else 0
        for r in range(rows):
            cy = wy + r * wp + wp / 2
            lit = abs(r - half) <= k if vals else r == half
            if c == 0:
                fill = RED + (255,) if lit or r == half else ink + (34,)
            else:
                fill = (ink + (232,)) if lit else (ink + (34,))
            d.ellipse((cx - wr, cy - wr, cx + wr, cy + wr), fill=fill)

    footer(d, " · ".join(x for x in (clock(info["duration"]) if info.get("duration") else "", info.get("ext") or "") if x),
           info.get("album"), ink, soft)
    return finish(img), "#%02x%02x%02x" % cols[0]


# ---------------------------------------------------------------- cached entry points


def _key(path, st):
    return hashlib.sha1(json.dumps([path, st.st_size, st.st_mtime, VERSION]).encode()).hexdigest()


def describe(path, st):
    """(info, raw tags): title, artist, album, duration, ext, key - read fresh from the file."""
    k = _key(path, st)
    try:
        meta = read_tags(path)
    except Exception:
        meta = {"title": "", "artists": [], "album_artist": "", "album": "", "pics": [], "duration": 0.0}
    gt, ga = name_guess(path)
    info = {"title": meta["title"] or gt, "artist": ", ".join(meta["artists"]) or meta["album_artist"] or ga,
            "album": meta["album"], "duration": round(meta["duration"] or 0, 2),
            "ext": os.path.splitext(path)[1].lstrip(".").upper(), "key": k, "has_art": bool(meta["pics"])}
    return info, meta


def touch(*paths):
    """Mark cached files as used (eviction goes by modified time); at most once a day, so hits stay read-only."""
    import time
    for p in paths:
        try:
            if os.path.getmtime(p) < time.time() - 86400:
                os.utime(p, None)
        except OSError:
            pass


def card(path, st, cache_dir, ov=None):
    """(jpeg bytes, info) - drawn once per file version (and per link-preview override)."""
    ov = ov or {}
    k = _key(path, st)
    if ov:
        k = hashlib.sha1((k + json.dumps(ov, sort_keys=True)).encode()).hexdigest()
    cdir = os.path.join(cache_dir, "cards", k[:2])
    cp, jp = os.path.join(cdir, k + ".jpg"), os.path.join(cdir, k + ".json")
    if os.path.isfile(cp) and os.path.isfile(jp):
        try:
            with open(cp, "rb") as f, open(jp, encoding="utf-8") as g:
                hit = f.read(), json.load(g)
            touch(cp, jp)
            return hit
        except (OSError, ValueError):
            pass
    with _LOCK:
        info, meta = describe(path, st)
        info["key"] = k
        if ov.get("title"):
            info["title"] = ov["title"]
        art = None
        pics = meta.get("pics") or []
        pic = next((p for t, p in pics if t == 3), None) or (pics[0][1] if pics else None)
        if pic is None:
            art = sidecar(path)
        else:
            try:
                from PIL import Image
                Image.MAX_IMAGE_PIXELS = 60_000_000
                art = Image.open(io.BytesIO(pic))
                art.load()
            except Exception:
                art = sidecar(path)
        try:
            wave = envelope(path, info["duration"], 120)
        except Exception:
            wave = None
        data, color = render(info, art, wave)
        info["color"] = ov.get("color") or color
        if ov.get("description"):
            info["description"] = ov["description"]
        info["has_art"] = art is not None
        os.makedirs(cdir, exist_ok=True)
        for p, blob in ((cp, data), (jp, json.dumps(info).encode("utf-8"))):
            tmp = p + ".tmp"
            with open(tmp, "wb") as f:
                f.write(blob)
            os.replace(tmp, p)
        return data, info


def sidecar(path):
    """cover.jpg / folder.jpg / front.png ... next to the file (same names the player looks for)."""
    from PIL import Image
    d = os.path.dirname(path)
    try:
        names = os.listdir(d)
    except OSError:
        return None
    pref = sorted((n for n in names if re.fullmatch(r"(?i)(cover|folder|front|album|albumart|artwork)\.(jpe?g|png|webp)", n)),
                  key=lambda n: not re.match(r"(?i)cover|front", n))
    for n in pref:
        try:
            Image.MAX_IMAGE_PIXELS = 60_000_000
            im = Image.open(os.path.join(d, n))
            im.load()
            return im
        except Exception:
            continue
    return None


def info_for(path, st, cache_dir):
    """Metadata for the link preview; draws the card first if needed (it also fixes the embed colour)."""
    return card(path, st, cache_dir)[1]


def embed_html(info, page_url, card_url, host, custom_image=False):
    e = lambda v: html.escape(str(v or ""), quote=True)  # noqa: E731
    title = info.get("title") or "Untitled"
    artist = info.get("artist") or ""
    bits = [b for b in (artist, clock(info["duration"]) if info.get("duration") else "", info.get("ext") or "") if b]
    desc = info.get("description") or " · ".join(bits)
    full = "%s — %s" % (title, artist) if artist else title
    tags = [
        ("property", "og:type", "music.song"), ("property", "og:site_name", host),
        ("property", "og:title", title), ("property", "og:description", desc),
        ("property", "og:url", page_url), ("property", "og:image", card_url),
        ("property", "og:image:secure_url", card_url),
    ] + ([] if custom_image else [("property", "og:image:type", "image/jpeg"),
                                   ("property", "og:image:width", W), ("property", "og:image:height", H)]) + [
        ("property", "og:image:alt", full),
        ("name", "twitter:card", "summary_large_image"), ("name", "twitter:title", title),
        ("name", "twitter:description", desc), ("name", "twitter:image", card_url),
        ("name", "theme-color", info.get("color") or "#111111"),
    ]
    if info.get("duration"):
        tags.append(("property", "music:duration", int(round(info["duration"]))))
    if artist:
        tags.append(("property", "music:musician", artist))
    head = "\n".join('<meta %s="%s" content="%s">' % (a, e(k), e(v)) for a, k, v in tags)
    return ("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n<title>%s</title>\n%s\n"
            "<link rel=\"canonical\" href=\"%s\">\n</head><body><p><a href=\"%s\">%s</a></p>"
            "</body></html>\n" % (e(full), head, e(page_url), e(page_url), e(full))).encode("utf-8")
