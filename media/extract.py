"""Strata Media safe archive extraction (DESIGN.md 7.5).

Archives are hostile until proven otherwise. extract() unpacks one into a private sandbox dir (the worker passes
<cache_root>/sandbox/<job id>) so scan.py can run the detectors and AV over the members, and it never lets an
archive write outside that dir or eat the disk:
  * member names are validated before anything is created (absolute / drive / UNC paths, '..', NUL and control
    characters, ADS colons, reserved device names, trailing dots and spaces) and the final path must stay
    under the sandbox (sandbox.safe_join);
  * links, hard links and device entries are never created: zip unix-mode symlinks are refused, tar members go
    through tarfile.data_filter plus our own checks, 7-Zip runs with -snl- and a post-walk deletes any reparse
    point and re-validates every path that landed;
  * sizes come from counting the bytes actually written, never from headers: per-entry, total and ratio limits
    (scan.archive.*) are enforced while streaming, overlapping zip entries (the "zip bomb without recursion")
    are refused, the entry count is capped, nesting stops at max_depth, and one budget (bytes, entries, time) is
    shared by an archive and everything nested in it. Disk free space is checked as we go.
Limit breaches raise BombError (scan.py records finding archive_bomb, high); a single bad member (traversal,
link) is skipped and reported as archive_bomb; encrypted members become "unscannable" (medium) findings.
zip/tar/gz/bz2/xz use the stdlib, zst the vendored zstandard when importable, and 7z/rar (and zip methods the
stdlib cannot read) go through 7-Zip inside sandbox.run.
"""
import bz2
import gzip
import lzma
import os
import re
import shutil
import stat
import tarfile
import time
import zipfile
import zlib

import config
import detect
import sandbox

try:
    import zstandard
except ImportError:
    zstandard = None
_ZSTD_ERRORS = (zstandard.ZstdError,) if zstandard is not None else ()

CHUNK = 1 << 20
LIMITS = {"max_total_bytes": 24 << 30, "max_entries": 50000, "max_entry_bytes": 12 << 30, "max_ratio": 250,
          "max_depth": 3,
          # not in core.DEFAULTS (safe built-in values, overridable through scan.archive):
          "ratio_min_bytes": 1 << 20,     # the ratio limit only applies above this many bytes (DESIGN 7.5)
          "min_free_bytes": 2 << 30,      # stop (SpaceError, retried later) before the sandbox disk runs dry
          "max_findings": 50}             # per finding type; the rest are summarised
ZIP_METHODS = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA}
if hasattr(zipfile, "ZIP_ZSTANDARD"):  # Python 3.14+
    ZIP_METHODS.add(zipfile.ZIP_ZSTANDARD)
_STREAM_ERRORS = (zipfile.BadZipFile, tarfile.TarError, EOFError, zlib.error, lzma.LZMAError, ValueError,
                  NotImplementedError, RuntimeError) + _ZSTD_ERRORS
_TAR_ERRORS = (tarfile.TarError, EOFError, zlib.error, lzma.LZMAError, OSError) + _ZSTD_ERRORS
_RESERVED = re.compile(r"(con|prn|aux|nul|conin\$|conout\$|clock\$|(com|lpt)[0-9¹²³])", re.I)
_BAD_CHARS = re.compile(r'[<>:"|?*]')
_SINGLE_EXT = {"gz": ("gz", "tgz"), "bz2": ("bz2", "tbz2", "tbz"), "xz": ("xz", "txz"), "zst": ("zst", "tzst")}


class ArchiveError(Exception):
    """The archive cannot be (fully) unpacked: corrupt, unknown format, tool failure."""


class BombError(ArchiveError):
    """A limit was breached (size, ratio, entries, overlap, nesting): the whole archive is treated as hostile."""


class EncryptedError(ArchiveError):
    """The archive as a whole is encrypted (e.g. 7z with encrypted headers): nothing inside can be inspected."""


class SpaceError(ArchiveError):
    """The sandbox disk is running low: retry later - this says nothing about the archive itself."""


class Timeout(ArchiveError):
    """The scan time budget ran out."""


class Cancelled(ArchiveError):
    """The caller's cancel() returned true."""


_FATAL = (BombError, EncryptedError, SpaceError, Timeout, Cancelled)


def limits(conf):
    lim = dict(LIMITS)
    s = (conf or {}).get("scan") or {}
    lim.update({k: v for k, v in (s.get("archive") or {}).items() if k in LIMITS})
    lim["timeout_s"] = float(s.get("timeout_s") or 1800)
    return lim


def long_path(path):
    """\\\\?\\ form for paths near MAX_PATH (archives nest deep); unchanged elsewhere."""
    p = os.path.abspath(path)
    if os.name != "nt" or len(p) < 240 or p.startswith("\\\\?\\"):
        return p
    return "\\\\?\\UNC\\" + p[2:] if p.startswith("\\\\") else "\\\\?\\" + p


def check_name(name):
    """(parts, None) for a safe member name, (None, reason) otherwise. Pure string checks, nothing touches disk."""
    if not isinstance(name, str) or not name:
        return None, "empty name"
    if any(ord(c) < 32 or ord(c) == 127 for c in name):
        return None, "NUL or control characters in name"
    n = name.replace("\\", "/")
    if n.startswith("/"):
        return None, "absolute path"
    if re.match(r"[A-Za-z]:", n):
        return None, "drive-letter path"
    parts = [p for p in n.split("/") if p not in ("", ".")]
    if not parts:
        return None, "empty name"
    for p in parts:
        if p == "..":
            return None, "path traversal (..)"
        if ":" in p:
            return None, "colon in name (drive or alternate data stream)"
        if _BAD_CHARS.search(p):
            return None, "reserved characters in name"
        if p[-1] in ". ":
            return None, "trailing dot or space in name"
        if _RESERVED.fullmatch(p.split(".", 1)[0].rstrip(" ")):
            return None, "reserved device name"
        if len(p) > 255:
            return None, "name component too long"
    return parts, None


def _root_entry(name):
    """'.' / './' directory members (tar -C dir .) name the archive root itself: nothing to create or report."""
    n = (name or "").replace("\\", "/")
    return bool(n) and not n.startswith("/") and all(p in ("", ".") for p in n.split("/"))


def sniff(path):
    """Archive format by magic bytes (extensions lie): zip 7z rar gz bz2 xz zst tar, or None."""
    with open(path, "rb") as f:
        head = f.read(512)
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "zip"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if head[:7] == b"Rar!\x1a\x07\x00" or head[:8] == b"Rar!\x1a\x07\x01\x00":
        return "rar"
    if head[:2] == b"\x1f\x8b":
        return "gz"
    if head[:3] == b"BZh":
        return "bz2"
    if head[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if head[:4] == b"\x28\xb5\x2f\xfd":
        return "zst"
    if head[257:262] == b"ustar":
        return "tar"
    try:
        if zipfile.is_zipfile(path):       # self-extracting / prefixed zip
            return "zip"
        if config.ext_of(path) == "tar" and tarfile.is_tarfile(path):   # pre-POSIX tar has no magic
            return "tar"
    except OSError:
        pass
    return None


# ---------------------------------------------------------------- budget / findings helpers

def _printable(name):
    return re.sub(r"[\x00-\x1f\x7f]", "?", str(name))[:240]


def _add(res, f, lim):
    """Keep at most max_findings per type (50 000 encrypted members are one problem); count the rest."""
    kept = res["_kept"].get(f["type"], 0)
    if kept < lim["max_findings"]:
        res["_kept"][f["type"]] = kept + 1
        res["findings"].append(f)
    else:
        res["_supp"][f["type"]] = res["_supp"].get(f["type"], (0, f["severity"]))[0] + 1, f["severity"]


def _bad(res, lim, name, why):
    _add(res, detect.finding("archive_bomb", "high", why, _printable(name), "high"), lim)


def _unscannable(res, lim, name, why):
    _add(res, detect.finding("unscannable", "medium", why, _printable(name), "high"), lim)


def _tick(budget):
    now = time.monotonic()
    if now - budget["tick"] < 0.25:
        return
    budget["tick"] = now
    if now > budget["deadline"]:
        raise Timeout("scan time budget exhausted while extracting")
    cancel = budget.get("cancel")
    if cancel is not None and cancel():
        raise Cancelled("cancelled")


def _left(budget):
    return max(5.0, budget["deadline"] - time.monotonic())


def _count(budget, lim, n):
    budget["entries"] += n
    if budget["entries"] > lim["max_entries"]:
        raise BombError("more than %d entries" % lim["max_entries"])


def _space(budget, lim, need=0):
    budget["checked"] = budget["bytes"]
    try:
        free = shutil.disk_usage(budget["root"]).free
    except OSError:
        return
    if free - need < lim["min_free_bytes"]:
        raise SpaceError("sandbox disk low (%d MB free)" % (free >> 20))


def _gib(n):
    return "%.1f GiB" % (n / 1073741824.0) if n >= 1 << 30 else "%d MiB" % (n >> 20)


def _copy(src, target, lim, budget, packed, base=None):
    """Stream src into a new file, counting real bytes. packed = compressed size the ratio is measured against
    (the entry's, or the whole archive's when base = budget bytes at archive start); None = no ratio check."""
    os.makedirs(long_path(os.path.dirname(target)), exist_ok=True)
    n, ok = 0, False
    f = open(long_path(target), "xb")     # never overwrite: duplicate names are reported, not merged
    try:
        while True:
            _tick(budget)
            buf = src.read(CHUNK)
            if not buf:
                break
            n += len(buf)
            budget["bytes"] += len(buf)
            if n > lim["max_entry_bytes"]:
                raise BombError("entry expands beyond %s" % _gib(lim["max_entry_bytes"]))
            if budget["bytes"] > lim["max_total_bytes"]:
                raise BombError("archive expands beyond %s" % _gib(lim["max_total_bytes"]))
            if packed is not None:
                counted = n if base is None else budget["bytes"] - base
                if counted > lim["ratio_min_bytes"] and counted > lim["max_ratio"] * max(packed, 1):
                    raise BombError("compression ratio above %d:1" % lim["max_ratio"])
            f.write(buf)
            if budget["bytes"] - budget["checked"] >= 256 << 20:
                _space(budget, lim)
        ok = True
        return n
    finally:
        f.close()
        if not ok:
            try:
                os.remove(long_path(target))
            except OSError:
                pass


def _write_member(res, lim, budget, name, parts, root, opener, packed, base=None):
    """Create one member; per-member failures become findings, limit breaches propagate."""
    try:
        target = sandbox.safe_join(root, *parts)
    except ValueError:
        _bad(res, lim, name, "path escapes the sandbox")
        return
    try:
        with opener() as src:
            n = _copy(src, target, lim, budget, packed, base)
    except FileExistsError:
        _unscannable(res, lim, name, "duplicate member name (only the first copy was scanned)")
        return
    except _STREAM_ERRORS as e:
        _unscannable(res, lim, name, "corrupt member: %s" % str(e)[:120])
        return
    except OSError as e:
        if getattr(e, "winerror", None) in (225, 226):   # ERROR_VIRUS_INFECTED / _DELETED: Defender blocked it
            _add(res, detect.finding("av_threat", "high", "blocked by real-time antivirus", _printable(name)), lim)
            return
        if isinstance(e, (NotADirectoryError, IsADirectoryError, PermissionError)):
            _unscannable(res, lim, name, "conflicting member names")
            return
        raise
    res["files"].append(("/".join(parts), target, n))


# ---------------------------------------------------------------- formats

def _zip(path, root, lim, budget, res, tools):
    size = os.path.getsize(path)
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError, ValueError, NotImplementedError, EOFError) as e:
        if (tools or {}).get("7z"):
            return _sevenzip(path, root, lim, budget, res, tools, "zip")
        raise ArchiveError("unreadable zip: %s" % str(e)[:160])
    with zf:
        infos = zf.infolist()
        if (tools or {}).get("7z") and any(i.compress_type not in ZIP_METHODS and not i.flag_bits & 1 for i in infos):
            zf.close()                    # Deflate64, PPMd, ...: let 7-Zip read it
            return _sevenzip(path, root, lim, budget, res, tools, "zip")
        _count(budget, lim, len(infos))
        prev_end = -1                     # entries sharing compressed data = overlap bomb
        for off, csize in sorted((i.header_offset, i.compress_size) for i in infos if i.compress_size):
            if off < prev_end:
                raise BombError("overlapping zip entries")
            prev_end = off + 30 + csize   # a local header is at least 30 bytes
        for info in infos:
            _tick(budget)
            name = info.filename
            if info.is_dir() and _root_entry(name):
                continue
            parts, why = check_name(name)
            if why:
                _bad(res, lim, name, why)
                continue
            # only the file-type bits count: zip writers such as Python's store a plain file as bare permissions (0o600)
            kind = stat.S_IFMT((info.external_attr >> 16) & 0xFFFF)
            if info.create_system == 3 and kind and kind not in (stat.S_IFREG, stat.S_IFDIR):
                _bad(res, lim, name, "symlink" if kind == stat.S_IFLNK else "device or special file")
                continue
            if info.is_dir():
                _mkdir(res, lim, root, name, parts)
                continue
            if info.flag_bits & 0x1:
                _unscannable(res, lim, name, "encrypted member")
                continue
            if info.compress_type not in ZIP_METHODS:
                _unscannable(res, lim, name, "unsupported compression method %d (7-Zip missing)" % info.compress_type)
                continue
            _write_member(res, lim, budget, name, parts, root, lambda i=info: zf.open(i), min(info.compress_size, size))
    return "zipfile"


def _mkdir(res, lim, root, name, parts):
    try:
        os.makedirs(long_path(sandbox.safe_join(root, *parts)), exist_ok=True)
    except ValueError:
        _bad(res, lim, name, "path escapes the sandbox")
    except OSError:
        _unscannable(res, lim, name, "conflicting member names")


def _tar(path, root, lim, budget, res, fileobj=None):
    packed = os.path.getsize(path)
    base = budget["bytes"]
    try:
        tf = tarfile.open(path if fileobj is None else None, "r:*" if fileobj is None else "r|", fileobj=fileobj)
    except _TAR_ERRORS as e:
        raise ArchiveError("unreadable tar: %s" % str(e)[:160])
    declared = 0
    with tf:
        try:
            for m in tf:
                _tick(budget)
                _count(budget, lim, 1)
                if m.isdir() and _root_entry(m.name):
                    continue
                # tarfile decompresses a member's data even to skip it, so header sizes are an early bomb signal
                # (only ever used to refuse; what we extract is still counted byte by byte in _copy)
                declared += max(0, m.size) if m.isreg() else 0
                if m.size > lim["max_entry_bytes"]:
                    raise BombError("entry declares more than %s" % _gib(lim["max_entry_bytes"]))
                if declared > lim["max_total_bytes"]:
                    raise BombError("archive declares more than %s" % _gib(lim["max_total_bytes"]))
                if declared > lim["ratio_min_bytes"] and declared > lim["max_ratio"] * max(packed, 1):
                    raise BombError("compression ratio above %d:1" % lim["max_ratio"])
                parts, why = check_name(m.name)
                if why:
                    _bad(res, lim, m.name, why)
                    continue
                if m.issym() or m.islnk():
                    _bad(res, lim, m.name, "symlink" if m.issym() else "hard link")
                    continue
                if not (m.isfile() or m.isdir()):
                    _bad(res, lim, m.name, "device or special file")
                    continue
                try:
                    tarfile.data_filter(m, root)         # the stdlib's own "data" policy, on top of ours
                except tarfile.FilterError as e:
                    _bad(res, lim, m.name, "refused by tar data filter (%s)" % e.__class__.__name__)
                    continue
                if m.isdir():
                    _mkdir(res, lim, root, m.name, parts)
                    continue
                _write_member(res, lim, budget, m.name, parts, root, lambda m=m: tf.extractfile(m), packed, base)
        except _TAR_ERRORS as e:
            if not res["files"]:
                raise ArchiveError("unreadable tar: %s" % str(e)[:160])
            _unscannable(res, lim, "", "truncated or corrupt tar: %s" % str(e)[:120])
    return "tarfile"


def _single(path, root, lim, budget, res, opener, tool):
    """A lone compressed file (x.log.gz): decompress it to one member named like the source minus its suffix."""
    base = os.path.basename(path)
    stem = base.rsplit(".", 1)[0] if "." in base.strip(".") else base + ".out"
    parts, why = check_name(stem)
    if why:
        parts = ["content"]
    size = os.path.getsize(path)
    before = len(res["files"])
    _write_member(res, lim, budget, stem, parts, root, opener, size)
    if len(res["files"]) == before and not res["findings"]:
        raise ArchiveError("unreadable %s stream" % tool)
    return tool


def _compressed(kind, path, root, lim, budget, res, tools):
    """gz / bz2 / xz / zst: a compressed tar, else a single compressed file. A "tar" without a single member is
    treated as a single file too: tarfile reads a stream that starts with 512 zero bytes as an empty archive, which
    would let a gzip bomb of zeros (or any content starting with zeros) pass unread."""
    before = budget["entries"]
    if kind == "zst":
        if zstandard is None:
            return _sevenzip(path, root, lim, budget, res, tools, "zst")
        try:
            with open(path, "rb") as fh:
                tool = _tar(path, root, lim, budget, res, fileobj=_zstd_reader(fh))
            if budget["entries"] > before:
                return tool
            _reset(root, res)
        except _FATAL:
            raise
        except ArchiveError:
            if res["files"]:
                raise
            _reset(root, res)
        opener = lambda: _ZstdFile(path)                     # noqa: E731
        return _single(path, root, lim, budget, res, opener, "zstandard")
    try:
        tool = _tar(path, root, lim, budget, res)
        if budget["entries"] > before:
            return tool
        _reset(root, res)
    except _FATAL:        # a bomb / timeout / cancel inside a real tar is not "maybe it is a single file"
        raise
    except ArchiveError:
        if res["files"]:
            raise
        _reset(root, res)
    opener = {"gz": lambda: gzip.open(path, "rb"), "bz2": lambda: bz2.open(path, "rb"),
              "xz": lambda: lzma.open(path, "rb")}[kind]
    return _single(path, root, lim, budget, res, opener, {"gz": "gzip", "bz2": "bz2", "xz": "lzma"}[kind])


def _zstd_reader(fh):
    try:
        return zstandard.ZstdDecompressor().stream_reader(fh, read_across_frames=True, closefd=False)
    except TypeError:  # older zstandard without read_across_frames
        return zstandard.ZstdDecompressor().stream_reader(fh)


class _ZstdFile:
    def __init__(self, path):
        self._fh = open(path, "rb")
        self._r = _zstd_reader(self._fh)

    def read(self, n):
        return self._r.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self._r.close()
        self._fh.close()


def _reset(root, res):
    """Undo a failed tar attempt before treating the stream as a single compressed file."""
    res["findings"], res["_kept"], res["_supp"] = [], {}, {}
    sandbox.rmtree(root)
    os.makedirs(root, exist_ok=True)


def parse_slt(text):
    """7-Zip 'l -slt' output -> list of {key: value} per member (the archive's own block is skipped)."""
    body = text.split("\n----------", 1)
    if len(body) < 2:
        return []
    entries, cur = [], {}
    for line in body[1].splitlines():
        line = line.rstrip("\r")
        if not line.strip():
            if cur:
                entries.append(cur)
                cur = {}
            continue
        k, sep, v = line.partition(" = ")
        if sep:
            cur[k.strip()] = v
        elif line.endswith(" ="):
            cur[line[:-2].strip()] = ""
    if cur:
        entries.append(cur)
    return [e for e in entries if "Path" in e]


def _slt_link(e):
    attrs = e.get("Attributes", "")
    return bool(e.get("Symbolic Link") or e.get("Hard Link") or re.search(r"(?:^|\s)l[rwxsStT-]{9}", attrs))


def _sevenzip(path, root, lim, budget, res, tools, kind):
    exe = (tools or {}).get("7z")
    if not exe:
        _unscannable(res, lim, "", "%s archive not inspected: 7-Zip missing" % kind)
        return "missing"
    r = sandbox.run([exe, "l", "-slt", "-p-", "-y", "-sccUTF-8", path], timeout=min(_left(budget), 600.0),
                    mem_mb=1024, cpu_pct=35)
    if r.timed_out:
        raise Timeout("7-Zip listing timed out")
    if r.rc != 0:
        blob = (r.out + r.err).lower()
        if "password" in blob or "encrypted" in blob:
            raise EncryptedError("encrypted archive (headers)")
        raise ArchiveError("7-Zip cannot read the archive (rc=%s): %s" % (r.rc, (r.err or r.out).strip()[-160:]))
    entries = parse_slt(r.out)
    _count(budget, lim, len(entries))
    listed, encrypted = 0, 0
    for e in entries:
        name = e.get("Path", "")
        try:
            size = int(e.get("Size") or 0)
        except ValueError:
            size = 0
        parts, why = check_name(name)
        if why:     # 7-Zip sanitises such names itself; still a sign of a hostile archive
            _bad(res, lim, name, why)
        if _slt_link(e):
            _bad(res, lim, name, "symlink")
        if e.get("Encrypted") == "+":
            encrypted += 1
            _unscannable(res, lim, name, "encrypted member")
        if size > lim["max_entry_bytes"]:
            raise BombError("entry expands beyond %s" % _gib(lim["max_entry_bytes"]))
        listed += size
    if budget["bytes"] + listed > lim["max_total_bytes"]:
        raise BombError("archive expands beyond %s" % _gib(lim["max_total_bytes"]))
    if listed > lim["ratio_min_bytes"] and listed > lim["max_ratio"] * max(os.path.getsize(path), 1):
        raise BombError("compression ratio above %d:1" % lim["max_ratio"])
    _space(budget, lim, need=listed)
    x = sandbox.run([exe, "x", "-y", "-bd", "-p-", "-snl-", "-sccUTF-8", "-o" + root, path], timeout=_left(budget),
                    mem_mb=1024, cpu_pct=35)
    if x.timed_out:
        raise Timeout("7-Zip extraction timed out")
    if x.killed or (x.rc not in (0, 1) and not encrypted):
        raise ArchiveError("7-Zip extraction failed (rc=%s, %s): %s" % (x.rc, x.killed or "error",
                                                                         (x.err or x.out).strip()[-160:]))
    _post_walk(root, lim, budget, res)
    return "7z"


def _is_link(path):
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return (stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & 0x400)
            or (hasattr(os.path, "isjunction") and os.path.isjunction(path)))


def _post_walk(root, lim, budget, res):
    """After an external extractor: delete every reparse point, re-validate every path, count real sizes."""
    lroot = long_path(root)
    real_root = os.path.normcase(os.path.realpath(root))
    for dp, dns, fns in os.walk(lroot, followlinks=False):
        for d in list(dns):
            full = os.path.join(dp, d)
            if _is_link(full):
                dns.remove(d)
                sandbox.rmtree(full)
                _bad(res, lim, _rel(lroot, full), "link or junction (removed)")
        for fn in fns:
            _tick(budget)
            full = os.path.join(dp, fn)
            rel = _rel(lroot, full)
            parts, why = check_name(rel)
            if why is None and _is_link(full):
                why = "link or junction (removed)"
            if why is None:
                real = os.path.normcase(os.path.realpath(full))
                if os.path.commonpath([real, real_root]) != real_root:
                    why = "path escapes the sandbox"
            if why:
                sandbox.rmtree(full)
                _bad(res, lim, rel, why)
                continue
            size = os.lstat(full).st_size
            if size > lim["max_entry_bytes"]:
                raise BombError("entry expands beyond %s" % _gib(lim["max_entry_bytes"]))
            budget["bytes"] += size
            if budget["bytes"] > lim["max_total_bytes"]:
                raise BombError("archive expands beyond %s" % _gib(lim["max_total_bytes"]))
            res["files"].append(("/".join(parts), os.path.join(root, *parts), size))


def _rel(lroot, full):
    return os.path.relpath(full, lroot).replace("\\", "/")


# ---------------------------------------------------------------- entry point

def extract(path, dest, conf, tools, depth=0, budget=None, cancel=None, deadline=None):
    """Unpack path under dest; nested archives are unpacked too (up to scan.archive.max_depth) with one shared
    budget. Returns {"files": [(rel, abs, size)], "findings": [...], "tool": str}; rel of nested members is
    "inner.zip/member". Raises BombError / EncryptedError / SpaceError / Timeout / Cancelled / ArchiveError.
    The caller owns dest and deletes it afterwards (sandbox.rmtree)."""
    lim = limits(conf)
    if budget is None:
        os.makedirs(dest, exist_ok=True)
        budget = {"bytes": 0, "entries": 0, "seq": 0, "root": os.path.abspath(dest), "checked": 0, "tick": 0.0,
                  "cancel": cancel, "deadline": deadline or time.monotonic() + lim["timeout_s"]}
        _space(budget, lim)
    if depth > lim["max_depth"]:
        raise BombError("nested deeper than %d levels" % lim["max_depth"])
    root = os.path.join(budget["root"], "a%d" % budget["seq"])   # every (nested) archive gets its own dir
    budget["seq"] += 1
    os.makedirs(root, exist_ok=True)
    res = {"files": [], "findings": [], "tool": "", "_kept": {}, "_supp": {}}
    kind = sniff(path)
    if kind is None:
        raise ArchiveError("unknown archive format")
    if kind == "zip":
        res["tool"] = _zip(path, root, lim, budget, res, tools)
    elif kind == "tar":
        res["tool"] = _tar(path, root, lim, budget, res)
    elif kind in _SINGLE_EXT:
        res["tool"] = _compressed(kind, path, root, lim, budget, res, tools)
    else:  # 7z, rar
        res["tool"] = _sevenzip(path, root, lim, budget, res, tools, kind)

    for rel, full, _size in list(res["files"]):
        if config.category(rel) != "archive":
            continue
        if depth + 1 > lim["max_depth"]:
            _bad(res, lim, rel, "archive nested deeper than %d levels" % lim["max_depth"])
            continue
        try:
            sub = extract(full, dest, conf, tools, depth + 1, budget)
        except BombError as e:
            raise BombError("%s: %s" % (_printable(rel), e))
        except (SpaceError, Timeout, Cancelled):
            raise
        except EncryptedError:
            _unscannable(res, lim, rel, "encrypted archive")
            continue
        except ArchiveError as e:
            _unscannable(res, lim, rel, "inner archive unreadable: %s" % str(e)[:120])
            continue
        res["files"].extend((rel + "/" + r, a, s) for r, a, s in sub["files"])
        for f in sub["findings"]:
            _add(res, dict(f, where=rel + "/" + f["where"] if f["where"] else rel), lim)
        for t, (n, sev) in sub["_supp"].items():
            res["_supp"][t] = res["_supp"].get(t, (0, sev))[0] + n, sev
    res.pop("_kept")
    if not depth:
        for t, (n, sev) in res.pop("_supp").items():
            res["findings"].append(detect.finding(t, sev, "%d more similar findings" % n, "", "high"))
    return res
