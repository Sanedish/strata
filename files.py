"""Storage file manager for the admin UI, across every drive (mount) Caddy serves.

Every client-supplied path goes through resolve(mount, rel). On each drive's root:
    .strata-trash/<batch>/...                 deleted items + manifest (dot-folder: never served)
    .strata-versions/<h2>/<sha1(rel)>/v<n>    previous versions (served only via ?ver=n by Strata Transform)
    <dir>/.strata-up-<id>.part                uploads in flight (chunked, resumable)
    <file>.br                                  Brotli variants written by compress.py (hidden in listings)

Deleting is meant to make a file unloadable everywhere: the trash is mirrored into table binpath, from which the
generated Caddy config answers 403 for binned paths and 404 (with Clear-Site-Data) for permanently deleted ones,
and every URL form of the path is queued for a Cloudflare prefix purge (see purge_targets / sync_bin).
"""
import collections
import hashlib
import io
import json
import mimetypes
import os
import re
import secrets
import shutil
import stat
import tempfile
import threading
import time
import urllib.parse

import core
from core import CFG, category, connect, get_meta, rows_of

try:
    import pillow_avif
except ImportError:
    pass


TRASH = ".strata-trash"
VERS = ".strata-versions"
PART_PREFIX = ".strata-up-"
SIDE = {".br": "br", ".zst": "zstd", ".gz": "gzip"}
BAD_CHARS = re.compile(r'[\x00-\x1f<>:"|?*\\/]')
RESERVED = {"CON", "PRN", "AUX", "NUL"} | {"COM%d" % i for i in range(1, 10)} | {"LPT%d" % i for i in range(1, 10)}
SKIP_DIRS = {"$recycle.bin", "system volume information"}
TEXT_EXT = {"txt", "md", "html", "htm", "css", "js", "mjs", "json", "xml", "svg", "csv", "tsv", "yml", "yaml", "toml",
            "ini", "log", "srt", "vtt", "ass", "webmanifest", "map", "glsl", "frag", "vert", "py", "sh", "bat", "ps1",
            "conf", "cfg", "tex", "rtf", "gltf"}
MAX_TEXT = 2 * 1024 * 1024
MiB = 1024 * 1024


class FileError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code


# ---------------------------------------------------------------- paths

def get_mount(mid, writable=True):
    m = core.mount(mid)
    if not m or m["kind"] not in ("files", "page"):
        raise FileError(404, "unknown drive")
    if not os.path.isdir(m["path"]):
        raise FileError(503, "drive %s is offline (%s)" % (m["name"], m["path"]))
    return m


def root_of(m):
    return os.path.normpath(m["path"])


def parts_of(rel):
    parts = [p for p in (rel or "").split("/") if p != ""]
    for p in parts:
        if (p in (".", "..") or BAD_CHARS.search(p) or p != p.strip() or p.endswith(".") or len(p) > 200
                or p.split(".")[0].upper() in RESERVED):
            raise FileError(400, "invalid name: %s" % p[:80])
    return parts


def resolve(m, rel, allow_internal=False):
    parts = parts_of(rel)
    if parts and parts[0].lower() in (TRASH, VERS) and not allow_internal:
        raise FileError(403, "that folder is managed by Strata")
    root = root_of(m)
    full = os.path.normpath(os.path.join(root, *parts)) if parts else root
    try:  # ValueError: different drives on Windows
        if os.path.commonpath([os.path.normcase(full), os.path.normcase(root)]) != os.path.normcase(root):
            raise FileError(400, "outside the drive")
    except ValueError:
        raise FileError(400, "outside the drive")
    # realpath resolves symlinks in whatever part of the path already exists, so a new file under a linked folder is caught too
    real, real_root = os.path.realpath(full), os.path.realpath(root)
    try:
        if os.path.commonpath([os.path.normcase(real), os.path.normcase(real_root)]) != os.path.normcase(real_root):
            raise FileError(403, "symlink escape detected")
    except ValueError:
        raise FileError(403, "symlink escape detected")
    real_parts = os.path.relpath(real, real_root).split(os.sep)
    if not allow_internal and real_parts[0].lower() in (TRASH, VERS):
        raise FileError(403, "that folder is managed by Strata")
    return full, parts


def rel_of(parts):
    return "/" + "/".join(parts)


def url_path(m, rel):
    return rel if m["prefix"] == "/" else m["prefix"] + rel


def urls_for(m, rel):
    """Every public URL a file is reachable at (for cache purges)."""
    up = urllib.parse.quote(url_path(m, rel))
    return ["https://%s%s" % (h, up) for h in m["hosts"]]


def public_url(m, rel):
    import rules
    return rules.public_url(m, rel)


# ---------------------------------------------------------------- cache purge targets

URL_SAFE_BROWSER = "/!$&'()*+,;=:@~"  # sub-delims browsers leave unescaped in a path
_seen = {"t": 0, "v": []}
_seen_lock = threading.Lock()


def url_forms(up):
    """Encodings a path is commonly requested with. Cloudflare keys its cache on the raw URL, so '/a (1).png' requested
    as /a%20(1).png (typed or pasted) and as /a%20%281%29.png (Strata's own links) are two separate cache entries."""
    return list(dict.fromkeys([urllib.parse.quote(up), urllib.parse.quote(up, safe=URL_SAFE_BROWSER)]))


def seen_forms(m, ups):
    """Raw paths visitors actually used for these url paths (other letter case or percent-encoding), from the access
    log: Cloudflare can only hold what once reached the origin, and every origin hit is logged.
    ups: [(url path, is_dir)] -> {'host/raw-path'} (folders end in /)."""
    want = {up.rstrip("/").lower(): is_dir for up, is_dir in ups}
    with _seen_lock:
        if time.time() - _seen["t"] > 15:
            import rollup  # one row per served (host, path) and day - not one per request
            db = connect()
            try:
                raw = db.execute("SELECT DISTINCT host, path FROM req WHERE status < 400 AND ts >= ?",
                                 [time.time() - 2 * 86400]).fetchall()
            finally:
                db.close()
            # agg_pd keeps decoded paths; the raw forms of the last two days keep odd encodings purgeable too
            _seen.update(t=time.time(), v=list(dict.fromkeys(
                raw + [(h, urllib.parse.quote(p, safe=URL_SAFE_BROWSER)) for h, p in rollup.seen_paths()])))
        rows = _seen["v"]
    hosts, out = set(m["hosts"]), set()
    for host, raw in rows:
        if host not in hosts or not raw:
            continue
        dec = urllib.parse.unquote(raw).lower()
        if want.get(dec) is False:
            out.add(host + raw)
        segs, dsegs = raw.split("/"), dec.split("/")
        if len(segs) != len(dsegs):  # an encoded slash - can't map the folder part back reliably
            continue
        for k in range(2, len(dsegs)):
            if want.get("/".join(dsegs[:k])) is True:
                out.add(host + "/".join(segs[:k]) + "/")
    return out


def purge_targets(m, items):
    """Cloudflare purge prefixes ('host/path') for [(rel, is_dir)] of drive m: every host x every URL form. A prefix
    also covers every query-string variant (?w= ?fm= ?ver= ?dl=); a folder's prefix covers everything inside it."""
    ups = [(url_path(m, rel).rstrip("/") + "/" if is_dir else url_path(m, rel), is_dir) for rel, is_dir in items if rel]
    out = [h + form for up, _ in ups for h in m["hosts"] for form in url_forms(up)]
    try:
        out += sorted(seen_forms(m, ups))
    except Exception as e:  # the log lookup only adds extra forms; it must never block a purge
        core.log("purge: access-log lookup failed: %s" % e)
    return list(dict.fromkeys(out))


def unique_name(full):
    if not os.path.exists(full):
        return full
    base, ext = os.path.splitext(full)
    for i in range(1, 10000):
        cand = "%s (%d)%s" % (base, i, ext)
        if not os.path.exists(cand):
            return cand
    raise FileError(409, "no free name")


# ---------------------------------------------------------------- hits from the access log

_hits = {"t": 0, "v": {}}
_hits_lock = threading.Lock()


def hits_by_path():
    """decoded url path -> [requests, bytes, last] over 30 days (daily rollups: cost independent of traffic)."""
    import rollup
    return rollup.path_hits(30)


# ---------------------------------------------------------------- listing

LIST_SORTS = ("name", "size", "mtime", "hits", "sent", "ext", "cat")


def listdir(mid, rel, sort="name", desc=False, q="", cat="", offset=0, limit=None, hidden=True, focus=""):
    """One folder. Folders come first, then files; both sorted by `sort`. With `limit` the answer is one page
    (offset / limit over folders + files together) and only that page pays for per-entry access/version work.
    Directory discovery and totals still scan the current folder. `focus` opens the page containing one exact name.
    `q` filters names (case-insensitive substring), `cat` the file category; totals describe the filtered folder."""
    import rules
    m = get_mount(mid)
    full, parts = resolve(m, rel)
    if not os.path.isdir(full):
        raise FileError(404, "folder not found")
    ents = {}
    for e in os.scandir(full):
        try:
            ents[e.name] = (e.is_dir(), e.stat())
        except OSError:
            pass
    here = rel_of(parts)
    ql = (q or "").strip().lower()
    base_url = url_path(m, here).rstrip("/") + "/"
    import rollup  # this folder's subtree only (index range), not the whole site's hit map
    hits = rollup.path_hits_children(base_url, 30)
    db = connect()
    try:
        dsizes = {r[0]: r[1:] for r in db.execute(
            "SELECT path, files, dirs, bytes, newest FROM fdir WHERE mount=? AND parent=?", [m["id"], here])}
        inv = get_meta(db, "inventory:%d" % m["id"]) or (get_meta(db, "inventory") if m == core.primary_mount() else None)
    finally:
        db.close()
    # pass 1: cheap fields for every entry (enough to filter and sort)
    dirs, fl = [], []
    for name, (is_dir, st) in ents.items():
        if name.startswith(PART_PREFIX) or name.startswith(".strata-c-") or name.endswith(".strata-copy"):
            continue
        if not parts and name.lower() in (TRASH, VERS):
            continue
        if not hidden and name.startswith("."):
            continue
        if ql and ql not in name.lower():
            continue
        child = here.rstrip("/") + "/" + name
        if is_dir:
            if name.lower() in SKIP_DIRS or (cat and cat != "folder"):
                continue
            ds = dsizes.get(child)
            dirs.append({"name": name, "mtime": st.st_mtime, "hidden": name.startswith("."), "size": ds[2] if ds else None,
                         "files": ds[0] if ds else None, "dirs": ds[1] if ds else None, "dir": True})
            continue
        b, ext = os.path.splitext(name)
        if ext.lower() in SIDE and b in ents and not ents[b][0]:
            continue
        c = category(name)
        if cat and cat != c:
            continue
        h = hits.get(name)
        fl.append({"name": name, "size": st.st_size, "mtime": st.st_mtime, "cat": c, "ext": core.ext_of(name),
                   "hidden": name.startswith("."), "hits": h[0] if h else 0, "sent": h[1] if h else 0,
                   "last": h[2] if h else 0})
    if dirs:  # folder hits: everything served below them
        for d in dirs:
            v = hits.get(d["name"], [0, 0, 0])
            d["hits"], d["sent"], d["last"] = v
    sort = sort if sort in LIST_SORTS else "name"

    def key(e):
        v = e.get(sort)
        if sort == "name":
            return e["name"].lower()
        if isinstance(v, str):
            return v.lower()
        return v if v is not None else -1
    for lst in (dirs, fl):
        lst.sort(key=key, reverse=bool(desc))
    total = len(dirs) + len(fl)
    total_bytes = sum(f["size"] for f in fl) + sum(d["size"] or 0 for d in dirs)
    if limit:
        offset, limit = max(0, int(offset or 0)), max(1, min(5000, int(limit)))
        if focus:
            at = next((i for i, entry in enumerate(dirs + fl) if entry["name"] == focus), None)
            if at is not None:
                offset = (at // limit) * limit
        page = (dirs + fl)[offset:offset + limit]
        dirs, fl = [e for e in page if e.get("dir")], [e for e in page if not e.get("dir")]
    # pass 2: the expensive fields, for the returned entries only
    db = connect()
    try:
        rl = [r for r in rules.load(db)["rules"] if rules.active(r)]
        names = [here.rstrip("/") + "/" + f["name"] for f in fl]
        vcount, lcount = {}, collections.Counter()
        for i in range(0, len(names), 500):
            chunk = names[i:i + 500]
            marks = ",".join("?" * len(chunk))
            for p, n in db.execute("SELECT path, count(*) FROM fversion WHERE mount=? AND path IN (%s) GROUP BY path"
                                   % marks, [m["id"]] + chunk):
                vcount[p] = n
            for p, n in db.execute("SELECT path, count(*) FROM link WHERE mount=? AND path IN (%s) GROUP BY path"
                                   % marks, [m["id"]] + chunk):
                lcount[p] = n
    finally:
        db.close()
    for d in dirs:
        acc = rules.effective(m["id"], url_path(m, here.rstrip("/") + "/" + d["name"]) + "/", rl)
        d["access"], d["rules"] = acc["state"], acc["rules"]
        d.pop("dir", None)
    for f in fl:
        child = here.rstrip("/") + "/" + f["name"]
        acc = rules.effective(m["id"], url_path(m, child), rl)
        f.update(variants={v: ents[f["name"] + suf][1].st_size for suf, v in SIDE.items() if f["name"] + suf in ents},
                 url=public_url(m, child), versions=vcount.get(child, 0), links=lcount.get(child, 0),
                 access=acc["state"], rules=acc["rules"], text=f["ext"] in TEXT_EXT)
    du = None
    try:
        u = shutil.disk_usage(root_of(m))
        du = {"total": u.total, "used": u.used, "free": u.free}
    except OSError:
        pass
    return {"mount": m["id"], "path": here, "parts": parts, "dirs": dirs, "files": fl, "disk": du,
            "inventory": inv, "base_url": public_url(m, "/"), "total": total, "total_bytes": total_bytes,
            "offset": int(offset or 0), "limit": limit, "sort": sort, "desc": bool(desc)}


def tree(mid, rel):
    """Sub-folders of one folder for the folder tree (names, whether they have sub-folders, indexed sizes)."""
    m = get_mount(mid)
    full, parts = resolve(m, rel)
    if not os.path.isdir(full):
        raise FileError(404, "folder not found")
    here = rel_of(parts)
    db = connect()
    try:
        idx = {r[0]: r[1:] for r in db.execute("SELECT path, files, dirs, bytes FROM fdir WHERE mount=? AND parent=?",
                                               [m["id"], here])}
    finally:
        db.close()
    out = []
    try:
        for e in os.scandir(full):
            try:
                if not e.is_dir() or e.name.startswith(".") or e.name.lower() in SKIP_DIRS:
                    continue
            except OSError:
                continue
            child = here.rstrip("/") + "/" + e.name
            i = idx.get(child)
            out.append({"name": e.name, "path": child, "files": i[0] if i else None, "sub": (i[1] if i else None),
                        "bytes": i[2] if i else None})
    except OSError as e:
        raise FileError(403, e.strerror or str(e))
    out.sort(key=lambda d: d["name"].lower())
    return {"mount": m["id"], "path": here, "dirs": out[:2000]}


def recent(mid, limit=60):
    """Newest files of a drive (from the index)."""
    m = get_mount(mid)
    db = connect()
    try:
        rows = rows_of(db.execute("SELECT path, name, size, mtime, cat FROM fidx WHERE mount=? ORDER BY mtime DESC LIMIT ?",
                                  [m["id"], max(1, min(500, int(limit)))]))
    finally:
        db.close()
    return {"files": rows}


def up_check(mid, items):
    """Pre-flight for the uploader: which destinations already exist (so conflicts are decided before sending).
    items: [path] (drive-relative) -> {path: {"exists", "size", "mtime", "dir"}} for the existing ones only."""
    m = get_mount(mid)
    out = {}
    for rel in (items or [])[:5000]:
        try:
            full, parts = resolve(m, rel)
        except FileError as e:
            out[rel] = {"error": str(e)}
            continue
        if parts and os.path.exists(full):
            st = os.stat(full)
            out[rel] = {"exists": True, "size": st.st_size, "mtime": st.st_mtime, "dir": os.path.isdir(full)}
    return {"existing": out}


def like_prefix(p):
    return p.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def search(mid, q, within="/", limit=300):
    m = get_mount(mid)
    q = (q or "").strip()
    if len(q) < 2:
        raise FileError(400, "type at least 2 characters")
    db = connect()
    try:
        pat = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        pre = like_prefix(within.rstrip("/") + "/") if within and within != "/" else "%"
        files = rows_of(db.execute(
            "SELECT path, name, size, mtime, cat FROM fidx WHERE mount=? AND name LIKE ? ESCAPE '\\' "
            "AND path LIKE ? ESCAPE '\\' ORDER BY size DESC LIMIT ?", [m["id"], pat, pre, limit]))
        dirs = rows_of(db.execute(
            "SELECT path, bytes size, files FROM fdir WHERE mount=? AND path LIKE ? ESCAPE '\\' AND path LIKE ? "
            "ESCAPE '\\' AND path != '/' ORDER BY bytes DESC LIMIT 200", [m["id"], pat, pre]))
        dirs = [d for d in dirs if q.lower() in d["path"].rsplit("/", 1)[-1].lower()][:60]
    finally:
        db.close()
    return {"files": files, "dirs": dirs, "indexed": True}


# ---------------------------------------------------------------- versions

def vdir(m, rel):
    h = hashlib.sha1(rel.encode("utf-8")).hexdigest()
    return os.path.join(root_of(m), VERS, h[:2], h)


def keep_version(db, m, rel, full, user, note="replaced"):
    """Move the current file into the version store before it is overwritten."""
    if not os.path.isfile(full):
        return None
    n = (db.execute("SELECT max(n) FROM fversion WHERE mount=? AND path=?", [m["id"], rel]).fetchone()[0] or 0) + 1
    d = vdir(m, rel)
    os.makedirs(d, exist_ok=True)
    st = os.stat(full)
    dest = os.path.join(d, "v%d" % n)
    os.replace(full, dest)
    for suf in SIDE:  # the old variant belongs to the old bytes
        try:
            os.remove(full + suf)
        except OSError:
            pass
    db.execute("INSERT INTO fversion(mount,path,n,size,mtime,created,stored,user,note) VALUES(?,?,?,?,?,?,?,?,?)",
               [m["id"], rel, n, st.st_size, st.st_mtime, time.time(), dest, user, note])
    keep = int(CFG.get("versions_keep") or 10)
    for n_old, stored in db.execute("SELECT n, stored FROM fversion WHERE mount=? AND path=? ORDER BY n DESC "
                                    "LIMIT -1 OFFSET ?", [m["id"], rel, keep]).fetchall():
        try:
            os.remove(stored)
        except OSError:
            pass
        db.execute("DELETE FROM fversion WHERE mount=? AND path=? AND n=?", [m["id"], rel, n_old])
    return n


def versions(mid, rel):
    m = get_mount(mid)
    full, parts = resolve(m, rel)
    rel = rel_of(parts)
    db = connect()
    try:
        rows = rows_of(db.execute("SELECT n, size, mtime, created, user, note FROM fversion WHERE mount=? AND path=? "
                                  "ORDER BY n DESC", [m["id"], rel]))
    finally:
        db.close()
    import rules
    for r in rows:
        r["url"] = rules.public_url(m, rel, {"ver": r["n"]})
    cur = os.stat(full) if os.path.isfile(full) else None
    return {"current": {"size": cur.st_size, "mtime": cur.st_mtime} if cur else None, "versions": rows}


def restore_version(user, mid, rel, n):
    m = get_mount(mid)
    full, parts = resolve(m, rel)
    rel = rel_of(parts)
    db = connect()
    try:
        row = db.execute("SELECT stored FROM fversion WHERE mount=? AND path=? AND n=?", [m["id"], rel, int(n)]).fetchone()
        if not row or not os.path.isfile(row[0]):
            raise FileError(404, "version not found")
        with db:
            tmp = full + ".strata-restore"
            shutil.copy2(row[0], tmp)
            keep_version(db, m, rel, full, user, "before restoring v%d" % int(n))
            os.replace(tmp, full)
    finally:
        db.close()
    return {"path": rel, "restored": int(n), "urls": urls_for(m, rel), "purge": purge_targets(m, [(rel, False)])}


def delete_version(mid, rel, n):
    m = get_mount(mid)
    _, parts = resolve(m, rel)
    rel = rel_of(parts)
    db = connect()
    try:
        with db:
            row = db.execute("SELECT stored FROM fversion WHERE mount=? AND path=? AND n=?", [m["id"], rel, int(n)]).fetchone()
            if not row:
                raise FileError(404, "version not found")
            try:
                os.remove(row[0])
            except OSError:
                pass
            db.execute("DELETE FROM fversion WHERE mount=? AND path=? AND n=?", [m["id"], rel, int(n)])
    finally:
        db.close()
    return {"deleted": int(n)}


def move_versions(db, m_old, rel_old, m_new, rel_new):
    """Keep version history attached when a file or folder is renamed / moved."""
    rows = db.execute("SELECT path FROM fversion WHERE mount=? AND (path=? OR path LIKE ? ESCAPE '\\') GROUP BY path",
                      [m_old["id"], rel_old, like_prefix(rel_old.rstrip("/") + "/")]).fetchall()
    for (p,) in rows:
        np = rel_new + p[len(rel_old):]
        src, dst = vdir(m_old, p), vdir(m_new, np)
        if os.path.isdir(src):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if not os.path.exists(dst):
                shutil.move(src, dst)
        for n, stored in db.execute("SELECT n, stored FROM fversion WHERE mount=? AND path=?", [m_old["id"], p]).fetchall():
            db.execute("UPDATE fversion SET mount=?, path=?, stored=? WHERE mount=? AND path=? AND n=?",
                       [m_new["id"], np, os.path.join(dst, os.path.basename(stored)), m_old["id"], p, n])


def move_cfile(db, old, new):
    sep = old + os.sep
    db.execute("UPDATE cfile SET path = ? || substr(path, ?) WHERE path = ? OR substr(path, 1, ?) = ?",
               [new, len(old) + 1, old, len(sep), sep])


# ---------------------------------------------------------------- uploads (single request + chunked/resumable)

UPLOCKS = collections.defaultdict(threading.Lock)


def max_chunk():
    return int(min(95, max(1, CFG["upload"].get("max_chunk_mb", 95)))) * MiB


def content_length(headers, limit=None, required=False, allow_chunked=False):
    """Validate framing before any read: negative lengths otherwise mean 'read to EOF'."""
    lengths = headers.get_all("Content-Length", []) if hasattr(headers, "get_all") else (
        [headers["Content-Length"]] if headers.get("Content-Length") is not None else [])
    transfer = headers.get("Transfer-Encoding")
    if transfer:
        if not allow_chunked or transfer.strip().lower() != "chunked" or lengths:
            raise FileError(400, "unsupported or ambiguous request framing")
        return None
    if len(lengths) > 1 or lengths and not re.fullmatch(r"[0-9]{1,20}", str(lengths[0]).strip()):
        raise FileError(400, "invalid Content-Length")
    if not lengths:
        if required:
            raise FileError(411, "Content-Length required")
        return 0
    n = int(lengths[0])
    if limit is not None and n > limit:
        raise FileError(413, "request body too large")
    return n


def read_into(rfile, headers, f, limit, sha=None):
    """Stream a request body (Content-Length or chunked) into file f. Returns bytes written."""
    written = 0

    def put(buf):
        nonlocal written
        if written + len(buf) > limit:
            raise FileError(413, "request body too large (limit %d MiB per request)" % (limit // MiB))
        f.write(buf)
        if sha:
            sha.update(buf)
        written += len(buf)
    length = content_length(headers, limit, required=True, allow_chunked=True)
    if length is None:
        while True:
            line = rfile.readline(1024)
            size = line.split(b";", 1)[0].strip()
            if not line.endswith(b"\r\n") or not re.fullmatch(rb"[0-9A-Fa-f]{1,16}", size):
                raise FileError(400, "invalid upload chunk")
            n = int(size, 16)
            if n > limit - written:
                raise FileError(413, "request body too large")
            if n == 0:
                trailers = 0
                while True:
                    trailer = rfile.readline(8193)
                    trailers += len(trailer)
                    if not trailer.endswith(b"\r\n") or trailers > 8192:
                        raise FileError(400, "invalid upload trailers")
                    if trailer == b"\r\n":
                        return written
            left = n
            while left:
                buf = rfile.read(min(left, MiB))
                if not buf:
                    raise FileError(400, "upload interrupted")
                put(buf); left -= len(buf)
            if rfile.read(2) != b"\r\n":
                raise FileError(400, "invalid upload chunk ending")
    left = length
    while left:
        buf = rfile.read(min(left, MiB))
        if not buf:
            raise FileError(400, "upload interrupted")
        put(buf); left -= len(buf)
    return written


def target_for(m, rel, policy):
    full, parts = resolve(m, rel)
    if not parts:
        raise FileError(400, "missing file name")
    if parts[-1].lower().startswith(".strata"):
        raise FileError(400, "reserved name")
    if os.path.isdir(full):
        raise FileError(409, "a folder with that name exists")
    if os.path.exists(full):
        if policy == "skip":
            return None, parts
        if policy == "rename":
            full = unique_name(full)
            parts = parts[:-1] + [os.path.basename(full)]
        elif policy != "replace":
            raise FileError(409, "exists")
    return full, parts


def check_space(m, size):
    try:
        free = shutil.disk_usage(root_of(m)).free
    except OSError:
        return
    if size + 64 * MiB > free:
        raise FileError(507, "not enough space on %s (%d MiB free)" % (m["name"], free // MiB))


def finalize(user, m, parts, tmp, policy):
    """Move a completed upload into place; an existing file becomes a version first."""
    rel = rel_of(parts)
    full, parts = resolve(m, rel)  # the destination may have changed while the upload was in flight
    if not parts or parts[-1].lower().startswith(".strata"):
        raise FileError(400, "reserved or missing file name")
    if os.path.isdir(full):
        raise FileError(409, "a folder with that name exists")
    replaced = False
    db = connect()
    try:
        with db:
            if os.path.exists(full):
                if policy == "rename":
                    full = unique_name(full)
                    parts = parts[:-1] + [os.path.basename(full)]
                    rel = rel_of(parts)
                elif policy == "replace":
                    keep_version(db, m, rel, full, user, "replaced by upload")
                    replaced = True
                else:
                    raise FileError(409, "exists")
            os.replace(tmp, full)
    finally:
        db.close()
    return {"mount": m["id"], "path": rel, "size": os.path.getsize(full), "full": full, "url": public_url(m, rel),
            "replaced": replaced, "urls": urls_for(m, rel) if replaced else [],
            "purge": purge_targets(m, [(rel, False)]) if replaced else []}


def upload_single(user, mid, rel, rfile, headers, policy):
    m = get_mount(mid)
    full, parts = target_for(m, rel, policy)
    if full is None:
        return {"skipped": True, "path": rel_of(parts)}
    length = content_length(headers, min(max_chunk(), upload_limit()), required=True, allow_chunked=True)
    check_space(m, length or 0)
    parent = os.path.dirname(full)
    os.makedirs(parent, exist_ok=True)
    tmp = os.path.join(parent, PART_PREFIX + secrets.token_hex(6) + ".part")
    try:
        with open(tmp, "wb") as f:
            read_into(rfile, headers, f, min(max_chunk(), upload_limit()))
        return finalize(user, m, parts, tmp, policy)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def upload_limit():
    return int(CFG.get("upload_max_bytes") or (20 << 30))


def up_init(user, d):
    m = get_mount(d.get("mount"))
    policy = d.get("policy") if d.get("policy") in ("ask", "replace", "skip", "rename") else "ask"
    size = int(d.get("size") or 0)
    if size < 0 or size > 16 * 1024 ** 4:
        raise FileError(400, "bad size")
    if size > upload_limit():
        raise FileError(413, "file is larger than the upload limit")
    full, parts = target_for(m, d.get("path", ""), policy)
    if full is None:
        return {"skipped": True, "path": rel_of(parts)}
    fp = "%s|%s|%d|%s|%s" % (m["id"], rel_of(parts), size, d.get("mtime"), d.get("name"))
    db = connect()
    try:
        row = db.execute("SELECT * FROM upload WHERE fingerprint=? AND user=?", [fp, user]).fetchone()
        if row:
            r = rows_of(db.execute("SELECT * FROM upload WHERE id=?", [row[0]]))[0]
            if os.path.exists(r["tmp"]):
                return {"id": r["id"], "chunk": r["chunk"], "chunks": r["chunks"], "received": json.loads(r["received"]),
                        "path": r["path"], "resumed": True}
            db.execute("DELETE FROM upload WHERE id=?", [r["id"]])
        check_space(m, size)
        chunk = int(min(max_chunk(), max(MiB, int(d.get("chunk_mb") or CFG["upload"]["chunk_mb"]) * MiB)))
        chunks = max(1, -(-size // chunk))
        uid = secrets.token_hex(12)
        parent = os.path.dirname(full)
        os.makedirs(parent, exist_ok=True)
        tmp = os.path.join(parent, PART_PREFIX + uid + ".part")
        with open(tmp, "wb") as f:
            f.truncate(size)
        with db:
            db.execute("INSERT INTO upload(id,mount,path,size,chunk,chunks,received,policy,fingerprint,user,tmp,created,"
                       "updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       [uid, m["id"], rel_of(parts), size, chunk, chunks, "[]", policy, fp, user, tmp, time.time(),
                        time.time()])
        return {"id": uid, "chunk": chunk, "chunks": chunks, "received": [], "path": rel_of(parts), "resumed": False}
    finally:
        db.close()


def up_row(uid, user):
    db = connect()
    try:
        r = rows_of(db.execute("SELECT * FROM upload WHERE id=?", [uid]))
    finally:
        db.close()
    if not r or r[0]["user"] != user:
        raise FileError(404, "upload session not found (expired or finished)")
    return r[0]


def up_chunk(user, uid, index, rfile, headers):
    r = up_row(uid, user)
    i = int(index)
    if not 0 <= i < r["chunks"]:
        raise FileError(400, "chunk index out of range")
    want = min(r["chunk"], r["size"] - i * r["chunk"])
    if content_length(headers, required=True) != want:
        raise FileError(400, "chunk %d must be exactly %d bytes" % (i, want))
    sha = hashlib.sha256()
    # Validate the entire retry before touching an already accepted chunk. Bodies can arrive in parallel;
    # committing bytes and the receipt is serialized with completion and cancellation for this upload.
    with tempfile.TemporaryFile() as staged:
        read_into(rfile, headers, staged, want, sha)
        given = (headers.get("X-Chunk-SHA256") or "").lower()
        if given and given != sha.hexdigest():
            raise FileError(422, "chunk %d arrived corrupted (checksum mismatch) - it will be resent" % i)
        with UPLOCKS[uid]:
            r = up_row(uid, user)
            tmp = upload_tmp(r)
            db = connect()
            try:
                cur = set(json.loads(r["received"]))
                cur.discard(i)
                with db:
                    db.execute("UPDATE upload SET received=? WHERE id=?", [json.dumps(sorted(cur)), uid])
                staged.seek(0)
                with open(tmp, "r+b") as f:
                    f.seek(i * r["chunk"])
                    shutil.copyfileobj(staged, f, MiB)
                cur.add(i)
                with db:
                    db.execute("UPDATE upload SET received=?, updated=? WHERE id=?", [json.dumps(sorted(cur)), time.time(), uid])
            finally:
                db.close()
    return {"received": len(cur), "chunks": r["chunks"], "sha256": sha.hexdigest()}


def upload_tmp(r):
    m = get_mount(r["mount"])
    _, parts = resolve(m, r["path"])
    tmp, _ = resolve(m, rel_of(parts[:-1] + [os.path.basename(r["tmp"])]))
    if os.path.normcase(os.path.abspath(tmp)) != os.path.normcase(os.path.abspath(r["tmp"])):
        raise FileError(409, "the upload destination changed - start it again")
    return tmp


def up_complete(user, uid):
    with UPLOCKS[uid]:
        return _up_complete(user, uid)


def _up_complete(user, uid):
    r = up_row(uid, user)
    got = set(json.loads(r["received"]))
    missing = [i for i in range(r["chunks"]) if i not in got]
    if missing and r["size"] > 0:
        raise FileError(409, "missing chunks: %s" % missing[:20])
    tmp = upload_tmp(r)
    if os.path.getsize(tmp) != r["size"]:
        raise FileError(500, "assembled size mismatch")
    m = get_mount(r["mount"])
    res = finalize(user, m, parts_of(r["path"]), tmp, r["policy"])
    db = connect()
    try:
        with db:
            db.execute("DELETE FROM upload WHERE id=?", [uid])
    finally:
        db.close()
    UPLOCKS.pop(uid, None)
    return res


def up_abort(user, uid):
    with UPLOCKS[uid]:
        return _up_abort(user, uid)


def _up_abort(user, uid):
    r = up_row(uid, user)
    try:
        os.remove(upload_tmp(r))
    except OSError:
        pass
    db = connect()
    try:
        with db:
            db.execute("DELETE FROM upload WHERE id=?", [uid])
    finally:
        db.close()
    UPLOCKS.pop(uid, None)
    return {"aborted": uid}


def up_list(user):
    db = connect()
    try:
        rows = rows_of(db.execute("SELECT id, mount, path, size, chunk, chunks, received, policy, created, updated "
                                  "FROM upload WHERE user=? ORDER BY updated DESC", [user]))
    finally:
        db.close()
    for r in rows:
        got = json.loads(r.pop("received"))
        r["done"] = len(got)
        r["bytes_done"] = sum(min(r["chunk"], r["size"] - i * r["chunk"]) for i in got)
    return {"sessions": rows, "chunk_mb": CFG["upload"]["chunk_mb"], "max_chunk_mb": max_chunk() // MiB,
            "parallel": CFG["upload"]["parallel"]}


def up_gc():
    cutoff = time.time() - CFG["upload"]["stale_hours"] * 3600
    db = connect()
    try:
        stale = db.execute("SELECT id, tmp FROM upload WHERE updated < ?", [cutoff]).fetchall()
        with db:
            for uid, tmp in stale:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
                db.execute("DELETE FROM upload WHERE id=?", [uid])
    finally:
        db.close()
    return len(stale)


# ---------------------------------------------------------------- folders, rename, delete, trash

def mkdir(mid, rel):
    m = get_mount(mid)
    full, parts = resolve(m, rel)
    if not parts:
        raise FileError(400, "missing folder name")
    try:
        os.makedirs(full)
    except FileExistsError:
        raise FileError(409, "already exists")
    return {"path": rel_of(parts)}


def rename(mid, src, dst):
    m = get_mount(mid)
    sfull, sparts = resolve(m, src)
    dfull, dparts = resolve(m, dst)
    if not sparts or not dparts:
        raise FileError(400, "cannot rename the drive root")
    if not os.path.exists(sfull):
        raise FileError(404, "not found")
    if os.path.exists(dfull) and sfull.lower() != dfull.lower():
        raise FileError(409, "target already exists")
    if not os.path.isdir(os.path.dirname(dfull)):
        raise FileError(404, "target folder does not exist")
    if (dfull.lower() + os.sep).startswith(sfull.lower() + os.sep) and sfull.lower() != dfull.lower():
        raise FileError(400, "cannot move a folder into itself")
    purge = collect_urls(m, rel_of(sparts))
    targets = purge_targets(m, [(rel_of(sparts), os.path.isdir(sfull))])
    os.rename(sfull, dfull)
    if os.path.isfile(dfull):
        for suf in SIDE:
            if os.path.exists(sfull + suf) and not os.path.exists(dfull + suf):
                os.rename(sfull + suf, dfull + suf)
    db = connect()
    try:
        with db:
            move_cfile(db, sfull, dfull)
            move_versions(db, m, rel_of(sparts), m, rel_of(dparts))
            db.execute("UPDATE link SET path = ? || substr(path, ?) WHERE mount=? AND (path=? OR path LIKE ? ESCAPE '\\')",
                       [rel_of(dparts), len(rel_of(sparts)) + 1, m["id"], rel_of(sparts),
                        like_prefix(rel_of(sparts).rstrip("/") + "/")])
    finally:
        db.close()
    return {"from": rel_of(sparts), "to": rel_of(dparts), "url": public_url(m, rel_of(dparts)), "urls": purge,
            "purge": targets}


def collect_urls(m, rel, limit=3000):
    """Public URLs of a file, or of every indexed file inside a folder (for cache purges)."""
    full, _ = resolve(m, rel, allow_internal=True)
    if os.path.isfile(full):
        return urls_for(m, rel)
    db = connect()
    try:
        paths = [r[0] for r in db.execute("SELECT path FROM fidx WHERE mount=? AND path LIKE ? ESCAPE '\\' LIMIT ?",
                                          [m["id"], like_prefix(rel.rstrip("/") + "/"), limit])]
    finally:
        db.close()
    return [u for p in paths for u in urls_for(m, p)]


def delete(user, mid, paths):
    """Move items into <root>/.strata-trash/<batch>/ (with their versions) and write a restore manifest."""
    m = get_mount(mid)
    root = root_of(m)
    batch = time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)
    bdir = os.path.join(root, TRASH, batch)
    moved = []
    db = connect()
    try:
        for rel in paths:
            full, parts = resolve(m, rel)
            if not parts:
                raise FileError(400, "cannot delete the drive root")
            if not os.path.exists(full):
                continue
            r = rel_of(parts)
            dest = os.path.join(bdir, *parts)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            is_dir = os.path.isdir(full)
            size = 0 if is_dir else os.path.getsize(full)
            if is_dir:
                row = db.execute("SELECT bytes FROM fdir WHERE mount=? AND path=?", [m["id"], r]).fetchone()
                size = row[0] if row else 0
            os.rename(full, dest)
            if not is_dir:
                for suf in SIDE:
                    if os.path.exists(full + suf):
                        os.rename(full + suf, dest + suf)
            with db:
                move_cfile(db, full, dest)
                vrows = db.execute("SELECT path FROM fversion WHERE mount=? AND (path=? OR path LIKE ? ESCAPE '\\') "
                                   "GROUP BY path", [m["id"], r, like_prefix(r.rstrip("/") + "/")]).fetchall()
                for (vp,) in vrows:  # park the version history in the batch so a restore brings it back
                    src = vdir(m, vp)
                    if os.path.isdir(src):
                        shutil.move(src, os.path.join(bdir, ".versions", os.path.basename(src)))
            moved.append({"path": r, "dir": is_dir, "size": size, "versions": [v[0] for v in vrows]})
    finally:
        db.close()
        if moved:
            with open(os.path.join(bdir, ".manifest.json"), "w", encoding="utf-8") as f:
                json.dump({"ts": time.time(), "user": user, "items": moved}, f)
    if moved:
        sync_bin(m)
    return {"batch": batch, "moved": moved, "purge": purge_targets(m, [(x["path"], x["dir"]) for x in moved])}


def sync_bin(m, items=None):
    """Mirror the drive's trash into table binpath, which the generated Caddy config reads when a file is missing:
    binned paths answer 403; paths that left the trash without coming back (emptied, or removed by hand) answer 404
    for CFG['gone_days'] - both with Clear-Site-Data so browsers drop their cached copies. Restored paths are dropped.
    Returns True when something changed (a Caddy re-apply is then scheduled)."""
    if m["kind"] != "files":
        return False
    if items is None:
        items = trash_list(m["id"])["items"]
    inbin = {}
    for it in items:
        inbin.setdefault(it["path"], 1 if it.get("dir") else 0)
    t = time.time()
    changed = False
    db = connect()
    try:
        with db:
            rows = dict(db.execute("SELECT path, state FROM binpath WHERE mount=?", [m["id"]]).fetchall())
            for p, d in inbin.items():
                if rows.get(p) != "bin":
                    db.execute("INSERT OR REPLACE INTO binpath(mount, path, dir, state, ts) VALUES(?,?,?,'bin',?)",
                               [m["id"], p, d, t])
                    changed = True
            for p, state in rows.items():
                if state != "bin" or p in inbin:
                    continue
                try:
                    back = os.path.exists(os.path.join(root_of(m), *parts_of(p)))
                except FileError:
                    back = False
                if back:
                    db.execute("DELETE FROM binpath WHERE mount=? AND path=?", [m["id"], p])
                else:
                    db.execute("UPDATE binpath SET state='gone', ts=? WHERE mount=? AND path=?", [t, m["id"], p])
                changed = True
            cutoff = t - float(CFG.get("gone_days") or 30) * 86400
            if db.execute("DELETE FROM binpath WHERE mount=? AND state='gone' AND ts < ?", [m["id"], cutoff]).rowcount:
                changed = True
    finally:
        db.close()
    if changed:
        import rules
        rules.APPLY_SOON.set()
    return changed


def sync_all_bins():
    for m in core.file_mounts():
        if m["kind"] == "files" and os.path.isdir(m["path"]):
            try:
                sync_bin(m)
            except Exception as e:
                core.log("bin sync failed for %s: %s" % (m["name"], e))


def trash_list(mid, sync=False):
    m = get_mount(mid)
    root = os.path.join(root_of(m), TRASH)
    out, total = [], 0
    if os.path.isdir(root):
        for b in sorted(os.listdir(root), reverse=True):
            if not re.fullmatch(r"[0-9]{8}-[0-9]{6}-[0-9a-f]{4}", b):
                continue
            try:
                with open(os.path.join(root, b, ".manifest.json"), encoding="utf-8") as f:
                    man = json.load(f)
            except (OSError, ValueError):
                continue
            for it in man.get("items", []):
                if os.path.exists(os.path.join(root, b, *parts_of(it["path"]))):
                    out.append(dict(it, batch=b, ts=man.get("ts"), user=man.get("user")))
                    total += it.get("size") or 0
    if sync:
        sync_bin(m, out)
    return {"items": out, "bytes": total}


def restore(mid, batch, rel):
    m = get_mount(mid)
    if not re.fullmatch(r"[0-9]{8}-[0-9]{6}-[0-9a-f]{4}", batch or ""):
        raise FileError(400, "bad batch")
    parts = parts_of(rel)
    bdir = os.path.join(root_of(m), TRASH, batch)
    src = os.path.join(bdir, *parts)
    dst, _ = resolve(m, rel)
    if os.path.islink(src):
        raise FileError(403, "refusing to restore symlink from trash")
    if not os.path.exists(src):
        raise FileError(404, "not in trash")
    if os.path.exists(dst):
        raise FileError(409, "something already exists at %s" % rel_of(parts))
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    os.rename(src, dst)
    if os.path.isfile(dst):
        for suf in SIDE:
            if os.path.exists(src + suf) and not os.path.exists(dst + suf):
                os.rename(src + suf, dst + suf)
    db = connect()
    try:
        with db:
            move_cfile(db, src, dst)
            for (vp,) in db.execute("SELECT path FROM fversion WHERE mount=? AND (path=? OR path LIKE ? ESCAPE '\\') "
                                    "GROUP BY path", [m["id"], rel_of(parts), like_prefix(rel_of(parts).rstrip("/") + "/")]).fetchall():
                parked = os.path.join(bdir, ".versions", os.path.basename(vdir(m, vp)))
                if os.path.isdir(parked) and not os.path.exists(vdir(m, vp)):
                    os.makedirs(os.path.dirname(vdir(m, vp)), exist_ok=True)
                    shutil.move(parked, vdir(m, vp))
    finally:
        db.close()
    sync_bin(m)
    return {"path": rel_of(parts)}


def empty_trash(mid):
    m = get_mount(mid)
    root = os.path.join(root_of(m), TRASH)
    listing = trash_list(mid)
    db = connect()
    try:
        with db:
            for it in listing["items"]:
                for vp in it.get("versions") or []:  # history of permanently deleted files goes too
                    if not os.path.exists(os.path.join(root_of(m), *parts_of(vp))):
                        db.execute("DELETE FROM fversion WHERE mount=? AND path=?", [m["id"], vp])
            sep = root + os.sep
            db.execute("DELETE FROM cfile WHERE substr(path, 1, ?) = ?", [len(sep), sep])
    finally:
        db.close()
    try:
        if os.path.isdir(root):
            shutil.rmtree(root)
    finally:
        sync_bin(m)  # binned paths now answer 404 (whatever rmtree managed to remove)
    return {"freed": listing["bytes"], "items": len(listing["items"]),
            "purge": purge_targets(m, [(it["path"], bool(it.get("dir"))) for it in listing["items"]])}


# ---------------------------------------------------------------- copy / cross-drive move jobs

JOBS = collections.OrderedDict()
JOB_LOCK = threading.Lock()


def job_list():
    with JOB_LOCK:
        return {"jobs": [{k: v for k, v in j.items() if k != "purge"} for j in reversed(JOBS.values())][:30]}


def start_job(user, kind, title, fn):
    jid = secrets.token_hex(6)
    job = {"id": jid, "kind": kind, "title": title, "status": "running", "files": 0, "files_total": 0,
           "bytes": 0, "bytes_total": 0, "error": "", "user": user, "started": time.time(), "finished": None, "current": ""}
    with JOB_LOCK:
        JOBS[jid] = job
        while len(JOBS) > 60:
            JOBS.popitem(last=False)

    def run():
        try:
            job["result"] = fn(job)
            job["status"] = "done"
        except Exception as e:
            job["status"], job["error"] = "error", str(e)[:300]
        job["finished"] = time.time()
        for h in JOB_HOOKS:
            h(job)
    threading.Thread(target=run, daemon=True, name="job-" + jid).start()
    return job


JOB_HOOKS = []  # f(job) called when a job finishes (reindex, cache purge of moved-away sources)


def copy_items(user, smid, paths, dmid, ddir, move=False):
    sm, dm = get_mount(smid), get_mount(dmid)
    dfull, dparts = resolve(dm, ddir)
    if not os.path.isdir(dfull):
        raise FileError(404, "destination folder not found")
    items = []
    for rel in paths:
        full, parts = resolve(sm, rel)
        if not parts or not os.path.exists(full):
            raise FileError(404, "not found: %s" % rel)
        if os.path.isdir(full) and (dfull.lower() + os.sep).startswith(full.lower() + os.sep):
            raise FileError(400, "cannot copy a folder into itself")
        items.append((full, parts))
    same = sm["id"] == dm["id"] and move
    if same:  # instant renames on the same drive
        out = []
        for full, parts in items:
            out.append(rename(sm["id"], rel_of(parts), rel_of(dparts + [parts[-1]])))
        return {"moved": out, "instant": True}

    def work(job):
        plan = []
        for full, parts in items:
            if os.path.isdir(full):
                for dp, dn, fn in safe_walk(full):
                    for n in fn:
                        if n.startswith(".strata") or os.path.splitext(n)[1] in SIDE and os.path.exists(os.path.join(dp, os.path.splitext(n)[0])):
                            continue
                        p = os.path.join(dp, n)
                        plan.append((p, os.path.join(parts[-1], os.path.relpath(p, full)), os.path.getsize(p)))
            else:
                plan.append((full, parts[-1], os.path.getsize(full)))
        job["files_total"], job["bytes_total"] = len(plan), sum(s for _, _, s in plan)
        check_space(dm, job["bytes_total"])
        roots = {}
        for src, relname, size in plan:
            src, _ = resolve(sm, rel_of(os.path.relpath(src, root_of(sm)).split(os.sep)))
            top = relname.split(os.sep)[0]
            if top not in roots:
                roots[top] = os.path.basename(unique_name(os.path.join(dfull, top)))
            target, _ = resolve(dm, rel_of(dparts + [roots[top]] + relname.split(os.sep)[1:]))
            os.makedirs(os.path.dirname(target), exist_ok=True)
            job["current"] = relname
            with open(src, "rb") as fi, open(target + ".strata-copy", "wb") as fo:
                while True:
                    buf = fi.read(4 * MiB)
                    if not buf:
                        break
                    fo.write(buf)
                    job["bytes"] += len(buf)
            shutil.copystat(src, target + ".strata-copy")
            os.replace(target + ".strata-copy", target)
            job["files"] += 1
        if move:
            job["purge"] = delete(user, sm["id"], [rel_of(p) for _, p in items])["purge"]
        return {"into": rel_of(dparts), "roots": list(roots.values())}
    job = start_job(user, "move" if move else "copy", "%s %d item(s) to %s:%s" % (
        "Move" if move else "Copy", len(items), dm["name"], rel_of(dparts)), work)
    job["mount"], job["dest"] = dm["id"], rel_of(dparts)
    return {"job": job["id"]}


# ---------------------------------------------------------------- text files

def read_text(mid, rel):
    m = get_mount(mid)
    full, parts = resolve(m, rel)
    if not os.path.isfile(full):
        raise FileError(404, "file not found")
    if os.path.getsize(full) > MAX_TEXT:
        raise FileError(413, "too large to edit here (limit 2 MiB)")
    with open(full, "rb") as f:
        raw = f.read()
    if b"\x00" in raw[:8192]:
        raise FileError(415, "binary file")
    try:
        text, enc = raw.decode("utf-8-sig"), "utf-8"
    except UnicodeDecodeError:
        text, enc = raw.decode("latin-1"), "latin-1"
    return {"path": rel_of(parts), "text": text, "encoding": enc, "mtime": os.path.getmtime(full),
            "size": len(raw), "crlf": b"\r\n" in raw[:65536]}


def write_text(user, mid, rel, text, expect_mtime=None, create=False):
    m = get_mount(mid)
    full, parts = resolve(m, rel)
    if not parts:
        raise FileError(400, "missing file name")
    data = text.encode("utf-8")
    if len(data) > MAX_TEXT:
        raise FileError(413, "too large (limit 2 MiB)")
    exists = os.path.exists(full)
    if create and exists:
        raise FileError(409, "exists")
    if exists and expect_mtime and abs(os.path.getmtime(full) - float(expect_mtime)) > 0.01:
        raise FileError(409, "the file changed on disk since you opened it - reload to see the new version")
    os.makedirs(os.path.dirname(full), exist_ok=True)
    tmp = os.path.join(os.path.dirname(full), PART_PREFIX + secrets.token_hex(6) + ".part")
    with open(tmp, "wb") as f:
        f.write(data)
    db = connect()
    try:
        with db:
            if exists:
                keep_version(db, m, rel_of(parts), full, user, "edited")
            os.replace(tmp, full)
    finally:
        db.close()
    return {"path": rel_of(parts), "size": len(data), "mtime": os.path.getmtime(full), "full": full,
            "urls": urls_for(m, rel_of(parts)) if exists else [],
            "purge": purge_targets(m, [(rel_of(parts), False)]) if exists else []}


# ---------------------------------------------------------------- info, raw, thumbnails, zip

ACTIVE = {"text/html", "application/xhtml+xml", "text/xml", "application/xml", "text/javascript",
          "application/javascript", "application/x-javascript", "text/css", "image/svg+xml"}


def raw_info(mid, rel, ver=None):
    m = get_mount(mid)
    full, parts = resolve(m, rel)
    if ver:
        db = connect()
        try:
            row = db.execute("SELECT stored FROM fversion WHERE mount=? AND path=? AND n=?", [m["id"], rel_of(parts), int(ver)]).fetchone()
        finally:
            db.close()
        if not row:
            raise FileError(404, "version not found")
        full = row[0]
    if not os.path.isfile(full):
        raise FileError(404, "file not found")
    ctype = mimetypes.guess_type(parts[-1])[0] or "application/octet-stream"
    name = parts[-1] if not ver else "%s.v%s%s" % (os.path.splitext(parts[-1])[0], ver, os.path.splitext(parts[-1])[1])
    return full, os.path.getsize(full), ctype, name


def info(mid, rel, allow=None):
    """allow(mount id, path) -> bool hides duplicates the caller may not see (scoped accounts)."""
    import rules
    m = get_mount(mid)
    full, parts = resolve(m, rel)
    if not os.path.exists(full):
        raise FileError(404, "not found")
    st = os.stat(full)
    r = rel_of(parts)
    out = {"mount": m["id"], "path": r, "name": parts[-1] if parts else m["name"], "size": st.st_size,
           "mtime": st.st_mtime, "ctime": st.st_ctime, "dir": os.path.isdir(full), "cat": category(r),
           "url": public_url(m, r), "urls": urls_for(m, r), "access": rules.effective(m["id"], url_path(m, r))}
    if not out["dir"] and out["cat"] == "image":
        try:
            from PIL import Image
            with Image.open(full) as im:
                out["image"] = {"width": im.width, "height": im.height, "format": im.format, "mode": im.mode,
                                "frames": getattr(im, "n_frames", 1)}
        except Exception as e:
            out["image"] = {"error": str(e)[:120]}
    db = connect()
    try:
        up = url_path(m, r)
        q = urllib.parse.quote(up)
        import rollup
        out["daily"] = rollup.path_daily([up], 30)
        # referrers of one file: recent raw requests only, bounded (newest 20,000 matching rows of the last 7 days)
        out["referrers"] = rows_of(db.execute(
            "SELECT ref k, count(*) c FROM (SELECT ref FROM req WHERE (path=? OR path=?) AND ts >= ? ORDER BY rowid DESC "
            "LIMIT 20000) WHERE ref != '' GROUP BY ref ORDER BY c DESC LIMIT 8", [q, up, time.time() - 7 * 86400]))
        out["links"] = rows_of(db.execute("SELECT code, clicks, mods, expires, max_clicks, enabled FROM link WHERE mount=? AND path=?",
                                          [m["id"], r]))
        idx = db.execute("SELECT hash, qhash FROM fidx WHERE mount=? AND path=?", [m["id"], r]).fetchone()
        out["sha256"] = idx[0] if idx and idx[0] else None
        if idx and idx[0]:
            out["duplicates"] = [p for mt, p in db.execute("SELECT mount, path FROM fidx WHERE hash=? AND NOT (mount=? AND path=?) LIMIT 20",
                                                           [idx[0], m["id"], r]) if not allow or allow(mt, p)]
    finally:
        db.close()
    return out


def sha256_of(mid, rel):
    m = get_mount(mid)
    full, parts = resolve(m, rel)
    if not os.path.isfile(full):
        raise FileError(404, "file not found")
    h = hashlib.sha256()
    with open(full, "rb") as f:
        for buf in iter(lambda: f.read(4 * MiB), b""):
            h.update(buf)
    db = connect()
    try:
        with db:
            db.execute("UPDATE fidx SET hash=? WHERE mount=? AND path=?", [h.hexdigest(), m["id"], rel_of(parts)])
    finally:
        db.close()
    return {"sha256": h.hexdigest()}


THUMB_DIR = os.path.join(core.HOME, "data", "thumbs")
THUMB_SEM = threading.Semaphore(3)


def thumbnail(mid, rel, w):
    m = get_mount(mid)
    full, parts = resolve(m, rel)
    if not os.path.isfile(full) or category(full) != "image":
        raise FileError(404, "not an image")
    w = max(32, min(640, int(w or 240)))
    st = os.stat(full)
    key = hashlib.sha1(("%s|%s|%s|%s|%d" % (m["id"], rel_of(parts), st.st_mtime, st.st_size, w)).encode()).hexdigest()
    path = os.path.join(THUMB_DIR, key[:2], key + ".webp")
    if not os.path.exists(path):
        if st.st_size > 200 * MiB:
            raise FileError(413, "image too large for a thumbnail")
        from PIL import Image, ImageOps
        Image.MAX_IMAGE_PIXELS = 120_000_000
        with THUMB_SEM:
            with Image.open(full) as im:
                im = ImageOps.exif_transpose(im)
                im.thumbnail((w, w * 2))
                if im.mode not in ("RGB", "RGBA"):
                    im = im.convert("RGBA")
                os.makedirs(os.path.dirname(path), exist_ok=True)
                im.save(path + ".tmp", "WEBP", quality=72, method=4)
                os.replace(path + ".tmp", path)
    return path


ZIPS = {}


def zip_prepare(mid, paths):
    m = get_mount(mid)
    items = []
    for rel in paths:
        full, parts = resolve(m, rel)
        if not parts or not os.path.exists(full):
            raise FileError(404, "not found: %s" % rel)
        items.append((full, parts))
    if not items:
        raise FileError(400, "nothing selected")
    tok = secrets.token_urlsafe(18)
    ZIPS[tok] = {"mount": m["id"], "items": items, "exp": time.time() + 600,
                 "name": (items[0][1][-1] if len(items) == 1 else (m["name"] + "-" + time.strftime("%Y%m%d-%H%M"))) + ".zip"}
    for t in [t for t, z in ZIPS.items() if z["exp"] < time.time()]:
        ZIPS.pop(t, None)
    return {"token": tok, "name": ZIPS[tok]["name"]}


def zip_take(tok):
    z = ZIPS.pop(tok, None)
    if not z or z["exp"] < time.time():
        raise FileError(404, "download expired - start it again")
    return z


def zip_write(z, out):
    """Write a ZIP of the prepared selection to the (unseekable) response stream."""
    import zipfile
    m = get_mount(z["mount"])
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as zf:
        for full, parts in z["items"]:
            full, _ = resolve(m, rel_of(parts))
            if os.path.isdir(full):
                for dp, dn, fn in safe_walk(full):
                    for n in fn:
                        if n.startswith(".strata"):
                            continue
                        p, _ = resolve(m, rel_of(os.path.relpath(os.path.join(dp, n), root_of(m)).split(os.sep)))
                        if os.path.splitext(n)[1] in SIDE and os.path.exists(os.path.join(dp, os.path.splitext(n)[0])):
                            continue
                        zf.write(p, os.path.join(parts[-1], os.path.relpath(p, full)))
            else:
                zf.write(full, parts[-1])


def safe_walk(full):
    """Recursive exports never follow links or Windows junctions into unselected folders."""
    def allowed(p):
        if os.path.basename(p).lower().startswith(".strata"):
            return False
        s = os.lstat(p)
        return not (stat.S_ISLNK(s.st_mode) or getattr(s, "st_file_attributes", 0) & 0x400)

    for dp, dn, fn in os.walk(full):
        dn[:] = [d for d in dn if allowed(os.path.join(dp, d))]
        yield dp, dn, [n for n in fn if allowed(os.path.join(dp, n))]


# ---------------------------------------------------------------- drives on this machine

def drives():
    import ctypes
    out = []
    try:
        letters = os.listdrives()
    except AttributeError:
        letters = ["%s:\\" % c for c in "CDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists("%s:\\" % c)]
    kinds = {0: "unknown", 1: "none", 2: "removable", 3: "fixed", 4: "network", 5: "optical", 6: "ramdisk"}
    for d in letters:
        e = {"path": d, "kind": "unknown", "label": ""}
        try:
            e["kind"] = kinds.get(ctypes.windll.kernel32.GetDriveTypeW(d), "unknown")
            buf = ctypes.create_unicode_buffer(261)
            if ctypes.windll.kernel32.GetVolumeInformationW(d, buf, 261, None, None, None, None, 0):
                e["label"] = buf.value
            du = shutil.disk_usage(d)
            e.update(total=du.total, used=du.used, free=du.free)
        except Exception:
            pass
        out.append(e)
    return {"drives": out, "served": served()}


def served():
    """Strata's own file drives with their disk usage. Unlike drives(), never asks Windows about every drive letter,
    which can block for many seconds on a sleeping network or removable drive."""
    out = []
    for m in core.file_mounts(enabled_only=False):
        s = {"path": m["path"], "mount": m["id"], "name": m["name"], "kind": m["kind"], "base_url": public_url(m, "/")}
        try:
            du = shutil.disk_usage(m["path"])
            s.update(total=du.total, used=du.used, free=du.free, online=True)
        except OSError:
            s["online"] = False
        out.append(s)
    return out


def browse_dirs(path):
    """Sub-folders of any local path (only folders) - used when choosing a new drive root."""
    path = os.path.normpath(path or "C:\\")
    if not os.path.isdir(path):
        raise FileError(404, "not a folder")
    try:
        names = sorted(e.name for e in os.scandir(path) if e.is_dir() and not e.name.startswith(("$", ".")))
    except OSError as e:
        raise FileError(403, e.strerror or str(e))
    return {"path": path, "parent": os.path.dirname(path) if os.path.dirname(path) != path else None,
            "dirs": names[:500]}


# ---------------------------------------------------------------- remote upload (fetch a URL onto a drive)

def _public_host(host):
    """Resolve and refuse anything that is not a public internet address (SSRF: the admin UI must not become a way
    to read LAN services, cloud metadata or this PC's own admin endpoints)."""
    import ipaddress
    import socket
    clean_host = str(host or "").strip().strip("[]")  # [::1] as it appears in a URL
    cgnat = ipaddress.ip_network("100.64.0.0/10")  # carrier-grade NAT, which is also where Tailscale lives
    try:
        infos = socket.getaddrinfo(clean_host, None)
    except OSError as e:
        raise FileError(400, "cannot resolve %s: %s" % (host, e))
    ips = [ipaddress.ip_address(info[4][0].split("%")[0]) for info in infos]
    if not ips:
        raise FileError(400, "cannot resolve %s" % host)
    for ip in ips:  # every answer must be public, else a second record could point at the LAN
        if getattr(ip, "ipv4_mapped", None):
            ip = ip.ipv4_mapped
        if (not ip.is_global or ip in cgnat or ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
                or ip.is_reserved or ip.is_unspecified):
            raise FileError(400, "%s resolves to a non-public address (%s) - remote uploads only fetch from the internet"
                            % (host, ip))
    return str(ips[0])


def _pinned_opener():
    """urllib opener whose every connection (including each redirect hop) goes to an address _public_host() approved
    at connect time - no DNS-rebinding window - while TLS is still verified against the real host name.
    No ProxyHandler: an environment proxy would bypass the address check."""
    import http.client
    import socket
    import ssl
    import urllib.request

    def pinned(base, tls):
        class Conn(base):
            def connect(self):
                sock = socket.create_connection((_public_host(self.host), self.port), self.timeout)
                self.sock = self._context.wrap_socket(sock, server_hostname=self.host) if tls else sock
        return Conn

    class Handler(urllib.request.HTTPHandler, urllib.request.HTTPSHandler):
        def __init__(self):
            urllib.request.HTTPHandler.__init__(self)
            urllib.request.HTTPSHandler.__init__(self, context=ssl.create_default_context())

        def http_open(self, req):
            return self.do_open(pinned(http.client.HTTPConnection, False), req)

        def https_open(self, req):
            return self.do_open(pinned(http.client.HTTPSConnection, True), req, context=self._context)

    class Redirects(urllib.request.HTTPRedirectHandler):
        max_redirections = 5

        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            nu = urllib.parse.urlsplit(newurl)
            if nu.scheme not in ("http", "https") or not nu.hostname:
                raise FileError(400, "redirect to a non-http URL refused")
            _public_host(nu.hostname)
            return super().redirect_request(req, fp, code, msg, hdrs, newurl)

    return urllib.request.build_opener(urllib.request.ProxyHandler({}), Handler, Redirects)


def fetch_url(user, mid, dest_dir, url, name=None, policy="rename"):
    """Download `url` into a drive folder as a background job (Jobs panel shows progress)."""
    import urllib.request
    m = get_mount(mid)
    dfull, dparts = resolve(m, dest_dir)
    if not os.path.isdir(dfull):
        raise FileError(404, "destination folder not found")
    u = urllib.parse.urlsplit(str(url or "").strip())
    if u.scheme not in ("http", "https") or not u.hostname:
        raise FileError(400, "only http(s) URLs")
    _public_host(u.hostname)
    fname = name or urllib.parse.unquote(u.path.rsplit("/", 1)[-1]) or "download"
    fname = BAD_CHARS.sub("_", fname).strip(" .")[:180] or "download"
    parts_of(fname)
    if policy not in ("rename", "replace", "skip", "ask"):
        policy = "rename"
    limit = upload_limit()

    def work(job):
        req = urllib.request.Request(urllib.parse.urlunsplit(u), headers={"User-Agent": "Strata remote upload"})
        with _pinned_opener().open(req, timeout=30) as r:
            size = int(r.headers.get("Content-Length") or 0)
            if size > limit:
                raise FileError(413, "remote file is larger than the upload limit")
            job["bytes_total"], job["files_total"], job["current"] = size, 1, fname
            check_space(m, size)
            tmp = os.path.join(dfull, PART_PREFIX + secrets.token_hex(6) + ".part")
            try:
                with open(tmp, "wb") as f:
                    while True:
                        buf = r.read(1 << 20)
                        if not buf:
                            break
                        f.write(buf)
                        job["bytes"] += len(buf)
                        if job["bytes"] > limit:
                            raise FileError(413, "remote file exceeds the upload limit")
                res = finalize(user, m, dparts + [fname], tmp, policy if policy != "ask" else "rename")
            except BaseException:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
                raise
        job["files"] = 1
        res.pop("full", None)
        job["purge"] = res.get("purge") or []
        return {"path": res["path"], "url": res["url"], "size": res["size"]}
    job = start_job(user, "fetch", "Fetch %s" % (u.hostname + u.path)[-80:], work)
    job["mount"], job["dest"] = m["id"], rel_of(dparts)
    return {"job": job["id"]}


# ---------------------------------------------------------------- trash: permanently delete single items

def trash_delete(mid, entries):
    """Permanently delete selected trash items: entries [{batch, path}]. Their URLs answer 404 from now on."""
    m = get_mount(mid)
    root = os.path.join(root_of(m), TRASH)
    freed, done = 0, []
    for e in entries or []:
        batch, rel = str(e.get("batch") or ""), str(e.get("path") or "")
        if not re.fullmatch(r"[0-9]{8}-[0-9]{6}-[0-9a-f]{4}", batch):
            raise FileError(400, "bad batch")
        parts = parts_of(rel)
        if not parts:
            continue
        bdir = os.path.join(root, batch)
        full = os.path.normpath(os.path.join(bdir, *parts))
        if os.path.commonpath([full.lower(), bdir.lower()]) != bdir.lower() or not os.path.exists(full):
            continue
        if os.path.isdir(full):
            freed += dir_bytes(full)
            shutil.rmtree(full)
        else:
            freed += os.path.getsize(full)
            os.remove(full)
            for suf in SIDE:
                if os.path.exists(full + suf):
                    os.remove(full + suf)
        done.append({"path": rel_of(parts), "dir": False})
        try:  # an empty batch (only the manifest left) goes away entirely
            left = [x for x in os.listdir(bdir) if x not in (".manifest.json", ".versions")]
            if not left:
                shutil.rmtree(bdir)
        except OSError:
            pass
    sync_bin(m)  # binned paths that left the trash now answer 404
    return {"deleted": len(done), "freed": freed, "purge": purge_targets(m, [(d["path"], d["dir"]) for d in done])}


def dir_bytes(path):
    total = 0
    for dp, _, fn in os.walk(path):
        for n in fn:
            try:
                total += os.path.getsize(os.path.join(dp, n))
            except OSError:
                pass
    return total
