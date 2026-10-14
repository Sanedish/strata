"""Storage scanner: file index (for the analyzer, search and folder sizes), Brotli precompression and inventory.

One walk per drive does everything:
  * fidx  - every file (size, mtime, category, quick hash / sha256 for duplicate detection)
  * fdir  - recursive folder totals (files, sub-folders, bytes, newest, bytes per category)
  * .br   - Brotli sidecars for compressible files on drives with precompression on. Rules:
            only sidecars Strata made itself (tracked in cfile) are ever replaced or removed; a variant is kept
            only if it saves >= min_saving (min_saving_large above large_bytes); stale ones are regenerated.
  * inventory - per drive, including Strata's own overhead (trash, versions, stalled uploads, variants)
Uploads and file operations queue a quick re-index of just the affected folder.
"""
import collections
import gzip
import hashlib
import json
import os
import queue
import secrets
import shutil
import threading
import time
import traceback

import core
from core import CFG, PRECOMP, category, connect, get_meta, log, rows_of, set_meta

try:
    import brotli
except ImportError:
    brotli = None
try:
    import zstandard
except ImportError:
    zstandard = None

SUFFIX = {"br": ".br", "zstd": ".zst", "gzip": ".gz"}
SIDE_SUFFIXES = tuple(SUFFIX.values())
CHUNK = 1 << 20
SKIP_DIRS = {"$recycle.bin", "system volume information"}
INTERNAL = (".strata-trash", ".strata-versions")


class Incompressible(Exception):
    pass


def available():
    return [v for v in CFG["compression"]["variants"]
            if v == "gzip" or (v == "br" and brotli) or (v == "zstd" and zstandard)]


def levels(size):
    if size <= 1 << 20:
        return {"br": 11, "zstd": 19, "gzip": 9}
    if size <= 16 << 20:
        return {"br": 9, "zstd": 16, "gzip": 9}
    return {"br": 5, "zstd": 10, "gzip": 6}


def compress_file(src, dst, variant, size):
    lv = levels(size)[variant]
    fed = 0
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        if variant == "br":
            c = brotli.Compressor(quality=lv, lgwin=22)
            write, finish = (lambda b: fout.write(c.process(b))), (lambda: fout.write(c.finish()))
        elif variant == "zstd":
            w = zstandard.ZstdCompressor(level=lv).stream_writer(fout, size=size, closefd=False)
            write, finish = w.write, (lambda: w.flush(zstandard.FLUSH_FRAME))
        else:
            g = gzip.GzipFile(filename="", mode="wb", fileobj=fout, compresslevel=lv, mtime=0)
            write, finish = g.write, g.close
        while True:
            b = fin.read(CHUNK)
            if not b:
                break
            write(b)
            fed += len(b)
            if fed >= 8 << 20 and fout.tell() > fed * 0.97:
                raise Incompressible()
        finish()
        return fout.tell()


def mount_roots():
    return [(m, os.path.normpath(m["path"])) for m in core.file_mounts()]


def url_for(full):
    """Public URL path of an absolute file path (drive prefix included), or None."""
    for m, root in mount_roots():
        if full.lower().startswith(root.lower() + os.sep):
            rel = "/" + full[len(root) + 1:].replace(os.sep, "/")
            return rel if m["prefix"] == "/" else m["prefix"] + rel
    return None


def quick_hash(full, size):
    h = hashlib.sha1(str(size).encode())
    with open(full, "rb") as f:
        h.update(f.read(65536))
        if size > 131072:
            f.seek(size - 65536)
            h.update(f.read(65536))
    return h.hexdigest()


def full_hash(full):
    h = hashlib.sha256()
    with open(full, "rb") as f:
        for buf in iter(lambda: f.read(4 << 20), b""):
            h.update(buf)
    return h.hexdigest()


def dir_size(path):
    total, n = 0, 0
    for dp, dn, fn in os.walk(path):
        for x in fn:
            try:
                total += os.path.getsize(os.path.join(dp, x))
                n += 1
            except OSError:
                pass
    return {"bytes": total, "files": n}


class Compressor(threading.Thread):
    daemon = True

    def __init__(self):
        super().__init__(name="scanner")
        self.q = queue.Queue()
        self.lock = threading.Lock()
        self.state = {"running": False, "trigger": "", "current": "", "done": 0, "scanned": 0, "started": None,
                      "next_scan": None, "variants": available(), "hashing": False}

    # -- public API (called from HTTP threads)
    def enqueue(self, full):
        self.q.put(("file", full))

    def request_scan(self):
        self.q.put(("scan", None))

    def reload_map(self):
        self.q.put(("map", None))

    def reindex(self, mid, rel):
        self.q.put(("reindex", (int(mid), rel or "/")))

    def status(self):
        with self.lock:
            return dict(self.state)

    # -- worker
    def run(self):
        db = connect()
        self.load_map(db)
        next_scan = time.time() + 20
        while True:
            with self.lock:
                self.state["next_scan"] = next_scan
            try:
                kind, arg = self.q.get(timeout=5)
            except queue.Empty:
                kind, arg = None, None
            try:
                if kind == "scan" or (kind is None and time.time() >= next_scan):
                    self.full_scan(db, "manual" if kind == "scan" else "scheduled")
                    next_scan = time.time() + CFG["compression"]["scan_minutes"] * 60
                elif kind == "file":
                    files = [arg]
                    later = []
                    while True:
                        try:
                            k, a = self.q.get_nowait()
                        except queue.Empty:
                            break
                        (files.append(a) if k == "file" else later.append((k, a)))
                    for item in later:
                        self.q.put(item)
                    self.compress_paths(db, files, "upload")
                elif kind == "reindex":
                    self.reindex_subtree(db, *arg)
                elif kind == "map":
                    self.load_map(db)
            except Exception:
                log("scanner error:\n" + traceback.format_exc())
                with self.lock:
                    self.state.update(running=False, current="", hashing=False)

    def load_map(self, db):
        m = {}
        for path, orig in db.execute("SELECT path, max(orig) FROM cfile WHERE size IS NOT NULL GROUP BY path"):
            u = url_for(path)
            if u:
                m[u] = orig
        PRECOMP.clear()
        PRECOMP.update(m)

    # -- compression
    def candidate(self, m, name, size):
        c = CFG["compression"]
        return (c["enabled"] and m["precompress"] and c["min_bytes"] <= size <= c["max_bytes"]
                and core.ext_of(name) in set(c["extensions"]))

    @staticmethod
    def threshold(size):
        c = CFG["compression"]
        return c["min_saving"] if size <= c.get("large_bytes", 1 << 20) else c.get("min_saving_large", c["min_saving"])

    def retire(self, db, full, v, recs, stats):
        rec = recs.pop((full, v), None) or {}
        try:
            if rec.get("size") and os.path.getsize(full + SUFFIX[v]) == rec["size"]:
                os.remove(full + SUFFIX[v])
        except OSError:
            pass
        with db:
            db.execute("DELETE FROM cfile WHERE path=? AND variant=?", [full, v])
        stats["removed"] += 1

    def review(self, db, m, full, st, recs, stats):
        cand = self.candidate(m, full, st.st_size)
        wanted = set(CFG["compression"]["variants"])  # the configured variants - NOT the importable ones:
        for v in SUFFIX:                              # a missing library must never delete a valid variant
            rec = recs.get((full, v))
            if not rec:
                continue
            weak = (rec["size"] and rec["mtime"] == st.st_mtime
                    and rec["size"] > st.st_size * (1 - self.threshold(st.st_size)))
            if not cand or v not in wanted or weak:
                self.retire(db, full, v, recs, stats)

    def process(self, db, full, st, recs, names, stats):
        for v in available():
            side = full + SUFFIX[v]
            rec = recs.get((full, v))
            side_exists = (os.path.basename(side) in names) if names is not None else os.path.exists(side)
            if rec is None and side_exists:
                continue  # somebody else's sidecar - not ours to touch
            if rec and rec["mtime"] == st.st_mtime and rec["orig"] == st.st_size:
                if rec["size"] is None or side_exists:
                    continue
            with self.lock:
                self.state["current"] = url_for(full) or full
            tmp = os.path.join(os.path.dirname(full), ".strata-c-%s.tmp" % secrets.token_hex(4))
            t0 = time.perf_counter()
            try:
                out = compress_file(full, tmp, v, st.st_size)
            except Incompressible:
                out = None
            except OSError as e:
                stats["errors"] += 1
                log("compress failed %s (%s): %s" % (full, v, e))
                try:
                    os.remove(tmp)
                except OSError:
                    pass
                continue
            secs = time.perf_counter() - t0
            if out is not None and out <= st.st_size * (1 - self.threshold(st.st_size)):
                os.replace(tmp, side)
                stats["compressed"] += 1
                stats["bytes_in"] += st.st_size
                stats["bytes_out"] += out
            else:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
                if rec and rec["size"] and side_exists:
                    try:
                        os.remove(side)
                    except OSError:
                        pass
                out = None
                stats["skipped"] += 1
            with db:
                db.execute("INSERT OR REPLACE INTO cfile(path, variant, orig, size, mtime, created, secs) "
                           "VALUES(?,?,?,?,?,?,?)", [full, v, st.st_size, out, st.st_mtime, time.time(), secs])
            recs[(full, v)] = {"orig": st.st_size, "size": out, "mtime": st.st_mtime}
            with self.lock:
                self.state["done"] += 1

    def load_recs(self, db):
        return {(p, v): {"orig": o, "size": s, "mtime": mt}
                for p, v, o, s, mt in db.execute("SELECT path, variant, orig, size, mtime FROM cfile")}

    def begin(self, trigger):
        with self.lock:
            self.state.update(running=True, trigger=trigger, current="", done=0, scanned=0, started=time.time())
        return {"scanned": 0, "compressed": 0, "skipped": 0, "bytes_in": 0, "bytes_out": 0, "removed": 0,
                "errors": 0, "t0": time.time()}

    def finish(self, db, trigger, stats, note=""):
        secs = time.time() - stats["t0"]
        with db:
            db.execute("INSERT INTO crun VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                       [time.time(), trigger, stats["scanned"], stats["compressed"], stats["skipped"],
                        stats["bytes_in"], stats["bytes_out"], stats["removed"], stats["errors"], secs, note])
        self.load_map(db)
        with self.lock:
            self.state.update(running=False, current="", last={k: v for k, v in stats.items() if k != "t0"},
                              last_secs=secs, last_ts=time.time(), last_trigger=trigger)
        if trigger != "upload" or stats["compressed"]:
            log("scan %s: %d files, %d compressed (%d -> %d bytes), %d skipped, %d removed, %.1fs"
                % (trigger, stats["scanned"], stats["compressed"], stats["bytes_in"], stats["bytes_out"],
                   stats["skipped"], stats["removed"], secs))

    def mount_of(self, full):
        for m, root in mount_roots():
            if full.lower().startswith(root.lower() + os.sep):
                return m, root
        return None, None

    def compress_paths(self, db, files, trigger):
        stats = self.begin(trigger)
        recs = self.load_recs(db)
        touched = set()
        for full in files:
            m, root = self.mount_of(full)
            try:
                st = os.stat(full)
            except OSError:
                continue
            stats["scanned"] += 1
            if m:
                touched.add((m["id"], "/" + os.path.dirname(full)[len(root) + 1:].replace(os.sep, "/")))
                if self.candidate(m, full, st.st_size):
                    self.process(db, full, st, recs, None, stats)
        self.finish(db, trigger, stats, "%d uploaded file(s)" % len(files))
        for mid, rel in touched:
            self.reindex_subtree(db, mid, rel.rstrip("/") or "/")

    # -- indexing
    def walk_mount(self, db, m, root, sub, recs, stats, compress):
        """Walk root/sub; returns (file rows, dir set, inventory bits)."""
        start = os.path.join(root, *[p for p in sub.split("/") if p])
        old = {r[0]: r[1:] for r in db.execute(
            "SELECT path, size, mtime, qhash, hash FROM fidx WHERE mount=? AND (path LIKE ? ESCAPE '\\')",
            [m["id"], like(sub)])}
        files, dirs = [], set()
        variants = [0, 0]
        for dirpath, dirnames, filenames in os.walk(start):
            dirnames[:] = [d for d in dirnames if not d.startswith(".") and d.lower() not in SKIP_DIRS]
            relroot = "/" + dirpath[len(root) + 1:].replace(os.sep, "/") if dirpath != root else "/"
            dirs.add(relroot)
            names = set(filenames)
            for name in filenames:
                if name.startswith(".strata"):
                    continue
                full = os.path.join(dirpath, name)
                is_side = name.endswith(SIDE_SUFFIXES) and os.path.splitext(name)[0] in names
                try:
                    st = os.stat(full)
                except OSError:
                    continue
                if is_side:
                    variants[0] += 1
                    variants[1] += st.st_size
                    continue
                rel = (relroot.rstrip("/") + "/" + name)
                o = old.get(rel)
                qh, h = (o[2], o[3]) if o and o[0] == st.st_size and o[1] == st.st_mtime else (None, None)
                files.append((m["id"], rel, relroot, name, core.ext_of(name), category(name), st.st_size,
                              st.st_mtime, rel.count("/"), qh, h))
                stats["scanned"] += 1
                if stats["scanned"] % 250 == 0:
                    with self.lock:
                        self.state.update(scanned=stats["scanned"], current=m["name"] + ":" + relroot)
                if compress is not None:
                    compress.add(full)
                    self.review(db, m, full, st, recs, stats)
                    if self.candidate(m, name, st.st_size):
                        self.process(db, full, st, recs, names, stats)
                    self.service_uploads(db, recs, stats)
        return files, dirs, variants

    def store_index(self, db, m, sub, files, dirs):
        with db:
            db.execute("DELETE FROM fidx WHERE mount=? AND path LIKE ? ESCAPE '\\'", [m["id"], like(sub)])
            db.executemany("INSERT OR REPLACE INTO fidx(mount,path,parent,name,ext,cat,size,mtime,depth,qhash,hash) "
                           "VALUES(?,?,?,?,?,?,?,?,?,?,?)", files)
            keep = {r[0] for r in db.execute("SELECT path FROM fdir WHERE mount=?", [m["id"]])
                    if not (r[0] == sub or r[0].startswith(sub.rstrip("/") + "/"))} if sub != "/" else set()
            self.rebuild_fdir(db, m["id"], keep | dirs)

    def rebuild_fdir(self, db, mid, dirs):
        agg = {d: [0, 0, 0, 0.0, collections.Counter()] for d in dirs}
        agg.setdefault("/", [0, 0, 0, 0.0, collections.Counter()])

        def ancestors(p):
            while True:
                yield p
                if p == "/":
                    return
                p = p.rsplit("/", 1)[0] or "/"
        for d in list(agg):
            if d != "/":
                for a in ancestors((d.rsplit("/", 1)[0] or "/")):
                    agg.setdefault(a, [0, 0, 0, 0.0, collections.Counter()])[1] += 1
        for parent, size, mtime, cat in db.execute("SELECT parent, size, mtime, cat FROM fidx WHERE mount=?", [mid]):
            for a in ancestors(parent):
                x = agg.setdefault(a, [0, 0, 0, 0.0, collections.Counter()])
                x[0] += 1
                x[2] += size
                if mtime > x[3]:
                    x[3] = mtime
                x[4][cat] += size
        db.execute("DELETE FROM fdir WHERE mount=?", [mid])
        db.executemany("INSERT INTO fdir(mount,path,parent,files,dirs,bytes,newest,cats) VALUES(?,?,?,?,?,?,?,?)",
                       [(mid, p, None if p == "/" else (p.rsplit("/", 1)[0] or "/"), v[0], v[1], v[2], v[3],
                         json.dumps(dict(v[4]))) for p, v in agg.items()])

    def reindex_subtree(self, db, mid, rel):
        m = core.mount(mid)
        if not m or m["kind"] not in ("files", "page"):
            return
        root = os.path.normpath(m["path"])
        rel = "/" + "/".join(p for p in rel.split("/") if p)
        while rel != "/" and not os.path.isdir(os.path.join(root, *rel.strip("/").split("/"))):
            rel = rel.rsplit("/", 1)[0] or "/"
        stats = {"scanned": 0, "compressed": 0, "skipped": 0, "bytes_in": 0, "bytes_out": 0, "removed": 0, "errors": 0}
        files, dirs, _ = self.walk_mount(db, m, root, rel, {}, stats, None)
        self.store_index(db, m, rel, files, dirs)

    def service_uploads(self, db, recs, stats):
        if self.q.empty():
            return
        later = []
        while True:
            try:
                k, a = self.q.get_nowait()
            except queue.Empty:
                break
            if k != "file":
                later.append((k, a))
                continue
            m, _ = self.mount_of(a)
            try:
                st = os.stat(a)
            except OSError:
                continue
            if m and self.candidate(m, a, st.st_size):
                self.process(db, a, st, recs, None, stats)
        for item in later:
            if item[0] != "scan":
                self.q.put(item)

    def full_scan(self, db, trigger):
        stats = self.begin(trigger)
        recs = self.load_recs(db)
        seen = set()
        roots = mount_roots()
        for m, root in roots:
            if not os.path.isdir(root):
                continue
            files, dirs, variants = self.walk_mount(db, m, root, "/", recs, stats, seen)
            self.store_index(db, m, "/", files, dirs)
            self.write_inventory(db, m, root, files, variants)
        # originals that vanished outside Strata: drop our sidecars + records
        for (path, v), rec in list(recs.items()):
            if path in seen:
                continue
            m, root = self.mount_of(path)
            if root is None or not os.path.isdir(root) or os.path.exists(path):
                continue
            if any(part in path for part in INTERNAL):
                continue  # parked in trash / versions: kept for a restore
            self.retire(db, path, v, recs, stats)
        self.finish(db, trigger, stats, "%d drives indexed" % len(roots))
        self.hash_dupes(db, budget=120)

    def write_inventory(self, db, m, root, files, variants):
        cats = collections.defaultdict(lambda: [0, 0])
        folders = collections.defaultdict(lambda: [0, 0])
        for f in files:
            cats[f[5]][0] += 1
            cats[f[5]][1] += f[6]
            top = f[1].split("/")[1] if f[1].count("/") >= 2 else "(root)"
            folders[top][0] += 1
            folders[top][1] += f[6]
        largest = sorted(files, key=lambda f: -f[6])[:12]
        over = {"trash": dir_size(os.path.join(root, ".strata-trash")),
                "versions": dir_size(os.path.join(root, ".strata-versions")),
                "variants": {"files": variants[0], "bytes": variants[1]}}
        # uploads in flight: from the session table (a second walk of the whole drive would double the scan cost)
        parts = db.execute("SELECT count(*), coalesce(sum(size),0) FROM upload WHERE mount=?", [m["id"]]).fetchone()
        over["uploads"] = {"files": parts[0], "bytes": parts[1]}
        inv = {"ts": time.time(), "files": len(files), "bytes": sum(f[6] for f in files), "variants": variants[0],
               "variant_bytes": variants[1], "overhead": over,
               "cats": sorted(({"k": k, "c": v[0], "b": v[1]} for k, v in cats.items()), key=lambda r: -r["b"]),
               "folders": sorted(({"k": k, "c": v[0], "b": v[1]} for k, v in folders.items()), key=lambda r: -r["b"]),
               "largest": [{"k": (f[1] if m["prefix"] == "/" else m["prefix"] + f[1]), "b": f[6]} for f in largest]}
        # one point per day for Analyze > Growth (and its "disk full in N days" forecast); the day's last scan wins
        try:
            du = shutil.disk_usage(root)
            disk = {"total": du.total, "used": du.used, "free": du.free}
        except OSError:
            disk = {}
        point = dict({"ts": inv["ts"], "d": time.strftime("%Y-%m-%d"), "files": inv["files"], "bytes": inv["bytes"],
                      "cats": {c["k"]: c["b"] for c in inv["cats"]}}, **disk)
        with db:
            hist = [h for h in (get_meta(db, "inv_hist:%d" % m["id"]) or []) if h.get("d") != point["d"]]
            set_meta(db, "inv_hist:%d" % m["id"], (hist + [point])[-730:])
            set_meta(db, "inventory:%d" % m["id"], inv)
            if core.primary_mount() and core.primary_mount()["id"] == m["id"]:
                set_meta(db, "inventory", inv)

    def hash_dupes(self, db, budget=120):
        """Duplicate detection: quick hash for same-size files, sha256 only when quick hashes collide."""
        t0 = time.time()
        roots = {m["id"]: root for m, root in mount_roots()}
        with self.lock:
            self.state["hashing"] = True
        try:
            groups = db.execute("SELECT size FROM fidx WHERE size >= 4096 GROUP BY size HAVING count(*) > 1 "
                                "ORDER BY size DESC").fetchall()
            for (size,) in groups:
                if time.time() - t0 > budget:
                    break
                rows = db.execute("SELECT mount, path, qhash, hash FROM fidx WHERE size=?", [size]).fetchall()
                upd = []
                qmap = collections.defaultdict(list)
                for mid, path, qh, h in rows:
                    if mid not in roots:
                        continue
                    full = os.path.join(roots[mid], *path.strip("/").split("/"))
                    if not qh:
                        try:
                            qh = quick_hash(full, size)
                            upd.append(("qhash", qh, mid, path))
                        except OSError:
                            continue
                    qmap[qh].append((mid, path, h, full))
                for qh, items in qmap.items():
                    if len(items) < 2 or size > 8 << 30:
                        continue
                    for mid, path, h, full in items:
                        if not h and time.time() - t0 < budget:
                            try:
                                upd.append(("hash", full_hash(full), mid, path))
                            except OSError:
                                pass
                if upd:
                    with db:
                        for col, val, mid, path in upd:
                            if col not in ("qhash", "hash"):
                                raise ValueError("invalid column")
                            db.execute("UPDATE fidx SET %s=? WHERE mount=? AND path=?" % col, [val, mid, path])
        finally:
            with self.lock:
                self.state["hashing"] = False


def like(sub):
    p = "/" if sub in ("", "/") else sub.rstrip("/") + "/"
    return p.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def q_compression(q, worker):
    where, args, rng, span = core.where_clause(q)
    db = connect()
    try:
        x = lambda sql, a=(): rows_of(db.execute(sql, list(a)))
        store = x("SELECT variant k, count(*) files, sum(orig) orig, sum(size) size, sum(secs) secs FROM cfile "
                  "WHERE size IS NOT NULL GROUP BY variant")
        originals = x("SELECT count(*) files, coalesce(sum(o),0) orig, coalesce(sum(best),0) best FROM "
                      "(SELECT path, max(orig) o, min(size) best FROM cfile WHERE size IS NOT NULL GROUP BY path)")[0]
        skipped = db.execute("SELECT count(DISTINCT path) FROM cfile WHERE size IS NULL").fetchone()[0]
        files = x("""SELECT path, max(orig) orig, min(size) best,
                     max(CASE WHEN variant='br' THEN size END) br, max(CASE WHEN variant='zstd' THEN size END) zstd,
                     max(CASE WHEN variant='gzip' THEN size END) gzip, max(created) created FROM cfile
                     WHERE size IS NOT NULL GROUP BY path ORDER BY max(orig) - min(size) DESC LIMIT 60""")
        for f in files:
            f["k"] = url_for(f.pop("path")) or "(in trash / versions)"
        served = x("""SELECT CASE WHEN enc IS NULL OR enc='' THEN 'identity' ELSE enc END k, count(*) c,
                      sum(bytes) b, sum(saved) saved FROM req WHERE %s AND status<400 GROUP BY k ORDER BY c DESC"""
                   % where, args)
        by_type = x("""SELECT ctype k, count(*) c, sum(enc != '' AND enc IS NOT NULL) enc, sum(bytes) b,
                       sum(saved) saved FROM req WHERE %s AND status<400 AND ctype != '' GROUP BY k
                       ORDER BY c DESC LIMIT 14""" % where, args)
        savers = x("""SELECT path k, count(*) c, sum(saved) saved, sum(bytes) b FROM req WHERE %s AND saved > 0
                      GROUP BY path ORDER BY saved DESC LIMIT 20""" % where, args)
        series = core.filled_series(db, where, args, span, core.BUCKETS.get(rng, 900),
                                    [("saved", "sum(saved)"), ("bytes", "sum(bytes)"),
                                     ("encoded", "sum(enc != '' AND enc IS NOT NULL)"), ("reqs", "count(*)")])
        runs = x("SELECT * FROM crun ORDER BY ts DESC LIMIT 60")
        return {"range": rng, "store": store, "originals": originals, "skipped": skipped, "files": files,
                "served": served, "by_type": by_type, "savers": savers, "series": series, "runs": runs,
                "status": worker.status() if worker else {}, "inventory": get_meta(db, "inventory"),
                "config": {k: CFG["compression"][k] for k in ("enabled", "scan_minutes", "min_bytes", "min_saving")}}
    finally:
        db.close()
