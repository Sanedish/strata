"""File analyser: what takes up space, where, and how it is (or is not) being served. Reads the fidx/fdir index
(compress.py keeps it current) and the per-file hit rollups (rollup.agg_pd), never the raw request log.

    overview   totals, categories, extensions, size / age histograms, cleanup candidates, delivery limits
    tree       one folder's children for the treemap (+ hits and age per node for the heat / age colourings)
    find       the filter builder: name, path, type, size, age, hits -> paged rows + totals (bulk actions in the UI)
    growth     daily storage history per drive (compress.write_inventory) + linear forecast of "disk full"
    folders    folders by origin bandwidth / hits (hot folders)
    dupes / listing  as before
"""
import collections
import json
import re
import shutil
import threading
import time

import core
from core import connect, get_meta, rows_of

SIZE_EDGES = [(0, "empty"), (1 << 10, "< 1 KB"), (100 << 10, "1–100 KB"), (1 << 20, "0.1–1 MB"), (10 << 20, "1–10 MB"),
              (100 << 20, "10–100 MB"), (512 << 20, "100–512 MB"), (1 << 30, "0.5–1 GB"), (float("inf"), "≥ 1 GB")]
AGE_EDGES = [(7, "< 1 week"), (30, "< 1 month"), (90, "< 3 months"), (365, "< 1 year"), (730, "1–2 years"),
             (1825, "2–5 years"), (float("inf"), "> 5 years")]
CLEANUP = [
    ("Blender backups", r"\.blend\d+$", "Blender writes .blend1/.blend2 backups on every save"),
    ("Temporary files", r"(\.tmp|\.temp|\.part|\.crdownload|~)$|^~\$", "leftovers from editors and downloads"),
    ("OS junk", r"^(thumbs\.db|desktop\.ini|\.ds_store|ehthumbs\.db)$", "created by Windows Explorer / macOS Finder"),
    ("Log files", r"\.log$", "usually safe to archive"),
    ("Backup copies", r"(\.bak|\.old|\.orig|- copy(\s\(\d+\))?\.[^.]+)$", "manual copies and editor backups"),
]
CF_CACHE_MAX = 512 << 20
CF_UPLOAD_MAX = 100 << 20
SORTS = {"size": "size DESC", "-size": "size ASC", "mtime": "mtime DESC", "-mtime": "mtime ASC",
         "name": "name COLLATE NOCASE ASC", "path": "path COLLATE NOCASE ASC"}


def mounts_for(mid):
    ms = core.file_mounts(enabled_only=False)
    if mid in (None, "", "all"):
        return ms
    return [m for m in ms if m["id"] == int(mid)]


def where_mount(ms):
    ids = [m["id"] for m in ms] or [-1]
    return "mount IN (%s)" % ",".join(str(int(i)) for i in ids)


def origin_hits(days=90):
    """decoded URL path -> [requests, bytes, last] at the origin (Cloudflare cache hits never reach it)."""
    import rollup
    return rollup.path_hits(days)


def url_of(m, rel):
    return rel if m["prefix"] == "/" else m["prefix"] + rel


_ov = {}
_ov_lock = threading.Lock()


def overview(q):
    """Cached for 60 s per drive selection: one pass over the whole index (millions of files) is not per-click work."""
    key = str(q.get("mount") or "all")
    with _ov_lock:
        hit = _ov.get(key)
        if hit and time.time() - hit[0] < 60 and q.get("force") != "1":
            return hit[1]
    v = _overview(q)
    with _ov_lock:
        _ov[key] = (time.time(), v)
    return v


def _overview(q):
    ms = mounts_for(q.get("mount"))
    W = where_mount(ms)
    byid = {m["id"]: m for m in ms}
    cold_days = 90
    db = connect()
    try:
        x = lambda sql, a=(): rows_of(db.execute(sql, list(a)))
        tot = x("SELECT count(*) files, coalesce(sum(size),0) bytes, max(size) largest, min(mtime) oldest, "
                "max(mtime) newest FROM fidx WHERE " + W)[0]
        tot["folders"] = db.execute("SELECT count(*) FROM fdir WHERE %s AND path != '/'" % W).fetchone()[0]
        cats = x("SELECT cat k, count(*) c, sum(size) b FROM fidx WHERE %s GROUP BY cat ORDER BY b DESC" % W)
        exts = x("SELECT ext k, count(*) c, sum(size) b, max(size) mx FROM fidx WHERE %s GROUP BY ext ORDER BY b DESC "
                 "LIMIT 60" % W)
        sizes = collections.OrderedDict((l, [0, 0]) for _, l in SIZE_EDGES)
        ages = collections.OrderedDict((l, [0, 0]) for _, l in AGE_EDGES)
        now = time.time()
        cleanup = {name: {"c": 0, "b": 0, "why": why, "items": []} for name, _, why in CLEANUP}
        rxs = [(name, re.compile(rx, re.I)) for name, rx, _ in CLEANUP]
        big_cache, big_upload, video = [0, 0], [0, 0], [0, 0]
        empties = []
        hits = origin_hits(cold_days)
        hot, cold = [], [0, 0]
        for mid, path, name, size, mtime, cat in db.execute(
                "SELECT mount, path, name, size, mtime, cat FROM fidx WHERE " + W):
            for edge, label in SIZE_EDGES:
                if size < edge or (edge == 0 and size == 0):
                    sizes[label][0] += 1; sizes[label][1] += size
                    break
            days = (now - (mtime or now)) / 86400
            for edge, label in AGE_EDGES:
                if days < edge:
                    ages[label][0] += 1; ages[label][1] += size
                    break
            for cname, rx in rxs:
                if rx.search(name):
                    c = cleanup[cname]
                    c["c"] += 1; c["b"] += size
                    if len(c["items"]) < 200:
                        c["items"].append({"mount": mid, "path": path, "size": size})
                    break
            if size == 0 and len(empties) < 200:
                empties.append({"mount": mid, "path": path, "size": 0})
            if size > CF_CACHE_MAX:
                big_cache[0] += 1; big_cache[1] += size
            if size > CF_UPLOAD_MAX:
                big_upload[0] += 1; big_upload[1] += size
            if cat == "video":
                video[0] += 1; video[1] += size
            m = byid.get(mid)
            h = hits.get(url_of(m, path)) if m else None
            if h:
                if len(hot) < 5000 or h[1] > hot[-1]["sent"]:
                    hot.append({"mount": mid, "path": path, "size": size, "hits": h[0], "sent": h[1], "last": h[2]})
                    if len(hot) > 10000:
                        hot.sort(key=lambda r: -r["sent"])
                        del hot[5000:]
            else:
                cold[0] += 1; cold[1] += size
        cleanup["Empty files"] = {"c": len(empties), "b": 0, "why": "zero-byte files", "items": empties}
        empty_dirs = x("SELECT mount, path FROM fdir WHERE %s AND files = 0 AND path != '/' LIMIT 200" % W)
        cleanup["Empty folders"] = {"c": len(empty_dirs), "b": 0, "why": "folders without any files",
                                    "items": [{"mount": d["mount"], "path": d["path"], "size": 0, "dir": True} for d in empty_dirs]}
        largest = x("SELECT mount, path, size, mtime, cat FROM fidx WHERE %s ORDER BY size DESC LIMIT 100" % W)
        folders = x("SELECT mount, path, files, dirs, bytes, newest, cats FROM fdir WHERE %s AND path != '/' "
                    "ORDER BY bytes DESC LIMIT 100" % W)
        for f in folders:
            f["cats"] = json.loads(f["cats"] or "{}")
        dup = x("SELECT count(*) groups, coalesce(sum(n),0) files, coalesce(sum((n-1)*size),0) wasted FROM "
                "(SELECT hash, size, count(*) n FROM fidx WHERE %s AND hash IS NOT NULL GROUP BY hash HAVING n > 1)" % W)[0]
        dup["hashed"] = db.execute("SELECT count(*) FROM fidx WHERE %s AND hash IS NOT NULL" % W).fetchone()[0]
        dup["candidates"] = db.execute("SELECT count(*) FROM fidx WHERE %s AND size IN (SELECT size FROM fidx WHERE "
                                       "size >= 4096 GROUP BY size HAVING count(*) > 1)" % W).fetchone()[0]
        overhead, drives = {}, []
        for m in ms:
            inv = get_meta(db, "inventory:%d" % m["id"]) or {}
            for k, v in (inv.get("overhead") or {}).items():
                o = overhead.setdefault(k, {"files": 0, "bytes": 0})
                o["files"] += v.get("files", 0); o["bytes"] += v.get("bytes", 0)
            root = rows_of(db.execute("SELECT files, dirs, bytes, newest, cats FROM fdir WHERE mount=? AND path='/'", [m["id"]]))
            d = {"id": m["id"], "name": m["name"], "path": m["path"], "kind": m["kind"], "enabled": m["enabled"],
                 "scanned": inv.get("ts")}
            if root:
                d.update(files=root[0]["files"], dirs=root[0]["dirs"], bytes=root[0]["bytes"],
                         cats=json.loads(root[0]["cats"] or "{}"))
            try:
                du = shutil.disk_usage(m["path"])
                d["disk"] = {"total": du.total, "used": du.used, "free": du.free}
            except OSError:
                d["disk"] = None
            d["forecast"] = forecast(get_meta(db, "inv_hist:%d" % m["id"]) or [], d["disk"])
            drives.append(d)
    finally:
        db.close()
    hot.sort(key=lambda r: -r["sent"])
    return {"totals": tot, "cats": cats, "exts": exts,
            "sizes": [{"k": k, "c": v[0], "b": v[1]} for k, v in sizes.items()],
            "ages": [{"k": k, "c": v[0], "b": v[1]} for k, v in ages.items()],
            "largest": largest, "folders": folders, "cleanup": cleanup,
            "delivery": {"over_cache_limit": {"c": big_cache[0], "b": big_cache[1]},
                         "over_upload_limit": {"c": big_upload[0], "b": big_upload[1]},
                         "video": {"c": video[0], "b": video[1]}},
            "duplicates": dup, "overhead": overhead, "drives": drives,
            "hot": hot[:100], "cold": {"c": cold[0], "b": cold[1], "days": cold_days}, "ts": time.time()}


def tree(q):
    """Children of one folder for the treemap (folders from fdir, files from fidx), with hits for heat colouring."""
    m = core.mount(q.get("mount"))
    if not m:
        return {"error": "unknown drive"}
    path = "/" + "/".join(p for p in (q.get("path") or "/").split("/") if p)
    db = connect()
    try:
        me = rows_of(db.execute("SELECT files, dirs, bytes, newest, cats FROM fdir WHERE mount=? AND path=?", [m["id"], path]))
        dirs = rows_of(db.execute("SELECT path, files, dirs, bytes, newest, cats FROM fdir WHERE mount=? AND parent=? "
                                  "ORDER BY bytes DESC LIMIT 400", [m["id"], path]))
        files = rows_of(db.execute("SELECT path, name, size, mtime, cat FROM fidx WHERE mount=? AND parent=? "
                                   "ORDER BY size DESC LIMIT 400", [m["id"], path]))
    finally:
        db.close()
    import rollup
    base = url_of(m, path).rstrip("/") + "/"
    hits = rollup.path_hits_prefix(base, 30)
    under = collections.defaultdict(lambda: [0, 0])
    for p, (c, b, _) in hits.items():
        if p.startswith(base):
            child = p[len(base):].split("/", 1)[0]
            u = under[child]
            u[0] += c; u[1] += b
    nodes = []
    for d in dirs:
        cats = json.loads(d["cats"] or "{}")
        name = d["path"].rsplit("/", 1)[-1]
        nodes.append({"name": name, "path": d["path"], "dir": True, "size": d["bytes"],
                      "files": d["files"], "dirs": d["dirs"], "newest": d["newest"], "mtime": d["newest"],
                      "cat": max(cats, key=cats.get) if cats else "other", "cats": cats,
                      "hits": under[name][0], "sent": under[name][1]})
    for f in files:
        nodes.append({"name": f["name"], "path": f["path"], "dir": False, "size": f["size"], "mtime": f["mtime"],
                      "cat": f["cat"], "hits": under[f["name"]][0], "sent": under[f["name"]][1]})
    nodes.sort(key=lambda n: -n["size"])
    here = me[0] if me else {"files": 0, "dirs": 0, "bytes": 0, "cats": "{}"}
    here["cats"] = json.loads(here.get("cats") or "{}")
    return {"mount": m["id"], "path": path, "self": here, "nodes": nodes[:300], "more": max(0, len(nodes) - 300)}


def duplicates(q):
    ms = mounts_for(q.get("mount"))
    W = where_mount(ms)
    names = {m["id"]: m["name"] for m in ms}
    db = connect()
    try:
        groups = rows_of(db.execute(
            "SELECT hash, size, count(*) n, (count(*)-1)*size wasted FROM fidx WHERE %s AND hash IS NOT NULL "
            "GROUP BY hash HAVING n > 1 ORDER BY wasted DESC LIMIT 300" % W))
        for g in groups:
            g["items"] = rows_of(db.execute("SELECT mount, path, mtime FROM fidx WHERE hash=? AND %s ORDER BY mtime" % W, [g["hash"]]))
            for it in g["items"]:
                it["drive"] = names.get(it["mount"])
    finally:
        db.close()
    return {"groups": groups}


def listing(q):
    """Lists for the analyser tabs: largest / cold / ext / cat / over the cache limit / video."""
    kind = q.get("kind", "largest")
    if kind == "cold":
        return find(dict(q, hits="cold", days=q.get("days") or 90, sort="size"))
    f = {"ext": {"ext": q.get("value", "")}, "cat": {"cat": q.get("value", "")},
         "over_cache_limit": {"min_size": CF_CACHE_MAX}, "video": {"cat": "video"}}.get(kind, {})
    return find(dict(q, sort="size", **f))


def _num(v, default=None):
    try:
        n = float(v) if v not in (None, "") else default
        return n if n is None or n - n == 0 else default  # inf / nan would crash int() further down
    except (TypeError, ValueError):
        return default


def find(q):
    """The filter builder. Every filter is optional:
         q (name contains), path (folder prefix), ext (comma list), cat, min_size / max_size (bytes),
         older / newer (days since modified), hits: cold | hot | none, days (hit window, default 30),
         min_hits, sort (size|-size|mtime|-mtime|name|path|hits), limit (<= 2000), offset.
    Returns rows (+ hits) and the totals of *all* matches, so bulk actions can say what they will touch."""
    ms = mounts_for(q.get("mount"))
    byid = {m["id"]: m for m in ms}
    w, a = [where_mount(ms)], []
    if q.get("q"):
        w.append("name LIKE ? ESCAPE '\\'"); a.append("%" + _like(q["q"]) + "%")
    if q.get("path") and q["path"] != "/":
        w.append("path LIKE ? ESCAPE '\\'"); a.append(_like(q["path"].rstrip("/") + "/") + "%")
    exts = [e.strip().lower().lstrip(".") for e in str(q.get("ext") or "").split(",") if e.strip()]
    if exts:
        w.append("ext IN (%s)" % ",".join("?" * len(exts))); a += exts
    if q.get("cat"):
        w.append("cat = ?"); a.append(q["cat"])
    for key, op in (("min_size", ">="), ("max_size", "<=")):
        v = _num(q.get(key))
        if v is not None:
            w.append("size %s ?" % op); a.append(int(v))
    now = time.time()
    if _num(q.get("older")) is not None:
        w.append("mtime <= ?"); a.append(now - _num(q["older"]) * 86400)
    if _num(q.get("newer")) is not None:
        w.append("mtime >= ?"); a.append(now - _num(q["newer"]) * 86400)
    sort = q.get("sort") or "size"
    limit = max(1, min(2000, int(_num(q.get("limit"), 200))))
    offset = max(0, int(_num(q.get("offset"), 0)))
    hmode = q.get("hits") or ""
    days = int(_num(q.get("days"), 30))
    min_hits = _num(q.get("min_hits"))
    db = connect()
    try:
        sql = "SELECT mount, path, name, size, mtime, cat, ext FROM fidx WHERE " + " AND ".join(w)
        if not hmode and min_hits is None and sort != "hits":
            total = db.execute("SELECT count(*), coalesce(sum(size),0) FROM fidx WHERE " + " AND ".join(w), a).fetchone()
            rows = rows_of(db.execute(sql + " ORDER BY %s LIMIT ? OFFSET ?" % SORTS.get(sort, SORTS["size"]),
                                      a + [limit, offset]))
            hits = origin_hits(days)
            for r in rows:
                m = byid.get(r["mount"])
                h = hits.get(url_of(m, r["path"])) if m else None
                r["hits"], r["sent"], r["last"] = (h[0], h[1], h[2]) if h else (0, 0, None)
            return {"rows": rows, "total": total[0], "bytes": total[1], "offset": offset, "limit": limit}
        # hit-based filters need the rollup per file: stream the matches (index order) and filter in Python
        hits = origin_hits(days)
        keep = []
        for r in rows_of(db.execute(sql, a)):
            m = byid.get(r["mount"])
            h = hits.get(url_of(m, r["path"])) if m else None
            r["hits"], r["sent"], r["last"] = (h[0], h[1], h[2]) if h else (0, 0, None)
            if hmode in ("cold", "none") and r["hits"]:
                continue
            if hmode == "hot" and not r["hits"]:
                continue
            if min_hits is not None and r["hits"] < min_hits:
                continue
            keep.append(r)
        key = {"hits": lambda r: -r["hits"], "size": lambda r: -r["size"], "-size": lambda r: r["size"],
               "mtime": lambda r: -(r["mtime"] or 0), "-mtime": lambda r: r["mtime"] or 0,
               "name": lambda r: r["name"].lower(), "path": lambda r: r["path"].lower()}.get(sort, lambda r: -r["size"])
        keep.sort(key=key)
        return {"rows": keep[offset:offset + limit], "total": len(keep), "bytes": sum(r["size"] for r in keep),
                "offset": offset, "limit": limit}
    finally:
        db.close()


def _like(s):
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def growth(q):
    """Daily storage history (one point per day and drive, written by compress.write_inventory) + forecast."""
    ms = mounts_for(q.get("mount"))
    db = connect()
    try:
        out = []
        for m in ms:
            hist = get_meta(db, "inv_hist:%d" % m["id"]) or []
            try:
                du = shutil.disk_usage(m["path"])
                disk = {"total": du.total, "used": du.used, "free": du.free}
            except OSError:
                disk = None
            out.append({"mount": m["id"], "name": m["name"], "history": hist, "disk": disk,
                        "forecast": forecast(hist, disk)})
        return {"drives": out}
    finally:
        db.close()


def forecast(hist, disk):
    """Linear fit of the drive's used bytes over the last 30 points -> growth per day and days until full."""
    pts = [(h["ts"], h.get("used")) for h in hist[-30:] if h.get("used") is not None]
    if len(pts) < 3 or not disk:
        return {"per_day": None, "days_left": None, "points": len(pts)}
    t0 = pts[0][0]
    xs = [(t - t0) / 86400 for t, _ in pts]
    ys = [u for _, u in pts]
    n, sx, sy = len(xs), sum(xs), sum(ys)
    sxx = sum(x * x for x in xs)
    sxy = sum(x * y for x, y in zip(xs, ys))
    den = n * sxx - sx * sx
    if not den:
        return {"per_day": None, "days_left": None, "points": n}
    slope = (n * sxy - sx * sy) / den
    left = disk["free"] / slope if slope > 0 else None
    return {"per_day": slope, "days_left": left, "points": n}


def hot_folders(q):
    """Folders (first two levels) by origin bandwidth over `days`."""
    ms = mounts_for(q.get("mount"))
    days = int(_num(q.get("days"), 30))
    depth = max(1, min(4, int(_num(q.get("depth"), 2))))
    hits = origin_hits(days)
    agg = collections.defaultdict(lambda: [0, 0, 0])
    for p, (c, b, last) in hits.items():
        segs = [s for s in p.split("/") if s][:-1][:depth]
        if not segs:
            continue
        k = "/" + "/".join(segs)
        v = agg[k]
        v[0] += c; v[1] += b; v[2] = max(v[2], last or 0)
    rows = sorted(({"path": k, "hits": v[0], "sent": v[1], "last": v[2]} for k, v in agg.items()),
                  key=lambda r: -r["sent"])[:100]
    return {"rows": rows, "days": days, "drives": [m["id"] for m in ms]}
