"""Pre-aggregated statistics ("rollups"): the dashboard stays fast at any amount of traffic.

The raw request table (req) grows with every request; scanning it for each dashboard refresh is fine for thousands of
requests a day and hopeless for millions. The tailer therefore also feeds every parsed request into an in-memory
accumulator (ACC), flushed every FLUSH_S seconds as additive upserts into:

    agg_m    per minute and host: requests, bytes, clean 4xx / 5xx, suspicious, bots, saved, ... (live-ish series)
    agg_h    per hour, dimension and key (and host): the same counters plus latency sum / max, last seen and a small
             HyperLogLog of client addresses for low-cardinality dimensions (unique visitors per country, agent ...)
    agg_d    per local day: agg_h folded once the day is over, keeping the top DAY_K keys of high-cardinality
             dimensions (the rest is one "(other)" row) - long ranges read ~1/24 of the rows
    agg_u    HyperLogLogs per hour (and, as host "d:<host>", per day): client addresses per host / "*" (all), plus
             "#path" (distinct paths) and "#sus" (distinct suspicious clients) - distinct counts of any range
    agg_lat  per hour (and "d:<host>" per day) and host: latency histogram (percentiles of any range)
    agg_pd   per local day, host and decoded path: successful requests (hits / bytes / last hit per file)
    visitor  per client address: first and last seen (returning visitors)

A range is read as [first partial day: hours] + [whole days: agg_d] + [the rest: hours], so it is exact to the hour.
High-cardinality dimensions (path, ip, ref, tag) are also compacted per finished hour (top TOP_K + "(other)");
addresses that probed or were flagged are always kept. Suspect reclassification after the fact (rules.on_rows) is
applied as a correction (on_reclass), so clean error rates stay right in the rollups too.

core.q_stats / q_insights / q_history pick the engine per request: exact queries on req while a range holds at most
RAW_MAX requests (and lies inside raw_retention_days), the rollups beyond that ("engine" in the answer says which).
"""
import collections
import hashlib
import json
import math
import threading
import time
import traceback
import urllib.parse

import core
from core import CLEAN, connect, get_meta, log, rows_of, set_meta

FLUSH_S = 20
TOP_K = 1000                # per hour, high-cardinality dimensions
DAY_K = 2000                # per day
RAW_MAX = 250_000           # above this many requests in a range the dashboard reads rollups instead of req
COMPACT = ("path", "ip", "ref", "tag")
U_DIMS = {"host", "country", "colo", "agent", "os", "kind", "ref", "status", "ctype", "method", "enc", "proto", "cat"}
DIMS = ("host", "path", "country", "colo", "agent", "kind", "os", "ctype", "status", "method", "enc", "proto", "ip",
        "ext", "cat", "size", "ref", "tag")
# latency buckets (ms, upper edges, shared with the live window); every edge of the dashboard's 11-bucket histogram
# is one of them
LAT_EDGES = core.LAT_EDGES
lat_bucket = core.lat_bucket
percentile = core.hist_percentile
UI_EDGES = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, float("inf")]
SIZE_EDGES = [0, 1024, 10240, 102400, 1048576, 10485760, 104857600]

_COLS = ("c INTEGER, b INTEGER, ok INTEGER, okb INTEGER, e4 INTEGER, e5 INTEGER, nf INTEGER, sus INTEGER, "
         "scan INTEGER, bots INTEGER, saved INTEGER, enc INTEGER, dur REAL, dmax REAL, last REAL, x TEXT, u BLOB")
SCHEMA = """
CREATE TABLE IF NOT EXISTS agg_m(t INTEGER NOT NULL, host TEXT NOT NULL, c INTEGER, b INTEGER, e4 INTEGER, e5 INTEGER,
  sus INTEGER, bots INTEGER, saved INTEGER, enc INTEGER, ok INTEGER, okb INTEGER, scan INTEGER, dur REAL,
  PRIMARY KEY(t, host)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS agg_h(dim TEXT NOT NULL, t INTEGER NOT NULL, k TEXT NOT NULL, host TEXT NOT NULL, %s,
  PRIMARY KEY(dim, t, k, host)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS agg_d(dim TEXT NOT NULL, t INTEGER NOT NULL, k TEXT NOT NULL, host TEXT NOT NULL, %s,
  PRIMARY KEY(dim, t, k, host)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS agg_u(t INTEGER NOT NULL, host TEXT NOT NULL, hll BLOB, PRIMARY KEY(t, host)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS agg_lat(t INTEGER NOT NULL, host TEXT NOT NULL, h TEXT, PRIMARY KEY(t, host)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS agg_pd(host TEXT NOT NULL, path TEXT NOT NULL, d INTEGER NOT NULL, c INTEGER, b INTEGER,
  last REAL, PRIMARY KEY(host, path, d)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS agg_pd_d ON agg_pd(d);
CREATE INDEX IF NOT EXISTS agg_pd_path ON agg_pd(path, d);
CREATE TABLE IF NOT EXISTS visitor(ip TEXT PRIMARY KEY, first REAL, last REAL, hits INTEGER) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS visitor_last ON visitor(last);
""" % (_COLS, _COLS)
# counters of agg_h / agg_d rows, in this order (index constants below)
CN = ("c", "b", "ok", "okb", "e4", "e5", "nf", "sus", "scan", "bots", "saved", "enc", "dur", "dmax", "last")
C_, B_, OK_, OKB_, E4_, E5_, NF_, SUS_, SCAN_, BOT_, SAVED_, ENC_, DUR_, DMAX_, LAST_ = range(len(CN))
MN = ("c", "b", "e4", "e5", "sus", "bots", "saved", "enc", "ok", "okb", "scan", "dur")


# ---------------------------------------------------------------- HyperLogLog
# Range totals (agg_u): p = 11 (2 KB, ~2.3 % error). Per dimension key (agg_h.u - countries, agents ...): p = 8
# (256 B, ~6.5 %): there are many keys and their counts only rank and anonymise, so merging must stay cheap.
P = 11
KP = 8


def hhash(s):
    return int.from_bytes(hashlib.blake2b(s.encode("utf-8", "replace"), digest_size=8).digest(), "big")


def hll_new(p=P):
    return bytearray(1 << p)


def hll_add(reg, h):
    p = (len(reg) - 1).bit_length()
    idx = h >> (64 - p)
    rest = h & ((1 << (64 - p)) - 1)
    rho = (64 - p) - rest.bit_length() + 1
    if rho > reg[idx]:
        reg[idx] = rho


def hll_merge(a, b):
    if not a:
        return bytearray(b) if b else None
    if not b or len(a) != len(b):
        return a
    return bytearray(map(max, a, b))


def hll_count(reg):
    if not reg:
        return 0
    m = len(reg)
    z = sum(2.0 ** -r for r in reg)
    e = (0.7213 / (1 + 1.079 / m)) * m * m / z
    zeros = reg.count(0)
    if e <= 2.5 * m and zeros:
        e = m * math.log(m / zeros)
    return int(round(e))


# ---------------------------------------------------------------- time helpers

def hour(ts):
    return int(ts // 3600 * 3600)


def minute(ts):
    return int(ts // 60 * 60)


def day(ts):
    """Local date as an int YYYYMMDD (agg_pd)."""
    return int(time.strftime("%Y%m%d", time.localtime(ts)))


def day_start(ts):
    """Epoch of local midnight of the day containing ts (agg_d.t)."""
    lt = time.localtime(ts)
    return int(time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 0, 0, 0, 0, 0, -1)))


def next_day(t):
    return day_start(t + 26 * 3600)


def size_bucket(b):
    if b == 0:
        return 0
    for i, e in enumerate(SIZE_EDGES[1:], 1):
        if b < e:
            return i
    return len(SIZE_EDGES)


def decoded(path):
    try:
        return urllib.parse.unquote(path or "")
    except Exception:
        return path or ""


def dims_of(r):
    """(dim, key) pairs one request counts towards."""
    p = decoded(r["path"])
    e = core.ext_of(p) or ("(folder)" if p.endswith("/") else "(none)")
    out = [("host", ""), ("path", r["path"] or ""), ("country", r["country"] or ""), ("colo", r["colo"] or ""),
           ("agent", "%s\x1f%s" % (r["kind"], r["agent"] or "")), ("kind", r["kind"] or ""), ("os", r["os"] or ""),
           ("ctype", r["ctype"] or ""), ("status", str(r["status"])), ("method", r["method"] or ""),
           ("enc", r["enc"] or "identity"), ("proto", r["proto"] or ""), ("ip", r["ip"] or ""),
           ("ext", e), ("cat", core.category(p) if e not in ("(folder)", "(none)") else "page"),
           ("size", str(size_bucket(r["bytes"] or 0)))]
    if r.get("ref"):
        out.append(("ref", r["ref"]))
    if r.get("tag"):
        out.append(("tag", r["tag"]))
    return out


# ---------------------------------------------------------------- accumulator

class Acc:
    def __init__(self):
        self.lock = threading.Lock()
        self.reset()

    def reset(self):
        self.m, self.h, self.u, self.lat, self.pd, self.vis = {}, {}, {}, {}, {}, {}

    def add(self, rows, reclass=False):
        """Count rows. reclass=True: these stored rows just became suspicious - move their clean errors into the
        suspicious column everywhere (rules.on_rows flags earlier requests of a new suspect)."""
        if not rows:
            return
        with self.lock:
            for r in rows:
                self._one(r, reclass)

    def _hrow(self, key):
        v = self.h.get(key)
        if v is None:
            v = self.h[key] = [0] * len(CN) + [None, None]   # + x (extra json), u (hll)
        return v

    def _uadd(self, key, h):
        u = self.u.get(key)
        if u is None:
            u = self.u[key] = hll_new()
        hll_add(u, h)

    def _one(self, r, reclass):
        ts, host, st = r["ts"], r["host"] or "", int(r["status"] or 0)
        clean = not r.get("sus")
        e4 = 1 if 400 <= st < 500 else 0
        e5 = 1 if st >= 500 else 0
        hh = hour(ts)
        if reclass:  # the row was counted as clean; it is not any more
            v = self.m.setdefault((minute(ts), host), [0] * len(MN))
            v[2] -= e4; v[3] -= e5; v[4] += 1
            for dim, k in dims_of(r):
                v = self._hrow((dim, hh, k, host))
                v[E4_] -= e4; v[E5_] -= e5; v[SUS_] += 1
            if r.get("ip"):
                self._uadd((hh, "#sus"), hhash(r["ip"]))
            return
        b, dur = int(r["bytes"] or 0), float(r["dur"] or 0)
        ok = 1 if st < 400 else 0
        bot = 1 if r["kind"] == "bot" else 0
        enc = 1 if r.get("enc") else 0
        saved = int(r.get("saved") or 0)
        scan = int(r.get("scan") or 0)
        ce4, ce5, sus = (e4, e5, 0) if clean else (0, 0, 1)
        v = self.m.setdefault((minute(ts), host), [0] * len(MN))
        for i, x in enumerate((1, b, ce4, ce5, sus, bot, saved, enc, ok, b if ok else 0, scan, dur)):
            v[i] += x
        ip = r["ip"] or ""
        ih = hhash(ip) if ip else None
        for dim, k in dims_of(r):
            v = self._hrow((dim, hh, k, host))
            v[C_] += 1; v[B_] += b; v[OK_] += ok; v[OKB_] += b if ok else 0; v[E4_] += ce4; v[E5_] += ce5
            v[NF_] += 1 if st == 404 else 0; v[SUS_] += sus; v[SCAN_] += scan; v[BOT_] += bot; v[SAVED_] += saved
            v[ENC_] += enc
            if ok:
                v[DUR_] += dur
                if dur > v[DMAX_]:
                    v[DMAX_] = dur
            if ts > v[LAST_]:
                v[LAST_] = ts
            if dim == "ip":
                x = v[-2] or {}
                x.update(cc=r["country"] or "", agent=r["agent"] or "", kind=r["kind"] or "")
                if not clean:
                    x["why"] = r.get("sus") or ""
                if scan:
                    x["sample"] = (r["path"] or "")[:200]
                v[-2] = x
            elif dim == "path" and ok:
                v[-2] = {"ctype": r["ctype"] or ""}
            if ih is not None and dim in U_DIMS:
                if v[-1] is None:
                    v[-1] = hll_new(KP)
                hll_add(v[-1], ih)
        if ih is not None:
            self._uadd((hh, host), ih)
            self._uadd((hh, "*"), ih)
            if not clean:
                self._uadd((hh, "#sus"), ih)
            vv = self.vis.get(ip)
            if vv is None:
                self.vis[ip] = [ts, ts, 1]
            else:
                vv[0] = min(vv[0], ts); vv[1] = max(vv[1], ts); vv[2] += 1
        self._uadd((hh, "#path"), hhash(r["path"] or ""))
        lt = self.lat.setdefault((hh, host), [0] * len(LAT_EDGES))
        lt[lat_bucket(dur)] += 1
        if ok:
            pk = (day(ts), host, decoded(r["path"]))
            p = self.pd.get(pk)
            if p is None:
                self.pd[pk] = [1, b, ts]
            else:
                p[0] += 1; p[1] += b; p[2] = max(p[2], ts)

    def take(self):
        with self.lock:
            out = (self.m, self.h, self.u, self.lat, self.pd, self.vis)
            self.reset()
        return out


FLUSH_LOCK = threading.Lock()  # live tailer and backfill both merge HLL blobs read-modify-write


def _upsert_rows(db, table, rows):
    """rows: [(dim, t, k, host, *CN, x, u)] added onto existing rows."""
    add = [c for c in CN if c not in ("dmax", "last")]
    db.executemany(
        "INSERT INTO %s(dim,t,k,host,%s,x,u) VALUES(?,?,?,?,%s,?,?) ON CONFLICT(dim,t,k,host) DO UPDATE SET "
        "%s, dmax=max(coalesce(dmax,0),excluded.dmax), last=max(coalesce(last,0),excluded.last), "
        "x=coalesce(excluded.x,x), u=coalesce(excluded.u,u)" % (
            table, ",".join(CN), ",".join("?" * len(CN)), ",".join("%s=coalesce(%s,0)+excluded.%s" % (c, c, c) for c in add)),
        rows)


def flush(acc, db):
    m, h, u, lat, pd, vis = acc.take()
    if not (m or h or u or lat or pd or vis):
        return 0
    with FLUSH_LOCK, db:
        if m:
            db.executemany("INSERT INTO agg_m(t,host,%s) VALUES(?,?,%s) ON CONFLICT(t,host) DO UPDATE SET %s" % (
                ",".join(MN), ",".join("?" * len(MN)), ",".join("%s=%s+excluded.%s" % (c, c, c) for c in MN)),
                [k + tuple(v) for k, v in m.items()])
        if h:
            rows = []
            for (dim, t, k, host), v in h.items():
                x = json.dumps(v[-2], separators=(",", ":")) if v[-2] else None
                ub = None
                if v[-1] is not None:
                    old = db.execute("SELECT u FROM agg_h WHERE dim=? AND t=? AND k=? AND host=?", [dim, t, k, host]).fetchone()
                    ub = bytes(hll_merge(v[-1], old[0] if old and old[0] else None))
                rows.append((dim, t, k, host) + tuple(v[:len(CN)]) + (x, ub))
            _upsert_rows(db, "agg_h", rows)
        for (t, host), reg in u.items():
            old = db.execute("SELECT hll FROM agg_u WHERE t=? AND host=?", [t, host]).fetchone()
            db.execute("INSERT OR REPLACE INTO agg_u(t,host,hll) VALUES(?,?,?)",
                       [t, host, bytes(hll_merge(reg, old[0] if old and old[0] else None))])
        for (t, host), hist in lat.items():
            old = db.execute("SELECT h FROM agg_lat WHERE t=? AND host=?", [t, host]).fetchone()
            if old and old[0]:
                prev = json.loads(old[0])
                hist = [a + (prev[i] if i < len(prev) else 0) for i, a in enumerate(hist)]
            db.execute("INSERT OR REPLACE INTO agg_lat(t,host,h) VALUES(?,?,?)", [t, host, json.dumps(hist)])
        if pd:
            db.executemany("INSERT INTO agg_pd(host,path,d,c,b,last) VALUES(?,?,?,?,?,?) ON CONFLICT(host,path,d) DO "
                           "UPDATE SET c=c+excluded.c, b=b+excluded.b, last=max(last,excluded.last)",
                           [(host, path, d, v[0], v[1], v[2]) for (d, host, path), v in pd.items()])
        if vis:
            db.executemany("INSERT INTO visitor(ip,first,last,hits) VALUES(?,?,?,?) ON CONFLICT(ip) DO UPDATE SET "
                           "first=min(first,excluded.first), last=max(last,excluded.last), hits=hits+excluded.hits",
                           [(ip, v[0], v[1], v[2]) for ip, v in vis.items()])
    return len(m) + len(h)


ACC = Acc()


def init(db):
    db.executescript(SCHEMA)


def on_rows(rows):
    """Tailer hook (after rules.on_rows set the final sus flags)."""
    ACC.add(rows)


def on_reclass(db, spans):
    """rules.on_rows is about to mark stored requests of new suspects: spans [(why, ip, since)]. Called inside its
    transaction, before the UPDATE, so exactly the rows that stop being clean are corrected."""
    rows = []
    for _, ip, since in spans:
        rows += rows_of(db.execute("SELECT ts, host, method, path, status, bytes, dur, ip, country, colo, agent, os, "
                                   "kind, ref, ctype, proto, scan, enc, saved, tag, sus FROM req WHERE ip=? AND ts>=? "
                                   "AND " + CLEAN, [ip, since]))
    if rows:
        ACC.add(rows, reclass=True)


# ---------------------------------------------------------------- background: flush, backfill, compaction

class Worker(threading.Thread):
    daemon = True

    def __init__(self):
        super().__init__(name="rollup")
        self.last_compact = 0

    def run(self):
        db = connect()
        try:
            self.backfill(db)
        except Exception:
            log("rollup backfill error:\n" + traceback.format_exc())
        while True:
            time.sleep(FLUSH_S)
            try:
                flush(ACC, db)
                if time.time() - self.last_compact > 600:
                    self.last_compact = time.time()
                    compact(db)
                    compact_days(db)
                    refresh_hits_async()
            except Exception:
                log("rollup error:\n" + traceback.format_exc())

    @staticmethod
    def backfill(db):
        """Once: build the rollups from the requests stored before they existed (rowid <= the max at start-up;
        everything newer arrives through the tailer hook). Chunked, so a big table never blocks the tailer long."""
        st = get_meta(db, "rollup_v1")
        if st and st.get("done"):
            return
        top = (st or {}).get("top") or db.execute("SELECT coalesce(max(rowid),0) FROM req").fetchone()[0]
        pos = (st or {}).get("pos") or 0
        with db:
            set_meta(db, "rollup_v1", {"top": top, "pos": pos, "done": False})
        acc, n0, t0 = Acc(), pos, time.time()
        cols = "rowid, ts, host, method, path, status, bytes, dur, ip, country, colo, agent, os, kind, ref, ctype, " \
               "proto, scan, enc, saved, tag, sus"
        while pos < top:
            batch = rows_of(db.execute("SELECT %s FROM req WHERE rowid > ? AND rowid <= ? ORDER BY rowid LIMIT 20000"
                                       % cols, [pos, top]))
            if not batch:
                break
            acc.add(batch)
            pos = batch[-1]["rowid"]
            flush(acc, db)
            with db:
                set_meta(db, "rollup_v1", {"top": top, "pos": pos, "done": False})
            time.sleep(0.05)
        compact(db)
        compact_days(db)
        with db:
            set_meta(db, "rollup_v1", {"top": top, "pos": pos, "done": True, "ts": time.time()})
        if pos > n0:
            log("rollups: backfilled %d stored requests in %.1fs" % (pos - n0, time.time() - t0))


def _fold(db, table, dim, t, keep_k):
    """Keep the top keep_k keys of (dim, t) in table; fold the rest into one "(other)" row."""
    n = db.execute("SELECT count(*) FROM %s WHERE dim=? AND t=?" % table, [dim, t]).fetchone()[0]
    if n <= keep_k:
        return
    keep_extra = "OR scan > 0 OR sus > 0" if dim == "ip" else ""
    cut = db.execute("SELECT c FROM %s WHERE dim=? AND t=? ORDER BY c DESC LIMIT 1 OFFSET ?" % table,
                     [dim, t, keep_k]).fetchone()[0]
    cond = "dim=? AND t=? AND k != '(other)' AND c <= ? AND NOT (0 %s)" % keep_extra
    agg = db.execute("SELECT %s FROM %s WHERE %s" % (
        ",".join("coalesce(sum(%s),0)" % c if c not in ("dmax", "last") else "coalesce(max(%s),0)" % c for c in CN),
        table, cond), [dim, t, cut]).fetchone()
    db.execute("DELETE FROM %s WHERE %s" % (table, cond), [dim, t, cut])
    if agg[0]:
        _upsert_rows(db, table, [(dim, t, "(other)", "") + tuple(agg) + (None, None)])


def compact(db):
    """Fold the long tail of high-cardinality dimensions of finished hours into "(other)"."""
    done = get_meta(db, "rollup_compacted", 0) or 0
    limit = hour(time.time()) - 3600  # the current and the previous hour can still receive rows
    hours = [r[0] for r in db.execute("SELECT DISTINCT t FROM agg_h WHERE dim='host' AND t > ? AND t < ? ORDER BY t",
                                      [done, limit])]
    for t in hours:
        with db:
            for dim in COMPACT:
                _fold(db, "agg_h", dim, t, TOP_K)
            set_meta(db, "rollup_compacted", t)


def compact_days(db):
    """Build agg_d (and the daily HyperLogLogs / latency histograms) for every finished local day not done yet."""
    done = get_meta(db, "rollup_days", 0) or 0   # start of the last day folded
    today = day_start(time.time())
    first = db.execute("SELECT min(t) FROM agg_h WHERE dim='host'").fetchone()[0]
    if first is None:
        return
    d = next_day(done) if done else day_start(first)
    while d < today:
        e = next_day(d)
        with db:
            sums = ",".join("sum(%s)" % c if c not in ("dmax", "last") else "max(%s)" % c for c in CN)
            for dim in DIMS:
                rows = db.execute("SELECT k, host, %s, max(x) FROM agg_h WHERE dim=? AND t >= ? AND t < ? GROUP BY k, host"
                                  % sums, [dim, d, e]).fetchall()
                if not rows:
                    continue
                us = {}
                if dim in U_DIMS:
                    for k, host, ub in db.execute("SELECT k, host, u FROM agg_h WHERE dim=? AND t >= ? AND t < ? AND "
                                                  "u IS NOT NULL", [dim, d, e]):
                        us[(k, host)] = hll_merge(us.get((k, host)), ub)
                db.execute("DELETE FROM agg_d WHERE dim=? AND t=?", [dim, d])
                db.executemany("INSERT INTO agg_d(dim,t,k,host,%s,x,u) VALUES(?,?,?,?,%s,?,?)" % (
                    ",".join(CN), ",".join("?" * len(CN))),
                    [(dim, d, r[0], r[1]) + tuple(r[2:2 + len(CN)]) + (r[-1], bytes(us[(r[0], r[1])]) if (r[0], r[1]) in us else None)
                     for r in rows])
                if dim in COMPACT:
                    _fold(db, "agg_d", dim, d, DAY_K)
            regs = collections.defaultdict(lambda: None)
            for host, ub in db.execute("SELECT host, hll FROM agg_u WHERE t >= ? AND t < ? AND host NOT LIKE 'd:%'", [d, e]):
                regs[host] = hll_merge(regs[host], ub)
            for host, reg in regs.items():
                db.execute("INSERT OR REPLACE INTO agg_u(t,host,hll) VALUES(?,?,?)", [d, "d:" + host, bytes(reg)])
            lats = collections.defaultdict(lambda: [0] * len(LAT_EDGES))
            for host, h in db.execute("SELECT host, h FROM agg_lat WHERE t >= ? AND t < ? AND host NOT LIKE 'd:%'", [d, e]):
                acc = lats[host]
                for i, n in enumerate(json.loads(h)):
                    if i < len(acc):
                        acc[i] += n
            for host, hist in lats.items():
                db.execute("INSERT OR REPLACE INTO agg_lat(t,host,h) VALUES(?,?,?)", [d, "d:" + host, json.dumps(hist)])
            set_meta(db, "rollup_days", d)
        d = e


def prune(db, raw_cutoff, cutoff):
    """Retention (called by core.Pruner): minute series and hourly rows follow the raw requests (but never go before
    their day is folded into agg_d), daily rows and the rest the long retention."""
    folded = get_meta(db, "rollup_days", 0) or 0
    hcut = min(raw_cutoff, folded)
    with db:
        db.execute("DELETE FROM agg_m WHERE t < ?", [raw_cutoff])
        db.execute("DELETE FROM agg_h WHERE t < ?", [hcut])
        db.execute("DELETE FROM agg_u WHERE t < ? AND host NOT LIKE 'd:%'", [hcut])
        db.execute("DELETE FROM agg_lat WHERE t < ? AND host NOT LIKE 'd:%'", [hcut])
        db.execute("DELETE FROM agg_d WHERE t < ?", [cutoff])
        db.execute("DELETE FROM agg_u WHERE t < ?", [cutoff])
        db.execute("DELETE FROM agg_lat WHERE t < ?", [cutoff])
        db.execute("DELETE FROM agg_pd WHERE d < ?", [day(max(cutoff, time.time() - 120 * 86400))])
        db.execute("DELETE FROM visitor WHERE last < ?", [cutoff])


# ---------------------------------------------------------------- engine choice

def raw_rows_estimate(db, since, host=None):
    """Requests in [since, now] from the minute series (cheap), None when the rollups do not cover the range."""
    st = get_meta(db, "rollup_v1") or {}
    if not st.get("done"):
        return None
    a = [minute(since)] + ([host] if host else [])
    row = db.execute("SELECT coalesce(sum(c),0) FROM agg_m WHERE t >= ?" + (" AND host=?" if host else ""), a).fetchone()
    return row[0]


def use_rollups(db, q, since, span):
    eng = q.get("engine")
    if eng in ("raw", "rollup"):
        return eng == "rollup"
    if span > float(core.CFG.get("raw_retention_days") or 30) * 86400:
        return True
    n = raw_rows_estimate(db, since, q.get("host"))
    return n is not None and n > RAW_MAX


# ---------------------------------------------------------------- range sources

class Span:
    """A range split into tiers: hours [h0, d0) + days [d0, d1) + hours [d1, now). With no whole day folded inside
    the range, everything comes from the hours."""

    def __init__(self, db, since):
        self.since = since
        self.h0 = hour(since)
        folded = get_meta(db, "rollup_days", 0) or 0
        d0 = next_day(since) if since > day_start(since) else day_start(since)
        d1 = next_day(folded) if folded else 0
        if d1 > d0 + 86400 - 1:
            self.d0, self.d1 = d0, d1
        else:
            self.d0 = self.d1 = None

    def parts(self, alias=""):
        """[(table, where, args)] for agg_h / agg_d rows of this range."""
        if self.d0 is None:
            return [("agg_h", "t >= ?", [self.h0])]
        out = []
        if self.h0 < self.d0:
            out.append(("agg_h", "t >= ? AND t < ?", [self.h0, self.d0]))
        out.append(("agg_d", "t >= ? AND t < ?", [self.d0, self.d1]))
        out.append(("agg_h", "t >= ?", [self.d1]))
        return out

    def union(self, cols, dim, extra="", eargs=()):
        """(sql, args): a sub-select of `cols` from every tier for one dimension."""
        sqls, args = [], []
        for table, w, a in self.parts():
            sqls.append("SELECT %s FROM %s WHERE dim=? AND %s%s" % (cols, table, w, extra))
            args += [dim] + a + list(eargs)
        return " UNION ALL ".join(sqls), args

    def hll(self, db, host="*"):
        reg = None
        if self.d0 is None:
            q = [("SELECT hll FROM agg_u WHERE t >= ? AND host=?", [self.h0, host])]
        else:
            q = [("SELECT hll FROM agg_u WHERE t >= ? AND t < ? AND host=?", [self.h0, self.d0, host]),
                 ("SELECT hll FROM agg_u WHERE t >= ? AND t < ? AND host=?", [self.d0, self.d1, "d:" + host]),
                 ("SELECT hll FROM agg_u WHERE t >= ? AND host=?", [self.d1, host])]
        for sql, a in q:
            for (b,) in db.execute(sql, a):
                reg = hll_merge(reg, b)
        return reg

    def lat(self, db, host=None):
        tot = [0] * len(LAT_EDGES)
        if self.d0 is None:
            q = [("t >= ?", [self.h0], False)]
        else:
            q = [("t >= ? AND t < ?", [self.h0, self.d0], False), ("t >= ? AND t < ?", [self.d0, self.d1], True),
                 ("t >= ?", [self.d1], False)]
        for w, a, daily in q:
            if host:
                hw, ha = " AND host=?", [("d:" if daily else "") + host]
            else:
                hw, ha = (" AND host LIKE 'd:%'", []) if daily else (" AND host NOT LIKE 'd:%'", [])
            for (h,) in db.execute("SELECT h FROM agg_lat WHERE " + w + hw, a + ha):
                for i, n in enumerate(json.loads(h)):
                    if i < len(tot):
                        tot[i] += n
        return tot


def _hw(q):
    """(host condition, args) for agg_* tables."""
    return (" AND host=?", [q["host"]]) if q.get("host") else ("", [])


def top(db, sp, dim, q, n=15, order="c", cond="", cols="sum(c) c, sum(b) b", group_host=False):
    """Top keys of a dimension over the range (all tiers)."""
    hw, ha = _hw(q)
    inner, args = sp.union("*", dim, cond + hw, ha)
    grp = "k, host" if group_host else "k"
    return rows_of(db.execute("SELECT k%s, %s FROM (%s) GROUP BY %s ORDER BY %s DESC LIMIT %d"
                              % (", host" if group_host else "", cols, inner, grp, order, n), args))


def u_of(db, sp, dim, keys, q):
    """Unique clients per key (from the per-key HyperLogLogs of low-cardinality dimensions)."""
    if dim not in U_DIMS or not keys:
        return {}
    hw, ha = _hw(q)
    out = {}
    for k in keys:
        inner, args = sp.union("u", dim, " AND k=? AND u IS NOT NULL" + hw, [k] + ha)
        reg = None
        for (b,) in db.execute(inner, args):
            reg = hll_merge(reg, b)
        out[k] = hll_count(reg)
    return out


def merged_hll(db, t0, t1=None, host=None):
    """Hourly HyperLogLogs merged (used by the public feed for hosts)."""
    sp = Span(db, t0)
    return sp.hll(db, host or "*")


def lat_hist(db, t0, host=None):
    return Span(db, t0).lat(db, host)


def ui_hist(hist):
    """The dashboard's 11 latency buckets from the fine histogram."""
    out = [0] * len(UI_EDGES)
    for i, c in enumerate(hist):
        e = LAT_EDGES[i]
        out[next(j for j, u in enumerate(UI_EDGES) if e <= u)] += c
    return [{"k": i, "c": c} for i, c in enumerate(out) if c]


def series(db, since, span, b, q):
    """Bucketed series like core.filled_series: minutes (agg_m) below an hour, hours (agg_h host rows) below a day,
    days (agg_d) otherwise."""
    hw, ha = _hw(q)
    start = int(since // b * b)
    names = ("reqs", "bytes", "e4", "e5", "uniq", "bots", "saved", "sus")
    pts = collections.defaultdict(lambda: [0] * 8)
    host = q.get("host") or "*"
    if b < 3600:
        src = [("SELECT t, c, b, e4, e5, bots, saved, sus FROM agg_m WHERE t >= ?" + hw, [start] + ha)]
    elif b < 86400:
        src = [("SELECT t, c, b, e4, e5, bots, saved, sus FROM agg_h WHERE dim='host' AND t >= ?" + hw, [hour(start)] + ha)]
    else:
        start = day_start(since)
        sp = Span(db, since)
        src = []
        for table, w, a in sp.parts():
            src.append(("SELECT t, c, b, e4, e5, bots, saved, sus FROM %s WHERE dim='host' AND %s%s" % (table, w, hw), a + ha))
    for sql, a in src:
        for t, c, by, e4, e5, bots, saved, sus in db.execute(sql, a):
            k = day_start(t) if b >= 86400 else t // b * b
            v = pts[k]
            v[0] += c; v[1] += by; v[2] += e4; v[3] += e5; v[5] += bots; v[6] += saved; v[7] += sus
    if b >= 3600:
        regs = collections.defaultdict(lambda: None)
        for t, h, hs in db.execute("SELECT t, hll, host FROM agg_u WHERE t >= ? AND host IN (?, ?)",
                                   [hour(start), host, "d:" + host]):
            daily = hs.startswith("d:")
            if b >= 86400:  # a union is idempotent: a day's own sketch and its hours may both be merged in
                k = day_start(t)
                regs[k] = hll_merge(regs[k], h)
            elif not daily:
                regs[t // b * b] = hll_merge(regs[t // b * b], h)
        for k, reg in regs.items():
            pts[k][4] = hll_count(reg)
    out = {"t0": start, "step": b}
    for n in names:
        out[n] = []
    ts = []
    t = start
    while t <= time.time():
        ts.append(t)
        t = next_day(t) if b >= 86400 else t + b
    for t in ts:
        v = pts.get(t) or [0] * 8
        for i, n in enumerate(names):
            out[n].append(v[i] if not (n == "uniq" and b < 3600) else None)
    return out


# ---------------------------------------------------------------- queries on the rollups (cached)

_qc = {}
_qc_lock = threading.Lock()


def cached(fn):
    """Rollup answers change slowly compared with how often the dashboard asks: keep each one for a while
    (15 s for a day, a minute for a week, 3 min beyond), per range and host filter."""
    def wrap(q, rng, span, *a):
        key = (fn.__name__, rng, q.get("host") or "", q.get("nobots") or "")
        ttl = 15 if span <= 86400 else 60 if span <= 7 * 86400 else 180
        with _qc_lock:
            hit = _qc.get(key)
            if hit and time.time() - hit[0] < ttl and q.get("force") != "1":
                return hit[1]
        v = fn(q, rng, span, *a)
        with _qc_lock:
            _qc[key] = (time.time(), v)
            if len(_qc) > 200:
                _qc.clear()
        return v
    wrap.__name__ = fn.__name__
    wrap.__wrapped__ = fn
    return wrap


def _x(r):
    x = json.loads(r.pop("x", None) or "{}") or {}
    return x


@cached
def stats(q, rng, span, b):
    """core.q_stats from the rollups (same shape; per-path / per-client 'u' are unavailable -> None)."""
    since = time.time() - span
    db = connect()
    try:
        sp = Span(db, since)
        hw, ha = _hw(q)
        inner, args = sp.union("*", "host", hw, ha)
        T = rows_of(db.execute(
            "SELECT coalesce(sum(c),0) reqs, coalesce(sum(b),0) bytes, coalesce(sum(e4),0) e4, coalesce(sum(e5),0) e5,"
            " coalesce(sum(sus),0) sus, coalesce(sum(bots),0) bots, coalesce(sum(scan),0) scans,"
            " coalesce(sum(ok),0) ok, coalesce(sum(okb),0) ok_bytes, coalesce(sum(saved),0) saved,"
            " coalesce(sum(enc),0) encoded, coalesce(sum(dur),0) dsum FROM (%s)" % inner, args))[0]
        T["clean"] = T["reqs"] - T["sus"]
        T["avg_dur"] = T.pop("dsum") / T["ok"] if T["ok"] else 0
        T["uniq"] = hll_count(sp.hll(db, q.get("host") or "*"))
        T["paths"] = hll_count(sp.hll(db, "#path"))
        T["sus_ips"] = hll_count(sp.hll(db, "#sus"))
        st = {r["k"]: r for r in top(db, sp, "status", q, 100)}
        T["e4_all"] = sum(r["c"] for k, r in st.items() if k.isdigit() and 400 <= int(k) < 500)
        T["e5_all"] = sum(r["c"] for k, r in st.items() if k.isdigit() and int(k) >= 500)
        hist = sp.lat(db, q.get("host"))
        T.update(p50=percentile(hist, .5), p95=percentile(hist, .95), p99=percentile(hist, .99))

        def withu(dim, rows, key="k"):
            us = u_of(db, sp, dim, [r[key] for r in rows], q)
            for r in rows:
                r["u"] = us.get(r[key])
            return rows
        paths = top(db, sp, "path", q, 40, "c", " AND ok > 0",
                    "sum(ok) c, sum(okb) b, sum(dur)/max(sum(ok),1) d, max(last) last, max(x) x, sum(saved) saved",
                    group_host=True)
        for p in paths:
            p["u"], p["ctype"] = None, _x(p).get("ctype", "")
        heavy = top(db, sp, "path", q, 15, "b", " AND ok > 0", "sum(ok) c, sum(okb) b, max(x) x", group_host=True)
        for p in heavy:
            p["u"], p["ctype"] = None, _x(p).get("ctype", "")
        notfound = top(db, sp, "path", q, 30, "c", " AND nf > 0", "sum(nf) c, max(scan) scan, max(last) last")
        for p in notfound:
            p["u"] = None
        agents = []
        for r in top(db, sp, "agent", q, 30):
            kind, _, agent = r["k"].partition("\x1f")
            agents.append({"kind": kind, "k": agent, "c": r["c"], "b": r["b"], "_k": r["k"]})
        us = u_of(db, sp, "agent", [a["_k"] for a in agents], q)
        for a in agents:
            a["u"] = us.get(a.pop("_k"))
        ipcols = ("sum(c) c, sum(b) b, sum(e4)+sum(e5)+sum(nf) err, sum(scan) scan, sum(sus) sus, max(x) x, "
                  "min(last) first, max(last) last")
        ips = top(db, sp, "ip", q, 30, "c", " AND k != '(other)'", ipcols)
        scanners = top(db, sp, "ip", q, 30, "scan", " AND (scan > 0 OR sus > 0) AND k != '(other)'", ipcols)
        for r in ips + scanners:
            x = _x(r)
            r.update(country=x.get("cc", ""), kind=x.get("kind", ""), agent=x.get("agent", ""),
                     why=x.get("why") or None, sample=x.get("sample"))
        hinner, hargs = sp.union("*", "host", hw, ha)
        hostrows = rows_of(db.execute("SELECT host k, sum(c) c, sum(b) b, sum(dur)/max(sum(ok),1) avg, max(dmax) max "
                                      "FROM (%s) GROUP BY host ORDER BY c DESC" % hinner, hargs))
        slowest = [s for s in top(db, sp, "path", q, 15, "avg", " AND ok > 1",
                                  "sum(ok) c, sum(dur)/max(sum(ok),1) avg, max(dmax) max, sum(okb) b", group_host=True)
                   if s["c"] >= 2]
        res = {
            "range": rng, "engine": "rollup", "totals": T, "series": series(db, since, span, b, q),
            "paths": paths, "heavy": heavy, "notfound": notfound,
            "countries": withu("country", top(db, sp, "country", q, 40)),
            "referrers": withu("ref", top(db, sp, "ref", q, 20, "c", " AND k != '(other)'")),
            "agents": agents, "kinds": withu("kind", top(db, sp, "kind", q, 6)),
            "os": withu("os", top(db, sp, "os", q, 10, "c", " AND k != '-'")),
            "ctypes": withu("ctype", top(db, sp, "ctype", q, 12, "b", " AND k != ''", "sum(ok) c, sum(okb) b")),
            "statuses": [dict(r, k=int(r["k"]) if str(r["k"]).isdigit() else r["k"]) for r in
                         withu("status", top(db, sp, "status", q, 20))],
            "hosts": [dict(k=r["k"], c=r["c"], b=r["b"], u=hll_count(sp.hll(db, r["k"]))) for r in hostrows[:10]],
            "colos": withu("colo", top(db, sp, "colo", q, 20)),
            "methods": withu("method", top(db, sp, "method", q, 8)),
            "encodings": [dict(r, u=None) for r in top(db, sp, "enc", q, 6, "b", "", "sum(ok) c, sum(okb) b")],
            "ips": ips, "scanners": scanners, "latency_hist": ui_hist(hist),
            "latency_hosts": [{"k": r["k"], "c": r["c"], "avg": r["avg"], "max": r["max"]} for r in hostrows],
            "slowest": slowest,
        }
        return res
    finally:
        db.close()


SIZE_LABELS = ["0", "<1 KB", "1–10 KB", "10–100 KB", "0.1–1 MB", "1–10 MB", "10–100 MB", "≥100 MB"]


@cached
def insights(q, rng, span):
    since = time.time() - span
    db = connect()
    try:
        sp = Span(db, since)
        hw, ha = _hw(q)
        heat = collections.defaultdict(lambda: [0, 0])
        byday = collections.defaultdict(lambda: [0, 0, 0])
        hours = []
        # the heat map needs hours: agg_h covers raw_retention_days (beyond that the busiest days stand in)
        for t, c, b, e4, e5 in db.execute("SELECT t, sum(c), sum(b), sum(e4), sum(e5) FROM agg_h WHERE dim='host' AND "
                                          "t >= ?%s GROUP BY t" % hw, [hour(since)] + ha):
            lt = time.localtime(t)
            k = ((lt.tm_wday + 1) % 7, lt.tm_hour)  # strftime('%w'): Sunday = 0
            heat[k][0] += c; heat[k][1] += b
            hours.append((t, c, b))
        inner, args = sp.union("t, c, b, e4, e5", "host", hw, ha)
        for t, c, b, e4, e5 in db.execute(inner, args):
            dk = time.strftime("%Y-%m-%d", time.localtime(t))
            byday[dk][0] += c; byday[dk][1] += b; byday[dk][2] += e4 + e5
        uregs = {}
        host = q.get("host") or "*"
        for t, h in db.execute("SELECT t, hll FROM agg_u WHERE t >= ? AND host IN (?, ?)", [hour(since), host, "d:" + host]):
            dk = time.strftime("%Y-%m-%d", time.localtime(t))
            uregs[dk] = hll_merge(uregs.get(dk), h)
        busiest = sorted(hours, key=lambda x: -x[1])[:8]
        hu = {t: hll_count(h) for t, h in db.execute("SELECT t, hll FROM agg_u WHERE host=? AND t IN (%s)" % (
            ",".join(str(int(x[0])) for x in busiest) or "0"), [host])}
        clients = top(db, sp, "ip", q, 15, "b", " AND k != '(other)'", "sum(c) c, sum(b) b, max(x) x")
        for r in clients:
            x = _x(r)
            r.update(country=x.get("cc", ""), agent=x.get("agent", ""), kind=x.get("kind", ""))
        ret = db.execute("SELECT coalesce(sum(first < ?),0), count(*) FROM visitor WHERE last >= ?", [since, since]).fetchone()
        classes = collections.defaultdict(lambda: [0, 0])
        for r in top(db, sp, "status", q, 200):
            if str(r["k"]).isdigit():
                v = classes[int(r["k"]) // 100]
                v[0] += r["c"]; v[1] += r["b"]
        return {
            "range": rng, "engine": "rollup",
            "heat": [{"d": d, "h": h, "c": v[0], "b": v[1], "u": None} for (d, h), v in heat.items()],
            "sizes": [{"k": int(r["k"]), "c": r["c"], "b": r["b"]} for r in top(db, sp, "size", q, 20)],
            "size_labels": SIZE_LABELS,
            "classes": [{"k": k, "c": v[0], "b": v[1]} for k, v in classes.items()],
            "exts": top(db, sp, "ext", q, 25, "c", " AND ok > 0", "sum(ok) c, sum(okb) b"),
            "cats": top(db, sp, "cat", q, 20, "b", " AND ok > 0", "sum(ok) c, sum(okb) b"),
            "returning": ret[0], "visitors": ret[1],
            "daily": [{"k": k, "c": v[0], "b": v[1], "u": hll_count(uregs.get(k)), "e": v[2]} for k, v in sorted(byday.items())],
            "busiest": [{"t": t, "c": c, "b": b, "u": hu.get(t, 0)} for t, c, b in busiest],
            "clients": clients, "protos": top(db, sp, "proto", q, 10),
            "inventory": get_meta(db, "inventory"),
        }
    finally:
        db.close()


def history():
    """core.q_history from the rollups."""
    end = int(time.time() // 3600 * 3600) + 3600
    start = end - 24 * 3600
    db = connect()
    try:
        req = {r["t"]: r for r in rows_of(db.execute(
            "SELECT t, sum(c) reqs, sum(b) bytes, sum(e4)+sum(e5) err, sum(dur)/max(sum(ok),1) dur, sum(bots) bots, "
            "sum(saved) saved FROM agg_h WHERE dim='host' AND t >= ? GROUP BY t", [start]))}
        uq = {t: hll_count(h) for t, h in db.execute("SELECT t, hll FROM agg_u WHERE host='*' AND t >= ?", [start])}
        met = collections.defaultdict(dict)
        for k, t, v in db.execute("SELECT key, CAST(ts/3600 AS INTEGER)*3600 t, avg(val) FROM metric WHERE ts >= ? "
                                  "GROUP BY key, t", [start]):
            met[k][t] = v
        hours = list(range(start, end, 3600))
        col = lambda k: [(req.get(h) or {}).get(k) or 0 for h in hours]
        mcol = lambda k: [met[k].get(h) for h in hours]
        return {"hours": hours, "reqs": col("reqs"), "bytes": col("bytes"), "uniq": [uq.get(h, 0) for h in hours],
                "err": col("err"), "dur": col("dur"), "bots": col("bots"), "saved": col("saved"), "engine": "rollup",
                "caddy_cpu": mcol("caddy_cpu"), "tunnel_rtt": mcol("tunnel_rtt"), "nas_ms": mcol("nas_ms"),
                "host_cpu": mcol("host_cpu"), "tunnel_tx": mcol("tunnel_tx")}
    finally:
        db.close()


# ---------------------------------------------------------------- per-file hits (Files, Analyze, purges)

_ph = {}          # days -> (ts, map)
_ph_lock = threading.Lock()
_ph_busy = set()


def _load_hits(days):
    db = connect()
    try:
        out = {}
        for path, c, b, last in db.execute("SELECT path, sum(c), sum(b), max(last) FROM agg_pd WHERE d >= ? "
                                           "GROUP BY path", [day(time.time() - days * 86400)]):
            out[path] = [c, b or 0, last or 0]
        return out
    finally:
        db.close()


def path_hits(days=30):
    """decoded url path -> [requests, bytes, last] over `days` local days (all hosts). Served from memory and
    refreshed in the background (stale-while-revalidate, 5 min), so a request never waits for the full scan -
    except the very first one."""
    with _ph_lock:
        hit = _ph.get(days)
    if hit is None:
        v = _load_hits(days)
        with _ph_lock:
            _ph[days] = (time.time(), v)
        return v
    if time.time() - hit[0] > 300:
        refresh_hits_async(days)
    return hit[1]


def refresh_hits_async(days=None):
    for d in ([days] if days else list(_ph)):
        with _ph_lock:
            if d in _ph_busy:
                continue
            _ph_busy.add(d)

        def run(d=d):
            try:
                v = _load_hits(d)
                with _ph_lock:
                    _ph[d] = (time.time(), v)
            except Exception:
                log("path hits refresh failed:\n" + traceback.format_exc())
            finally:
                with _ph_lock:
                    _ph_busy.discard(d)
        threading.Thread(target=run, name="path-hits", daemon=True).start()


def path_hits_prefix(prefix, days=30):
    """Like path_hits, for one folder's subtree only (index range on agg_pd(path, d)): exact and current."""
    db = connect()
    try:
        out = {}
        for path, c, b, last in db.execute(
                "SELECT path, sum(c), sum(b), max(last) FROM agg_pd WHERE path >= ? AND path < ? AND d >= ? GROUP BY path",
                [prefix, prefix + "\U0010ffff", day(time.time() - days * 86400)]):
            out[path] = [c, b or 0, last or 0]
        return out
    finally:
        db.close()


def path_hits_children(prefix, days=30):
    """Aggregate recent path traffic by immediate child of a folder, without materializing every descendant."""
    db = connect()
    try:
        rows = db.execute(
            "SELECT CASE WHEN instr(suffix, '/') > 0 THEN substr(suffix, 1, instr(suffix, '/') - 1) ELSE suffix END child, "
            "sum(c), sum(b), max(last) FROM (SELECT substr(path, ? + 1) suffix, c, b, last FROM agg_pd "
            "WHERE path >= ? AND path < ? AND d >= ?) WHERE suffix != '' GROUP BY child",
            [len(prefix), prefix, prefix + "\U0010ffff", day(time.time() - days * 86400)]).fetchall()
        return {name: [c or 0, b or 0, last or 0] for name, c, b, last in rows}
    finally:
        db.close()


def path_daily(paths, days=30):
    """[{d: 'YYYY-MM-DD', c, b}] for the given decoded paths (one file, any host)."""
    db = connect()
    try:
        rows = db.execute("SELECT d, sum(c), sum(b) FROM agg_pd WHERE path IN (%s) AND d >= ? GROUP BY d ORDER BY d"
                          % ",".join("?" * len(paths)), list(paths) + [day(time.time() - days * 86400)]).fetchall()
    finally:
        db.close()
    return [{"d": "%s-%s-%s" % (str(d)[:4], str(d)[4:6], str(d)[6:]), "c": c, "b": b} for d, c, b in rows]


def seen_paths():
    """{(host, decoded path)} that were ever served successfully (Cloudflare can only cache what reached us)."""
    db = connect()
    try:
        return db.execute("SELECT DISTINCT host, path FROM agg_pd").fetchall()
    finally:
        db.close()
