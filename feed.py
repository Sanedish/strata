"""Redacted statistics feed for Strata Telemetry - served on feed_listen (loopback only), behind a bearer token.

The feed is *built* from aggregate SQL, it is never a filtered copy of raw rows:
  * no query here selects ip, ua, ref, or a full path - so none of them can leak by omission
  * every string that does go out comes from a fixed vocabulary (country code, browser family, file
    category, threat category) or passes a strict pattern (single folder name, 3-letter edge code)
  * countries, edge locations and folders are only named when >= k distinct visitors were seen
  * requests from the LAN / direct to Caddy and to hosts outside `public.hosts` are not counted at all
Strata Telemetry then re-validates everything it receives against its own schema (defence in depth).
"""
import collections
import hmac
import json
import os
import re
import secrets
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import core
import instance
from auth import token_hash
from core import CFG, connect, log, rows_of

SEG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$")
EXT_RE = re.compile(r"^[a-z0-9]{1,8}$")
CC_RE = re.compile(r"^[A-Z]{2}$")
COLO_RE = re.compile(r"^[A-Z]{3}$")
AGENT_RE = re.compile(r"^[A-Za-z][A-Za-z .-]{0,30}$")
OSES = {"Windows", "Android", "iOS", "macOS", "ChromeOS", "Linux"}
KINDS = {"browser": "people", "player": "players", "embed": "previews", "bot": "bots"}
THREATS = [
    ("WordPress", r"wp-|wordpress|xmlrpc"),
    ("Secrets & config files", r"\.env|\.git|/config\.|\.ya?ml|\.ini|\.conf|\.bak|\.sql|\.old|\.swp|ds_store|\.log"),
    ("PHP & framework exploits", r"\.php|phpmyadmin|pma/|eval-stdin|xdebug|_ignition|telescope|/vendor/"),
    ("Admin panels & logins", r"/admin|/login|/console|/manager/|/setup|/jenkins|/druid|/solr|/actuator|/geoserver"),
    ("Router & IoT exploits", r"boaform|hnap1|cgi-bin|/sdk$|/evox|/remote/|/cf_scripts|\.cgi"),
    ("Mail server probes", r"/owa/|/ecp/|autodiscover"),
    ("Path traversal", r"\.\./|%2e%2e"),
]
THREAT_RES = [(n, re.compile(p, re.I)) for n, p in THREATS]
FEED_RANGES = {"24h": (86400, 900), "7d": (604800, 3600), "30d": (2592000, 21600)}


def threat_category(path):
    for name, rx in THREAT_RES:
        if rx.search(path or ""):
            return name
    return "Other probes"


def k_fold(rows, key, k, label="other"):
    """Keep rows with >= k distinct visitors; fold the rest into one anonymous bucket."""
    kept, rest = [], {"k": label, "c": 0, "b": 0, "u": 0}
    for r in rows:
        if r["u"] >= k and r[key] is not None:
            kept.append(r)
        else:
            rest["c"] += r["c"]; rest["b"] += r.get("b") or 0; rest["u"] += r["u"]
    if rest["c"]:
        kept.append(rest)
    return kept


def merge(rows):
    out = {}
    for r in rows:
        o = out.setdefault(r["k"], {"k": r["k"], "c": 0, "b": 0, "u": 0})
        o["c"] += r["c"]; o["b"] += r.get("b") or 0; o["u"] += r.get("u") or 0
    return sorted(out.values(), key=lambda r: (r["k"] == "other", -r["c"]))


def pub_where(span):
    hosts = [h.lower() for h in CFG["public"]["hosts"]]
    w = "ts >= ? AND colo != 'LAN' AND host IN (%s)" % ",".join("?" * len(hosts))
    return w, [time.time() - span] + hosts


def build_stats(rng, snap):
    span, b = FEED_RANGES[rng]
    import rollup
    db = connect()
    try:
        big = rollup.use_rollups(db, {}, time.time() - span, span)
    finally:
        db.close()
    if big:
        return build_stats_rollup(rng, snap, span, b)
    where, args = pub_where(span)
    K = max(1, int(CFG["public"]["k_anon"]))
    hide = {p.lower() for p in CFG["public"]["hide_prefixes"]}
    db = connect()
    try:
        x = lambda sql, extra=(): rows_of(db.execute(sql, args + list(extra)))
        # errors (e4 / e5 / series.errors / classes) leave suspicious traffic out: probes, blacklisted addresses,
        # flagged scanner clients, fake crawlers, internal tests; `clean` is their denominator, `suspicious` the rest
        t = x("""SELECT count(*) reqs, coalesce(sum(bytes),0) bytes, count(DISTINCT ip) visitors,
                 coalesce(sum(status>=400 AND status<500 AND {c}),0) e4, coalesce(sum(status>=500 AND {c}),0) e5,
                 coalesce(sum({c}),0) clean, coalesce(sum(NOT {c}),0) suspicious,""".replace("{c}", core.CLEAN) + """
                 coalesce(sum(kind='bot'),0) bots, coalesce(sum(scan),0) probes, coalesce(sum(saved),0) saved,
                 coalesce(sum(enc != '' AND enc IS NOT NULL),0) encoded FROM req WHERE """ + where)[0]
        t.update(core.percentiles(db, where, args))
        series = core.filled_series(db, where, args, span, b, [
            ("reqs", "count(*)"), ("bytes", "sum(bytes)"), ("visitors", "count(DISTINCT ip)"),
            ("errors", "sum(status>=400 AND %s)" % core.CLEAN), ("saved", "sum(saved)")])
        countries = k_fold(x("SELECT country k, count(*) c, sum(bytes) b, count(DISTINCT ip) u FROM req WHERE %s "
                             "GROUP BY k ORDER BY c DESC" % where), "k", K)
        countries = merge([dict(r, k=r["k"] if CC_RE.match(r["k"] or "") else "other") for r in countries])
        colos = k_fold(x("SELECT colo k, count(*) c, sum(bytes) b, count(DISTINCT ip) u FROM req WHERE %s "
                         "GROUP BY k ORDER BY c DESC" % where), "k", K)
        colos = merge([dict(r, k=r["k"] if COLO_RE.match(r["k"] or "") else "other") for r in colos])
        kinds = {KINDS.get(r["k"], "bots"): r["c"] for r in x(
            "SELECT kind k, count(*) c FROM req WHERE %s GROUP BY k" % where)}
        agents = collections.Counter()
        for r in x("SELECT kind, agent, count(*) c FROM req WHERE %s GROUP BY kind, agent" % where):
            name = r["agent"] if r["kind"] in ("browser", "player", "embed") and AGENT_RE.match(r["agent"] or "") \
                else "Bots & tools"
            agents[name] += r["c"]
        oses = collections.Counter()
        for r in x("SELECT os, count(*) c FROM req WHERE %s GROUP BY os" % where):
            if r["os"] in OSES:
                oses[r["os"]] += r["c"]
        classes = {str(r["k"]) + "xx": r["c"] for r in x(
            "SELECT status/100 k, count(*) c FROM req WHERE %s AND %s GROUP BY k" % (where, core.CLEAN))
            if 1 <= (r["k"] or 0) <= 5}
        # content: file category + extension of successful requests, and the top-level folder ("collection")
        cats, exts = collections.defaultdict(lambda: [0, 0]), collections.defaultdict(lambda: [0, 0])
        coll = collections.defaultdict(lambda: {"c": 0, "b": 0, "ips": set()})
        for path, ip, c, bb in db.execute("SELECT path, ip, count(*), sum(bytes) FROM req WHERE %s AND status<400 "
                                          "GROUP BY path, ip" % where, args):
            p = urllib.parse.unquote(path or "")
            e = core.ext_of(p)
            cat = core.category(p) if e else "pages"
            cats[cat][0] += c; cats[cat][1] += bb or 0
            ek = e if EXT_RE.match(e or "") else ("—" if not e else "other")
            exts[ek][0] += c; exts[ek][1] += bb or 0
            segs = [s for s in p.split("/") if s]
            name = segs[0] if len(segs) >= 2 else "(root)"
            if name != "(root)" and (not SEG_RE.match(name) or name.lower() in hide):
                name = "other"
            g = coll[name]
            g["c"] += c; g["b"] += bb or 0; g["ips"].add(ip)  # ips never leave this function - only len()
        collections_ = k_fold(sorted(({"k": k, "c": v["c"], "b": v["b"], "u": len(v["ips"])} for k, v in coll.items()),
                                     key=lambda r: -r["c"]), "k", K)
        threats = collections.Counter()
        for path, c in db.execute("SELECT path, count(*) FROM req WHERE %s AND scan=1 GROUP BY path" % where, args):
            threats[threat_category(path)] += c
        scanners = db.execute("SELECT count(DISTINCT ip) FROM req WHERE %s AND scan=1" % where, args).fetchone()[0]
        lat = {r["k"]: r["c"] for r in x(
            """SELECT CASE WHEN dur<1 THEN 0 WHEN dur<5 THEN 1 WHEN dur<10 THEN 2 WHEN dur<25 THEN 3
               WHEN dur<50 THEN 4 WHEN dur<100 THEN 5 WHEN dur<250 THEN 6 WHEN dur<500 THEN 7
               WHEN dur<1000 THEN 8 WHEN dur<2500 THEN 9 ELSE 10 END k, count(*) c FROM req WHERE %s GROUP BY k"""
            % where)}
        heat = [[0] * 24 for _ in range(7)]
        for r in x("""SELECT CAST(strftime('%%w', ts, 'unixepoch', 'localtime') AS INTEGER) d,
                      CAST(strftime('%%H', ts, 'unixepoch', 'localtime') AS INTEGER) h, count(*) c FROM req
                      WHERE %s GROUP BY d, h""" % where):
            heat[r["d"]][r["h"]] = r["c"]
        enc = {(r["k"] or "identity"): {"c": r["c"], "b": r["b"], "saved": r["s"]} for r in x(
            """SELECT CASE WHEN enc IS NULL OR enc='' THEN 'identity' ELSE enc END k, count(*) c, sum(bytes) b,
               sum(saved) s FROM req WHERE %s AND status<400 GROUP BY k""" % where) if r["k"] in (
            "identity", "br", "zstd", "gzip")}
        store = {r["k"]: {"files": r["files"], "orig": r["orig"], "size": r["size"]} for r in rows_of(db.execute(
            "SELECT variant k, count(*) files, sum(orig) orig, sum(size) size FROM cfile WHERE size IS NOT NULL "
            "GROUP BY variant")) if r["k"] in ("br", "zstd", "gzip")}
        inv = core.get_meta(db, "inventory") or {}
        uptime = {k: core.uptime(db, k, time.time() - span) for k in ("caddy_up", "tunnel_up", "origins_up")}
        first = db.execute("SELECT min(ts) FROM metric").fetchone()[0]
    finally:
        db.close()
    return {
        "range": rng, "generated": time.time(), "k_anon": K,
        "totals": {k: t[k] for k in ("reqs", "bytes", "visitors", "e4", "e5", "clean", "suspicious", "bots", "probes",
                                     "saved", "encoded", "p50", "p95", "p99")},
        "series": series,
        "countries": [{"k": r["k"], "c": r["c"], "b": r["b"], "u": r["u"]} for r in countries][:30],
        "colos": [{"k": r["k"], "c": r["c"]} for r in colos][:20],
        "kinds": {v: kinds.get(v, 0) for v in KINDS.values()},
        "agents": [{"k": k, "c": c} for k, c in agents.most_common(12)],
        "os": [{"k": k, "c": c} for k, c in oses.most_common()],
        "classes": classes,
        "categories": sorted(({"k": k, "c": v[0], "b": v[1]} for k, v in cats.items()), key=lambda r: -r["b"]),
        "extensions": sorted(({"k": k, "c": v[0], "b": v[1]} for k, v in exts.items()), key=lambda r: -r["c"])[:15],
        "collections": [{"k": r["k"], "c": r["c"], "b": r["b"]} for r in collections_][:15],
        "threats": [{"k": k, "c": c} for k, c in threats.most_common()], "scanners": scanners,
        "latency": [lat.get(i, 0) for i in range(11)],
        "heat": heat,
        "encodings": enc,
        "precompressed": store,
        "inventory": {"files": inv.get("files"), "bytes": inv.get("bytes"), "variants": inv.get("variants"),
                      "variant_bytes": inv.get("variant_bytes"),
                      "cats": [{"k": c["k"], "c": c["c"], "b": c["b"]} for c in inv.get("cats", [])
                               if c["k"] in core.CATEGORIES or c["k"] == "other"]},
        "uptime": uptime, "monitoring_since": first,
        "edge": edge_summary(),
        "live": build_live(snap),
    }


def build_stats_rollup(rng, snap, span, b):
    """build_stats from the rollups (rollup.py) once raw scans get too big. Same shape and the same anonymity rules:
    countries / edge locations are named only with >= k_anon distinct visitors (HyperLogLog per key); top-level
    folders, whose visitors are not counted per key, need max(50, 10 x k_anon) requests instead. LAN requests are
    subtracted through the edge-location dimension (colo 'LAN')."""
    import rollup
    K = max(1, int(CFG["public"]["k_anon"]))
    hide = {p.lower() for p in CFG["public"]["hide_prefixes"]}
    hosts = [h.lower() for h in CFG["public"]["hosts"]]
    since = time.time() - span
    hw = " AND host IN (%s)" % ",".join("?" * len(hosts)) if hosts else " AND 0"
    db = connect()
    try:
        sp = rollup.Span(db, since)

        def dim(d, cols="sum(c) c, sum(b) b", extra=""):
            inner, args = sp.union("*", d, hw + extra, hosts)
            return rows_of(db.execute("SELECT k, %s FROM (%s) GROUP BY k" % (cols, inner), args))

        def total(d, cols, extra=""):
            inner, args = sp.union("*", d, hw + extra, hosts)
            return rows_of(db.execute("SELECT %s FROM (%s)" % (cols, inner), args))[0]
        tot = total("host", "coalesce(sum(c),0) reqs, coalesce(sum(b),0) bytes, coalesce(sum(e4),0) e4, "
                            "coalesce(sum(e5),0) e5, coalesce(sum(sus),0) suspicious, coalesce(sum(bots),0) bots, "
                            "coalesce(sum(scan),0) probes, coalesce(sum(saved),0) saved, coalesce(sum(enc),0) encoded")
        lan = total("colo", "coalesce(sum(c),0) c, coalesce(sum(b),0) b, coalesce(sum(e4),0) e4, coalesce(sum(e5),0) e5, "
                            "coalesce(sum(sus),0) sus", " AND k='LAN'")
        tot["reqs"] -= lan["c"]; tot["bytes"] -= lan["b"]; tot["e4"] -= lan["e4"]; tot["e5"] -= lan["e5"]
        tot["suspicious"] -= lan["sus"]
        tot["clean"] = tot["reqs"] - tot["suspicious"]
        reg = None
        for h in hosts:
            reg = rollup.hll_merge(reg, sp.hll(db, h))
        tot["visitors"] = rollup.hll_count(reg)
        hist = [0] * len(core.LAT_EDGES)
        for h in hosts:
            for i, n in enumerate(sp.lat(db, h)):
                hist[i] += n
        tot.update(p50=core.hist_percentile(hist, .5), p95=core.hist_percentile(hist, .95),
                   p99=core.hist_percentile(hist, .99))
        s = rollup.series(db, since, span, b, {})
        series = {"t0": s["t0"], "step": s["step"], "reqs": s["reqs"], "bytes": s["bytes"],
                  "visitors": [v or 0 for v in s["uniq"]], "errors": [a + c for a, c in zip(s["e4"], s["e5"])],
                  "saved": s["saved"]}

        def with_u(d, rows):
            us = rollup.u_of(db, sp, d, [r["k"] for r in rows], {})
            return [dict(r, u=us.get(r["k"], 0)) for r in rows]
        countries = merge([dict(r, k=r["k"] if CC_RE.match(r["k"] or "") else "other") for r in k_fold(
            sorted(with_u("country", dim("country")), key=lambda r: -r["c"]), "k", K)])
        colos = merge([dict(r, k=r["k"] if COLO_RE.match(r["k"] or "") else "other") for r in k_fold(
            sorted(with_u("colo", dim("colo", extra=" AND k != 'LAN'")), key=lambda r: -r["c"]), "k", K)])
        kinds = {KINDS.get(r["k"], "bots"): r["c"] for r in dim("kind")}
        agents = collections.Counter()
        for r in dim("agent"):
            kind, _, agent = r["k"].partition("\x1f")
            name = agent if kind in ("browser", "player", "embed") and AGENT_RE.match(agent or "") else "Bots & tools"
            agents[name] += r["c"]
        oses = collections.Counter({r["k"]: r["c"] for r in dim("os") if r["k"] in OSES})
        classes = collections.Counter()
        for r in dim("status", "sum(c) - sum(sus) c"):
            if str(r["k"]).isdigit() and 1 <= int(r["k"]) // 100 <= 5:
                classes["%dxx" % (int(r["k"]) // 100)] += r["c"]
        cats = {r["k"] if r["k"] != "page" else "pages": [r["c"], r["b"]]
                for r in dim("cat", "sum(ok) c, sum(okb) b", " AND ok > 0")}
        exts = collections.defaultdict(lambda: [0, 0])
        for r in dim("ext", "sum(ok) c, sum(okb) b", " AND ok > 0"):
            e = r["k"] if r["k"] not in ("(folder)", "(none)") else ""
            ek = e if EXT_RE.match(e or "") else ("—" if not e else "other")
            exts[ek][0] += r["c"]; exts[ek][1] += r["b"]
        coll = collections.defaultdict(lambda: [0, 0])
        for r in dim("path", "sum(ok) c, sum(okb) b", " AND ok > 0 AND k != '(other)'"):
            segs = [x for x in urllib.parse.unquote(r["k"] or "").split("/") if x]
            name = segs[0] if len(segs) >= 2 else "(root)"
            if name != "(root)" and (not SEG_RE.match(name) or name.lower() in hide):
                name = "other"
            coll[name][0] += r["c"]; coll[name][1] += r["b"]
        need = max(50, 10 * K)
        collections_, rest = [], [0, 0]
        for k, v in sorted(coll.items(), key=lambda kv: -kv[1][0]):
            if v[0] >= need or k == "(root)":
                collections_.append({"k": k, "c": v[0], "b": v[1]})
            else:
                rest[0] += v[0]; rest[1] += v[1]
        if rest[0]:
            collections_.append({"k": "other", "c": rest[0], "b": rest[1]})
        threats = collections.Counter()
        for r in dim("path", "sum(scan) c", " AND scan > 0"):
            threats[threat_category(r["k"])] += r["c"]
        scanners = len(dim("ip", "sum(scan) c", " AND scan > 0 AND k != '(other)'"))
        lat = {r["k"]: r["c"] for r in rollup.ui_hist(hist)}
        heat = [[0] * 24 for _ in range(7)]
        for t, c in db.execute("SELECT t, sum(c) FROM agg_h WHERE dim='host' AND t >= ?%s GROUP BY t" % hw,
                               [rollup.hour(since)] + hosts):
            lt = time.localtime(t)
            heat[(lt.tm_wday + 1) % 7][lt.tm_hour] += c
        enc = {r["k"]: {"c": r["c"], "b": r["b"], "saved": r["s"]} for r in dim(
            "enc", "sum(ok) c, sum(okb) b, sum(saved) s", " AND ok > 0") if r["k"] in ("identity", "br", "zstd", "gzip")}
        store = {r["k"]: {"files": r["files"], "orig": r["orig"], "size": r["size"]} for r in rows_of(db.execute(
            "SELECT variant k, count(*) files, sum(orig) orig, sum(size) size FROM cfile WHERE size IS NOT NULL "
            "GROUP BY variant")) if r["k"] in ("br", "zstd", "gzip")}
        inv = core.get_meta(db, "inventory") or {}
        uptime = {k: core.uptime(db, k, since) for k in ("caddy_up", "tunnel_up", "origins_up")}
        first = db.execute("SELECT min(ts) FROM metric").fetchone()[0]
    finally:
        db.close()
    return {
        "range": rng, "generated": time.time(), "k_anon": K,
        "totals": {k: tot[k] for k in ("reqs", "bytes", "visitors", "e4", "e5", "clean", "suspicious", "bots", "probes",
                                       "saved", "encoded", "p50", "p95", "p99")},
        "series": series,
        "countries": [{"k": r["k"], "c": r["c"], "b": r["b"], "u": r["u"]} for r in countries][:30],
        "colos": [{"k": r["k"], "c": r["c"]} for r in colos][:20],
        "kinds": {v: kinds.get(v, 0) for v in KINDS.values()},
        "agents": [{"k": k, "c": c} for k, c in agents.most_common(12)],
        "os": [{"k": k, "c": c} for k, c in oses.most_common()],
        "classes": dict(classes),
        "categories": sorted(({"k": k, "c": v[0], "b": v[1]} for k, v in cats.items()), key=lambda r: -r["b"]),
        "extensions": sorted(({"k": k, "c": v[0], "b": v[1]} for k, v in exts.items()), key=lambda r: -r["c"])[:15],
        "collections": collections_[:15],
        "threats": [{"k": k, "c": c} for k, c in threats.most_common()], "scanners": scanners,
        "latency": [lat.get(i, 0) for i in range(11)],
        "heat": heat, "encodings": enc, "precompressed": store,
        "inventory": {"files": inv.get("files"), "bytes": inv.get("bytes"), "variants": inv.get("variants"),
                      "variant_bytes": inv.get("variant_bytes"),
                      "cats": [{"k": c["k"], "c": c["c"], "b": c["b"]} for c in inv.get("cats", [])
                               if c["k"] in core.CATEGORIES or c["k"] == "other"]},
        "uptime": uptime, "monitoring_since": first, "edge": edge_summary(), "live": build_live(snap),
    }


def build_live(snap):
    live, metrics, probes = snap
    m, p = metrics.snapshot(), probes.snapshot()
    w, w5 = live.window(60), live.window(300)
    public = {h.lower() for h in CFG["public"]["hosts"]}
    probed = [o for o in p["origins"] if o.get("ok") is not None]
    sites = [{"k": o["hostname"], "ok": bool(o["ok"]), "ms": round(o["ms"] or 0, 1)}
             for o in probed if o["hostname"].lower() in public]
    storage = p["storage"][0] if p["storage"] else {}
    t = m["tunnel"]
    return {
        "generated": time.time(),
        "rps": round(w["rps"], 2), "bps": round(w["bps"]), "visitors_5m": w5["uniq"],
        "caddy": bool(m["caddy"].get("up")),
        "tunnel": bool(t.get("up")) and (t.get("ha") or 0) > 0,
        "tunnel_connections": int(t.get("ha") or 0),
        "tunnel_rtt": round(t["rtt"], 1) if t.get("rtt") else None,
        "sites": sites,
        "services_up": sum(1 for o in probed if o["ok"]), "services_total": len(probed),
        "storage_online": bool(storage.get("ok")),
        "storage_used_pct": round(storage["used"] / storage["total"] * 100, 1) if storage.get("total") else None,
    }


def edge_summary():
    try:
        e = core.q_edge({})  # shares the admin's 5-minute cache, so at most one Cloudflare call per 5 minutes
    except Exception:
        return None
    if not e or not e.get("ok"):
        return None
    hours = e.get("hours") or []
    s = lambda f: sum((h.get("sum") or {}).get(f) or 0 for h in hours)
    countries = collections.Counter()
    for h in hours:
        for c in (h.get("sum") or {}).get("countryMap") or []:
            if CC_RE.match(c.get("clientCountryName") or ""):
                countries[c["clientCountryName"]] += c.get("requests") or 0
    return {
        "requests": s("requests"), "cached": s("cachedRequests"), "bytes": s("bytes"),
        "cached_bytes": s("cachedBytes"), "threats": s("threats"),
        "hours": [{"t": h["dimensions"]["datetime"], "r": h["sum"]["requests"], "c": h["sum"]["cachedRequests"]}
                  for h in hours if re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$", h["dimensions"]["datetime"])],
        "days": [{"d": d["dimensions"]["date"], "r": d["sum"]["requests"], "c": d["sum"]["cachedRequests"],
                  "b": d["sum"]["bytes"]} for d in e.get("days") or []
                 if re.match(r"^\d{4}-\d\d-\d\d$", d["dimensions"]["date"])],
        "countries": [{"k": k, "c": c} for k, c in countries.most_common(15)],
        "fetched": e.get("fetched"),
    }


# ---------------------------------------------------------------- token + server

TELEMETRY_CONFIG = os.path.join(core.HOME, "telemetry", "telemetry.json")


def ensure_token():
    """Generate the feed token on first start: token and its hash -> data/.env (STRATA_FEED_TOKEN,
    STRATA_FEED_TOKEN_HASH); telemetry/telemetry.json keeps only the feed address. A token left in telemetry.json by
    an older Strata moves to data/.env."""
    tele = {}
    if os.path.exists(TELEMETRY_CONFIG):
        with open(TELEMETRY_CONFIG, encoding="utf-8-sig") as f:
            tele = json.load(f)
    old = tele.pop("feed_token", None)
    tok = instance.env_get(instance.FEED_TOKEN)[0] or old
    if tok and CFG.get("feed_token_hash") and hmac.compare_digest(token_hash(tok), CFG["feed_token_hash"]):
        if old:  # move it out of telemetry.json
            instance.env_write({instance.FEED_TOKEN: tok})
            _write_tele(tele)
        return
    tok = secrets.token_urlsafe(32)
    instance.env_write({instance.FEED_TOKEN: tok})
    tele.update(feed_url="http://%s" % CFG["feed_listen"])
    tele.setdefault("listen", "127.0.0.1:8082")
    _write_tele(tele)
    core.save_config({"feed_token_hash": token_hash(tok)})
    log("feed: generated a new telemetry token (stored in data/.env)")


def _write_tele(tele):
    os.makedirs(os.path.dirname(TELEMETRY_CONFIG), exist_ok=True)
    tmp = TELEMETRY_CONFIG + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(tele, f, indent=2)
    os.replace(tmp, TELEMETRY_CONFIG)


class Cache:
    def __init__(self):
        self.lock = threading.Lock()
        self.v = {}

    def get(self, key, ttl, fn):
        with self.lock:
            hit = self.v.get(key)
            if hit and time.time() - hit[0] < ttl:
                return hit[1]
            val = fn()
            self.v[key] = (time.time(), val)
            return val


class FeedHandler(BaseHTTPRequestHandler):
    server_version = "StrataFeed"
    sys_version = ""
    snap = None
    cache = Cache()

    def log_message(self, *a):
        pass

    def deny(self, code):
        time.sleep(0.25)
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        if self.client_address[0] not in ("127.0.0.1", "::1"):
            return self.deny(403)
        auth = self.headers.get("Authorization", "")
        want = CFG.get("feed_token_hash") or ""
        if not (want and auth.startswith("Bearer ") and hmac.compare_digest(token_hash(auth[7:].strip()), want)):
            return self.deny(401)
        u = urllib.parse.urlsplit(self.path)
        q = {k: v[-1] for k, v in urllib.parse.parse_qs(u.query).items()}
        try:
            if u.path == "/feed/stats":
                rng = q.get("range") if q.get("range") in FEED_RANGES else "24h"
                body = self.cache.get("stats:" + rng, 15, lambda: build_stats(rng, self.snap))
            elif u.path == "/feed/live":
                body = self.cache.get("live", 2, lambda: build_live(self.snap))
            else:
                return self.deny(404)
        except Exception:
            log("feed error:\n" + __import__("traceback").format_exc())
            return self.deny(500)
        data = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        self.deny(405)

    do_PUT = do_DELETE = do_PATCH = do_POST


def serve(live, metrics, probes):
    FeedHandler.snap = (live, metrics, probes)
    host, port = CFG["feed_listen"].rsplit(":", 1)
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise SystemExit("feed_listen must be a loopback address")
    srv = ThreadingHTTPServer((host, int(port)), FeedHandler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, name="feed", daemon=True).start()
    log("feed listening on http://%s:%s (loopback only, token required)" % (host, port))
