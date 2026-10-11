"""Cloudflare edge enforcement (optional) - blacklist at the edge and cache purges.

Why it matters: the origin (Caddy) blacklist cannot stop Cloudflare from answering a banned visitor from its
cache. Pushing the list to the edge closes that gap. Free plan budget used here: 1 IP list (<= 10,000 items)
and at most 2 of the 5 WAF custom rules; both are identified by a fixed `ref`, other rules are never touched.

Token permissions needed on top of Zone:Read + Analytics:Read:
    Account > Account Filter Lists > Edit      (the IP list)
    Zone    > Zone WAF             > Edit      (the custom rules)
    Zone    > Cache Purge          > Purge     (purging renamed / deleted / newly protected files)
"""
import json
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

import core
import rules
from core import CFG, connect, get_meta, log, set_meta

API = "https://api.cloudflare.com/client/v4"
LIST_NAME = core.prefixed("blacklist")   # account-level: every instance needs its own list
REF_BLOCK = core.prefixed("blacklist_block")
REF_CHALLENGE = core.prefixed("blacklist_challenge")
PHASE = "http_request_firewall_custom"
CACHE_PHASE = "http_request_cache_settings"
REF_PREVIEWS = core.prefixed("previews_nocache")
PERMS = {
    "lists": "Account › Account Filter Lists › Edit",
    "waf": "Zone › Zone WAF › Edit",
    "purge": "Zone › Cache Purge › Purge",
    "cache_rules": "Zone › Cache Rules › Edit",
}
EDGE_AGENT = {
    "bots": ["bot", "crawl", "spider", "slurp", "curl/", "wget", "python", "go-http", "httpclient", "okhttp", "java/",
             "libwww", "axios", "node-fetch", "headless", "zgrab", "masscan", "nmap", "nuclei", "censys", "shodan",
             "scrapy", "aiohttp", "httpx", "powershell"],
    "previews": ["discordbot", "telegrambot", "twitterbot", "facebookexternalhit", "slackbot", "whatsapp",
                 "linkedinbot", "redditbot", "mastodon"],
    "players": ["vlc/", "mpv", "lavf/", "applecoremedia", "stagefright", "exoplayer", "gstreamer"],
}
EDGE_BROWSER = {"Edge": ["edg/"], "Opera": ["opr/"], "Samsung": ["samsungbrowser"], "Yandex": ["yabrowser"],
                "Vivaldi": ["vivaldi"], "Firefox": ["firefox/", "fxios"], "Discord app": ["discord/"],
                "Electron": ["electron/"], "Chrome (all Chromium)": ["chrome/", "crios"], "Safari": ["safari/"]}
EDGE_OS = {"Windows": ["windows"], "Android": ["android"], "iOS": ["iphone", "ipad"],
           "macOS": ["macintosh", "mac os x"], "ChromeOS": ["cros"], "Linux": ["linux"]}


class CFError(Exception):
    def __init__(self, status, msg):
        super().__init__(msg)
        self.status = status


def call(method, path, body=None, timeout=30):
    tok = CFG["cloudflare"].get("api_token")
    if not tok:
        raise CFError(0, "no Cloudflare API token configured")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            j = json.loads(e.read())
            msg = "; ".join("%s (code %s)" % (x.get("message"), x.get("code")) for x in j.get("errors", [])) or str(e)
        except Exception:
            msg = str(e)
        raise CFError(e.code, msg)
    except urllib.error.URLError as e:
        raise CFError(0, "network: %s" % e.reason)


_ids = {}


def zone_id():
    if CFG["cloudflare"].get("zone_id"):
        return CFG["cloudflare"]["zone_id"]
    if "zone" not in _ids:
        r = call("GET", "/zones?name=" + urllib.parse.quote(CFG["cloudflare"]["zone_name"]))
        if not r.get("result"):
            raise CFError(403, "zone %s not visible to this token" % CFG["cloudflare"]["zone_name"])
        _ids["zone"] = r["result"][0]["id"]
        _ids["account"] = r["result"][0]["account"]["id"]
    return _ids["zone"]


def account_id():
    if "account" not in _ids:
        z = call("GET", "/zones/%s" % zone_id())["result"]
        _ids["account"] = z["account"]["id"]
    return _ids["account"]


def capabilities():
    caps = {"token": {"ok": bool(CFG["cloudflare"].get("api_token"))}}
    if not caps["token"]["ok"]:
        return caps
    try:
        zone_id()
        caps["zone"] = {"ok": True}
    except CFError as e:
        caps["zone"] = {"ok": False, "error": str(e)}
        return caps
    try:
        call("GET", "/accounts/%s/rules/lists" % account_id())
        caps["lists"] = {"ok": True}
    except CFError as e:
        caps["lists"] = {"ok": False, "error": str(e), "need": PERMS["lists"]}
    try:
        call("GET", "/zones/%s/rulesets/phases/%s/entrypoint" % (zone_id(), PHASE))
        caps["waf"] = {"ok": True}
    except CFError as e:
        caps["waf"] = {"ok": e.status == 404, "error": "" if e.status == 404 else str(e), "need": PERMS["waf"]}
    try:
        call("GET", "/zones/%s/rulesets/phases/%s/entrypoint" % (zone_id(), CACHE_PHASE))
        caps["cache_rules"] = {"ok": True}
    except CFError as e:
        caps["cache_rules"] = {"ok": e.status == 404, "error": "" if e.status == 404 else str(e),
                               "need": PERMS["cache_rules"]}
    db = connect()
    try:
        p = get_meta(db, "cf_purge", {}) or {}
    finally:
        db.close()
    caps["purge"] = {"ok": p.get("ok"), "error": p.get("error", ""), "need": PERMS["purge"], "tested": p.get("ts")}
    return caps


def cf_str(s):
    return '"%s"' % str(s).replace("\\", "\\\\").replace('"', '\\"')


def expression(entries, list_ref=None):
    parts, skipped = [], []
    if list_ref:
        parts.append("(ip.src in $%s)" % list_ref)
    else:
        ips = [e["value"] for e in entries if e["kind"] in ("ip", "cidr")]
        if ips:
            parts.append("(ip.src in {%s})" % " ".join(ips))
    ccs = [e["value"] for e in entries if e["kind"] == "country"]
    if ccs:
        parts.append("(ip.src.country in {%s})" % " ".join(cf_str(c) for c in ccs))
    asns = [e["value"] for e in entries if e["kind"] == "asn"]
    if asns:
        parts.append("(ip.src.asnum in {%s})" % " ".join(asns))
    subs = []
    for e in entries:
        k, v = e["kind"], e["value"]
        if k == "ua_contains":
            subs.append(v.lower())
        elif k == "agent" and v == "empty":
            parts.append('(http.user_agent eq "")')
        elif k == "agent":
            subs += EDGE_AGENT.get(v, [])
        elif k == "browser":
            subs += EDGE_BROWSER.get(v, [])
        elif k == "os":
            subs += EDGE_OS.get(v, [])
        elif k == "referer":
            parts.append("(lower(http.referer) contains %s)" % cf_str(v.lower()))
        elif k in ("ua_regex", "path"):
            skipped.append(e["id"])
    for s in dict.fromkeys(subs):
        parts.append("(lower(http.user_agent) contains %s)" % cf_str(s))
    expr, used = "", 0
    for p in parts:  # Cloudflare's limit is 4096 characters per expression
        if len(expr) + len(p) + 4 > 4000:
            skipped.append("overflow")
            break
        expr = p if not expr else expr + " or " + p
        used += 1
    return expr, skipped


def wait_op(acct, op):
    for _ in range(40):
        r = call("GET", "/accounts/%s/rules/lists/bulk_operations/%s" % (acct, op))["result"]
        if r.get("status") in ("completed", "failed"):
            if r["status"] == "failed":
                raise CFError(0, "list update failed: %s" % r.get("error"))
            return
        time.sleep(0.75)


def sync():
    db = connect()
    try:
        if not (get_meta(db, "cf_edge_enabled", True)):
            return {"skipped": "edge sync disabled"}
        entries = [b for b in rules.load(db)["blacklist"] if rules.active(b) and b["scope"] in ("edge", "both")]
    finally:
        db.close()
    block = [e for e in entries if e["action"] == "block"]
    chal = [e for e in entries if e["action"] == "challenge"]
    zone, acct = zone_id(), account_id()
    ips = [e["value"] for e in block if e["kind"] in ("ip", "cidr")]
    lst = next((l for l in call("GET", "/accounts/%s/rules/lists" % acct)["result"] if l["name"] == LIST_NAME), None)
    if ips and not lst:
        lst = call("POST", "/accounts/%s/rules/lists" % acct,
                   {"name": LIST_NAME, "kind": "ip", "description": "Managed by Strata - edits are overwritten"})["result"]
    if lst:
        op = call("PUT", "/accounts/%s/rules/lists/%s/items" % (acct, lst["id"]),
                  [{"ip": ip, "comment": "strata"} for ip in ips[:10000]])
        if op.get("result", {}).get("operation_id"):
            wait_op(acct, op["result"]["operation_id"])
    want, skipped = [], []
    ex, sk = expression(block, LIST_NAME if (lst and ips) else None)
    skipped += sk
    if ex:
        want.append({"ref": REF_BLOCK, "description": "Strata blacklist - block (managed by Strata)", "expression": ex,
                     "action": "block", "enabled": True})
    ex, sk = expression(chal)
    skipped += sk
    if ex:
        want.append({"ref": REF_CHALLENGE, "description": "Strata blacklist - challenge (managed by Strata)",
                     "expression": ex, "action": "managed_challenge", "enabled": True})
    try:
        rs = call("GET", "/zones/%s/rulesets/phases/%s/entrypoint" % (zone, PHASE))["result"]
    except CFError as e:
        if e.status != 404:
            raise
        rs = None
    if rs is None:
        if want:
            call("PUT", "/zones/%s/rulesets/phases/%s/entrypoint" % (zone, PHASE), {"rules": want})
    else:
        have = {r.get("ref"): r for r in rs.get("rules", [])}
        first = rs["rules"][0]["id"] if rs.get("rules") else None
        for w in want:
            if w["ref"] in have:
                call("PATCH", "/zones/%s/rulesets/%s/rules/%s" % (zone, rs["id"], have[w["ref"]]["id"]), w)
            else:
                body = dict(w, position={"before": first}) if first else w
                call("POST", "/zones/%s/rulesets/%s/rules" % (zone, rs["id"]), body)
        for ref in (REF_BLOCK, REF_CHALLENGE):
            if ref in have and ref not in {w["ref"] for w in want}:
                call("DELETE", "/zones/%s/rulesets/%s/rules/%s" % (zone, rs["id"], have[ref]["id"]))
    return {"ips": len(ips), "rules": len(want), "skipped": [s for s in skipped if s != "overflow"],
            "overflow": "overflow" in skipped}


def sync_previews():
    """One cache rule: link-preview crawlers skip the edge cache on file types that get a Strata card, so they reach
    Caddy (which answers them with a preview page) instead of a copy of the file Cloudflare cached for people.
    Pictures, videos and web pages are left alone (the platforms embed those themselves), and the card image
    (?card=1) stays cached. Files for people are unaffected."""
    zone = zone_id()
    bots = " or ".join('lower(http.user_agent) contains %s' % cf_str(b) for b in core.EMBED_RE.pattern.split("|"))
    native = " ".join(cf_str(e) for e in rules.PREVIEW_NATIVE)
    want = {"ref": REF_PREVIEWS, "description": "Strata link previews - crawlers bypass the cache (managed by Strata)",
            "expression": '(%s) and http.request.uri.path.extension ne "" and not lower(http.request.uri.path.extension) in {%s}'
                          ' and not http.request.uri.query contains "card="' % (bots, native),
            "action": "set_cache_settings", "action_parameters": {"cache": False}, "enabled": True}
    try:
        rs = call("GET", "/zones/%s/rulesets/phases/%s/entrypoint" % (zone, CACHE_PHASE))["result"]
    except CFError as e:
        if e.status != 404:
            raise
        call("PUT", "/zones/%s/rulesets/phases/%s/entrypoint" % (zone, CACHE_PHASE), {"rules": [want]})
        return {"previews": "created"}
    have = {r.get("ref"): r for r in rs.get("rules", [])}
    if REF_PREVIEWS in have:
        call("PATCH", "/zones/%s/rulesets/%s/rules/%s" % (zone, rs["id"], have[REF_PREVIEWS]["id"]), want)
        return {"previews": "updated"}
    call("POST", "/zones/%s/rulesets/%s/rules" % (zone, rs["id"]), want)
    return {"previews": "created"}


class EdgeSync(threading.Thread):
    daemon = True

    def run(self):
        time.sleep(10)
        rules.EDGE_SYNC.set()  # one sync after start-up
        while True:
            rules.EDGE_SYNC.wait()
            time.sleep(3)  # coalesce bursts of changes
            rules.EDGE_SYNC.clear()
            status = {"ts": time.time()}
            try:
                if not CFG["cloudflare"].get("api_token"):
                    status.update(ok=False, error="no API token")
                else:
                    status.update(sync(), ok=True, error="")
                    try:
                        status.update(sync_previews(), previews_error="")
                    except CFError as e:  # a token without Cache Rules: previews still work, just not past the edge cache
                        status["previews_error"] = str(e) + (" - add %s" % PERMS["cache_rules"] if e.status == 403 else "")
            except CFError as e:
                status.update(ok=False, error=str(e), status=e.status)
                if e.status == 403:
                    status["hint"] = "Add %s and %s to the API token." % (PERMS["lists"], PERMS["waf"])
            except Exception as e:
                status.update(ok=False, error=str(e))
                log("edge sync error:\n" + traceback.format_exc())
            db = connect()
            try:
                with db:
                    prev = get_meta(db, "cf_sync", {}) or {}
                    set_meta(db, "cf_sync", status)
            finally:
                db.close()
            if not status.get("ok") and prev.get("ok"):
                for h in rules.ALERT_HOOK:
                    h("cloudflare", "warning", "Cloudflare edge sync failed", status.get("error", ""), "cf-sync")


# ---------------------------------------------------------------- cache purge
#
# Automatic purges go through a durable queue (table purgeq) drained by the Purger thread. A purge Cloudflare refuses
# (token without Cache Purge, rate limit, network) stays queued and is retried until it succeeds, so a deleted file
# cannot keep being served from the edge because one API call failed.
# Targets are prefixes ("host/path", no scheme): a prefix purge also drops every query-string variant of the path
# (?w= ?fm= ?ver= ?dl= ...), which exact-URL purges miss. Free plan: 100 prefixes per call, 5 calls/min (burst 25).

PURGE_WAKE = threading.Event()
PURGE_LOCK = threading.Lock()
PREFIX_BATCH, URL_BATCH = 100, 30
PREFIX_MAX_SLASHES = 31  # Cloudflare's limit of path separators in a prefix


def auth_hint(err):
    return " - add %s to the token" % PERMS["purge"] if any(s in err for s in ("uthenticat", "uthoriz", "ermission")) else ""


def purge(urls):
    """Purge exact URLs right now (the manual 'Purge URLs' tool); raises CFError when Cloudflare refuses."""
    urls = [u for u in dict.fromkeys(urls) if u.startswith("https://")]
    if not urls:
        return {"purged": 0}
    zone = zone_id()
    done = 0
    try:
        for i in range(0, len(urls), URL_BATCH):
            call("POST", "/zones/%s/purge_cache" % zone, {"files": urls[i:i + URL_BATCH]})
            done += len(urls[i:i + URL_BATCH])
        ok, err = True, ""
    except CFError as e:
        ok, err = False, str(e)
    db = connect()
    try:
        with db:
            set_meta(db, "cf_purge", {"ts": time.time(), "ok": ok, "error": err, "last": done})
    finally:
        db.close()
    if not ok:
        raise CFError(403, err + auth_hint(err))
    return {"purged": done}


def purge_everything():
    call("POST", "/zones/%s/purge_cache" % zone_id(), {"purge_everything": True})
    return {"purged": "everything"}


def split_targets(items):
    """https://host/path -> prefix host/path. URLs with a query (or paths too deep for a prefix) stay exact URLs."""
    prefixes, urls = [], []
    for it in items or []:
        it = str(it).strip().split("#", 1)[0]
        if it.startswith("http://"):
            it = "https://" + it[7:]
        bare = it[8:] if it.startswith("https://") else it
        host, _, path = bare.partition("/")
        if not host or not path:  # never purge a whole host by accident
            continue
        if "?" in bare or bare.count("/") > PREFIX_MAX_SLASHES:
            urls.append("https://" + bare)
        else:
            prefixes.append(bare)
    return list(dict.fromkeys(prefixes)), list(dict.fromkeys(urls))


def purge_enabled():
    if not CFG["cloudflare"].get("api_token"):
        return False
    db = connect()
    try:
        return bool(get_meta(db, "cf_autopurge", True))
    finally:
        db.close()


def enqueue(items):
    """Queue purges (https URLs or 'host/path' prefixes). Returns how many were queued (0 while purging is off)."""
    prefixes, urls = split_targets(items)
    if not (prefixes or urls) or not purge_enabled():
        return 0
    t = time.time()
    db = connect()
    try:
        with db:
            db.executemany("INSERT OR IGNORE INTO purgeq(kind, value, added, tries) VALUES(?,?,?,0)",
                           [("prefix", p, t) for p in prefixes] + [("url", u, t) for u in urls])
    finally:
        db.close()
    PURGE_WAKE.set()
    return len(prefixes) + len(urls)


def purge_async(urls):
    """Kept for callers that pass URL lists: queue them (as prefixes) for the Purger thread."""
    enqueue(urls)


def purge_status():
    db = connect()
    try:
        st = dict(get_meta(db, "cf_purge", {}) or {})
        st["pending"], st["oldest"] = db.execute("SELECT count(*), min(added) FROM purgeq").fetchone()
    finally:
        db.close()
    st["enabled"] = purge_enabled()
    return st


def _send(zone, kind, batch):
    """POST one batch. A 400 means Cloudflare rejected an entry: split until the bad ones are isolated.
    Returns (purged, rejected); raises CFError for anything worth retrying later (auth, rate limit, network)."""
    try:
        call("POST", "/zones/%s/purge_cache" % zone, {"prefixes" if kind == "prefix" else "files": batch}, timeout=20)
        return batch, []
    except CFError as e:
        if e.status != 400:
            raise
        if len(batch) == 1:
            log("purge: Cloudflare rejected %s %s: %s" % (kind, batch[0], e))
            return [], batch
        a_ok, a_bad = _send(zone, kind, batch[:len(batch) // 2])
        b_ok, b_bad = _send(zone, kind, batch[len(batch) // 2:])
        return a_ok + b_ok, a_bad + b_bad


def drain(wait=None, max_calls=None):
    """Send what is queued to Cloudflare, oldest first. Stops at the first error; the rest stays queued.
    wait: seconds to wait for a drain already running elsewhere (None = block). Returns purge_status()."""
    if not PURGE_LOCK.acquire(timeout=-1 if wait is None else wait):
        return purge_status()
    try:
        if not purge_enabled():
            return purge_status()
        done, calls, err, code = 0, 0, "", 0
        while max_calls is None or calls < max_calls:
            db = connect()
            try:
                kind = "prefix"
                batch = [r[0] for r in db.execute("SELECT value FROM purgeq WHERE kind='prefix' ORDER BY added, value "
                                                  "LIMIT ?", [PREFIX_BATCH])]
                if not batch:
                    kind = "url"
                    batch = [r[0] for r in db.execute("SELECT value FROM purgeq WHERE kind='url' ORDER BY added, value "
                                                      "LIMIT ?", [URL_BATCH])]
            finally:
                db.close()
            if not batch:
                break
            calls += 1
            try:
                ok, bad = _send(zone_id(), kind, batch)
            except CFError as e:
                err, code = str(e), e.status
                db = connect()
                try:
                    with db:
                        db.executemany("UPDATE purgeq SET tries=tries+1 WHERE kind=? AND value=?", [(kind, v) for v in batch])
                finally:
                    db.close()
                break
            db = connect()
            try:
                with db:
                    db.executemany("DELETE FROM purgeq WHERE kind=? AND value=?", [(kind, v) for v in ok + bad])
                    if kind == "prefix" and bad:  # refused as a prefix: fall back to the exact URL
                        db.executemany("INSERT OR IGNORE INTO purgeq(kind, value, added, tries) VALUES('url',?,?,0)",
                                       [("https://" + v, time.time()) for v in bad])
            finally:
                db.close()
            done += len(ok)
        if done or err:
            st = {"ts": time.time(), "ok": not err, "error": err + auth_hint(err), "status": code, "last": done}
            db = connect()
            try:
                with db:
                    set_meta(db, "cf_purge", st)
            finally:
                db.close()
        return purge_status()
    finally:
        PURGE_LOCK.release()


def purge_now(items, wait=8):
    """Queue items and try to send them before answering, so the UI can tell whether Cloudflare dropped its copies."""
    n = enqueue(items)
    st = drain(wait=wait, max_calls=6) if n else purge_status()
    st["queued"] = n
    return st


class Purger(threading.Thread):
    """Drains the purge queue. While Cloudflare refuses, retries with back-off (1 min, doubling to 15 min)."""
    daemon = True

    def run(self):
        delay, was_failing = 5, False
        while True:
            PURGE_WAKE.wait(timeout=delay)
            PURGE_WAKE.clear()
            try:
                st = drain()
            except Exception:
                log("purge queue error:\n" + traceback.format_exc())
                st = {"ok": False, "enabled": True, "pending": 1, "error": "internal error (see strata log)"}
            failing = bool(st.get("enabled") and st.get("pending") and not st.get("ok", True))
            if not st.get("pending") or not st.get("enabled"):
                delay = 600
            elif st.get("status") == 429:
                delay = 60
            elif failing:
                delay = min(max(delay * 2, 60), 900)
            else:
                delay = 5
            if failing and not was_failing:
                for h in rules.ALERT_HOOK:
                    h("cloudflare", "warning", "Cloudflare cache purge failing",
                      "%d purge(s) are queued, so deleted or changed files may still be served from Cloudflare's "
                      "cache: %s" % (st["pending"], st.get("error", "")), "cf-purge")
            was_failing = failing
