"""Strata Media at the Cloudflare edge: URL-rewrite (Transform) rules for format negotiation (media/DESIGN.md 6.1, 9).

Why: Cloudflare Free ignores `Vary: Accept`, so the origin must never answer different formats under one URL. The
edge rules add `_v=avif` / `_v=webp` (images, by the Accept header) or `_v=webm` (videos played by Chromium /
Firefox) to *query-less* requests before the cache lookup: each format is cached under its own key, the visible URL
stays the same and there is no extra round trip. Without the Transform Rules permission the bridge falls back to
redirect mode (media.py answers 302 ?_v=...).

The three rules live in phase http_request_transform and are identified by their fixed `ref`; every other rule of
that phase is left alone (same approach as cloudflare.sync() for the WAF rules). Only cloudflare.call / zone_id /
CFError are used, so this module holds no token and no state of its own.
"""
import json

import core
import cloudflare

MEDIA_PHASE = "http_request_transform"
REF_AVIF, REF_WEBP, REF_WEBM = core.prefixed("media_avif"), core.prefixed("media_webp"), core.prefixed("media_webm")
REFS = (REF_AVIF, REF_WEBP, REF_WEBM)
PERMS = {
    "transform": "Zone › Transform Rules › Edit",
    "purge": "Zone › Cache Purge › Purge",
}
IMG_EXTS = ("png", "jpg", "jpeg", "jfif", "gif", "bmp", "tif", "tiff", "webp")   # negotiable images (webp: AVIF)
# Cache-Control: no-transform asks for the original (RFC 9111 5.2.1.6): such requests are not rewritten, so they get
# the canonical URL's cache entry, which only ever holds the original
NO_TRANSFORM = 'not any(http.request.headers["cache-control"][*] contains "no-transform")'
VID_EXTS = ("mp4", "m4v", "mov")      # auto-swapped to WebM; mkv/avi/wmv/flv are downloads and never swapped
RULE_KEYS = ("description", "expression", "action", "action_parameters", "enabled")


def _q(s):
    return '"%s"' % str(s).replace("\\", "\\\\").replace('"', '\\"')


def _set(items):
    return "{%s}" % " ".join(_q(x) for x in items)


def _clean(items, lower=True):
    """Hosts / extensions for an expression: de-duplicated, order kept, anything that is not a plain token dropped."""
    out = []
    for x in items or ():
        x = str(x).strip()
        x = x.lower() if lower else x
        if x and all(c.isalnum() or c in ".-" for c in x) and x not in out:
            out.append(x)
    return out


def _rewrite(value):
    return {"uri": {"query": {"value": value}}}


def build_rules(hosts, img_exts=IMG_EXTS, vid_exts=VID_EXTS):
    """The wanted rules (DESIGN 9), exact expressions. No hosts -> no rules; no image / video extensions -> the
    avif+webp / webm rules are left out (the caller then deletes them)."""
    hosts, img, vid = _clean(hosts), _clean(img_exts), _clean(vid_exts)
    if not hosts:
        return []
    base = "(http.host in %s) and http.request.uri.query eq \"\"" % _set(hosts)
    accept = 'any(http.request.headers["accept"][*] contains "image/%s")'
    out = []
    if img:
        img_base = "%s and http.request.uri.path.extension in %s and %s" % (base, _set(img), NO_TRANSFORM)
        out.append({"ref": REF_AVIF, "description": "Strata Media - AVIF for query-less images (managed by Strata)",
                    "expression": "%s and %s" % (img_base, accept % "avif"),
                    "action": "rewrite", "action_parameters": _rewrite("_v=avif"), "enabled": True})
        out.append({"ref": REF_WEBP, "description": "Strata Media - WebP for query-less images (managed by Strata)",
                    "expression": "%s and not %s and %s" % (img_base, accept % "avif", accept % "webp"),
                    "action": "rewrite", "action_parameters": _rewrite("_v=webp"), "enabled": True})
    if vid:
        out.append({"ref": REF_WEBM, "description": "Strata Media - WebM for videos in Chromium/Firefox (managed by Strata)",
                    "expression": "%s and http.request.uri.path.extension in %s"
                                  ' and any(http.request.headers["sec-fetch-dest"][*] eq "video")'
                                  ' and (lower(http.user_agent) contains "chrome/" or lower(http.user_agent) contains "firefox/")'
                                  ' and not lower(http.user_agent) contains "crios"'
                                  ' and not lower(http.user_agent) contains "fxios"' % (base, _set(vid)),
                    "action": "rewrite", "action_parameters": _rewrite("_v=webm"), "enabled": True})
    return out


def media_hosts(mounts=None):
    """Hosts of the enabled files mounts that have transforms on (the ones media.py serves variants for)."""
    out = []
    for m in (core.file_mounts() if mounts is None else mounts):
        if m.get("kind") == "files" and m.get("enabled", 1) and m.get("transforms"):
            for h in m.get("hosts") or ():
                if h not in out:
                    out.append(h)
    return out


def _entrypoint(zone):
    return "/zones/%s/rulesets/phases/%s/entrypoint" % (zone, MEDIA_PHASE)


def _same(have, want):
    """Does the rule Cloudflare holds already match? (compared as JSON so key order never matters)"""
    return all(json.dumps(have.get(k), sort_keys=True) == json.dumps(want.get(k), sort_keys=True) for k in RULE_KEYS)


def sync_media_rules(enable, hosts=None, img_exts=None, vid_exts=None):
    """Create / patch / delete the three media rules by ref; other rules of the phase are never touched.

    enable=False removes them (redirect / off mode). hosts None = media_hosts(); img_exts None = the negotiable
    images; vid_exts None = mp4/m4v/mov when CFG media.video.enabled. Raises cloudflare.CFError (the bridge maps
    401/403 to "no permission" -> redirect mode). A missing entrypoint (404) is created with PUT, like sync()."""
    if img_exts is None:
        img_exts = IMG_EXTS
    if vid_exts is None:
        vid_exts = VID_EXTS if ((core.CFG.get("media") or {}).get("video") or {}).get("enabled", True) else ()
    want = build_rules(media_hosts() if hosts is None else hosts, img_exts, vid_exts) if enable else []
    zone = cloudflare.zone_id()
    res = {"enabled": bool(enable), "phase": MEDIA_PHASE, "ruleset": None, "created": [], "updated": [],
           "deleted": [], "unchanged": []}
    try:
        rs = cloudflare.call("GET", _entrypoint(zone))["result"]
    except cloudflare.CFError as e:
        if e.status != 404:
            raise
        rs = None
    if rs is None:
        if want:
            r = cloudflare.call("PUT", _entrypoint(zone), {"rules": want})
            res["ruleset"] = ((r or {}).get("result") or {}).get("id")
            res["created"] = [w["ref"] for w in want]
    else:
        res["ruleset"] = rs.get("id")
        have = {r.get("ref"): r for r in rs.get("rules") or [] if r.get("ref")}
        for w in want:
            h = have.get(w["ref"])
            if h is None:
                cloudflare.call("POST", "/zones/%s/rulesets/%s/rules" % (zone, rs["id"]), w)
                res["created"].append(w["ref"])
            elif _same(h, w):
                res["unchanged"].append(w["ref"])
            else:
                cloudflare.call("PATCH", "/zones/%s/rulesets/%s/rules/%s" % (zone, rs["id"], h["id"]), w)
                res["updated"].append(w["ref"])
        wanted = {w["ref"] for w in want}
        for ref in REFS:
            if ref in have and ref not in wanted:
                cloudflare.call("DELETE", "/zones/%s/rulesets/%s/rules/%s" % (zone, rs["id"], have[ref]["id"]))
                res["deleted"].append(ref)
    live = {w["ref"] for w in want}
    res["rules"] = {ref: ref in live for ref in REFS}
    return res


def capabilities():
    """{"transform": {ok, error, need, rules}, "purge": {ok, error, need, tested}} - reads only (GETs + strata.db meta).
    transform.ok means the phase is readable (404 = no entrypoint yet, still fine); edit rights are only proven by a
    successful sync_media_rules(). purge is what the Purger last saw (meta cf_purge)."""
    out = {"transform": {"ok": False, "error": "", "need": PERMS["transform"], "rules": {r: False for r in REFS}},
           "purge": {"ok": None, "error": "", "need": PERMS["purge"], "tested": None}}
    try:
        zone = cloudflare.zone_id()
        try:
            rs = cloudflare.call("GET", _entrypoint(zone))["result"] or {}
            refs = {r.get("ref") for r in rs.get("rules") or []}
            out["transform"].update(ok=True, rules={r: r in refs for r in REFS})
        except cloudflare.CFError as e:
            out["transform"].update(ok=e.status == 404, error="" if e.status == 404 else str(e))
    except cloudflare.CFError as e:
        out["transform"]["error"] = str(e)
    try:
        db = core.connect()
        try:
            p = core.get_meta(db, "cf_purge", {}) or {}
        finally:
            db.close()
        out["purge"].update(ok=p.get("ok"), error=p.get("error", "") or "", tested=p.get("ts"))
    except Exception as e:  # capabilities never fail as a whole
        out["purge"]["error"] = str(e)[:200]
    return out
