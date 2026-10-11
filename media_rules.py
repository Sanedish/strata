"""Strata Media - Caddy rendering for the CDN site (media/DESIGN.md sections 4-6, 11-13).

All media-specific Caddyfile rendering lives here; rules.py only has tiny guarded hooks that go through
rules.media() -> hook() below. Everything is a no-op unless CFG["media"]["enabled"] is on, so with media off
render() is byte-for-byte what it was before this module existed.

Rendering (each writes into the CDN site's `route { }` at depth 2, same conventions as rules.py):
  render_prologue(o)                       step 0: strip client-supplied internal headers
  render_file_policy(o, mounts, allows)    step 4: dangerous -> 404, unknown type -> 403, SVG CSP
  render_media_routes(o, m, up, db) -> bool  step 5: media variants (+ negotiation in redirect mode); True = skip @tf
  render_gate(o, fmounts)                  steps 6-7: scan gate (forward_auth /_scan) + large-file lane
Config / analysis: enabled(), effective_negotiation(db), write_media_config(mounts, db), file_policy_preview(db),
variant_urls(url).

rules.py imports this module at import time, so `rules` is imported lazily inside functions. `core` is safe at
module scope (it imports neither rules nor media_rules).

Caddy facts this file relies on (verified against caddy 2.11.3 with a private instance, see
media/tests/test_rules_media.py):
* `{rp.header.X}` is looked up by Go's *canonical* header key: `X-Strata-CDN-Cache-Control` never resolves, it
  must be written `X-Strata-Cdn-Cache-Control`.
* `header Name {rp.header.X}` with X absent emits the literal text "{http.reverse_proxy.header.X}", and with X
  empty an empty header - so every copied header is guarded by `not vars {rp.header.X} ""`.
* header_down only touches pass-through answers (302/403/503/4xx), never the handle_response (accel/orig) ones.
* deferred header ops of access rules (`>Cache-Control`, `-Cloudflare-CDN-Cache-Control`) run after
  handle_response, so private actions and `cache` rules still win over what media asks for.

Windows/NTFS (file policy): path_regexp sees the %-decoded, slash-cleaned path, but Windows may open a different
file than that path names: `\\` (%5C) is a separator, trailing dots/spaces are stripped ("x.env." opens x.env),
`:` reaches alternate data streams, and 8.3 short names ("CREDEN~1.TXT") alias long ones. Those forms are denied
outright (404) - which also stops them from slipping past path-based access rules - and the name/extension
matchers additionally accept either separator and a trailing [ .]*. Unknown types are default-deny (403).
"""
import copy
import json
import os
import re
import tempfile

import core

# Media extension sets (DESIGN 4.1) as regex bodies, so the matcher reproduces the DESIGN 4.2 fragment
# (jpe?g / tiff? rather than expanded alternations). A unit test checks them against media/config.py.
MEDIA_EXT_RX = "png|jpe?g|jfif|gif|bmp|tiff?|webp|avif|mp4|m4v|mov|mkv|avi|wmv|flv|webm"
NEG_IMG_RX = "png|jpe?g|jfif|gif|bmp|tiff?|webp"
NEG_IMG = ("png", "jpg", "jpeg", "jfif", "gif", "bmp", "tif", "tiff", "webp")
# query keys that make a request something other than "the image, negotiated" (never sent to @neg): explicit
# transforms keep their legacy meaning, ?ver= is a stored version, ?dl=1 a download of the original file
NEG_EXCLUDE = ("_v", "fm", "h", "q", "fit", "ver", "dl")
VIDEO_EXT = ("mp4", "m4v", "mov", "mkv", "avi", "wmv", "flv")

# Gate categories -> extensions (DESIGN 5.1). Must stay equal to media/config.py CATEGORIES (unit-tested); only
# the categories listed in CFG.media.gate.categories are gated.
CATEGORY_EXT = {
    "image": "png jpg jpeg jfif gif webp avif bmp tif tiff ico heic heif jxl psd tga",
    "svg": "svg",
    "pdf": "pdf",
    "archive": "zip 7z rar tar gz tgz bz2 tbz2 xz txz zst mrpack",
    "document": "docx xlsx pptx odt ods odp epub doc xls ppt rtf",
    "text": "txt md csv tsv log json xml yml yaml toml ini srt vtt ass html htm css js mjs map webmanifest",
    "exec": "exe msi dll bat cmd ps1 py sh jar apk dmg iso img appimage deb rpm com scr",
    "video": "mp4 m4v mov mkv avi wmv flv webm ts m3u8 ogv",
    "audio": "mp3 flac wav ogg oga opus m4a aac wma mid midi alac amr wv ape",
    "font": "ttf otf woff woff2 eot",
    "3d": "blend blend1 fbx obj glb gltf stl ply 3ds dae usd usdz",
}

# request headers only Caddy may set (DESIGN 4 step 0); the admin token is stripped too (defence in depth)
INTERNAL_HEADERS = ("X-Strata-Lane", "X-Strata-Throttle", "X-Strata-Negotiate", "X-Strata-Mount", "X-Strata-Cache",
                    "X-Strata-Edge-Cache", "X-Strata-Admin-Token")
# media answer headers -> response headers (canonical Go spelling, see the module docstring)
COPY_HEADERS = (("Cache-Control", "X-Strata-Cache-Control"), ("Cloudflare-CDN-Cache-Control", "X-Strata-Cdn-Cache-Control"),
                ("Content-Disposition", "X-Strata-Disposition"), ("X-Strata-Media", "X-Strata-Media"),
                ("+Vary", "X-Strata-Vary"),   # appended: precompressed br may add Accept-Encoding to the same Vary
                ("X-CDN-Image-Format", "X-Cdn-Image-Format"), ("X-CDN-Image-Cache", "X-Cdn-Image-Cache"),
                ("X-CDN-Image-Source", "X-Cdn-Image-Source"), ("X-CDN-Image-Width", "X-Cdn-Image-Width"))
SVG_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:"
DEFAULT_LISTEN = "127.0.0.1:8084"

SEP = r"[/\\]"       # segment boundary: slash or (Windows) backslash
GLOB = r"[^/\\]*"    # a file-policy glob '*': within one segment, never across a separator
TRAIL = r"[ .]*"     # NTFS strips trailing dots and spaces
_C83 = r"[^/\\.~ ]"  # a character of an 8.3 short-name base
# 8.3 aliases: base of at most 8 chars with a '~' inside (PROGRA~1, CREDEN~1, AB12C~1D), optional 1-3 char ext
SHORT_NAME = "(?:%s)" % "|".join("%s{%d}~%s{1,%d}" % (_C83, i, _C83, 7 - i) for i in range(1, 7))
ALIAS_RX = r"[\\:\x00-\x1f]|[ .](?:[/\\]|$)|(?:^|[/\\])%s(?:\.[^/\\.]{1,3})?(?:[/\\]|$)" % SHORT_NAME


# ---------------------------------------------------------------- config helpers

def _m():
    return core.CFG.get("media") or {}


def enabled():
    """Master switch (kill switch until deployment): every hook and the apply-time config write are no-ops unless on."""
    return bool(_m().get("enabled"))


def listen():
    return _m().get("listen") or DEFAULT_LISTEN


def effective_negotiation(db=None):
    """Negotiation mode to render (DESIGN 6.1). An explicit `redirect` / `off` wins at once; `auto` / `edge` use the
    mode the bridge verified and stored in strata.db meta `media_negotiation_effective`, and until there is one the
    safe `redirect` (edge rules unverified; if they are live anyway, the rewritten `?_v=` never reaches @neg)."""
    configured = _m().get("negotiation") or "auto"
    if configured in ("redirect", "off"):
        return configured
    stored = None
    if db is not None:
        stored = core.get_meta(db, "media_negotiation_effective")
        if isinstance(stored, dict):
            stored = stored.get("mode") or stored.get("effective")
    return stored if stored in ("edge", "redirect", "off") else "redirect"


# ---------------------------------------------------------------- file-policy regexes (Caddy RE2 == Python re here)

def _lit(s):
    import rules
    return rules.re2_literal(str(s))


def _bodies(names):
    """Names as segment bodies: literal, with the file-policy glob '*' -> [^/\\]* (within one segment)."""
    return [GLOB.join(_lit(part) for part in str(n).split("*")) for n in names if str(n).strip()]


def _names_part(fp):
    names = _bodies(fp.get("deny_names") or [])
    return "(?:^|%s)(?:%s)%s(?:%s|$)" % (SEP, "|".join(names), TRAIL, SEP) if names else None


def _ext_part(fp):
    exts = [_lit(e) for e in (fp.get("deny_ext") or []) if str(e).strip()]
    return r"\.(?:%s)%s%s?$" % ("|".join(exts), TRAIL, SEP) if exts else None


def dangerous_parts(fp):
    """{reason: regex body} for the 404 class; deny wins over safe. `alias` = the Windows/NTFS forms (see top)."""
    parts = {"deny_name": _names_part(fp), "deny_ext": _ext_part(fp),
             "alias": ALIAS_RX if fp.get("deny_aliases", True) else None}
    return {k: v for k, v in parts.items() if v}


def dangerous_regex(fp):
    parts = list(dangerous_parts(fp).values())
    return "(?i)(?:%s)" % "|".join(parts) if parts else None


def safe_regex(fp):
    """A directory request (path ends '/'), a known-safe final extension or a known-safe last segment (LICENSE ...).
    The unknown-type matcher fires when a path does NOT match this: default deny -> 403."""
    parts = ["/$"]
    exts = [_lit(e) for e in (fp.get("safe_ext") or []) if str(e).strip()]
    if exts:
        parts.append(r"\.(?:%s)%s$" % ("|".join(exts), TRAIL))
    names = _bodies(fp.get("safe_names") or [])
    if names:
        parts.append("(?:^|%s)(?:%s)%s$" % (SEP, "|".join(names), TRAIL))
    return "(?i)(?:%s)" % "|".join(parts)


SVG_RX = r"(?i)\.svg%s$" % TRAIL


def gated_regex(cats):
    exts = []
    for c in cats or ():
        for e in (CATEGORY_EXT.get(c) or "").split():
            if e not in exts:
                exts.append(e)
    # TRAIL: with the file policy off, "/x.pdf." must still not slip past the gate to file_server (opens x.pdf)
    return r"(?i)\.(?:%s)%s$" % ("|".join(_lit(e) for e in exts), TRAIL) if exts else None


def _policy_blocks(mounts):
    """Enabled files mounts -> policy blocks [{hosts, ids, prefixes, browse_root}]. Hosts whose files mounts are the
    same set share a block; a block without a "/" mount is limited to its prefixes (a proxy mount on the same host
    keeps its paths). Page mounts only ever serve "/" (always safe), so they need no policy."""
    import rules
    fm = [m for m in mounts if m["kind"] == "files" and m.get("enabled", 1)]
    fm.sort(key=lambda m: (-len(m["prefix"]), m.get("sort") or 0, m["id"]))  # drive order: the first one serves
    per_host = {}
    for m in fm:
        for h in m["hosts"]:
            per_host.setdefault(h, []).append(m)
    blocks = {}
    for h, ms in per_host.items():
        key = tuple(m["id"] for m in ms)
        b = blocks.get(key)
        if b is None:
            root = next((m for m in ms if m["prefix"] == "/"), None)
            b = blocks[key] = {"hosts": [], "ids": {m["id"] for m in ms},
                               "prefixes": [] if root else sorted({m["prefix"] for m in ms}),
                               "browse_root": root["path"] if root and root.get("browse") else None}
        b["hosts"].append(h)
    out = list(blocks.values())
    for b in out:
        b["scope"] = [rules.host_cond(b["hosts"])]
        if b["prefixes"]:
            b["scope"].append("path " + " ".join(rules.bq(p) + " " + rules.bq(p + "/*") for p in b["prefixes"]))
    return out


# ---------------------------------------------------------------- rendering

def render_prologue(o):
    """Step 0, first lines inside `route { }`: a client can never inject a lane / mount / cache / negotiate decision."""
    for h in INTERNAL_HEADERS:
        o.add(2, "request_header -%s" % h)


def render_file_policy(o, mounts, allows):
    """Step 4 (after short links, before link modifiers): per block of files-mount hosts, dangerous names /
    extensions / NTFS aliases -> 404 (like "hide"), not a known-safe type -> 403, and the SVG CSP header. `allow`
    access rules (global or scoped to one of the block's mounts) carve exceptions exactly like in rules.render()."""
    import rules
    fp = _m().get("file_policy") or {}
    blocks = _policy_blocks(mounts)
    if not blocks:
        return
    on = bool(fp.get("enabled"))
    dang, safe = dangerous_regex(fp), safe_regex(fp)
    if on:
        o.add(2, "# file policy (Strata Media): dangerous -> 404, unknown type -> 403")
    for b in blocks:
        mine = [a for a in allows if not a.get("mount") or a["mount"] in b["ids"]]
        if on and dang:
            n = o.name("mfd")
            o.matcher(2, n, b["scope"] + ["path_regexp %s %s" % (n, rules.bq(dang))] + rules.exception_conds(mine, o))
            o.add(2, "error @%s 404" % n)
        if on:
            n = o.name("mfu")
            conds = b["scope"] + ["not path_regexp %s %s" % (n, rules.bq(safe))] + rules.exception_conds(mine, o)
            o.add(2, "@%s {" % n)
            for c in conds:
                o.add(3, c)
            if b["browse_root"]:  # a browsable folder asked for without its slash: let file_server redirect it
                o.add(3, "not file {")
                o.add(4, "root %s" % rules.bq(b["browse_root"]))
                o.add(4, "try_files {path}/")
                o.add(3, "}")
            o.add(2, "}")
            o.add(2, "error @%s 403" % n)
        if fp.get("svg_csp"):  # protective only (never blocks), so it stays on even with the policy off
            n = o.name("msvg")
            o.matcher(2, n, b["scope"] + ["path_regexp %s %s" % (n, rules.bq(SVG_RX))])
            o.add(2, "header @%s Content-Security-Policy %s" % (n, rules.bq(SVG_CSP)))


def _copy_headers(o, depth, m):
    """Copy media's answer headers onto the served file, each only when media actually sent a non-empty value
    (an absent one would leak the literal placeholder, an empty one an empty header). Cache-Control falls back to
    the drive's browser value; the CDN header, Content-Disposition and X-Strata-Media are simply left out."""
    import rules
    for dst, src in COPY_HEADERS:
        g = o.name("mh")
        o.add(depth, '@%s not vars {rp.header.%s} ""' % (g, src))
        o.add(depth, "header @%s %s {rp.header.%s}" % (g, dst, src))
    if m.get("cache"):
        g = o.name("mh")
        o.add(depth, '@%s vars {rp.header.X-Strata-Cache-Control} ""' % g)
        o.add(depth, "header @%s Cache-Control %s" % (g, rules.bq(m["cache"])))


def _media_proxy(o, n, m, up, extra=()):
    """reverse_proxy @n -> media with the accel / orig / missing handle_response blocks (DESIGN 4.2)."""
    import rules
    cache_root = str(_m().get("cache_root") or "").replace("\\", "/").rstrip("/")
    o.add(2, "reverse_proxy @%s %s {" % (n, listen()))
    for u in list(up) + list(extra):
        o.add(3, u)
    # pass-through answers (302 / 403 held / 503 pending / 4xx) are never edge-cacheable - even when a `cache`
    # access rule rewrites their Cache-Control (its deferred header wins). Not applied to accel / orig answers.
    o.add(3, "header_down CDN-Cache-Control `no-store`")
    acc = o.name("acc%d" % m["id"])
    o.add(3, "@%s header X-Strata-Accel *" % acc)
    o.add(3, "handle_response @%s {" % acc)
    o.add(4, "root * %s" % rules.bq(cache_root + "/cache"))
    o.add(4, "rewrite * {rp.header.X-Strata-Accel}")
    _copy_headers(o, 4, m)
    o.add(4, "file_server")
    o.add(3, "}")
    org = o.name("org%d" % m["id"])
    o.add(3, "@%s header X-Strata-Orig *" % org)
    o.add(3, "handle_response @%s {" % org)
    if m["prefix"] != "/":
        o.add(4, "uri strip_prefix %s" % rules.bq(m["prefix"]))
    o.add(4, "root * %s" % rules.bq(m["path"]))
    _copy_headers(o, 4, m)
    if m.get("precompress"):   # the original keeps its .br sidecar (BMP/TIFF ...), exactly like the drive itself
        o.add(4, "file_server {")
        o.add(5, "precompressed br")
        o.add(4, "}")
    else:
        o.add(4, "file_server")
    o.add(3, "}")
    # binned / deleted original: media's 404 becomes the real 404/403 page (same as the transform proxies)
    o.add(3, "@%s_missing status 404" % n)
    o.add(3, "handle_response @%s_missing {" % n)
    o.add(4, "error 404")
    o.add(3, "}")
    o.add(2, "}")


def render_media_routes(o, m, up, db=None, negotiation=None):
    """Step 5 for a files mount with transforms on, to media on CFG.media.listen:
      `@neg<id>` (first) negotiable image whose query names no variant / explicit transform / version / download:
                 redirect mode -> every such request (canonical URL, ?w=, unrelated parameters like ?t=);
                 edge mode     -> only ?w= requests (Cloudflare rewrites query-less ones before its cache, but its
                                  rules cannot add _v to a URL that already has a query)
                 media answers 302 ?[w=<rung>&]_v=avif|webp|orig by Accept (private, no-store, Vary: Accept).
      `@mv<id>`  media extension AND (`_v` in avif|webp|webm OR any of w/h/fm/q/fit): the variant itself.
    In edge mode the canonical original additionally gets `Vary: Accept` (Cloudflare rewrote it by Accept).
    Returns True so render() skips the old @tf block (explicit ?w= now goes to media); ?ver= stays on Strata
    Transform. `?_v=orig` alone is deliberately not matched: gate + drive serve the untouched original."""
    import rules
    if not m.get("transforms"):
        return False
    mode = negotiation or effective_negotiation(db)
    pc = [] if m["prefix"] == "/" else ["path " + rules.bq(m["prefix"] + "/*")]
    neg_rx = rules.bq("(?i)\\.(%s)$" % NEG_IMG_RX)
    if mode in ("redirect", "edge"):
        n = o.name("neg%d" % m["id"])
        cond = " && ".join('{query.%s} == ""' % k for k in NEG_EXCLUDE)
        if mode == "edge":
            cond += ' && {query.w} != ""'
        o.matcher(2, n, [rules.host_cond(m["hosts"])] + pc + ["path_regexp %s %s" % (n, neg_rx),
                                                              "expression %s" % rules.bq(cond)])
        # media answers 302 / 403 / 503 (or the original for Cache-Control: no-transform); the accel/orig blocks
        # are a safety net so an empty 200 never leaks
        _media_proxy(o, n, m, up, ["header_up X-Strata-Negotiate 1"])
    if mode == "edge":
        n = o.name("nv%d" % m["id"])
        o.matcher(2, n, [rules.host_cond(m["hosts"])] + pc + ["path_regexp %s %s" % (n, neg_rx),
                                                              "expression `{http.request.uri.query} == \"\"`"])
        o.add(2, "header @%s +Vary Accept" % n)
    n = o.name("mv%d" % m["id"])
    o.matcher(2, n, [rules.host_cond(m["hosts"])] + pc + [
        "path_regexp %s %s" % (n, rules.bq("(?i)\\.(%s)$" % MEDIA_EXT_RX)),
        "expression %s" % rules.bq(
            '{query._v} == "avif" || {query._v} == "webp" || {query._v} == "webm" || '
            '{query.w} != "" || {query.h} != "" || {query.fm} != "" || {query.q} != "" || {query.fit} != ""')])
    _media_proxy(o, n, m, up)
    return True


def render_gate(o, fmounts):
    """Steps 6-7 (after link modifiers, before drives), per files mount: `@gate<id>` forward_auths gated extensions to
    media /_scan (403 held / 503 pending pass through; 200 may carry X-Strata-Lane: throttle), then `@lane<id>`
    sends what the gate marked to media's throttled streamer. Step 0 strips a client's own X-Strata-Lane."""
    import rules
    gate = _m().get("gate") or {}
    rx = gated_regex(gate.get("categories"))
    fm = [m for m in fmounts if m["kind"] == "files" and m.get("enabled", 1)]
    if not gate.get("enabled") or not rx or not fm:
        return
    o.add(2, "# scan gate + large-file lane (Strata Media)")
    for m in fm:
        hc = rules.host_cond(m["hosts"])
        pc = [] if m["prefix"] == "/" else ["path " + rules.bq(m["prefix"] + "/*")]
        n = o.name("gate%d" % m["id"])
        o.matcher(2, n, [hc] + pc + ["path_regexp %s %s" % (n, rules.bq(rx))])
        o.add(2, "forward_auth @%s %s {" % (n, listen()))
        o.add(3, "uri /_scan")
        o.add(3, "header_up X-Strata-Mount %d" % m["id"])
        o.add(3, "copy_headers X-Strata-Lane")
        o.add(3, "header_down CDN-Cache-Control `no-store`")  # held 403 / pending 503 never cached at the edge
        o.add(2, "}")
        if (_m().get("lane") or {}).get("enabled", True):
            n = o.name("lane%d" % m["id"])
            o.matcher(2, n, [hc] + pc + ["header X-Strata-Lane throttle"])
            o.add(2, "reverse_proxy @%s %s {" % (n, listen()))
            o.add(3, "header_up X-Strata-Throttle 1")
            o.add(3, "header_up X-Strata-Mount %d" % m["id"])
            o.add(3, "header_up X-Strata-Cache %s" % rules.bq(m["cache"] or "no-store"))
            if m.get("edge_cache"):
                o.add(3, "header_up X-Strata-Edge-Cache %s" % rules.bq(m["edge_cache"]))
            o.add(3, "@%s_missing status 404" % n)
            o.add(3, "handle_response @%s_missing {" % n)
            o.add(4, "error 404")
            o.add(3, "}")
            o.add(2, "}")


_RENDER = {"prologue": render_prologue, "file_policy": render_file_policy, "media_routes": render_media_routes,
           "gate": render_gate}


def hook(name, *a):
    """rules.media() entry point. None while media is off. Renderers write into a scratch Out that is merged only
    when they return normally, so an exception can never leave half a block in the Caddyfile (rules.media() logs
    it and render() carries on without that block). "config" writes media/media.json."""
    if not enabled():
        return None
    if name == "config":
        return write_media_config(*a)
    o = a[0]
    tmp = type(o)()
    tmp.n = o.n.copy()
    res = _RENDER[name](tmp, *a[1:])
    o.lines.extend(tmp.lines)
    o.n = tmp.n
    return res


# ---------------------------------------------------------------- media.json (DESIGN 11 / 12)

def write_media_config(mounts, db=None, path=None):
    """Atomically write media/media.json for media.py / worker.py (they never read strata.json): the whole
    CFG["media"] section plus the runtime keys of DESIGN 11. Unchanged content is not rewritten (config.load()
    reloads on mtime). `mounts` = core.mounts() rows; only enabled files mounts are exported."""
    m = _m()
    conf = copy.deepcopy(m)
    db_path = m.get("db") or "data/media.db"
    conf.update({
        "listen": listen(),
        "sign_secret": core.CFG.get("sign_secret", ""),
        "admin_token": m.get("admin_token", ""),
        "db": (db_path if os.path.isabs(db_path) else os.path.join(core.HOME, db_path)).replace("\\", "/"),
        "cache_root": m.get("cache_root"),
        "event_log": m.get("event_log"),
        "negotiation": effective_negotiation(db),
        "cutover": m.get("cutover", 0),
        "mounts": {str(x["id"]): {"path": x["path"], "prefix": x["prefix"], "hosts": list(x["hosts"]),
                                  "cache": x.get("cache") or "", "edge_cache": x.get("edge_cache") or "",
                                  "transforms": 1 if x.get("transforms") else 0}
                   for x in mounts if x["kind"] == "files" and x["enabled"]},
    })
    target = path or os.path.join(core.HOME, "media", "media.json")
    text = json.dumps(conf, indent=2, sort_keys=True) + "\n"
    try:
        with open(target, encoding="utf-8") as f:
            if f.read() == text:
                return target
    except OSError:
        pass
    os.makedirs(os.path.dirname(target), exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".media-", suffix=".tmp", dir=os.path.dirname(target))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    return target


def variant_urls(url):
    """Extra CDN URLs of a public file URL that caches may hold (`?_v=` variants, DESIGN 9). Cloudflare prefix purges
    already cover them, so files.urls_for does not need this; it is here for exact-URL purges."""
    path = url.split("?", 1)[0]
    if "?" in url:
        return []
    ext = path.rsplit("/", 1)[-1].rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
    if ext in NEG_IMG:
        return [path + "?_v=avif", path + "?_v=webp", path + "?_v=orig"]
    if ext in VIDEO_EXT:
        return [path + "?_v=webm", path + "?_v=orig"]
    return []


# ---------------------------------------------------------------- file-policy dry run (DESIGN 12 / 13.2)

def file_policy_preview(db, limit=200):
    """Dry run of the file policy over the file index (fidx) with the very regexes Caddy gets: which currently
    served files it would refuse (404 dangerous / 403 unknown type), by reason and extension, with samples. Files
    an existing hide/deny rule already blocks are not counted; files an `allow` rule covers are "rescued"."""
    import rules
    fp = _m().get("file_policy") or {}
    dparts = {k: re.compile("(?i)" + v) for k, v in dangerous_parts(fp).items()}
    safe = re.compile(safe_regex(fp))
    svg = re.compile(SVG_RX)
    D = rules.load(db)
    mounts = {m["id"]: m for m in D["mounts"] if m["enabled"] and m["kind"] == "files"}
    active = [r for r in D["rules"] if rules.active(r)]
    allows = [r for r in active if r["action"] == "allow"]
    counts = {"files": 0, "safe": 0, "refused": 0, "rescued": 0, "already_blocked": 0, "svg_csp": 0}
    by_reason, by_ext, samples = {}, {}, []
    for mid in sorted(mounts):
        pre = "" if mounts[mid]["prefix"] == "/" else mounts[mid]["prefix"]
        for path, ext, size in db.execute("SELECT path, ext, size FROM fidx WHERE mount=? ORDER BY path", [mid]):
            url = pre + path
            counts["files"] += 1
            if rules.effective(mid, url, active)["state"] in ("hide", "deny"):
                counts["already_blocked"] += 1
                continue
            reason = next((k for k, rx in dparts.items() if rx.search(url)), None)
            if reason is None and not safe.search(url):
                reason = "unknown"
            if reason is None:
                counts["safe"] += 1
                counts["svg_csp"] += 1 if svg.search(url) else 0
                continue
            if any((not a["mount"] or a["mount"] == mid) and rules.rule_matches(a, url) for a in allows):
                counts["rescued"] += 1
                continue
            counts["refused"] += 1
            e = (ext or "").lower() or "(none)"
            for d, k in ((by_reason, reason), (by_ext, e)):
                d.setdefault(k, {"count": 0, "bytes": 0})
                d[k]["count"] += 1
                d[k]["bytes"] += size or 0
            if len(samples) < limit:
                samples.append({"mount": mid, "path": url, "ext": e, "reason": reason, "size": size or 0})
    return {"enabled": enabled() and bool(fp.get("enabled")), "media_enabled": enabled(),
            "policy_enabled": bool(fp.get("enabled")), "total": counts["refused"], "counts": counts,
            "by_reason": by_reason, "by_ext": by_ext, "samples": samples}
