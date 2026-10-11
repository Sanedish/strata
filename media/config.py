"""Strata Media configuration, file categories and path resolution (DESIGN.md sections 4.1, 5.1, 11).

media.py and worker.py never read strata.json (least privilege: no CF token, no password hash). Strata's
rules.write_media_config() copies CFG["media"] plus a few runtime keys into media/media.json; load() deep-merges
that file over DEFAULTS, so a missing or partial file still yields a complete, safe config. MEDIA below is a
literal copy of core.DEFAULTS["media"] (a unit test keeps the two in sync); RUNTIME holds the keys only
media.json carries.
"""
import copy
import hashlib
import json
import os
import re
import threading
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))           # <install folder>\media (shared code)
# the instance home (instance.py): relative paths (data/media.db, data/media-cache) and media.json live there
STRATA_ROOT = os.path.normpath(os.environ.get("STRATA_HOME") or os.path.dirname(HERE))
CONF_PATH = os.environ.get("STRATA_MEDIA_CONFIG") or os.path.join(STRATA_ROOT, "media", "media.json")

# ---------------------------------------------------------------- defaults (copy of core.DEFAULTS["media"])

MEDIA = {
    # off until deployed: rules.render() only emits media routes (and the bridge only starts media.py /
    # worker.py) when this is on, so a Strata restart mid-rollout cannot point Caddy at a dead :8084.
    "enabled": False,
    "listen": "127.0.0.1:8084",       # media.py; Strata Transform keeps 8083 (?ver=, signed links)
    "cache_root": "data/media-cache", # local disk, not published (relative: inside the instance home)
    "cache_max_gb": 150,
    "db": "data/media.db",
    "event_log": "data/media-events.jsonl",
    "negotiation": "auto",           # auto | edge | redirect | off
    "cutover": 0,                    # set on first start: files born before it are "legacy"
    "admin_token": "",               # generated on first start; guards media.py /_admin/*
    "gate": {"enabled": True, "categories": ["image", "svg", "pdf", "archive", "document", "text", "exec"],
             "legacy_while_pending": True, "pending_retry_after": 30},
    "lane": {"enabled": True, "min_bytes": 512 << 20, "total_mbps": 25, "per_conn_mbps": 10},
    "breaker": {"cpu_trip": 85, "cpu_resume": 70, "cpu_trip_seconds": 3, "mem_min_mb": 768, "slots": 2,
                "max_waiters": 6, "wait_timeout_ms": 1500, "wait_trip_ms": 1200, "error_trip": 5,
                "slow_trip": 3, "cooldown_s": 15, "cooldown_max_s": 300},
    "image": {"sync_budget_s": 2.5, "sync_budget_max_s": 6.0, "sync_max_mp": 20, "sync_max_bytes": 32 << 20,
              "max_mp": 150, "bg_max_mp": 280, "min_bytes": 4096, "max_source_bytes": 160 << 20,
              "max_frames": 1000, "max_anim_mp": 96, "avif_quality_lossy": 62, "avif_quality_lossless": 74,
              "avif_alpha_quality": 90, "webp_quality": 86, "jpeg_quality": 85, "speed_sync": 8, "speed_bg": 6,
              "threads": 2, "min_saving": 0.10, "short_ttl": "public, max-age=60", "prewarm_uploads": False,
              "prewarm_popular": 200, "max_dim": 4096,
              "widths": [320, 640, 1080, 1440, 1920, 2160, 2560, 3840, 4320, 7680], "max_width": 7680,
              "snap_widths": True, "max_queue_depth": 500, "debug_headers": True, "profile": "p1",
              "tiers": {"interval_s": 300, "half_life_h": 72, "promote_min_hits": 4, "promote_rate_per_day": 2.0,
                        "promote_min_value_mb": 32, "horizon_days": 30, "storage_weight": 0.02,
                        "cpu_mb_per_s": 4, "demote_rate_per_day": 0.2, "demote_idle_days": 21,
                        "persistent_max_gb": 100, "ephemeral_max_age_days": 30, "tombstone_days": 30,
                        "failure_retry_h": 24, "upgrade_on_promote": True}},
    "video": {"enabled": True, "format": "webm", "codec": "av1", "crf_av1": 30, "preset_av1": 8, "crf_vp9": 32,
              "audio_kbps": 128, "threads": 2, "cpu_pct": 50, "max_seconds": 10800, "max_bytes": 8 << 30,
              "min_saving": 0.10, "timeout_factor": 15},
    "scan": {"legacy": False,  # existing library (born before cutover): never scanned / OCR'd, only compressed
                 "hold_threshold": "medium", "av_engines": ["defender", "clamav"], "require_av": True,
             "av_categories": ["archive", "pdf", "document", "exec", "svg"], "text_max_bytes": 8 << 20,
             "timeout_s": 1800,
             "archive": {"max_total_bytes": 24 << 30, "max_entries": 50000, "max_entry_bytes": 12 << 30,
                         "max_ratio": 250, "max_depth": 3, "ocr_images": 25, "text_bytes": 64 << 20,
                         "hold_inner_ext": ["scr", "com", "pif", "hta", "lnk", "vbs", "vbe", "jse", "wsf",
                                            "wsh", "ps1", "bat", "cmd", "msi", "reg"],
                         "report_inner_ext": ["exe", "dll", "jar", "apk", "sys"]},
             "pdf": {"max_pages": 300, "ocr_pages": 30, "dpi": 170}},
    "ocr": {"engine": "tesseract", "required": True, "langs": "eng", "psm": 3, "tile_px": 2400, "max_mp": 60,
            "timeout_s": 180, "min_side": 48},
    "detect": {"private_ip_severity": "low", "public_ip_severity": "medium", "email_severity": "low",
               "gps_severity": "low", "entropy_min": 3.8},
    "worker": {"cpu_max": 65, "mem_min_mb": 1024, "lease_s": 900, "max_attempts": 3,
                   "backfill": False},  # backfill = compress the whole existing library up front (off: demand driven)
    "tools": {"ffmpeg": "", "ffprobe": "", "7z": "", "tesseract": "", "mpcmdrun": "", "clamscan": "",
              "clamdscan": ""},
    "capacity": {"uplink_mbps": 50, "cpu_p95": 85, "mem_p95": 90, "backlog_hours": 6, "open_ratio": 0.10,
                 "cache_free_pct": 10},
    "file_policy": {
        "enabled": True,
        "deny_names": [".env", ".env.*", ".git", ".svn", ".hg", ".htaccess", ".htpasswd", ".npmrc", ".pypirc",
                       ".netrc", ".bash_history", ".ssh", ".aws", ".azure", ".kube", ".docker", "id_rsa",
                       "id_dsa", "id_ecdsa", "id_ed25519", "authorized_keys", "known_hosts", "web.config",
                       "wp-config.php", "appsettings*.json", "secrets.*", "secret.*", "credentials",
                       "credentials.*", "docker-compose.yml", "docker-compose.yaml", "terraform.tfstate*",
                       "thumbs.db", "desktop.ini", "strata.json", "media.json", "transform.json",
                       "telemetry.json"],
        "deny_ext": ["env", "ini", "cfg", "conf", "config", "cnf", "properties", "yml", "yaml", "toml", "sql",
                     "sqlite", "sqlite3", "db", "mdb", "accdb", "bak", "backup", "old", "swp", "swo", "tmp",
                     "log", "pem", "key", "crt", "cer", "csr", "der", "p12", "pfx", "jks", "keystore", "kdbx",
                     "asc", "gpg", "pgp", "ovpn", "rdp", "ppk", "tfstate", "php", "phtml", "asp", "aspx",
                     "jsp", "cgi", "pl"],
        "safe_ext": ["png", "jpg", "jpeg", "jfif", "gif", "webp", "avif", "bmp", "ico", "svg", "tif", "tiff",
                     "heic", "heif", "jxl", "psd", "tga", "mp4", "m4v", "webm", "mkv", "mov", "avi", "wmv",
                     "flv", "ts", "m3u8", "ogv", "mp3", "flac", "wav", "ogg", "oga", "opus", "m4a", "aac",
                     "wma", "mid", "midi", "html", "htm", "css", "js", "mjs", "map", "json", "webmanifest",
                     "wasm", "xml", "txt", "md", "csv", "tsv", "srt", "vtt", "ass", "ttf", "otf", "woff",
                     "woff2", "eot", "blend", "blend1", "fbx", "obj", "glb", "gltf", "stl", "ply", "3ds",
                     "dae", "usd", "usdz", "pdf", "epub", "docx", "xlsx", "pptx", "odt", "ods", "odp",
                     "zip", "7z", "rar", "tar", "gz", "tgz", "bz2", "xz", "zst", "mrpack", "br"],
        "safe_names": ["LICENSE", "LICENCE", "README", "CHANGELOG", "COPYING", "NOTICE", "AUTHORS"],
        "svg_csp": True},
}

# Keys only media.json carries (written by rules.write_media_config), or whose media.json value differs from
# strata.json's. Without a media.json the service falls back to these: redirect negotiation (never poisons the
# edge cache), no signing secret (/_gate refuses everything), no admin token (/_admin refuses everything), no
# mounts (every request is a 404). "listen" is a regular media key now (127.0.0.1:8084, DESIGN 4.2).
RUNTIME = {
    "sign_secret": "",
    "admin_token": "",
    "db": os.path.join(STRATA_ROOT, "data", "media.db"),
    "cache_root": os.path.join(STRATA_ROOT, "data", "media-cache"),
    "event_log": os.path.join(STRATA_ROOT, "data", "media-events.jsonl"),
    "negotiation": "redirect",       # the *effective* mode (edge | redirect | off), decided by the bridge
    "cutover": 0,
    "mounts": {},                    # {"1": {"path", "prefix", "hosts", "cache", "edge_cache"}}
}


def _merge(base, over):
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = copy.deepcopy(v)
    return base


DEFAULTS = _merge(copy.deepcopy(MEDIA), RUNTIME)

_lock = threading.Lock()
_cache = {}  # path -> (stat signature, conf)


def _abs(p):
    return p if not p or os.path.isabs(p) else os.path.normpath(os.path.join(STRATA_ROOT, p))


def load(path=None):
    """The merged config. Re-read only when media.json changes (mtime/size), so calling it per request is cheap.

    The returned dict is shared: treat it as read-only. A missing file gives DEFAULTS; an unreadable or
    half-written file keeps the last good version (rules writes it atomically, so that should never happen).
    """
    path = path or CONF_PATH
    try:
        st = os.stat(path)
        sig = (st.st_mtime_ns, st.st_size)
    except OSError:
        sig = None
    hit = _cache.get(path)
    if hit and hit[0] == sig:
        return hit[1]
    with _lock:
        hit = _cache.get(path)
        if hit and hit[0] == sig:
            return hit[1]
        conf = copy.deepcopy(DEFAULTS)
        if sig is not None:
            try:
                with open(path, encoding="utf-8-sig") as f:
                    raw = json.load(f)
                if not isinstance(raw, dict):
                    raise ValueError("media.json is not an object")
                _merge(conf, raw)
            except (OSError, ValueError):
                if hit:  # keep the last good config until the file changes again
                    _cache[path] = (sig, hit[1])
                    return hit[1]
                conf = copy.deepcopy(DEFAULTS)
        for k in ("db", "cache_root", "event_log"):
            conf[k] = _abs(conf.get(k) or DEFAULTS[k])
        conf["mounts"] = {str(k): v for k, v in (conf.get("mounts") or {}).items() if isinstance(v, dict)}
        _cache[path] = (sig, conf)
        return conf


def mount(conf, mount_id):
    """Mount config for an X-Strata-Mount header value / mount id, or None."""
    return (conf.get("mounts") or {}).get(str(mount_id).strip())


# ---------------------------------------------------------------- categories (DESIGN 5.1)

CATEGORIES = {
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
EXT_CAT = {e: c for c, exts in CATEGORIES.items() for e in exts.split()}

# 4.1 extension sets (no leading dot, lower case - compare with ext_of())
NEGOTIABLE = frozenset("png jpg jpeg jfif gif bmp tif tiff webp".split())  # auto AVIF/WebP (webp: AVIF only)
TRANSFORMABLE = NEGOTIABLE | {"webp", "avif"}                               # explicit ?w= ?fm= ...
VIDEO_EXT = frozenset("mp4 m4v mov mkv avi wmv flv".split())               # WebM variants (webm is served as is)


def ext_of(name):
    """Lower-case extension without the dot; "" for none and for dotfiles (".env" has no extension)."""
    base = re.split(r"[\\/]", name or "")[-1]
    return base.rsplit(".", 1)[1].lower() if "." in base.strip(".") else ""


def category(name):
    return EXT_CAT.get(ext_of(name), "other")


def gated(name, conf=None):
    """Does the scan gate apply to this file name?"""
    g = (conf or load()).get("gate") or {}
    return bool(g.get("enabled", True)) and category(name) in (g.get("categories") or ())


# ---------------------------------------------------------------- paths

_BAD_CHARS = re.compile(r'[\x00-\x1f\x7f<>:"|?*\\]')
_RESERVED = re.compile(r"(con|prn|aux|nul|conin\$|conout\$|clock\$|(com|lpt)[0-9\u00b9\u00b2\u00b3])", re.I)


def _bad_segment(p):
    """Segments Windows would reinterpret: dot segments / dotfiles (as transform.py), ADS and drive colons,
    reserved characters, trailing dots/spaces (Windows strips them: "a.png." opens "a.png"), device names."""
    return (p.startswith(".") or _BAD_CHARS.search(p) is not None or p[-1] in ". "
            or _RESERVED.fullmatch(p.split(".", 1)[0].rstrip(" ")) is not None)


def resolve(mount_conf, url_path):
    """(full filesystem path, decoded mount-relative path "/a/b.png") or (None, None).

    Port of transform.resolve: honours the mount prefix, decodes %XX once, rejects dot segments, dotfiles,
    backslashes and anything Windows would reinterpret, and finally checks the result stays under the root.
    """
    try:
        if not mount_conf or not mount_conf.get("path") or url_path is None:
            return None, None
        root = os.path.normpath(mount_conf["path"])
        path = urllib.parse.unquote(url_path, errors="strict")
        prefix = "/" + (mount_conf.get("prefix") or "/").strip("/")
        if prefix != "/":
            if not (path == prefix or path.startswith(prefix + "/")):
                return None, None
            path = path[len(prefix):] or "/"
        if not path.startswith("/"):
            return None, None
        parts = [p for p in path.split("/") if p]
        if any(_bad_segment(p) for p in parts):
            return None, None
        full = os.path.normpath(os.path.join(root, *parts))
        # compare with the root as commonpath spells it: on POSIX it drops the second slash of a //server/share root
        if os.path.commonpath([full.lower(), root.lower()]) != os.path.commonpath([root.lower()]):
            return None, None
        return full, "/" + "/".join(parts)
    except (ValueError, TypeError, UnicodeDecodeError):
        return None, None


def birth_time(st):
    """When this content appeared: a copy made today of an old file is new, and so is an overwritten file."""
    born = getattr(st, "st_birthtime", None) or st.st_ctime
    return max(st.st_mtime, born or 0)


def quick_hash(full, size):
    """compress.quick_hash: sha1 of size + first 64 KB + last 64 KB (identifies renamed copies cheaply)."""
    h = hashlib.sha1(str(size).encode())
    with open(full, "rb") as f:
        h.update(f.read(65536))
        if size > 131072:
            f.seek(size - 65536)
            h.update(f.read(65536))
    return h.hexdigest()
