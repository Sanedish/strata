"""Strata core - config, access-log tailer, metric scrapers, probes and the SQLite queries.

Everything here runs inside the private Strata process. Nothing in this module is reachable from the
public telemetry page: that only ever sees what feed.py deliberately builds from these queries.
"""
import os as _os
import site as _site
import sys as _sys

# Task Scheduler starts pythonw without APPDATA, so Python cannot find the per-user site-packages where
# pip --user put brotli / Pillow / qrcode. Add it explicitly (it silently disabled Brotli once).
def _roaming_appdata():
    try:  # ask Windows (works even when the environment has no APPDATA / USERPROFILE)
        import ctypes as _ct
        buf = _ct.create_unicode_buffer(520)
        if _ct.windll.shell32.SHGetFolderPathW(None, 0x1A, None, 0, buf) == 0 and buf.value:
            return buf.value
    except Exception:
        pass
    return _os.environ.get("APPDATA") or _os.path.join(_os.path.expanduser("~"), "AppData", "Roaming")


# Third-party packages (brotli, zstandard, Pillow, qrcode) live in ./vendor (pip install --target vendor ...):
# a --user install can land in an app-private virtualised AppData that the scheduled tasks never see.
_VENDOR = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "vendor")
if _os.path.isdir(_VENDOR) and _VENDOR not in _sys.path:
    _sys.path.insert(0, _VENDOR)
_USER_SITE = _os.path.join(_roaming_appdata(), "Python", "Python%d%d" % _sys.version_info[:2], "site-packages")
if _os.path.isdir(_USER_SITE) and _USER_SITE not in _sys.path:
    _site.addsitedir(_USER_SITE)

import collections
import ctypes
import http.client
import ipaddress
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

import instance

VERSION = "0.4.0.1"                  # bump on every release; the dashboard compares it with the latest GitHub release
ROOT = instance.CODE                     # shared code: static/, gallery/, media/*.py, vendor/
HOME = instance.HOME                     # this site's instance home: strata.json, data/, generated/ (see instance.py)
CONFIG_PATH = os.path.join(HOME, "strata.json")

DEFAULTS = {
    # who this instance is. Several sites run from the same code (instance.py); everything that must not collide
    # between them - cookies, API key prefix, Cloudflare list / rule names, the token variable - derives from here.
    "instance": {
        "id": "",                        # short id, e.g. "example"
        "name": "",                      # shown in the dashboard, e.g. "example.com"
        "prefix": "strata",              # cookies <prefix>_session, API keys <prefix>_..., CF list <prefix>_blacklist
        "token_env": "CF_API_TOKEN",     # environment variable that overrides cloudflare.api_token
        "accent": "",                    # default accent colour of this instance's dashboard (#rrggbb)
        "siblings": [],                  # [{"name", "url"}] - other Strata dashboards, linked in the sidebar
        "cdn_listen": ":8080",           # the CDN site block Strata renders (Caddyfile import)
        # how the tunnel is restarted after an ingress change: {"kind": "service"|"task", "name": "..."}
        "tunnel_restart": {},
        "dry_run": False,                # test instances: validate Caddy configs but never reload Caddy
        "update_repo": "Sanedish/strata",  # "owner/name" on GitHub: once a day, look for a newer release ("" = never)
    },
    "listen": "127.0.0.1:8090",          # admin UI + API (Caddy exposes it to the LAN)
    "feed_listen": "127.0.0.1:8081",     # redacted feed for Strata Telemetry - loopback only
    "feed_token_hash": "",               # sha256 of the telemetry token; generated on first start
    "auth": {"user": "", "password_hash": "", "session_hours": 336},
    "access_log": "",
    "db": "data/strata.db",
    "retention_days": 400,               # aggregated statistics (rollups, see rollup.py) - small, kept long
    "raw_retention_days": 30,            # individual requests (table req) - the expensive part at scale
    "caddy_exe": "caddy.exe",
    "caddy_metrics": "http://localhost:2019/metrics",
    "cloudflared_metrics": "auto",       # or an explicit http://127.0.0.1:PORT/metrics
    "cloudflared_config": os.path.expanduser("~/.cloudflared/config.yml"),
    "cloudflared_exe": "cloudflared",
    "storage_paths": [],
    "public_base_url": "",
    "upload_max_bytes": 20 * 1024 ** 3,
    "scrape_seconds": 2,
    "probe_seconds": 15,
    "compression": {
        "enabled": True,
        "roots": [],
        "scan_minutes": 30,
        "min_bytes": 1024,
        "max_bytes": 512 * 1024 ** 2,
        "min_saving": 0.05,              # keep a variant if it is at least 5 % smaller ...
        "min_saving_large": 0.20,        # ... or 20 % for files above large_bytes (not worth the disk otherwise)
        "large_bytes": 1024 ** 2,
        # Brotli only: Caddy's `encode` already does gzip/zstd on the fly, and Cloudflare asks the origin for br.
        "variants": ["br"],
        "extensions": ["html", "htm", "css", "js", "mjs", "cjs", "json", "map", "xml", "svg", "txt", "md", "csv",
                       "tsv", "wasm", "ttf", "otf", "eot", "ico", "bmp", "tga", "webmanifest", "gltf", "obj", "stl",
                       "ply", "dae", "fbx", "blend", "glsl", "frag", "vert", "yaml", "yml", "toml", "ini", "rtf",
                       "log", "psd", "tif", "tiff", "pdb", "srt", "vtt", "ass"],
    },
    "public": {
        "hosts": [],
        "hide_prefixes": [],             # top-level folders never named on the public page
        "k_anon": 3,                     # a country / folder is only named with at least this many visitors
    },
    "cloudflare": {"api_token": "", "zone_id": "", "zone_name": ""},
    # serving config: Strata renders the CDN site into <home>/generated/cdn.caddy (see rules.py)
    "caddyfile": "",
    "transform_listen": "127.0.0.1:8083",
    "gate_listen": "127.0.0.1:8085",     # gate.py: login in front of proxied services (forward_auth) - loopback only
    # Proxy drives ("services") pointing at this PC itself: allowed from the UI except reserved ports (Strata's and
    # Caddy's own admin / feeds / gates of every instance, monitoring, see rules.reserved_ports). A reserved port can
    # only be opened by listing the exact address here - deliberately never through the UI or the API.
    "proxy_local_allow": [],
    "proxy_reserved_ports": [],          # extra loopback ports the UI must never expose (on top of the built-in list)
    "sign_secret": "",                   # HMAC key for signed links; generated on first start
    "upload": {"chunk_mb": 32, "max_chunk_mb": 95, "parallel": 3, "stale_hours": 48},
    "versions_keep": 10,
    "gone_days": 30,                     # permanently deleted paths keep answering 404 + Clear-Site-Data this long
    # Smart-Sorting (static/storage.js): uploads at a drive root go to the user's home, sorted into type folders;
    # with the Files toggle on, uploads into any other folder get <folder>/css, /js and /<assets>/<type>/.
    "smartsort": {
        "homes": {},                     # user (case-insensitive) -> "drive id:folder"
        "root_to_home": False,
        "assets": "assets",
        "folders": {"image": "image", "gif": "gif", "video": "video", "audio": "audio", "archive": "arch",
                    "html": "html", "css": "css", "js": "js", "data": "data", "font": "font", "document": "doc",
                    "3d": "3d", "text": "text", "other": "misc"},
    },
    # short / share links: new ones expire after default_days; LinkGuard (rules.py) expires one early on abuse
    "links": {"default_days": 7,
              "abuse": {"enabled": True, "per_ip_10m": 60, "clicks_10m": 500, "countries_1h": 25,
                        "bot_min": 30, "bot_share": 0.8}},
    # Bot protection (anubis.py): off until the operator installs Anubis and switches it on. Nothing is bundled or started.
    "anubis": {"enabled": False,
               "bind": "",                    # Anubis' listen address; "" = 127.0.0.1:<8923 + this instance's port offset>
               "exe": "",                     # anubis.exe / anubis, for the start-up task ("" = the task is not offered)
               "difficulty": 4,               # leading zero hex digits of the proof of work (each +1 is ~16x the work)
               "defaults": True,              # also apply Anubis' shipped lists: deny known AI scrapers, allow real search crawlers
               "cookie_domain": "",           # registrable domain, never with a port; "" = one cookie per host
               "public_url": "https://",      # Anubis' --public-url: only the scheme. Without one its puzzle page redirects back to
                                              # itself; "http://" for a site that is not reached over Cloudflare's https
               "metrics": ""},                # "" = 127.0.0.1:<9923 + offset>
    # Crackdown (rules.py): suspects are left out of error rates, clear cases are banned at origin + Cloudflare.
    "autoban": {"enabled": True, "probes": 10, "window_minutes": 60, "ban_hours": 72,
                "credential_probes": 2,          # /.env, keys, cloud credentials: nobody legitimate asks twice
                "spray_errors": 20, "spray_paths": 15, "spray_minutes": 10,  # 4xx on many paths, >= 80 % errors
                "ua_rotation": 5,                # distinct user agents from one address within spray_minutes
                "fake_crawler_hits": 3,          # claims Googlebot/Bingbot/... but reverse DNS disagrees
                "suspect_probes": 2, "suspect_hours": 24,
                "repeat_factor": 4, "max_ban_days": 90,  # 72 h, then 12 d, then 48 d ... for repeat offenders
                "subnet_after": 3,               # auto-banned addresses in one /24 (/64) within 7 days -> ban it
                # never banned or flagged: forward-confirmed reverse DNS under these domains (real search and
                # security crawlers, e.g. Google Safe Browsing), plus the `safe` and `never` ranges
                "safe_domains": ["googlebot.com", "google.com", "gae.googleusercontent.com", "search.msn.com",
                                 "applebot.apple.com", "crawl.yahoo.net", "yandex.ru", "yandex.net", "yandex.com",
                                 "baidu.com", "baidu.jp", "petalsearch.com", "seznam.cz"],
                "safe": [],
                "never": ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "100.64.0.0/10", "127.0.0.0/8", "::1/128",
                          "fc00::/7"]},
    "alerts": {"resend_api_key": "", "from": "", "to": [], "min_severity": "warning", "max_per_hour": 12,
               "provider": "", "smtp": {"host": "", "port": 0, "security": "starttls", "user": "", "password": ""},
               "digest_hour": 8, "digest": "daily", "webhooks": []},
    # Strata Media (media/DESIGN.md): format negotiation, WebM variants, scan gate, circuit breaker.
    # rules.write_media_config() copies this section into media/media.json for media.py / worker.py.
    "media": {
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
        # image optimizer (media/OPTIMIZER.md). Defaults measured on this VM (2026-10-03, libavif 1.4.2/aom 3.14):
        # AVIF speed 8 is 1.5-2.5x faster than 7 for 0-17 % more bytes (hot path); speed 6 another 2x slower for
        # 0-27 % fewer bytes (background + re-encode of promoted variants). Encodes are demand driven only.
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
    },
}

_cfg_lock = threading.Lock()


def _merge(base, over):
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = v
    return base


def load_config():
    """DEFAULTS < strata.json < data/.env < the machine environment (secrets only, see instance.SECRETS)."""
    cfg = json.loads(json.dumps(DEFAULTS))
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, encoding="utf-8-sig") as f:
            _merge(cfg, json.load(f))
    return instance.overlay_secrets(cfg)


def _write_json(raw):
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(raw, f, indent=2)
        f.write("\n")
    os.replace(tmp, CONFIG_PATH)


def _move_secrets():
    """Secrets found in strata.json (an older Strata, setup.py, a hand edit) move to data/.env, overwriting what is
    there: Strata itself never writes one to strata.json, so a value found there is the newest. Then data/.env is
    locked down (it may have been created by hand)."""
    with _cfg_lock:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, encoding="utf-8-sig") as f:
                raw = json.load(f)
            found = instance.split_secrets(raw, raw)
            if found:
                keep = {k: v for k, v in found.items() if v}   # an empty value in strata.json never erases one
                if keep:
                    instance.env_write(keep)
                _write_json(raw)
                log("config: moved %d secret(s) from strata.json to data/.env" % len(keep))
        if os.path.exists(instance.env_path()):
            instance.lock_down(instance.env_path())


def prefixed(name):
    """`<instance prefix>_<name>`: cookie, API key, Cloudflare list and rule names that must differ per site."""
    return "%s_%s" % (CFG["instance"].get("prefix") or "strata", name)


def home_path(p):
    """Config paths may be relative to the instance home (e.g. "data/strata.db")."""
    return p if not p or os.path.isabs(p) else os.path.normpath(os.path.join(HOME, p))


def save_config(updates):
    """Merge `updates` into the config: secrets go to data/.env ("" / [] removes one), everything else into
    strata.json on disk (keeps whatever else the user put there). The running config gets all of it."""
    with _cfg_lock:
        raw = {}
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, encoding="utf-8-sig") as f:
                raw = json.load(f)
        plain = json.loads(json.dumps(updates))
        found = instance.split_secrets(plain, CFG)
        if found:
            instance.env_write(found)
        _merge(raw, plain)
        instance.split_secrets(raw, CFG)    # never a secret in strata.json
        _write_json(raw)
        _merge(CFG, updates)


CFG = load_config()
DB_PATH = home_path(CFG["db"])
RUNTIME_LOG_PATH = home_path(os.path.join("data", "strata.log"))
NCPU = os.cpu_count() or 1
STORAGE_ROOT = os.path.normpath(CFG["storage_paths"][0]) if CFG["storage_paths"] else HOME


_log_lock = threading.Lock()
_LOG_MAX = 16 * 1024 * 1024
_LOG_KEEP = 4
_LOG_SECRET = re.compile(r"(?i)(password|passwd|api[_-]?key|authorization|access[_-]?token|secret)\s*([:=])\s*([^\s,;]+)")


def log(*a):
    message = " ".join(str(x) for x in a)
    message = _LOG_SECRET.sub(lambda m: "%s%s[redacted]" % (m.group(1), m.group(2)), message)
    line = "%s %s\n" % (time.strftime("%Y-%m-%dT%H:%M:%S%z"), message)
    print(line, end="", flush=True)
    try:
        os.makedirs(os.path.dirname(RUNTIME_LOG_PATH), exist_ok=True)
        with _log_lock:
            if os.path.exists(RUNTIME_LOG_PATH) and os.path.getsize(RUNTIME_LOG_PATH) >= _LOG_MAX:
                oldest = RUNTIME_LOG_PATH + ".%d" % _LOG_KEEP
                if os.path.exists(oldest):
                    os.remove(oldest)
                for n in range(_LOG_KEEP - 1, 0, -1):
                    src, dst = RUNTIME_LOG_PATH + ".%d" % n, RUNTIME_LOG_PATH + ".%d" % (n + 1)
                    if os.path.exists(src):
                        os.replace(src, dst)
                os.replace(RUNTIME_LOG_PATH, RUNTIME_LOG_PATH + ".1")
            with open(RUNTIME_LOG_PATH, "a", encoding="utf-8", errors="replace") as f:
                f.write(line)
    except OSError:
        pass


try:  # on every start: leftovers in strata.json move to data/.env, and data/.env is locked down
    _move_secrets()
    instance.overlay_secrets(CFG)   # a value just moved out of strata.json is the newest
except Exception as e:  # never fatal, never silent
    log("config: could not secure data/.env: %s" % e)


_job = {"h": None}


def tie_to_me(proc):
    """Put a child process into a Windows job object that is killed when this process ends, so stopping the
    scheduled task never leaves media.py / worker.py running from an old code version. Best effort."""
    if sys.platform != "win32":
        return False
    try:
        k32 = ctypes.windll.kernel32
        if _job["h"] is None:
            class LIMIT(ctypes.Structure):
                _fields_ = [("a", ctypes.c_int64), ("b", ctypes.c_int64), ("flags", ctypes.c_uint32),
                            ("c", ctypes.c_size_t), ("d", ctypes.c_size_t), ("e", ctypes.c_uint32),
                            ("f", ctypes.c_size_t), ("g", ctypes.c_uint32), ("h", ctypes.c_uint32)]

            class EXT(ctypes.Structure):
                _fields_ = [("basic", LIMIT), ("io", ctypes.c_uint64 * 6), ("p", ctypes.c_size_t),
                            ("j", ctypes.c_size_t), ("pp", ctypes.c_size_t), ("pj", ctypes.c_size_t)]
            k32.CreateJobObjectW.restype = ctypes.c_void_p
            h = k32.CreateJobObjectW(None, None)
            info = EXT()
            info.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            k32.SetInformationJobObject(ctypes.c_void_p(h), 9, ctypes.byref(info), ctypes.sizeof(info))
            _job["h"] = h
        k32.OpenProcess.restype = ctypes.c_void_p
        ph = k32.OpenProcess(0x0101, False, proc.pid)  # PROCESS_SET_QUOTA | PROCESS_TERMINATE
        ok = bool(k32.AssignProcessToJobObject(ctypes.c_void_p(_job["h"]), ctypes.c_void_p(ph)))
        k32.CloseHandle(ctypes.c_void_p(ph))
        return ok
    except Exception:
        return False


# ---------------------------------------------------------------- file categories

CATEGORIES = {
    "image": "jpg jpeg png gif webp avif svg bmp ico tif tiff heic psd tga jxl",
    "video": "mp4 webm mkv mov avi m4v ts m3u8 wmv flv",
    "audio": "mp3 flac wav ogg opus m4a aac wma mid midi alac amr wv ape",
    "3d": "blend blend1 fbx obj glb gltf stl ply 3ds dae usd usdz max ma mb",
    "web": "html htm css js mjs cjs json xml map wasm webmanifest",
    "text": "txt md csv tsv log yaml yml toml ini rtf srt vtt ass",
    "font": "ttf otf woff woff2 eot",
    "archive": "zip 7z rar tar gz tgz bz2 xz zst br",
    "document": "pdf doc docx xls xlsx ppt pptx odt ods odp epub",
}
EXT_CAT = {e: c for c, exts in CATEGORIES.items() for e in exts.split()}


def ext_of(name):
    base = name.rsplit("/", 1)[-1]
    return base.rsplit(".", 1)[1].lower() if "." in base.strip(".") else ""


def category(name):
    return EXT_CAT.get(ext_of(name), "other")


# ---------------------------------------------------------------- log parsing

EMBED_RE = re.compile(r"discordbot|telegrambot|twitterbot|facebookexternalhit|slackbot|whatsapp|linkedinbot|"
                      r"skypeuripreview|redditbot|mastodon|vkshare|embedly|iframely|pinterestbot|bsky|cardyb", re.I)
PLAYER_RE = re.compile(r"\b(vlc|mpv|lavf|applecoremedia|stagefright|exoplayer|gstreamer|foobar|winamp|"
                       r"windows-media-player|nsplayer|kodi|jellyfin|plex)\b", re.I)
BOT_RE = re.compile(r"bot\b|bot/|crawl|spider|slurp|scan|curl|wget|python|go-http|httpclient|okhttp|java/|libwww|"
                    r"axios|node-fetch|undici|headless|phantom|zgrab|masscan|nmap|nuclei|censys|shodan|expanse|"
                    r"l9explore|httpx|fasthttp|aiohttp|scrapy|feedfetcher|uptime|monitor|powershell|postman|"
                    r"insomnia|palo alto|internetmeasurement|netcraft|dataprovider|ahrefs|semrush|petalbot", re.I)
SCAN_RE = re.compile(r"\.(php\d?|aspx?|jsp|cgi|env|git|sql|bak|old|ini|ya?ml|conf|log|swp|DS_Store)(/|$)|"
                     r"wp-|wordpress|phpmyadmin|pma/|/\.|/admin|/boaform|/cgi-bin|/vendor/|/actuator|/solr|/owa/|"
                     r"/ecp/|hnap1|/console|/manager/|/autodiscover|/telescope|/debug|/server-status|/config\.|"
                     r"/login|/setup|xmlrpc|/shell|eval-stdin|xdebug|\.\./|%2e%2e|/remote/|/api/v\d/|/geoserver|"
                     r"/sdk$|/evox|/cf_scripts|/druid|/jenkins|/_ignition|/containers/|graphql|/_profiler|"
                     r"/_environment|/__[a-z]|/rest/api/|webpack-stats|/sites/default|/storage/logs|/@fs/|"
                     r"/api/(config|env|debug|keys?|secrets?)\b", re.I)
# credential / secret grabs: a 4xx on one of these is never an honest mistake (autoban.credential_probes)
CRED_RE = re.compile(r"/\.(env|git|svn|hg|aws|ssh|docker|kube|azure|npmrc|pypirc|netrc|htpasswd|git-credentials|"
                     r"bash_history|boto|s3cfg|terraform)|/(id_rsa|id_dsa|id_ecdsa|id_ed25519)|aws-exports|"
                     r"/latest/meta-data|/computeMetadata/|service-?account[\w.-]*\.json|gcloud[\w.-]*\.json|"
                     r"/credentials?(\.(json|ya?ml|xml|txt|csv))?$|/secrets?\.(json|ya?ml|txt|env|toml)$|/proc/self|"
                     r"/etc/(passwd|shadow)|/var/run/secrets|wp-config|appsettings[\w.-]*\.json|/web\.config$|"
                     r"\.(pem|key|p12|pfx|jks|keystore|kdbx|ppk|tfstate)$|docker-compose[\w.-]*\.ya?ml$|phpinfo|"
                     r"/actuator/(env|heapdump)", re.I)
PROBE_UA = "strata-probe"
BROWSERS = ["Edge", "Opera", "Samsung", "Yandex", "Vivaldi", "Firefox", "Discord app", "Electron", "Chrome",
            "Safari", "Other browser"]
PLAYERS = {"lavf": "FFmpeg", "applecoremedia": "Apple Media", "stagefright": "Android Media"}


def classify_ua(ua):
    if not ua:
        return "bot", "(empty)", "-"
    m = EMBED_RE.search(ua)
    if m:
        return "embed", m.group(0).capitalize(), "-"
    m = PLAYER_RE.search(ua)
    if m:
        name = PLAYERS.get(m.group(1).lower(), m.group(1).upper() if len(m.group(1)) <= 3 else m.group(1).capitalize())
        return "player", name, os_of(ua)
    if BOT_RE.search(ua):
        m = re.search(r"[A-Za-z][\w\-.]{0,30}(?:bot|Bot|spider|Spider|crawler|Crawler)\b", ua)
        if not m:  # name it after the product token that tripped the bot check, e.g. "WindowsPowerShell"
            m = next((t for t in re.finditer(r"[A-Za-z][\w\-. ]*?(?=/|;|\)|$)", ua) if BOT_RE.search(t.group(0))), None)
        name = (m.group(0) if m else ua.split("/")[0])[:28].strip() or "bot"
        return "bot", name, "-"
    for pat, name in ((r"Edg[AeiO]?/", "Edge"), (r"OPR/|Opera", "Opera"), (r"SamsungBrowser", "Samsung"),
                      (r"YaBrowser", "Yandex"), (r"Vivaldi", "Vivaldi"), (r"Firefox/|FxiOS", "Firefox"),
                      (r"discord/", "Discord app"), (r"Electron/", "Electron"), (r"Chrome/|CriOS", "Chrome"),
                      (r"Version/.*Safari/", "Safari"), (r"Mozilla/", "Other browser")):
        if re.search(pat, ua):
            return "browser", name, os_of(ua)
    return "bot", ua.split("/")[0][:28] or "unknown", "-"


def os_of(ua):
    for pat, name in ((r"Windows", "Windows"), (r"Android", "Android"), (r"iPhone|iPad|iOS", "iOS"),
                      (r"Mac OS X|Macintosh", "macOS"), (r"CrOS", "ChromeOS"), (r"Linux", "Linux")):
        if re.search(pat, ua):
            return name
    return "-"


# url path (decoded) -> original size, for files that have precompressed variants (maintained by compress.py)
PRECOMP = {}


CHALLENGE_PATH = "/.within.website/"  # Anubis' own URL space (rules.render_challenge routes it to Anubis)


def parse_line(line):
    try:
        j = json.loads(line)
    except ValueError:
        return None
    if j.get("msg") != "handled request":
        return None
    r = j.get("request") or {}
    h = r.get("headers") or {}

    def hv(name):
        v = h.get(name)
        return v[0] if v else ""

    ua = hv("User-Agent")
    if ua == PROBE_UA:  # our own origin health checks
        return None
    uri = r.get("uri") or ""
    if uri.startswith(CHALLENGE_PATH) or ((j.get("resp_headers") or {}).get("Location") or [""])[0].startswith(CHALLENGE_PATH):
        return None  # Anubis (bot protection): challenge pages, solutions and the redirect to them are not traffic
    path, _, query = uri.partition("?")
    ray = hv("Cf-Ray")
    ref = hv("Referer")
    if ref:
        ref = urllib.parse.urlsplit(ref).hostname or ref[:80]
    kind, agent, osname = classify_ua(ua)
    status = int(j.get("status") or 0)
    size = int(j.get("size") or 0)
    rh = j.get("resp_headers") or {}
    ctype = (rh.get("Content-Type") or [""])[0].split(";")[0]
    enc = (rh.get("Content-Encoding") or [""])[0].lower()
    tag, mods = query_bits(query)
    scan, cred = probe_flags(uri, status)
    ip = r.get("client_ip") or r.get("remote_ip") or ""
    saved = 0
    if enc and status == 200:
        orig = PRECOMP.get(urllib.parse.unquote(path))
        if orig and orig > size:
            saved = orig - size
    return {
        "ts": float(j.get("ts") or time.time()),
        "host": (r.get("host") or "").split(":")[0].lower()[:120],
        "method": (r.get("method") or "")[:10],
        "path": path[:600],
        "query": 1 if query else 0,
        "status": status,
        "bytes": size,
        "dur": round(float(j.get("duration") or 0) * 1000, 3),  # ms
        "ip": ip,
        "country": hv("Cf-Ipcountry")[:3],
        "colo": ray.rsplit("-", 1)[1][:4] if "-" in ray else ("LAN" if not ray else ""),
        "ua": ua[:400],
        "agent": agent,
        "os": osname,
        "kind": kind,
        "ref": (ref or "")[:120],
        "ctype": ctype[:60],
        "proto": r.get("proto") or "",
        "scan": scan,
        "cred": cred,  # not stored: only feeds the credential-grab autoban in rules.on_rows
        "enc": enc[:12],
        "saved": saved,
        "tag": tag,
        "mods": mods,
        "blocked": "",
        # why this request stays out of error rates ('' = counted); rules.on_rows adds blacklist / suspect reasons
        "sus": "probe" if scan else "internal" if internal(ip, ua, path) else "",
    }


INTERNAL_PATH = re.compile(r"^/strata-(bin-)?selftest(/|$)", re.I)


def internal(ip, ua, path):
    """Strata's own tests and loopback requests: real visitors never look like this."""
    return ua.startswith("strata-") or ip.startswith("127.") or ip == "::1" or bool(INTERNAL_PATH.match(path))


def probe_flags(uri, status):
    """(scan, cred) for a failed request: a known probe path, and the stronger credential / secret grab.
    Checks the raw and the decoded path, so /%2eenv and /%252e%252e/ count too."""
    if status < 400:
        return 0, 0
    path = uri.partition("?")[0]
    dec = urllib.parse.unquote(urllib.parse.unquote(path))
    cred = 1 if CRED_RE.search(dec) else 0
    return (1 if cred or SCAN_RE.search(uri) or SCAN_RE.search(dec) else 0), cred


TAG_KEYS = ("t", "utm_campaign", "utm_source", "ref", "src")
MOD_KEYS = ("w", "h", "fit", "fm", "q", "dl", "ver", "v", "exp")
SAFE_VAL = re.compile(r"[^A-Za-z0-9._\-]")


def query_bits(query):
    """Tracking tag (?t= / utm_*) and link modifiers (?w=&fm=...) from a raw query string."""
    if not query:
        return "", ""
    try:
        q = urllib.parse.parse_qs(query, keep_blank_values=True)
    except ValueError:
        return "", ""
    tag = next((SAFE_VAL.sub("", q[k][0])[:40] for k in TAG_KEYS if q.get(k) and q[k][0]), "")
    mods = ",".join("%s=%s" % (k, SAFE_VAL.sub("", q[k][0])[:12]) for k in MOD_KEYS if k in q)[:80]
    return tag, mods


COLS = ["ts", "host", "method", "path", "query", "status", "bytes", "dur", "ip", "country", "colo",
        "ua", "agent", "os", "kind", "ref", "ctype", "proto", "scan", "enc", "saved", "tag", "mods", "blocked", "sus"]
ROW_HOOKS = []  # f(rows) called by the tailer before rows are stored (blacklist attribution, link clicks, autoban)
STORED_HOOKS = []  # f(rows) after they are stored, with their final flags (rollup.on_rows)
CLEAN = "coalesce(sus,'')=''"  # SQL: a request that counts towards error rates

# address -> (until, reason): clients whose traffic is left out of error rates (maintained by rules.on_rows)
SUSPECT = {}


def suspects():
    t = time.time()
    return {ip for ip, (until, _) in list(SUSPECT.items()) if until > t}


# This site's own public address(es), as Cloudflare sees them: the household and Strata's own tests reach the CDN
# from here, so the crackdown never flags or bans them. Dynamic, so re-learned every 30 min and remembered 7 days.
OWN_TRACE = "https://www.cloudflare.com/cdn-cgi/trace"
_own = {"t": 0, "ips": None, "busy": False}
_own_lock = threading.Lock()


def refresh_own(db=None):
    mine = db is None
    db = db or connect()
    try:
        ips = _own["ips"] if _own["ips"] is not None else dict(get_meta(db, "own_ips", {}) or {})
        try:
            with urllib.request.urlopen(OWN_TRACE, timeout=8) as f:
                m = re.search(r"^ip=(\S+)$", f.read().decode("utf-8", "replace"), re.M)
            if m:
                ipaddress.ip_address(m.group(1))
                ips[m.group(1)] = time.time()
        except Exception as e:
            log("own address lookup failed: %s" % e)
        ips = {ip: seen for ip, seen in ips.items() if seen > time.time() - 7 * 86400}
        with db:
            set_meta(db, "own_ips", ips)
        _own["ips"] = ips
    finally:
        _own["t"] = time.time()
        if mine:
            db.close()


def own_ips(max_age=1800):
    """Own public addresses. Refreshes in the background when older than max_age; max_age <= 60 waits for it."""
    if time.time() - _own["t"] > max_age:
        if max_age <= 60:
            with _own_lock:
                if time.time() - _own["t"] > max_age:
                    refresh_own()
        elif not _own["busy"]:
            _own["busy"] = True

            def run():
                try:
                    with _own_lock:
                        refresh_own()
                finally:
                    _own["busy"] = False
            threading.Thread(target=run, name="own-ip", daemon=True).start()
    return set(_own["ips"] or ())


# ---------------------------------------------------------------- storage

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS req(ts REAL NOT NULL, host TEXT, method TEXT, path TEXT, query INTEGER,
  status INTEGER, bytes INTEGER, dur REAL, ip TEXT, country TEXT, colo TEXT, ua TEXT, agent TEXT, os TEXT,
  kind TEXT, ref TEXT, ctype TEXT, proto TEXT, scan INTEGER);
CREATE INDEX IF NOT EXISTS req_ts ON req(ts);
CREATE INDEX IF NOT EXISTS req_ip ON req(ip, ts);
CREATE INDEX IF NOT EXISTS req_path ON req(path, ts);
CREATE TABLE IF NOT EXISTS metric(key TEXT NOT NULL, ts INTEGER NOT NULL, val REAL, PRIMARY KEY(key, ts)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS cfile(path TEXT NOT NULL, variant TEXT NOT NULL, orig INTEGER, size INTEGER,
  mtime REAL, created REAL, secs REAL, PRIMARY KEY(path, variant)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS crun(ts REAL, trigger TEXT, scanned INTEGER, compressed INTEGER, skipped INTEGER,
  bytes_in INTEGER, bytes_out INTEGER, removed INTEGER, errors INTEGER, secs REAL, note TEXT);
CREATE TABLE IF NOT EXISTS audit(ts REAL, ip TEXT, user TEXT, action TEXT, target TEXT, ok INTEGER, note TEXT);
CREATE TABLE IF NOT EXISTS mount(id INTEGER PRIMARY KEY, name TEXT, kind TEXT, path TEXT, prefix TEXT, hosts TEXT,
  cache TEXT, precompress INTEGER DEFAULT 1, browse INTEGER DEFAULT 0, transforms INTEGER DEFAULT 1,
  enabled INTEGER DEFAULT 1, sort INTEGER DEFAULT 0, note TEXT, created REAL, updated REAL);
CREATE TABLE IF NOT EXISTS rule(id INTEGER PRIMARY KEY, name TEXT, mount INTEGER, patterns TEXT, action TEXT,
  params TEXT, enabled INTEGER DEFAULT 1, sort INTEGER DEFAULT 0, expires REAL, note TEXT, builtin INTEGER DEFAULT 0,
  created REAL, updated REAL, hits INTEGER DEFAULT 0, last_hit REAL);
CREATE TABLE IF NOT EXISTS blacklist(id INTEGER PRIMARY KEY, kind TEXT, value TEXT, action TEXT DEFAULT 'block',
  scope TEXT DEFAULT 'both', enabled INTEGER DEFAULT 1, expires REAL, note TEXT, source TEXT, created REAL,
  hits INTEGER DEFAULT 0, last_hit REAL);
CREATE TABLE IF NOT EXISTS link(code TEXT PRIMARY KEY, mount INTEGER, path TEXT, url TEXT, mods TEXT, expires REAL,
  max_clicks INTEGER, enabled INTEGER DEFAULT 1, note TEXT, created REAL, clicks INTEGER DEFAULT 0, last_click REAL);
CREATE TABLE IF NOT EXISTS fidx(mount INTEGER NOT NULL, path TEXT NOT NULL, parent TEXT, name TEXT, ext TEXT,
  cat TEXT, size INTEGER, mtime REAL, depth INTEGER, qhash TEXT, hash TEXT, PRIMARY KEY(mount, path)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS fidx_parent ON fidx(mount, parent);
CREATE INDEX IF NOT EXISTS fidx_size ON fidx(size);
CREATE TABLE IF NOT EXISTS fdir(mount INTEGER NOT NULL, path TEXT NOT NULL, parent TEXT, files INTEGER, dirs INTEGER,
  bytes INTEGER, newest REAL, cats TEXT, PRIMARY KEY(mount, path)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS fversion(mount INTEGER NOT NULL, path TEXT NOT NULL, n INTEGER NOT NULL, size INTEGER,
  mtime REAL, created REAL, stored TEXT, user TEXT, note TEXT, PRIMARY KEY(mount, path, n)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS upload(id TEXT PRIMARY KEY, mount INTEGER, path TEXT, size INTEGER, chunk INTEGER,
  chunks INTEGER, received TEXT, policy TEXT, fingerprint TEXT, user TEXT, tmp TEXT, created REAL, updated REAL);
CREATE TABLE IF NOT EXISTS confhist(id INTEGER PRIMARY KEY, ts REAL, user TEXT, reason TEXT, content TEXT,
  sha TEXT, ok INTEGER, error TEXT);
CREATE TABLE IF NOT EXISTS alert(id INTEGER PRIMARY KEY, ts REAL, kind TEXT, severity TEXT, title TEXT, detail TEXT,
  key TEXT, sent INTEGER DEFAULT 0, ack INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS alert_ts ON alert(ts);
CREATE TABLE IF NOT EXISTS session(hash TEXT PRIMARY KEY, user TEXT, exp REAL, ip TEXT, created REAL, ttl REAL);
CREATE TABLE IF NOT EXISTS binpath(mount INTEGER NOT NULL, path TEXT NOT NULL, dir INTEGER, state TEXT, ts REAL,
  PRIMARY KEY(mount, path)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS purgeq(kind TEXT NOT NULL, value TEXT NOT NULL, added REAL, tries INTEGER DEFAULT 0,
  PRIMARY KEY(kind, value)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS gate_user(mount INTEGER NOT NULL, user TEXT NOT NULL, hash TEXT, totp TEXT, created REAL,
  PRIMARY KEY(mount, user)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS gate_session(hash TEXT PRIMARY KEY, mount INTEGER, user TEXT, host TEXT, exp REAL,
  created REAL, ip TEXT);
CREATE TABLE IF NOT EXISTS account(user TEXT PRIMARY KEY COLLATE NOCASE, email TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'employee', permissions TEXT NOT NULL DEFAULT '[]',
  enabled INTEGER NOT NULL DEFAULT 1, email_verified INTEGER NOT NULL DEFAULT 0,
  privacy_version TEXT NOT NULL DEFAULT '', privacy_ts REAL, created REAL NOT NULL, updated REAL NOT NULL,
  last_login REAL);
CREATE TABLE IF NOT EXISTS account_zone(id INTEGER PRIMARY KEY, user TEXT NOT NULL COLLATE NOCASE,
  mount INTEGER NOT NULL, path TEXT NOT NULL DEFAULT '/', access TEXT NOT NULL DEFAULT 'read',
  created REAL NOT NULL, created_by TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS account_zone_user ON account_zone(user, mount);
CREATE TABLE IF NOT EXISTS account_code(user TEXT PRIMARY KEY COLLATE NOCASE, email TEXT NOT NULL,
  digest TEXT NOT NULL, expires REAL NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, purpose TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS account_invite(token_hash TEXT PRIMARY KEY, user TEXT NOT NULL COLLATE NOCASE,
  email TEXT NOT NULL, expires REAL NOT NULL, created_by TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_event(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, ip TEXT NOT NULL,
  user TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL DEFAULT '', ok INTEGER NOT NULL DEFAULT 1,
  note TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS audit_event_ts ON audit_event(ts DESC, id DESC);
CREATE INDEX IF NOT EXISTS audit_event_user ON audit_event(user, ts DESC);
CREATE INDEX IF NOT EXISTS audit_event_action ON audit_event(action, ts DESC);
CREATE TRIGGER IF NOT EXISTS audit_event_no_update BEFORE UPDATE ON audit_event
  BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_event_no_delete BEFORE DELETE ON audit_event
  BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END;
CREATE TABLE IF NOT EXISTS office_note(id INTEGER PRIMARY KEY, ts REAL NOT NULL, author TEXT NOT NULL COLLATE NOCASE,
  target TEXT NOT NULL DEFAULT '' COLLATE NOCASE, body TEXT NOT NULL, private INTEGER NOT NULL DEFAULT 0,
  pinned INTEGER NOT NULL DEFAULT 0, edited REAL);
CREATE INDEX IF NOT EXISTS office_note_target ON office_note(target, ts DESC);
CREATE TABLE IF NOT EXISTS office_seen(user TEXT PRIMARY KEY COLLATE NOCASE, board REAL, notes REAL);
"""
MIGRATIONS = [("req", "enc", "TEXT"), ("req", "saved", "INTEGER DEFAULT 0"), ("req", "tag", "TEXT"),
              ("req", "mods", "TEXT"), ("req", "blocked", "TEXT"), ("mount", "edge_cache", "TEXT"),
              ("req", "sus", "TEXT DEFAULT ''"), ("mount", "gate", "TEXT"), ("mount", "strip", "INTEGER DEFAULT 1"),
              # account constraints, pfps, preference sync, per-zone capabilities & share-link ownership control
              ("account", "expires", "REAL"), ("account", "allowed_ips", "TEXT NOT NULL DEFAULT ''"),
              ("account", "session_hours", "REAL"), ("account", "note", "TEXT NOT NULL DEFAULT ''"),
              ("account", "avatar", "TEXT NOT NULL DEFAULT ''"), ("account", "prefs", "TEXT NOT NULL DEFAULT ''"),
              ("account_zone", "caps", "TEXT"), ("account_zone", "expires", "REAL"),
              ("link", "owner", "TEXT NOT NULL DEFAULT ''"),
              # administrative members, profile fields (e.g, title, status, ...), coarse last-seen time
              ("account", "administrative", "INTEGER NOT NULL DEFAULT 0"), ("account", "profile", "TEXT NOT NULL DEFAULT ''"),
              ("account", "last_seen", "REAL")]


def connect():
    db = sqlite3.connect(DB_PATH, timeout=15, check_same_thread=False)
    db.execute("PRAGMA busy_timeout=15000")
    return db


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = connect()
    db.executescript(SCHEMA)
    for table, col, typ in MIGRATIONS:
        if col not in [r[1] for r in db.execute("PRAGMA table_info(%s)" % table)]:
            db.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, col, typ))
    import rollup
    rollup.init(db)
    # Ensure the original activity table is read-only and will only be appended to the ledger once.
    if not get_meta(db, "audit_event_v1", False):
        db.execute("INSERT INTO audit_event(ts,ip,user,action,target,ok,note) "
                   "SELECT ts,ip,user,action,target,ok,note FROM audit")
        set_meta(db, "audit_event_v1", True)
    db.commit()
    try:
        if get_meta(db, "sus_backfill") != 1:
            n = backfill_sus(db)
            with db:
                set_meta(db, "sus_backfill", 1)
            log("suspicious-traffic backfill: ignoring %d in error log" % n)
    finally:
        db.close()


def backfill_sus(db):
    """storing requests the same as the tailer does (e.g, new probe patterns, blacklist hits, internal
       tests, and addresses that probed, sprayed 4xx or rotated user agents within an hour of each other)."""
    ab = CFG["autoban"]
    # Current self-address and previous self-tests (strata-*) through Cloudflare
    seen = dict(get_meta(db, "own_ips", {}) or {})
    for ip, last in db.execute("SELECT ip, max(ts) FROM req WHERE ua LIKE 'strata-%' AND colo != 'LAN' GROUP BY ip"):
        if ip and not internal(ip, "", "") and last > time.time() - 7 * 86400:
            seen[ip] = max(seen.get(ip, 0), last)
    with db:
        set_meta(db, "own_ips", seen)
    refresh_own(db)
    own = own_ips(10 ** 9)
    with db:
        for rid, path, status in db.execute("SELECT rowid, path, status FROM req WHERE status>=400 AND scan=0").fetchall():
            if probe_flags(path or "", status)[0]:
                db.execute("UPDATE req SET scan=1 WHERE rowid=?", [rid])
        db.execute("UPDATE req SET sus='probe' WHERE scan=1 AND " + CLEAN)
        db.execute("UPDATE req SET sus='blacklist' WHERE blocked LIKE 'bl:%' AND " + CLEAN)
        db.executemany("UPDATE req SET sus='internal' WHERE rowid=?", [(rid,) for rid, ip, ua, path in db.execute(
            "SELECT rowid, ip, ua, path FROM req WHERE " + CLEAN).fetchall() if internal(ip or "", ua or "", path or "")])
        spans = []
        for ip, t, why in db.execute(
                """SELECT ip, CAST(ts/600 AS INTEGER)*600 t, CASE
                     WHEN sum(scan) >= ? THEN 'scanner' WHEN count(DISTINCT ua) >= ? THEN 'rotating-ua'
                     ELSE 'error-spray' END FROM req WHERE colo != 'LAN' GROUP BY ip, t
                   HAVING sum(scan) >= ? OR count(DISTINCT ua) >= ?
                     OR (sum(status>=400) >= ? AND count(DISTINCT CASE WHEN status>=400 THEN path END) >= ?
                         AND sum(status>=400) >= 0.8 * count(*))""",
                [ab["suspect_probes"], ab["ua_rotation"], ab["suspect_probes"], ab["ua_rotation"],
                 ab["spray_errors"], ab["spray_paths"]]).fetchall():
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if ip not in own and not any(addr in ipaddress.ip_network(n, strict=False)
                                         for n in list(ab.get("never", [])) + list(ab.get("safe", []))):
                spans.append((why, ip, t - 3600, t + ab["suspect_hours"] * 3600))
        db.executemany("UPDATE req SET sus=? WHERE ip=? AND ts>=? AND ts<? AND " + CLEAN, spans)
    return db.execute("SELECT count(*) FROM req WHERE NOT " + CLEAN).fetchone()[0]


def get_meta(db, k, default=None):
    row = db.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
    return json.loads(row[0]) if row else default


def version_tuple(v):
    """'v1.10.0' -> (1, 10, 0): numeric, so 1.10 sorts after 1.9."""
    return tuple(int(x) for x in re.findall(r"\d+", str(v))[:3])


def check_update():
    """Store the latest GitHub release tag in meta 'latest_release' (no-op without instance.update_repo)."""
    repo = CFG["instance"].get("update_repo") or ""
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", repo):
        return
    req = urllib.request.Request("https://api.github.com/repos/%s/releases/latest" % repo,
                                 headers={"Accept": "application/vnd.github+json", "User-Agent": "Strata/" + VERSION})
    with urllib.request.urlopen(req, timeout=20) as r:
        rel = json.load(r)
    db = connect()
    try:
        with db:
            set_meta(db, "latest_release", {"tag": str(rel.get("tag_name") or "")[:40],
                                            "url": "https://github.com/%s/releases/latest" % repo, "ts": time.time()})
    finally:
        db.close()


def set_meta(db, k, v):
    db.execute("INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, json.dumps(v)))


def audit(ip, user, action, target, ok=True, note=""):
    ts = time.time()
    target = str(target or "")[:600]
    note = str(note or "")[:300]
    try:
        db = connect()
        with db:
            db.execute("INSERT INTO audit VALUES(?,?,?,?,?,?,?)", (ts, ip, user, action, target, int(ok), note))
            db.execute("INSERT INTO audit_event(ts,ip,user,action,target,ok,note) VALUES(?,?,?,?,?,?,?)",
                       (ts, str(ip or "")[:80], str(user or "")[:100], str(action or "event")[:100], target,
                        int(bool(ok)), note))
        db.close()
    except Exception:
        log("audit error:\n" + traceback.format_exc())


def audit_event(ip, user, action, target="", ok=True, note=""):
    """Append a user-facing event to the immutable event ledger (never accepts actor identity from the client)."""
    try:
        db = connect()
        with db:
            db.execute("INSERT INTO audit_event(ts,ip,user,action,target,ok,note) VALUES(?,?,?,?,?,?,?)",
                       (time.time(), str(ip or "")[:80], str(user or "")[:100], str(action or "event")[:100],
                        str(target or "")[:600], int(bool(ok)), str(note or "")[:300]))
        db.close()
    except Exception:
        log("audit event error:\n" + traceback.format_exc())


# ---------------------------------------------------------------- mounts (drives Caddy serves; managed in rules.py)

_mount_cache = {"v": None}
_mount_lock = threading.Lock()


def mounts(refresh=False):
    with _mount_lock:
        if refresh or _mount_cache["v"] is None:
            db = connect()
            try:
                rows = rows_of(db.execute("SELECT * FROM mount ORDER BY sort, id"))
            finally:
                db.close()
            for r in rows:
                r["hosts"] = json.loads(r["hosts"] or "[]")
            _mount_cache["v"] = rows
        return [dict(m) for m in _mount_cache["v"]]


def file_mounts(enabled_only=True):
    return [m for m in mounts() if m["kind"] in ("files", "page") and (m["enabled"] or not enabled_only)]


def mount(mid):
    try:
        mid = int(mid)
    except (TypeError, ValueError):
        return None
    return next((m for m in mounts() if m["id"] == mid), None)


def primary_mount():
    fm = [m for m in file_mounts() if m["kind"] == "files"]
    return fm[0] if fm else None


# ---------------------------------------------------------------- live window (in memory)

# latency histogram edges in ms (upper bounds). This is shared by the live window and rollups (agg_lat).
LAT_EDGES = [0.25, 0.5, 1, 2, 3, 5, 7.5, 10, 15, 25, 35, 50, 75, 100, 150, 250, 350, 500, 750, 1000, 1500, 2500,
             5000, 10000, float("inf")]


def lat_bucket(ms):
    for i, e in enumerate(LAT_EDGES):
        if ms < e:
            return i
    return len(LAT_EDGES) - 1


def hist_percentile(hist, p):
    """Percentile from a LAT_EDGES histogram (linear inside the bucket)."""
    n = sum(hist)
    if not n:
        return 0
    want, acc = n * p, 0
    for i, c in enumerate(hist):
        if c and acc + c >= want:
            lo = LAT_EDGES[i - 1] if i else 0
            hi = LAT_EDGES[i] if LAT_EDGES[i] != float("inf") else (lo * 2 or 1)
            return lo + (hi - lo) * (want - acc) / c
        acc += c
    return LAT_EDGES[-2]


class Live:
    """Per-second buckets for the last 10 minutes, fed straight from the tailer. Errors (e4/e5/err_pct) count clean
    traffic only: rows flagged `sus` are left out, and so are addresses in SUSPECT, retroactively, because the
    buckets keep clean counts per address ("c": ip -> [requests, 4xx, 5xx]). Latency is a fixed histogram per
    second, so percentiles cost the same at 1 or 10,000 requests per second."""
    SPAN = 600

    @staticmethod
    def clean(b, bad):
        n = e4 = e5 = 0
        for ip, c in b["c"].items():
            if ip not in bad:
                n += c[0]; e4 += c[1]; e5 += c[2]
        return n, e4, e5

    def __init__(self):
        self.lock = threading.Lock()
        self.sec = {}
        self.recent = collections.deque(maxlen=400)

    def add(self, rows):
        cutoff = time.time() - self.SPAN
        with self.lock:
            for r in rows:
                self.recent.append(r)
                if r["ts"] < cutoff:
                    continue
                b = self.sec.get(int(r["ts"]))
                if b is None:
                    b = self.sec[int(r["ts"])] = {"n": 0, "b": 0, "e4": 0, "e5": 0, "d": [0] * len(LAT_EDGES),
                                                  "ip": set(), "c": {}}
                b["n"] += 1
                b["b"] += r["bytes"]
                b["e4"] += 400 <= r["status"] < 500
                b["e5"] += r["status"] >= 500
                b["d"][lat_bucket(r["dur"])] += 1
                b["ip"].add(r["ip"])
                if not r.get("sus"):
                    c = b["c"].setdefault(r["ip"], [0, 0, 0])
                    c[0] += 1
                    c[1] += 400 <= r["status"] < 500
                    c[2] += r["status"] >= 500
            for k in [k for k in self.sec if k < cutoff]:
                del self.sec[k]

    def series(self, n=300):
        end = int(time.time())
        bad = suspects()
        with self.lock:
            out = {"t0": end - n, "step": 1, "reqs": [], "bytes": [], "e4": [], "e5": [], "sus": []}
            for t in range(end - n, end):
                b = self.sec.get(t)
                cn, e4, e5 = self.clean(b, bad) if b else (0, 0, 0)
                out["reqs"].append(b["n"] if b else 0)
                out["bytes"].append(b["b"] if b else 0)
                out["e4"].append(e4)
                out["e5"].append(e5)
                out["sus"].append(b["n"] - cn if b else 0)
        return out

    def window(self, sec=60):
        end = int(time.time())
        bad = suspects()
        n = by = e = cn = e4 = e5 = 0
        hist, ips = [0] * len(LAT_EDGES), set()
        with self.lock:
            for t in range(end - sec, end + 1):
                b = self.sec.get(t)
                if b:
                    n += b["n"]; by += b["b"]; e += b["e4"] + b["e5"]
                    for i, x in enumerate(b["d"]):
                        hist[i] += x
                    ips |= b["ip"]
                    c = self.clean(b, bad)
                    cn += c[0]; e4 += c[1]; e5 += c[2]
        return {"reqs": n, "bytes": by, "rps": n / sec, "bps": by / sec, "uniq": len(ips),
                "clean": cn, "sus": n - cn, "e4": e4, "e5": e5,
                "err_pct": ((e4 + e5) / cn * 100) if cn else 0,  # suspicious traffic left out
                "err_all_pct": (e / n * 100) if n else 0, "p50": hist_percentile(hist, 0.5),
                "p95": hist_percentile(hist, 0.95), "p99": hist_percentile(hist, 0.99)}

    def tail(self, n=40):
        with self.lock:
            return list(self.recent)[-n:][::-1]


# ---------------------------------------------------------------- access-log tailer

class Tailer(threading.Thread):
    daemon = True

    def __init__(self, live):
        super().__init__(name="tailer")
        self.live = live
        self.path = CFG["access_log"]
        self.fid, self.pos, self.buf = None, 0, b""

    def run(self):
        db = connect()
        st = get_meta(db, "tail", {})
        self.fid, self.pos = st.get("ident"), st.get("pos", 0)
        backlog = True
        while True:
            try:
                n = self.pump(db)
                if backlog and n == 0:
                    backlog = False
                    log("tailer: caught up at", self.path, "offset", self.pos)
            except Exception:
                n = 0
                log("tailer error:\n" + traceback.format_exc())
            time.sleep(0.05 if n else 0.5)

    @staticmethod
    def fid_of(st):
        return "%s:%s" % (st.st_dev, st.st_ino)

    def drain_rotated(self, db):
        """Caddy renames access.log on rotation - finish reading the tail of the old file."""
        d = os.path.dirname(self.path) or "."
        for name in os.listdir(d):
            p = os.path.join(d, name)
            try:
                if name.startswith("access") and self.fid_of(os.stat(p)) == self.fid and p != self.path:
                    with open(p, "rb") as f:
                        f.seek(self.pos)
                        self.ingest(db, f.read(), final=True)
                    return
            except OSError:
                pass

    def pump(self, db):
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return 0
        ident = self.fid_of(st)
        if ident != self.fid:
            if self.fid:
                self.drain_rotated(db)
            self.fid, self.pos, self.buf = ident, 0, b""
        if st.st_size < self.pos:
            self.pos, self.buf = 0, b""
        if st.st_size == self.pos:
            return 0
        # open/read/close each time: holding the file open on Windows would block Caddy's log rotation
        with open(self.path, "rb") as f:
            f.seek(self.pos)
            chunk = f.read(8 * 1024 * 1024)
        self.pos += len(chunk)
        return self.ingest(db, chunk)

    def ingest(self, db, chunk, final=False):
        lines = (self.buf + chunk).split(b"\n")
        self.buf = b"" if final else lines.pop()
        rows = [r for r in (parse_line(l) for l in lines if l.strip()) if r]
        for hook in ROW_HOOKS:
            try:
                hook(rows)
            except Exception:
                log("row hook error:\n" + traceback.format_exc())
        with db:
            if rows:
                db.executemany("INSERT INTO req(%s) VALUES(%s)" % (",".join(COLS), ",".join("?" * len(COLS))),
                               [tuple(r[c] for c in COLS) for r in rows])
            set_meta(db, "tail", {"ident": self.fid, "pos": self.pos - len(self.buf)})
        for hook in STORED_HOOKS:
            try:
                hook(rows)
            except Exception:
                log("stored-row hook error:\n" + traceback.format_exc())
        self.live.add(rows)
        return len(rows) or len(chunk)


# ---------------------------------------------------------------- prometheus scraping

PROM_RE = re.compile(r"^([a-zA-Z_:][\w:]*)(?:\{(.*)\})?\s+(\S+)")
LABEL_RE = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')


def prom_text(url, timeout=2):
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def prom(url):
    out = collections.defaultdict(list)
    for line in prom_text(url).splitlines():
        if not line or line[0] == "#":
            continue
        m = PROM_RE.match(line)
        if m:
            try:
                out[m.group(1)].append((dict(LABEL_RE.findall(m.group(2) or "")), float(m.group(3))))
            except ValueError:
                pass
    return out


def one(d, name, default=None):
    v = d.get(name)
    return v[0][1] if v else default


def total(d, name):
    return sum(v for _, v in d.get(name, []))


class Rate:
    def __init__(self):
        self.prev = {}

    def __call__(self, key, value, now):
        p = self.prev.get(key)
        self.prev[key] = (now, value)
        if not p or value is None or p[1] is None or now <= p[0] or value < p[1]:
            return None
        return (value - p[1]) / (now - p[0])


class FILETIME(ctypes.Structure):
    _fields_ = [("lo", ctypes.c_uint32), ("hi", ctypes.c_uint32)]


class MEMSTAT(ctypes.Structure):
    _fields_ = [("dwLength", ctypes.c_uint32), ("dwMemoryLoad", ctypes.c_uint32),
                ("ullTotalPhys", ctypes.c_uint64), ("ullAvailPhys", ctypes.c_uint64),
                ("ullTotalPageFile", ctypes.c_uint64), ("ullAvailPageFile", ctypes.c_uint64),
                ("ullTotalVirtual", ctypes.c_uint64), ("ullAvailVirtual", ctypes.c_uint64),
                ("ullAvailExtendedVirtual", ctypes.c_uint64)]


def host_sample():
    if sys.platform != "win32":
        return None
    k32 = ctypes.windll.kernel32
    idle, kern, user = FILETIME(), FILETIME(), FILETIME()
    k32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kern), ctypes.byref(user))
    ft = lambda f: (f.hi << 32) | f.lo
    m = MEMSTAT()
    m.dwLength = ctypes.sizeof(MEMSTAT)
    k32.GlobalMemoryStatusEx(ctypes.byref(m))
    k32.GetTickCount64.restype = ctypes.c_uint64
    return {"idle": ft(idle), "busy": ft(kern) + ft(user), "mem_total": m.ullTotalPhys,
            "mem_used": m.ullTotalPhys - m.ullAvailPhys, "uptime": k32.GetTickCount64() / 1000}


class Metrics(threading.Thread):
    daemon = True
    HIST = 180  # samples kept for sparklines

    def __init__(self):
        super().__init__(name="metrics")
        self.lock = threading.Lock()
        self.rate = Rate()
        self.caddy, self.tunnel, self.host = {"up": False}, {"up": False}, {}
        self.hist = collections.defaultdict(lambda: collections.deque(maxlen=self.HIST))
        self.minute = collections.defaultdict(list)
        self.prev_host = None
        self.cfd_url = None
        self.caddy_version = self.read_caddy_version()

    @staticmethod
    def read_caddy_version():
        try:
            out = subprocess.run([CFG["caddy_exe"], "version"], capture_output=True, text=True, timeout=10,
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout
            return out.split()[0] if out else ""
        except Exception:
            return ""

    def push(self, key, val):
        if val is None:
            return
        self.hist[key].append(round(val, 3))
        self.minute[key].append(val)

    def find_cloudflared(self):
        """cloudflared will pick up the first free port in the range 20241 - 20245 - This function attempts to find the live one."""
        if CFG["cloudflared_metrics"] != "auto":
            return CFG["cloudflared_metrics"]
        if self.cfd_url:
            return self.cfd_url
        for port in range(20241, 20251):
            url = "http://127.0.0.1:%d/metrics" % port
            try:
                if "cloudflared_tunnel_ha_connections" in prom_text(url, timeout=0.5):
                    self.cfd_url = url
                    return url
            except Exception:
                pass
        raise RuntimeError("no cloudflared metrics endpoint on 127.0.0.1:20241-20250")

    def run(self):
        db = connect()
        last_flush = int(time.time() // 60)
        while True:
            now = time.time()
            try:
                self.scrape_caddy(now)
            except Exception as e:
                with self.lock:
                    self.caddy = {"up": False, "error": str(e)[:200], "version": self.caddy_version}
                    self.push("caddy_up", 0)
            try:
                self.scrape_tunnel(now)
            except Exception as e:
                self.cfd_url = None
                with self.lock:
                    self.tunnel = {"up": False, "error": str(e)[:200]}
                    self.push("tunnel_up", 0)
            try:
                self.scrape_host()
            except Exception:
                pass
            minute = int(now // 60)
            if minute != last_flush:
                self.flush(db, last_flush * 60)
                last_flush = minute
            time.sleep(max(0.2, CFG["scrape_seconds"] - (time.time() - now)))

    def flush(self, db, ts):
        with self.lock:
            rows = [(k, ts, sum(v) / len(v)) for k, v in self.minute.items() if v]
            self.minute.clear()
        with db:
            db.executemany("INSERT OR REPLACE INTO metric(key,ts,val) VALUES(?,?,?)", rows)

    def scrape_caddy(self, now):
        d = prom(CFG["caddy_metrics"])
        cpu = self.rate("caddy_cpu", one(d, "process_cpu_seconds_total"), now)
        start = one(d, "process_start_time_seconds")
        c = {
            "up": True,
            "version": self.caddy_version,
            "cpu": cpu * 100 / NCPU if cpu is not None else None,  # % of whole machine
            "rss": one(d, "process_resident_memory_bytes"),
            "heap": one(d, "go_memstats_heap_inuse_bytes"),
            "goroutines": one(d, "go_goroutines"),
            "threads": one(d, "go_threads"),
            "fds": one(d, "process_open_fds"),
            "uptime": now - start if start else None,
            "reload_ok": one(d, "caddy_config_last_reload_successful") == 1,
            "reload_ts": one(d, "caddy_config_last_reload_success_timestamp_seconds"),
            "in_flight": total(d, "caddy_http_requests_in_flight"),
            "handled": total(d, "caddy_http_requests_total"),
        }
        with self.lock:
            self.caddy = c
            self.push("caddy_up", 1)
            self.push("caddy_cpu", c["cpu"])
            self.push("caddy_rss", c["rss"])
            self.push("caddy_goroutines", c["goroutines"])

    def scrape_tunnel(self, now):
        url = self.find_cloudflared()
        d = prom(url)
        conns = {}
        for lab, v in d.get("cloudflared_tunnel_server_locations", []):
            if v == 1:
                conns.setdefault(lab.get("connection_id"), {})["colo"] = lab.get("edge_location")
        for name, key in (("quic_client_latest_rtt", "rtt"), ("quic_client_smoothed_rtt", "srtt"),
                          ("quic_client_min_rtt", "min_rtt"), ("quic_client_congestion_window", "cwnd"),
                          ("quic_client_congestion_state", "cstate"), ("quic_client_mtu", "mtu"),
                          ("quic_client_sent_bytes", "tx"), ("quic_client_receive_bytes", "rx"),
                          ("quic_client_lost_packets", "lost")):
            for lab, v in d.get(name, []):
                c = conns.setdefault(lab.get("conn_index"), {})
                c[key] = c.get(key, 0) + v if key == "lost" else v
        tx = sum(c.get("tx", 0) for c in conns.values())
        rx = sum(c.get("rx", 0) for c in conns.values())
        cpu = self.rate("cfd_cpu", one(d, "process_cpu_seconds_total"), now)
        reqs = one(d, "cloudflared_tunnel_total_requests")
        rtts = [c["srtt"] for c in conns.values() if c.get("srtt")]
        start = one(d, "process_start_time_seconds")
        build = (d.get("build_info") or [({}, 0)])[0][0]
        t = {
            "up": True,
            "metrics_url": url,
            "version": build.get("version", ""),
            "ha": one(d, "cloudflared_tunnel_ha_connections", 0),
            "total": reqs,
            "rps": self.rate("cfd_reqs", reqs, now),
            "errors": one(d, "cloudflared_tunnel_request_errors", 0),
            "concurrent": one(d, "cloudflared_tunnel_concurrent_requests_per_tunnel", 0),
            "codes": {lab.get("status_code"): v for lab, v in d.get("cloudflared_tunnel_response_by_code", [])},
            "tx_bps": self.rate("cfd_tx", tx, now),
            "rx_bps": self.rate("cfd_rx", rx, now),
            "tx": tx, "rx": rx,
            "rtt": sum(rtts) / len(rtts) if rtts else None,
            "cpu": cpu * 100 / NCPU if cpu is not None else None,
            "rss": one(d, "process_resident_memory_bytes"),
            "uptime": now - start if start else None,
            "registrations": total(d, "cloudflared_tunnel_tunnel_register_success"),
            "conns": [dict(c, id=k) for k, c in sorted(conns.items(), key=lambda kv: str(kv[0]))],
        }
        with self.lock:
            self.tunnel = t
            self.push("tunnel_up", 1 if t["ha"] else 0)
            self.push("tunnel_ha", t["ha"])
            self.push("tunnel_rps", t["rps"])
            self.push("tunnel_tx", t["tx_bps"])
            self.push("tunnel_rx", t["rx_bps"])
            self.push("tunnel_rtt", t["rtt"])
            self.push("cfd_cpu", t["cpu"])

    def scrape_host(self):
        s = host_sample()
        if not s:
            return
        p, self.prev_host = self.prev_host, s
        cpu = None
        if p and s["busy"] > p["busy"]:
            cpu = max(0.0, 100 * (1 - (s["idle"] - p["idle"]) / (s["busy"] - p["busy"])))
        with self.lock:
            self.host = {"cpu": cpu, "mem_used": s["mem_used"], "mem_total": s["mem_total"],
                         "uptime": s["uptime"], "cores": NCPU, "name": socket.gethostname()}
            self.push("host_cpu", cpu)
            self.push("host_mem", s["mem_used"] / s["mem_total"] * 100)

    def snapshot(self):
        with self.lock:
            return {"caddy": dict(self.caddy), "tunnel": dict(self.tunnel), "host": dict(self.host),
                    "hist": {k: list(v) for k, v in self.hist.items()}}


# ---------------------------------------------------------------- origin + storage probes

def read_ingress():
    try:
        with open(CFG["cloudflared_config"], encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return []
    out = []
    for host, service in re.findall(r"-\s+(?:hostname:\s*(\S+)\s+(?:path:\s*\S+\s+)?)?service:\s*(\S+)", text):
        out.append({"hostname": host or "*", "service": service})
    return out


class Probes(threading.Thread):
    daemon = True

    def __init__(self, metrics):
        super().__init__(name="probes")
        self.metrics = metrics
        self.lock = threading.Lock()
        self.origins, self.storage = [], []
        self.hist = collections.defaultdict(lambda: collections.deque(maxlen=120))

    def run(self):
        while True:
            try:
                self.probe()
            except Exception:
                log("probe error:\n" + traceback.format_exc())
            time.sleep(CFG["probe_seconds"])

    def probe(self):
        origins = []
        for ing in read_ingress():
            o = dict(ing, ok=None, ms=None, status=None, error="")
            u = urllib.parse.urlsplit(ing["service"])
            if u.scheme in ("http", "https") and u.hostname:
                t0 = time.perf_counter()
                try:
                    cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
                    conn = cls(u.hostname, u.port or (443 if u.scheme == "https" else 80), timeout=4)
                    conn.request("HEAD", "/", headers={"Host": ing["hostname"] if ing["hostname"] != "*" else u.netloc,
                                                       "User-Agent": PROBE_UA})
                    o["status"] = conn.getresponse().status
                    conn.close()
                    o["ok"] = o["status"] < 500
                except Exception as e:
                    o["ok"], o["error"] = False, (str(e) or e.__class__.__name__)[:120]
                o["ms"] = (time.perf_counter() - t0) * 1000
                self.hist["origin:" + ing["hostname"]].append(round(o["ms"], 2))
                o["hist"] = list(self.hist["origin:" + ing["hostname"]])
            origins.append(o)
        storage = []
        try:
            paths = list(dict.fromkeys(m["path"] for m in file_mounts() if m["kind"] == "files")) or CFG["storage_paths"]
        except Exception:
            paths = CFG["storage_paths"]
        for path in paths + [os.path.dirname(CFG["access_log"])]:
            s = {"path": path, "ok": False, "ms": None, "total": None, "used": None, "free": None, "error": ""}
            t0 = time.perf_counter()
            try:
                os.stat(path)
                du = shutil.disk_usage(path)
                s.update(ok=True, total=du.total, used=du.used, free=du.free)
            except OSError as e:
                s["error"] = (e.strerror or str(e))[:120]
            s["ms"] = (time.perf_counter() - t0) * 1000
            self.hist["store:" + path].append(round(s["ms"], 2))
            s["hist"] = list(self.hist["store:" + path])
            storage.append(s)
        with self.lock:
            self.origins, self.storage = origins, storage
        with self.metrics.lock:
            if storage and storage[0]["ok"]:
                self.metrics.push("nas_ms", storage[0]["ms"])
            probed = [o for o in origins if o["ok"] is not None]
            if probed:
                self.metrics.push("origins_up", sum(1 for o in probed if o["ok"]) / len(probed))

    def snapshot(self):
        with self.lock:
            return {"origins": list(self.origins), "storage": list(self.storage)}


# ---------------------------------------------------------------- housekeeping

class Pruner(threading.Thread):
    daemon = True

    """Retention. Raw requests (the bulky part) are deleted in small batches so the tailer never waits long for the
    write lock; aggregated statistics (rollup.py) are kept for retention_days."""

    def run(self):
        import rollup
        while True:
            try:
                raw_cut = time.time() - float(CFG.get("raw_retention_days") or 30) * 86400
                cutoff = time.time() - float(CFG["retention_days"]) * 86400
                db = connect()
                while True:
                    with db:
                        n = db.execute("DELETE FROM req WHERE rowid IN (SELECT rowid FROM req WHERE ts < ? LIMIT 20000)",
                                       (raw_cut,)).rowcount
                    if n < 20000:
                        break
                    time.sleep(0.2)
                with db:
                    db.execute("DELETE FROM metric WHERE ts < ?", (cutoff,))
                    db.execute("DELETE FROM crun WHERE ts < ?", (cutoff,))
                    db.execute("DELETE FROM audit WHERE ts < ?", (time.time() - 365 * 86400,))
                rollup.prune(db, raw_cut, cutoff)
                db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                db.execute("PRAGMA optimize")
                db.close()
            except Exception:
                log("prune error:\n" + traceback.format_exc())
            time.sleep(3600)


# ---------------------------------------------------------------- queries

RANGES = {"live": 3600, "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800, "30d": 2592000, "90d": 7776000}
BUCKETS = {"live": 60, "1h": 60, "6h": 300, "24h": 900, "7d": 3600, "30d": 21600, "90d": 86400}


def where_clause(q):
    rng = q.get("range", "24h")
    if rng not in RANGES:
        rng = "24h"
    span = RANGES[rng]
    w, a = ["ts >= ?"], [time.time() - span]
    if q.get("host"):
        w.append("host = ?"); a.append(q["host"])
    if q.get("nobots") == "1":
        w.append("kind != 'bot'")
    return " AND ".join(w), a, rng, span


def percentiles(db, where, args, ps=(0.5, 0.95, 0.99)):
    n = db.execute("SELECT count(*) FROM req WHERE " + where, args).fetchone()[0]
    out = {}
    for p in ps:
        row = db.execute("SELECT dur FROM req WHERE %s ORDER BY dur LIMIT 1 OFFSET ?" % where,
                         args + [max(0, int(n * p) - 1)]).fetchone() if n else None
        out["p%d" % round(p * 100)] = row[0] if row else 0
    return out


def rows_of(cur):
    names = [c[0] for c in cur.description]
    return [dict(zip(names, r)) for r in cur.fetchall()]


def filled_series(db, where, args, span, b, cols):
    """Bucketed counts over the range with empty buckets filled with zeros."""
    start = int((time.time() - span) // b * b)
    pts = {r["t"]: r for r in rows_of(db.execute(
        "SELECT CAST(ts/%d AS INTEGER)*%d t, %s FROM req WHERE %s GROUP BY t"
        % (b, b, ", ".join("%s %s" % (expr, name) for name, expr in cols), where), args))}
    series = {"t0": start, "step": b}
    for name, _ in cols:
        series[name] = []
    for t in range(start, int(time.time()) + 1, b):
        r = pts.get(t, {})
        for name, _ in cols:
            series[name].append(r.get(name) or 0)
    return series


SERIES_COLS = [("reqs", "count(*)"), ("bytes", "sum(bytes)"), ("e4", "sum(status>=400 AND status<500 AND %s)" % CLEAN),
               ("e5", "sum(status>=500 AND %s)" % CLEAN), ("uniq", "count(DISTINCT ip)"), ("bots", "sum(kind='bot')"),
               ("saved", "sum(saved)"), ("sus", "sum(NOT %s)" % CLEAN)]


def engine_for(q, span):
    """True when this range is answered from the rollups (see rollup.use_rollups)."""
    import rollup
    db = connect()
    try:
        return rollup.use_rollups(db, q, time.time() - span, span)
    finally:
        db.close()


def q_stats(q):
    where, args, rng, span = where_clause(q)
    b = BUCKETS.get(rng, 900)
    if engine_for(q, span):
        import rollup
        return rollup.stats(q, rng, span, b)
    db = connect()
    try:
        x = lambda sql, extra=(): rows_of(db.execute(sql, args + list(extra)))
        # e4 / e5 / clean leave suspicious traffic out (probes, blacklisted, flagged clients, internal tests)
        tot = x("""SELECT count(*) reqs, coalesce(sum(bytes),0) bytes, count(DISTINCT ip) uniq,
                   coalesce(sum(status>=400 AND status<500 AND {c}),0) e4, coalesce(sum(status>=500 AND {c}),0) e5,
                   coalesce(sum({c}),0) clean, coalesce(sum(NOT {c}),0) sus,
                   count(DISTINCT CASE WHEN NOT {c} THEN ip END) sus_ips,
                   coalesce(sum(status>=400 AND status<500),0) e4_all, coalesce(sum(status>=500),0) e5_all,
                   coalesce(avg(dur),0) avg_dur, coalesce(sum(kind='bot'),0) bots, coalesce(sum(scan),0) scans,
                   coalesce(sum(status<400),0) ok, coalesce(sum(CASE WHEN status<400 THEN bytes END),0) ok_bytes,
                   count(DISTINCT path) paths, coalesce(sum(saved),0) saved,
                   coalesce(sum(enc != '' AND enc IS NOT NULL),0) encoded FROM req WHERE """.replace("{c}", CLEAN)
                + where)[0]
        tot.update(percentiles(db, where, args))
        series = filled_series(db, where, args, span, b, SERIES_COLS)
        top = lambda col, n=15, cond="", order="c": x(
            "SELECT %s k, count(*) c, coalesce(sum(bytes),0) b, count(DISTINCT ip) u FROM req WHERE %s %s "
            "GROUP BY k ORDER BY %s DESC LIMIT %d" % (col, where, cond, order, n))
        hist = x("""SELECT CASE WHEN dur<1 THEN 0 WHEN dur<5 THEN 1 WHEN dur<10 THEN 2 WHEN dur<25 THEN 3
                    WHEN dur<50 THEN 4 WHEN dur<100 THEN 5 WHEN dur<250 THEN 6 WHEN dur<500 THEN 7
                    WHEN dur<1000 THEN 8 WHEN dur<2500 THEN 9 ELSE 10 END k, count(*) c FROM req WHERE %s
                    GROUP BY k""" % where)
        return {
            "range": rng, "engine": "raw", "totals": tot, "series": series,
            "paths": x("""SELECT path k, host, count(*) c, sum(bytes) b, count(DISTINCT ip) u, avg(dur) d,
                          max(ts) last, max(ctype) ctype, sum(saved) saved FROM req WHERE %s AND status<400
                          GROUP BY path, host ORDER BY c DESC LIMIT 40""" % where),
            "heavy": x("""SELECT path k, host, count(*) c, sum(bytes) b, count(DISTINCT ip) u, max(ctype) ctype
                          FROM req WHERE %s AND status<400 GROUP BY path, host ORDER BY b DESC LIMIT 15""" % where),
            "notfound": x("""SELECT path k, count(*) c, count(DISTINCT ip) u, max(scan) scan, max(ts) last
                             FROM req WHERE %s AND status=404 GROUP BY path ORDER BY c DESC LIMIT 30""" % where),
            "countries": top("country", 40),
            "referrers": top("ref", 20, "AND ref != ''"),
            "agents": x("""SELECT kind, agent k, count(*) c, sum(bytes) b, count(DISTINCT ip) u FROM req
                           WHERE %s GROUP BY kind, agent ORDER BY c DESC LIMIT 30""" % where),
            "kinds": top("kind", 6),
            "os": top("os", 10, "AND os != '-'"),
            "ctypes": top("ctype", 12, "AND status<400 AND ctype != ''", "b"),
            "statuses": top("status", 20),
            "hosts": top("host", 10),
            "colos": top("colo", 20),
            "methods": top("method", 8),
            "encodings": top("CASE WHEN enc IS NULL OR enc = '' THEN 'identity' ELSE enc END", 6,
                             "AND status<400", "b"),
            "ips": x("""SELECT ip k, max(country) country, count(*) c, sum(bytes) b, sum(status>=400) err,
                        sum(scan) scan, sum(NOT %s) sus, max(kind) kind, max(agent) agent, min(ts) first,
                        max(ts) last FROM req WHERE %s GROUP BY ip ORDER BY c DESC LIMIT 30""" % (CLEAN, where)),
            # probing addresses and clients flagged by the crackdown (rules.py); `why` = the strongest reason
            "scanners": x("""SELECT ip k, max(country) country, count(*) c, sum(scan) scan, sum(NOT %s) sus,
                             max(CASE WHEN sus NOT IN ('', 'probe', 'internal') THEN sus END) why, min(ts) first,
                             max(ts) last, max(agent) agent, max(CASE WHEN scan THEN path END) sample FROM req
                             WHERE %s GROUP BY ip HAVING sum(scan) > 0 OR sum(sus NOT IN ('', 'probe', 'internal')) > 0
                             ORDER BY scan DESC, sus DESC LIMIT 30""" % (CLEAN, where)),
            "latency_hist": hist,
            "latency_hosts": x("""SELECT host k, count(*) c, avg(dur) avg, max(dur) max FROM req WHERE %s
                                  GROUP BY host ORDER BY c DESC""" % where),
            "slowest": x("""SELECT path k, host, count(*) c, avg(dur) avg, max(dur) max, sum(bytes) b FROM req
                            WHERE %s AND status<400 GROUP BY path, host HAVING c >= 2 ORDER BY avg DESC
                            LIMIT 15""" % where),
        }
    finally:
        db.close()


SIZE_BUCKETS = ["0", "<1 KB", "1–10 KB", "10–100 KB", "0.1–1 MB", "1–10 MB", "10–100 MB", "≥100 MB"]


def q_insights(q):
    where, args, rng, span = where_clause(q)
    since = args[0]
    if engine_for(q, span):
        import rollup
        return rollup.insights(q, rng, span)
    db = connect()
    try:
        x = lambda sql, extra=(): rows_of(db.execute(sql, args + list(extra)))
        heat = x("""SELECT CAST(strftime('%%w', ts, 'unixepoch', 'localtime') AS INTEGER) d,
                    CAST(strftime('%%H', ts, 'unixepoch', 'localtime') AS INTEGER) h, count(*) c, sum(bytes) b,
                    count(DISTINCT ip) u FROM req WHERE %s GROUP BY d, h""" % where)
        sizes = x("""SELECT CASE WHEN bytes=0 THEN 0 WHEN bytes<1024 THEN 1 WHEN bytes<10240 THEN 2
                     WHEN bytes<102400 THEN 3 WHEN bytes<1048576 THEN 4 WHEN bytes<10485760 THEN 5
                     WHEN bytes<104857600 THEN 6 ELSE 7 END k, count(*) c, sum(bytes) b FROM req WHERE %s
                     GROUP BY k""" % where)
        classes = x("SELECT status/100 k, count(*) c, sum(bytes) b FROM req WHERE %s GROUP BY k" % where)
        exts = collections.defaultdict(lambda: [0, 0])
        cats = collections.defaultdict(lambda: [0, 0])
        for path, c, b in db.execute("SELECT path, count(*), sum(bytes) FROM req WHERE %s AND status<400 "
                                     "GROUP BY path" % where, args):
            p = urllib.parse.unquote(path or "")
            e = ext_of(p) or ("(folder)" if p.endswith("/") else "(none)")
            exts[e][0] += c; exts[e][1] += b or 0
            k = category(p) if e not in ("(folder)", "(none)") else "page"
            cats[k][0] += c; cats[k][1] += b or 0
        ret = db.execute("""SELECT coalesce(sum(f < ?),0), count(*) FROM
                            (SELECT min(ts) f FROM req GROUP BY ip HAVING max(ts) >= ?)""", [since, since]).fetchone()
        daily = x("""SELECT date(ts, 'unixepoch', 'localtime') k, count(*) c, sum(bytes) b, count(DISTINCT ip) u,
                     sum(status>=400 AND %s) e FROM req WHERE %s GROUP BY k ORDER BY k""" % (CLEAN, where))
        busiest = x("""SELECT CAST(ts/3600 AS INTEGER)*3600 t, count(*) c, sum(bytes) b, count(DISTINCT ip) u
                       FROM req WHERE %s GROUP BY t ORDER BY c DESC LIMIT 8""" % where)
        clients = x("""SELECT ip k, max(country) country, max(agent) agent, max(kind) kind, count(*) c,
                       sum(bytes) b FROM req WHERE %s GROUP BY ip ORDER BY b DESC LIMIT 15""" % where)
        protos = x("SELECT proto k, count(*) c FROM req WHERE %s GROUP BY k ORDER BY c DESC" % where)
        return {
            "range": rng, "engine": "raw", "heat": heat, "sizes": sizes, "size_labels": SIZE_BUCKETS, "classes": classes,
            "exts": sorted(({"k": k, "c": v[0], "b": v[1]} for k, v in exts.items()), key=lambda r: -r["c"])[:25],
            "cats": sorted(({"k": k, "c": v[0], "b": v[1]} for k, v in cats.items()), key=lambda r: -r["b"]),
            "returning": ret[0], "visitors": ret[1], "daily": daily, "busiest": busiest, "clients": clients,
            "protos": protos, "inventory": get_meta(db, "inventory"),
        }
    finally:
        db.close()


def q_requests(q):
    w, a = ["1=1"], []
    scope = q.get("scope", "all")
    w.append({"all": "1=1", "ok": "status<400", "errors": "status>=400 AND " + CLEAN, "bots": "kind='bot'",
              "scan": "scan=1 OR sus NOT IN ('', 'internal')", "all_errors": "status>=400",
              "media": "status<400 AND (ctype LIKE 'image/%' OR ctype LIKE 'video/%' OR "
                                         "ctype LIKE 'audio/%')", "people": "kind IN ('browser','player','embed')",
              "compressed": "enc != '' AND enc IS NOT NULL"}.get(scope, "1=1"))
    if q.get("ip"):
        w.append("ip = ?"); a.append(q["ip"])
    # structured filters (Requests view filter bar): exact columns, so they use the indexes / stay cheap
    st = q.get("status") or ""
    if re.fullmatch(r"[1-5]xx", st):
        w.append("status >= ? AND status < ?"); a += [int(st[0]) * 100, int(st[0]) * 100 + 100]
    elif st.isdigit():
        w.append("status = ?"); a.append(int(st))
    for col in ("host", "method", "country", "kind", "colo"):
        if q.get(col):
            w.append("%s = ?" % col); a.append(q[col] if col != "country" else q[col].upper())
    if q.get("path"):
        w.append("path LIKE ? ESCAPE '\\'")
        a.append(q["path"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    if q.get("since"):
        w.append("ts >= ?"); a.append(time.time() - float(q["since"]))
    if q.get("min_ms"):
        w.append("dur >= ?"); a.append(float(q["min_ms"]))
    if q.get("before"):  # cursor: rows older than this id ("load older")
        w.append("rowid < ?"); a.append(int(q["before"]))
    if q.get("q"):
        like = "%" + q["q"] + "%"
        w.append("(path LIKE ? OR ip LIKE ? OR ua LIKE ? OR country = ? OR host LIKE ? OR CAST(status AS TEXT) = ?"
                 " OR colo = ? OR agent LIKE ? OR ref LIKE ?)")
        a += [like, like, like, q["q"].upper(), like, q["q"], q["q"].upper(), like, like]
    limit = max(1, min(2000, int(q.get("limit", 250))))
    db = connect()
    try:
        # newest first by rowid (insertion order == log order): the primary key walk stops after `limit` matches
        rows = rows_of(db.execute("SELECT rowid id, %s FROM req WHERE %s ORDER BY rowid DESC LIMIT %d"
                                  % (",".join(COLS), " AND ".join(w), limit), a))
        return {"rows": rows, "more": len(rows) == limit, "cursor": rows[-1]["id"] if rows else None}
    finally:
        db.close()


def q_ip(q):
    ip = q.get("ip", "")
    db = connect()
    try:
        s = rows_of(db.execute("""SELECT count(*) c, coalesce(sum(bytes),0) b, sum(status>=400) err, sum(scan) scan,
                                  min(ts) first, max(ts) last, max(country) country FROM req WHERE ip=?""", [ip]))[0]
        s["paths"] = rows_of(db.execute("""SELECT path k, count(*) c, max(status) status FROM req WHERE ip=?
                                           GROUP BY path ORDER BY c DESC LIMIT 12""", [ip]))
        s["agents"] = rows_of(db.execute("""SELECT agent k, count(*) c FROM req WHERE ip=? GROUP BY agent
                                            ORDER BY c DESC LIMIT 5""", [ip]))
        return s
    finally:
        db.close()


def q_history(q):
    """Hourly means for the last 24 h - requests from the log, vitals from the minute samples."""
    if engine_for(q or {}, 86400):
        import rollup
        return rollup.history()
    end = int(time.time() // 3600 * 3600) + 3600
    start = end - 24 * 3600
    db = connect()
    try:
        req = {r["t"]: r for r in rows_of(db.execute(
            """SELECT CAST(ts/3600 AS INTEGER)*3600 t, count(*) reqs, sum(bytes) bytes, count(DISTINCT ip) uniq,
               sum(status>=400 AND %s) err, avg(dur) dur, sum(kind='bot') bots, sum(saved) saved FROM req
               WHERE ts >= ? GROUP BY t""" % CLEAN, [start]))}
        met = collections.defaultdict(dict)
        for r in db.execute("""SELECT key, CAST(ts/3600 AS INTEGER)*3600 t, avg(val) FROM metric WHERE ts >= ?
                               GROUP BY key, t""", [start]):
            met[r[0]][r[1]] = r[2]
        hours = list(range(start, end, 3600))
        col = lambda k: [(req.get(h) or {}).get(k) or 0 for h in hours]
        mcol = lambda k: [met[k].get(h) for h in hours]
        return {"hours": hours, "reqs": col("reqs"), "bytes": col("bytes"), "uniq": col("uniq"),
                "err": col("err"), "dur": col("dur"), "bots": col("bots"), "saved": col("saved"),
                "caddy_cpu": mcol("caddy_cpu"), "tunnel_rtt": mcol("tunnel_rtt"), "nas_ms": mcol("nas_ms"),
                "host_cpu": mcol("host_cpu"), "tunnel_tx": mcol("tunnel_tx")}
    finally:
        db.close()


def q_audit(q=None):
    q = q or {}
    limit = max(1, min(500, int(q.get("limit") or 100)))
    where, args = [], []
    if q.get("user"):
        where.append("user LIKE ? ESCAPE '\\'")
        args.append("%" + str(q["user"]).replace("%", "\\%").replace("_", "\\_")[:80] + "%")
    if q.get("action"):
        where.append("action LIKE ? ESCAPE '\\'")
        args.append("%" + str(q["action"]).replace("%", "\\%").replace("_", "\\_")[:80] + "%")
    if q.get("search"):
        where.append("(target LIKE ? OR note LIKE ? OR ip LIKE ?)")
        term = "%" + str(q["search"])[:120] + "%"
        args.extend([term, term, term])
    if q.get("before"):
        where.append("id < ?")
        args.append(max(1, int(q["before"])))
    db = connect()
    try:
        sql = "SELECT id,ts,ip,user,action,target,ok,note FROM audit_event"
        if where:
            sql += " WHERE " + " AND ".join(where)
        rows = rows_of(db.execute(sql + " ORDER BY id DESC LIMIT ?", args + [limit]))
        return {"rows": rows, "next": rows[-1]["id"] if rows else None, "append_only": True}
    finally:
        db.close()


def q_runtime_logs(q=None):
    """Bounded tail of this Strata process log. The file is rotated and secrets are redacted at write time."""
    q = q or {}
    limit = max(1, min(500, int(q.get("limit") or 200)))
    term = str(q.get("search") or "").strip().lower()[:120]
    max_bytes = 4 * 1024 * 1024
    lines = []
    paths = [RUNTIME_LOG_PATH + ".%d" % n for n in range(_LOG_KEEP, 0, -1)] + [RUNTIME_LOG_PATH]
    remaining = max_bytes
    for path in paths:
        try:
            size = os.path.getsize(path)
            if not size:
                continue
            take = min(size, remaining)
            with open(path, "rb") as f:
                f.seek(max(0, size - take))
                chunk = f.read(take).decode("utf-8", "replace")
            if size > take:
                chunk = chunk.split("\n", 1)[-1]
            lines.extend(chunk.splitlines())
            remaining -= take
            if remaining <= 0:
                break
        except OSError:
            continue
    filtered = [line for line in lines if not term or term in line.lower()]
    return {"source": "runtime", "path": RUNTIME_LOG_PATH, "lines": filtered[-limit:], "limit": limit,
            "truncated": remaining <= 0}


def uptime(db, key, since):
    row = db.execute("SELECT avg(val), count(*) FROM metric WHERE key=? AND ts >= ?", [key, since]).fetchone()
    return {"pct": row[0] * 100 if row[0] is not None else None, "minutes": row[1]}


_dbinfo = {"t": 0, "v": {}}


def db_info():
    if time.time() - _dbinfo["t"] > 30:
        db = connect()
        try:
            n, first = db.execute("SELECT count(*), min(ts) FROM req").fetchone()
        finally:
            db.close()
        size = sum(os.path.getsize(DB_PATH + s) for s in ("", "-wal") if os.path.exists(DB_PATH + s))
        _dbinfo.update(t=time.time(), v={"rows": n, "first": first, "size": size})
    return _dbinfo["v"]


# ---------------------------------------------------------------- Cloudflare edge analytics (optional)

_edge = {"t": 0, "v": None}
_edge_lock = threading.Lock()

EDGE_GQL = """query($zone: String!, $since: Time!, $until: Time!, $d0: Date!, $d1: Date!) {
  viewer { zones(filter: {zoneTag: $zone}) {
    hours: httpRequests1hGroups(limit: 48, filter: {datetime_geq: $since, datetime_lt: $until}, orderBy: [datetime_ASC]) {
      dimensions { datetime }
      sum { requests cachedRequests bytes cachedBytes threats pageViews
            countryMap { clientCountryName requests bytes threats }
            responseStatusMap { edgeResponseStatus requests }
            contentTypeMap { edgeResponseContentTypeName requests bytes } }
      uniq { uniques }
    }
    days: httpRequests1dGroups(limit: 31, filter: {date_geq: $d0, date_leq: $d1}, orderBy: [date_ASC]) {
      dimensions { date }
      sum { requests cachedRequests bytes cachedBytes threats }
      uniq { uniques }
    }
  } }
}"""


def cf_call(url, token, body=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body else None,
                                 headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read())
            msg = "; ".join(x.get("message", "?") for x in body.get("errors", [])) or str(e)
        except Exception:
            msg = str(e)
        raise RuntimeError("Cloudflare API %s: %s" % (e.code, msg))


def q_edge(q):
    cf = CFG["cloudflare"]
    if not cf.get("api_token"):
        return {"configured": False}
    with _edge_lock:
        if _edge["v"] and time.time() - _edge["t"] < 300 and q.get("force") != "1":
            return _edge["v"]
        try:
            zone = cf.get("zone_id")
            if not zone:
                r = cf_call("https://api.cloudflare.com/client/v4/zones?name=" + urllib.parse.quote(cf["zone_name"]),
                            cf["api_token"])
                if not r.get("result"):
                    raise RuntimeError("zone %s not visible to this token (needs Zone:Read, or set zone_id)"
                                       % cf["zone_name"])
                zone = cf["zone_id"] = r["result"][0]["id"]
            now = time.time()
            fmt = lambda t: time.strftime("%Y-%m-%dT%H:00:00Z", time.gmtime(t))
            day = lambda t: time.strftime("%Y-%m-%d", time.gmtime(t))
            r = cf_call("https://api.cloudflare.com/client/v4/graphql", cf["api_token"], {
                "query": EDGE_GQL,
                "variables": {"zone": zone, "since": fmt(now - 24 * 3600), "until": fmt(now + 3600),
                              "d0": day(now - 29 * 86400), "d1": day(now)}})
            if r.get("errors"):
                raise RuntimeError("; ".join(e.get("message", "?") for e in r["errors"])[:400])
            z = (r.get("data") or {}).get("viewer", {}).get("zones") or [{}]
            v = {"configured": True, "ok": True, "zone": zone, "hours": z[0].get("hours", []),
                 "days": z[0].get("days", []), "fetched": now}
        except Exception as e:
            v = {"configured": True, "ok": False, "error": str(e)[:400], "fetched": time.time()}
        _edge.update(t=time.time(), v=v)
        return v
