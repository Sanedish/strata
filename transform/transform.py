#!/usr/bin/env python3
"""Strata Transform - link modifiers for the CDN (reached only through Caddy's generated rules).

    pythonw transform.py --home <instance home>     (config: <home>/transform/transform.json, see instance.py)

    ?w=400 ?h=300          resize (never upscales)           ?fit=inside|cover|contain|fill
    ?fm=webp|avif|jpeg|png  convert                           ?q=1-100 quality
    ?ver=3                  serve stored version 3 of a file (works for any file type, with Range support)
    X-Strata-Embed: 1       a link-preview crawler on a bare URL: Open Graph tags for Discord, Slack, Telegram...
    ?card=1                 the preview image those tags point at (1200 x 630 JPEG, drawn once per file version)
    /_gate                  forward_auth target: checks ?exp=&sig= on signed links (HMAC-SHA256)

Least privilege: reads drive folders (read-only use) and its own cache dir; knows no database, no users, no
tokens except the signing secret. Config comes from transform.json, written by Strata whenever drives change.
"""
import base64
import hashlib
import hmac
import io
import json
import mimetypes
import os
import re
import site
import sys
import threading

# Task Scheduler starts pythonw without APPDATA, so the per-user site-packages (Pillow) would be invisible
def _roaming_appdata():
    try:  # ask Windows (works even when the environment has no APPDATA / USERPROFILE)
        import ctypes
        buf = ctypes.create_unicode_buffer(520)
        if ctypes.windll.shell32.SHGetFolderPathW(None, 0x1A, None, 0, buf) == 0 and buf.value:
            return buf.value
    except Exception:
        pass
    return os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Roaming")


_VENDOR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vendor")  # <install folder>\vendor
if os.path.isdir(_VENDOR) and _VENDOR not in sys.path:
    sys.path.insert(0, _VENDOR)
_USER_SITE = os.path.join(_roaming_appdata(), "Python", "Python%d%d" % sys.version_info[:2], "site-packages")
_DIAG = {"vendor": _VENDOR, "vendor_exists": os.path.isdir(_VENDOR), "user_site": _USER_SITE, "exists": os.path.isdir(_USER_SITE)}
if os.path.isdir(_USER_SITE) and _USER_SITE not in sys.path:
    site.addsitedir(_USER_SITE)
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import instance  # noqa: E402  (the instance home: --home / STRATA_HOME)
CONF_PATH = instance.home("transform", "transform.json")
IMAGE_EXT = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".tif", ".tiff", ".avif"}
FORMATS = {"webp": ("WEBP", "image/webp"), "avif": ("AVIF", "image/avif"), "jpeg": ("JPEG", "image/jpeg"),
           "jpg": ("JPEG", "image/jpeg"), "png": ("PNG", "image/png")}
SEM = threading.Semaphore(2)
_conf = {"mtime": 0, "v": {}}


def conf():
    try:
        mt = os.path.getmtime(CONF_PATH)
    except OSError:
        return _conf["v"]
    if mt != _conf["mtime"]:
        with open(CONF_PATH, encoding="utf-8") as f:
            _conf["v"] = json.load(f)
        _conf["mtime"] = mt
    return _conf["v"]


def sign(secret, path, exp):
    msg = "%s\n%d" % (urllib.parse.unquote(path), int(exp))
    mac = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode().rstrip("=")[:32]


def resolve(mount, url_path):
    root = os.path.normpath(mount["path"])
    path = urllib.parse.unquote(url_path)
    if mount.get("prefix", "/") != "/":
        if not (path == mount["prefix"] or path.startswith(mount["prefix"] + "/")):
            return None, None
        path = path[len(mount["prefix"]):] or "/"
    parts = [p for p in path.split("/") if p]
    if any(p in (".", "..") or p.startswith(".") or "\\" in p or ":" in p for p in parts):
        return None, None
    full = os.path.normpath(os.path.join(root, *parts))
    if os.path.commonpath([full.lower(), root.lower()]) != root.lower():
        return None, None
    return full, "/" + "/".join(parts)


def version_file(mount, rel, n):
    h = hashlib.sha1(rel.encode("utf-8")).hexdigest()
    return os.path.join(os.path.normpath(mount["path"]), ".strata-versions", h[:2], h, "v%d" % n)


def evict(cache_dir, max_bytes):
    files = []
    total = 0
    for dp, dn, fn in os.walk(cache_dir):
        for n in fn:
            p = os.path.join(dp, n)
            try:
                st = os.stat(p)
            except OSError:
                continue
            files.append((st.st_atime, st.st_size, p))
            total += st.st_size
    files.sort()
    while total > max_bytes and files:
        _, size, p = files.pop(0)
        try:
            os.remove(p)
            total -= size
        except OSError:
            pass


def transform(src, st, params, c):
    """Resize/convert src; returns (bytes, content-type). Cached on disk by source identity + parameters."""
    from PIL import Image, ImageOps
    Image.MAX_IMAGE_PIXELS = 80_000_000
    maxd = int(c.get("max_dim", 4096))
    w = int(params["w"]) if params.get("w") else None
    h = int(params["h"]) if params.get("h") else None
    if (w and not 1 <= w <= maxd) or (h and not 1 <= h <= maxd):
        raise ValueError("w/h must be 1-%d" % maxd)
    fit = params.get("fit") or "inside"
    if fit not in ("inside", "cover", "contain", "fill"):
        raise ValueError("fit must be inside, cover, contain or fill")
    q = int(params.get("q") or 82)
    if not 1 <= q <= 100:
        raise ValueError("q must be 1-100")
    fm = (params.get("fm") or "auto").lower()
    if fm not in FORMATS and fm != "auto":
        raise ValueError("fm must be webp, avif, jpeg or png")
    key = hashlib.sha1(json.dumps([src, st.st_size, st.st_mtime, w, h, fit, q, fm]).encode()).hexdigest()
    cache_dir = c.get("cache_dir") or instance.home("data", "tcache")
    cpath = os.path.join(cache_dir, key[:2], key)
    for ext, (_, ctype) in FORMATS.items():
        if os.path.exists(cpath + "." + ext):
            with open(cpath + "." + ext, "rb") as f:
                os.utime(cpath + "." + ext)
                return f.read(), ctype, "hit"
    with SEM:
        with Image.open(src) as im:
            src_fmt = (im.format or "PNG").upper()
            im = ImageOps.exif_transpose(im)
            if fm == "auto":
                fm = {"JPEG": "jpeg", "WEBP": "webp", "AVIF": "avif"}.get(src_fmt, "png")
            ow, oh = im.size
            if w or h:
                tw = w or max(1, round(ow * h / oh))
                th = h or max(1, round(oh * w / ow))
                tw, th = min(tw, ow) if fit != "fill" or not (w and h) else tw, min(th, oh) if fit != "fill" or not (w and h) else th
                if fit == "cover" and w and h:
                    im = ImageOps.fit(im, (min(w, ow), min(h, oh)), Image.LANCZOS)
                elif fit == "fill" and w and h:
                    im = im.resize((w, h), Image.LANCZOS)
                elif fit == "contain" and w and h:
                    inner = im.copy()
                    inner.thumbnail((w, h), Image.LANCZOS)
                    mode = "RGBA" if fm in ("png", "webp", "avif") else "RGB"
                    canvas = Image.new(mode, (w, h), (255, 255, 255, 0) if mode == "RGBA" else (255, 255, 255))
                    canvas.paste(inner.convert(mode), ((w - inner.width) // 2, (h - inner.height) // 2))
                    im = canvas
                else:
                    im = im.copy()
                    im.thumbnail((w or ow, h or oh), Image.LANCZOS)
            pil, ctype = FORMATS[fm]
            if pil == "JPEG" and im.mode not in ("RGB", "L"):
                bg = Image.new("RGB", im.size, (255, 255, 255))
                rgba = im.convert("RGBA")
                bg.paste(rgba, mask=rgba.split()[-1])
                im = bg
            elif im.mode in ("P", "LA", "I;16", "I", "F", "CMYK"):
                im = im.convert("RGBA" if pil != "JPEG" else "RGB")
            buf = io.BytesIO()
            opts = {"quality": q}
            if pil == "WEBP":
                opts["method"] = 5
            if pil == "JPEG":
                opts.update(optimize=True, progressive=True)
            if pil == "PNG":
                opts = {"optimize": True}
            im.save(buf, pil, **opts)
    data = buf.getvalue()
    os.makedirs(os.path.dirname(cpath), exist_ok=True)
    tmp = cpath + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, cpath + "." + fm)
    if hash(key) % 50 == 0:
        threading.Thread(target=evict, args=(cache_dir, int(c.get("cache_max_mb", 2048)) << 20), daemon=True).start()
    return data, ctype, "miss"


class Handler(BaseHTTPRequestHandler):
    server_version = "StrataTransform"
    sys_version = ""

    def log_message(self, *a):
        pass

    def plain(self, code, msg):
        body = msg.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        if self.client_address[0] not in ("127.0.0.1", "::1"):
            return self.plain(403, "forbidden")
        c = conf()
        u = urllib.parse.urlsplit(self.path)
        if u.path == "/_gate":
            return self.gate(c)
        mount = c.get("mounts", {}).get(self.headers.get("X-Strata-Mount", ""))
        if not mount:
            return self.plain(404, "not found")
        q = {k: v[-1] for k, v in urllib.parse.parse_qs(u.query).items()}
        full, rel = resolve(mount, u.path)
        if not full:
            return self.plain(404, "not found")
        src = full
        if q.get("ver"):
            if not re.fullmatch(r"\d{1,6}", q["ver"]):
                return self.plain(400, "ver must be a number")
            src = version_file(mount, rel, int(q["ver"]))
        if not os.path.isfile(src):
            return self.plain(404, "not found")
        st = os.stat(src)
        if not q.get("ver") and (self.headers.get("X-Strata-Embed") == "1" or q.get("card")):
            return self.preview(full, st, q, c, u.path)
        cache = self.headers.get("X-Strata-Cache") or "public, max-age=31536000, immutable"
        edge = self.headers.get("X-Strata-Edge-Cache") or ""  # Cloudflare-only TTL, sent on successful answers only
        wants_tf = any(q.get(k) for k in ("w", "h", "fm", "q", "fit"))
        ext = os.path.splitext(full)[1].lower()
        if wants_tf:
            if ext not in IMAGE_EXT:
                return self.plain(415, "image modifiers only apply to images")
            if st.st_size > 150 << 20:
                return self.plain(413, "image too large to transform")
            try:
                data, ctype, state = transform(src, st, q, c)
            except ValueError as e:
                return self.plain(400, str(e))
            except Exception as e:
                return self.plain(422, "could not transform this image (%s)" % e.__class__.__name__)
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", cache)
            if edge:
                self.send_header("Cloudflare-CDN-Cache-Control", edge)
            self.send_header("ETag", '"%s"' % hashlib.sha1(data).hexdigest()[:20])
            self.send_header("X-Strata-Transform", state)
            self.send_header("Vary", "Accept-Encoding")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)
            return
        return self.stream(src, st, mimetypes.guess_type(full)[0] or "application/octet-stream", cache, edge)

    do_HEAD = do_GET

    def preview(self, path, st, q, c, url_path):
        """Link previews. The page answers one client class (crawlers) on a URL that serves the file to everyone
        else, so it must never be stored at the edge; the card URL carries the file version and is cached for good."""
        import audiocard
        if os.path.splitext(path)[1].lower() not in audiocard.AUDIO_EXT:
            return self.plain(415, "no link preview for this file type")
        try:
            data, info = audiocard.card(path, st, c.get("cache_dir") or instance.home("data", "tcache"))
        except Exception as e:
            return self.plain(422, "could not draw the preview (%s)" % e.__class__.__name__)
        v = info["key"][:12]
        if q.get("card"):
            body, ctype = data, "image/jpeg"
            cache = "public, max-age=31536000, immutable" if q.get("v") == v else "public, max-age=300"
        else:
            host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or ""
            local = re.match(r"(localhost|127\.|10\.|192\.168\.|\[)", host)
            page = "%s://%s%s" % ("http" if local else "https", host, url_path)
            body = audiocard.embed_html(info, page, page + "?card=1&v=" + v, host)
            ctype, cache = "text/html; charset=utf-8", "private, no-store"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        if ctype.startswith("text/html"):
            self.send_header("Cloudflare-CDN-Cache-Control", "no-store")
            self.send_header("X-Robots-Tag", "noindex")
        self.send_header("ETag", '"%s"' % v)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def stream(self, src, st, ctype, cache, edge=""):
        size = st.st_size
        start, end, code = 0, max(0, size - 1), 200
        m = re.fullmatch(r"bytes=(\d*)-(\d*)", self.headers.get("Range") or "")
        if m and size and (m.group(1) or m.group(2)):
            if m.group(1):
                start = int(m.group(1))
                end = min(int(m.group(2)), size - 1) if m.group(2) else size - 1
            else:
                start = max(0, size - int(m.group(2)))
            if start > end:
                self.send_response(416)
                self.send_header("Content-Range", "bytes */%d" % size)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            code = 206
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(end - start + 1 if size else 0))
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Cache-Control", cache)
        if edge:
            self.send_header("Cloudflare-CDN-Cache-Control", edge)
        self.send_header("Last-Modified", self.date_time_string(st.st_mtime))
        if code == 206:
            self.send_header("Content-Range", "bytes %d-%d/%d" % (start, end, size))
        self.end_headers()
        if self.command == "HEAD" or not size:
            return
        with open(src, "rb") as f:
            f.seek(start)
            left = end - start + 1
            while left:
                buf = f.read(min(left, 1 << 20))
                if not buf:
                    break
                try:
                    self.wfile.write(buf)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    return
                left -= len(buf)

    def gate(self, c):
        uri = self.headers.get("X-Forwarded-Uri") or ""
        u = urllib.parse.urlsplit(uri)
        q = {k: v[-1] for k, v in urllib.parse.parse_qs(u.query).items()}
        try:
            exp = int(q.get("exp", "0"))
        except ValueError:
            exp = 0
        sig = q.get("sig", "")
        secret = c.get("sign_secret", "")
        if not secret or not sig or exp < time.time():
            return self.plain(403, "This link has expired or is not valid." if sig else "A signed link is required.")
        if not hmac.compare_digest(sign(secret, u.path, exp), sig):
            return self.plain(403, "This link is not valid.")
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def refuse(self):
        self.plain(405, "method not allowed")

    do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = refuse


def diagnose():
    """Written at start-up so a missing Pillow is visible without a console."""
    info = dict(_DIAG, executable=sys.executable, path=sys.path, env={k: os.environ.get(k) for k in ("APPDATA", "USERPROFILE", "HOME", "PYTHONNOUSERSITE")})
    try:
        import PIL
        info["pillow"] = PIL.__version__
    except Exception as e:
        info["pillow_error"] = "%s: %s" % (e.__class__.__name__, e)
    try:
        with open(instance.home("transform", "diag.json"), "w", encoding="utf-8") as f:
            json.dump(info, f, indent=1)
    except OSError:
        pass


def main():
    diagnose()
    host, port = conf().get("listen", "127.0.0.1:8083").rsplit(":", 1)
    srv = ThreadingHTTPServer((host, int(port)), Handler)
    srv.daemon_threads = True
    print(time.strftime("%H:%M:%S"), "strata transform on http://%s:%s" % (host, port), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
