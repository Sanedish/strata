"""Strata Media imaging - probe, format choice, AVIF/WebP encoding, cost model and the legacy ?w=/?fm= transforms.

Why it looks like this (media/DESIGN.md 6.2 / 6.3):
  * The hot path must decide *before* decoding whether an encode fits the sync budget, so probe() only reads the
    header and CostModel turns (megapixels, format, speed) into seconds from measurements taken on this VM.
  * Originals are never touched. Variants keep the ICC profile (colours stay right) but never EXIF/XMP: that is
    where GPS positions, camera serials and editing history live, and the CDN must not re-publish them.
    Pillow 12.3 only writes metadata that is passed in encoderinfo (AVIF also falls back to im.info for ICC), so
    every writer gets icc_profile / exif=b"" / xmp=b"" explicitly and im.info is stripped as a second fence.
  * Lossless sources (PNG screenshots, UI, text) go to AVIF 4:4:4 so edges stay sharp; palette-like images of
    <= 4 MP also try lossless WebP (often far smaller for flat UI) and the smaller one wins, which is why
    encode_auto() returns the format it actually produced.
  * encode_explicit() is transform/transform.py's transform() without its disk cache (cache.py owns caching):
    same parameter ranges, fit modes, error messages and output sizes, so existing links keep their meaning.
Errors carry a `.kind` (decode_error, encode_error, too_large) that media.py / worker.py log as event kinds;
ValueError is reserved for invalid request parameters (-> HTTP 400).
"""
import hashlib
import io
import os
import re
import threading
import time
import warnings

try:
    from PIL import Image, ImageOps
except ImportError:  # media.py / worker.py import pathfix first; without Pillow every encode is a clean error
    Image = ImageOps = None

# Safety net only: config.load() deep-merges core.DEFAULTS["media"] (the source of truth) over media.json.
IMAGE_DEFAULTS = {"sync_budget_s": 2.5, "sync_max_mp": 20, "sync_max_bytes": 32 << 20, "max_mp": 150,
                  "bg_max_mp": 280, "min_bytes": 4096, "max_source_bytes": 160 << 20, "max_frames": 1000,
                  "max_anim_mp": 96,
                  "avif_quality_lossy": 62, "avif_quality_lossless": 74, "avif_alpha_quality": 90,
                  "webp_quality": 86, "jpeg_quality": 85, "speed_sync": 8, "speed_bg": 6, "threads": 2,
                  "min_saving": 0.10, "short_ttl": "public, max-age=60", "max_dim": 4096,
                  "widths": [320, 640, 1080, 1440, 1920, 2160, 2560, 3840, 4320, 7680], "max_width": 7680,
                  "snap_widths": True, "sync_budget_max_s": 6.0, "max_queue_depth": 500, "debug_headers": True,
                  "profile": "p1"}
# what goes into a variant's identity (spec): changing any of these makes every old variant unreachable
PROFILE_KEYS = ("avif_quality_lossy", "avif_quality_lossless", "avif_alpha_quality", "webp_quality", "jpeg_quality",
                "profile")
CONTENT_TYPE = {"avif": "image/avif", "webp": "image/webp", "jpeg": "image/jpeg", "png": "image/png"}
FORMATS = {"webp": "WEBP", "avif": "AVIF", "jpeg": "JPEG", "jpg": "JPEG", "png": "PNG"}   # explicit ?fm=
LOSSY = {"JPEG", "MPO"}                        # MPO = multi-picture JPEG straight from phones and cameras
MODERN = {"AVIF", "WEBP"}
ANIMATED = {"GIF", "PNG", "WEBP", "AVIF"}      # formats whose extra frames are an animation (not TIFF pages)
WEBP_MAX_SIDE = 16383                          # hard limit of the WebP bitstream
AVIF_MAX_SIDE = 32768                          # libavif's default decoder limits (what browsers ship)
AVIF_MAX_PIXELS = 16384 * 16384
PALETTE_MAX_MP = 4                             # palette-like images up to this size also try lossless WebP
LOW_MEM_MB = 3072                              # below this much free RAM the worker stays within max_mp
MB_PER_MP = 45.0                               # measured peak working set of decode + AVIF encode per megapixel
MEM_RESERVE_MB = 768                           # = breaker mem_min_mb: what an encode must leave for the VM
MIN_MEM_MP = 4.0                               # small images are always allowed (the breaker guards the rest)
KEEP_INFO = ("icc_profile", "transparency")    # everything else in im.info (exif, xmp, comments ...) is dropped

_tls = threading.local()


class ImagingError(Exception):
    kind = "encode_error"


class DecodeError(ImagingError):
    kind = "decode_error"


class EncodeError(ImagingError):
    kind = "encode_error"


class TooLarge(ImagingError):
    """Source exceeds the megapixel limit of this path (hot path max_mp, worker bg_max_mp)."""
    kind = "too_large"

    def __init__(self, mp, limit):
        super().__init__("%.1f MP exceeds the %.0f MP limit" % (mp, limit))
        self.mp, self.limit = mp, limit


def _need_pil():
    if Image is None:
        raise EncodeError("Pillow is not available")


def image_conf(conf):
    """The image tunables from a full media config, an image sub-dict or None, with defaults filled in."""
    conf = conf or {}
    sub = conf.get("image") if isinstance(conf.get("image"), dict) else conf
    return dict(IMAGE_DEFAULTS, **{k: v for k, v in sub.items() if k in IMAGE_DEFAULTS})


def codec_versions():
    """libavif / libwebp versions: part of the profile, so an encoder upgrade re-encodes instead of mixing outputs."""
    try:
        from PIL import features
        return "avif=%s,webp=%s" % (features.version("avif") or getattr(_avif_mod(), "libavif_version", "?"),
                                    features.version("webp"))
    except Exception:
        return "pil=%s" % (getattr(Image, "__version__", "?") if Image is not None else "none")


def _avif_mod():
    try:
        from PIL import _avif
        return _avif
    except Exception:
        return None


def profile_token(conf):
    """Short, stable id of everything that changes what a variant looks like (qualities, codec versions, the manual
    `profile` bump) - but not the encoder speed, so the hot path's fast encode and the worker's slower, smaller one
    are the same variant (the worker may replace the file in place)."""
    ic = image_conf(conf)
    raw = "|".join("%s=%s" % (k, ic.get(k)) for k in PROFILE_KEYS) + "|" + codec_versions()
    return hashlib.sha1(raw.encode()).hexdigest()[:10]


def auto_spec(want, width, conf):
    """The cache spec of an automatic variant - the one place media.py, worker.py and prewarm jobs agree on it:
    format + output width (None = source size) + profile_token()."""
    return "auto:%s:w=%s:%s:v2" % (want, int(width) if width else "full", profile_token(conf))


def snap_width(w, conf):
    """Requested width -> the smallest ladder rung >= w (capped at max_width), so `?w=` cannot fan out into thousands
    of variants. Raises ValueError for a non-number or w < 1 (-> 400)."""
    ic = image_conf(conf)
    s = str(w).strip()
    if not re.fullmatch(r"[0-9]{1,6}", s) or int(s) < 1:
        raise ValueError("w must be a whole number of pixels (1-%d)" % int(ic["max_width"]))
    w, top = int(s), int(ic["max_width"])
    rungs = sorted(int(x) for x in (ic.get("widths") or ()) if 0 < int(x) <= top) or [top]
    return next((r for r in rungs if r >= w), rungs[-1])


def target_size(w, h, width):
    """(tw, th) for a width rung on a w x h source; never larger than the source (no upscaling)."""
    if not width or width >= w:
        return w, h
    return int(width), max(1, round(h * width / w))


def _bomb_guard(ic):
    """Pillow's global decompression-bomb limit (warns above it, raises above 2x) as a backstop.

    It is set to the larger of max_mp / bg_max_mp so probe() can still read the size of a big image (and say
    "too large") and the worker can decode up to bg_max_mp; the per-call checks (_check_pixels against
    mp_limit()) are what actually keep a hot-path decode within max_mp. Nothing else in media.py / worker.py
    may lower this global.
    """
    if Image is not None:
        Image.MAX_IMAGE_PIXELS = int(max(ic["max_mp"], ic["bg_max_mp"]) * 1e6)


if Image is not None:
    _bomb_guard(IMAGE_DEFAULTS)
    # between the limit and 2x Pillow only warns; our own checks decide, so keep stderr quiet
    warnings.filterwarnings("ignore", category=Image.DecompressionBombWarning)


def mp_limit(conf, sync=True, mem_avail_mb=None):
    """Megapixel ceiling: max_mp on the hot path; bg_max_mp in the worker unless free RAM is below 3 GB - and never
    more than the available RAM can hold (measured 2026-10-03: ~41-45 MB peak working set per megapixel for an AVIF
    encode, e.g. 1.6 GB for a 39 MP PNG), keeping MEM_RESERVE_MB for everything else on the VM."""
    ic = image_conf(conf)
    if sync or (mem_avail_mb is not None and mem_avail_mb < LOW_MEM_MB):
        limit = float(ic["max_mp"])
    else:
        limit = float(max(ic["max_mp"], ic["bg_max_mp"]))
    if mem_avail_mb is not None:
        limit = min(limit, max(MIN_MEM_MP, (float(mem_avail_mb) - MEM_RESERVE_MB) / MB_PER_MP))
    return limit


def speed_for(fmt, conf, sync=True):
    """The 'speed' number used by encode_auto and the cost model: AVIF speed, or the WebP method (4 / 5)."""
    ic = image_conf(conf)
    if fmt == "avif":
        return int(ic["speed_sync"] if sync else ic["speed_bg"])
    return 4 if sync else 5


def beneficial(src_bytes, out_bytes, conf):
    """A variant is only worth serving if it is at least min_saving (10 %) smaller than the original."""
    if not src_bytes or out_bytes is None:
        return False
    return out_bytes <= src_bytes * (1 - float(image_conf(conf)["min_saving"]))


def last_timing():
    """Timing breakdown of this thread's last encode_auto/encode_explicit: decode_s, encode_s, candidates."""
    return dict(getattr(_tls, "timing", None) or {})


# ---------------------------------------------------------------------------------------------------- probe

def _webp_lossless(path):
    """True when a WebP file is VP8L (lossless). Reads chunk headers only."""
    try:
        with open(path, "rb") as f:
            head = f.read(65536)
    except (OSError, TypeError):
        return False
    if head[:4] != b"RIFF" or head[8:12] != b"WEBP":
        return False
    pos = 12
    while pos + 8 <= len(head):
        tag, size = head[pos:pos + 4], int.from_bytes(head[pos + 4:pos + 8], "little")
        if tag == b"VP8L":
            return True
        if tag == b"VP8 ":
            return False
        if tag == b"ANMF":  # first animation frame: 16 bytes of frame header, then its bitstream chunk
            return head[pos + 24:pos + 28] == b"VP8L"
        pos += 8 + size + (size & 1)
    return False


def probe(path, conf=None):
    """Header-only facts: format, mode, w, h, frames, lossless, alpha, mp (+ bytes, icc, palette_like, animated).

    palette_like is True for palette images and None (= not known yet) otherwise; palette_like() decides on demand.
    A file too large for even Pillow's backstop answers {"too_large": True} instead of raising.
    Unreadable / unknown files raise DecodeError.
    """
    _need_pil()
    if conf is not None:
        _bomb_guard(image_conf(conf))
    try:
        size = os.path.getsize(path)
    except (OSError, TypeError):
        size = None
    try:
        im = Image.open(path)
    except Image.DecompressionBombError as e:
        m = re.search(r"\((\d+) pixels\)", str(e))
        mp = int(m.group(1)) / 1e6 if m else float("inf")
        return {"format": None, "mode": None, "w": None, "h": None, "frames": 1, "lossless": False, "alpha": False,
                "mp": mp, "bytes": size, "icc": False, "palette_like": None, "animated": False, "too_large": True}
    except Exception as e:  # UnidentifiedImageError, truncated headers, unsupported variants ...
        raise DecodeError("%s: %s" % (e.__class__.__name__, e)) from e
    with im:
        fmt = (im.format or "").upper()
        w, h = im.size
        frames = 1
        if fmt in ANIMATED:
            try:
                frames = int(getattr(im, "n_frames", 1) or 1)
            except Exception:  # a broken trailing frame must not make the whole image unusable
                frames = 1
        if fmt == "WEBP":
            lossless = _webp_lossless(path)
        else:
            lossless = fmt not in LOSSY and fmt != "AVIF"
        return {"format": fmt, "mode": im.mode, "w": w, "h": h, "frames": frames, "lossless": lossless,
                "alpha": bool(im.has_transparency_data), "mp": round(w * h / 1e6, 4), "bytes": size,
                "icc": bool(im.info.get("icc_profile")), "palette_like": True if im.mode in ("P", "1") else None,
                "animated": frames > 1}


def palette_like(img_or_path):
    """<= 256 colours? Palette images are by definition; otherwise count colours on a <= 256 px nearest thumbnail
    (nearest keeps the real colour set, a smoothing filter would invent new ones)."""
    _need_pil()
    if not isinstance(img_or_path, Image.Image):
        with Image.open(img_or_path) as im:
            if im.mode in ("P", "1"):
                return True
            im.load()
            return palette_like(im)
    im = img_or_path
    if im.mode in ("P", "1"):
        return True
    w, h = im.size
    if max(w, h) > 256:
        s = 256 / max(w, h)
        im = im.resize((max(1, round(w * s)), max(1, round(h * s))), Image.NEAREST)
    return im.getcolors(256) is not None


# ---------------------------------------------------------------------------------------------------- choice

class Plan(tuple):
    """fmt ("avif" | "webp" | "orig"), opts (encoder options), animated, reason. Immutable, JSON-friendly."""
    __slots__ = ()

    def __new__(cls, fmt, opts=None, animated=False, reason=""):
        return super().__new__(cls, (fmt, dict(opts or {}), bool(animated), reason))

    fmt = property(lambda self: self[0])
    opts = property(lambda self: self[1])
    animated = property(lambda self: self[2])
    reason = property(lambda self: self[3])

    def as_dict(self):
        return {"fmt": self.fmt, "opts": dict(self.opts), "animated": self.animated, "reason": self.reason}

    @classmethod
    def from_dict(cls, d):
        return cls(d["fmt"], d.get("opts"), d.get("animated", False), d.get("reason", ""))

    def __repr__(self):
        return "Plan(fmt=%r, opts=%r, animated=%r, reason=%r)" % self


def _fits(fmt, w, h):
    if fmt == "webp":
        return max(w, h) <= WEBP_MAX_SIDE
    return max(w, h) <= AVIF_MAX_SIDE and w * h <= AVIF_MAX_PIXELS


def choose(info, want, conf, width=None):
    """Format decision for an automatic (_v=avif|webp) variant. want = "avif" (client takes AVIF and WebP) | "webp".

    width = the snapped ladder rung (None = source size). Format selection and dimension selection are separate:
    the plan carries opts["resize"] = (w, h) only when the rung is smaller than the source (never upscales).
    Sources already in the wanted format are only re-encoded for a resize; a lossy WebP source may still go to AVIF
    (measured: 118 KB WebP -> 14-19 KB AVIF) - the caller's min_saving check decides whether that is worth serving."""
    ic = image_conf(conf)
    want = (want or "avif").lower()
    if want not in ("avif", "webp"):
        raise ValueError("want must be avif or webp")
    if info.get("too_large") or not info.get("w") or not info.get("h"):
        return Plan("orig", reason="too_large")
    fmt, w, h = (info.get("format") or "").upper(), int(info["w"]), int(info["h"])
    mp = info.get("mp") or w * h / 1e6
    tw, th = target_size(w, h, width)
    resize = (tw, th) != (w, h)
    if fmt == "AVIF" and not resize:
        return Plan("orig", reason="already_avif")
    if fmt == "WEBP" and not resize and (want == "webp" or int(info.get("frames") or 1) > 1):
        return Plan("orig", reason="already_webp")
    if not resize and info.get("bytes") is not None and info["bytes"] < ic["min_bytes"]:
        return Plan("orig", reason="small")
    if mp > max(ic["max_mp"], ic["bg_max_mp"]):
        return Plan("orig", reason="too_large")
    frames = int(info.get("frames") or 1)
    if frames > int(ic["max_frames"]):
        return Plan("orig", reason="too_many_frames")
    # measured: a 127-frame 1080p GIF (263 MP of animation) took 151 s and came out 2.1x larger as animated WebP;
    # at 1080 wide (84 MP) 54 s, -50 %, 385 MB peak (resized frames are held in memory) -> cap the total
    if frames > 1 and tw * th / 1e6 * frames > float(ic["max_anim_mp"]):
        return Plan("orig", reason="animation_too_large")
    webp_q = int(ic["webp_quality"])
    extra = {"resize": [tw, th]} if resize else {}
    if frames > 1:  # animation -> animated WebP whatever the client prefers (never just the first frame)
        if not _fits("webp", tw, th):
            return Plan("orig", reason="too_large")
        return Plan("webp", dict({"quality": webp_q, "alpha_quality": 100, "minimize_size": True}, **extra), True,
                    "animated")
    lossless = bool(info.get("lossless")) and fmt not in LOSSY
    if want == "avif" and not _fits("avif", tw, th):
        want = "webp"
    if not _fits(want, tw, th):
        return Plan("orig", reason="too_large")
    if want == "avif":
        opts = ({"quality": int(ic["avif_quality_lossless"]), "subsampling": "4:4:4"} if lossless
                else {"quality": int(ic["avif_quality_lossy"]), "subsampling": "4:2:0"})
    else:
        opts = {"quality": webp_q, "alpha_quality": 100}
    opts.update(extra)
    if lossless and tw * th / 1e6 <= PALETTE_MAX_MP and info.get("palette_like") is not False and _fits("webp", tw, th):
        opts["lossless_candidate"] = True
    return Plan(want, opts, False, "lossless" if lossless else "lossy")


# ---------------------------------------------------------------------------------------------------- cost model

class CostModel:
    """Seconds an encode will take: EWMA seconds per megapixel per (fmt, speed) + decode + NAS read.

    Seeds were measured on this VM (Xeon E5-2667 v4, max_threads=2) with 4 MP photo-like and UI-like images:
    AVIF speed 7 0.20-0.49 s/MP (a 33 MP sample photo: 8.3 s = 0.25 s/MP; DESIGN's 3.7 s used Pillow's
    default of 6 threads), speed 6 ~0.55, speed 5 3.0-4.4 (!), WebP method 4 0.19-0.34, method 5 0.19-0.40,
    lossless WebP 0.05-0.74, PNG decode 0.003-0.025 s/MP.
    For fmt "webp" the speed is the WebP method; an AVIF-style speed > 6 is read as the hot-path method 4.
    observe() wants encode seconds only; encode_auto(..., model=m) feeds the model with exactly that.
    """
    ALPHA = 0.3
    NAS_BPS = 80e6            # SMB read throughput from the NAS
    OVERHEAD_S = 0.03         # fixed cost per encode (setup, container)
    MIN_MP = 0.05             # tiny images are dominated by the fixed cost, not by pixels
    RESIZE_S_PER_MP = 0.02    # LANCZOS downscale, per source megapixel
    SEED = {"avif:10": 0.10, "avif:9": 0.14, "avif:8": 0.22, "avif:7": 0.32, "avif:6": 0.60, "avif:5": 3.6,
            "avif:4": 5.5, "webp:0": 0.10, "webp:1": 0.14, "webp:2": 0.18, "webp:3": 0.24, "webp:4": 0.30,
            "webp:5": 0.34, "webp:6": 0.50, "webpll:4": 0.40, "webpll:5": 0.50, "webp_anim:4": 0.45,
            "webp_anim:5": 0.50}
    DECODE = {"PNG": 0.025, "JPEG": 0.008, "MPO": 0.008, "GIF": 0.02, "BMP": 0.006, "TIFF": 0.03, "WEBP": 0.02,
              "AVIF": 0.05}

    def __init__(self, rates=None):
        self.lock = threading.Lock()
        self.rates = dict(self.SEED)
        self.samples = {}
        if rates:
            self.rates.update({k: float(v) for k, v in rates.items() if k in self.SEED or ":" in k})

    @staticmethod
    def _key(fmt, speed):
        fmt = (fmt or "").lower()
        speed = int(speed)
        if fmt in ("webp", "webpll", "webp_anim") and speed > 6:
            speed = 4
        return "%s:%d" % (fmt, speed)

    def rate(self, fmt, speed):
        """Seconds per megapixel; unknown speeds extrapolate from the nearest measured one."""
        key = self._key(fmt, speed)
        with self.lock:
            if key in self.rates:
                return self.rates[key]
            fam, sp = key.split(":")
            known = sorted((int(k.split(":")[1]), v) for k, v in self.rates.items() if k.split(":")[0] == fam)
        if not known:
            return 1.0  # unknown format: pessimistic, so the hot path defers it
        sp = int(sp)
        near_speed, near_rate = min(known, key=lambda kv: abs(kv[0] - sp))
        return near_rate * (1.6 ** (near_speed - sp))  # every speed step down ~1.6x slower, up ~1.6x faster

    def observe(self, fmt, speed, mp, secs):
        """Feed one measured encode (encode seconds, not decode/read). Outliers are clamped to 5x per sample."""
        if not secs or secs <= 0 or not mp:
            return
        key = self._key(fmt, speed)
        cur = self.rate(fmt, speed)
        obs = max(0.0, secs - self.OVERHEAD_S) / max(float(mp), self.MIN_MP)
        obs = min(max(obs, cur / 5), cur * 5)
        with self.lock:
            self.rates[key] = cur + self.ALPHA * (obs - cur)
            self.samples[key] = self.samples.get(key, 0) + 1

    def estimate(self, info, fmt, speed, src_bytes=None, out_mp=None):
        """Predicted wall seconds for encode_auto(info -> fmt at speed), including decode and the NAS read.
        out_mp = megapixels actually encoded (a resized variant); decode still costs the full source."""
        fmt = (fmt or "").lower()
        if fmt not in ("avif", "webp"):
            return 0.0
        src_mp = float(info.get("mp") or ((info.get("w") or 0) * (info.get("h") or 0) / 1e6))
        mp = min(src_mp, float(out_mp)) if out_mp else src_mp
        frames = max(1, int(info.get("frames") or 1))
        src_bytes = info.get("bytes") if src_bytes is None else src_bytes
        read = (src_bytes or 0) / self.NAS_BPS
        # animations are decoded twice (durations pass + encoder pass)
        decode = self.DECODE.get((info.get("format") or "").upper(), 0.03) * src_mp * frames * (2 if frames > 1 else 1)
        if mp < src_mp:
            decode += self.RESIZE_S_PER_MP * src_mp * frames
        method = speed if fmt == "webp" else (4 if int(speed) >= 6 else 5)   # WebP method of this sync/bg path
        if frames > 1:
            enc = self.rate("webp_anim", method) * max(mp * frames, self.MIN_MP)
        else:
            enc = self.rate(fmt, speed) * max(mp, self.MIN_MP)
            if (info.get("lossless") and mp <= PALETTE_MAX_MP and info.get("palette_like") is not False
                    and (info.get("format") or "").upper() not in LOSSY):
                enc += self.rate("webpll", method) * max(mp, self.MIN_MP)  # the lossless WebP candidate
        return round(self.OVERHEAD_S + read + decode + enc, 4)

    def to_dict(self):
        with self.lock:
            return {"rates": {k: round(v, 5) for k, v in self.rates.items()}, "samples": dict(self.samples)}

    @classmethod
    def from_dict(cls, d):
        m = cls((d or {}).get("rates"))
        m.samples = dict((d or {}).get("samples") or {})
        return m


# ---------------------------------------------------------------------------------------------------- pixels

def _check_pixels(w, h, limit_mp):
    mp = w * h / 1e6
    if mp > limit_mp:
        raise TooLarge(mp, limit_mp)


def _strip_info(im):
    im.info = {k: im.info[k] for k in KEEP_INFO if k in im.info}
    return im


def _to_l(im):
    """16/32-bit and float greyscale -> 8-bit L, scaled (Pillow's plain convert() clips everything above 255)."""
    if im.mode == "F":
        lo, hi = im.getextrema()
        scale = 255.0 if hi <= 1.0 else (255.0 / hi if hi > 255 else 1.0)
        return im.point(lambda v: v * scale).convert("L")
    im = im.convert("I") if im.mode != "I" else im
    lo, hi = im.getextrema()
    if hi > 255:
        scale = 255.0 / (65535 if hi <= 65535 else hi)
        im = im.point(lambda v: v * scale)
    return im.convert("L")


def _cmyk_to_rgb(im, icc):
    if icc:
        try:  # colour-managed conversion through the embedded profile (print CMYK looks wrong otherwise)
            from PIL import ImageCms
            src = ImageCms.ImageCmsProfile(io.BytesIO(icc))
            return ImageCms.profileToProfile(im, src, ImageCms.createProfile("sRGB"), outputMode="RGB")
        except Exception:
            pass
    return im.convert("RGB")


def _normalize(im):
    """Any decoded mode -> L, LA, RGB or RGBA (+ the ICC profile that still describes the pixels, or None)."""
    icc = im.info.get("icc_profile")
    mode = im.mode
    if mode == "CMYK":
        return _strip_info(_cmyk_to_rgb(im, icc)), None  # now sRGB, which is what untagged means on the web
    if mode in ("I", "F") or mode.startswith("I;16"):
        im = _to_l(im)
    elif mode == "1":
        im = im.convert("L")
    elif mode in ("P", "PA"):
        im = im.convert("RGBA" if im.has_transparency_data else "RGB")
    elif mode in ("RGB", "L") and "transparency" in im.info:  # tRNS colour key -> real alpha
        im = im.convert("RGBA" if mode == "RGB" else "LA")
    elif mode == "RGBa":
        im = im.convert("RGBA")
    elif mode == "La":
        im = im.convert("LA")
    elif mode not in ("L", "LA", "RGB", "RGBA"):
        im = im.convert("RGB")  # YCbCr, LAB, HSV, RGBX ...
    im = _strip_info(im)
    im.info.pop("transparency", None)   # already applied as alpha above
    return im, icc


def _icc_for(icc, mode):
    """Keep the profile only if its colour space matches the pixels we write (a GRAY profile on RGB is invalid)."""
    if not icc or len(icc) < 20:
        return None
    space = icc[16:20]
    if mode in ("RGB", "RGBA") and space == b"RGB ":
        return icc
    if mode in ("L", "LA") and space == b"GRAY":
        return icc
    return None


def _opaque(im):
    return im.getchannel("A").getextrema() == (255, 255)


def _for_output(im, icc, target):
    """Final mode for one writer: flatten for JPEG, drop an all-opaque alpha plane for AVIF/WebP (saves bytes)."""
    mode = im.mode
    if target == "jpeg":
        if mode not in ("RGB", "L"):
            bg = Image.new("RGB", im.size, (255, 255, 255))
            rgba = im.convert("RGBA")
            bg.paste(rgba, mask=rgba.split()[-1])
            im = bg
    elif target in ("avif", "webp"):
        if mode == "LA":
            im = im.convert("RGBA")
        if im.mode == "RGBA" and _opaque(im):
            im = im.convert("RGB")
        if target == "webp" and im.mode == "L":
            im = im.convert("RGB")  # libwebp has no greyscale; do it here so the ICC check below sees RGB
    return im, _icc_for(icc, im.mode)


def _save(im, fmt, **opts):
    buf = io.BytesIO()
    try:
        im.save(buf, fmt, **opts)
    except Exception as e:
        raise EncodeError("%s: %s" % (e.__class__.__name__, e)) from e
    return buf.getvalue()


def alpha_cq(alpha_quality):
    """avif_alpha_quality (0-100, like quality) -> libavif/aom alpha quantizer (0 = lossless .. 63)."""
    q = min(100, max(0, int(alpha_quality)))
    return int(round((100 - q) * 63 / 100))


def _avif(im, icc, quality, speed, threads, subsampling=None, alpha_quality=None):
    out, prof = _for_output(im, icc, "avif")
    opts = {"quality": int(quality), "speed": int(speed), "max_threads": int(threads), "icc_profile": prof,
            "exif": b"", "xmp": b""}
    if subsampling:
        opts["subsampling"] = "4:0:0" if out.mode == "L" else subsampling
    if alpha_quality is not None and out.mode == "RGBA":   # separate alpha plane quality (measured: a:cq-level)
        opts["advanced"] = {"a:end-usage": "q", "a:cq-level": str(alpha_cq(alpha_quality))}
    return _save(out, "AVIF", **opts)


def _resize_to(im, size):
    """LANCZOS to exactly `size`; alpha is resized premultiplied so transparent pixels never bleed dark fringes."""
    if tuple(im.size) == tuple(size):
        return im
    try:
        if im.mode == "RGBA":
            return im.convert("RGBa").resize(tuple(size), Image.LANCZOS).convert("RGBA")
        if im.mode == "LA":
            return im.convert("La").resize(tuple(size), Image.LANCZOS).convert("LA")
        return im.resize(tuple(size), Image.LANCZOS)
    except Exception as e:
        raise EncodeError("%s: %s" % (e.__class__.__name__, e)) from e


def _webp(im, icc, quality, method, lossless=False, alpha_quality=100):
    out, prof = _for_output(im, icc, "webp")
    return _save(out, "WEBP", quality=int(quality), method=int(method), lossless=bool(lossless),
                 alpha_quality=int(alpha_quality), icc_profile=prof or "", exif=b"", xmp=b"")


def _open(src, limit_mp):
    """Open lazily and refuse sources above limit_mp before a single pixel is decoded."""
    try:
        im = Image.open(src)
    except Image.DecompressionBombError as e:
        raise TooLarge(float("inf"), limit_mp) from e
    except Exception as e:
        raise DecodeError("%s: %s" % (e.__class__.__name__, e)) from e
    try:
        _check_pixels(im.width, im.height, limit_mp)
    except TooLarge:
        im.close()
        raise
    return im


def _decode(im):
    try:
        out = ImageOps.exif_transpose(im)
        out.load()
        return out
    except Exception as e:
        raise DecodeError("%s: %s" % (e.__class__.__name__, e)) from e


# ---------------------------------------------------------------------------------------------------- encoders

def _encode_animated(im, plan, ic, sync, timing):
    """Animated GIF/APNG -> animated WebP, streaming frames through the encoder (never all frames in RAM)."""
    try:
        im.seek(0)
        loop = int(im.info.get("loop", 1))   # no NETSCAPE/acTL loop -> the GIF played once
        durations = []
        for i in range(im.n_frames):
            im.seek(i)
            d = int(im.info.get("duration") or 0)
            durations.append(d if d > 10 else 100)  # browsers show 0-10 ms GIF frames for 100 ms; keep that look
        im.seek(0)
        icc = im.info.get("icc_profile")
    except Exception as e:
        raise DecodeError("%s: %s" % (e.__class__.__name__, e)) from e
    timing["decode_s"] = round(time.perf_counter() - timing["_t0"], 4)
    method = speed_for("webp", ic, sync)
    size = plan.opts.get("resize")
    src, extra = im, {}
    if size:   # a resized animation: every frame (composited by Pillow) scaled; bounded by the caller's MP check
        try:
            frames = []
            for i in range(len(durations)):
                im.seek(i)
                frames.append(_resize_to(im.convert("RGBA"), size))
        except ImagingError:
            raise
        except Exception as e:
            raise DecodeError("%s: %s" % (e.__class__.__name__, e)) from e
        src, extra = frames[0], {"append_images": frames[1:]}
    t = time.perf_counter()
    prof = icc if icc and icc[16:20] == b"RGB " else ""
    data = _save(src, "WEBP", save_all=True, duration=durations, loop=loop, minimize_size=True, lossless=False,
                 quality=int(plan.opts.get("quality", ic["webp_quality"])), method=method,
                 alpha_quality=int(plan.opts.get("alpha_quality", 100)), background=(0, 0, 0, 0),
                 icc_profile=prof, exif=b"", xmp=b"", **extra)
    secs = round(time.perf_counter() - t, 4)
    timing["candidates"].append({"fmt": "webp", "kind": "animated", "bytes": len(data), "secs": secs,
                                 "key": "webp_anim", "speed": method, "mp": src.width * src.height / 1e6 * len(durations)})
    return data, "webp"


def encode_auto(src, info, plan, conf, sync=True, model=None, mem_avail_mb=None, speed=None):
    """Encode `src` (path or file object) as planned. Returns (data, fmt) - fmt may be "webp" for an AVIF plan
    when the lossless WebP candidate was smaller. `model` (a CostModel) is fed with pure encode seconds.
    speed overrides the AVIF speed of this path (speed_sync / speed_bg).
    Raises TooLarge / DecodeError / EncodeError (all with .kind); ValueError for an unusable plan."""
    _need_pil()
    if plan.fmt not in ("avif", "webp"):
        raise ValueError("plan %r has nothing to encode" % (plan.fmt,))
    ic = image_conf(conf)
    _bomb_guard(ic)
    limit = mp_limit(ic, sync, mem_avail_mb)
    if info and (info.get("mp") or 0) > limit:
        raise TooLarge(info["mp"], limit)
    timing = {"_t0": time.perf_counter(), "decode_s": 0.0, "candidates": [], "sync": sync}
    _tls.timing = None
    src_im = _open(src, limit)
    try:
        if plan.animated and getattr(src_im, "n_frames", 1) > 1:
            n = src_im.n_frames
            if n > int(ic["max_frames"]):
                raise TooLarge(float(n), float(ic["max_frames"]))
            out_w, out_h = plan.opts.get("resize") or src_im.size
            if out_w * out_h / 1e6 * n > float(ic["max_anim_mp"]):   # the real header, not the caller's info
                raise TooLarge(out_w * out_h / 1e6 * n, float(ic["max_anim_mp"]))
            data, fmt = _encode_animated(src_im, plan, ic, sync, timing)
        else:
            was_palette = src_im.mode in ("P", "1")
            im, icc = _normalize(_decode(src_im))
            if plan.opts.get("resize"):
                im = _resize_to(im, plan.opts["resize"])
            timing["decode_s"] = round(time.perf_counter() - timing["_t0"], 4)
            mp = im.width * im.height / 1e6
            cands = []
            t = time.perf_counter()
            if plan.fmt == "avif":
                speed = int(speed) if speed is not None else speed_for("avif", ic, sync)
                data = _avif(im, icc, plan.opts.get("quality", ic["avif_quality_lossless"]), speed, ic["threads"],
                             plan.opts.get("subsampling", "4:2:0"), ic.get("avif_alpha_quality"))
                cands.append({"fmt": "avif", "kind": "lossy", "key": "avif", "speed": speed, "data": data})
            else:
                speed = speed_for("webp", ic, sync)
                data = _webp(im, icc, plan.opts.get("quality", ic["webp_quality"]), speed,
                             alpha_quality=plan.opts.get("alpha_quality", 100))
                cands.append({"fmt": "webp", "kind": "lossy", "key": "webp", "speed": speed, "data": data})
            cands[-1]["secs"] = round(time.perf_counter() - t, 4)
            if plan.opts.get("lossless_candidate") and _fits("webp", *im.size) and (was_palette or palette_like(im)):
                t = time.perf_counter()
                method = speed_for("webp", ic, sync)
                data = _webp(im, icc, 75 if sync else 90, method, lossless=True)  # quality = effort when lossless
                cands.append({"fmt": "webp", "kind": "lossless", "key": "webpll", "speed": method, "data": data,
                              "secs": round(time.perf_counter() - t, 4)})
            for c in cands:
                c["bytes"], c["mp"] = len(c["data"]), mp
            best = min(cands, key=lambda c: c["bytes"])  # ties keep the planned (first) candidate
            data, fmt = best["data"], best["fmt"]
            timing["candidates"] = [{k: v for k, v in c.items() if k != "data"} for c in cands]
            timing["chosen"] = best["kind"]
    finally:
        src_im.close()
    timing["encode_s"] = round(sum(c["secs"] for c in timing["candidates"]), 4)
    timing["total_s"] = round(time.perf_counter() - timing.pop("_t0"), 4)
    _tls.timing = timing
    if model is not None:
        for c in timing["candidates"]:
            model.observe(c["key"], c["speed"], c["mp"], c["secs"])
    return data, fmt


# ---------------------------------------------------------------------------------------------------- explicit

def _int_param(v, lo, hi, msg):
    v = str(v).strip()
    if not re.fullmatch(r"[0-9]{1,9}", v):
        raise ValueError(msg)
    n = int(v)
    if n and not lo <= n <= hi:
        raise ValueError(msg)
    return n


def validate_explicit(params, conf):
    """Normalise ?w= ?h= ?fit= ?q= ?fm= exactly like transform.py (w=0 / h=0 mean "not given" there too).
    Returns {"w", "h", "fit", "q", "fm"}; raises ValueError with transform.py's messages (-> 400)."""
    ic = image_conf(conf)
    maxd = int(ic.get("max_dim") or 4096)
    msg = "w/h must be 1-%d" % maxd
    w = (_int_param(params["w"], 1, maxd, msg) or None) if params.get("w") else None
    h = (_int_param(params["h"], 1, maxd, msg) or None) if params.get("h") else None
    fit = params.get("fit") or "inside"
    if fit not in ("inside", "cover", "contain", "fill"):
        raise ValueError("fit must be inside, cover, contain or fill")
    q = _int_param(params.get("q") or 82, 1, 100, "q must be 1-100")
    if not 1 <= q <= 100:
        raise ValueError("q must be 1-100")
    fm = (params.get("fm") or "auto").lower()
    if fm not in FORMATS and fm != "auto":
        raise ValueError("fm must be webp, avif, jpeg or png")
    return {"w": w, "h": h, "fit": fit, "q": q, "fm": fm}


def _resize(im, w, h, fit, fm):
    """transform.py's geometry, verbatim: never upscales except fit=fill (exact box) and contain's padding canvas."""
    ow, oh = im.size
    if not (w or h):
        return im
    if fit == "cover" and w and h:
        return ImageOps.fit(im, (min(w, ow), min(h, oh)), Image.LANCZOS)
    if fit == "fill" and w and h:
        return im.resize((w, h), Image.LANCZOS)
    if fit == "contain" and w and h:
        inner = im.copy()
        inner.thumbnail((w, h), Image.LANCZOS)
        mode = "RGBA" if fm in ("png", "webp", "avif") else "RGB"
        canvas = Image.new(mode, (w, h), (255, 255, 255, 0) if mode == "RGBA" else (255, 255, 255))
        pos = ((w - inner.width) // 2, (h - inner.height) // 2)
        if mode == "RGB" and inner.mode in ("RGBA", "LA"):
            rgba = inner.convert("RGBA")
            canvas.paste(rgba, pos, mask=rgba.split()[-1])   # transparent pixels become white, not black
        else:
            canvas.paste(inner.convert(mode), pos)
        return canvas
    im = im.copy()
    im.thumbnail((w or ow, h or oh), Image.LANCZOS)
    return im


def family_format(info):
    """The output format of a plain resize that keeps the source's format family (no client negotiation): JPEG stays
    JPEG, WebP/AVIF stay themselves, everything lossless (PNG, BMP, TIFF, static GIF) becomes PNG."""
    fmt = (info.get("format") or "").upper()
    return {"JPEG": "jpeg", "MPO": "jpeg", "WEBP": "webp", "AVIF": "avif"}.get(fmt, "png")


def encode_family(src, info, width, conf):
    """`?w=` without a negotiated format: resize to the rung in the source's own format family. Returns (data, fmt).
    Animated sources are refused by the caller (a resized single frame would silently drop the animation)."""
    ic = image_conf(conf)
    fm = family_format(info)
    q = {"jpeg": ic["jpeg_quality"], "webp": ic["webp_quality"], "avif": ic["avif_quality_lossy"]}.get(fm, 82)
    tw, _th = target_size(int(info["w"]), int(info["h"]), width)
    sub = dict(ic, max_dim=max(int(ic["max_dim"]), int(ic["max_width"])))
    return encode_explicit(src, {"w": str(tw), "fm": fm, "q": str(int(q))}, sub)


def encode_explicit(src, params, conf):
    """Legacy ?w=&h=&fit=&fm=&q= transform (no caching here). Returns (data, fmt) with fmt in CONTENT_TYPE."""
    _need_pil()
    p = validate_explicit(params, conf)
    ic = image_conf(conf)
    _bomb_guard(ic)
    t0 = time.perf_counter()
    _tls.timing = None
    src_im = _open(src, float(ic["max_mp"]))
    try:
        src_fmt = (src_im.format or "PNG").upper()
        im, icc = _normalize(_decode(src_im))   # modes first: LANCZOS on a palette image would fall back to nearest
    finally:
        src_im.close()
    decode_s = time.perf_counter() - t0
    fm = p["fm"]
    if fm == "auto":
        fm = {"JPEG": "jpeg", "MPO": "jpeg", "WEBP": "webp", "AVIF": "avif"}.get(src_fmt, "png")
    fm = "jpeg" if fm == "jpg" else fm
    t = time.perf_counter()
    try:
        im = _resize(im, p["w"], p["h"], p["fit"], fm)
    except Exception as e:
        raise EncodeError("%s: %s" % (e.__class__.__name__, e)) from e
    q = p["q"]
    if fm == "avif":
        data = _avif(im, icc, q, ic["speed_sync"], ic["threads"])
    elif fm == "webp":
        data = _webp(im, icc, q, 4)
    elif fm == "jpeg":
        out, prof = _for_output(im, icc, "jpeg")
        opts = {"quality": q, "optimize": True, "progressive": True, "exif": b"", "comment": b""}
        if prof:
            opts["icc_profile"] = prof
        data = _save(out, "JPEG", **opts)
    else:
        out, prof = _for_output(im, icc, "png")
        data = _save(out, "PNG", optimize=True, icc_profile=prof)
    _tls.timing = {"decode_s": round(decode_s, 4), "encode_s": round(time.perf_counter() - t, 4),
                   "total_s": round(time.perf_counter() - t0, 4), "candidates": [], "sync": True}
    return data, fm
