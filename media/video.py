"""Corium Media video - ffprobe / ffmpeg variants: WebM (AV1 via SVT-AV1, VP9 fallback, Opus audio) or, with
video.format = "mp4", MP4 (H.264 via libx264 or a GPU - NVENC, Quick Sync, AMF, VAAPI, see gpu.py - AAC audio)
for broad playback support.

Why it looks like this (media/DESIGN.md 7.6):
  * Video only ever runs in the background worker. Every ffprobe / ffmpeg call goes through sandbox.run (Job
    Object: IDLE priority, CPU hard cap video.cpu_pct, memory cap), and the encoder's own threads are capped too
    (SVT-AV1 lp=<threads>, -threads for decoding / VP9), so a 4K transcode can never starve Caddy/cloudflared.
  * Inputs are untrusted uploads. A file named .mp4 can really be an HLS/concat playlist that makes ffmpeg read
    other local files or URLs into the output, so inputs are opened as `file:<path>` with
    -protocol_whitelist file and -format_whitelist limited to the real video demuxers we transcode.
  * Output is WebM or MP4 (video.format): the picture is kept (resolution, fps, all audio tracks), only
    metadata goes (-map_metadata -1 drops titles, GPS "location" atoms, encoder tags).
  * The encode writes to <dst>.part and is renamed only when ffmpeg succeeded, so a crash or kill never leaves
    a truncated file that looks like a finished variant.
  * While GPU compute is on (video.encoder not "cpu", video.gpu_decode) the source is decoded on the GPU as well:
    decoding a large source costs more CPU than anything else in a GPU encode. A run that fails that way is
    repeated with CPU decoding (plan["hw_decode"], _hw_decode), so a format the decoder lacks still converts.
Missing ffmpeg/ffprobe raises VideoError(kind="tool_missing") (DESIGN 7.4: no retry until the tools change).
"""
import json
import hashlib
import math
import os
import threading
import time

try:
    import sandbox
except ImportError:  # parallel development / partial install: every call below then reports tool_missing
    sandbox = None
import gpu

VIDEO_DEFAULTS = {"enabled": True, "format": "webm", "codec": "av1", "encoder": "cpu",
                  "crf_av1": 30, "preset_av1": 8, "crf_vp9": 32,
                  "crf_h264": 23, "preset_h264": "medium", "nvenc_cq": 25, "nvenc_preset": "p5", "gpu": "auto",
                  "gpu_jobs": 1, "gpu_decode": True, "audio_kbps": 128, "threads": 2, "cpu_pct": 50,
                  "max_seconds": 10800, "max_bytes": 8 << 30, "min_saving": 0.10, "timeout_factor": 15}
SW_ENCODER = {"av1": "libsvtav1", "vp9": "libvpx-vp9"}
FORMATS = ("webm", "mp4")
CONTENT_TYPE = "video/webm"
SOURCE_EXT = {"mp4", "m4v", "mov", "mkv", "avi", "wmv", "flv"}
# sources already in a codec at least as efficient as the output: re-encoding would only lose quality
SKIP_CODECS = {"webm": {"av1", "vp9"}, "mp4": {"av1", "vp9", "hevc"}}
H264_PRESETS = ("ultrafast", "superfast", "veryfast", "faster", "fast", "medium", "slow", "slower", "veryslow")
NVENC_PRESETS = gpu.PRESETS   # shared by every hardware backend (gpu.QSV_PRESET / AMF_QUALITY map them)
ENCODERS = ("cpu", "auto") + gpu.BACKENDS
HW_CODECS = gpu.CODECS
ENCODER_NAME = dict(gpu.ENCODER)
# Demuxers ffmpeg may use on an input (av_match_list: "mov" matches "mov,mp4,m4a,3gp,3g2,mj2" etc.).
DEMUXERS = "mov,matroska,avi,asf,flv"
OPUS_LAYOUTS = "mono|stereo|3.0|quad|5.0|5.1|6.1|7.1"   # what libopus' Vorbis mapping (family 1) accepts
PROBE_TIMEOUT = 60
ENCODERS_TTL = 600
_enc_lock = threading.Lock()
_enc_cache = {}   # ffmpeg path -> (checked ts, mtime, set of encoder names)


class VideoError(Exception):
    """kind: tool_missing | probe_error | timeout | encode_error (becomes the job's error_kind)."""

    def __init__(self, kind, detail=""):
        super().__init__("%s: %s" % (kind, detail) if detail else kind)
        self.kind, self.detail = kind, detail


def video_conf(conf):
    """Video tunables from a full media config (or a video sub-dict / None), defaults filled in."""
    conf = conf or {}
    sub = conf.get("video") if isinstance(conf.get("video"), dict) else conf
    out = dict(VIDEO_DEFAULTS, **{k: v for k, v in sub.items() if k in VIDEO_DEFAULTS or k == "mem_mb"})
    if out["format"] not in FORMATS:
        out["format"] = "webm"
    return out


def spec(fmt, conf):
    """Variant identity includes every encode policy so changed settings never reuse stale output."""
    vc = video_conf(conf)
    # which GPU runs a job, how many share it and whether it decodes too (video.gpu, gpu_jobs, gpu_decode) is not
    # policy: the same settings on another card are the same variant
    relevant = {k: v for k, v in vc.items() if k not in ("enabled", "cpu_pct", "threads", "max_seconds", "max_bytes",
                                                          "timeout_factor", "mem_mb", "gpu", "gpu_jobs", "gpu_decode")}
    baseline = {k: v for k, v in VIDEO_DEFAULTS.items() if k in relevant}
    version = "v1" if relevant == baseline else hashlib.sha256(
        json.dumps(relevant, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:12]
    return "auto:%s:%s" % (fmt, version)


def _which(name, conf):
    if sandbox is None:
        return None
    try:
        return sandbox.which(name, conf or {})
    except Exception:
        return None


def _run(cmd, timeout, mem_mb, cpu_pct, env=None):
    if sandbox is None:
        raise VideoError("tool_missing", "sandbox module unavailable")
    if env is None:
        return sandbox.run(cmd, timeout, mem_mb=mem_mb, cpu_pct=cpu_pct, priority="idle")
    return sandbox.run(cmd, timeout, mem_mb=mem_mb, cpu_pct=cpu_pct, priority="idle", env=env)


def beneficial(src_bytes, out_bytes, conf):
    """DESIGN 7.6: not beneficial if the variant is >= 90 % (1 - min_saving) of the source."""
    if not src_bytes or out_bytes is None:
        return False
    return out_bytes < src_bytes * (1 - float(video_conf(conf)["min_saving"]))


def _encoders(ffmpeg):
    try:
        mtime = os.path.getmtime(ffmpeg)
    except OSError:
        mtime = 0
    with _enc_lock:
        hit = _enc_cache.get(ffmpeg)
        if hit and hit[1] == mtime and time.time() - hit[0] < ENCODERS_TTL:
            return hit[2]
    r = _run([ffmpeg, "-hide_banner", "-nostdin", "-encoders"], 30, 512, 35)
    if r.rc != 0 or r.timed_out:
        raise VideoError("tool_missing", "ffmpeg -encoders failed (rc=%s)" % r.rc)
    names, table = set(), False
    for line in (r.out or "").splitlines():
        if line.strip().startswith("------"):
            table = True
            continue
        parts = line.split()
        if table and len(parts) >= 2 and len(parts[0]) == 6:
            names.add(parts[1])
    with _enc_lock:
        _enc_cache[ffmpeg] = (time.time(), mtime, names)
    return names


def _filters(ffmpeg):
    """Filter names of a build (cached like _encoders); empty when it cannot say. Builds with CUDA decoding but no
    scale_cuda (it needs the CUDA compiler at build time) are common, so zero-copy jobs check for it first."""
    try:
        mtime = os.path.getmtime(ffmpeg)
    except OSError:
        mtime = 0
    key = (ffmpeg, "filters")
    with _enc_lock:
        hit = _enc_cache.get(key)
        if hit and hit[1] == mtime and time.time() - hit[0] < ENCODERS_TTL:
            return hit[2]
    try:
        r = _run([ffmpeg, "-hide_banner", "-nostdin", "-filters"], 30, 512, 35)
    except VideoError:
        return set()
    if r.rc != 0 or r.timed_out:
        return set()
    names = {p[1] for p in (ln.split() for ln in (r.out or "").splitlines()) if len(p) >= 3 and "->" in p[2]}
    with _enc_lock:
        _enc_cache[key] = (time.time(), mtime, names)
    return names


def _candidates(conf):
    if sandbox is None:
        return []
    try:
        return sandbox.candidates("ffmpeg", conf or {})
    except Exception:
        return []


def hardware(conf, fresh=False):
    """gpu.discover() over every installed ffmpeg (only the configured one when media.tools.ffmpeg is set)."""
    return gpu.discover(_candidates(conf), video_conf(conf), _run, _encoders, fresh=fresh)


def hardware_status(conf):
    """Dashboard view of the GPUs: devices, which ffmpeg drives them, what is selected / benched."""
    return gpu.summary(hardware(conf), video_conf(conf))


def bench(device_id, error=""):
    """worker.py: a real job failed on this GPU, plan the next one elsewhere for a while (gpu.BENCH_S)."""
    gpu.bench(device_id, error)


def reset_cache():
    with _enc_lock:
        _enc_cache.clear()
    gpu.reset()


def _hw_error(disc, engine, pin):
    """Why no GPU is selected for `engine` ('' = there is simply none): per device "<id>: <error>"."""
    mine = [d for d in disc["devices"] if (engine == "auto" or d["backend"] == engine) and pin in ("auto", d["id"])]
    if pin != "auto" and not mine:
        return "GPU %s not found" % pin
    rest = gpu.benched()
    return "; ".join("%s: %s" % (d["id"], d["error"] or ("resting after a failed job: " + rest[d["id"]]["error"]
                                                         if d["id"] in rest else "not selected"))
                     for d in mine)[:400]


def available(conf, fmt=None):
    """{"ffmpeg", "ffprobe", "av1", "vp9", "opus", "h264", "aac", "format", "codec" (effective), "ok", "error",
    "devices" (usable GPUs for this encoder setting, best first), "hw_ffmpeg" (the build that drives them),
    "decode_devices" / "decode_ffmpeg" (GPUs that decode for a WebM CPU encode), "zero_copy" (the GPU build has
    scale_cuda, so NVENC jobs can keep their frames on the card)} for fmt (default video.format) -
    the encoder list and the GPU discovery are cached 10 min."""
    vc = video_conf(conf)
    fmt = fmt if fmt in FORMATS else vc["format"]
    out = {"ffmpeg": _which("ffmpeg", conf), "ffprobe": _which("ffprobe", conf), "av1": False, "vp9": False,
           "opus": False, "h264": False, "h264_nvenc": False, "aac": False, "format": fmt,
           "codec": None, "ok": False, "error": "", "nvenc_error": "", "devices": [], "hw_ffmpeg": None,
           "decode_devices": [], "decode_ffmpeg": None, "zero_copy": False}
    if not out["ffmpeg"] or not out["ffprobe"]:
        out["error"] = "ffmpeg missing" if not out["ffmpeg"] else "ffprobe missing"
        return out
    try:
        names = _encoders(out["ffmpeg"])
    except VideoError as e:
        out["error"] = str(e)
        return out
    out.update(av1="libsvtav1" in names, vp9="libvpx-vp9" in names, opus="libopus" in names,
               h264="libx264" in names, h264_nvenc="h264_nvenc" in names, aac="aac" in names)
    if fmt == "mp4":
        engine = vc.get("encoder", "cpu")
        engine = engine if engine in ENCODERS else "cpu"
        sel, hw_err = [], ""
        if engine != "cpu":
            disc = hardware(conf)
            sel = gpu.select(disc, vc)
            nv = [d for d in disc["devices"] if d["backend"] == "nvenc"]
            out["h264_nvenc"] = any(d["ok"] for d in nv)          # listed *and* usable on this machine
            out["nvenc_error"] = "" if out["h264_nvenc"] else next((d["error"] for d in nv if d["error"]), "")
            hw_err = "" if sel else _hw_error(disc, engine, gpu.effective_pin(dict(vc, encoder=engine)))
            if sel:
                cuda = any(d["backend"] == "nvenc" for d in sel)
                out.update(devices=sel, hw_ffmpeg=disc["ffmpeg"],
                           zero_copy=cuda and "scale_cuda" in _filters(disc["ffmpeg"]))
        out["codec"] = (gpu.ENCODER[sel[0]["backend"]] if sel else
                        "h264" if engine in ("cpu", "auto") and out["h264"] else None)
        out["ok"] = bool(out["codec"] and out["aac"])
        if not out["ok"]:
            out["error"] = (("%s unusable: %s" % (ENCODER_NAME[engine], hw_err) if hw_err else
                             "no %s encoder" % ENCODER_NAME[engine]) if engine in gpu.BACKENDS else
                            "no libx264 encoder") if not out["codec"] else "no aac encoder"
        return out
    if vc["codec"] == "vp9":
        out["codec"] = "vp9" if out["vp9"] else ("av1" if out["av1"] else None)
    else:
        out["codec"] = "av1" if out["av1"] else ("vp9" if out["vp9"] else None)
    out["ok"] = bool(out["codec"] and out["opus"])
    if not out["ok"]:
        out["error"] = "no AV1/VP9 encoder" if not out["codec"] else "no libopus encoder"
    elif vc.get("encoder") == "auto" and vc.get("gpu_decode", True):
        # WebM is encoded on the CPU, but a GPU can still decode the source; the build that drives the GPU must
        # also have the software encoders, or the job keeps the default build and decodes on the CPU
        disc = hardware(conf)
        dec = [d for d in gpu.select(disc, vc) if gpu.hwaccel(d)]
        try:
            need = {SW_ENCODER[out["codec"]], "libopus"}
            fits = bool(dec and disc.get("ffmpeg")) and need <= _encoders(disc["ffmpeg"])
        except VideoError:
            fits = False
        if fits:
            out.update(decode_devices=dec, decode_ffmpeg=disc["ffmpeg"])
    return out


def _rate(s):
    try:
        num, _, den = str(s or "").partition("/")
        num, den = float(num), float(den or 1)
        return num / den if den and num > 0 else 0.0
    except ValueError:
        return 0.0


def _num(v, cast=float, default=0):
    try:
        return cast(v)
    except (TypeError, ValueError):
        return default


def parse_probe(data, path):
    """ffprobe JSON -> our info dict. Cover art (attached_pic) is never taken for the video track."""
    fmt = data.get("format") or {}
    streams = data.get("streams") or []
    vids = [s for s in streams if s.get("codec_type") == "video"]
    main = next(((i, s) for i, s in enumerate(vids) if not (s.get("disposition") or {}).get("attached_pic")), None)
    video = None
    if main:
        i, s = main
        rot = 0
        for sd in s.get("side_data_list") or []:
            if "rotation" in sd:
                rot = _num(sd.get("rotation"), int, 0)
        video = {"index": i, "codec": (s.get("codec_name") or "").lower(), "width": _num(s.get("width"), int, 0),
                 "height": _num(s.get("height"), int, 0),
                 "fps": round(_rate(s.get("avg_frame_rate")) or _rate(s.get("r_frame_rate")), 3),
                 "pix_fmt": s.get("pix_fmt") or "", "bit_rate": _num(s.get("bit_rate"), int, 0), "rotation": rot}
    audio = [{"codec": (s.get("codec_name") or "").lower(), "channels": _num(s.get("channels"), int, 0),
              "channel_layout": s.get("channel_layout") or "", "sample_rate": _num(s.get("sample_rate"), int, 0)}
             for s in streams if s.get("codec_type") == "audio"]
    duration = _num(fmt.get("duration"), float, 0.0) or (_num(vids[main[0]].get("duration"), float, 0.0) if main else 0.0)
    size = _num(fmt.get("size"), int, 0)
    if not size:
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
    return {"path": path, "ext": os.path.splitext(path)[1].lower().lstrip("."), "container": fmt.get("format_name", ""),
            "duration": round(duration, 3), "size": size, "bit_rate": _num(fmt.get("bit_rate"), int, 0),
            "video": video, "audio": audio}


def probe(path, conf):
    """ffprobe (sandboxed, 60 s) -> {"path", "ext", "container", "duration", "size", "bit_rate", "video", "audio"}."""
    ffprobe = _which("ffprobe", conf)
    if not ffprobe:
        raise VideoError("tool_missing", "ffprobe")
    cmd = [ffprobe, "-hide_banner", "-v", "error", "-protocol_whitelist", "file", "-format_whitelist", DEMUXERS,
           "-print_format", "json", "-show_format", "-show_streams", "file:" + path]
    r = _run(cmd, PROBE_TIMEOUT, 512, 35)
    if r.timed_out:
        raise VideoError("timeout", "ffprobe")
    if r.rc != 0:
        raise VideoError("probe_error", (r.err or "").strip()[-300:])
    try:
        return parse_probe(json.loads(r.out or "{}"), path)
    except ValueError as e:
        raise VideoError("probe_error", "bad ffprobe json: %s" % e) from e


def skip_reason(info, conf, fmt=None):
    """Why no variant is made (None = transcode): disabled, webm, no_video, already_av1|vp9|hevc, too_long, too_big."""
    vc = video_conf(conf)
    fmt = fmt if fmt in FORMATS else vc["format"]
    if not vc["enabled"]:
        return "disabled"
    if (info.get("ext") or "").lower() == "webm":
        return "webm"
    v = info.get("video")
    if not v:
        return "no_video"
    if v.get("codec") in SKIP_CODECS[fmt]:
        return "already_" + v["codec"]
    if (info.get("duration") or 0) > vc["max_seconds"]:
        return "too_long"
    if (info.get("size") or 0) > vc["max_bytes"]:
        return "too_big"
    return None


def plan(info, conf, avail=None, fmt=None):
    """Transcode plan (dict) or None when the source is skipped (see skip_reason). `avail` = available(conf, fmt)."""
    vc = video_conf(conf)
    fmt = fmt if fmt in FORMATS else vc["format"]
    if skip_reason(info, conf, fmt):
        return None
    if avail is None:
        avail = available(conf, fmt)
    codec = (avail.get("codec") or "h264") if fmt == "mp4" else avail.get("codec") or vc["codec"]
    threads = max(1, int(vc["threads"]))
    v = info["video"]
    fps = v.get("fps") or 30.0
    gop = max(1, int(round(min(fps, 60.0) * 10)))   # keyframe every ~10 s (<= 600 frames: bogus timebases)
    dev = None
    if codec in HW_CODECS:
        backend = next(b for b, c in gpu.ENCODER.items() if c == codec)
        # spread jobs over every usable GPU of that backend; an avail without devices (tests, old callers) means
        # the backend's default device
        dev = (gpu.pick([d for d in avail.get("devices") or () if d.get("backend") == backend])
               or {"id": backend + ":0", "backend": backend, "index": None})
        vargs = gpu.video_args(dev, vc)
    elif codec == "h264":   # High profile, 4:2:0 8-bit: plays on every browser, phone, TV and Discord embed
        preset = vc["preset_h264"] if vc["preset_h264"] in H264_PRESETS else "medium"
        vargs = ["-c:v", "libx264", "-preset", preset, "-crf", str(int(vc["crf_h264"])), "-profile:v", "high",
                 "-threads", str(threads)]
    elif codec == "vp9":
        vargs = ["-c:v", "libvpx-vp9", "-deadline", "good", "-cpu-used", "4", "-row-mt", "1",
                 "-crf", str(int(vc["crf_vp9"])), "-b:v", "0", "-threads", str(threads)]
    else:
        codec = "av1"
        vargs = ["-c:v", "libsvtav1", "-preset", str(int(vc["preset_av1"])), "-crf", str(int(vc["crf_av1"])),
                 "-svtav1-params", "lp=%d" % threads]
    pf = gpu.pix_fmt(dev) if dev else "yuv420p"
    zero_args = vargs + ["-g", str(gop), "-vf", ",".join(gpu.zero_copy_filters())]
    vargs = vargs + (["-pix_fmt", pf] if pf else []) + ["-g", str(gop)]
    vf = []
    if (v.get("width") or 0) % 2 or (v.get("height") or 0) % 2:
        vf.append("scale=trunc(iw/2)*2:trunc(ih/2)*2")   # 4:2:0 needs even sizes (drops at most 1 px)
    vf += gpu.filters(dev)
    if vf:
        vargs += ["-vf", ",".join(vf)]
    audio = info.get("audio") or []
    acodec = "aac" if fmt == "mp4" else "opus"
    if not audio:
        aargs, amode = [], None
    elif all(a.get("codec") == acodec for a in audio):
        aargs, amode = ["-c:a", "copy"], "copy"
    elif fmt == "mp4":
        ch = max(a.get("channels") or 2 for a in audio)
        aargs, amode = ["-c:a", "aac", "-b:a", "%dk" % min(512, int(vc["audio_kbps"]) * max(1, math.ceil(ch / 2)))], "aac"
    else:
        ch = max(a.get("channels") or 2 for a in audio)
        kbps = min(512, int(vc["audio_kbps"]) * max(1, math.ceil(ch / 2)))
        aargs, amode = ["-c:a", "libopus", "-b:a", "%dk" % kbps], "opus"
        if ch > 2:  # e.g. 5.1(side) is not a layout libopus takes: remap to the nearest one it does
            aargs += ["-mapping_family", "1", "-af", "aformat=channel_layouts=" + OPUS_LAYOUTS]
    duration = float(info.get("duration") or 0)
    pixels = (v.get("width") or 0) * (v.get("height") or 0)
    return {"format": fmt, "codec": codec, "video_index": int(v.get("index") or 0), "video_args": vargs, "audio_args": aargs,
            "audio": amode, "threads": threads, "fps": fps, "gop": gop, "duration": duration,
            "src_bytes": int(info.get("size") or 0),
            "timeout": max(600, int(math.ceil(duration * float(vc["timeout_factor"])))),
            "cpu_pct": int(vc["cpu_pct"]), "mem_mb": int(vc.get("mem_mb") or (3072 if pixels > 2_100_000 else 2048)),
            "device": dev["id"] if dev else None, "device_name": (dev or {}).get("name"),
            "input_args": gpu.input_args(dev), "ffmpeg": avail.get("hw_ffmpeg") if dev else None,
            "nv_env": bool(dev and dev.get("backend") == "nvenc"),
            "hw_decode": _hw_decode(v, vc, dev, avail, vargs, zero_args)}


def _hw_decode(v, vc, dev, avail, sw_args, zero_args):
    """How a GPU decodes the source, or None (the CPU does): mode "gpu" keeps the frames on the NVIDIA card from the
    decoder through scale_cuda into NVENC (when the build has it); "gpu_copy" brings them back to system memory for
    the CPU filters or a software encoder - always for rotated sources, whose autorotate filters run on the CPU.
    Only while GPU compute is on (video.encoder not "cpu", video.gpu_decode) and the device has not failed this kind
    of source lately."""
    if vc.get("encoder") == "cpu" or not vc.get("gpu_decode", True):
        return None
    on = dev or gpu.pick(list(avail.get("decode_devices") or ()))
    if not on or not gpu.hwaccel(on):
        return None
    src = "%s/%s" % (v.get("codec") or "?", v.get("pix_fmt") or "?")
    zero = (bool(dev) and dev.get("backend") == "nvenc" and bool(avail.get("zero_copy"))
            and not (v.get("rotation") or 0) % 360)
    mode = "gpu" if zero else "gpu_copy"
    if not gpu.decode_ok(on["id"], src, mode):
        return None
    return {"mode": mode, "device": on["id"], "src": src, "input_args": gpu.decode_args(on, zero),
            "video_args": zero_args if zero else sw_args, "ffmpeg": None if dev else avail.get("decode_ffmpeg"),
            "nv_env": on.get("backend") == "nvenc"}


def command(ffmpeg, src, out, p, hw=None):
    """The exact ffmpeg command line for plan p (src and out are plain paths); hw = p["hw_decode"] decodes on it."""
    t = str(p["threads"])
    return ([ffmpeg, "-hide_banner", "-nostdin", "-nostats", "-loglevel", "error", "-y",
             "-threads", t, "-filter_threads", t]
            + list(p.get("input_args") or ()) + list((hw or {}).get("input_args") or ())
            + ["-protocol_whitelist", "file", "-format_whitelist", DEMUXERS, "-i", "file:" + src,
             "-map", "0:v:%d" % p["video_index"], "-map", "0:a?"]
            + list((hw or p)["video_args"]) + list(p["audio_args"])
            + ["-map_metadata", "-1"]
            # MP4: the index goes to the front, so a player can start before the whole file has arrived
            + (["-movflags", "+faststart", "-f", "mp4"] if p.get("format") == "mp4" else ["-f", "webm"])
            + ["file:" + out])


def result_kind(r):
    """Error kind of a finished sandbox.Result: None (success), timeout, memory | processes | sandbox_error
    (the sandbox killed it), encode_error (ffmpeg failed)."""
    if r is None:
        return "encode_error"
    if getattr(r, "timed_out", False):
        return "timeout"
    if getattr(r, "killed", None):
        return str(r.killed)
    if getattr(r, "rc", 1) != 0:
        return "encode_error"
    return None


def _rm(path):
    try:
        os.remove(path)
    except OSError:
        pass


def transcode(src, dst, plan, conf):
    """Run ffmpeg for `plan` into dst (via dst.part + os.replace). Returns the sandbox.Result; dst exists only
    on success (result_kind(r) is None and a non-empty output) - check os.path.exists(dst), then beneficial().
    A plan with hw_decode decodes on the GPU first; when that fails (not a timeout) the same encode runs again with
    CPU decoding, so a decoder limit never counts as a failed GPU, and plan["decoded"] says which one made it."""
    ffmpeg = plan.get("ffmpeg") or _which("ffmpeg", conf)   # a GPU plan names the build that passed its test
    if not ffmpeg:
        raise VideoError("tool_missing", "ffmpeg")
    part = dst + ".part"
    hw = plan.get("hw_decode")
    plan["decoded"] = "cpu"
    if hw:
        r = _attempt(hw.get("ffmpeg") or ffmpeg, src, part, plan, hw)
        if _done(r, part):
            plan["decoded"] = hw["mode"]
            os.replace(part, dst)
            return r
        if result_kind(r) == "timeout":   # a second run would only double the wait
            _rm(part)
            return r
    r = _attempt(ffmpeg, src, part, plan)
    if not _done(r, part):
        _rm(part)
        return r
    if hw:
        gpu.decode_failed(hw["device"], hw["src"], hw["mode"])
    os.replace(part, dst)
    return r


def _attempt(ffmpeg, src, part, plan, hw=None):
    _rm(part)
    env = gpu.env_for({"backend": "nvenc"}) if plan.get("nv_env") or (hw or {}).get("nv_env") else None
    return _run(command(ffmpeg, src, part, plan, hw), plan["timeout"], plan["mem_mb"], plan["cpu_pct"], env=env)


def _done(r, part):
    return result_kind(r) is None and os.path.isfile(part) and os.path.getsize(part) > 0
