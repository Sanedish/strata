"""Strata Media video - ffprobe / ffmpeg variants: WebM (AV1 via SVT-AV1, VP9 fallback, Opus audio) or, with
video.format = "mp4", MP4 (H.264 via libx264, AAC audio) that every player and device takes.

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
Missing ffmpeg/ffprobe raises VideoError(kind="tool_missing") (DESIGN 7.4: no retry until the tools change).
"""
import json
import math
import os
import threading
import time

try:
    import sandbox
except ImportError:  # parallel development / partial install: every call below then reports tool_missing
    sandbox = None

VIDEO_DEFAULTS = {"enabled": True, "format": "webm", "codec": "av1", "crf_av1": 30, "preset_av1": 8, "crf_vp9": 32,
                  "crf_h264": 23, "preset_h264": "medium", "audio_kbps": 128, "threads": 2, "cpu_pct": 50,
                  "max_seconds": 10800, "max_bytes": 8 << 30, "min_saving": 0.10, "timeout_factor": 15}
FORMATS = ("webm", "mp4")
CONTENT_TYPE = "video/webm"
SOURCE_EXT = {"mp4", "m4v", "mov", "mkv", "avi", "wmv", "flv"}
# sources already in a codec at least as efficient as the output: re-encoding would only lose quality
SKIP_CODECS = {"webm": {"av1", "vp9"}, "mp4": {"av1", "vp9", "hevc"}}
H264_PRESETS = ("ultrafast", "superfast", "veryfast", "faster", "fast", "medium", "slow", "slower", "veryslow")
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


def _which(name, conf):
    if sandbox is None:
        return None
    try:
        return sandbox.which(name, conf or {})
    except Exception:
        return None


def _run(cmd, timeout, mem_mb, cpu_pct):
    if sandbox is None:
        raise VideoError("tool_missing", "sandbox module unavailable")
    return sandbox.run(cmd, timeout, mem_mb=mem_mb, cpu_pct=cpu_pct, priority="idle")


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


def reset_cache():
    with _enc_lock:
        _enc_cache.clear()


def available(conf, fmt=None):
    """{"ffmpeg", "ffprobe", "av1", "vp9", "opus", "h264", "aac", "format", "codec" (effective), "ok", "error"} for
    fmt (default video.format) - the encoder list is cached 10 min."""
    vc = video_conf(conf)
    fmt = fmt if fmt in FORMATS else vc["format"]
    out = {"ffmpeg": _which("ffmpeg", conf), "ffprobe": _which("ffprobe", conf), "av1": False, "vp9": False,
           "opus": False, "h264": False, "aac": False, "format": fmt, "codec": None, "ok": False, "error": ""}
    if not out["ffmpeg"] or not out["ffprobe"]:
        out["error"] = "ffmpeg missing" if not out["ffmpeg"] else "ffprobe missing"
        return out
    try:
        names = _encoders(out["ffmpeg"])
    except VideoError as e:
        out["error"] = str(e)
        return out
    out.update(av1="libsvtav1" in names, vp9="libvpx-vp9" in names, opus="libopus" in names,
               h264="libx264" in names, aac="aac" in names)
    if fmt == "mp4":
        out["codec"] = "h264" if out["h264"] else None
        out["ok"] = bool(out["h264"] and out["aac"])
        if not out["ok"]:
            out["error"] = "no libx264 encoder" if not out["h264"] else "no aac encoder"
        return out
    if vc["codec"] == "vp9":
        out["codec"] = "vp9" if out["vp9"] else ("av1" if out["av1"] else None)
    else:
        out["codec"] = "av1" if out["av1"] else ("vp9" if out["vp9"] else None)
    out["ok"] = bool(out["codec"] and out["opus"])
    if not out["ok"]:
        out["error"] = "no AV1/VP9 encoder" if not out["codec"] else "no libopus encoder"
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
    codec = "h264" if fmt == "mp4" else avail.get("codec") or vc["codec"]
    threads = max(1, int(vc["threads"]))
    v = info["video"]
    fps = v.get("fps") or 30.0
    gop = max(1, int(round(min(fps, 60.0) * 10)))   # keyframe every ~10 s (<= 600 frames: bogus timebases)
    if codec == "h264":   # High profile, 4:2:0 8-bit: plays on every browser, phone, TV and Discord embed
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
    vargs += ["-pix_fmt", "yuv420p", "-g", str(gop)]
    if (v.get("width") or 0) % 2 or (v.get("height") or 0) % 2:
        vargs += ["-vf", "scale=trunc(iw/2)*2:trunc(ih/2)*2"]   # 4:2:0 needs even sizes (drops at most 1 px)
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
            "cpu_pct": int(vc["cpu_pct"]), "mem_mb": int(vc.get("mem_mb") or (3072 if pixels > 2_100_000 else 2048))}


def command(ffmpeg, src, out, p):
    """The exact ffmpeg command line for plan p (src and out are plain paths)."""
    t = str(p["threads"])
    return ([ffmpeg, "-hide_banner", "-nostdin", "-nostats", "-loglevel", "error", "-y",
             "-threads", t, "-filter_threads", t,
             "-protocol_whitelist", "file", "-format_whitelist", DEMUXERS, "-i", "file:" + src,
             "-map", "0:v:%d" % p["video_index"], "-map", "0:a?"]
            + list(p["video_args"]) + list(p["audio_args"])
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
    on success (result_kind(r) is None and a non-empty output) - check os.path.exists(dst), then beneficial()."""
    ffmpeg = _which("ffmpeg", conf)
    if not ffmpeg:
        raise VideoError("tool_missing", "ffmpeg")
    part = dst + ".part"
    _rm(part)
    r = _run(command(ffmpeg, src, part, plan), plan["timeout"], plan["mem_mb"], plan["cpu_pct"])
    ok = result_kind(r) is None and os.path.isfile(part) and os.path.getsize(part) > 0
    if ok:
        os.replace(part, dst)
    else:
        _rm(part)
    return r
