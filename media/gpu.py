"""Corium Media hardware video encoding: which GPUs exist, which ffmpeg can drive them, and their encoder flags.

Why it looks like this (media/DESIGN.md 7.6):
  * `ffmpeg -encoders` only says a build was compiled with a hardware encoder. The GPU, its driver and the
    driver's API version decide at runtime (every ffmpeg release needs a minimum NVIDIA driver, for example), so each
    device is proven with a one-frame test encode before a job is planned on it.
  * Machines often have several ffmpeg installs (winget, an unpacked zip in C:\\ffmpeg-*, a distro package,
    jellyfin-ffmpeg). While media.tools.ffmpeg is empty and the first build cannot drive any GPU, the others are
    tried, so a driver older than the newest ffmpeg still gets hardware encoding from an older build. A configured
    media.tools.ffmpeg is the operator's choice and is never second-guessed.
  * Several GPUs: devices are found per backend (NVIDIA cards through nvidia-smi, VAAPI render nodes). worker.py runs
    one video job per usable device at the same time (capacity(): video.gpu_jobs per device) and places each job on
    the least busy one. A device that fails at runtime is benched for BENCH_S and the job moves to the next device,
    then to the CPU when the encoder is "auto".
  * Hardware output is H.264 in MP4 only; WebM (AV1 / VP9) stays on the CPU.
  * Decoding runs on the GPU too while GPU compute is on (decode_args, video.gpu_decode): NVIDIA keeps the frames on
    the card from NVDEC through scale_cuda into NVENC, the other backends copy them back. Decoders lack some formats
    (AV1 or 4:4:4 H.264 on older cards), so video.transcode retries on the CPU and decode_failed() remembers it.

Backends: nvenc (NVIDIA, Windows + Linux), qsv (Intel Quick Sync), amf (AMD, Windows), vaapi (Intel / AMD, Linux).
Quality and speed come from the shared video.nvenc_cq / video.nvenc_preset settings, mapped per backend.
Nothing here imports video.py: it passes its sandboxed runner and encoder-list reader in (no import cycle).
"""
import glob
import os
import re
import shutil
import sys
import threading
import time

WIN = sys.platform == "win32"
BACKENDS = ("nvenc", "qsv", "amf", "vaapi")   # "auto" preference order
ENCODER = {"nvenc": "h264_nvenc", "qsv": "h264_qsv", "amf": "h264_amf", "vaapi": "h264_vaapi"}
CODECS = frozenset(ENCODER.values())
LABEL = {"nvenc": "NVENC", "qsv": "Quick Sync", "amf": "AMF", "vaapi": "VAAPI"}
VENDOR = {"nvenc": "NVIDIA", "qsv": "Intel", "amf": "AMD", "vaapi": "VAAPI"}
ID_RX = re.compile(r"^(nvenc|qsv|amf|vaapi):[A-Za-z0-9_.-]{1,32}$")
PRESETS = tuple("p%d" % n for n in range(1, 8))
QSV_PRESET = dict(zip(PRESETS, ("veryfast", "faster", "fast", "medium", "slow", "slower", "veryslow")))
AMF_QUALITY = dict(zip(PRESETS, ("speed", "speed", "balanced", "balanced", "quality", "quality", "quality")))
TTL = 600            # discovery is cached like the encoder list (a driver update is picked up within 10 min)
BENCH_S = 600        # a device that failed a real job sits out this long
MAX_FFMPEG = 6       # ffmpeg builds tried at most per discovery
MAX_JOBS = 8         # video.gpu_jobs ceiling per device
NO_DECODE_S = 3600   # a source type the GPU failed to decode is decoded on the CPU this long
PROBE_TIMEOUT = 30
NVIDIA_SMI = ([r"C:\Windows\System32\nvidia-smi.exe", r"C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe"]
              if WIN else ["/usr/bin/nvidia-smi", "/usr/local/bin/nvidia-smi"])
# nvidia-smi numbers GPUs in PCI bus order; CUDA (and so NVENC's -gpu) puts the fastest first unless told otherwise
NV_ENV = {"CUDA_DEVICE_ORDER": "PCI_BUS_ID"}

_lock = threading.Lock()
_discovering = threading.Lock()   # held while one thread runs the test encodes (discover)
_cache = {}          # key -> (monotonic ts, result)
_bench = {}          # device id -> (monotonic until, wall-clock until, error)
_rr = [0]            # round-robin position over the usable devices
_nodecode = {}       # (device id, "<codec>/<pix_fmt>", mode) -> monotonic until (decode_failed)


def is_device_id(s):
    return isinstance(s, str) and bool(ID_RX.match(s))


def reset():
    with _lock:
        _cache.clear()
        _bench.clear()
        _nodecode.clear()
        _rr[0] = 0
        _adapters[:] = [0.0, None]


# ---------------------------------------------------------------- encoder arguments

def env_for(dev):
    """Extra environment for ffmpeg runs on this device (merged into os.environ), or None."""
    return dict(os.environ, **NV_ENV) if dev and dev.get("backend") == "nvenc" else None


def input_args(dev):
    """Arguments before -i (device creation)."""
    if dev and dev.get("backend") == "vaapi" and dev.get("path"):
        return ["-vaapi_device", dev["path"]]
    return []


def filters(dev):
    """Video filters the backend needs after any scaling (frames to the GPU for VAAPI)."""
    return ["format=nv12", "hwupload"] if dev and dev.get("backend") == "vaapi" else []


def pix_fmt(dev):
    """-pix_fmt for the encoder input, None when the frames are already on the GPU."""
    b = (dev or {}).get("backend")
    return None if b == "vaapi" else "nv12" if b == "qsv" else "yuv420p"


def video_args(dev, vc):
    """-c:v ... for one device from the shared GPU settings (nvenc_cq 0-51, nvenc_preset p1-p7)."""
    b = (dev or {}).get("backend") or "nvenc"
    preset = vc.get("nvenc_preset") if vc.get("nvenc_preset") in PRESETS else "p5"
    cq = str(max(0, min(51, int(vc.get("nvenc_cq", 25)))))
    if b == "qsv":
        return ["-c:v", "h264_qsv", "-preset", QSV_PRESET[preset], "-global_quality", cq, "-profile:v", "high"]
    if b == "amf":
        return ["-c:v", "h264_amf", "-usage", "transcoding", "-quality", AMF_QUALITY[preset], "-rc", "cqp",
                "-qp_i", cq, "-qp_p", cq, "-qp_b", cq, "-profile:v", "high"]
    if b == "vaapi":
        return ["-c:v", "h264_vaapi", "-qp", cq, "-profile:v", "high"]
    args = ["-c:v", "h264_nvenc", "-preset", preset, "-rc", "vbr", "-cq", cq, "-b:v", "0", "-profile:v", "high"]
    if (dev or {}).get("index") is not None:
        args += ["-gpu", str(dev["index"])]
    return args


def hwaccel(dev):
    """ffmpeg -hwaccel that decodes on this device, or None (Quick Sync / AMF decode through D3D11 on Windows)."""
    b = (dev or {}).get("backend")
    if b == "nvenc":
        return "cuda"
    if b == "vaapi" and dev.get("path"):
        return "vaapi"
    return "d3d11va" if b in ("qsv", "amf") and WIN else None


def decode_args(dev, zero_copy=False):
    """Arguments before -i that decode on the device. zero_copy (NVIDIA): frames stay on the GPU for scale_cuda and
    NVENC; otherwise they come back to system memory for the CPU filters / a software encoder."""
    acc = hwaccel(dev)
    if not acc:
        return []
    args = ["-hwaccel", acc]
    if acc == "cuda":
        if dev.get("index") is not None:
            args += ["-hwaccel_device", str(dev["index"])]
        if zero_copy:
            args += ["-hwaccel_output_format", "cuda"]
    elif acc == "vaapi":
        args += ["-hwaccel_device", dev["path"]]
    return args


def zero_copy_filters():
    """Even sizes (4:2:0) and 8-bit 4:2:0 for H.264 High, done by the GPU on frames that never leave it."""
    return ["scale_cuda=trunc(iw/2)*2:trunc(ih/2)*2:format=yuv420p"]


def decode_ok(dev_id, src, mode):
    """False while this device is known not to decode `src` ("<codec>/<pix_fmt>") in `mode` (gpu | gpu_copy)."""
    with _lock:
        until = _nodecode.get((dev_id, src, mode))
    return not until or until <= time.monotonic()


def decode_failed(dev_id, src, mode):
    """A job decoded on the GPU failed and worked with CPU decoding: plan that kind of source on the CPU for a while
    (e.g. AV1 or 4:4:4 H.264 on a card whose decoder lacks them)."""
    with _lock:
        _nodecode[(dev_id, src, mode)] = time.monotonic() + NO_DECODE_S


def probe_cmd(ffmpeg, dev, vc):
    """One black 256x256 frame through the device's real encoder settings into the null muxer."""
    vf = filters(dev)
    pf = pix_fmt(dev)
    return ([ffmpeg, "-hide_banner", "-nostdin", "-loglevel", "error"] + input_args(dev)
            + ["-f", "lavfi", "-i", "color=c=black:s=256x256:r=1:d=1", "-frames:v", "1"]
            + (["-vf", ",".join(vf)] if vf else []) + (["-pix_fmt", pf] if pf else [])
            + video_args(dev, vc) + ["-f", "null", "-"])


# ---------------------------------------------------------------- error messages

def _short(err):
    """The lines of an ffmpeg failure that say why (encoder / driver / device lines), prefixes stripped."""
    lines = [ln.strip() for ln in (err or "").splitlines() if ln.strip()]
    keys = ("nvenc", "driver", "cuda", "qsv", "mfx", "amf", "vaapi", "va_", "device", "gpu", "encoder")
    why = [ln.split("] ", 1)[-1] for ln in lines if any(k in ln.lower() for k in keys)]
    return ("; ".join(dict.fromkeys(why[:3])) or (lines[0] if lines else ""))[:300]


def hint(backend, err, dev=None):
    """What the operator can do about a failed test encode ('' when there is nothing specific to say)."""
    e = (err or "").lower()
    m = re.search(r"required:\s*([\d.]+)\s*found:\s*([\d.]+)", e)
    drv = re.search(r"minimum required nvidia driver for nvenc is\s*([\d.]+)", e)
    if m or drv:
        need = drv.group(1) if drv else "a newer version"
        found = (" (this driver has NVENC API %s, this ffmpeg needs %s)" % (m.group(2), m.group(1))) if m else ""
        return ("This ffmpeg is newer than the NVIDIA driver%s. Update the driver to %s or newer, or install an "
                "older ffmpeg build next to it: Corium tries every installed ffmpeg while media.tools.ffmpeg is "
                "empty." % (found, need))
    if backend == "nvenc":
        if "cannot load" in e or "no nvenc capable devices" in e or "no device" in e or "cuda_error_no_device" in e:
            return "No usable NVIDIA GPU: install the NVIDIA driver (in a VM, pass the GPU through to it)."
        if "incompatible client key" in e or "out of memory" in e or "too many" in e:
            return ("The GPU's limit of parallel NVENC sessions is reached (other programs are encoding); "
                    "Corium retries later.")
        if "invalid gpu" in e or "requested gpu" in e:
            return "This GPU index does not exist (any more): pick another GPU in the video settings."
    if backend == "qsv" and ("mfx" in e or "session" in e or "unsupported" in e or "device" in e):
        return "Intel Quick Sync is not available: install the Intel graphics driver (oneVPL runtime) for this GPU."
    if backend == "amf" and ("amf" in e or "dll" in e):
        return "AMD AMF is not available: install the AMD graphics driver for this GPU."
    if backend == "vaapi":
        if "permission" in e or "denied" in e:
            return "The account Corium runs as cannot open %s: add it to the 'render' group." % (
                (dev or {}).get("path") or "the render node")
        return "VAAPI cannot open this device: install the Mesa (AMD) or intel-media-driver (Intel) VA driver."
    return ""


# ---------------------------------------------------------------- devices

PCI_VENDOR = {"10de": "nvidia", "8086": "intel", "1002": "amd", "1022": "amd"}
DISPLAY_CLASS = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
_adapters = [0.0, None]   # monotonic ts, cached adapters()


def _vendor_of(text):
    m = re.search(r"(?:ven_|0x)([0-9a-f]{4})", (text or "").lower())
    return PCI_VENDOR.get(m.group(1), "other") if m else "other"


def adapters():
    """Display adapters [{vendor: nvidia|intel|amd|other, name, node}] from the registry (Windows) or sysfs
    (Linux); None when that cannot be read. Quick Sync / AMF are only offered when such a GPU is present: a
    build lists both on every machine, and "unusable" for hardware that is not there would only confuse."""
    now = time.monotonic()
    with _lock:
        if _adapters[1] is not None and now - _adapters[0] < TTL:
            return _adapters[1]
    out = None
    try:
        if WIN:
            import winreg
            out = []
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, DISPLAY_CLASS) as cls:
                for i in range(64):
                    try:
                        sub = winreg.EnumKey(cls, i)
                    except OSError:
                        break
                    if not sub.isdigit():
                        continue
                    try:
                        with winreg.OpenKey(cls, sub) as k:
                            name = winreg.QueryValueEx(k, "DriverDesc")[0]
                            dev = winreg.QueryValueEx(k, "MatchingDeviceId")[0]
                    except OSError:
                        continue
                    out.append({"vendor": _vendor_of(dev), "name": str(name), "node": ""})
        else:
            out = []
            for v in sorted(glob.glob("/sys/class/drm/renderD*/device/vendor")):
                node = "/dev/dri/" + v.split("/")[4]
                with open(v) as f:
                    out.append({"vendor": _vendor_of(f.read()), "name": "", "node": node})
    except Exception:
        out = None
    with _lock:
        _adapters[:] = [now, out]
    return out


def _nvidia_smi():
    for p in [shutil.which("nvidia-smi")] + NVIDIA_SMI:
        if p and os.path.isfile(p):
            return p
    return None


def nvidia_gpus(run):
    """[{index, name, driver, uuid}] from nvidia-smi (PCI bus order), [] when it is missing or fails."""
    smi = _nvidia_smi()
    if not smi:
        return []
    try:
        r = run([smi, "--query-gpu=index,name,driver_version,uuid", "--format=csv,noheader,nounits"], 20, 256, 35)
    except Exception:
        return []
    if getattr(r, "rc", 1) != 0:
        return []
    out = []
    for line in (r.out or "").splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 3 and parts[0].isdigit():
            out.append({"index": int(parts[0]), "name": parts[1], "driver": parts[2],
                        "uuid": parts[3] if len(parts) > 3 else ""})
    return out


def devices(names, run):
    """Every hardware device this ffmpeg build could drive, untested: [{id, backend, index, name, ...}]."""
    out = []
    ads = adapters()
    present = None if ads is None else {a["vendor"] for a in ads}
    named = {v: next((a["name"] for a in ads or () if a["vendor"] == v and a["name"]), "") for v in ("intel", "amd")}
    if "h264_nvenc" in names:
        gpus = nvidia_gpus(run)
        for g in gpus:
            out.append({"id": "nvenc:%d" % g["index"], "backend": "nvenc", "index": g["index"], "name": g["name"],
                        "driver": g["driver"]})
        if not gpus:   # no nvidia-smi: one device, NVENC's default GPU
            out.append({"id": "nvenc:0", "backend": "nvenc", "index": None, "name": "NVIDIA GPU", "driver": ""})
    if "h264_qsv" in names and (present is None or "intel" in present):
        out.append({"id": "qsv:0", "backend": "qsv", "index": None, "name": named["intel"] or "Intel Quick Sync",
                    "driver": ""})
    if "h264_amf" in names and WIN and (present is None or "amd" in present):
        out.append({"id": "amf:0", "backend": "amf", "index": None, "name": named["amd"] or "AMD AMF", "driver": ""})
    if "h264_vaapi" in names and not WIN:
        vendor = {a["node"]: a["vendor"] for a in ads or ()}
        for node in sorted(glob.glob("/dev/dri/renderD*")):
            base = os.path.basename(node)
            v = vendor.get(node, "")
            out.append({"id": "vaapi:" + base, "backend": "vaapi", "index": None, "path": node,
                        "name": "VAAPI %s%s" % (base, " (%s)" % v.upper() if v in ("intel", "amd") else ""),
                        "driver": ""})
    return out


def _test(ffmpeg, dev, vc, run):
    try:
        r = run(probe_cmd(ffmpeg, dev, vc), PROBE_TIMEOUT, 1024, 35, env=env_for(dev))
    except Exception as e:
        return "%s: %s" % (e.__class__.__name__, str(e)[:200])
    if getattr(r, "rc", 1) == 0 and not getattr(r, "timed_out", False):
        return ""
    if getattr(r, "timed_out", False):
        return "test encode timed out"
    return _short(getattr(r, "err", "")) or "test encode failed (rc=%s)" % getattr(r, "rc", "?")


def _ffprobe_for(ffmpeg):
    """The ffprobe next to an ffmpeg (same build), or None."""
    d = os.path.dirname(ffmpeg)
    p = os.path.join(d, "ffprobe.exe" if WIN or ffmpeg.lower().endswith(".exe") else "ffprobe")
    return p if os.path.isfile(p) else None


def _mtime(p):
    try:
        return os.path.getmtime(p)
    except OSError:
        return 0


def discover(candidates, vc, run, encoders, fresh=False):
    """Hardware status for the ffmpeg builds in `candidates` (best first):
      {"ffmpeg": build that drives a GPU (else the first candidate), "ffprobe": its sibling or None,
       "devices": [{id, backend, index, name, driver, ok, error, hint}], "tried": [{ffmpeg, devices, usable}]}
    The first build with at least one usable device wins; later builds are only tried when the earlier ones have none.
    `encoders(ffmpeg)` -> set of encoder names, `run` = sandboxed runner. Cached TTL seconds."""
    cands = list(candidates)[:MAX_FFMPEG]
    key = (tuple((p, _mtime(p)) for p in cands), vc.get("nvenc_cq"), vc.get("nvenc_preset"))
    with _lock:
        hit = _cache.get(key)
        if hit and not fresh and time.monotonic() - hit[0] < TTL:
            return hit[1]
    # single flight: the worker's lanes all ask when the cache runs out, one round of test encodes answers them all
    with _discovering:
        with _lock:
            hit = _cache.get(key)
            if hit and not fresh and time.monotonic() - hit[0] < TTL:
                return hit[1]                 # another thread just discovered
        return _discover(cands, key, vc, run, encoders)


def _discover(cands, key, vc, run, encoders):
    now = time.monotonic()
    first, tried = None, []
    for ff in cands:
        try:
            names = encoders(ff)
        except Exception as e:
            tried.append({"ffmpeg": ff, "devices": 0, "usable": 0, "error": str(e)[:200]})
            continue
        devs = devices(names, run)
        for d in devs:
            d["error"] = _test(ff, d, vc, run)
            d["ok"] = not d["error"]
            d["hint"] = hint(d["backend"], d["error"], d) if d["error"] else ""
        usable = sum(1 for d in devs if d["ok"])
        tried.append({"ffmpeg": ff, "devices": len(devs), "usable": usable})
        res = {"ffmpeg": ff, "ffprobe": _ffprobe_for(ff), "devices": devs, "tried": tried}
        if first is None:
            first = res
        if usable:
            first = res
            break
    if first is None:
        first = {"ffmpeg": None, "ffprobe": None, "devices": [], "tried": tried}
    first["tried"] = tried
    with _lock:
        _cache[key] = (now, first)
    return first


# ---------------------------------------------------------------- selection, spreading, benching

def bench(dev_id, error=""):
    """A real job failed on this device: skip it for BENCH_S (the next discovery may clear it sooner)."""
    if not dev_id:
        return
    with _lock:
        _bench[dev_id] = (time.monotonic() + BENCH_S, time.time() + BENCH_S, (error or "")[-300:])


def benched():
    """{device id: {"until": wall-clock ts, "error": str}} for devices currently sitting out."""
    now = time.monotonic()
    with _lock:
        for k in [k for k, v in _bench.items() if v[0] <= now]:
            del _bench[k]
        return {k: {"until": round(v[1], 1), "error": v[2]} for k, v in _bench.items()}


def effective_pin(vc):
    """video.gpu as it applies to video.encoder: a GPU of another type than an explicit backend is ignored
    (pinned NVIDIA card, encoder switched to Quick Sync -> any Quick Sync device), so is a malformed id."""
    pin = vc.get("gpu") or "auto"
    engine = vc.get("encoder", "cpu")
    if pin == "auto" or not is_device_id(pin):
        return "auto"
    return pin if engine == "auto" or pin.split(":", 1)[0] == engine else "auto"


def select(disc, vc):
    """Usable devices for the encoder setting, in preference order: auto = every backend, a backend name = only
    that one; video.gpu = "auto" (all of them) or one device id. Benched devices are left out."""
    engine = vc.get("encoder", "cpu")
    allowed = BACKENDS if engine == "auto" else (engine,) if engine in BACKENDS else ()
    pin = effective_pin(vc)
    out_ = benched()
    devs = [d for d in disc.get("devices") or () if d.get("ok") and d["backend"] in allowed and d["id"] not in out_
            and (pin == "auto" or d["id"] == pin)]
    devs.sort(key=lambda d: (BACKENDS.index(d["backend"]), d["index"] if d.get("index") is not None else -1, d["id"]))
    return devs


def pick(devs):
    """Next device round-robin (jobs spread over all usable GPUs), None for an empty list."""
    if not devs:
        return None
    with _lock:
        i = _rr[0] % len(devs)
        _rr[0] += 1
    return devs[i]


def capacity(dev, vc):
    """Encodes one device runs at the same time (worker.py gives it that many video slots): video.gpu_jobs is a
    number for every GPU or {device id | backend | "*": number}; 1 by default, at most MAX_JOBS. More than one pays
    off on cards with several encoder engines or headroom left by one stream; GeForce drivers cap the parallel NVENC
    sessions per system (see session_limited)."""
    v = vc.get("gpu_jobs", 1)
    if isinstance(v, dict):
        dev = dev or {}
        v = next((v[k] for k in (dev.get("id"), dev.get("backend"), "*") if k in v), 1)
    try:
        n = int(v)
    except (TypeError, ValueError):
        n = 1
    return max(1, min(MAX_JOBS, n))


def session_limited(err):
    """ffmpeg's error says the driver refused another encode session (NVENC's per-system session cap: "incompatible
    client key" / "OpenEncodeSessionEx failed: out of memory"), i.e. the GPU is busy, not broken."""
    e = (err or "").lower()
    return ("incompatible client key" in e or "too many" in e or
            ("openencodesession" in e and "out of memory" in e))


def summary(disc, vc, selected=None):
    """JSON-friendly status for the dashboard (worker meta 'tools'.video.gpu)."""
    sel = selected if selected is not None else select(disc, vc)
    return {"ffmpeg": disc.get("ffmpeg"), "ffprobe": disc.get("ffprobe"), "tried": disc.get("tried") or [],
            "devices": [dict({k: d.get(k) for k in ("id", "backend", "index", "name", "driver", "ok", "error", "hint")},
                             jobs=capacity(d, vc))
                        for d in disc.get("devices") or ()],
            "selected": [d["id"] for d in sel], "benched": benched(),
            "encoder": vc.get("encoder", "cpu"), "gpu": vc.get("gpu") or "auto"}
