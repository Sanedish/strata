"""video.py: encoder discovery, ffprobe parsing, skip rules, exact ffmpeg command lines, atomic output.

Run: python -m unittest discover -s media/tests -t media/tests -p "test_codecs_video*.py"
sandbox.run / sandbox.which are replaced by a recording fake, so the command lines are asserted exactly without
ffmpeg. The real-transcode test runs only when the real sandbox finds ffmpeg + ffprobe (install.ps1).
"""
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
MEDIA = os.path.dirname(HERE)
if MEDIA not in sys.path:
    sys.path.insert(0, MEDIA)
try:
    import pathfix  # noqa: F401
except Exception:
    pass

import gpu  # noqa: E402
import video  # noqa: E402

try:
    import sandbox as real_sandbox
except Exception:  # parallel development: the real-ffmpeg test is skipped then
    real_sandbox = None

FFMPEG, FFPROBE = r"C:\fake\ffmpeg.exe", r"C:\fake\ffprobe.exe"
CONF = {"video": dict(video.VIDEO_DEFAULTS), "tools": {}}
ENC_HEAD = """Encoders:
 V..... = Video
 A..... = Audio
 S..... = Subtitle
 .F.... = Frame-level multithreading
 ------
 V....D libx264              libx264 H.264 / AVC / MPEG-4 AVC / MPEG-4 part 10 (codec h264)
 V....D libvpx-vp9           libvpx VP9 (codec vp9)
 A....D aac                  AAC (Advanced Audio Coding)
 A....D libopus              libopus Opus (codec opus)
"""
ENC_AV1 = ENC_HEAD + " V....D libsvtav1            SVT-AV1(Scalable Video Technology for AV1) encoder (codec av1)\n"
ENC_NVENC = ENC_AV1 + " V....D h264_nvenc          NVIDIA NVENC H.264 encoder (codec h264)\n"
FILTERS = """Filters:
  T.. = Timeline support
  ------
 .. scale              V->V       Scale the input video size and/or convert the image format.
 .. scale_cuda         V->V       GPU accelerated video resizer
"""
NO_SCALE_CUDA = FILTERS.split(" .. scale_cuda")[0]
AVAIL_AV1 = {"codec": "av1", "ok": True, "av1": True, "vp9": True, "opus": True}
AVAIL_VP9 = {"codec": "vp9", "ok": True, "av1": False, "vp9": True, "opus": True}
AVAIL_MP4 = {"codec": "h264", "ok": True, "h264": True, "aac": True, "format": "mp4"}
MP4 = {"video": dict(video.VIDEO_DEFAULTS, format="mp4"), "tools": {}}


def ffprobe_json(vcodec="h264", w=1920, h=1080, fps="30000/1001", duration="120.5", size="50000000",
                 audio=(("aac", 2, "stereo"),), cover=False, fmt="mov,mp4,m4a,3gp,3g2,mj2", rotation=-90,
                 pix_fmt="yuv420p"):
    streams = []
    if cover:
        streams.append({"index": 0, "codec_type": "video", "codec_name": "mjpeg", "width": 600, "height": 600,
                        "avg_frame_rate": "0/0", "disposition": {"attached_pic": 1}})
    streams.append({"index": len(streams), "codec_type": "video", "codec_name": vcodec, "width": w, "height": h,
                    "avg_frame_rate": fps, "r_frame_rate": fps, "pix_fmt": pix_fmt, "bit_rate": "4000000",
                    "disposition": {"attached_pic": 0},
                    "side_data_list": [{"side_data_type": "Display Matrix", "rotation": rotation}]})
    for codec, ch, layout in audio:
        streams.append({"index": len(streams), "codec_type": "audio", "codec_name": codec, "channels": ch,
                        "channel_layout": layout, "sample_rate": "48000"})
    return {"format": {"format_name": fmt, "duration": duration, "size": size, "bit_rate": "3300000"},
            "streams": streams}


class Res:
    def __init__(self, rc=0, out="", err="", timed_out=False, killed=None):
        self.rc, self.out, self.err, self.timed_out, self.killed, self.secs = rc, out, err, timed_out, killed, 0.1


SMI = r"C:\fake\nvidia-smi.exe"
DRIVER_TOO_OLD = ("[h264_nvenc @ 0x1] Driver does not support the required nvenc API version. Required: 13.1 Found: 13.0\n"
                  "[h264_nvenc @ 0x1] The minimum required Nvidia driver for nvenc is 610.00 or newer\n"
                  "[vost#0:0/h264_nvenc @ 0x2] Error while opening encoder\n")


def is_hw_test(cmd):
    return cmd[-1] == "-" and "-c:v" in cmd


class FakeSandbox:
    """Records every run(); answers -encoders / nvidia-smi / GPU test encodes / ffprobe / ffmpeg like the real tools.
    `builds` = {ffmpeg path: encoder list} for extra installs (candidates() lists them after FFMPEG);
    `hw_err(cmd)` -> stderr of a failing GPU test encode ('' = it works); `gpus` = nvidia-smi rows (None = no smi);
    `fail(cmd)` -> a Res for a transcode that should end that way (None = the defaults below); `filters` = what
    `ffmpeg -filters` lists."""

    def __init__(self, encoders=ENC_AV1, probe=None, tools=None, rc=0, write=True, timed_out=False, killed=None,
                 nvenc_err="", builds=None, hw_err=None, gpus=None, configured=False, fail=None, filters=FILTERS):
        self.encoders, self.probe, self.nvenc_err = encoders, probe or ffprobe_json(), nvenc_err
        self.tools = {"ffmpeg": FFMPEG, "ffprobe": FFPROBE} if tools is None else tools
        self.rc, self.write, self.timed_out, self.killed = rc, write, timed_out, killed
        self.builds, self.hw_err, self.gpus, self.configured = dict(builds or {}), hw_err, gpus, configured
        self.fail, self.filters = fail, filters
        self.calls = []

    def which(self, name, conf=None):
        return self.tools.get(name)

    def candidates(self, name, conf=None):
        if not self.tools.get(name):
            return []
        return [self.tools[name]] + ([] if self.configured else list(self.builds))

    def run(self, cmd, timeout, mem_mb=1024, cpu_pct=35, priority="idle", cwd=None, env=None, max_output=4 << 20):
        self.calls.append({"cmd": list(cmd), "timeout": timeout, "mem_mb": mem_mb, "cpu_pct": cpu_pct,
                           "priority": priority, "env": env})
        if "-encoders" in cmd:
            return Res(out=self.builds.get(cmd[0], self.encoders))
        if "-filters" in cmd:
            return Res(out=self.filters)
        if cmd[0] == SMI:
            rows = "\n".join("%d, %s, %s, GPU-%d" % (i, n, d, i) for i, (n, d) in enumerate(self.gpus or ()))
            return Res(out=rows + "\n")
        if is_hw_test(cmd):
            err = self.hw_err(cmd) if self.hw_err else (self.nvenc_err if "h264_nvenc" in cmd else "")
            return Res(rc=1 if err else 0, err=err)
        if cmd[0] == FFPROBE:
            return Res(rc=self.rc, out=json.dumps(self.probe), err="boom" if self.rc else "")
        out = cmd[-1]
        assert out.startswith("file:"), out
        res = self.fail(cmd) if self.fail else None
        if res is not None:
            return res
        if self.write:
            with open(out[5:], "wb") as f:
                f.write(b"\x1a\x45\xdf\xa3" + b"\0" * 64)   # EBML magic + filler
        return Res(rc=self.rc, timed_out=self.timed_out, killed=self.killed or ("timeout" if self.timed_out else None))


class Base(unittest.TestCase):
    def setUp(self):
        video.reset_cache()
        self.tmp = tempfile.mkdtemp(prefix="strata-video-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)
        video.reset_cache()

    def fake(self, **kw):
        ads = kw.pop("adapters", None)   # display adapters; None = unknown (every backend the build lists is offered)
        fk = FakeSandbox(**kw)
        for p in (mock.patch.object(video, "sandbox", fk),
                  mock.patch.object(gpu, "_nvidia_smi", lambda: SMI if fk.gpus is not None else None),
                  mock.patch.object(gpu, "adapters", lambda: ads)):
            p.start()
            self.addCleanup(p.stop)
        video.reset_cache()
        return fk

    def info(self, **kw):
        path = kw.pop("path", os.path.join(self.tmp, "clip.mp4"))
        return video.parse_probe(ffprobe_json(**kw), path)


class TestAvailable(Base):
    def test_av1_default(self):
        fk = self.fake()
        a = video.available(CONF)
        self.assertEqual((a["codec"], a["av1"], a["vp9"], a["opus"], a["ok"]), ("av1", True, True, True, True))
        self.assertEqual(fk.calls[0]["cmd"], [FFMPEG, "-hide_banner", "-nostdin", "-encoders"])
        self.assertEqual(fk.calls[0]["priority"], "idle")
        video.available(CONF)
        self.assertEqual(len(fk.calls), 1)          # encoder list is cached

    def test_vp9_fallback_without_svtav1(self):
        self.fake(encoders=ENC_HEAD)
        a = video.available(CONF)
        self.assertEqual((a["codec"], a["av1"], a["ok"]), ("vp9", False, True))

    def test_configured_vp9(self):
        self.fake()
        self.assertEqual(video.available({"video": {"codec": "vp9"}})["codec"], "vp9")

    def test_nothing_usable(self):
        self.fake(encoders=" ------\n V....D libx264  x\n")
        a = video.available(CONF)
        self.assertEqual((a["codec"], a["ok"]), (None, False))
        self.assertTrue(a["error"])

    def test_mp4(self):
        self.fake()
        a = video.available(MP4)
        self.assertEqual((a["format"], a["codec"], a["h264"], a["aac"], a["ok"]), ("mp4", "h264", True, True, True))
        self.assertEqual(video.available(CONF, "mp4")["codec"], "h264")      # the job's format wins
        video.reset_cache()
        self.fake(encoders=" ------\n V....D libsvtav1  x\n A....D aac  x\n")
        a = video.available(MP4)
        self.assertEqual((a["ok"], a["error"]), (False, "no libx264 encoder"))
        self.assertEqual(video.video_conf({"video": {"format": "mkv"}})["format"], "webm")   # unknown -> default

    def test_tools_missing(self):
        self.fake(tools={})
        a = video.available(CONF)
        self.assertEqual((a["ok"], a["error"]), (False, "ffmpeg missing"))
        with mock.patch.object(video, "sandbox", None):
            self.assertFalse(video.available(CONF)["ok"])

    def test_nvenc_selection_and_policy_key(self):
        self.fake(encoders=ENC_NVENC)
        gpu = {"video": dict(video.VIDEO_DEFAULTS, format="mp4", encoder="nvenc", nvenc_cq=27)}
        a = video.available(gpu)
        self.assertEqual((a["codec"], a["ok"], a["h264_nvenc"]), ("h264_nvenc", True, True))
        p = video.plan(self.info(), gpu, a)
        self.assertEqual(p["video_args"][:10], ["-c:v", "h264_nvenc", "-preset", "p5", "-rc", "vbr",
                                                 "-cq", "27", "-b:v", "0"])
        self.assertEqual(video.spec("webm", CONF), "auto:webm:v1")
        self.assertNotEqual(video.spec("mp4", gpu), video.spec("mp4", MP4))
        self.fake(encoders=ENC_AV1)
        video.reset_cache()
        self.assertEqual(video.available(gpu)["error"], "no h264_nvenc encoder")

    def test_nvenc_listed_but_unusable(self):
        # e.g. ffmpeg 9 needs NVENC API 13.1 (driver 610+): the build lists h264_nvenc, the test encode fails
        fk = self.fake(encoders=ENC_NVENC, nvenc_err=DRIVER_TOO_OLD)
        auto = {"video": dict(video.VIDEO_DEFAULTS, format="mp4", encoder="auto")}
        a = video.available(auto)
        self.assertEqual((a["codec"], a["ok"], a["h264_nvenc"]), ("h264", True, False))   # auto -> CPU
        self.assertIn("Required: 13.1 Found: 13.0", a["nvenc_error"])
        self.assertIn("610.00", a["nvenc_error"])
        probes = [c for c in fk.calls if is_hw_test(c["cmd"])]
        self.assertEqual(len(probes), 1)
        self.assertIn("h264_nvenc", probes[0]["cmd"])
        self.assertEqual(probes[0]["env"]["CUDA_DEVICE_ORDER"], "PCI_BUS_ID")
        video.available(auto)
        self.assertEqual(len([c for c in fk.calls if is_hw_test(c["cmd"])]), 1)   # the discovery is cached
        gpu_conf = {"video": dict(video.VIDEO_DEFAULTS, format="mp4", encoder="nvenc")}
        a = video.available(gpu_conf)
        self.assertEqual((a["codec"], a["ok"]), (None, False))
        self.assertTrue(a["error"].startswith("h264_nvenc unusable: nvenc:0: Driver does not support"), a["error"])
        st = video.hardware_status(gpu_conf)
        self.assertEqual([(d["id"], d["ok"]) for d in st["devices"]], [("nvenc:0", False)])
        self.assertIn("610.00 or newer", st["devices"][0]["hint"])
        self.assertIn("NVENC API 13.0, this ffmpeg needs 13.1", st["devices"][0]["hint"])
        cpu = {"video": dict(video.VIDEO_DEFAULTS, format="mp4", encoder="cpu")}
        fk = self.fake(encoders=ENC_NVENC, nvenc_err=DRIVER_TOO_OLD)
        self.assertEqual(video.available(cpu)["codec"], "h264")
        self.assertFalse([c for c in fk.calls if is_hw_test(c["cmd"])])   # CPU mode never touches the GPU


ENC_ALL_HW = ENC_NVENC + (" V....D h264_qsv            H.264 (Intel Quick Sync Video acceleration) (codec h264)\n"
                          " V....D h264_amf            AMD AMF H.264 Encoder (codec h264)\n")
OLD_FFMPEG = r"C:\ffmpeg-8.1.1\bin\ffmpeg.exe"


class TestGpu(Base):
    def conf(self, **kw):
        return {"video": dict(video.VIDEO_DEFAULTS, format="mp4", **kw), "tools": {}}

    def test_two_gpus_round_robin_with_pci_order(self):
        fk = self.fake(encoders=ENC_NVENC, gpus=[("NVIDIA T1000 8GB", "597.16"), ("NVIDIA RTX A2000", "597.16")])
        a = video.available(self.conf(encoder="auto"))
        self.assertEqual(a["codec"], "h264_nvenc")
        self.assertEqual([d["id"] for d in a["devices"]], ["nvenc:0", "nvenc:1"])
        tests = [c for c in fk.calls if is_hw_test(c["cmd"])]
        self.assertEqual([c["cmd"][c["cmd"].index("-gpu") + 1] for c in tests], ["0", "1"])
        plans = [video.plan(self.info(), self.conf(encoder="auto"), a) for _ in range(3)]
        self.assertEqual([p["device"] for p in plans], ["nvenc:0", "nvenc:1", "nvenc:0"])
        self.assertEqual(plans[1]["video_args"][:12], ["-c:v", "h264_nvenc", "-preset", "p5", "-rc", "vbr", "-cq",
                                                       "25", "-b:v", "0", "-profile:v", "high"])
        self.assertEqual(plans[1]["video_args"][12:14], ["-gpu", "1"])
        self.assertEqual(plans[1]["device_name"], "NVIDIA RTX A2000")
        dst = os.path.join(self.tmp, "out.mp4")
        video.transcode(os.path.join(self.tmp, "in.mp4"), dst, plans[1], self.conf(encoder="auto"))
        enc = fk.calls[-1]
        self.assertEqual(enc["env"]["CUDA_DEVICE_ORDER"], "PCI_BUS_ID")   # -gpu 1 = nvidia-smi's GPU 1
        self.assertEqual(enc["cmd"][0], FFMPEG)

    def test_broken_gpu_is_skipped_and_pin(self):
        def hw_err(cmd):
            return "[h264_nvenc @ 0x1] No NVENC capable devices found" if cmd[cmd.index("-gpu") + 1] == "0" else ""
        self.fake(encoders=ENC_NVENC, gpus=[("Old card", "470.1"), ("Good card", "597.16")], hw_err=hw_err)
        a = video.available(self.conf(encoder="auto"))
        self.assertEqual([d["id"] for d in a["devices"]], ["nvenc:1"])
        st = video.hardware_status(self.conf(encoder="auto"))
        self.assertEqual([(d["id"], d["ok"]) for d in st["devices"]], [("nvenc:0", False), ("nvenc:1", True)])
        self.assertIn("install the NVIDIA driver", st["devices"][0]["hint"])
        self.assertEqual(st["selected"], ["nvenc:1"])
        # pinned to the broken GPU: auto falls back to the CPU, explicit NVENC says which GPU and why
        self.assertEqual(video.available(self.conf(encoder="auto", gpu="nvenc:0"))["codec"], "h264")
        e = video.available(self.conf(encoder="nvenc", gpu="nvenc:0"))
        self.assertEqual((e["ok"], e["error"]), (False, "h264_nvenc unusable: nvenc:0: No NVENC capable devices found"))
        self.assertEqual(video.available(self.conf(encoder="nvenc", gpu="nvenc:7"))["error"],
                         "h264_nvenc unusable: GPU nvenc:7 not found")
        self.assertEqual([d["id"] for d in video.available(self.conf(encoder="nvenc", gpu="nvenc:1"))["devices"]],
                         ["nvenc:1"])

    def test_older_ffmpeg_build_is_used_when_the_newest_cannot_drive_the_gpu(self):
        def hw_err(cmd):
            return DRIVER_TOO_OLD if cmd[0] == FFMPEG else ""
        fk = self.fake(encoders=ENC_NVENC, builds={OLD_FFMPEG: ENC_NVENC}, hw_err=hw_err)
        a = video.available(self.conf(encoder="auto"))
        self.assertEqual((a["codec"], a["hw_ffmpeg"]), ("h264_nvenc", OLD_FFMPEG))
        st = video.hardware_status(self.conf(encoder="auto"))
        self.assertEqual(st["ffmpeg"], OLD_FFMPEG)
        self.assertEqual([(t["ffmpeg"], t["usable"]) for t in st["tried"]], [(FFMPEG, 0), (OLD_FFMPEG, 1)])
        p = video.plan(self.info(), self.conf(encoder="auto"), a)
        self.assertEqual(p["ffmpeg"], OLD_FFMPEG)
        video.transcode(os.path.join(self.tmp, "in.mp4"), os.path.join(self.tmp, "o.mp4"), p, self.conf())
        self.assertEqual(fk.calls[-1]["cmd"][0], OLD_FFMPEG)
        # the CPU path keeps the default build
        cpu = video.plan(self.info(), self.conf(encoder="cpu"), video.available(self.conf(encoder="cpu")))
        self.assertIsNone(cpu["ffmpeg"])

    def test_configured_ffmpeg_is_never_second_guessed(self):
        def hw_err(cmd):
            return DRIVER_TOO_OLD if cmd[0] == FFMPEG else ""
        self.fake(encoders=ENC_NVENC, builds={OLD_FFMPEG: ENC_NVENC}, hw_err=hw_err, configured=True)
        a = video.available(self.conf(encoder="auto"))
        self.assertEqual((a["codec"], a["hw_ffmpeg"]), ("h264", None))

    def test_bench_moves_jobs_to_the_next_gpu_then_cpu(self):
        self.fake(encoders=ENC_NVENC, gpus=[("A", "597"), ("B", "597")])
        video.bench("nvenc:0", "CUDA_ERROR_LAUNCH_FAILED")
        self.assertEqual([d["id"] for d in video.available(self.conf(encoder="auto"))["devices"]], ["nvenc:1"])
        video.bench("nvenc:1", "boom")
        self.assertEqual(video.available(self.conf(encoder="auto"))["codec"], "h264")
        e = video.available(self.conf(encoder="nvenc"))
        self.assertFalse(e["ok"])
        self.assertIn("resting after a failed job: CUDA_ERROR_LAUNCH_FAILED", e["error"])
        self.assertEqual(set(video.hardware_status(self.conf(encoder="auto"))["benched"]), {"nvenc:0", "nvenc:1"})

    def test_backend_preference_and_explicit_backends(self):
        with mock.patch.object(gpu, "WIN", True):
            self.fake(encoders=ENC_ALL_HW, gpus=[("T1000", "597")])
            a = video.available(self.conf(encoder="auto"))
            self.assertEqual([d["id"] for d in a["devices"]], ["nvenc:0", "qsv:0", "amf:0"])
            self.assertEqual(a["codec"], "h264_nvenc")
            q = video.available(self.conf(encoder="qsv"))
            self.assertEqual((q["codec"], [d["id"] for d in q["devices"]]), ("h264_qsv", ["qsv:0"]))
            p = video.plan(self.info(), self.conf(encoder="qsv", nvenc_cq=24, nvenc_preset="p7"), q)
            self.assertEqual(p["video_args"][:8], ["-c:v", "h264_qsv", "-preset", "veryslow", "-global_quality", "24",
                                                   "-profile:v", "high"])
            self.assertEqual(p["video_args"][8:10], ["-pix_fmt", "nv12"])   # QSV takes NV12 system frames
            # a pinned NVIDIA card does not apply once the encoder is Quick Sync (no "GPU not found" error)
            q = video.available(self.conf(encoder="qsv", gpu="nvenc:0"))
            self.assertEqual((q["ok"], q["codec"], [d["id"] for d in q["devices"]]), (True, "h264_qsv", ["qsv:0"]))
            self.assertEqual(gpu.effective_pin({"encoder": "auto", "gpu": "nvenc:0"}), "nvenc:0")
            self.assertEqual(gpu.effective_pin({"encoder": "nvenc", "gpu": "bogus"}), "auto")
            m = video.available(self.conf(encoder="amf"))
            p = video.plan(self.info(), self.conf(encoder="amf", nvenc_preset="p3"), m)
            self.assertEqual(p["video_args"][:14], ["-c:v", "h264_amf", "-usage", "transcoding", "-quality",
                                                    "balanced", "-rc", "cqp", "-qp_i", "25", "-qp_p", "25",
                                                    "-qp_b", "25"])
            self.assertFalse(p["nv_env"])

    def test_only_gpus_that_are_present_are_offered(self):
        # every Gyan build lists QSV and AMF; on an NVIDIA-only machine they must not show up as "unusable"
        nv_only = [{"vendor": "other", "name": "Microsoft Basic Display Adapter", "node": ""},
                   {"vendor": "nvidia", "name": "NVIDIA T1000 8GB", "node": ""}]
        with mock.patch.object(gpu, "WIN", True):
            fk = self.fake(encoders=ENC_ALL_HW, gpus=[("NVIDIA T1000 8GB", "597.16")], adapters=nv_only)
            st = video.hardware_status(self.conf(encoder="auto"))
            self.assertEqual([d["id"] for d in st["devices"]], ["nvenc:0"])
            self.assertFalse([c for c in fk.calls if is_hw_test(c["cmd"]) and "h264_qsv" in c["cmd"]])
            mixed = nv_only + [{"vendor": "intel", "name": "Intel(R) UHD Graphics 770", "node": ""}]
            self.fake(encoders=ENC_ALL_HW, gpus=[("NVIDIA T1000 8GB", "597.16")], adapters=mixed)
            st = video.hardware_status(self.conf(encoder="auto"))
            self.assertEqual([(d["id"], d["name"]) for d in st["devices"]],
                             [("nvenc:0", "NVIDIA T1000 8GB"), ("qsv:0", "Intel(R) UHD Graphics 770")])
        self.assertEqual(gpu._vendor_of(r"pci\ven_8086&dev_4680"), "intel")
        self.assertEqual(gpu._vendor_of("0x1002\n"), "amd")
        self.assertEqual(gpu._vendor_of("pci\\ven_1414"), "other")

    def test_vaapi_plan(self):
        dev = {"id": "vaapi:renderD129", "backend": "vaapi", "index": None, "path": "/dev/dri/renderD129",
               "name": "VAAPI renderD129", "ok": True}
        avail = {"codec": "h264_vaapi", "ok": True, "h264": True, "aac": True, "format": "mp4", "devices": [dev],
                 "hw_ffmpeg": "/usr/lib/jellyfin-ffmpeg/ffmpeg"}
        p = video.plan(self.info(w=1919, h=1080), self.conf(encoder="vaapi"), avail)
        self.assertEqual(p["input_args"], ["-vaapi_device", "/dev/dri/renderD129"])
        self.assertEqual(p["video_args"][:6], ["-c:v", "h264_vaapi", "-qp", "25", "-profile:v", "high"])
        self.assertNotIn("-pix_fmt", p["video_args"])                     # frames are uploaded, not converted
        self.assertEqual(p["video_args"][-1], "scale=trunc(iw/2)*2:trunc(ih/2)*2,format=nv12,hwupload")
        cmd = video.command(p["ffmpeg"], "/in.mp4", "/out.mp4", p)
        self.assertLess(cmd.index("-vaapi_device"), cmd.index("-i"))
        nodes = ["/dev/dri/renderD128", "/dev/dri/renderD129"]
        with mock.patch.object(gpu, "WIN", False), mock.patch.object(gpu.glob, "glob", lambda pat: nodes):
            devs = gpu.devices({"h264_vaapi"}, None)
        self.assertEqual([d["id"] for d in devs], ["vaapi:renderD128", "vaapi:renderD129"])
        self.assertIn("'render' group", gpu.hint("vaapi", "Permission denied", devs[0]))

    def test_gpu_choice_is_not_part_of_the_variant(self):
        self.assertEqual(video.spec("mp4", self.conf(encoder="auto", gpu="nvenc:1")),
                         video.spec("mp4", self.conf(encoder="auto")))
        self.assertNotEqual(video.spec("mp4", self.conf(encoder="qsv")), video.spec("mp4", self.conf(encoder="auto")))
        self.assertEqual(video.spec("webm", CONF), "auto:webm:v1")
        self.assertTrue(gpu.is_device_id("nvenc:0") and gpu.is_device_id("vaapi:renderD128"))
        self.assertFalse(gpu.is_device_id("nvenc:0;rm") or gpu.is_device_id("cuda:0") or gpu.is_device_id(3))


def hw_decoded(cmd):
    return "-hwaccel" in cmd


class TestGpuDecode(Base):
    """video.gpu_decode: the GPU decodes too while GPU compute is on, with CPU decoding as the fallback."""

    def conf(self, **kw):
        return {"video": dict(video.VIDEO_DEFAULTS, **dict({"format": "mp4"}, **kw)), "tools": {}}

    def nvenc(self, **kw):
        fk = self.fake(encoders=ENC_NVENC, gpus=[("NVIDIA T1000 8GB", "597.16"), ("NVIDIA RTX A2000", "597.16")], **kw)
        return fk, video.available(self.conf(encoder="auto"))

    def test_nvenc_job_stays_on_the_gpu(self):
        fk, a = self.nvenc()
        video.plan(self.info(rotation=0), self.conf(encoder="auto"), a)          # round-robin: the next is nvenc:1
        p = video.plan(self.info(rotation=0, w=1919), self.conf(encoder="auto"), a)
        hw = p["hw_decode"]
        self.assertEqual((hw["mode"], hw["device"], hw["src"]), ("gpu", "nvenc:1", "h264/yuv420p"))
        self.assertEqual(hw["input_args"], ["-hwaccel", "cuda", "-hwaccel_device", "1", "-hwaccel_output_format", "cuda"])
        self.assertNotIn("-pix_fmt", hw["video_args"])                    # CUDA frames: scale_cuda converts
        self.assertEqual(hw["video_args"][-2:], ["-vf", "scale_cuda=trunc(iw/2)*2:trunc(ih/2)*2:format=yuv420p"])
        self.assertEqual(hw["video_args"][:14], p["video_args"][:14])     # same encoder settings, -gpu 1 too
        self.assertIn("scale=trunc(iw/2)*2:trunc(ih/2)*2", p["video_args"])   # the CPU-decoding fallback
        dst = os.path.join(self.tmp, "out.mp4")
        r = video.transcode(os.path.join(self.tmp, "in.mp4"), dst, p, self.conf(encoder="auto"))
        self.assertIsNone(video.result_kind(r))
        runs = [c for c in fk.calls if c["cmd"][-1].startswith("file:")]
        self.assertEqual(len(runs), 1)
        cmd = runs[0]["cmd"]
        self.assertLess(cmd.index("-hwaccel"), cmd.index("-i"))
        self.assertEqual(runs[0]["env"]["CUDA_DEVICE_ORDER"], "PCI_BUS_ID")
        self.assertEqual(p["decoded"], "gpu")
        self.assertTrue(os.path.isfile(dst))

    def test_build_without_scale_cuda_still_decodes_on_the_gpu(self):
        # distro and minimal builds often have CUDA decoding but no scale_cuda (needs the CUDA compiler)
        fk, a = self.nvenc(filters=NO_SCALE_CUDA)
        self.assertFalse(a["zero_copy"])
        p = video.plan(self.info(rotation=0), self.conf(encoder="auto"), a)
        self.assertEqual(p["hw_decode"]["mode"], "gpu_copy")
        self.assertNotIn("-hwaccel_output_format", p["hw_decode"]["input_args"])
        self.assertEqual(p["hw_decode"]["video_args"], p["video_args"])
        video.available(self.conf(encoder="auto"))
        self.assertEqual(len([c for c in fk.calls if "-filters" in c["cmd"]]), 1)   # cached with the encoder list
        _, a = self.nvenc(filters="")                                              # a build that lists nothing
        self.assertEqual((a["codec"], a["zero_copy"]), ("h264_nvenc", False))

    def test_rotated_source_comes_back_to_the_cpu_filters(self):
        self.nvenc()
        p = video.plan(self.info(rotation=-90), self.conf(encoder="auto"), video.available(self.conf(encoder="auto")))
        hw = p["hw_decode"]
        self.assertEqual(hw["mode"], "gpu_copy")                          # autorotate needs system-memory frames
        self.assertEqual(hw["input_args"], ["-hwaccel", "cuda", "-hwaccel_device", "0"])
        self.assertEqual(hw["video_args"], p["video_args"])
        self.assertEqual(video.plan(self.info(rotation=180), self.conf(encoder="auto"),
                                    video.available(self.conf(encoder="auto")))["hw_decode"]["mode"], "gpu_copy")

    def test_only_while_gpu_compute_is_on(self):
        self.nvenc()
        self.assertIsNone(video.plan(self.info(rotation=0), self.conf(encoder="cpu"),
                                     video.available(self.conf(encoder="cpu")))["hw_decode"])
        off = self.conf(encoder="auto", gpu_decode=False)
        p = video.plan(self.info(rotation=0), off, video.available(off))
        self.assertEqual(p["codec"], "h264_nvenc")                        # still encoded on the GPU
        self.assertIsNone(p["hw_decode"])
        fk = self.fake()
        p = video.plan(self.info(rotation=0), CONF, video.available(CONF))  # WebM on the CPU encoder: no GPU
        self.assertIsNone(p["hw_decode"])
        self.assertFalse([c for c in fk.calls if is_hw_test(c["cmd"])])
        self.assertEqual(video.spec("mp4", off), video.spec("mp4", self.conf(encoder="auto")))   # not policy

    def test_decoder_limit_falls_back_to_cpu_decoding_and_is_remembered(self):
        av1_err = ("[av1 @ 0x1] Hardware is lacking required capabilities\n"
                   "[av1 @ 0x1] Failed setup for format cuda: hwaccel initialisation returned error.\n")
        fk, a = self.nvenc(fail=lambda cmd: Res(rc=69, err=av1_err) if hw_decoded(cmd) else None)
        conf = self.conf(encoder="auto")
        src = self.info(rotation=0, vcodec="mpeg4")
        p = video.plan(src, conf, a)
        dst = os.path.join(self.tmp, "out.mp4")
        r = video.transcode(os.path.join(self.tmp, "in.mp4"), dst, p, conf)
        self.assertIsNone(video.result_kind(r))                           # the job worked: no failed GPU
        self.assertTrue(os.path.isfile(dst))
        self.assertFalse(os.path.exists(dst + ".part"))
        runs = [c["cmd"] for c in fk.calls if c["cmd"][-1].startswith("file:")]
        self.assertEqual([hw_decoded(c) for c in runs], [True, False])
        self.assertIn("h264_nvenc", runs[1])                              # same GPU encode, CPU decoding
        self.assertEqual(p["decoded"], "cpu")
        self.assertFalse(gpu.decode_ok(p["device"], "mpeg4/yuv420p", "gpu"))
        # the same kind of source on that GPU is planned with CPU decoding; another codec or GPU still decodes there
        again = [video.plan(src, conf, a) for _ in range(2)]
        self.assertEqual([(q["device"], bool(q["hw_decode"])) for q in again],
                         [("nvenc:1", True), ("nvenc:0", False)] if p["device"] == "nvenc:0" else
                         [("nvenc:0", True), ("nvenc:1", False)])
        self.assertTrue(video.plan(self.info(rotation=0), conf, a)["hw_decode"])
        with mock.patch.object(gpu.time, "monotonic", return_value=gpu.time.monotonic() + gpu.NO_DECODE_S + 1):
            self.assertTrue(gpu.decode_ok(p["device"], "mpeg4/yuv420p", "gpu"))   # tried again after an hour

    def test_timeouts_and_real_failures(self):
        fk, a = self.nvenc(fail=lambda cmd: Res(rc=1, timed_out=True, killed="timeout") if hw_decoded(cmd) else None)
        conf = self.conf(encoder="auto")
        p = video.plan(self.info(rotation=0), conf, a)
        r = video.transcode(os.path.join(self.tmp, "in.mp4"), os.path.join(self.tmp, "o.mp4"), p, conf)
        self.assertEqual(video.result_kind(r), "timeout")                 # not run a second time
        self.assertEqual(len([c for c in fk.calls if c["cmd"][-1].startswith("file:")]), 1)
        # both runs fail: the CPU-decoding result goes back to the worker (GPU failover), nothing is remembered
        fk, a = self.nvenc(fail=lambda cmd: Res(rc=1, err="CUDA_ERROR_LAUNCH_FAILED"))
        p = video.plan(self.info(rotation=0), conf, a)
        r = video.transcode(os.path.join(self.tmp, "in.mp4"), os.path.join(self.tmp, "o.mp4"), p, conf)
        self.assertEqual(video.result_kind(r), "encode_error")
        self.assertEqual([hw_decoded(c["cmd"]) for c in fk.calls if c["cmd"][-1].startswith("file:")], [True, False])
        self.assertTrue(gpu.decode_ok(p["device"], "h264/yuv420p", "gpu"))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "o.mp4.part")))

    def test_webm_is_decoded_on_the_gpu_by_a_build_that_also_encodes_it(self):
        def hw_err(cmd):
            return DRIVER_TOO_OLD if cmd[0] == FFMPEG else ""
        fk = self.fake(encoders=ENC_NVENC, builds={OLD_FFMPEG: ENC_NVENC}, hw_err=hw_err, gpus=[("T1000", "597")])
        webm = self.conf(format="webm", encoder="auto")
        a = video.available(webm)
        self.assertEqual((a["codec"], [d["id"] for d in a["decode_devices"]], a["decode_ffmpeg"]),
                         ("av1", ["nvenc:0"], OLD_FFMPEG))
        p = video.plan(self.info(rotation=0), webm, a)
        self.assertEqual((p["codec"], p["device"], p["ffmpeg"]), ("av1", None, None))   # CPU encode, default build
        hw = p["hw_decode"]
        self.assertEqual((hw["mode"], hw["ffmpeg"]), ("gpu_copy", OLD_FFMPEG))
        self.assertEqual(hw["input_args"], ["-hwaccel", "cuda", "-hwaccel_device", "0"])
        video.transcode(os.path.join(self.tmp, "in.mp4"), os.path.join(self.tmp, "o.webm"), p, webm)
        self.assertEqual(fk.calls[-1]["cmd"][0], OLD_FFMPEG)
        self.assertIn("libsvtav1", fk.calls[-1]["cmd"])
        self.assertEqual(p["decoded"], "gpu_copy")
        # the GPU's build lacks the software encoders: the job keeps the default build and the CPU decodes
        self.fake(encoders=ENC_NVENC, builds={OLD_FFMPEG: ENC_HEAD + ENC_NVENC.split(ENC_HEAD)[1].replace(
            " V....D libsvtav1", " V....D libaom-av1")}, hw_err=hw_err, gpus=[("T1000", "597")])
        a = video.available(webm)
        self.assertEqual((a["decode_devices"], a["decode_ffmpeg"]), ([], None))
        self.assertIsNone(video.plan(self.info(rotation=0), webm, a)["hw_decode"])

    def test_decode_arguments_per_backend(self):
        nv = {"id": "nvenc:0", "backend": "nvenc", "index": 0}
        self.assertEqual(gpu.decode_args(nv), ["-hwaccel", "cuda", "-hwaccel_device", "0"])
        self.assertEqual(gpu.decode_args(dict(nv, index=None), True), ["-hwaccel", "cuda", "-hwaccel_output_format", "cuda"])
        va = {"id": "vaapi:renderD128", "backend": "vaapi", "path": "/dev/dri/renderD128"}
        self.assertEqual(gpu.decode_args(va), ["-hwaccel", "vaapi", "-hwaccel_device", "/dev/dri/renderD128"])
        with mock.patch.object(gpu, "WIN", True):
            self.assertEqual(gpu.decode_args({"id": "qsv:0", "backend": "qsv"}), ["-hwaccel", "d3d11va"])
            self.assertEqual(gpu.decode_args({"id": "amf:0", "backend": "amf"}), ["-hwaccel", "d3d11va"])
        with mock.patch.object(gpu, "WIN", False):
            self.assertEqual(gpu.decode_args({"id": "qsv:0", "backend": "qsv"}), [])
        self.assertEqual(gpu.decode_args(None), [])
        # a VAAPI encode decodes on its render node and keeps its own upload filters (frames come back first)
        avail = {"codec": "h264_vaapi", "ok": True, "h264": True, "aac": True, "format": "mp4", "devices": [va]}
        p = video.plan(self.info(rotation=0), self.conf(encoder="vaapi"), avail)
        self.assertEqual(p["hw_decode"]["mode"], "gpu_copy")
        cmd = video.command("ffmpeg", "/in.mp4", "/out.mp4", p, p["hw_decode"])
        self.assertEqual(cmd[cmd.index("-vaapi_device"):cmd.index("-protocol_whitelist")],
                         ["-vaapi_device", "/dev/dri/renderD128", "-hwaccel", "vaapi", "-hwaccel_device", "/dev/dri/renderD128"])


class TestProbe(Base):
    def test_probe_command_and_parse(self):
        fk = self.fake(probe=ffprobe_json(cover=True, audio=(("aac", 2, "stereo"), ("opus", 6, "5.1"))))
        src = os.path.join(self.tmp, "a b.mp4")
        info = video.probe(src, CONF)
        c = fk.calls[0]
        self.assertEqual(c["cmd"], [FFPROBE, "-hide_banner", "-v", "error", "-protocol_whitelist", "file",
                                    "-format_whitelist", video.DEMUXERS, "-print_format", "json", "-show_format",
                                    "-show_streams", "file:" + src])
        self.assertEqual((c["timeout"], c["priority"]), (video.PROBE_TIMEOUT, "idle"))
        v = info["video"]
        self.assertEqual((v["index"], v["codec"], v["width"], v["height"], v["rotation"]), (1, "h264", 1920, 1080, -90))
        self.assertAlmostEqual(v["fps"], 29.97, places=2)
        self.assertEqual((info["duration"], info["size"], info["ext"]), (120.5, 50000000, "mp4"))
        self.assertEqual([(a["codec"], a["channels"]) for a in info["audio"]], [("aac", 2), ("opus", 6)])

    def test_probe_errors(self):
        self.fake(rc=1)
        with self.assertRaises(video.VideoError) as cm:
            video.probe(os.path.join(self.tmp, "x.mp4"), CONF)
        self.assertEqual(cm.exception.kind, "probe_error")
        self.fake(tools={})
        with self.assertRaises(video.VideoError) as cm:
            video.probe(os.path.join(self.tmp, "x.mp4"), CONF)
        self.assertEqual(cm.exception.kind, "tool_missing")

    def test_parse_robust(self):
        info = video.parse_probe({"format": {}, "streams": [{"codec_type": "audio", "codec_name": "mp3"}]},
                                 os.path.join(self.tmp, "nope.mp4"))
        self.assertIsNone(info["video"])
        self.assertEqual((info["duration"], info["size"]), (0.0, 0))
        vfr = video.parse_probe(ffprobe_json(fps="0/0"), "x.mkv")["video"]
        self.assertEqual(vfr["fps"], 0.0)


class TestPlan(Base):
    def test_skip_rules(self):
        vc = CONF["video"]
        self.assertEqual(video.skip_reason(self.info(path="x.webm", vcodec="vp8"), CONF), "webm")
        self.assertEqual(video.skip_reason(self.info(vcodec="av1"), CONF), "already_av1")
        self.assertEqual(video.skip_reason(self.info(vcodec="vp9", fmt="matroska,webm", path="x.mkv"), CONF),
                         "already_vp9")
        self.assertEqual(video.skip_reason(self.info(duration=str(vc["max_seconds"] + 1)), CONF), "too_long")
        self.assertEqual(video.skip_reason(self.info(size=str(vc["max_bytes"] + 1)), CONF), "too_big")
        self.assertEqual(video.skip_reason(video.parse_probe({"streams": []}, "a.mp4"), CONF), "no_video")
        self.assertEqual(video.skip_reason(self.info(), {"video": {"enabled": False}}), "disabled")
        for bad in (self.info(vcodec="av1"), self.info(path="x.webm")):
            self.assertIsNone(video.plan(bad, CONF, AVAIL_AV1))
        self.assertIsNone(video.skip_reason(self.info(vcodec="hevc", path="x.mov"), CONF))

    def test_mp4_plan(self):
        p = video.plan(self.info(), MP4, AVAIL_MP4)
        self.assertEqual((p["format"], p["codec"]), ("mp4", "h264"))
        self.assertEqual(p["video_args"], ["-c:v", "libx264", "-preset", "medium", "-crf", "23", "-profile:v", "high",
                                           "-threads", "2", "-pix_fmt", "yuv420p", "-g", "300"])
        self.assertEqual((p["audio"], p["audio_args"]), ("copy", ["-c:a", "copy"]))     # AAC stays AAC
        p = video.plan(self.info(audio=(("opus", 6, "5.1"),)), MP4, AVAIL_MP4)
        self.assertEqual(p["audio_args"], ["-c:a", "aac", "-b:a", "384k"])
        # HEVC is skipped for MP4 (H.264 would rarely be smaller) but still goes to AV1/VP9 for WebM
        self.assertEqual(video.skip_reason(self.info(vcodec="hevc"), MP4), "already_hevc")
        self.assertIsNone(video.skip_reason(self.info(vcodec="hevc"), CONF))
        self.assertEqual(video.plan(self.info(), CONF, AVAIL_MP4, "mp4")["codec"], "h264")   # per-job format

    def test_av1_plan(self):
        p = video.plan(self.info(), CONF, AVAIL_AV1)
        self.assertEqual(p["codec"], "av1")
        self.assertEqual(p["video_args"], ["-c:v", "libsvtav1", "-preset", "8", "-crf", "30", "-svtav1-params",
                                           "lp=2", "-pix_fmt", "yuv420p", "-g", "300"])
        self.assertEqual(p["audio_args"], ["-c:a", "libopus", "-b:a", "128k"])
        self.assertEqual((p["timeout"], p["cpu_pct"], p["threads"], p["video_index"]), (1808, 50, 2, 0))
        self.assertEqual(p["mem_mb"], 2048)

    def test_vp9_plan(self):
        p = video.plan(self.info(fps="25/1", w=3840, h=2160), CONF, AVAIL_VP9)
        self.assertEqual(p["video_args"], ["-c:v", "libvpx-vp9", "-deadline", "good", "-cpu-used", "4", "-row-mt", "1",
                                           "-crf", "32", "-b:v", "0", "-threads", "2", "-pix_fmt", "yuv420p",
                                           "-g", "250"])
        self.assertEqual(p["mem_mb"], 3072)          # 4K gets more headroom

    def test_gop_capped(self):
        self.assertEqual(video.plan(self.info(fps="90000/1"), CONF, AVAIL_AV1)["gop"], 600)

    def test_timeout_floor_and_factor(self):
        self.assertEqual(video.plan(self.info(duration="10"), CONF, AVAIL_AV1)["timeout"], 600)
        self.assertEqual(video.plan(self.info(duration="100"), CONF, AVAIL_AV1)["timeout"], 1500)
        self.assertEqual(video.plan(self.info(duration="0"), CONF, AVAIL_AV1)["timeout"], 600)

    def test_audio_modes(self):
        p = video.plan(self.info(audio=(("opus", 2, "stereo"),)), CONF, AVAIL_AV1)
        self.assertEqual((p["audio"], p["audio_args"]), ("copy", ["-c:a", "copy"]))
        p = video.plan(self.info(audio=()), CONF, AVAIL_AV1)
        self.assertEqual((p["audio"], p["audio_args"]), (None, []))
        p = video.plan(self.info(audio=(("aac", 6, "5.1(side)"), ("aac", 2, "stereo"))), CONF, AVAIL_AV1)
        self.assertEqual(p["audio_args"], ["-c:a", "libopus", "-b:a", "384k", "-mapping_family", "1",
                                           "-af", "aformat=channel_layouts=" + video.OPUS_LAYOUTS])
        p = video.plan(self.info(audio=(("opus", 2, "stereo"), ("aac", 2, "stereo"))), CONF, AVAIL_AV1)
        self.assertEqual(p["audio"], "opus")          # mixed tracks: all re-encoded, none dropped

    def test_odd_size_and_cover_art(self):
        p = video.plan(self.info(w=641, h=361, cover=True), CONF, AVAIL_AV1)
        self.assertEqual(p["video_args"][-2:], ["-vf", "scale=trunc(iw/2)*2:trunc(ih/2)*2"])
        self.assertEqual(p["video_index"], 1)

    def test_plan_asks_available(self):
        self.fake(encoders=ENC_HEAD)
        self.assertEqual(video.plan(self.info(), CONF)["codec"], "vp9")


class TestTranscode(Base):
    def test_exact_command_and_atomic_output(self):
        fk = self.fake()
        src = os.path.join(self.tmp, "in put.mp4")
        dst = os.path.join(self.tmp, "out.webm")
        p = video.plan(self.info(path=src, duration="60"), CONF, AVAIL_AV1)
        r = video.transcode(src, dst, p, CONF)
        self.assertIsNone(video.result_kind(r))
        c = fk.calls[-1]
        self.assertEqual(c["cmd"], [
            FFMPEG, "-hide_banner", "-nostdin", "-nostats", "-loglevel", "error", "-y",
            "-threads", "2", "-filter_threads", "2",
            "-protocol_whitelist", "file", "-format_whitelist", "mov,matroska,avi,asf,flv", "-i", "file:" + src,
            "-map", "0:v:0", "-map", "0:a?",
            "-c:v", "libsvtav1", "-preset", "8", "-crf", "30", "-svtav1-params", "lp=2", "-pix_fmt", "yuv420p",
            "-g", "300", "-c:a", "libopus", "-b:a", "128k",
            "-map_metadata", "-1", "-f", "webm", "file:" + dst + ".part"])
        self.assertEqual((c["timeout"], c["cpu_pct"], c["mem_mb"], c["priority"]), (900, 50, 2048, "idle"))
        self.assertTrue(os.path.isfile(dst))
        self.assertFalse(os.path.exists(dst + ".part"))
        with open(dst, "rb") as f:
            self.assertEqual(f.read(4), b"\x1a\x45\xdf\xa3")

    def test_mp4_command(self):
        fk = self.fake()
        src, dst = os.path.join(self.tmp, "in.mov"), os.path.join(self.tmp, "out.mp4")
        video.transcode(src, dst, video.plan(self.info(path=src), MP4, AVAIL_MP4), MP4)
        cmd = fk.calls[-1]["cmd"]
        self.assertEqual(cmd[-7:], ["-map_metadata", "-1", "-movflags", "+faststart", "-f", "mp4", "file:" + dst + ".part"])

    def test_failure_leaves_nothing(self):
        dst = os.path.join(self.tmp, "out.webm")
        p = video.plan(self.info(), CONF, AVAIL_AV1)
        for kw, kind in (({"rc": 1}, "encode_error"), ({"rc": 1, "timed_out": True}, "timeout"),
                         ({"rc": 3, "killed": "memory"}, "memory"), ({"rc": 0, "write": False}, None)):
            self.fake(**kw)
            r = video.transcode(os.path.join(self.tmp, "in.mp4"), dst, p, CONF)
            self.assertEqual(video.result_kind(r), kind, kw)
            self.assertFalse(os.path.exists(dst), kw)
            self.assertFalse(os.path.exists(dst + ".part"), kw)

    def test_stale_part_removed_and_tool_missing(self):
        dst = os.path.join(self.tmp, "out.webm")
        with open(dst + ".part", "wb") as f:
            f.write(b"old garbage")
        self.fake(write=False, rc=1)
        video.transcode("in.mp4", dst, video.plan(self.info(), CONF, AVAIL_AV1), CONF)
        self.assertFalse(os.path.exists(dst + ".part"))
        self.fake(tools={"ffprobe": FFPROBE})
        with self.assertRaises(video.VideoError) as cm:
            video.transcode("in.mp4", dst, video.plan(self.info(), CONF, AVAIL_AV1), CONF)
        self.assertEqual(cm.exception.kind, "tool_missing")

    def test_beneficial(self):
        self.assertFalse(video.beneficial(1000, 900, CONF))     # >= 90 % of the source: not worth it
        self.assertTrue(video.beneficial(1000, 899, CONF))
        self.assertFalse(video.beneficial(1000, 1500, CONF))
        self.assertFalse(video.beneficial(0, 10, CONF))
        self.assertTrue(video.beneficial(1000, 700, {"video": {"min_saving": 0.25}}))
        self.assertEqual(video.CONTENT_TYPE, "video/webm")


def _real_tools():
    if real_sandbox is None:
        return None, None
    try:
        return real_sandbox.which("ffmpeg", {}), real_sandbox.which("ffprobe", {})
    except Exception:
        return None, None


@unittest.skipUnless(all(_real_tools()), "ffmpeg/ffprobe not installed (install.ps1)")
class TestRealTranscode(unittest.TestCase):
    """End to end with the real sandbox and ffmpeg: a 2 s synthetic H.264/AAC clip -> WebM."""

    def test_roundtrip(self):
        ffmpeg, _ = _real_tools()
        tmp = tempfile.mkdtemp(prefix="strata-video-real-")
        try:
            src, dst = os.path.join(tmp, "src.mp4"), os.path.join(tmp, "out.webm")
            r = real_sandbox.run([ffmpeg, "-hide_banner", "-nostdin", "-loglevel", "error", "-y",
                                  "-f", "lavfi", "-i", "testsrc2=size=320x240:rate=25:duration=2",
                                  "-f", "lavfi", "-i", "sine=frequency=440:duration=2",
                                  "-c:v", "libx264", "-pix_fmt", "yuv420p", "-c:a", "aac", "-shortest",
                                  "-metadata", "title=StrataSecretTitle", src], 120, mem_mb=1024, cpu_pct=50)
            if r.rc != 0:
                self.skipTest("cannot make a test clip: %s" % r.err[-200:])
            conf = {"video": dict(video.VIDEO_DEFAULTS), "tools": {}}
            info = video.probe(src, conf)
            self.assertEqual(info["video"]["codec"], "h264")
            p = video.plan(info, conf)
            self.assertIsNotNone(p)
            r = video.transcode(src, dst, p, conf)
            self.assertIsNone(video.result_kind(r), r.err[-500:])
            with open(dst, "rb") as f:
                head = f.read()
            self.assertEqual(head[:4], b"\x1a\x45\xdf\xa3")
            self.assertNotIn(b"StrataSecretTitle", head)
            out = video.probe(dst, conf)
            self.assertIn(out["video"]["codec"], ("av1", "vp9"))
            self.assertEqual([a["codec"] for a in out["audio"]], ["opus"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_roundtrip_mp4(self):
        """video.format=mp4: H.264 + AAC in MP4, index at the front (+faststart), metadata gone."""
        ffmpeg, _ = _real_tools()
        tmp = tempfile.mkdtemp(prefix="strata-video-real-")
        try:
            src, dst = os.path.join(tmp, "src.mov"), os.path.join(tmp, "out.mp4")
            r = real_sandbox.run([ffmpeg, "-hide_banner", "-nostdin", "-loglevel", "error", "-y",
                                  "-f", "lavfi", "-i", "testsrc2=size=320x240:rate=25:duration=2",
                                  "-f", "lavfi", "-i", "sine=frequency=440:duration=2",
                                  "-c:v", "mjpeg", "-q:v", "2", "-c:a", "pcm_s16le", "-shortest",
                                  "-metadata", "title=StrataSecretTitle", src], 120, mem_mb=1024, cpu_pct=50)
            if r.rc != 0:
                self.skipTest("cannot make a test clip: %s" % r.err[-200:])
            conf = {"video": dict(video.VIDEO_DEFAULTS, format="mp4"), "tools": {}}
            info = video.probe(src, conf)
            p = video.plan(info, conf)
            if p is None or not video.available(conf)["ok"]:
                self.skipTest("this ffmpeg has no libx264 / aac")
            r = video.transcode(src, dst, p, conf)
            self.assertIsNone(video.result_kind(r), r.err[-500:])
            with open(dst, "rb") as f:
                data = f.read()
            self.assertLess(data.index(b"moov"), data.index(b"mdat"))     # playable before it has fully arrived
            self.assertNotIn(b"StrataSecretTitle", data)
            out = video.probe(dst, conf)
            self.assertEqual((out["video"]["codec"], [a["codec"] for a in out["audio"]]), ("h264", ["aac"]))
            self.assertLess(os.path.getsize(dst), os.path.getsize(src))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
