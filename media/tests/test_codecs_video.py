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
AVAIL_AV1 = {"codec": "av1", "ok": True, "av1": True, "vp9": True, "opus": True}
AVAIL_VP9 = {"codec": "vp9", "ok": True, "av1": False, "vp9": True, "opus": True}


def ffprobe_json(vcodec="h264", w=1920, h=1080, fps="30000/1001", duration="120.5", size="50000000",
                 audio=(("aac", 2, "stereo"),), cover=False, fmt="mov,mp4,m4a,3gp,3g2,mj2"):
    streams = []
    if cover:
        streams.append({"index": 0, "codec_type": "video", "codec_name": "mjpeg", "width": 600, "height": 600,
                        "avg_frame_rate": "0/0", "disposition": {"attached_pic": 1}})
    streams.append({"index": len(streams), "codec_type": "video", "codec_name": vcodec, "width": w, "height": h,
                    "avg_frame_rate": fps, "r_frame_rate": fps, "pix_fmt": "yuv420p", "bit_rate": "4000000",
                    "disposition": {"attached_pic": 0},
                    "side_data_list": [{"side_data_type": "Display Matrix", "rotation": -90}]})
    for codec, ch, layout in audio:
        streams.append({"index": len(streams), "codec_type": "audio", "codec_name": codec, "channels": ch,
                        "channel_layout": layout, "sample_rate": "48000"})
    return {"format": {"format_name": fmt, "duration": duration, "size": size, "bit_rate": "3300000"},
            "streams": streams}


class Res:
    def __init__(self, rc=0, out="", err="", timed_out=False, killed=None):
        self.rc, self.out, self.err, self.timed_out, self.killed, self.secs = rc, out, err, timed_out, killed, 0.1


class FakeSandbox:
    """Records every run(); answers -encoders / ffprobe / ffmpeg like the real tools would."""

    def __init__(self, encoders=ENC_AV1, probe=None, tools=None, rc=0, write=True, timed_out=False, killed=None):
        self.encoders, self.probe = encoders, probe or ffprobe_json()
        self.tools = {"ffmpeg": FFMPEG, "ffprobe": FFPROBE} if tools is None else tools
        self.rc, self.write, self.timed_out, self.killed = rc, write, timed_out, killed
        self.calls = []

    def which(self, name, conf=None):
        return self.tools.get(name)

    def run(self, cmd, timeout, mem_mb=1024, cpu_pct=35, priority="idle", cwd=None, env=None, max_output=4 << 20):
        self.calls.append({"cmd": list(cmd), "timeout": timeout, "mem_mb": mem_mb, "cpu_pct": cpu_pct,
                           "priority": priority})
        if "-encoders" in cmd:
            return Res(out=self.encoders)
        if cmd[0] == FFPROBE:
            return Res(rc=self.rc, out=json.dumps(self.probe), err="boom" if self.rc else "")
        out = cmd[-1]
        assert out.startswith("file:"), out
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
        fk = FakeSandbox(**kw)
        p = mock.patch.object(video, "sandbox", fk)
        p.start()
        self.addCleanup(p.stop)
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

    def test_tools_missing(self):
        self.fake(tools={})
        a = video.available(CONF)
        self.assertEqual((a["ok"], a["error"]), (False, "ffmpeg missing"))
        with mock.patch.object(video, "sandbox", None):
            self.assertFalse(video.available(CONF)["ok"])


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


if __name__ == "__main__":
    unittest.main()
