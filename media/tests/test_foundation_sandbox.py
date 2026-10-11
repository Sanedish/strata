"""sandbox.py: Job-Object runner (limits verified from inside the child), timeout / memory / process-count kills,
output cap, CPU cap, whole-tree kill, tool discovery, safe_join and rmtree (read-only, long paths, junctions).

The child processes are this Python interpreter running tiny inline scripts, so nothing external is needed.
"""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
MEDIA = os.path.dirname(HERE)
if MEDIA not in sys.path:
    sys.path.insert(0, MEDIA)

import sandbox  # noqa: E402

PY = sys.executable
WIN = sys.platform == "win32"

# Runs inside the sandboxed child: QueryInformationJobObject(NULL, ...) describes the job the calling process
# belongs to (the innermost one), so this proves the limits are applied, not just requested.
JOB_REPORT = r'''
import ctypes, json
from ctypes import wintypes
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
class B(ctypes.Structure):
    _fields_ = [("a", ctypes.c_int64), ("b", ctypes.c_int64), ("LimitFlags", wintypes.DWORD),
                ("mn", ctypes.c_size_t), ("mx", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("Sched", wintypes.DWORD)]
class E(ctypes.Structure):
    _fields_ = [("B", B), ("io", ctypes.c_uint64 * 6), ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t), ("p1", ctypes.c_size_t), ("p2", ctypes.c_size_t)]
class C(ctypes.Structure):
    _fields_ = [("ControlFlags", wintypes.DWORD), ("CpuRate", wintypes.DWORD)]
k32.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                          ctypes.c_void_p]
k32.GetCurrentProcess.restype = wintypes.HANDLE
k32.GetPriorityClass.argtypes = [wintypes.HANDLE]
e, c = E(), C()
ok_e = bool(k32.QueryInformationJobObject(None, 9, ctypes.byref(e), ctypes.sizeof(e), None))
ok_c = bool(k32.QueryInformationJobObject(None, 15, ctypes.byref(c), ctypes.sizeof(c), None))
print(json.dumps({"ok_e": ok_e, "ok_c": ok_c, "flags": e.B.LimitFlags, "mem": e.ProcessMemoryLimit,
                  "procs": e.B.ActiveProcessLimit, "prio": e.B.PriorityClass, "cpu_flags": c.ControlFlags,
                  "cpu_rate": c.CpuRate, "own_class": k32.GetPriorityClass(k32.GetCurrentProcess())}))
'''


def py(code, **kw):
    kw.setdefault("timeout", 30)
    return sandbox.run([PY, "-c", code], **kw)


def process_gone(pid):
    """True when pid has exited (OpenProcess + WaitForSingleObject; never signals anything)."""
    if not WIN:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        return False
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    h = k32.OpenProcess(0x00100000 | 0x1000, False, pid)        # SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return True
    try:
        return k32.WaitForSingleObject(h, 0) == 0                  # WAIT_OBJECT_0 = signalled = exited
    finally:
        k32.CloseHandle(h)


def wait_gone(pid, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process_gone(pid):
            return True
        time.sleep(0.05)
    return process_gone(pid)


class RunTest(unittest.TestCase):
    def test_echo_and_capture(self):
        # raw UTF-8 bytes: independent of the child's stdio encoding (PYTHONIOENCODING is not set under pythonw)
        r = py("import sys; sys.stdout.buffer.write('hello \\u00e9\\n'.encode('utf-8')); sys.stdout.flush(); "
               "print('oops', file=sys.stderr); sys.exit(3)")
        self.assertEqual(r.rc, 3)
        self.assertEqual(r.out.strip(), "hello \u00e9")
        self.assertEqual(r.err.strip(), "oops")
        self.assertIsNone(r.killed)
        self.assertFalse(r.timed_out)
        self.assertFalse(r.truncated)
        self.assertFalse(r.ok)
        self.assertGreater(r.secs, 0)
        self.assertIsInstance(r.out_bytes, bytes)
        ok = py("print('fine')")
        self.assertTrue(ok.ok)
        self.assertEqual(ok.rc, 0)

    def test_cwd_and_env(self):
        d = tempfile.mkdtemp(prefix="sbx-")
        try:
            env = dict(os.environ, STRATA_SBX_TEST="42")
            r = py("import os; print(os.getcwd()); print(os.environ.get('STRATA_SBX_TEST'))", cwd=d, env=env)
            lines = r.out.splitlines()
            self.assertEqual(os.path.normcase(lines[0]), os.path.normcase(os.path.abspath(d)))
            self.assertEqual(lines[1], "42")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_timeout_kills(self):
        t0 = time.perf_counter()
        r = py("import time; print('started', flush=True); time.sleep(60)", timeout=1.5)
        took = time.perf_counter() - t0
        self.assertEqual(r.killed, "timeout")
        self.assertTrue(r.timed_out)
        self.assertNotEqual(r.rc, 0)
        self.assertFalse(r.ok)
        self.assertIn("started", r.out)                                    # output before the kill is kept
        self.assertGreaterEqual(took, 1.4)
        self.assertLess(took, 10)

    def test_memory_limit_kills(self):
        r = py("b = bytearray(400 << 20); print('allocated')", mem_mb=150)
        self.assertNotIn("allocated", r.out)
        self.assertNotEqual(r.rc, 0)
        self.assertFalse(r.ok)
        if WIN:                                                             # the job reports it (completion port)
            self.assertEqual(r.killed, "memory")
            self.assertFalse(r.timed_out)
        r = py("xs = []\nfor i in range(400):\n    xs.append(bytearray(1 << 20))\nprint('allocated')", mem_mb=150)
        self.assertNotIn("allocated", r.out)
        if WIN:
            self.assertEqual(r.killed, "memory")
            self.assertLessEqual(r.peak_mb, 151)                            # never got past the cap

    def test_output_cap(self):
        r = py("import sys; sys.stdout.write('x' * (1 << 20)); sys.stderr.write('y' * 5000)", max_output=1000)
        self.assertEqual(r.rc, 0)                                           # the child never blocked on the pipe
        self.assertEqual(len(r.out_bytes), 1000)
        self.assertEqual(len(r.err_bytes), 1000)
        self.assertTrue(r.truncated)
        self.assertIsNone(r.killed)

    def test_cpu_cap_run_completes(self):
        r = py("s = 0\nfor i in range(300000):\n    s += i\nprint(s)", cpu_pct=5)
        self.assertEqual((r.rc, r.killed), (0, None))
        self.assertEqual(r.out.strip(), str(sum(range(300000))))
        self.assertEqual(r.notes, [])                                       # the hard cap was accepted
        r = py("print('uncapped')", cpu_pct=0, mem_mb=0)                   # 0 = no cap
        self.assertEqual((r.rc, r.out.strip()), (0, "uncapped"))

    def test_bad_input(self):
        with self.assertRaises(ValueError):
            sandbox.run([PY, "-c", "pass"], timeout=5, priority="realtime")
        r = sandbox.run([os.path.join(tempfile.gettempdir(), "no-such-tool-%d.exe" % os.getpid())], timeout=5)
        self.assertEqual((r.rc, r.killed), (-1, "sandbox_error"))          # never raises for tool trouble
        self.assertIn("sandbox:", r.err)


@unittest.skipUnless(WIN, "Windows Job Objects")
class JobObjectTest(unittest.TestCase):
    def test_limits_seen_from_inside(self):
        r = py(JOB_REPORT, mem_mb=150, cpu_pct=35, priority="idle")
        self.assertEqual(r.rc, 0, r.err)
        info = json.loads(r.out)
        self.assertTrue(info["ok_e"] and info["ok_c"])
        for flag in (sandbox.LIMIT_KILL_ON_JOB_CLOSE, sandbox.LIMIT_PROCESS_MEMORY, sandbox.LIMIT_ACTIVE_PROCESS,
                     sandbox.LIMIT_PRIORITY_CLASS, sandbox.LIMIT_DIE_ON_UNHANDLED_EXCEPTION):
            self.assertTrue(info["flags"] & flag, hex(flag))
        self.assertEqual(info["mem"], 150 << 20)
        self.assertEqual(info["procs"], sandbox.ACTIVE_PROCESS_LIMIT)
        self.assertEqual(info["prio"], sandbox.PRIORITY["idle"])
        self.assertEqual(info["own_class"], sandbox.PRIORITY["idle"])       # the child really runs at IDLE
        self.assertEqual(info["cpu_flags"], sandbox.CPU_RATE_ENABLE | sandbox.CPU_RATE_HARD_CAP)
        self.assertEqual(info["cpu_rate"], 3500)                            # 35 % in 1/100 percent

    def test_priority_below_normal(self):
        info = json.loads(py(JOB_REPORT, priority="below_normal").out)
        self.assertEqual((info["prio"], info["own_class"]), (0x4000, 0x4000))

    def test_timeout_kills_the_whole_tree(self):
        code = ("import subprocess, sys, time\n"
                "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
                "print(p.pid, flush=True)\n"
                "time.sleep(60)\n")
        r = py(code, timeout=3)
        self.assertEqual(r.killed, "timeout")
        pid = int(r.out.split()[0])
        self.assertTrue(wait_gone(pid), "grandchild %d survived the timeout" % pid)

    def test_leftover_grandchild_dies_with_the_job(self):
        code = ("import subprocess, sys\n"
                "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
                "print(p.pid, flush=True)\n")                               # exits at once, grandchild keeps running
        t0 = time.perf_counter()
        r = py(code, timeout=30)
        self.assertLess(time.perf_counter() - t0, 15)
        self.assertEqual((r.rc, r.killed), (0, None))
        pid = int(r.out.split()[0])
        self.assertTrue(wait_gone(pid), "grandchild %d outlived the tool" % pid)

    def test_process_limit(self):
        old = sandbox.ACTIVE_PROCESS_LIMIT
        sandbox.ACTIVE_PROCESS_LIMIT = 2
        try:
            code = ("import subprocess, sys, time\n"
                    "ps = []\n"
                    "for i in range(3):\n"
                    "    ps.append(subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']))\n"
                    "print('spawned all', flush=True)\n"
                    "time.sleep(30)\n")
            r = py(code, timeout=20)
        finally:
            sandbox.ACTIVE_PROCESS_LIMIT = old
        self.assertEqual(r.killed, "processes")
        self.assertNotIn("spawned all", r.out)


class WhichTest(unittest.TestCase):
    @unittest.skipUnless(WIN, "Microsoft Defender")
    def test_finds_defender(self):
        p = sandbox.which("mpcmdrun", {}, fresh=True)
        if p is None and not os.path.isdir(r"C:\Program Files\Windows Defender"):
            self.skipTest("no Defender on this machine")
        self.assertIsNotNone(p)
        self.assertTrue(os.path.isfile(p))
        self.assertEqual(os.path.basename(p).lower(), "mpcmdrun.exe")
        self.assertEqual(sandbox.which("MpCmdRun", None), p)                # case-insensitive, cached
        self.assertEqual(sandbox.tools({})["mpcmdrun"], p)
        d = tempfile.mkdtemp(prefix="sbx-")                                 # and it still works inside the job
        try:
            clean = os.path.join(d, "clean.txt")
            with open(clean, "w") as f:
                f.write("just a harmless text file\n")
            r = sandbox.run([p, "-Scan", "-ScanType", "3", "-File", clean, "-DisableRemediation"], timeout=180,
                            mem_mb=512, cpu_pct=35, priority="idle")
            self.assertEqual((r.rc, r.killed), (0, None), r.out[-500:])    # 0 = clean (2 = threats)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_configured_path_wins_and_unknown_names(self):
        d = tempfile.mkdtemp(prefix="sbx-")
        try:
            fake = os.path.join(d, "my-7z.exe")
            with open(fake, "wb") as f:
                f.write(b"MZ")
            conf = {"tools": {"7z": fake}}
            self.assertEqual(os.path.normcase(sandbox.which("7z", conf, fresh=True)), os.path.normcase(fake))
            self.assertEqual(os.path.normcase(sandbox.tools(conf)["7z"]), os.path.normcase(fake))
            self.assertEqual(set(sandbox.tools({})), set(sandbox.TOOL_NAMES))
            self.assertIsNone(sandbox.which("definitely-not-a-tool", conf))
            self.assertIsNone(sandbox.which("", conf))
            gone = {"tools": {"7z": os.path.join(d, "missing.exe")}}      # a stale configured path is skipped
            self.assertNotEqual(sandbox.which("7z", gone, fresh=True), os.path.join(d, "missing.exe"))
        finally:
            shutil.rmtree(d, ignore_errors=True)


class SafeJoinTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="sbx-")
        self.addCleanup(shutil.rmtree, self.root, True)

    def test_inside(self):
        self.assertEqual(sandbox.safe_join(self.root, "a", "b.txt"), os.path.join(self.root, "a", "b.txt"))
        self.assertEqual(sandbox.safe_join(self.root, "a/b/../c.txt"), os.path.join(self.root, "a", "c.txt"))
        self.assertEqual(sandbox.safe_join(self.root, "a\\b.txt"), os.path.join(self.root, "a", "b.txt"))
        self.assertEqual(sandbox.safe_join(self.root), os.path.abspath(self.root))

    def test_rejects_escapes(self):
        bad = ["..", "../x", "a/../../x", "a\\..\\..\\x", "/etc/passwd", "\\Windows", "C:\\Windows", "C:x",
               "\\\\server\\share\\x", "a\x00b", "file.txt:stream", "//server/share"]
        for p in bad:
            with self.assertRaises(ValueError, msg=repr(p)):
                sandbox.safe_join(self.root, p)
        with self.assertRaises(ValueError):
            sandbox.safe_join(self.root, "ok", "..", "..", "x")            # escape spread over parts
        sibling = os.path.basename(self.root) + "-evil"                     # prefix trick: /tmp/sbx-1 vs /tmp/sbx-1-evil
        with self.assertRaises(ValueError):
            sandbox.safe_join(self.root, "..", sibling, "x")


class RmtreeTest(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="sbx-")
        self.addCleanup(shutil.rmtree, self.base, True)

    def test_read_only_files_and_dirs(self):
        top = os.path.join(self.base, "tree")
        sub = os.path.join(top, "a", "b")
        os.makedirs(sub)
        for i, d in enumerate((top, sub)):
            p = os.path.join(d, "ro%d.txt" % i)
            with open(p, "w") as f:
                f.write("x")
            os.chmod(p, stat.S_IREAD)
        os.chmod(sub, stat.S_IREAD)                                         # read-only directory attribute too
        sandbox.rmtree(top)
        self.assertFalse(os.path.lexists(top))
        single = os.path.join(self.base, "single.txt")
        with open(single, "w") as f:
            f.write("x")
        os.chmod(single, stat.S_IREAD)
        sandbox.rmtree(single)
        self.assertFalse(os.path.exists(single))
        sandbox.rmtree(os.path.join(self.base, "never-existed"))            # missing: no error

    def test_long_paths(self):
        top = os.path.join(self.base, "deep")
        deep = os.path.join(top, *(["d" * 40] * 8))                          # > 260 characters
        self.assertGreater(len(deep), 300)
        os.makedirs(sandbox._long(deep))
        with open(sandbox._long(os.path.join(deep, "f.txt")), "w") as f:
            f.write("x")
        sandbox.rmtree(top)
        self.assertFalse(os.path.lexists(top))

    @unittest.skipUnless(WIN, "NTFS junctions")
    def test_junction_is_unlinked_not_followed(self):
        outside = os.path.join(self.base, "outside")
        os.makedirs(outside)
        keep = os.path.join(outside, "keep.txt")
        with open(keep, "w") as f:
            f.write("precious")
        top = os.path.join(self.base, "tree")
        os.makedirs(top)
        link = os.path.join(top, "link")
        r = subprocess.run(["cmd", "/c", "mklink", "/J", link, outside], capture_output=True)
        if r.returncode != 0:
            self.skipTest("cannot create a junction here")
        self.assertTrue(os.path.exists(os.path.join(link, "keep.txt")))
        sandbox.rmtree(top)
        self.assertFalse(os.path.lexists(top))
        self.assertTrue(os.path.isfile(keep))                               # the target survived


if __name__ == "__main__":
    unittest.main()
