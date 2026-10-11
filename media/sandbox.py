"""Run external tools (ffmpeg, 7-Zip, Tesseract, MpCmdRun, ClamAV) inside a Windows Job Object (DESIGN.md 7.2, 11).

Every tool processes untrusted uploads, so every run is boxed: the child starts suspended, joins a job, and only
then runs. The job caps memory per process, the number of processes (no fork bombs), the priority class (idle:
Caddy and cloudflared always win) and, when asked, hard-caps CPU; closing the job kills everything in it, so a
timeout or a crashed worker never leaves orphans. Unhandled exceptions die quietly instead of opening WER
dialogs nobody sees under pythonw. Output is drained by threads and capped. A job object is a resource box, not a
security boundary - the archive/text parsers still treat everything as hostile.

Also: tool discovery (config path, PATH, usual install dirs), safe_join() for sandbox-relative paths and an
rmtree() that copes with read-only files, long paths and junctions/symlinks (removes the link, never follows it).
"""
import ctypes
import glob
import os
import re
import shutil
import stat
import subprocess
import sys
import threading
import time

WIN = sys.platform == "win32"
TOOL_NAMES = ("ffmpeg", "ffprobe", "7z", "tesseract", "mpcmdrun", "clamscan", "clamdscan")
PRIORITY = {"idle": 0x40, "below_normal": 0x4000, "normal": 0x20}    # *_PRIORITY_CLASS
ACTIVE_PROCESS_LIMIT = 16
WHICH_TTL = 600                                                        # re-discover tools every 10 min

# job object limit flags / info classes / completion-port messages
LIMIT_ACTIVE_PROCESS = 0x8
LIMIT_PRIORITY_CLASS = 0x20
LIMIT_PROCESS_MEMORY = 0x100
LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x400
LIMIT_KILL_ON_JOB_CLOSE = 0x2000
INFO_BASIC_UI = 4
INFO_ASSOC_PORT = 7
INFO_EXTENDED = 9
INFO_CPU_RATE = 15
CPU_RATE_ENABLE, CPU_RATE_HARD_CAP = 0x1, 0x4
UI_ALL = 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x20 | 0x40 | 0x80      # handles, clipboard r/w, sysparams, display, atoms, desktop, exitwindows
MSG_ACTIVE_PROCESS_LIMIT, MSG_ACTIVE_PROCESS_ZERO = 3, 4
MSG_PROCESS_MEMORY_LIMIT, MSG_JOB_MEMORY_LIMIT = 9, 10
CREATE_SUSPENDED, CREATE_NO_WINDOW = 0x4, 0x08000000
FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_DIRECTORY = 0x400, 0x10

if WIN:
    from ctypes import wintypes

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [(n, ctypes.c_uint64) for n in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                                                   "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class _BASIC_LIMIT(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]

    class _EXTENDED_LIMIT(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", _BASIC_LIMIT), ("IoInfo", _IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

    class _CPU_RATE(ctypes.Structure):
        _fields_ = [("ControlFlags", wintypes.DWORD), ("CpuRate", wintypes.DWORD)]

    class _ASSOC_PORT(ctypes.Structure):
        _fields_ = [("CompletionKey", ctypes.c_void_p), ("CompletionPort", wintypes.HANDLE)]

    class _UI_RESTRICT(ctypes.Structure):
        _fields_ = [("UIRestrictionsClass", wintypes.DWORD)]

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)   # private instance: our argtypes never leak elsewhere
    _ntdll = ctypes.WinDLL("ntdll")
    _k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    _k32.CreateJobObjectW.restype = wintypes.HANDLE
    _k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    _k32.SetInformationJobObject.restype = wintypes.BOOL
    _k32.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                               ctypes.POINTER(wintypes.DWORD)]
    _k32.QueryInformationJobObject.restype = wintypes.BOOL
    _k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _k32.AssignProcessToJobObject.restype = wintypes.BOOL
    _k32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _k32.TerminateJobObject.restype = wintypes.BOOL
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.CloseHandle.restype = wintypes.BOOL
    _k32.CreateIoCompletionPort.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.c_size_t, wintypes.DWORD]
    _k32.CreateIoCompletionPort.restype = wintypes.HANDLE
    _k32.GetQueuedCompletionStatus.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
                                               ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_void_p),
                                               wintypes.DWORD]
    _k32.GetQueuedCompletionStatus.restype = wintypes.BOOL
    _ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
    _ntdll.NtResumeProcess.restype = ctypes.c_long
    INVALID_HANDLE_VALUE = wintypes.HANDLE(-1)


class Result:
    """rc, out/err (decoded text), timed_out, secs, killed ("timeout" | "memory" | "processes" | "sandbox_error" |
    None), plus out_bytes/err_bytes (raw), truncated, peak_mb (largest process commit, Windows) and notes.
    A killed run's rc (Windows) is the job exit code (1 timeout, 3 memory, 4 processes); -1 = never started
    (sandbox_error: missing executable or the job could not be set up - a tool is never run un-boxed)."""

    def __init__(self):
        self.rc, self.out, self.err, self.timed_out, self.secs, self.killed = None, "", "", False, 0.0, None
        self.out_bytes = self.err_bytes = b""
        self.truncated, self.peak_mb, self.notes = False, None, []

    @property
    def ok(self):
        return self.rc == 0 and not self.killed

    def __repr__(self):
        return "Result(rc=%r, killed=%r, secs=%.2f, out=%d B, err=%d B)" % (
            self.rc, self.killed, self.secs, len(self.out_bytes), len(self.err_bytes))


def _drain(pipe, buf, cap, res):
    """Read a pipe to EOF, keeping at most cap bytes (the rest is discarded so the child never blocks)."""
    kept = 0
    try:
        while True:
            chunk = pipe.read1(65536) if hasattr(pipe, "read1") else pipe.read(65536)
            if not chunk:
                break
            room = cap - kept
            if room > 0:
                buf.append(chunk[:room])
                kept += min(room, len(chunk))
            if len(chunk) > room:
                res.truncated = True
    except (OSError, ValueError):
        pass
    finally:
        try:
            pipe.close()
        except OSError:
            pass


def _collect(proc, res, max_output):
    out, err = [], []
    readers = [threading.Thread(target=_drain, args=(proc.stdout, out, max_output, res), daemon=True),
               threading.Thread(target=_drain, args=(proc.stderr, err, max_output, res), daemon=True)]
    for t in readers:
        t.start()
    return readers, out, err


def _finish(res, proc, readers, out, err, t0):
    try:
        proc.wait(10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(5)
    for t in readers:
        t.join(10)
    res.rc = proc.returncode
    res.out_bytes, res.err_bytes = b"".join(out), b"".join(err)
    res.out = res.out_bytes.decode("utf-8", "replace")
    res.err = res.err_bytes.decode("utf-8", "replace")
    res.timed_out = res.killed == "timeout"
    res.secs = time.monotonic() - t0
    return res


def run(cmd, timeout, mem_mb=1024, cpu_pct=35, priority="idle", cwd=None, env=None, max_output=4 << 20):
    """Run cmd (argument list) boxed; never raises for tool failures - inspect the Result."""
    if priority not in PRIORITY:
        raise ValueError("priority must be one of %s" % ", ".join(PRIORITY))
    if not WIN:
        return _run_posix(cmd, timeout, mem_mb, priority, cwd, env, max_output)
    t0 = time.monotonic()
    res = Result()
    job = port = proc = None
    try:
        try:
            job = _k32.CreateJobObjectW(None, None)
            if not job:
                raise ctypes.WinError(ctypes.get_last_error())
            info = _EXTENDED_LIMIT()
            b = info.BasicLimitInformation
            b.LimitFlags = (LIMIT_KILL_ON_JOB_CLOSE | LIMIT_ACTIVE_PROCESS | LIMIT_PRIORITY_CLASS
                            | LIMIT_DIE_ON_UNHANDLED_EXCEPTION | (LIMIT_PROCESS_MEMORY if mem_mb else 0))
            b.ActiveProcessLimit = ACTIVE_PROCESS_LIMIT
            b.PriorityClass = PRIORITY[priority]
            if mem_mb:
                info.ProcessMemoryLimit = int(mem_mb) << 20
            if not _k32.SetInformationJobObject(job, INFO_EXTENDED, ctypes.byref(info), ctypes.sizeof(info)):
                raise ctypes.WinError(ctypes.get_last_error())
            if cpu_pct:
                rate = _CPU_RATE(CPU_RATE_ENABLE | CPU_RATE_HARD_CAP, max(1, min(10000, int(cpu_pct * 100))))
                if not _k32.SetInformationJobObject(job, INFO_CPU_RATE, ctypes.byref(rate), ctypes.sizeof(rate)):
                    res.notes.append("cpu cap unavailable (winerror %d)" % ctypes.get_last_error())
            ui = _UI_RESTRICT(UI_ALL)
            _k32.SetInformationJobObject(job, INFO_BASIC_UI, ctypes.byref(ui), ctypes.sizeof(ui))
            port = _k32.CreateIoCompletionPort(INVALID_HANDLE_VALUE, None, 0, 1)
            if port:
                assoc = _ASSOC_PORT(ctypes.c_void_p(1), port)
                if not _k32.SetInformationJobObject(job, INFO_ASSOC_PORT, ctypes.byref(assoc), ctypes.sizeof(assoc)):
                    _k32.CloseHandle(port)
                    port = None
            proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    cwd=cwd, env=env,
                                    creationflags=CREATE_SUSPENDED | CREATE_NO_WINDOW | PRIORITY[priority])
            if not _k32.AssignProcessToJobObject(job, int(proc._handle)):
                raise ctypes.WinError(ctypes.get_last_error())
            status = _ntdll.NtResumeProcess(int(proc._handle))
            if status != 0:
                raise OSError("NtResumeProcess failed (0x%08x)" % (status & 0xFFFFFFFF))
        except (OSError, ValueError) as e:
            # never run a tool un-boxed: a memory bomb must not be able to starve Caddy
            if proc is not None:
                try:
                    proc.kill()
                    proc.communicate(timeout=5)
                except Exception:
                    pass
            res.rc, res.killed, res.err = -1, "sandbox_error", "sandbox: %s" % e
            res.secs = time.monotonic() - t0
            return res
        readers, out, err = _collect(proc, res, max_output)
        deadline = None if timeout is None else t0 + timeout
        while proc.poll() is None:
            left = None if deadline is None else deadline - time.monotonic()
            if left is not None and left <= 0:
                res.killed = "timeout"
                _k32.TerminateJobObject(job, 1)
                break
            ms = 200 if left is None else max(1, min(200, int(left * 1000)))
            msg = _next_msg(port, ms) if port else _sleep_wait(proc, ms)
            if msg in (MSG_PROCESS_MEMORY_LIMIT, MSG_JOB_MEMORY_LIMIT):
                res.killed = "memory"
                _k32.TerminateJobObject(job, 3)
                break
            if msg == MSG_ACTIVE_PROCESS_LIMIT:
                res.killed = "processes"
                _k32.TerminateJobObject(job, 4)
                break
        # the limit message can race the child's own exit (e.g. it died of MemoryError): look once more
        while port and res.killed is None:
            msg = _next_msg(port, 0)
            if msg is None:
                break
            if msg in (MSG_PROCESS_MEMORY_LIMIT, MSG_JOB_MEMORY_LIMIT):
                res.killed = "memory"
            elif msg == MSG_ACTIVE_PROCESS_LIMIT:
                res.killed = "processes"
        _k32.TerminateJobObject(job, 0)      # anything the tool left running dies with it
        info = _EXTENDED_LIMIT()
        if _k32.QueryInformationJobObject(job, INFO_EXTENDED, ctypes.byref(info), ctypes.sizeof(info), None):
            res.peak_mb = round(info.PeakProcessMemoryUsed / 1048576.0, 1)
            if (res.killed is None and mem_mb and proc.poll() not in (0, None)
                    and info.PeakProcessMemoryUsed >= 0.97 * (int(mem_mb) << 20)):
                res.killed = "memory"
        return _finish(res, proc, readers, out, err, t0)
    finally:
        if port:
            _k32.CloseHandle(port)
        if job:
            _k32.CloseHandle(job)           # KILL_ON_JOB_CLOSE


def _next_msg(port, ms):
    n, key, ov = wintypes.DWORD(), ctypes.c_size_t(), ctypes.c_void_p()
    if _k32.GetQueuedCompletionStatus(port, ctypes.byref(n), ctypes.byref(key), ctypes.byref(ov), int(ms)):
        return n.value
    return None


def _sleep_wait(proc, ms):
    try:
        proc.wait(ms / 1000.0)
    except subprocess.TimeoutExpired:
        pass
    return None


def _run_posix(cmd, timeout, mem_mb, priority, cwd, env, max_output):
    """Fallback for non-Windows hosts (tests elsewhere): rlimit + nice + own session, killed on timeout."""
    import signal

    def limits():
        try:
            import resource
            if mem_mb:
                resource.setrlimit(resource.RLIMIT_AS, (int(mem_mb) << 20, int(mem_mb) << 20))
            os.nice({"idle": 19, "below_normal": 10, "normal": 0}[priority])
        except Exception:
            pass
    t0 = time.monotonic()
    res = Result()
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                cwd=cwd, env=env, preexec_fn=limits, start_new_session=True)
    except OSError as e:
        res.rc, res.killed, res.err = -1, "sandbox_error", "sandbox: %s" % e
        res.secs = time.monotonic() - t0
        return res
    readers, out, err = _collect(proc, res, max_output)
    try:
        proc.wait(timeout)
    except subprocess.TimeoutExpired:
        res.killed = "timeout"
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            proc.kill()
    return _finish(res, proc, readers, out, err, t0)


# ---------------------------------------------------------------- tool discovery

EXE_NAMES = {"ffmpeg": ["ffmpeg"], "ffprobe": ["ffprobe"], "7z": ["7z", "7za", "7zz"], "tesseract": ["tesseract"],
             "mpcmdrun": ["MpCmdRun"], "clamscan": ["clamscan"], "clamdscan": ["clamdscan"]}
_which_cache = {}
_which_lock = threading.Lock()


def _local_appdata():
    if WIN:
        try:  # like pathfix: Task Scheduler may start us without LOCALAPPDATA
            buf = ctypes.create_unicode_buffer(520)
            if ctypes.windll.shell32.SHGetFolderPathW(None, 0x1C, None, 0, buf) == 0 and buf.value:
                return buf.value
        except Exception:
            pass
    return os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")


def _version_key(path):
    return tuple(int(x) for x in re.findall(r"\d+", os.path.basename(os.path.dirname(path))))


def _known_paths(name):
    if not WIN:
        return []
    pf = [os.environ.get("ProgramFiles") or r"C:\Program Files", r"C:\Program Files",
          os.environ.get("ProgramFiles(x86)") or r"C:\Program Files (x86)"]
    pf = list(dict.fromkeys(pf))
    local, pdata = _local_appdata(), os.environ.get("ProgramData") or r"C:\ProgramData"
    if name == "7z":
        return [os.path.join(p, "7-Zip", "7z.exe") for p in pf]
    if name == "tesseract":
        return ([os.path.join(p, "Tesseract-OCR", "tesseract.exe") for p in pf]
                + [os.path.join(local, "Programs", "Tesseract-OCR", "tesseract.exe")])
    if name in ("ffmpeg", "ffprobe"):
        exe = name + ".exe"
        found = glob.glob(os.path.join(local, "Microsoft", "WinGet", "Packages", "Gyan.FFmpeg*", "**", "bin", exe),
                          recursive=True)
        found.sort(key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0, reverse=True)
        return found + [os.path.join(local, "Microsoft", "WinGet", "Links", exe), os.path.join(r"C:\ffmpeg\bin", exe)] \
            + [os.path.join(p, "ffmpeg", "bin", exe) for p in pf]
    if name == "mpcmdrun":
        plat = glob.glob(os.path.join(pdata, "Microsoft", "Windows Defender", "Platform", "*", "MpCmdRun.exe"))
        plat.sort(key=_version_key, reverse=True)
        return plat + [os.path.join(pf[0], "Windows Defender", "MpCmdRun.exe")]
    if name in ("clamscan", "clamdscan"):
        exe = name + ".exe"
        return ([os.path.join(p, d, exe) for p in pf for d in ("ClamAV", "ClamAV-x64")]
                + [os.path.join(r"C:\ClamAV", exe)])
    return []


def which(name, conf=None, fresh=False):
    """Path of a tool (ffmpeg ffprobe 7z tesseract mpcmdrun clamscan clamdscan) or None. Order: the configured
    path (media.tools.<name>), PATH, the usual install dirs. Results are cached for 10 minutes."""
    name = (name or "").lower()
    if name not in EXE_NAMES:
        return None
    tools_conf = (conf or {}).get("tools") or {} if isinstance(conf, dict) else {}
    configured = (tools_conf.get(name) or "").strip()
    key, now = (name, configured), time.monotonic()
    with _which_lock:
        hit = _which_cache.get(key)
        if hit and not fresh and now - hit[0] < WHICH_TTL and (hit[1] is None or os.path.isfile(hit[1])):
            return hit[1]
    found = None
    if configured and os.path.isfile(configured):
        found = os.path.abspath(configured)
    if not found:
        for exe in EXE_NAMES[name]:
            p = shutil.which(exe)
            if p:
                found = os.path.abspath(p)
                break
    if not found:
        for p in _known_paths(name):
            try:
                if os.path.isfile(p):
                    found = p
                    break
            except OSError:
                pass
    with _which_lock:
        _which_cache[key] = (now, found)
    return found


def tools(conf=None, fresh=False):
    return {n: which(n, conf, fresh) for n in TOOL_NAMES}


# ---------------------------------------------------------------- paths

def safe_join(root, *parts):
    """root/parts, refusing absolute parts, drive letters, streams (':'), NUL and anything that resolves outside
    root. Raises ValueError."""
    base = os.path.abspath(root)
    for p in parts:
        s = os.fspath(p)
        if not isinstance(s, str):
            s = os.fsdecode(s)
        if "\x00" in s or ":" in s or s.replace("\\", "/").startswith("/") or os.path.isabs(s):
            raise ValueError("unsafe path component %r" % s)
    full = os.path.abspath(os.path.join(base, *[os.fspath(p) for p in parts]))
    b, f = os.path.normcase(base), os.path.normcase(full)
    try:
        inside = os.path.commonpath([b, f]) == b
    except ValueError:
        inside = False
    if not inside:
        raise ValueError("path escapes %s" % root)
    return full


def _long(path):
    """\\\\?\\ form so paths deeper than MAX_PATH (extracted archives) can be removed."""
    p = os.path.abspath(path)
    if not WIN or p.startswith("\\\\?\\"):
        return p
    if p.startswith("\\\\"):
        return "\\\\?\\UNC\\" + p[2:]
    return "\\\\?\\" + p


def _is_link(st):
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def _retry_rw(fn, p):
    try:
        fn(p)
    except PermissionError:
        os.chmod(p, stat.S_IWRITE | stat.S_IREAD)   # read-only attribute (common in extracted archives)
        fn(p)


def _rm_once(top):
    first = None
    stack = [(top, False)]
    while stack:
        p, done = stack.pop()
        try:
            if done:
                _retry_rw(os.rmdir, p)
                continue
            st = os.lstat(p)
            if _is_link(st):
                # junction / symlink / other reparse point: delete the link itself, never what it points to
                is_dir = stat.S_ISDIR(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_DIRECTORY)
                _retry_rw(os.rmdir if is_dir else os.remove, p)
            elif stat.S_ISDIR(st.st_mode):
                stack.append((p, True))
                with os.scandir(p) as it:
                    stack.extend((e.path, False) for e in it)
            else:
                _retry_rw(os.remove, p)
        except FileNotFoundError:
            pass
        except OSError as e:
            first = first or e
    if first is not None:
        raise first


def rmtree(path, retries=5):
    """Delete a tree (or a single file / link). Retries briefly: an AV scanner may still hold a file open.
    Raises OSError if it could not be removed."""
    top = _long(path)
    last = None
    for attempt in range(max(1, retries)):
        try:
            _rm_once(top)
        except OSError as e:
            last = e
        if not os.path.lexists(top):
            return
        time.sleep(0.1 * (attempt + 1))
    if os.path.lexists(top):
        raise last or OSError("could not remove %s" % path)
