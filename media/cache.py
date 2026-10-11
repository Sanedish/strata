"""Variant cache for Strata Media (DESIGN.md 4.2, 11) - the two derived tiers of the image optimizer.

    <cache_root>/cache/img/<ab>/<cd>/<key>.<ext>          ephemeral: LRU + age evicted, capped by cache_max_gb
    <cache_root>/cache/static/img/<ab>/<cd>/<key>.<ext>   persistent: promoted hot variants, never LRU-evicted,
                                                           capped by image.tiers.persistent_max_gb (demotion)
    <cache_root>/locks/<ab>/<key>.lock                    cross-process single-flight (one encode per variant)

Caddy serves these files itself (the accel answer rewrites to rel_url under <cache_root>/cache and file_server does
Range/ETag/304/sendfile), so names are pure hex keys: nothing from a request ever reaches a cache path. Two shard
levels keep directories small (65 536 buckets: 4 M variants are ~60 files per directory). Writes are atomic (temp
file in <cache_root>/tmp on the same volume, fsync, os.replace), so Caddy can never serve half a variant.

Every variant file gets a deterministic mtime (its source's), so Caddy's ETag ("<mtime ns base36><size base36>")
is stable across re-encodes and promotion, and etag_for() can predict it: media.py answers a conditional request for
an evicted variant with 304 instead of encoding it again. Promotion hard-links the file into static/ and only then
switches the row, so a request in flight keeps reading the old name; the ephemeral name is removed afterwards (or
by the orphan sweep if Caddy still holds it open). Originals are never touched - this module only knows cache_root.
"""
import contextlib
import hashlib
import os
import re
import shutil
import stat
import threading
import time
import uuid

try:
    import msvcrt
except ImportError:  # not Windows (tests elsewhere)
    msvcrt = None
    import fcntl

KINDS = {"img": "img", "image": "img", "vid": "vid", "video": "vid"}
REL_RE = re.compile(r"/(?:(static)/)?(img|vid)/([0-9a-f]{2})/([0-9a-f]{2})/([0-9a-f]{40})\.([a-z0-9]{1,8})")
EVICT_EVERY = 60                 # seconds between eviction runs (per process)
EVICT_TO = 0.90                  # evict down to 90 % of max_bytes
TMP_MAX_AGE = 48 * 3600          # leftovers of crashed encodes (a long video transcode can legitimately run for hours)
ORPHAN_MIN_AGE = 3600            # cache files without a variant row are only removed once they are this old
TOUCH_EVERY = 30                 # seconds between batched last_used writes
B36 = "0123456789abcdefghijklmnopqrstuvwxyz"


def _kind(kind):
    k = KINDS.get(kind)
    if k is None:
        raise ValueError("cache kind must be img or vid, not %r" % (kind,))
    return k


def _ext(ext):
    e = (ext or "").lower().lstrip(".")
    if not re.fullmatch(r"[a-z0-9]{1,8}", e):
        raise ValueError("bad cache extension %r" % (ext,))
    return e


def _b36(n):
    n, out = int(n), ""
    neg, n = n < 0, abs(n)
    while True:
        n, r = divmod(n, 36)
        out = B36[r] + out
        if not n:
            return ("-" if neg else "") + out


def caddy_etag(mtime_ns, size):
    """The strong validator Caddy 2.11's file_server derives from a file (verified against the live server)."""
    if int(mtime_ns) // 10 ** 9 in (0, 1):
        return ""
    return '"%s%s"' % (_b36(mtime_ns), _b36(size))


def _created(st):
    """When the file appeared (st_mtime is the source's, see module doc)."""
    return getattr(st, "st_birthtime", None) or st.st_ctime


class Cache:
    def __init__(self, root, max_bytes, store):
        self.root = os.path.abspath(root)
        self.dir = os.path.join(self.root, "cache")      # Caddy's `root` for accel answers
        self.tmp_dir = os.path.join(self.root, "tmp")
        self.lock_dir = os.path.join(self.root, "locks")
        self.max_bytes = int(max_bytes)
        self.max_age_s = None                            # ephemeral age limit (media.py sets it from config)
        self.store = store
        self.clock = time.monotonic
        self._evict_lock = threading.Lock()
        self._last_evict = None
        self._usage = None
        self._usage_at = None
        self._touch = set()
        self._touch_lock = threading.Lock()
        self._touch_at = time.monotonic()
        self.last_evict = {}
        self.evicted = 0                                 # files removed by eviction since start (metrics)
        for d in (self.dir, self.tmp_dir, self.lock_dir):
            try:
                os.makedirs(d, exist_ok=True)
            except OSError:
                pass

    # ------------------------------------------------------------ naming
    def key(self, mount, rel, size, mtime, spec):
        raw = "%s|%s|%d|%r|%s" % (mount, rel, int(size), float(mtime), spec)
        return hashlib.sha1(raw.encode("utf-8", "surrogatepass")).hexdigest()

    def rel_url(self, key, ext, kind, tier="ephemeral"):
        if not re.fullmatch(r"[0-9a-f]{40}", key or ""):
            raise ValueError("bad cache key")
        return "%s/%s/%s/%s/%s.%s" % ("/static" if tier == "persistent" else "", _kind(kind), key[:2], key[2:4],
                                      key, _ext(ext))

    def path_for(self, key, ext, kind, tier="ephemeral"):
        return self._path(self.rel_url(key, ext, kind, tier))

    def _path(self, rel_url):
        """Filesystem path for a rel_url, or None if it is not one of ours (never trusts the string)."""
        m = REL_RE.fullmatch(rel_url or "")
        if not m or m.group(5)[:2] != m.group(3) or m.group(5)[2:4] != m.group(4):
            return None
        parts = (["static"] if m.group(1) else []) + [m.group(2), m.group(3), m.group(4),
                                                       "%s.%s" % (m.group(5), m.group(6))]
        return os.path.join(self.dir, *parts)

    @staticmethod
    def tier_of(rel_url):
        m = REL_RE.fullmatch(rel_url or "")
        return None if not m else ("persistent" if m.group(1) else "ephemeral")

    def tmp_path(self, suffix=""):
        """A fresh temp file name under <root>/tmp (same volume as the cache, so adopt() is an atomic rename)."""
        os.makedirs(self.tmp_dir, exist_ok=True)
        return os.path.join(self.tmp_dir, uuid.uuid4().hex + (suffix or ""))

    # ------------------------------------------------------------ writing
    @staticmethod
    def _stamp(path, mtime):
        """Deterministic mtime (the source's, whole microseconds) -> a stable, predictable Caddy ETag."""
        if mtime is not None:
            ns = int(round(float(mtime) * 1e6)) * 1000
            os.utime(path, ns=(time.time_ns(), ns))

    def write_bytes(self, key, ext, kind, data, mtime=None, tier="ephemeral"):
        """Atomically store a variant; returns its rel_url ("/img/ab/cd/<key>.avif")."""
        rel = self.rel_url(key, ext, kind, tier)
        final = self._path(rel)
        os.makedirs(os.path.dirname(final), exist_ok=True)
        tmp = self.tmp_path("." + _ext(ext))
        try:
            with open(tmp, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            self._stamp(tmp, mtime)
            os.replace(tmp, final)
        except BaseException:
            _quiet_remove(tmp)
            raise
        self._grow(len(data))
        return rel

    def adopt(self, key, ext, kind, tmp_path, mtime=None):
        """Move a finished temp file (e.g. ffmpeg output from tmp_path()) into place; returns its rel_url."""
        rel = self.rel_url(key, ext, kind)
        final = self._path(rel)
        os.makedirs(os.path.dirname(final), exist_ok=True)
        size = os.path.getsize(tmp_path)
        self._stamp(tmp_path, mtime)
        try:
            os.replace(tmp_path, final)
        except OSError:
            if os.path.splitdrive(os.path.abspath(tmp_path))[0].lower() == os.path.splitdrive(final)[0].lower():
                raise
            staged = self.tmp_path("." + _ext(ext))   # other volume: copy next to the cache first, then rename
            try:
                shutil.copyfile(tmp_path, staged)
                self._stamp(staged, mtime)
                os.replace(staged, final)
            except BaseException:
                _quiet_remove(staged)
                raise
            _quiet_remove(tmp_path)
        self._grow(size)
        return rel

    def etag_for(self, rel_url):
        """The ETag Caddy will send for this cache file ("" if it does not exist)."""
        p = self._path(rel_url)
        try:
            st = os.stat(p) if p else None
        except OSError:
            return ""
        return caddy_etag(st.st_mtime_ns, st.st_size) if st else ""

    def exists(self, rel_url):
        p = self._path(rel_url)
        return bool(p) and os.path.isfile(p)

    def remove(self, rel_url):
        """Delete one cache file (bridge: source deleted/replaced). True if it is gone."""
        p = self._path(rel_url)
        if not p:
            return False
        try:
            os.remove(p)
        except FileNotFoundError:
            pass
        except OSError:
            return False
        return True

    # ------------------------------------------------------------ tiers
    def move_tier(self, rel_url, key, tier):
        """Place a variant file in `tier` (persistent = static/, ephemeral = the LRU area) and return its new rel_url.

        Race-safe for requests in flight: the new name is created first (hard link, or copy + atomic rename where
        links are impossible), the caller then switches the variant row, and the old name is removed last; if Caddy
        still holds the old file open the removal fails quietly and the orphan sweep takes it later."""
        src = self._path(rel_url)
        m = REL_RE.fullmatch(rel_url or "")
        if not src or not m or m.group(5) != key:
            raise ValueError("not a cache file of this key: %r" % (rel_url,))
        new = self.rel_url(key, m.group(6), m.group(2), tier)
        if new == rel_url:
            return new
        dst = self._path(new)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if not os.path.exists(dst):
            try:
                os.link(src, dst)
            except FileExistsError:
                pass
            except OSError:
                staged = self.tmp_path("." + m.group(6))
                try:
                    shutil.copy2(src, staged)      # copy2 keeps the mtime -> same ETag
                    os.replace(staged, dst)
                except BaseException:
                    _quiet_remove(staged)
                    raise
        return new

    def lock(self, key):
        """Cross-process single-flight for one variant: KeyLock(...).acquire(blocking) (see KeyLock)."""
        return KeyLock(os.path.join(self.lock_dir, key[:2], key + ".lock"))

    # ------------------------------------------------------------ hits
    def touch(self, key):
        """Note a cache hit; last_used is written to the store in batches (every TOUCH_EVERY s, off-thread)."""
        with self._touch_lock:
            self._touch.add(key)
            due = time.monotonic() - self._touch_at >= TOUCH_EVERY
            if due:
                self._touch_at = time.monotonic()
        if due:
            threading.Thread(target=self.flush_touches, name="media-touch", daemon=True).start()

    def flush_touches(self):
        with self._touch_lock:
            keys, self._touch = list(self._touch), set()
        if keys and self.store is not None:
            try:
                self.store.touch_variants(keys)
            except Exception:
                with self._touch_lock:
                    self._touch.update(keys)

    # ------------------------------------------------------------ size limit
    def _grow(self, n):
        if self._usage is not None:
            self._usage["bytes"] += n
            self._usage["files"] += 1

    def _walk(self, sub=None):
        """(bytes, files) under the cache dir; sub="static" counts only the persistent tier."""
        total = files = 0
        top = os.path.join(self.dir, sub) if sub else self.dir
        stack = [top]
        while stack:
            d = stack.pop()
            try:
                with os.scandir(d) as it:
                    for e in it:
                        try:
                            if e.is_dir(follow_symlinks=False):
                                if sub is None and d == self.dir and e.name == "static":
                                    continue    # counted separately: the ephemeral cap must not include it
                                stack.append(e.path)
                            elif e.is_file(follow_symlinks=False):
                                total += e.stat(follow_symlinks=False).st_size
                                files += 1
                        except OSError:
                            pass
            except OSError:
                pass
        return total, files

    def usage(self, fresh=False):
        """{"bytes", "files" (ephemeral), "static_bytes", "static_files", "disk_free", "disk_total", "max_bytes"};
        the directory walk is reused for 60 s."""
        now = self.clock()
        if fresh or self._usage is None or self._usage_at is None or now - self._usage_at >= EVICT_EVERY:
            b, n = self._walk()
            sb, sn = self._walk("static")
            self._usage, self._usage_at = {"bytes": b, "files": n, "static_bytes": sb, "static_files": sn}, now
        out = dict(self._usage, max_bytes=self.max_bytes)
        try:
            du = shutil.disk_usage(self.root)
            out.update(disk_free=du.free, disk_total=du.total)
        except OSError:
            out.update(disk_free=None, disk_total=None)
        return out

    def maybe_evict(self):
        """Start an eviction pass in the background unless one ran in the last 60 s. Returns True if started."""
        now = self.clock()
        if self._last_evict is not None and now - self._last_evict < EVICT_EVERY:
            return False
        if not self._evict_lock.acquire(blocking=False):
            return False
        self._last_evict = now

        def bg():
            try:
                self.evict(locked=True)
            except Exception as e:
                self.last_evict = {"error": "%s: %s" % (e.__class__.__name__, e)}
            finally:
                self._evict_lock.release()
        threading.Thread(target=bg, name="media-evict", daemon=True).start()
        return True

    def evict(self, locked=False):
        """Synchronous eviction pass over the ephemeral tier: variants older than max_age_s, then LRU until <= 90 % of
        max_bytes, then (still over) orphan files, oldest first; also clears stale temp files. Rows of evicted
        variants stay as tombstones (store.evict_variant). Returns stats."""
        if not locked and not self._evict_lock.acquire(timeout=60):
            return {"skipped": True}
        try:
            return self._evict()
        finally:
            if not locked:
                self._evict_lock.release()

    def _drop_file(self, r, busy):
        """Remove one variant's file and tombstone its row: freed bytes, or None if the file is in use."""
        p = self._path(r.get("file") or "")
        size = 0
        if p:
            try:
                size = os.path.getsize(p)
                os.remove(p)
            except FileNotFoundError:
                size = 0
            except OSError:          # being served right now (Caddy holds it open): it is not LRU
                busy.add(r["key"])
                self.store.touch_variants([r["key"]])
                return None
        self.store.evict_variant(r["key"])
        self.evicted += 1
        return size

    def _evict(self):
        t0 = time.monotonic()
        self.flush_touches()
        tmp_removed = self._clean_tmp()
        total, files = self._walk()
        target = int(self.max_bytes * EVICT_TO)
        removed = freed = aged = 0
        busy = set()
        if self.max_age_s and self.store is not None:   # age limit applies whatever the size
            before = time.time() - self.max_age_s
            for _ in range(20):
                rows = [r for r in self.store.stale_ephemeral(before, 500) if r["key"] not in busy]
                if not rows:
                    break
                for r in rows:
                    size = self._drop_file(r, busy)
                    if size is not None:
                        total, freed, removed, aged = total - size, freed + size, removed + 1, aged + 1
        over = total > self.max_bytes    # only a run that starts over the cap evicts (then down to 90 %)
        if over and self.store is not None:
            while total > target:
                rows = [r for r in self.store.lru_variants(500) if r["key"] not in busy]
                if not rows:
                    break
                for r in rows:
                    if total <= target:
                        break
                    size = self._drop_file(r, busy)
                    if size is not None:
                        total, freed, removed = total - size, freed + size, removed + 1
        if over and total > target:
            n, f, total = self._evict_orphans(total, target)
            removed, freed = removed + n, freed + f
        self._usage = None   # next usage() walks again (static tier included)
        self.last_evict = {"ts": time.time(), "removed": removed, "aged": aged, "freed": freed, "bytes": total,
                           "tmp_removed": tmp_removed, "secs": round(time.monotonic() - t0, 3)}
        return self.last_evict

    def sweep_orphans(self, min_age=ORPHAN_MIN_AGE):
        """Remove files no variant row points at (old names left by promotion/demotion, crashed writes)."""
        return self._evict_orphans(None, None, min_age)

    def _evict_orphans(self, total, target, min_age=None):
        """Files with no (or a lost) variant row: crash between write and put_variant, rows dropped elsewhere, the
        old name of a promoted variant. With total/target None every orphan old enough goes."""
        if min_age is None:
            min_age = ORPHAN_MIN_AGE if self.store is not None else 0
        now, cand = time.time(), []
        for dp, dn, fn in os.walk(self.dir):
            for name in fn:
                p = os.path.join(dp, name)
                try:
                    st = os.stat(p)
                except OSError:
                    continue
                if now - _created(st) >= min_age:
                    cand.append((_created(st), st.st_size, p, name.split(".", 1)[0]))
        cand.sort()
        removed = freed = 0
        for _, size, p, key in cand:
            if target is not None and total <= target:
                break
            if self.store is not None:
                row = self.store.variant(key)
                if row and row.get("beneficial") and self._path(row.get("file") or "") == p:
                    continue             # a tracked variant (in use / persistent)
            try:
                os.remove(p)
            except OSError:
                continue
            if total is not None:
                total -= size
            freed += size
            removed += 1
        return removed, freed, total

    def _clean_tmp(self):
        n, now = 0, time.time()
        try:
            with os.scandir(self.tmp_dir) as it:
                for e in it:
                    try:
                        if e.is_file(follow_symlinks=False) and now - e.stat().st_mtime > TMP_MAX_AGE:
                            os.remove(e.path)
                            n += 1
                    except OSError:
                        pass             # still open by a running encoder
        except OSError:
            pass
        return n


class KeyLock:
    """An exclusive OS lock on <locks>/<ab>/<key>.lock, shared by media.py's threads (via its in-process flight)
    and the worker process. The OS drops it when the holder dies, so there are no stale locks to clean up."""

    def __init__(self, path):
        self.path = path
        self.fd = None

    def acquire(self, blocking=False, timeout=0.0):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o644)
            try:
                if msvcrt is not None:
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.fd = fd
                return True
            except OSError:
                os.close(fd)
                if not blocking or time.monotonic() >= deadline:
                    return False
                time.sleep(0.05)

    def release(self):
        fd, self.fd = self.fd, None
        if fd is None:
            return
        try:
            if msvcrt is not None:
                os.lseek(fd, 0, 0)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)
        if msvcrt is not None:          # Windows refuses to delete a file another process has open, so this can
            try:                         # never orphan a waiter's lock (on POSIX unlinking would: leave it there)
                os.remove(self.path)
            except OSError:
                pass

    @contextlib.contextmanager
    def held(self, blocking=False, timeout=0.0):
        ok = self.acquire(blocking, timeout)
        try:
            yield ok
        finally:
            if ok:
                self.release()


def _quiet_remove(p):
    try:
        os.chmod(p, stat.S_IWRITE)
        os.remove(p)
    except OSError:
        pass
