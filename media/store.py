"""media.db - verdicts, jobs, variants, events, samples and meta for Strata Media (DESIGN.md section 10).

Shared by media.py (hot path: reads, enqueues), worker.py (claims jobs, writes verdicts and variants) and the
bridge inside strata.py (discovery, admin). WAL lets all of them read while one writes. sqlite3 connections
are not thread-safe, so every thread gets its own (threading.local) with a 15 s busy timeout. Operations that
read and then write (claim, enqueue dedupe, fail, set_verdict) run inside BEGIN IMMEDIATE: the write lock is
taken up front, so two workers can never claim the same job and a dedupe check cannot race an insert.
Timestamps are wall-clock seconds (self.clock, replaceable in tests).
"""
import contextlib
import json
import os
import sqlite3
import threading
import time
import urllib.parse

SCHEMA = """
CREATE TABLE IF NOT EXISTS verdict(mount INTEGER NOT NULL, path TEXT NOT NULL, size INTEGER, mtime REAL,
  qhash TEXT, state TEXT NOT NULL, severity TEXT, findings TEXT, engines TEXT, scanned REAL, updated REAL NOT NULL,
  legacy INTEGER DEFAULT 0, reviewed_by TEXT, review_note TEXT, PRIMARY KEY(mount, path)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS verdict_updated ON verdict(updated);
CREATE INDEX IF NOT EXISTS verdict_state ON verdict(state);
CREATE INDEX IF NOT EXISTS verdict_hash ON verdict(size, qhash);
CREATE TABLE IF NOT EXISTS job(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, mount INTEGER, path TEXT,
  params TEXT NOT NULL DEFAULT '', size INTEGER, mtime REAL, priority INTEGER NOT NULL, state TEXT NOT NULL,
  attempts INTEGER DEFAULT 0, lease_until REAL, not_before REAL DEFAULT 0, worker TEXT, created REAL,
  started REAL, finished REAL, error TEXT, error_kind TEXT, result TEXT, UNIQUE(kind, mount, path, params));
CREATE INDEX IF NOT EXISTS job_pick ON job(state, priority, created);
CREATE TABLE IF NOT EXISTS variant(key TEXT PRIMARY KEY, mount INTEGER, path TEXT, src_size INTEGER,
  src_mtime REAL, kind TEXT, fmt TEXT, spec TEXT, file TEXT, bytes INTEGER, src_bytes INTEGER, secs REAL,
  beneficial INTEGER, created REAL, last_used REAL);
CREATE INDEX IF NOT EXISTS variant_src ON variant(mount, path);
CREATE INDEX IF NOT EXISTS variant_used ON variant(last_used);
CREATE TABLE IF NOT EXISTS event(id INTEGER PRIMARY KEY, ts REAL NOT NULL, proc TEXT, kind TEXT NOT NULL,
  severity TEXT, mount INTEGER, path TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS event_ts ON event(ts);
CREATE INDEX IF NOT EXISTS event_kind ON event(kind, ts);
CREATE TABLE IF NOT EXISTS sample(ts INTEGER NOT NULL, proc TEXT NOT NULL, data TEXT, PRIMARY KEY(ts, proc)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
"""

# Columns added after v1 (ALTER TABLE on open; SQLite cannot ADD COLUMN IF NOT EXISTS). Image optimizer tiers:
#   tier       ephemeral (LRU / age evicted) | persistent (promoted hot variant, never LRU-evicted) | evicted
#              (tombstone: the file is gone but the row keeps hotness, ETag and the decision)
#   hits/score lifetime origin requests / exponentially decayed request count (half-life image.tiers.half_life_h)
#   served/saved  bytes the origin answered from this variant / bytes that saved against the original
#   etag       the validator Caddy's file_server sends for the file (lets media answer 304 for an evicted variant)
#   reason     why a decision row says "orig" (not_beneficial, too_large, failed:<kind> ...)
VARIANT_COLS = (("tier", "TEXT DEFAULT 'ephemeral'"), ("width", "INTEGER"), ("etag", "TEXT"), ("reason", "TEXT"),
                ("hits", "INTEGER DEFAULT 0"), ("score", "REAL DEFAULT 0"), ("score_at", "REAL"),
                ("promoted", "REAL"), ("served", "INTEGER DEFAULT 0"), ("saved", "INTEGER DEFAULT 0"))
TIERS = ("ephemeral", "persistent", "evicted")
JSON_COLS = ("findings", "engines", "detail", "data", "result")
VERDICT_STATES = ("pending", "clean", "flagged", "held", "released", "error", "skipped")
SEVERITY = {"low": 1, "medium": 2, "high": 3}
BACKOFF = (60, 600, 3600)          # retry delays after the 1st, 2nd, 3rd+ failed attempt
NO_RETRY = {"tool_missing"}        # no point retrying until the tools change (retry_failed / force requeue)
FAILED_REQUEUE_S = 3600            # an unchanged failed job is requeued by enqueue() at most this often


def _mid(mount):
    return None if mount is None or mount == "" else int(mount)


def _mid_or_none(mount):
    try:
        return _mid(mount)
    except (TypeError, ValueError):
        return None


def _j(v):
    return None if v is None else json.dumps(v, separators=(",", ":"), default=str)


def _row(r):
    if r is None:
        return None
    d = dict(r)
    for k in JSON_COLS:
        v = d.get(k)
        if isinstance(v, str) and v:
            try:
                d[k] = json.loads(v)
            except ValueError:
                pass
    return d


def _rows(cur):
    return [_row(r) for r in cur.fetchall()]


def _params(p):
    """Job params are part of the dedupe key: dicts are encoded canonically, None means ''."""
    if p is None:
        return ""
    if isinstance(p, str):
        return p
    return json.dumps(p, sort_keys=True, separators=(",", ":"))


def _under(col, path):
    """SQL + args matching `path` itself and everything below it (folder renames)."""
    base = path.rstrip("/")
    return "(%s=? OR substr(%s, 1, ?)=?)" % (col, col), (path, len(base) + 1, base + "/")


class Store:
    def __init__(self, path, readonly=False):
        self.path = os.path.abspath(path)
        self.readonly = readonly
        self.clock = time.time
        self._local = threading.local()
        if not readonly:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)

    # ------------------------------------------------------------ connections
    def _db(self):
        db = getattr(self._local, "db", None)
        if db is None:
            if self.readonly:
                uri = "file:" + urllib.parse.quote(self.path.replace("\\", "/"), safe="/:") + "?mode=ro"
                db = sqlite3.connect(uri, uri=True, timeout=15, isolation_level=None)
            else:
                db = sqlite3.connect(self.path, timeout=15, isolation_level=None)
            db.execute("PRAGMA busy_timeout=15000")
            if not self.readonly:
                db.execute("PRAGMA journal_mode=WAL")
                db.execute("PRAGMA synchronous=NORMAL")
            db.row_factory = sqlite3.Row
            self._local.db = db
        return db

    @contextlib.contextmanager
    def _tx(self):
        db = self._db()
        db.execute("BEGIN IMMEDIATE")
        try:
            yield db
        except BaseException:
            db.execute("ROLLBACK")
            raise
        db.execute("COMMIT")

    def close(self):
        """Close this thread's connection (threads that exit drop theirs automatically)."""
        db = getattr(self._local, "db", None)
        if db is not None:
            self._local.db = None
            db.close()

    def init(self):
        db = self._db()
        db.executescript(SCHEMA)
        have = {r[1] for r in db.execute("PRAGMA table_info(variant)")}
        for name, decl in VARIANT_COLS:
            if name not in have:
                try:
                    db.execute("ALTER TABLE variant ADD COLUMN %s %s" % (name, decl))
                except sqlite3.OperationalError as e:   # another process added it first
                    if "duplicate column" not in str(e).lower():
                        raise
        db.execute("CREATE INDEX IF NOT EXISTS variant_tier ON variant(tier, last_used)")
        return self

    # ------------------------------------------------------------ verdicts
    def verdict(self, mount, path):
        return _row(self._db().execute("SELECT * FROM verdict WHERE mount=? AND path=?",
                                        (_mid(mount), path)).fetchone())

    def verdicts_since(self, ts):
        """Rows with updated > ts, oldest first. Timestamps come from several processes: callers polling with
        the newest `updated` they saw should pass it minus a few seconds (rows are idempotent to re-apply)."""
        return _rows(self._db().execute("SELECT * FROM verdict WHERE updated > ? ORDER BY updated", (ts or 0,)))

    def verdict_by_hash(self, size, qhash):
        """The most severe verdict of any file with this size + quick hash (renamed copies inherit a hold)."""
        if not qhash or size is None:
            return None
        return _row(self._db().execute(
            "SELECT * FROM verdict WHERE size=? AND qhash=? ORDER BY "
            "CASE state WHEN 'held' THEN 0 WHEN 'flagged' THEN 0 WHEN 'error' THEN 1 WHEN 'pending' THEN 3 "
            "ELSE 2 END, CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END, "
            "updated DESC LIMIT 1", (int(size), qhash)).fetchone())

    def set_verdict(self, mount, path, *, size, mtime, state, qhash=None, severity="", findings=None,
                    engines=None, legacy=0, scanned=None):
        """Upsert a scan result. Admin review (reviewed_by / review_note) survives a re-scan of the same content
        (size, mtime and - when both known - quick hash): an admin hold stays held, and a release stays released
        unless the new scan is flagged with a higher severity than what was released. New content or a reset
        to pending drops the review."""
        if state not in VERDICT_STATES:
            raise ValueError("bad verdict state %r" % state)
        m, now = _mid(mount), self.clock()
        if scanned is None and state != "pending":
            scanned = now
        with self._tx() as db:
            old = db.execute("SELECT * FROM verdict WHERE mount=? AND path=?", (m, path)).fetchone()
            by = note = None
            if old is not None:
                same = (old["size"] == size and old["mtime"] == mtime
                        and (qhash is None or old["qhash"] is None or old["qhash"] == qhash))
                if same:
                    qhash = qhash or old["qhash"]
                    if old["reviewed_by"] is not None and state != "pending":
                        by, note = old["reviewed_by"], old["review_note"]
                        if old["state"] == "held":
                            state = "held"
                        elif old["state"] == "released" and not (
                                state == "flagged" and SEVERITY.get(severity, 0) > SEVERITY.get(old["severity"], 0)):
                            state, severity = "released", severity or old["severity"]
                if scanned is None:
                    scanned = old["scanned"]
            db.execute("INSERT OR REPLACE INTO verdict(mount, path, size, mtime, qhash, state, severity, findings, "
                       "engines, scanned, updated, legacy, reviewed_by, review_note) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (m, path, size, mtime, qhash, state, severity or "", _j(findings), _j(engines), scanned, now,
                        int(bool(legacy)), by, note))

    def review(self, mount, path, state, user, note=""):
        if state not in ("released", "held"):
            raise ValueError("review state must be released or held")
        cur = self._db().execute("UPDATE verdict SET state=?, reviewed_by=?, review_note=?, updated=? "
                                 "WHERE mount=? AND path=?", (state, user or "admin", note or "", self.clock(),
                                                               _mid(mount), path))
        return cur.rowcount > 0

    def move_verdict(self, mount, old, new):
        """File or folder rename: verdicts (and variant rows / queued jobs) follow the new path."""
        o, n = (old or "").rstrip("/"), (new or "").rstrip("/")
        if not o or not n or o == n:
            return
        m, now = _mid(mount), self.clock()
        where, args = _under("path", o)
        with self._tx() as db:
            for (p,) in db.execute("SELECT path FROM verdict WHERE mount=? AND " + where, (m, *args)).fetchall():
                np = n + p[len(o):]
                db.execute("DELETE FROM verdict WHERE mount=? AND path=?", (m, np))
                db.execute("UPDATE verdict SET path=?, updated=? WHERE mount=? AND path=?", (np, now, m, p))
            # variant keys embed the old path, so these rows only matter for drop_variants() of the new path
            db.execute("UPDATE variant SET path=? || substr(path, ?) WHERE mount=? AND " + where,
                       (n, len(o) + 1, m, *args))
            db.execute("UPDATE OR IGNORE job SET path=? || substr(path, ?) WHERE state='queued' AND mount=? AND "
                       + where, (n, len(o) + 1, m, *args))
            db.execute("DELETE FROM job WHERE state='queued' AND mount=? AND " + where, (m, *args))

    def drop_verdict(self, mount, path):
        self._db().execute("DELETE FROM verdict WHERE mount=? AND path=?", (_mid(mount), path))

    def list_verdicts(self, states=None, limit=500, offset=0, q=None):
        if isinstance(states, str):
            states = [s for s in states.split(",") if s.strip()]
        sql, args = "SELECT * FROM verdict WHERE 1=1", []
        if states:
            sql += " AND state IN (%s)" % ",".join("?" * len(states))
            args += [s.strip() for s in states]
        if q:
            sql += " AND path LIKE ? ESCAPE '\\'"
            args.append("%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
        sql += " ORDER BY updated DESC LIMIT ? OFFSET ?"
        return _rows(self._db().execute(sql, (*args, int(limit), int(offset))))

    def verdict_counts(self):
        return dict(self._db().execute("SELECT state, count(*) FROM verdict GROUP BY state").fetchall())

    # ------------------------------------------------------------ jobs
    def enqueue(self, kind, mount, path, *, size=None, mtime=None, params="", priority=50, not_before=0,
                force=False):
        """Queue a job; returns its id, or None when nothing was queued.

        Dedupe on (kind, mount, path, params): a queued/running job only gets its priority number lowered (and,
        with force, a queued job loses its retry backoff); a done job for the same size+mtime is left alone unless
        force; failed/cancelled/done-but-changed jobs are requeued (an unchanged failed job at most once per
        FAILED_REQUEUE_S, never after a NO_RETRY kind of error, unless force)."""
        m, params, now = _mid(mount), _params(params), self.clock()
        with self._tx() as db:
            row = db.execute("SELECT * FROM job WHERE kind=? AND mount IS ? AND path IS ? AND params=?",
                             (kind, m, path, params)).fetchone()
            if row is None:
                cur = db.execute("INSERT INTO job(kind, mount, path, params, size, mtime, priority, state, attempts, "
                                 "not_before, created) VALUES(?,?,?,?,?,?,?,'queued',0,?,?)",
                                 (kind, m, path, params, size, mtime, int(priority), not_before or 0, now))
                return cur.lastrowid
            jid, state = row["id"], row["state"]
            same = row["size"] == size and row["mtime"] == mtime
            if state in ("queued", "running"):
                db.execute("UPDATE job SET priority=min(priority, ?) WHERE id=?", (int(priority), jid))
                if state == "queued" and (size is not None or mtime is not None):
                    db.execute("UPDATE job SET size=?, mtime=? WHERE id=?", (size, mtime, jid))
                if state == "queued" and force:      # admin "rescan now": skip any retry backoff
                    db.execute("UPDATE job SET not_before=? WHERE id=?", (not_before or 0, jid))
                return jid
            if not force and same:
                if state == "done":
                    return None
                if state == "failed":
                    if row["error_kind"] in NO_RETRY:
                        return None
                    not_before = max(not_before or 0, (row["finished"] or 0) + FAILED_REQUEUE_S)
            db.execute("UPDATE job SET state='queued', priority=?, size=?, mtime=?, attempts=0, not_before=?, "
                       "lease_until=NULL, worker=NULL, started=NULL, finished=NULL, error=NULL, error_kind=NULL, "
                       "result=NULL, created=? WHERE id=?", (int(priority), size, mtime, not_before or 0, now, jid))
            return jid

    def claim(self, worker, kinds, lease_s=900):
        """Atomically take the most urgent runnable job of one of `kinds` (attempts counts claims, so a file that
        crashes the worker is not retried forever - see requeue_expired)."""
        kinds = [kinds] if isinstance(kinds, str) else list(kinds or ())
        if not kinds:
            return None
        now = self.clock()
        with self._tx() as db:
            row = db.execute("SELECT id FROM job WHERE state='queued' AND kind IN (%s) AND not_before <= ? "
                             "ORDER BY priority, created, id LIMIT 1" % ",".join("?" * len(kinds)),
                             (*kinds, now)).fetchone()
            if row is None:
                return None
            db.execute("UPDATE job SET state='running', worker=?, lease_until=?, started=?, attempts=attempts+1 "
                       "WHERE id=?", (worker, now + lease_s, now, row["id"]))
            return _row(db.execute("SELECT * FROM job WHERE id=?", (row["id"],)).fetchone())

    def heartbeat(self, job_id, lease_s=900):
        """Extend the lease. Returns False when the job is no longer running (cancelled or re-leased)."""
        cur = self._db().execute("UPDATE job SET lease_until=? WHERE id=? AND state='running'",
                                 (self.clock() + lease_s, job_id))
        return cur.rowcount > 0

    def finish(self, job_id, result=None):
        cur = self._db().execute("UPDATE job SET state='done', finished=?, lease_until=NULL, result=?, error=NULL, "
                                 "error_kind=NULL WHERE id=? AND state='running'", (self.clock(), _j(result), job_id))
        return cur.rowcount > 0

    def fail(self, job_id, error, error_kind, retry_in=None, max_attempts=3):
        """Record a failed attempt: requeue with backoff (60 s, 10 min, 1 h) or give up after max_attempts
        claims. Returns the new state ("queued" | "failed"), or the unchanged state if the job was not running."""
        now = self.clock()
        with self._tx() as db:
            row = db.execute("SELECT state, attempts FROM job WHERE id=?", (job_id,)).fetchone()
            if row is None:
                return "missing"
            if row["state"] != "running":
                return row["state"]
            attempts = max(1, row["attempts"] or 0)
            err = str(error or "")[:2000]
            if error_kind in NO_RETRY or attempts >= max_attempts:
                db.execute("UPDATE job SET state='failed', finished=?, lease_until=NULL, error=?, error_kind=? "
                           "WHERE id=?", (now, err, error_kind, job_id))
                return "failed"
            delay = retry_in if retry_in is not None else BACKOFF[min(attempts, len(BACKOFF)) - 1]
            db.execute("UPDATE job SET state='queued', not_before=?, lease_until=NULL, worker=NULL, error=?, "
                       "error_kind=? WHERE id=?", (now + delay, err, error_kind, job_id))
            return "queued"

    def requeue_expired(self, max_attempts=3):
        """Running jobs whose lease ran out (worker crashed or hung): requeue, or fail after max_attempts."""
        now = self.clock()
        with self._tx() as db:
            rows = db.execute("SELECT id, attempts FROM job WHERE state='running' AND lease_until < ?",
                              (now,)).fetchall()
            for r in rows:
                if (r["attempts"] or 0) >= max_attempts:
                    db.execute("UPDATE job SET state='failed', finished=?, lease_until=NULL, error=?, "
                               "error_kind='lease_expired' WHERE id=?", (now, "lease expired (worker died?)", r["id"]))
                else:
                    db.execute("UPDATE job SET state='queued', lease_until=NULL, worker=NULL, "
                               "error_kind='lease_expired' WHERE id=?", (r["id"],))
            return len(rows)

    def cancel(self, kind, mount, path):
        """Drop jobs for a file (kind None = every kind). Running ones are marked cancelled; the worker's
        heartbeat()/finish() then return False."""
        where, args = " WHERE mount IS ? AND path=?", [_mid(mount), path]
        if kind:
            where += " AND kind=?"
            args.append(kind)
        with self._tx() as db:
            n = db.execute("UPDATE job SET state='cancelled', finished=?, lease_until=NULL" + where
                           + " AND state='running'", (self.clock(), *args)).rowcount
            n += db.execute("DELETE FROM job" + where + " AND state NOT IN ('running', 'cancelled')", args).rowcount
            return n

    def job_counts(self):
        out = {}
        for kind, state, n in self._db().execute("SELECT kind, state, count(*) FROM job GROUP BY kind, state"):
            out.setdefault(kind, {})[state] = n
        return out

    def oldest_queued_age(self, kind=None):
        sql, args = "SELECT min(created) FROM job WHERE state='queued'", ()
        if kind:
            sql, args = sql + " AND kind=?", (kind,)
        t = self._db().execute(sql, args).fetchone()[0]
        return None if t is None else max(0.0, self.clock() - t)

    def jobs(self, state=None, kind=None, limit=200):
        sql, args = "SELECT * FROM job WHERE 1=1", []
        if state:
            sql += " AND state=?"
            args.append(state)
        if kind:
            sql += " AND kind=?"
            args.append(kind)
        if state in ("done", "failed", "cancelled"):
            sql += " ORDER BY finished DESC"
        else:
            sql += " ORDER BY state='running' DESC, priority, created"
        return _rows(self._db().execute(sql + " LIMIT ?", (*args, int(limit))))

    def retry_failed(self, kind=None):
        sql, args = ("UPDATE job SET state='queued', attempts=0, not_before=0, lease_until=NULL, worker=NULL, "
                     "finished=NULL, error=NULL, error_kind=NULL WHERE state='failed'"), ()
        if kind:
            sql, args = sql + " AND kind=?", (kind,)
        return self._db().execute(sql, args).rowcount

    # ------------------------------------------------------------ variants
    def variant(self, key):
        return _row(self._db().execute("SELECT * FROM variant WHERE key=?", (key,)).fetchone())

    def put_variant(self, key, *, mount, path, src_size, src_mtime, kind, fmt, spec, file, bytes, src_bytes, secs,
                    beneficial, tier="ephemeral", width=None, etag=None, reason=None):
        """Insert or replace a variant decision/file. An upsert, not INSERT OR REPLACE: a re-encode of an evicted
        variant keeps its hotness (hits, score, served, saved), so popularity survives eviction."""
        now = self.clock()
        tier = tier if tier in TIERS else "ephemeral"
        self._db().execute(
            "INSERT INTO variant(key, mount, path, src_size, src_mtime, kind, fmt, spec, file, bytes, src_bytes, secs, "
            "beneficial, created, last_used, tier, width, etag, reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET mount=excluded.mount, path=excluded.path, src_size=excluded.src_size, "
            "src_mtime=excluded.src_mtime, kind=excluded.kind, fmt=excluded.fmt, spec=excluded.spec, "
            "file=excluded.file, bytes=excluded.bytes, src_bytes=excluded.src_bytes, secs=excluded.secs, "
            "beneficial=excluded.beneficial, created=excluded.created, last_used=excluded.last_used, "
            "tier=excluded.tier, width=excluded.width, etag=excluded.etag, reason=excluded.reason",
            (key, _mid(mount), path, src_size, src_mtime, kind, fmt, spec, file, bytes, src_bytes, secs,
             int(bool(beneficial)), now, now, tier, width, etag, reason))

    def touch_variants(self, keys):
        keys = list(dict.fromkeys(k for k in keys or () if k))
        if not keys:
            return
        now = self.clock()
        with self._tx() as db:
            db.executemany("UPDATE variant SET last_used=? WHERE key=?", [(now, k) for k in keys])

    def add_hits(self, counts, half_life_s):
        """Fold origin requests into the hotness columns: {key: (requests, served bytes, saved bytes)}.
        score is an exponentially decayed request count, so score * ln2 / half_life is a request rate."""
        if not counts:
            return 0
        now, hl = self.clock(), max(60.0, float(half_life_s))
        keys = list(counts)
        n = 0
        with self._tx() as db:
            for i in range(0, len(keys), 500):
                part = keys[i:i + 500]
                rows = db.execute("SELECT key, score, score_at FROM variant WHERE key IN (%s)" % ",".join("?" * len(part)),
                                  part).fetchall()
                for r in rows:
                    req, served, saved = counts[r["key"]]
                    age = max(0.0, now - (r["score_at"] or now))
                    score = (r["score"] or 0.0) * 0.5 ** (age / hl) + req
                    db.execute("UPDATE variant SET hits=coalesce(hits, 0)+?, score=?, score_at=?, last_used=?, "
                               "served=coalesce(served, 0)+?, saved=coalesce(saved, 0)+? WHERE key=?",
                               (int(req), score, now, now, int(served), int(saved), r["key"]))
                    n += 1
        return n

    @staticmethod
    def decayed(row, now, half_life_s):
        """A row's score decayed to `now` (rows are only rewritten when they get hits)."""
        age = max(0.0, now - (row.get("score_at") or now))
        return (row.get("score") or 0.0) * 0.5 ** (age / max(60.0, float(half_life_s)))

    def set_tier(self, key, tier, file=None, promoted=None):
        """Move a variant between tiers (file = its new rel_url; None keeps it, '' clears it)."""
        if tier not in TIERS:
            raise ValueError("bad tier %r" % tier)
        sets, args = ["tier=?"], [tier]
        if file is not None:
            sets.append("file=?")
            args.append(file or None)
        if promoted is not None:
            sets.append("promoted=?")
            args.append(promoted)
        cur = self._db().execute("UPDATE variant SET %s WHERE key=?" % ", ".join(sets), (*args, key))
        return cur.rowcount > 0

    def evict_variant(self, key):
        """The cache file is gone; keep the row as a tombstone (hotness, ETag, decision) - see prune_variants."""
        cur = self._db().execute("UPDATE variant SET tier='evicted', file=NULL WHERE key=?", (key,))
        return cur.rowcount > 0

    def variants_in_tier(self, tier, limit=100000, min_hits=0):
        return _rows(self._db().execute(
            "SELECT * FROM variant WHERE tier=? AND beneficial=1 AND coalesce(hits, 0) >= ? ORDER BY last_used LIMIT ?",
            (tier, int(min_hits), int(limit))))

    def stale_ephemeral(self, before, limit=500):
        """Ephemeral variants with a file not used since `before` (age-based eviction)."""
        return _rows(self._db().execute(
            "SELECT * FROM variant WHERE tier='ephemeral' AND beneficial=1 AND file IS NOT NULL AND file != '' "
            "AND last_used < ? ORDER BY last_used LIMIT ?", (before, int(limit))))

    def prune_variants(self, tombstone_before, failure_before):
        """Forget tombstones nobody asked for since tombstone_before, and failure decisions older than
        failure_before (so a file that once broke the encoder is retried eventually, never in a hot loop)."""
        with self._tx() as db:
            a = db.execute("DELETE FROM variant WHERE tier='evicted' AND last_used < ?", (tombstone_before,)).rowcount
            b = db.execute("DELETE FROM variant WHERE beneficial=0 AND reason LIKE 'failed:%' AND created < ?",
                           (failure_before,)).rowcount
        return {"tombstones": a, "failures": b}

    def variants_for(self, mount, path):
        return _rows(self._db().execute("SELECT * FROM variant WHERE mount=? AND path=?", (_mid(mount), path)))

    def drop_variants(self, mount, path):
        with self._tx() as db:
            rows = _rows(db.execute("SELECT * FROM variant WHERE mount=? AND path=?", (_mid(mount), path)))
            db.execute("DELETE FROM variant WHERE mount=? AND path=?", (_mid(mount), path))
        return rows

    def variant_sources(self):
        """[(mount, path, src_size, src_mtime, key, file)] of every variant row (bridge: source deleted / changed)."""
        return [tuple(r) for r in self._db().execute(
            "SELECT mount, path, src_size, src_mtime, key, file FROM variant WHERE path IS NOT NULL")]

    def drop_variant_keys(self, keys):
        """Delete these rows; returns them (with their file) so the caller can delete the files."""
        keys = list(keys)
        out = []
        with self._tx() as db:
            for i in range(0, len(keys), 500):
                part = keys[i:i + 500]
                q = ",".join("?" * len(part))
                out += _rows(db.execute("SELECT * FROM variant WHERE key IN (%s)" % q, part))
                db.execute("DELETE FROM variant WHERE key IN (%s)" % q, part)
        return out

    def drop_variant(self, key):
        """Delete one variant row (cache eviction). Returns the row or None."""
        with self._tx() as db:
            row = _row(db.execute("SELECT * FROM variant WHERE key=?", (key,)).fetchone())
            db.execute("DELETE FROM variant WHERE key=?", (key,))
        return row

    def lru_variants(self, limit=500, with_file=True):
        """Least recently used variants first. with_file: only rows that own a cache file (beneficial ones);
        not-beneficial rows are tiny decisions worth keeping and free no disk when dropped."""
        where = (" WHERE beneficial=1 AND file IS NOT NULL AND file != '' AND coalesce(tier, 'ephemeral')='ephemeral'"
                 if with_file else "")   # persistent variants are never LRU-evicted (only demoted, see media.py)
        return _rows(self._db().execute("SELECT * FROM variant%s ORDER BY last_used, created LIMIT ?" % where,
                                        (int(limit),)))

    def variant_totals(self):
        n, good, b, sb = self._db().execute(
            "SELECT count(*), coalesce(sum(beneficial=1), 0), coalesce(sum(CASE WHEN beneficial=1 THEN bytes END), 0), "
            "coalesce(sum(CASE WHEN beneficial=1 THEN src_bytes END), 0) FROM variant").fetchone()
        out = {"count": n, "beneficial": good, "bytes": b, "src_bytes": sb, "saved": max(0, sb - b), "tiers": {}}
        for tier, cnt, nbytes, hits, served, saved in self._db().execute(
                "SELECT coalesce(tier, 'ephemeral'), count(*), coalesce(sum(CASE WHEN file IS NOT NULL THEN bytes END), 0), "
                "coalesce(sum(hits), 0), coalesce(sum(served), 0), coalesce(sum(saved), 0) FROM variant "
                "WHERE beneficial=1 GROUP BY 1"):
            out["tiers"][tier] = {"count": cnt, "bytes": nbytes, "hits": hits, "served": served, "saved": saved}
        out["served"] = sum(t["served"] for t in out["tiers"].values())
        out["bytes_saved_served"] = sum(t["saved"] for t in out["tiers"].values())
        return out

    # ------------------------------------------------------------ events / samples / meta
    def add_events(self, rows):
        vals = [(r.get("ts") or self.clock(), r.get("proc"), r.get("kind") or "unknown", r.get("severity"),
                 _mid_or_none(r.get("mount")), r.get("path"), _j(r.get("detail") or {})) for r in rows or ()]
        if not vals:
            return
        with self._tx() as db:
            db.executemany("INSERT INTO event(ts, proc, kind, severity, mount, path, detail) VALUES(?,?,?,?,?,?,?)",
                           vals)

    def events(self, since=0, kind=None, limit=200):
        """Newest first. kind "bypass" matches "bypass" and "bypass.*"."""
        sql, args = "SELECT * FROM event WHERE ts > ?", [since or 0]
        if kind:
            sql += " AND (kind=? OR substr(kind, 1, ?)=?)"
            args += [kind, len(kind) + 1, kind + "."]
        return _rows(self._db().execute(sql + " ORDER BY ts DESC, id DESC LIMIT ?", (*args, int(limit))))

    def event_counts(self, since):
        return dict(self._db().execute("SELECT kind, count(*) FROM event WHERE ts > ? GROUP BY kind",
                                       (since or 0,)).fetchall())

    def add_sample(self, ts_minute, proc, data):
        self._db().execute("INSERT OR REPLACE INTO sample(ts, proc, data) VALUES(?,?,?)",
                           (int(ts_minute), proc, _j(data)))

    def samples(self, since, proc=None):
        sql, args = "SELECT * FROM sample WHERE ts >= ?", [int(since or 0)]
        if proc:
            sql += " AND proc=?"
            args.append(proc)
        return _rows(self._db().execute(sql + " ORDER BY ts", args))

    def get_meta(self, k, default=None):
        r = self._db().execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        if r is None or r[0] is None:
            return default
        try:
            return json.loads(r[0])
        except ValueError:
            return r[0]

    def set_meta(self, k, v):
        self._db().execute("INSERT OR REPLACE INTO meta(k, v) VALUES(?,?)", (k, _j(v)))

    def prune(self, event_days=30, job_days=14, sample_days=30):
        now = self.clock()
        with self._tx() as db:
            db.execute("DELETE FROM event WHERE ts < ?", (now - event_days * 86400,))
            db.execute("DELETE FROM job WHERE state IN ('done', 'failed', 'cancelled') AND coalesce(finished, created) < ?",
                       (now - job_days * 86400,))
            db.execute("DELETE FROM sample WHERE ts < ?", (int(now - sample_days * 86400),))
        try:
            self._db().execute("PRAGMA wal_checkpoint(PASSIVE)")
        except sqlite3.Error:
            pass
