"""The office: colleagues can see each other, leave notes and post on a shared noticeboard; presence dots.

Access model (all checks on the server; strata.py ROUTE_CAPS decides who may call which route):
  * office.view    - the directory (who works here, title, status, presence), the noticeboard and team notes
  * office.post    - write noticeboard posts
  * office.notes   - leave notes on a colleague's profile, visible to the team or private (author + that colleague)
  * office.contact - colleagues' e-mail addresses and last sign-in (anyone may also opt in to show their address)
  * "administrative" accounts (account.administrative = 1, set by root) hold every office capability and moderate:
    pin board posts, remove team-visible posts and notes, and change colleagues' office capabilities and job title.
    Private notes stay private - administrative members cannot read them either.
Nothing here reveals permissions, storage zones, allowed networks, sign-in limits or the root note on an account.
"""
import json
import re
import threading
import time
from collections import deque

import accounts
import core

TITLE_MAX, DEPT_MAX, STATUS_MAX, ABOUT_MAX, BODY_MAX = 60, 60, 80, 600, 2000
POST_BURST, POST_WINDOW = 20, 600          # at most 20 posts / notes per author in 10 minutes
PRESENCE_FRESH = 75                        # seconds a heartbeat keeps someone online / idle (browsers beat every 30 s)
SEEN_PERSIST = 300                         # write account.last_seen at most every 5 minutes per account
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f​-‏‪-‮⁦-⁩]")


def clean(text, limit, multiline=False):
    """Plain text only: control and bidi-override characters out, whitespace tidied, length capped."""
    text = str(text or "")
    if multiline:
        text = "\n".join(_CTRL.sub("", line).rstrip() for line in text.replace("\r\n", "\n").split("\n"))
        text = re.sub(r"\n{3,}", "\n\n", text).strip()
    else:
        text = re.sub(r"\s+", " ", _CTRL.sub("", text)).strip()
    return text[:limit]


# ---------------------------------------------------------------- profiles

PROFILE_KEYS = ("title", "department", "status", "about", "show_email")


def profile_of(a):
    try:
        p = json.loads((a or {}).get("profile") or "{}")
    except (TypeError, ValueError):
        p = {}
    return {"title": str(p.get("title") or ""), "department": str(p.get("department") or ""),
            "status": str(p.get("status") or ""), "about": str(p.get("about") or ""),
            "show_email": bool(p.get("show_email"))}


def save_profile(user, fields, own=True):
    """Own profile: every field. A colleague's (administrative members): job title and department only."""
    a = accounts.get(user)
    if not a:
        raise ValueError("Account not found")
    p = profile_of(a)
    limits = {"title": TITLE_MAX, "department": DEPT_MAX, "status": STATUS_MAX, "about": ABOUT_MAX}
    for k, limit in limits.items():
        if k in fields and (own or k in ("title", "department")):
            p[k] = clean(fields[k], limit, multiline=(k == "about"))
    if own and "show_email" in fields:
        p["show_email"] = bool(fields["show_email"])
    db = core.connect()
    try:
        with db:
            db.execute("UPDATE account SET profile=? WHERE user=? COLLATE NOCASE", (json.dumps(p), user))
    finally:
        db.close()
    return p


# ---------------------------------------------------------------- presence

class Presence:
    """Who has a dashboard open right now. Browsers send a heartbeat every 30 s with 'active' (input in the last
    5 minutes and the tab visible) or 'idle'. Several tabs: the most present one wins. Memory only, plus a coarse
    account.last_seen for the 'last seen' line after a restart."""

    def __init__(self):
        self.lock = threading.Lock()
        self.tabs = {}      # user (lower) -> {tab: (ts, state)}
        self.names = {}     # user (lower) -> spelling as stored
        self.persisted = {}

    def beat(self, user, tab, state):
        if not user or user.startswith("api:"):
            return
        state = "idle" if state == "idle" else "active"
        tab = re.sub(r"[^A-Za-z0-9_-]", "", str(tab or ""))[:32] or "tab"
        now = time.time()
        key = user.lower()
        with self.lock:
            t = self.tabs.setdefault(key, {})
            t[tab] = (now, state)
            for k in [k for k, (ts, _) in t.items() if now - ts > PRESENCE_FRESH]:
                del t[k]
            while len(t) > 20:
                del t[min(t, key=lambda k: t[k][0])]
            self.names[key] = user
            write = now - self.persisted.get(key, 0) > SEEN_PERSIST
            if write:
                self.persisted[key] = now
        if write:
            db = core.connect()
            try:
                with db:
                    db.execute("UPDATE account SET last_seen=? WHERE user=? COLLATE NOCASE", (now, user))
            finally:
                db.close()

    def leave(self, user, tab):
        with self.lock:
            (self.tabs.get(str(user).lower()) or {}).pop(str(tab or ""), None)

    def drop_user(self, user):
        with self.lock:
            self.tabs.pop(str(user).lower(), None)

    def state(self, user):
        now = time.time()
        with self.lock:
            live = [s for ts, s in (self.tabs.get(str(user).lower()) or {}).values() if now - ts <= PRESENCE_FRESH]
            last = max((ts for ts, _ in (self.tabs.get(str(user).lower()) or {}).values()), default=None)
        if "active" in live:
            return "online", last
        if live:
            return "idle", last
        return "offline", last


PRESENCE = Presence()


def presence_map(rows):
    """{user: {"s": online|idle|offline, "seen": ts}} for the given account rows."""
    out = {}
    for a in rows:
        s, last = PRESENCE.state(a["user"])
        out[a["user"]] = {"s": s, "seen": last or a.get("last_seen") or a.get("last_login")}
    return out


# ---------------------------------------------------------------- directory

def _members():
    """Accounts that show up in the office: enabled, activated, access period not over."""
    db = core.connect()
    try:
        rows = core.rows_of(db.execute("SELECT * FROM account WHERE enabled=1 AND password_hash!='' "
                                       "ORDER BY CASE role WHEN 'root' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, user"))
    finally:
        db.close()
    now = time.time()
    return [accounts._row(a) for a in rows if not (a.get("expires") and a["expires"] < now)]


def role_label(a):
    if a.get("role") == "root":
        return "Owner"
    if a.get("role") == "admin":
        return "Administrator"
    return "Team member"


def can_contact(viewer):
    return "office.contact" in accounts.capabilities(viewer)


def people(viewer):
    """The directory as `viewer` (an account row) may see it."""
    contact = can_contact(viewer)
    admin_view = accounts.is_administrative(viewer)
    rows = _members()
    pres = presence_map(rows)
    out = []
    for a in rows:
        p = profile_of(a)
        self_row = a["user"].lower() == viewer["user"].lower()
        item = {"user": a["user"], "avatar": (a.get("avatar") or "")[:8], "role": role_label(a),
                "administrative": accounts.is_administrative(a), "title": p["title"], "department": p["department"],
                "status": p["status"], "about": p["about"], "presence": pres[a["user"]], "self": self_row}
        if contact or p["show_email"] or self_row:
            item["email"] = a.get("email") or ""
        if contact or self_row:
            item["last_login"] = a.get("last_login")
        if admin_view and a.get("role") not in ("root", "admin") and not self_row:
            # what an administrative member may change here: office capabilities only (never files or system)
            item["office_caps"] = sorted(accounts.capabilities(a) & accounts.OFFICE_CAPS)
            item["manageable"] = not accounts.is_administrative(a) or viewer.get("role") == "root"
        out.append(item)
    return out


def member_names():
    return {a["user"].lower(): a["user"] for a in _members()}


# ---------------------------------------------------------------- noticeboard and notes

_burst = {}
_burst_lock = threading.Lock()


def _rate(author):
    now = time.time()
    with _burst_lock:
        q = _burst.setdefault(author.lower(), deque())
        while q and now - q[0] > POST_WINDOW:
            q.popleft()
        if len(q) >= POST_BURST:
            raise ValueError("You’re posting too fast. Try again in a few minutes.")
        q.append(now)


def _visible_sql(viewer):
    """Rows `viewer` may read: board posts and team notes, plus private notes they wrote or received."""
    return "(private=0 OR author=? COLLATE NOCASE OR target=? COLLATE NOCASE)", [viewer, viewer]


def _note_out(r, viewer_acct, names):
    me = viewer_acct["user"].lower()
    mod = accounts.is_administrative(viewer_acct)
    mine = r["author"].lower() == me
    on_mine = bool(r["target"]) and r["target"].lower() == me
    return {"id": r["id"], "ts": r["ts"], "author": names.get(r["author"].lower(), r["author"]),
            "author_gone": r["author"].lower() not in names, "target": r["target"], "body": r["body"],
            "private": bool(r["private"]), "pinned": bool(r["pinned"]), "edited": r["edited"],
            "can_edit": mine, "can_delete": mine or on_mine or (mod and not r["private"]),
            "can_pin": mod and not r["target"]}


def board(viewer_acct, before=None, limit=50):
    names = member_names()
    db = core.connect()
    try:
        pinned = core.rows_of(db.execute("SELECT * FROM office_note WHERE target='' AND pinned=1 ORDER BY ts DESC LIMIT 20")) \
            if before is None else []
        q = "SELECT * FROM office_note WHERE target='' AND pinned=0"
        args = []
        if before:
            q += " AND ts<?"
            args.append(float(before))
        rows = core.rows_of(db.execute(q + " ORDER BY ts DESC LIMIT ?", args + [int(limit) + 1]))
    finally:
        db.close()
    more = len(rows) > limit
    rows = rows[:limit]
    return {"pinned": [_note_out(r, viewer_acct, names) for r in pinned],
            "posts": [_note_out(r, viewer_acct, names) for r in rows],
            "next": rows[-1]["ts"] if more and rows else None}


def notes_for(viewer_acct, target, limit=100):
    if not target or target.lower() not in member_names():
        raise ValueError("No such person")
    names = member_names()
    cond, args = _visible_sql(viewer_acct["user"])
    db = core.connect()
    try:
        rows = core.rows_of(db.execute("SELECT * FROM office_note WHERE target=? COLLATE NOCASE AND " + cond +
                                       " ORDER BY ts DESC LIMIT ?", [target] + args + [int(limit)]))
    finally:
        db.close()
    return {"user": names[target.lower()], "notes": [_note_out(r, viewer_acct, names) for r in rows]}


def create(author_acct, body, target="", private=False):
    author = author_acct["user"]
    body = clean(body, BODY_MAX, multiline=True)
    if not body:
        raise ValueError("Write something first")
    target = str(target or "").strip()
    if target:
        names = member_names()
        if target.lower() not in names:
            raise ValueError("No such person")
        target = names[target.lower()]
    else:
        private = False  # the noticeboard is always for everyone
    _rate(author)
    db = core.connect()
    try:
        with db:
            cur = db.execute("INSERT INTO office_note(ts,author,target,body,private,pinned) VALUES(?,?,?,?,?,0)",
                             (time.time(), author, target, body, int(bool(private))))
            nid = cur.lastrowid
        row = core.rows_of(db.execute("SELECT * FROM office_note WHERE id=?", [nid]))[0]
    finally:
        db.close()
    return _note_out(row, author_acct, member_names())


def _get(nid):
    db = core.connect()
    try:
        rows = core.rows_of(db.execute("SELECT * FROM office_note WHERE id=?", [int(nid)]))
    finally:
        db.close()
    if not rows:
        raise LookupError("That post no longer exists")
    return rows[0]


def edit(viewer_acct, nid, body):
    r = _get(nid)
    if r["author"].lower() != viewer_acct["user"].lower():
        raise PermissionError("Only the author can edit this")
    body = clean(body, BODY_MAX, multiline=True)
    if not body:
        raise ValueError("Write something first")
    db = core.connect()
    try:
        with db:
            db.execute("UPDATE office_note SET body=?, edited=? WHERE id=?", (body, time.time(), int(nid)))
    finally:
        db.close()
    return _note_out(_get(nid), viewer_acct, member_names())


def delete(viewer_acct, nid):
    r = _get(nid)
    out = _note_out(r, viewer_acct, member_names())
    if not out["can_delete"]:
        raise PermissionError("You cannot remove this")
    db = core.connect()
    try:
        with db:
            db.execute("DELETE FROM office_note WHERE id=?", [int(nid)])
    finally:
        db.close()
    return r


def pin(viewer_acct, nid, pinned):
    r = _get(nid)
    if r["target"] or not accounts.is_administrative(viewer_acct):
        raise PermissionError("Only moderators can pin posts")
    db = core.connect()
    try:
        with db:
            db.execute("UPDATE office_note SET pinned=? WHERE id=?", (int(bool(pinned)), int(nid)))
    finally:
        db.close()
    return r


def forget_account(user):
    """Account deleted: notes on its profile and its read markers go; what it wrote stays (shown as a former member)."""
    db = core.connect()
    try:
        with db:
            db.execute("DELETE FROM office_note WHERE target=? COLLATE NOCASE", [user])
            db.execute("DELETE FROM office_note WHERE private=1 AND author=? COLLATE NOCASE", [user])
            db.execute("DELETE FROM office_seen WHERE user=? COLLATE NOCASE", [user])
    finally:
        db.close()
    PRESENCE.drop_user(user)


# ---------------------------------------------------------------- unread markers

def mark_seen(user, what):
    if what not in ("board", "notes"):
        raise ValueError("unknown marker")
    db = core.connect()
    try:
        with db:
            db.execute("INSERT INTO office_seen(user,board,notes) VALUES(?,0,0) ON CONFLICT(user) DO NOTHING", [user])
            db.execute("UPDATE office_seen SET %s=? WHERE user=? COLLATE NOCASE" % what, (time.time(), user))
    finally:
        db.close()


def unread(user):
    db = core.connect()
    try:
        row = db.execute("SELECT board,notes FROM office_seen WHERE user=? COLLATE NOCASE", [user]).fetchone()
        b_seen, n_seen = (row or (0, 0))
        board_n = db.execute("SELECT count(*) FROM office_note WHERE target='' AND ts>? AND author!=? COLLATE NOCASE",
                             [b_seen or 0, user]).fetchone()[0]
        notes_n = db.execute("SELECT count(*) FROM office_note WHERE target=? COLLATE NOCASE AND ts>? AND author!=? COLLATE NOCASE",
                             [user, n_seen or 0, user]).fetchone()[0]
    finally:
        db.close()
    return {"board": board_n, "notes": notes_n}


# ---------------------------------------------------------------- office capabilities of colleagues

def set_member_caps(actor_acct, target, caps):
    """Administrative members switch a colleague's office capabilities on or off. Only office.* ids change; every
    other grant on the account stays exactly as root set it."""
    a = accounts.get(target)
    if not a:
        raise ValueError("Account not found")
    if a["user"].lower() == actor_acct["user"].lower():
        raise PermissionError("You can’t change your own team access")
    if a.get("role") in ("root", "admin"):
        raise PermissionError("The owner and administrators always have full team access")
    if accounts.is_administrative(a) and actor_acct.get("role") != "root":
        raise PermissionError("Only the owner can change another moderator")
    wanted = {str(c) for c in (caps or []) if str(c) in accounts.OFFICE_CAPS}
    if wanted and "office.view" not in wanted:
        raise ValueError("The other team permissions need “View the team”")
    kept = [p for p in (a.get("permissions") or []) if p not in accounts.OFFICE_CAPS]
    grants = sorted(set(kept) | wanted)
    db = core.connect()
    try:
        with db:
            db.execute("UPDATE account SET permissions=?,updated=? WHERE user=? COLLATE NOCASE",
                       (json.dumps(grants), time.time(), a["user"]))
    finally:
        db.close()
    return sorted(wanted)
