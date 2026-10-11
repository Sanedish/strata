"""Dashboard accounts, e-mail one-time codes, privacy consent, storage-zone grants, constraints and profile pictures.

Access model (deny by default, all checks on the server):
  * root holds everything. ROOT_ONLY capabilities exist on no other account.
  * admin holds every capability except ROOT_ONLY.
  * employee holds exactly the capabilities granted to it (fine-grained ids below; older coarse ids still expand).
  * file capabilities additionally need a storage zone: effective rights at a path = the account's file capabilities
    intersected with the capabilities of the zone(s) containing that path (union over overlapping zones).
  * account constraints - expiry, allowed IP ranges, maximum session length - apply to every role but root.
"""
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import time

import auth
import core

PRIVACY_VERSION = "2026-10-08-v1"

# (id, label, group, description). Groups drive the editor; ids are what routes check.
PERMISSIONS = [
    ("files.read", "Browse and preview", "files", "List folders, open previews and file details"),
    ("files.download", "Download", "files", "Download originals and ZIP archives"),
    ("files.upload", "Upload", "files", "Upload new files, including fetching a URL onto the drive"),
    ("files.mkdir", "Create folders", "files", "Create new folders"),
    ("files.rename", "Rename", "files", "Rename files and folders"),
    ("files.move", "Move", "files", "Move files and folders (cut and paste)"),
    ("files.copy", "Copy", "files", "Copy files and folders"),
    ("files.edit", "Edit contents", "files", "Edit text files and restore older versions"),
    ("files.delete", "Move to trash", "files", "Delete files and folders into the trash"),
    ("files.restore", "Restore from trash", "files", "Bring trashed files back"),
    ("files.purge", "Delete permanently", "files", "Empty the trash, delete stored versions, purge the CDN cache"),
    ("files.share", "Share", "files", "Create and manage own share links and signed URLs"),
    ("files.analyze", "Analyze storage", "files", "Storage analysis (needs a whole-drive zone)"),
    ("analytics.read", "Traffic statistics", "insight", "Aggregated traffic, content and performance views"),
    ("analytics.visitors", "Visitor details", "insight", "Individual requests: IP addresses, user agents, locations (personal data)"),
    ("alerts.read", "See alerts", "insight", "Open alerts and their history"),
    ("logs.runtime", "Process log", "insight", "Strata's own runtime log"),
    ("logs.access", "Website request log", "insight", "Raw Caddy request log (contains IP addresses)"),
    ("audit.read", "Account activity", "insight", "Every account's activity ledger"),
    ("system.read", "System health", "insight", "Processes, database size and retention"),
    ("serving.read", "View serving setup", "insight", "Drives, rules, blacklist and links (read only)"),
    ("network.read", "View network setup", "insight", "Cloudflare zone, DNS and tunnel (read only)"),
    ("code.read", "Read source code", "insight", "Browse Strata's source in the web IDE (read only)"),
    ("media.read", "View media pipeline", "insight", "Media processing status, holds and jobs"),
    ("alerts.ack", "Acknowledge alerts", "operate", "Mark alerts as handled"),
    ("alerts.config", "Alert rules", "operate", "Alert thresholds, digest and test messages (not the mail sender)"),
    ("security.autoban", "Auto-ban settings", "operate", "Automatic banning of probing clients"),
    ("serving.blacklist", "Blacklist", "operate", "Block and unblock IPs, ranges, countries and agents"),
    ("serving.rules", "Serving rules", "operate", "Create, change and order access / cache / redirect rules"),
    ("serving.links", "All share links", "operate", "Manage every share link, including links to external URLs"),
    ("serving.drives", "Drives", "operate", "Add, change and remove served drives"),
    ("serving.site", "Site settings", "operate", "Site-wide serving options and error pages"),
    ("serving.apply", "Apply and roll back", "operate", "Push serving changes live and roll back to earlier versions"),
    ("cdn.manage", "CDN cache", "operate", "Purge the Cloudflare cache and change edge cache settings"),
    ("network.dns", "DNS records", "operate", "Create, change and delete DNS records"),
    ("network.ingress", "Tunnel routes", "operate", "Change cloudflared ingress rules"),
    ("network.zone", "Zone settings", "operate", "Change Cloudflare zone settings"),
    ("network.tunnel", "Restart tunnel", "operate", "Restart cloudflared"),
    ("network.expose", "Expose services", "operate", "Publish a local service under the domain (DNS + route + drive)"),
    ("system.retention", "Retention", "operate", "Change how long statistics are kept"),
    ("system.optimize", "Database maintenance", "operate", "Optimize and checkpoint the database"),
    ("system.settings", "Dashboard settings", "operate", "Upload, link-abuse and smart-sort defaults"),
    ("system.compression", "Compression runs", "operate", "Start precompression scans"),
    ("media.manage", "Manage media pipeline", "operate", "Change media processing and resolve holds"),
    ("office.view", "View the team", "office", "People, who’s online, the noticeboard and team notes"),
    ("office.post", "Post on the noticeboard", "office", "Write noticeboard posts the whole team reads"),
    ("office.notes", "Leave notes", "office", "Leave public or private notes on people’s profiles"),
    ("office.contact", "See contact details", "office", "E-mail addresses and last sign-in times"),
]
PERMISSION_IDS = {x[0] for x in PERMISSIONS}
FILE_CAPS = {x[0] for x in PERMISSIONS if x[2] == "files"}
OFFICE_CAPS = {x[0] for x in PERMISSIONS if x[2] == "office"}
OFFICE_DEFAULT = ["office.view", "office.post", "office.notes"]  # every new account; office.contact is opt-in
GROUPS = {"files": "Files (inside assigned storage zones)", "insight": "Read access", "operate": "Change things",
          "office": "Team"}
# Capabilities that can create or take over identities, or run code on this machine. They are never stored on an
# account: only the root account (and CLI-issued API keys) holds them, so no grant can lead to privilege escalation.
ROOT_ONLY = {"accounts.manage", "code.write", "mail.manage"}
# Older coarse ids (still valid in stored grants) and what they mean in fine-grained terms.
LEGACY = {
    "files.write": {"files.upload", "files.mkdir", "files.rename", "files.move", "files.copy", "files.edit",
                    "files.delete", "files.restore"},
    "logs.read": {"logs.runtime", "logs.access"},
    "system.manage": {"system.retention", "system.optimize", "system.settings", "system.compression"},
    "serving.manage": {"serving.read", "serving.blacklist", "serving.rules", "serving.links", "serving.drives",
                       "serving.site", "serving.apply", "cdn.manage"},
    "network.manage": {"network.read", "network.dns", "network.ingress", "network.zone", "network.tunnel",
                       "network.expose", "cdn.manage"},
    "security.manage": {"security.autoban", "alerts.config", "alerts.ack", "serving.blacklist"},
    "analytics.read": {"alerts.read"},
    "media.manage": {"media.read"},
}
# A zone without explicit capabilities (older rows) means: read -> look and download, write -> every file capability.
ZONE_READ = {"files.read", "files.download"}


def expand(perms):
    """Stored grants -> the set of fine-grained capability ids they confer (never a ROOT_ONLY one)."""
    out = set()
    for p in perms or []:
        p = str(p)
        if p in PERMISSION_IDS:
            out.add(p)
        out |= LEGACY.get(p, set())
    return out - ROOT_ONLY


PRESETS = {
    "admin": {"id": "admin", "name": "Administrator", "role": "admin",
              "description": "Everything except accounts, code editing and the e-mail sender", "permissions": ["*"]},
    "file_manager": {"id": "file_manager", "name": "File manager", "role": "employee",
                     "description": "Every file action inside the assigned zones",
                     "permissions": sorted(FILE_CAPS)},
    "contributor": {"id": "contributor", "name": "Contributor", "role": "employee",
                    "description": "Add, organise and edit files; cannot delete permanently or share",
                    "permissions": ["files.read", "files.download", "files.upload", "files.mkdir", "files.rename",
                                    "files.move", "files.copy", "files.edit", "files.delete", "files.restore"]},
    "uploader": {"id": "uploader", "name": "Uploader", "role": "employee",
                 "description": "See files and add new ones", "permissions": ["files.read", "files.upload", "files.mkdir"]},
    "read_only": {"id": "read_only", "name": "Read-only", "role": "employee",
                  "description": "Browse and download", "permissions": ["files.read", "files.download"]},
    "analyst": {"id": "analyst", "name": "Analyst", "role": "employee",
                "description": "Read-only statistics and health, no visitor details",
                "permissions": ["analytics.read", "alerts.read", "system.read", "serving.read", "network.read"]},
    "custom": {"id": "custom", "name": "Custom", "role": "employee", "description": "Hand-picked capabilities",
               "permissions": []},
}
for _p in PRESETS.values():  # everyone is part of the office unless an administrative member switches it off
    if _p["role"] == "employee" and _p["id"] != "custom":
        _p["permissions"] = sorted(set(_p["permissions"]) | set(OFFICE_DEFAULT))


def get_preset(role, permissions):
    if role in ("root", "admin") or "*" in (permissions or []):
        return "admin"
    grants = expand(permissions)
    for p_id, p in PRESETS.items():
        if p_id not in ("admin", "custom") and set(p["permissions"]) == grants:
            return p_id
    return "custom"


USER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,59}$")
EMAIL_RE = re.compile(r"^[^\s@]{1,128}@[^\s@.]{1,128}(?:\.[^\s@.]{2,63})+$")


def bootstrap():
    """Import the owner from strata.json (auth.user / auth.password_hash) as the root account, once."""
    username = str(core.CFG.get("auth", {}).get("user") or "").strip()
    password_hash = str(core.CFG.get("auth", {}).get("password_hash") or "")
    if not username or not password_hash:
        return
    db = core.connect()
    try:
        with db:
            row = db.execute("SELECT user FROM account WHERE role='root' LIMIT 1").fetchone()
            if not row:
                now = time.time()
                bootstrap_email = (core.CFG.get("alerts", {}).get("to") or [""])[0]
                db.execute("INSERT OR IGNORE INTO account(user,email,password_hash,role,permissions,enabled,created,updated) "
                           "VALUES(?,?,?,'root','[\"*\"]',1,?,?)", (username, bootstrap_email, password_hash, now, now))
            else:
                db.execute("UPDATE account SET password_hash=?,updated=? WHERE user=? COLLATE NOCASE AND role='root' "
                           "AND password_hash!=?", (password_hash, time.time(), username, password_hash))
    finally:
        db.close()


def _row(a):
    try:
        a["permissions"] = json.loads(a.get("permissions") or "[]")
    except (TypeError, ValueError):
        a["permissions"] = []
    return a


def get(user):
    db = core.connect()
    try:
        row = core.rows_of(db.execute("SELECT * FROM account WHERE user=? COLLATE NOCASE", [user]))
        return _row(row[0]) if row else None
    finally:
        db.close()


def capabilities(a):
    """Fine-grained capability set an account (row from get()) holds right now."""
    if not a:
        return set()
    if a.get("role") == "root":
        return PERMISSION_IDS | ROOT_ONLY
    if a.get("role") == "admin" or "*" in (a.get("permissions") or []):
        return set(PERMISSION_IDS)
    caps = expand(a.get("permissions"))
    if a.get("administrative"):
        caps |= OFFICE_CAPS
    return caps


def is_administrative(a):
    """Administrative members run the office (moderation, colleagues' office access). Root always is; the flag is
    set by root only and grants nothing outside the office."""
    return bool(a) and (a.get("role") == "root" or bool(a.get("administrative")))


def set_administrative(user, flag):
    a = get(user)
    if not a:
        raise ValueError("Account not found")
    if a.get("role") == "root":
        raise ValueError("Root is always administrative")
    db = core.connect()
    try:
        with db:
            db.execute("UPDATE account SET administrative=?,updated=? WHERE user=? COLLATE NOCASE",
                       (int(bool(flag)), time.time(), user))
    finally:
        db.close()


def office_migrate():
    """Once: existing employee accounts join the office (the default for new accounts since 2026-10-10)."""
    db = core.connect()
    try:
        if core.get_meta(db, "office_v1", False):
            return
        with db:
            for user, perms in db.execute("SELECT user, permissions FROM account WHERE role='employee'").fetchall():
                try:
                    p = json.loads(perms or "[]")
                except ValueError:
                    p = []
                if "*" not in p:
                    db.execute("UPDATE account SET permissions=? WHERE user=?",
                               (json.dumps(sorted(set(p) | set(OFFICE_DEFAULT))), user))
            core.set_meta(db, "office_v1", True)
    finally:
        db.close()


# ---------------------------------------------------------------- zones (per-folder file capabilities)

def zone_caps(z):
    """The file capabilities a zone row allows (its own list, else derived from the older read / write access)."""
    raw = z.get("caps")
    if raw:
        try:
            return {c for c in json.loads(raw) if c in FILE_CAPS}
        except (TypeError, ValueError):
            return set()
    return set(FILE_CAPS) if z.get("access") == "write" else set(ZONE_READ)


def zones(user, include_expired=False):
    db = core.connect()
    try:
        rows = core.rows_of(db.execute("SELECT id,user,mount,path,access,caps,expires,created,created_by FROM account_zone "
                                       "WHERE user=? COLLATE NOCASE ORDER BY mount,path", [user]))
    finally:
        db.close()
    now = time.time()
    out = []
    for z in rows:
        z["expired"] = bool(z.get("expires") and z["expires"] < now)
        if z["expired"] and not include_expired:
            continue
        z["caps"] = sorted(zone_caps(z))
        out.append(z)
    return out


def _within(path, prefix):
    path = "/" + "/".join(p for p in str(path or "/").split("/") if p)
    prefix = "/" + "/".join(p for p in str(prefix or "/").split("/") if p)
    return prefix == "/" or path == prefix or path.startswith(prefix + "/")


def file_caps_at(user, mount, path, acct=None, z_list=None):
    """Effective file capabilities of `user` at mount:path - account grants intersected with the containing zones."""
    a = acct or get(user)
    held = capabilities(a) & FILE_CAPS
    if not a or a.get("role") in ("root", "admin"):
        return held
    got = set()
    for z in (zones(user) if z_list is None else z_list):
        if str(z["mount"]) == str(mount) and _within(path, z["path"]):
            got |= set(z["caps"])
    return held & got


def effective_zones(user, acct=None):
    """Zones with the capabilities the account really has inside each (what /api/me sends to the browser)."""
    a = acct or get(user)
    held = capabilities(a) & FILE_CAPS
    return [dict(z, effective=sorted(held & set(z["caps"]))) for z in zones(user)]


# ---------------------------------------------------------------- account constraints

def parse_networks(text):
    """'10.0.0.0/8, 192.168.1.20' -> canonical list; raises ValueError on anything else."""
    nets = []
    for part in re.split(r"[\s,;]+", str(text or "").strip()):
        if part:
            try:
                nets.append(str(ipaddress.ip_network(part, strict=False)))
            except ValueError:
                raise ValueError("not an IP address or range: %s" % part[:60])
    if len(nets) > 50:
        raise ValueError("at most 50 address ranges")
    return nets


def access_problem(a, ip):
    """Why this account may not be used right now from `ip`, or None. Root is exempt (never lock out the owner)."""
    if not a or not a.get("enabled"):
        return "disabled"
    if a.get("role") == "root":
        return None
    if a.get("expires") and a["expires"] < time.time():
        return "expired"
    nets = [n for n in (a.get("allowed_ips") or "").split(",") if n]
    if nets:
        try:
            addr = ipaddress.ip_address(ip)
            if getattr(addr, "ipv4_mapped", None):
                addr = addr.ipv4_mapped
            if not any(addr in ipaddress.ip_network(n, strict=False) for n in nets):
                return "network"
        except ValueError:
            return "network"
    return None


def session_seconds(a, default_hours):
    """Session lifetime for this account: its own limit when it is shorter than the instance default."""
    hours = float(default_hours)
    if a and a.get("role") != "root" and a.get("session_hours"):
        hours = min(hours, float(a["session_hours"]))
    return hours * 3600


def set_constraints(user, expires=None, allowed_ips="", session_hours=None, note=""):
    a = get(user)
    if not a:
        raise ValueError("Account not found")
    if a.get("role") == "root":
        raise ValueError("Root has no constraints - it must always be able to sign in")
    if expires not in (None, ""):
        expires = float(expires)
        if expires < time.time() - 60:
            raise ValueError("The expiry date is in the past - disable the account instead")
    else:
        expires = None
    nets = parse_networks(allowed_ips)
    if session_hours not in (None, ""):
        session_hours = float(session_hours)
        if not 0.25 <= session_hours <= 24 * 90:
            raise ValueError("Session length must be between 15 minutes and 90 days")
    else:
        session_hours = None
    note = str(note or "").strip()[:500]
    db = core.connect()
    try:
        with db:
            db.execute("UPDATE account SET expires=?,allowed_ips=?,session_hours=?,note=?,updated=? WHERE user=? COLLATE NOCASE",
                       (expires, ",".join(nets), session_hours, note, time.time(), user))
    finally:
        db.close()


# ---------------------------------------------------------------- profile pictures and synced preferences

AVATAR_DIR = os.path.join(core.HOME, "data", "avatars")
AVATAR_MAX_BYTES = 8 << 20
AVATAR_SIZE = 256


def avatar_file(a):
    name = str((a or {}).get("avatar") or "")
    if not re.fullmatch(r"[0-9a-f]{32}\.webp", name):
        return None
    p = os.path.join(AVATAR_DIR, name)
    return p if os.path.isfile(p) else None


def set_avatar(user, raw):
    """Store a profile picture. The upload is decoded and re-encoded (square crop, 256 px WebP): nothing of the original
    file - metadata, other embedded content, polyglot tricks - reaches the browser."""
    if not raw or len(raw) > AVATAR_MAX_BYTES:
        raise ValueError("Choose an image up to 8 MB")
    import io
    import warnings
    from PIL import Image, ImageOps
    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        try:
            im = Image.open(io.BytesIO(raw))
            if im.format not in ("PNG", "JPEG", "WEBP", "GIF", "AVIF", "BMP"):
                raise ValueError("Use a PNG, JPEG, WebP, GIF or AVIF image")
            if im.width * im.height > 40_000_000:
                raise ValueError("That image is too large (over 40 megapixels)")
            im.seek(0)
            im = ImageOps.exif_transpose(im)
            im.load()
        except ValueError:
            raise
        except Exception:
            raise ValueError("That file is not a readable image")
    im = im.convert("RGBA" if im.mode in ("RGBA", "LA", "P") else "RGB")
    im = ImageOps.fit(im, (AVATAR_SIZE, AVATAR_SIZE), Image.LANCZOS)
    os.makedirs(AVATAR_DIR, exist_ok=True)
    name = secrets.token_hex(16) + ".webp"
    tmp = os.path.join(AVATAR_DIR, name + ".part")
    im.save(tmp, "WEBP", quality=85, method=4)
    os.replace(tmp, os.path.join(AVATAR_DIR, name))
    old = avatar_file(get(user))
    db = core.connect()
    try:
        with db:
            db.execute("UPDATE account SET avatar=?,updated=? WHERE user=? COLLATE NOCASE", (name, time.time(), user))
    finally:
        db.close()
    if old:
        try:
            os.remove(old)
        except OSError:
            pass
    return name


def clear_avatar(user):
    old = avatar_file(get(user))
    db = core.connect()
    try:
        with db:
            db.execute("UPDATE account SET avatar='',updated=? WHERE user=? COLLATE NOCASE", (time.time(), user))
    finally:
        db.close()
    if old:
        try:
            os.remove(old)
        except OSError:
            pass


def get_prefs(user):
    a = get(user) or {}
    try:
        return json.loads(a.get("prefs") or "{}")
    except ValueError:
        return {}


def set_prefs(user, prefs):
    if not isinstance(prefs, dict):
        raise ValueError("preferences must be an object")
    raw = json.dumps(prefs, separators=(",", ":"))
    if len(raw) > 64 << 10:
        raise ValueError("preferences are too large")
    db = core.connect()
    try:
        with db:
            db.execute("UPDATE account SET prefs=? WHERE user=? COLLATE NOCASE", (raw, user))
    finally:
        db.close()


# ---------------------------------------------------------------- listing

def get_user_home(user, z_list=None):
    """The zone shown as the account's home (its /users/<name> zone, else its first zone); None without zones.
    Display only - access is decided by the zones themselves."""
    z_list = zones(user) if z_list is None else z_list
    own = "/users/%s" % str(user).lower()
    for z in z_list:
        if str(z.get("path") or "").rstrip("/").lower() == own:
            return {"mount": z["mount"], "path": z["path"], "access": z.get("access", "read")}
    if z_list:
        return {"mount": z_list[0]["mount"], "path": z_list[0]["path"], "access": z_list[0].get("access", "read")}
    return None


def public(a):
    user = a.get("user")
    perms = a.get("permissions") or []
    if isinstance(perms, str):
        try:
            perms = json.loads(perms)
        except Exception:
            perms = []
    out = {k: a.get(k) for k in ("user", "email", "role", "enabled", "email_verified", "privacy_version", "privacy_ts",
                                  "created", "updated", "last_login", "expires", "session_hours", "note")}
    out["permissions"] = sorted(expand(perms)) if "*" not in perms else ["*"]
    out["preset"] = get_preset(a.get("role"), perms)
    out["allowed_ips"] = [n for n in (a.get("allowed_ips") or "").split(",") if n]
    out["zones"] = zones(user, include_expired=True)
    out["home"] = get_user_home(user, [z for z in out["zones"] if not z["expired"]])
    out["pending"] = not a.get("password_hash")
    out["expired"] = bool(a.get("expires") and a["expires"] < time.time())
    out["avatar"] = (a.get("avatar") or "")[:8]  # a version tag for the URL; the file name itself stays server-side
    out["administrative"] = is_administrative(a)
    out["last_seen"] = a.get("last_seen")
    return out


def all_accounts():
    db = core.connect()
    try:
        rows = core.rows_of(db.execute("SELECT * FROM account ORDER BY CASE role WHEN 'root' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END,user"))
    finally:
        db.close()
    return [public(_row(a)) for a in rows]


def has(user, capability):
    if str(user).startswith("api:"):
        return True
    a = get(user)
    if not a or not a.get("enabled"):
        return False
    if capability == "account.self":
        return True
    return capability in capabilities(a)


def hmac_code(user, email, code, purpose):
    key = str(core.CFG.get("auth", {}).get("cookie_secret") or "").encode()
    raw = "%s|%s|%s|%s" % (user.lower(), email.lower(), code, purpose)
    return hmac.new(key, raw.encode(), hashlib.sha256).hexdigest()


def send_code(user, email, sender, ip="", purpose="login"):
    if not EMAIL_RE.fullmatch(str(email or "")):
        raise ValueError("Add a valid e-mail address before signing in")
    if not core.CFG.get("alerts", {}).get("resend_api_key") or not core.CFG.get("alerts", {}).get("from"):
        raise ValueError("E-mail OTP is not configured. Ask the root administrator to configure Resend from the local network.")
    code = "%06d" % secrets.randbelow(1000000)
    expiry = time.time() + 600
    db = core.connect()
    try:
        with db:
            db.execute("INSERT INTO account_code(user,email,digest,expires,attempts,purpose) VALUES(?,?,?,?,0,?) "
                       "ON CONFLICT(user) DO UPDATE SET email=excluded.email,digest=excluded.digest,expires=excluded.expires,attempts=0,purpose=excluded.purpose",
                       (user, email, hmac_code(user, email, code, purpose), expiry, purpose))
    finally:
        db.close()
    subject = "Strata sign-in verification code"
    body = "Your Strata verification code is %s. It expires in 10 minutes. If you did not request it, ignore this message." % code
    import html
    html_body = "<p>Your Strata verification code:</p><p style='font:700 28px monospace;letter-spacing:.2em'>%s</p><p>It expires in 10 minutes. If you did not request it, ignore this message.</p>" % html.escape(code)
    # Alerts owns rate limiting and provider details; send only to the account's address.
    if sender is None:
        raise ValueError("E-mail sender is not ready")
    sender.send_to([email], subject, body, html_body)
    core.audit_event(ip, user, "email-otp.send", purpose)
    return expiry


def verify_code(user, code, purpose):
    db = core.connect()
    try:
        row = db.execute("SELECT email,digest,expires,attempts,purpose FROM account_code WHERE user=? COLLATE NOCASE", [user]).fetchone()
        if not row or row[4] != purpose or row[2] < time.time() or row[3] >= 5:
            return None
        email, digest, expiry, attempts, _ = row
        candidate = hmac_code(user, email, str(code or "").strip(), purpose)
        if not hmac.compare_digest(candidate, digest):
            with db:
                db.execute("UPDATE account_code SET attempts=attempts+1 WHERE user=? COLLATE NOCASE", [user])
            return None
        with db:
            db.execute("DELETE FROM account_code WHERE user=? COLLATE NOCASE", [user])
        return email
    finally:
        db.close()


def accept_privacy(user, ip):
    db = core.connect()
    try:
        with db:
            db.execute("UPDATE account SET privacy_version=?,privacy_ts=?,updated=? WHERE user=? COLLATE NOCASE",
                       (PRIVACY_VERSION, time.time(), time.time(), user))
    finally:
        db.close()
    core.audit(ip, user, "privacy.accept", PRIVACY_VERSION)


def update_email(user, email):
    email = str(email or "").strip().lower()
    if not EMAIL_RE.fullmatch(email):
        raise ValueError("Enter a valid e-mail address")
    db = core.connect()
    try:
        with db:
            db.execute("UPDATE account SET email=?,email_verified=0,updated=? WHERE user=? COLLATE NOCASE",
                       (email, time.time(), user))
    finally:
        db.close()


def confirm_email(user, email=None):
    db = core.connect()
    try:
        with db:
            if email is None:
                db.execute("UPDATE account SET email_verified=1,updated=? WHERE user=? COLLATE NOCASE",
                           (time.time(), user))
            else:
                db.execute("UPDATE account SET email=?,email_verified=1,updated=? WHERE user=? COLLATE NOCASE",
                           (str(email).strip().lower(), time.time(), user))
    finally:
        db.close()


def signups_allowed():
    """Check whether account registration is allowed.
    Policy priority:
    1. ALLOW_SIGNUPS (or STRATA_ALLOW_SIGNUPS) environment variable if set.
    2. auth.allow_signups in instance configuration (strata.json on disk or in-memory core.CFG).
    3. Defaults to False: accounts exist only when root creates them.
    """
    import os
    env = os.environ.get("ALLOW_SIGNUPS")
    if env is None:
        env = os.environ.get("STRATA_ALLOW_SIGNUPS")
    if env is not None:
        return env.strip().lower() not in ("0", "false", "no", "off", "disable", "disabled")
    try:
        if os.path.exists(core.CONFIG_PATH):
            with open(core.CONFIG_PATH, "r", encoding="utf-8-sig") as f:
                disk_cfg = json.load(f)
                val = disk_cfg.get("auth", {}).get("allow_signups")
                if val is not None:
                    return bool(val)
    except Exception:
        pass
    cfg_val = core.CFG.get("auth", {}).get("allow_signups")
    if cfg_val is not None:
        return bool(cfg_val)
    return False



def set_signups_allowed(enabled):
    """Update registration setting in config unless overridden by environment."""
    import os
    if os.environ.get("ALLOW_SIGNUPS") is not None or os.environ.get("STRATA_ALLOW_SIGNUPS") is not None:
        raise ValueError("Registration policy is locked by deployment environment variable (ALLOW_SIGNUPS)")
    core.save_config({"auth": {"allow_signups": bool(enabled)}})


def provision_user_storage(user, mount=None, path=None, created_by=""):
    import os
    import files
    if mount is None:
        for d in files.served():
            if d.get("kind") == "files":
                mount = d["mount"]
                break
        if mount is None:
            mount = 1
    rel_path = path or f"/users/{user}"
    normalized = files.rel_of(files.parts_of(str(rel_path or "/")))
    m = core.mount(mount)
    if m and os.path.isdir(m.get("path", "")):
        try:
            full, _ = files.resolve(m, normalized, allow_internal=True)
            os.makedirs(full, exist_ok=True)
        except Exception:
            pass
    db = core.connect()
    try:
        with db:
            exists = db.execute("SELECT 1 FROM account_zone WHERE user=? COLLATE NOCASE AND mount=? AND path=?",
                                (user, int(mount), normalized)).fetchone()
            if not exists:
                db.execute("INSERT INTO account_zone(user,mount,path,access,created,created_by) VALUES(?,?,?,?,?,?)",
                           (user, int(mount), normalized, "write", time.time(), created_by))
    finally:
        db.close()
    return {"mount": int(mount), "path": normalized, "access": "write"}


def issue_invite(username, email, role, permissions, created_by, preset=None, mount=None, storage_path=None):
    username = str(username or "").strip()
    email = str(email or "").strip().lower() if email else ""
    role = str(role or "employee")
    if not USER_RE.fullmatch(username):
        raise ValueError("Use a 2–60 character username with letters, numbers, dots, hyphens or underscores")
    if email and not EMAIL_RE.fullmatch(email):
        raise ValueError("Enter a valid e-mail address")
    if role not in ("employee", "admin"):
        raise ValueError("Only employee and admin accounts can be invited")
    if preset and preset in PRESETS and preset != "custom":
        role = PRESETS[preset]["role"]
        grants = list(PRESETS[preset]["permissions"])
    else:
        grants = sorted(set(str(p) for p in (permissions or []) if str(p) in PERMISSION_IDS))
        if role == "admin":
            grants = ["*"]
    token = secrets.token_urlsafe(32)
    now, expires = time.time(), time.time() + 24 * 3600
    db = core.connect()
    try:
        with db:
            if db.execute("SELECT 1 FROM account WHERE user=? COLLATE NOCASE", [username]).fetchone():
                raise ValueError("That account name already exists")
            if email and db.execute("SELECT 1 FROM account WHERE email=? COLLATE NOCASE AND enabled=1", [email]).fetchone():
                raise ValueError("That e-mail address is already assigned")
            db.execute("INSERT INTO account(user,email,password_hash,role,permissions,enabled,email_verified,created,updated) "
                       "VALUES(?,?,?,?,?,0,0,?,?)", (username, email, "", role, json.dumps(grants), now, now))
            db.execute("INSERT INTO account_invite(token_hash,user,email,expires,created_by) VALUES(?,?,?,?,?)",
                       (auth.token_hash(token), username, email, expires, created_by))
    finally:
        db.close()
    try:
        provision_user_storage(username, mount=mount, path=storage_path, created_by=created_by)
    except Exception:
        pass
    return token, expires


def cancel_invite(token):
    token_hash = auth.token_hash(str(token or ""))
    db = core.connect()
    try:
        row = db.execute("SELECT user FROM account_invite WHERE token_hash=?", [token_hash]).fetchone()
        if row:
            with db:
                db.execute("DELETE FROM account_invite WHERE token_hash=?", [token_hash])
                db.execute("DELETE FROM account WHERE user=? COLLATE NOCASE AND password_hash=''", [row[0]])
    finally:
        db.close()


def use_invite(token, password, privacy_accepted, ip):
    if not isinstance(privacy_accepted, bool) or not privacy_accepted:
        raise ValueError("Accept the privacy note to create this account")
    if len(str(password or "")) < 12:
        raise ValueError("Use a password with at least 12 characters")
    db = core.connect()
    try:
        row = db.execute("SELECT user,email,expires FROM account_invite WHERE token_hash=?", [auth.token_hash(str(token or ""))]).fetchone()
        if not row or row[2] < time.time():
            raise ValueError("This invite is invalid or expired")
        user, email, expires = row
        acct = db.execute("SELECT role,password_hash FROM account WHERE user=? COLLATE NOCASE", [user]).fetchone()
        if not acct or acct[0] == "root":
            raise ValueError("This invite is invalid or expired")
        reset = bool(acct[1])  # an account that already had a password: a reset keeps its enabled / disabled state
        with db:
            db.execute("UPDATE account SET password_hash=?,%sprivacy_version=?,privacy_ts=?,updated=? "
                       "WHERE user=? COLLATE NOCASE" % ("" if reset else "enabled=1,"),
                       (auth.hash_password(password), PRIVACY_VERSION, time.time(), time.time(), user))
            db.execute("DELETE FROM account_invite WHERE user=? COLLATE NOCASE", [user])
            db.execute("DELETE FROM session WHERE user=? COLLATE NOCASE", [user])
    finally:
        db.close()
    core.audit(ip, user, "account.password-reset.done" if reset else "account.enroll", "privacy accepted")
    return user


def issue_password_reset(username, created_by):
    a = get(username)
    if not a:
        raise ValueError("Account not found")
    if a.get("role") == "root":
        raise ValueError("The root password can only be changed by root itself or from the server CLI")
    token = secrets.token_urlsafe(32)
    expires = time.time() + 24 * 3600
    db = core.connect()
    try:
        with db:
            db.execute("DELETE FROM account_invite WHERE user=? COLLATE NOCASE", [username])
            db.execute("INSERT INTO account_invite(token_hash,user,email,expires,created_by) VALUES(?,?,?,?,?)",
                       (auth.token_hash(token), username, a.get("email") or "", expires, created_by))
    finally:
        db.close()
    return token, expires


def delete_account(user, storage_action="retain"):
    import os
    import shutil
    a = get(user)
    if not a:
        raise ValueError("Account not found")
    db = core.connect()
    try:
        root_count = db.execute("SELECT COUNT(*) FROM account WHERE role='root' AND enabled=1").fetchone()[0]
        if a.get("role") == "root" and root_count <= 1:
            raise ValueError("The last root administrator cannot be deleted")
        if storage_action in ("delete", "archive"):
            import files
            z_list = zones(user)
            for z in z_list:
                z_path = str(z.get("path") or "").rstrip("/")
                if z_path.lower() == f"/users/{user.lower()}":
                    m = core.mount(z["mount"])
                    if m and os.path.isdir(m.get("path", "")):
                        try:
                            full, _ = files.resolve(m, z["path"], allow_internal=True)
                            if os.path.exists(full):
                                if storage_action == "delete":
                                    shutil.rmtree(full, ignore_errors=True)
                                elif storage_action == "archive":
                                    ts = int(time.time())
                                    os.rename(full, f"{full}_archived_{ts}")
                        except Exception:
                            pass
        old_avatar = avatar_file(a)
        if old_avatar:
            try:
                os.remove(old_avatar)
            except OSError:
                pass
        import office
        office.forget_account(user)
        with db:
            db.execute("DELETE FROM account_invite WHERE user=? COLLATE NOCASE", [user])
            db.execute("DELETE FROM account_zone WHERE user=? COLLATE NOCASE", [user])
            db.execute("DELETE FROM account_code WHERE user=? COLLATE NOCASE", [user])
            db.execute("DELETE FROM account WHERE user=? COLLATE NOCASE", [user])
    finally:
        db.close()
    return True


def set_permissions(user, role, permissions, preset=None):
    a = get(user)
    if not a:
        raise ValueError("Account not found")
    if a["role"] == "root":
        raise ValueError("Root access is protected")
    if preset and preset in PRESETS and preset != "custom":
        role = PRESETS[preset]["role"]
        grants = list(PRESETS[preset]["permissions"])
    else:
        if role not in ("employee", "admin"):
            raise ValueError("Invalid account role")
        grants = sorted(set(str(p) for p in (permissions or []) if str(p) in PERMISSION_IDS))
        if role == "admin":
            grants = ["*"]
    db = core.connect()
    try:
        with db:
            db.execute("UPDATE account SET role=?,permissions=?,updated=? WHERE user=? COLLATE NOCASE",
                       (role, json.dumps(grants), time.time(), user))
    finally:
        db.close()


def _zone_fields(caps, expires):
    caps = sorted({str(c) for c in (caps or []) if str(c) in FILE_CAPS})
    if not caps:
        raise ValueError("Pick at least one file capability for this folder")
    if "files.read" not in caps:
        raise ValueError("Every zone needs Browse and preview - without it the folder cannot be opened")
    if expires not in (None, ""):
        expires = float(expires)
        if expires < time.time():
            raise ValueError("The access end date is in the past")
    else:
        expires = None
    access = "write" if set(caps) - {"files.read", "files.download", "files.share", "files.analyze"} else "read"
    return json.dumps(caps), access, expires


def zone_save(user, mount, path, caps, expires, created_by):
    """Grant `user` the file capabilities `caps` inside mount:path (until `expires`, a unix time, if given).
    Granting the same folder again replaces its capabilities."""
    import files
    m = core.mount(mount)
    if not m or m.get("kind") != "files":
        raise ValueError("Choose a file storage drive")
    normalized = files.rel_of(files.parts_of(str(path or "/")))
    caps_json, access, expires = _zone_fields(caps, expires)
    db = core.connect()
    try:
        with db:
            row = db.execute("SELECT id FROM account_zone WHERE user=? COLLATE NOCASE AND mount=? AND path=?",
                             (user, int(mount), normalized)).fetchone()
            if row:
                db.execute("UPDATE account_zone SET caps=?,access=?,expires=? WHERE id=?", (caps_json, access, expires, row[0]))
            else:
                db.execute("INSERT INTO account_zone(user,mount,path,access,caps,expires,created,created_by) VALUES(?,?,?,?,?,?,?,?)",
                           (user, int(mount), normalized, access, caps_json, expires, time.time(), created_by))
    finally:
        db.close()
    return zones(user, include_expired=True)


def zone_update(zone_id, caps, expires):
    caps_json, access, expires = _zone_fields(caps, expires)
    db = core.connect()
    try:
        with db:
            if not db.execute("UPDATE account_zone SET caps=?,access=?,expires=? WHERE id=?",
                              (caps_json, access, expires, int(zone_id))).rowcount:
                raise ValueError("Storage zone not found")
    finally:
        db.close()


def zone_delete(zone_id):
    db = core.connect()
    try:
        with db:
            db.execute("DELETE FROM account_zone WHERE id=?", [int(zone_id)])
    finally:
        db.close()
