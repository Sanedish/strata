"""Login for the admin UI: PBKDF2 password, optional TOTP 2FA + recovery codes, in-memory sessions, limiter.

    python auth.py <username>      # prompts for the password (or reads it from stdin) and stores the hash
    python auth.py --api-key <name>  # prints a new API key once; only its sha256 is stored (auth.api_keys)
    python auth.py --totp [off]    # sets up (or removes) the owner's authenticator app, which replaces the e-mailed code
"""
import base64
import collections
import hashlib
import hmac
import secrets
import struct
import sys
import threading
import time

import core

ITERATIONS = 600_000
# cookies ignore the port: two instances on one host need their own names (instance.prefix in strata.json)
COOKIE = core.prefixed("session")
PENDING_COOKIE = core.prefixed("2fa")
TRUST_COOKIE = core.prefixed("trust")
TRUST_DAYS = 30


def hash_password(password):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return "pbkdf2_sha256$%d$%s$%s" % (ITERATIONS, base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def verify_password(password, stored):
    try:
        algo, iters, salt, dk = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        calc = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), base64.b64decode(salt), int(iters))
        return hmac.compare_digest(calc, base64.b64decode(dk))
    except (ValueError, TypeError):
        return False


def token_hash(token):
    """High-entropy machine tokens only need a plain SHA-256 at rest."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- API keys (Authorization: Bearer <key>, full admin API)

API_KEY_PREFIX = core.prefixed("")   # tells the instances' keys apart


def new_api_key():
    return API_KEY_PREFIX + secrets.token_urlsafe(32)


def api_key_name(keys, token):
    """Name of the stored key (auth.api_keys: [{name, hash, created}]) matching `token`, else None.
    Every entry is compared so the answer takes the same time whichever key matched."""
    if not token or len(token) > 200:
        return None
    h, hit = token_hash(token), None
    for k in keys or []:
        if hmac.compare_digest(h, str(k.get("hash", ""))) and hit is None:
            hit = str(k.get("name") or "key")
    return hit


# ---------------------------------------------------------------- TOTP (RFC 6238: SHA-1, 30 s, 6 digits)

def totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _totp(secret, step):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    h = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = h[-1] & 15
    return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


def totp_verify(secret, code, last_step=0, window=1):
    """Returns the matched time step (store it to stop replays) or None."""
    code = "".join(ch for ch in str(code) if ch.isdigit())
    if len(code) != 6 or not secret:
        return None
    now = int(time.time() // 30)
    for step in range(now - window, now + window + 1):
        if step > (last_step or 0) and hmac.compare_digest(_totp(secret, step), code):
            return step
    return None


def totp_uri(secret, user, issuer="Strata"):
    import urllib.parse
    return "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30" % (
        urllib.parse.quote(issuer), urllib.parse.quote(user), secret, urllib.parse.quote(issuer))


def qr_svg(text):
    """Enrolment QR code as an SVG string (qrcode package, no Pillow needed for SVG)."""
    try:
        import qrcode
        import qrcode.image.svg
        img = qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage, box_size=10, border=2)
        return img.to_string(encoding="unicode")
    except Exception:
        return ""


def qr_text(text):
    """The same QR code drawn with block characters for a terminal, or "" without the qrcode package."""
    try:
        import io
        import qrcode
        q = qrcode.QRCode(border=2)
        q.add_data(text)
        out = io.StringIO()
        q.print_ascii(out=out, invert=True)
        return out.getvalue()
    except Exception:
        return ""


def spaced(secret):
    """ABCD EFGH ...: easier to type into an authenticator app."""
    return " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))


def recovery_codes(n=10):
    """Returns (plain codes for the user, hashes to store)."""
    codes = ["%s-%s" % (secrets.token_hex(3), secrets.token_hex(3)) for _ in range(n)]
    return codes, [token_hash(c) for c in codes]


def normalize_recovery(code):
    c = "".join(ch for ch in str(code).lower() if ch in "0123456789abcdef")
    return c[:6] + "-" + c[6:] if len(c) == 12 else None


# ---------------------------------------------------------------- trusted-browser cookie (skips the 2FA step)

def trust_token(key, user, pw_hash, days=TRUST_DAYS):
    exp = int(time.time() + days * 86400)
    mac = hmac.new(key.encode(), ("%s|%d|%s" % (user, exp, pw_hash[-24:])).encode(), hashlib.sha256).hexdigest()
    return "%d.%s" % (exp, mac)


def trust_ok(key, token, user, pw_hash):
    try:
        exp, mac = token.split(".", 1)
        if int(exp) < time.time():
            return False
        want = hmac.new(key.encode(), ("%s|%s|%s" % (user, exp, pw_hash[-24:])).encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(mac, want)
    except (ValueError, AttributeError):
        return False


# ---------------------------------------------------------------- sessions

class Sessions:
    def __init__(self, hours):
        self.ttl = hours * 3600
        self.lock = threading.Lock()
        self.by_hash = {}  # sha256(token) -> {user, exp, ip}; the raw token only lives in the browser cookie

    def create(self, user, ip, ttl=None, **extra):
        token = secrets.token_urlsafe(32)
        with self.lock:
            self.by_hash[token_hash(token)] = {"user": user, "exp": time.time() + (ttl or self.ttl), "ip": ip,
                                               "created": time.time(), "ttl": ttl or self.ttl, "attempts": 0, **extra}
        return token

    def get(self, token):
        if not token:
            return None
        h = token_hash(token)
        with self.lock:
            s = self.by_hash.get(h)
            if not s:
                return None
            if s["exp"] < time.time():
                del self.by_hash[h]
                return None
            return s

    def check(self, token):
        s = self.get(token)
        if not s:
            return None
        with self.lock:
            s["exp"] = time.time() + s["ttl"]  # sliding expiry
        return s["user"]

    def drop(self, token):
        if token:
            with self.lock:
                self.by_hash.pop(token_hash(token), None)

    def drop_user(self, user):
        with self.lock:
            for h in [h for h, s in self.by_hash.items() if s["user"] == user]:
                del self.by_hash[h]

    def count(self):
        now = time.time()
        with self.lock:
            return sum(1 for s in self.by_hash.values() if s["exp"] > now)


class Limiter:
    """At most `limit` failed attempts per client per `window` seconds."""

    def __init__(self, limit=8, window=900):
        self.limit, self.window = limit, window
        self.lock = threading.Lock()
        self.fails = collections.defaultdict(collections.deque)

    def recent(self, ip):
        with self.lock:
            q = self.fails[ip]
            while q and q[0] < time.time() - self.window:
                q.popleft()
            return len(q)

    def blocked(self, ip):
        return self.recent(ip) >= self.limit

    def fail(self, ip):
        with self.lock:
            self.fails[ip].append(time.time())

    def ok(self, ip):
        with self.lock:
            self.fails.pop(ip, None)


def cookie_value(header, name=COOKIE):
    for part in (header or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == name:
            return v
    return None


if __name__ == "__main__":
    import getpass
    from core import CFG, CONFIG_PATH, save_config
    argv = list(sys.argv)
    for i, a in enumerate(argv):  # --home <dir> / --home=<dir> picks the instance (instance.py); not an argument here
        if a == "--home":
            del argv[i:i + 2]
            break
        if a.startswith("--home="):
            del argv[i]
            break
    sys.argv = argv
    print("instance config: %s" % CONFIG_PATH, file=sys.stderr)
    if len(sys.argv) == 3 and sys.argv[1] == "--api-key":
        key = new_api_key()
        keep = [k for k in CFG["auth"].get("api_keys") or [] if k.get("name") != sys.argv[2]]
        save_config({"auth": {"api_keys": keep + [{"name": sys.argv[2], "hash": token_hash(key), "created": int(time.time())}]}})
        print(key)
        print("stored as API key %r (replaces any key of that name) - restart Strata to load it" % sys.argv[2])
        sys.exit(0)
    if len(sys.argv) == 3 and sys.argv[1] == "--email":
        new_email = sys.argv[2].strip().lower()
        if "@" not in new_email:
            sys.exit("invalid email address")
        current_to = list(CFG.get("alerts", {}).get("to") or [])
        if new_email not in current_to:
            current_to.insert(0, new_email)
        save_config({"alerts": {"to": current_to}})
        import core
        db = core.connect()
        try:
            with db:
                db.execute("UPDATE account SET email=?, email_verified=1, updated=? WHERE role='root'", (new_email, time.time()))
        finally:
            db.close()
        print("stored root email address: %s" % new_email)
        sys.exit(0)
    if len(sys.argv) == 4 and sys.argv[1] == "--resend":
        api_key, sender = sys.argv[2].strip(), sys.argv[3].strip()
        save_config({"alerts": {"resend_api_key": api_key, "from": sender}})
        print("configured Resend alerts and OTP sender: %s" % sender)
        sys.exit(0)
    if len(sys.argv) == 3 and sys.argv[1] == "--allow-signups":
        allowed = sys.argv[2].strip().lower() in ("1", "true", "yes", "on")
        save_config({"auth": {"allow_signups": allowed}})
        print("account registration enabled: %s" % allowed)
        sys.exit(0)
    if sys.argv[1:] == ["--totp", "off"]:
        save_config({"auth": {"totp_secret": "", "recovery": [], "totp_last": 0}})
        print("removed the owner's authenticator app. Restart Strata to apply it.")
        mail = CFG.get("alerts", {})
        if not (mail.get("resend_api_key") and mail.get("from")):
            print("E-mail isn't set up either, so the owner can't sign in until you run: python auth.py --totp")
        sys.exit(0)
    if sys.argv[1:] == ["--totp"]:
        owner = str(CFG["auth"].get("user") or "owner")
        secret = totp_secret()
        uri = totp_uri(secret, owner)
        print("Scan this with your authenticator app:\n")
        try:
            print(qr_text(uri) or "(no QR code: the qrcode package isn't installed)")
        except UnicodeEncodeError:  # a console that can't draw the block characters
            print("(this console can't show the QR code)")
        print("Or enter this key in the app: %s\n" % spaced(secret))
        step = None
        for _ in range(3):
            try:
                step = totp_verify(secret, input("Code from the app: "))
            except EOFError:
                break
            if step:
                break
            print("That code didn't match. Check that the time on your phone is correct.")
        if not step:
            sys.exit("Nothing changed.")
        codes, hashes = recovery_codes()
        save_config({"auth": {"totp_secret": secret, "totp_last": step, "recovery": hashes}})
        print("\nThe owner now signs in with a code from this app. If you lose your phone, each of these recovery codes "
              "works once instead:")
        print("\n".join("  " + c for c in codes))
        print("They are shown only now. Restart Strata to use the app.")
        sys.exit(0)
    if len(sys.argv) != 2:
        sys.exit("usage: python auth.py --home <dir> <username> | --api-key <name> | --email <addr> | --resend <key> <from> | "
                 "--totp [off] | --allow-signups <yes|no>")
    pw = getpass.getpass("Password: ") if sys.stdin.isatty() else sys.stdin.readline().rstrip("\r\n")
    pw = pw.lstrip("﻿")  # Windows PowerShell prefixes piped input with a BOM
    if len(pw) < 8:
        sys.exit("password too short")
    save_config({"auth": {"user": sys.argv[1], "password_hash": hash_password(pw)}})
    print("stored password hash for", sys.argv[1])
