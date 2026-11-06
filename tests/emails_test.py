"""Settings › Emails (mailtpl.py) against the DEV instance on 127.0.0.1:8190: only the owner reads or edits the
templates, a preview fills the sample data and escapes it, an edit is saved per instance and reset drops it, and a
test e-mail needs delivery set up. Usage: python tests/emails_test.py <path to the dev strata.db>. Exit code 1 on
failure."""
import hashlib
import json
import os
import secrets
import sqlite3
import sys
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8190"
COOKIE = "dev_strata_session"
DB = sys.argv[1]
HOME = os.path.dirname(os.path.dirname(os.path.abspath(DB)))
results = []


def session(user):
    tok = secrets.token_urlsafe(32)
    c = sqlite3.connect(DB)
    c.execute("INSERT OR REPLACE INTO session VALUES(?,?,?,?,?,?)",
              [hashlib.sha256(tok.encode()).hexdigest(), user, time.time() + 3600, "127.0.0.1", time.time(), 3600])
    c.commit()
    c.close()
    return tok


def call(tok, path, body=None):
    h = {"X-Strata": "1", "Origin": BASE, "Cookie": COOKIE + "=" + tok, "Content-Type": "application/json"}
    req = urllib.request.Request(BASE + path, data=None if body is None else json.dumps(body).encode(), headers=h)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"raw": raw[:200].decode("utf-8", "replace")}


def check(name, ok, detail=""):
    results.append(ok)
    print("%s %s%s" % ("PASS" if ok else "FAIL", name, "" if ok else "  -> %s" % (detail,)))


def stored():
    with open(os.path.join(HOME, "strata.json"), encoding="utf-8-sig") as f:
        return json.load(f).get("emails") or {}


owner = session("dev")
KINDS = {"alert", "digest", "test", "login_code", "email_change", "invite", "password_reset"}

s, r = call(owner, "/api/emails")
check("owner lists the e-mails", s == 200 and {k["id"] for k in r.get("kinds", [])} == KINDS, (s, r))
k0 = {k["id"]: k for k in r.get("kinds", [])}
check("every kind documents its variables", all(k["vars"] and k["default"]["html"] and k["default"]["text"] for k in k0.values()))
check("defaults are complete documents", all(k["default"]["html"].lstrip().lower().startswith("<!doctype html>") for k in k0.values()))

# an administrator holds everything except the root-only powers: mail.manage is one, so no templates
s, r = call(owner, "/api/accounts/invite", {"user": "emails_admin", "email": "ea@example.test", "preset": "admin"})
admin = session("emails_admin") if r.get("token") else None
c = sqlite3.connect(DB)
c.execute("UPDATE account SET enabled=1, privacy_version=(SELECT privacy_version FROM account WHERE user='dev') WHERE user='emails_admin'")
c.commit()
c.close()
s, _ = call(admin or "", "/api/alerts")
check("the administrator's session works", s == 200, s)
for who in ("emails_admin", "mara", "lena"):
    tok = session(who)
    s, _ = call(tok, "/api/emails")
    s2, _ = call(tok, "/api/emails/save", {"kind": "invite", "subject": "pwned {{link}}"})
    check("%s can't read or edit the templates" % who, s == 403 and s2 == 403, (s, s2))

s, r = call(owner, "/api/emails/preview", {"kind": "login_code"})
check("preview fills the sample data", s == 200 and "482915" in r.get("html", "") and "482915" in r.get("text", ""), (s, r))
check("preview inlines the CSS", 'style="' in r.get("html", "") and "<style" in r.get("html", ""), r.get("html", "")[:200])

draft = {"kind": "invite", "subject": "Hi {{user}}\nBcc: x@example.org", "html": "<p class='x'>{{{user}}} {{nope}}</p>",
         "css": ".x { color: {{accent}}; }", "text": "Link: {{link}}"}
s, r = call(owner, "/api/emails/preview", draft)
check("preview uses the unsaved draft", s == 200 and r.get("text", "").startswith("Link: http"), (s, r))
check("a subject stays one line", "\n" not in r.get("subject", "x\n") and r.get("subject", "").startswith("Hi alex"), r.get("subject"))
check("unknown variables are reported", r.get("unknown") == ["nope"], r.get("unknown"))
check("draft CSS is inlined", "color: #" in r.get("html", ""), r.get("html", "")[-300:])

s, r = call(owner, "/api/emails/save", {"kind": "invite", "subject": "Welcome to {{site}}, {{user}}"})
cur = {k["id"]: k for k in r.get("kinds", [])}.get("invite", {})
check("save keeps the edit", s == 200 and cur.get("custom", {}).get("subject") == "Welcome to {{site}}, {{user}}", (s, cur.get("custom")))
check("parts left alone stay default", set(cur.get("custom", {})) == {"subject"}, cur.get("custom"))
check("the edit is in this instance's strata.json", (stored().get("invite") or {}).get("subject") == "Welcome to {{site}}, {{user}}", stored())
s, r = call(owner, "/api/emails/preview", {"kind": "invite"})
check("preview follows the saved edit", r.get("subject", "").startswith("Welcome to ") and r["subject"].endswith(", alex"), r.get("subject"))

s, r = call(owner, "/api/emails/reset", {"kind": "invite"})
cur = {k["id"]: k for k in r.get("kinds", [])}.get("invite", {})
check("reset goes back to the default", s == 200 and not cur.get("custom") and stored().get("invite") is None, (s, cur.get("custom"), stored()))

s, _ = call(owner, "/api/emails/save", {"kind": "nope", "subject": "x"})
check("unknown kind refused", s == 400, s)
s, _ = call(owner, "/api/emails/save", {"kind": "invite", "html": "x" * 100001})
check("oversized part refused", s == 400, s)
s, _ = call(owner, "/api/emails/save", {"kind": "invite", "text": "   "})
check("empty text refused", s == 400, s)
s, r = call(owner, "/api/emails/test", {"kind": "login_code"})
check("test e-mail needs delivery set up", s == 400 and "delivery" in json.dumps(r), (s, r))

if admin:  # leave the seeded accounts as they were
    call(owner, "/api/accounts/delete", {"user": "emails_admin"})

print("%d/%d passed" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
