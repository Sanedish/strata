"""Seed the DEV instance for UI checks: an employee 'mara' with fine-grained grants, two zones, limits. Prints its token."""
import hashlib
import json
import os
import secrets
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE, DB, FILES = "http://127.0.0.1:8190", sys.argv[1], sys.argv[2]
assert "scratchpad" in DB.replace("\\", "/")


def session(user):
    tok = secrets.token_urlsafe(32)
    c = sqlite3.connect(DB)
    c.execute("INSERT OR REPLACE INTO session VALUES(?,?,?,?,?,?)",
              [hashlib.sha256(tok.encode()).hexdigest(), user, time.time() + 86400, "127.0.0.1", time.time(), 86400])
    c.commit()
    return tok


root = session("dev")


def post(path, body, form=False, tok=root):
    h = {"X-Strata": "1", "Cookie": "dev_strata_session=" + tok, "Origin": BASE,
         "Content-Type": "application/x-www-form-urlencoded" if form else "application/json"}
    data = urllib.parse.urlencode(body).encode() if form else json.dumps(body).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(BASE + path, data=data, headers=h), timeout=20) as r:
            b = r.read()
            return json.loads(b) if b[:1] == b"{" else {}
    except urllib.error.HTTPError as e:
        return {"error": e.code, "body": e.read()[:200]}


for d in ("projects/site-redesign", "projects/press-kit", "inbox"):
    os.makedirs(os.path.join(FILES, *d.split("/")), exist_ok=True)
    with open(os.path.join(FILES, *d.split("/"), "notes.txt"), "w") as f:
        f.write("notes for " + d)
r = post("/api/accounts/invite", {"user": "mara", "email": "mara@example.test", "preset": "contributor"})
if r.get("token"):
    post("/enroll", {"token": r["token"], "password": "correct horse battery staple 42", "privacy": "yes"}, form=True)
post("/api/accounts/permissions", {"user": "mara", "role": "employee", "preset": "custom", "permissions": [
    "files.read", "files.download", "files.upload", "files.mkdir", "files.rename", "files.move", "files.copy", "files.edit",
    "files.delete", "files.restore", "files.share", "analytics.read", "alerts.read"]})
print(post("/api/accounts/zone", {"user": "mara", "mount": 1, "path": "/projects/site-redesign",
                                 "caps": ["files.read", "files.download", "files.upload", "files.mkdir", "files.rename",
                                          "files.edit", "files.delete", "files.share", "files.purge"]}).get("error", "zone 1 ok"))
print(post("/api/accounts/zone", {"user": "mara", "mount": 1, "path": "/projects/press-kit", "caps": ["files.read", "files.download"],
                                 "expires": time.time() + 30 * 86400}).get("error", "zone 2 ok"))
print(post("/api/accounts/constraints", {"user": "mara", "allowed_ips": "127.0.0.0/8, 192.168.1.0/24", "session_hours": 12,
                                        "expires": time.time() + 90 * 86400, "note": "Agency contractor - site redesign"}).get("error", "limits ok"))
print("MARA_TOKEN=" + session("mara"))
print("ROOT_TOKEN=" + root)
