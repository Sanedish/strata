"""Regression suite for fine-grained access control, account constraints, profile pictures and synced preferences.
DEV instance only (127.0.0.1:8190, a home under a 'scratchpad' folder). Exit code 1 if any check fails.

    python granular_regress.py <dev-home>\\data\\strata.db <dev-home>\\files
"""
import hashlib
import io
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
COOKIE = "dev_strata_session"
assert "scratchpad" in DB.replace("\\", "/"), "dev databases only"
results = []


def session(user, created=None):
    tok = secrets.token_urlsafe(32)
    c = sqlite3.connect(DB)
    now = time.time()
    c.execute("INSERT OR REPLACE INTO session VALUES(?,?,?,?,?,?)",
              [hashlib.sha256(tok.encode()).hexdigest(), user, now + 3600, "127.0.0.1", created or now, 3600])
    c.commit()
    return tok


def call(method, path, tok=None, body=None, raw=None, ctype=None, form=False):
    h = {"X-Strata": "1", "Origin": BASE}
    if tok:
        h["Cookie"] = "%s=%s" % (COOKIE, tok)
    data = None
    if raw is not None:
        data, h["Content-Type"] = raw, ctype or "application/octet-stream"
    elif body is not None:
        data = urllib.parse.urlencode(body).encode() if form else json.dumps(body).encode()
        h["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
    req = urllib.request.Request(BASE + path, data=data, headers=h, method=method)

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    try:
        with urllib.request.build_opener(NoRedirect).open(req, timeout=30) as r:
            b = r.read()
            return r.status, (json.loads(b) if b[:1] == b"{" else b), r.headers
    except urllib.error.HTTPError as e:
        b = e.read()
        try:
            return e.code, json.loads(b), e.headers
        except ValueError:
            return e.code, b, e.headers


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else "  -> " + str(detail)[:300]))


def mkfile(rel, text="x"):
    p = os.path.join(FILES, *rel.strip("/").split("/"))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(text)


root = session("dev")
sfx = secrets.token_hex(3)
emp = "gran" + sfx


def make(user, preset="read_only", **extra):
    st, r, _ = call("POST", "/api/accounts/invite", root, dict({"user": user, "email": user + "@example.test", "preset": preset}, **extra))
    assert st == 200, r
    st, _, h = call("POST", "/enroll", body={"token": r["token"], "password": "correct horse battery staple 42", "privacy": "yes"}, form=True)
    return st == 303


# ---- an employee with hand-picked capabilities and three zones with different rights
make(emp)
c = sqlite3.connect(DB)
c.execute("DELETE FROM account_zone WHERE user=?", [emp])  # drop the default home zone: zones below define everything
c.commit()
base = "/gran-" + sfx
for d in ("view", "work", "drop", "gone"):
    mkfile("%s/%s/readme.txt" % (base, d), "hello " + d)
st, r, _ = call("POST", "/api/accounts/permissions", root, {"user": emp, "role": "employee", "preset": "custom", "permissions": [
    "files.read", "files.download", "files.upload", "files.mkdir", "files.rename", "files.move", "files.copy", "files.delete"]})
check("custom fine-grained permissions save", st == 200 and "files.rename" in r["account"]["permissions"], r)
st, r, _ = call("POST", "/api/accounts/permissions", root, {"user": emp, "role": "employee", "preset": "custom",
                                                           "permissions": ["files.read", "accounts.manage", "code.write"]})
check("root-only capabilities cannot be granted", st == 200 and "accounts.manage" not in r["account"]["permissions"]
      and "code.write" not in r["account"]["permissions"], r)
call("POST", "/api/accounts/permissions", root, {"user": emp, "role": "employee", "preset": "custom", "permissions": [
    "files.read", "files.download", "files.upload", "files.mkdir", "files.rename", "files.move", "files.copy", "files.delete"]})
zone = lambda path, caps, exp=None: call("POST", "/api/accounts/zone", root, {"user": emp, "mount": 1, "path": path, "caps": caps, "expires": exp})
st, r, _ = zone(base + "/view", ["files.read"])
check("zone with explicit capabilities is stored", st == 200 and any(z["path"] == base + "/view" and z["caps"] == ["files.read"] for z in r["zones"]), r)
zone(base + "/work", ["files.read", "files.download", "files.rename", "files.mkdir", "files.move", "files.copy", "files.delete"])
zone(base + "/drop", ["files.read", "files.upload", "files.move", "files.copy"])
st, r, _ = zone(base + "/gone", ["files.read", "files.download"], time.time() + 2)
check("zone with an end date is stored", st == 200, r)
st, r, _ = zone(base + "/x", ["files.download"])
check("zone without Browse is refused", st == 400, (st, r))
st, r, _ = zone(base + "/x", ["files.read"], time.time() - 10)
check("zone ending in the past is refused", st == 400, (st, r))

e = session(emp)
st, me, _ = call("GET", "/api/me", e)
eff = {z["path"]: set(z["effective"]) for z in me.get("zones", [])}
check("/api/me reports effective per-zone capabilities", eff.get(base + "/view") == {"files.read"}
      and "files.upload" in eff.get(base + "/drop", set()) and "files.copy" in eff.get(base + "/work", set()), me.get("zones"))
check("effective = account grants AND zone caps (no edit in work)", "files.edit" not in eff.get(base + "/work", {"files.edit"}), eff)

q = lambda p: "mount=1&path=" + urllib.parse.quote(p)
check("browse a read-only zone", call("GET", "/api/files?" + q(base + "/view"), e)[0] == 200)
check("preview a file in a read-only zone", call("GET", "/api/files/raw?" + q(base + "/view/readme.txt"), e)[0] == 200)
check("download refused where the zone only allows browsing",
      call("GET", "/api/files/raw?download=1&" + q(base + "/view/readme.txt"), e)[0] == 403)
check("download allowed where the zone allows it", call("GET", "/api/files/raw?download=1&" + q(base + "/work/readme.txt"), e)[0] == 200)
check("mkdir refused in the read-only zone", call("POST", "/api/files/mkdir", e, {"mount": 1, "path": base + "/view/new"})[0] == 403)
check("mkdir allowed in the work zone", call("POST", "/api/files/mkdir", e, {"mount": 1, "path": base + "/work/new"})[0] == 200)
check("rename refused when the target lies in another zone without rename",
      call("POST", "/api/files/rename", e, {"mount": 1, "from": base + "/work/readme.txt", "to": base + "/view/stolen.txt"})[0] == 403)
check("move refused into a zone without move", call("POST", "/api/files/move", e, {"mount": 1, "paths": [base + "/work/readme.txt"], "dest": base + "/view"})[0] == 403)
check("copy refused out of a zone the account cannot read",
      call("POST", "/api/files/copy", e, {"mount": 1, "paths": ["/share/demo/sample-0.png"], "dest": base + "/drop"})[0] == 403)
check("copy allowed from work into drop", call("POST", "/api/files/copy", e, {"mount": 1, "paths": [base + "/work/readme.txt"], "dest": base + "/drop"})[0] == 200)
check("delete refused where the zone has no delete", call("POST", "/api/files/delete", e, {"mount": 1, "paths": [base + "/drop/readme.txt"]})[0] == 403)
check("edit refused without files.edit", call("POST", "/api/files/text", e, {"mount": 1, "path": base + "/work/readme.txt", "text": "x"})[0] == 403)
check("upload refused into a zone without upload",
      call("PUT", "/api/files/upload?" + q(base + "/work/up.txt"), e, raw=b"data", ctype="text/plain")[0] == 403)
st, r, _ = call("PUT", "/api/files/upload?" + q(base + "/drop/up.txt") + "&policy=rename", e, raw=b"data", ctype="text/plain")
check("upload allowed into the drop zone", st == 200, (st, r))
check("trash needs a whole-drive zone", call("GET", "/api/files/trash?mount=1", e)[0] == 403)
check("analysis needs files.analyze", call("GET", "/api/analyze/overview?mount=1", e)[0] == 403)
time.sleep(2.5)
check("expired zone no longer grants access", call("GET", "/api/files?" + q(base + "/gone"), e)[0] == 403)
check("folders outside every zone stay closed", call("GET", "/api/files?" + q("/share"), e)[0] == 403)
check("traffic statistics refused without analytics.read", call("GET", "/api/stats", e)[0] == 403)

# ---- capability split outside files
ana = "ana" + sfx
make(ana, "analyst")
a = session(ana)
check("analyst sees statistics", call("GET", "/api/stats?range=24h", a)[0] == 200)
check("analyst cannot see visitor IPs", call("GET", "/api/requests", a)[0] == 403)
for route, fields in (("/api/stats?range=24h", ("ips", "scanners")),
                      ("/api/stats?range=90d", ("ips", "scanners")),
                      ("/api/insights?range=24h", ("clients",)),
                      ("/api/insights?range=90d", ("clients",)),
                      ("/api/live", ("recent",))):
    st, r, _ = call("GET", route, a)
    check("analyst gets no visitor details from " + route, st == 200 and all(r.get(k) == [] for k in fields), r)
check("owner still gets visitor detail fields", isinstance(call("GET", "/api/stats", root)[1].get("ips"), list))
check("analyst cannot read the raw request log", call("GET", "/api/logs?source=access", a)[0] == 403)
check("analyst cannot read the process log", call("GET", "/api/logs?source=runtime", a)[0] == 403)
check("analyst sees serving config read-only", call("GET", "/api/serving", a)[0] == 200)
check("analyst cannot change the blacklist", call("POST", "/api/serving/bl", a, {"kind": "ip", "value": "203.0.113.9"})[0] == 403)
check("analyst cannot purge the CDN", call("POST", "/api/cloudflare/purge", a, {"urls": ["https://x.test/a"]})[0] == 403)
call("POST", "/api/accounts/permissions", root, {"user": ana, "role": "employee", "preset": "custom",
                                                 "permissions": ["analytics.read", "serving.read", "serving.blacklist"]})
a = session(ana)
st, r, _ = call("POST", "/api/serving/bl", a, {"kind": "ip", "value": "203.0.113.9", "note": "granular test"})
check("serving.blacklist allows the blacklist and nothing else in serving", st == 200
      and call("POST", "/api/serving/rule", a, {"name": "x", "action": "deny", "patterns": ["/x"]})[0] == 403, (st, r))

# ---- share links: ownership and scope
sh, sh2 = "shr" + sfx, "shs" + sfx
for u in (sh, sh2):
    make(u, "read_only")
    call("POST", "/api/accounts/permissions", root, {"user": u, "role": "employee", "preset": "custom", "permissions": ["files.read", "files.share"]})
    call("POST", "/api/accounts/zone", root, {"user": u, "mount": 1, "path": base + "/work", "caps": ["files.read", "files.share"]})
s1, s2 = session(sh), session(sh2)
st, srv, _ = call("GET", "/api/serving", s1)
check("share-only account gets a scoped serving state", st == 200 and srv.get("scoped") and not srv.get("rules") and srv.get("mounts"), (st, str(srv)[:200]))
code = "t" + sfx
st, r, _ = call("POST", "/api/serving/link", s1, {"code": code, "mount": 1, "path": base + "/work/readme.txt", "mods": {}})
check("share link to a file inside the zone", st == 200, (st, r))
st, r, _ = call("POST", "/api/serving/link", s1, {"code": "u" + sfx, "mount": 1, "path": "/share/demo/sample-0.png", "mods": {}})
check("share link outside the zone refused", st == 403, (st, r))
st, r, _ = call("POST", "/api/serving/link", s1, {"code": "v" + sfx, "mount": None, "path": "", "url": "https://evil.example/", "mods": {}})
check("share link to an external URL refused (open redirect)", st == 403, (st, r))
check("another sharer cannot delete the link", call("POST", "/api/serving/link/delete", s2, {"code": code})[0] == 403)
check("another sharer does not see the link", code not in [l["code"] for l in call("GET", "/api/serving", s2)[1].get("links", [])])
check("the creator sees and deletes it", code in [l["code"] for l in call("GET", "/api/serving", s1)[1].get("links", [])]
      and call("POST", "/api/serving/link/delete", s1, {"code": code})[0] == 200)

# ---- account constraints
st, r, _ = call("POST", "/api/accounts/constraints", root, {"user": emp, "allowed_ips": "10.99.0.0/16"})
check("IP allowlist saved", st == 200 and r["account"]["allowed_ips"] == ["10.99.0.0/16"], r)
check("session from outside the allowlist is refused", call("GET", "/api/me", session(emp))[0] == 401)
call("POST", "/api/accounts/constraints", root, {"user": emp, "allowed_ips": "127.0.0.0/8, ::1"})
check("session inside the allowlist works", call("GET", "/api/me", session(emp))[0] == 200)
st, r, _ = call("POST", "/api/accounts/constraints", root, {"user": emp, "allowed_ips": "not-an-ip"})
check("invalid address range rejected", st == 400, (st, r))
call("POST", "/api/accounts/constraints", root, {"user": emp, "allowed_ips": "", "session_hours": 1})
check("absolute session length enforced", call("GET", "/api/me", session(emp, created=time.time() - 7200))[0] == 401)
check("a fresh session within the length works", call("GET", "/api/me", session(emp))[0] == 200)
call("POST", "/api/accounts/constraints", root, {"user": emp, "expires": time.time() + 2})
time.sleep(2.5)
check("account end date ends access", call("GET", "/api/me", session(emp))[0] == 401)
st, r, _ = call("POST", "/api/accounts/constraints", root, {"user": "dev", "expires": time.time() + 99})
check("root cannot be given constraints", st == 400, (st, r))
call("POST", "/api/accounts/constraints", root, {"user": emp})

# ---- profile pictures
from PIL import Image  # noqa: E402
buf = io.BytesIO()
Image.new("RGB", (640, 480), (200, 40, 30)).save(buf, "JPEG")
st, r, _ = call("POST", "/api/account/avatar", e, raw=buf.getvalue(), ctype="image/jpeg")
e = session(emp)
st, r, _ = call("POST", "/api/account/avatar", e, raw=buf.getvalue(), ctype="image/jpeg")
check("account sets its own profile picture", st == 200 and r.get("avatar"), (st, r))
st, img, h = call("GET", "/api/avatar", e)
ok_img = st == 200 and h.get("Content-Type") == "image/webp" and Image.open(io.BytesIO(img)).size == (256, 256)
check("picture is re-encoded to a 256 px WebP", ok_img, (st, h.get("Content-Type")))
check("other accounts cannot fetch it", call("GET", "/api/avatar?user=" + emp, a)[0] == 403)
check("root can fetch it", call("GET", "/api/avatar?user=" + emp, root)[0] == 200)
st, r, _ = call("POST", "/api/account/avatar", e, raw=b"<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>", ctype="image/svg+xml")
check("SVG / non-image uploads are refused", st == 400, (st, r))
st, r, _ = call("POST", "/api/account/avatar", e, raw=b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, ctype="image/png")
check("corrupt image refused", st == 400, (st, r))
check("root removes it", call("POST", "/api/accounts/avatar/delete", root, {"user": emp})[0] == 200
      and call("GET", "/api/avatar", e)[0] == 404)

# ---- synced preferences
check("preferences save", call("POST", "/api/prefs", e, {"prefs": {"theme": "dark", "syncPrefs": True}})[0] == 200)
st, r, _ = call("GET", "/api/prefs", e)
check("preferences load back", st == 200 and r["prefs"].get("theme") == "dark", r)
check("oversized preferences refused", call("POST", "/api/prefs", e, {"prefs": {"x": "y" * 70000}})[0] == 400)

for u in (emp, ana, sh, sh2):
    call("POST", "/api/accounts/delete", root, {"user": u, "storage_action": "retain"})
call("POST", "/api/serving/bl/delete", root, {"ids": [x["id"] for x in call("GET", "/api/serving", root)[1].get("blacklist", [])
                                                    if x.get("note") == "granular test"]})
failed = [n for n, ok in results if not ok]
print("\n%d checks, %d failed" % (len(results), len(failed)))
sys.exit(1 if failed else 0)
