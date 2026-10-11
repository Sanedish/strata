"""office_regress.py <dev-db> - the office (office.py): directory privacy, presence, noticeboard / notes ownership,
private notes, the administrative flag and office-only delegation, avatars, rate limit. DEV instance only
(127.0.0.1:8190, a home under a 'scratchpad' folder; uses the seeded accounts dev, mara, lena)."""
import hashlib
import json
import secrets
import sqlite3
import sys
import time
import urllib.error
import urllib.request

DB = sys.argv[1]
assert "scratchpad" in DB.replace("\\", "/")
BASE = "http://127.0.0.1:8190"
c = sqlite3.connect(DB)


def session(user):
    tok = secrets.token_urlsafe(32)
    now = time.time()
    c.execute("INSERT OR REPLACE INTO session VALUES(?,?,?,?,?,?)",
              [hashlib.sha256(tok.encode()).hexdigest(), user, now + 3600, "127.0.0.1", now, 3600])
    c.commit()
    return tok


def call(tok, method, path, body=None):
    h = {"X-Strata": "1", "Origin": BASE, "Cookie": "dev_strata_session=" + tok}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {}


ok = fail = 0


def check(name, cond, info=""):
    global ok, fail
    if cond:
        ok += 1
    else:
        fail += 1
        print("FAIL", name, info)


# make sure accounts are in a known state: mara = employee with office defaults, lena = employee read-only
for u in ("mara", "lena"):
    c.execute("UPDATE account SET enabled=1, privacy_version=(SELECT privacy_version FROM account WHERE user='dev'), "
              "administrative=0 WHERE user=?", [u])
c.execute("UPDATE account SET privacy_version='2026-10-08-v1' WHERE user IN ('dev','mara','lena')")
c.commit()
root, mara, lena = session("dev"), session("mara"), session("lena")

st, me = call(mara, "GET", "/api/me")
check("me ok", st == 200, st)
check("mara has office.view after migration", "office.view" in me.get("capabilities", []), me.get("capabilities"))
check("me has administrative False", me.get("administrative") is False)

st, o = call(mara, "GET", "/api/office")
check("office state", st == 200, o)
people = {p["user"]: p for p in o.get("people", [])}
check("dev listed", "dev" in people, list(people))
check("no permissions leak", all("permissions" not in p and "zones" not in p and "allowed_ips" not in p and "note" not in p for p in people.values()))
check("email hidden without contact", "email" not in people.get("dev", {}), people.get("dev"))
check("no manage fields for non-admin", all("office_caps" not in p for p in people.values()))

# presence
st, pr = call(mara, "POST", "/api/presence", {"tab": "t1", "state": "active"})
check("beat ok", st == 200 and pr["presence"].get("mara", {}).get("s") == "online", pr)
st, pr = call(lena, "POST", "/api/presence", {"tab": "t2", "state": "idle"})
check("lena idle", st == 200, pr)
st, pr = call(mara, "POST", "/api/presence", {"tab": "t1", "state": "active"})
check("mara sees lena idle", pr["presence"].get("lena", {}).get("s") == "idle", pr["presence"].get("lena"))
check("dev offline", pr["presence"].get("dev", {}).get("s") == "offline")

# profile
st, p = call(mara, "POST", "/api/office/profile", {"title": "Designer‮ evil", "status": "  On   holiday\n", "about": "line1\n\n\n\nline2", "show_email": True})
check("profile saved & cleaned", st == 200 and p["profile"]["title"] == "Designer evil" and p["profile"]["status"] == "On holiday" and p["profile"]["about"] == "line1\n\nline2", p)
st, o = call(lena, "GET", "/api/office")
mp = {x["user"]: x for x in o["people"]}["mara"]
check("opt-in email visible", "email" in mp, mp)

# noticeboard
st, n = call(mara, "POST", "/api/office/post", {"body": "Hello team <script>alert(1)</script>"})
check("post ok", st == 200 and n["note"]["body"].startswith("Hello"), n)
pid = n["note"]["id"]
st, bd = call(lena, "GET", "/api/office/board")
check("lena sees post", any(x["id"] == pid for x in bd["posts"]), bd)
check("lena cannot delete", not [x for x in bd["posts"] if x["id"] == pid][0]["can_delete"])
st, r = call(lena, "POST", "/api/office/post/delete", {"id": pid})
check("lena delete refused", st == 403, (st, r))
st, r = call(lena, "POST", "/api/office/post/edit", {"id": pid, "body": "hacked"})
check("lena edit refused", st == 403, (st, r))
st, r = call(lena, "POST", "/api/office/post/pin", {"id": pid, "pinned": True})
check("lena pin refused", st == 403, (st, r))
st, u = call(lena, "POST", "/api/office/seen", {"what": "board"})
check("seen ok", st == 200 and u["unread"]["board"] == 0, u)

# notes: team and private
st, n1 = call(lena, "POST", "/api/office/post", {"body": "nice work", "target": "mara"})
check("team note", st == 200, n1)
st, n2 = call(lena, "POST", "/api/office/post", {"body": "secret", "target": "mara", "private": True})
check("private note", st == 200 and n2["note"]["private"], n2)
st, nt = call(root, "GET", "/api/office/notes?user=mara")
ids = [x["id"] for x in nt["notes"]]
check("root sees team note", n1["note"]["id"] in ids, ids)
check("root does NOT see private note", n2["note"]["id"] not in ids, ids)
st, nt = call(mara, "GET", "/api/office/notes?user=mara")
check("mara sees private note to her", n2["note"]["id"] in [x["id"] for x in nt["notes"]])
check("mara can delete notes on her profile", all(x["can_delete"] for x in nt["notes"]))
st, nt = call(mara, "GET", "/api/office/notes?user=nobody")
check("unknown colleague 400", st == 400, st)
st, nt = call(mara, "POST", "/api/office/post", {"body": "x", "target": "evil1ee332"})
check("note to non-member (pending/disabled) refused", st == 400, (st, nt))

# administrative flag: only root may set it
st, r = call(mara, "POST", "/api/accounts/administrative", {"user": "lena", "administrative": True})
check("mara cannot set administrative", st == 403, (st, r))
st, r = call(root, "POST", "/api/accounts/administrative", {"user": "mara", "administrative": True})
check("root sets mara administrative", st == 200 and r["account"]["administrative"], r)
st, me = call(mara, "GET", "/api/me")
check("mara administrative + contact", me["administrative"] and "office.contact" in me["capabilities"], me.get("capabilities"))
check("administrative grants nothing outside office", "accounts.manage" not in me["capabilities"] and "serving.rules" not in me["capabilities"])
st, o = call(mara, "GET", "/api/office")
lp = {x["user"]: x for x in o["people"]}["lena"]
check("mara sees manage fields for lena", "office_caps" in lp and lp["manageable"], lp)
check("mara sees lena email now", "email" in lp)
st, r = call(mara, "POST", "/api/office/member", {"user": "lena", "caps": ["office.view"]})
check("mara narrows lena", st == 200 and r["caps"] == ["office.view"], (st, r))
st, me_l = call(lena, "GET", "/api/me")
check("lena keeps file perms", "files.read" in me_l["capabilities"] and "office.post" not in me_l["capabilities"], me_l["capabilities"])
st, r = call(lena, "POST", "/api/office/post", {"body": "can I post?"})
check("lena can no longer post", st == 403, (st, r))
st, r = call(mara, "POST", "/api/office/member", {"user": "lena", "caps": ["office.post"]})
check("caps without view refused", st == 400, (st, r))
st, r = call(mara, "POST", "/api/office/member", {"user": "lena", "caps": ["files.purge", "office.view", "accounts.manage"]})
check("cannot sneak non-office caps", st == 200 and r["caps"] == ["office.view"], (st, r))
st, me_l = call(lena, "GET", "/api/me")
check("no files.purge granted", "files.purge" not in me_l["capabilities"], me_l["capabilities"])
st, r = call(mara, "POST", "/api/office/member", {"user": "dev", "caps": []})
check("cannot change root", st == 403, (st, r))
st, r = call(mara, "POST", "/api/office/member", {"user": "mara", "caps": []})
check("cannot change self", st == 403, (st, r))
st, r = call(mara, "POST", "/api/office/member", {"user": "lena", "title": "Intern"})
check("set colleague title", st == 200 and r["profile"]["title"] == "Intern", (st, r))
st, r = call(mara, "POST", "/api/office/post/pin", {"id": pid, "pinned": True})
check("administrative pins", st == 200, (st, r))
st, r = call(mara, "POST", "/api/office/post/delete", {"id": n1["note"]["id"]})
check("administrative removes team note", st == 200, (st, r))
st, r = call(mara, "POST", "/api/office/member", {"user": "lena", "caps": ["office.view", "office.post", "office.notes"]})
check("restore lena", st == 200)

# avatars: office members may see colleagues' pictures; others not
st, _ = call(lena, "GET", "/api/avatar?user=dev")
check("avatar of colleague allowed or 404 (no picture)", st in (200, 404), st)
st, _ = call(lena, "GET", "/api/avatar?user=evil1ee332")
check("avatar of non-member refused", st == 403, st)

# rate limit
codes = [call(root, "POST", "/api/office/post", {"body": "rate test %d" % i})[0] for i in range(22)]  # root: reruns within 10 min stay limited, the rest still posts
check("rate limited", 429 in codes or codes.count(400) >= 1, codes)

# cleanup: un-administrative
call(root, "POST", "/api/accounts/administrative", {"user": "mara", "administrative": False})
print("%d checks, %d failed" % (ok + fail, fail))
sys.exit(1 if fail else 0)
