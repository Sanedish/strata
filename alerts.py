"""Alerts: security + health events, stored in SQLite, shown in the UI, e-mailed through Resend once configured.

Configure in strata.json (or Security › Alerts › Delivery):
    "alerts": {"resend_api_key": "re_...", "from": "Strata <alerts@yourdomain>", "to": ["you@..."],
               "min_severity": "warning", "max_per_hour": 12, "digest": "daily", "digest_hour": 8}
Without a key everything still works - alerts are kept in the database and listed in the Alerts view.
"""
import collections
import html
import json
import threading
import time
import traceback
import urllib.error
import urllib.request

import core
from core import CFG, connect, get_meta, log, rows_of, set_meta

SEV = {"info": 0, "warning": 1, "critical": 2}
RESEND = "https://api.resend.com/emails"


class Alerts(threading.Thread):
    daemon = True

    def __init__(self, metrics, probes, live):
        super().__init__(name="alerts")
        self.metrics, self.probes, self.live = metrics, probes, live
        self.lock = threading.Lock()
        self.login_fails = collections.defaultdict(collections.deque)
        self.state = {}  # last known up/down per component
        self.sent = collections.deque()

    # -- raising
    def raise_(self, kind, severity, title, detail="", key=None, coalesce_minutes=30):
        key = key or "%s:%s" % (kind, title)
        db = connect()
        try:
            with db:
                row = db.execute("SELECT id FROM alert WHERE key=? AND ts > ? ORDER BY id DESC LIMIT 1",
                                 [key, time.time() - coalesce_minutes * 60]).fetchone()
                if row:
                    return None
                cur = db.execute("INSERT INTO alert(ts,kind,severity,title,detail,key) VALUES(?,?,?,?,?,?)",
                                 [time.time(), kind, severity, title[:200], detail[:2000], key[:200]])
                return cur.lastrowid
        finally:
            db.close()

    hook = raise_  # signature used by rules.ALERT_HOOK

    def login_failed(self, ip, user):
        with self.lock:
            q = self.login_fails[ip]
            q.append(time.time())
            while q and q[0] < time.time() - 600:
                q.popleft()
            n = len(q)
        if n in (5, 20, 100):
            self.raise_("login", "warning" if n < 20 else "critical", "%d failed logins from %s" % (n, ip),
                        "Last attempted user name: %r. The address is locked out after 8 failures in 15 minutes." % user[:40],
                        "loginfail:%s:%d" % (ip, n))

    def login_ok(self, ip, user):
        db = connect()
        try:
            seen = db.execute("SELECT 1 FROM audit WHERE action='login' AND ok=1 AND ip=? AND ts < ? LIMIT 1",
                              [ip, time.time() - 5]).fetchone()
        finally:
            db.close()
        if not seen:
            self.raise_("login", "info", "New sign-in from %s" % ip, "User %s signed in from an address not seen before." % user,
                        "newip:%s" % ip, coalesce_minutes=24 * 60)

    # -- periodic checks
    def transition(self, comp, up, title_down, title_up, detail="", severity="critical"):
        prev = self.state.get(comp)
        self.state[comp] = up
        if prev is None or prev == up:
            return
        if up:
            self.raise_("health", "info", title_up, detail, "%s:up:%d" % (comp, time.time() // 60), 0)
        else:
            self.raise_("health", severity, title_down, detail, "%s:down:%d" % (comp, time.time() // 60), 0)

    def checks(self):
        snap = self.metrics.snapshot()
        c, t = snap["caddy"], snap["tunnel"]
        self.transition("caddy", bool(c.get("up")), "Caddy is not responding", "Caddy is back", c.get("error", ""))
        self.transition("tunnel", bool(t.get("up")) and (t.get("ha") or 0) > 0, "Cloudflare tunnel is down",
                        "Cloudflare tunnel is back", t.get("error", ""))
        if t.get("up") and 0 < (t.get("ha") or 0) < 4:
            self.raise_("health", "warning", "Tunnel degraded: %d of 4 edge connections" % t["ha"], "", "tunnel-degraded", 60)
        p = self.probes.snapshot()
        for s in p["storage"][:-1] if len(p["storage"]) > 1 else p["storage"]:
            self.transition("store:" + s["path"], bool(s["ok"]), "Storage offline: %s" % s["path"],
                            "Storage back online: %s" % s["path"], s.get("error", ""))
            if s.get("total") and s["free"] / s["total"] < 0.08:
                self.raise_("health", "warning", "Low disk space on %s" % s["path"], "%.1f %% free (%d GB)" % (
                    s["free"] / s["total"] * 100, s["free"] // 2 ** 30), "lowdisk:" + s["path"], 12 * 60)
        for o in p["origins"]:
            if o.get("ok") is not None:
                self.transition("origin:" + o["hostname"], bool(o["ok"]), "Service down: %s" % o["hostname"],
                                "Service back: %s" % o["hostname"], o.get("error", ""), "warning")
        w = self.live.window(300)  # err_pct leaves probes, blacklisted and suspect clients out
        if w["clean"] >= 50 and w["err_pct"] > 30:
            self.raise_("traffic", "warning", "High error rate: %.0f %% of requests failed in 5 minutes" % w["err_pct"],
                        "%d requests in the last 5 minutes (plus %d from scanners and other suspicious clients, not "
                        "counted). Check the Security and Requests views." % (w["clean"], w["sus"]), "errspike", 60)

    # -- delivery
    def configured(self):
        a = CFG["alerts"]
        return bool(a.get("resend_api_key") and a.get("from") and a.get("to"))

    def send(self, subject, text, body_html):
        a = CFG["alerts"]
        return self.send_to(a["to"], subject, text, body_html)

    def send_to(self, recipients, subject, text, body_html):
        a = CFG["alerts"]
        now = time.time()
        while self.sent and self.sent[0] < now - 3600:
            self.sent.popleft()
        if len(self.sent) >= int(a.get("max_per_hour") or 12):
            raise RuntimeError("hourly e-mail limit reached")
        req = urllib.request.Request(RESEND, method="POST", data=json.dumps({
            "from": a["from"], "to": list(recipients or []), "subject": subject, "text": text, "html": body_html}).encode(),
            headers={"Authorization": "Bearer " + a["resend_api_key"], "Content-Type": "application/json",
                     "User-Agent": "Strata/1"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                r.read()
        except urllib.error.HTTPError as e:
            raise RuntimeError("Resend %s: %s" % (e.code, e.read()[:200].decode("utf-8", "replace")))
        self.sent.append(now)

    def deliver(self):
        if not self.configured():
            return
        minsev = SEV.get(CFG["alerts"].get("min_severity"), 1)
        db = connect()
        try:
            rows = rows_of(db.execute("SELECT * FROM alert WHERE sent=0 AND ts > ? ORDER BY id LIMIT 20",
                                      [time.time() - 6 * 3600]))
            todo = [r for r in rows if SEV.get(r["severity"], 0) >= minsev]
            if not todo:
                if rows:
                    with db:
                        db.executemany("UPDATE alert SET sent=2 WHERE id=?", [(r["id"],) for r in rows])
                return
            subject = ("[Strata] " + todo[0]["title"]) if len(todo) == 1 else "[Strata] %d alerts: %s" % (len(todo), todo[0]["title"])
            text = "\n\n".join("%s  [%s] %s\n%s" % (time.strftime("%Y-%m-%d %H:%M", time.localtime(r["ts"])),
                                                    r["severity"].upper(), r["title"], r["detail"]) for r in todo)
            body = "".join("<p><b>[%s] %s</b><br><small>%s</small><br>%s</p>" % (
                html.escape(r["severity"].upper()), html.escape(r["title"]),
                time.strftime("%Y-%m-%d %H:%M", time.localtime(r["ts"])), html.escape(r["detail"])) for r in todo)
            self.send(subject, text, "<div style='font-family:sans-serif'>%s</div>" % body)
            with db:
                db.executemany("UPDATE alert SET sent=1 WHERE id=?", [(r["id"],) for r in rows])
        except Exception as e:
            log("alert delivery failed: %s" % e)
        finally:
            db.close()

    def digest(self):
        a = CFG["alerts"]
        if not self.configured() or a.get("digest") not in ("daily", "weekly"):
            return
        lt = time.localtime()
        if lt.tm_hour != int(a.get("digest_hour", 8)) or (a["digest"] == "weekly" and lt.tm_wday != 0):
            return
        db = connect()
        try:
            last = get_meta(db, "digest_sent", 0) or 0
            if time.time() - last < 20 * 3600:
                return
            span = 7 * 86400 if a["digest"] == "weekly" else 86400
            st = core.q_stats({"range": "7d" if span > 86400 else "24h"})
            t = st["totals"]
            al = db.execute("SELECT severity, count(*) FROM alert WHERE ts > ? GROUP BY severity", [time.time() - span]).fetchall()
            bans = db.execute("SELECT count(*) FROM blacklist WHERE created > ?", [time.time() - span]).fetchone()[0]
            with db:
                set_meta(db, "digest_sent", time.time())
        finally:
            db.close()
        lines = ["Requests: %d" % t["reqs"], "Data served: %.2f GB" % (t["bytes"] / 2 ** 30), "Visitors: %d" % t["uniq"],
                 "Errors: %d 4xx, %d 5xx" % (t["e4"], t["e5"]), "Probe requests: %d" % t["scans"],
                 "Suspicious requests (not in the error counts): %d from %d addresses" % (t["sus"], t["sus_ips"]),
                 "New blacklist entries: %d" % bans,
                 "Alerts: " + (", ".join("%d %s" % (n, s) for s, n in al) or "none")]
        try:
            self.send("[Strata] %s report" % ("Weekly" if span > 86400 else "Daily"), "\n".join(lines),
                      "<div style='font-family:sans-serif'><h3>Strata %s report</h3><p>%s</p></div>" % (
                          "weekly" if span > 86400 else "daily", "<br>".join(html.escape(l) for l in lines)))
        except Exception as e:
            log("digest failed: %s" % e)

    def run(self):
        time.sleep(30)
        while True:
            try:
                self.checks()
                self.deliver()
                self.digest()
            except Exception:
                log("alerts error:\n" + traceback.format_exc())
            time.sleep(30)


def q_alerts(q):
    db = connect()
    try:
        rows = rows_of(db.execute("SELECT * FROM alert ORDER BY id DESC LIMIT ?", [max(10, min(500, int(q.get("limit", 200))))]))
        open_ = db.execute("SELECT severity, count(*) FROM alert WHERE ack=0 GROUP BY severity").fetchall()
    finally:
        db.close()
    a = CFG["alerts"]
    return {"alerts": rows, "open": dict(open_), "config": {
        "configured": bool(a.get("resend_api_key") and a.get("from") and a.get("to")),
        "key_set": bool(a.get("resend_api_key")), "from": a.get("from", ""), "to": a.get("to", []),
        "min_severity": a.get("min_severity"), "digest": a.get("digest"), "digest_hour": a.get("digest_hour"),
        "max_per_hour": a.get("max_per_hour")}}


def ack(ids):
    db = connect()
    try:
        with db:
            if ids == "all":
                db.execute("UPDATE alert SET ack=1 WHERE ack=0")
            else:
                db.executemany("UPDATE alert SET ack=1 WHERE id=?", [(int(i),) for i in ids])
    finally:
        db.close()
    return {"ok": True}
