"""Alerts: security + health events, stored in SQLite, shown in the UI, e-mailed once a mail provider is configured.

Configure in strata.json (or Security › Alerts › Delivery):
    "alerts": {"from": "Strata <alerts@yourdomain>", "to": ["you@..."],
               "smtp": {"host": "smtp.example.com", "port": 587, "security": "starttls", "user": "...", "password": "..."},
               "min_severity": "warning", "max_per_hour": 12, "digest": "daily", "digest_hour": 8}
Mail goes out over SMTP when smtp.host is set (any provider or a self-hosted server), otherwise through the Resend API
("resend_api_key": "re_..."). Without either everything still works - alerts are kept in the database and listed in
the Alerts view.
"webhooks": ["https://..."] also posts each batch to Discord, Slack, ntfy (by host name) or any other URL as JSON.
"""
import collections
import html
import json
import smtplib
import ssl
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

import core
from core import CFG, connect, get_meta, log, rows_of, set_meta

SEV = {"info": 0, "warning": 1, "critical": 2}
RESEND = "https://api.resend.com/emails"
NTFY_PRIORITY = {"info": "3", "warning": "4", "critical": "5"}
SMTP_SECURITY = {"starttls": 587, "tls": 465, "none": 25}  # default port per mode


def provider(a=None):
    """'smtp', 'resend' or '' - which way e-mail leaves this server: the one chosen under Delivery ("provider"),
    or for older configs without a choice SMTP when a host is set, else Resend; '' while the chosen one lacks its setup."""
    a = CFG["alerts"] if a is None else a
    host = (a.get("smtp") or {}).get("host")
    want = a.get("provider") or ("smtp" if host else "resend")
    return ("smtp" if host else "") if want == "smtp" else ("resend" if a.get("resend_api_key") else "")


def mail_ready(a=None):
    """Sign-in codes and invitations can be sent: a provider and a sender address."""
    a = CFG["alerts"] if a is None else a
    return bool(provider(a) and a.get("from"))


def send_smtp(smtp, sender, recipients, subject, text, body_html):
    msg = EmailMessage()  # its default policy refuses line breaks in headers
    msg["From"], msg["To"], msg["Subject"] = sender, ", ".join(recipients), subject
    msg["Date"], msg["Message-ID"] = formatdate(localtime=True), make_msgid(domain=sender.rpartition("@")[2].strip("> "))
    msg.set_content(text)
    msg.add_alternative(body_html, subtype="html")
    mode = smtp.get("security") if smtp.get("security") in SMTP_SECURITY else "starttls"
    host, port = smtp["host"], int(smtp.get("port") or SMTP_SECURITY[mode])
    if mode == "none" and smtp.get("user"):
        raise RuntimeError("SMTP: a password is never sent unencrypted; use STARTTLS or TLS")
    ctx = ssl.create_default_context()
    try:
        with (smtplib.SMTP_SSL(host, port, timeout=20, context=ctx) if mode == "tls" else smtplib.SMTP(host, port, timeout=20)) as c:
            if mode == "starttls":
                c.starttls(context=ctx)
            if smtp.get("user"):
                c.login(smtp["user"], smtp.get("password") or "")
            c.send_message(msg)
    except (smtplib.SMTPException, OSError) as e:
        raise RuntimeError("SMTP %s:%s: %s" % (host, port, e))


def hook_kind(url):
    # ponytail: picked by host name; a self-hosted ntfy needs "ntfy" in its host name, everything else gets JSON
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    if host in ("discord.com", "discordapp.com"):
        return "discord"
    if host == "hooks.slack.com":
        return "slack"
    if host == "ntfy.sh" or "ntfy" in host.split(".")[0]:
        return "ntfy"
    return "json"


def post_hook(url, title, text, severity="warning"):
    """One webhook POST in the format its service expects. Raises on any failure."""
    kind = hook_kind(url)
    headers = {"User-Agent": "Strata/1", "Content-Type": "application/json"}
    if kind == "ntfy":
        data = text.encode()
        headers.update({"Content-Type": "text/plain; charset=utf-8", "Title": title.encode("ascii", "replace").decode(),
                        "Priority": NTFY_PRIORITY.get(severity, "3")})
    elif kind == "discord":
        data = json.dumps({"content": ("**%s**\n%s" % (title, text))[:2000]}).encode()
    elif kind == "slack":
        data = json.dumps({"text": "*%s*\n%s" % (title, text)}).encode()
    else:  # title + message also suit Gotify, Home Assistant and n8n
        data = json.dumps({"title": title, "message": text, "severity": severity, "source": "strata"}).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=headers, method="POST"), timeout=15) as r:
            r.read(1024)
    except urllib.error.HTTPError as e:
        raise RuntimeError("%s webhook answered %s" % (kind, e.code))


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
        return bool(mail_ready(a) and a.get("to"))

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
        if provider(a) == "smtp":
            send_smtp(a["smtp"], a["from"], list(recipients or []), subject, text, body_html)
            self.sent.append(now)
            return
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

    def hooks(self):
        return [u for u in CFG["alerts"].get("webhooks") or [] if u]

    def notify(self, subject, text, body_html, severity="warning"):
        """E-mail and every webhook; one channel failing doesn't stop the others. Raises only if all of them fail."""
        errors, sent = [], 0
        for url in self.hooks():
            try:
                post_hook(url, subject, text, severity)
                sent += 1
            except Exception as e:
                errors.append("%s: %s" % (urllib.parse.urlsplit(url).hostname, e))
        if self.configured():
            try:
                self.send(subject, text, body_html)
                sent += 1
            except Exception as e:
                errors.append("e-mail: %s" % e)
        for e in errors:
            log("alert delivery failed: %s" % e)
        if errors and not sent:
            raise RuntimeError("; ".join(errors))
        return sent

    def deliver(self):
        if not (self.configured() or self.hooks()):
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
            top = max((r["severity"] for r in todo), key=lambda v: SEV.get(v, 0))
            self.notify(subject, text, "<div style='font-family:sans-serif'>%s</div>" % body, top)
            with db:
                db.executemany("UPDATE alert SET sent=1 WHERE id=?", [(r["id"],) for r in rows])
        except Exception as e:
            log("alert delivery failed: %s" % e)
        finally:
            db.close()

    def digest(self):
        a = CFG["alerts"]
        if not (self.configured() or self.hooks()) or a.get("digest") not in ("daily", "weekly"):
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
            self.notify("[Strata] %s report" % ("Weekly" if span > 86400 else "Daily"), "\n".join(lines),
                        "<div style='font-family:sans-serif'><h3>Strata %s report</h3><p>%s</p></div>" % (
                            "weekly" if span > 86400 else "daily", "<br>".join(html.escape(l) for l in lines)), "info")
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
    smtp = a.get("smtp") or {}
    return {"alerts": rows, "open": dict(open_), "config": {
        "configured": bool(mail_ready(a) and a.get("to")), "provider": provider(a), "choice": a.get("provider") or "",
        "key_set": bool(a.get("resend_api_key")), "from": a.get("from", ""), "to": a.get("to", []),
        "smtp": {"host": smtp.get("host", ""), "port": smtp.get("port") or "", "security": smtp.get("security") or "starttls",
                 "user": smtp.get("user", ""), "password_set": bool(smtp.get("password"))},
        "min_severity": a.get("min_severity"), "digest": a.get("digest"), "digest_hour": a.get("digest_hour"),
        "max_per_hour": a.get("max_per_hour"),
        # the URLs carry their own secret (Discord, Slack): only host and format leave the server
        "webhooks": [{"host": urllib.parse.urlsplit(u).hostname, "kind": hook_kind(u)} for u in a.get("webhooks") or []]}}


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
