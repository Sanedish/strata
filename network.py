"""Network: Cloudflare zone settings + DNS, the cloudflared tunnel (ingress, restart) and "expose a service".

Everything Cloudflare goes through cloudflare.call() with this instance's API token. What the token may do is probed
(read endpoints) or learnt from the last write attempt, and shown per feature, so a missing permission is a clear
"add Zone > DNS > Edit to the token", never a stack trace.

The tunnel's config.yml (instance cloudflared_config) is edited conservatively: only the `ingress:` list is rewritten,
each rule keeps its own lines (comments, originRequest blocks), every candidate is checked with
`cloudflared tunnel --config <candidate> ingress validate` before it replaces the file, and the previous file is kept
as config.yml.<timestamp>.bak. cloudflared only reads its config at start, so a change ends with a tunnel restart
(instance.tunnel_restart: {"kind": "task" | "service", "name": ...}).
"""
import base64
import json
import os
import re
import subprocess
import threading
import time
import urllib.parse

import cloudflare
import core
import rules
from cloudflare import CFError, call, zone_id
from core import CFG, connect, get_meta, log, set_meta

NOWIN = getattr(subprocess, "CREATE_NO_WINDOW", 0)
API_PERMS = {
    "zone": "Zone › Zone › Read",
    "settings_read": "Zone › Zone Settings › Read",
    "settings": "Zone › Zone Settings › Edit",
    "dns_read": "Zone › DNS › Read",
    "dns": "Zone › DNS › Edit",
    "purge": "Zone › Cache Purge › Purge",
    "lists": "Account › Account Filter Lists › Edit",
    "waf": "Zone › Zone WAF › Edit",
    "transform": "Zone › Transform Rules › Edit",
    "analytics": "Zone › Analytics › Read",
}
# zone settings the dashboard offers: id -> (label, kind, choices / unit, help)
SETTINGS = {
    "ssl": ("SSL/TLS mode", "choice", ["off", "flexible", "full", "strict"],
            "How Cloudflare talks to your origin. Tunnels are encrypted end to end; 'full' is the usual choice."),
    "always_use_https": ("Always use HTTPS", "toggle", None, "Redirect every http:// request to https://."),
    "min_tls_version": ("Minimum TLS version", "choice", ["1.0", "1.1", "1.2", "1.3"], "Oldest TLS clients may use."),
    "tls_1_3": ("TLS 1.3", "choice", ["on", "off", "zrt"], "zrt = TLS 1.3 with 0-RTT resumption."),
    "automatic_https_rewrites": ("Automatic HTTPS rewrites", "toggle", None, "Rewrite http:// links in HTML to https://."),
    "security_level": ("Security level", "choice", ["essentially_off", "low", "medium", "high", "under_attack"],
                       "How eagerly visitors with a bad IP reputation are challenged. under_attack = I'm Under Attack mode."),
    "browser_check": ("Browser integrity check", "toggle", None, "Challenge requests with suspicious headers."),
    "challenge_ttl": ("Challenge passage", "choice", [300, 900, 1800, 2700, 3600, 7200, 10800, 14400, 28800, 57600, 86400],
                      "Seconds a solved challenge stays valid."),
    "development_mode": ("Development mode", "toggle", None, "Bypass Cloudflare's cache for 3 hours (switches itself off)."),
    "cache_level": ("Caching level", "choice", ["basic", "simplified", "aggressive"],
                    "How query strings take part in the cache key (aggressive = standard)."),
    "browser_cache_ttl": ("Browser cache TTL", "choice", [0, 1800, 3600, 7200, 14400, 28800, 86400, 604800, 2678400, 16070400],
                          "0 = respect the origin's headers (recommended: Strata sets revalidation per drive)."),
    "always_online": ("Always Online", "toggle", None, "Serve archived copies when the origin is down."),
    "http3": ("HTTP/3 (QUIC)", "toggle", None, "Offer HTTP/3 to visitors."),
    "0rtt": ("0-RTT resumption", "toggle", None, "Faster repeat TLS handshakes."),
    "ipv6": ("IPv6", "toggle", None, "Answer on IPv6 at the edge."),
    "websockets": ("WebSockets", "toggle", None, "Allow WebSocket connections (services behind the gate may need them)."),
    "early_hints": ("Early Hints", "toggle", None, "Send 103 Early Hints from cached Link headers."),
    "email_obfuscation": ("Email obfuscation", "toggle", None, "Hide e-mail addresses in HTML from scrapers."),
    "hotlink_protection": ("Hotlink protection (zone)", "toggle", None, "Cloudflare's own image hotlink block (Strata has per-folder rules)."),
    "opportunistic_encryption": ("Opportunistic encryption", "toggle", None, "Advertise HTTPS to HTTP/2 clients."),
    "rocket_loader": ("Rocket Loader", "toggle", None, "Async JavaScript loading - can break pages; usually off for a CDN."),
}
DNS_TYPES = ("A", "AAAA", "CNAME", "TXT", "MX")
HOST_LABEL = re.compile(r"^(?:\*|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$")
_cache = {"settings": (0, None), "dns": (0, None)}
_lock = threading.Lock()


class NetError(Exception):
    pass


def _seen(kind, ok, err=""):
    """Remember whether the last attempt of a permission-gated action worked (writes cannot be probed safely)."""
    db = connect()
    try:
        with db:
            caps = get_meta(db, "net_caps", {}) or {}
            caps[kind] = {"ok": ok, "error": err[:300], "ts": time.time()}
            set_meta(db, "net_caps", caps)
    finally:
        db.close()


def _try(path):
    try:
        return call("GET", path), None
    except CFError as e:
        return None, e


def status():
    """Token permission matrix: read endpoints are probed, write permissions come from the last attempt."""
    out = {"token": bool(CFG["cloudflare"].get("api_token")), "zone_name": CFG["cloudflare"].get("zone_name"),
           "perms": API_PERMS, "caps": {}}
    if not out["token"]:
        return out
    db = connect()
    try:
        seen = get_meta(db, "net_caps", {}) or {}
    finally:
        db.close()
    caps = out["caps"]
    try:
        out["zone_id"] = zone_id()
        caps["zone"] = {"ok": True}
    except CFError as e:
        caps["zone"] = {"ok": False, "error": str(e)}
        return out
    z = out["zone_id"]
    for k, path in (("settings_read", "/zones/%s/settings/ssl" % z), ("dns_read", "/zones/%s/dns_records?per_page=1" % z)):
        _, err = _try(path)
        caps[k] = {"ok": err is None, "error": str(err) if err else ""}
    for k in ("settings", "dns"):
        caps[k] = seen.get(k) or {"ok": None}
    return out


# ---------------------------------------------------------------- zone settings

def settings(force=False):
    with _lock:
        t, v = _cache["settings"]
        if v is not None and time.time() - t < 60 and not force:
            return v
    z = zone_id()
    r = call("GET", "/zones/%s/settings" % z)
    have = {s["id"]: s for s in r.get("result") or []}
    out = []
    for sid, (label, kind, choices, help_) in SETTINGS.items():
        s = have.get(sid)
        if not s:
            continue
        out.append({"id": sid, "label": label, "kind": kind, "choices": choices, "help": help_, "value": s.get("value"),
                    "editable": s.get("editable", True), "modified": s.get("modified_on"),
                    "remaining": s.get("time_remaining")})
    v = {"settings": out, "fetched": time.time()}
    with _lock:
        _cache["settings"] = (time.time(), v)
    return v


def set_setting(sid, value):
    if sid not in SETTINGS:
        raise NetError("unknown setting %s" % sid)
    label, kind, choices, _ = SETTINGS[sid]
    if kind == "toggle":
        value = "on" if value in (True, 1, "1", "on", "true") else "off"
    elif choices and value not in choices and str(value) not in [str(c) for c in choices]:
        raise NetError("%s: choose one of %s" % (label, ", ".join(str(c) for c in choices)))
    if choices and all(isinstance(c, int) for c in choices):
        value = int(value)
    try:
        r = call("PATCH", "/zones/%s/settings/%s" % (zone_id(), sid), {"value": value})
        _seen("settings", True)
    except CFError as e:
        _seen("settings", False, str(e))
        if e.status in (401, 403):
            raise NetError("the API token may not change zone settings - add %s" % API_PERMS["settings"])
        raise
    with _lock:
        _cache["settings"] = (0, None)
    return {"id": sid, "value": (r.get("result") or {}).get("value", value)}


# ---------------------------------------------------------------- DNS

def dns_list(force=False):
    with _lock:
        t, v = _cache["dns"]
        if v is not None and time.time() - t < 30 and not force:
            return v
    z = zone_id()
    recs, page = [], 1
    while page <= 20:
        r = call("GET", "/zones/%s/dns_records?per_page=500&page=%d" % (z, page))
        recs += r.get("result") or []
        info = r.get("result_info") or {}
        if page >= (info.get("total_pages") or 1):
            break
        page += 1
    tid = tunnel_id()
    out = [{"id": x["id"], "type": x["type"], "name": x["name"], "content": x.get("content", ""),
            "proxied": x.get("proxied"), "ttl": x.get("ttl"), "comment": x.get("comment") or "",
            "priority": x.get("priority"),
            "tunnel": (x.get("content") or "").split(".")[0] if (x.get("content") or "").endswith(".cfargotunnel.com") else "",
            "mine": bool(tid) and (x.get("content") or "").startswith(tid + "."), "modified": x.get("modified_on")}
           for x in recs]
    v = {"records": sorted(out, key=lambda r: (r["name"], r["type"])), "tunnel_id": tid, "fetched": time.time()}
    with _lock:
        _cache["dns"] = (time.time(), v)
    return v


def clean_record(d):
    typ = str(d.get("type") or "").upper()
    if typ not in DNS_TYPES:
        raise NetError("record type must be one of %s" % ", ".join(DNS_TYPES))
    zone = CFG["cloudflare"]["zone_name"].lower()
    name = str(d.get("name") or "").strip().lower().rstrip(".")
    if name in ("", "@"):
        name = zone
    elif not name.endswith(zone):
        name = name + "." + zone
    if not HOST_LABEL.match(name):
        raise NetError("invalid record name: %s" % name)
    content = str(d.get("content") or "").strip()
    if not content or len(content) > 2048 or re.search(r"[\r\n]", content):
        raise NetError("content is required (one line)")
    import ipaddress
    if typ in ("A", "AAAA"):
        try:
            ip = ipaddress.ip_address(content)
        except ValueError:
            raise NetError("%s records point at an IP address" % typ)
        if (typ == "A") != (ip.version == 4):
            raise NetError("A needs IPv4, AAAA needs IPv6")
    if typ in ("CNAME", "MX") and not HOST_LABEL.match(content.lower().rstrip(".")):
        raise NetError("%s points at a hostname" % typ)
    try:
        ttl = 1 if d.get("proxied") else int(d.get("ttl") or 1)
        prio = int(d.get("priority") or 10)
    except (TypeError, ValueError):
        raise NetError("TTL and priority are whole numbers")
    body = {"type": typ, "name": name, "content": content, "ttl": ttl,
            "comment": str(d.get("comment") or "")[:100]}
    if typ in ("A", "AAAA", "CNAME"):
        body["proxied"] = bool(d.get("proxied", True))
    if typ == "MX":
        body["priority"] = prio
    return body


def _dns_write(method, path, body=None):
    try:
        r = call(method, path, body)
        _seen("dns", True)
    except CFError as e:
        _seen("dns", False, str(e))
        if e.status in (401, 403):
            raise NetError("the API token may not change DNS - add %s (or use the tunnel's own login, see Tunnel)"
                           % API_PERMS["dns"])
        raise
    with _lock:
        _cache["dns"] = (0, None)
    return r.get("result") or {}


def dns_save(d):
    body = clean_record(d)
    if d.get("id"):
        return _dns_write("PUT", "/zones/%s/dns_records/%s" % (zone_id(), d["id"]), body)
    return _dns_write("POST", "/zones/%s/dns_records" % zone_id(), body)


def dns_delete(rid):
    if not re.fullmatch(r"[0-9a-f]{32}", str(rid or "")):
        raise NetError("bad record id")
    return _dns_write("DELETE", "/zones/%s/dns_records/%s" % (zone_id(), rid))


def route_dns(hostname):
    """CNAME hostname -> <tunnel>.cfargotunnel.com, proxied. API first; without DNS permission cloudflared's own
    `tunnel route dns` (uses the origin certificate) when that certificate belongs to this zone."""
    tid = tunnel_id()
    if not tid:
        raise NetError("no tunnel id in %s" % CFG["cloudflared_config"])
    target = "%s.cfargotunnel.com" % tid
    try:
        recs = dns_list(force=True)["records"]
        same = [r for r in recs if r["name"] == hostname]
        if any(r["type"] == "CNAME" and r["content"] == target for r in same):
            return {"dns": "exists", "via": "api"}
        if same:
            raise NetError("%s already has DNS records (%s) - change them in DNS first" % (
                hostname, ", ".join("%s %s" % (r["type"], r["content"]) for r in same)))
        _dns_write("POST", "/zones/%s/dns_records" % zone_id(), {"type": "CNAME", "name": hostname, "content": target,
                                                                "proxied": True, "ttl": 1, "comment": "Strata: tunnel"})
        return {"dns": "created", "via": "api"}
    except (NetError, CFError) as e:
        cert = cert_zone()
        if cert and cert.get("zone_id") == CFG["cloudflare"].get("zone_id"):
            code, out = cloudflared("tunnel", "route", "dns", tid, hostname)
            if code == 0:
                return {"dns": "created", "via": "cloudflared"}
            raise NetError("DNS: %s; cloudflared route dns failed too: %s" % (e, out[-300:]))
        raise


def cert_zone():
    """Which zone the origin certificate (cert.pem next to the config / in ~/.cloudflared) belongs to."""
    for p in (os.path.join(os.path.dirname(CFG["cloudflared_config"]), "cert.pem"),
              os.path.expanduser("~/.cloudflared/cert.pem")):
        try:
            text = open(p, encoding="ascii", errors="ignore").read()
        except OSError:
            continue
        m = re.search(r"-----BEGIN ARGO TUNNEL TOKEN-----(.+?)-----END", text, re.S)
        if m:
            try:
                tok = json.loads(base64.b64decode("".join(m.group(1).split())))
                return {"path": p, "zone_id": tok.get("zoneID"), "account_id": tok.get("accountID")}
            except (ValueError, TypeError):
                pass
    return None


# ---------------------------------------------------------------- tunnel (cloudflared config.yml)

def cloudflared(*args, timeout=60):
    exe = CFG.get("cloudflared_exe") or "cloudflared"
    try:
        r = subprocess.run([exe] + list(args), capture_output=True, text=True, timeout=timeout, creationflags=NOWIN)
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, str(e)
    return r.returncode, ((r.stdout or "") + (r.stderr or "")).strip()


def read_config():
    path = CFG["cloudflared_config"]
    try:
        with open(path, encoding="utf-8-sig") as f:
            return path, f.read()
    except OSError as e:
        raise NetError("Could not read the tunnel configuration at %s. Check the cloudflared_config path and file permissions." % path) from e


def tunnel_id():
    try:
        _, text = read_config()
    except (OSError, NetError):
        return ""
    m = re.search(r"^tunnel:\s*([0-9a-f-]{36})\s*$", text, re.M)
    return m.group(1) if m else ""


def parse_ingress(text):
    """(head, items, tail): head = everything up to and including `ingress:`; items = one dict per rule with its raw
    lines (comments directly above a rule belong to it); tail = what follows the list."""
    lines = text.splitlines(keepends=True)
    start = next((i for i, l in enumerate(lines) if re.match(r"^ingress:\s*(#.*)?$", l)), None)
    if start is None:
        raise NetError("config.yml has no top-level `ingress:` list")
    items, cur, pend, end = [], None, [], len(lines)
    indent = None
    for i in range(start + 1, len(lines)):
        l = lines[i]
        s = l.strip()
        if s and not l[0].isspace() and not s.startswith("#"):
            end = i
            break
        m = re.match(r"^(\s*)-\s", l)
        if m and (indent is None or len(m.group(1)) == indent):
            indent = len(m.group(1))
            cur = {"lines": pend + [l]}
            pend = []
            items.append(cur)
        elif cur is not None and (not s or s.startswith("#")) and not l.startswith(" " * ((indent or 0) + 2)):
            pend.append(l)  # blank / comment between rules: belongs to the next rule
        elif cur is not None:
            cur["lines"].append(l)
        else:
            pend.append(l)
    tail_lines = pend + lines[end:]
    for it in items:
        body = "".join(it["lines"])
        h = re.search(r"hostname:\s*['\"]?([^\s'\"#]+)", body)
        s = re.search(r"service:\s*['\"]?([^\s'\"#]+)", body)
        p = re.search(r"\bpath:\s*['\"]?([^\s'\"#]+)", body)
        it.update(hostname=h.group(1) if h else "", service=s.group(1) if s else "", path=p.group(1) if p else "",
                  extra=bool(re.search(r"originRequest:", body)))
    return "".join(lines[:start + 1]), items, "".join(tail_lines)


def render_rule(hostname, service, path="", indent=2):
    pad = " " * indent
    out = "%s- hostname: %s\n" % (pad, hostname)
    if path:
        out += "%s  path: %s\n" % (pad, path)
    return out + "%s  service: %s\n" % (pad, service)


SERVICE_RE = re.compile(r"^(https?|tcp|ssh|rdp|unix|http_status):\S+$|^hello_world$")


def ingress():
    try:
        path, text = read_config()
        _, items, _ = parse_ingress(text)
    except NetError as e:
        return {"available": False, "error": str(e), "path": CFG["cloudflared_config"], "rules": []}
    return {"path": path, "tunnel_id": tunnel_id(), "cdn": cdn_service(),
            "rules": [{"i": i, "hostname": it["hostname"] or "*", "service": it["service"], "path": it["path"],
                       "extra": it["extra"], "catchall": not it["hostname"]} for i, it in enumerate(items)],
            "restart": CFG["instance"].get("tunnel_restart") or {}, "raw": text}


def cdn_service():
    port = (CFG["instance"].get("cdn_listen") or ":8080").rsplit(":", 1)[-1]
    return "http://localhost:%s" % port


def write_ingress(items_fn, user, reason):
    """Apply items_fn(items) -> items, validate the candidate with cloudflared, keep a backup, replace the file."""
    path, text = read_config()
    head, items, tail = parse_ingress(text)
    items = items_fn(items)
    if not items or items[-1]["hostname"]:
        raise NetError("the last ingress rule must be a catch-all (service: http_status:404)")
    if any(not it["hostname"] for it in items[:-1]):
        raise NetError("only the last ingress rule may be a catch-all")
    new = head + "".join("".join(it["lines"]) for it in items) + tail
    if new == text:
        return {"changed": False}
    cand = path + ".candidate"
    with open(cand, "w", encoding="utf-8") as f:
        f.write(new)
    try:
        code, out = cloudflared("tunnel", "--config", cand, "ingress", "validate")
        if code != 0:
            raise NetError("cloudflared rejected the ingress: %s" % out[-400:])
        bak = "%s.%s.bak" % (path, time.strftime("%Y%m%d-%H%M%S"))
        with open(bak, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(cand, path)
    finally:
        if os.path.exists(cand):
            os.remove(cand)
    core.audit("", user, "tunnel-ingress", reason)
    log("tunnel: ingress changed (%s) by %s, backup %s" % (reason, user, bak))
    return {"changed": True, "backup": bak}


def ingress_add(user, hostname, service, path=""):
    hostname = hostname.strip().lower()
    if not HOST_LABEL.match(hostname) or "." not in hostname:
        raise NetError("invalid hostname")
    service = (service or cdn_service()).strip()
    if not SERVICE_RE.match(service):
        raise NetError("service must look like http://localhost:8080 or http_status:404")
    if path and (not path.startswith("/") or re.search(r"\s", path)):
        raise NetError("path must start with /")

    def fn(items):
        if any(it["hostname"] == hostname and it["path"] == path for it in items):
            raise NetError("%s already has an ingress rule" % hostname)
        rule = {"lines": [render_rule(hostname, service, path, indent=_item_indent(items))], "hostname": hostname,
                "service": service, "path": path}
        return items[:-1] + [rule] + items[-1:] if items and not items[-1]["hostname"] else items + [rule]
    return write_ingress(fn, user, "add %s -> %s" % (hostname, service))


def _item_indent(items):
    for it in items:
        for l in it["lines"]:
            m = re.match(r"^(\s*)-\s", l)
            if m:
                return len(m.group(1))
    return 2


def ingress_delete(user, index):
    def fn(items):
        i = int(index)
        if not 0 <= i < len(items) - 1:
            raise NetError("that rule cannot be removed (the catch-all stays last)")
        return items[:i] + items[i + 1:]
    return write_ingress(fn, user, "remove rule #%s" % index)


def ingress_move(user, index, delta):
    def fn(items):
        i, j = int(index), int(index) + (1 if int(delta) > 0 else -1)
        if not (0 <= i < len(items) - 1 and 0 <= j < len(items) - 1):
            raise NetError("rules move within the list; the catch-all stays last")
        items[i], items[j] = items[j], items[i]
        return items
    return write_ingress(fn, user, "move rule #%s" % index)


def ingress_test(url):
    path, _ = read_config()
    if not re.match(r"^https?://[^\s]+$", url or ""):
        raise NetError("enter a full URL, e.g. https://app.%s/" % CFG["cloudflare"].get("zone_name", "example.com"))
    code, out = cloudflared("tunnel", "--config", path, "ingress", "rule", url)
    return {"ok": code == 0, "output": out[-1500:]}


def restart_tunnel(user):
    """Restart cloudflared as configured (instance.tunnel_restart). A short blip for every tunnel hostname."""
    r = CFG["instance"].get("tunnel_restart") or {}
    kind, name = r.get("kind"), r.get("name")
    if CFG["instance"].get("dry_run"):
        return {"restarted": False, "note": "dry run instance: tunnel not restarted"}
    if not name or kind not in ("task", "service"):
        raise NetError("set instance.tunnel_restart in strata.json ({\"kind\": \"task\"|\"service\", \"name\": ...})")
    if kind == "task":
        subprocess.run(["schtasks", "/End", "/TN", name], capture_output=True, creationflags=NOWIN, timeout=30)
        time.sleep(2)
        p = subprocess.run(["schtasks", "/Run", "/TN", name], capture_output=True, text=True, creationflags=NOWIN, timeout=30)
    elif os.name != "nt":
        p = subprocess.run(["systemctl", "restart", name], capture_output=True, text=True, timeout=90)
    else:
        p = subprocess.run(["powershell", "-NoProfile", "-Command", "Restart-Service -Name '%s' -Force" % name.replace("'", "")],
                           capture_output=True, text=True, creationflags=NOWIN, timeout=90)
    ok = p.returncode == 0
    core.audit("", user, "tunnel-restart", name, ok=ok, note=(p.stderr or p.stdout or "")[:200])
    if not ok:
        raise NetError("restart of %s %s failed: %s" % (kind, name, (p.stderr or p.stdout or "").strip()[-300:]))
    return {"restarted": True, "kind": kind, "name": name}


# ---------------------------------------------------------------- expose a service

def expose(user, d):
    """One step for "make localhost:1234 reachable as app.example.com (or cdn.example.com/app)":
         1 the Strata drive (Caddy reverse proxy, login gate unless public)   - rules.save_mount
         2 a tunnel ingress rule for the hostname -> this site's Caddy           - only for a new hostname
         3 the DNS record hostname -> tunnel                                   - only for a new hostname
         4 a tunnel restart when the ingress changed
    Each step reports what it did; a failing later step leaves the earlier ones in place (and says so)."""
    steps = []
    host = str(d.get("hostname") or "").strip().lower()
    prefix = "/" + str(d.get("prefix") or "").strip().strip("/")
    zone = (CFG["cloudflare"].get("zone_name") or "").lower()
    if host and "." not in host and zone:
        host = "%s.%s" % (host, zone)
    if not host:
        raise NetError("hostname required (e.g. app.%s)" % (zone or "example.com"))
    drive = {"kind": "proxy", "name": str(d.get("name") or host + (prefix if prefix != "/" else ""))[:60],
             "path": d.get("upstream"), "prefix": prefix, "hosts": [host], "gate": d.get("gate") or {"mode": "login"},
             "strip": d.get("strip", True), "enabled": True, "note": "exposed with Strata > Network"}
    res = rules.save_mount(user, drive)
    steps.append({"step": "drive", "ok": True, "note": "Caddy serves %s%s -> %s" % (host, prefix if prefix != "/" else "",
                                                                                rules.clean_upstream(d.get("upstream")))})
    out = {"steps": steps, "drive": res.get("result"), "enrol": res.get("enrol") or []}
    known = {r["hostname"] for r in ingress()["rules"]}
    if host not in known and d.get("ingress", True):
        try:
            r = ingress_add(user, host, cdn_service())
            steps.append({"step": "ingress", "ok": True, "note": "tunnel routes %s to %s" % (host, cdn_service()),
                          "backup": r.get("backup")})
            changed = True
        except Exception as e:
            steps.append({"step": "ingress", "ok": False, "note": str(e)})
            changed = False
    else:
        steps.append({"step": "ingress", "ok": True, "note": "tunnel already routes %s" % host if host in known else "skipped"})
        changed = False
    if d.get("dns", True):
        try:
            r = route_dns(host)
            steps.append({"step": "dns", "ok": True, "note": "DNS %s (%s)" % (r["dns"], r["via"])})
        except Exception as e:
            steps.append({"step": "dns", "ok": False, "note": str(e)})
    if changed and d.get("restart", True):
        try:
            r = restart_tunnel(user)
            steps.append({"step": "restart", "ok": True, "note": r.get("note") or "tunnel restarted (%s)" % r.get("name")})
        except Exception as e:
            steps.append({"step": "restart", "ok": False, "note": str(e)})
    out["url"] = "https://%s%s" % (host, (prefix + "/") if prefix != "/" else "/")
    return out


def reserved_ports():
    """Loopback ports a service drive may never point at from the UI (see rules.clean_upstream): this site's and every
    known Strata / Caddy / monitoring port, remote access, plus strata.json proxy_reserved_ports."""
    ports = {22, 135, 139, 445, 3389, 5985, 5986, 2019, 2020, 3000, 9095, 9097, 9098, 9182}
    ports |= set(range(8080, 8100)) | set(range(9080, 9100)) | set(range(20241, 20271))
    for k in ("listen", "feed_listen", "transform_listen", "gate_listen"):
        try:
            ports.add(int(str(CFG.get(k) or "").rsplit(":", 1)[1]))
        except (IndexError, ValueError):
            pass
    try:
        ports.add(int(str(CFG["media"].get("listen") or "").rsplit(":", 1)[1]))
    except (IndexError, ValueError):
        pass
    for p in CFG.get("proxy_reserved_ports") or []:
        try:
            ports.add(int(p))
        except (TypeError, ValueError):
            pass
    return ports


def listening():
    """Local TCP ports in LISTEN state with their process names (for the expose wizard's suggestions)."""
    try:
        out = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True, text=True, timeout=15,
                             creationflags=NOWIN).stdout
        tl = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True, timeout=15,
                            creationflags=NOWIN).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    names = {}
    for line in tl.splitlines():
        cols = [c.strip('"') for c in line.split('","')]
        if len(cols) > 1 and cols[1].isdigit():
            names[int(cols[1])] = cols[0]
    rows, seen = [], set()
    reserved = reserved_ports()
    for line in out.splitlines():
        # listening sockets have no remote end (0.0.0.0:0 / [::]:0); the state word itself is localised (ABHÖREN ...)
        m = re.match(r"\s*TCP\s+(\S+):(\d+)\s+(?:0\.0\.0\.0:0|\[::\]:0)\s+\S+\s+(\d+)\s*$", line)
        if not m:
            continue
        addr, port, pid = m.group(1).strip("[]"), int(m.group(2)), int(m.group(3))
        if (port, addr) in seen:
            continue
        seen.add((port, addr))
        rows.append({"addr": addr, "port": port, "pid": pid, "process": names.get(pid, ""),
                     "reserved": port in reserved})
    return sorted(rows, key=lambda r: (r["reserved"], r["port"]))
