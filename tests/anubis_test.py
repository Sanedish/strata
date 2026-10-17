"""Bot protection (Anubis): the generated config, the policy and key files, and real requests through Caddy.

    python tests/anubis_test.py        (run_all.py runs it)

Part 1 needs nothing installed. In throwaway instances it checks that with bot protection off the Caddy config is
exactly what it was before Anubis existed, what the config, the policy file and the key file look like when it is on,
that bad settings are refused and that challenge pages stay out of the statistics.

Part 2 starts a real Caddy on the generated config, in front of a stub Strata Transform and a stub Anubis, and sends
requests: a browser gets the puzzle, a link-preview crawler gets its card, a spoofed crawler agent never gets the
file, a Bearer header doesn't skip the puzzle, a client-sent X-Real-IP is ignored. Without a Caddy (STRATA_CADDY, or
caddy on the PATH) it is skipped. With STRATA_ANUBIS (or anubis on the PATH) the same requests run again against the
real Anubis, whose puzzle the test solves, so the policy file and the forward_auth wiring are checked end to end.
"""
import hashlib
import http.client
import http.server
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_all as ra  # noqa: E402

CODE = ra.CODE
CADDY = os.environ.get("STRATA_CADDY") or shutil.which("caddy")
ANUBIS = os.environ.get("STRATA_ANUBIS") or shutil.which("anubis")
HOST = "cdn.dev.example.com"
BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/130.0"
CRAWLER = "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)"
CLIENT = "198.51.100.7"  # the visitor Cloudflare would name in Cf-Connecting-Ip (documentation range)
FAILS = []


def check(ok, label, detail=""):
    print(("PASS " if ok else "FAIL ") + label + ("" if ok or detail == "" else " - %s" % (detail,)))
    if not ok:
        FAILS.append(label)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


SEED = '''
import json, sys
import anubis, core, rules
core.init_db(); db = core.connect(); rules.seed(db); db.commit(); db.close()
for body in json.loads(sys.argv[1]):
    rules.save_rule("test", body)
if anubis.enabled():
    anubis.ensure_key(); anubis.write_policy()
print(json.dumps({"argv": anubis.command() if anubis.settings()["exe"] else []}))
'''
GALLERY = {"name": "Gallery", "action": "gallery", "patterns": ["/gal/*"]}
SIGNED = {"name": "Signed", "action": "signed", "patterns": ["/signed/*"]}


def challenge(downloads=False):
    return {"name": "Challenge all", "action": "challenge", "patterns": ["/*"], "params": {"downloads": downloads}}


def instance(root, anubis_cfg, rules_, ports=None, hosts=None):
    """A throwaway instance (run_all's) with this bot protection config and these rules; returns what the tests need."""
    home, files = ra.make_home(root)
    cfgp = os.path.join(home, "strata.json")
    cfg = json.load(open(cfgp))
    if hosts:
        cfg["public"]["hosts"] = hosts
    if ports:
        cfg["instance"]["cdn_listen"] = ":%d" % ports["cdn"]
        cfg["transform_listen"] = "127.0.0.1:%d" % ports["transform"]
    if anubis_cfg:
        cfg["anubis"] = anubis_cfg
    json.dump(cfg, open(cfgp, "w"), indent=2)
    for name, text in (("note.txt", "note text"), ("robots.txt", "User-agent: *"), ("pic.png", "PNG...."),
                       ("gal/a.txt", "gallery file"), ("signed/s.txt", "signed file")):
        os.makedirs(os.path.dirname(os.path.join(files, name)), exist_ok=True)
        open(os.path.join(files, name), "w").write(text)
    env = dict(os.environ, STRATA_HOME=home, PYTHONIOENCODING="utf-8")
    p = subprocess.run([sys.executable, "-c", SEED, json.dumps(rules_)], cwd=CODE, env=env, capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit("seeding failed:\n" + p.stdout + p.stderr)
    gen = os.path.join(home, "generated", "cdn.caddy")
    return {"home": home, "env": env, "gen": gen, "text": open(gen, encoding="utf-8").read(),
            "argv": json.loads(p.stdout.strip().splitlines()[-1])["argv"]}


def py(inst, code):
    """Run python in the instance (its config, its database) and return the JSON it prints."""
    p = subprocess.run([sys.executable, "-c", code], cwd=CODE, env=inst["env"], capture_output=True, text=True)
    return json.loads(p.stdout.strip().splitlines()[-1]) if p.returncode == 0 and p.stdout.strip() else {"error": p.stderr[-800:]}


def body_of(text):
    return text.split("\n", 1)[1]  # the first line names the instance folder


def part1(root):
    on_cfg = {"enabled": True, "bind": "127.0.0.1:18423", "metrics": "127.0.0.1:18424", "difficulty": 3,
              "exe": os.path.join(root, "anubis.exe")}  # never run here: only its command line is looked at
    plain = instance(os.path.join(root, "plain"), None, [GALLERY])
    off = instance(os.path.join(root, "off"), None, [GALLERY, challenge()])
    check(body_of(plain["text"]).replace(plain["home"], "HOME") == body_of(off["text"]).replace(off["home"], "HOME"),
          "off by default: a challenge rule changes nothing in the Caddy config")
    check("within.website" not in off["text"] and "api/check" not in off["text"], "off: no Anubis route or forward_auth")
    check(not os.path.exists(os.path.join(off["home"], "generated", "anubis-policy.yaml")) and
          not os.path.exists(os.path.join(off["home"], ".private")), "off: no policy file, no key file")

    on = instance(os.path.join(root, "on"), on_cfg, [GALLERY, SIGNED, challenge()])
    t = on["text"]
    check("reverse_proxy @anubis_1 127.0.0.1:18423" in t and "forward_auth 127.0.0.1:18423" in t, "on: Caddy talks to Anubis")
    check("uri /.within.website/x/cmd/anubis/api/check" in t and "redir * /.within.website/?redir={uri} 307" in t and "status 401 307" in t,
          "on: a 401 or 307 from Anubis redirects to the puzzle")
    check(t.count("header_up X-Real-IP {client_ip}") == 2 and t.count("header_up X-Forwarded-For {client_ip}") == 2,
          "on: Anubis is told Caddy's client_ip, in the puzzle route and in forward_auth")
    pos = lambda s: t.index(s)  # noqa: E731
    check(pos("reverse_proxy @anubis_1") < pos("# access rules"), "order: the puzzle route comes before the access rules")
    check(pos("# bot challenge") < pos("# gallery folders") < pos("# link previews"), "order: challenge, galleries, then link previews")
    chal = t.split("# bot challenge")[1].split("# gallery")[0]
    check('{http.request.header.Authorization}.startsWith("Bearer ") && {http.request.uri.path}.startsWith("/api/")' in chal,
          "challenge: a Bearer header is only an exemption on /api/")
    check('not path `/signed/*`' in chal, "challenge: paths under a signed rule are left to it")
    check("header -Cloudflare-CDN-Cache-Control" in chal, "challenge: the redirect is never cached")
    pol_path = os.path.join(on["home"], "generated", "anubis-policy.yaml")
    pol = open(pol_path).read() if os.path.exists(pol_path) else ""
    check("difficulty: 3" in pol and "CHALLENGE: 200" in pol and "DENY: 403" in pol and 'network: "tcp"' in pol,
          "policy: difficulty, status codes (a DENY must not be a 200 for forward_auth) and metrics")
    check("import: (data)/crawlers/_allow-good.yaml" in pol and "geoip" not in pol, "policy: Anubis' shipped lists, no GeoIP rules")
    key_path = os.path.join(on["home"], ".private", "anubis.key")
    key = open(key_path).read() if os.path.exists(key_path) else ""
    check(re.fullmatch(r"[0-9a-f]{64}", key) is not None, "key: 64 hex characters in <home>/.private/")
    check(key not in open(os.path.join(on["home"], "strata.json")).read() and key not in pol and key not in t,
          "key: not in strata.json, the policy or the Caddy config")

    probe = py(on, r'''
import json, os, time
import anubis, core, rules
out = {}
def refused(d):
    try:
        anubis.clean(d); return False
    except anubis.BotError:
        return True
out["bad"] = [refused({"public_url": "https://example.com"}), refused({"bind": "10.0.0.5:8923"}), refused({"bind": "example.com:8923"}), refused({"difficulty": 99}),
              refused({"exe": os.__file__}), refused({"cookie_domain": "example.com:8080"})]
out["good"] = anubis.clean({"bind": "127.0.0.1:9000", "difficulty": 5, "cookie_domain": "Example.com"})
out["ports"] = [anubis.settings()["bind"], anubis.settings()["metrics"]]
import cloudflare
pair = lambda pats, **p: [({"patterns": pats, "params": p}, {"hosts": ["cdn.example.com"]})]
cx = cloudflare.challenge_expression
out["cf"] = [cx(pair(["/*"])), cx(pair(["/a/*", "*.psd", "/exact.png"], downloads=True)), cx(pair(["re:/x/.*"], downloads=True)),
             cx(pair(["/a*b"], downloads=True)), cx([])]
out["rule"] = rules.clean_rule({"action": "challenge", "patterns": ["/x/*"], "params": {"downloads": "yes"}})["params"]
# Under Attack Mode: raised difficulty comes from settings(), the window clears itself, the auto rule is an ordinary row
out["ua_off"] = [anubis.under_attack(), anubis.under_attack_left()]
anubis.set_under_attack("t", 0)  # off while protection is off is allowed (no-op)
core.save_config({"anubis": {"under_attack_until": time.time() + 3600}})
out["ua_on"] = [anubis.under_attack(), anubis.settings()["difficulty"] >= anubis.UNDER_ATTACK_DIFFICULTY]
core.save_config({"anubis": {"under_attack_until": time.time() - 10}})
out["ua_lapsed"] = [anubis.under_attack(), core.CFG["anubis"]["under_attack_until"]]
out["auto"] = [anubis.ensure_auto_rule("t", downloads=True), anubis.ensure_auto_rule("t"), anubis.ensure_auto_rule("t")]
dbx = core.connect()
arow = anubis.auto_rule(dbx)
out["auto_row"] = [arow["name"], arow["patterns"], arow["params"], arow["mount"]]
out["rules_before"] = dbx.execute("SELECT count(*) FROM rule").fetchone()[0]
out["autos_before"] = dbx.execute("SELECT count(*) FROM rule WHERE name=?", (anubis.AUTO_RULE_NAME,)).fetchone()[0]
dbx.close()
out["ua_flag_rule"] = anubis.set_under_attack("t", 3600)  # on: downloads is overlaid, the rule row is not touched
out["ua_overlay"] = [anubis.under_attack(), anubis.set_under_attack("t", 0)["under_attack"]]  # and off again
dbx = core.connect()
out["rules_after"] = dbx.execute("SELECT count(*) FROM rule").fetchone()[0]
out["autos_after"] = dbx.execute("SELECT count(*) FROM rule WHERE name=?", (anubis.AUTO_RULE_NAME,)).fetchone()[0]
dbx.close()
line = lambda uri, loc=None: json.dumps({"msg": "handled request", "status": 307 if loc else 200, "request": {"uri": uri, "headers": {}},
                                          "resp_headers": {"Location": [loc]} if loc else {}})
out["parse"] = [core.parse_line(line("/.within.website/x/cmd/anubis/static/js/main.mjs")) is None,
                core.parse_line(line("/note.txt", "/.within.website/?redir=/note.txt")) is None,
                core.parse_line(line("/note.txt")) is not None]
print(json.dumps(out))''')
    check(probe.get("bad") == [True] * 6, "settings: a full public URL, a remote address, a non-Anubis program, difficulty 99 and a cookie port are refused", probe)
    check(probe.get("good", {}).get("cookie_domain") == "example.com" and probe["good"]["difficulty"] == 5, "settings: valid values are kept")
    check(probe.get("ports") == ["127.0.0.1:18423", "127.0.0.1:18424"], "settings: configured addresses are used", probe.get("ports"))
    cf = probe.get("cf") or [""] * 5
    check('http.host in {"cdn.example.com"}' in cf[0] and 'starts_with(http.request.uri.path, "/")' in cf[0] and "sec-fetch-dest" in cf[0],
          "cloudflare: the cache bypass covers browser requests for the challenged paths", cf[0])
    check('starts_with(http.request.uri.path, "/a/") or ends_with(http.request.uri.path, ".psd") or http.request.uri.path eq "/exact.png"' in cf[1]
          and "sec-fetch-dest" not in cf[1], "cloudflare: 'downloads' bypasses the cache for every request, patterns become starts_with / ends_with / eq", cf[1])
    check(cf[2] == '(http.host in {"cdn.example.com"})' == cf[3] and cf[4] is None,
          "cloudflare: a regex or a * in the middle bypasses the whole host (never a gap); no rule, no expression", cf[2:])
    check(probe.get("rule") == {"downloads": True}, "rule: challenge keeps only its downloads flag", probe.get("rule"))
    ua = probe.get("ua_off") == [False, 0] and probe.get("ua_on") == [True, True] and probe.get("ua_lapsed") == [False, 0]
    check(ua, "under attack: off by default, raises difficulty while on, clears itself when the window lapses", {k: probe.get(k) for k in ("ua_off", "ua_on", "ua_lapsed")})
    check(probe.get("auto") == ["created", "kept", "kept"], "auto rule: created once, then left alone", probe.get("auto"))
    check(probe.get("auto_row") == ["Automatic bot challenge", ["/*"], {"downloads": True}, None],
          "auto rule: one global row, the flag the user chose at activation", probe.get("auto_row"))
    check(probe.get("rules_after") == probe.get("rules_before") and probe.get("autos_after") == probe.get("autos_before") == 1,
          "auto rule: under attack never duplicates or rewrites the row",
          {k: probe.get(k) for k in ("rules_before", "rules_after", "autos_before", "autos_after")})
    check(probe.get("ua_overlay") == [True, False], "under attack: switches on and off again, rule row untouched", probe.get("ua_overlay"))
    check(probe.get("parse") == [True, True, True], "statistics: challenge pages and their redirect are not traffic", probe.get("parse"))
    argv = on["argv"]
    check(argv[argv.index("--public-url") + 1] == "https://" and "--cookie-secure=false" not in argv,
          "command line: a public URL (scheme only), or the puzzle page redirects to itself; Secure cookies stay on for https", argv)
    check(argv[:1] == [on_cfg["exe"]] and "--ed25519-private-key-hex-file" in argv and key not in " ".join(argv) and
          argv[argv.index("--target") + 1] == " ", "command line: key by file (never the value), blank target (auth-request mode)", argv)


INSTALL = r'''
import hashlib, io, json, os, tarfile, zipfile
import anubis, core
exe_key = "bin/anubis.exe" if os.name == "nt" else "bin/anubis"
members = {"anubis-9.9.9/" + exe_key: b"EXE", "anubis-9.9.9/doc/LICENSE": b"MIT TEXT", "anubis-9.9.9/bin/other.exe": b"NO",
           "anubis-9.9.9/doc/data/x.yaml": b"NO", "../evil.txt": b"NO", "evil2.txt": b"NO"}
def archive():
    b = io.BytesIO()
    if os.name == "nt":
        with zipfile.ZipFile(b, "w") as z:
            for k, v in members.items():
                z.writestr(k, v)
    else:
        with tarfile.open(fileobj=b, mode="w:gz") as t:
            for k, v in members.items():
                i = tarfile.TarInfo(k); i.size = len(v); t.addfile(i, io.BytesIO(v))
    return b.getvalue()
data = archive()
def serve(digest=None, size=None):
    rel = {"assets": [{"name": anubis.asset_name(), "size": size if size is not None else len(data), "digest": digest,
                       "browser_download_url": "https://github.com/TecharoHQ/anubis/releases/download/v/file"}]}
    def fetch(url):
        return io.BytesIO(json.dumps(rel).encode() if url == anubis.RELEASE_API else data)
    anubis.fetch = fetch
real_fetch = anubis.fetch
anubis.version = lambda exe: "test"
out = {}
def tries(**kw):
    serve(**kw)
    try:
        anubis.install("t"); return None
    except anubis.BotError as e:
        return str(e)
good = "sha256:" + hashlib.sha256(data).hexdigest()
out["wrong"] = tries(digest="sha256:" + "0" * 64)
out["nodigest"] = tries(digest=None)
out["big"] = tries(digest=good, size=anubis.MAX_DOWNLOAD + 1)
out["after_refusals"] = sorted(os.listdir(anubis.program_dir())) if os.path.isdir(anubis.program_dir()) else []
out["ok"] = tries(digest=good)
out["files"] = sorted(os.listdir(anubis.program_dir()))
out["saved"] = core.CFG["anubis"]["exe"] == os.path.join(anubis.program_dir(), os.path.basename(exe_key))
out["licence"] = open(os.path.join(anubis.program_dir(), "LICENSE")).read()
out["escaped"] = [os.path.exists(os.path.join(anubis.program_dir(), "..", "evil.txt")), os.path.exists(os.path.join(core.HOME, "evil2.txt"))]
import urllib.request
def refuses(f, *a):
    try:
        f(*a); return False
    except anubis.BotError:
        return True
out["hosts"] = [refuses(real_fetch, "http://github.com/x"), refuses(real_fetch, "https://evil.example/x"),
                refuses(real_fetch, "https://github.com.evil.example/x"),
                refuses(anubis.Pinned().redirect_request, urllib.request.Request("https://github.com/x"), None, 302, "", {}, "https://evil.example/y"),
                refuses(anubis.Pinned().redirect_request, urllib.request.Request("https://github.com/x"), None, 302, "", {}, "http://objects.githubusercontent.com/y")]
anubis.fetch = real_fetch
# the demo/dry-run set-up: downloads into the instance, registers and starts nothing
import shutil; shutil.rmtree(anubis.program_dir()); core.save_config({"anubis": {"exe": ""}})
serve(digest=good)
anubis.install_task = lambda *a, **k: (_ for _ in ()).throw(AssertionError("registered a task"))
log = anubis.setup_all("t")
out["setup_log"] = log
out["setup_files"] = [os.path.exists(anubis.key_path()), os.path.exists(anubis.policy_path())]
anubis.save({"enabled": True})
out["stop_refused"] = [refuses(anubis.stop, "t"), refuses(anubis.remove_task, "t")]
real = urllib.request.urlopen
urllib.request.urlopen = lambda *a, **k: io.BytesIO(b'# HELP x\nanubis_policy_results{action="CHALLENGE",rule="a"} 3\nanubis_policy_results{action="CHALLENGE",rule="b"} 4\nanubis_policy_results{action="ALLOW",rule="c"} 5\nother 9\n')
out["counts"] = anubis.counts("127.0.0.1:1")
print(json.dumps(out))
'''


def part_install(root):
    inst = instance(os.path.join(root, "install"), None, [])
    r = py(inst, INSTALL)
    check("error" not in r, "install: the test script ran", r.get("error"))
    check("checksum" in (r.get("wrong") or "") and "checksum" in (r.get("nodigest") or "") and r.get("big") is not None,
          "install: a wrong checksum, a missing checksum and an oversize file are refused", r)
    check(r.get("after_refusals") == [], "install: a refused download leaves nothing behind", r.get("after_refusals"))
    check(r.get("ok") is None and r.get("saved"), "install: a download matching GitHub's checksum is installed and its path saved", r.get("ok"))
    check(r.get("files") == (["LICENSE", "anubis.exe"] if os.name == "nt" else ["LICENSE", "anubis"]),
          "install: only the program and its licence are unpacked (not the other files, not ../ paths)", r.get("files"))
    check(r.get("licence") == "MIT TEXT", "install: the licence goes along", r.get("licence"))
    check(r.get("escaped") == [False, False], "install: nothing outside the program folder is written", r.get("escaped"))
    check(r.get("hosts") == [True] * 5, "install: only https to github.com hosts, also across redirects", r.get("hosts"))
    log = " | ".join(r.get("setup_log") or [])
    check("downloaded" in log and "Demo instance" in log and r.get("setup_files") == [True, True],
          "set-up on a demo instance: downloads, makes key and policy, registers and starts nothing", log)
    check(r.get("stop_refused") == [True, True], "stop / remove task: refused while protection is on (Caddy would answer 502)", r.get("stop_refused"))
    check(r.get("counts") == {"CHALLENGE": 7, "ALLOW": 5}, "metrics: results are summed per action", r.get("counts"))


class Servers:
    """The stub Strata Transform and the stub Anubis (HTTP on loopback), and what the stub Anubis saw."""

    def __init__(self, ports):
        self.seen = []
        outer = self

        class Transform(http.server.BaseHTTPRequestHandler):
            def do_GET(s):
                if s.path.startswith("/_gate"):  # forward_auth of a `signed` rule: good signatures only
                    code, body = (200, b"") if "sig=good" in s.headers.get("X-Forwarded-Uri", "") else (403, b"bad signature")
                else:
                    code, body = 200, (b"OGCARD" if s.headers.get("X-Strata-Embed") else b"JPEGCARD" if "card=1" in s.path else b"TRANSFORM")
                s.send_response(code)
                s.send_header("Content-Length", str(len(body)))
                s.end_headers()
                s.wfile.write(body)

            def log_message(*a):
                pass

        class Anubis(http.server.BaseHTTPRequestHandler):
            def do_GET(s):
                path, _, q = s.path.partition("?")
                headers = {k.lower(): v for k, v in s.headers.items()}
                if path.endswith("/api/check"):
                    outer.seen.append(headers)
                    passed = "stub-pass=1" in headers.get("cookie", "")
                    s.send_response(200 if passed else 401)
                    s.send_header("Content-Length", "0")
                    s.end_headers()
                    return
                body = b"STUB-CHALLENGE"
                if path.endswith("/pass"):  # the stub's "solved it"
                    body = b""
                    s.send_response(302)
                    s.send_header("Set-Cookie", "stub-pass=1; Path=/")
                    s.send_header("Location", urllib.parse.parse_qs(q).get("redir", ["/"])[0])
                else:
                    s.send_response(200)
                s.send_header("Content-Length", str(len(body)))
                s.end_headers()
                s.wfile.write(body)

            def log_message(*a):
                pass
        self.transform = http.server.ThreadingHTTPServer(("127.0.0.1", ports["transform"]), Transform)
        self.anubis = http.server.ThreadingHTTPServer(("127.0.0.1", ports["anubis"]), Anubis)
        for s in (self.transform, self.anubis):
            threading.Thread(target=s.serve_forever, daemon=True).start()

    def stop_anubis(self):
        self.anubis.shutdown()
        self.anubis.server_close()

    def stop(self):
        self.transform.shutdown()
        self.transform.server_close()


class Stack:
    """Caddy on the instance's generated config + stub Transform + Anubis (stub or the real one)."""

    def __init__(self, root, real, downloads=False):
        self.real = real
        self.ports = {k: free_port() for k in ("cdn", "transform", "anubis", "metrics")}
        cfg = {"enabled": True, "bind": "127.0.0.1:%d" % self.ports["anubis"], "metrics": "127.0.0.1:%d" % self.ports["metrics"],
               "difficulty": 2, "exe": ANUBIS if real else "", "public_url": "http://"}  # the test has no TLS
        self.inst = instance(root, cfg, [GALLERY, SIGNED, challenge(downloads)], self.ports)
        self.servers = Servers(self.ports)
        self.procs = []
        main = os.path.join(root, "Caddyfile.test")
        with open(main, "w") as f:  # what the production Caddyfile has: Cloudflare's address is trusted from loopback only
            f.write("{\n\tadmin off\n\tauto_https off\n\tservers {\n\t\ttrusted_proxies static private_ranges\n"
                    "\t\tclient_ip_headers Cf-Connecting-Ip\n\t}\n}\nimport %s\n" % self.inst["gen"].replace("\\", "/"))
        env = dict(os.environ, APPDATA=root, XDG_CONFIG_HOME=root, HOME=root)  # Caddy's autosave stays in the test folder
        v = subprocess.run([CADDY, "validate", "--adapter", "caddyfile", "--config", main], capture_output=True, text=True, env=env)
        check(v.returncode == 0, "caddy validate accepts the config with bot protection on (%s)" % ("real Anubis" if real else "stub"),
              (v.stderr or v.stdout)[-1200:])
        if v.returncode:
            raise SystemExit(1)
        self.log = open(os.path.join(root, "anubis.log"), "w+")
        if real:  # the argv Strata itself builds (public_url http:// adds the plain-http cookie flags)
            self.servers.stop_anubis()
            self.procs.append(subprocess.Popen(self.inst["argv"] + ["--slog-level", "INFO"],
                                               stdout=self.log, stderr=self.log))
        self.procs.append(subprocess.Popen([CADDY, "run", "--adapter", "caddyfile", "--config", main], env=env,
                                           stdout=subprocess.DEVNULL, stderr=open(os.path.join(root, "caddy.log"), "w")))
        for _ in range(60):
            try:
                socket.create_connection(("127.0.0.1", self.ports["cdn"]), 0.5).close()
                if not real or "listening" in self.anubis_log():
                    break
            except OSError:
                pass
            time.sleep(0.25)

    def anubis_log(self):
        self.log.flush()
        self.log.seek(0)
        return self.log.read()

    def get(self, path, ua=BROWSER, nav=True, ip=CLIENT, cookie="", **headers):
        h = {"Host": HOST, "User-Agent": ua, "Cf-Connecting-Ip": ip}
        h.update({"Accept": "text/html,application/xhtml+xml", "Sec-Fetch-Dest": "document"} if nav else {"Accept": "*/*"})
        if cookie:
            h["Cookie"] = cookie
        h.update(headers)
        c = http.client.HTTPConnection("127.0.0.1", self.ports["cdn"], timeout=15)
        c.request("GET", path, headers=h)
        r = c.getresponse()
        return r.status, r.getheaders(), r.read()

    def passed(self, ip=CLIENT, path="/note.txt"):
        """Solve the puzzle for this visitor; returns the Cookie header to send afterwards."""
        if not self.real:
            return "; ".join(v.split(";")[0] for k, v in self.get("/.within.website/pass?redir=" + path, ip=ip)[1] if k.lower() == "set-cookie")
        st, hs, page = self.get("/.within.website/?redir=" + path, ip=ip)
        jar = [v.split(";")[0] for k, v in hs if k.lower() == "set-cookie"]
        ch = json.loads(re.search(rb'<script id="anubis_challenge" type="application/json">(.*?)</script>', page, re.S).group(1))
        data, diff, n = ch["challenge"]["randomData"], ch["rules"]["difficulty"], 0
        while not hashlib.sha256((data + str(n)).encode()).hexdigest().startswith("0" * diff):
            n += 1
        q = urllib.parse.urlencode({"id": ch["challenge"]["id"], "response": hashlib.sha256((data + str(n)).encode()).hexdigest(),
                                    "nonce": n, "redir": path, "elapsedTime": 5})
        st, hs, _ = self.get("/.within.website/x/cmd/anubis/api/pass-challenge?" + q, ip=ip, cookie="; ".join(jar))
        return "; ".join(jar + [v.split(";")[0] for k, v in hs if k.lower() == "set-cookie"])

    def stop(self):
        for p in self.procs:
            p.terminate()
        for p in self.procs:
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
        self.servers.stop()


def location(hs):
    return next((v for k, v in hs if k.lower() == "location"), "")


def flow(root, real):
    name = "anubis" if real else "stub"
    s = Stack(root, real)
    try:
        st, hs, _ = s.get("/note.txt")
        check(st == 307 and location(hs) == "/.within.website/?redir=/note.txt", "%s: a browser opening a file is sent to the puzzle" % name, (st, location(hs)))
        check(py(s.inst, "import anubis, json; print(json.dumps(anubis.probe()))") == [True, True],
              "%s: Strata's own check recognises Anubis (with the instance's host, a 307 or 401 counts)" % name)
        st, hs, body = s.get("/.within.website/?redir=/note.txt")
        check(st == 200 and (b"STUB-CHALLENGE" in body or b"anubis_challenge" in body), "%s: the puzzle page is served (not hidden as a dot-file)" % name, st)
        st, _, body = s.get("/note.txt", ua=CRAWLER, nav=False)
        check((st, body) == (200, b"OGCARD"), "%s: a link-preview crawler gets the Open Graph card, not a puzzle" % name, (st, body[:20]))
        st, _, body = s.get("/note.txt?card=1", ua=CRAWLER, nav=False)
        check((st, body) == (200, b"JPEGCARD"), "%s: the card image (?card=1) is not challenged" % name, (st, body[:20]))
        st, hs, body = s.get("/note.txt?x=1", ua=CRAWLER)
        check(st == 307 and b"note text" not in body, "%s: a spoofed crawler agent asking for the file itself gets the puzzle" % name, st)
        st, _, body = s.get("/note.txt", ua=CRAWLER)
        check(body == b"OGCARD", "%s: ... and only ever the cheap card on the bare URL" % name, body[:20])
        st, hs, _ = s.get("/note.txt", Authorization="Bearer not-a-real-key")
        check(st == 307, "%s: a junk Bearer header does not skip the puzzle on a file" % name, st)
        st, _, _ = s.get("/api/something", Authorization="Bearer key")
        check(st == 404, "%s: a Bearer call to /api/ is not challenged (answered by the file server)" % name, st)
        st, _, body = s.get("/note.txt", ua="curl/8.5", nav=False)
        check((st, body) == (200, b"note text"), "%s: without 'downloads', a plain download is not challenged (documented)" % name, st)
        st, _, _ = s.get("/pic.png", nav=False, **{"Sec-Fetch-Dest": "image"})
        check(st == 200, "%s: an <img> subresource is not challenged" % name, st)
        check(s.get("/gal/")[0] == 307 and s.get("/gal/", ua="curl/8.5", nav=False)[0] == 307, "%s: gallery folders are challenged even for a plain request" % name)
        check(s.get("/robots.txt")[0] == 200, "%s: robots.txt is never challenged" % name)
        st, _, body = s.get("/signed/s.txt?sig=good")
        check((st, body) == (200, b"signed file"), "%s: a valid signed link is left to the signed rule" % name, (st, body[:20]))
        check(s.get("/signed/s.txt?sig=bad")[0] == 403, "%s: a bad signature is refused by the signed rule, before any puzzle" % name)
        check(s.get("/note.txt?sig=good")[0] == 307, "%s: a sig= on a path no signed rule covers skips nothing" % name)
        if real:  # what the puzzle page's script does to find where to go after the puzzle: with a public URL that is a prefix of
            #       the page's own address it reads ?redir=, otherwise it returns to the puzzle page itself (the bug a browser found)
            page = s.get("/.within.website/?redir=/note.txt")[2]
            pub = json.loads(re.search(rb'<script id="anubis_public_url" type="application/json">(.*?)</script>', page, re.S).group(1))
            check(bool(pub) and ("http://%s:%d/.within.website/?redir=/note.txt" % (HOST, s.ports["cdn"])).startswith(pub),
                  "anubis: the puzzle page has a public URL, so its script goes back to ?redir=", pub)
        cookie = s.passed()
        st, _, body = s.get("/note.txt", cookie=cookie)
        check((st, body) == (200, b"note text"), "%s: after the puzzle the file is served" % name, (st, body[:20]))
        if real:
            check(s.get("/note.txt", cookie=cookie, ip="198.51.100.99")[0] == 307, "anubis: a pass cookie replayed from another address is challenged again")
        if real:
            seen = [l for l in s.anubis_log().splitlines() if '"x-real-ip"' in l]
            ips = {re.search(r'"x-real-ip":"([^"]*)"', l).group(1) for l in seen}
            check(bool(seen) and ips <= {CLIENT, "198.51.100.99"}, "anubis: Anubis saw only the Cloudflare-named visitor addresses", ips)
        s.servers.seen.clear()
        s.get("/note.txt", **{"X-Real-IP": "1.2.3.4", "X-Forwarded-For": "5.6.7.8"})
        if not real:
            h = s.servers.seen[-1] if s.servers.seen else {}
            check(h.get("x-real-ip") == CLIENT and h.get("x-forwarded-for") == CLIENT and h.get("x-forwarded-proto") == "https",
                  "stub: a client-sent X-Real-IP / X-Forwarded-For is overwritten with the real client address", {k: h.get(k) for k in ("x-real-ip", "x-forwarded-for")})
        else:
            s.get("/.within.website/?redir=/note.txt", **{"X-Real-IP": "1.2.3.4", "X-Forwarded-For": "5.6.7.8"})
            log = [l for l in s.anubis_log().splitlines() if '"x-real-ip"' in l][-1]
            check('"x-real-ip":"%s"' % CLIENT in log and "1.2.3.4" not in log and "5.6.7.8" not in log,
                  "anubis: a client-sent X-Real-IP / X-Forwarded-For never reaches Anubis", log[-300:])
        for p in s.procs[:1] if real else []:
            p.terminate()
            p.wait(10)
        if not real:
            s.servers.stop_anubis()
        check(s.get("/note.txt")[0] == 502, "%s: with Anubis down a challenged path fails closed (502), it is never served open" % name)
    finally:
        s.stop()


def downloads_flow(root):
    s = Stack(root, False, downloads=True)
    try:
        st, hs, body = s.get("/note.txt", ua="curl/8.5", nav=False)
        check(st == 307 and b"note text" not in body, "downloads: a plain download is challenged too")
        check(s.get("/note.txt", ua=CRAWLER, nav=False)[2] == b"OGCARD", "downloads: the crawler still gets its card")
        check(s.get("/pic.png", nav=False, **{"Sec-Fetch-Dest": "image"})[0] == 307, "downloads: a hotlinked <img> is challenged (documented)")
    finally:
        s.stop()


def main():
    root = tempfile.mkdtemp(prefix="strata-scratchpad-")
    try:
        part1(root)
        part_install(root)
        if not CADDY:
            print("skipped the request tests: no caddy found (put it on the PATH or set STRATA_CADDY)")
        else:
            flow(os.path.join(root, "stub"), False)
            downloads_flow(os.path.join(root, "dl"))
            if ANUBIS:
                flow(os.path.join(root, "real"), True)
            else:
                print("skipped the real-Anubis run: no anubis found (put it on the PATH or set STRATA_ANUBIS)")
    finally:
        shutil.rmtree(root, ignore_errors=True)
    print("\n%s" % ("all passed" if not FAILS else "FAILED: " + "; ".join(FAILS)))
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
