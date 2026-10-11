"""A demo instance with a week of made-up traffic, for screenshots and for clicking around.

    python tests/demo.py            starts it on http://127.0.0.1:8290, already signed in as alex; Ctrl+C stops it

Everything lives in a temp folder: sample files (generated images, a site, a zip), a Caddy access log written in
Caddy's JSON format, and the stub Caddy from run_all.py. Visitors use documentation address ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32), so nothing here points at a real person. Traffic keeps trickling
in while it runs, so the live views move.

No sign-in: Strata itself listens on 8291 with its sign-in untouched, and a small proxy on 8290 (in this file only,
never in Strata) adds alex's session cookie to every request. Nothing about this reaches a real installation.
"""
import http.client
import http.server
import io
import json
import math
import os
import random
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import zipfile

TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TESTS)
import run_all as ra  # noqa: E402

PORT = 8290          # the proxy you open: already signed in
STRATA_PORT = 8291   # Strata itself, sign-in as in production
DAYS = 7
rnd = random.Random(7)

COUNTRIES = [(30, "US", ["IAD", "DFW", "LAX", "ORD", "SEA"]), (18, "DE", ["FRA", "DUS", "HAM"]), (9, "GB", ["LHR", "MAN"]),
             (6, "NL", ["AMS"]), (6, "FR", ["CDG", "MRS"]), (5, "JP", ["NRT", "KIX"]), (4, "BR", ["GRU"]),
             (4, "CA", ["YYZ", "YVR"]), (4, "IN", ["BOM", "DEL"]), (3, "AU", ["SYD"]), (3, "PL", ["WAW"]),
             (2, "SE", ["ARN"]), (2, "ES", ["MAD"]), (2, "IT", ["MXP"]), (1, "KR", ["ICN"]), (1, "SG", ["SIN"])]
UAS = [(26, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"),
       (14, "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36"),
       (13, "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1"),
       (8, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15"),
       (8, "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0"),
       (7, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0"),
       (4, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"),
       (3, "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)"),
       (2, "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)"),
       (2, "curl/8.9.1"), (1, "python-requests/2.32.3")]
REFERRERS = ["", "", "", "", "https://www.google.com/", "https://news.ycombinator.com/", "https://www.reddit.com/",
             "https://duckduckgo.com/", "https://github.com/", "https://example.com/blog/"]
PROBES = ["/.env", "/wp-login.php", "/.git/config", "/wp-admin/setup-config.php", "/phpmyadmin/index.php",
          "/.aws/credentials", "/admin.php", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/../../etc/passwd"]


def signed_in_proxy(token):
    """Forward http://127.0.0.1:PORT to Strata on STRATA_PORT with alex's session cookie on every request."""
    cookie = "strata_session=" + token

    class Proxy(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def forward(self):
            if self.path.split("?")[0] == "/logout":  # signing out would end the only session the demo has
                self.send_response(303)
                self.send_header("Location", "/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            headers = {k: v for k, v in self.headers.items() if k.lower() not in ("cookie", "connection", "keep-alive")}
            others = [c.strip() for c in (self.headers.get("Cookie") or "").split(";")
                      if c.strip() and not c.strip().startswith("strata_session=")]
            headers["Cookie"] = "; ".join(others + [cookie])
            up = http.client.HTTPConnection("127.0.0.1", STRATA_PORT, timeout=120)
            try:
                up.request(self.command, self.path, body or None, headers)  # Host stays as the browser sent it
                r = up.getresponse()
                data = r.read()
            finally:
                up.close()
            self.send_response(r.status, r.reason)
            for k, v in r.getheaders():
                if k.lower() not in ("transfer-encoding", "connection", "content-length", "keep-alive"):
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = forward

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Proxy)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def make_files(root):
    """A small site, generated images, a zip: what the Files view and the traffic point at. Returns {path: (size, type)}."""
    from PIL import Image, ImageDraw
    out = {}

    def put(rel, data, ctype):
        full = os.path.join(root, *rel.strip("/").split("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as f:
            f.write(data)
        out[rel] = (len(data), ctype)

    palette = [((24, 32, 58), (230, 90, 70)), ((12, 60, 66), (240, 200, 90)), ((40, 20, 60), (120, 200, 230)),
               ((250, 245, 235), (30, 30, 30)), ((20, 20, 24), (160, 120, 250)), ((235, 240, 230), (40, 120, 90))]
    names = ["hero", "team-offsite", "product-shot", "office-plants", "night-skyline", "workshop", "poster-a2",
             "launch-banner", "gallery-01", "gallery-02", "gallery-03", "gallery-04"]
    for i, name in enumerate(names):
        bg, fg = palette[i % len(palette)]
        w, h = (1920, 1080) if i % 3 else (1080, 1350)
        im = Image.new("RGB", (w, h), bg)
        d = ImageDraw.Draw(im)
        for k in range(14):
            t = k / 14
            r = int(h * (0.9 - 0.06 * k))
            c = tuple(int(bg[j] + (fg[j] - bg[j]) * t) for j in range(3))
            d.ellipse([w * 0.62 - r / 2 + k * 9, h * 0.55 - r / 2, w * 0.62 + r / 2 + k * 9, h * 0.55 + r / 2], fill=c)
        d.rectangle([w * 0.07, h * 0.72, w * 0.42, h * 0.75], fill=fg)
        buf = io.BytesIO()
        ext = ("webp", "jpg", "png")[i % 3]
        im.save(buf, {"jpg": "JPEG", "webp": "WEBP", "png": "PNG"}[ext], quality=82)
        put("/images/%s.%s" % (name, ext), buf.getvalue(), "image/" + ("jpeg" if ext == "jpg" else ext))
    page = "<!doctype html><title>Example</title><link rel=stylesheet href=/css/site.css><h1>Example</h1>" + "<p>Lorem ipsum.</p>" * 400
    put("/index.html", page.encode(), "text/html")
    put("/blog/index.html", (page * 2).encode(), "text/html")
    put("/css/site.css", (":root{--a:#e65a46}body{margin:0;font:16px system-ui}" * 300).encode(), "text/css")
    put("/js/app.js", ("export function init(){document.body.dataset.ready=1}\n" * 900).encode(), "text/javascript")
    put("/fonts/inter-var.woff2", os.urandom(98000), "font/woff2")
    put("/video/launch-teaser.mp4", os.urandom(2_400_000), "video/mp4")
    put("/audio/podcast-ep12.mp3", os.urandom(1_200_000), "audio/mpeg")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for p in list(out)[:6]:
            z.writestr(p.strip("/"), open(os.path.join(root, *p.strip("/").split("/")), "rb").read())
    put("/downloads/press-kit.zip", buf.getvalue(), "application/zip")
    put("/downloads/handbook.pdf", b"%PDF-1.4\n" + os.urandom(340000), "application/pdf")
    put("/robots.txt", b"User-agent: *\nAllow: /\n", "text/plain")
    for code in ("403", "404", "502"):  # the default error pages, at the paths the site settings use
        with open(os.path.join(ra.CODE, "static", "errors", code + ".html"), "rb") as f:
            put("/404/%s.html" % code, f.read(), "text/html")
    return out


def visitor(n):
    """n-th visitor: a stable address in a documentation range and a country."""
    r = random.Random(n)
    _, cc, colos = pick_with(r, COUNTRIES)
    if n % 5 == 0:
        ip = "2001:db8:%x:%x::%x" % (r.randrange(65536), r.randrange(65536), r.randrange(1, 65536))
    else:
        ip = "%s.%d" % (r.choice(["192.0.2", "198.51.100", "203.0.113"]), r.randrange(1, 255))
    return ip, cc, r.choice(colos), pick_with(r, UAS)[1]


def pick_with(r, weighted):
    """Weighted choice from (weight, ...) tuples."""
    return r.choices(weighted, weights=[w[0] for w in weighted])[0]


def line(ts, files, n_visitors):
    ip, cc, colo, ua = visitor(int(n_visitors * rnd.random() ** 2))  # a few regulars, a long tail
    probe = rnd.random() < 0.012
    if probe:
        ip, cc, colo, ua = "198.51.100.%d" % rnd.choice([66, 67, 99, 142]), rnd.choice(["CN", "RU", "VN"]), "HKG", \
            "Mozilla/5.0 zgrab/0.x"
        path, (size, ctype), status = rnd.choice(PROBES), (162, "text/plain"), 404
    else:
        path = rnd.choices(list(files), weights=[9 if p.endswith((".css", ".js", ".woff2")) else
                                                  6 if p.startswith("/images/") else 4 if p.endswith(".html") else 1
                                                  for p in files])[0]
        size, ctype = files[path]
        status = 304 if rnd.random() < 0.12 else 206 if path.endswith((".mp4", ".mp3")) else 200
        if rnd.random() < 0.008:
            path, status, size, ctype = "/images/old-logo.png", 404, 162, "text/plain"
        if status == 304:
            size = 0
        elif status == 206:
            size = min(size, 524288)
    enc = "br" if ctype in ("text/html", "text/css", "text/javascript") and status == 200 else ""
    if enc:
        size = int(size * rnd.uniform(0.18, 0.3))
    if path.startswith("/images/") and rnd.random() < 0.2:
        path += "?w=%d" % rnd.choice([640, 1080, 1440])
    dur = rnd.lognormvariate(math.log(0.012), 0.8) + size / 40e6
    headers = {"User-Agent": [ua], "Cf-Ipcountry": [cc], "Cf-Ray": ["%016x-%s" % (rnd.getrandbits(64), colo)]}
    ref = rnd.choice(REFERRERS)
    if ref:
        headers["Referer"] = [ref]
    resp = {"Content-Type": [ctype]}
    if enc:
        resp["Content-Encoding"] = [enc]
    return json.dumps({"level": "info", "ts": ts, "logger": "http.log.access", "msg": "handled request",
                       "request": {"remote_ip": "127.0.0.1", "client_ip": ip, "proto": "HTTP/2.0", "method": "GET",
                                   "host": "example.com" if path.endswith(".html") and rnd.random() < 0.5 else "cdn.example.com",
                                   "uri": path, "headers": headers},
                       "duration": round(dur, 6), "size": size, "status": status, "resp_headers": resp})


def history(files, now):
    """DAYS of traffic: a daily rhythm, slow growth, and one launch-day spike."""
    out = []
    start = now - DAYS * 86400
    for h in range(DAYS * 24):
        t0 = start + h * 3600
        hour = time.gmtime(t0).tm_hour
        rate = 260 * (1 + 0.65 * math.sin((hour - 9) / 24 * 2 * math.pi)) * (1 + 0.04 * h / 24)
        if 4 * 24 + 14 <= h < 4 * 24 + 20:
            rate *= 3.2
        for _ in range(int(rate * rnd.uniform(0.85, 1.15))):
            out.append((t0 + rnd.uniform(0, 3600), None))
    out.sort()
    return [line(ts, files, 2400) for ts, _ in out if ts < now]


METRICS_PORT = 18486  # 1848x: run_all.py and the media tests use 1818x-1838x, so the demo can run beside them
STARTED = time.time()


def metrics_server():
    """Prometheus text for the Caddy and cloudflared health tiles, numbers that move like a quiet production box."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            up = time.time() - STARTED
            if self.path == "/caddy":
                body = ("process_cpu_seconds_total %f\nprocess_resident_memory_bytes %d\ngo_memstats_heap_inuse_bytes %d\n"
                        "go_goroutines %d\ngo_threads 14\nprocess_open_fds 61\nprocess_start_time_seconds %f\n"
                        "caddy_config_last_reload_successful 1\ncaddy_config_last_reload_success_timestamp_seconds %f\n"
                        'caddy_http_requests_in_flight{server="srv0"} %d\ncaddy_http_requests_total{server="srv0"} %d\n'
                        % (400 + up * 0.04 * (1 + rnd.random()), 61e6 + rnd.randrange(4_000_000), 28e6, 40 + rnd.randrange(12),
                           STARTED - 3 * 86400, STARTED - 3600, rnd.randrange(4), 54000 + up * 1.2))
            else:
                conns = [(i, loc, 11 + i * 2 + rnd.random() * 3) for i, loc in enumerate(["fra08", "ams01", "fra10", "ams06"])]
                body = 'build_info{goversion="go1.24.6",version="2025.9.1"} 1\ncloudflared_tunnel_ha_connections 4\n' \
                       "cloudflared_tunnel_total_requests %d\ncloudflared_tunnel_request_errors 0\n" \
                       "cloudflared_tunnel_concurrent_requests_per_tunnel %d\nprocess_cpu_seconds_total %f\n" \
                       "process_resident_memory_bytes %d\nprocess_start_time_seconds %f\n" \
                       'cloudflared_tunnel_response_by_code{status_code="200"} %d\n' % (
                           54000 + up * 1.2, rnd.randrange(3), 900 + up * 0.02, 41e6, STARTED - 3 * 86400, 51000 + up)
                for i, loc, rtt in conns:
                    body += ('cloudflared_tunnel_server_locations{connection_id="%d",edge_location="%s"} 1\n'
                             'quic_client_smoothed_rtt{conn_index="%d"} %f\nquic_client_latest_rtt{conn_index="%d"} %f\n'
                             'quic_client_sent_bytes{conn_index="%d"} %d\nquic_client_receive_bytes{conn_index="%d"} %d\n'
                             % (i, loc, i, rtt, i, rtt + 1, i, 9e8 + up * 30000, i, 4e7 + up * 2000))
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", METRICS_PORT), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def main():
    root = tempfile.mkdtemp(prefix="strata-demo-")
    home = os.path.join(root, "home")
    files_root = os.path.join(home, "files")
    os.makedirs(os.path.join(home, "generated"))
    caddyfile = os.path.join(home, "Caddyfile")
    with open(caddyfile, "w") as f:
        f.write("import %s\n" % os.path.join(home, "generated", "cdn.caddy").replace("\\", "/"))
    with open(os.path.join(home, "generated", "cdn.caddy"), "w") as f:
        f.write("# placeholder\n")
    print("generating files and %d days of traffic ..." % DAYS)
    files = make_files(files_root)
    access_log = os.path.join(home, "data", "access.log")
    os.makedirs(os.path.dirname(access_log))
    with open(access_log, "w") as f:
        f.write("\n".join(history(files, time.time())) + "\n")
    os.environ["STRATA_HOME"] = home
    sys.path.insert(0, ra.CODE)
    import auth  # noqa: E402
    cfg = {"instance": {"id": "example", "name": "example.com", "dry_run": True, "cdn_listen": ":18480",
                        "accent": "#e65a46"},
           "listen": "127.0.0.1:%d" % STRATA_PORT, "feed_listen": "127.0.0.1:18481", "transform_listen": "127.0.0.1:18483",
           "gate_listen": "127.0.0.1:18485", "media": {"listen": "127.0.0.1:18484"},
           "caddy_exe": ra.stub_caddy(os.path.join(root, "bin")), "caddyfile": caddyfile, "access_log": access_log,
           "caddy_metrics": "http://127.0.0.1:%d/caddy" % METRICS_PORT,
           "cloudflared_metrics": "http://127.0.0.1:%d/cloudflared" % METRICS_PORT,
           "cloudflared_config": os.path.join(home, "cloudflared.yml"),
           "storage_paths": [files_root], "public": {"hosts": ["cdn.example.com", "example.com"]},
           "public_base_url": "https://cdn.example.com",
           "auth": {"user": "alex", "password_hash": auth.hash_password(ra.PASSWORD)},
           "alerts": {"to": ["alex@example.com"]}}
    with open(os.path.join(home, "strata.json"), "w") as f:
        json.dump(cfg, f, indent=2)
    metrics_server()
    # a neutral host name on the System tiles instead of this machine's own
    launch = ("import runpy, socket, sys; socket.gethostname = lambda: 'cdn-01'; "
              "sys.argv = [sys.argv[1]] + sys.argv[2:]; runpy.run_path(sys.argv[0], run_name='__main__')")
    proc = subprocess.Popen([sys.executable, "-c", launch, os.path.join(ra.CODE, "strata.py"), "--home", home], cwd=ra.CODE,
                            env=dict(os.environ, STRATA_HOME=home), stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    ra.BASE = "http://127.0.0.1:%d" % STRATA_PORT
    if not ra.wait_up(proc):
        sys.exit("demo server did not start")
    db = os.path.join(home, "data", "strata.db")
    c = sqlite3.connect(db)
    c.execute("UPDATE account SET privacy_version=? WHERE user='alex'", [ra.privacy_version()])
    c.commit()
    c.close()
    token = ra.session(db, "alex")
    proxy = signed_in_proxy(token)
    req = urllib.request.Request("http://127.0.0.1:%d/api/serving/site" % PORT, method="POST",
                                 data=json.dumps({"error_page_502": "/404/502.html"}).encode(),
                                 headers={"X-Strata": "1", "Origin": "http://127.0.0.1:%d" % PORT, "Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=30).read()  # the 404 and 403 pages already sit at the default paths

    stop = threading.Event()

    def trickle():
        while not stop.wait(rnd.uniform(0.2, 1.2)):
            with open(access_log, "a") as f:
                f.write(line(time.time(), files, 2400) + "\n")
    threading.Thread(target=trickle, daemon=True).start()
    print("demo: http://127.0.0.1:%d   signed in as alex   (instance folder %s)" % (PORT, home))
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))  # a plain kill also stops the server and removes the folder
    try:
        proc.wait()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        proxy.shutdown()
        proc.terminate()
        proc.wait(10)
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
