"""Try bot protection: a small site behind a real Caddy and a real Anubis, to open in a browser.

    python tests/anubis_demo.py --caddy <caddy> --anubis <anubis>    then open http://localhost:8480/ ; Ctrl+C stops it

(--caddy / --anubis default to STRATA_CADDY / STRATA_ANUBIS, then the PATH.) Everything lives in a temp folder; nothing
of your own installation is touched. The site is what a Strata drive with one "Bot challenge" rule looks like:

    http://localhost:8480/            a page: your browser gets Anubis' puzzle first, then the page
    http://localhost:8480/note.txt    a file: the same
    http://localhost:8480/gal/        a gallery folder: challenged even for a plain request

Try it from a terminal as well (the puzzle needs a browser; these do not run JavaScript):

    curl -i -H "Accept: text/html" -H "Sec-Fetch-Dest: document" http://localhost:8480/note.txt     307 to the puzzle
    curl -i -A "Mozilla/5.0 Discordbot/2.0" http://localhost:8480/note.txt                          the preview card (a stub here)
    curl -i http://localhost:8480/note.txt                                                           the file (default rule: pages only)

The link-preview server is a stub, so the card is just the word OGCARD; only the Caddy config, Anubis and the rule are real.
"""
import argparse
import http.server
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import anubis_test as t  # noqa: E402

PAGE = """<!doctype html><meta charset="utf-8"><title>Strata bot protection demo</title>
<style>body{font:15px/1.5 system-ui;max-width:42rem;margin:3rem auto;padding:0 1rem}code{background:#eee;padding:0 .3em}</style>
<h1>You passed the puzzle</h1>
<p>This page came from a Strata drive behind Caddy. Before it was sent, Caddy asked Anubis whether your browser had solved
its proof-of-work puzzle; it had, so you got the file.</p>
<p>The picture below is loaded by this page, so it is not challenged again (the page's pass cookie goes along):</p>
<p><img src="/pic.png" alt="a picture" width="160" height="90"></p>
<ul><li><a href="/note.txt">/note.txt</a>, a file</li><li><a href="/gal/">/gal/</a>, a gallery folder</li></ul>
<p>Open the same addresses with <code>curl</code> to see what a scraper gets (see tests/anubis_demo.py).</p>
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--caddy", default=t.CADDY)
    ap.add_argument("--anubis", default=t.ANUBIS)
    ap.add_argument("--port", type=int, default=8480)
    ap.add_argument("--difficulty", type=int, default=4)
    a = ap.parse_args()
    if not (a.caddy and a.anubis):
        sys.exit("needs a Caddy and an Anubis: --caddy <path> --anubis <path> (or STRATA_CADDY / STRATA_ANUBIS)")
    root = tempfile.mkdtemp(prefix="strata-scratchpad-")
    ports = {"cdn": a.port, "transform": a.port + 3, "anubis": a.port + 4, "metrics": a.port + 5}
    cfg = {"enabled": True, "bind": "127.0.0.1:%d" % ports["anubis"], "metrics": "127.0.0.1:%d" % ports["metrics"],
           "difficulty": a.difficulty, "exe": a.anubis, "public_url": "http://"}  # plain http here, not Cloudflare's https
    inst = t.instance(root, cfg, [t.GALLERY, t.challenge()], ports, hosts=["localhost"])
    files = os.path.join(inst["home"], "files")
    open(os.path.join(files, "index.html"), "w").write(PAGE)
    try:  # a real picture, if Pillow is around (it is, once requirements.txt is installed)
        sys.path.insert(0, os.path.join(t.CODE, "vendor"))
        from PIL import Image
        Image.new("RGB", (320, 180), (53, 114, 165)).save(os.path.join(files, "pic.png"))
    except ImportError:
        pass

    class Transform(http.server.BaseHTTPRequestHandler):  # the link-preview server, as a stub
        def do_GET(s):
            body = b"OGCARD" if s.headers.get("X-Strata-Embed") else b"JPEGCARD" if "card=1" in s.path else b"TRANSFORM"
            s.send_response(200)
            s.send_header("Content-Length", str(len(body)))
            s.end_headers()
            s.wfile.write(body)

        def log_message(*x):
            pass
    stub = http.server.ThreadingHTTPServer(("127.0.0.1", ports["transform"]), Transform)
    threading.Thread(target=stub.serve_forever, daemon=True).start()
    main_caddyfile = os.path.join(root, "Caddyfile.demo")
    with open(main_caddyfile, "w") as f:  # what the production Caddyfile has: Cloudflare's address trusted from loopback only
        f.write("{\n\tadmin off\n\tauto_https off\n\tservers {\n\t\ttrusted_proxies static private_ranges\n"
                "\t\tclient_ip_headers Cf-Connecting-Ip\n\t}\n}\nimport %s\n" % inst["gen"].replace("\\", "/"))
    env = dict(os.environ, APPDATA=root, XDG_CONFIG_HOME=root, HOME=root)
    log = open(os.path.join(root, "anubis.log"), "w")
    # the host has a port here (Anubis compares it with its redirect list, which holds bare host names)
    argv = inst["argv"] + ["--redirect-domains", "localhost,localhost:%d" % a.port]
    procs = [subprocess.Popen(argv, stdout=log, stderr=log)]
    for _ in range(100):  # Caddy only once Anubis listens: a browser opened early would get a 502
        try:
            socket.create_connection(("127.0.0.1", ports["anubis"]), 0.3).close()
            break
        except OSError:
            time.sleep(0.1)
    procs.append(subprocess.Popen([a.caddy, "run", "--adapter", "caddyfile", "--config", main_caddyfile], env=env,
                                  stdout=subprocess.DEVNULL, stderr=open(os.path.join(root, "caddy.log"), "w")))

    def stop(*_):
        for p in procs:
            p.terminate()
        stub.shutdown()
        shutil.rmtree(root, ignore_errors=True)
        sys.exit(0)
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    print("bot protection demo: http://localhost:%d/   (difficulty %d; Ctrl+C stops it)" % (a.port, a.difficulty), flush=True)
    print("Anubis log: %s" % os.path.join(root, "anubis.log"), flush=True)
    while True:
        time.sleep(1)
        if any(p.poll() is not None for p in procs):
            print("Caddy or Anubis stopped; see %s" % root, flush=True)
            stop()


if __name__ == "__main__":
    main()
