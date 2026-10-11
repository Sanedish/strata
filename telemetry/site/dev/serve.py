#!/usr/bin/env python3
"""Local test server for the built site (dist/).

Serves dist/ with the same security headers as production and answers /api/stats and /api/live from
recorded fixtures, so the page can be exercised without the real backend.

  python build.py && python dev/serve.py [--port 8099] [--mode real|noedge|empty|hostile|big]
  (fixtures default to dev/fixtures: a recorded copy of the public /api/stats and /api/live output)

Modes rewrite the fixture on the fly:
  noedge   drops the Cloudflare edge block (tile layout must close the gap)
  empty    every list empty, every number zero, no live block
  hostile  every string is an XSS payload, every number is a string / null / negative / huge
  big      long lists with long labels (row-fitting must hide what does not fit)
"""
import argparse, ast, copy, http.server, json, mimetypes, pathlib, time, urllib.parse


def load_headers():
    """Read SECURITY_HEADERS from ../../telemetry.py (a plain literal dict, parsed with ast.literal_eval, never
    executed), so this server enforces exactly what production sends. Only HSTS and `upgrade-insecure-requests`
    are dropped: both are meaningless over http://127.0.0.1."""
    src = (pathlib.Path(__file__).resolve().parent.parent.parent / "telemetry.py").read_text(encoding="utf-8")
    headers = None
    for node in ast.parse(src).body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "SECURITY_HEADERS" for t in node.targets):
            headers = ast.literal_eval(node.value)
    assert headers and "Content-Security-Policy" in headers, "SECURITY_HEADERS not found in telemetry.py"
    headers.pop("Strict-Transport-Security", None)
    headers["Content-Security-Policy"] = headers["Content-Security-Policy"].replace("upgrade-insecure-requests; ", "")
    return headers


HEADERS = load_headers()
PAYLOAD = "<img src=x onerror=alert(1)>\"'><svg/onload=alert(2)>"


def transform(mode, d):
    d = copy.deepcopy(d)
    if mode == "noedge":
        d.pop("edge", None)
    elif mode == "empty":
        def z(v):
            if isinstance(v, dict):
                return {k: z(x) for k, x in v.items()}
            if isinstance(v, list):
                return []
            return 0 if isinstance(v, (int, float)) and not isinstance(v, bool) else v
        d = z(d)
        d["series"] = {"t0": time.time() - 86400, "step": 900, "reqs": [], "bytes": [], "visitors": [], "errors": [], "saved": []}
        d.pop("live", None)
        d.pop("edge", None)
    elif mode == "hostile":
        n = [0]

        def w(v):
            if isinstance(v, dict):
                return {k: w(x) for k, x in v.items()}
            if isinstance(v, list):
                return [w(x) for x in v]
            if isinstance(v, str):
                return PAYLOAD
            if isinstance(v, bool):
                return v
            if isinstance(v, (int, float)):
                n[0] += 1
                return [PAYLOAD + ";background:url(//evil.example/x)", None, -5, 1e308, "12;x", float(v)][n[0] % 6]
            return v
        d = w(d)
    elif mode == "big":
        def biglist(rows, key="k"):
            out = []
            for i in range(40):
                r = dict(rows[i % len(rows)]) if rows else {"k": "x", "c": 1, "b": 1}
                r[key] = f"{r.get(key, 'x')}-a-really-long-label-that-must-be-ellipsised-{i}"
                r["c"] = max(1, r.get("c", 1) * (40 - i) // 7)
                r["b"] = max(1, r.get("b", 1) * (40 - i) // 7)
                out.append(r)
            return out
        for key in ("countries", "colos", "agents", "os", "categories", "extensions", "collections", "threats"):
            if d.get(key):
                d[key] = biglist(d[key])
        d["inventory"]["cats"] = biglist(d["inventory"]["cats"])
        d["totals"]["reqs"] = 123456789
        d["totals"]["bytes"] = 98765432109876
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--fixtures", default=str(pathlib.Path(__file__).resolve().parent / "fixtures"))
    ap.add_argument("--mode", default="real", choices=["real", "noedge", "empty", "hostile", "big"])
    a = ap.parse_args()
    dist = pathlib.Path(__file__).resolve().parent.parent / "dist"
    fx = pathlib.Path(a.fixtures)

    class H(http.server.BaseHTTPRequestHandler):
        server_version = "test"
        sys_version = ""

        def log_message(self, *args):
            pass

        def send(self, code, body, ctype, cache="no-store"):
            self.send_response(code)
            for k, v in HEADERS.items():
                self.send_header(k, v)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", cache)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            u = urllib.parse.urlparse(self.path)
            if u.path == "/api/stats":
                rng = urllib.parse.parse_qs(u.query).get("range", ["24h"])[0]
                if rng not in ("24h", "7d", "30d"):
                    return self.send(400, b"bad range", "text/plain; charset=utf-8")
                d = json.loads((fx / f"stats-{rng}.json").read_text(encoding="utf-8-sig"))
                d["generated"] = time.time()
                return self.send(200, json.dumps(transform(a.mode, d)).encode(), "application/json")
            if u.path == "/api/live":
                d = json.loads((fx / "live.json").read_text(encoding="utf-8-sig"))
                d["generated"] = time.time()
                if a.mode == "empty":
                    return self.send(503, b"down", "text/plain; charset=utf-8")
                return self.send(200, json.dumps(transform(a.mode, d) if a.mode == "hostile" else d).encode(), "application/json")
            if u.path == "/favicon.ico":
                return self.send(204, b"", "image/x-icon")
            rel = "index.html" if u.path == "/" else urllib.parse.unquote(u.path).lstrip("/")
            f = (dist / rel).resolve()
            if dist not in f.parents or not f.is_file():
                return self.send(404, b"not found", "text/plain; charset=utf-8")
            ctype = mimetypes.guess_type(f.name)[0] or "application/octet-stream"
            if f.suffix in (".html", ".css", ".js"):
                ctype += "; charset=utf-8"
            self.send(200, f.read_bytes(), ctype)

        def do_POST(self):
            self.send(405, b"method not allowed", "text/plain; charset=utf-8")
        do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_POST

    http.server.ThreadingHTTPServer(("127.0.0.1", a.port), H).serve_forever()


if __name__ == "__main__":
    main()
