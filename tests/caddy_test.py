"""The generated Caddy config, checked by a real Caddy (`caddy validate`).

    python tests/caddy_test.py <test db>      (run_all.py runs it against its throwaway instance)

The rest of the suite uses a stub that accepts any config, so this is the only place the generated config meets
Caddy's own parser. It adds a gallery, an audio player and a link-preview rule first, so every kind of route is in
the config. Without a Caddy (STRATA_CADDY, or caddy on the PATH) it says so and passes.
"""
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_all as ra  # noqa: E402

DB = sys.argv[1]
caddy = os.environ.get("STRATA_CADDY") or shutil.which("caddy")
if not caddy:
    print("skipped: no caddy found (put it on the PATH or set STRATA_CADDY)")
    sys.exit(0)

root = ra.session(DB, "dev")
added = []
for body in ({"name": "Gallery test", "action": "gallery", "patterns": ["/gallery-test/*"]},
             {"name": "Player test", "action": "player", "patterns": ["/music-test/*"]},
             {"name": "Preview test", "action": "preview", "patterns": ["/notes.txt"], "params": {"title": "Notes"}},
             {"name": "Preview off test", "action": "preview", "patterns": ["/quiet/*"], "params": {"off": True}}):
    r = ra.post(root, "/api/serving/rule", body)
    if not r.get("result"):
        print("FAIL could not add rule %s: %s" % (body["name"], r))
        sys.exit(1)
    added.append(r["result"])

gen = os.path.join(os.path.dirname(os.path.dirname(DB)), "generated", "cdn.caddy")
d = tempfile.mkdtemp(prefix="strata-caddy-")
try:
    main = os.path.join(d, "Caddyfile")
    with open(main, "w", encoding="utf-8") as f:
        f.write("{\n\tadmin off\n}\nimport %s\n" % gen.replace("\\", "/"))
    p = subprocess.run([caddy, "validate", "--adapter", "caddyfile", "--config", main], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=120)
    ok = p.returncode == 0
    print(("PASS" if ok else "FAIL") + " caddy validate accepts the generated config (%s)" % caddy)
    if not ok:
        print((p.stderr or p.stdout)[-3000:])
finally:
    shutil.rmtree(d, ignore_errors=True)
    for rid in added:
        ra.post(root, "/api/serving/rule/delete", {"id": rid})
sys.exit(0 if ok else 1)
