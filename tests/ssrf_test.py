"""Exercise files._pinned_opener directly: public HTTPS must work (TLS verified), private targets must be refused."""
import os
import sys

os.environ["STRATA_HOME"] = sys.argv[1]
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import files  # noqa: E402
import urllib.request  # noqa: E402

ok = True
try:
    with files._pinned_opener().open(urllib.request.Request("https://example.com/"), timeout=15) as r:
        print("PASS https://example.com ->", r.status, "(certificate verified against the host name)")
except Exception as e:
    ok = False
    print("FAIL https://example.com ->", repr(e)[:200])
for url in ("http://127.0.0.1:8190/", "http://192.168.1.50/", "http://169.254.169.254/latest/meta-data/", "http://[::1]:8190/",
            "http://localtest.me/"):
    try:
        files._pinned_opener().open(urllib.request.Request(url), timeout=5)
        ok = False
        print("FAIL", url, "was fetched")
    except files.FileError as e:
        print("PASS", url, "refused:", str(e)[:90])
    except Exception as e:
        ok = False
        print("FAIL", url, "unexpected", repr(e)[:150])
sys.exit(0 if ok else 1)
