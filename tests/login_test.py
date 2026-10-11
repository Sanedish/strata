"""Exercise POST /login on the DEV instance (passwords are the dev seed's test values)."""
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8190"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def login(user, pw):
    req = urllib.request.Request(BASE + "/login", data=urllib.parse.urlencode({"user": user, "password": pw}).encode(),
                                 headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": BASE})
    try:
        r = urllib.request.build_opener(NoRedirect).open(req, timeout=20)
    except urllib.error.HTTPError as e:
        r = e
    return r.headers.get("Location")


ok = True
for user, pw, want, why in (
        ("lena", "correct horse battery staple 42", "/login?e=email", "right password reaches the e-mail-code step (mail not set up on dev)"),
        ("lena", "wrong password entirely", "/login?e=1", "wrong password is rejected"),
        ("nobody-here", "whatever", "/login?e=1", "unknown account is rejected"),
        ("alexandra.konstantinopoulou-wellington_contractor-2026-team", "x", "/login?e=1", "pending account is rejected")):
    got = login(user, pw)
    good = got == want
    ok &= good
    print(("PASS " if good else "FAIL ") + why + ("" if good else "  got %s" % got))
sys.exit(0 if ok else 1)
