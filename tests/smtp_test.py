"""SMTP delivery (alerts.send_smtp): STARTTLS / TLS / plain chosen right, login only when encrypted, a proper message.
Swaps smtplib's classes for a recorder, so no mail server is needed. Exit code 1 on failure."""
import os
import smtplib
import sys

sys.path[:0] = [os.path.join(os.path.dirname(__file__), ".."), os.path.join(os.path.dirname(__file__), "..", "vendor")]
import alerts  # noqa: E402

calls = []


class Fake:
    def __init__(self, host, port, **kw):
        calls.append(("open", type(self).__name__, host, port))
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def starttls(self, context=None): calls.append(("starttls",))
    def login(self, u, p): calls.append(("login", u, p))
    def send_message(self, m): calls.append(("send", m))


class SMTP(Fake): pass
class SMTP_SSL(Fake): pass


smtplib.SMTP, smtplib.SMTP_SSL = SMTP, SMTP_SSL
args = ("Strata <alerts@example.com>", ["a@x.org", "b@x.org"], "[Strata] Test", "plain", "<p>html</p>")

alerts.send_smtp({"host": "mail.example.com", "user": "u", "password": "p"}, *args)
assert calls[:3] == [("open", "SMTP", "mail.example.com", 587), ("starttls",), ("login", "u", "p")], calls
m = calls[3][1]
assert m["To"] == "a@x.org, b@x.org" and m["Subject"] == "[Strata] Test" and m["Message-ID"].endswith("@example.com>")
assert [p.get_content_type() for p in m.iter_parts()] == ["text/plain", "text/html"]

calls.clear()
alerts.send_smtp({"host": "mail.example.com", "port": 465, "security": "tls", "user": "u", "password": "p"}, *args)
assert calls[0] == ("open", "SMTP_SSL", "mail.example.com", 465) and ("starttls",) not in calls

calls.clear()  # a LAN relay without TLS and without sign-in
alerts.send_smtp({"host": "10.0.0.5", "security": "none"}, *args)
assert calls[0] == ("open", "SMTP", "10.0.0.5", 25) and [c[0] for c in calls[1:]] == ["send"], calls

try:  # never a password over plain text
    alerts.send_smtp({"host": "10.0.0.5", "security": "none", "user": "u", "password": "p"}, *args)
    raise SystemExit("FAIL: password sent without encryption")
except RuntimeError:
    pass

try:  # no header injection through an alert title
    alerts.send_smtp({"host": "h"}, args[0], args[1], "x\nBcc: evil@x.org", "t", "h")
    raise SystemExit("FAIL: line break accepted in the subject")
except ValueError:
    pass

assert alerts.provider({"smtp": {"host": "h"}, "resend_api_key": "re_x"}) == "smtp"  # no choice yet: SMTP
assert alerts.provider({"provider": "resend", "smtp": {"host": "h"}, "resend_api_key": "re_x"}) == "resend"
assert alerts.provider({"provider": "smtp", "resend_api_key": "re_x"}) == ""  # chosen but not set up: no silent fallback
assert alerts.provider({"resend_api_key": "re_x"}) == "resend" and not alerts.mail_ready({"resend_api_key": "re_x"})
print("smtp ok")
