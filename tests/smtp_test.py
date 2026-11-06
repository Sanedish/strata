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
args = ("Corium <alerts@example.com>", ["a@x.org", "b@x.org"], "[Corium] Test", "plain", "<p>html</p>")

alerts.send_smtp({"host": "mail.example.com", "user": "u", "password": "p"}, *args)
assert calls[:3] == [("open", "SMTP", "mail.example.com", 587), ("starttls",), ("login", "u", "p")], calls
m = calls[3][1]
assert m["To"] == "a@x.org, b@x.org" and m["Subject"] == "[Corium] Test" and m["Message-ID"].endswith("@example.com>")
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

# -- the e-mail templates (mailtpl.py): every kind renders, goes out as text + HTML, and escapes what it is given
import mailtpl  # noqa: E402

for kind in mailtpl.KINDS:
    m = mailtpl.render(kind, mailtpl.sample(kind))
    assert not m["unknown"], (kind, m["unknown"])
    for part in ("subject", "text", "html"):
        assert m[part] and "{{" not in m[part], (kind, part)
    assert m["html"].lstrip().lower().startswith("<!doctype html>") and "</html>" in m["html"], kind
    assert 'class="card"' in m["html"] and "prefers-color-scheme: dark" in m["html"], kind  # error-page layout, dark mode
    assert mailtpl.common()["accent"] in m["html"], kind  # the instance accent, inlined
    calls.clear()
    alerts.send_smtp({"host": "mail.example.com"}, args[0], ["a@x.org"], m["subject"], m["text"], m["html"])
    sent = calls[-1][1]
    assert [p.get_content_type() for p in sent.iter_parts()] == ["text/plain", "text/html"], kind
    assert sent["Subject"] == m["subject"], kind

# untrusted values (alert titles carry user names and host names) are escaped, also through {{{ }}}
evil = '<img src=x onerror=alert(1)>"\'&'
m = mailtpl.render("alert", mailtpl.alert_vars([{"ts": 0, "severity": "warning", "title": evil, "detail": evil}]))
assert "<img src=x" not in m["html"] and "&lt;img src=x onerror=alert(1)&gt;" in m["html"], m["html"]
assert evil in m["text"] and m["subject"].endswith(evil)
m = mailtpl.render("invite", {"user": evil, "link": "https://h/e?token=a&b=\"x"},
                   {"html": "<p>{{{user}}}</p><a href=\"{{link}}\">x</a>", "subject": "{{user}}\r\nBcc: e@x.org",
                    "css": "p { color: {{user}}; }"})
assert "<img" not in m["html"] and 'href="https://h/e?token=a&amp;b=&quot;x"' in m["html"], m["html"]
assert "\n" not in m["subject"] and "\r" not in m["subject"]
assert "onerror=alert(1)>" not in m["html"].split("<style", 1)[1].split("</style>")[0], "CSS variable not made CSS-safe"
assert mailtpl.render("alert", mailtpl.sample("alert"), {"html": "{{{alerts_html}}}"})["html"].count('<td class="al-sev') == 2

# template syntax: sections, inverted sections, unknown names
f = lambda src, **v: mailtpl.fill(src, v, "text")
assert f("a{{#x}}b{{/x}}c", x="1") == "abc" and f("a{{#x}}b{{/x}}c", x="") == "ac" and f("{{^x}}none{{/x}}") == "none"
unk = set()
mailtpl.fill("{{a}} {{#b}}{{/b}}", {}, "html", unknown=unk)
assert unk == {"a", "b"}

# CSS inlining: simple rules into style attributes, inline styles win, @media stays in <style> only
doc = mailtpl.inline_css('<html><head></head><body><p class="a b" style="color: red">x</p><td id="z">y</td>'
                         '<div class="a c">z</div></body></html>',
                         "p { margin: 0 } .a.b { color: blue } #z { padding: 1px } div .a { font-size: 9px } "
                         "@media (max-width: 9px) { p { margin: 9px } }")
assert '<p class="a b" style="margin: 0; color: blue; color: red">' in doc, doc
assert '<td id="z" style="padding: 1px">' in doc and '<div class="a c">' in doc and "9px" not in doc, doc
assert "<style" not in mailtpl.with_style("<p>x</p>", "  ") and mailtpl.with_style("<head></head>", "p{}").startswith("<head><style")

# a stored override is used per part; an empty part falls back to the default
saved = mailtpl.CFG.get("emails")
mailtpl.CFG["emails"] = {"test": {"subject": "Custom {{site}}", "html": "", "css": "", "text": ""}}
try:
    m = mailtpl.render("test", {"requested_by": "x"})
    assert m["subject"].startswith("Custom ") and 'class="card"' in m["html"]
    assert mailtpl.overrides("test") == {"subject": "Custom {{site}}"}
    mailtpl.CFG["emails"] = {"test": None}
    assert mailtpl.template("test") == mailtpl.defaults("test")
finally:
    if saved is None:
        mailtpl.CFG.pop("emails", None)
    else:
        mailtpl.CFG["emails"] = saved
print("smtp ok")
