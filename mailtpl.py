"""E-mail templates: every message Corium sends, in the look of its error pages, editable per instance.

Each kind of e-mail (KINDS) has four parts: subject, HTML, CSS and a plain-text version. The defaults live here; an
instance overrides any part in its strata.json under "emails" (Settings › Emails, owner only: a template sees the
sign-in codes and reset links it carries, so whoever edits one could send them elsewhere):

    "emails": {"login_code": {"subject": "", "html": "<!doctype html>...", "css": "", "text": ""}, "invite": null}

An empty part means the default; null drops the whole override.

Template syntax, the same in every part:
    {{name}}               a variable. HTML-escaped in the HTML, as is in the text and subject, CSS-safe in the CSS
    {{{name}}}             unescaped: only for the variables Corium builds as HTML itself (marked html=True below);
                           any other variable is escaped anyway
    {{#name}}...{{/name}}  shown when the variable is set (not empty, not 0)
    {{^name}}...{{/name}}  shown when it isn't

Sending: the CSS goes into a <style> in the head, and its simple rules (tag, .class, #id and lists of those) are also
copied into style attributes, for the mail apps that drop <style>. @media rules (dark mode, narrow screens) stay in
<style> only. Inline styles written in the HTML win over the copied rules.
"""
import html
import re
import time

import core
from core import CFG

FIELDS = ("subject", "html", "css", "text")
MAX_FIELD = 100000
DEFAULT_ACCENT = "#ec3013"

SANS = '-apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif'
MONO = 'ui-monospace, "SF Mono", "Cascadia Code", Consolas, monospace'


# ---------------------------------------------------------------- variables

def V(desc, sample, html_=False):
    return {"desc": desc, "sample": sample, "html": html_}


COMMON = {
    "site": V("This site's name (the instance name)", "example.com"),
    "brand": V("The dashboard's name from Settings › Branding, else Corium", "Corium"),
    "accent": V("This site's accent colour", DEFAULT_ACCENT),
    "dashboard": V("The dashboard's address, when known", "https://admin.example.com"),
    "date": V("When the e-mail was made, local time", "2026-11-01 08:00"),
    "year": V("The current year", "2026"),
}

SAMPLE_ALERTS = [
    {"ts": 0, "severity": "critical", "title": "Cloudflare tunnel is down", "detail": "connection refused"},
    {"ts": 0, "severity": "warning", "title": "20 failed logins from 203.0.113.7",
     "detail": "Last attempted user name: 'admin'. The address is locked out after 8 failures in 15 minutes."},
]
SAMPLE_STATS = [("Requests", "184,220"), ("Data served", "42.17 GB"), ("Visitors", "3,904"), ("Errors", "312 4xx, 4 5xx"),
                ("Probe requests", "1,207"), ("Suspicious requests (not in the error counts)", "880 from 41 addresses"),
                ("New blacklist entries", "6"), ("Alerts", "2 warning, 1 info")]


# ---------------------------------------------------------------- the default look

CSS = """/* The look of Corium's error pages. Simple rules (tag, .class, #id) are copied into style attributes when the
   e-mail is sent; the @media rules at the end stay in <style> for the mail apps that read them. */
body { margin: 0; padding: 0; background-color: #ececec; -webkit-text-size-adjust: 100%; }
.page { background-color: #ececec; }
.outer { padding: 28px 12px; }
.card { width: 600px; max-width: 600px; background-color: #ffffff; border-top: 4px solid {{accent}}; }
.head { padding: 30px 36px 22px; background-color: #ffffff; }
.ray { font-family: MONO; font-size: 12px; line-height: 1.5; color: #8a8a8a; }
h1 { margin: 6px 0 0; font-family: SANS; font-size: 34px; font-weight: 300; line-height: 1.15; letter-spacing: -0.025em; color: #333333; }
.subtitle { margin: 4px 0 0; font-family: SANS; font-size: 19px; font-weight: 300; line-height: 1.35; color: #8a8a8a; }
.band { padding: 26px 36px; background-color: #ececec; border-top: 1px solid #d4d4d4; border-bottom: 1px solid #d4d4d4; }
.node { padding: 0 6px; text-align: center; vertical-align: top; }
.label { font-family: SANS; font-size: 12px; line-height: 1.3; color: #6b6b6b; }
.who { font-family: SANS; font-size: 22px; font-weight: 300; line-height: 1.3; letter-spacing: -0.015em; color: #8a8a8a; }
.state { font-family: SANS; font-size: 15px; line-height: 1.35; color: #7fae22; }
.state-warn { color: #c98a06; }
.state-err { color: #c8282d; }
.code { display: inline-block; margin: 8px 0; padding: 12px 22px; background-color: #ffffff; border: 1px solid #d4d4d4; border-radius: 6px; font-family: MONO; font-size: 34px; font-weight: 600; letter-spacing: 0.3em; color: #333333; }
.btn { display: inline-block; padding: 13px 24px; background-color: {{accent}}; border-radius: 4px; font-family: SANS; font-size: 15px; font-weight: 600; line-height: 1; color: #ffffff; text-decoration: none; }
.url { margin-top: 12px; font-family: MONO; font-size: 11px; line-height: 1.5; color: #8a8a8a; word-break: break-all; }
.text { padding: 26px 36px 28px; background-color: #ffffff; }
.col { width: 50%; padding: 0 14px 0 0; vertical-align: top; }
.col-r { padding: 0 0 0 14px; }
h2 { margin: 0 0 6px; font-family: SANS; font-size: 18px; font-weight: 500; line-height: 1.2; letter-spacing: -0.02em; color: #333333; }
p { margin: 0 0 10px; font-family: SANS; font-size: 14px; line-height: 1.6; color: #6b6b6b; }
ul { margin: 0 0 10px; padding-left: 18px; }
li { font-family: SANS; font-size: 14px; line-height: 1.6; color: #6b6b6b; }
a { color: #333333; text-decoration: underline; }
strong { color: #333333; font-weight: 600; }
code { padding: 0 5px; background-color: #f3f3f3; border: 1px solid #d9d9d9; border-radius: 4px; font-family: MONO; font-size: 12px; color: #333333; }
.al { width: 100%; }
.al-sev { width: 86px; padding: 10px 10px 10px 0; vertical-align: top; font-family: MONO; font-size: 11px; line-height: 1.6; color: #7fae22; text-transform: uppercase; }
.sev-warning { color: #c98a06; }
.sev-critical { color: #c8282d; }
.al-main { padding: 10px 0; vertical-align: top; border-bottom: 1px solid #d9d9d9; }
.al-title { font-family: SANS; font-size: 15px; line-height: 1.35; color: #333333; }
.al-detail { font-family: SANS; font-size: 13px; line-height: 1.5; color: #6b6b6b; }
.al-when { font-family: MONO; font-size: 11px; line-height: 1.6; color: #8a8a8a; }
.st { width: 100%; }
.st-k { padding: 6px 12px 6px 0; border-bottom: 1px solid #d9d9d9; font-family: SANS; font-size: 13px; color: #6b6b6b; }
.st-v { padding: 6px 0; border-bottom: 1px solid #d9d9d9; font-family: MONO; font-size: 13px; color: #333333; text-align: right; }
.foot { padding: 14px 36px; background-color: #ffffff; border-top: 1px solid #d9d9d9; font-family: SANS; font-size: 12px; line-height: 1.5; color: #8a8a8a; text-align: center; }
.foot-link { color: #8a8a8a; }

@media (max-width: 620px) {
  .card { width: 100% !important; }
  .outer { padding: 0 !important; }
  .head, .band, .text, .foot { padding-left: 20px !important; padding-right: 20px !important; }
  .col, .col-r { display: block !important; width: 100% !important; padding: 0 0 14px !important; }
  h1 { font-size: 28px !important; }
  .code { font-size: 28px !important; letter-spacing: 0.2em !important; }
}
@media (prefers-color-scheme: dark) {
  body, .page, .band { background-color: #0b0b0d !important; }
  .card, .head, .text, .foot { background-color: #1a1a1d !important; }
  .band { border-color: #2a2a2e !important; }
  h1, h2, strong, a, .al-title, .st-v { color: #f4f4f5 !important; }
  p, li, .label, .al-detail, .st-k { color: #a1a1aa !important; }
  .ray, .subtitle, .who, .foot, .foot-link, .url, .al-when { color: #71717a !important; }
  .code { background-color: #26262b !important; border-color: #3a3a41 !important; color: #f4f4f5 !important; }
  code { background-color: #222226 !important; border-color: #2a2a2e !important; color: #f4f4f5 !important; }
  .foot, .al-main, .st-k, .st-v { border-color: #2a2a2e !important; }
  .state, .al-sev { color: #9bca3e !important; }
  .state-warn, .sev-warning { color: #f0b429 !important; }
  .state-err, .sev-critical { color: #f26363 !important; }
}
""".replace("font-family: SANS", "font-family: " + SANS).replace("font-family: MONO", "font-family: " + MONO)

LAYOUT = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<title>@HEADING@</title>
</head>
<body>
<div style="display:none;max-height:0;overflow:hidden;opacity:0">@PREHEADER@</div>
<table role="presentation" class="page" width="100%" cellpadding="0" cellspacing="0" border="0">
<tr><td class="outer" align="center">
<table role="presentation" class="card" width="600" cellpadding="0" cellspacing="0" border="0">
<tr><td class="head">
  <div class="ray">{{site}} &middot; @KICKER@</div>
  <h1>@HEADING@</h1>
  <div class="subtitle">@SUBTITLE@</div>
</td></tr>
<tr><td class="band">
@BAND@
</td></tr>
<tr><td class="text">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
    <td class="col">
      <h2>What happened?</h2>
      @HAPPENED@
    </td>
    <td class="col col-r">
      <h2>What can I do?</h2>
      @TODO@
    </td>
  </tr></table>
</td></tr>
<tr><td class="foot">{{site}} &middot; {{#dashboard}}<a class="foot-link" href="{{dashboard}}">{{brand}}</a>{{/dashboard}}{{^dashboard}}{{brand}}{{/dashboard}} &middot; {{date}}</td></tr>
</table>
</td></tr>
</table>
</body>
</html>
"""


def nodes(*items):
    """The error page's status row: label, name, state per node."""
    cells = "".join('<td class="node" width="%d%%"><div class="label">%s</div><div class="who">%s</div>'
                    '<div class="state%s">%s</div></td>' % (100 // len(items), lab, who, " state-" + st if st else "", txt)
                    for lab, who, st, txt in items)
    return ('<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0"><tr>%s</tr></table>'
            % cells)


def centered(inner):
    return ('<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0"><tr>'
            '<td align="center" style="text-align:center">%s</td></tr></table>' % inner)


def page(kicker, heading, subtitle, preheader, band, happened, todo):
    out = LAYOUT
    for k, v in (("@KICKER@", kicker), ("@HEADING@", heading), ("@SUBTITLE@", subtitle), ("@PREHEADER@", preheader),
                 ("@BAND@", band), ("@HAPPENED@", happened), ("@TODO@", todo)):
        out = out.replace(k, v)
    return out


SIGN = "\n\n-- \n{{site}} · {{brand}}{{#dashboard}}\n{{dashboard}}{{/dashboard}}\n"

KINDS = {
    "alert": {
        "label": "Alerts",
        "desc": "New alerts at or above the e-mail level (Alerts › Delivery), a batch at a time. The subject and text "
                "also go to the webhooks.",
        "vars": {
            "summary": V("The alert's title, or the number of alerts and the first title", "2 alerts: Cloudflare tunnel is down"),
            "count": V("How many alerts this e-mail carries", "2"),
            "title": V("The first alert's title", "Cloudflare tunnel is down"),
            "severity": V("The highest level among them: info, warning or critical", "critical"),
            "state": V("err, warn or ok: the highest level as a state-* class name", "err"),
            "alerts_html": V("Every alert as table rows (level, title, detail, time)", "", True),
            "alerts_text": V("Every alert as plain text", ""),
        },
        "subject": "[{{site}}] {{summary}}",
        "html": page("Alerts", "{{count}} new alert{{#plural}}s{{/plural}}", "{{title}}",
                     "{{summary}}",
                     '<table role="presentation" class="al" cellpadding="0" cellspacing="0" border="0">{{{alerts_html}}}</table>',
                     "<p>Corium noticed something on <strong>{{site}}</strong> that needs a look. The highest level "
                     "in this e-mail is <strong>{{severity}}</strong>.</p>",
                     "<ul><li>Open the Alerts view{{#dashboard}} in <a href=\"{{dashboard}}\">the dashboard</a>"
                     "{{/dashboard}} and mark them done once handled.</li><li>Change which levels are e-mailed under "
                     "Alerts › Delivery.</li></ul>"),
        "text": "{{summary}}\n\n{{alerts_text}}" + SIGN,
    },
    "digest": {
        "label": "Daily or weekly report",
        "desc": "The summary e-mail of the past day or week (Alerts › Delivery › Summary e-mail).",
        "vars": {
            "period": V("Daily or Weekly", "Daily"),
            "span": V("day or week", "day"),
            "requests": V("Requests", "184,220"), "data_served": V("Data served", "42.17 GB"),
            "visitors": V("Unique visitors", "3,904"), "errors_4xx": V("4xx responses", "312"),
            "errors_5xx": V("5xx responses", "4"), "probes": V("Probe requests", "1,207"),
            "suspicious": V("Suspicious requests", "880"), "suspicious_ips": V("Addresses they came from", "41"),
            "bans": V("New blacklist entries", "6"), "alerts": V("Alerts by level, or none", "2 warning, 1 info"),
            "stats_html": V("Every figure as table rows", "", True),
            "stats_text": V("Every figure as plain text", ""),
        },
        "subject": "[{{site}}] {{period}} report",
        "html": page("{{period}} report", "{{period}} report", "The past {{span}} on {{site}}",
                     "{{requests}} requests, {{visitors}} visitors, {{data_served}} served",
                     nodes(("Requests", "{{requests}}", "", "served"), ("Visitors", "{{visitors}}", "", "unique"),
                           ("Data", "{{data_served}}", "", "sent")) +
                     '<div style="height:18px;line-height:18px">&nbsp;</div>'
                     '<table role="presentation" class="st" cellpadding="0" cellspacing="0" border="0">{{{stats_html}}}</table>',
                     "<p>Corium's summary of the past {{span}} on <strong>{{site}}</strong>. Probe and "
                     "suspicious requests are kept out of the error counts.</p>",
                     "<ul><li>Look closer in Traffic and Security{{#dashboard}} in <a href=\"{{dashboard}}\">the "
                     "dashboard</a>{{/dashboard}}.</li><li>Turn the report off or change its hour under Alerts › "
                     "Delivery.</li></ul>"),
        "text": "{{site}}: {{period}} report\n\n{{stats_text}}" + SIGN,
    },
    "test": {
        "label": "Test message",
        "desc": "Sent by Send test under Alerts › Delivery, to check the set-up.",
        "vars": {"requested_by": V("The account that sent the test", "owner")},
        "subject": "[{{site}}] Test message",
        "html": page("Test", "It works", "E-mail from {{site}} reaches you",
                     "This is a test from {{site}}.",
                     nodes(("Corium", "{{site}}", "", "Working"), ("Mail provider", "Delivery", "", "Working"),
                           ("You", "Inbox", "", "Working")),
                     "<p><strong>{{requested_by}}</strong> sent this test from Corium to check that alerts, "
                     "reports and sign-in codes can reach this address.</p>",
                     "<p>Nothing. If it landed in spam, mark it as not spam so the real alerts don't.</p>"),
        "text": "This is a test from {{site}}, sent by {{requested_by}}. E-mail delivery works." + SIGN,
    },
    "login_code": {
        "label": "Sign-in code",
        "desc": "The code an account types in after its password, when it has no authenticator app.",
        "vars": {
            "code": V("The six-digit code", "482915"), "user": V("The account signing in", "alex"),
            "minutes": V("Minutes the code works", "10"), "ip": V("The address the sign-in came from", "203.0.113.7"),
        },
        "subject": "[{{site}}] Your sign-in code",
        "html": page("Sign-in", "Your sign-in code", "for {{user}}",
                     "Your sign-in code for {{site}}. It expires in {{minutes}} minutes.",
                     centered('<div class="label">Verification code</div><div class="code">{{code}}</div>'
                              '<div class="state">Valid for {{minutes}} minutes</div>'),
                     "<p>Someone signed in to <strong>{{site}}</strong> as <strong>{{user}}</strong> with the right "
                     "password{{#ip}} from <code>{{ip}}</code>{{/ip}}. This code is the second step.</p>",
                     "<p>If it was you, type the code into the sign-in page. It works once.</p>"
                     "<p>If it wasn't, don't share the code, and change your password: someone knows it.</p>"),
        "text": "Your {{site}} sign-in code: {{code}}\n\nIt expires in {{minutes}} minutes and works once. Someone "
                "signed in as {{user}}{{#ip}} from {{ip}}{{/ip}} with the right password. If that wasn't you, don't "
                "share the code and change your password." + SIGN,
    },
    "email_change": {
        "label": "New e-mail address",
        "desc": "The code that confirms a new address for an account (Settings › Account).",
        "vars": {
            "code": V("The six-digit code", "482915"), "user": V("The account", "alex"),
            "email": V("The new address", "alex@example.org"), "minutes": V("Minutes the code works", "10"),
            "ip": V("The address the change came from", "203.0.113.7"),
        },
        "subject": "[{{site}}] Confirm your new e-mail address",
        "html": page("Account", "Confirm this address", "for {{user}}",
                     "Your code to confirm {{email}} for {{site}}.",
                     centered('<div class="label">Verification code</div><div class="code">{{code}}</div>'
                              '<div class="state">Valid for {{minutes}} minutes</div>'),
                     "<p>The account <strong>{{user}}</strong> on <strong>{{site}}</strong> asked to use "
                     "<strong>{{email}}</strong> for sign-in codes and messages{{#ip}}, from <code>{{ip}}</code>"
                     "{{/ip}}.</p>",
                     "<p>If it was you, type the code into Settings › Account.</p>"
                     "<p>If it wasn't, ignore this e-mail: the address only changes with the code.</p>"),
        "text": "Your code to confirm {{email}} for {{user}} on {{site}}: {{code}}\n\nIt expires in {{minutes}} "
                "minutes. If you didn't ask for this, ignore this message." + SIGN,
    },
    "invite": {
        "label": "Invitation",
        "desc": "Sent when an administrator invites someone or creates an account with an e-mail address.",
        "vars": {
            "user": V("The new account's user name", "alex"), "link": V("The set-up link", "https://admin.example.com/enroll?token=abc"),
            "hours": V("Hours the link works", "24"), "role": V("owner, admin or employee", "employee"),
            "invited_by": V("The administrator who sent it", "owner"),
        },
        "subject": "[{{site}}] Your account invitation",
        "html": page("Invitation", "You're invited", "to {{site}}",
                     "{{invited_by}} invited you to {{site}}. Set your password within {{hours}} hours.",
                     centered('<a class="btn" href="{{link}}">Set up your account</a>'
                              '<div class="url">{{link}}</div>'),
                     "<p><strong>{{invited_by}}</strong> made an account for you on <strong>{{site}}</strong>: "
                     "user name <strong>{{user}}</strong>.</p>",
                     "<p>Open the link, choose a password and read the privacy note. It works for {{hours}} hours "
                     "and only once.</p><p>Not expecting this? Ignore the e-mail and the account stays unused.</p>"),
        "text": "{{invited_by}} invited you to {{site}} as {{user}}.\n\nSet your password and review the privacy "
                "note within {{hours}} hours:\n{{link}}" + SIGN,
    },
    "password_reset": {
        "label": "Password reset",
        "desc": "Sent when an administrator resets an account's password.",
        "vars": {
            "user": V("The account", "alex"), "link": V("The reset link", "https://admin.example.com/enroll?token=abc"),
            "hours": V("Hours the link works", "24"), "requested_by": V("The administrator who reset it", "owner"),
        },
        "subject": "[{{site}}] Reset your password",
        "html": page("Account", "Reset your password", "for {{user}}",
                     "Set a new password for {{site}} within {{hours}} hours.",
                     centered('<a class="btn" href="{{link}}">Set a new password</a>'
                              '<div class="url">{{link}}</div>'),
                     "<p><strong>{{requested_by}}</strong> started a password reset for your account "
                     "<strong>{{user}}</strong> on <strong>{{site}}</strong>.</p>",
                     "<p>Open the link and choose a new password. It works for {{hours}} hours and only once.</p>"
                     "<p>Didn't expect this? Ask {{requested_by}} about it before you use the link.</p>"),
        "text": "{{requested_by}} started a password reset for {{user}} on {{site}}.\n\nSet a new password within "
                "{{hours}} hours:\n{{link}}" + SIGN,
    },
}
KINDS["alert"]["vars"]["plural"] = V("Set when there is more than one alert", "1")
for _k in KINDS.values():
    _k["css"] = CSS


# ---------------------------------------------------------------- template engine

_SECTION = re.compile(r"\{\{([#^])\s*([a-z_][a-z0-9_]*)\s*\}\}(.*?)\{\{/\s*\2\s*\}\}", re.S)
_VAR = re.compile(r"\{\{\{\s*([a-z_][a-z0-9_]*)\s*\}\}\}|\{\{\s*([a-z_][a-z0-9_]*)\s*\}\}")
_CSS_UNSAFE = re.compile(r"[<>{};\"'\\\r\n]")


def _truthy(v):
    return v not in (None, "", 0, "0", False, [], {})


def fill(src, vals, mode, safe=(), unknown=None):
    """Fill one template part. mode: html | text | subject | css. `safe`: names that {{{x}}} may put in unescaped."""
    def section(m):
        if m.group(2) not in vals and unknown is not None:
            unknown.add(m.group(2))
        on = _truthy(vals.get(m.group(2)))
        return m.group(3) if on == (m.group(1) == "#") else ""

    for _ in range(20):  # nested sections: inner ones go first
        new = _SECTION.sub(section, src)
        if new == src:
            break
        src = new

    def var(m):
        name = m.group(1) or m.group(2)
        if name not in vals and unknown is not None:
            unknown.add(name)
        v = vals.get(name)
        v = "" if v is None else str(v)
        if mode == "html":
            return v if m.group(1) and name in safe else html.escape(v, quote=True)
        if mode == "css":
            return _CSS_UNSAFE.sub("", v)
        return v

    out = _VAR.sub(var, src)
    if mode == "subject":
        out = re.sub(r"\s+", " ", out).strip()[:250]
    elif mode == "text":
        out = out.replace("\r\n", "\n").replace("\r", "\n")
    return out


# ---------------------------------------------------------------- CSS inlining

_SIMPLE = re.compile(r"^([a-z][a-z0-9]*)?((?:[.#][A-Za-z_][\w-]*)*)$")
_TAG = re.compile(r"<([a-zA-Z][a-zA-Z0-9]*)(\s(?:[^<>\"']|\"[^\"]*\"|'[^']*')*?)?(/?)>")
_ATTR = re.compile(r"""\s([a-zA-Z_:][-\w:.]*)\s*=\s*("[^"]*"|'[^']*'|[^\s"'>]+)""")
_SKIP = {"html", "head", "meta", "title", "style", "link", "br", "script"}


def _strip_blocks(css):
    """CSS without comments and @-blocks (@media and the like): those stay in <style> only."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    out, i = [], 0
    while i < len(css):
        at = css.find("@", i)
        if at < 0:
            out.append(css[i:])
            break
        out.append(css[i:at])
        brace, semi = css.find("{", at), css.find(";", at)
        if brace < 0 or 0 <= semi < brace:  # @import / @charset: up to the semicolon
            i = len(css) if semi < 0 else semi + 1
            continue
        depth, j = 0, brace
        while j < len(css):
            depth += {"{": 1, "}": -1}.get(css[j], 0)
            j += 1
            if depth == 0:
                break
        i = j
    return "".join(out)


def _rules(css):
    """[(specificity, order, tag, classes, id, declarations)] for the simple selectors in `css`."""
    rules, order = [], 0
    for sel_list, body in re.findall(r"([^{}]+)\{([^{}]*)\}", _strip_blocks(css)):
        decls = [d.strip() for d in body.split(";") if ":" in d]
        if not decls:
            continue
        for sel in sel_list.split(","):
            sel = sel.strip()
            m = _SIMPLE.match(sel)
            if not sel or not m:
                continue
            parts = re.findall(r"([.#])([\w-]+)", m.group(2))
            cls = {p[1] for p in parts if p[0] == "."}
            ids = [p[1] for p in parts if p[0] == "#"]
            if len(ids) > 1:
                continue
            spec = 100 * len(ids) + 10 * len(cls) + (1 if m.group(1) else 0)
            order += 1
            rules.append((spec, order, (m.group(1) or "").lower(), cls, ids[0] if ids else None, decls))
    rules.sort(key=lambda r: (r[0], r[1]))
    return rules


def inline_css(doc, css):
    """Copy the simple rules of `css` into the style attributes of the body's elements (existing styles win)."""
    rules = _rules(css)
    if not rules:
        return doc
    start = doc.lower().find("<body")
    start = 0 if start < 0 else start

    def tag(m):
        name, attrs, close = m.group(1).lower(), m.group(2) or "", m.group(3)
        if name in _SKIP:
            return m.group(0)
        found = {k.lower(): v for k, v in _ATTR.findall(attrs)}
        unq = lambda v: html.unescape(v[1:-1] if v[:1] in "\"'" else v)
        cls = set(unq(found.get("class", '""')).split())
        id_ = unq(found["id"]) if "id" in found else None
        decls = [d for _, _, t, c, i, ds in rules if (not t or t == name) and c <= cls and (i is None or i == id_)
                 for d in ds]
        if not decls:
            return m.group(0)
        old = unq(found["style"]).strip().rstrip(";") if "style" in found else ""
        style = "; ".join(decls + ([old] if old else [])).replace('"', "'")  # font names: no &quot; in the attribute
        attrs = re.sub(r"""\sstyle\s*=\s*("[^"]*"|'[^']*'|[^\s"'>]+)""", "", attrs, flags=re.I)
        return '<%s%s style="%s"%s>' % (m.group(1), attrs.rstrip(), html.escape(style, quote=False), close)

    body = doc[start:]
    head = body[:body.find(">") + 1] if body.lower().startswith("<body") else ""
    rest = body[len(head):]
    # <style> inside the body isn't touched: split it out, inline the rest
    pieces = re.split(r"(<style\b.*?</style>)", rest, flags=re.S | re.I)
    rest = "".join(p if p.lower().startswith("<style") else _TAG.sub(tag, p) for p in pieces)
    return doc[:start] + (_TAG.sub(tag, head) if head else "") + rest


def with_style(doc, css):
    if not css.strip():
        return doc
    block = '<style type="text/css">\n%s\n</style>\n' % css.replace("</", "<\\/")
    i = doc.lower().find("</head>")
    return doc[:i] + block + doc[i:] if i >= 0 else block + doc


# ---------------------------------------------------------------- per-instance overrides

def overrides(kind):
    o = (CFG.get("emails") or {}).get(kind)
    return {f: o[f] for f in FIELDS if isinstance(o, dict) and isinstance(o.get(f), str) and o[f]} if isinstance(o, dict) else {}


def defaults(kind):
    k = KINDS[kind]
    return {f: k[f] for f in FIELDS}


def template(kind):
    return dict(defaults(kind), **overrides(kind))


def check(kind, fields):
    """The parts of an edit as strings, or ValueError."""
    if kind not in KINDS:
        raise ValueError("unknown kind of e-mail")
    out = {}
    for f in FIELDS:
        v = fields.get(f)
        if v is None:
            continue
        if not isinstance(v, str):
            raise ValueError("%s must be text" % f)
        if len(v) > MAX_FIELD:
            raise ValueError("%s is longer than %d characters" % (f, MAX_FIELD))
        out[f] = v
    return out


def save(kind, fields):
    """Store an edit: a part equal to the default (or empty) is stored as "" and follows later default changes."""
    fields, d = check(kind, fields), defaults(kind)
    cur = template(kind)
    merged = {f: fields.get(f, cur[f]) for f in FIELDS}
    if not merged["subject"].strip() or not merged["html"].strip() or not merged["text"].strip():
        raise ValueError("the subject, HTML and text can't be empty; reset the e-mail to go back to the default")
    core.save_config({"emails": {kind: {f: "" if merged[f].strip() == d[f].strip() else merged[f] for f in FIELDS}}})
    return template(kind)


def reset(kind):
    if kind not in KINDS:
        raise ValueError("unknown kind of e-mail")
    core.save_config({"emails": {kind: None}})


# ---------------------------------------------------------------- rendering

def common(extra=None):
    inst = CFG.get("instance") or {}
    acc = str(inst.get("accent") or "")
    lt = time.localtime()
    return dict({"site": inst.get("name") or inst.get("brand") or "Corium", "brand": inst.get("brand") or "Corium",
                 "accent": acc if re.fullmatch(r"#[0-9a-fA-F]{3}|#[0-9a-fA-F]{6}", acc) else DEFAULT_ACCENT,
                 "dashboard": str(CFG.get("dashboard_url") or "").rstrip("/"),
                 "date": time.strftime("%Y-%m-%d %H:%M", lt), "year": str(lt.tm_year)}, **(extra or {}))


def render(kind, data=None, draft=None, base=None):
    """{subject, text, html, unknown}: `data` fills the variables (missing ones count as empty), `draft` replaces
    parts of the stored template (the editor's unsaved text), `base` the common variables (dashboard for links)."""
    k = KINDS[kind]
    tpl = template(kind)
    if draft:
        tpl.update({f: v for f, v in check(kind, draft).items()})
    vals = dict(common(base), **(data or {}))
    safe = {n for n, v in k["vars"].items() if v["html"]}
    unknown = set()
    css = fill(tpl["css"], vals, "css", unknown=unknown)
    body = fill(tpl["html"], vals, "html", safe, unknown)
    known = set(COMMON) | set(k["vars"])
    return {"subject": fill(tpl["subject"], vals, "subject", unknown=unknown),
            "text": fill(tpl["text"], vals, "text", unknown=unknown),
            "html": with_style(inline_css(body, css), css),
            "unknown": sorted(unknown - known)}


def build(kind, data=None, base=None):
    """What the senders use: the instance's template, or the default if that one fails to render."""
    try:
        return render(kind, data, base=base)
    except Exception as e:
        core.log("e-mail template %s failed, sending the default: %s" % (kind, e))
        return render(kind, data, draft=defaults(kind), base=base)


def sample(kind):
    """Preview data: every variable's sample, with the built lists of the alert and report e-mails."""
    vals = {n: v["sample"] for n, v in KINDS[kind]["vars"].items()}
    if kind == "alert":
        now = time.time()
        vals.update(alert_vars([dict(a, ts=now - 60 * i) for i, a in enumerate(SAMPLE_ALERTS)]))
    if kind == "digest":
        vals.update(stats_vars(SAMPLE_STATS))
    return vals


# ---------------------------------------------------------------- the variables the senders pass in

SEV_RANK = {"info": 0, "warning": 1, "critical": 2}
SEV_STATE = {"info": "ok", "warning": "warn", "critical": "err"}


def alert_vars(rows):
    when = lambda r: time.strftime("%Y-%m-%d %H:%M", time.localtime(r["ts"]))
    top = max((r["severity"] for r in rows), key=lambda v: SEV_RANK.get(v, 0)) if rows else "info"
    e = lambda s: html.escape(str(s or ""), quote=True)
    return {
        "count": str(len(rows)), "plural": "1" if len(rows) != 1 else "", "title": rows[0]["title"] if rows else "",
        "summary": (rows[0]["title"] if len(rows) == 1 else "%d alerts: %s" % (len(rows), rows[0]["title"])) if rows else "",
        "severity": top, "state": SEV_STATE.get(top, "ok"),
        "alerts_html": "".join(
            '<tr><td class="al-sev sev-%s">%s</td><td class="al-main"><div class="al-title">%s</div>%s'
            '<div class="al-when">%s</div></td></tr>' % (e(r["severity"]), e(r["severity"]), e(r["title"]),
                                                       '<div class="al-detail">%s</div>' % e(r["detail"]) if r.get("detail") else "",
                                                       e(when(r))) for r in rows),
        "alerts_text": "\n\n".join("%s  [%s] %s%s" % (when(r), str(r["severity"]).upper(), r["title"],
                                                     "\n" + r["detail"] if r.get("detail") else "") for r in rows),
    }


def stats_vars(lines):
    e = lambda s: html.escape(str(s), quote=True)
    return {"stats_html": "".join('<tr><td class="st-k">%s</td><td class="st-v">%s</td></tr>' % (e(k), e(v)) for k, v in lines),
            "stats_text": "\n".join("%s: %s" % kv for kv in lines)}


def catalog():
    """Settings › Emails: every kind with its variables, defaults and this instance's overrides."""
    out = []
    for kid, k in KINDS.items():
        out.append({"id": kid, "label": k["label"], "desc": k["desc"],
                    "vars": [{"name": n, "desc": v["desc"], "html": v["html"]} for n, v in list(COMMON.items()) + list(k["vars"].items())],
                    "default": defaults(kid), "custom": overrides(kid), "current": template(kid)})
    return out
