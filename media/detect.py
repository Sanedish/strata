"""Strata Media sensitive-data detectors and redaction (DESIGN.md 7.3, 11).

scan.py runs these over text files, OCR output of images and PDF pages, document XML and archive members before
a file may be published. Two rules shape everything here:
  * a hold must mean something: every pattern has a validator (prefix, checksum, entropy, placeholder and
    code-expression filters, version-number context for IPs) so version strings, hashes, UUIDs, CSS and lorem
    ipsum never hold a public asset. Public web assets (web_asset=True) only keep full severity for things that
    are never legitimately public: private keys, provider credentials and connection strings.
  * a finding never carries the secret: every sample goes through redact() (at most first 4 + last 4 chars, and
    never more than 25 % of the value), because findings end up in media.db, the admin UI and alert mails.
Stdlib only (Pillow objects are used duck-typed), so importing it is cheap for every process.
"""
import base64
import bisect
import collections
import html
import ipaddress
import json
import math
import re
import zlib

SEVERITY = {"low": 1, "medium": 2, "high": 3}
_SEV_NAMES = {0: "none", 1: "low", 2: "medium", 3: "high"}
CONF = {"private_ip_severity": "low", "public_ip_severity": "medium", "email_severity": "low",
        "gps_severity": "low", "entropy_min": 3.8}
MAX_PER_TYPE = 50            # a log full of IPs is one problem, not 10 000 findings
MAX_FINDINGS = 500
_CONF_DOWN = {"high": "medium", "medium": "low", "low": "low"}


def finding(type_, severity, sample, where="", confidence="high"):
    """The one finding shape used by detect, extract and scan (stored as JSON in media.db verdict.findings)."""
    return {"type": type_, "severity": severity, "sample": sample, "where": where or "", "confidence": confidence}


def max_severity(findings):
    """"none" | "low" | "medium" | "high"."""
    return _SEV_NAMES[max((SEVERITY.get(f.get("severity"), 0) for f in findings or ()), default=0)]


def redact(value):
    """"ghp_…Xy3Q": reveals at most the first 4 + last 4 characters and never more than 25 % of the value."""
    s = str(value or "")
    k = min(8, len(s) // 4)
    head = min(4, (k + 1) // 2)
    tail = min(4, k - head)
    return s[:head] + "\u2026" + (s[len(s) - tail:] if tail else "")


def dedupe(findings):
    """Drop identical findings (same type, severity, sample and place), keeping the first occurrence."""
    seen, out = set(), []
    for f in findings:
        k = (f.get("type"), f.get("severity"), f.get("sample"), f.get("where"))
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def _dconf(conf):
    d = dict(CONF)
    if isinstance(conf, dict):
        src = conf.get("detect") if isinstance(conf.get("detect"), dict) else conf
        d.update({k: src[k] for k in CONF if k in src})
    return d


# ---------------------------------------------------------------- value heuristics

def _entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in collections.Counter(s).values())


def _classes(s):
    return (any(c.islower() for c in s) + any(c.isupper() for c in s) + any(c.isdigit() for c in s))


def _randomish(s, min_entropy=3.0):
    return len(set(s)) > 5 and _entropy(s) >= min_entropy


# Values that are obviously not a secret: masks, template variables, env references, type names, UI words.
_PLACEHOLDER = re.compile(
    r"^(?:[*\u2022\u25cf\u00b7xX_.\-#?]+"
    r"|<[^>]*>|\[[^\]]*\]|\{[^}]*\}|\$\{[^}]*\}?|\$\([^)]*\)?|\$[A-Za-z_]\w*|%[A-Za-z_]\w*%|%\(?\w*\)?s|%s|\?+"
    r"|(?:your|my|example|sample|dummy|fake|placeholder|redacted|insert|enter|replace|change_?me|todo|fixme"
    r"|xxx)[\w.\-]*"
    r"|secret|secrets|password|passwd|pass|pwd|passphrase|token|apikey|api_key|api-key|key|none|null|nil|undefined"
    r"|true|false|yes|no|on|off|string|str|int|integer|number|bool|boolean|any|object|bytes|text|varchar|char"
    r"|required|optional|empty|default|value|test|testing|anonymous|guest|forgot|reset|incorrect|invalid|wrong"
    r"|confirm|show|hide|hidden|change|login|logout|sign|signin|strength|weak|strong|expired|updated|changed"
    r"|protected|characters|minimum|maximum|must|should|mask|masked|secure|encrypted|omitted|removed|n/a"
    r"|passwort|kennwort|vergessen|anzeigen|ausblenden|erforderlich|eingeben|falsch|ungültig)$", re.I)
_DOTTED = re.compile(r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$")        # self.password, process.env.TOKEN
_IDENT = re.compile(r"^(?:[a-z]+(?:_[a-z]+)+|[a-z]+(?:[A-Z][a-z]+)+|[A-Z]+(?:_[A-Z]+)+)$")  # snake/camel/CONST


def _placeholder(v):
    return (not v or _PLACEHOLDER.match(v) is not None or len(set(v)) <= 2 or _DOTTED.match(v) is not None
            or v.lower() in ("user:pass", "username:password"))


# ---------------------------------------------------------------- token patterns

def _b64dec(s):
    s = s.replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def _ck_body(prefix_len):
    return lambda v: _randomish(v[prefix_len:])


def _ck_aws_id(v):
    return "EXAMPLE" not in v and len(set(v[4:])) > 5


def _ck_mixed(v):
    return "EXAMPLE" not in v.upper() and _classes(v) >= 2 and _randomish(v)


def _ck_discord(v):
    try:  # the first segment is the base64 of the bot's numeric user id
        uid = _b64dec(v.split(".", 1)[0]).decode("ascii")
    except Exception:
        return False
    return uid.isdigit() and 15 <= len(uid) <= 21 and _randomish(v.rsplit(".", 1)[1])


def _ck_jwt(v):
    try:
        head = json.loads(_b64dec(v.split(".", 1)[0]))
    except Exception:
        return False
    return isinstance(head, dict) and ("alg" in head or "typ" in head)


def _ck_openai(v):
    body = v[3:]
    return _classes(body) >= 3 and _randomish(body)


def _ck_cf40(v):
    return not re.fullmatch(r"[0-9a-f]{40}", v) and _classes(v) >= 2 and _randomish(v, 3.5)


def _ck_hex(v):
    body = v[2:]
    return any(c.isdigit() for c in body) and any(c.isalpha() for c in body) and _randomish(body)


def _ck_resend(v):
    body = v[3:]
    return _classes(body) >= 3 and _randomish(body)


def _ck_slack(v):
    return any(c.isdigit() for c in v) and _randomish(v[5:], 2.5)


def _ck_any(v):
    return True


class _Pat:
    __slots__ = ("type", "rx", "severity", "confidence", "needles", "ci", "check", "keep_web")

    def __init__(self, type_, rx, severity="high", confidence="high", needles=(), ci=False, check=_ck_any,
                 keep_web=True):
        self.type, self.rx, self.severity, self.confidence = type_, re.compile(rx), severity, confidence
        self.needles, self.ci, self.check, self.keep_web = needles, ci, check, keep_web


_TOKENS = [
    _Pat("aws_access_key", r"\b((?:AKIA|ASIA)[A-Z0-9]{16})\b", needles=("AKIA", "ASIA"), check=_ck_aws_id),
    _Pat("aws_secret_key", r"(?i)\baws[\w.-]{0,24}?(?:secret|sk)[\w.-]{0,24}?[\"'`]?[ \t]*[:=][ \t]*[\"'`]?"
         r"([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])", needles=("aws",), ci=True, check=_ck_mixed),
    _Pat("github_token", r"\b(gh[pousr]_[A-Za-z0-9]{36,251})\b", needles=("ghp_", "gho_", "ghu_", "ghs_", "ghr_"),
         check=_ck_body(4)),
    _Pat("github_token", r"\b(github_pat_[A-Za-z0-9_]{50,251})\b", needles=("github_pat_",), check=_ck_body(11)),
    _Pat("gitlab_token", r"\b(glpat-[A-Za-z0-9_-]{20,64})", needles=("glpat-",), check=_ck_body(6)),
    _Pat("slack_token", r"\b(xox[abprs]-[A-Za-z0-9-]{10,250})", needles=("xox",), check=_ck_slack),
    _Pat("slack_webhook", r"(https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9_/-]{20,200})",
         needles=("hooks.slack.com",)),
    _Pat("discord_token", r"(?<![A-Za-z0-9_-])([MNO][A-Za-z0-9_-]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40})"
         r"(?![A-Za-z0-9_-])", needles=(".",), check=_ck_discord),
    _Pat("discord_webhook", r"(?i)(https?://(?:(?:canary|ptb)\.)?discord(?:app)?\.com/api/(?:v\d+/)?webhooks/"
         r"\d{15,22}/[A-Za-z0-9_-]{40,100})", needles=("discord",), ci=True),
    _Pat("stripe_key", r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,247})\b", needles=("_live_",), check=_ck_body(8)),
    _Pat("google_api_key", r"\b(AIza[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])", "medium", needles=("AIza",),
         check=_ck_body(4)),
    _Pat("google_oauth_secret", r"\b(GOCSPX-[A-Za-z0-9_-]{28})(?![A-Za-z0-9_-])", needles=("GOCSPX-",),
         check=_ck_body(7)),
    _Pat("anthropic_key", r"\b(sk-ant-[A-Za-z0-9_-]{32,300})", needles=("sk-ant-",), check=_ck_body(7)),
    _Pat("openai_key", r"\b(sk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,300}|(?!ant-)[A-Za-z0-9]{32,64}"
         r"(?![A-Za-z0-9_-])))", needles=("sk-",), check=_ck_openai),
    _Pat("cloudflare_token", r"\b(cfut_[A-Za-z0-9_-]{30,120})", needles=("cfut_",), check=_ck_body(5)),
    _Pat("cloudflare_token", r"(?i)(?:cloudflare|\bcf[_-]?api[_-]?(?:token|key)|\bcf[_-]?token)[^\n]{0,40}?"
         r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{40})(?![A-Za-z0-9_-])",
         needles=("cloudflare", "cf_api", "cf-api", "cfapi", "cf_token", "cf-token"), ci=True, check=_ck_cf40),
    _Pat("cloudflare_token", r"(?i)(?:x-auth-key|\bcf[_-]?api[_-]?key|cloudflare[_-]?(?:global[_-]?)?api[_-]?key)"
         r"[^\n]{0,20}?\b([0-9a-f]{37})\b", needles=("x-auth-key", "api_key", "api-key", "apikey"), ci=True,
         check=lambda v: _randomish(v)),
    _Pat("twilio_key", r"\b(SK[0-9a-fA-F]{32})\b", needles=("SK",), check=_ck_hex),
    _Pat("sendgrid_key", r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])", needles=("SG.",),
         check=_ck_body(3)),
    _Pat("resend_key", r"\b(re_[A-Za-z0-9]{6,12}_[A-Za-z0-9]{16,40}|re_[A-Za-z0-9]{24,48})\b", needles=("re_",),
         check=_ck_resend),
    _Pat("npm_token", r"\b(npm_[A-Za-z0-9]{36})\b", needles=("npm_",), check=_ck_body(4)),
    _Pat("pypi_token", r"\b(pypi-AgE[A-Za-z0-9_-]{50,300})", needles=("pypi-AgE",)),
    _Pat("telegram_bot_token", r"\b(\d{8,10}:AA[A-Za-z0-9_-]{33})(?![A-Za-z0-9_-])", needles=(":AA",),
         check=lambda v: _randomish(v.split(":", 1)[1])),
    _Pat("azure_storage_key", r"(?i)\b(?:AccountKey|SharedAccessKey)[ \t]*=[ \t]*([A-Za-z0-9+/]{40,100}={0,2})",
         needles=("accountkey", "sharedaccesskey"), ci=True, check=_ck_mixed),
    _Pat("jwt", r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})", "medium", needles=("eyJ",),
         check=_ck_jwt, keep_web=False),
]

_PRIVKEY = re.compile(r"-{3,}[ \t]?BEGIN[ \t]((?:[A-Z0-9]+[ \t]){0,3})PRIVATE[ \t]KEY(?:[ \t]BLOCK)?[ \t]?-{3,}")
_PUTTY = re.compile(r"PuTTY-User-Key-File-\d+:")
_KEY_BODY = re.compile(r"[A-Za-z0-9+/=]{48,}")
_KEY_HEADERS = re.compile(r"^(?:Proc-Type|DEK-Info|Version|Comment|Hash|Encryption|Public-Lines|Private-Lines)"
                          r":[^\n]*$", re.M)

_CONN = re.compile(r"(?i)\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver"
                   r"|jdbc:[a-z]+)://)([^\s:/@'\"<>]{1,64}):([^\s@/'\"<>]{1,128})@([^\s/'\"<>?#,;]{1,255})")
_BASIC = re.compile(r"(?i)\b((?:https?|ftps?|sftp|ssh|smb|wss?|git)://)([^\s:/@'\"<>]{1,64}):([^\s@/'\"<>]{1,128})"
                    r"@([A-Za-z0-9.-]{1,253}|\[[0-9A-Fa-f:.]+\])")

_PW_WORDS = r"pass(?:w[o0]r[dt]|wd|phrase)?|kennw[o0]rt|pwd|secret|token|api[_ -]?key|apikey"   # + German UIs
_ASSIGN = re.compile(r"(?i:(" + _PW_WORDS + r"))(?:[_.-][A-Za-z0-9]+|[A-Z][a-z0-9]*)?[\"'`]?[ \t]*(?::=|=>|[:=])"
                     r"[ \t]*[\"'`]?([^\s\"'`,;<>(){}\[\]]{1,128})")
_ASSIGN_XML = re.compile(r"<(?i:(pass(?:w[o0]rd|wd)?|secret|token|api_?key))>([^<\s]{4,128})</")
_GENERIC = re.compile(r"(?i:(secret|token|api[_-]?key|apikey|auth|credential|access[_-]?key|private[_-]?key"
                      r"|signing[_-]?key|bearer|session[_-]?(?:id|key|token)?))[\w-]{0,20}?[\"'`]?[ \t]*"
                      r"(?::=|=>|[:=]|[ \t])[ \t]*[\"'`]?([A-Za-z0-9+/_\-=.~]{20,256})")

_IPV4 = re.compile(r"(?<![\w.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?!\w|\.\d)")
_IPV6 = re.compile(r"(?<![\w:.])((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})(?![\w:.])")
_VERSION_CTX = re.compile(r"(?:\bv|\bver\.?|version|\brev\.?|revision|\bbuild|release|firmware|\bfw|[a-z]/)"
                          r"[ \t]*[:=#]?[ \t]*$", re.I)
_RESOLVERS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222",
              "208.67.220.220", "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888",
              "2001:4860:4860::8844", "2620:fe::fe", "2620:fe::9"}
_DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
                                               "100.64.0.0/10", "198.18.0.0/15")]

_EMAIL = re.compile(r"(?<![\w.+%-])([A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24})\b")
_EMAIL_SKIP_TLD = set("png jpg jpeg gif svg webp avif bmp ico js mjs css html htm json map ts tsx jsx py md txt xml "
                      "yml yaml toml lock zip gz".split())
_EMAIL_SKIP_DOM = re.compile(r"(?:^|\.)(?:example\.(?:com|org|net)|[\w-]+\.(?:test|invalid|example|localhost|local))$",
                             re.I)

_CARD = re.compile(r"(?<![\w.,-])(\d(?:[ -]?\d){12,18})(?![\w-]|[.,]\d)")
_TEST_CARDS = {"4111111111111111", "4242424242424242", "4012888888881881", "5555555555554444", "5105105105105100",
               "378282246310005", "371449635398431", "6011111111111117", "6011000990139424", "3530111333300000",
               "4000056655665556", "5200828282828210", "4000000000000002", "30569309025904"}
_IBAN = re.compile(r"\b([A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){10,30})\b")
_IBAN_LEN = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22, "BR": 29, "BY": 28,
    "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18,
    "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28, "IE": 22,
    "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20,
    "LU": 20, "LV": 21, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15,
    "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "SA": 24, "SC": 31, "SE": 24, "SI": 19,
    "SK": 24, "SM": 27, "ST": 25, "SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20}


def _luhn(digits):
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _card_brand(d):
    n, p2, p4 = len(d), int(d[:2]), int(d[:4])
    if d[0] == "4":
        return n in (13, 16, 19)
    if 51 <= p2 <= 55 or 2221 <= p4 <= 2720:
        return n == 16
    if p2 in (34, 37):
        return n == 15
    if d.startswith(("6011", "65")) or 644 <= int(d[:3]) <= 649:
        return 16 <= n <= 19
    if 3528 <= p4 <= 3589:
        return 16 <= n <= 19
    if p2 in (36, 38, 39) or 300 <= int(d[:3]) <= 305:
        return 14 <= n <= 19
    return False


def _iban_ok(s):
    want = _IBAN_LEN.get(s[:2])
    if not want or len(s) < want:
        return None
    s = s[:want]
    num = "".join(str(int(c, 36)) for c in s[4:] + s[:4])
    return s if int(num) % 97 == 1 else None


# ---------------------------------------------------------------- OCR normalisation

_OCR_FIXES = [
    (re.compile(r"\bA[Il1|]za(?=[0-9A-Za-z_-]{20})"), "AIza"),
    (re.compile(r"\bAK[Il1|]A(?=[A-Z0-9]{12})"), "AKIA"),
    (re.compile(r"\bAS[Il1|]A(?=[A-Z0-9]{12})"), "ASIA"),
    (re.compile(r"\bG[O0]CSPX ?-"), "GOCSPX-"),
    (re.compile(r"\bg[l1I|]pat ?-"), "glpat-"),
    (re.compile(r"\bx[o0O]x([abprs]) ?-"), r"xox\1-"),
    (re.compile(r"\bg[i1l|]thub_pat_"), "github_pat_"),
    (re.compile(r"\bgh([pousr]) ?_"), r"gh\1_"),
    (re.compile(r"\b([sr])k_[l1I|][i1l|]ve_"), r"\1k_live_"),
    (re.compile(r"\bpyp[i1l|]-AgE"), "pypi-AgE"),
    (re.compile(r"\bsk ?- ?ant ?-"), "sk-ant-"),
    (re.compile(r"\bsk ?- ?proj ?-"), "sk-proj-"),
    (re.compile(r"\bS[G6] ?\.(?=[A-Za-z0-9_-]{20})"), "SG."),
    (re.compile(r"\bey[JI] ?"), "eyJ"),
]
_JOIN = re.compile(r"(?<![A-Za-z0-9])(gh[pousr]_|github_pat_|glpat-|xox[abprs]-|sk-ant-|sk-proj-|sk-|[sr]k_live_|AKIA|ASIA|AIza"
                   r"|GOCSPX-|SG\.|npm_|pypi-|re_|cfut_|eyJ|SK)([A-Za-z0-9_\-+/=.]*)((?: [A-Za-z0-9_\-+/=.]{2,}){1,6})")
_FRAGMENT_OK = re.compile(r"[A-Z0-9]")
_DIGITISH = re.compile(r"(?<![A-Za-z])[0-9OoIl|]{2,}(?![A-Za-z])")
_DIGIT_MAP = str.maketrans("OoIl|", "00111")
_HEXTOK = re.compile(r"\bSK[0-9a-fA-FOlI]{32}\b")


def _join_tokens(m):
    frags, taken = m.group(3).split(" ")[1:], []
    for fr in frags:
        if not _FRAGMENT_OK.search(fr) or len(m.group(2)) + sum(map(len, taken)) > 120:
            break
        taken.append(fr)
    rest = frags[len(taken):]
    return m.group(1) + m.group(2) + "".join(taken) + ("" if not rest else " " + " ".join(rest))


def _fix_digits(m):
    s = m.group(0)
    nd = sum(c.isdigit() for c in s)
    return s.translate(_DIGIT_MAP) if nd and nd * 2 >= len(s) else s


def ocr_normalize(text):
    """Undo typical OCR damage: confused prefixes (AIza read as Alza), tokens broken by single spaces after a
    known prefix, and O/0 + l/1 confusion inside digit runs (IPs, card numbers, bot ids) and hex tokens."""
    for rx, rep in _OCR_FIXES:
        text = rx.sub(rep, text)
    text = _JOIN.sub(_join_tokens, text)
    text = _DIGITISH.sub(_fix_digits, text)
    return _HEXTOK.sub(lambda m: "SK" + m.group(0)[2:].translate(str.maketrans("OlI", "011")), text)


# ---------------------------------------------------------------- scan_text

class _Collector:
    def __init__(self, text, where, web_asset, lines):
        self.text, self.where, self.web, self.lines = text, where, web_asset, lines
        self.out, self.per_type, self._nl = [], collections.Counter(), None
        self._starts, self._ends = [], []    # claimed spans, sorted; they never overlap (every add checks first)

    def overlaps(self, a, b):
        i = bisect.bisect_left(self._starts, b)          # spans starting before b; the last few can reach a
        return i > 0 and max(self._ends[max(0, i - 4):i]) > a

    def claim(self, span):
        i = bisect.bisect_left(self._starts, span[0])
        self._starts.insert(i, span[0])
        self._ends.insert(i, span[1])

    def place(self, pos):
        if not self.lines:
            return self.where
        if self._nl is None:
            self._nl = [m.start() for m in re.finditer("\n", self.text)]
        line = bisect.bisect_left(self._nl, pos) + 1
        return "%s:%d" % (self.where, line) if self.where else "line %d" % line

    def add(self, type_, severity, sample, pos, span=None, confidence="high", keep_web=False):
        if self.web and not keep_web:
            severity = "low"
        if span:  # claimed even when not reported (cap): weaker detectors must not re-report the same value
            self.claim(span)
        if self.per_type[type_] >= MAX_PER_TYPE:
            return
        self.per_type[type_] += 1
        self.out.append(finding(type_, severity, sample, self.place(pos), confidence))


def _boundary_ok(text, start):
    """Keyword start: beginning, non-alphanumeric, or a camelCase hump (dbPassword) - but never 'bypass'."""
    if start == 0:
        return True
    prev = text[start - 1]
    if not prev.isalnum():
        return True
    return (prev.islower() or prev.isdigit()) and text[start].isupper()


def _scan(text, where, d, web_asset, lines):
    c = _Collector(text, where, web_asset, lines)
    low = None

    # private keys first: they are the one thing that is high everywhere (with a key body)
    if "PRIVATE" in text or "PuTTY" in text:
        for m in _PRIVKEY.finditer(text):
            tail = _KEY_HEADERS.sub("", text[m.end():m.end() + 1200])
            body = _KEY_BODY.search(re.sub(r"\s+", "", tail)[:1000]) is not None
            label = re.sub(r"\s+", " ", m.group(1)).strip()
            sample = "BEGIN %sPRIVATE KEY" % (label + " " if label else "")
            if body:
                c.add("private_key", "high", sample, m.start(), (m.start(), m.end()), "high", keep_web=True)
            else:  # a bare header: key material in a screenshot or config, or a library that parses PEM
                c.add("private_key", "low" if web_asset else "high", sample, m.start(), (m.start(), m.end()),
                      "medium", keep_web=True)
        for m in _PUTTY.finditer(text):
            if "Private-Lines" in text[m.end():m.end() + 4000]:
                c.add("private_key", "high", "PuTTY private key", m.start(), (m.start(), m.end()), keep_web=True)

    for p in _TOKENS:
        if p.needles:
            if p.ci:
                low = low if low is not None else text.lower()
                if not any(n in low for n in p.needles):
                    continue
            elif not any(n in text for n in p.needles):
                continue
        for m in p.rx.finditer(text):
            v = m.group(1)
            if not p.check(v) or c.overlaps(m.start(1), m.end(1)):
                continue
            sev = p.severity
            if p.type == "google_api_key":  # Maps/Firebase browser keys are meant to ship in web pages
                sev = "low" if web_asset else "high"
            c.add(p.type, sev, redact(v), m.start(1), (m.start(1), m.end(1)), p.confidence,
                  keep_web=p.keep_web or p.type == "google_api_key")

    if "://" in text:
        for m in _CONN.finditer(text):
            user, pw, host = m.group(2), m.group(3), m.group(4)
            if len(pw) < 3 or _placeholder(pw) or c.overlaps(m.start(), m.end()):
                continue
            c.add("connection_string", "high", "%s\u2026@%s" % (m.group(1).lower(), redact(host)), m.start(),
                  (m.start(), m.end()), "high", keep_web=True)
        for m in _BASIC.finditer(text):
            user, pw, host = m.group(2), m.group(3), m.group(4)
            if c.overlaps(m.start(), m.end()):
                continue
            tokenish_user = len(user) >= 20 and _randomish(user)
            if (len(pw) < 3 or _placeholder(pw) or _placeholder(user)) and not tokenish_user:
                continue
            c.add("basic_auth_url", "high", "%s\u2026@%s" % (m.group(1).lower(), redact(host)), m.start(),
                  (m.start(), m.end()), "high", keep_web=True)

    # password / secret assignments ("Password: hunter22", DB_PASSWORD=..., "apiKey": "...")
    for m in list(_ASSIGN.finditer(text)) + list(_ASSIGN_XML.finditer(text)):
        kw, v = m.group(1), m.group(2).rstrip(".!)?:")        # "Password: Forgot?" is a link, not a value
        if not _boundary_ok(text, m.start(1)) or c.overlaps(m.start(2), m.end(2)):
            continue
        if m.end(2) < len(text) and text[m.end(2)] == "(":   # get_password() - a call, not a value
            continue
        if _placeholder(v) or _IDENT.match(v):
            continue
        is_pw = kw.lower().startswith(("pass", "pwd", "kennw"))
        if is_pw:
            if len(v) < 6:
                continue
        elif len(v) < 8 or not (any(ch.isdigit() for ch in v) or _classes(v) >= 2) or not _randomish(v, 2.5):
            continue
        name = re.sub(r"[o0]", "o", kw.lower())
        c.add("password" if is_pw else "secret_assignment", "medium", "%s: %s" % (name, redact(v)), m.start(2),
              (m.start(2), m.end(2)), "medium")

    # generic high-entropy strings near secret keywords
    for m in _GENERIC.finditer(text):
        v = m.group(2).rstrip(".")
        if not _boundary_ok(text, m.start(1)) or c.overlaps(m.start(2), m.end(2)):
            continue
        if (len(v) < 20 or _placeholder(v) or _IDENT.match(v) or not any(ch.isdigit() for ch in v)
                or not any(ch.isalpha() for ch in v) or _entropy(v) < float(d["entropy_min"])):
            continue
        c.add("generic_secret", "medium", "%s: %s" % (m.group(1).lower(), redact(v)), m.start(2),
              (m.start(2), m.end(2)), "low")

    # IP addresses
    for m in _IPV4.finditer(text):
        octets = m.groups()
        if any(len(o) > 1 and o[0] == "0" for o in octets) or any(int(o) > 255 for o in octets):
            continue
        ip_s = ".".join(octets)
        if ip_s in _RESOLVERS or octets[0] == "0" or _VERSION_CTX.search(text[max(0, m.start() - 24):m.start()]):
            continue
        _add_ip(c, d, ip_s, m.start())
    if "::" in text or text.count(":") >= 7:
        for m in _IPV6.finditer(text):
            s = m.group(1)
            if s.count(":") < 2 or not any(ch.isalnum() for ch in s):
                continue
            try:
                ipaddress.IPv6Address(s)
            except ValueError:
                continue
            _add_ip(c, d, s, m.start())

    if "@" in text:
        for m in _EMAIL.finditer(text):
            addr = m.group(1)
            dom = addr.rsplit("@", 1)[1].lower()
            if (dom.rsplit(".", 1)[1] in _EMAIL_SKIP_TLD or _EMAIL_SKIP_DOM.search(dom)
                    or re.search(r"@\d+x\.", addr) or addr[:4].lower() == "git@"      # icon@2x.png, ssh remotes
                    or c.overlaps(m.start(), m.end())):
                continue
            c.add("email", d["email_severity"], redact(addr), m.start(), None, "high")

    for m in _CARD.finditer(text):
        digits = re.sub(r"\D", "", m.group(1))
        if (not 13 <= len(digits) <= 19 or digits in _TEST_CARDS or len(set(digits)) < 4 or not _card_brand(digits)
                or not _luhn(digits) or c.overlaps(m.start(1), m.end(1))):
            continue
        c.add("credit_card", "high", redact(digits), m.start(1), (m.start(1), m.end(1)), "high")

    for m in _IBAN.finditer(text):
        iban = _iban_ok(m.group(1).replace(" ", ""))
        if iban and not c.overlaps(m.start(1), m.end(1)):
            c.add("iban", "medium", redact(iban), m.start(1), (m.start(1), m.end(1)), "high")
    return c.out


def _add_ip(c, d, s, pos):
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return
    if (s in _RESOLVERS or str(ip) in _RESOLVERS or ip.is_unspecified or ip.is_loopback or ip.is_multicast
            or ip.is_reserved or ip.is_link_local or any(ip in n for n in _DOC_NETS if n.version == ip.version)
            or (ip.version == 4 and s == "255.255.255.255")):
        return
    if ip.is_private:
        c.add("ip_private", d["private_ip_severity"], redact(s), pos, None, "medium")
    elif ip.is_global:
        c.add("ip_public", d["public_ip_severity"], redact(s), pos, None, "medium")


def scan_text(text, where="", conf=None, ocr=False, web_asset=False):
    """Findings for a piece of text. ocr=True also scans an OCR-normalised copy (findings only seen there get a
    lower confidence); web_asset=True downgrades everything except keys / provider credentials / connection
    strings to low. Returned findings are deduplicated and redacted."""
    if not text:
        return []
    if not isinstance(text, str):
        text = bytes(text).decode("utf-8", "replace")
    d = _dconf(conf)
    found = _scan(text, where, d, web_asset, lines=not ocr)
    if ocr:
        norm = ocr_normalize(text)
        if norm != text:
            seen = {(f["type"], f["sample"]) for f in found}
            for f in _scan(norm, where, d, web_asset, lines=False):
                if (f["type"], f["sample"]) not in seen:
                    f["confidence"] = _CONF_DOWN[f["confidence"]]
                    seen.add((f["type"], f["sample"]))
                    found.append(f)
    out, seen = [], set()
    for f in found:  # identical secret seen on several lines = one finding (first place wins)
        k = (f["type"], f["severity"], f["sample"])
        if k not in seen:
            seen.add(k)
            out.append(f)
    out.sort(key=lambda f: -SEVERITY.get(f["severity"], 0))
    return out[:MAX_FINDINGS]


# ---------------------------------------------------------------- images, SVG, PDF, names

_GPS_IFD = 0x8825


def exif_findings(img, conf=None, where=""):
    """GPS position in EXIF (or XMP) -> finding with detect.gps_severity. img: a PIL image or a path."""
    d = _dconf(conf)
    own = None
    if isinstance(img, (str, bytes)) or hasattr(img, "__fspath__"):
        from PIL import Image
        img = own = Image.open(img)
    try:
        gps = {}
        try:
            exif = img.getexif()
            gps = exif.get_ifd(_GPS_IFD) if exif else {}
        except Exception:
            pass
        xmp = img.info.get("xmp") or img.info.get("XML:com.adobe.xmp") or b""
        if isinstance(xmp, str):
            xmp = xmp.encode("utf-8", "replace")
        if any(k in gps for k in (2, 4)) or b"GPSLatitude" in xmp or b"GPSLongitude" in xmp:
            return [finding("gps", d["gps_severity"], "GPS position in image metadata", where, "high")]
        return []
    finally:
        if own is not None:
            own.close()


_SVG_SCRIPT = re.compile(r"<\s*(?:[\w-]+:)?script\b", re.I)
_SVG_ON = re.compile(r"<[^>]*?[\s/\"'](on[a-z]{3,})\s*=", re.I)
_SVG_FOREIGN = re.compile(r"<\s*(?:[\w-]+:)?foreignObject\b", re.I)
_SVG_EMBED = re.compile(r"<\s*(?:[\w-]+:)?(iframe|embed|object|applet|meta|base)\b", re.I)
_SVG_ENTITY = re.compile(r"<!ENTITY|<!DOCTYPE[^>]*\[", re.I)
_SVG_HREF = re.compile(r"(?:xlink:)?href\s*=\s*[\"']\s*([^\"']*)[\"']", re.I)
_SVG_URL = re.compile(r"(?:url\(\s*[\"']?\s*|@import\s+[\"']?)((?:https?:|ftp:|file:)?//[^\s\"')]*)", re.I)
_JS_URI = re.compile(r"(?:java|vb)script:|data:text/html", re.I)


def svg_findings(text, where=""):
    """Active content in an SVG: script, on* handlers, javascript: URIs, foreignObject, external references."""
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode("utf-8", "replace")
    out = []

    def add(sample):
        out.append(finding("svg_active", "medium", sample, where, "high"))
    if _SVG_SCRIPT.search(text):
        add("<script>")
    for m in _SVG_ON.finditer(text):
        add("%s= handler" % m.group(1).lower())
    squashed = re.sub(r"[\s\x00-\x1f]+", "", html.unescape(text))
    m = _JS_URI.search(squashed)
    if m:
        add(m.group(0).lower() + " URI")
    if _SVG_FOREIGN.search(text):
        add("<foreignObject>")
    for m in _SVG_EMBED.finditer(text):
        add("<%s>" % m.group(1).lower())
    if _SVG_ENTITY.search(text):
        add("DTD entity declaration")
    for m in _SVG_HREF.finditer(text):
        v = html.unescape(m.group(1)).strip()
        if re.match(r"(?i)(?:[a-z][a-z0-9+.-]*:|//)", v) and not re.match(r"(?i)data:image/", v):
            add("external href " + redact(v))
    for m in _SVG_URL.finditer(text):
        add("external resource " + redact(m.group(1)))
    return dedupe(out)


_PDF_STREAM = re.compile(rb">>\s*stream(?:\r\n|\r|\n)")
_PDF_STRING = re.compile(rb"\((?:[^()\\]|\\.)*\)", re.S)
_PDF_COMMENT = re.compile(rb"%[^\r\n]*")
_PDF_NAME = re.compile(rb"/([^\s/<>\[\]()\{\}%\x00]{1,127})")
_PDF_HEX = re.compile(rb"#([0-9A-Fa-f]{2})")
_PDF_ACTIVE = {"JavaScript": "/JavaScript", "JS": "/JS", "Launch": "/Launch", "EmbeddedFile": "/EmbeddedFile",
               "EmbeddedFiles": "/EmbeddedFile", "RichMedia": "/RichMedia", "XFA": "/XFA", "AA": "/AA"}
_PDF_OBJSTM_MAX = 32 << 20      # decompressed bytes per object stream
_PDF_INFLATE_BUDGET = 256 << 20  # decompressed bytes per document


def _pdf_tokens(chunk, names):
    for _ in range(3):  # literal strings may nest; three passes cover real-world documents
        chunk = _PDF_STRING.sub(b" ", chunk)
    chunk = _PDF_COMMENT.sub(b"", chunk)
    for m in _PDF_NAME.finditer(chunk):
        raw = m.group(1)
        if b"#" in raw:  # /J#61vaScript == /JavaScript
            raw = _PDF_HEX.sub(lambda h: bytes([int(h.group(1), 16)]), raw)
        names.add(raw.decode("latin-1"))


def pdf_names(raw_bytes):
    """The set of PDF name tokens outside stream data (object streams are inflated and included). Names inside
    literal strings, comments and page content are ignored, so "/JS" in running text never counts."""
    data = raw_bytes
    names, pos, budget = set(), 0, _PDF_INFLATE_BUDGET
    n = len(data)
    while pos < n:
        m = _PDF_STREAM.search(data, pos)
        end = m.start() if m else n
        _pdf_tokens(bytes(data[pos:end]), names)
        if not m:
            break
        dict_area = bytes(data[max(pos, m.start() - 2048):m.start()])
        e = data.find(b"endstream", m.end())
        if e < 0:
            break
        if b"/ObjStm" in dict_area and b"/FlateDecode" in dict_area and budget > 0:
            try:  # compressed object streams hide dictionaries (and /JavaScript) from a raw scan
                z = zlib.decompressobj()
                inner = z.decompress(bytes(data[m.end():e]), min(_PDF_OBJSTM_MAX, budget))
                budget -= len(inner)
                _pdf_tokens(inner, names)
            except zlib.error:
                pass
        pos = e + 9
    return names


def pdf_encrypted(raw_bytes=None, names=None):
    return "Encrypt" in (names if names is not None else pdf_names(raw_bytes))


def pdf_active_findings(raw_bytes, where="", names=None):
    """Active content in a PDF (/JavaScript /JS /Launch /EmbeddedFile /OpenAction+JS /RichMedia /XFA /AA)."""
    names = names if names is not None else pdf_names(raw_bytes)
    out = [finding("pdf_active", "medium", sample, where, "high")
           for sample in sorted({v for k, v in _PDF_ACTIVE.items() if k in names})]
    if "OpenAction" in names and ("JS" in names or "JavaScript" in names):
        out.append(finding("pdf_active", "medium", "/OpenAction+JS", where, "high"))
    return out


# inner file names that should never be published (DESIGN 7.3 archive row)
_DANGER_NAMES = {".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".htpasswd", ".netrc", ".npmrc", ".pypirc",
                 ".git-credentials", "wp-config.php", "terraform.tfstate", ".bash_history", "shadow"}
_DANGER_GLOBS = re.compile(r"^(?:\.env\..+|credentials.*|.+\.(?:pem|key|p12|pfx|kdbx|ppk|jks|keystore)"
                           r"|terraform\.tfstate.*)$", re.I)
_DANGER_DIRS = {".git", ".ssh", ".aws", ".azure", ".kube", ".docker", ".gnupg"}
_HOLD_EXT = ["scr", "com", "pif", "hta", "lnk", "vbs", "vbe", "jse", "wsf", "wsh", "ps1", "bat", "cmd", "msi", "reg"]
_REPORT_EXT = ["exe", "dll", "jar", "apk", "sys"]


def name_findings(relpath, conf=None, where=None):
    """Dangerous names inside an archive: secrets/key files and VCS dirs -> high, script/installer extensions
    (scan.archive.hold_inner_ext) -> medium, binaries (report_inner_ext) -> low."""
    rel = (relpath or "").replace("\\", "/")
    parts = [p for p in rel.split("/") if p]
    if not parts:
        return []
    where = rel if where is None else where
    arc = (((conf or {}).get("scan") or {}).get("archive") or {}) if isinstance(conf, dict) else {}
    hold = set(arc.get("hold_inner_ext") or _HOLD_EXT)
    report = set(arc.get("report_inner_ext") or _REPORT_EXT)
    base = parts[-1]
    low = base.lower()
    out = []
    for p in parts[:-1]:
        if p.lower() in _DANGER_DIRS:
            out.append(finding("dangerous_name", "high", p + "/", where, "high"))
            break
    if low in _DANGER_NAMES or _DANGER_GLOBS.match(low) or low in _DANGER_DIRS:
        out.append(finding("dangerous_name", "high", base, where, "high"))
    ext = low.rsplit(".", 1)[1] if "." in low.strip(".") else ""
    if ext in hold:
        out.append(finding("risky_file", "medium", "." + ext, where, "high"))
    elif ext in report:
        out.append(finding("executable", "low", "." + ext, where, "high"))
    return out
