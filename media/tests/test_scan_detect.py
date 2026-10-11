"""detect.py: true positives per pattern family, OCR noise, false-positive corpus, web-asset downgrade, redaction.

Run: python -m unittest discover -s media/tests -t media/tests -p "test_scan_detect*.py"
Every token below is synthetic: built at runtime from a seeded RNG so it matches the pattern's shape and validators
(prefix, length, entropy, checksum) without being anybody's credential, and no token literal sits in this file.
"""
import base64
import io
import json
import os
import random
import string
import sys
import unittest
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
MEDIA = os.path.dirname(HERE)
if MEDIA not in sys.path:
    sys.path.insert(0, MEDIA)
try:
    import pathfix  # noqa: F401
except Exception:
    pass

import detect  # noqa: E402

AN = string.ascii_letters + string.digits
UPPER32 = string.ascii_uppercase + "234567"
HEX = "0123456789abcdef"
ELL = "\u2026"


class Gen:
    """Seeded synthetic secrets (deterministic per test run)."""

    def __init__(self, seed=20260929):
        self.r = random.Random(seed)

    def s(self, n, alpha=AN):
        while True:   # mixed classes, so the entropy / class validators accept it like a real token
            v = "".join(self.r.choice(alpha) for _ in range(n))
            if alpha is not AN or (any(c.isdigit() for c in v) and any(c.isupper() for c in v)
                                   and any(c.islower() for c in v)):
                return v

    def card(self, prefix, n):
        body = prefix + "".join(self.r.choice(string.digits) for _ in range(n - len(prefix) - 1))
        return next(body + c for c in string.digits if detect._luhn(body + c))


def b64u(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def lcs(a, b):
    """Length of the longest common substring (how much of a secret a sample reveals in one piece)."""
    best, prev = 0, [0] * (len(b) + 1)
    for ca in a:
        cur = [0] * (len(b) + 1)
        for j, cb in enumerate(b, 1):
            if ca == cb:
                cur[j] = prev[j - 1] + 1
                best = max(best, cur[j])
        prev = cur
    return best


def build_true_positives():
    """[(label, text, secret, type, severity)] - one or more per pattern family."""
    g = Gen()
    key_body = "\n".join(g.s(64, AN + "+/") for _ in range(4))
    uid = base64.b64encode(b"123456789012345678").decode().rstrip("=")
    jwt = "%s.%s.%s" % (b64u(b'{"alg":"HS256","typ":"JWT"}'), b64u(b'{"sub":"42","name":"Synthetic"}'),
                        g.s(43, AN + "_-"))
    rows = []

    def add(label, text, secret, type_, sev="high"):
        rows.append((label, text, secret, type_, sev))

    add("rsa_key", "-----BEGIN RSA PRIVATE KEY-----\n%s\n-----END RSA PRIVATE KEY-----" % key_body, key_body,
        "private_key")
    add("openssh_key", "x\n-----BEGIN OPENSSH PRIVATE KEY-----\n%s\n-----END OPENSSH PRIVATE KEY-----\n" % key_body,
        key_body, "private_key")
    add("pkcs8_key", "-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----" % key_body, key_body,
        "private_key")
    v = "AKIA" + g.s(16, UPPER32)
    add("aws_akia", "aws_access_key_id = %s" % v, v, "aws_access_key")
    v = "ASIA" + g.s(16, UPPER32)
    add("aws_asia", "key: %s" % v, v, "aws_access_key")
    v = g.s(40, AN + "/+")
    add("aws_secret", "aws_secret_access_key = %s" % v, v, "aws_secret_key")
    v = "ghp_" + g.s(36)
    add("github_ghp", "token %s end" % v, v, "github_token")
    v = "github_pat_" + g.s(22) + "_" + g.s(59)
    add("github_pat", "GH_TOKEN=%s" % v, v, "github_token")
    v = "glpat-" + g.s(20)
    add("gitlab", "CI_TOKEN: %s" % v, v, "gitlab_token")
    v = "xoxb-1234567890123-1234567890123-" + g.s(24)
    add("slack_xoxb", "SLACK=%s" % v, v, "slack_token")
    v = "xoxp-1234567890-1234567890-" + g.s(32)
    add("slack_xoxp", v, v, "slack_token")
    v = "https://hooks.slack.com/services/T0%s/B0%s/%s" % (g.s(8, UPPER32), g.s(8, UPPER32), g.s(24))
    add("slack_webhook", "curl -X POST %s" % v, v, "slack_webhook")
    v = uid + "." + g.s(6, AN + "_-") + "." + g.s(38, AN + "_-")
    add("discord_token", "client.run('%s')" % v, v, "discord_token")
    v = "https://discord.com/api/webhooks/123456789012345678/" + g.s(68, AN + "_-")
    add("discord_webhook", v, v, "discord_webhook")
    v = "sk_live_" + g.s(24)
    add("stripe_sk", "stripe.api_key = '%s'" % v, v, "stripe_key")
    v = "rk_live_" + g.s(24)
    add("stripe_rk", v, v, "stripe_key")
    v = "AIza" + g.s(35)
    add("google_aiza", "key=%s" % v, v, "google_api_key")
    v = "GOCSPX-" + g.s(28)
    add("google_gocspx", "client_secret: %s" % v, v, "google_oauth_secret")
    v = "sk-" + g.s(48)
    add("openai_classic", "OPENAI_API_KEY=%s" % v, v, "openai_key")
    v = "sk-proj-" + g.s(80, AN + "_-")
    add("openai_proj", v, v, "openai_key")
    v = "sk-ant-api03-" + g.s(90, AN + "_-") + "AA"
    add("anthropic", "ANTHROPIC_API_KEY=%s" % v, v, "anthropic_key")
    v = "cfut_" + g.s(40)
    add("cloudflare_cfut", v, v, "cloudflare_token")
    v = g.s(40, AN + "_-")
    add("cloudflare_keyword", "CLOUDFLARE_API_TOKEN=%s" % v, v, "cloudflare_token")
    v = g.s(37, HEX)
    add("cloudflare_global", "X-Auth-Key: %s" % v, v, "cloudflare_token")
    v = "SK" + g.s(32, HEX)
    add("twilio", "TWILIO_API_KEY=%s" % v, v, "twilio_key")
    v = "SG.%s.%s" % (g.s(22, AN + "_-"), g.s(43, AN + "_-"))
    add("sendgrid", v, v, "sendgrid_key")
    v = "re_%s_%s" % (g.s(8), g.s(24))
    add("resend", "RESEND_API_KEY=%s" % v, v, "resend_key")
    v = "npm_" + g.s(36)
    add("npm", "//registry.npmjs.org/:_authToken=%s" % v, v, "npm_token")
    v = "pypi-AgEIcHlwaS5vcmc" + g.s(60, AN + "_-")
    add("pypi", "password = %s" % v, v, "pypi_token")
    v = "123456789:AA" + g.s(33, AN + "_-")
    add("telegram", "BOT_TOKEN=%s" % v, v, "telegram_bot_token")
    v = g.s(86, AN + "+/") + "=="
    add("azure", "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=%s;EndpointSuffix=core.windows.net" % v,
        v, "azure_storage_key")
    add("jwt", "Authorization: Bearer %s" % jwt, jwt, "jwt", "medium")
    v = g.s(14)
    add("conn_postgres", "DATABASE_URL=postgres://app:%s@db.internal.corp:5432/app" % v, v, "connection_string")
    v = g.s(14)
    add("conn_mongo", "mongodb+srv://svc:%s@cluster0.abcde.mongodb.net/db" % v, v, "connection_string")
    v = g.s(14)
    add("conn_redis", "REDIS_URL=rediss://default:%s@cache.corp.io:6380" % v, v, "connection_string")
    v = g.s(14)
    add("basic_auth", "git clone https://deploy:%s@git.corp.io/repo.git" % v, v, "basic_auth_url")
    add("pw_screenshot", "Username: admin\nPassword: hunter2xyz\n[ Sign in ]", "hunter2xyz", "password", "medium")
    v = g.s(12)
    add("pw_env", "DB_PASSWORD=%s" % v, v, "password", "medium")
    add("pw_json", '{"user": "a", "password": "c0rrect-h0rse-battery"}', "c0rrect-h0rse-battery", "password",
        "medium")
    add("pw_camel", "const dbPassword = 'Tr0ub4dor&3x';", "Tr0ub4dor&3x", "password", "medium")
    v = "Zx9" + g.s(10)
    add("pw_xml", "<password>%s</password>" % v, v, "password", "medium")
    add("pw_german", "Passwort: geheim123x", "geheim123x", "password", "medium")
    v = g.s(24)
    add("secret_assign", "client_secret = %s" % v, v, "secret_assignment", "medium")
    v = g.s(40)
    add("entropy_bearer", "Authorization: Bearer %s" % v, v, "generic_secret", "medium")
    v = g.s(32)
    add("entropy_credential", "credential %s" % v, v, "generic_secret", "medium")
    add("ipv4_private", "db host 10.20.30.40 port 5432", "10.20.30.40", "ip_private", "low")
    add("ipv4_public", "peer 93.184.216.34 connected", "93.184.216.34", "ip_public", "medium")
    add("ipv6_public", "peer 2a01:4f8:c0c:1234::1 connected", "2a01:4f8:c0c:1234::1", "ip_public", "medium")
    add("ipv6_private", "peer fd12:3456:789a::1 connected", "fd12:3456:789a::1", "ip_private", "low")
    add("email", "contact alice.smith@corp.io please", "alice.smith@corp.io", "email", "low")
    v = g.card("4", 16)
    add("card_visa", "card %s %s %s %s exp 12/29" % (v[:4], v[4:8], v[8:12], v[12:]), v, "credit_card")
    v = g.card("51", 16)
    add("card_mc", "mc %s" % v, v, "credit_card")
    v = g.card("37", 15)
    add("card_amex", "amex %s-%s-%s" % (v[:4], v[4:10], v[10:]), v, "credit_card")
    add("iban_de", "IBAN DE89 3704 0044 0532 0130 00", "DE89370400440532013000", "iban", "medium")
    add("iban_gb", "iban: GB82WEST12345698765432", "GB82WEST12345698765432", "iban", "medium")
    return rows


TRUE_POSITIVES = build_true_positives()

FALSE_POSITIVES = [
    "Version v1.2.3.4 build 10.0.19045.3693, Chrome/120.0.0.0 Safari/537.36, firmware 2.1.0.12, ver. 4.3.2.1",
    "semver 1.2.3-beta.4+build.5, ^4.17.21, ~2.0.0, python 3.12.1, node v18.19.0, 1.2.3 and 10.0.0",
    "id 550e8400-e29b-41d4-a716-446655440000 guid {6F9619FF-8B86-D011-B42D-00C04FC964FF}",
    "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
    "sha1 da39a3ee5e6b4b0d3255bfef95601890afd80709 md5 d41d8cd98f00b204e9800998ecf8427e",
    "commit 3f2a9c1b7d4e5f60718293a4b5c6d7e8f9012345 bundle app.3f2a9c1b.js "
    "photo_e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.png",
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore "
    "magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo.",
    "color: #ff00aa; background: rgba(0, 0, 0, .5); border: 1px solid #333333; fill: hsl(120, 100%, 50%); "
    "--accent: #1e90ffcc; transform: translate(12.5px, 3.25px) matrix(1.0, 0.0, 0.0, 1.0, 0, 0)",
    "dates 2024-01-15 15.01.2024 12/31/2024 2024-01-15T10:20:30Z 10:20:30 epoch 1705312830 build 20240115.1",
    "localhost 127.0.0.1 0.0.0.0 ::1 fe80::1 255.255.255.255 8.8.8.8 1.1.1.1 9.9.9.9 2001:4860:4860::8888",
    "documentation 192.0.2.1 198.51.100.7 203.0.113.9 2001:db8::1 2001:db8:85a3::8a2e:370:7334",
    "AWS docs: AKIAIOSFODNN7EXAMPLE / wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "password = os.environ['DB_PASSWORD'] ; password: str ; Password: ******** ; Password: Forgot? ; "
    "password=${DB_PASS} ; Passwort: vergessen? ; password: <your password>",
    "const token = getToken(); let apiKey = config.apiKey; secret: process.env.SECRET; token=null",
    "The token bucket refills every second; the secret sauce is simplicity. Passwords must be 12 characters.",
    "phone +49 170 1234567, order 2024-000123, invoice 000123456789, test card 4242 4242 4242 4242",
    "std::vector<int> a; Foo::Bar::baz(); mac 00:1A:2B:3C:4D:5E time 12:30:45",
    "git@github.com:user/repo.git icon@2x.png user@example.com npm i left-pad@1.3.0 noreply@corp.test",
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5E"
    "rkJggg==",
    "sk-learn scikit-learn; stripe test key sk_test_" + "a" * 24 + "; npm_config_cache=/tmp",
    "coords 48.8566, 2.3522 and pi 3.14159265358979 and 1,234,567.89 EUR",
]


class TruePositives(unittest.TestCase):
    def test_every_family_found(self):
        for label, text, secret, type_, sev in TRUE_POSITIVES:
            with self.subTest(label):
                fs = detect.scan_text(text, "f.txt")
                hits = [f for f in fs if f["type"] == type_]
                self.assertTrue(hits, "%s: no %s finding in %r" % (label, type_, [f["type"] for f in fs]))
                self.assertEqual(hits[0]["severity"], sev, label)
                self.assertTrue(set(hits[0]) >= {"type", "severity", "sample", "where", "confidence"})

    def test_every_type_covered(self):
        types = {row[3] for row in TRUE_POSITIVES}
        for t in ("private_key", "aws_access_key", "github_token", "gitlab_token", "slack_token", "slack_webhook",
                  "discord_token", "discord_webhook", "stripe_key", "google_api_key", "google_oauth_secret",
                  "openai_key", "anthropic_key", "cloudflare_token", "twilio_key", "sendgrid_key", "resend_key",
                  "npm_token", "pypi_token", "telegram_bot_token", "azure_storage_key", "jwt", "connection_string",
                  "basic_auth_url", "password", "generic_secret", "ip_private", "ip_public", "email", "credit_card",
                  "iban"):
            self.assertIn(t, types)

    def test_findings_never_carry_the_secret(self):
        for label, text, secret, _type, _sev in TRUE_POSITIVES:
            with self.subTest(label):
                for f in detect.scan_text(text, "f.txt") + detect.scan_text(text, "f.txt", ocr=True):
                    self.assertNotIn(secret, f["sample"])
                    self.assertNotIn(secret, f["where"])
                    self.assertLessEqual(lcs(secret, f["sample"]), 4, (label, f["sample"]))

    def test_where_has_line_numbers(self):
        v = "ghp_" + Gen(1).s(36)
        fs = detect.scan_text("a\nb\ntoken %s\n" % v, "cfg/app.txt")
        self.assertEqual(fs[0]["where"], "cfg/app.txt:3")
        self.assertEqual(detect.scan_text("token " + v)[0]["where"], "line 1")

    def test_private_key_header_without_body(self):
        fs = detect.scan_text("-----BEGIN PRIVATE KEY-----\n(redacted)\n", "notes.txt")
        self.assertEqual([(f["type"], f["severity"], f["confidence"]) for f in fs], [("private_key", "high", "medium")])
        fs = detect.scan_text("if (s.startsWith('-----BEGIN PRIVATE KEY-----')) parse(s)", "lib.js", web_asset=True)
        self.assertEqual([(f["type"], f["severity"]) for f in fs], [("private_key", "low")])

    def test_putty_key(self):
        text = "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nPublic-Lines: 2\nx\nPrivate-Lines: 1\ny\n"
        self.assertEqual(detect.scan_text(text)[0]["type"], "private_key")

    def test_ip_severity_from_conf(self):
        pub, priv = "peer 93.184.216.34", "host 10.1.2.3"
        self.assertEqual(detect.scan_text(pub, conf={"detect": {"public_ip_severity": "high"}})[0]["severity"], "high")
        self.assertEqual(detect.scan_text(pub, conf={"public_ip_severity": "low"})[0]["severity"], "low")  # flat
        self.assertEqual(detect.scan_text(priv, conf={"detect": {"private_ip_severity": "medium"}})[0]["severity"],
                         "medium")
        self.assertEqual(detect.scan_text("mail bob@corp.io", conf={"detect": {"email_severity": "medium"}})[0]
                         ["severity"], "medium")
        v6 = detect.scan_text("peer 2a01:4f8:c0c:1234::1", conf={"detect": {"public_ip_severity": "high"}})
        self.assertEqual(v6[0]["severity"], "high")

    def test_ip_version_context_ignored(self):
        for s in ("version 93.184.216.34", "v93.184.216.34", "Chrome/93.184.216.34", "build 93.184.216.34",
                  "firmware: 93.184.216.34", "093.184.216.34", "93.184.216.340", "93.184.216.34.5"):
            with self.subTest(s):
                self.assertEqual(detect.scan_text(s), [])

    def test_luhn_and_iban_checksums(self):
        good = Gen(3).card("4", 16)
        bad = good[:-1] + str((int(good[-1]) + 1) % 10)
        self.assertEqual(detect.scan_text("card " + good)[0]["type"], "credit_card")
        self.assertEqual(detect.scan_text("card " + bad), [])
        self.assertEqual(detect.scan_text("IBAN DE88 3704 0044 0532 0130 00"), [])        # mod-97 fails
        self.assertEqual(detect.scan_text("IBAN DE89 3704 0044 0532 0130"), [])           # too short for DE
        self.assertEqual(detect.scan_text("IBAN ZZ89 3704 0044 0532 0130 00"), [])        # unknown country
        self.assertTrue(detect._luhn("79927398713"))
        self.assertFalse(detect._luhn("79927398710"))

    def test_invalid_shapes_rejected(self):
        g = Gen(4)
        for s in ("ghp_" + "a" * 36,                       # no entropy
                  "AKIA" + "A" * 16,                        # repeated
                  "sk_live_" + "0" * 24,
                  "eyJhbGciOi.eyJzdWIiOi.abcdefgh",         # header is not JSON
                  "xoxb-abcdefghijkl",                      # no digits
                  "SK" + "0" * 32,                          # hex check: needs letters and digits
                  "MTIzNDU2.abcdef." + g.s(30)):            # discord: user id segment too short
            with self.subTest(s[:12]):
                self.assertEqual([f for f in detect.scan_text(s) if f["severity"] != "low"], [])

    def test_dedupe_and_caps(self):
        v = "ghp_" + Gen(5).s(36)
        fs = detect.scan_text("\n".join(["token " + v] * 20))
        self.assertEqual(len(fs), 1)
        g = Gen(55)
        fs = detect.scan_text("\n".join("token ghp_" + g.s(36) for _ in range(120)))
        self.assertEqual(len(fs), detect.MAX_PER_TYPE)          # a file full of tokens is one problem
        ips = detect.scan_text("\n".join("10.0.%d.%d" % (i // 250, i % 250 + 1) for i in range(400)))
        self.assertLessEqual(len(ips), detect.MAX_PER_TYPE)     # same redacted sample = one finding
        self.assertEqual(detect.dedupe([{"type": "a", "severity": "low", "sample": "x", "where": "w"}] * 3),
                         [{"type": "a", "severity": "low", "sample": "x", "where": "w"}])

    def test_sorted_by_severity_and_max(self):
        v = "ghp_" + Gen(6).s(36)
        fs = detect.scan_text("mail a.b@corp.io\npeer 93.184.216.34\ntoken %s" % v)
        self.assertEqual([f["severity"] for f in fs], ["high", "medium", "low"])
        self.assertEqual(detect.max_severity(fs), "high")
        self.assertEqual(detect.max_severity([]), "none")
        self.assertEqual(detect.max_severity(None), "none")
        self.assertEqual(detect.max_severity([{"severity": "low"}, {"severity": "bogus"}]), "low")

    def test_bytes_and_empty_input(self):
        v = "ghp_" + Gen(7).s(36)
        self.assertEqual(detect.scan_text(("token " + v).encode())[0]["type"], "github_token")
        self.assertEqual(detect.scan_text(""), [])
        self.assertEqual(detect.scan_text(None), [])


class OcrNoise(unittest.TestCase):
    """OCR splits tokens with spaces and confuses O/0, l/1/I; ocr=True undoes that (lower confidence)."""

    def check(self, text, type_):
        self.assertFalse([f for f in detect.scan_text(text) if f["type"] == type_], "plain scan should miss it")
        hits = [f for f in detect.scan_text(text, ocr=True) if f["type"] == type_]
        self.assertTrue(hits, text)
        return hits[0]

    def test_spaces_inside_tokens(self):
        g = Gen(11)
        v = "ghp_" + g.s(36)
        f = self.check("token %s %s %s" % (v[:14], v[14:26], v[26:]), "github_token")
        self.assertEqual(f["confidence"], "medium")
        self.assertEqual(f["severity"], "high")
        v = "glpat-" + g.s(20)
        self.check("glpat - %s %s" % (v[6:16], v[16:]), "gitlab_token")
        self.check("sk - ant - api03-" + g.s(60), "anthropic_key")
        v = "sk_live_" + g.s(24)
        self.check("sk_l1ve_%s %s" % (v[8:20], v[20:]), "stripe_key")

    def test_letter_digit_confusion(self):
        g = Gen(12)
        self.check("Alza" + g.s(35), "google_api_key")                        # AIza read as Alza
        self.check("AKlA" + g.s(16, UPPER32), "aws_access_key")               # AKIA read as AKlA
        self.check("x0xb-1234567890123-" + g.s(24), "slack_token")
        self.check("G0CSPX-" + g.s(28), "google_oauth_secret")
        f = self.check("server l92.168.1O.23", "ip_private")
        head, tail = f["sample"].split(ELL)
        self.assertTrue("192.168.10.23".startswith(head) and "192.168.10.23".endswith(tail))
        card = g.card("4", 16)
        noisy = card[:4] + " " + card[4:8].replace("1", "l").replace("0", "O") + " " + card[8:12] + " " + card[12:]
        if noisy.replace(" ", "") != card:
            self.check("card " + noisy, "credit_card")
        self.check("card 4539 l488 O343 6467", "credit_card")

    def test_screenshot_password(self):
        fs = detect.scan_text("Username: admin\nPassw0rd: hunter2xyz", ocr=True)
        self.assertEqual([f["type"] for f in fs], ["password"])
        self.assertNotIn("hunter2xyz", fs[0]["sample"])

    def test_ocr_mode_without_noise_keeps_confidence(self):
        v = "ghp_" + Gen(13).s(36)
        f = detect.scan_text("token " + v, "shot.png", ocr=True)[0]
        self.assertEqual((f["confidence"], f["where"]), ("high", "shot.png"))     # no line numbers for OCR text

    def test_normalize_leaves_prose_alone(self):
        prose = "Hello world, the quick brown fox jumps over the lazy dog. Call me at 10:30 on Monday."
        self.assertEqual(detect.ocr_normalize(prose), prose)


class FalsePositives(unittest.TestCase):
    def test_corpus_is_clean(self):
        for text in FALSE_POSITIVES:
            for kw in ({}, {"ocr": True}, {"web_asset": True}):
                with self.subTest(text=text[:40], **kw):
                    fs = detect.scan_text(text, "f.txt", **kw)
                    self.assertEqual(fs, [], [(f["type"], f["sample"]) for f in fs])

    def test_corpus_as_one_document(self):
        self.assertEqual(detect.scan_text("\n".join(FALSE_POSITIVES), ocr=True), [])

    def test_placeholders_and_code(self):
        for s in ('password: "${PASSWORD}"', "PASSWORD=<changeme>", "password = get_password()",
                  "password: {{ vault_password }}", "password=%s", "pwd = self.password",
                  "api_key: YOUR_API_KEY_HERE", "token: xxxxxxxxxxxxxxxxxxxx", "secret = process.env.APP_SECRET",
                  "password: required", "Password: \u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022",
                  "Password: Show", "passwords: must_contain_digits"):
            with self.subTest(s):
                self.assertEqual(detect.scan_text(s), [])


class WebAssets(unittest.TestCase):
    def test_downgrade(self):
        rows = {r[0]: r for r in TRUE_POSITIVES}
        keep_high = ("rsa_key", "github_ghp", "stripe_sk", "conn_postgres", "basic_auth", "anthropic", "aws_akia")
        to_low = ("jwt", "pw_env", "email", "ipv4_public", "entropy_bearer", "google_aiza", "card_visa", "iban_de")
        for label in keep_high:
            with self.subTest(label):
                f = [x for x in detect.scan_text(rows[label][1], "app.js", web_asset=True) if x["type"] == rows[label][3]]
                self.assertEqual(f[0]["severity"], "high")
        for label in to_low:
            with self.subTest(label):
                fs = detect.scan_text(rows[label][1], "app.js", web_asset=True)
                self.assertTrue(fs)
                self.assertEqual({f["severity"] for f in fs}, {"low"})


class Redaction(unittest.TestCase):
    def test_bounds(self):
        r = random.Random(99)
        for n in list(range(0, 80)) + [100, 255, 1000]:
            s = "".join(r.choice(AN) for _ in range(n))
            out = detect.redact(s)
            visible = out.replace(ELL, "")
            with self.subTest(n=n):
                self.assertIn(ELL, out)
                self.assertLessEqual(len(visible), min(8, n // 4))            # <= first 4 + last 4, <= 25 %
                head = out.split(ELL)[0]
                tail = out.split(ELL)[1]
                self.assertLessEqual(len(head), 4)
                self.assertLessEqual(len(tail), 4)
                self.assertTrue(s.startswith(head) and s.endswith(tail))
                if n:
                    self.assertNotEqual(out, s)

    def test_examples(self):
        v = "ghp_" + "A1b2" * 8 + "Xy3Q"
        self.assertEqual(detect.redact(v), "ghp_" + ELL + "Xy3Q")
        self.assertEqual(detect.redact("abc"), ELL)
        self.assertEqual(detect.redact(None), ELL)
        self.assertEqual(detect.redact(12345678), "1" + ELL + "8")


class ImageSvgPdfNames(unittest.TestCase):
    def jpeg(self, gps):
        from PIL import Image
        img = Image.new("RGB", (32, 32), "white")
        exif = Image.Exif()
        if gps:
            exif.get_ifd(0x8825).update({1: "N", 2: (48.0, 51.0, 29.0), 3: "E", 4: (2.0, 17.0, 40.0)})
        buf = io.BytesIO()
        img.save(buf, "JPEG", exif=exif)
        buf.seek(0)
        return Image.open(buf)

    def test_exif_gps(self):
        fs = detect.exif_findings(self.jpeg(True), where="a.jpg")
        self.assertEqual([(f["type"], f["severity"], f["where"]) for f in fs], [("gps", "low", "a.jpg")])
        fs = detect.exif_findings(self.jpeg(True), {"detect": {"gps_severity": "medium"}})
        self.assertEqual(fs[0]["severity"], "medium")
        self.assertEqual(detect.exif_findings(self.jpeg(False)), [])

    def test_exif_gps_from_path_and_xmp(self):
        import tempfile
        from PIL import Image
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "x.jpg")
            self.jpeg(True).save(p, "JPEG", exif=self.jpeg(True).getexif())
            self.assertEqual(detect.exif_findings(p)[0]["type"], "gps")
            img = Image.new("RGB", (8, 8))
            img.info["xmp"] = b"<x:xmpmeta><rdf:Description exif:GPSLatitude='48,51.5N'/></x:xmpmeta>"
            self.assertEqual(detect.exif_findings(img)[0]["type"], "gps")
        finally:
            import shutil
            shutil.rmtree(d, ignore_errors=True)

    def test_svg_active(self):
        cases = {
            "<svg><script>alert(1)</script></svg>": "<script>",
            "<svg><svg:script href='x.js'/></svg>": "<script>",
            '<svg onload="alert(1)"><rect/></svg>': "onload= handler",
            '<svg><a href="javascript:alert(1)"><text>x</text></a></svg>': "javascript: URI",
            '<svg><a href="jav&#x09;ascript:alert(1)">x</a></svg>': "javascript: URI",
            "<svg><foreignObject><div/></foreignObject></svg>": "<foreignObject>",
            '<svg><image href="https://tracker.example.net/p.png"/></svg>': "external href",
            '<svg><style>@import "https://cdn.example.net/x.css";</style></svg>': "external resource",
            '<!DOCTYPE svg [<!ENTITY x SYSTEM "file:///c:/windows/win.ini">]><svg>&x;</svg>': "DTD entity",
            "<svg><iframe src='x'/></svg>": "<iframe>",
        }
        for svg, sample in cases.items():
            with self.subTest(sample):
                fs = detect.svg_findings(svg, "x.svg")
                self.assertTrue(any(f["sample"].startswith(sample) for f in fs), fs)
                self.assertTrue(all(f["severity"] == "medium" and f["type"] == "svg_active" for f in fs))

    def test_svg_clean(self):
        svg = ('<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" '
               'xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 10 10"><defs><linearGradient id="g"/>'
               '</defs><use xlink:href="#g"/><image href="data:image/png;base64,iVBORw0KGgo="/>'
               '<path d="M1 1L9 9" style="fill:url(#g)"/><text>Say onload = no</text></svg>')
        self.assertEqual(detect.svg_findings(svg), [])
        self.assertEqual(detect.svg_findings(svg.encode()), [])

    def test_pdf_active(self):
        fs = detect.pdf_active_findings(PDF_JS, "a.pdf")
        samples = {f["sample"] for f in fs}
        self.assertTrue({"/JavaScript", "/JS", "/OpenAction+JS"} <= samples, samples)
        self.assertTrue(all(f["severity"] == "medium" and f["where"] == "a.pdf" for f in fs))
        self.assertEqual({f["sample"] for f in detect.pdf_active_findings(pdf_with(b"/Type /Catalog /AA 9 0 R"))},
                         {"/AA"})
        for name, want in ((b"/Launch", "/Launch"), (b"/EmbeddedFiles", "/EmbeddedFile"), (b"/XFA", "/XFA"),
                           (b"/RichMedia", "/RichMedia")):
            got = {f["sample"] for f in detect.pdf_active_findings(pdf_with(b"/Type /Catalog " + name + b" 5 0 R"))}
            self.assertEqual(got, {want}, name)

    def test_pdf_hex_escaped_and_object_stream(self):
        fs = detect.pdf_active_findings(pdf_with(b"/S /J#61vaScript /J#53 (x)"))
        self.assertIn("/JavaScript", {f["sample"] for f in fs})
        inner = b"5 0 << /S /JavaScript /JS (app.alert\\(1\\)) >>"
        z = zlib.compress(inner)
        objstm = (b"%PDF-1.7\n5 0 obj << /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length "
                  + str(len(z)).encode() + b" >>\nstream\n" + z + b"\nendstream\nendobj\n%%EOF\n")
        self.assertIn("/JavaScript", {f["sample"] for f in detect.pdf_active_findings(objstm)})

    def test_pdf_harmless_mentions(self):
        self.assertEqual(detect.pdf_active_findings(PDF_HARMLESS), [])
        self.assertFalse(detect.pdf_encrypted(PDF_HARMLESS))
        self.assertTrue(detect.pdf_encrypted(pdf_with(b"/Type /Catalog", trailer=b"/Encrypt 9 0 R")))

    def test_name_findings(self):
        cases = [(".env", "high"), ("app/.env.production", "high"), ("home/.ssh/id_rsa", "high"),
                 ("keys/server.pem", "high"), ("certs/client.P12", "high"), ("aws/credentials.json", "high"),
                 ("proj/.git/config", "high"), ("vault.kdbx", "high"), ("tools/run.ps1", "medium"),
                 ("setup.bat", "medium"), ("x/y.hta", "medium"), ("bin/app.exe", "low"), ("lib/x.dll", "low"),
                 ("docs/readme.txt", None), ("img/cat.png", None), ("envelope.txt", None), ("key.txt", None)]
        for rel, sev in cases:
            with self.subTest(rel):
                fs = detect.name_findings(rel)
                self.assertEqual(detect.max_severity(fs), sev or "none", fs)
                if fs:
                    self.assertEqual(fs[0]["where"], rel)
        self.assertEqual(detect.name_findings("a\\b\\.env")[0]["severity"], "high")
        conf = {"scan": {"archive": {"hold_inner_ext": ["exe"], "report_inner_ext": ["ps1"]}}}
        self.assertEqual(detect.max_severity(detect.name_findings("a.exe", conf)), "medium")
        self.assertEqual(detect.max_severity(detect.name_findings("a.ps1", conf)), "low")
        self.assertEqual(detect.name_findings(""), [])


def pdf_with(catalog, trailer=b""):
    return (b"%PDF-1.4\n1 0 obj << " + catalog + b" >> endobj\n2 0 obj << /Type /Pages /Kids [] /Count 0 >> endobj\n"
            b"trailer << /Root 1 0 R " + trailer + b" >>\n%%EOF\n")


def _pdf(objs):
    out, offs = bytearray(b"%PDF-1.4\n"), []
    for i, body in enumerate(objs, 1):
        offs.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    out += b"".join(b"%010d 00000 n \n" % o for o in offs)
    out += b"trailer << /Size %d /Root 1 0 R /Info %d 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, len(objs),
                                                                                          xref)
    return bytes(out)


def _stream(data):
    return b"<< /Length %d >>\nstream\n" % len(data) + data + b"\nendstream"


# Minimal but structurally valid PDFs (hand-written xref), shared with test_scan_scan.
PDF_JS = _pdf([b"<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>",
               b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
               b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>",
               _stream(b"BT /F1 12 Tf 20 100 Td (Hello) Tj ET"),
               b"<< /S /JavaScript /JS (app.alert\\('hi'\\);) >>",
               b"<< /Title (js demo) >>"])
PDF_HARMLESS = _pdf([b"<< /Type /Catalog /Pages 2 0 R >>",
                     b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
                     b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>",
                     _stream(b"BT /F1 12 Tf 20 100 Td (Learning JavaScript: /JS and /Launch explained) Tj ET"),
                     b"<< /Title (JavaScript /JavaScript /OpenAction /AA handbook) /Subject (see /JS) >>"])


if __name__ == "__main__":
    unittest.main()
