"""Strata Media rules integration: media_rules.py and its hooks in rules.py (DESIGN 4, 4.1-4.3, 5, 6.1, 11-13).

Never touches production: every render runs against a sqlite backup of a read-only connection to strata.db (a
temp copy), CFG is only changed in memory, the private Caddy runs on test ports 18380-18382 with admin
localhost:2098, its own storage and log, and two stubs emulate the upstreams: 18384 = media.py (accel / orig /
302 / 403 / 503 / lane / 404, /_scan) and 18385 = Strata Transform (/_gate, ?ver=).
"""
import base64
import contextlib
import copy
import http.client
import http.server
import json
import os
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
MEDIA_DIR = os.path.dirname(HERE)
STRATA = os.path.dirname(MEDIA_DIR)
for _p in (MEDIA_DIR, STRATA):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import pathfix  # noqa: E402,F401  (vendored Pillow / user site)
import config as mconfig  # noqa: E402  (media/config.py)
import core  # noqa: E402

# tests follow the design defaults, never whatever the live strata.json currently says (e.g. the deployed profile)
core.CFG["media"].clear()
core.CFG["media"].update(copy.deepcopy(core.DEFAULTS["media"]))
import rules  # noqa: E402
import media_rules  # noqa: E402

CADDY = os.environ.get("STRATA_CADDY") or shutil.which("caddy") or "caddy"
SITE_PORT, HTTP_PORT, HTTPS_PORT, MEDIA_PORT, TF_PORT = 18380, 18381, 18382, 18384, 18385
ADMIN = "localhost:2098"
MID = 77  # test files mount id in the temp DB copy
TMP = None


def setUpModule():
    global TMP
    TMP = tempfile.mkdtemp(prefix="strata-rules-media-")


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


def copy_db(path):
    """Temp copy of the live strata.db through a read-only connection (the original is never opened for writing)."""
    src = sqlite3.connect("file:%s?mode=ro" % core.DB_PATH.replace("\\", "/"), uri=True)
    dst = sqlite3.connect(path)
    try:
        src.backup(dst)
    finally:
        src.close()
    return dst


@contextlib.contextmanager
def media_cfg(enabled=True, **over):
    """CFG["media"] (and transform_listen) changed in memory only, restored in place afterwards."""
    saved, tl = copy.deepcopy(core.CFG["media"]), core.CFG.get("transform_listen")
    try:
        core.CFG["media"]["enabled"] = enabled
        for k, v in over.items():
            if k == "transform_listen":
                core.CFG["transform_listen"] = v
            else:
                core.CFG["media"][k] = v
        yield core.CFG["media"]
    finally:
        core.CFG["media"].clear()
        core.CFG["media"].update(saved)
        core.CFG["transform_listen"] = tl


def add_test_mount(db, root, log_file, browse=0, pw_hash=None):
    """Test files mount (host localhost) + test-scoped access rules + site settings for the private Caddy."""
    t = time.time()
    db.execute("INSERT INTO mount(id,name,kind,path,prefix,hosts,cache,edge_cache,precompress,browse,transforms,"
               "enabled,sort,note,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,1,?,?,?,?)",
               [MID, "Media test", "files", root.replace("\\", "/"), "/", json.dumps(["localhost"]), "public, no-cache",
                "public, max-age=31536000", 0, browse, 1, 5, "rules-media test", t, t])
    rows = [("test allow exe", ["/tools/*.exe"], "allow", {}),
            ("test cache", ["/cached/*"], "cache", {"value": "public, max-age=86400"}),
            ("test signed", ["/signed/*"], "signed", {})]
    if pw_hash:
        rows.append(("test password", ["/private/*"], "password", {"users": [{"user": "tester", "hash": pw_hash}],
                                                                  "realm": "Test"}))
    for i, (name, pats, action, params) in enumerate(rows):
        db.execute("INSERT INTO rule(name,mount,patterns,action,params,enabled,sort,note,builtin,created,updated) "
                   "VALUES(?,?,?,?,?,1,?,?,0,?,?)", [name, MID, json.dumps(pats), action, json.dumps(params),
                                                     900 + i, "rules-media test", t, t])
    s = rules.site(db)
    s.update(listen=":%d" % SITE_PORT, log_file=log_file.replace("\\", "/"), error_mount=MID,
             error_page="/404/404.html", error_page_403="/404/403.html")
    core.set_meta(db, "site", s)
    db.commit()


def caddyfile(site_path, storage, extra=""):
    return ("{\n\tadmin %s\n\tpersist_config off\n\tauto_https off\n\thttp_port %d\n\thttps_port %d\n"
            "\tstorage file_system %s\n%s}\nimport %s\n" % (ADMIN, HTTP_PORT, HTTPS_PORT,
                                                           rules.bq(storage.replace("\\", "/")), extra,
                                                           site_path.replace("\\", "/")))


def caddy_validate(text, name):
    d = os.path.join(TMP, "validate-" + name)
    os.makedirs(d, exist_ok=True)
    site = os.path.join(d, "cdn.caddy")
    with open(site, "w", encoding="utf-8") as f:
        f.write(text)
    main = os.path.join(d, "Caddyfile")
    with open(main, "w", encoding="utf-8") as f:
        f.write(caddyfile(site, os.path.join(d, "storage")))
    r = subprocess.run([CADDY, "validate", "--config", main, "--adapter", "caddyfile"], capture_output=True,
                       text=True, timeout=120, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return r.returncode, (r.stderr or "")[-1500:]


def logfile(name):
    return os.path.join(TMP, name + "-access.log")


# ---------------------------------------------------------------- regexes (Python re == RE2 for these constructs)

class TestRegexes(unittest.TestCase):
    def setUp(self):
        self.fp = copy.deepcopy(core.DEFAULTS["media"]["file_policy"])
        self.dang = re.compile(media_rules.dangerous_regex(self.fp))
        self.safe = re.compile(media_rules.safe_regex(self.fp))

    def verdict(self, path):
        if self.dang.search(path):
            return 404
        return 200 if self.safe.search(path) else 403

    def test_dangerous_names_and_extensions(self):
        for p in ("/.env", "/a/.env", "/a/.env.local", "/x/.git/config", "/.git", "/a/id_rsa", "/cfg/app.env",
                  "/a/b.ENV", "/secrets.txt", "/Secrets.JSON", "/appsettings.Development.json", "/a/credentials",
                  "/a/credentials.csv", "/a/wp-config.php", "/x.php", "/a/Thumbs.db", "/strata.json",
                  "/terraform.tfstate.backup", "/db.sqlite3", "/x.log", "/k.PEM", "/.ssh/id_ed25519.pub",
                  "/docker-compose.yml", "/x.env/"):
            self.assertEqual(self.verdict(p), 404, p)

    def test_ntfs_aliases(self):
        for p in ("/x.env.", "/x.env ", "/x.env. .", "/.env./", "/a\\.env", "/a\\b.png", "/x.png::$DATA", "/x:y.png",
                  "/CREDEN~1.TXT", "/credEN~1.txt", "/PROGRA~1/x.png", "/GIT~1/config", "/AB~12345", "/A~1",
                  "/lyla./audio/x.mp3", "/dir /x.png", "/a\x01b.png", "/x.png.", "/LICENSE."):
            self.assertEqual(self.verdict(p), 404, repr(p))

    def test_unknown_types(self):
        for p in ("/tool.exe", "/data.xyz", "/noext", "/a/b.PY", "/x.bat", "/x.svgz", "/l/somecode", "/a/b.pub"):
            self.assertEqual(self.verdict(p), 403, p)

    def test_safe(self):
        for p in ("/", "/dir/", "/a.PNG", "/general/photo.png", "/LICENSE", "/sub/README", "/x.tar.gz", "/a.svg",
                  "/my.env.png", "/environment.png", "/secretsauce.png", "/credentials-guide.pdf", "/x..png",
                  "/file~name.jpeg", "/a/b.min.js", "/v1.2/app.css", "/404/404.html", "/m.webmanifest", "/x.br"):
            self.assertEqual(self.verdict(p), 200, p)

    def test_globs_stay_within_a_segment(self):
        self.assertEqual(self.verdict("/appsettings/x/y.json"), 200)       # appsettings*.json never crosses '/'
        self.assertEqual(self.verdict("/secrets./x.png"), 404)             # trailing dot segment (alias)
        self.assertEqual(self.verdict("/secrets.d/x.png"), 404)            # secrets.* matches a folder too

    def test_re2_safe_and_caddyfile_tokens(self):
        rxs = [media_rules.dangerous_regex(self.fp), media_rules.safe_regex(self.fp), media_rules.SVG_RX,
               media_rules.gated_regex(core.DEFAULTS["media"]["gate"]["categories"])]
        for rx in rxs:
            self.assertIsNone(rules.RE2_BAD.search(rx), rx[:80])
            self.assertTrue(rules.bq(rx).startswith("`"))
            re.compile(rx)

    def test_gate_regex_tolerates_trailing_dots(self):
        g = re.compile(media_rules.gated_regex(["pdf", "exec"]))
        for p in ("/a.pdf", "/a.PDF.", "/a.pdf ", "/b.exe"):
            self.assertTrue(g.search(p), p)
        self.assertFalse(g.search("/a.png"))

    def test_sets_match_media_config(self):
        self.assertEqual(media_rules.CATEGORY_EXT, mconfig.CATEGORIES)
        mv = re.compile(r"(?i)\.(%s)$" % media_rules.MEDIA_EXT_RX)
        for e in mconfig.TRANSFORMABLE | mconfig.VIDEO_EXT | {"webm"}:
            self.assertTrue(mv.search("/x." + e.upper()), e)
        for e in ("svg", "pdf", "ts", "ogv", "ico"):
            self.assertFalse(mv.search("/x." + e), e)
        neg = re.compile(r"(?i)\.(%s)$" % media_rules.NEG_IMG_RX)
        self.assertEqual({e for e in mconfig.TRANSFORMABLE | {"webp", "avif"} if neg.search("/x." + e)},
                         set(mconfig.NEGOTIABLE))

    def test_variant_urls(self):
        u = "https://cdn.example.com/general/photo.png"
        self.assertEqual(media_rules.variant_urls(u), [u + "?_v=avif", u + "?_v=webp", u + "?_v=orig"])
        self.assertEqual(media_rules.variant_urls(u.replace(".png", ".MP4")),
                         [u.replace(".png", ".MP4") + "?_v=" + v for v in ("webm", "mp4", "orig")])
        self.assertEqual(media_rules.variant_urls(u + "?w=10"), [])
        self.assertEqual(media_rules.variant_urls(u.replace(".png", ".pdf")), [])


# ---------------------------------------------------------------- render (temp DB copy)

class TestRender(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = os.path.join(TMP, "render")
        cls.mount = os.path.join(cls.dir, "mount")
        os.makedirs(cls.mount)
        cls.db_path = os.path.join(cls.dir, "strata.db")
        db = copy_db(cls.db_path)
        add_test_mount(db, cls.mount, logfile("render"))
        db.close()

    def setUp(self):
        self.db = sqlite3.connect(self.db_path)
        self.addCleanup(self.db.close)

    def render(self, **over):
        with media_cfg(**over):
            return rules.render(self.db)

    def test_disabled_is_identical_to_no_media(self):
        off = self.render(enabled=False)
        saved, rules.media_rules = rules.media_rules, None
        try:
            with media_cfg(enabled=True):
                bare = rules.render(self.db)      # media_rules missing: must not matter that media is "on"
        finally:
            rules.media_rules = saved
        self.assertEqual(off, bare)
        for s in ("request_header", "@mv", "@neg", "@gate", "@lane", "@mfd", "@mfu", "Content-Security-Policy"):
            self.assertNotIn(s, off)
        self.assertIn("@tf%d_" % MID, off)
        self.assertIsNone(media_rules.hook("prologue", rules.Out()))  # disabled -> hook is a no-op

    def test_enabled_blocks_in_order(self):
        text = self.render(negotiation="redirect")
        lines = text.splitlines()
        i = lines.index("\troute {")
        self.assertEqual([l.strip() for l in lines[i + 1:i + 1 + len(media_rules.INTERNAL_HEADERS)]],
                         ["request_header -" + h for h in media_rules.INTERNAL_HEADERS])

        def at(s):
            self.assertIn(s, text)
            return text.index(s)
        # @neg before @mv: a bare ?w= must be negotiated (302 to ?w=<rung>&_v=...) before @mv could take it
        order = [at("# access rules"), at("# file policy (Strata Media)"), at("# link modifiers"),
                 at("@neg%d_" % MID), at("@mv%d_" % MID), at("@ver%d_" % MID), at("# scan gate"),
                 at("@gate%d_" % MID), at("@lane%d_" % MID), at("# drives")]
        self.assertEqual(order, sorted(order))
        if "# short links" in text:
            self.assertLess(at("# short links"), at("# file policy (Strata Media)"))
        self.assertNotIn("@tf%d_" % MID, text)                    # old transform block replaced for media mounts
        ver = text[at("@ver%d_" % MID):]
        self.assertIn("reverse_proxy @ver%d_1 %s {" % (MID, core.CFG["transform_listen"]), ver)  # ?ver= on 8083
        self.assertIn("reverse_proxy @mv%d_1 %s {" % (MID, core.CFG["media"]["listen"]), text)
        self.assertIn("forward_auth @gate%d_1 %s {" % (MID, core.CFG["media"]["listen"]), text)
        self.assertIn("{rp.header.X-Strata-Cdn-Cache-Control}", text)   # canonical spelling, see media_rules
        self.assertNotIn("X-Strata-CDN-Cache-Control}", text)
        self.assertIn("header_up X-Strata-Edge-Cache `public, max-age=31536000`", text)
        # one policy block per host set: the production drives and the localhost test drive
        self.assertEqual(text.count("error @mfd_"), 2)
        self.assertEqual(text.count("error @mfu_"), 2)

    def test_negotiation_route_per_mode(self):
        """off: none. edge: requests with a query (Cloudflare rewrites only query-less ones: ?w=, ?t=, ?v= are left to
        the origin) + Vary: Accept on the canonical original. redirect: every request without variant / explicit /
        version / download parameters, plus WebM for <video> players (the edge rule's job in edge mode)."""
        self.db.execute("DELETE FROM meta WHERE k='media_negotiation_effective'")
        text = self.render(negotiation="off")
        self.assertNotIn("@neg", text)
        self.assertNotIn("+Vary Accept", text)
        for over, meta in (({"negotiation": "auto"}, "edge"), ({"negotiation": "edge"}, {"mode": "edge"})):
            core.set_meta(self.db, "media_negotiation_effective", meta)
            text = self.render(**over)
            neg = text[text.index("@neg%d_1 {" % MID):]
            neg = neg[:neg.index("\n\t\t}")]
            self.assertIn('{http.request.uri.query} != ""', neg, over)
            self.assertNotIn('{query.w} != ""', neg, over)   # an image with ?t=1 is negotiated too, not only ?w=
            self.assertIn("header @nv%d_1 +Vary Accept" % MID, text)
            self.assertIn("@mv%d_" % MID, text)
            self.assertNotIn("@nvid", text)                    # videos: Cloudflare's WebM rule
        text = self.render(negotiation="redirect")
        vid = text[text.index("@nvid%d_1 {" % MID):]
        vid = vid[:vid.index("\n\t\t}")]
        for want in ("mp4|m4v|mov", "Sec-Fetch-Dest video", "(chrome|firefox)/", "not header_regexp", "(crios|fxios)",
                     '{http.request.uri.query} == ""'):
            self.assertIn(want, vid)
        self.assertIn("reverse_proxy @nvid%d_1" % MID, text)
        self.assertNotIn("@nvid", self.render(negotiation="redirect", video={"enabled": False}))
        # MP4 plays everywhere: every client of a query-less video is sent to ?_v=mp4, not only Chrome/Firefox players
        text = self.render(negotiation="redirect", video={"enabled": True, "format": "mp4"})
        vid = text[text.index("@nvid%d_1 {" % MID):]
        vid = vid[:vid.index("\n\t\t}")]
        self.assertIn("mp4|m4v|mov", vid)
        self.assertNotIn("Sec-Fetch-Dest", vid)
        self.assertNotIn("User-Agent", vid)
        self.assertIn('{query._v} == "mp4"', text)          # @mv takes the variant URL
        text = self.render(negotiation="redirect")
        neg = text[text.index("@neg%d_1 {" % MID):]
        neg = neg[:neg.index("\n\t\t}")]
        self.assertNotIn('{query.w} != ""', neg)
        for k in media_rules.NEG_EXCLUDE:
            self.assertIn('{query.%s} == ""' % k, neg)
        self.assertNotIn("@nv%d_" % MID, text)
        self.db.rollback()

    def test_effective_negotiation(self):
        self.db.execute("DELETE FROM meta WHERE k='media_negotiation_effective'")
        with media_cfg(negotiation="auto"):
            self.assertEqual(media_rules.effective_negotiation(self.db), "redirect")
            self.assertEqual(media_rules.effective_negotiation(None), "redirect")
            core.set_meta(self.db, "media_negotiation_effective", "edge")
            self.assertEqual(media_rules.effective_negotiation(self.db), "edge")
        with media_cfg(negotiation="off"):
            self.assertEqual(media_rules.effective_negotiation(self.db), "off")   # explicit choice wins at once
        with media_cfg(negotiation="redirect"):
            self.assertEqual(media_rules.effective_negotiation(self.db), "redirect")
        self.db.rollback()

    def test_allow_rules_carve_exceptions(self):
        text = self.render()
        # one unknown-type block per host set; their numbering follows drive order, so find them by host
        blocks = [text[text.index("@mfu_%d {" % i):text.index("error @mfu_%d 403" % i)] for i in (1, 2)]
        test = next(b for b in blocks if "host `localhost`" in b)
        prod = next(b for b in blocks if "host `localhost`" not in b)
        self.assertIn("not path `/tools/*.exe`", test)
        self.assertNotIn("/tools/*.exe", prod)                    # scoped to the test drive's hosts only

    def test_failures_never_leave_partial_blocks(self):
        good = self.render()
        orig = media_rules._RENDER["file_policy"]

        def broken(o, *a):
            o.add(2, "PARTIAL-BLOCK {")
            raise RuntimeError("boom")
        media_rules._RENDER["file_policy"] = broken
        try:
            text = self.render()
        finally:
            media_rules._RENDER["file_policy"] = orig
        self.assertNotIn("PARTIAL-BLOCK", text)
        self.assertNotIn("@mfd_", text)
        self.assertIn("@mv%d_" % MID, text)
        self.assertTrue(any("file_policy" in e for e in rules.MEDIA_ERRORS))
        # a failing media-routes renderer falls back to the old @tf transform block
        orig = media_rules._RENDER["media_routes"]
        media_rules._RENDER["media_routes"] = broken
        try:
            text = self.render()
        finally:
            media_rules._RENDER["media_routes"] = orig
        self.assertIn("@tf%d_" % MID, text)
        self.assertNotIn("@mv", text)
        self.assertEqual(self.render(), good)

    def test_prefixed_and_browse_mounts(self):
        m = {"id": 9, "kind": "files", "enabled": 1, "prefix": "/pre", "hosts": ["localhost"], "path": "C:/x",
             "cache": "public, no-cache", "edge_cache": "", "browse": 1, "transforms": 1, "sort": 1}
        with media_cfg():
            o = rules.Out()
            media_rules.render_file_policy(o, [m], [])
            text = "\n".join(o.lines)
            self.assertIn("path `/pre` `/pre/*`", text)           # no "/" drive: policy limited to its prefix
            self.assertNotIn("not file {", text)                   # browse redirect only for "/" drives
            o = rules.Out()
            self.assertTrue(media_rules.render_media_routes(o, m, [], negotiation="redirect"))
            text = "\n".join(o.lines)
            self.assertIn("uri strip_prefix `/pre`", text)
            self.assertIn("path `/pre/*`", text)
            o = rules.Out()
            media_rules.render_file_policy(o, [dict(m, prefix="/")], [])
            self.assertIn("try_files {path}/", "\n".join(o.lines))
            self.assertFalse(media_rules.render_media_routes(rules.Out(), dict(m, transforms=0), []))

    def test_caddy_validate_redirect_edge_browse(self):
        if not os.path.exists(CADDY):
            self.skipTest("caddy.exe not found")
        self.db.execute("DELETE FROM meta WHERE k='media_negotiation_effective'")
        cases = [("redirect", {"negotiation": "redirect"}, None)]
        cases.append(("edge", {"negotiation": "auto"}, "edge"))
        for name, over, meta in cases:
            if meta:
                core.set_meta(self.db, "media_negotiation_effective", meta)
            with media_cfg(cache_root=os.path.join(TMP, "cache-root"), **over):
                text = rules.render(self.db)
            self.assertIn("@neg", text)                              # both modes negotiate ?w=
            self.assertEqual(("+Vary Accept" in text), name == "edge")
            code, err = caddy_validate(text, name)
            self.assertEqual(code, 0, "%s: %s" % (name, err))
        self.db.execute("UPDATE mount SET browse=1 WHERE id=?", [MID])
        text = self.render()
        self.assertIn("not file {", text)
        code, err = caddy_validate(text, "browse")
        self.assertEqual(code, 0, "browse: %s" % err)
        self.db.rollback()


# ---------------------------------------------------------------- preview + media.json

class TestPreviewAndConfig(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = os.path.join(TMP, "preview")
        os.makedirs(cls.dir)
        cls.db = copy_db(os.path.join(cls.dir, "strata.db"))

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_file_policy_preview_on_live_index(self):
        with media_cfg():
            p = media_rules.file_policy_preview(self.db)
        c = p["counts"]
        self.assertTrue(p["enabled"])
        self.assertEqual(c["files"], c["safe"] + c["refused"] + c["rescued"] + c["already_blocked"])
        self.assertEqual(p["total"], c["refused"])
        self.assertEqual(sum(v["count"] for v in p["by_reason"].values()), c["refused"])
        self.assertEqual(sum(v["count"] for v in p["by_ext"].values()), c["refused"])
        self.assertLessEqual(set(p["by_reason"]), {"deny_name", "deny_ext", "alias", "unknown"})
        for s in p["samples"]:
            self.assertEqual(set(s), {"mount", "path", "ext", "reason", "size"})
        n_idx = self.db.execute("SELECT count(*) FROM fidx f JOIN mount m ON m.id=f.mount "
                                "WHERE m.kind='files' AND m.enabled=1").fetchone()[0]
        self.assertEqual(c["files"], n_idx)
        # the report the task asks for: currently served files the policy would refuse
        print("\n[file policy preview on the live index] counts=%s" % json.dumps(c))
        print("  by reason: %s" % json.dumps({k: v["count"] for k, v in p["by_reason"].items()}))
        print("  by ext: %s" % json.dumps({k: v["count"] for k, v in sorted(p["by_ext"].items(),
                                                                          key=lambda kv: -kv[1]["count"])}))
        for s in p["samples"][:60]:
            print("  %-9s mount %s  %s" % (s["reason"], s["mount"], s["path"]))
        with media_cfg(enabled=False):
            self.assertFalse(media_rules.file_policy_preview(self.db)["enabled"])

    def test_write_media_config_schema(self):
        mounts = rules.load(self.db)["mounts"]
        target = os.path.join(self.dir, "media", "media.json")
        with media_cfg(negotiation="redirect", admin_token="synthetic-admin-token"):
            path = media_rules.write_media_config(mounts, self.db, path=target)
            listen = core.CFG["media"]["listen"]
        self.assertEqual(path, target)
        with open(target, encoding="utf-8") as f:
            conf = json.load(f)
        for k in ("listen", "db", "cache_root", "event_log", "negotiation", "cutover", "mounts"):
            self.assertIn(k, conf)
        for k in ("sign_secret", "admin_token"):                    # secrets stay in data/.env
            self.assertNotIn(k, conf)
        for k in set(core.DEFAULTS["media"]) - {"admin_token"}:     # every tunable travels along
            self.assertIn(k, conf)
        self.assertEqual(conf["listen"], listen)
        self.assertEqual(conf["negotiation"], "redirect")
        self.assertTrue(os.path.isabs(conf["db"]))
        files = [m for m in mounts if m["kind"] == "files" and m["enabled"]]
        self.assertEqual(sorted(conf["mounts"]), sorted(str(m["id"]) for m in files))
        for m in files:
            mc = conf["mounts"][str(m["id"])]
            self.assertEqual(set(mc), {"path", "prefix", "hosts", "cache", "edge_cache", "transforms"})
            self.assertEqual((mc["path"], mc["prefix"], mc["hosts"]), (m["path"], m["prefix"], m["hosts"]))
        # media/config.py reads it back (deep merge over its defaults, absolute paths, str mount ids)
        loaded = mconfig.load(target)
        self.assertEqual(loaded["listen"], listen)
        self.assertEqual(loaded["mounts"].keys(), conf["mounts"].keys())
        # unchanged content is not rewritten; no temp files are left behind
        before = os.stat(target).st_mtime_ns
        time.sleep(0.05)
        with media_cfg(negotiation="redirect", admin_token="synthetic-admin-token"):
            media_rules.write_media_config(mounts, self.db, path=target)
        self.assertEqual(os.stat(target).st_mtime_ns, before)
        self.assertEqual(os.listdir(os.path.dirname(target)), ["media.json"])

    def test_apply_hooks_present(self):
        import inspect
        src = inspect.getsource(rules.apply)
        self.assertIn('media("config", core.mounts(), db)', src)
        self.assertLess(src.index("write_transform_config"), src.index('media("config"'))
        self.assertLess(src.index('media("config"'), src.index('caddy("reload"'))


# ---------------------------------------------------------------- live proof: private Caddy + stub upstreams

SEEN = []          # (port, path, {header: value}) of every stub request
GATE_SIG = "good"


class Stub(http.server.BaseHTTPRequestHandler):
    """Answers like media.py (MEDIA_PORT) or Strata Transform (TF_PORT); the behaviour is the last '-part' of the
    file name: a-accel.png -> accel, x-orig.png -> orig, r-redir.png -> 302 ..."""
    accel = "/img/ab/x.avif"

    def log_message(self, *a):
        pass

    def answer(self, status, headers, body=b""):
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        port = self.server.server_address[1]
        h = {k.lower(): v for k, v in self.headers.items()}
        SEEN.append((port, self.path, h))
        u = urllib.parse.urlsplit(self.path)
        if port == TF_PORT:
            if u.path == "/_gate":
                q = urllib.parse.parse_qs(urllib.parse.urlsplit(h.get("x-forwarded-uri", "")).query)
                ok = q.get("sig") == [GATE_SIG]
                return self.answer(200 if ok else 403, {"Content-Type": "text/plain"}, b"" if ok else b"bad signature")
            if "ver=" in u.query:
                return self.answer(200, {"Content-Type": "text/plain", "X-Stub": "transform"}, b"VERSION")
            return self.answer(404, {"Content-Type": "text/plain"}, b"nope")
        if u.path == "/_scan":
            name = urllib.parse.urlsplit(h.get("x-forwarded-uri", "")).path.rsplit("/", 1)[-1]
            if "held" in name:
                return self.answer(403, {"Cache-Control": "no-store", "Content-Type": "text/plain"},
                                   b"This file is being held for review.")
            if "pending" in name:
                return self.answer(503, {"Cache-Control": "no-store", "Retry-After": "30", "Content-Type": "text/plain"},
                                   b"pending")
            return self.answer(200, {"X-Strata-Lane": "throttle"} if name.startswith("big") else {})
        if h.get("x-strata-throttle") == "1":
            return self.answer(200, {"Content-Type": "application/octet-stream", "X-Stub": "lane",
                                     "Cache-Control": h.get("x-strata-cache", "")}, b"LANE-STREAM")
        if h.get("x-strata-negotiate") == "1":
            return self.answer(302, {"Location": u.path + "?_v=avif", "Cache-Control": "private, no-store",
                                     "Vary": "Accept"})
        kind = u.path.rsplit("/", 1)[-1].split(".")[0].rsplit("-", 1)[-1]
        cc, edge = h.get("x-strata-cache", ""), h.get("x-strata-edge-cache", "")
        stem = u.path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
        accel = {"X-Strata-Accel": self.accel, "X-Strata-Cache-Control": cc, "X-Strata-Media": "miss",
                 "X-Strata-Disposition": "inline; filename*=UTF-8''%s.avif" % stem}
        if kind == "accel":
            return self.answer(200, dict(accel, **{"X-Strata-CDN-Cache-Control": edge}))
        if kind == "nocdn":        # absent CDN + disposition headers
            return self.answer(200, {k: v for k, v in accel.items() if k != "X-Strata-Disposition"})
        if kind == "emptycdn":     # present but empty
            return self.answer(200, dict(accel, **{"X-Strata-CDN-Cache-Control": "", "X-Strata-Disposition": ""}))
        if kind == "nocc":         # no Cache-Control / X-Strata-Media at all -> drive fallback
            return self.answer(200, {"X-Strata-Accel": self.accel})
        if kind == "orig":
            return self.answer(200, {"X-Strata-Orig": "1", "X-Strata-Cache-Control": cc, "X-Strata-CDN-Cache-Control": edge,
                                     "X-Strata-Media": "orig;reason=not_beneficial"})
        if kind == "short":        # bypass/deferred: browser value + short CDN TTL (Browser Cache TTL caveat)
            return self.answer(200, {"X-Strata-Orig": "1", "X-Strata-Cache-Control": cc,
                                     "X-Strata-CDN-Cache-Control": "public, max-age=60", "X-Strata-Media": "deferred"})
        if kind == "redir":
            return self.answer(302, {"Location": u.path + "?_v=orig", "Cache-Control": "private, no-store"})
        if kind == "held":
            return self.answer(403, {"Cache-Control": "no-store", "Content-Type": "text/plain"},
                               b"This file is being held for review.")
        if kind == "pending":
            return self.answer(503, {"Cache-Control": "no-store", "Retry-After": "30", "Content-Type": "text/plain"},
                               b"pending")
        return self.answer(404, {"Content-Type": "text/plain"}, b"missing")


def port_free(port):
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


INTERNAL_RESPONSE = ("x-strata-accel", "x-strata-orig", "x-strata-cache-control", "x-strata-cdn-cache-control",
                     "x-strata-disposition")


class TestLiveProof(unittest.TestCase):
    proc = None

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(CADDY):
            raise unittest.SkipTest("caddy.exe not found")
        busy = [p for p in (SITE_PORT, HTTP_PORT, HTTPS_PORT, MEDIA_PORT, TF_PORT) if not port_free(p)]
        if busy:
            raise unittest.SkipTest("test ports busy: %s" % busy)
        from PIL import Image, features
        cls.dir = os.path.join(TMP, "live")
        cls.mount = root = os.path.join(cls.dir, "mount")
        cls.cache_root = os.path.join(cls.dir, "cache-root")
        fmt = "avif" if features.check("avif") else "webp"
        cls.ctype = "image/" + fmt
        cls.variant = os.path.join(cls.cache_root, "cache", "img", "ab", "0123456789abcdef." + fmt)
        os.makedirs(os.path.dirname(cls.variant))
        Image.new("RGB", (96, 64), (200, 40, 90)).save(cls.variant, fmt.upper())
        Stub.accel = "/img/ab/0123456789abcdef." + fmt

        def put(rel, data):
            p = os.path.join(root, *rel.split("/"))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(data if isinstance(data, bytes) else data.encode())
            return p
        put("index.html", "INDEX")
        put("404/404.html", "NOTFOUND-PAGE")
        put("404/403.html", "FORBIDDEN-PAGE")
        for name in ("a-orig.png", "x-short.png", "n.png"):
            Image.new("RGB", (40, 30), (10, 120, 200)).save(os.path.join(root, name), "PNG")
        put("cfg/app.env", "SYNTHETIC_SETTING=1\n")
        put("secrets.txt", "synthetic\n")
        put("tool.exe", b"MZ-synthetic-not-a-program")
        put("tools/ok.exe", b"MZ-synthetic-not-a-program")
        put("data.xyz", "xyz")
        put("noext", "noext")
        put("LICENSE", "MIT-ish synthetic licence")
        put("notes.txt", "NOTES")
        put("logo.svg", '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>')
        put("big.zip", os.urandom(1 << 20))
        put("lyla/audio/x.mp3", b"ID3-synthetic")
        with open(os.path.join(root, "a-orig.png"), "rb") as f:
            cls.orig_bytes = f.read()
        with open(cls.variant, "rb") as f:
            cls.variant_bytes = f.read()

        cls.db_path = os.path.join(cls.dir, "strata.db")
        db = copy_db(cls.db_path)
        cls.password = secrets.token_urlsafe(12)       # synthetic, lives only in memory; the temp DB has its hash
        add_test_mount(db, root, logfile("live"), pw_hash=rules.bcrypt_hash(cls.password))
        db.execute("DELETE FROM meta WHERE k='media_negotiation_effective'")
        db.commit()
        cls.db = db
        cls.cfg = dict(listen="127.0.0.1:%d" % MEDIA_PORT, transform_listen="127.0.0.1:%d" % TF_PORT,
                       cache_root=cls.cache_root.replace("\\", "/"))
        with media_cfg(negotiation="redirect", **cls.cfg):
            text = rules.render(db)
        cls.site = os.path.join(cls.dir, "cdn.caddy")
        with open(cls.site, "w", encoding="utf-8") as f:
            f.write(text)
        cls.main = os.path.join(cls.dir, "Caddyfile")
        with open(cls.main, "w", encoding="utf-8") as f:
            f.write(caddyfile(cls.site, os.path.join(cls.dir, "storage")))

        cls.stubs = []
        for port in (MEDIA_PORT, TF_PORT):
            s = http.server.ThreadingHTTPServer(("127.0.0.1", port), Stub)
            s.daemon_threads = True
            threading.Thread(target=s.serve_forever, daemon=True).start()
            cls.stubs.append(s)
        cls.addClassCleanup(cls.stop)
        cls.err = os.path.join(cls.dir, "caddy.err")
        cls.proc = subprocess.Popen([CADDY, "run", "--config", cls.main, "--adapter", "caddyfile"],
                                    stdout=subprocess.DEVNULL, stderr=open(cls.err, "w"),
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        deadline = time.time() + 20
        while True:
            try:
                cls.get("/")
                break
            except OSError:
                if cls.proc.poll() is not None or time.time() > deadline:
                    raise RuntimeError("private caddy did not start:\n" + open(cls.err).read()[-2000:])
                time.sleep(0.2)

    @classmethod
    def stop(cls):
        if cls.proc is not None and cls.proc.poll() is None:   # only the process this test started
            cls.proc.terminate()
            cls.proc.wait(15)
        for s in getattr(cls, "stubs", []):
            s.shutdown()
            s.server_close()
        if getattr(cls, "db", None) is not None:
            cls.db.close()

    @staticmethod
    def get(path, headers=None, method="GET"):
        c = http.client.HTTPConnection("127.0.0.1", SITE_PORT, timeout=15)
        try:
            h = {"Host": "localhost"}
            h.update(headers or {})
            c.request(method, path, headers=h)
            r = c.getresponse()
            body = r.read()
            raw = r.getheaders()
            return r.status, {k.lower(): v for k, v in raw}, body, raw
        finally:
            c.close()

    def seen(self, port, needle):
        return [x for x in SEEN if x[0] == port and needle in x[1]]

    def assertClean(self, raw, handled=True):
        """No placeholder text, no empty values, no duplicate header lines, no internal answer headers."""
        names = [k.lower() for k, _ in raw]
        for k, v in raw:
            self.assertNotIn("{", v, "placeholder leak %s: %s" % (k, v))
            if k.lower() in ("cache-control", "cloudflare-cdn-cache-control", "content-disposition", "x-strata-media"):
                self.assertTrue(v.strip(), "empty %s" % k)
        for k in ("cache-control", "cloudflare-cdn-cache-control", "content-disposition", "content-type"):
            self.assertLessEqual(names.count(k), 1, "duplicate %s" % k)
        if handled:
            for k in INTERNAL_RESPONSE + ("cdn-cache-control",):
                self.assertNotIn(k, names)

    # -- variants: accel / orig / pass-through

    def test_accel_serves_cache_file(self):
        st, h, body, raw = self.get("/a-accel.png?_v=avif")
        self.assertEqual(st, 200)
        self.assertEqual(body, self.variant_bytes)
        self.assertEqual(h["content-type"], self.ctype)
        self.assertEqual(h["cache-control"], "public, no-cache")
        self.assertEqual(h["cloudflare-cdn-cache-control"], "public, max-age=31536000")
        self.assertEqual(h["content-disposition"], "inline; filename*=UTF-8''a-accel.avif")
        self.assertEqual(h["x-strata-media"], "miss")
        self.assertIn("etag", h)
        self.assertClean(raw)
        up = self.seen(MEDIA_PORT, "/a-accel.png?_v=avif")[-1][2]
        self.assertEqual((up["x-strata-mount"], up["x-strata-cache"], up["x-strata-edge-cache"]),
                         (str(MID), "public, no-cache", "public, max-age=31536000"))
        st, h, body, raw = self.get("/a-accel.png?_v=avif", {"Range": "bytes=0-9"})
        self.assertEqual(st, 206)
        self.assertEqual(body, self.variant_bytes[:10])
        self.assertEqual(h["content-range"], "bytes 0-9/%d" % len(self.variant_bytes))
        st, h, body, raw = self.get("/a-accel.png?w=20&fm=webp")   # explicit transforms go to media too
        self.assertEqual(st, 200)
        self.assertTrue(self.seen(MEDIA_PORT, "/a-accel.png?w=20&fm=webp"))

    def test_orig_serves_original(self):
        st, h, body, raw = self.get("/a-orig.png?_v=avif")
        self.assertEqual(st, 200)
        self.assertEqual(body, self.orig_bytes)
        self.assertEqual(h["content-type"], "image/png")
        self.assertEqual(h["cache-control"], "public, no-cache")
        self.assertEqual(h["cloudflare-cdn-cache-control"], "public, max-age=31536000")
        self.assertEqual(h["x-strata-media"], "orig;reason=not_beneficial")
        self.assertNotIn("content-disposition", h)
        self.assertClean(raw)
        st, h, body, raw = self.get("/x-short.png?_v=webp")
        self.assertEqual((st, h["cache-control"], h["cloudflare-cdn-cache-control"], h["x-strata-media"]),
                         (200, "public, no-cache", "public, max-age=60", "deferred"))
        st, h, body, raw = self.get("/a-orig.png?_v=orig")        # not matched by @mv: gate + drive
        self.assertEqual((st, body), (200, self.orig_bytes))
        self.assertFalse(self.seen(MEDIA_PORT, "/a-orig.png?_v=orig"))
        self.assertTrue([x for x in self.seen(MEDIA_PORT, "/_scan") if x[2].get("x-forwarded-uri") == "/a-orig.png?_v=orig"])

    def test_pass_through_answers(self):
        st, h, body, raw = self.get("/r-redir.png?_v=webm")
        self.assertEqual((st, h["location"], h["cache-control"]), (302, "/r-redir.png?_v=orig", "private, no-store"))
        self.assertNotIn("cloudflare-cdn-cache-control", h)
        self.assertEqual(h["cdn-cache-control"], "no-store")
        self.assertClean(raw, handled=False)
        st, h, body, raw = self.get("/h-held.png?_v=avif")
        self.assertEqual((st, h["cache-control"], body), (403, "no-store", b"This file is being held for review."))
        self.assertNotIn("cloudflare-cdn-cache-control", h)
        st, h, body, raw = self.get("/p-pending.png?_v=avif")
        self.assertEqual((st, h["cache-control"], h["retry-after"]), (503, "no-store", "30"))
        self.assertNotIn("cloudflare-cdn-cache-control", h)
        st, h, body, raw = self.get("/m-missing.png?_v=avif")       # media 404 -> the site's 404 page
        self.assertEqual((st, body, h["cache-control"]), (404, b"NOTFOUND-PAGE", "no-store"))
        self.assertNotIn("cloudflare-cdn-cache-control", h)

    def test_redirect_negotiation(self):
        st, h, body, raw = self.get("/n.png", {"Accept": "image/avif,image/webp,*/*"})
        self.assertEqual((st, h["location"], h["cache-control"], h["vary"]),
                         (302, "/n.png?_v=avif", "private, no-store", "Accept"))
        self.assertNotIn("cloudflare-cdn-cache-control", h)
        up = self.seen(MEDIA_PORT, "/n.png")[-1][2]
        self.assertEqual(up.get("x-strata-negotiate"), "1")
        # ?ver= stays on Strata Transform
        st, h, body, raw = self.get("/n.png?ver=2")
        self.assertEqual((st, body), (200, b"VERSION"))
        self.assertTrue(self.seen(TF_PORT, "/n.png?ver=2"))
        self.assertFalse(self.seen(MEDIA_PORT, "/n.png?ver=2"))

    def test_empty_placeholders_never_leak(self):
        for path in ("/e-nocdn.png?_v=avif", "/e-emptycdn.png?_v=avif"):
            st, h, body, raw = self.get(path)
            self.assertEqual((st, body, h["cache-control"], h["x-strata-media"]),
                             (200, self.variant_bytes, "public, no-cache", "miss"), path)
            self.assertNotIn("cloudflare-cdn-cache-control", h)
            self.assertNotIn("content-disposition", h)
            self.assertClean(raw)
        st, h, body, raw = self.get("/e-nocc.png?_v=avif")          # no Cache-Control from media: drive fallback
        self.assertEqual((st, h["cache-control"]), (200, "public, no-cache"))
        self.assertNotIn("x-strata-media", h)
        self.assertClean(raw)

    # -- file policy

    def test_file_policy(self):
        for path, want, page in (("/cfg/app.env", 404, b"NOTFOUND-PAGE"), ("/.env", 404, b"NOTFOUND-PAGE"),
                                 ("/secrets.txt", 404, None), ("/cfg/app.env.", 404, None),
                                 ("/cfg/app.env%20", 404, None), ("/CREDEN~1.TXT", 404, None),
                                 ("/sub%5Cx.png", 404, None), ("/a-orig.png::$DATA", 404, None),
                                 ("/lyla/audio/x.mp3", 403, None), ("/lyla./audio/x.mp3", 404, None),
                                 ("/lyla%5Caudio/x.mp3", 404, None),
                                 ("/tool.exe", 403, b"FORBIDDEN-PAGE"), ("/data.xyz", 403, None), ("/noext", 403, None),
                                 ("/tool.exe?_v=avif", 403, None), ("/cfg/app.env?dl=1", 404, None)):
            st, h, body, raw = self.get(path)
            self.assertEqual(st, want, path)
            self.assertEqual(h.get("cache-control"), "no-store", path)
            self.assertNotIn("cloudflare-cdn-cache-control", h)
            if page:
                self.assertEqual(body, page, path)
        for path, body in (("/LICENSE", b"MIT-ish synthetic licence"), ("/", b"INDEX"), ("/notes.txt", b"NOTES"),
                           ("/tools/ok.exe", b"MZ-synthetic-not-a-program")):
            st, h, got, raw = self.get(path)
            self.assertEqual((st, got), (200, body), path)
        st, h, body, raw = self.get("/logo.svg")
        self.assertEqual(st, 200)
        self.assertEqual(h["content-security-policy"], media_rules.SVG_CSP)
        # allowed executables still pass the gate (category exec)
        self.assertTrue([x for x in self.seen(MEDIA_PORT, "/_scan") if x[2].get("x-forwarded-uri") == "/tools/ok.exe"
                         and x[2].get("x-strata-mount") == str(MID)])

    # -- gate + lane + injected internal headers

    def test_gate_and_lane(self):
        st, h, body, raw = self.get("/doc-held.pdf")
        self.assertEqual((st, h["cache-control"], body), (403, "no-store", b"This file is being held for review."))
        self.assertEqual(h["cdn-cache-control"], "no-store")
        st, h, body, raw = self.get("/doc-pending.pdf")
        self.assertEqual((st, h["retry-after"]), (503, "30"))
        st, h, body, raw = self.get("/big.zip")                     # gate sets the lane -> throttled streamer
        self.assertEqual((st, body, h.get("x-stub")), (200, b"LANE-STREAM", "lane"))
        up = self.seen(MEDIA_PORT, "/big.zip")[-1][2]
        self.assertEqual((up.get("x-strata-throttle"), up.get("x-strata-mount"), up.get("x-strata-cache")),
                         ("1", str(MID), "public, no-cache"))

    def test_injected_internal_headers_are_stripped(self):
        evil = {"X-Strata-Lane": "throttle", "X-Strata-Throttle": "1", "X-Strata-Negotiate": "1",
                "X-Strata-Mount": "1", "X-Strata-Cache": "evil", "X-Strata-Edge-Cache": "evil",
                "X-Strata-Admin-Token": "guess"}
        n = len(SEEN)
        st, h, body, raw = self.get("/notes.txt", evil)             # gated, small: no lane
        self.assertEqual((st, body), (200, b"NOTES"))
        self.assertNotIn("x-stub", h)
        scans = [x for x in SEEN[n:] if x[1] == "/_scan"]
        self.assertTrue(scans)
        for _, _, hh in scans:
            for k in ("x-strata-lane", "x-strata-throttle", "x-strata-negotiate", "x-strata-cache",
                      "x-strata-edge-cache", "x-strata-admin-token"):
                self.assertNotIn(k, hh)
            self.assertEqual(hh["x-strata-mount"], str(MID))
        n = len(SEEN)
        st, h, body, raw = self.get("/i-accel.png?_v=avif", evil)   # would be LANE-STREAM / 302 if not stripped
        self.assertEqual((st, body), (200, self.variant_bytes))
        up = [x for x in SEEN[n:] if x[1].startswith("/i-accel.png")][-1][2]
        self.assertEqual((up["x-strata-mount"], up["x-strata-cache"], up["x-strata-edge-cache"]),
                         (str(MID), "public, no-cache", "public, max-age=31536000"))
        for k in ("x-strata-lane", "x-strata-throttle", "x-strata-negotiate", "x-strata-admin-token"):
            self.assertNotIn(k, up)

    # -- access rules still win

    def test_password_rule_still_challenges_variants(self):
        st, h, body, raw = self.get("/private/p-accel.png?_v=avif")
        self.assertEqual(st, 401)
        self.assertIn("www-authenticate", h)
        self.assertFalse(self.seen(MEDIA_PORT, "/private/p-accel.png"))
        auth = "Basic " + base64.b64encode(("tester:" + self.password).encode()).decode()
        st, h, body, raw = self.get("/private/p-accel.png?_v=avif", {"Authorization": auth})
        self.assertEqual((st, body), (200, self.variant_bytes))
        # deferred private-action headers win over what handle_response set from media's answer
        self.assertEqual(h["cache-control"], "private, no-store")
        self.assertNotIn("cloudflare-cdn-cache-control", h)
        self.assertEqual(self.seen(MEDIA_PORT, "/private/p-accel.png")[-1][2]["x-strata-edge-cache"],
                         "public, max-age=31536000")                # media did ask for the edge TTL

    def test_signed_rule_still_requires_gate(self):
        st, h, body, raw = self.get("/signed/s-accel.png?_v=avif")
        self.assertEqual((st, body), (403, b"bad signature"))
        self.assertFalse(self.seen(MEDIA_PORT, "/signed/s-accel.png"))
        self.assertTrue(self.seen(TF_PORT, "/_gate"))
        st, h, body, raw = self.get("/signed/s-accel.png?_v=avif&exp=1&sig=" + GATE_SIG)
        self.assertEqual((st, body), (200, self.variant_bytes))
        self.assertEqual(h["cache-control"], "private, no-store")
        self.assertNotIn("cloudflare-cdn-cache-control", h)

    def test_cache_rule_cannot_make_redirect_edge_cacheable(self):
        st, h, body, raw = self.get("/cached/c.png")                 # redirect mode: @neg -> 302
        self.assertEqual(st, 302)
        self.assertEqual(h["cache-control"], "public, max-age=86400")   # the rule's deferred header wins ...
        self.assertEqual(h["cdn-cache-control"], "no-store")             # ... but Cloudflare still never caches it
        self.assertNotIn("cloudflare-cdn-cache-control", h)

    # -- edge mode (reload of the private instance only)

    def test_zz_edge_mode_reload(self):
        core.set_meta(self.db, "media_negotiation_effective", "edge")
        self.db.commit()
        with media_cfg(negotiation="auto", **self.cfg):
            text = rules.render(self.db)
        self.assertIn('{query.w} != ""', text[text.index("@neg"):])   # edge mode: @neg only for ?w=
        with open(self.site, "w", encoding="utf-8") as f:
            f.write(text)
        r = subprocess.run([CADDY, "reload", "--config", self.main, "--adapter", "caddyfile", "--address", ADMIN],
                           capture_output=True, text=True, timeout=60,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.assertEqual(r.returncode, 0, r.stderr[-800:])
        n = len(SEEN)
        st, h, body, raw = self.get("/n.png", {"Accept": "image/avif,*/*"})
        self.assertEqual(st, 200)                                   # edge rewrites at Cloudflare; origin serves it
        self.assertEqual((h["content-type"], h["cache-control"], h["cloudflare-cdn-cache-control"]),
                         ("image/png", "public, no-cache", "public, max-age=31536000"))
        self.assertIn("Accept", h.get("vary", ""))                  # Cloudflare negotiated this URL by Accept
        self.assertEqual([x[1] for x in SEEN[n:]], ["/_scan"])      # only the gate asked media


if __name__ == "__main__":
    unittest.main()
