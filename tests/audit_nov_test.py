"""Regressions for the November 2026 audit (continuation of the Gemini-started review).

Each test names the finding it guards (changelog, 0.5.0 Security). Runs on its own or through run_all.py;
everything lives in a throwaway home.
"""
import io
import lzma
import os
import pathlib
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

HOME = tempfile.TemporaryDirectory(prefix="strata-audit-nov-")
os.environ["STRATA_HOME"] = HOME.name
CODE = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(CODE), str(CODE / "vendor"), str(CODE / "transform")]
import accounts  # noqa: E402
import alerts  # noqa: E402
import analyze  # noqa: E402
import auth  # noqa: E402
import compress  # noqa: E402
import core  # noqa: E402
import files  # noqa: E402
import network  # noqa: E402
import rules  # noqa: E402
import strata  # noqa: E402
import cards  # noqa: E402  (transform/ is on the path, like transform.py itself sees it)

core.init_db()


class CaddyPlaceholderTests(unittest.TestCase):
    """N-02: Caddy expands {file.*} / {env.*} in respond bodies and header values at request time."""

    def test_bq_text_escapes_every_brace(self):
        self.assertEqual(rules.bq_text("a {file./etc/passwd} b"), "`a \\{file./etc/passwd\\} b`")
        self.assertEqual(rules.bq_text("{env.X}"), "`\\{env.X\\}`")

    def test_unknown_host_refuses_braces(self):
        def run(user, reason, fn, preview=False):
            db = core.connect()
            try:
                with db:
                    return fn(db)
            finally:
                db.close()
        with mock.patch.object(rules, "mutate", side_effect=run):
            for v in ("{file.C:/strata/data/.env}", "x {env.CF_API_TOKEN}", "}"):
                with self.subTest(v=v), self.assertRaises(rules.ServeError):
                    rules.save_site("admin", {"unknown_host": v})
            self.assertEqual(rules.save_site("admin", {"unknown_host": "Nothing here"})["unknown_host"], "Nothing here")

    def test_stored_placeholder_is_rendered_inert(self):
        db = core.connect()
        try:
            with db:
                s = rules.site(db)
                s["unknown_host"] = "{file.C:/strata/data/.env}"  # e.g. saved before the check existed
                core.set_meta(db, "site", s)
            text = rules.render(db)
        finally:
            db.close()
        self.assertIn("respond `\\{file.C:/strata/data/.env\\}` 404", text)
        self.assertNotIn("respond `{file.", text)


class ErrorTemplateTests(unittest.TestCase):
    """N-06 / O-02: error pages are files on a drive and never Caddy templates (whoever writes the folder would get
    Caddy's file and environment functions); the reason, version and Ray ID reach the page in Server-Timing."""

    def render_with(self, page):
        root = tempfile.mkdtemp(dir=HOME.name)
        db = core.connect()
        try:
            with db:
                mid = db.execute("INSERT INTO mount(name,kind,path,prefix,hosts,cache,edge_cache,precompress,browse,"
                                 "transforms,enabled,note,sort) VALUES('E','files',?,'/','[\"e.example\"]','no-store',"
                                 "'',0,0,0,1,'',0)", [root.replace("\\", "/")]).lastrowid
                s = rules.site(db)
                s.update(error_mount=mid, error_assets="/_errors", error_page=page)
                core.set_meta(db, "site", s)
            return rules.render(db)
        finally:
            with db:
                db.execute("DELETE FROM mount WHERE id=?", [mid])
            db.close()

    def test_fallback_outside_assets_is_not_a_template(self):
        self.assertNotRegex(self.render_with("/_errors/404/index.html /uploads/404.html"), r"(?m)^\s*templates\b")

    def test_pages_inside_assets_are_not_templates_either(self):
        text = self.render_with("/_errors/404/index.html /_errors/legacy/404.html")
        self.assertNotRegex(text, r"(?m)^\s*templates\b")
        self.assertIn('header Server-Timing `corium;desc="%s", reason;desc="{http.vars.strata_reason}", '
                      'ray;desc="{http.request.header.Cf-Ray}"`' % core.VERSION, text)


class StockErrorPagesTests(unittest.TestCase):
    """The default error pages install into a drive folder without overwriting anything, and contain no templates."""

    def setUp(self):
        self.root = tempfile.mkdtemp(dir=HOME.name)
        db = core.connect()
        with db:
            self.mid = db.execute("INSERT INTO mount(name,kind,path,prefix,hosts,cache,edge_cache,precompress,browse,"
                                  "transforms,enabled,note,sort) VALUES('S','files',?,'/','[\"s.example\"]','',"
                                  "'',0,0,0,1,'',0)", [self.root.replace("\\", "/")]).lastrowid
        db.close()
        core.mounts(refresh=True)  # the drive list is cached

    def tearDown(self):
        db = core.connect()
        with db:
            db.execute("DELETE FROM mount WHERE id=?", [self.mid])
        db.close()
        core.mounts(refresh=True)

    def test_install_copies_rewrites_and_keeps_edits(self):
        mine = os.path.join(self.root, "errs", "not-found", "info.md")
        os.makedirs(os.path.dirname(mine))
        with open(mine, "w") as f:
            f.write("my text")
        r = rules.install_error_pages(self.mid, "/errs/")
        self.assertEqual(r["folder"], "/errs")
        self.assertEqual(r["pages"]["404"], "/errs/not-found/index.html")
        self.assertNotIn("not-found/info.md", r["created"])
        self.assertIn("_shared/page.js", r["created"])
        self.assertIn("_shared/img/kcat_1.webp", r["created"])
        with open(mine) as f:
            self.assertEqual(f.read(), "my text")
        with open(os.path.join(self.root, "errs", "forbidden", "index.html")) as f:
            page = f.read()
        self.assertIn('<base href="/errs/forbidden/">', page)
        self.assertEqual(rules.install_error_pages(self.mid, "/errs")["created"], [])  # a second run adds nothing

    def test_bad_folders_are_refused(self):
        for folder in ("/", "/../x", "/a b", "/.strata-trash"):
            with self.assertRaises((rules.ServeError, files.FileError)):
                rules.install_error_pages(self.mid, folder)

    def test_stock_pages_hold_no_template_actions(self):
        for dirpath, _dirs, names in os.walk(rules.STOCK_ERRORS):
            for name in names:
                if name.endswith((".html", ".md")):
                    with open(os.path.join(dirpath, name), encoding="utf-8") as f:
                        self.assertNotIn("{{", f.read(), name)


class TunnelIngressTests(unittest.TestCase):
    """N-03: a tunnel route skips Caddy and every Corium rule; non-owners may not publish internal ports."""

    def as_role(self, role):
        return mock.patch.object(accounts, "get", return_value={"user": "x", "role": role, "enabled": 1})

    def test_admin_cannot_route_to_reserved_or_raw_services(self):
        with self.as_role("admin"):
            for svc in ("http://127.0.0.1:2019", "http://localhost:8090", "http://169.254.169.254:80",
                        "https://8.8.8.8:443", "tcp://127.0.0.1:22", "rdp://localhost:3389", "ssh://localhost:22",
                        "unix:/run/docker.sock", "http://internal.example:8080"):
                with self.subTest(svc=svc), self.assertRaises(network.NetError):
                    network.check_ingress_service("x", svc)

    def test_admin_may_route_lan_services_and_own_caddy(self):
        with self.as_role("admin"):
            self.assertEqual(network.check_ingress_service("x", network.cdn_service()), network.cdn_service())
            self.assertEqual(network.check_ingress_service("x", "http_status:404"), "http_status:404")
            self.assertEqual(network.check_ingress_service("x", "http://192.168.1.20:3000"), "http://192.168.1.20:3000")

    def test_cors_password_is_not_owner(self):
        with self.assertRaises(network.NetError):
            network.check_ingress_service("api:cors", "http://127.0.0.1:2019")

    def test_owner_keeps_full_control(self):
        with self.as_role("root"):
            self.assertEqual(network.check_ingress_service("x", "tcp://127.0.0.1:22"), "tcp://127.0.0.1:22")


class CorsPrincipalTests(unittest.TestCase):
    """N-01: the CORS password ("api:cors") never holds root-only capabilities, also not through accounts.has()."""

    def test_cors_lacks_root_only(self):
        for cap in accounts.ROOT_ONLY:
            self.assertFalse(accounts.has("api:cors", cap), cap)
        self.assertTrue(accounts.has("api:cors", "serving.drives"))
        self.assertTrue(accounts.has("api:somekey", "code.write"))  # a generated API key is the owner's own

    def test_cors_cannot_mount_outside_storage(self):
        outside = tempfile.mkdtemp(dir=HOME.name)
        with mock.patch.object(core, "file_mounts", return_value=[]), \
                mock.patch.dict(core.CFG, {"storage_paths": [tempfile.mkdtemp(dir=HOME.name)]}), \
                mock.patch.object(rules, "mutate", return_value={"diff": "ok"}), self.assertRaises(files.FileError):
            rules.save_mount("api:cors", {"name": "code", "kind": "files", "path": outside, "prefix": "/x",
                                          "hosts": ["c.example"]})


class LoginLimiterTests(unittest.TestCase):
    """N-04: a successful sign-in does not clear the address's failure count; N-05: 5 wrong codes end a 2FA step."""

    def test_success_keeps_failures(self):
        lim = auth.Limiter(limit=8, window=900)
        for _ in range(7):
            lim.fail("203.0.113.9")
        h = strata.Handler.__new__(strata.Handler)
        h.cookie = lambda *a, **k: ("c", a)
        h.redirect = lambda dest, cookies=(): dest
        sess = mock.Mock()
        sess.create.return_value = "tok"
        with mock.patch.object(strata.App, "limiter", lim), mock.patch.object(strata.App, "sessions", sess), \
                mock.patch.object(strata.App, "alerts", mock.Mock()), mock.patch.object(core, "audit"), \
                mock.patch.object(accounts, "get", return_value={"user": "u", "privacy_version": accounts.PRIVACY_VERSION}):
            h.finish_login("203.0.113.9", "u", [])
        self.assertEqual(lim.recent("203.0.113.9"), 7)
        lim.fail("203.0.113.9")
        self.assertTrue(lim.blocked("203.0.113.9"))

    def test_pending_token_dies_after_five_wrong_codes(self):
        s = auth.Sessions(0.1)
        tok = s.create("u", "1.2.3.4", ttl=600, step="app")
        self.assertEqual([s.fail_attempt(tok) for _ in range(5)], [False, False, False, False, True])
        self.assertIsNone(s.get(tok))


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=HOME.name)
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name, "drive")
        self.root.mkdir()
        self.m = {"id": 1, "name": "N", "path": str(self.root), "kind": "files", "prefix": "/", "hosts": ["n.example"]}
        p = mock.patch.object(files, "get_mount", return_value=self.m)
        p.start()
        self.addCleanup(p.stop)

    def test_trash_metadata_is_not_restorable_or_deletable(self):
        """N-09: restore / permanent delete refuse the batch's own .manifest.json and .versions."""
        batch = "20261106-120000-abcd"
        bdir = self.root / files.TRASH / batch
        (bdir / ".versions").mkdir(parents=True)
        (bdir / ".manifest.json").write_text("{}")
        for rel in ("/.manifest.json", "/.versions"):
            with self.subTest(rel=rel), self.assertRaises(files.FileError):
                files.restore(1, batch, rel)
        with mock.patch.object(files, "sync_bin"):
            r = files.trash_delete(1, [{"batch": batch, "path": "/.manifest.json"}, {"batch": batch, "path": "/.versions"}])
        self.assertEqual(r["deleted"], 0)
        self.assertTrue((bdir / ".manifest.json").exists() and (bdir / ".versions").is_dir())
        self.assertFalse((self.root / ".manifest.json").exists())

    def test_permanently_deleted_folder_purges_its_prefix(self):
        """N-09b: a folder deleted from the trash reported "dir": False, so its URL prefix was never purged."""
        batch = "20261106-120001-abcd"
        (self.root / files.TRASH / batch / "album").mkdir(parents=True)
        (self.root / files.TRASH / batch / "album" / "a.jpg").write_bytes(b"x")
        with mock.patch.object(files, "sync_bin"), mock.patch.object(files, "purge_targets", side_effect=lambda m, t: t):
            r = files.trash_delete(1, [{"batch": batch, "path": "/album"}])
        self.assertEqual(r["purge"], [("/album", True)])


class CompressRootTests(unittest.TestCase):
    """N-10: a drive at a disk root (D:\\ or /) was never indexed: root + os.sep doubled the separator."""

    def test_rel_under(self):
        root = os.path.abspath(os.sep)  # C:\ on Windows, / elsewhere
        self.assertEqual(compress.rel_under(os.path.join(root, "a", "b.txt"), root), "/a/b.txt")
        self.assertEqual(compress.rel_under(root, root), "/")
        sub = os.path.join(root, "share")
        self.assertEqual(compress.rel_under(os.path.join(sub, "x.txt"), sub), "/x.txt")
        self.assertIsNone(compress.rel_under(os.path.join(root, "shared", "x.txt"), sub))

    def test_url_for_on_root_drive(self):
        root = os.path.abspath(os.sep)
        with mock.patch.object(compress, "mount_roots", return_value=[({"prefix": "/d"}, os.path.normpath(root))]):
            self.assertEqual(compress.url_for(os.path.join(root, "pics", "a.png")), "/d/pics/a.png")


class TarCardTests(unittest.TestCase):
    """N-07: the link-preview card of a compressed tarball stops after TAR_SCAN_BYTES of uncompressed stream."""

    def test_bomb_is_cut_short(self):
        path = os.path.join(HOME.name, "bomb.txz")
        size = 64 << 20
        with tarfile.open(path, "w:xz", preset=0) as t:
            info = tarfile.TarInfo("zeros.bin")
            info.size = size

            class Zeros(io.RawIOBase):
                left = size

                def readinto(self, b):
                    n = min(len(b), self.left)
                    b[:n] = bytes(n)
                    self.left -= n
                    return n
            t.addfile(info, Zeros())
            t.addfile(tarfile.TarInfo("after.txt"), io.BytesIO(b""))
        with mock.patch.object(cards, "TAR_SCAN_BYTES", 8 << 20):
            started = time.time()
            info = cards.archive_info(path, ".txz")
        self.assertLess(time.time() - started, 10)
        self.assertEqual(info["files"], 1)  # saw the first member, never decompressed past the cap
        self.assertEqual(cards.archive_info(path, ".txz")["files"], 2)  # under the real cap: complete

    def test_plain_and_gzip_tars_still_list(self):
        for ext, mode in ((".tar", "w"), (".tgz", "w:gz")):
            path = os.path.join(HOME.name, "ok" + ext)
            with tarfile.open(path, mode) as t:
                for n in ("a/1.txt", "a/2.txt"):
                    t.addfile(tarfile.TarInfo(n), io.BytesIO(b""))
            self.assertEqual(cards.archive_info(path, ext)["files"], 2, ext)


class AnalyzeTests(unittest.TestCase):
    """N-08: hot folders of one drive no longer include every other drive's (and service's) URL paths."""

    def test_hot_folders_filtered_to_drive_prefix(self):
        ms = [{"id": 2, "prefix": "/media"}]
        hits = {"/media/a/x.mp4": (3, 30, 1), "/private/b/y.pdf": (5, 50, 2), "/mediafake/c/z": (1, 1, 1)}
        with mock.patch.object(analyze, "mounts_for", return_value=ms), \
                mock.patch.object(analyze, "origin_hits", return_value=hits):
            rows = analyze.hot_folders({"mount": "2"})["rows"]
        self.assertEqual([r["path"] for r in rows], ["/media/a"])


class MailBudgetTests(unittest.TestCase):
    """N-11: sign-in codes have their own hourly budget; alerts can no longer use it up."""

    def test_codes_survive_a_full_alert_budget(self):
        a = alerts.Alerts(None, None, None)
        cfg = {"max_per_hour": 2, "smtp": {}, "from": "s@example.com", "provider": "smtp"}
        with mock.patch.dict(core.CFG, {"alerts": cfg}), mock.patch.object(alerts, "provider", return_value="smtp"), \
                mock.patch.object(alerts, "send_smtp") as smtp:
            a.send_to(["o@example.com"], "s", "t", "h")
            a.send_to(["o@example.com"], "s", "t", "h")
            with self.assertRaises(RuntimeError):
                a.send_to(["o@example.com"], "s", "t", "h")
            a.send_to(["u@example.com"], "code", "t", "h", kind="code")  # still delivered
        self.assertEqual(smtp.call_count, 3)


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2)
    finally:
        HOME.cleanup()
