"""Isolated regressions for the October 2026 security and reliability audit.

Runs on its own or through run_all.py; all files and the database live in a throwaway home.
"""
import concurrent.futures
import hashlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from email.message import Message
from unittest import mock

HOME = tempfile.TemporaryDirectory(prefix="strata-audit-")
os.environ["STRATA_HOME"] = HOME.name
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import accounts
import auth
import core
import files
import gate
import network
import rules
import setup
import strata
from transform import transform
from media import config as media_config

core.init_db()


class FramingTests(unittest.TestCase):
    def test_unsafe_lengths_and_ambiguous_framing(self):
        for value in ("-1", "+1", "1, 1", "bad", "1.0"):
            with self.subTest(value=value), self.assertRaises(files.FileError):
                files.read_into(io.BytesIO(b"secret"), {"Content-Length": value}, io.BytesIO(), 10)
        h = Message()
        h.add_header("Content-Length", "1")
        h.add_header("Content-Length", "1")
        with self.assertRaises(files.FileError):
            files.content_length(h)
        with self.assertRaises(files.FileError):
            files.content_length({"Content-Length": "1", "Transfer-Encoding": "chunked"}, allow_chunked=True)

    def test_chunked_upload_validation_and_limit(self):
        h = {"Transfer-Encoding": "chunked"}
        out = io.BytesIO()
        self.assertEqual(files.read_into(io.BytesIO(b"4\r\ndata\r\n0\r\n\r\n"), h, out, 4), 4)
        self.assertEqual(out.getvalue(), b"data")
        for raw in (b"-1\r\n", b"5\r\nhello\r\n0\r\n\r\n", b"1\r\naXX0\r\n\r\n", b"0\r\n", b"\r\n"):
            with self.subTest(raw=raw), self.assertRaises(files.FileError):
                files.read_into(io.BytesIO(raw), h, io.BytesIO(), 4)

    def test_json_requires_object(self):
        h = strata.Handler.__new__(strata.Handler)
        for raw in (b"[]", b"null", b'"hello"', b"1"):
            h.headers, h.rfile = {"Content-Length": str(len(raw))}, io.BytesIO(raw)
            with self.subTest(raw=raw), self.assertRaises(files.FileError):
                h.body_json()

    def test_gate_rejects_negative_length(self):
        h = gate.Handler.__new__(gate.Handler)
        h.headers, h.rfile = {"Content-Length": "-1"}, io.BytesIO(b"user=someone")
        self.assertIsNone(h.form())


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=HOME.name)
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name, "drive")
        self.root.mkdir()
        self.m = {"id": 1, "name": "Audit", "path": str(self.root), "kind": "files", "prefix": "/", "hosts": ["test.example"]}
        self.patch = mock.patch.object(files, "get_mount", return_value=self.m)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def link(self, name, target, directory=False):
        try:
            os.symlink(target, name, target_is_directory=directory)
        except OSError as e:
            if os.name == "nt" and directory:
                result = subprocess.run(["cmd", "/c", "mklink", "/J", str(name), str(target)], capture_output=True)
                if result.returncode == 0:
                    return
            self.skipTest("symlink creation unavailable: " + str(e))

    def test_public_transform_refuses_symlink_escape_and_hidden_alias(self):
        outside = pathlib.Path(self.temp.name, "outside")
        outside.mkdir()
        (outside / "secret.txt").write_text("secret")
        self.link(self.root / "outside", outside, True)
        self.assertEqual(transform.resolve(self.m, "/outside/secret.txt"), (None, None))
        self.assertEqual(media_config.resolve(self.m, "/outside/secret.txt"), (None, None))
        hidden = self.root / ".private"
        hidden.mkdir()
        (hidden / "secret.txt").write_text("secret")
        self.link(self.root / "alias", hidden, True)
        self.assertEqual(transform.resolve(self.m, "/alias/secret.txt"), (None, None))
        self.assertEqual(media_config.resolve(self.m, "/alias/secret.txt"), (None, None))
        self.assertIsNotNone(transform.resolve(self.m, "/")[0])

    def test_zip_does_not_export_nested_links(self):
        selected = self.root / "selected"
        selected.mkdir()
        (selected / "ok.txt").write_text("ok")
        secret = pathlib.Path(self.temp.name, "secret.txt")
        secret.write_text("secret")
        if os.name == "nt":
            self.link(selected / "leak", secret.parent, True)
        else:
            self.link(selected / "stolen.txt", secret)
        out = io.BytesIO()
        files.zip_write({"mount": 1, "items": [(str(selected), ["selected"])]}, out)
        with zipfile.ZipFile(out) as z:
            self.assertEqual(z.namelist(), ["selected/ok.txt"])

    def test_copy_does_not_export_nested_links(self):
        selected, dest = self.root / "selected", self.root / "dest"
        selected.mkdir()
        dest.mkdir()
        (selected / "ok.txt").write_text("ok")
        secret = pathlib.Path(self.temp.name, "secret.txt")
        secret.write_text("secret")
        if os.name == "nt":
            self.link(selected / "leak", secret.parent, True)
        else:
            self.link(selected / "stolen.txt", secret)
        result = files.copy_items("audit", 1, ["/selected"], 1, "/dest")
        job = files.JOBS[result["job"]]
        end = time.monotonic() + 10
        while job["status"] == "running" and time.monotonic() < end:
            time.sleep(.01)
        self.assertEqual(job["status"], "done", job)
        self.assertEqual((dest / "selected" / "ok.txt").read_text(), "ok")
        self.assertFalse((dest / "selected" / "stolen.txt").exists())
        self.assertFalse((dest / "selected" / "leak").exists())

    def test_zone_alias_cannot_read_another_zone(self):
        allowed, secret = self.root / "allowed", self.root / "secret"
        allowed.mkdir()
        secret.mkdir()
        (secret / "secret.txt").write_text("secret")
        self.link(allowed / "alias", secret, True)
        acct = {"role": "employee", "permissions": ["files.read"]}
        zones = [{"mount": 1, "path": "/allowed", "caps": ["files.read"]}]
        h = strata.Handler.__new__(strata.Handler)
        with mock.patch.object(accounts, "zones", return_value=zones):
            self.assertFalse(h.authorize_zone("audit", acct, "/api/files/raw", "GET",
                                              {"mount": 1, "path": "/allowed/alias/secret.txt"}, {}, "files.read"))

    def test_resumable_upload_limit(self):
        with mock.patch.dict(core.CFG, {"upload_max_bytes": 3}), self.assertRaises(files.FileError) as caught:
            files.up_init("audit", {"mount": 1, "path": "/large", "size": 4})
        self.assertEqual(caught.exception.code, 413)

    def test_non_owner_storage_roots_cannot_expand_host_access(self):
        drive = {"kind": "files", "name": "Audit", "hosts": ["audit.example"], "path": self.temp.name, "preview": True}
        with mock.patch.object(accounts, "has", return_value=False), mock.patch.object(core, "file_mounts", return_value=[]), \
                mock.patch.dict(core.CFG, {"storage_paths": [str(self.root)]}), mock.patch.object(rules, "mutate", return_value={"diff": "ok"}):
            with self.assertRaises(files.FileError) as denied:
                rules.save_mount("admin", drive)
            self.assertEqual(denied.exception.code, 403)
            drive["path"] = str(self.root)
            self.assertEqual(rules.save_mount("admin", drive)["diff"], "ok")
            drive["path"] = self.temp.name
            with mock.patch.object(accounts, "has", return_value=True):
                self.assertEqual(rules.save_mount("owner", drive)["diff"], "ok")

    def test_failed_retry_preserves_accepted_chunk(self):
        r = files.up_init("audit", {"mount": 1, "path": "/retry.txt", "size": 4})
        self.addCleanup(lambda: files.up_abort("audit", r["id"]))
        files.up_chunk("audit", r["id"], 0, io.BytesIO(b"good"), {"Content-Length": "4"})
        with self.assertRaises(files.FileError):
            files.up_chunk("audit", r["id"], 0, io.BytesIO(b"evil"), {"Content-Length": "4", "X-Chunk-SHA256": "0" * 64})
        stored = files.up_row(r["id"], "audit")
        self.assertEqual(pathlib.Path(stored["tmp"]).read_bytes(), b"good")
        self.assertEqual(json.loads(stored["received"]), [0])

    def test_chunked_request_cannot_overwrite_adjacent_chunk(self):
        r = files.up_init("audit", {"mount": 1, "path": "/bounds.txt", "size": 4})
        self.addCleanup(lambda: files.up_abort("audit", r["id"]))
        with self.assertRaises(files.FileError):
            files.up_chunk("audit", r["id"], 0, io.BytesIO(b"8\r\noverflow\r\n0\r\n\r\n"),
                           {"Content-Length": "4", "Transfer-Encoding": "chunked"})
        self.assertEqual(pathlib.Path(files.up_row(r["id"], "audit")["tmp"]).read_bytes(), b"\0" * 4)


class IdentityTests(unittest.TestCase):
    def test_installer_detects_vulnerable_pillow_versions(self):
        versions = {"brotli": "1.2.0", "zstandard": "0.25.0", "Pillow": "11.0.0", "qrcode": "8.2"}
        with mock.patch("importlib.util.find_spec", return_value=True), mock.patch("importlib.metadata.version", side_effect=versions.get):
            self.assertEqual(setup.package_problems(), ["Pillow 11.0.0 (need >=12.3.0)"])
            versions["Pillow"] = "12.3.0.dev0"
            self.assertEqual(len(setup.package_problems()), 1)
            versions["Pillow"] = "12.3.0"
            self.assertEqual(setup.package_problems(), [])

    def test_session_revocation_is_case_insensitive(self):
        s = auth.Sessions(1)
        token = s.create("MiXeD", "127.0.0.1")
        s.drop_user("mixed")
        self.assertIsNone(s.check(token))

    def test_email_code_is_consumed_once_under_concurrency(self):
        db = core.connect()
        with db:
            db.execute("INSERT OR REPLACE INTO account_code VALUES(?,?,?,?,?,?)",
                       ["audit", "audit@example.test", accounts.hmac_code("audit", "audit@example.test", "123456", "login"),
                        time.time() + 60, 0, "login"])
        db.close()
        barrier = threading.Barrier(12)
        def verify(_):
            barrier.wait()
            return accounts.verify_code("audit", "123456", "login")
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            self.assertEqual(list(pool.map(verify, range(12))).count("audit@example.test"), 1)

    def test_invite_is_consumed_once_under_concurrency(self):
        db = core.connect()
        with db:
            db.execute("INSERT OR REPLACE INTO account(user,email,password_hash,role,permissions,enabled,created,updated) "
                       "VALUES('invite-audit','audit@example.test','','employee','[]',0,?,?)", [time.time(), time.time()])
            db.execute("INSERT INTO account_invite(token_hash,user,email,expires,created_by) VALUES(?,?,?,?,?)",
                       [auth.token_hash("audit-token"), "invite-audit", "audit@example.test", time.time() + 60, "audit"])
        db.close()
        barrier = threading.Barrier(2)
        def redeem(_):
            barrier.wait()
            try:
                return accounts.use_invite("audit-token", "a long audit password", True, "127.0.0.1")
            except ValueError:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(list(pool.map(redeem, range(2))).count("invite-audit"), 1)


class TrafficTests(unittest.TestCase):
    def test_missing_tunnel_config_is_an_actionable_empty_state(self):
        with mock.patch.dict(core.CFG, {"cloudflared_config": os.path.join(HOME.name, "missing.yml")}):
            state = network.ingress()
        self.assertFalse(state["available"])
        self.assertIn("cloudflared_config", state["error"])
        self.assertEqual(state["rules"], [])

    def test_malformed_referrer_keeps_request_and_rest_of_batch(self):
        entry = {"msg": "handled request", "ts": time.time(), "status": 200, "request": {
            "host": "test.example", "uri": "/ok", "remote_ip": "203.0.113.9", "headers": {"Referer": ["http://["]}}}
        self.assertEqual(core.parse_line(json.dumps(entry))["ref"], "")
        live = core.Live()
        tailer = core.Tailer(live)
        db = core.connect()
        try:
            tailer.ingest(db, (json.dumps(entry) + '\n{"msg":"handled request","status":"bad"}\n' + json.dumps(entry) + '\n').encode())
        finally:
            db.close()
        self.assertEqual(len(live.tail()), 2)


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2)
    finally:
        HOME.cleanup()
