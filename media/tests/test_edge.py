"""media_edge.py: exact Cloudflare rule strings (DESIGN 9) and create / patch / delete by ref against a fake ruleset.

cloudflare.call / zone_id and core.connect are replaced for the duration of each test: no API call ever leaves the
box and the production strata.db is never opened.
"""
import copy
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
MEDIA_DIR = os.path.dirname(HERE)
STRATA = os.path.dirname(MEDIA_DIR)
for _p in (MEDIA_DIR, STRATA):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import core  # noqa: E402

# tests follow the design defaults, never whatever the live strata.json currently says (e.g. the deployed profile)
core.CFG["media"].clear()
core.CFG["media"].update(copy.deepcopy(core.DEFAULTS["media"]))
import cloudflare  # noqa: E402
import media_edge  # noqa: E402

HOSTS = ["example.com", "cdn.example.com"]
H = '(http.host in {"example.com" "cdn.example.com"}) and http.request.uri.query eq ""'
IMG = ('http.request.uri.path.extension in {"png" "jpg" "jpeg" "jfif" "gif" "bmp" "tif" "tiff" "webp"}'
       # Cache-Control: no-transform -> not rewritten: the canonical entry only ever holds the original
       ' and not any(http.request.headers["cache-control"][*] contains "no-transform")')
ACC = 'any(http.request.headers["accept"][*] contains "image/%s")'
AVIF = "%s and %s and %s" % (H, IMG, ACC % "avif")
WEBP = "%s and %s and not %s and %s" % (H, IMG, ACC % "avif", ACC % "webp")
WEBM = (H + ' and http.request.uri.path.extension in {"mp4" "m4v" "mov"}'
        ' and any(http.request.headers["sec-fetch-dest"][*] eq "video")'
        ' and (lower(http.user_agent) contains "chrome/" or lower(http.user_agent) contains "firefox/")'
        ' and not lower(http.user_agent) contains "crios" and not lower(http.user_agent) contains "fxios"')
ZONE = "zone-test"
EP = "/zones/%s/rulesets/phases/http_request_transform/entrypoint" % ZONE


class FakeCF:
    """The http_request_transform entrypoint of one zone, answering like the Rulesets API."""

    def __init__(self, rules=None, get_error=None):
        self.rs = None if rules is None else {"id": "rs1", "rules": copy.deepcopy(rules)}
        self.get_error = get_error
        self.calls = []
        self.n = 0

    def call(self, method, path, body=None, timeout=30):
        self.calls.append((method, path, copy.deepcopy(body)))
        if method == "GET" and path == EP:
            if self.get_error:
                raise self.get_error
            if self.rs is None:
                raise cloudflare.CFError(404, "could not find entrypoint ruleset (code 10003)")
            return {"result": copy.deepcopy(self.rs)}
        if method == "PUT" and path == EP:
            self.rs = {"id": "rs1", "rules": [dict(r, id=self._id()) for r in body["rules"]]}
            return {"result": copy.deepcopy(self.rs)}
        base = "/zones/%s/rulesets/rs1/rules" % ZONE
        if method == "POST" and path == base:
            self.rs["rules"].append(dict(body, id=self._id()))
            return {"result": copy.deepcopy(self.rs)}
        rid = path[len(base) + 1:]
        idx = next(i for i, r in enumerate(self.rs["rules"]) if r["id"] == rid)
        if method == "PATCH":
            self.rs["rules"][idx] = dict(body, id=rid)
        elif method == "DELETE":
            del self.rs["rules"][idx]
        return {"result": copy.deepcopy(self.rs)}

    def _id(self):
        self.n += 1
        return "r%d" % self.n

    def writes(self):
        return [(m, p) for m, p, _ in self.calls if m != "GET"]

    def by_ref(self):
        return {r.get("ref"): r for r in (self.rs or {}).get("rules", [])}


class EdgeBase(unittest.TestCase):
    def setUp(self):
        self.saved = (cloudflare.call, cloudflare.zone_id, core.connect)
        cloudflare.zone_id = lambda: ZONE
        self.tmp = tempfile.mkdtemp(prefix="strata-media-edge-")

    def tearDown(self):
        cloudflare.call, cloudflare.zone_id, core.connect = self.saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def use(self, fake):
        cloudflare.call = fake.call
        return fake


class RuleStrings(unittest.TestCase):
    def test_exact_expressions_and_actions(self):
        rules = media_edge.build_rules(HOSTS, media_edge.IMG_EXTS, media_edge.VID_EXTS)
        self.assertEqual([r["ref"] for r in rules], ["strata_media_avif", "strata_media_webp", "strata_media_webm"])
        exprs = {r["ref"]: r["expression"] for r in rules}
        self.assertEqual(exprs["strata_media_avif"], AVIF)
        self.assertEqual(exprs["strata_media_webp"], WEBP)
        self.assertEqual(exprs["strata_media_webm"], WEBM)
        for r, v in zip(rules, ("avif", "webp", "webm")):
            self.assertEqual(r["action"], "rewrite")
            self.assertEqual(r["action_parameters"], {"uri": {"query": {"value": "_v=" + v}}})
            self.assertTrue(r["enabled"])
            self.assertIn("managed by Strata", r["description"])
            self.assertLess(len(r["expression"]), 4096)

    def test_mp4_video_rule(self):
        """video.format=mp4: the same rule (same ref, patched in place) rewrites every client to _v=mp4 - no
        Sec-Fetch-Dest / browser test, H.264 plays everywhere; Cache-Control: no-transform still gets the original."""
        r = media_edge.build_rules(HOSTS, (), ("mp4", "mov"), "mp4")
        self.assertEqual([x["ref"] for x in r], ["strata_media_webm"])
        self.assertEqual(r[0]["action_parameters"], {"uri": {"query": {"value": "_v=mp4"}}})
        self.assertIn('extension in {"mp4" "mov"}', r[0]["expression"])
        self.assertIn(media_edge.NO_TRANSFORM, r[0]["expression"])
        self.assertNotIn("sec-fetch-dest", r[0]["expression"])
        self.assertNotIn("user_agent", r[0]["expression"])

    def test_partial_sets_and_sanitising(self):
        self.assertEqual(media_edge.build_rules([], media_edge.IMG_EXTS, media_edge.VID_EXTS), [])
        self.assertEqual([r["ref"] for r in media_edge.build_rules(HOSTS, media_edge.IMG_EXTS, ())],
                         ["strata_media_avif", "strata_media_webp"])
        self.assertEqual([r["ref"] for r in media_edge.build_rules(HOSTS, (), ("mp4",))], ["strata_media_webm"])
        r = media_edge.build_rules(['evil" or true or "', "CDN.Example.Com", "cdn.example.com"], ("PNG",), ())
        self.assertTrue(r[0]["expression"].startswith('(http.host in {"cdn.example.com"})'), r[0]["expression"])
        self.assertIn('extension in {"png"}', r[0]["expression"])

    def test_media_hosts(self):
        mounts = [{"id": 1, "kind": "files", "enabled": 1, "transforms": 1, "hosts": ["a.test", "b.test"]},
                  {"id": 2, "kind": "files", "enabled": 1, "transforms": 0, "hosts": ["c.test"]},
                  {"id": 3, "kind": "files", "enabled": 0, "transforms": 1, "hosts": ["d.test"]},
                  {"id": 4, "kind": "proxy", "enabled": 1, "transforms": 1, "hosts": ["e.test"]},
                  {"id": 5, "kind": "files", "enabled": 1, "transforms": 1, "hosts": ["b.test", "f.test"]}]
        self.assertEqual(media_edge.media_hosts(mounts), ["a.test", "b.test", "f.test"])


class Sync(EdgeBase):
    def test_missing_entrypoint_is_created_with_put(self):
        fake = self.use(FakeCF(rules=None))
        res = media_edge.sync_media_rules(True, hosts=HOSTS)
        self.assertEqual(fake.writes(), [("PUT", EP)])
        self.assertEqual(res["created"], ["strata_media_avif", "strata_media_webp", "strata_media_webm"])
        self.assertEqual(res["rules"], {"strata_media_avif": True, "strata_media_webp": True, "strata_media_webm": True})
        self.assertEqual(fake.by_ref()["strata_media_webp"]["expression"], WEBP)

    def test_disable_without_entrypoint_writes_nothing(self):
        fake = self.use(FakeCF(rules=None))
        res = media_edge.sync_media_rules(False, hosts=HOSTS)
        self.assertEqual(fake.writes(), [])
        self.assertEqual(res["rules"], {r: False for r in media_edge.REFS})

    def test_create_patch_delete_by_ref_other_rules_untouched(self):
        foreign = {"id": "u1", "ref": "someone_else", "description": "user rule", "expression": "true",
                   "action": "rewrite", "action_parameters": {"uri": {"query": {"value": "x=1"}}}, "enabled": True}
        no_ref = {"id": "u2", "description": "no ref", "expression": "false", "action": "rewrite", "enabled": True}
        stale = {"id": "s1", "ref": "strata_media_avif", "description": "old", "expression": "old expression",
                 "action": "rewrite", "action_parameters": {"uri": {"query": {"value": "_v=avif"}}}, "enabled": True}
        webm = dict(media_edge.build_rules(HOSTS, (), ("mp4",))[0], id="s2")
        fake = self.use(FakeCF(rules=[foreign, no_ref, stale, webm]))
        res = media_edge.sync_media_rules(True, hosts=HOSTS, vid_exts=())
        base = "/zones/%s/rulesets/rs1/rules" % ZONE
        self.assertEqual(res["updated"], ["strata_media_avif"])
        self.assertEqual(res["created"], ["strata_media_webp"])
        self.assertEqual(res["deleted"], ["strata_media_webm"])
        self.assertEqual(sorted(fake.writes()), sorted([("PATCH", base + "/s1"), ("POST", base), ("DELETE", base + "/s2")]))
        have = fake.by_ref()
        self.assertEqual(have["someone_else"], foreign)
        self.assertIn(no_ref, fake.rs["rules"])
        self.assertEqual(have["strata_media_avif"]["expression"], AVIF)
        self.assertNotIn("strata_media_webm", have)
        # idempotent: a second sync changes nothing
        n = len(fake.writes())
        res = media_edge.sync_media_rules(True, hosts=HOSTS, vid_exts=())
        self.assertEqual(len(fake.writes()), n)
        self.assertEqual(sorted(res["unchanged"]), ["strata_media_avif", "strata_media_webp"])
        # disable: only our rules go
        res = media_edge.sync_media_rules(False, hosts=HOSTS)
        self.assertEqual(sorted(res["deleted"]), ["strata_media_avif", "strata_media_webp"])
        self.assertEqual([r["id"] for r in fake.rs["rules"]], ["u1", "u2"])

    def test_permission_error_propagates(self):
        self.use(FakeCF(rules=[], get_error=cloudflare.CFError(403, "Authentication error (code 10000)")))
        with self.assertRaises(cloudflare.CFError) as cm:
            media_edge.sync_media_rules(True, hosts=HOSTS)
        self.assertEqual(cm.exception.status, 403)


class Capabilities(EdgeBase):
    def fake_db(self, purge=None):
        path = os.path.join(self.tmp, "strata-test.db")
        db = sqlite3.connect(path)
        db.execute("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT)")
        if purge is not None:
            db.execute("INSERT OR REPLACE INTO meta VALUES('cf_purge', ?)", [json.dumps(purge)])
        db.commit()
        db.close()
        core.connect = lambda: sqlite3.connect(path)

    def test_readable_phase_with_our_rules(self):
        self.fake_db({"ts": 123.0, "ok": False, "error": "Authentication error"})
        fake = self.use(FakeCF(rules=[dict(media_edge.build_rules(HOSTS)[0], id="s1")]))
        caps = media_edge.capabilities()
        self.assertEqual(fake.writes(), [])  # reads only
        self.assertTrue(caps["transform"]["ok"])
        self.assertEqual(caps["transform"]["rules"],
                         {"strata_media_avif": True, "strata_media_webp": False, "strata_media_webm": False})
        self.assertEqual(caps["transform"]["need"], media_edge.PERMS["transform"])
        self.assertEqual(caps["purge"], {"ok": False, "error": "Authentication error",
                                         "need": media_edge.PERMS["purge"], "tested": 123.0})

    def test_missing_entrypoint_is_ok_and_403_is_not(self):
        self.fake_db()
        self.use(FakeCF(rules=None))
        caps = media_edge.capabilities()
        self.assertTrue(caps["transform"]["ok"])
        self.assertEqual(caps["transform"]["error"], "")
        self.use(FakeCF(rules=[], get_error=cloudflare.CFError(403, "Authentication error (code 10000)")))
        caps = media_edge.capabilities()
        self.assertFalse(caps["transform"]["ok"])
        self.assertIn("Authentication", caps["transform"]["error"])
        self.assertIsNone(caps["purge"]["ok"])


if __name__ == "__main__":
    unittest.main()
