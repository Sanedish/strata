"""pathfix.py: vendor/ first and the roaming user site added even when the environment has no APPDATA /
LOCALAPPDATA / USERPROFILE (how Task Scheduler starts pythonw). Runs in a child so this process' sys.path stays."""
import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
MEDIA = os.path.dirname(HERE)
VENDOR = os.path.join(os.path.dirname(MEDIA), "vendor")

CHILD = r'''
import json, sys
sys.path.insert(0, %r)
import pathfix
pathfix.apply()                                   # idempotent: a second call changes nothing
out = {"first": sys.path[0], "vendor_count": sys.path.count(pathfix.VENDOR), "diag": pathfix.DIAG,
       "user_site_in_path": pathfix.DIAG.get("user_site") in sys.path}
try:
    import PIL
    out["pil"] = PIL.__file__
except ImportError:
    out["pil"] = None
print(json.dumps(out))
''' % MEDIA


class PathfixTest(unittest.TestCase):
    def test_scheduler_like_environment(self):
        strip = {"APPDATA", "LOCALAPPDATA", "USERPROFILE", "HOMEPATH", "HOMEDRIVE", "PYTHONPATH", "PYTHONUSERBASE"}
        env = {k: v for k, v in os.environ.items() if k.upper() not in strip}
        r = subprocess.run([sys.executable, "-c", CHILD], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        info = json.loads(r.stdout)
        self.assertNotIn("error", info["diag"])
        if not os.path.isdir(VENDOR):
            self.skipTest("no vendor dir")
        self.assertEqual(os.path.normcase(info["first"]), os.path.normcase(VENDOR))
        self.assertEqual(info["vendor_count"], 1)
        if info["diag"]["user_site_exists"]:
            self.assertTrue(info["user_site_in_path"])
            if sys.platform == "win32":                                  # asked from Windows, not from %APPDATA%
                self.assertIn("Roaming", info["diag"]["user_site"])
        if os.path.isdir(os.path.join(VENDOR, "PIL")):
            self.assertTrue(os.path.normcase(info["pil"]).startswith(os.path.normcase(VENDOR)))  # vendored Pillow wins


if __name__ == "__main__":
    unittest.main()
