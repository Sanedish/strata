"""Auto-ban widening to a range (rules.ban_all): enough banned addresses in one /24 ban the /24, once, without errors."""
import os
import shutil
import sys
import tempfile
import time

home = tempfile.mkdtemp(prefix="strata-autoban-")
os.environ["STRATA_HOME"] = home
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import core  # noqa: E402
import rules  # noqa: E402

core.init_db()
db = core.connect()
ab = dict(core.CFG["autoban"], subnet_after=3)
t = time.time()
bans = [("198.51.100.%d" % i, "probing", "3 probes", "/.env", "", "") for i in (10, 11, 12, 13)]
with db:
    banned = rules.ban_all(db, bans, ab, t, [])
rows = db.execute("SELECT kind, value FROM blacklist WHERE source='autoban' ORDER BY kind, value").fetchall()
db.close()
shutil.rmtree(home, ignore_errors=True)
ok =banned.count("198.51.100.0/24") == 1 and ("cidr", "198.51.100.0/24") in rows and len(rows) == 5
print(("PASS " if ok else "FAIL ") + "four addresses in one /24 ban the range once", "" if ok else rows)
sys.exit(0 if ok else 1)
