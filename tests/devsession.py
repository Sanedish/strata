"""devsession.py <db> <user> - mint a session for the DEV instance only and print the cookie token.
Inserts sha256(token) into the dev DB's session table, exactly what Strata stores after a real login."""
import hashlib
import secrets
import sqlite3
import sys
import time

db, user = sys.argv[1], sys.argv[2]
if "scratchpad" not in db.replace("\\", "/"):
    sys.exit("refusing: dev databases only")
tok = secrets.token_urlsafe(32)
c = sqlite3.connect(db)
now = time.time()
c.execute("INSERT OR REPLACE INTO session VALUES(?,?,?,?,?,?)",
          [hashlib.sha256(tok.encode()).hexdigest(), user, now + 86400, "127.0.0.1", now, 86400])
c.commit()
print(tok)
