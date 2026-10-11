"""Backup and restore: strata.json without its secrets plus a snapshot of the database, as one zip.

Restore copies the database in through SQLite's backup API, so it works while Strata runs, and merges the settings
over the current strata.json. Secrets are never in the zip, so the ones on this machine stay as they are.
The database itself still holds password hashes and share-link codes: the zip is for the owner only.
"""
import json
import os
import re
import shutil
import sqlite3
import tempfile
import time
import zipfile

import core

SECRET = re.compile(r"secret|password|_hash|api_key|api_token|admin_token|recovery|totp|webhooks", re.I)


def strip(d):
    """The config without any key that names a secret (nested dicts too)."""
    return {k: strip(v) if isinstance(v, dict) else v for k, v in d.items() if not SECRET.search(k)}


def name():
    return "strata-backup-%s.zip" % time.strftime("%Y%m%d-%H%M")


def write(out):
    """Write the backup zip to the (possibly unseekable) stream `out`."""
    raw = {}
    if os.path.exists(core.CONFIG_PATH):
        with open(core.CONFIG_PATH, encoding="utf-8-sig") as f:
            raw = json.load(f)
    fd, tmp = tempfile.mkstemp(prefix=".strata-backup-", suffix=".db", dir=os.path.dirname(core.DB_PATH))
    os.close(fd)
    try:
        src, dst = core.connect(), sqlite3.connect(tmp)
        try:
            src.backup(dst)  # a consistent snapshot while other threads keep writing
        finally:
            dst.close()
            src.close()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("strata.json", json.dumps(strip(raw), indent=2) + "\n")
            z.writestr("version.txt", core.VERSION + "\n")
            z.write(tmp, "strata.db")
    finally:
        os.remove(tmp)


def restore(zpath):
    """Load a backup zip (a file path) into this instance. Raises ValueError when it isn't a usable backup."""
    try:
        z = zipfile.ZipFile(zpath)
    except zipfile.BadZipFile:
        raise ValueError("that file isn't a zip")
    with z:
        if "strata.db" not in z.namelist():
            raise ValueError("not a Strata backup: strata.db is missing")
        cfg = json.loads(z.read("strata.json")) if "strata.json" in z.namelist() else {}
        if not isinstance(cfg, dict):
            raise ValueError("strata.json in the backup is not a settings object")
        size = z.getinfo("strata.db").file_size
        if size > shutil.disk_usage(os.path.dirname(core.DB_PATH)).free // 2:
            raise ValueError("not enough free disk space to unpack the database (%d MB)" % (size >> 20))
        fd, tmp = tempfile.mkstemp(prefix=".strata-restore-", suffix=".db", dir=os.path.dirname(core.DB_PATH))
        with os.fdopen(fd, "wb") as f, z.open("strata.db") as src:
            shutil.copyfileobj(src, f, 1 << 20)
    try:
        src = sqlite3.connect(tmp)
        try:
            try:
                ok = src.execute("PRAGMA integrity_check").fetchone()[0]
                has = src.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='account'").fetchone()
            except sqlite3.DatabaseError:
                ok, has = "not a database", None
            if ok != "ok" or not has:
                raise ValueError("the database in the backup is damaged or not Strata's (%s)" % ok)
            live = core.connect()
            try:
                src.backup(live)
            finally:
                live.close()
        finally:
            src.close()
    finally:
        os.remove(tmp)
    core.save_config(strip(cfg))
    core.init_db()  # brings an older backup's tables up to this version
    core.mounts(refresh=True)


if __name__ == "__main__":  # self-check of the secret filter
    c = strip({"auth": {"user": "a", "password_hash": "x", "cookie_secret": "y", "totp_last": 9, "session_hours": 1, "api_keys": [{"hash": "k"}]},
               "alerts": {"resend_api_key": "re", "to": ["a@b.c"], "webhooks": ["https://x"]},
               "cloudflare": {"api_token": "t", "zone_name": "z"}, "feed_token_hash": "h", "sign_secret": "s",
               "media": {"admin_token": "m", "enabled": True}, "instance": {"token_env": "CF_API_TOKEN"}})
    assert c == {"auth": {"user": "a", "session_hours": 1}, "alerts": {"to": ["a@b.c"]},
                 "cloudflare": {"zone_name": "z"}, "media": {"enabled": True},
                 "instance": {"token_env": "CF_API_TOKEN"}}, c
    print("ok")
