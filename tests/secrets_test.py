"""Secrets live in <home>/data/.env, never in strata.json (instance.SECRETS): an old strata.json is emptied of them on
start, save_config routes them to data/.env and the file is locked down.
Fake values only, in a throwaway home."""
import json
import os
import shutil
import subprocess
import sys
import tempfile

home = tempfile.mkdtemp(prefix="strata-secrets-")
os.environ["STRATA_HOME"] = home
os.makedirs(os.path.join(home, "data"))
with open(os.path.join(home, "strata.json"), "w") as f:
    json.dump({"sign_secret": "fake-sign", "auth": {"cookie_secret": "fake-cookie", "user": "u", "recovery": ["h1", "h2"]},
               "alerts": {"smtp": {"host": "mail", "password": "fake-pw"}, "webhooks": ["https://example.invalid/hook?t=fake"]}}, f)
with open(os.path.join(home, "data", ".env"), "w") as f:
    f.write("# kept as it is\nOTHER=untouched\n")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import core  # noqa: E402  (moves the secrets out of strata.json on import)
import instance  # noqa: E402

failed = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else "  -> %s" % (detail,)))
    if not cond:
        failed.append(name)


def disk():
    with open(core.CONFIG_PATH) as f:
        return json.load(f), instance.env_read()


try:
    raw, env = disk()
    check("strata.json lost every secret", not any(instance.split_secrets(json.loads(json.dumps(raw)), raw).values()), raw)
    check("non-secret settings stay in strata.json", raw["auth"]["user"] == "u" and raw["alerts"]["smtp"]["host"] == "mail", raw)
    check("secrets moved to data/.env", env.get("STRATA_SIGN_SECRET") == "fake-sign" and env.get("STRATA_SMTP_PASSWORD") == "fake-pw"
          and json.loads(env["STRATA_RECOVERY_HASHES"]) == ["h1", "h2"], sorted(env))
    check("other lines and comments in data/.env survive", env.get("OTHER") == "untouched"
          and "# kept as it is" in open(instance.env_path()).read())
    check("the running config has them", core.CFG["sign_secret"] == "fake-sign" and core.CFG["auth"]["recovery"] == ["h1", "h2"]
          and core.CFG["alerts"]["webhooks"] == ["https://example.invalid/hook?t=fake"])

    core.save_config({"auth": {"totp_secret": "fake-totp", "session_hours": 5}})
    raw, env = disk()
    check("save_config: secret to data/.env, setting to strata.json", env.get("STRATA_TOTP_SECRET") == "fake-totp"
          and "totp_secret" not in raw["auth"] and raw["auth"]["session_hours"] == 5, (raw, sorted(env)))
    core.save_config({"auth": {"recovery": []}})
    check("an emptied secret is removed", "STRATA_RECOVERY_HASHES" not in instance.env_read())

    instance.env_write({"QUOTED": 'a"b c#d ='})
    check("values round-trip (quotes, #, spaces)", instance.env_read()["QUOTED"] == 'a"b c#d =')
    try:
        instance.env_write({"BAD": "line\nbreak"})
        check("a line break is refused", False)
    except ValueError:
        check("a line break is refused", True)

    if os.name == "nt":
        acl = subprocess.run(["icacls", instance.env_path()], capture_output=True, text=True).stdout
        check("data/.env: no inherited or broad access", "(I)" not in acl and "Users:" not in acl and "Everyone" not in acl
              and "SYSTEM:(F)" in acl and "Administrators:(F)" in acl, acl)
    else:
        check("data/.env is 0600", oct(os.stat(instance.env_path()).st_mode & 0o777) == "0o600")

finally:
    shutil.rmtree(home, ignore_errors=True)
sys.exit(1 if failed else 0)
