"""Which Strata instance this process serves.

One code folder (this one) runs several sites. Everything a site owns lives in its *instance home*:

    <home>/strata.json                 config (site identity, ports, paths) - no secrets
    <home>/data/.env                   every secret (API keys, tokens, hashes), locked to this account
    <home>/data/                       strata.db, media.db, thumbnails, transform cache, process logs
    <home>/generated/cdn.caddy         the rendered CDN site its Caddyfile imports
    <home>/transform/transform.json    written by rules.py for Strata Transform
    <home>/telemetry/telemetry.json    feed token + listen address of Strata Telemetry
    <home>/media/media.json            written by media_rules.py for Strata Media

The home is chosen by `--home <dir>` on the command line or the STRATA_HOME environment variable (the first one
wins), else this code folder itself. It is exported to STRATA_HOME so the processes Strata starts (media.py,
worker.py) serve the same instance.
"""
import json
import os
import re
import sys

CODE = os.path.dirname(os.path.abspath(__file__))


def _from_argv(argv):
    for i, a in enumerate(argv):
        if a == "--home" and i + 1 < len(argv):
            return argv[i + 1]
        if a.startswith("--home="):
            return a.split("=", 1)[1]
    return None


def resolve():
    h = _from_argv(sys.argv) or os.environ.get("STRATA_HOME") or CODE
    return os.path.normpath(os.path.abspath(h))


HOME = resolve()
os.environ["STRATA_HOME"] = HOME
os.environ.setdefault("STRATA_MEDIA_CONFIG", os.path.join(HOME, "media", "media.json"))


def home(*parts):
    """A path inside the instance home."""
    return os.path.join(HOME, *parts)


def code(*parts):
    """A path inside the shared code folder."""
    return os.path.join(CODE, *parts)


# ---------------------------------------------------------------- secrets: <home>/data/.env

# Every secret of an instance lives in <home>/data/.env, never in strata.json or the JSON files Strata writes for its
# helper processes. Highest source first: the process environment (set on the machine) > data/.env > a leftover in
# strata.json (moved into data/.env on the next start). Config path -> variable name; JSON ones hold lists.
SECRETS = {
    ("cloudflare", "api_token"): "CF_API_TOKEN",          # renamed by instance.token_env, see secret_name()
    ("sign_secret",): "STRATA_SIGN_SECRET",
    ("feed_token_hash",): "STRATA_FEED_TOKEN_HASH",
    ("auth", "cookie_secret"): "STRATA_COOKIE_SECRET",
    ("auth", "password_hash"): "STRATA_PASSWORD_HASH",
    ("auth", "totp_secret"): "STRATA_TOTP_SECRET",
    ("auth", "recovery"): "STRATA_RECOVERY_HASHES",
    ("auth", "api_keys"): "STRATA_API_KEYS",
    ("alerts", "resend_api_key"): "STRATA_RESEND_API_KEY",
    ("alerts", "smtp", "password"): "STRATA_SMTP_PASSWORD",
    ("alerts", "webhooks"): "STRATA_WEBHOOKS",           # the URLs carry their tokens (Discord, Slack, ntfy)
    ("media", "admin_token"): "STRATA_MEDIA_ADMIN_TOKEN",
}
JSON_SECRETS = {("auth", "recovery"), ("auth", "api_keys"), ("alerts", "webhooks")}
FEED_TOKEN = "STRATA_FEED_TOKEN"                          # the telemetry token itself (feed.py, telemetry.py)
_ENV_LINE = re.compile(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


def env_path(home_dir=None):
    return os.path.join(home_dir or HOME, "data", ".env")


def env_read(path=None):
    """data/.env as {NAME: value}. NAME=value lines; '#' starts a comment line; one pair of matching outer quotes
    is removed; nothing is expanded. A missing file is empty."""
    out = {}
    try:
        with open(path or env_path(), encoding="utf-8-sig") as f:
            for line in f:
                m = None if line.lstrip().startswith("#") else _ENV_LINE.match(line)
                if m:
                    v = m.group(2)
                    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                        v = v[1:-1]
                    out[m.group(1)] = v
    except FileNotFoundError:
        pass
    return out


def env_get(name, path=None):
    """One secret, machine environment first: (value, "machine" | "env" | "")."""
    if os.environ.get(name):
        return os.environ[name], "machine"
    v = env_read(path).get(name)
    return (v, "env") if v else ("", "")


def env_write(updates, path=None):
    """Set (str) or remove (None / "") variables in data/.env. Every other line and comment stays as it is; the file
    is replaced atomically and locked down before it takes the real name (lock_down)."""
    path = path or env_path()
    for k, v in updates.items():
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k) or (v and re.search(r"[\r\n\x00]", v)):
            raise ValueError("refusing to write %s to .env" % k)
    try:
        with open(path, encoding="utf-8-sig") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        lines = []
    todo, out = dict(updates), []
    for line in lines:
        m = None if line.lstrip().startswith("#") else _ENV_LINE.match(line)
        if m and m.group(1) in todo:
            v = todo.pop(m.group(1))
            if v:
                out.append('%s="%s"' % (m.group(1), v))   # always quoted: env_read strips exactly one pair
            continue
        out.append(line)
    out += ['%s="%s"' % (k, v) for k, v in todo.items() if v]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    if os.path.exists(tmp):
        os.remove(tmp)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out) + "\n")
    lock_down(tmp)
    os.replace(tmp, path)   # a rename on one volume keeps the file's ACL / mode
    lock_down(path)


def lock_down(path):
    """Only this account, SYSTEM and the Administrators group may open the file (Windows: inheritance removed, those
    three granted full control); owner-only 0600 elsewhere. Raises if Windows refuses, so a caller never believes an
    unprotected file is protected."""
    if os.name != "nt":
        os.chmod(path, 0o600)
        return
    import subprocess
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    me = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, creationflags=flags, timeout=15)
    sid = re.search(r"S-1-[\d-]+", me.stdout or "")
    grants = ["*S-1-5-18:F", "*S-1-5-32-544:F"] + (["*%s:F" % sid.group(0)] if sid else [])
    r = subprocess.run(["icacls", path, "/inheritance:r", "/grant:r"] + grants, capture_output=True, text=True,
                       creationflags=flags, timeout=15)
    if r.returncode:
        raise OSError("icacls could not lock down %s: %s" % (path, (r.stdout + r.stderr).strip()[:200]))


def secret_name(path, cfg=None):
    if path == ("cloudflare", "api_token"):
        return ((cfg or {}).get("instance") or {}).get("token_env") or "CF_API_TOKEN"
    return SECRETS[path]


def _walk(d, path, pop=False):
    for k in path[:-1]:
        d = d.get(k) if isinstance(d, dict) else None
    if not isinstance(d, dict) or path[-1] not in d:
        return False, None
    return True, (d.pop(path[-1]) if pop else d[path[-1]])


def split_secrets(d, cfg=None):
    """Take every secret out of the config dict `d` (in place): {variable name: .env text, "" to remove}."""
    found = {}
    for path in SECRETS:
        there, v = _walk(d, path, pop=True)
        if there:
            if path in JSON_SECRETS:
                found[secret_name(path, cfg or d)] = json.dumps(v, separators=(",", ":")) if v else ""
            else:
                found[secret_name(path, cfg or d)] = str(v or "")
    return found


def overlay_secrets(cfg, path=None):
    """Put the secrets from the machine environment and data/.env into the config dict (in place)."""
    env = env_read(path)
    for p in SECRETS:
        name = secret_name(p, cfg)
        raw = os.environ.get(name) or env.get(name)
        if not raw:
            continue
        if p in JSON_SECRETS:
            try:
                raw = json.loads(raw)
            except ValueError:
                continue
        d = cfg
        for k in p[:-1]:
            d = d.setdefault(k, {})
        d[p[-1]] = raw
    return cfg
