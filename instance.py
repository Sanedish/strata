"""Which Strata instance this process serves.

One code folder (this one) runs several sites. Everything a site owns lives in its *instance home*:

    <home>/strata.json                 config (site identity, ports, paths, secrets)
    <home>/data/                       strata.db, media.db, thumbnails, transform cache, process logs
    <home>/generated/cdn.caddy         the rendered CDN site its Caddyfile imports
    <home>/transform/transform.json    written by rules.py for Strata Transform
    <home>/telemetry/telemetry.json    feed token + listen address of Strata Telemetry
    <home>/media/media.json            written by media_rules.py for Strata Media

The home is chosen by `--home <dir>` on the command line or the STRATA_HOME environment variable (the first one
wins), else this code folder itself. It is exported to STRATA_HOME so the processes Strata starts (media.py,
worker.py) serve the same instance.
"""
import os
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
