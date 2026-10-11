"""sys.path fix for the Strata Media entry points - `import pathfix` first thing in media.py and worker.py.

Task Scheduler starts pythonw without APPDATA, so Python cannot see the per-user site-packages, and a --user
install can land in an app-private virtualised AppData the scheduled tasks never see. Third-party packages
(Pillow with AVIF/WebP, brotli, zstandard) are therefore vendored in <install folder>\\vendor, which goes first;
the real roaming user site (asked from Windows, not the environment) is added after it. Same block as the top
of core.py / transform/transform.py. Idempotent and never raises: a broken path fix must not stop the CDN.
"""
import os
import site
import sys

HERE = os.path.dirname(os.path.abspath(__file__))          # <install folder>\media
VENDOR = os.path.join(os.path.dirname(HERE), "vendor")      # <install folder>\vendor
DIAG = {}


def _roaming_appdata():
    try:  # ask Windows (works even when the environment has no APPDATA / USERPROFILE)
        import ctypes
        buf = ctypes.create_unicode_buffer(520)
        if ctypes.windll.shell32.SHGetFolderPathW(None, 0x1A, None, 0, buf) == 0 and buf.value:  # CSIDL_APPDATA
            return buf.value
    except Exception:
        pass
    return os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Roaming")


def apply():
    """Put vendor/ at sys.path[0] and add the user site. Safe to call any number of times."""
    try:
        if os.path.isdir(VENDOR):
            if VENDOR in sys.path and sys.path[0] != VENDOR:
                sys.path.remove(VENDOR)        # vendor must win over any other copy of Pillow
            if VENDOR not in sys.path:
                sys.path.insert(0, VENDOR)
        user_site = os.path.join(_roaming_appdata(), "Python", "Python%d%d" % sys.version_info[:2], "site-packages")
        if os.path.isdir(user_site) and user_site not in sys.path:
            site.addsitedir(user_site)
        DIAG.update(vendor=VENDOR, vendor_exists=os.path.isdir(VENDOR), user_site=user_site,
                    user_site_exists=os.path.isdir(user_site))
    except Exception as e:  # never fatal
        DIAG["error"] = "%s: %s" % (e.__class__.__name__, e)
    return DIAG


apply()
