#!/usr/bin/env python3
"""Build src/ -> dist/.

- styles.css, dashboard.css and app.js get content-hashed file names (app.3fa9c1d20b.js). Cloudflare keeps
  static files by URL for months, so a changed file must never reuse a name.
- index.html gets the hashed URLs plus Subresource Integrity (sha384): if any byte of an asset is altered in
  transit, at the CDN edge or on disk, the browser refuses to run it.
- dist/manifest.json lists exactly which asset files the telemetry service may serve (it reads the list once
  at start-up; nothing else in static/ is reachable).

Usage:  python build.py        then  deploy.ps1   (or copy dist/* into ..\\static and restart "Strata Telemetry")
"""
import base64, hashlib, json, pathlib, re, shutil, sys

ROOT = pathlib.Path(__file__).resolve().parent
SRC, DIST = ROOT / "src", ROOT / "dist"
HASHED = ["styles.css", "dashboard.css", "app.js"]  # renamed by content hash
FIXED = ["fonts/archivo-latin.woff2"]               # served under their own name; rename the file if it ever changes


def main():
    if DIST.exists():
        shutil.rmtree(DIST)
    shutil.copytree(SRC, DIST)

    names, sri = {}, {}
    for name in HASHED:
        f = DIST / name
        data = f.read_bytes()
        stem, dot, ext = name.rpartition(".")
        hashed = f"{stem}.{hashlib.sha256(data).hexdigest()[:10]}.{ext}"
        f.rename(DIST / hashed)
        names[name] = hashed
        sri[name] = "sha384-" + base64.b64encode(hashlib.sha384(data).digest()).decode()
    for name in FIXED:
        if not (DIST / name).is_file():
            sys.exit(f"missing {name}")

    html_path = DIST / "index.html"
    html = html_path.read_text(encoding="utf-8")
    html = re.sub(r"\{\{path:([A-Za-z0-9._/-]+)\}\}", lambda m: "/" + names[m.group(1)], html)
    html = re.sub(r"\{\{sri:([A-Za-z0-9._/-]+)\}\}", lambda m: sri[m.group(1)], html)
    if "{{" in html:
        sys.exit("unresolved placeholder left in index.html")
    html_path.write_text(html, encoding="utf-8", newline="\n")

    assets = sorted(names.values()) + FIXED
    (DIST / "manifest.json").write_text(json.dumps({"assets": assets}, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("built", DIST)
    for a in ["index.html", *assets, "manifest.json"]:
        print(f"{(DIST / a).stat().st_size:8}  {a}")


if __name__ == "__main__":
    main()
