# Strata Telemetry site: source, build, deploy

```
telemetry.py        the service (127.0.0.1:8082): serves ../static, sets every security header (SECURITY_HEADERS)
static/             what the service serves (written by deploy.ps1, do not edit by hand)
site/src/           the page: index.html, styles.css, dashboard.css, app.js, fonts/archivo-latin.woff2   <- edit here
site/build.py       src -> dist: content-hashed file names + Subresource Integrity + manifest.json
site/deploy.ps1     build, back up, install, restart the service, verify, roll back on failure
site/dev/serve.py   local test server (same headers, recorded API data, stress modes)
```

## Change the page

```
# edit site\src\*, then
powershell -ExecutionPolicy Bypass -File telemetry\site\deploy.ps1
```

`static/` is generated. Because `index.html` carries SRI hashes of the CSS/JS, a hand-edit of a file in `static/`
is refused by the browser; always edit `site/src` and deploy. Every deploy first backs up the live files to
`backups\telemetry-<timestamp> (next to the install folder)` and rolls back by itself if the restarted service fails its checks.
Downtime is the few seconds the service needs to restart.

To roll back by hand: copy `telemetry.py` and `static\` from a backup folder over the live ones, then
`Stop-ScheduledTask "Strata Telemetry"; Start-ScheduledTask "Strata Telemetry"`.

## Why it looks like this

**16:9.** In any landscape window at least 4:3 and 1100px wide (so every 16:9 screen) the root font size follows the
viewport (`1rem = 1/120` of the width = `1/67.5` of the height) and the page is exactly one screen: KPIs, live strip,
a 6x3 grid of all 15 tiles, footer. Edge to edge, no scrolling, no bars, vector text and charts. Grid tracks are `fr`,
so 21:9 / 16:10 / 3:2 windows absorb the extra room instead of letterboxing. Lists show as many whole rows as fit their
tile (`fit()` in `app.js`). Portrait, phones and windows under 1100px keep a responsive scrolling layout.

**Security.**
- CSP: `default-src 'none'`, `script-src 'self'`, `style-src 'self'` (no `unsafe-inline`), `font-src 'self'`,
  `require-trusted-types-for 'script'` + `trusted-types 'none'`. The page never parses HTML: nodes come from
  `createElement`/`textContent`, styles via the CSSOM, and every API number goes through `num()`. A future
  `innerHTML` is an error, not a hole.
- Zero third-party requests: Archivo is self-hosted (the old page sent every visitor's IP to Google Fonts).
- HSTS (2 years), COOP/COEP/CORP, `nosniff`, `DENY`, `no-referrer`, a 17-feature Permissions-Policy.
- Assets get content-hashed names + SRI, served `immutable` for a year (Cloudflare keeps static files by URL for
  months; a changed file never reuses a name). `manifest.json` is the fixed list of extra files the service may
  serve, read once at start-up and regex-checked (no `..`, no absolute paths); nothing else in `static/` is reachable.
- `fetch` uses `credentials: 'omit'`, `redirect: 'error'`, a 10 s timeout and a JSON content-type check; polling
  pauses while the tab is hidden.

## Test locally without touching the live service

```
python site\build.py
python site\dev\serve.py                    # http://127.0.0.1:8099/  (recorded data)
python site\dev\serve.py --mode hostile     # or: empty | noedge | big
```
`serve.py` reads `SECURITY_HEADERS` from `telemetry.py` (parsed, never executed), so it enforces what production sends.
HSTS and `upgrade-insecure-requests` are skipped locally (meaningless over plain http).

## Recommended Cloudflare settings for the stats host

These live in the Cloudflare dashboard, not in this repository.

- **Minimum TLS version 1.2.**
- **DNSSEC** on, with the DS record added at the registrar.
- **CAA records** that limit issuance to Cloudflare's CAs.
- **JavaScript Detections / Bot Fight Mode** off for this host. Cloudflare injects an inline script, the CSP blocks it,
  and the browser logs an error. Don't loosen the CSP for it.
- **Rate-limit `/api/*`** with a WAF rule. A tab polls about 14 times a minute, so 60/min per IP is comfortable.
- Optional: `/.well-known/security.txt`.

Font: `src/fonts/archivo-latin.woff2` is Archivo (c) The Archivo Project Authors, SIL Open Font License 1.1
(https://openfontlicense.org). Keep the licence with it if you redistribute.
