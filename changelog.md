# Changelog

10/17/2026 - From: (v0.4.0.1), To: (v0.4.1).

## Security

- **Drive roots:** only the owner (or an owner-issued API key) can add a drive outside the configured storage roots. Administrators could previously mount Strata's own folder and edit it through Files.
- **First-run setup** requires a loopback client *and* a localhost Host header, closing a DNS-rebinding path to owner creation.
- **Filesystem links:** public Transform/Media paths, ZIP downloads, copy jobs and zone permission checks no longer follow symlinks or Windows junctions out of the selected tree.
- **Request framing:** negative, duplicate or ambiguous `Content-Length` / `Transfer-Encoding` are refused; chunked uploads validate sizes, terminators and trailers.
- **Uploads:** a failed chunk retry can no longer corrupt an accepted chunk; resumable uploads respect `upload_max_bytes`.
- **Single-use credentials:** e-mailed codes, invites and reset links are consumed atomically; authenticator and recovery checks are serialized.
- **Analytics-only accounts** no longer receive visitor IPs, scanners or raw requests without `analytics.visitors`.
- **Session revocation** is case-insensitive, matching sign-in.
- **Malformed input hardening:** non-ASCII signed-link signatures, gate CSRF tokens, trust cookies and Unicode digits in 2FA codes are rejected cleanly instead of raising server errors.
- Pillow minimum raised to 12.3.0; `setup.py` checks installed versions, not just presence.

## Bot protection

- One-switch activation with an automatic challenge rule, an option to challenge direct download tools, and **Under Attack Mode** (harder puzzle for a set time).
- Under Attack Mode now ends on time even with no dashboard open, and Anubis is restarted so the normal difficulty actually applies again.

## Media

- Video settings in the dashboard: encoder (CPU / NVENC / auto), codec, presets and quality. Changed settings produce new variants instead of reusing stale ones; NVENC failures in auto mode fall back to software.

## Fixes

- A malformed `Referer` no longer drops a whole batch of traffic log lines.
- Network view shows a clear message when the tunnel config is missing instead of a 500.
- Upload cancel / retry races, modal focus handling, and the connection indicator.
- Storage analysis filters ignore `inf` / `nan` instead of failing.

After updating: restart Strata (and its Transform/Media helpers), refresh dashboard tabs, and on older installs re-run `python setup.py` to pick up the new Pillow floor. Full details: `docs/security-audit-2026-10-15.md`.

---

10/14/2026 - From: (v0.3.1), To: (v0.4.0). 

## Security

**Secrets now live in** `data/.env`**, this was done so**`strata.json` no longer holds anything sensitive.

- API keys, tokens, SMTP password, webhook URLs, owner account's password hash, authenticator secret and recovery codes, as well as cookie and link-signing secrets for Anubis now all go to `<instance>/data/.env`.
- The file is written atomically and locked to the account Strata runs as, SYSTEM and Administrators (mode `0600` on Linux). This task is reoccuring, so handwritten files are automatically locked.
- Secrets are automatically moved from `strata.json`to `<instgance>/data/.env`, machine environment values will be respected and treated as overwrites.
- Secrets no longer appear in `strata.json`, its backups, logs, or the JSON files handed to Transform, Media and Telemetry. Those helpers read `data/.env` themselves. The telemetry feed token moved out of `telemetry.json` too.
- `setup.py` writes secrets to `data/.env`, and the `strata.json` backup it makes has them stripped.
- The dashboard hints now say "set `CF_API_TOKEN` in `data/.env`" instead of pointing at `strata.json`.

**Hardening**

- **Symlink escapes.** The drive-boundary check now runs even when the target doesn't exist yet, so a new file under a symlinked folder can't leave the drive. Paths on another drive (Windows) get a clean 400 instead of a crash. The bin refuses to restore a symlink and ignores any folder Strata didn't create.
- **Webhooks and remote upload.** Alert webhooks go through the same guarded connection as remote upload. Loopback, private LAN, link-local, cloud-metadata and Tailscale/CGNAT (`100.64.0.0/10`) addresses are refused, DNS tricks and redirects included. Bracketed IPv6 hosts are handled, and every redirect hop is re-checked.
- **Account deletion** now removes the account's sessions and unfinished uploads, including their temp files.
- **Owner account** follows `strata.json`: if you change the owner's username or password hash, it updates on the next start.
- **Invite links** are rate-limited like sign-in, so tokens can't be guessed by brute force.
- **Scoped accounts** only learn about duplicate files that sit inside their own zones.
- **Path fields** (placeholder folder, error pages, URL paths in rules) go through the file manager's own name rules, eliminating `..`, backslashes or odd segments.
- `python auth.py` strips only the BOM that Windows PowerShell adds to piped input. Leading spaces in a password are kept.
- The duplicate finder checks its column name before it goes into a query. While it was never reachable from the outside, it just shouldn't be a string you have to trust.

**Heads-up:** webhooks to a service on your LAN (a self-hosted ntfy, Gotify, Home Assistant) are now refused. That's deliberate. If you need it, open an issue and an opt-in allow-list can be added.

## General

- **The address bar names the view.** `/health/logs` opens Logs, Back and Forward work, and a refresh keeps you where you were.
- **One look across the dashboard.** Views share the same raised surface split by hairlines, with no page-coloured gutters, rounded cards or shadows. The Accounts, web IDE and Network headers became a compact toolbar.
- **Clearer messages.** "Collecting, please wait…" replaces the old loading text together with improved dashboard error screns. Error page preview now fetches from `/errors/…` so it also works from nested URLs.
- **Windows file locks.** Files read before being replaced (the generated Caddy config, text files in the editor, static assets) are closed at once. `os.replace` no longer fails with WinError 32 when something still held a handle.
- **Tests.** New `tests/secrets_test.py`, updated installer, setup and run-all tests, and the demo uses the new secret layout.

## UI

- **Files -> Analyze**; Updated the fiddly blockchart with a graph-driven system lead by a Pi-Chart.
- **Conistency**; Cleaned up the user interface's consistency to match the dashboards intended blocky design and flat background.

- **Bot defense**: Added optional Anubis bot challenging; This system will likely be replaced by an in-house system in the future.  