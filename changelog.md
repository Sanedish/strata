# Changelog

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