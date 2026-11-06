# Changelog

11/07/2026 - From: (v0.4.1), To: (v0.5.0).

## Corium

- **New name:** Strata is now **Corium**. Everything you see says Corium: the dashboard, e-mails, error pages, setup, messages and docs. The repositories moved to `github.com/Sanedish/corium` (the old URLs redirect). File, config, cookie, header, folder and task names keep the old name for now, so existing installations need no migration; [docs/RENAMING.md](docs/RENAMING.md) lists them and the plan to rename them later.

## Security

- **Error pages are no longer Caddy templates.** Pages in the error assets folder ran as templates, so anyone who could write that folder (an administrator, or an account with write access to it) could use Caddy's template functions to read Caddy's environment and other files on that drive. The reason, the Cloudflare Ray ID and the version now reach the page in the `Server-Timing` header of its response. Pages that still contain `{{…}}` show it as text; the new default pages read the header.
- **Owner boundary and Caddy placeholders:** the unknown-host text can no longer contain `{` or `}` (a `{file.…}` or `{env.…}` placeholder there leaked files and the environment); tunnel routes from non-owners may only point at the CDN, Cloudflare's status services or LAN addresses that pass the drive checks, never at Caddy's admin API or Corium's own ports.
- **Sign-in:** failed second-factor attempts are counted per pending sign-in (5, then start again) and no longer consume the address limiter on success.
- **Files and links:** a rename that leaves a redirect needs the rules permission, link aliases re-check the zone, trash metadata can't be restored or deleted as a file, the folder analysis needs `analytics.read`, compression never follows links or junctions, and a compressed archive's listing reads at most 256 MiB.
- **Backups and mail:** restoring a backup reloads sessions and drops pending sign-ins; sign-in codes and alerts have separate e-mail budgets, counted before sending.
- **Smaller fixes:** a telemetry GET with a body is refused, the dashboard's CSV export neutralises formulas, and imported preferences are filtered.

## Dashboard

- **Media settings, redone:** Site › Media has its own Overview and Settings tabs. Settings uses the same panels, switches and segments as the main Settings page (Image delivery, Upload scanning, Image quality, Image encoding, Video, Video quality, Video limits), has a filter, and only shows what applies to the current choices: WebM shows its codec and CRF, MP4 on a GPU shows the GPU preset, GPU choice and GPU decoding. Changed rows are marked and a bar at the bottom saves them together (Save & apply) or discards them. The traffic tiles stay out of the way, as on other settings pages.
- **Simpler Site navigation:** Serving, Links, Compression and Media are plain tabs; the Compression pop-up menu is gone. Compression has its own Store, Run log and Served tabs; actions such as Scan now and Edit ingress sit apart from the tabs.
- **Consistent headings:** every panel heading has an icon, as on the Settings page.
- **Motion:** overlays, sheets and toasts animate in and out, view switches slide, changed live numbers roll, theme changes cross-fade, the sidebar selection grows into place and categories fold smoothly (`motion.css`, `motion.js`). Settings › Reduce motion and the system setting turn it off.
- **One copy per port:** Corium, its feed and gate, Telemetry and Transform now hold their ports exclusively (as Corium Media already did). On Windows a second copy of a service, for example a scheduled task that started twice, could bind the same port and quietly take part of its requests; now it exits with "can't listen … is it already running?". Corium binds its admin port before anything else, so a second copy stops before it touches the database. A port the feed or gate can't get is logged and the admin UI keeps running.
- **E-mails in the error-page look:** alerts, the daily / weekly report, test messages, sign-in and new-address codes, invitations and password resets are rebuilt as e-mail-safe HTML (tables, inlined styles, dark mode, phone layout) in the style of the error pages, with the site's name and accent colour and a plain-text version. Subjects now start with the site's name instead of `[Strata]`.
- **Settings › E-mails (owner only):** change the subject, HTML, CSS and plain text of each e-mail with CodeMirror, a live preview (light / dark, wide / phone, HTML / text) on sample data, a list of the variables to insert, a test send to your own address and a reset to the default. Saved per instance in `strata.json` (`emails`); untouched parts follow the defaults. Values are escaped (`{{name}}`; `{{{name}}}` only for the lists Corium builds), subjects stay one line, and a template that fails falls back to the default (`mailtpl.py`).
- **Setup:** `setup.py --caddy <exe>` uses that Caddy instead of looking for one, and setup no longer creates a new Caddyfile inside Corium's code folder (a stray answer such as `n` used to become a file named `n` there). The installer test passes `--caddy`, so a Caddy installed on the test machine no longer shifts its answers.
- **Fix:** a `local/` folder without `__init__.py` (for example the one `tests/demo.py --dev` leaves behind) no longer stops Corium at start-up.

## GPU video encoding

- **Every GPU type:** the video encoder can be CPU, Auto, NVENC (NVIDIA), Quick Sync (Intel), AMF (AMD, Windows) or VAAPI (Intel / AMD, Linux). Hardware output is H.264 in MP4; WebM stays on the CPU. The GPU quality and preset settings apply to all of them.
- **Proven, not assumed:** each GPU gets a one-frame test encode. A build that merely lists NVENC (for example ffmpeg 9 with an NVIDIA driver older than 610) is no longer picked; the dashboard says why and what to do.
- **Right ffmpeg automatically:** when no ffmpeg path is configured, Corium tries every installed build (PATH, winget, unpacked zips in `C:\ffmpeg*`, Program Files, Chocolatey, Scoop, jellyfin-ffmpeg) and uses the first one that drives a GPU for GPU jobs.
- **Several GPUs:** all NVIDIA cards (via nvidia-smi) and every VAAPI render node are found. Jobs are spread over all usable GPUs, or pinned to one (Video settings > GPU). A GPU that fails a job rests for 10 minutes and the job moves to the next GPU, then (Auto) to the CPU.
- **Dashboard:** Tools and Video settings list each GPU with its driver, state and a hint. Settings saved in the dashboard now reach the media worker even when the Caddy config does not change.
- **GPUs encode at the same time:** the media worker runs one video per GPU in parallel instead of taking turns. **Jobs per GPU** (Video settings, `video.gpu_jobs`, 1 to 8, also per GPU id or backend) runs several on one card; GeForce drivers limit parallel NVENC sessions. A card that refuses an extra session is given fewer jobs for 10 minutes instead of being benched. CPU (WebM, software H.264) encodes and image encodes still run one at a time, and a second parallel encode only starts with CPU and memory headroom left, so security scans keep running.
- **GPU decoding:** while the video encoder is not CPU, the GPU also decodes the source (**GPU decoding**, Video settings, `video.gpu_decode`, on by default). NVIDIA jobs keep every frame on the card from decoder to encoder when the ffmpeg build has `scale_cuda`, so the CPU mostly handles audio. WebM jobs in Auto are still encoded on the CPU but decoded on the GPU. Rotated phone videos are decoded on the GPU and turned on the CPU. A format the GPU cannot decode (ProRes, 4:4:4 H.264, AV1 on older cards) is retried with CPU decoding by itself and no longer rests the GPU; job results show where each video was decoded. Images are still encoded on the CPU (no common GPU encodes AVIF or WebP).
- **Safer job leases:** every claim gets its own lease token, so a job that timed out and was picked up again (by another GPU slot or worker) can no longer be extended or completed by the stale run.

## Error pages

- **Reasons:** an optional reason when moving files to the trash, deleting them from the trash (`/api/files/trash/delete`), or on Hide / Forbid / IP / country / hotlink rules. The 403 / 404 page shows it.
- **Maintenance mode** per drive (Serving > Drives > Maintenance): its hostnames / prefix answer 503, 502, 504 or 500 with the maintenance page and *What happened?*, *Who is affected?* and a return time. The LAN can optionally keep working. API: `POST /api/serving/maintenance`.
- **Fallbacks:** every error page setting takes several paths separated by spaces; the first that exists is served.
- **More pages:** separate 500, 503, 504 and maintenance pages (503 / 504 fall back to the 502 page).
- **Assets folder** (Site > Error pages, `/_errors` by default): served on every host, so error pages render on service hostnames too.
- **New default pages:** one folder per status (404, 403, 500, 502, 503, 504, maintenance) with an `index.html` and its texts in `info.md`, shared script, style and images, light and dark mode, the Ray ID, an automatic reload once a 5xx service is back, and a *Powered by Corium (v…)* note. **Edit** next to a status installs them into the assets folder (files already there are kept) and opens that page's texts. They replace the single-file 403 / 404 / 502 pages, whose background photos came from the author's CDN; the images now ship with the pages. New installations use them by default and fall back to the old `/404/404.html` and `/404/403.html`.

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