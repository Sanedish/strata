# Strata roadmap

Written 2026-10-11, updated the same day after Phase 1.

## Done in this round

| Change | Where |
|---|---|
| "Office" is now **Team** everywhere users can see it (view, permissions, messages, empty states) | `static/office.js`, `office.py`, `accounts.py`, `static/admin.js` |
| The "administrative" team flag is now **Moderator**, so it can't be confused with the Administrator role | same |
| Sidebar regrouped by task: Overview, Traffic, Files, Site, Security, Infrastructure, Admin | `static/app.js` `NAV_GROUPS` |
| Infrastructure is collapsible (click its heading) and collapsed for new users: 18 entries instead of 25 | `static/app.js`, `static/index.html` |
| Upload removed from the sidebar (the header button opens it from every page); duplicate gauge button removed from the header | same |
| Every page subtitle rewritten as a short label; duplicate icons fixed; "Blacklist" is now "Blocklist"; "Web IDE" is now "Code" | `static/app.js` `VIEWS` |
| Configuration pages (Serving, Blocklist, Links, Alerts, Network) no longer show traffic tiles, time ranges or the request filter | `static/app.js` `WORK_VIEWS` |
| Sign-in says "Sign in" (not "Unlock"); account setup shows one sentence and a link instead of a privacy wall of text | `static/login.html`, `static/enroll.html` |
| **Error pages:** 404 and 403 side by side in Serving › Site, each with an **Edit** button that creates the page from a starter template and opens it in the editor (the 403 setting existed but couldn't be saved from the UI) | `static/control.js`, `rules.py` |
| `.gitignore` keeps secrets (`strata.json`, `telemetry.json`) and your database (`data/`) out of any repository | `.gitignore` |

Internal names (`office.py`, `/api/office/*`, the `office.*` permission keys) are unchanged on purpose. The permission keys are stored in each account's database row, so renaming them needs a migration. Users never see them.

---

## Phase 1: done (ready to publish)

| Item | What changed |
|---|---|
| Git | The repository has its first commits. `strata.json`, `data/`, `generated/`, `backups/` and `vendor/` are ignored |
| Personal details | Domains, the owner's handle, LAN addresses, NAS paths and machine paths replaced with `example.com`, documentation ranges and `<home>` / `<install folder>`. Tests take tool paths from the environment (`STRATA_CADDY`, `STRATA_SAMPLE_PHOTO`) |
| Basics | `LICENSE` (MIT), `README.md` with screenshots from the demo instance, `SECURITY.md` (private reports through GitHub) |
| Installer | `setup.py` / `setup.cmd`: packages, site, Caddy (backup, import line, validation, rollback), Cloudflare Tunnel (backup, ingress rule, DNS route, optional new tunnel), keys, owner, `strata.json` (backup), then a Task Scheduler task (Windows) or systemd unit (Linux). `--check`, `--no-service`, `--uninstall`, `--home`. Safe to re-run |
| First run in the browser | With no owner, `/login` sends a local browser to `/setup` (loopback only, gone once an owner exists). It also asks for the Resend key when mail isn't set up, because sign-in needs it |
| Platform | Windows first. `requirements.txt` replaces the committed `vendor/`; the installer fills `vendor/` with pip, which also makes Linux possible. The Linux path is written but untested |
| Tests | `tests/run_all.py` builds a throwaway instance with a stub Caddy, seeds accounts and runs every suite in order (first-run setup, security, permissions, Team, sign-in, installer, auto-ban ranges, SSRF, Strata Media). All pass on a fresh machine. `tests/demo.py` starts a demo with a week of made-up traffic |

Bugs found on the way and fixed:

- **Inviting an account could hang for 30 s or more.** `provision_user_storage()` called `files.drives()`, which asks Windows about every drive letter; a sleeping network drive blocks that. It now uses the new `files.served()`, which only looks at Strata's own drives. The admin drive picker still lists every letter.
- **Range auto-bans crashed.** `rules.ban_all()` appended each new /24 ban to the list it was looping over and then tried to widen `x.x.x.0/24/24`. The row hook failed for that batch of requests. Covered by `tests/autoban_test.py`.
- Media tests had drifted from the code: the audio extensions in `media/config.py` and `media_rules.py` disagreed (`alac amr wv ape` added to config), and the bridge test database lacked the `audit_event` table.

Still open from Phase 1:

- **The Linux path needs one real run** (a VM or `docker run python:3.12`) of `setup.py` and `tests/run_all.py`.
- **The service as SYSTEM needs one real run as administrator.** The task definition was checked by registering it under a normal account; the boot trigger and SYSTEM account were not.
- **Decide whether sign-in should work without e-mail.** Today every sign-in needs a code sent through Resend, so a new user must have a Resend account and a verified sender domain before they can sign in at all. Options: TOTP as an alternative second factor for the owner, or e-mail codes only when mail is configured.

## Phase 2: de-sloppify (UX)

### 2a. Break up the Settings page (biggest win)
Settings mixes personal preferences with server configuration. Most sections belong on the page they configure:

| Settings section now | Moves to |
|---|---|
| Appearance, Interface scale, Navigation, Vitals strip, Data & refresh, Time & notifications, Preferences | **Settings** (stays: your own preferences) |
| Security (password, 2FA, sessions), Account profile | **Settings › Account** tab |
| Notifications (Resend key, recipients, summary e-mail) | **Alerts** › Delivery tab |
| Uploads & versions, Smart-Sorting | **Files** › a gear button opening a settings panel |
| Auto-ban | **Blocklist** › Auto-ban tab |
| Cloudflare (edge blocklist, purges) | **Network** › Cache tab |
| Share links (lifetime, abuse guard) | **Links** › Settings tab |
| Session & system | **System** |
| Keyboard list | Delete it; the `?` overlay already shows it |
| "Root & staff administration" callout | Delete it; Accounts is in the sidebar |

How: each section is already a function pushed into `SETTINGS_PANELS`. Moving one means calling that function from the destination view instead. Settings gets two tabs (Preferences, Account) and a filter box at the top.

### 2b. Merge pages into tabbed pages
The sidebar still overflows on a 900 px-tall screen. Merging related pages into one page with tabs takes it to about 11 entries:
- **Traffic**: Requests · Visitors · Content · Insights
- **Health** (replaces Infrastructure): Tunnel · Origins · Edge · Latency · History · System · Logs
- **Security**: Blocklist · Scanners · Alerts

How: a small `hub(view, tabs)` helper renders a tab row and calls the existing view function for the selected tab. The tricky part is per-view polling keyed on `S.view` (`pollInsights`, `VIEW_REFRESH`, `VIEW_NEEDS`): it has to be keyed on the active tab instead. About half a day, with a click-through of every tab afterwards.

### 2c. Scaling
Interface scale defaults to **130 %**, then auto-fit shrinks it on smaller windows, so the same page looks different from one machine to the next. Proposal: default 100 %, keep the slider, and drop auto-fit (browser zoom already does this). **Needs your decision**, because it changes how your own dashboard looks.

### 2d. Spacing and styles
Styles live in three places (`styles.css`, `dashboard.css` and ~550 lines inline in `index.html`) plus dozens of `style="..."` attributes in the JS. Plan: move the inline block into `dashboard.css`, define spacing tokens (`--s1` 4px … `--s6` 32px), and replace one-off `style="width:180px"` and `gap:6px` values with classes. Do this page by page with before/after screenshots, so nothing shifts by accident.

### 2e. Copy pass, page by page
House style for every string:
- Say what something does in under 8 words. Leave out the how ("chunked and resumable…") unless the user has to act on it.
- No feature lists joined with " · ". No em-dash asides.
- Error messages say what happened and what to do next: "Couldn't save: the file changed on disk. Reload to see it."
- One name per thing: **Owner** (never "root" in the UI), **Administrator**, **Member**, **Moderator**.

Biggest offenders by count: `control.js`, `storage.js`, `media.js`, then the Settings rows in `app.js`.

## Phase 3: customisation (done)

| Item | What changed |
|---|---|
| **Branding** | Settings › Appearance › Branding (administrators): dashboard name (sidebar, tab title, sign-in pages), a line of sign-in text, and a PNG logo up to 256 KB. Name and text live in `strata.json` (`instance.brand`, `instance.login_text`), the logo in `<home>/brand.png` |
| **Custom CSS** | Same sheet. Saved to `<home>/custom.css` and loaded after the built-in styles on the dashboard and the sign-in pages. A built-in empty `static/custom.css` is served when there is none |
| **502 page** | Serving › Site has a third error page for 502, 503 and 504 (a proxied service, Transform or the gate is down). Empty keeps Caddy's plain text |
| **Preview** | Each error page has a Preview button that opens it in a new tab (sandboxed, like any file preview) |

The logo is PNG only on purpose: an SVG served from the dashboard's own origin could run script. Edits are audited (`branding`) and covered by `tests/sec_regress.py`.

## Phase 4: features dashboards like this usually have (done)

| Item | What changed |
|---|---|
| **Backup and restore** | System › Backup (owner only): **Download backup** gives a zip with `strata.json` minus every key, password, token, TOTP and webhook, plus a consistent snapshot of the database. **Restore…** checks the zip (integrity check, Strata tables), copies the database in through SQLite's backup API while Strata runs, merges the settings over the current ones (secrets on this machine stay), migrates older tables and re-applies the Caddy config. New owner-only capability `system.backup`. Code in `backup.py` |
| **Alert webhooks** | Alerts › Delivery › Webhooks (owner only, up to 5): Discord, Slack and ntfy are recognised by host name, anything else gets JSON with `title` and `message` (Gotify, Home Assistant, n8n). Alerts and the daily or weekly summary go to every channel; one failing channel doesn't hold up the others. The URLs carry their own secret, so only host and format are ever sent back to the browser. LAN targets are allowed on purpose (a self-hosted ntfy) |
| **Version and update check** | `core.VERSION` (now 0.1.0) shows in the sidebar footer and System › Versions, signed-in users only. Once a day Strata reads the latest release from `instance.update_repo` (`owner/name` on GitHub) and shows "vX available" with a link. Empty until the repository is public, so nothing is fetched |
| **Config preview** | Save & apply on a drive, a rule and Serving › Site first shows the diff of the Caddy config the change would produce. The change is rendered inside a database transaction that is rolled back. No diff, no dialog |

Still open from Phase 4:
- Set `instance.update_repo` (in `core.py` DEFAULTS) once the GitHub repository exists, and tag releases to match `core.VERSION`.
- Restore says "restart Strata to finish": in-memory state (sessions, the compressor's map) refreshes on restart. A restart button needs the service run as SYSTEM tested first (Phase 1).

Based on how comparable self-hosted panels are reviewed (Nginx Proxy Manager, Coolify) and common checklists. These sources are mostly blog posts and guides, so treat them as orientation, not research.

Already in Strata: accounts with fine-grained permissions, 2FA, an audit log, API keys, e-mail alerts, DNS management, a blocklist with auto-ban, a raw config view with history and rollback, signed links.

Missing, in suggested order:
1. **Backup and restore**: a button that downloads `strata.json` (with secrets removed) plus a database snapshot as a zip, and a way to restore one. This is the most common ask for self-hosted tools.
2. **Alert webhooks** (Discord, Slack, ntfy, generic URL) next to e-mail. Many self-hosters don't run a mail sender.
3. **Version display and update check**: show the version in the sidebar footer and a notice when a newer release exists.
4. ~~**One-command install**~~: done in Phase 1 (`setup.py`). Docker Compose could follow once Linux is tested.
5. **Config preview before apply**: show the diff of the Caddy config before "Save & apply". History and rollback already exist; this adds the "before".

---

### Sources
- [Caddy vs Traefik vs Nginx Proxy Manager, 2026](https://www.pkgpulse.com/guides/caddy-vs-traefik-vs-nginx-proxy-manager-reverse-proxies-2026)
- [Caddy vs Traefik vs Nginx Proxy Manager](https://aicybr.com/blog/caddy-vs-traefik-vs-nginx-proxy-manager)
- [Coolify proxy overview](https://coolify.io/docs/core/networking/proxy/overview)
- [Coolify vs Dokploy](https://www.hostinger.com/ng/tutorials/?p=117422)
- [Settings UI design](https://setproduct.com/blog/settings-ui-design)
- [Settings best practices (Uxcel)](https://uxcel.com/lessons/settings-best-practices-572)
- [Box Admin Console settings redesign](https://support.box.com/hc/en-us/articles/360052052734)
- [GitLab: standardizing settings UI](https://gitlab.com/gitlab-org/gitlab/-/issues/275969)
- [Packaging checklist (Hack Club)](https://sterndocs.hackclub.dev/raw/cloudfall/packaging)
- [Keywarden alpha release notes](https://git.techniverse.net/scriptos/keywarden/releases/tag/v0.1.0-alpha)
- [OpenSSF best practices](https://www.bestpractices.dev/zh-CN/projects/12931)
