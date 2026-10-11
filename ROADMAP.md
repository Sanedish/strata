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

## Phase 2: done (de-sloppify)

| Item | What changed |
|---|---|
| 2c Scale | New browsers start at 100 %. Auto-fit is gone (browser zoom does that). A browser that already saved a scale keeps it |
| 2b Hubs | The sidebar has 11 entries instead of 26. **Traffic** (Requests, Visitors, Content, Insights), **Security** (Blocklist, Scanners, Alerts), **Health** (Tunnel, Origins, Edge, Latency, History, System, Logs), **Files** (Files, Analyze) and **Site** (Serving, Links, Compression, Media) are one entry each, with a tab row. A hub opens the tab used last and shows the badge of a tab that needs attention. The Infrastructure toggle (`I`) is gone |
| 2a Settings | Two tabs, **Preferences** and **Account**, plus a filter that searches both. Server settings open in a sheet from the page they configure: Security › Alerts › Delivery, Blocklist › Auto-ban, Links and Files (gear button). Cloudflare is **Network › Cache**; version read-outs are on **Health › System**. The keyboard list, the duplicate Session panel and the admin callout are gone |
| 2d Styles | The 517-line `<style>` block moved from `index.html` to the top of `dashboard.css`, unchanged. The spacing tokens already existed (`--space-1` … `--space-8` in `styles.css`), so no new ones. The most common inline styles became classes: `.grow` spacers, `.hrow`, `.mt-1` … `.mt-4` (about 60 of 290). The rest are one-off widths on inputs |
| 2e Copy | Settings rows, the moved sections, em-dash asides in `control.js`, `storage.js`, `app.js` and `office.js`, and every user-visible "root" on Accounts (now **Owner**) |

How it is built, for whoever touches it next:

- `S.view` is always a leaf view, never a hub. `HUBS` in `app.js` only changes the sidebar and the header's tab row, so polling (`VIEW_REFRESH`, `pollInsights`), permissions (`VIEW_NEEDS`), `g` keys and saved pins work as before. `go(hub)` opens the hub's last tab.
- Page settings use `PAGE_SHEETS` in `control.js`. Settings is the only view in `STATIC_VIEWS`; every other view redraws on each poll, so a form inline on Alerts would lose what you typed. Sheets sit outside `#main`. Their save actions return `true`, and the sheet closes only when all of them succeeded.

Bugs found on the way and fixed:

- **Upload bounced back to Summary.** The access check required the view to be listed in the sidebar, and Upload isn't. It now asks `canSeeView()`.
- The password dialog asked for "10+ characters"; the server requires 12.

Still open from Phase 2:

- `media.js` copy (59 em dashes, mostly `—` placeholders for missing values, which are fine) and the Code page were left out of the copy pass.
- A non-number in a settings form gets the server's raw Python error ("int() argument must be…"). The settings endpoints in `strata.py` should validate and say which field is wrong.

### House style (keep using it)
- Say what something does in under 8 words. Leave out the how unless the user has to act on it.
- No feature lists joined with " · ". No em-dash asides.
- Error messages say what happened and what to do next: "Couldn't save: the file changed on disk. Reload to see it."
- One name per thing: **Owner** (never "root" in the UI), **Administrator**, **Member**, **Moderator**.

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
