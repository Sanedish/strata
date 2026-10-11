# Strata roadmap

Written 2026-10-11, updated the same day after Phase 1, after 2c, 2d and 2e, and after the release fixes.

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
| Git | The repository has its first commits. `strata.json`, `data/`, `generated/`, `backups/` and the top-level `vendor/` (Python packages) are ignored; `static/vendor/` (CodeMirror, icon licenses) is committed |
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

- **The Linux install needs one real run** (a VM or `docker run python:3.12`) of `setup.py`, with its systemd units and Caddy and cloudflared from their packages. `tests/run_all.py` passes on Linux now (see "Found on the way" below).
- **The service as SYSTEM needs one real run as administrator.** The task definition was checked by registering it under a normal account; the boot trigger and SYSTEM account were not.
- ~~**Decide whether sign-in should work without e-mail.**~~ Done: the owner can use an authenticator app instead of the e-mailed code (see "Sign-in without e-mail" below). Other accounts still need e-mail.

## Sign-in without e-mail: done

| Change | Where |
|---|---|
| The owner can sign in with an authenticator app instead of the e-mailed code. With the app set up, sign-in is the password plus the app code; the e-mailed code is skipped | `strata.py` `login()` |
| First-run setup (`/setup`) and the installer offer the app first; e-mail and a Resend key are needed only for e-mailed codes. Both show the recovery codes once | `static/setup.html`, `static/setupdone.html`, `setup.py` |
| `python auth.py --totp` sets up the app from the server, `--totp off` removes it: the way back in for a locked-out owner | `auth.py` |
| A half-finished sign-in remembers which code it waits for, and each code page accepts only its own. Before, `/login/2fa` accepted any pending sign-in, so posting there skipped the e-mail step | `strata.py` |
| The app can't be turned off while e-mail isn't set up, and e-mail can't be removed while the owner has no app: either would lock the owner out | `strata.py` |
| Sign-in pages no longer scroll sideways on a phone: their cards were wider than a 390 px screen | `static/login*.html`, `static/setup*.html` |

Other accounts still get e-mailed codes, so inviting people still needs Resend.

## Found on the way: fixed

| Problem | Fix | Where |
|---|---|---|
| No code editor on a fresh clone: `vendor/` in `.gitignore` also matched `static/vendor/`, so CodeMirror and the Lucide license never reached the repository | The pattern is anchored (`/vendor/`) and `static/vendor/` holds CodeMirror 5.65.21. `index.html` also loads `addon/fold/xml-fold`, which `matchtags` needs: without it the editor showed no lines | `.gitignore`, `static/vendor/`, `static/index.html` |
| The preset select next to Cache-Control and Cloudflare cache (drive editor, rule editor) took the whole row and left the text field 18 px wide | The select is a compact "presets…" menu that fills the field in and resets. Text inputs in sheets also lost an 8 px margin meant for stacked dialogs, which put them out of line with the selects and buttons beside them | `static/control.js`, `static/dashboard.css` |
| "Trust this browser for 30 days" did nothing | It sets a cookie only the sign-in pages receive, and the owner's next sign-ins from that browser skip the app code. The password is still checked. A new password or a new app ends the trust | `strata.py`, `auth.py` |
| Before the privacy note is accepted, `guard()` sent the 428 and then a redirect in the same response, and answered POST and PUT before reading the body (as did the two local-network refusals), which Caddy reports as a 502 | One answer, after the body is read | `strata.py` |
| On Linux, 33 Strata Media unit tests failed and 2 errored | All 438 pass (16 skipped: Windows-only features, Defender, Caddy not installed, the opt-in sample photo). Three real bugs: every member of a zip written by Python was flagged as a "device or special file" archive bomb, `safe_join()` let `a\..\..\x` through, and `config.resolve()` refused every file under a `//server/share` root. The two bridge failures came from the demo using the test ports: it moved to 1848x, and a plain kill now stops its server too | `media/extract.py`, `media/sandbox.py`, `media/config.py`, `tests/demo.py` |
| New browsers got Sharp corners on the sign-in pages; the default is Soft | `boot.js` uses the same default as the dashboard | `static/boot.js` |
| Serving › Site and Test stayed two columns on a phone | The narrow-screen rule wins over the column helper | `static/dashboard.css` |

Still open: the same `commonpath` comparison as in `config.resolve()` is in `files.py` and `strata.py`, so on POSIX they refuse every file under a `//server/share` root. That fails closed, and on Linux a share is mounted at a normal path anyway, so it stays as is.

## Phase 2: done (de-sloppify)

| Item | What changed |
|---|---|
| 2c Scale | New browsers start at 100 %. Auto-fit is gone (browser zoom does that). Browsers and synced accounts still on the old 130 % default move to 100 % once (`scale100` in the preferences); any other saved scale is kept |
| 2b Hubs | The sidebar has 11 entries instead of 26. **Traffic** (Requests, Visitors, Content, Insights), **Security** (Blocklist, Scanners, Alerts), **Health** (Tunnel, Origins, Edge, Latency, History, System, Logs), **Files** (Files, Analyze) and **Site** (Serving, Links, Compression, Media) are one entry each, with a tab row. A hub opens the tab used last and shows the badge of a tab that needs attention. The Infrastructure toggle (`I`) is gone |
| 2a Settings | Two tabs, **Preferences** and **Account**, plus a filter that searches both. Server settings open in a sheet from the page they configure: Security › Alerts › Delivery, Blocklist › Auto-ban, Links and Files (gear button). Cloudflare is **Network › Cache**; version read-outs are on **Health › System**. The keyboard list, the duplicate Session panel and the admin callout are gone |
| 2d Styles | The 517-line `<style>` block moved from `index.html` to the top of `dashboard.css`, unchanged. The spacing tokens already existed (`--space-1` … `--space-8` in `styles.css`), so no new ones. The most common inline styles became classes: `.grow` spacers, `.srow`, `.smt-1` … `.smt-4`. A second pass from the release-fixes branch turned most of the remaining static `style="..."` attributes into helpers nested under `#app` (the last section of `dashboard.css`, e.g. `.hrow`, `.mt-8`, `.fill`); the first pass's names were changed to `.srow` / `.smt-N` so the two sets don't clash |
| 2e Copy | Settings rows, the moved sections, em-dash asides in `control.js`, `storage.js`, `app.js` and `office.js`, and every user-visible "root" on Accounts (now **Owner**) |

How it is built, for whoever touches it next:

- `S.view` is always a leaf view, never a hub. `HUBS` in `app.js` only changes the sidebar and the header's tab row, so polling (`VIEW_REFRESH`, `pollInsights`), permissions (`VIEW_NEEDS`), `g` keys and saved pins work as before. `go(hub)` opens the hub's last tab.
- Page settings use `PAGE_SHEETS` in `control.js`. Settings is the only view in `STATIC_VIEWS`; every other view redraws on each poll, so a form inline on Alerts would lose what you typed. Sheets sit outside `#main`. Their save actions return `true`, and the sheet closes only when all of them succeeded.

Bugs found on the way and fixed:

- **Upload bounced back to Summary.** The access check required the view to be listed in the sidebar, and Upload isn't. It now asks `canSeeView()`.
- The password dialog asked for "10+ characters"; the server requires 12.

Still open from Phase 2:

- `media.js` copy (59 em dashes, mostly `—` placeholders for missing values, which are fine) and the Code page were left out of the copy pass.
- ~~A non-number in a settings form gets the server's raw Python error.~~ Done (0.3.0): `strata.num()` answers 400 with the field's name and range.

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
| **Version and update check** | `core.VERSION` shows in the sidebar footer and System › Versions, signed-in users only. Once a day Strata reads the latest release from `instance.update_repo` (`Sanedish/strata`) and shows "vX available" with a link |
| **Config preview** | Save & apply on a drive, a rule and Serving › Site first shows the diff of the Caddy config the change would produce. The change is rendered inside a database transaction that is rolled back. No diff, no dialog |

Still open from Phase 4:
- ~~Set `instance.update_repo` once the GitHub repository exists.~~ Done (0.3.0). Each release needs a GitHub release whose tag matches `core.VERSION`.
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
