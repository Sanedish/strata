# Strata roadmap

Written 2026-10-11, updated the same day after Phase 1 and again after 2c, 2d and 2e.

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

## Found on the way, not fixed yet

- `static/vendor/` (CodeMirror and the Lucide license) is caught by `vendor/` in `.gitignore`, so a fresh clone has no code editor. Anchor the pattern (`/vendor/`) and commit the folder.
- In the drive editor (and wherever a form row pairs a preset select with a text field, like the rule editor's Cache-Control), the select takes the full width and squeezes the text field to a sliver, so you can't read the current value. `.form .input, .form select { width: 100% }` beats the row's flex layout; it was like this before 2d.
- The app-code page's "Trust this browser for 30 days" checkbox does nothing: `auth.trust_token()` and `trust_ok()` exist but nothing calls them. Wire them up or drop the checkbox.
- For an account that hasn't accepted the privacy note, `guard()` answers an API call with 428 and then writes a redirect into the same response.
- On Linux, 33 Strata Media unit tests fail and 2 error, exactly the same tests on the original commit: mostly archive scanning and text extraction (`test_scan_*`), plus the sandbox and the bridge supervisor. A few depend on the network, so the count can vary by one or two.

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

### 2c. Scaling: done
The interface scale defaults to 100 %, the slider stays and auto-fit is gone: a chosen size applies on every window, like browser zoom (phones still always get 100 %). The old 130 % default was saved with every other preference, so browsers and synced accounts still on it move to 100 % once (`scale100` in the preferences).

### 2d. Spacing and styles: done
- The 517-line `<style>` block from `index.html` now opens `dashboard.css`, in the same cascade position. CodeMirror's stylesheets were linked twice; the pair that took effect is kept.
- The views' 241 static `style="..."` attributes are helper classes in the last section of `dashboard.css`. They are nested under the elements the UI renders into, so they outrank class rules exactly as the inline styles did.
- The spacing tokens already existed as `--space-1` … `--space-8` (4 to 32 px) in `styles.css`, so there is no second set. The helpers use them where the values match.
- Still inline on purpose: values from data, `display` that JS toggles, styles inside row `attrs` strings, and the `.split` column templates, which `layout.js` reads back from the attribute to make panes resizable.
- Checked with before/after snapshots of 65 states (every view, its tabs and the main dialogs) in light, dark and phone layouts, replaying the same recorded API answers: every element's computed style is identical. That caught one rule matching `span[style*="display:flex"]`, now `span:is(.d-flex, .hrow)`.

Next, if wanted: the base CSS still uses literal px, and many values sit off the 4 px scale (6, 10, 14, 18 px). Moving them onto it changes how dense the dashboard looks, so it needs its own pass with screenshots and your sign-off.

### 2e. Copy pass, page by page: done
House style for every string:
- Say what something does in under 8 words. Leave out the how ("chunked and resumable…") unless the user has to act on it.
- No feature lists joined with " · ". No em-dash asides.
- Error messages say what happened and what to do next: "Couldn't save: the file changed on disk. Reload to see it."
- One name per thing: **Owner** (never "root" in the UI), **Administrator**, **Member**, **Moderator**.

Done for every view, the sign-in pages and the server messages that reach the UI: "root" is Owner wherever it shows, Blacklist is Blocklist, Polling interval is Refresh rate, and "storage area" is storage zone. Data separators like "3 active · 12 MB" stay. Two bugs fixed on the way: the password dialog asked for 10+ characters while the server needs 12, and the account profile showed the raw role ("root").

## Phase 3: customisation

- **Code editor** already exists (Admin › Code, CodeMirror, conflict-safe saves with backups). Next: a **Custom CSS** file (`<home>/custom.css`) loaded after the built-in styles and editable from Settings › Appearance. That lets people restyle the dashboard without touching source code. About 20 lines.
- **Error pages**: done for 404 and 403. Next: a **502/503 page** for when a proxied service is down, and a **Preview** button that opens the page in a new tab.
- **Branding**: dashboard name, logo and login-page text per instance (the accent colour already exists as `instance.accent`).

## Phase 4: features dashboards like this usually have

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
