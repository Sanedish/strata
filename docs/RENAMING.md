# Strata → Corium: what is renamed and what isn't yet

Since the release of v0.5.0, our project is now called **Corium** (formerly **Strata**) in an attempt to be more unique.
To protect currently running instances, we are implementing this naming change in **steps**;

## What's been renamed in 0.5.0?

All the visual parts, this includes; the dashboard, e-mails, error pages (now featuring a "Powered by Corium" + version tag for stock error screens), setup prompts, log and error
messages, as well as authenticator-app labels for new set-ups, Cloudflare rule descriptions, the README file and our other docs,
as well as our GitHub repositories (Links using the old `Sanedish/strata` URLs will automatically be forwarded to `Sanedish/corium`).

## What's still Strata (for now)?

Any names that are stored on disk, in browsers, in scheduled tasks or in other installation configs are still referring to "Strata", or "STRATA".
This is done purposefully as changing these would involve user migration, therefore they are kept until future releases;

| Item | Current Name |
| --- | --- |
| Entry point and instance config | `strata.py`, `strata.json` |
| Databases | `data/strata.db` (and `media.db` beside it) |
| Environment variables | `STRATA_HOME`, `STRATA_*` secrets in `data/.env` (e.g. `STRATA_SIGN_SECRET`) |
| HTTP headers | `X-Strata` (CSRF), `X-Strata-*` between Caddy, Transform, Media and the gate |
| Cookies | `strata_*` (sign-in, trust, gate), `dev_strata_*` |
| Folders on drives | `.strata-trash`, `.strata-versions`, `.strata-copy` |
| Caddy variables and meta tags | `strata_reason`, `strata_media_*` |
| Scheduled tasks / systemd units | `Strata`, `Strata <id>`, `Strata Tunnel`, `Strata <id> Anubis` / `strata`, `strata-*` |
| Python identifiers | e.g. `strata.Handler`, `StrataTransform` in tests |

## Plan for the config rename

A list of future releases will rename these with a migration on first start. This migration will read both the old and the new name for a while,
write only the new one, move the drive folders and the tasks, and re-issue cookies (requiring a new sign-in on all users).
This will not happen for a while as that'd involve a lot of work and time I cannot allocate at the time being, and the current system works well at the scale the project has as of writing this.
