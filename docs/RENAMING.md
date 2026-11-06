# Strata → Corium: what is renamed and what isn't yet

Since v0.5.0 the project is called **Corium** (previously **Strata**). The rename is done in steps, so that existing
installations keep running without a migration.

## Done in 0.5.0

Everything people see: the dashboard, e-mails, error pages ("Powered by Corium"), setup prompts, log and error
messages, the authenticator-app label for new set-ups, Cloudflare rule descriptions, the README and the other docs,
and the GitHub repositories (`Sanedish/corium`; GitHub redirects the old `Sanedish/strata` URLs).

## Still named Strata (on purpose, for now)

These names are stored on disk, in browsers, in scheduled tasks or in other installations' configs. Changing them
needs a migration, so they keep the old name until a later release does that in one go:

| What | Name today |
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

A future release will rename these with a migration on first start: read both the old and the new name for a while,
write only the new one, move the drive folders and the tasks, and re-issue cookies (everyone signs in once). Until then
new code keeps using the names above.
