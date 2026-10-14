# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the repository's **Security** tab and choose
**Report a vulnerability**. Don't open a public issue for them.

Include what you found, how to reproduce it, and what an attacker could do with it. A proof of concept against your
own instance helps; please don't test against anyone else's.

You'll get an acknowledgement within a week. Fixes go into `main` first, and the report is credited in the fix
unless you'd rather stay anonymous.

## Supported versions

Only the latest commit on `main` is supported. There are no release branches yet.

## Scope

In scope: anything in this repository, including the installer, the dashboard and its API, the login gate,
Strata Transform, Strata Media and Strata Telemetry.

Worth knowing before you report:

- The dashboard listens on loopback only. Accounts that can change more than files can sign in only from private
  address ranges (loopback, LAN, CGNAT/VPN), so "an administrator on the LAN can do X" is usually by design.
- The owner account can edit Strata's own source code from the dashboard (Admin › Code). That is a feature, not a
  privilege escalation.
- Caddy, cloudflared, Cloudflare, Resend and Anubis are separate projects; report their bugs to them. Strata's own
  wiring of Anubis (the generated Caddy config, the policy and key files, the settings) is in scope.
- Bot protection (Anubis) slows scrapers; it is not access control. A client that sends `Accept: */*` is not challenged
  unless "also challenge direct file requests" is on, and a visitor who solves the puzzle gets the file. Use a password,
  a signed link or a login for anything private.

## Running Strata safely

- Keep `strata.json` private. It holds the Cloudflare token, the mail credentials (SMTP password or Resend key) and the signing secrets, and it is
  listed in `.gitignore`.
- Give the Cloudflare API token only the permissions the installer lists, scoped to your zone.
- If you use bot protection, keep `.private/anubis.key` (the signing key) as private as `strata.json`, and run Anubis on
  loopback only: the settings accept nothing else. Only the owner can change them, because they download and register a
  program to run. The Challenger download is https to github.com hosts only (also across redirects), size-limited and
  checked against the SHA-256 GitHub lists for the file; the PGP signature next to it is not checked, so a compromised
  release would pass. Only `anubis(.exe)` and its licence are unpacked, read by name. Prefer your package manager's copy
  and set its path under Challenger › Settings if that matters to you.
- Don't publish the dashboard port through the tunnel. Use your LAN, a VPN, or Tailscale to reach it from elsewhere.
