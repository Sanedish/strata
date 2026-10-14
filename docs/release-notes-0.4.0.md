# Strata 0.4.0

Optional bot protection, and the first steps towards a tested Linux install.

## New

- **Bot protection (optional, off by default).** A new **Bot challenge** access rule makes browsers solve a short
  proof-of-work puzzle before they get a page, which slows scrapers down. It uses
  [Anubis](https://github.com/TecharoHQ/anubis) (MIT, by Techaro), which Strata doesn't bundle. A new **Security ›
  Challenger** page (owner only) sets it up in one click: it downloads Anubis 1.28.1 from github.com (SHA-256 checked),
  creates the key and policy, registers a start-up task, starts it and switches protection on once it answers. Every
  step is also a button of its own, and **Challenge all pages** adds the rule (or use **Serving › Rules**). Until you
  switch it on, nothing changes, and the generated Caddy config is identical to 0.3.1.
  - People opening a page, and anyone opening a gallery folder, are challenged. Link-preview crawlers, signed links,
    paths an **Allow** rule covers, `/.well-known/`, `robots.txt`, favicons and Bearer-key calls to `/api/` are not.
    **Also challenge direct file requests** is a separate checkbox, with a warning: it breaks curl, download managers,
    media players, Range requests and hotlinked images.
  - Strata won't switch it on while Anubis doesn't answer, and won't stop it while it is on (challenged pages would
    answer 502). The page also shows what Anubis has judged since it started.
  - Anubis is told Caddy's own client address, so a forged `X-Real-IP` or `X-Forwarded-For` changes nothing, and a pass
    cookie only works from the address that solved the puzzle.
  - Cloudflare's cache would hand out cached files before Anubis ever saw the request, so Strata adds one managed Cache
    Rule for the challenged paths (the **Cache Rules** permission link previews already use) and removes it again when
    protection is off.
  - Each instance gets its own port, signing key (`.private/anubis.key`, never in `strata.json` or a log) and policy
    file. Puzzle pages leave the traffic statistics, and a failed puzzle never triggers an auto-ban by itself.
- **Settings › About** credits Anubis; its licence is in `third_party/anubis/` and goes into the folder of every download.

## Dashboard

- **Analyze** shows charts instead of the block diagram: a donut of the current folder by file type, the largest folders
  as columns stacked by type (click one to open it), and the folder's contents beside them. **Age & sizes** are column
  charts and **Drives** has a used/free donut per drive. One colour per file type, with values on every chart.
- **Health** (Tunnel, Origins, Latency, History, Edge, System) and **Security** use the same layout as Requests: one
  toolbar with the actions and the numbers' context, then the content. System, Accounts and the code editor lost their
  rounded cards and page-coloured gaps.

## Linux

- The test suites and the demo now run on Ubuntu in CI (`.github/workflows/linux.yml`), with a real Caddy.
- **Restarting the tunnel** from the dashboard works on Linux too: `instance.tunnel_restart` of kind `service` runs
  `systemctl restart`.
- A sample systemd unit for Anubis is in `docs/anubis/strata-anubis.service`.

## Tests and tooling

- `tests/anubis_test.py` checks the config, policy and key files and the download (fake archives: a wrong checksum,
  a hostile archive path and a redirect to another host are refused), then sends real requests through a real Caddy;
  with an Anubis binary available (`STRATA_ANUBIS`) it runs the same requests against the real thing and solves its puzzle.
- `tests/anubis_demo.py` starts a small site behind a real Caddy and a real Anubis to open in a browser, with `curl`
  lines for what a scraper gets.
- `.private/` is now in `.gitignore`.

## Good to know

- Bot protection slows scrapers; it is not access control. By default only navigations are challenged, so a client
  that asks for `Accept: */*` still gets the file unless the direct-file checkbox is on.
- If Anubis is down, challenged paths answer 502 until it is back. After a host name, difficulty or program change,
  restart Anubis from the same settings sheet.
- After the puzzle, the redirect keeps only the first `?parameter` of the address.
- Tested with Caddy 2.10.2 and Anubis 1.28.1 on Windows, and the download against github.com. Not yet verified: the
  Cloudflare cache-rule expression, registering the start-up task from the dashboard on a real machine (a demo
  instance registers nothing), and the Linux install.

## Upgrading

Nothing to do. Replace the code and restart the Strata service.
