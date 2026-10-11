# Strata Media: UI hooks (`static/media.js`)

The Media view is complete in `static/media.js`, and every piece of logic lives there. Integration needs **one
line in `index.html`** and nothing else in the shared front-end files. The server side (`strata.py` dispatching
`/api/media/*` to `media_bridge.api_get` / `api_post`, DESIGN 13.2) is part of the integration step. Until that
lands, the view shows a calm "Not deployed" page.

## 1. `index.html`: the only shared-file edit

Make a small anchored Edit: re-read `index.html` first and never rewrite the whole file. Add the tag after
`control.js` and **before** `layout.js`, which must stay the last script (DESIGN 13.3).

Anchor (the end of `<body>` today):

```html
<script src="control.js"></script>
<script src="layout.js"></script>
```

Replace with:

```html
<script src="control.js"></script>
<script src="media.js"></script>
<script src="layout.js"></script>
```

Load order matters: `media.js` uses globals from `app.js` (required) and, optionally, `storage.js` (`loadDrives`,
`D.drives`) and `control.js` (`D.serv`) for drive names. If `app.js` is missing, the file does nothing, so it can
never take the page down.

### The nav entry: no HTML

`<nav id="nav">` has no static markup. `app.js` `renderNav()` rebuilds it on every render from `NAV1` / `NAV_S`
/ `NAV_C` / `NAV2`. `media.js` adds the single nav entry itself with `NAV_C.push('media')`, so it shows in the
**Control** group after Alerts. Its badge is the count of flagged + error files, or `down` / `open` / `upgrade`,
or `off` when switched off (never an alert). It also appears in the Ctrl-K palette as "Go to Media". Keys 1-9
only reach the first nine views, so there is no number shortcut. **Do not** add a `nav-item` button to
`index.html`: the next `renderNav()` would wipe it.

## 2. What `media.js` registers (existing extension points only)

| extension point | use |
|---|---|
| `VIEWS.media`, `NAV_C`, `VIEWFN.media` | title/subtitle, nav entry (Control group), view function |
| `STATIC_VIEWS.add('media')` | app.js's 1 s poll does not redraw the view; media.js redraws with `render(true)` after its own fetches (skipped while text is selected or a drag is running, then caught up on pointerup) |
| `VIEW_REFRESH.media` | full reload when the view is opened |
| `NAV_BADGES` | badge described above |
| `ACT.md*`, `MENUS.mdHold` | actions via app.js's `data-act` click delegation; right-click menu on hold rows |
| `S.md`, `D.md` | view state / data (no top-level globals: everything is inside one IIFE) |
| `<style id="md-css">` | view CSS, injected once |
| localStorage `strata:media` | hold filter, event kind, event window (removed by Settings, Reset preferences) |
| layout.js pane key `media:360` | width of the hold-details aside (`.split` with inline `1fr 360px`) |

The view reuses these app.js helpers: `esc`, `enc`, `get`, `post`, `fmt`, `share`, `segs`, `sparkSvg`, `gauge`,
`barList`, `table`/`cell`/`hcell`, `loading`, `ask`, `note`, `copy`, `render`, `mainBusy`, `store`. It uses the
existing classes too (`.ins`, `.kpis`, `.panel`, `.tbar`, `.pill`, `.seg-row`, `.split`/`.aside`, `.set-row`,
`.setup`, `.kv`, `.bl`, `.acc`, `.logline`). Nothing needs to change in `app.js`, `storage.js`, `control.js`,
`layout.js` or `styles.css`.

Layout conventions (DESIGN 13.3) the view follows:

* Panels sit in an `.ins` grid, which already has `grid-auto-rows: max-content`. Media panels lift the 460 px
  panel cap so the holds and jobs tables are not squeezed; long lists scroll inside boxes sized with
  `calc(N * var(--vh))`, never raw `vh`.
* Controls use the shared heights: the toolbar filter is `--ctl-sm`; settings rows use `.set-row` inside an
  inline-size container, so the control wraps under its label when the panel is narrow.
* Confirmations go through app.js `ask()`, whose dialog is capped at 88 % and scrolls inside.
* At 1100 px and below, the grid is one column (the existing breakpoints).

The holds columns are ordered so that State, Severity, Path, Findings, Size, Scanned and the action buttons fit
the ~1024 css px `#main` at 130 % zoom. The drive column comes last.

## 3. CSP

The view works under the existing `strata.py` CSP (`script-src 'self'`, `style-src 'self' 'unsafe-inline'`)
without changes:

* No inline scripts, no `on*` attributes, no `eval` / `new Function` / string timers, and no direct
  `innerHTML` writes. The view returns HTML strings to app.js `render()`, like every other view.
* The injected `<style>` element is allowed by `'unsafe-inline'`, the same as `index.html`'s own `<style>`.

Paths, findings, event kinds/details, drive names and review notes are untrusted, because anyone can upload a
file. They reach the DOM only through `esc()` (or app.js's escaping `table()` cells, `ask()` and `note()`). Count
maps built from server keys have no prototype.

## 4. Server contract (`media_bridge.api_get(user, path, q)` / `api_post(user, ip, path, body)`)

The endpoints are exactly DESIGN 13.2. Errors come back as `{"error": "..."}` with a 4xx/5xx status, and
app.js `get()`/`post()` show that text. The view reads every field defensively: a missing or oddly typed field
renders as "—" and never throws. The shapes below are what it reads first.

### 4.1 Not deployed (media.enabled = false is the default kill switch)

* **Bridge not hooked yet:** `/api/media/*` falls through to `static()`, which answers
  `404 {"error": "not found"}`. The view shows "Not deployed · the bridge is not hooked"; there is no badge and
  no background polling.
* **Switched off:** `GET /api/media/status` should answer
  `200 {"enabled": false, "now": <epoch>, "reason": "media pipeline disabled", "tools": sandbox.tools(conf)}`.
  `tools` is optional; when present it is shown as a pre-flight check. `GET /api/media/policy` may keep
  answering, since a dry run is useful before switching on. The page has a "Preview the file policy" button, and
  a refusal is shown calmly. Every other endpoint should answer `409 {"error": "media pipeline disabled"}`.
  The view also accepts a 409/503 on status whose error text names media/pipeline together with
  disabled/switched off/not deployed/not enabled. In the switched-off state the badge reads `off` (no alert),
  no lists are fetched, and no action buttons are shown.

### 4.2 `GET /api/media/status` (pipeline on)

Called every 5 s while the Media view is open, and every 60 s elsewhere for the badge. **It must be cheap:** no
fidx walk and no Cloudflare call. Read cached values (`/_stats` of media.py, `meta.worker_heartbeat`,
`store.*_counts`, the capacity advisor's last result, the edge state the bridge stores every 6 h).

```json
{
  "enabled": true,
  "now": 1790612345.6,
  "version": "1",
  "error": null,
  "processes": {
    "media":  {"up": true, "pid": 1234, "uptime": 3600, "restarts": 0, "listen": "127.0.0.1:8084", "error": null},
    "worker": {"up": true, "pid": 1240, "heartbeat_age": 3.1, "paused": null, "restarts": 0, "error": null}
  },
  "breaker": {"state": "closed", "reason": null, "forced": null, "forced_for": null, "open_for": 0,
              "cooldown": 15, "trips": 0, "slots": 2, "busy": 0, "waiters": 0, "wait_p90_ms": 0},
  "monitor": {"cpu": 12.0, "cpu_ewma": 10.4, "mem_avail_mb": 4200, "mem_pct": 48, "ts": 1790612345.1},
  "tools": {"ffmpeg": null, "ffprobe": null, "7z": null, "tesseract": null,
            "mpcmdrun": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18...\\MpCmdRun.exe",
            "clamscan": null, "clamdscan": null, "pypdfium2": null},
  "cache": {"bytes": 0, "files": 0, "disk_free": 83000000000, "disk_total": 250000000000, "max_bytes": 32212254720},
  "negotiation": {"configured": "auto", "effective": "redirect", "checked": 1790600000, "error": "",
                  "edge": {"state": "no permission",
                           "rules": {"strata_media_avif": false, "strata_media_webp": false, "strata_media_webm": false},
                           "error": ""},
                  "caps": {"transform": {"ok": false, "error": "...", "need": "Zone › Transform Rules › Edit"},
                           "purge": {"ok": false, "error": "...", "need": "Zone › Cache Purge › Purge"}}},
  "counts": {"verdicts": {"clean": 1480, "flagged": 3, "held": 1, "error": 2, "pending": 57, "released": 4},
             "jobs": {"scan": {"queued": 57, "running": 1, "done": 1500, "failed": 2}},
             "oldest": {"scan": 1800.0, "image": null, "video": null}},
  "capacity": {"ts": 1790612100, "advice": [{"resource": "cpu", "level": "upgrade",
               "evidence": "host_cpu p95 92 % (1 h), breaker open 14 %", "recommendation": "add 2 vCPU (6 -> 8)"}]},
  "events_24h": {"bypass.breaker_open": 12, "tool.missing": 3},
  "savings": {"count": 900, "beneficial": 812, "bytes": 410000000, "src_bytes": 5300000000, "saved": 4890000000},
  "settings": {"negotiation": "auto", "gate_legacy": true, "hold_threshold": "medium"},
  "config": {"breaker": {"slots": 2, "max_waiters": 6, "cpu_trip": 85, "mem_min_mb": 768}, "capacity": {"backlog_hours": 6}}
}
```

| field | source |
|---|---|
| `now` | `time.time()` on the server; the view corrects all ages for clock skew with it |
| `error` | optional bridge-level problem (e.g. media.db unreadable), shown in the view's top bar |
| `processes.media` | Supervisor + `GET 127.0.0.1:8084/_stats` (2 s timeout); `up` false when it does not answer |
| `processes.worker` | Supervisor + `meta.worker_heartbeat` (`heartbeat_age` in seconds, or `heartbeat` = epoch); healthy while younger than 30 s; `paused` = null or the reason (`cpu`, `mem`, `breaker`) |
| `breaker` | `breaker.Breaker.status()` as published by media.py (`/_stats` or `meta.breaker`) as is; `forced` `"open"`/`"closed"`/null, `forced_for` = seconds left, `open_for` = seconds until half-open |
| `monitor` | `breaker.Monitor.snapshot()`; if absent, the view falls back to `breaker.monitor` |
| `tools` | `sandbox.tools(conf)` (name -> path or null); may add `"pypdfium2": "<version>"` or null |
| `cache` | `cache.Cache.usage()` |
| `negotiation.caps` | `media_edge.capabilities()` (cached; never call Cloudflare per request) |
| `counts.verdicts` / `.jobs` | `store.verdict_counts()` / `store.job_counts()` |
| `counts.oldest` | `store.oldest_queued_age(kind)` per kind |
| `capacity` | the 5 min advisor's last result (DESIGN 13.1) |
| `events_24h` | `store.event_counts(now - 86400)` |
| `savings` | `store.variant_totals()` |
| `settings` | current `CFG.media.negotiation`, `.gate.legacy_while_pending`, `.scan.hold_threshold` |
| `config` | optional thresholds for gauges (`CFG.media.breaker`, `CFG.media.capacity`) |

### 4.3 Lists

* `GET /api/media/holds?state=<csv>&limit=200&offset=<n>[&q=<text>]` returns
  `{"rows": store.list_verdicts(states, limit, offset, q), "total": <n or null>}`.
  * `state` is one of `flagged,held,error` / `flagged` / `held` / `error` / `pending` / `released` /
    `flagged,held,error,pending,released`.
  * `q` is a substring of the path.
  * Row keys: `mount, path, size, state, severity, findings` (a list of redacted
    `{type, severity, sample, where, confidence}`), `engines, scanned, updated, legacy, reviewed_by,
    review_note`.
  * `total` enables paging; without it the view pages while a page is full.
* `GET /api/media/events?[kind=<prefix>&]since=<server epoch>&limit=200` returns
  `{"rows": store.events(since, kind, limit)}`, newest first. `kind` is a prefix (`bypass` matches
  `bypass.*`), as `store.events` already does.
* `GET /api/media/jobs?state=failed` returns `{"rows": store.jobs(state, kind, limit)}`.
* `GET /api/media/policy` returns `media_rules.file_policy_preview(db)` as is (`counts`, `by_ext` per reason,
  `samples` with `rescued`, `effective_blocked`). The view never draws `blocked`, which can list thousands of
  paths, so the bridge may drop it. The view calls this on open, on demand, and at most every 10 min.

Plain arrays instead of `{"rows": [...]}` are accepted as well.

### 4.4 POST (existing login + CSRF; every POST audited with `core.audit`)

| endpoint | body sent by the view | answer the view expects |
|---|---|---|
| `/api/media/release` | `{mount, path, note}`; the note is required client-side (at least 3 chars) and should be server-side too | `{"ok": true}` |
| `/api/media/hold` | `{mount, path, note}`; the note may be empty | `{"ok": true}` |
| `/api/media/rescan` | `{mount, path}` | `{"ok": true}` |
| `/api/media/retry` | `{kind}`, one call per kind for "Retry all failed" | `{"ok": true, "retried": n}` |
| `/api/media/settings` | any of `{negotiation: "auto"\|"edge"\|"redirect"\|"off", gate_legacy: bool, hold_threshold: "low"\|"medium"\|"high"}` | `{"ok": true, "apply": <rules.apply() result>}`; "Caddy updated (sha)" is shown when `apply.changed` |
| `/api/media/breaker` | `{state: "open"\|"closed"\|"auto", seconds}`; `seconds` is 60-86400 for open/closed and 0 for auto | `{"ok": true, "breaker": {...}}` |

After every successful POST the view refreshes the status and lists. Errors are shown as a toast.

## 5. Verification done here

`node` is not installed, so `node --check` was not possible. `media.js` was instead loaded in headless Chrome
(`chrome --headless=new --dump-dom`, no ports) from a `file://` copy of the current `index.html` with the tag
above. The copy used the real `app.js` / `storage.js` / `control.js` / `layout.js`, a stub `fetch`, and a meta CSP
that forbids inline scripts and eval.

The scenarios were: bridge not hooked (404), switched off (200 `enabled:false`), switched off (409), full data
with XSS canaries in paths, findings, event kinds and drive names, garbage field types, and a 500. In every
scenario:

* there were no errors and no CSP violations;
* no canary fired, and no `on*` attribute ended up in the DOM;
* no section fell back to its error box;
* the saved view was restored after a reload;
* layout.js attached its grip to the hold aside;
* the query strings matched 13.2;
* Escape closed the aside.

Screenshots were checked at 1600 px and 900 px wide.

After the integration adds the tag, check that:

1. Media appears under Control, and the console is clean.
2. With `media.enabled` false the view says "Not deployed" and the badge reads `off`.
3. Once the bridge is on, the status fields above populate.

## 6. Rollback

Remove the `<script src="media.js"></script>` line. A browser that was on the Media view falls back to Summary.
The only leftovers are the `strata:media` and `strata:paneWidths` (`media:360`) entries in localStorage.
