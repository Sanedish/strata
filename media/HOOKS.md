# Strata Media: server hooks in `strata.py` (`media_bridge.py`)

All bridge logic is in `strata/media_bridge.py` (DESIGN 13) and `strata/media_edge.py` (DESIGN 9). `strata.py`
needs **six small anchored edits**, and nothing else changes. Other sessions edit `strata.py` concurrently, so:

* Apply each hook with the Edit tool (exact anchor -> replacement). Never rewrite the whole file.
* **Re-read `strata.py` right before each edit.** The anchors below were checked against `strata.py` on
  2026-09-29 (anchor line numbers are only hints; the anchor text is what counts).
* If an anchor no longer matches, find the equivalent spot. Do not force it.

With `media.enabled` off (the default), the hooks have almost no effect:

* `start()` logs one line and returns.
* `on_upload` and `on_rename` return at once.
* `/api/media/status` answers `{"enabled": false, ...}` (config summary, tools pre-flight).
* `/api/media/policy` still runs the file-policy dry run.
* Every other `/api/media/*` endpoint answers `409 {"error": "media pipeline disabled"}` (settings still save).

`media.db` is never opened while the pipeline is off.

## 1. Import (line ~29)

Anchor:

```python
import files
import rules
from core import CFG, log
```

Replace with:

```python
import files
import media_bridge
import rules
from core import CFG, log
```

At import time, `media_bridge` only imports `core`, `files` and the stdlib, and adds `strata/media` to `sys.path`.
The `media/*.py` modules are imported lazily on first use.

## 2. `/api/media/*` GET dispatch: top of `get_routes` (line ~322)

Anchor:

```python
    def get_routes(self, user, path, q):
        if path == "/api/live":
```

Replace with:

```python
    def get_routes(self, user, path, q):
        if path.startswith("/api/media/"):  # Strata Media admin API (media_bridge, DESIGN 13.2)
            r = media_bridge.api_get(user, path, q)
            return self.json(r) if r is not None else self.json({"error": "not found"}, 404)
        if path == "/api/live":
```

`do_GET` has already run `guard()` (login). Exceptions reach the existing `self.fail(e)`:

* `ValueError` becomes 400.
* `media_bridge.MediaError` is a `files.FileError` subclass, so it is answered with its own code (404, 409, 502, 503).

## 3. `/api/media/*` POST dispatch: top of `post_routes` (line ~520)

Anchor:

```python
    def post_routes(self, user, ip, path, b):
        A = lambda action, target, note="": core.audit(ip, user, action, target, note=note)
        mid = b.get("mount")
```

Replace with:

```python
    def post_routes(self, user, ip, path, b):
        if path.startswith("/api/media/"):  # Strata Media admin API (validates and audits itself)
            return media_bridge.api_post(user, ip, path, b)
        A = lambda action, target, note="": core.audit(ip, user, action, target, note=note)
        mid = b.get("mount")
```

`do_POST` has already checked the login and CSRF. A `None` result becomes the existing 404, and failures are
audited by `do_POST` as usual. `api_post` audits each successful action itself:

* `media-release`
* `media-hold`
* `media-rescan`
* `media-retry`
* `media-settings`
* `media-breaker`

## 4. Upload hook: `after_upload` (line ~512)

Anchor:

```python
        if full:
            App.compressor.enqueue(full)
        purge_later(r)
```

Replace with:

```python
        if full:
            App.compressor.enqueue(full)
            media_bridge.on_upload(r["mount"], r["path"], full)  # scan first (prio 20), prewarm AVIF (70)
        purge_later(r)
```

`on_upload` never raises and costs one or two `media.db` inserts. It covers both upload paths: chunked
`/complete` and `/api/files/upload`.

## 5. Rename hook: the `/api/files/rename` route in `post_routes` (line ~530)

Anchor:

```python
            r = files.rename(mid, b.get("from", ""), b.get("to", ""))
            A("rename", "%s:%s -> %s" % (mid, r["from"], r["to"]))
```

Replace with:

```python
            r = files.rename(mid, b.get("from", ""), b.get("to", ""))
            A("rename", "%s:%s -> %s" % (mid, r["from"], r["to"]))
            media_bridge.on_rename(mid, r["from"], r["to"])  # verdicts (and queued jobs) follow the file / folder
```

`on_rename` never raises. `mid` may be the raw body value: `store.move_verdict` converts it to an int.

Cross-drive moves and deletes are deliberately **not** hooked, so the next discovery pass (every 2 min)
handles them:

* A verdict whose file is gone from both fidx and the disk is dropped, together with its variants.
* The file at its new place is scanned like any new file.
* Until that scan finishes, a moved held file is still caught by the gate's hash lookup (`verdict_by_hash`).

## 6. Bridge start: `main()` (line ~976)

Anchor:

```python
              cloudflare.EdgeSync(), cloudflare.Purger(), App.alerts, Housekeeping()):
        t.start()
    feed.serve(App.live, App.metrics, App.probes)
```

Replace with:

```python
              cloudflare.EdgeSync(), cloudflare.Purger(), App.alerts, Housekeeping()):
        t.start()
    media_bridge.start()  # Strata Media: supervisor, discovery, purges, alerts; no-op while media.enabled is off
    feed.serve(App.live, App.metrics, App.probes)
```

This must come **after** `rules.ALERT_HOOK.append(App.alerts.hook)`, which it does at this spot, so the bridge's
alerts reach the Alerts view.

On the first start with media on, the bridge does three things:

1. It saves `media.cutover` and a generated `media.admin_token` to `strata.json` (`core.save_config`). The token is
   never logged.
2. It sets `rules.APPLY_SOON`, so `media.json` picks them up.
3. It starts `media/media.py` (`127.0.0.1:8084`) and `media/worker.py` (BELOW_NORMAL) with Strata's own
   interpreter (pythonw under the scheduled task), without windows. Their output is appended to
   `data/media.out|err` and `data/worker.out|err`.

A healthy instance the bridge did not start (for example one left running across a Strata restart) is adopted as
"external" and is never killed.

## 7. Verify after applying

1. Run `python -m py_compile strata.py`.
2. Run the tests (they never touch production):
   `python -m unittest discover -s media\tests -t media\tests -p "test_bridge.py"`
   and the same with `-p "test_edge.py"`.
3. Restart Strata the usual way (scheduled task "Strata"). With media off, `run.out` shows
   `media: disabled (media.enabled is off) - bridge not started`.
4. Check that `GET /api/media/status` (logged in) answers `{"enabled": false, ...}`.

## 8. Switching on (deployment, not part of these hooks)

1. Set `"media": {"enabled": true}` in `strata.json`.
2. Restart Strata.
3. Watch `GET /api/media/status` until `processes.media.up` and `processes.worker.up` are both true.
4. Check `negotiation.effective`:
   * `edge` means the token manages Transform Rules.
   * Otherwise it is `redirect`, and `negotiation.caps.transform.need` names the missing permission.

## 9. Rollback

Remove the six edits, or set `media.enabled` to false. With media off, the supervisor never starts anything.

* If `media.enabled` is switched off while Strata runs (through `core.save_config`), the running bridge pauses
  within 30 s and stops the processes it started itself. It resumes when the switch is turned back on.
* If Strata exits, the bridge stops with it. Its children stay up until they are stopped by hand, because the bridge
  only ever kills processes it started, and only while it runs. The strata.db meta keys can stay; they are
ignored while media is off:

* `media_negotiation_effective`
* `media_capacity`
* `media_verdict_cursor`
