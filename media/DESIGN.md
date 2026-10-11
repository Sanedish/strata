# Strata Media — edge processing for the :8080 CDN

Status: design contract (v1). Every module below is implemented against this document; if code and this
file disagree, fix one of them in the same change.

## User decisions (2026-09-29, override anything below)

* **The existing library is never scanned / OCR'd** (`scan.legacy = False`). Files born before `cutover` are
  served without a verdict and the gate never enqueues a scan for them (no 503, no hold); only **new**
  uploads/files go through the scan gate. For the existing library the pipeline does **compression only**:
  the bridge's backfill (`worker.backfill`) enqueues `image` prewarm jobs (AVIF + WebP where beneficial) and
  `video` WebM jobs, lowest priority. With `scan.legacy = True` the old behaviour (legacy served while
  pending, scanned in the background) comes back.
* **E: is no longer published** (drive 4 removed) -> `cache_root = E:/strata-media`, `cache_max_gb = 150`.
* **2026-10-03: deployed as the image optimizer, images-only** (OPTIMIZER.md): scan gate, file policy, lane and
  video off; encodes demand driven (no upload prewarm, no library backfill). Added on top of this design: width
  ladder (`?w=` snapped, negotiated with the format), `?nocompress` / `Cache-Control: no-transform` bypass, a
  persistent tier with hotness-based promotion/demotion, profile-versioned variant keys, cross-process single-flight
  (per-key OS lock), negative cache for failures, 304 from recorded ETags, `/_metrics`. Section 6.1/6.2 deviations:
  WebP sources are negotiable (AVIF only), `@neg` also handles `?w=` in edge mode, speeds 8 (sync) / 6 (bg).

## 0. Environment facts this design is built on

* VM: QEMU, 6 vCPU Xeon E5-2667 v4 (Broadwell, AVX2), 8 GB RAM, Windows 11 Pro, Python 3.12, Caddy 2.11.3
  (standard modules only), cloudflared tunnel, 50 Mbps uplink. Cloudflare **Free** plan.
* Originals live on the NAS `//192.168.1.55/data2/storage` (SMB, mount id 1). **Originals are never
  modified.** `E:` is a local 400 GB NTFS disk, but drive (mount) 4 now publishes `E:/` as `/disk2`, so derived data must NOT live there: cache + sandbox go to `<home>/data/media-cache` (C: has ~78 GB free; cap 30 GB).
* Library (fidx, Sept 2026): 880 PNG = 5.4 GB (max 151 MB), 156 JPG, 915 WebP, 156 AVIF, 64 GIF, 18 MP4,
  3 MOV, 3 WebM, 4 ZIP (5.8 GB, max 5 GB), 1 TAR, 1 RAR, 3 EXE, 4 BAT, 6 PY ...
* Pillow 12.3 has native AVIF (libavif 1.4.2) and WebP. Measured: a sample photo
  `/general/photo.png` (29.4 MB, 4320x7680) -> AVIF q72 4:4:4 speed 7 = 184 KB (0.6 %) in 3.7 s;
  WebP q88 = 256 KB in 6.2 s. 1080p AVIF speed 7 ~ 0.25 s.
* Microsoft Defender is active; `MpCmdRun.exe -Scan -ScanType 3 -File <path> -DisableRemediation` works as
  the (non-admin) service user: exit 0 = clean, 2 = threats. Newest platform dir:
  `C:\ProgramData\Microsoft\Windows Defender\Platform\<ver>\MpCmdRun.exe` (fallback
  `C:\Program Files\Windows Defender\MpCmdRun.exe`).
* Not installed yet (install.ps1 installs them): ffmpeg/ffprobe (Gyan build, has libsvtav1/libvpx/libopus),
  7-Zip, Tesseract OCR, `pypdfium2`. **Every code path must degrade gracefully when a tool is missing**
  (see 7.4).
* The Cloudflare token currently lacks Cache Purge / WAF / Lists; Transform Rules not verified. Code must
  detect permissions and fall back (see 9).

## 1. Existing system (do not break)

Strata (`<home>`) is the control plane:

| process | port | owns |
|---|---|---|
| `strata.py` (Scheduled Task "Strata", pythonw) | 127.0.0.1:8090 admin, :8081 feed | `data/strata.db`, CF token, renders `generated/cdn.caddy` (rules.py), reloads Caddy |
| `telemetry/telemetry.py` | 127.0.0.1:8082 | public stats page |
| `transform/transform.py` | 127.0.0.1:8083 | ?w= ?h= ?fit= ?fm= ?q= ?ver=, `/_gate` (signed links). **Currently not running.** |
| caddy | :8080 (CDN via tunnel), :8091 (admin LAN) | |

Conventions to keep: stdlib `http.server` services, no frameworks, loopback-only internal services, least
privilege (transform "knows no database"), atomic file writes (tmp + `os.replace`), `core.log()` style
logging, Caddyfile tokens always through `rules.bq()`, everything validated by `caddy validate` before a
reload (rules.apply), 4-space Python, comment density like the existing files.

## 2. New processes

| process | file | port | privileges |
|---|---|---|---|
| **Strata Media** (hot path) | `media/media.py` | 127.0.0.1:8083 (replaces transform.py, same port, same features) | reads mounts, `media.db`, writes `<cache_root>/cache`. No strata.db, no CF token. |
| **Strata Media Worker** (background) | `media/worker.py` | none | BELOW_NORMAL priority; reads mounts, `media.db`, writes cache + sandbox. No strata.db, no CF token. |
| bridge (thread inside strata.py) | `media_bridge.py` | — | has strata.db + CF token: supervision, discovery, purge, alerts, capacity advice, admin API |

`transform/transform.py` stays on disk for rollback but is no longer started. `media.py` must stay
drop-in compatible with it (`/_gate`, `?ver=`, `?w=...`).

Supervision: `media_bridge.Supervisor` (in strata.py) starts `media.py` / `worker.py` with the same
interpreter that runs Strata (pythonw), restarts them with backoff (10 s, 30 s, 60 s, max 5 min) and records
`supervisor.restart` events. Single instance: media.py exits if it cannot bind its port; worker.py holds an
exclusive lock on `data/media-worker.lock` (msvcrt.locking) and exits if it cannot get it. Health: media =
`GET /_stats` answers within 2 s; worker = `meta.worker_heartbeat.ts` younger than 30 s.
Child stdout/stderr -> `data/media.out|err`, `data/worker.out|err` (append).

## 3. Files and ownership

Other Claude sessions edit Strata concurrently. Therefore **all logic goes into NEW files**; shared files
only get tiny anchored hooks (Edit tool, re-read immediately before, never a full-file Write):

```
strata/
  core.py            DEFAULTS["media"] (section 12) — already in place
  rules.py           hooks only: render() calls media_rules.render_*; apply() calls media_rules.write_media_config
  media_rules.py     NEW: file policy / media routes / gate / lane rendering, write_media_config(),
                     file_policy_preview()                                                 [rules]
  media_edge.py      NEW: Cloudflare transform (URL rewrite) rules + capability probe (uses cloudflare.call) [integration]
  files.py           hook only: urls_for() appends media_rules.variant_urls(...)            [integration]
  strata.py          hooks only: bridge start in main(), media_bridge.on_upload() in after_upload(),
                     /api/media/* dispatch to media_bridge.api_get / api_post              [integration]
  media_bridge.py    NEW: Bridge thread, Supervisor, discovery, purge, alerts, capacity, admin API [integration]
  static/media.js    NEW: "Media" view; index.html gets one <script> tag + one nav entry  [ui]
  media/
    DESIGN.md        this file
    README.md        operator guide                                                      [docs]
    install.ps1      installs tools, creates dirs, records tool paths                    [docs]
    media.json       generated by rules.write_media_config() (never hand-edited)
    config.py        load media.json, categories, resolve(), birth_time()               [foundation]
    store.py         media.db schema + all queries                                       [foundation]
    events.py        failure/event log (JSONL + db), non-blocking                        [foundation]
    cache.py         variant cache on E:, keys, atomic writes, LRU eviction             [foundation]
    breaker.py       resource monitor, circuit breaker, admission, thread/process priority [foundation]
    sandbox.py       Job-Object subprocess runner, tool discovery, safe paths           [foundation]
    imaging.py       image probe, format choice, encode, cost model, legacy transforms   [codecs]
    video.py         ffprobe/ffmpeg WebM (AV1/VP9 + Opus) transcoding                    [codecs]
    detect.py        sensitive-data detectors + redaction                                [scan]
    extract.py       safe archive extraction (zip/tar/7z) with bomb/traversal limits     [scan]
    scan.py          scan dispatcher: OCR, PDF, archives, documents, text, AV engines    [scan]
    media.py         HTTP hot path                                                       [service]
    worker.py        background job runner                                               [service]
    tests/           unittest suites (+ e2e with a private Caddy on test ports)          [tests]
```

All `media/*.py` modules import each other as plain modules (`import store`), because media.py and
worker.py are started with `media/` as the script directory. Strata imports them by adding
`os.path.join(core.ROOT, "media")` to `sys.path` inside `media_bridge.py` only.

**Import path fix (mandatory in media.py and worker.py, before importing PIL):** Task Scheduler starts
pythonw without APPDATA, so the per-user site-packages are invisible. Copy the block from the top of
`transform/transform.py`: insert `<install folder>\vendor` (vendored Pillow, brotli, zstandard) at
`sys.path[0]` if it exists, then `site.addsitedir()` the user site resolved via `SHGetFolderPathW(0x1A)`.
Put it in `media/pathfix.py` (`import pathfix` first thing) so both entry points share it.

Mounts can have a prefix (e.g. drive 4 = `E:/` at `/disk2`); every generated route and
media.py's resolve() must honour prefixes (`uri strip_prefix` in the orig `handle_response`, like the
drive handle does).

## 4. Request flow at the origin (generated cdn.caddy)

Route order inside the `:8080` `route { }` (literal order — Caddy does not re-sort inside `route`):

0. `request_header -X-Strata-Lane`, `-X-Strata-Throttle`, `-X-Strata-Negotiate`, `-X-Strata-Mount`,
   `-X-Strata-Cache` (clients can never inject internal headers).
1. blacklist (existing) 2. access rules (existing) 3. short links (existing)
4. **file policy** (per files/page mount host set; `allow` access rules carve exceptions, same as today):
   * dangerous names/extensions -> `error 404` (like the existing "hide")
   * not a known-safe type -> `error 403`
   * `.svg` -> `header Content-Security-Policy "default-src 'none'; style-src 'unsafe-inline'; img-src data:"`
5. link modifiers (existing `?dl=1`), then per files mount with `transforms` on:
   * **media variants** `@mv<id>`: media extensions AND (`_v` in avif|webp|webm OR any of w,h,fit,fm,q)
     -> `reverse_proxy` media with `handle_response` accel/orig blocks (4.2)
   * `?ver=` -> media (existing, unchanged semantics)
   * **negotiation (only when effective mode = redirect)** `@neg<id>`: negotiable image ext AND empty query
     -> media with `header_up X-Strata-Negotiate 1` (media answers 302 / 403 / 503)
6. **scan gate** `@gate<id>`: gated extensions -> `forward_auth 127.0.0.1:8083 { uri /_scan; header_up
   X-Strata-Mount <id>; copy_headers X-Strata-Lane }`
7. **large-file lane** `@lane<id>`: `header X-Strata-Lane throttle` -> `reverse_proxy` media with
   `header_up X-Strata-Throttle 1`, `X-Strata-Mount`, `X-Strata-Cache`
8. drives (existing) 9. unknown host (existing)

### 4.1 Extension sets (single source: `CFG["media"]["file_policy"]` and config.py categories)

* negotiable images (auto AVIF/WebP): `png jpg jpeg jfif gif bmp tif tiff`
* transformable images (explicit ?w/?fm): the above + `webp avif`
* videos (WebM variants): `mp4 m4v mov mkv avi wmv flv` (`webm` sources are served as is)
* gated categories (default): image, svg, pdf, archive, document, text, exec (config.py 5.1)

### 4.2 Media response protocol (media.py -> Caddy)

media.py never streams large bodies on the hot path. It answers one of:

| answer | status | headers set by media | Caddy does |
|---|---|---|---|
| **accel** | 200, empty body | `X-Strata-Accel: /img/ab/<key>.avif` (path under `<cache_root>/cache`, URL-safe), `X-Strata-Cache-Control`, `X-Strata-Disposition`, `X-Strata-Media` | `handle_response`: `root * <cache_root>/cache`, `rewrite * {rp.header.X-Strata-Accel}`, copy the three headers, `file_server` (Range, ETag, sendfile) |
| **orig** | 200, empty body | `X-Strata-Orig: 1`, `X-Strata-Cache-Control`, `X-Strata-Media` | `handle_response`: `root * <mount path>` (+ `uri strip_prefix` for prefixed mounts), copy headers, `file_server` — i.e. the untouched original |
| redirect | 302 | `Location: <request path>?_v=<fmt>` (relative), `Cache-Control: private, no-store`, `Vary: Accept` | passes through |
| held | 403 | `Cache-Control: no-store`, text body "This file is being held for review." | passes through |
| pending | 503 | `Retry-After: <gate.pending_retry_after>`, `Cache-Control: no-store`, text body | passes through |
| small direct body | 200 | normal headers | passes through (only `?ver=` streaming, `/_stream`, errors) |

**Port decision (after coordination):** Strata Transform stays on 127.0.0.1:8083 as its own scheduled task
("Strata Transform") and keeps `?ver=` and `/_gate` (signed links). **media.py listens on
`CFG.media.listen` = 127.0.0.1:8084** and receives everything else in this document: `?_v=`, explicit
`?w ?h ?fit ?fm ?q` (now cached + breaker-admitted), negotiation, `/_scan`, the lane. media.py still
implements `/_gate` and `?ver=` for compatibility, but rules route those to 8083.

**Browser Cache TTL caveat:** the zone's Browser Cache TTL is 6 months, so Cloudflare rewrites any browser
`max-age` it sees. Therefore short-TTL answers (bypass/deferred) send browsers the mount's browser value
(`public, no-cache` = revalidate) and put the short TTL only in the CDN header
(`X-Strata-CDN-Cache-Control: public, max-age=60`).

**Cache headers (coordinated with the "file deletion cache clearing" session, which is changing rules.py):**
file mounts now send browsers `Cache-Control: public, no-cache` and give Cloudflare its TTL separately via
`Cloudflare-CDN-Cache-Control` (mount column `edge_cache`, e.g. `public, max-age=31536000`; Cloudflare
uses and strips it). Caddy passes both to media: `header_up X-Strata-Cache <browser cache>` and
`header_up X-Strata-Edge-Cache <edge cache>`. media echoes them as `X-Strata-Cache-Control` and
`X-Strata-CDN-Cache-Control`; the handle_response blocks set `Cache-Control` and
`Cloudflare-CDN-Cache-Control` from them. Rules: cacheable answers (accel, not-beneficial orig) -> browser
value + edge value; short-TTL answers (bypass/deferred) -> `image.short_ttl` for both; held 403 / pending
503 / redirect 302 -> `Cache-Control: no-store` (302: `private, no-store`) and **no** CDN header. If
`X-Strata-Edge-Cache` is absent (older rules.py), fall back to the old single header behaviour.
Purges are Cloudflare *prefix* purges (`host/path`), which already cover every `?_v=` variant, so
files.urls_for is NOT changed; the bridge just calls `cloudflare.purge_async(urls)`.
The generated Caddy fragment in this section is illustrative: the final shape must keep the peer's
additions (`@missing status 404` handle_response -> `error 404`, handle_errors binpath logic).

Header values: `X-Strata-Media` = `hit`, `miss`, `bypass;kind=<kind>`, `deferred`, `orig;reason=<reason>`.
`X-Strata-Disposition` = `inline; filename*=UTF-8''<original base name with new extension>`.
Cache-Control: accel and "not beneficial" orig answers use the mount's `X-Strata-Cache` value (immutable);
bypass/deferred orig answers use `image.short_ttl` (`public, max-age=60`) so Cloudflare asks again soon.

Expected generated fragment for mount 1 (prefix `/`) — the rules agent must produce exactly this shape
and prove it with `caddy validate`:

```
		@mv1_1 {
			host `example.com` `cdn.example.com`
			path_regexp mv1_1 `(?i)\.(png|jpe?g|jfif|gif|bmp|tiff?|webp|avif|mp4|m4v|mov|mkv|avi|wmv|flv|webm)$`
			expression `{query._v} == "avif" || {query._v} == "webp" || {query._v} == "webm" || {query.w} != "" || {query.h} != "" || {query.fm} != "" || {query.q} != "" || {query.fit} != ""`
		}
		reverse_proxy @mv1_1 127.0.0.1:8083 {
			header_up X-Strata-Mount 1
			header_up X-Strata-Cache `public, max-age=31536000, immutable`
			@acc1_1 header X-Strata-Accel *
			handle_response @acc1_1 {
				root * `<home>/data/media-cache/cache`
				rewrite * {rp.header.X-Strata-Accel}
				header Cache-Control {rp.header.X-Strata-Cache-Control}
				header Content-Disposition {rp.header.X-Strata-Disposition}
				header X-Strata-Media {rp.header.X-Strata-Media}
				file_server
			}
			@org1_1 header X-Strata-Orig *
			handle_response @org1_1 {
				root * `//192.168.1.55/data2/storage`
				header Cache-Control {rp.header.X-Strata-Cache-Control}
				header X-Strata-Media {rp.header.X-Strata-Media}
				file_server
			}
		}
```

The `?_v=orig` query is deliberately NOT matched by `@mv`: it falls through to the gate and the drive's
normal `file_server` (original bytes, immutable caching). It exists so every heavy byte lives under a
cacheable URL.

### 4.3 Large-file lane

Cloudflare Free does not cache objects > 512 MB, so every download of e.g. the 5 GB zip hits the 50 Mbps
uplink. The gate adds `X-Strata-Lane: throttle` for gated files `>= lane.min_bytes` (512 MiB); Caddy sends
those to media `/_stream`-style handling (any path with `X-Strata-Throttle: 1`), which streams with Range
support through two token buckets: lane total `lane.total_mbps` (25) and per connection
`lane.per_conn_mbps` (10). Leaves half the uplink for everything else.

## 5. The gate (media.py, `/_scan` and internally for every media answer)

### 5.1 Categories (config.py `category(name)`)

```
image    png jpg jpeg jfif gif webp avif bmp tif tiff ico heic heif jxl psd tga
svg      svg
pdf      pdf
archive  zip 7z rar tar gz tgz bz2 tbz2 xz txz zst mrpack
document docx xlsx pptx odt ods odp epub doc xls ppt rtf
text     txt md csv tsv log json xml yml yaml toml ini srt vtt ass html htm css js mjs map webmanifest
exec     exe msi dll bat cmd ps1 py sh jar apk dmg iso img appimage deb rpm com scr
video    mp4 m4v mov mkv avi wmv flv webm ts m3u8 ogv
audio    mp3 flac wav ogg oga opus m4a aac wma mid midi
font     ttf otf woff woff2 eot
3d       blend blend1 fbx obj glb gltf stl ply 3ds dae usd usdz
other    everything else
```
(Categories are for the media pipeline; the file policy decides what may be served at all.)

### 5.2 Decision `gate.decide(mount_id, rel, full, st) -> Decision(action, reason, lane)`

```
if category not in gate.categories: allow("exempt")
v = verdict_cache[(mount, rel)]
if v and v.size == st.st_size and v.mtime == st.st_mtime:
    clean | released | skipped -> allow("clean")
    flagged | held            -> deny_held
    error                     -> deny_held if not legacy else allow("legacy")    # error = unscannable
    pending                   -> fall through
if v is None: h = verdict_by_hash(st.st_size, quick_hash(full))  # renamed copies inherit a hold
    if h in (flagged, held) -> deny_held
legacy = birth_time(st) < cutover
enqueue scan (priority 10 if not legacy else 60)       # deduplicated by store
if legacy and gate.legacy_while_pending: allow("legacy")
else: pending (503)
lane = "throttle" if lane.enabled and st.st_size >= lane.min_bytes
```
`birth_time(st) = max(st.st_mtime, st.st_birthtime or st.st_ctime)` — a copy made today of an old file is
new; an overwritten file (new mtime) is new. `quick_hash` = compress.quick_hash algorithm (sha1 of size +
first 64 KB + last 64 KB), computed only on a verdict miss.
The verdict cache is an in-memory dict refreshed every 2 s from `store.verdicts_since(last_updated)` plus
a full reload every 10 min. The gate never blocks on the database (reads are from memory; enqueue is
fire-and-forget on a small background queue).

`cutover` is set once by the bridge on first start (`CFG.media.cutover`, saved to strata.json) = time the
pipeline was switched on. Everything born before it is "legacy": served while pending, but **held as soon
as a scan flags it** (and purged from Cloudflare).

## 6. Images

### 6.1 Negotiation

Modes (`CFG.media.negotiation`: `auto` | `edge` | `redirect` | `off`; the bridge stores the effective mode
in strata.db meta `media_negotiation_effective` and rules.render reads it):

* **edge** (preferred): Cloudflare URL-rewrite rules (phase `http_request_transform`) add `_v=avif` or
  `_v=webp` to *query-less* image requests based on the `Accept` header, *before* the cache lookup, so each
  format is cached separately at the edge, the visible URL is unchanged, zero extra round trips.
* **redirect** (fallback when the token cannot manage Transform Rules): every query-less negotiable image
  request reaches media, which answers `302 ?_v=avif|webp|orig` (`private, no-store`, `Vary: Accept`).
  All heavy bytes live under cacheable `?_v=` URLs; the canonical URL only ever returns tiny uncacheable
  redirects, so Cloudflare can never serve the wrong format.
* **off**: only explicit `?fm=`/`?_v=` URLs.
* **auto**: edge if the rules are installed and verified, else redirect.

Rationale: Cloudflare Free ignores `Vary: Accept`, so negotiating on the canonical URL at the origin would
poison the edge cache.

### 6.2 Format choice (`imaging.choose(info, want, conf) -> Plan`)

`want` = `avif` (client accepts AVIF and therefore WebP) or `webp`.
* source already AVIF/WebP and no resize -> `orig` (not beneficial)
* animated (frames > 1) -> animated WebP (lossy q=`webp_quality`, `minimize_size`) regardless of want
* lossy source (JPEG, JFIF): AVIF q=`avif_quality_lossy` (62) 4:2:0 / WebP q=`webp_quality` (86)
* lossless source (PNG/BMP/TIFF/static GIF): AVIF q=`avif_quality_lossless` (74) **4:4:4** (keeps text and
  UI edges sharp) / WebP q=`webp_quality`, alpha_quality 100; if the image is palette-like (<= 256 colours,
  <= 4 MP) also try WebP lossless and keep the smaller
* always: `ImageOps.exif_transpose`, keep ICC profile, drop EXIF/XMP (removes GPS from what the CDN
  serves), speed `speed_sync` (7) on the hot path / `speed_bg` (5) in the worker, `max_threads=image.threads`
* **not beneficial**: if the result is not at least `min_saving` (10 %) smaller than the source, record the
  variant with `beneficial=0` and answer `orig` (immutable cache: the decision is deterministic)
* decode-bomb guard: `Image.MAX_IMAGE_PIXELS = max_mp*1e6`; > `max_mp` (150) on hot path -> deferred;
  worker allows up to `bg_max_mp` (280) when > 3 GB RAM available, else `skipped` with event

### 6.3 Hot-path algorithm (`_v=avif|webp`, explicit transforms)

1. resolve mount/path (config.resolve; traversal-safe) -> 404 if missing
2. gate.decide -> held/pending answered directly
3. key = cache.key(mount, rel, size, mtime, spec) where spec = `"auto:avif:v1"` / `"auto:webp:v1"` /
   `"tf:w=..,h=..,fit=..,fm=..,q=..:v1"`; `store.variant(key)` hit and file exists -> accel (or orig when
   `beneficial=0`), `X-Strata-Media: hit`
4. plan; `orig` -> record not-beneficial, answer orig
5. est = cost model (EWMA seconds per megapixel per (fmt, speed) + decode + NAS read at 80 MB/s). If
   est > `sync_budget_s` (6 s) or MP > `sync_max_mp` (40) or animated with frames*MP > 8 -> enqueue
   worker job (kind `image`, priority 30), event `bypass.deferred`, answer orig with short TTL.
6. `with breaker.admit(est)`: encode in a `below_normal_thread()`; write cache atomically; put_variant;
   feed the cost model; answer accel `X-Strata-Media: miss`. `Bypass(kind)` -> event
   `bypass.<kind>`, orig short TTL. Any exception -> event `bypass.encode_error` (or `decode_error`),
   orig short TTL. Encodes slower than 2 x est and > 3 s -> event `encode.slow` (also counts as a slow
   strike in the breaker).

Explicit `?fm=` is honoured exactly (existing semantics from transform.py: w/h 1..max_dim, fit
inside|cover|contain|fill, q 1..100, never upscale). Invalid parameters -> 400 as today.

## 7. Background worker

### 7.1 Jobs (`media.db.job`)

kinds: `scan`, `image` (deferred / prewarm encodes), `video`. Priority (lower = sooner):
10 gate miss on a new file, 20 upload, 30 deferred image, 40 video demand, 60 discovery of changed files,
70 prewarm after upload, 80 legacy backfill, 85 popularity prewarm.
Dedup key `(kind, mount, path, params)`: enqueueing an existing queued/running job only lowers its
priority number. A `done` job with the same size+mtime is not re-enqueued unless `force`.
Leases: `claim` sets `lease_until = now + lease_s`; running jobs heartbeat; expired leases are requeued
(crash safety). Failures retry with backoff 60 s, 10 min, 1 h up to `worker.max_attempts` (3), then
`failed`.

### 7.2 Worker loop

Two lanes (threads): **scan lane** (`scan` jobs — they gate content, never starved by video) and
**encode lane** (`image`, `video`). Before each claim a lane checks: `cpu_ewma < worker.cpu_max` (65),
`mem_avail > worker.mem_min_mb`, media breaker (`meta.breaker.state`) not `open`. Otherwise it sleeps
5 s and emits `worker.paused` (at most once per 5 min per reason). Process priority BELOW_NORMAL; every
external tool runs through `sandbox.run` with IDLE priority, a CPU hard cap (`video.cpu_pct` 50 % for
ffmpeg, 35 % for others) and a memory cap.

### 7.3 Scan pipeline (`scan.scan_file(full, name, conf, tools, cancel) -> ScanResult`)

| category | work |
|---|---|
| image | EXIF findings (GPS -> `detect.gps_severity`, default low); OCR (tesseract) of the image: grayscale, upscale x2 if max side < 1000, tile tall/wide images into <= `ocr.tile_px` tiles with 120 px overlap, max `ocr.max_mp` (downscale beyond), animated: first frame + up to 4 evenly spaced frames; detectors on OCR text with `ocr=True` |
| svg | detectors on text + active-content check (`<script`, `on*=` attributes, `javascript:`, `<foreignObject`, external `href`) -> medium |
| pdf | raw active-content scan (`/JavaScript /JS /Launch /EmbeddedFile /OpenAction+JS /RichMedia /XFA /AA`) -> medium; pypdfium2 text per page (<= `pdf.max_pages`); pages with < 20 chars rendered at `pdf.dpi` and OCR'd (<= `pdf.ocr_pages`); password-protected -> `unscannable` medium; AV |
| archive | extract.extract into `<cache_root>/sandbox/<job id>/` (limits 7.5); AV scan of the archive file and the extracted tree; inner files: dangerous names (`.env`, `id_rsa`, `*.pem|key|p12|pfx|kdbx`, `credentials*`, `.git/`) -> high; `hold_inner_ext` (scr com pif hta lnk vbs vbe jse wsf wsh ps1 bat cmd msi reg) -> medium; `report_inner_ext` (exe dll jar apk sys) -> low; texty inner files -> detectors (<= `archive.text_bytes` total); inner images -> OCR (<= `archive.ocr_images`); nested archives recurse (depth <= 3); encrypted entries -> `unscannable` medium; sandbox always deleted afterwards |
| document | AV; OOXML/ODF/EPUB: read XML parts via zipfile (no extraction to disk), strip tags, detectors; `vbaProject.bin` / macros -> medium; legacy doc/xls/ppt/rtf -> AV + detectors on printable strings |
| text | detectors on the content (<= `scan.text_max_bytes`); `.html/.htm/.js/.mjs/.css/.map/.json/.webmanifest` only hold on **high** findings (public web assets often embed public keys) |
| exec | AV only |

Verdict: `flagged` if any AV threat (always high) or max finding severity >= `scan.hold_threshold`
(medium); else `clean` (low findings are kept for the admin). Exceptions -> retry, then `error`.
`unscannable` findings (encrypted, OCR required but missing, AV required but missing) are medium, i.e.
held, so nothing unscanned is published silently.

### 7.4 Missing tools

`sandbox.which()` resolves tools from `CFG.media.tools` paths, PATH and the usual install dirs. Missing
tool -> event `tool.missing` (once per 10 min) and:
* tesseract missing & `ocr.required` -> images/PDF pages that need OCR get an `unscannable` finding (held
  if new; legacy stays served while pending). `ocr.required=false` -> OCR skipped, note in engines.
* no AV engine & `scan.require_av` -> `unscannable` for av categories.
* ffmpeg missing -> video jobs fail with `error_kind=tool_missing` (no retry until tools change); `_v=webm`
  keeps redirecting to `?_v=orig`.
* 7-Zip missing -> rar/7z/zst archives `unscannable`; zip/tar still handled by the stdlib.
* pypdfium2 missing -> PDFs: raw active-content check + AV only + `unscannable` (text) medium.

### 7.5 Archive limits (`scan.archive`)

max_total_bytes 24 GiB, max_entries 50 000, max_entry_bytes 12 GiB, max_ratio 250 (only for entries
> 1 MiB), max_depth 3. Reject absolute paths, drive letters, `..`, NUL/control chars, reserved device
names, symlinks/hardlinks/devices (tar uses `filter="data"` plus own checks), and anything resolving
outside the sandbox. Breach -> finding `archive_bomb` high (held). zip: stdlib `zipfile` (stream copy with
running byte count, never trust header sizes); tar/tgz/tbz2/txz/gz/bz2/xz: stdlib; 7z/rar/zst and zip
methods the stdlib cannot read: `7z l -slt` listing first (sizes, encryption, attributes), then
`7z x -y -bd -p- -snl- -o<dir>` inside sandbox.run, then a post-walk that deletes reparse points and
re-checks every path.

### 7.6 Video (`video.py`)

`probe` via ffprobe JSON. Plan: skip if container is WebM or codec is already AV1/VP9, duration >
`max_seconds`, or file > `max_bytes`. Profile `av1` (default): `-c:v libsvtav1 -preset 8 -crf 30
-svtav1-params lp=<threads> -pix_fmt yuv420p -g <fps*10>`; fallback `vp9`: `-c:v libvpx-vp9 -deadline good
-cpu-used 4 -row-mt 1 -crf 32 -b:v 0`; audio `-c:a libopus -b:a 128k` (copy if already Opus, drop nothing);
keep resolution/fps; `-map 0:v:0 -map 0:a? -map_metadata -1 -f webm`; timeout = max(600,
duration*timeout_factor). Not beneficial if output >= 90 % of the source -> variant row with
`beneficial=0`, file deleted. Output goes to `<cache_root>/tmp` then `os.replace` into the cache.

Hot path for `_v=webm` (and `fm=webm`): variant ready & beneficial -> accel; otherwise enqueue (priority 40)
and answer `302 ?_v=orig` (`private, no-store`). Never serves mp4 bytes under the webm URL (a playback that
spans the moment the variant appears would mix byte ranges of two different files).

Edge rule for video (edge mode only): query-less `mp4|m4v|mov` with `Sec-Fetch-Dest: video` and a Chromium or
Firefox UA (not `CriOS`/`FxiOS` = iOS WebKit) -> `_v=webm`. `mkv avi wmv flv` are never auto-swapped (they
are downloads); `?fm=webm` makes them playable in browsers explicitly.

## 8. Circuit breaker and admission (`breaker.py`)

* `Monitor` thread samples every 1 s: system CPU % (GetSystemTimes, like core.host_sample), EWMA with ~5 s
  time constant, available memory (GlobalMemoryStatusEx). Non-Windows: psutil-free fallback (os.getloadavg
  / 0) so tests run anywhere.
* `Breaker(name, monitor, conf, events)` states `closed` -> `open` -> `half_open` -> `closed`.
  Trips when any of: cpu_ewma >= `cpu_trip` (85) continuously for `cpu_trip_seconds` (3); available memory
  < `mem_min_mb` (768); waiters >= `max_waiters` (6); p90 of the last 20 slot waits >= `wait_trip_ms`
  (1200); `error_trip` (5) consecutive failures; `slow_trip` (3) consecutive slow encodes.
  Open for `cooldown_s` (15 s), doubling per consecutive trip up to `cooldown_max_s` (300). After the
  cooldown it only goes half-open if cpu_ewma < `cpu_resume` (70) and memory is fine (hysteresis).
  Half-open admits exactly one request; success closes (cooldown resets), failure re-opens.
* `admit(est_seconds)` context manager: check state -> wait for one of `slots` (2) up to
  `wait_timeout_ms` (1500) -> yield -> record duration/outcome. Raises `Bypass(kind, detail)` with kind in
  `breaker_open` (detail: cpu|mem|queue|wait|errors|slow), `queue_full`, `queue_timeout`.
* Every bypass is an event (`bypass.<kind>`), i.e. "log a failure + kind, and bypass it".
* `below_normal_thread()` context manager lowers the encoding thread's priority (SetThreadPriority
  THREAD_PRIORITY_BELOW_NORMAL) so Caddy and cloudflared always win the CPU.
* media.py publishes `status()` to `/_stats` and to `media.db meta.breaker` every 2 s (worker reads it).
* Per-minute samples (`store.add_sample`): cpu avg/max, mem min avail, breaker open seconds, trips,
  waiters max, wait p90, encodes, encode p95 secs, bypass counts by kind, gate pending/held counts.

## 9. Cloudflare

Current token: purge/WAF/lists missing. Needed (all zone-scoped to example.com):

| permission | why | without it |
|---|---|---|
| Zone › Transform Rules › Edit | edge negotiation rules (6.1, 7.6) | redirect mode (one extra tiny round trip per image view) |
| Zone › Cache Purge › Purge | purge a file (and its `?_v=` variants) the moment a scan holds it or it is replaced | a legacy file flagged after Cloudflare cached it stays at the edge until its TTL (1 year!) |
| (existing) Zone WAF Edit, Account Filter Lists Edit | Strata's edge blacklist | unchanged |

Recommended dashboard toggles (no API permission needed): Caching › Tiered Cache › Smart Tiered Cache
(fewer origin fetches across colos), Speed › Optimization › Polish **off** (we already optimize).

`media_edge.py` (new; imports `cloudflare` for `call`, `zone_id`, `CFError`): `PERMS = {"transform": "Zone › Transform Rules › Edit", "purge": ...}`; `MEDIA_PHASE="http_request_transform"`; refs
`strata_media_avif`, `strata_media_webp`, `strata_media_webm`; `media_rules(hosts, img_exts, vid_exts)`;
`sync_media_rules(enable)` (create/patch/delete by ref, never touching other rules, like `sync()`);
`capabilities()` -> `{"transform": {ok, error, need}, "purge": {...}}` (reads only).

Rule expressions (Cloudflare Rules language):
```
avif: (http.host in {"example.com" "cdn.example.com"}) and http.request.uri.query eq ""
      and http.request.uri.path.extension in {"png" "jpg" "jpeg" "jfif" "gif" "bmp" "tif" "tiff"}
      and any(http.request.headers["accept"][*] contains "image/avif")
      -> rewrite query "_v=avif"
webp: same, and not any(...contains "image/avif") and any(...contains "image/webp") -> "_v=webp"
webm: host ... and query eq "" and http.request.uri.path.extension in {"mp4" "m4v" "mov"}
      and any(http.request.headers["sec-fetch-dest"][*] eq "video")
      and (lower(http.user_agent) contains "chrome/" or lower(http.user_agent) contains "firefox/")
      and not lower(http.user_agent) contains "crios" and not lower(http.user_agent) contains "fxios"
      -> "_v=webm"
```
Action: `"action": "rewrite", "action_parameters": {"uri": {"query": {"value": "_v=avif"}}}`.

`files.urls_for()` (via `media_rules.variant_urls(url)`) adds `?_v=avif`, `?_v=webp`, `?_v=orig` for negotiable images and `?_v=webm`,
`?_v=orig` for videos, so every existing purge (rename, delete, replace, rule change) also purges variants.

## 10. media.db (store.py)

```sql
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS verdict(mount INTEGER NOT NULL, path TEXT NOT NULL, size INTEGER, mtime REAL,
  qhash TEXT, state TEXT NOT NULL, severity TEXT, findings TEXT, engines TEXT, scanned REAL, updated REAL NOT NULL,
  legacy INTEGER DEFAULT 0, reviewed_by TEXT, review_note TEXT, PRIMARY KEY(mount, path)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS verdict_updated ON verdict(updated);
CREATE INDEX IF NOT EXISTS verdict_state ON verdict(state);
CREATE INDEX IF NOT EXISTS verdict_hash ON verdict(size, qhash);
CREATE TABLE IF NOT EXISTS job(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, mount INTEGER, path TEXT,
  params TEXT NOT NULL DEFAULT '', size INTEGER, mtime REAL, priority INTEGER NOT NULL, state TEXT NOT NULL,
  attempts INTEGER DEFAULT 0, lease_until REAL, not_before REAL DEFAULT 0, worker TEXT, created REAL,
  started REAL, finished REAL, error TEXT, error_kind TEXT, result TEXT, UNIQUE(kind, mount, path, params));
CREATE INDEX IF NOT EXISTS job_pick ON job(state, priority, created);
CREATE TABLE IF NOT EXISTS variant(key TEXT PRIMARY KEY, mount INTEGER, path TEXT, src_size INTEGER,
  src_mtime REAL, kind TEXT, fmt TEXT, spec TEXT, file TEXT, bytes INTEGER, src_bytes INTEGER, secs REAL,
  beneficial INTEGER, created REAL, last_used REAL);
CREATE INDEX IF NOT EXISTS variant_src ON variant(mount, path);
CREATE INDEX IF NOT EXISTS variant_used ON variant(last_used);
CREATE TABLE IF NOT EXISTS event(id INTEGER PRIMARY KEY, ts REAL NOT NULL, proc TEXT, kind TEXT NOT NULL,
  severity TEXT, mount INTEGER, path TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS event_ts ON event(ts);
CREATE INDEX IF NOT EXISTS event_kind ON event(kind, ts);
CREATE TABLE IF NOT EXISTS sample(ts INTEGER NOT NULL, proc TEXT NOT NULL, data TEXT, PRIMARY KEY(ts, proc)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
```
Verdict states: `pending`, `clean`, `flagged`, `held` (admin forced), `released` (admin override of a
flag), `error`, `skipped`. `findings` = JSON list of redacted findings (never raw secrets). `engines` =
JSON `{"ocr": "tesseract 5.x"|"missing"|"skipped", "av": ["defender 1.4xx"], "pdf": ...}`. Paths are the
mount-relative decoded path with a leading slash, exactly like `fidx.path` (e.g. `/general/photo.png`).

### 10.1 store.py API (all methods thread-safe; one sqlite connection per thread; busy_timeout 15 s)

```python
class Store:
    def __init__(self, path, readonly=False)
    def init(self)                                       # schema (idempotent)
    # verdicts
    def verdict(self, mount, path) -> dict | None
    def verdicts_since(self, ts) -> list[dict]           # updated > ts, ordered by updated
    def verdict_by_hash(self, size, qhash) -> dict | None  # most severe matching verdict
    def set_verdict(self, mount, path, *, size, mtime, state, qhash=None, severity="", findings=None,
                    engines=None, legacy=0, scanned=None) -> None   # upsert; updated=now; keeps review fields unless state changes to pending
    def review(self, mount, path, state, user, note="") -> bool      # state in ("released","held"); updated=now
    def move_verdict(self, mount, old, new) -> None
    def drop_verdict(self, mount, path) -> None
    def list_verdicts(self, states=None, limit=500, offset=0, q=None) -> list[dict]
    def verdict_counts(self) -> dict[str, int]
    # jobs
    def enqueue(self, kind, mount, path, *, size=None, mtime=None, params="", priority=50,
                not_before=0, force=False) -> int | None
    def claim(self, worker, kinds, lease_s=900) -> dict | None        # atomic (BEGIN IMMEDIATE)
    def heartbeat(self, job_id, lease_s=900) -> None
    def finish(self, job_id, result=None) -> None
    def fail(self, job_id, error, error_kind, retry_in=None, max_attempts=3) -> str   # returns new state
    def requeue_expired(self) -> int
    def cancel(self, kind, mount, path) -> int
    def job_counts(self) -> dict[str, dict[str, int]]                   # kind -> state -> n
    def oldest_queued_age(self, kind=None) -> float | None
    def jobs(self, state=None, kind=None, limit=200) -> list[dict]
    def retry_failed(self, kind=None) -> int
    # variants
    def variant(self, key) -> dict | None
    def put_variant(self, key, *, mount, path, src_size, src_mtime, kind, fmt, spec, file, bytes, src_bytes,
                    secs, beneficial) -> None
    def touch_variants(self, keys) -> None                # batched last_used
    def variants_for(self, mount, path) -> list[dict]
    def drop_variants(self, mount, path) -> list[dict]     # returns rows so the caller can delete files
    def lru_variants(self, limit=500) -> list[dict]
    def variant_totals(self) -> dict                        # bytes, src_bytes, count, beneficial count
    # events / samples / meta
    def add_events(self, rows) -> None                    # rows: dicts with ts, proc, kind, severity, mount, path, detail(dict)
    def events(self, since=0, kind=None, limit=200) -> list[dict]
    def event_counts(self, since) -> dict[str, int]
    def add_sample(self, ts_minute, proc, data) -> None
    def samples(self, since, proc=None) -> list[dict]
    def get_meta(self, k, default=None); def set_meta(self, k, v)
    def prune(self, event_days=30, job_days=14, sample_days=30) -> None
```
Dicts returned use column names; JSON columns (`findings`, `engines`, `detail`, `data`, `result`) are
decoded.

## 11. Other module APIs

```python
# config.py
CONF_PATH = os.environ.get("STRATA_MEDIA_CONFIG") or <media dir>/media.json
def load(path=None) -> dict            # cached by mtime, deep-merged over DEFAULTS (same keys as core.DEFAULTS["media"] + runtime keys)
def category(name) -> str; def ext_of(name) -> str
def gated(name, conf) -> bool
def resolve(mount_conf, url_path) -> tuple[str|None, str|None]   # (full path, decoded rel "/a/b.png"); traversal-safe (port of transform.resolve)
def birth_time(st) -> float
def quick_hash(full, size) -> str      # same as compress.quick_hash
NEGOTIABLE, TRANSFORMABLE, VIDEO_EXT   # sets from 4.1
# runtime keys written by rules.write_media_config: listen, sign_secret, admin_token, db, cache_root,
# event_log, negotiation (effective), cutover, mounts {id: {path, prefix, hosts, cache}} + all tunables

# events.py
class Events:
    def __init__(self, store, log_path, proc)
    def start(self)                                       # flusher thread: every 1 s -> JSONL (rotate 20 MB x5) + store.add_events
    def emit(self, kind, severity="warning", mount=None, path=None, **detail)   # never blocks, never raises
    def counts(self) -> dict ; def recent(self, n=50) -> list

# cache.py
class Cache:
    def __init__(self, root, max_bytes, store)
    def key(self, mount, rel, size, mtime, spec) -> str   # sha1 hex
    def rel_url(self, key, ext, kind) -> str              # "/img/ab/<key>.avif" | "/vid/ab/<key>.webm"
    def path_for(self, key, ext, kind) -> str
    def write_bytes(self, key, ext, kind, data) -> str
    def adopt(self, key, ext, kind, tmp_path) -> str      # os.replace a finished temp file into place
    def tmp_path(self, suffix) -> str                     # under <root>/tmp
    def exists(self, rel_url) -> bool
    def maybe_evict(self)                                 # at most every 60 s, LRU down to 90 % of max
    def usage(self) -> dict                               # bytes, files, disk_free, max_bytes

# breaker.py
class Monitor(threading.Thread): snapshot() -> {"cpu", "cpu_ewma", "mem_avail_mb", "mem_pct", "ts"}
class Bypass(Exception): kind, detail
class Breaker: __init__(name, monitor, conf, events=None, clock=time.monotonic); state; check();
               admit(est_seconds=0.0) (contextmanager); record(ok, secs, slow=False); trip(reason);
               force(state, seconds=None); status() -> dict
def below_normal_thread()  (contextmanager); def set_process_priority(level)   # "below_normal"|"idle"|"normal"

# sandbox.py
class Result: rc, out (str), err (str), timed_out, secs, killed (str|None)
def run(cmd, timeout, mem_mb=1024, cpu_pct=35, priority="idle", cwd=None, env=None, max_output=4<<20) -> Result
def which(name, conf) -> str | None                     # name in ffmpeg ffprobe 7z tesseract mpcmdrun clamscan clamdscan
def tools(conf) -> dict[str, str|None]
def safe_join(root, *parts) -> str                       # raises ValueError when escaping root
def rmtree(path) -> None

# imaging.py
def probe(path) -> dict   # format, mode, w, h, frames, lossless, alpha, mp
class CostModel: observe(fmt, speed, mp, secs); estimate(info, fmt, speed, src_bytes) -> float
def choose(info, want, conf) -> Plan                      # Plan: fmt, opts, animated, reason
def encode_auto(src, info, plan, conf, sync=True) -> tuple[bytes, str]      # (data, fmt)
def encode_explicit(src, params, conf) -> tuple[bytes, str]                  # legacy transform semantics
def validate_explicit(params, conf) -> dict              # raises ValueError (-> 400)
CONTENT_TYPE = {"avif": "image/avif", "webp": "image/webp", "jpeg": "image/jpeg", "png": "image/png"}

# video.py
def available(conf) -> dict; def probe(path, conf) -> dict; def plan(info, conf) -> dict | None
def transcode(src, dst, plan, conf) -> sandbox.Result

# detect.py
SEVERITY = {"low": 1, "medium": 2, "high": 3}
def scan_text(text, where="", conf=None, ocr=False, web_asset=False) -> list[dict]
def redact(value) -> str                                  # "ghp_…Xy3Q" (first 4 + last 4, never more than 25 %)
def exif_findings(img, conf=None) -> list[dict]; def svg_findings(text) -> list[dict]
def pdf_active_findings(raw_bytes) -> list[dict]; def name_findings(relpath) -> list[dict]
def max_severity(findings) -> str                          # "none" | "low" | "medium" | "high"
# finding dict: {"type", "severity", "sample", "where", "confidence"}

# extract.py
class ArchiveError(Exception); class BombError(ArchiveError); class EncryptedError(ArchiveError)
def extract(path, dest, conf, tools, depth=0, budget=None) -> dict   # {"files": [(rel, abs, size)], "findings": [...], "tool": str}

# scan.py
class ScanResult: state, severity, findings, engines, secs, error_kind
def scan_file(full, name, conf, tools, cancel=None, sandbox_dir=None) -> ScanResult
def av_scan(path, conf, tools) -> dict                    # {"engine", "ok", "threats": [...], "error"}
def ocr_image(img_or_path, conf, tools, where="") -> tuple[str, dict]
```

## 12. `core.DEFAULTS["media"]`

```python
"media": {
    "enabled": False,                 # kill switch; OFF until deployment (then save_config media.enabled=True)
    "listen": "127.0.0.1:8084",
    "cache_root": "<home>/data/media-cache",
    "cache_max_gb": 30,
    "db": "data/media.db",
    "event_log": "<caddy folder>/logs/media-events.jsonl",
    "negotiation": "auto",            # auto | edge | redirect | off
    "cutover": 0,                     # set on first start
    "admin_token": "",                # generated on first start; guards media.py /_admin/*
    "gate": {"enabled": True, "categories": ["image", "svg", "pdf", "archive", "document", "text", "exec"],
             "legacy_while_pending": True, "pending_retry_after": 30},
    "lane": {"enabled": True, "min_bytes": 512 << 20, "total_mbps": 25, "per_conn_mbps": 10},
    "breaker": {"cpu_trip": 85, "cpu_resume": 70, "cpu_trip_seconds": 3, "mem_min_mb": 768, "slots": 2,
                "max_waiters": 6, "wait_timeout_ms": 1500, "wait_trip_ms": 1200, "error_trip": 5,
                "slow_trip": 3, "cooldown_s": 15, "cooldown_max_s": 300},
    "image": {"sync_budget_s": 6.0, "sync_max_mp": 40, "max_mp": 150, "bg_max_mp": 280, "min_bytes": 4096,
              "avif_quality_lossy": 62, "avif_quality_lossless": 74, "webp_quality": 86, "speed_sync": 7,
              "speed_bg": 5, "threads": 2, "min_saving": 0.10, "short_ttl": "public, max-age=60",
              "prewarm_uploads": True, "prewarm_popular": 200, "max_dim": 4096},
    "video": {"enabled": True, "codec": "av1", "crf_av1": 30, "preset_av1": 8, "crf_vp9": 32,
              "audio_kbps": 128, "threads": 2, "cpu_pct": 50, "max_seconds": 10800, "max_bytes": 8 << 30,
              "min_saving": 0.10, "timeout_factor": 15},
    "scan": {"hold_threshold": "medium", "av_engines": ["defender", "clamav"], "require_av": True,
             "av_categories": ["archive", "pdf", "document", "exec", "svg"], "text_max_bytes": 8 << 20,
             "timeout_s": 1800,
             "archive": {"max_total_bytes": 24 << 30, "max_entries": 50000, "max_entry_bytes": 12 << 30,
                         "max_ratio": 250, "max_depth": 3, "ocr_images": 25, "text_bytes": 64 << 20,
                         "hold_inner_ext": ["scr", "com", "pif", "hta", "lnk", "vbs", "vbe", "jse", "wsf",
                                            "wsh", "ps1", "bat", "cmd", "msi", "reg"],
                         "report_inner_ext": ["exe", "dll", "jar", "apk", "sys"]},
             "pdf": {"max_pages": 300, "ocr_pages": 30, "dpi": 170}},
    "ocr": {"engine": "tesseract", "required": True, "langs": "eng", "psm": 3, "tile_px": 2400, "max_mp": 60,
            "timeout_s": 180, "min_side": 48},
    "detect": {"private_ip_severity": "low", "public_ip_severity": "medium", "email_severity": "low",
               "gps_severity": "low", "entropy_min": 3.8},
    "worker": {"cpu_max": 65, "mem_min_mb": 1024, "lease_s": 900, "max_attempts": 3, "backfill": True},
    "tools": {"ffmpeg": "", "ffprobe": "", "7z": "", "tesseract": "", "mpcmdrun": "", "clamscan": "",
              "clamdscan": ""},
    "capacity": {"uplink_mbps": 50, "cpu_p95": 85, "mem_p95": 90, "backlog_hours": 6, "open_ratio": 0.10,
                 "cache_free_pct": 10},
    "file_policy": {
        "enabled": True,
        "deny_names": [".env", ".env.*", ".git", ".svn", ".hg", ".htaccess", ".htpasswd", ".npmrc", ".pypirc",
                       ".netrc", ".bash_history", ".ssh", ".aws", ".azure", ".kube", ".docker", "id_rsa",
                       "id_dsa", "id_ecdsa", "id_ed25519", "authorized_keys", "known_hosts", "web.config",
                       "wp-config.php", "appsettings*.json", "secrets.*", "secret.*", "credentials",
                       "credentials.*", "docker-compose.yml", "docker-compose.yaml", "terraform.tfstate*",
                       "thumbs.db", "desktop.ini", "strata.json", "media.json", "transform.json",
                       "telemetry.json"],
        "deny_ext": ["env", "ini", "cfg", "conf", "config", "cnf", "properties", "yml", "yaml", "toml", "sql",
                     "sqlite", "sqlite3", "db", "mdb", "accdb", "bak", "backup", "old", "swp", "swo", "tmp",
                     "log", "pem", "key", "crt", "cer", "csr", "der", "p12", "pfx", "jks", "keystore", "kdbx",
                     "asc", "gpg", "pgp", "ovpn", "rdp", "ppk", "tfstate", "php", "phtml", "asp", "aspx",
                     "jsp", "cgi", "pl"],
        "safe_ext": ["png", "jpg", "jpeg", "jfif", "gif", "webp", "avif", "bmp", "ico", "svg", "tif", "tiff",
                     "heic", "heif", "jxl", "psd", "tga", "mp4", "m4v", "webm", "mkv", "mov", "avi", "wmv",
                     "flv", "ts", "m3u8", "ogv", "mp3", "flac", "wav", "ogg", "oga", "opus", "m4a", "aac",
                     "wma", "mid", "midi", "html", "htm", "css", "js", "mjs", "map", "json", "webmanifest",
                     "wasm", "xml", "txt", "md", "csv", "tsv", "srt", "vtt", "ass", "ttf", "otf", "woff",
                     "woff2", "eot", "blend", "blend1", "fbx", "obj", "glb", "gltf", "stl", "ply", "3ds",
                     "dae", "usd", "usdz", "pdf", "epub", "docx", "xlsx", "pptx", "odt", "ods", "odp",
                     "zip", "7z", "rar", "tar", "gz", "tgz", "bz2", "xz", "zst", "mrpack", "br"],
        "safe_names": ["LICENSE", "LICENCE", "README", "CHANGELOG", "COPYING", "NOTICE", "AUTHORS"],
        "svg_csp": True},
}
```
`deny_*` wins over `safe_*`. `.br` is only listed so precompressed sidecars keep working (Caddy serves
them itself via `precompressed br`; direct requests are harmless). Existing executables (`.exe .bat .py`)
become 403 unless an `allow` access rule covers them; allowed executables still pass the AV gate
(category `exec`). `rules.file_policy_preview(db)` lists what the policy blocks today (fidx-based).

## 13. Bridge (media_bridge.py, inside strata.py)

**Never call `rules.ALERT_HOOK` (or anything that opens a strata.db connection) while holding an open
strata.db transaction** — alerts.raise_ opens its own connection and deadlocks into "database is locked"
(found by the credential-crawler session in autoban). Collect alerts, commit/close, then raise.

Thread `Bridge` (daemon), loops with independent timers:
* 10 s: `Supervisor.ensure()`
* 5 s: verdict watcher (`store.verdicts_since`): newly `flagged|held|error` -> `cloudflare.purge_async(
  files.urls_for(m, rel))`, alert `("media", "warning", "Held for review: <path>", "<redacted finding
  summary>", key "media-hold:<mount>:<path>")`; newly `released` -> nothing to purge.
* 2 min: discovery: `fidx` (strata.db) vs `verdict` -> enqueue `scan` for gated files without an up-to-date
  verdict (priority 60 new / 80 legacy); verdicts for files missing from fidx (and missing on disk) are
  dropped along with their variants (files deleted from the cache). Also prewarm: new images (born after
  cutover) -> `image` job `want=avif` priority 70; top `prewarm_popular` requested images of the last 30
  days (files.hits_by_path) priority 85.
* 60 s: events watcher -> alerts for `tool.missing` (warning), `supervisor.restart` (warning), repeated
  `job.failed` (> 10/h, warning).
* 5 min: capacity advisor (13.1) -> `meta` in strata.db `media_capacity` + alerts (coalesce 24 h, key
  `capacity:<resource>`).
* on start and every 6 h and on settings change: negotiation: mode `auto`/`edge` -> `cloudflare.sync_media_rules(True)`;
  success -> effective `edge`; permission error -> effective `redirect` (auto) / keep trying + warning
  (edge); `redirect`/`off` -> `sync_media_rules(False)` (best effort). Effective change -> store meta and
  trigger `rules.APPLY_SOON` so the Caddy config follows.
* first start: `cutover` = now (saved via `core.save_config`), `admin_token` generated.
* `on_upload(mount, rel, full)` (called from strata.after_upload): enqueue `scan` priority 20 (+ prewarm).
* `on_rename(mount, old, new)`: `store.move_verdict`.

### 13.1 Capacity advisor ("tell me when it's bottlenecking")

Inputs: strata.db `metric` per-minute (`host_cpu`, `host_mem`, `tunnel_tx`), media.db samples/events/jobs,
cache usage. Advice rows `{resource, level: watch|upgrade, evidence, recommendation}`:
* CPU: host_cpu p95 (1 h) > `cpu_p95` AND (breaker open ratio (1 h) > `open_ratio` OR oldest queued job
  > 2 h) -> "add 2 vCPU (6 -> 8)"; breaker trips (24 h) > 20 -> watch.
* Memory: host_mem p95 > `mem_p95` or any `bypass.breaker_open` with detail mem in 1 h -> "add 4 GB RAM".
* Backlog: oldest queued scan > `backlog_hours` or > 500 queued -> "background pipeline behind (scans)".
* Uplink: tunnel_tx p95 (1 h) > 80 % of `uplink_mbps` -> "uplink saturated" + hints (Tiered Cache,
  purge permission, large-file lane).
* Disk: cache disk free < `cache_free_pct` -> "cache disk".

### 13.2 Admin API (strata.py dispatches `/api/media/*` to `media_bridge.api_get(user, path, q)` / `api_post(user, ip, path, body)`; existing login + CSRF apply)

GET  `/api/media/status` — processes, breaker, monitor, tools, cache usage, negotiation (configured,
     effective, edge rule state), counts (verdicts by state, jobs by kind/state, oldest ages), capacity advice,
     event counts (24 h) by kind, savings (variant totals).
GET  `/api/media/holds?state=flagged,held,error,pending&q=&limit=&offset=`
GET  `/api/media/events?kind=&since=&limit=`
GET  `/api/media/jobs?state=&kind=`
GET  `/api/media/policy` — `rules.file_policy_preview`
POST `/api/media/release {mount, path, note}` · `/api/media/hold {mount, path, note}` ·
     `/api/media/rescan {mount, path}` · `/api/media/retry {kind}` ·
     `/api/media/settings {negotiation?, gate_legacy?, hold_threshold?}` (save_config + apply) ·
     `/api/media/breaker {state: "open"|"closed"|"auto", seconds}` (maintenance switch via media
     `/_admin/breaker` with the admin token)
Every POST is audited (`core.audit`).

### 13.3 UI integration notes (from the "UI/UX spacing and layout" session)

* index.html: add `<script src="media.js"></script>` **before** `<script src="layout.js"></script>` (layout.js
  must stay last) plus one nav entry.
* Inherited layout rules: `.settings/.upview/.ins` grids use `grid-auto-rows: max-content`; `.set-row` wraps its
  control under the label when narrow; control heights `--ctl` 32px (panels/header) and `--ctl-sm` 28px
  (`.pill/.seg-row/.tbar` inputs; `.tbar .input` is width:auto); dialogs cap at 88 % of the viewport and scroll
  inside; use `calc(N * var(--vh))` instead of `Nvh`; a `.split` with an inline `grid-template-columns:
  1fr <N>px` gets a draggable, remembered side panel from layout.js — use it for the Media view's aside.

## 14. media.py endpoints

* `GET|HEAD /_gate` — signed links (unchanged).
* `GET|HEAD /_scan` — forward_auth gate (5.2). Needs `X-Strata-Mount`, `X-Forwarded-Uri`.
  Allow -> `200`, empty body, optional `X-Strata-Lane: throttle`. File missing -> `200` (file_server
  then produces the normal 404 page).
* `GET|HEAD <path>` with `X-Strata-Mount` -> variants / explicit transforms / `?ver=` / negotiation
  (`X-Strata-Negotiate: 1`) / throttled lane (`X-Strata-Throttle: 1`).
* `GET /_stats` — JSON status (loopback only, no token): breaker, monitor, counters, cache, gate cache
  size, negotiation, version, uptime, recent events.
* `POST /_admin/breaker` — `X-Strata-Admin-Token` required; `{"state": "open|closed|auto", "seconds": n}`.
* Anything else -> 404/405. Non-loopback peers -> 403 (as transform.py).
* Server: `ThreadingHTTPServer`, `daemon_threads`, `request_queue_size = 64`, `--config <path>` and
  `--listen host:port` CLI overrides for tests.

## 15. Tests (`media/tests`, stdlib unittest, `python -m unittest discover -s media/tests`)

Unit: detect (true positives per pattern, OCR-noise variants, false-positive corpus: version numbers,
UUIDs, hashes in filenames, lorem ipsum), breaker (fake monitor + fake clock: trip/cooldown/half-open/
hysteresis/queue full/timeout), store (claim atomicity with threads, dedupe, leases, retries), extract
(zip slip, absolute paths, symlink tar, ratio bomb, too many entries, encrypted zip, nested depth), imaging
(choice matrix, not-beneficial, animated GIF, ICC kept, EXIF dropped, explicit transform parity with
transform.py), gate decision matrix, rules render (render against a temp copy of strata.db and
`caddy validate` the whole Caddyfile).
E2E (`test_e2e.py`): temp mount dir with fixtures; media.py on 127.0.0.1:18083 and a private Caddy
(`admin localhost:2099`, site `:18080`) running a rendered config that points at the test ports/dirs;
worker `--once`. Scenarios: canonical PNG in redirect mode -> 302 -> `_v=avif` -> AVIF bytes with Range;
`_v=webp`; not-beneficial small PNG -> original bytes; forced-open breaker -> original + `bypass.breaker_open`
event with kind; `.env` -> 404; `.exe` -> 403; unknown `.xyz` -> 403; new PDF -> 503 then 200 after worker;
text file with a GitHub token -> 403 held; zip-slip archive -> held; `_v=webm` without ffmpeg -> 302
`?_v=orig`; `.svg` gets the CSP header; large-file lane throttles (rate measured). **Never touches the
production ports (8080/8083/8090/2019) or the production strata.db.**
