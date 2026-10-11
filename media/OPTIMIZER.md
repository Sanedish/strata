# Strata image optimizer

Adaptive, bandwidth-first image delivery for the `:8080` CDN, built on Strata Media (DESIGN.md). Deployed
2026-10-03 in the **images-only profile**: `media.enabled` on, scan gate / file policy / large-file lane / video
off. Originals on the NAS are never modified; everything derived lives under `media.cache_root` (`E:/strata-media`).

## Request path

```
Cloudflare (cache keyed by URL; Free plan ignores Vary: Accept)
  edge mode:  Transform Rule adds ?_v=avif|webp to query-less images by Accept, before the cache lookup
  |
cloudflared -> Caddy :8080 (generated/cdn.caddy, rendered by rules.py + media_rules.py)
  0 request_header -X-Strata-*            clients cannot inject internal headers
  1 blacklist  2 access rules (password / signed / geo ... run first, unchanged)  3 short links  3b galleries
  4 ?dl=1
    @neg  image, query names no _v/fm/h/q/fit/ver/dl     -> media.py: 302 ?[w=<rung>&]_v=avif|webp|orig
          (redirect mode: every such request; edge mode: only ?w=)         private, no-store, Vary: Accept
    @mv   image + (_v=avif|webp | w/h/fm/q/fit)          -> media.py decides, Caddy serves the bytes:
          accel -> file_server from <cache_root>/cache (persistent or ephemeral tier)  Range/ETag/304/HEAD
          orig  -> file_server from the NAS (precompressed br kept)
          304 / 302 / 4xx pass through
    @ver  ?ver=N -> Strata Transform :8083 (unchanged), /_gate signed links (unchanged)
  5 drives: everything else exactly as before (non-images, ?_v=orig, ?nocompress=1 ...)
```

media.py on a variant request: bypass? -> lookup(key) [persistent hit | ephemeral hit | recorded decision |
304 from the recorded ETag] -> miss: HEAD/conditional/backoff/expensive => original now (60 s CDN TTL) + one
background job; cheap => single-flight encode now (breaker-admitted, below-normal priority) -> ephemeral tier.

## Variant identity

`cache.key(mount, path, size, mtime, spec)`, spec `auto:<avif|webp>:w=<px|full>:<profile>:v2`. `profile` hashes
the qualities, the manual `image.profile` bump and the libavif/libwebp versions (not the speed). A changed source
or setting gives new keys: stale variants are unreachable at once; the bridge reclaims their disk on its 2-min
discovery pass (deleted source: all variants; changed source: the old content's).

## Tiers

| tier | where | kept by | leaves by |
|---|---|---|---|
| source | NAS | always | never touched |
| ephemeral | `cache/img/ab/cd/<key>.<ext>` | LRU (`cache_max_gb`) + age (`tiers.ephemeral_max_age_days`) | eviction -> tombstone row (hotness + ETag survive) |
| persistent | `cache/static/img/ab/cd/<key>.<ext>` | promotion | demotion (cold, or over `tiers.persistent_max_gb`) |

Promotion pass every `tiers.interval_s`: requests/day = decayed score x ln2 / half-life. Promote when
`hits >= promote_min_hits`, `rate >= promote_rate_per_day` and
`value = rate x horizon_days x (src - variant bytes) + encode_secs x cpu_mb_per_s MB - bytes x storage_weight`
`>= promote_min_value_mb`. Demote only when `rate < demote_rate_per_day` AND idle `> demote_idle_days`
(hysteresis). A promoted AVIF is re-encoded once in the background at `speed_bg` and replaced in place when smaller.
Hotness counts *origin* requests (Cloudflare serves the rest), so "hot" means "keeps missing Cloudflare".

## Configuration (strata.json "media" -> media/media.json; all live-reloaded)

```
media.enabled                      kill switch
media.negotiation                  auto | edge | redirect | off   (auto: edge once the token may edit Transform Rules)
media.cache_root, cache_max_gb     variant store, ephemeral cap
media.breaker.slots / max_waiters  max concurrent sync encodes / queue in front of them
media.image.avif_quality_lossy|_lossless|_alpha_quality, webp_quality, jpeg_quality, profile
media.image.speed_sync / speed_bg  AVIF effort on the request path / in the worker
media.image.min_saving             0.10: a full-size variant must be 10 % smaller than the original
media.image.sync_budget_s / sync_budget_max_s / sync_max_mp / sync_max_bytes   first-request budget
media.image.max_mp, bg_max_mp, max_source_bytes, max_frames, max_anim_mp, max_queue_depth  resource limits
                                   (max_anim_mp = frames x output MP of an animation; 96 = 1080p x ~140 frames)
media.image.widths, max_width, snap_widths   width ladder
media.image.debug_headers          X-CDN-Image-Format / -Cache / -Source / -Width
media.image.prewarm_uploads (off), prewarm_popular (200 most requested), media.worker.backfill (off)
media.image.tiers.*                interval_s half_life_h promote_min_hits promote_rate_per_day promote_min_value_mb
                                   horizon_days storage_weight cpu_mb_per_s demote_rate_per_day demote_idle_days
                                   persistent_max_gb ephemeral_max_age_days tombstone_days failure_retry_h upgrade_on_promote
```

## Public URL behaviour

| request | answer |
|---|---|
| `/x.png` (redirect mode) | `302 /x.png?_v=avif` (or webp / orig) by Accept; `private, no-store`, `Vary: Accept` |
| `/x.png?_v=avif` | AVIF if it pays off, else the original; `Vary: Accept` |
| `/x.png?w=1000` | `302 ?w=1080&_v=avif`; rung >= source width -> full size; never upscales |
| `/x.png?w=1080&_v=orig` | resized in the source format family (PNG/JPEG); animations stay the original |
| `/x.png?nocompress=1` (1/true/yes/on/bare) | the original, cacheable under its own URL |
| `Cache-Control: no-transform` | the original, `private, no-store` + CDN `no-store` (never cached) |
| `?w=..&fm=..&q=..&h=..&fit=..` | legacy explicit transform, exact transform.py semantics |
| `?ver=N`, `?dl=1`, non-images | unchanged |

## Observability

* media.py `GET /_metrics` (loopback): `image_optimizer_*` Prometheus counters/gauges (requests by result/format/cache,
  original/served/saved bytes, encodes, failures, duration histogram, cache hits/misses, promotions, demotions,
  evictions, queue depth, tier bytes).
* `GET /_stats` -> `optimizer` (since start + lifetime per variant) -> Strata > Media > Image optimizer panel.
* media.db `sample` rows (per minute): `optimizer.{original,served,saved}` bytes.

## Operations

* Turn it off: `media.enabled=false` in Strata > Media (or strata.json) -> Caddy config re-renders to the old
  transform routes; Strata Transform (:8083) never stopped.
* Force a re-encode of everything: bump `media.image.profile`.
* Cloudflare: grant the token **Zone > Transform Rules > Edit** to move from redirect to edge mode automatically
  (no extra round trip per image view). Keep Polish off.
