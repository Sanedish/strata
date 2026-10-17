# Distributed media encoding plan

This document is the implementation contract for moving background video jobs to GPU nodes. The current
`media/worker.py` remains the local scan and image worker; `media/video.py` can use local NVENC for MP4 when
configured. Remote execution is **not yet wired**. Do not put `media.db` on SMB/NFS or copy it to another node:
SQLite, the variant cache, and the public Caddy route stay on the Strata origin.

## Goals and scheduling

The objective is fewer bytes sent from the origin and fewer reads of source drives. Extra cache space is acceptable.
Keep original files immutable. A viewer gets the original while a video job runs; a completed, beneficial variant is
then served by Caddy from the origin's local cache. No viewer waits for a remote GPU.

One coordinator on the origin owns the job queue, leases, source identities, policies, and variant cache. Each GPU
node runs an outbound-only agent. It advertises an ID, health, free slots, FFmpeg/driver versions, encoder names,
and per-encoder formats. The coordinator assigns only compatible jobs and prefers a healthy GPU node for MP4/H.264
when policy allows it. CPU remains a fallback. A node may process several jobs only up to its configured slot count.
Scans and image requests stay local initially; the remote protocol is for background video only.

## Two source transports

* **Shared mount**: a node has read-only access to the same media share. Its configuration maps a Strata mount ID
  to a local root, rather than accepting a path from the coordinator. It resolves the mount-relative path with the
  same traversal and symlink checks as `config.resolve`, then compares size, mtime, and a source fingerprint before
  and after encoding. This is the preferred transport when both Proxmox clusters can read the NAS.
* **Transfer**: when a share is unavailable, the node downloads the original from a private, authenticated origin
  endpoint into bounded local scratch space. The source is streamed with a byte cap and hash; it is never read into
  Python memory as one object. The same post-transfer fingerprint check applies. Resume with HTTP Range only when
  the generation/ETag matches. A transport policy can forbid transfer above a configured size or across an expensive
  link. A job stays queued for a shared node or runs locally if neither transport is suitable.

Both modes upload the encoded result to the coordinator. The origin streams it to a temporary cache file, verifies
its size, checksum, container/codec, policy, source generation, and lease token, and then atomically adopts it into
the cache. A node never writes directly to the origin's cache or database. A failed or oversized encode leaves the
original in service. Compare output size to `min_saving` before adopting, so NVENC speed cannot increase CDN traffic.

## Private protocol

Use a separate listener from the public media port, reachable only over WireGuard/Tailscale or an equivalent private
network, with TLS and a unique revocable credential per node. The coordinator must not expose these endpoints through
Caddy's public CDN. Suggested operations:

| Operation | Purpose |
| --- | --- |
| `POST /nodes/heartbeat` | Capabilities, load, free slots, versions, health. |
| `POST /jobs/claim` | Atomically reserve one compatible video job; return job ID, lease token, source generation, policy snapshot, and transport. |
| `POST /jobs/{id}/heartbeat` | Extend the lease and report progress; indicate cancellation or changed source. |
| `GET /jobs/{id}/source` | Authorized, bounded source stream for transfer mode; conditional Range for resume. |
| `PUT /jobs/{id}/result` | Bounded output stream plus checksum and ffprobe metadata; commit only after verification. |
| `POST /jobs/{id}/fail` | Structured error and retry hint; fall back to CPU if hardware is unavailable. |

Claim and completion need a short transaction in `store.py`. Lease renewal and completion must compare both the job
ID and the opaque lease token, not just `state='running'`, so an expired node cannot finish a job re-leased elsewhere.
Never embed an absolute source path, credential, or arbitrary FFmpeg switches in a job. Generate FFmpeg arguments
from validated policy at the worker. Permit only known input demuxers and local `file:` input as `media/video.py` does.
Rate limit claims and downloads; cap bytes, duration, scratch space, and concurrent uploads. Retain node ID, encoder,
transport, policy ID, time, source/output bytes, and failures in events and metrics without logging credentials.

## Configuration model

Add a versioned `media.distributed` section at the origin, with `enabled`, private `listen`, node enrollment,
`max_remote_jobs`, `prefer` (`local|remote|auto`), `fallback` (`local|queue`), `transfer.max_bytes`,
`transfer.max_mbps`, `transfer.allow_hosts`, `lease_s`, and `heartbeat_s`. Agent configuration holds its node ID,
coordinator private URL, certificate or token path, `slots`, scratch path and byte cap, and an optional
`mounts: {<origin mount ID>: <local read-only root>}` map. Credential material belongs in `.env` or protected files,
never in `strata.json`, `media.json`, UI responses, or job rows.

The admin UI should show each node's heartbeat age, capabilities, active jobs, transport, error rate, input/output
bytes and savings. Controls should drain/pause a node, set slots and transport policy, and retry failed jobs. Format,
quality, preset, audio rate, size gate, duration, and max source bytes remain origin-owned policy; node-specific
configuration is limited to capacity and local paths. Every encoding policy change creates a new variant spec, so old
outputs are never mistaken for outputs of the new settings. Old cache files can be evicted normally.

## Rollout and validation

1. Add token-aware claim/renew/complete transactions and unit tests for expired leases and cancellation.
2. Add the private coordinator API and a node agent with shared-mount mode. Test with synthetic files on two hosts.
3. Add transfer mode with streaming, byte/rate limits, resume, and content verification. Test a node without the share.
4. Add capability-aware scheduling, CPU fallback, node management UI, and metrics.
5. Test a real T1000 using `ffmpeg -hide_banner -encoders` and a short encode. Presence in the encoder list proves
   that FFmpeg was built with NVENC; only a live encode proves that the driver and GPU can run it. Compare actual
   byte savings and quality against the CPU preset before changing the default policy.

Keep on-demand image encoding local until remote jobs demonstrably reduce drive reads and latency. CDN cache hit rate,
origin egress, NAS read bytes, and encoded output size are the success measures; encoder speed alone is insufficient.

NVIDIA's [FFmpeg acceleration guide](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/ffmpeg-with-nvidia-gpu/index.html)
and [current SDK deprecation notices](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/deprecation-notices/index.html)
are the reference for runtime capabilities and supported NVENC presets.
