'use strict';
/* Strata Media: admin view of the edge-processing pipeline (media/DESIGN.md 13.2). Health of the hot path (media.py)
   and the background worker, the circuit breaker with its maintenance switch, CPU / encode slots / variant cache,
   format negotiation (configured vs effective, Cloudflare edge rules), tool availability, what the scan gate holds
   back (release / keep held / rescan, audited), jobs, the event log, capacity advice ("tell me when it bottlenecks"),
   the file-policy preview and the three operator settings.
   Loaded after app.js / storage.js / control.js and registers itself through their extension points (VIEWS, VIEWFN,
   ACT, MENUS, VIEW_REFRESH, NAV_BADGES, STATIC_VIEWS, NAV_C): index.html only needs the <script> tag.
   Everything lives in one IIFE because the admin scripts share one global scope - a top-level const that clashes
   with another module (storage.js already has mountName, MiB, D.jobs ...) would throw and take this file down.
   Paths, findings and event details describe files anyone can upload: they reach the DOM only through esc(). The
   bridge behind /api/media/* is built separately, so every field is read defensively (media/HOOKS-ui.md lists the
   shape this view prefers) and a missing one renders as "—" instead of throwing - a throw inside a view function
   would also stop app.js's live polling. media.enabled is a kill switch that stays off until deployment: a status
   with enabled=false (or /api/media/* not dispatched yet) shows a calm "not deployed" page, never red errors. */

(() => {
  if (typeof VIEWFN !== 'object' || typeof ACT !== 'object' || typeof NAV_C === 'undefined') return; // no app.js

  /* ------------------------------------------------------------------ constants */

  const POLL_MS = 5000;        // status refresh, only while this view is on screen
  const BADGE_MS = 60000;      // elsewhere: a status-only read for the nav badge, only while the tab is visible
  const LIST_MAX_AGE = 60;     // holds / events / failed jobs reload when their counts move, and at least this often
  const POLICY_MAX_AGE = 600;  // the policy preview walks the whole file index: on demand or every 10 min at most
  const NOT_HOOKED = /^(not found|HTTP 404)$/i;  // strata.py does not dispatch /api/media/* (yet)
  // bridge refusing because media.enabled is false, e.g. {"error": "media pipeline disabled"} (HOOKS-ui.md)
  const SWITCHED_OFF = /\b(media|pipeline)\b[^.]*\b(disabled|switched off|not (deployed|enabled))\b/i;
  const HOLD_LIMIT = 200, EVENT_LIMIT = 200, FAILED_SHOWN = 50, CPU_POINTS = 72, MIB = 1048576;
  const HOLD_FILTERS = [
    ['review', 'Held back', 'flagged,held,error'], ['flagged', 'Flagged', 'flagged'], ['held', 'Held by admin', 'held'],
    ['error', 'Scan error', 'error'], ['pending', 'Pending', 'pending'], ['released', 'Released', 'released'],
    ['all', 'All', 'flagged,held,error,pending,released'],
  ];
  const FILTER_OF = { flagged: 'flagged', held: 'held', error: 'error', pending: 'pending', released: 'released' };
  const SINCE = [['3600', '1 h'], ['21600', '6 h'], ['86400', '24 h'], ['604800', '7 d']];
  const NEG_MODES = [['auto', 'Auto'], ['edge', 'Edge'], ['redirect', 'Redirect'], ['off', 'Off']];
  const NEG_HELP = {
    auto: 'Cloudflare edge rules when the API token may manage Transform Rules, otherwise origin redirects.',
    edge: 'Cloudflare adds ?_v=avif|webp before its cache lookup: same URL, no extra round trip.',
    redirect: 'The origin answers a tiny 302 to ?_v=avif|webp|orig: one extra round trip per image view.',
    off: 'Only explicit ?fm= / ?_v= URLs get AVIF / WebP; canonical URLs serve the original.',
  };
  const THRESHOLDS = [['low', 'Low'], ['medium', 'Medium'], ['high', 'High']];
  const THRESHOLD_HELP = {
    low: 'Hold on any finding, even private IPs, e-mail addresses or GPS tags: strictest, most false positives.',
    medium: 'Hold on medium findings and above: passwords, public IPs, active content, unscannable files. Default.',
    high: 'Hold only on high findings (tokens, private keys) and AV detections: unscannable files get published.',
  };
  const TOOLS = [
    ['ffmpeg', ['ffmpeg'], 'video jobs fail and ?_v=webm keeps redirecting to the original'],
    ['ffprobe', ['ffprobe'], 'videos cannot be probed, so no WebM variants'],
    ['7z', ['7z', '7zip', 'sevenzip'], 'rar / 7z / zst archives are held as unscannable (zip and tar still work)'],
    ['tesseract', ['tesseract', 'ocr'], 'images and scanned PDF pages that need OCR are held as unscannable'],
    ['defender', ['defender', 'mpcmdrun'], 'no Microsoft Defender scans'],
    ['clamav', ['clamav', 'clamscan', 'clamdscan'], 'no ClamAV scans (fine while Defender works)'],
    ['pypdfium2', ['pypdfium2', 'pdfium'], 'no PDF text extraction: PDFs are held as unscannable'],
  ];
  const STATE_COLOR = { clean: 'var(--color-text)', released: 'var(--color-neutral-500)', skipped: 'var(--color-neutral-400)',
    pending: 'var(--color-neutral-300)', error: 'var(--color-accent-2-500)', flagged: 'var(--color-accent)',
    held: 'var(--color-accent-800)' };
  const STATE_ORDER = ['flagged', 'held', 'error', 'pending', 'released', 'skipped', 'clean'];
  const HOT_STATES = new Set(['flagged', 'held', 'error']);
  const RELEASABLE = new Set(['flagged', 'held', 'error', 'pending']);
  const SEV = { none: 0, low: 1, medium: 2, high: 3 };
  const HOT_KIND = (k) => /^(bypass\.(breaker_open|encode_error|decode_error)|tool\.missing|job\.failed|supervisor\.)/.test(k);
  const REASONS = { dangerous: 'dangerous name or extension · 404', deny_name: 'dangerous name · 404',
    deny_names: 'dangerous name · 404', deny_ext: 'dangerous extension · 404', unknown: 'not a known-safe type · 403',
    not_safe: 'not a known-safe type · 403', unsafe: 'not a known-safe type · 403', rescued: 'allowed by an access rule',
    svg: 'SVG · served with a CSP' };
  const REASON_SHORT = { dangerous: '404', deny_name: '404', deny_names: '404', deny_ext: '404', unknown: '403',
    not_safe: '403', unsafe: '403' };
  const CAP_LABEL = { transform: 'Transform Rules', purge: 'Cache Purge', zone: 'Zone access', waf: 'WAF rules', lists: 'IP lists' };

  // Media panels are as tall as their content (the .ins cap of 460px squeezed the holds / jobs tables); long lists
  // scroll inside boxes sized from --vh (1 % of the zoomed viewport), never from raw vh.
  const CSS = `
.mdv .md-full { grid-column: 1 / -1; }
.mdv .kpis { border-bottom: 0; }
.ins.mdv > .panel { max-height: none; }
.ins .panel.md-short { min-height: 0; }
.ins.mdv > .panel.md-set { container-type: inline-size; }
.tbar #md_q { flex: 1 1 130px; max-width: 240px; }
.md-list { max-height: max(220px, calc(38 * var(--vh))); overflow-y: auto; }
.md-list .logline span:last-child { max-width: 48%; overflow: hidden; text-overflow: ellipsis; }
.md-off { flex: 1; min-height: 0; overflow-y: auto; display: flex; flex-direction: column; }
.md-off .setup { overflow: visible; flex: none; }
.md-off .ins { flex: none; overflow: visible; border-top: 2px solid var(--color-divider); }
.mdv .kv { flex: none; overflow: visible; }
.mdv .kv > span:nth-child(even) { word-break: normal; overflow-wrap: anywhere; }
.md-ctl { display: inline-flex; margin-top: 7px; }
.md-ctl button { font-size: 10.5px; padding: 3px 7px; }
.md-hi { box-shadow: inset 4px 0 0 var(--color-accent); background: color-mix(in srgb, var(--color-accent) 6%, var(--color-bg)); }
.md-adv { display: grid; grid-template-columns: 120px 84px minmax(0, 1fr); gap: 2px 12px; align-items: baseline; padding: 8px 0;
  border-bottom: 1px solid color-mix(in srgb, var(--color-text) 10%, transparent); font-size: 12.5px; }
.md-adv.up { background: color-mix(in srgb, var(--color-accent) 9%, transparent); }
.md-adv.up .h800 { color: var(--color-accent-700); }
.md-tall { height: max(340px, calc(60 * var(--vh))); }
.md-box { max-height: max(300px, calc(55 * var(--vh))); display: flex; flex-direction: column; min-height: 0; }
.md-spark svg { width: 100%; height: 56px; display: block; border: 1px solid var(--color-divider); margin: 2px 0 8px; }
.md-tool { display: grid; grid-template-columns: 110px 64px minmax(0, 1fr); gap: 1px 10px; font-size: 12px; padding: 5px 0;
  border-bottom: 1px solid color-mix(in srgb, var(--color-text) 10%, transparent); align-items: baseline; }
.md-tool .why { grid-column: 2 / -1; }
.md-find { padding: 6px 0; border-bottom: 1px solid color-mix(in srgb, var(--color-text) 10%, transparent); font-size: 12px; }
.md-sample { font: 11.5px/1.4 ui-monospace, Consolas, monospace; word-break: break-all; }
.seg-row button.md-draft { outline: 2px solid var(--color-accent); outline-offset: -2px; }
.md-cols { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 18px; }
@media (max-width: 1100px) {
  .md-tall { height: auto; }
  .md-cols, .md-adv { grid-template-columns: 1fr; }
}`;

  /* ------------------------------------------------------------------ state */

  const ui = (() => { try { const u = store.get('media', {}); return u && typeof u === 'object' ? u : {}; } catch { return {}; } })();
  S.md = {
    hf: HOLD_FILTERS.some((f) => f[0] === ui.hf) ? ui.hf : 'review', q: '', qRaw: '', off: 0, sel: null,
    ekind: typeof ui.ekind === 'string' && ui.ekind.length < 100 ? ui.ekind : '',
    since: SINCE.some((s) => s[0] === String(ui.since)) ? String(ui.since) : '86400', draft: {},
  };
  // st = last /api/media/status; skew = local clock - server clock, so server timestamps show correct ages
  // deploy = null (running) | 'disabled' (media.enabled false) | 'missing' (strata.py does not dispatch /api/media/* yet)
  D.md = { st: null, err: null, deploy: null, offMsg: '', at: 0, skew: 0, holds: null, events: null, jobs: null, policy: null,
    sig: {}, cpu: [], dirty: false, holdsBusy: false, policyBusy: false };
  const saveUi = () => store.set('media', { hf: S.md.hf, ekind: S.md.ekind, since: S.md.since });

  /* ------------------------------------------------------------------ helpers */

  const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
  const first = (...vals) => { for (const v of vals) if (v !== undefined && v !== null && v !== '') return v; return undefined; };
  const num = (v) => {
    if (v === undefined || v === null || v === '' || typeof v === 'boolean') return null;
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  };
  const nowS = () => Date.now() / 1000;
  const epoch = (v) => { // wall-clock seconds; a monotonic clock (uptime-sized numbers) is not a time of day
    let n = num(v);
    if (n === null) return null;
    if (n > 1e12) n /= 1000;
    return n > 1e9 ? n : null;
  };
  const parse = (v) => { if (typeof v !== 'string') return v; try { return JSON.parse(v); } catch { return v; } };
  const asObj = (v) => { v = parse(v); return isObj(v) ? v : {}; };
  const asList = (v) => { v = parse(v); return Array.isArray(v) ? v : v === undefined || v === null || v === '' ? [] : [v]; };
  const rowsOf = (r, ...keys) => {
    if (Array.isArray(r)) return r;
    for (const k of keys) if (r && Array.isArray(r[k])) return r[k];
    return [];
  };
  const yes = (v) => v === true || v === 1 || v === '1' || v === 'true' || v === 'on' || v === 'yes';
  const sum = (m) => Object.values(m).reduce((a, b) => a + (b || 0), 0);
  const pct = (v) => fmt.pct(num(v));
  const local = (ts) => ts + (D.md.skew || 0);
  const srvAgo = (ts) => (ts ? fmt.ago(local(ts)) : '—');
  const srvDt = (ts) => (ts ? fmt.dt(local(ts)) : '—');
  const ageTxt = (s) => (s === null || s === undefined ? '—' : s < 5 ? 'now' : fmt.dur(s) + ' ago');
  function txt(v, max = 400) { // any JSON value -> one line of text (still unescaped: callers esc() it)
    let s;
    if (v === undefined || v === null) s = '';
    else if (typeof v === 'string') s = v;
    else if (Array.isArray(v)) s = v.map((x) => txt(x, max)).join(', ');
    else if (typeof v === 'object') s = Object.entries(v).map(([k, x]) => k + '=' + (x !== null && typeof x === 'object' ? JSON.stringify(x) : x)).join(' · ');
    else s = String(v);
    return s.length > max ? s.slice(0, max - 1) + '…' : s;
  }
  function toMap(v) { // {k: n} | [{k|state|kind, n|c|count}] -> {k: n} (no prototype: keys come from the server)
    v = parse(v);
    const out = Object.create(null);
    if (Array.isArray(v)) {
      v.forEach((r) => {
        if (!isObj(r)) return;
        const k = first(r.k, r.key, r.state, r.kind, r.name);
        if (k !== undefined) out[k] = (out[k] || 0) + (num(first(r.n, r.c, r.count, r.value)) || 0);
      });
    } else if (isObj(v)) {
      for (const [k, x] of Object.entries(v)) { const n = num(isObj(x) ? first(x.n, x.c, x.count) : x); if (n !== null) out[k] = n; }
    }
    return out;
  }
  function driveName(id) {
    if (id === null || id === undefined) return '—';
    const m = (D.serv?.mounts || []).find((x) => x.id === id) || (D.drives?.served || []).find((x) => x.mount === id);
    return (m && m.name) || 'drive ' + id;
  }
  function friendly(e) {
    const m = String((e && e.message) || e || 'error');
    if (NOT_HOOKED.test(m)) return 'the media API is not reachable (/api/media/* answered 404: strata.py does not dispatch it yet)';
    return m;
  }
  // A status of a switched-off pipeline: {"enabled": false, ...} (HOOKS-ui.md), or the same said another way.
  function isOff(st) {
    if (!isObj(st)) return false;
    const en = first(st.enabled, asObj(st.media).enabled, asObj(st.config).enabled);
    const state = String(first(st.state, st.status, st.mode) ?? '').toLowerCase();
    return en === false || en === 0 || en === 'false' || yes(st.disabled) || state === 'disabled' || state === 'off';
  }

  /* ------------------------------------------------------------------ reading /api/media/status */

  const ST = () => D.md.st || {};
  const counts = () => asObj(ST().counts);
  const conf = (sec) => asObj(asObj(first(ST().config, ST().conf))[sec]);
  const proc = (name) => { const s = ST(); return asObj(first(asObj(s.processes)[name], asObj(s.process)[name], s[name])); };
  function upOf(p) {
    const v = first(p.up, p.ok, p.alive, p.healthy, p.running);
    if (v === undefined) {
      const s = String(first(p.state, p.status) ?? '').toLowerCase();
      return s ? /^(up|ok|running|alive|healthy)$/.test(s) : null;
    }
    return yes(v);
  }
  function heartbeatAge(p) {
    const a = num(first(p.heartbeat_age, p.heartbeat_age_s, p.hb_age));
    if (a !== null) return a + Math.max(0, nowS() - (D.md.at || nowS())); // it was that old when fetched
    const hb = p.heartbeat;
    const ts = epoch(isObj(hb) ? hb.ts : hb) || epoch(first(p.heartbeat_ts, p.last_heartbeat, asObj(ST().worker_heartbeat).ts));
    return ts ? Math.max(0, nowS() - local(ts)) : null;
  }
  function workerState() { // health rule from DESIGN 2: heartbeat younger than 30 s
    const w = proc('worker'), age = heartbeatAge(w), u = upOf(w);
    return { w, age, up: u === false ? false : age !== null ? age < 30 : u };
  }
  function breaker() {
    const s = ST(), m = proc('media');
    const b = asObj(first(s.breaker, m.breaker, asObj(s.stats).breaker, asObj(m.stats).breaker)), bc = conf('breaker');
    const state = String(first(b.state, b.status) ?? '').toLowerCase().replace(/[- ]/g, '_');
    let forced = first(b.forced, b.force, b.override, b.manual);
    if (isObj(forced)) forced = first(forced.state, forced.mode);
    if (forced === true) forced = state;
    forced = typeof forced === 'string' && /^(open|closed)$/i.test(forced) ? forced.toLowerCase() : null;
    // breaker.Breaker.status(): forced_for = seconds the forced state has left (null: until "auto"), open_for =
    // seconds until an automatic trip may go half-open (null while forced open indefinitely)
    return {
      raw: b, state, forced, reason: first(b.reason, b.detail, b.trip_reason, b.last_reason),
      since: epoch(first(b.since, b.changed, b.opened_at, b.state_since)), until: epoch(first(b.until, b.forced_until, b.open_until)),
      left: num(first(b.forced_for, b.remaining_s, b.forced_left_s, b.left_s)), openFor: num(b.open_for),
      trips: num(first(b.trips, b.trip_count, b.trips_total)),
      slots: num(first(b.slots, b.slots_total, bc.slots)), busy: num(first(b.busy, b.in_use, b.active, b.running, b.slots_busy)),
      waiters: num(first(b.waiters, b.waiting)), maxWaiters: num(first(b.max_waiters, bc.max_waiters)),
      waitP90: num(first(b.wait_p90_ms, b.p90_wait_ms, b.wait_p90)), cooldown: num(first(b.cooldown_s, b.cooldown)),
      cpuTrip: num(first(b.cpu_trip, bc.cpu_trip)) ?? 85, memMin: num(first(b.mem_min_mb, bc.mem_min_mb)) ?? 768,
    };
  }
  function monitor() {
    const s = ST(), m = proc('media');
    const o = asObj(first(s.monitor, asObj(s.breaker).monitor, m.monitor, asObj(s.stats).monitor));
    return { ewma: num(first(o.cpu_ewma, o.ewma, asObj(s.breaker).cpu_ewma)), cpu: num(first(o.cpu, o.cpu_now)),
      mem: num(first(o.mem_avail_mb, o.mem_free_mb, o.mem_avail)), memPct: num(first(o.mem_pct, o.mem_load)) };
  }
  function cacheInfo() {
    const s = ST(), c = asObj(first(s.cache, s.cache_usage, proc('media').cache));
    const maxGb = num(first(c.max_gb, asObj(s.config).cache_max_gb));
    return { bytes: num(first(c.bytes, c.used, c.size)), files: num(first(c.files, c.count)), free: num(first(c.disk_free, c.free)),
      max: num(first(c.max_bytes, c.max)) ?? (maxGb !== null ? maxGb * 2 ** 30 : null), error: c.error };
  }
  function toolState(aliases) { // tool value: path string | null | bool | {ok|available, path, version, error}
    const T = asObj(first(ST().tools, proc('worker').tools, proc('media').tools));
    let known = false, ok = false, detail = '';
    for (const k of aliases) {
      if (!(k in T)) continue;
      known = true;
      const v = T[k];
      if (isObj(v)) {
        const flag = first(v.ok, v.available, v.found);
        if (flag !== undefined ? yes(flag) : !!first(v.path, v.version)) { ok = true; detail = txt(first(v.version, v.path) ?? '', 160); }
        else if (!detail) detail = txt(first(v.error, v.reason) ?? '', 160);
      } else if (typeof v === 'string' && v && !/^(missing|none|false|no|0)$/i.test(v)) { ok = true; detail = v; }
      else if (v === true) ok = true;
      if (ok) break;
    }
    return { known, ok, detail };
  }
  function negotiation() {
    const s = ST(), n = parse(s.negotiation), o = isObj(n) ? n : { effective: n };
    return { configured: first(o.configured, o.mode, asObj(s.settings).negotiation), effective: first(o.effective, o.active, o.current),
      edge: parse(first(o.edge, o.edge_rules, o.rules, o.edge_state)),
      caps: asObj(first(o.caps, o.capabilities, asObj(s.cloudflare).caps, s.caps)),
      error: first(o.error, o.last_error), checked: epoch(first(o.checked, o.ts, o.synced, o.updated)) };
  }
  const verdictCounts = () => toMap(first(counts().verdicts, ST().verdicts, ST().verdict_counts));
  const eventCounts = () => toMap(first(ST().events_24h, ST().event_counts, counts().events, asObj(ST().events).counts));
  function jobCounts() { // -> {kind: {state: n}}
    const s = ST();
    let j = parse(first(counts().jobs, s.job_counts, s.jobs));
    if (isObj(j) && isObj(j.counts)) j = j.counts;
    const out = Object.create(null);
    if (Array.isArray(j)) {
      j.forEach((r) => {
        if (!isObj(r)) return;
        const k = String(first(r.kind, r.k) ?? '?'), st = String(first(r.state, r.s) ?? '?');
        (out[k] = out[k] || {})[st] = (out[k][st] || 0) + (num(first(r.n, r.c, r.count)) || 0);
      });
    } else if (isObj(j)) {
      for (const [k, v] of Object.entries(j)) if (isObj(v)) out[k] = toMap(v);
    }
    return out;
  }
  function oldestAges() { // -> {kind: seconds} ('*' = overall)
    const s = ST(), c = counts(), j = asObj(s.jobs);
    const o = parse(first(c.oldest, c.oldest_queued, c.oldest_queued_age, s.oldest_queued, s.oldest, j.oldest, j.oldest_queued));
    if (isObj(o)) { const m = {}; for (const [k, v] of Object.entries(o)) m[k] = num(v); return m; }
    const n = num(o);
    return n === null ? {} : { '*': n };
  }
  function capacity() {
    let c = parse(first(ST().capacity, ST().capacity_advice, ST().advice)), ts = null;
    if (isObj(c)) { ts = epoch(first(c.ts, c.updated)); c = first(c.advice, c.rows, c.items, c.list); }
    const rows = asList(c).filter(isObj).map((a) => ({
      resource: txt(first(a.resource, a.k, a.kind) ?? '—', 60), level: String(first(a.level) ?? 'watch').toLowerCase(),
      evidence: txt(first(a.evidence, a.detail) ?? '', 400), recommendation: txt(first(a.recommendation, a.advice, a.text) ?? '', 400),
    }));
    return { ts, rows };
  }
  function savingsInfo() {
    const s = asObj(first(ST().savings, ST().variants, ST().variant_totals));
    return { bytes: num(first(s.bytes, s.variant_bytes)), src: num(first(s.src_bytes, s.source_bytes)),
      count: num(first(s.count, s.variants, s.n)), beneficial: num(first(s.beneficial, s.beneficial_count)) };
  }
  function settingsNow() { // current values as the settings form compares them ('1'/'0' for the toggle)
    const s = ST(), c = asObj(s.settings), g = asObj(first(s.gate, conf('gate'))), sc = asObj(first(s.scan, conf('scan')));
    const leg = first(c.gate_legacy, c.legacy_while_pending, g.legacy_while_pending);
    return { negotiation: first(c.negotiation, negotiation().configured),
      gate_legacy: leg === undefined ? undefined : yes(leg) ? '1' : '0', hold_threshold: first(c.hold_threshold, sc.hold_threshold) };
  }
  function edgeWord(N) {
    const e = N.edge, t = asObj(N.caps.transform);
    if (isObj(e)) {
      const w = first(e.state, e.status);
      if (w !== undefined) return txt(w, 40);
      if (e.ok === true || yes(e.installed)) return e.verified === false ? 'unverified' : 'installed';
      if (e.ok === false || e.installed === false) return 'not installed';
    } else if (typeof e === 'string' && e) return txt(e, 40);
    else if (typeof e === 'boolean') return e ? 'installed' : 'not installed';
    return t.ok === false ? 'no permission' : '—';
  }

  /* ------------------------------------------------------------------ loading */

  function holdFilter() { return HOLD_FILTERS.find((f) => f[0] === S.md.hf) || HOLD_FILTERS[0]; }
  function holdRow(r) {
    const mount = num(first(r.mount, r.mount_id)), path = String(first(r.path, r.rel) ?? '');
    return { mount, path, key: (mount ?? '') + '|' + path, state: String(r.state ?? '').toLowerCase(),
      severity: String(r.severity ?? '').toLowerCase(), findings: asList(r.findings).map((f) => (isObj(f) ? f : { type: txt(f, 80) })),
      engines: asObj(r.engines), size: num(r.size), scanned: epoch(first(r.scanned, r.updated)), updated: epoch(r.updated),
      legacy: yes(r.legacy), reviewedBy: r.reviewed_by, reviewNote: r.review_note };
  }
  let holdSeq = 0, eventSeq = 0;
  async function loadHolds() {
    const seq = ++holdSeq, qs = ['state=' + enc(holdFilter()[2]), 'limit=' + HOLD_LIMIT, 'offset=' + S.md.off];
    if (S.md.q) qs.push('q=' + enc(S.md.q));
    try {
      const r = await get('/api/media/holds?' + qs.join('&'));
      if (seq !== holdSeq) return;
      const rows = rowsOf(r, 'holds', 'rows', 'verdicts', 'items').filter(isObj).map(holdRow);
      D.md.holds = { rows, total: num(isObj(r) ? first(r.total, r.count) : null), at: nowS() };
      if (S.md.sel && !rows.some((h) => h.key === S.md.sel)) S.md.sel = null;
    } catch (e) {
      if (seq === holdSeq) D.md.holds = { rows: [], err: friendly(e), at: nowS() };
    }
  }
  async function loadEvents() {
    const seq = ++eventSeq;
    const since = Math.floor(nowS() - (D.md.skew || 0) - (+S.md.since || 86400));
    const qs = ['since=' + since, 'limit=' + EVENT_LIMIT];
    if (S.md.ekind) qs.unshift('kind=' + enc(S.md.ekind));
    try {
      const r = await get('/api/media/events?' + qs.join('&'));
      if (seq !== eventSeq) return;
      const rows = rowsOf(r, 'events', 'rows', 'items').filter(isObj).sort((a, b) => (epoch(b.ts) || 0) - (epoch(a.ts) || 0));
      D.md.events = { rows, at: nowS() };
    } catch (e) {
      if (seq === eventSeq) D.md.events = { rows: [], err: friendly(e), at: nowS() };
    }
  }
  async function loadJobs() {
    try {
      const r = await get('/api/media/jobs?state=failed');
      D.md.jobs = { rows: rowsOf(r, 'jobs', 'rows', 'items').filter(isObj), at: nowS() };
    } catch (e) { D.md.jobs = { rows: [], err: friendly(e), at: nowS() }; }
  }
  async function loadPolicy() {
    if (typeof loadDrives === 'function' && !D.drives && !D.md.drivesTried) { D.md.drivesTried = true; loadDrives(); } // names (storage.js)
    try { D.md.policy = { data: await get('/api/media/policy'), at: nowS() }; } catch (e) { D.md.policy = { err: friendly(e), at: nowS() }; }
  }

  /* Status every 5 s while visible. The lists behind it are only fetched again when their counts in the status
     move (or after LIST_MAX_AGE): no point re-reading 200 holds that did not change. */
  let busy = null, again = null;
  async function refresh(o = {}) {
    if (busy) { again = Object.assign(again || {}, o); return busy; }
    busy = (async () => {
      try {
        let st;
        try { st = await get('/api/media/status'); } catch (e) {
          // not deployed is a state, not an error: no bridge yet (404) or a bridge that refuses while switched off
          const m = String((e && e.message) || e || ''), off = NOT_HOOKED.test(m) ? 'missing' : SWITCHED_OFF.test(m) ? 'disabled' : null;
          if (!off || (off === 'missing' && D.md.st)) throw e;
          Object.assign(D.md, { st: null, deploy: off, offMsg: m, err: null, at: nowS() });
          return;
        }
        if (!isObj(st)) throw new Error('unexpected answer from /api/media/status');
        D.md.at = nowS(); D.md.st = st; D.md.err = null;
        D.md.deploy = isOff(st) ? 'disabled' : null;
        D.md.offMsg = '';
        const srv = epoch(st.now);
        D.md.skew = srv ? D.md.at - srv : 0;
        if (o.statusOnly) return;
        if (D.md.deploy) { if (o.policy) await loadPolicy(); return; } // nothing runs: no holds, events or jobs to list
        const e = monitor().ewma;
        if (e !== null) { D.md.cpu.push(Math.max(0, Math.min(100, e))); if (D.md.cpu.length > CPU_POINTS) D.md.cpu.shift(); }
        if (typeof loadDrives === 'function' && !D.drives && !D.md.drivesTried) { D.md.drivesTried = true; loadDrives(); } // names (storage.js)
        const sig = { v: JSON.stringify(verdictCounts()), e: JSON.stringify(eventCounts()), j: JSON.stringify(jobCounts()) };
        const stale = (x) => !x || nowS() - (x.at || 0) > LIST_MAX_AGE;
        const work = [];
        if (o.holds || sig.v !== D.md.sig.v || stale(D.md.holds)) work.push(loadHolds());
        if (o.events || sig.e !== D.md.sig.e || stale(D.md.events)) work.push(loadEvents());
        if (o.jobs || sig.j !== D.md.sig.j || stale(D.md.jobs)) work.push(loadJobs());
        if (o.policy || !D.md.policy || nowS() - D.md.policy.at > POLICY_MAX_AGE) work.push(loadPolicy());
        D.md.sig = sig;
        await Promise.all(work);
      } catch (e) {
        D.md.err = friendly(e);
        if (D.md.deploy === 'missing') D.md.deploy = null; // the route exists now, it just failed: show that error
      }
    })();
    try { await busy; } finally { busy = null; }
    draw();
    if (again) { const a = again; again = null; await refresh(a); }
  }
  // Redraw unless the user is selecting text or dragging (app.js mainBusy); then the next tick catches up.
  function draw() {
    if (S.view !== 'media') return;
    if (typeof mainBusy === 'function' && mainBusy()) { D.md.dirty = true; return; }
    D.md.dirty = false;
    render(true);
  }
  const visible = () => S.view === 'media' && document.visibilityState !== 'hidden';

  /* ------------------------------------------------------------------ building blocks */

  const kpi = (label, val, sub, o = {}) => `<div${o.title ? ` title="${esc(o.title)}"` : ''}><div class="cap">${esc(label)}</div>
    <div class="val ${o.hot ? 'hot' : ''}">${esc(val)}</div>${o.bar || ''}<div class="small dim ell" title="${esc(sub)}">${esc(sub)}</div>${o.extra || ''}</div>`;
  const panelH = (title, noteTxt, body, cls = '', tools = '') => `<section class="panel ${cls}"><div class="ph"><h5>${esc(title)}</h5>
    <span class="small dim ell" title="${esc(noteTxt || '')}">${esc(noteTxt || '')}</span>${tools}</div>${body}</section>`;
  const kvHtml = (pairs, style = '') => `<div class="kv" style="padding:8px 0 0;${style}">${pairs.map(([k, v]) =>
    `<span>${esc(k)}</span><span>${esc(v)}</span>`).join('')}</div>`;
  const setRow = (title, desc, control) => `<div class="set-row"><div style="min-width:0"><div class="h800">${esc(title)}</div>
    <div class="small dim">${esc(desc)}</div></div><div class="set-ctl">${control}</div></div>`;
  function findingsSummary(list) {
    const by = new Map();
    for (const f of list) {
      const t = txt(first(f.type, f.kind, f.name) ?? 'finding', 60), e = by.get(t) || { n: 0, sev: '' };
      const s = String(f.severity ?? '').toLowerCase();
      e.n++;
      if ((SEV[s] || 0) > (SEV[e.sev] || 0)) e.sev = s;
      by.set(t, e);
    }
    const short = [...by].sort((a, b) => (SEV[b[1].sev] || 0) - (SEV[a[1].sev] || 0) || b[1].n - a[1].n)
      .map(([t, e]) => t + (e.n > 1 ? ' ×' + e.n : '') + (e.sev ? ' (' + e.sev + ')' : '')).join(', ');
    const long = list.map((f) => [txt(first(f.type, f.kind) ?? 'finding', 60), f.severity, f.confidence != null ? 'confidence ' + txt(f.confidence, 12) : '',
      f.sample ? '“' + txt(f.sample, 120) + '”' : '', f.where ? '@ ' + txt(f.where, 120) : ''].filter(Boolean).join(' · ')).join('\n');
    return { short, long };
  }
  function findingHtml(f) {
    const sev = String(f.severity ?? '').toLowerCase();
    const meta = [sev, f.confidence != null ? 'confidence ' + txt(f.confidence, 12) : ''].filter(Boolean).join(' · ');
    return `<div class="md-find"><div><b class="${(SEV[sev] || 0) >= 2 ? 'hot' : ''}">${esc(txt(first(f.type, f.kind) ?? 'finding', 80))}</b>
      <span class="small dim">${esc(meta)}</span></div>
      ${f.sample != null && f.sample !== '' ? `<div class="md-sample">${esc(txt(f.sample, 200))}</div>` : ''}
      ${f.where ? `<div class="small dim" style="word-break:break-all">${esc(txt(f.where, 200))}</div>` : ''}</div>`;
  }
  function holdButtons(h) {
    const k = esc(h.key), b = [];
    if (RELEASABLE.has(h.state)) b.push(`<button class="pill danger" data-act="mdRelease" data-arg="${k}" title="Publish again (audited, note required)">Release</button>`);
    if (h.state !== 'held') b.push(`<button class="pill" data-act="mdHold" data-arg="${k}" title="Keep it off the CDN (audited)">Keep held</button>`);
    b.push(`<button class="pill" data-act="mdRescan" data-arg="${k}" title="Queue a fresh scan">Rescan</button>`);
    return b.join(' ');
  }
  const pairsOf = (x) => { // policy counts: {k: n} | {k: {count, bytes}} | [{k|reason|ext, c|count, b|bytes}] | [[k, n]]
    x = parse(x);
    let out = [];
    if (Array.isArray(x)) {
      out = x.map((r) => (Array.isArray(r) ? { k: r[0], c: num(r[1]), b: num(r[2]) }
        : isObj(r) ? { k: first(r.k, r.key, r.reason, r.ext, r.name, r.kind), c: num(first(r.c, r.count, r.n, r.files)), b: num(first(r.b, r.bytes, r.size)) }
          : { k: r, c: null }));
    } else if (isObj(x)) {
      out = Object.entries(x).map(([k, v]) => (isObj(v) ? { k, c: num(first(v.c, v.count, v.n, v.files)), b: num(first(v.b, v.bytes, v.size)) }
        : Array.isArray(v) ? { k, c: v.length } : { k, c: num(v) }));
    }
    return out.filter((r) => r.k !== undefined && r.k !== null && r.k !== '').map((r) => ({ k: txt(r.k, 80), c: r.c || 0, b: r.b }))
      .sort((a, b) => b.c - a.c);
  };
  function sampleList(x) { // [path] | [{path, mount, reason}] | {reason: [path | {...}]}
    x = parse(x);
    const out = [];
    const add = (s, reason) => {
      if (isObj(s)) out.push({ path: txt(first(s.path, s.p, s.k, s.name) ?? '', 500), mount: num(s.mount), reason: first(s.reason, s.why, s.rule, reason),
        rescued: yes(s.rescued) });
      else if (s !== undefined && s !== null && s !== '') out.push({ path: txt(s, 500), mount: null, reason, rescued: false });
    };
    if (Array.isArray(x)) x.forEach((s) => add(s));
    else if (isObj(x)) for (const [k, v] of Object.entries(x)) asList(v).forEach((s) => add(s, k));
    return out.slice(0, 80);
  }
  const reasonLabel = (k) => REASONS[k] || txt(k, 60);

  /* ------------------------------------------------------------------ sections */

  function topBar() {
    const bits = [D.md.at ? 'updated ' + fmt.ago(D.md.at) : '', S.paused ? 'sampling paused' : 'refreshing every ' + POLL_MS / 1000 + ' s while this view is open',
      first(ST().version, proc('media').version) ? 'media ' + txt(first(ST().version, proc('media').version), 30) : ''].filter(Boolean);
    const warn = txt(first(ST().error, ST().warning) ?? '', 300); // the bridge's own complaint (e.g. media.db unreadable)
    return `<div class="tbar md-full" style="border-bottom:0;background:var(--color-bg)"><span class="small dim">${esc(bits.join(' · '))}</span>
      ${D.md.err ? `<span class="small hot ell" title="${esc(D.md.err)}">last refresh failed: ${esc(D.md.err)}</span>` : ''}
      ${warn ? `<span class="small hot ell" title="${esc(warn)}">${esc(warn)}</span>` : ''}
      <div style="flex:1"></div><button class="pill" data-act="mdRefresh">Refresh</button></div>`;
  }

  function kpisHealth() {
    const m = proc('media'), mu = upOf(m), W = workerState(), B = breaker(), mon = monitor(), C = cacheInfo();
    const upTxt = (u) => (u === null || u === undefined ? '—' : u ? 'up' : 'down');
    const mSub = [mu === false && m.error ? txt(m.error, 120) : '', num(m.uptime) !== null ? 'up ' + fmt.dur(num(m.uptime)) : '',
      num(m.restarts) ? fmt.n(m.restarts) + ' restarts' : '', first(m.listen, m.addr) ? txt(first(m.listen, m.addr), 40) : '']
      .filter(Boolean).join(' · ') || 'hot path · on-the-fly encodes';
    const pr = first(W.w.pause_reason, typeof W.w.paused === 'string' ? W.w.paused : undefined);
    const wSub = ['heartbeat ' + ageTxt(W.age), pr || yes(W.w.paused) ? 'paused' + (pr ? ': ' + txt(pr, 60) : '') : '',
      num(W.w.restarts) ? fmt.n(W.w.restarts) + ' restarts' : '', W.up === false && W.w.error ? txt(W.w.error, 100) : ''].filter(Boolean).join(' · ');
    const stLbl = { closed: 'closed', open: 'open', half_open: 'half-open' }[B.state] || B.state || '—';
    const bSub = [B.forced ? 'forced ' + B.forced + (B.until ? ' until ' + fmt.hm(local(B.until)) : B.left !== null ? ' · ' + fmt.dur(B.left) + ' left' : '') : 'automatic',
      B.reason && (B.state !== 'closed' || B.forced) ? txt(B.reason, 60) : '',
      !B.forced && B.state === 'open' && B.openFor !== null ? 'half-open in ' + fmt.dur(B.openFor) : '',
      B.since ? 'since ' + srvAgo(B.since) : ''].filter(Boolean).join(' · ');
    const mode = B.forced || 'auto';
    const ctl = `<div class="seg-row md-ctl">${[['auto', 'Auto', 'Automatic: trips on CPU, memory, queue, wait time, errors or slow encodes'],
      ['open', 'Open', 'Maintenance: skip all on-the-fly processing and serve originals'],
      ['closed', 'Close', 'Ignore the trip conditions for a while (use with care)']].map(([k, l, t]) =>
      `<button class="${mode === k ? 'on' : ''}" data-act="mdBreaker" data-arg="${k}" title="${esc(t)}">${l}</button>`).join('')}</div>`;
    const cpuHot = mon.ewma !== null && mon.ewma >= B.cpuTrip;
    const wHot = B.waiters !== null && B.maxWaiters !== null && B.waiters >= B.maxWaiters;
    const cp = C.max ? share(C.bytes || 0, C.max) : 0;
    return `<div class="kpis md-full">
      ${kpi('Media service', upTxt(mu), mSub, { hot: mu === false })}
      ${kpi('Worker', upTxt(W.up), wSub, { hot: W.up === false })}
      ${kpi('Circuit breaker', stLbl, bSub, { hot: !!B.state && B.state !== 'closed', extra: ctl })}
      ${kpi('CPU · EWMA', mon.ewma === null ? '—' : pct(mon.ewma), [mon.cpu !== null ? 'now ' + pct(mon.cpu) : '',
        mon.mem !== null ? fmt.bytes(mon.mem * MIB) + ' RAM free' : '', 'trips at ' + B.cpuTrip + ' %'].filter(Boolean).join(' · '),
        { hot: cpuHot, bar: segs(mon.ewma || 0, 18, B.cpuTrip) })}
      ${kpi('Encode slots', (B.busy === null ? '—' : fmt.n(B.busy)) + ' / ' + (B.slots === null ? '—' : fmt.n(B.slots)),
        ['waiters ' + (B.waiters === null ? '—' : fmt.n(B.waiters)) + (B.maxWaiters !== null ? ' / ' + fmt.n(B.maxWaiters) : ''),
          B.waitP90 !== null ? 'wait p90 ' + fmt.ms(B.waitP90) : ''].filter(Boolean).join(' · '),
        { hot: wHot, bar: segs(share(B.busy || 0, B.slots || 0), 18, 101, '', wHot) })}
      ${kpi('Variant cache', C.bytes === null ? '—' : fmt.bytes(C.bytes), [C.max ? 'of ' + fmt.bytes(C.max, 0) : '', C.files !== null ? fmt.n(C.files) + ' files' : '',
        C.free !== null ? fmt.bytes(C.free, 0) + ' disk free' : ''].filter(Boolean).join(' · ') || txt(C.error, 80) || '—', { hot: cp >= 95, bar: segs(cp, 18, 95) })}
    </div>`;
  }

  function kpisPipeline() {
    const N = negotiation(), V = verdictCounts(), J = jobCounts(), O = oldestAges(), E = eventCounts(), sv = savingsInfo();
    const negHot = !!(N.configured && N.effective && N.configured !== 'auto' && N.configured !== N.effective);
    const held = (V.flagged || 0) + (V.held || 0) + (V.error || 0);
    const scanAge = first(O.scan, O['*']), backlogH = num(conf('capacity').backlog_hours) ?? 6;
    const failed = Object.entries(J).map(([k, m]) => [k, m.failed || 0]).filter(([, n]) => n > 0);
    const byp = Object.entries(E).filter(([k]) => k.startsWith('bypass.')).sort((a, b) => b[1] - a[1]);
    return `<div class="kpis md-full">
      ${kpi('Negotiation', txt(N.effective ?? '—', 20), `configured ${txt(N.configured ?? '—', 20)} · edge rules ${edgeWord(N)}`, { hot: negHot })}
      ${kpi('Variant savings', sv.src ? pct(100 - share(sv.bytes || 0, sv.src)) : '—',
        sv.src ? `${fmt.bytes(sv.bytes)} instead of ${fmt.bytes(sv.src)} · ${fmt.n(sv.count)} variants` : 'no variants yet')}
      ${kpi('Held back', fmt.n(held), `flagged ${fmt.n(V.flagged || 0)} · held ${fmt.n(V.held || 0)} · error ${fmt.n(V.error || 0)}`,
        { hot: (V.flagged || 0) + (V.error || 0) > 0 })}
      ${kpi('Scan backlog', fmt.n((J.scan || {}).queued || 0), `oldest ${scanAge === undefined || scanAge === null ? '—' : fmt.dur(scanAge)} · ${fmt.n(V.pending || 0)} pending`,
        { hot: scanAge !== undefined && scanAge !== null && scanAge > backlogH * 3600 })}
      ${kpi('Failed jobs', fmt.n(failed.reduce((a, [, n]) => a + n, 0)), failed.length ? failed.map(([k, n]) => k + ' ' + fmt.n(n)).join(' · ') : 'none',
        { hot: failed.length > 0 })}
      ${kpi('Bypasses · 24 h', fmt.n(byp.reduce((a, [, n]) => a + n, 0)),
        byp.length ? byp.slice(0, 2).map(([k, n]) => k.slice(7) + ' ' + fmt.n(n)).join(' · ') : 'none: everything was processed')}
    </div>`;
  }

  function capacityPanel() {
    const cap = capacity(), rows = cap.rows.slice().sort((a, b) => (b.level === 'upgrade') - (a.level === 'upgrade'));
    const up = rows.some((a) => a.level === 'upgrade');
    const noteTxt = 'advisor checks CPU, memory, scan backlog, uplink and cache disk every 5 min' + (cap.ts ? ' · ' + srvAgo(cap.ts) : '');
    const body = rows.length ? rows.map((a) => `<div class="md-adv ${a.level === 'upgrade' ? 'up' : ''}">
        <span class="h800">${esc(a.resource)}</span><span><span class="acc ${a.level === 'upgrade' ? 'hot' : 'dim'}">${esc(a.level)}</span></span>
        <span><b>${esc(a.recommendation || '—')}</b>${a.evidence ? `<br><span class="small dim">${esc(a.evidence)}</span>` : ''}</span></div>`).join('')
      : '<div class="small dim">No bottleneck: nothing needs more VM resources right now. When CPU, memory, the scan backlog, the uplink or the cache disk runs short, the advice shows up here (and as an alert) with its evidence.</div>';
    return panelH(up ? 'Capacity · more resources needed' : 'Capacity', noteTxt, body, 'md-full md-short' + (up ? ' md-hi' : ''));
  }

  function holdsPanel() {
    const H = D.md.holds, V = verdictCounts(), sel = S.md.sel ? (H?.rows || []).find((h) => h.key === S.md.sel) : null;
    const pills = HOLD_FILTERS.map(([k, l, states]) => {
      const n = states.split(',').reduce((a, s) => a + (V[s] || 0), 0);
      return `<button class="pill ${S.md.hf === k ? 'on' : ''}" data-act="mdHF" data-arg="${k}">${esc(l)}${n ? ' · ' + fmt.n(n) : ''}</button>`;
    }).join('');
    const rows = (H?.rows || []).map((h) => {
      const fs = findingsSummary(h.findings), sev = h.severity && h.severity !== 'none' ? h.severity : '';
      // actions before the drive: at the default zoom #main is ~1024 css px, and the buttons must not scroll away
      return {
        cells: [hcell(`<span class="acc ${HOT_STATES.has(h.state) ? 'hot' : 'dim'}">${esc(h.state || '?')}</span>${h.legacy ? ' <span class="small dim">legacy</span>' : ''}`),
          cell(sev || '—', sev === 'high' ? 'hot h800' : sev === 'medium' ? 'hot' : 'dim'), cell(h.path, '', h.path),
          cell(fs.short || '—', fs.short ? '' : 'dim', fs.long), cell(h.size === null ? '—' : fmt.bytes(h.size), 'r dim'),
          cell(h.scanned ? srvAgo(h.scanned) : '—', 'dim', h.scanned ? srvDt(h.scanned) : ''), hcell(holdButtons(h)),
          cell(driveName(h.mount), 'dim', driveName(h.mount))],
        cls: 'click' + (sel && sel.key === h.key ? ' sel' : ''), attrs: `data-act="mdSel" data-arg="${esc(h.key)}" data-menu="mdHold"`,
      };
    });
    const labels = [{ t: 'State', w: 108 }, { t: 'Severity', w: 62 }, { t: 'Path', w: 232 }, { t: 'Findings', w: 170 },
      { t: 'Size', w: 64, a: 'r' }, { t: 'Scanned', w: 76 }, { t: '', w: 212 }, { t: 'Drive', w: 110 }];
    const n = rows.length, off = S.md.off, total = H ? H.total : null;
    const more = total !== null && total !== undefined ? off + n < total : n >= HOLD_LIMIT;
    const range = n ? `${fmt.n(off + 1)}–${fmt.n(off + n)}${total !== null && total !== undefined ? ' of ' + fmt.n(total) : ''}` : '';
    const paging = off || more ? `<button class="pill" data-act="mdPage" data-arg="-1" ${off ? '' : 'disabled'}>‹</button>` +
      `<button class="pill" data-act="mdPage" data-arg="1" ${more ? '' : 'disabled'}>›</button>` : '';
    let body;
    if (!H) body = loading('Loading holds…');
    else if (H.err) body = `<div class="empty hot">${esc(H.err)}</div>`;
    else {
      body = table('md-holds', labels, rows, { empty: S.md.q ? 'No file in this state matches the filter.'
        : S.md.hf === 'review' ? 'Nothing is held back: every scanned file is clean or released.' : 'No files in this state.' });
    }
    // the inline "1fr 360px" is what layout.js looks for: it adds the drag grip and remembers the aside's width
    return `<section class="panel md-full md-short" style="padding:0">
      <div class="ph" style="padding:14px 18px 8px;margin:0"><h5>Holds</h5><span class="small dim ell">what the scan gate keeps off the CDN · paths and findings come from uploaded files · right-click a row for actions</span></div>
      <div class="tbar">${pills}<div style="flex:1"></div><span class="small dim">${D.md.holdsBusy ? 'loading…' : esc(range)}</span>${paging}
        <input id="md_q" class="input" value="${esc(S.md.qRaw)}" placeholder="Filter paths…" autocomplete="off" spellcheck="false" aria-label="Filter held paths"></div>
      <div class="split ${n > 12 || sel ? 'md-tall' : ''}" style="grid-template-columns:${sel ? '1fr 360px' : '1fr'}">
        <section class="aside">${body}</section>${sel ? holdAside(sel) : ''}</div>
    </section>`;
  }

  function holdAside(h) {
    const kv = [['Drive', driveName(h.mount)], ['State', h.state + (h.legacy ? ' · legacy (born before the cutover)' : '')],
      ['Severity', h.severity || '—'], ['Size', h.size === null ? '—' : fmt.bytes(h.size)], ['Scanned', srvDt(h.scanned)],
      ['Updated', srvDt(h.updated)], ['Reviewed by', txt(h.reviewedBy, 80) || '—'], ['Review note', txt(h.reviewNote, 400) || '—'],
      ...Object.entries(h.engines).map(([k, v]) => ['Engine · ' + k, txt(v, 200)])];
    return `<aside class="aside">
      <div style="padding:12px 16px;border-bottom:2px solid var(--color-divider);flex:none">
        <div class="cap red">${esc(h.state || '?')}${h.severity ? ' · ' + esc(h.severity) : ''}</div>
        <h5 style="margin:3px 0 2px;font-size:15px;word-break:break-all">${esc(h.path)}</h5>
        <div class="act-row" style="margin-top:8px">${holdButtons(h)} <button class="pill" data-act="mdSelClose">Close</button></div>
      </div>
      <div class="scroll" style="padding:2px 16px 14px" data-scroll="md-aside">
        <div class="cap" style="margin:8px 0 2px">Findings · ${fmt.n(h.findings.length)} · redacted</div>
        ${h.findings.length ? h.findings.map(findingHtml).join('') : '<div class="small dim">No findings recorded.</div>'}
        ${kvHtml(kv, 'padding-top:12px')}
      </div></aside>`;
  }

  function breakerPanel() {
    const B = breaker(), mon = monitor();
    const hot = mon.ewma !== null && mon.ewma >= B.cpuTrip, memLow = mon.mem !== null && mon.mem < B.memMin;
    const spark = D.md.cpu.length > 1 ? `<div class="md-spark">${sparkSvg(D.md.cpu, { w: 240, h: 56, cls: '', max: 100,
      stroke: hot ? 'var(--color-accent)' : 'var(--color-text)' })}</div><div class="small dim" style="margin:-4px 0 10px">CPU EWMA while this view is open · trips at ${esc(B.cpuTrip)} %</div>` : '';
    const body = spark +
      gauge('CPU · EWMA ~5 s', mon.ewma === null ? '—' : pct(mon.ewma), mon.ewma || 0, B.cpuTrip) +
      gauge('Memory', mon.mem === null ? '—' : fmt.bytes(mon.mem * MIB) + ' free' + (mon.memPct !== null ? ' · ' + pct(mon.memPct) + ' used' : ''),
        mon.memPct || 0, 90, memLow) +
      gauge('Encode slots busy', (B.busy === null ? '—' : fmt.n(B.busy)) + ' / ' + (B.slots === null ? '—' : fmt.n(B.slots)), share(B.busy || 0, B.slots || 0), 101) +
      gauge('Waiters', (B.waiters === null ? '—' : fmt.n(B.waiters)) + (B.maxWaiters !== null ? ' / ' + fmt.n(B.maxWaiters) : ''),
        share(B.waiters || 0, B.maxWaiters || 0), 100) +
      kvHtml([['State', (B.state || '—') + (B.forced ? ' (forced)' : '')], ['Reason', txt(B.reason, 120) || '—'], ['Since', B.since ? srvDt(B.since) : '—'],
        ['Forced until', B.until ? srvDt(B.until) : B.left !== null ? fmt.dur(B.left) + ' left' : B.forced ? 'set back to automatic' : '—'],
        ['Half-open in', !B.forced && B.state === 'open' && B.openFor !== null ? fmt.dur(B.openFor) : '—'], ['Trips', B.trips === null ? '—' : fmt.n(B.trips)],
        ['Cooldown', B.cooldown === null ? '—' : fmt.dur(B.cooldown)], ['Wait p90', B.waitP90 === null ? '—' : fmt.ms(B.waitP90)]]);
    return panelH('Circuit breaker', 'when the VM is busy, on-the-fly work is skipped, logged with its kind and the original served', body);
  }

  function negotiationPanel() {
    const N = negotiation(), caps = N.caps, E = N.edge;
    const diff = !!(N.configured && N.effective && N.configured !== N.effective);
    let why = '';
    if (diff && N.configured === 'auto') {
      why = N.effective === 'redirect' ? 'Auto fell back to origin redirects: the Cloudflare token cannot manage Transform Rules, or the rules are not verified yet.' : '';
    } else if (diff) why = `“${txt(N.configured, 20)}” is not in effect${N.error ? ': ' + txt(N.error, 200) : ' yet: the bridge retries every 6 h and after every settings change.'}`;
    let rules = parse(isObj(E) ? first(E.rules, E.refs, E.installed_rules) : Array.isArray(E) ? E : null);
    if (Array.isArray(rules)) rules = rules.map((r) => (isObj(r) ? [txt(first(r.ref, r.name, r.id) ?? '?', 60), r.ok === false || r.enabled === false ? 'missing' : 'installed'] : [txt(r, 60), 'installed']));
    else if (isObj(rules)) rules = Object.entries(rules).map(([k, v]) => [k, isObj(v) ? (v.ok === false || v.enabled === false ? 'missing' : 'installed') : yes(v) ? 'installed' : 'missing']);
    else rules = [];
    const edgeErr = isObj(E) ? txt(first(E.error, E.need) ?? '', 200) : '';
    const capRows = Object.entries(caps).filter(([, c]) => isObj(c)).map(([k, c]) => {
      const ok = yes(c.ok);
      return `<div class="md-tool"><span class="h800">${esc(CAP_LABEL[k] || k)}</span><span class="${ok ? '' : c.ok === false ? 'hot' : 'dim'} h800">${ok ? 'ok' : c.ok === false ? 'missing' : '—'}</span>
        <span class="small dim ell" title="${esc(txt(first(c.error, c.need) ?? '', 300))}">${esc(ok ? '' : txt(first(c.need, c.error) ?? '', 140))}</span></div>`;
    }).join('');
    const needs = Object.values(caps).filter((c) => isObj(c) && c.ok === false && c.need).map((c) => txt(c.need, 80));
    const big = (label, v, hot) => `<div><div class="cap">${esc(label)}</div><div class="big-num ${hot ? 'hot' : ''}" style="font-size:26px">${esc(txt(v ?? '—', 20))}</div></div>`;
    const body = `<div style="display:flex;gap:26px;margin:2px 0 6px">${big('Configured', N.configured)}${big('Effective', N.effective, diff && N.configured !== 'auto')}</div>
      <div class="small dim">${esc(NEG_HELP[N.effective] || '')}</div>
      ${why ? `<p class="small hot" style="margin:8px 0 0">${esc(why)}</p>` : ''}
      <div class="cap" style="margin-top:14px">Edge rules · ${esc(edgeWord(N))}${N.checked ? ' · checked ' + esc(srvAgo(N.checked)) : ''}</div>
      ${rules.map(([k, v]) => `<div class="logline"><span>${esc(k)}</span><span class="${v === 'installed' ? '' : 'hot'}">${esc(v)}</span></div>`).join('')}
      ${edgeErr ? `<div class="small hot" style="margin-top:4px">${esc(edgeErr)}</div>` : ''}
      <div class="cap" style="margin-top:14px">Cloudflare token</div>${capRows || '<div class="small dim">Not reported yet.</div>'}
      ${needs.length ? `<p class="small" style="margin:8px 0 0">Add to the Cloudflare token (zone ${esc(INST.zone)}): <b>${esc(needs.join(', '))}</b></p>` : ''}`;
    return panelH('Negotiation', 'AVIF / WebP for canonical image URLs', body);
  }

  function toolRows() { // -> html of the tool list ('' when the status reports no tools at all)
    const st = TOOLS.map(([name, aliases, why]) => [name, toolState(aliases), why]);
    if (!st.some(([, t]) => t.known)) return '';
    const rows = st.map(([name, t, why]) => `<div class="md-tool"><span class="h800">${esc(name)}</span>
      <span class="${t.known && !t.ok ? 'hot h800' : t.ok ? 'h800' : 'dim'}">${t.ok ? 'ok' : t.known ? 'missing' : '—'}</span>
      <span class="small dim ell" title="${esc(t.detail)}">${esc(t.ok ? t.detail : t.known ? t.detail : 'not reported')}</span>
      ${t.known && !t.ok ? `<span class="small hot why">${esc(why)}</span>` : ''}</div>`).join('');
    const av = st.filter(([n]) => n === 'defender' || n === 'clamav').map(([, t]) => t);
    const noAv = av.every((t) => t.known && !t.ok);
    return rows + (noAv ? '<p class="small hot" style="margin:10px 0 0">No antivirus engine: archives, PDFs, documents, executables and SVGs are held as unscannable.</p>' : '');
  }
  function toolsPanel() {
    return panelH('Tools', 'missing tools degrade the pipeline, they never crash it · media/install.ps1 installs them',
      toolRows() || '<div class="small dim">Not reported yet.</div>');
  }

  function verdictPanel() {
    const V = verdictCounts(), tot = sum(V);
    const states = STATE_ORDER.concat(Object.keys(V).filter((k) => !STATE_ORDER.includes(k)));
    const bar = `<div class="stackbar">${states.filter((s) => V[s] > 0).map((s) =>
      `<i title="${esc(s + ' · ' + fmt.n(V[s]))}" style="flex:${V[s]};background:${Object.hasOwn(STATE_COLOR, s) ? STATE_COLOR[s] : 'var(--color-neutral-600)'}"></i>`).join('')}</div>`;
    const list = barList(states.filter((s) => V[s] !== undefined).map((s) => ({ k: s, c: V[s] })), {
      label: (r) => r.k, value: (r) => r.c, fmtv: (r) => fmt.n(r.c) + ' · ' + pct(share(r.c, tot)), hot: (r) => HOT_STATES.has(r.k) && r.c > 0,
      attrs: (r) => (FILTER_OF[r.k] ? `data-act="mdHF" data-arg="${FILTER_OF[r.k]}" style="cursor:pointer"` : ''),
    });
    return panelH('Verdicts', 'scan results per file · click a state to list it', `<div class="big-num">${fmt.n(tot)}</div>${tot ? bar : ''}${list}`);
  }

  function savingsPanel() {
    const s = savingsInfo(), saved = s.src !== null && s.bytes !== null ? s.src - s.bytes : null;
    const body = !s.src ? '<div class="small dim">No variants yet. AVIF / WebP / WebM variants are counted here once they are encoded; originals are never modified.</div>'
      : `<div class="big-num">${esc(pct(100 - share(s.bytes || 0, s.src)))}</div><div class="small dim">smaller than the originals they stand in for</div>
        <div class="stackbar"><i title="variant bytes" style="flex:${Math.max(0, s.bytes || 0)};background:var(--color-text)"></i><i title="saved" style="flex:${Math.max(0, saved || 0)};background:var(--color-neutral-300)"></i></div>
        ${kvHtml([['Variants', fmt.bytes(s.bytes)], ['Sources', fmt.bytes(s.src)], ['Saved', saved === null ? '—' : fmt.bytes(saved)],
          ['Count', fmt.n(s.count)], ['Beneficial', s.beneficial === null ? '—' : fmt.n(s.beneficial)],
          ['Not worth it', s.beneficial === null || s.count === null ? '—' : fmt.n(Math.max(0, s.count - s.beneficial)) + ' (original served)']])}`;
    return panelH('Savings', 'variant bytes vs source bytes · per stored variant', body);
  }

  // image optimizer: what the origin actually did NOT have to send (bytes on the uplink), not just what is stored
  function optimizerPanel() {
    const o = asObj(ST().optimizer), life = asObj(o.lifetime), tiers = asObj(life.tiers);
    const lsaved = num(life.bytes_saved_served), lserved = num(life.served);
    const orig = num(o.original_bytes), sent = num(o.served_bytes), saved = num(o.bytes_saved);
    const req = asObj(o.requests), hits = asObj(o.cache_hits), tp = asObj(o.tier_pass);
    const tier = (k) => { const t = asObj(tiers[k]); return t.count === undefined ? '—' : fmt.n(t.count) + ' · ' + fmt.bytes(t.bytes || 0); };
    if (!Object.keys(o).length) return panelH('Image optimizer', 'bandwidth the origin did not have to send', '<div class="small dim">No data yet (media service not answering).</div>');
    const body = `<div class="big-num">${lsaved === null ? '—' : esc(fmt.bytes(lsaved))}</div>
      <div class="small dim">not sent on the uplink thanks to AVIF / WebP variants${lserved ? ' · ' + esc(fmt.bytes(lserved)) + ' sent instead' : ''} (lifetime, per variant)</div>
      ${kvHtml([['Since start', orig ? fmt.bytes(saved || 0) + ' saved of ' + fmt.bytes(orig) + ' (' + pct(100 - share(sent || 0, orig)) + ')' : '—'],
        ['Answers', ['variant ' + fmt.n(req.variant || 0), 'original ' + fmt.n(req.original || 0), '304 ' + fmt.n(req.not_modified || 0), 'redirect ' + fmt.n(req.redirect || 0)].join(' · ')],
        ['Cache hits', ['persistent ' + fmt.n(hits.persistent || 0), 'ephemeral ' + fmt.n(hits.ephemeral || 0), 'misses ' + fmt.n(o.cache_misses || 0)].join(' · ')],
        ['Persistent tier', tier('persistent')], ['Ephemeral tier', tier('ephemeral')],
        ['Encodes', fmt.n(o.encodes || 0) + (o.encode_failures ? ' · ' + fmt.n(o.encode_failures) + ' failed' : '')],
        ['Promotions', fmt.n(o.promotions || 0) + ' up · ' + fmt.n(o.demotions || 0) + ' down' + (tp.ts ? ' · last pass ' + fmt.ago(tp.ts) : '')],
        ['Queue', fmt.n(o.queue_depth || 0) + ' deferred encodes']])}`;
    return panelH('Image optimizer', 'bandwidth the origin did not have to send · Prometheus: media /_metrics', body);
  }

  function settingsPanel() {
    const cur = settingsNow(), d = S.md.draft, val = (k) => (k in d ? d[k] : cur[k]);
    const seg = (key, items) => `<div class="seg-row">${items.map(([v, l]) => `<button class="${String(val(key)) === v ? 'on' : ''}${key in d && d[key] === v ? ' md-draft' : ''}"
      data-act="mdSet" data-arg="${esc(key + ':' + v)}">${esc(l)}</button>`).join('')}</div>`;
    const dirty = Object.keys(d).length > 0, leg = val('gate_legacy');
    const body = setRow('Format negotiation', NEG_HELP[val('negotiation')] || 'How canonical image URLs reach AVIF / WebP.', seg('negotiation', NEG_MODES)) +
      setRow('Legacy files while pending', leg === '1' ? 'Files born before the cutover stay online until their first scan (held at once if flagged).'
        : leg === '0' ? 'Legacy files answer 503 until scanned: safest, but old links fail for a while.' : 'Serve files born before the cutover before their first scan?',
      seg('gate_legacy', [['1', 'Serve'], ['0', 'Block']])) +
      setRow('Hold threshold', THRESHOLD_HELP[val('hold_threshold')] || 'Minimum finding severity that holds a file back.', seg('hold_threshold', THRESHOLDS)) +
      `<div class="act-row"><button class="btn btn-primary" data-act="mdSave" ${dirty ? '' : 'disabled'}>Save & apply</button>
        ${dirty ? '<button class="btn btn-secondary" data-act="mdDiscard">Discard</button><span class="small hot" style="align-self:center">unsaved changes</span>' : ''}</div>`;
    return panelH('Settings', 'saved to strata.json · Caddy config re-rendered and validated', body, 'md-set');
  }

  function jobsPanel() {
    const J = jobCounts(), O = oldestAges(), backlogH = num(conf('capacity').backlog_hours) ?? 6;
    const kinds = [...new Set(['scan', 'image', 'video'].concat(Object.keys(J)))];
    const base = ['queued', 'running', 'failed', 'done'], seen = new Set();
    kinds.forEach((k) => Object.keys(J[k] || {}).forEach((s) => seen.add(s)));
    const states = base.concat([...seen].filter((s) => !base.includes(s)));
    const rows = kinds.map((k) => {
      const m = J[k] || {}, age = first(O[k]);
      return { cells: [cell(k, 'h800'), ...states.map((s) => cell(fmt.n(m[s] || 0), 'r ' + (s === 'failed' && m[s] ? 'hot h800' : m[s] ? '' : 'dim'))),
        cell(age === undefined ? '—' : fmt.dur(age), 'r ' + (k === 'scan' && age > backlogH * 3600 ? 'hot' : 'dim')),
        hcell((m.failed || 0) > 0 ? `<button class="pill" data-act="mdRetry" data-arg="${esc(k)}">Retry failed</button>` : '')] };
    });
    const labels = [{ t: 'Kind', w: 70 }].concat(states.map((s) => ({ t: s, w: 70, a: 'r' })), [{ t: 'Oldest queued', w: 100, a: 'r' }, { t: '', w: 110 }]);
    const F = D.md.jobs, totalFailed = kinds.reduce((a, k) => a + ((J[k] || {}).failed || 0), 0);
    const frows = (F?.rows || []).slice(0, FAILED_SHOWN).map((j) => ({ cells: [
      cell(srvDt(epoch(first(j.finished, j.started, j.created))), 'dim'), cell(txt(j.kind ?? '?', 20)),
      cell(num(j.mount) === null ? '—' : driveName(num(j.mount)), 'dim'),
      cell(txt(j.path ?? '', 300) || '—', '', txt(j.path ?? '', 2000)), cell(fmt.n(num(j.attempts)), 'r dim'),
      cell(txt(j.error_kind ?? '', 40) || '—', 'hot'), cell(txt(j.error ?? '', 300), 'dim', txt(j.error ?? '', 2000))] }));
    const ftable = F?.err ? `<div class="small hot">${esc(F.err)}</div>` : `<div class="md-box">${table('md-failed', [{ t: 'Finished', w: 100 }, { t: 'Kind', w: 60 },
      { t: 'Drive', w: 80 }, { t: 'Path', w: 260 }, { t: 'Tries', w: 50, a: 'r' }, { t: 'Error kind', w: 110 }, { t: 'Error', w: 320 }], frows,
      { empty: 'No failed jobs.' })}</div>`;
    return `<section class="panel span2 md-short">
      <div class="ph"><h5>Jobs</h5><span class="small dim ell">background worker queue · the scan lane never waits behind video</span>
        ${totalFailed ? '<button class="pill" data-act="mdRetry" data-arg="">Retry all failed</button>' : ''}</div>
      ${table('md-jobs', labels, rows)}
      <div class="cap" style="margin:14px 0 4px">Recently failed${F?.rows?.length ? ' · ' + fmt.n(F.rows.length) : ''}</div>${ftable}
    </section>`;
  }

  function eventCountsPanel() {
    const E = eventCounts(), rows = Object.entries(E).map(([k, c]) => ({ k, c })).sort((a, b) => b.c - a.c);
    return panelH('Events · 24 h', fmt.n(sum(E)) + ' by kind · click one to filter the log', `<div class="md-list" data-scroll="md-ekinds">${barList(rows, {
      label: (r) => r.k, value: (r) => r.c, fmtv: (r) => fmt.n(r.c), hot: (r) => HOT_KIND(r.k),
      attrs: (r) => `data-act="mdEKind" data-arg="${esc(r.k)}" style="cursor:pointer"`,
    })}</div>`, 'md-short');
  }

  function eventsPanel() {
    const E = D.md.events, cnt = eventCounts();
    const kinds = Object.entries(cnt).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([k]) => k);
    if (S.md.ekind && !kinds.includes(S.md.ekind)) kinds.push(S.md.ekind);
    const kindPills = [`<button class="pill ${S.md.ekind ? '' : 'on'}" data-act="mdEKind" data-arg="">All kinds</button>`]
      .concat(kinds.map((k) => `<button class="pill ${S.md.ekind === k ? 'on' : ''}" data-act="mdEKind" data-arg="${esc(k)}">${esc(k)}</button>`)).join('');
    const sincePills = `<div class="seg-row">${SINCE.map(([v, l]) => `<button class="${S.md.since === v ? 'on' : ''}" data-act="mdSince" data-arg="${v}">${l}</button>`).join('')}</div>`;
    const rows = (E?.rows || []).map((e) => {
      const kind = txt(e.kind ?? '?', 80), sev = txt(e.severity ?? '', 20), detail = parse(e.detail);
      return { cells: [cell(srvDt(epoch(e.ts)), 'dim'), cell(kind, HOT_KIND(kind) ? 'hot' : ''),
        cell(sev || '—', /^(error|critical|high)$/i.test(sev) ? 'hot h800' : 'dim'), cell(txt(e.proc ?? '', 20) || '—', 'dim'),
        cell(num(e.mount) === null ? '—' : driveName(num(e.mount)), 'dim'), cell(txt(e.path ?? '', 400) || '—', '', txt(e.path ?? '', 2000)),
        cell(txt(detail, 300) || '—', 'dim', txt(detail, 2000))] };
    });
    const body = !E ? loading('Loading events…') : E.err ? `<div class="empty hot">${esc(E.err)}</div>`
      : table('md-events', [{ t: 'When', w: 110 }, { t: 'Kind', w: 180 }, { t: 'Level', w: 64 }, { t: 'Process', w: 64 }, { t: 'Drive', w: 80 },
        { t: 'Path', w: 260 }, { t: 'Detail', w: 420 }], rows, { empty: 'No events in this window: nothing failed or was bypassed.' });
    return `<section class="panel md-full md-short" style="padding:0">
      <div class="ph" style="padding:14px 18px 8px;margin:0"><h5>Event log</h5><span class="small dim ell">failures and bypasses, each with its kind · newest first${E && !E.err ? ' · ' + fmt.n(rows.length) + ' shown' : ''}</span></div>
      <div class="tbar">${kindPills}<div style="flex:1"></div>${sincePills}</div><div class="md-box">${body}</div></section>`;
  }

  /* media_rules.file_policy_preview(): {counts: {total, dangerous, unknown, safe, rescued}, by_ext: {dangerous: {ext: n},
     unknown: {ext: n}}, samples: [{mount, path, ext, reason, rescued}] (<= 200), blocked: [...], effective_blocked}.
     Flat shapes ({reason: n}, [{ext, count}]) are still understood. `blocked` can list thousands of paths: never drawn. */
  function policyInfo(d) {
    d = asObj(d);
    const c = asObj(d.counts), be = parse(first(d.by_ext, d.exts, d.extensions, c.by_ext, c.ext)), exts = [];
    if (isObj(be) && Object.values(be).some((v) => isObj(parse(v)))) {
      for (const [r, m] of Object.entries(be)) for (const [k, n] of Object.entries(asObj(m))) exts.push({ k: k || '(none)', c: num(n) || 0, r });
    } else pairsOf(be).forEach((x) => exts.push(x));
    exts.sort((a, b) => b.c - a.c);
    let reasons = pairsOf(first(d.by_reason, d.reasons, c.by_reason, c.reason));
    if (!reasons.length) reasons = ['dangerous', 'unknown'].filter((k) => num(c[k])).map((k) => ({ k, c: num(c[k]) }));
    const refused = reasons.reduce((a, r) => a + r.c, 0), rescued = num(c.rescued);
    const blocked = num(first(d.effective_blocked, typeof d.blocked === 'number' ? d.blocked : undefined))
      ?? (rescued !== null ? Math.max(0, refused - rescued) : refused);
    return { total: num(first(c.total, d.total)), refused, rescued, blocked, reasons, exts, enabled: d.enabled,
      samples: sampleList(first(d.samples, d.sample, d.examples)) };
  }
  function policyPanel() {
    const P = D.md.policy;
    const btn = `<button class="pill" data-act="mdPolicy" ${D.md.policyBusy ? 'disabled' : ''}>${D.md.policyBusy ? 'Checking…' : P ? 'Refresh' : 'Check now'}</button>`;
    let body, noteTxt = 'what the file policy would refuse today, from the file index';
    if (!P) body = loading(D.md.policyBusy ? 'Checking the file index…' : 'Not checked yet.');
    else if (P.err && SWITCHED_OFF.test(P.err)) body = '<div class="small dim">The bridge does not preview the file policy while the pipeline is switched off.</div>';
    else if (P.err) body = `<div class="small hot">${esc(P.err)}</div>`;
    else {
      const I = policyInfo(P.data);
      const bl = (list, lab, hot, title) => (list.length ? barList(list, { label: lab, title, value: (r) => r.c, hot,
        fmtv: (r) => fmt.n(r.c) + (r.b ? ' · ' + fmt.bytes(r.b) : '') }) : '<div class="small dim">Nothing is refused.</div>');
      const short = (k) => ({ dangerous: 'dangerous · 404', unknown: 'unknown type · 403', rescued: 'allowed by a rule' }[k] || reasonLabel(k));
      const reasonRows = I.reasons.concat(I.rescued ? [{ k: 'rescued', c: I.rescued }] : []);
      noteTxt = [fmt.n(I.blocked) + ' files refused', I.rescued ? fmt.n(I.rescued) + ' more allowed by access rules' : '',
        I.total !== null ? 'of ' + fmt.n(I.total) + ' indexed' : '', P.at ? 'checked ' + fmt.ago(P.at) : '', I.enabled === false ? 'policy is OFF' : '']
        .filter(Boolean).join(' · ');
      const samples = I.samples.map((s) => `<div class="logline"><span title="${esc(s.path)}">${esc(s.path)}</span>
        <span>${esc([s.reason ? REASON_SHORT[s.reason] || reasonLabel(s.reason) : '', s.mount !== null ? driveName(s.mount) : '',
          s.rescued ? 'allowed by a rule' : ''].filter(Boolean).join(' · '))}</span></div>`).join('');
      body = `<div class="md-cols">
        <div><div class="cap">By reason</div>${bl(reasonRows, (r) => short(r.k), (r) => REASON_SHORT[r.k] === '404', (r) => reasonLabel(r.k))}
          <p class="small dim" style="margin:8px 0 0">deny wins over safe · an allow access rule makes an exception (and still passes the scan gate)</p></div>
        <div><div class="cap">By extension</div><div class="md-list" data-scroll="md-pext">${bl(I.exts.slice(0, 80),
          (r) => (/^[a-z0-9]+$/i.test(r.k) ? '.' + r.k : r.k) + (r.r ? ' · ' + (REASON_SHORT[r.r] || r.r) : ''), (r) => REASON_SHORT[r.r] === '404')}</div></div>
        <div><div class="cap">Sample paths${I.samples.length ? ' · ' + fmt.n(I.samples.length) : ''}</div><div class="md-list" data-scroll="md-psamp">${samples
          || '<div class="small dim">No samples.</div>'}</div></div></div>`;
    }
    return panelH('File policy preview', noteTxt, body, 'md-full md-short', btn);
  }

  // media.enabled false (kill switch until deployment) or no bridge yet: explain, offer the pre-flight checks, no alarms.
  function offView() {
    const disabled = D.md.deploy === 'disabled', s = ST();
    const why = disabled ? txt(first(s.reason, s.message, D.md.offMsg) ?? '', 300) : '';
    const tools = disabled ? toolRows() : '';
    const lead = disabled
      ? `<p>The media pipeline is switched off: <code>media.enabled</code> is <code>false</code> in <code>strata.json</code>, the kill switch
        it keeps until deployment. Nothing is transcoded, scanned or held back, <code>media.py</code> and the worker are not running, and
        Caddy serves every file exactly as before.</p>${why && !SWITCHED_OFF.test(why) ? `<p class="dim">${esc(why)}</p>` : ''}`
      : `<p>This Strata does not answer <code>/api/media/*</code> yet: the media bridge (<code>media_bridge.py</code>) is not hooked into
        <code>strata.py</code>. Nothing about serving has changed.</p>`;
    return `<div class="md-off" data-scroll="md-off"><div class="setup">
      <div class="cap">Strata Media</div><h5>Not deployed</h5>${lead}
      <p>Once deployed, this page shows the circuit breaker and its maintenance switch, AVIF / WebP / WebM savings, what the scan gate
        holds back (release, keep held, rescan), the background jobs, the event log and capacity advice.</p>
      <ol>
        <li>Run <code>media\\install.ps1</code> (ffmpeg, 7-Zip, Tesseract, pypdfium2). Missing tools only degrade the pipeline.</li>
        <li>Switch it on with <code>media.enabled = true</code> (see <code>media\\README.md</code>). Strata then starts the media service
          and the worker, and renders the file policy, media routes and scan gate into Caddy, validated before the reload.</li>
        <li>The switch-on time becomes the <i>cutover</i>: older files stay online while their first scan runs.</li>
      </ol>
      ${tools ? `<div class="cap" style="margin-top:14px">Tools on this machine</div>${tools}` : ''}
      <div class="act-row"><button class="btn btn-secondary" data-act="mdRefresh">Check again</button>
        ${disabled ? `<button class="btn btn-secondary" data-act="mdPolicy" ${D.md.policyBusy ? 'disabled' : ''}>Preview the file policy</button>` : ''}
        <span class="small dim">${D.md.at ? 'checked ' + esc(fmt.ago(D.md.at)) : ''}</span></div>
    </div>${disabled && (D.md.policy || D.md.policyBusy) ? `<div class="ins mdv">${policyPanel()}</div>` : ''}</div>`;
  }

  function vMedia() {
    try {
      if (D.md.deploy) return offView();
      if (!D.md.st) {
        if (!D.md.err) return loading('Asking the media bridge…');
        return `<div class="setup"><h5 class="hot">Media status unavailable</h5><p>${esc(D.md.err)}</p>
          <p>This view reads <code>/api/media/*</code> from Strata's media bridge (<code>media_bridge.py</code>). While the bridge is
          starting or restarting there is nothing to show yet.</p>
          <button class="btn btn-secondary" data-act="mdRefresh">Retry now</button></div>`;
      }
      // every section renders on its own: one odd field costs that section, not the whole view (or app.js polling)
      const safe = (f) => { try { return f(); } catch (e) { return `<section class="panel md-short"><div class="empty hot">${esc(f.name)}: ${esc(e && e.message)}</div></section>`; } };
      return `<div class="ins mdv" data-scroll="md">${[topBar, kpisHealth, kpisPipeline, capacityPanel, holdsPanel, breakerPanel, negotiationPanel, toolsPanel,
        verdictPanel, optimizerPanel, savingsPanel, settingsPanel, jobsPanel, eventCountsPanel, eventsPanel, policyPanel].map(safe).join('')}</div>`;
    } catch (e) {
      return `<div class="setup"><h5 class="hot">The media view could not render</h5><p>${esc(e && e.message)}</p></div>`;
    }
  }

  /* ------------------------------------------------------------------ actions */

  const parseKey = (k) => {
    k = String(k ?? '');
    const i = k.indexOf('|'), m = num(k.slice(0, i));
    return i > 0 && m !== null && k.length > i + 1 ? { mount: m, path: k.slice(i + 1) } : null;
  };
  const holdByKey = (k) => (D.md.holds?.rows || []).find((h) => h.key === k);

  async function act(url, body, okMsg, lists = { holds: true, events: true, jobs: true }) {
    try {
      const r = await post(url, body);
      note(okMsg + (r && r.apply && r.apply.changed ? ' · Caddy updated (' + r.apply.sha + ')' : ''));
      await refresh(lists);
      return r || {};
    } catch (e) { note(friendly(e)); return null; }
  }

  // Release publishes a file the scanner distrusted, so it needs a confirmation and an audit note.
  async function holdAction(kind, key) {
    const h = parseKey(key);
    if (!h) return;
    const row = holdByKey(key) || { mount: h.mount, path: h.path, state: '', severity: '', findings: [] };
    const where = h.path + ' on ' + driveName(h.mount);
    const fs = findingsSummary(row.findings).short || 'none recorded';
    if (kind === 'release') {
      const v = await ask({ kicker: 'Release' + (row.severity ? ' · ' + row.severity + ' severity' : ''), title: 'Publish this file again?', danger: true,
        ok: 'Release', input: '', text: `${where} will be served again and may be cached by Cloudflare. Findings: ${fs}. Audit note (required): why is it safe?` });
      if (v === null || v === undefined) return;
      const msg = String(v).trim();
      if (msg.length < 3) { note('Not released: an audit note is required'); return; }
      await act('/api/media/release', { mount: h.mount, path: h.path, note: msg }, 'Released ' + h.path);
    } else if (kind === 'hold') {
      const v = await ask({ kicker: 'Keep held', title: 'Keep this file off the CDN?', ok: 'Keep held', input: '',
        text: `${where} stays blocked (403) until someone releases it. Findings: ${fs}. Audit note (optional):` });
      if (v === null || v === undefined) return;
      await act('/api/media/hold', { mount: h.mount, path: h.path, note: String(v).trim() }, 'Held ' + h.path);
    } else if (kind === 'rescan') {
      const ok = await ask({ kicker: 'Rescan', title: 'Scan this file again?', ok: 'Rescan',
        text: `${where} is queued for a fresh scan with the current tools and hold threshold.` });
      if (!ok) return;
      await act('/api/media/rescan', { mount: h.mount, path: h.path }, 'Rescan queued for ' + h.path);
    }
  }

  async function reloadList(flag, loader) {
    D.md[flag] = true; draw();
    try { await loader(); } finally { D.md[flag] = false; draw(); }
  }
  let qTimer;

  Object.assign(ACT, {
    mdRefresh() { refresh({ holds: true, events: true, jobs: true }); },
    mdHF(k) {
      if (!HOLD_FILTERS.some((f) => f[0] === k)) return;
      S.md.hf = k; S.md.off = 0; S.md.sel = null; saveUi();
      reloadList('holdsBusy', loadHolds);
    },
    mdPage(d) { S.md.off = Math.max(0, S.md.off + (+d || 0) * HOLD_LIMIT); S.md.sel = null; reloadList('holdsBusy', loadHolds); },
    mdSel(key) { S.md.sel = S.md.sel === key ? null : key; render(true); },
    mdSelClose() { S.md.sel = null; render(true); },
    mdRelease(key) { holdAction('release', key); },
    mdHold(key) { holdAction('hold', key); },
    mdRescan(key) { holdAction('rescan', key); },
    mdEKind(k) { S.md.ekind = String(k || '').slice(0, 99); saveUi(); reloadList('eventsBusy', loadEvents); },
    mdSince(v) { if (!SINCE.some((s) => s[0] === v)) return; S.md.since = v; saveUi(); reloadList('eventsBusy', loadEvents); },
    mdPolicy() { reloadList('policyBusy', loadPolicy); },
    async mdRetry(kind) {
      const J = jobCounts(), kinds = kind ? [kind] : Object.keys(J).filter((k) => (J[k].failed || 0) > 0);
      if (!kinds.length) { note('No failed jobs'); return; }
      let n = 0;
      try {
        for (const k of kinds) { const r = await post('/api/media/retry', { kind: k }); n += num(isObj(r) ? first(r.retried, r.requeued, r.n, r.count) : null) || 0; }
        note(n ? `Requeued ${fmt.n(n)} failed job(s)` : 'Failed ' + kinds.join(' / ') + ' jobs requeued');
      } catch (e) { note(friendly(e)); }
      await refresh({ jobs: true });
    },
    // Maintenance switch: open = skip all on-the-fly work for a while, closed = ignore trips, auto = normal.
    async mdBreaker(state) {
      if (!['auto', 'open', 'closed'].includes(state)) return;
      let seconds = 0;
      if (state === 'auto') {
        const ok = await ask({ kicker: 'Circuit breaker', title: 'Back to automatic?', ok: 'Automatic',
          text: 'The breaker trips again on high CPU, low memory, long queues or wait times, errors and slow encodes.' });
        if (!ok) return;
      } else {
        const v = await ask({ kicker: 'Circuit breaker', title: state === 'open' ? 'Force the breaker open?' : 'Force the breaker closed?', danger: state === 'closed',
          ok: state === 'open' ? 'Force open' : 'Force closed', input: '15',
          text: (state === 'open' ? 'All on-the-fly processing is skipped (originals are served, each bypass is logged). '
            : 'The breaker ignores CPU, memory and queue pressure: encodes can then slow down Caddy and cloudflared. ') +
            'For how many minutes (1–1440)? It returns to automatic afterwards.' });
        if (v === null || v === undefined) return;
        const min = parseFloat(String(v).replace(',', '.'));
        if (!(min >= 1 && min <= 1440)) { note('Enter a number of minutes between 1 and 1440'); return; }
        seconds = Math.round(min * 60);
      }
      await act('/api/media/breaker', { state, seconds }, state === 'auto' ? 'Breaker back to automatic' : `Breaker forced ${state} for ${fmt.dur(seconds)}`, {});
    },
    mdSet(arg) {
      const s = String(arg || ''), i = s.indexOf(':'), k = s.slice(0, i), v = s.slice(i + 1);
      const allowed = { negotiation: NEG_MODES, gate_legacy: [['1'], ['0']], hold_threshold: THRESHOLDS }[k];
      if (!allowed || !allowed.some((a) => a[0] === v)) return;
      if (String(settingsNow()[k]) === v) delete S.md.draft[k]; else S.md.draft[k] = v;
      render(true);
    },
    mdDiscard() { S.md.draft = {}; render(true); },
    async mdSave() {
      const cur = settingsNow(), d = S.md.draft;
      if (!Object.keys(d).length) return;
      const body = {}, lines = [], warn = [];
      const legTxt = (x) => (x === '1' ? 'served' : x === '0' ? 'blocked' : '?');
      if ('negotiation' in d) { body.negotiation = d.negotiation; lines.push(`negotiation ${cur.negotiation || '?'} → ${d.negotiation}`); }
      if ('gate_legacy' in d) {
        body.gate_legacy = d.gate_legacy === '1';
        lines.push(`legacy files while pending ${legTxt(cur.gate_legacy)} → ${legTxt(d.gate_legacy)}`);
        if (d.gate_legacy === '1') warn.push('legacy files are served before their first scan');
      }
      if ('hold_threshold' in d) {
        body.hold_threshold = d.hold_threshold;
        lines.push(`hold threshold ${cur.hold_threshold || '?'} → ${d.hold_threshold}`);
        if ((SEV[d.hold_threshold] || 0) > (SEV[cur.hold_threshold] || 2)) warn.push('fewer files are held back' + (d.hold_threshold === 'high' ? ', unscannable ones get published' : ''));
      }
      const ok = await ask({ kicker: 'Media settings', title: 'Save and apply?', ok: 'Save & apply', danger: warn.length > 0,
        text: lines.join(' · ') + '. Saved to strata.json; the Caddy config is re-rendered and validated before it is applied.' +
          (warn.length ? ' Note: ' + warn.join('; ') + '.' : '') });
      if (!ok) return;
      try {
        const r = await post('/api/media/settings', body);
        S.md.draft = {};
        note('Media settings saved' + (r && r.apply && r.apply.changed ? ' · Caddy updated (' + r.apply.sha + ')' : ''));
      } catch (e) { note(friendly(e)); return; }
      await refresh({});
    },
  });

  MENUS.mdHold = (key) => {
    const h = holdByKey(key);
    if (!h) return null;
    const items = [{ label: 'Copy path', hint: '', run: () => copy(h.path, 'path') }];
    if (RELEASABLE.has(h.state)) items.push({ label: 'Release…', hint: 'audited', run: () => holdAction('release', key), sep: true, danger: true });
    if (h.state !== 'held') items.push({ label: 'Keep held…', hint: 'audited', run: () => holdAction('hold', key), sep: !RELEASABLE.has(h.state) });
    items.push({ label: 'Rescan…', hint: '', run: () => holdAction('rescan', key) });
    items.push({ label: S.md.sel === key ? 'Hide details' : 'Show details', hint: '', run: () => ACT.mdSel(key), sep: true });
    return { kicker: 'Hold · ' + (h.state || '?'), title: h.path, items };
  };

  /* ------------------------------------------------------------------ registration */

  VIEWS.media = ['Media', 'Edge processing · circuit breaker · scan holds · jobs · capacity advice', 'image'];
  if (!NAV_C.includes('media')) NAV_C.push('media');
  STATIC_VIEWS.add('media');      // form controls: only redrawn by render(true), i.e. by this module
  VIEWFN.media = vMedia;
  VIEW_REFRESH.media = () => refresh({ holds: true, events: true, jobs: true });
  NAV_BADGES.push(() => {
    if (D.md.deploy === 'disabled') return { badges: { media: 'off' }, alerts: { media: false } }; // switched off: not an alarm
    if (!D.md.st || D.md.deploy) return {};
    const v = verdictCounts(), n = (v.flagged || 0) + (v.error || 0), B = breaker(), W = workerState();
    const down = upOf(proc('media')) === false || W.up === false, up = capacity().rows.some((a) => a.level === 'upgrade');
    return { badges: { media: n ? fmt.n(n) : down ? 'down' : B.state === 'open' ? 'open' : up ? 'upgrade' : '' },
      alerts: { media: n > 0 || down || B.state === 'open' || up } };
  });
  if (!document.getElementById('md-css')) {
    const el = document.createElement('style');
    el.id = 'md-css';
    el.textContent = CSS;
    document.head.appendChild(el);
  }
  // app.js drops an unknown saved view to 'summary' before this file loads: restore it after a reload
  try { if (S.view !== 'media' && store.get('view', null) === 'media') S.view = 'media'; } catch { /* stay on summary */ }

  document.addEventListener('input', (e) => {
    if (e.target.id !== 'md_q') return;
    S.md.qRaw = e.target.value;
    S.md.q = e.target.value.trim();
    S.md.off = 0;
    clearTimeout(qTimer);
    qTimer = setTimeout(() => reloadList('holdsBusy', loadHolds), 300);
  });
  document.addEventListener('pointerup', () => { if (D.md.dirty) setTimeout(draw, 0); });
  // Escape closes the hold details (capture phase: an open menu, palette, dialog or sheet gets the key first)
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape' || S.view !== 'media' || !S.md.sel || S.dialog || S.menu || S.palette || document.getElementById('sheet')) return;
    if (/^(input|textarea|select)$/i.test(e.target.tagName)) return;
    S.md.sel = null;
    render(true);
  }, true);
  document.addEventListener('visibilitychange', () => { if (visible() && !S.paused) refresh({}); });
  (function loop() {
    setTimeout(async () => {
      if (visible() && !S.paused) { try { await refresh({}); } catch { /* shown in the view */ } }
      loop();
    }, POLL_MS);
  })();
  // Nav badge (held files, breaker open, service down) without opening the view: one status read shortly after boot,
  // then a slow status-only read while the tab is visible - but only once the bridge answered and the pipeline is on.
  setTimeout(() => { if (!D.md.st && !busy && S.view !== 'media') refresh({ statusOnly: true }); }, 4000);
  setInterval(() => {
    if (document.visibilityState === 'hidden' || S.paused || S.view === 'media' || busy || !D.md.st || D.md.deploy) return;
    refresh({ statusOnly: true });
  }, BADGE_MS);
})();
