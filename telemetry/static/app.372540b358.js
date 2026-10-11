'use strict';
/* Strata Telemetry - public statistics page. Reads /api/stats and /api/live (already aggregated and
   redacted upstream).

   Hardening: this file never parses HTML. Every node is made with createElement/createTextNode and
   styled through the CSSOM, so API data can only ever become text, never markup, and the CSP can forbid
   inline styles and require Trusted Types (there is no innerHTML/outerHTML/insertAdjacentHTML anywhere).
   Every number from the API is coerced through num() before it is used for layout. */

const $ = (s) => document.querySelector(s);
const isNum = (v) => typeof v === 'number' && Number.isFinite(v) && Math.abs(v) < 1e15; /* also rejects absurd magnitudes */
const num = (v, d = 0) => (isNum(v) ? v : d);
const arr = (v) => (Array.isArray(v) ? v : []);
const obj = (v) => (v !== null && typeof v === 'object' && !Array.isArray(v) ? v : {});
const str = (v) => (typeof v === 'string' ? v : isNum(v) ? String(v) : '');

/* ---------------------------------------------------------------- DOM builders */

const ATTR = /^(?:class|title|role|aria-[a-z]+|data-[a-z-]+)$/;
const SVG_ATTR = /^(?:class|viewBox|preserveAspectRatio|aria-hidden|x1|y1|x2|y2|points)$/;
const SVGNS = 'http://www.w3.org/2000/svg';

function add(el, kids) {
  for (const k of kids) {
    if (k == null || k === false) continue;
    if (Array.isArray(k)) add(el, k);
    else el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return el;
}
function make(el, allowed, props, kids) {
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'style') for (const [p, x] of Object.entries(v)) el.style.setProperty(p, String(x));
    else if (allowed.test(k)) el.setAttribute(k, String(v));
    else throw new Error('attribute not allowed: ' + k);
  }
  return add(el, kids);
}
const h = (tag, props, ...kids) => make(document.createElement(tag), ATTR, props, kids);
const svg = (tag, props, ...kids) => make(document.createElementNS(SVGNS, tag), SVG_ATTR, props, kids);

/* ---------------------------------------------------------------- state */

let range = (() => { try { return localStorage.getItem('tele:range') || '24h'; } catch { return '24h'; } })();
if (!['24h', '7d', '30d'].includes(range)) range = '24h';
let STATS = null, LIVE = null, hover = null;

const validDate = (ts) => isNum(ts) && !Number.isNaN(new Date(ts * 1000).getTime());
const fmt = {
  n: (v) => (isNum(v) ? Math.round(v).toLocaleString('en-US') : '—'),
  compact(v) {
    if (!isNum(v)) return '—';
    if (v < 1000) return String(Math.round(v));
    const u = ['', 'k', 'M', 'B'];
    let i = 0;
    while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; }
    return (v >= 100 ? v.toFixed(0) : v.toFixed(1)) + ' ' + u[i];
  },
  bytes(b) {
    if (!isNum(b)) return '—';
    const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    let i = 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return (i ? b.toFixed(b >= 100 ? 0 : 1) : Math.round(b)) + ' ' + u[i];
  },
  ms: (v) => (!isNum(v) ? '—' : v >= 1000 ? (v / 1000).toFixed(1) + ' s' : v < 10 ? v.toFixed(1) + ' ms' : Math.round(v) + ' ms'),
  pct: (v, d) => (!isNum(v) ? '—' : v.toFixed(d ?? (v >= 99.95 || v === 0 ? 0 : v >= 10 ? 1 : 2)) + ' %'),
  dt: (ts) => (validDate(ts) ? new Date(ts * 1000).toLocaleString('en-GB', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }) : '—'),
  time: (ts) => (validDate(ts) ? new Date(ts * 1000).toLocaleTimeString('en-GB') : '—'),
};
const share = (a, b) => (b ? (a / b) * 100 : 0);
const regionNames = (() => { try { return new Intl.DisplayNames(['en'], { type: 'region' }); } catch { return null; } })();
const cname = (cc) => { if (!cc || cc === 'other') return 'Other countries'; if (cc === 'XX') return 'Unknown'; if (cc === 'T1') return 'Tor'; try { return regionNames ? regionNames.of(cc) : cc; } catch { return cc; } };
const COLO = { TXL: 'Berlin', BER: 'Berlin', FRA: 'Frankfurt', HAM: 'Hamburg', MUC: 'Munich', DUS: 'Düsseldorf', AMS: 'Amsterdam', LHR: 'London', CDG: 'Paris', BRU: 'Brussels', ZRH: 'Zurich', VIE: 'Vienna', PRG: 'Prague', WAW: 'Warsaw', CPH: 'Copenhagen', ARN: 'Stockholm', OSL: 'Oslo', HEL: 'Helsinki', DUB: 'Dublin', MAD: 'Madrid', MXP: 'Milan', FCO: 'Rome', ORD: 'Chicago', BOS: 'Boston', IAD: 'Ashburn', EWR: 'Newark', LAX: 'Los Angeles', SJC: 'San Jose', SEA: 'Seattle', DFW: 'Dallas', ATL: 'Atlanta', MIA: 'Miami', CMH: 'Columbus', YYZ: 'Toronto', GRU: 'São Paulo', SIN: 'Singapore', NRT: 'Tokyo', HKG: 'Hong Kong', SYD: 'Sydney', BOM: 'Mumbai', DXB: 'Dubai' };
const CAT = { image: 'Images', video: 'Video', audio: 'Audio', '3d': '3D models', web: 'Web assets', text: 'Text & data', font: 'Fonts', archive: 'Archives', document: 'Documents', pages: 'Pages & folders', other: 'Other' };
const rangeWord = () => ({ '24h': 'last 24 hours', '7d': 'last 7 days', '30d': 'last 30 days' }[range]);
const bucketWord = (step) => (step >= 86400 ? 'day' : step >= 3600 ? (step / 3600 === 1 ? 'hour' : step / 3600 + ' h') : step / 60 + ' min');
const sum = (a) => a.reduce((x, y) => x + y, 0);

function niceMax(a, floor = 1) {
  let m = floor;
  for (const v of a) if (v > m) m = v;
  const p = Math.pow(10, Math.floor(Math.log10(m)));
  for (const s of [1, 2, 2.5, 5, 10]) if (s * p >= m) return s * p;
  return m;
}
function pts(a, w, ht, max) {
  const n = a.length;
  if (n < 2) return '';
  return a.map((v, i) => (i / (n - 1) * w).toFixed(1) + ',' + (ht - Math.min(v, max) / max * ht).toFixed(1)).join(' ');
}

/* ---------------------------------------------------------------- pieces */

function segs(v, n, hot) {
  const on = Math.round(Math.max(0, Math.min(100, num(v))) / 100 * n);
  return h('div', { class: 'segs' }, Array.from({ length: n }, (_, i) => h('span', { class: i < on ? (hot ? 'warn' : 'on') : null })));
}
function barList(rows, label, value, fmtv, o = {}) {
  rows = arr(rows).map(obj);
  if (!rows.length) return h('div', { class: 'empty' }, 'Nothing recorded in this range yet.');
  const val = (r) => num(value(r));
  const max = Math.max(1, ...rows.map(val));
  return h('div', { class: 'list' }, rows.map((r) => {
    const l = str(label(r));
    return h('div', { class: 'bl' + (o.hot && o.hot(r) ? ' hot' : '') },
      h('span', { class: 'ell', title: l }, l),
      h('span', { class: 'bar' }, h('i', { style: { width: share(val(r), max).toFixed(1) + '%' } })),
      h('span', { class: 'r' }, fmtv(r)));
  }));
}
const card = (key, title, note, ...body) => h('section', { class: 'card', 'data-t': key },
  h('div', { class: 'ph' }, h('h5', null, title), h('span', { class: 'small dim' }, note || '')), body);
const trio = (items, cls) => h('div', { class: 'trio' + (cls ? ' ' + cls : '') }, items.map(([label, value, hot]) =>
  h('div', null, h('div', { class: 'cap' }, label), h('div', { class: 'big' + (hot ? ' hot' : '') }, value))));
const stack = (parts) => h('div', { class: 'stack' }, parts.filter(([, v]) => v > 0).map(([k, v, c, t]) =>
  h('i', { title: t || k, style: { flex: String(v), background: c } })));
const keyrow = (items) => h('div', { class: 'keyrow' }, items.map(([text, color]) =>
  h('span', null, color ? h('i', { style: { background: color } }) : null, text)));

/* ---------------------------------------------------------------- render */

const kpi = (label, value, sub, bar) => h('div', { class: 'kpi' },
  h('div', { class: 'cap' }, label), h('div', { class: 'v' }, value), bar, h('div', { class: 'small dim ell' }, sub));
const unit = (s) => { const i = s.lastIndexOf(' '); return i < 0 ? s : [s.slice(0, i), h('small', null, s.slice(i + 1))]; };

function renderStatus() {
  const L = obj(LIVE), el = $('#status');
  if (!LIVE) return;
  const sitesDown = arr(L.sites).filter((s) => !obj(s).ok).length;
  const ok = L.caddy && L.tunnel && L.storage_online && !sitesDown;
  const degraded = L.caddy && L.tunnel;
  el.className = 'status' + (ok ? '' : ' bad');
  el.replaceChildren(h('i'), h('span', null, ok ? 'All systems operational' : degraded ? 'Partially degraded' : 'Major outage'));
  const item = (label, value) => h('span', { class: 'dim' }, label, h('b', null, value));
  $('#live').replaceChildren(
    h('span', null, h('span', { class: 'pulse' }), 'Live'),
    item('requests', num(L.rps).toFixed(2) + '/s'),
    item('serving', fmt.bytes(L.bps) + '/s'),
    item('visitors now', fmt.n(L.visitors_5m)),
    item('edge links', fmt.n(L.tunnel_connections) + '/4'),
    item('edge RTT', fmt.ms(L.tunnel_rtt)),
    item('services', fmt.n(L.services_up) + '/' + fmt.n(L.services_total)));
}

function renderKpis() {
  const S = STATS;
  if (!S) return;
  const t = obj(S.totals), up = obj(S.uptime), series = obj(S.series), K = obj(S.kinds);
  const peak = Math.max(0, ...arr(series.reqs).map((v) => num(v)));
  const errPct = share(num(t.e4) + num(t.e5), num(t.reqs));
  const humans = num(K.people) + num(K.players) + num(K.previews);
  const cu = obj(up.caddy_up), tu = obj(up.tunnel_up);
  const upPct = isNum(cu.pct) && isNum(tu.pct) ? Math.min(cu.pct, tu.pct) : null;
  const edge = S.edge ? obj(S.edge) : null;
  $('#kpis').replaceChildren(
    kpi('Requests', unit(fmt.compact(t.reqs)), `peak ${fmt.n(peak)} per ${bucketWord(num(series.step, 60))}`, segs(share(humans, num(t.reqs)), 18)),
    kpi('Data served', unit(fmt.bytes(t.bytes)), edge ? `${fmt.bytes(edge.bytes)} incl. Cloudflare cache (24 h)` : 'from the origin'),
    kpi('Visitors', unit(fmt.compact(t.visitors)), `${fmt.pct(share(humans, num(t.reqs)), 0)} of requests from people & apps`),
    kpi('Median response', unit(fmt.ms(t.p50)), `p95 ${fmt.ms(t.p95)} · p99 ${fmt.ms(t.p99)}`, segs(Math.min(100, num(t.p95) / 5), 18, num(t.p95) > 250)),
    kpi('Uptime', upPct == null ? '—' : unit(fmt.pct(upPct)), cu.minutes ? `measured over ${fmt.n(cu.minutes)} minutes` : 'measuring', segs(upPct || 0, 18, upPct != null && upPct < 99)),
    kpi('Saved by Brotli', unit(fmt.bytes(t.saved)), `${fmt.pct(share(num(t.encoded), num(t.reqs)), 0)} of responses compressed · ${fmt.pct(errPct, 1)} errors`));
}

/* Traffic chart: the SVG is drawn once per data refresh; hovering only moves the crosshair/tooltip. */
const chartEl = $('#chart');
const cross = h('div', { class: 'cross' });
const tip = h('div', { class: 'tip' });
cross.hidden = tip.hidden = true;
let chartData = null;

function renderChart() {
  const S = STATS;
  if (!S) return;
  const s = obj(S.series);
  if (!Array.isArray(s.reqs)) return;
  const reqs = s.reqs.map((v) => num(v)), bytes = arr(s.bytes).map((v) => num(v)), errs = arr(s.errors).map((v) => num(v)), vis = arr(s.visitors).map((v) => num(v));
  const step = num(s.step, 60), t0 = num(s.t0);
  const rMax = niceMax(reqs, 5), bMax = Math.max(1, ...bytes);
  const area = (a, max) => { const p = pts(a, 320, 128, max); return p ? `0,128 ${p} 320,128` : ''; };
  chartData = { reqs, bytes, errs, vis, step, t0 };
  chartEl.setAttribute('aria-label', `Requests over the ${rangeWord()}: peak ${fmt.n(Math.max(0, ...reqs))} per ${bucketWord(step)}, ${fmt.n(sum(errs))} errors in total.`);
  chartEl.replaceChildren(
    svg('svg', { viewBox: '0 0 320 128', preserveAspectRatio: 'none', 'aria-hidden': 'true' },
      [32, 64, 96].map((y) => svg('line', { class: 'gl', x1: 0, y1: y, x2: 320, y2: y })),
      svg('polygon', { class: 'area', points: area(bytes, bMax) }),
      svg('polyline', { class: 'l-req', points: pts(reqs, 320, 128, rMax) }),
      svg('polyline', { class: 'l-err', points: pts(errs, 320, 128, rMax) })),
    h('div', { class: 'ymax' }, `${fmt.n(rMax)} requests / ${bucketWord(step)}`), cross, tip);
  $('#axis').replaceChildren(h('span', null, fmt.dt(t0)), h('span', null, rangeWord()), h('span', null, 'now'));
  renderTip();
}
function renderTip() {
  if (hover == null || !chartData) { cross.hidden = tip.hidden = true; return; }
  const { reqs, bytes, errs, vis, step, t0 } = chartData;
  const i = Math.max(0, Math.min(reqs.length - 1, Math.round(hover * (reqs.length - 1))));
  cross.style.setProperty('left', (hover * 100).toFixed(2) + '%');
  const right = hover > 0.6;
  tip.style.setProperty('left', right ? 'auto' : (hover * 100 + 1).toFixed(2) + '%');
  tip.style.setProperty('right', right ? ((1 - hover) * 100 + 1).toFixed(2) + '%' : 'auto');
  tip.replaceChildren(`${fmt.dt(t0 + i * step)} · ${bucketWord(step)}`, h('br'),
    `${fmt.n(reqs[i])} requests · ${fmt.bytes(bytes[i])}`, h('br'), `${fmt.n(vis[i])} visitors · ${fmt.n(errs[i])} errors`);
  cross.hidden = tip.hidden = false;
}

function renderGrid() {
  const S = STATS;
  if (!S) return;
  const t = obj(S.totals), K = obj(S.kinds), reqs = num(t.reqs);
  const grid = $('#grid');

  const kTot = Math.max(1, num(K.people) + num(K.players) + num(K.previews) + num(K.bots));
  const kinds = [['People', 'people', 'var(--color-text)'], ['Media players', 'players', 'var(--color-neutral-600)'], ['Link previews', 'previews', 'var(--color-neutral-400)'], ['Bots & tools', 'bots', 'var(--color-accent)']];
  const asking = card('asking', 'Who is asking', 'share of requests',
    stack(kinds.map(([, k, c]) => [k, num(K[k]), c])),
    keyrow(kinds.map(([l, k, c]) => [`${l} ${fmt.pct(share(num(K[k]), kTot), 0)}`, c])),
    barList(S.agents, (r) => r.k, (r) => r.c, (r) => fmt.pct(share(num(r.c), reqs), 1), { hot: (r) => r.k === 'Bots & tools' }));

  const cls = obj(S.classes);
  const cTot = Math.max(1, sum(Object.values(cls).map((v) => num(v))));
  const classes = [['2xx', 'var(--color-text)'], ['3xx', 'var(--color-neutral-500)'], ['4xx', 'var(--color-accent)'], ['5xx', 'var(--color-accent-800)']];
  const codes = card('codes', 'Response codes', rangeWord(),
    stack(classes.map(([k, c]) => [k, num(cls[k]), c])),
    keyrow(classes.map(([k]) => [`${k} ${fmt.pct(share(num(cls[k]), cTot), 1)}`])),
    h('div', { class: 'cap sub' }, 'Operating systems'),
    barList(S.os, (r) => r.k, (r) => r.c, (r) => fmt.pct(share(num(r.c), reqs), 1)));

  const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const heatRows = [1, 2, 3, 4, 5, 6, 0].map((d) => { const r = arr(arr(S.heat)[d]).map((v) => num(v)); while (r.length < 24) r.push(0); return r.slice(0, 24); });
  const hmax = Math.max(1, ...heatRows.flat());
  const heat = h('div', { class: 'heat' }, h('span'),
    Array.from({ length: 24 }, (_, hr) => h('span', { class: 'lbl c' }, hr % 3 === 0 ? String(hr).padStart(2, '0') : '')),
    heatRows.map((row, i) => [h('span', { class: 'lbl' }, days[i]), row.map((v, hr) =>
      h('span', {
        title: `${days[i]} ${String(hr).padStart(2, '0')}:00 · ${fmt.n(v)} requests`,
        style: { background: v ? `color-mix(in srgb, var(--color-text) ${(8 + v / hmax * 82).toFixed(0)}%, transparent)` : 'var(--color-neutral-200)' },
      }))]));
  const rhythm = card('rhythm', 'Weekly rhythm', 'requests by weekday and hour (server time)', heat);

  const lat = arr(S.latency).map((v) => num(v));
  const lmax = Math.max(1, ...lat);
  const lnames = ['<1', '1–5', '5–10', '10–25', '25–50', '50–100', '100–250', '250–500', '.5–1s', '1–2.5s', '>2.5s'];
  const latency = card('latency', 'Response time', 'measured at the origin',
    trio([['p50', fmt.ms(t.p50)], ['p95', fmt.ms(t.p95)], ['p99', fmt.ms(t.p99)]]),
    h('div', { class: 'hist' }, lat.map((v, i) => h('span', { class: i >= 8 ? 'slow' : null, title: `${lnames[i] || ''} ms · ${fmt.n(v)}`, style: { height: share(v, lmax).toFixed(1) + '%' } }))),
    h('div', { class: 'hlab' }, lnames.map((l) => h('span', null, l))));

  const enc = obj(S.encodings), pre = obj(S.precompressed), br = obj(pre.br);
  const encRows = Object.entries(enc).map(([k, v]) => ({ k, ...obj(v) }));
  const encTot = Math.max(1, sum(encRows.map((e) => num(e.c))));
  const compress = card('compress', 'Compression', rangeWord(),
    trio([['Saved', fmt.bytes(t.saved)], ['Store', fmt.pct(br.orig ? 100 - share(num(br.size), num(br.orig)) : null, 0)], ['Files', fmt.n(br.files)]]),
    h('div', { class: 'note gap' }, 'Text, code, fonts and 3D assets are precompressed with Brotli at maximum quality' +
      (br.orig ? `; ${fmt.bytes(br.orig)} of originals are stored as ${fmt.bytes(br.size)}.` : '.')),
    barList(encRows.sort((a, b) => num(b.c) - num(a.c)),
      (r) => ({ identity: 'Not compressed (media)', br: 'Brotli (precompressed)', zstd: 'Zstandard (on the fly)', gzip: 'Gzip (on the fly)' }[r.k] || r.k),
      (r) => r.c, (r) => fmt.pct(share(num(r.c), encTot), 0)));

  const inv = obj(S.inventory), L = obj(LIVE), up = obj(S.uptime);
  const row = (ok, label, right) => h('div', { class: 'svc' }, h('span', null, h('span', { class: 'dot' + (ok ? '' : ' bad') }), label), right);
  const health = card('health', 'Service health', 'live',
    h('div', { class: 'list' },
      arr(L.sites).map(obj).map((s) => row(s.ok, str(s.k), h('span', { class: 'dim' }, s.ok ? 'up · ' + fmt.ms(s.ms) : h('b', { class: 'hot' }, 'down')))),
      row(L.tunnel, 'Cloudflare tunnel', h('span', { class: 'dim' }, `${fmt.n(L.tunnel_connections)}/4 links · ${fmt.ms(L.tunnel_rtt)}`)),
      row(L.storage_online, 'Media storage', h('span', { class: 'dim' }, L.storage_online ? 'online · ' + fmt.pct(L.storage_used_pct, 0) + ' full' : 'offline')),
      row(L.services_up === L.services_total, 'All hosted services', h('span', { class: 'dim' }, `${fmt.n(L.services_up)} of ${fmt.n(L.services_total)} up`))),
    trio([['Origin', fmt.pct(obj(up.caddy_up).pct)], ['Tunnel', fmt.pct(obj(up.tunnel_up).pct)], ['Services', fmt.pct(obj(up.origins_up).pct)]], 'tight'),
    h('div', { class: 'note' }, `Uptime over the ${rangeWord()}${S.monitoring_since ? ' · monitoring since ' + fmt.dt(S.monitoring_since) : ''}.`));

  const edge = S.edge ? obj(S.edge) : null;
  let edgeCard = null;
  if (edge) {
    const hrs = arr(edge.hours).map(obj);
    const m = Math.max(1, ...hrs.map((x) => num(x.r)));
    edgeCard = card('edge', 'Cloudflare edge · 24 h', 'ink = served from cache',
      trio([['Requests', fmt.compact(edge.requests)], ['Cache hits', fmt.pct(share(num(edge.cached), num(edge.requests)), 0)], ['Threats', fmt.n(edge.threats), num(edge.threats) > 0]]),
      h('div', { class: 'bars' }, hrs.map((x) => h('div', {
        class: 'col', title: `${str(x.t).slice(11, 16)} UTC · ${fmt.n(x.r)} requests · ${fmt.pct(share(num(x.c), num(x.r)), 0)} cached`,
        style: { height: Math.max(num(x.r) ? 3 : 0, share(num(x.r), m)).toFixed(1) + '%' },
      }, h('span', { style: { flex: String(num(x.c)), background: 'var(--color-text)' } }), h('span', { style: { flex: String(Math.max(0, num(x.r) - num(x.c))), background: 'var(--color-accent)' } })))),
      h('div', { class: 'note' }, `${fmt.bytes(edge.bytes)} delivered · ${fmt.pct(share(num(edge.cached_bytes), num(edge.bytes)), 0)} of it from cache`));
  }
  grid.classList.toggle('noedge', !edgeCard);

  const threats = arr(S.threats).map(obj);
  const threatTot = sum(threats.map((r) => num(r.c)));
  const tiles = [
    card('geo', 'Where visitors are', rangeWord(), barList(arr(S.countries).slice(0, 12), (r) => cname(r.k), (r) => r.c, (r) => fmt.compact(r.c))),
    asking, health, rhythm, codes,
    card('served', 'What gets served', 'by data volume', barList(S.categories, (r) => CAT[r.k] || r.k, (r) => r.b, (r) => fmt.bytes(r.b))),
    card('coll', 'Collections', 'top-level folders · by requests', barList(S.collections, (r) => r.k === '(root)' ? 'Top level' : r.k === 'other' ? 'Other / private' : r.k, (r) => r.c, (r) => fmt.compact(r.c))),
    card('ext', 'File types', 'by requests', barList(S.extensions, (r) => r.k === '—' ? '(no extension)' : '.' + r.k, (r) => r.c, (r) => fmt.compact(r.c))),
    latency, compress,
    card('probes', 'Blocked probes', `${fmt.n(t.probes)} requests · ${fmt.n(S.scanners)} scanners`,
      threats.length ? barList(threats, (r) => r.k, (r) => r.c, (r) => fmt.pct(share(num(r.c), threatTot), 0), { hot: () => true }) : h('div', { class: 'empty' }, 'No probing in this range.')),
    edgeCard,
    card('colos', 'Edge locations', 'Cloudflare data centres', barList(arr(S.colos).slice(0, 10), (r) => r.k === 'other' ? 'Other locations' : COLO[r.k] ? `${r.k} · ${COLO[r.k]}` : r.k, (r) => r.c, (r) => fmt.compact(r.c))),
    card('library', 'Library', inv.files ? `${fmt.n(inv.files)} files · ${fmt.bytes(inv.bytes)}` : 'first inventory pending', barList(inv.cats, (r) => (CAT[r.k] || r.k) + ' · ' + fmt.n(r.c), (r) => r.b, (r) => fmt.bytes(r.b))),
  ].filter(Boolean);
  for (const n of [...grid.children]) if (!n.classList.contains('traffic')) n.remove();
  grid.append(...tiles);
  $('#kanon').textContent = String(num(S.k_anon, 3));
  $('#updated').textContent = 'Updated ' + fmt.time(S.generated) + ' · Strata Telemetry';
  fit();
}

/* In wide mode every tile has a fixed height. Hide the trailing rows of a list that do not fit, so a tile
   shows as many whole rows as it can and never a half-cut one. Outside wide mode lists are natural height. */
const wideMQ = matchMedia('(min-width: 1100px) and (min-aspect-ratio: 4/3)');
function fit() {
  for (const list of document.querySelectorAll('#grid .list')) {
    const rows = [...list.children];
    for (const r of rows) r.hidden = false;
    if (!wideMQ.matches) continue;
    const limit = list.clientHeight + 1;
    let keep = rows.findIndex((r) => r.offsetTop + r.offsetHeight > limit);
    if (keep === 0) keep = 1;
    if (keep > 0) for (let i = keep; i < rows.length; i++) rows[i].hidden = true;
  }
}
let fitQueued = false;
const fitSoon = () => { if (!fitQueued) { fitQueued = true; requestAnimationFrame(() => { fitQueued = false; fit(); }); } };
new ResizeObserver(fitSoon).observe($('#grid'));
if (document.fonts && document.fonts.ready) document.fonts.ready.then(fitSoon);

function renderAll() {
  renderStatus(); renderKpis(); renderChart(); renderGrid();
  for (const b of document.querySelectorAll('#ranges button')) {
    const on = b.dataset.range === range;
    b.classList.toggle('on', on);
    b.setAttribute('aria-pressed', String(on));
  }
}

/* ---------------------------------------------------------------- data */

async function load(url) {
  const r = await fetch(url, {
    cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer',
    signal: AbortSignal.timeout ? AbortSignal.timeout(10000) : undefined,
  });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  if (!/^application\/json\b/i.test(r.headers.get('content-type') || '')) throw new Error('unexpected content type');
  return obj(await r.json());
}
let seq = 0;
async function pullStats() {
  const s = ++seq;
  try {
    const v = await load('/api/stats?range=' + encodeURIComponent(range));
    if (s !== seq) return;
    STATS = v;
    if (v.live) LIVE = LIVE || obj(v.live);
    $('#banner').classList.remove('show');
    renderAll();
  } catch { $('#banner').classList.add('show'); }
}
async function pullLive() {
  try { LIVE = await load('/api/live'); renderStatus(); } catch { /* keep last */ }
}

$('#ranges').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-range]');
  if (!b || !['24h', '7d', '30d'].includes(b.dataset.range)) return;
  range = b.dataset.range;
  try { localStorage.setItem('tele:range', range); } catch { /* private mode */ }
  for (const x of document.querySelectorAll('#ranges button')) { x.classList.toggle('on', x === b); x.setAttribute('aria-pressed', String(x === b)); }
  pullStats();
});
for (const x of document.querySelectorAll('#ranges button')) { const on = x.dataset.range === range; x.classList.toggle('on', on); x.setAttribute('aria-pressed', String(on)); }
chartEl.addEventListener('pointermove', (e) => { const r = chartEl.getBoundingClientRect(); hover = r.width ? Math.max(0, Math.min(1, (e.clientX - r.left) / r.width)) : null; renderTip(); });
chartEl.addEventListener('pointerleave', () => { hover = null; renderTip(); });

/* Poll only while the tab is visible: a hidden dashboard costs the server nothing. */
pullStats();
pullLive();
setInterval(() => { if (!document.hidden) pullStats(); }, 30000);
setInterval(() => { if (!document.hidden) pullLive(); }, 5000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) { pullStats(); pullLive(); } });
