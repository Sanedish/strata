'use strict';
/* Strata - CDN monitor front end. Renders strata.py's /api/* into the Strata System Monitor layout.
   Everything that comes from the access log is attacker-controlled (paths, user agents, referrers):
   it only ever reaches the DOM through esc(). Icons: Lucide (ISC), static/icons.svg. */

const $ = (s) => document.querySelector(s);
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const enc = encodeURIComponent;
// which site this dashboard manages (strata.py fills index.html's meta tag from the instance's strata.json)
const INST = (() => { try { return JSON.parse(document.querySelector('meta[name="strata-instance"]').content); } catch { return {}; } })();
const cdnHost = () => INST.cdn_host || location.hostname;
const icon = (name, cls = '') => `<svg class="ic ${cls}" aria-hidden="true"><use href="icons.svg#i-${name}"/></svg>`;

const VIEWS = {
  summary: ['Summary', 'Traffic and health at a glance', 'layout-dashboard'],
  requests: ['Requests', 'Live request log', 'activity'],
  logs: ['Logs', 'Errors, requests and account activity', 'terminal'],
  content: ['Content', 'Most requested files', 'file-text'],
  visitors: ['Visitors', 'Countries, networks and clients', 'earth'],
  insights: ['Insights', 'Patterns over time', 'lightbulb'],
  files: ['Files', 'Browse and manage your drives', 'folder-open'],
  upload: ['Upload', 'Add files to a drive', 'upload'],
  analyze: ['Analyze', 'Disk usage and growth', 'chart-pie'],
  serving: ['Serving', 'Drives, rules and error pages', 'server'],
  blacklist: ['Blocklist', 'Blocked IPs, countries and clients', 'ban'],
  links: ['Links', 'Short and signed links', 'link'],
  alerts: ['Alerts', 'Security and health events', 'bell'],
  network: ['Network', 'DNS, zone settings and exposed services', 'globe'],
  tunnel: ['Tunnel', 'Cloudflare tunnel connections', 'cable'],
  origins: ['Origins', 'Services behind the tunnel', 'network'],
  compression: ['Compression', 'Precompressed files and savings', 'archive'],
  security: ['Security', 'Scanners and suspicious requests', 'shield-alert'],
  latency: ['Latency', 'Response times', 'timer'],
  history: ['History', 'The last 24 hours', 'clock-fading'],
  edge: ['Edge', 'Cloudflare cache and threats', 'cloud'],
  system: ['System', 'Processes, database and retention', 'cpu'],
  accounts: ['Accounts', 'Users, permissions and storage access', 'key-round'],
  office: ['Team', 'People, noticeboard and notes', 'users'],
  ide: ['Code', 'Edit Strata’s source', 'code'],
  settings: ['Settings', 'Your preferences', 'settings'],
};
// grouped by task. Upload is not listed: the header's Upload button opens it from every view.
const NAV_GROUPS = [
  ['Overview', ['summary', 'alerts', 'office']],
  ['Traffic', ['requests', 'visitors', 'content', 'insights']],
  ['Files', ['files', 'analyze']],
  ['Site', ['serving', 'links', 'compression']],
  ['Security', ['blacklist', 'security']],
  ['Infrastructure', ['network', 'tunnel', 'origins', 'edge', 'latency', 'history', 'system', 'logs'], 'deep'],
  ['Admin', ['accounts', 'ide']],
];
const navGroup = (t) => NAV_GROUPS.find((g) => g[0] === t)[1];
const NAV_C = navGroup('Site'), NAV2 = navGroup('Infrastructure'); // media.js appends 'media' to NAV_C
// "work" views (files, team, configuration, administration, settings) have no use for the traffic vitals, time ranges
// or the request filter: they get that height and width back unless Settings › Vitals › Show everywhere is on
const WORK_VIEWS = new Set(['office', 'files', 'upload', 'analyze', 'serving', 'blacklist', 'links', 'alerts', 'network', 'accounts', 'ide', 'settings']);
const workView = (v = S.view) => WORK_VIEWS.has(v);
const NAV_BADGES = [];   // modules push () => ({badges: {view: text}, alerts: {view: true}})
const STATIC_VIEWS = new Set(['settings']);
const OVERLAYS = [];     // modules push () => html (rendered by renderOverlay)
const VIEW_REFRESH = {}; // modules register view -> loader
const SETTINGS_PANELS = []; // modules push () => html
const PALETTE_SOURCES = []; // modules push (q) => [{label, hint, icon, run, group}]
const RANGES = [['live', 'Live'], ['1h', '1 h'], ['6h', '6 h'], ['24h', '24 h'], ['7d', '7 d'], ['30d', '30 d'], ['90d', '90 d']];
const RATES = [500, 1000, 2000, 5000, 10000];
const ACCENTS = [['#ec3013', 'Signal red'], ['#5b4fe8', 'Indigo'], ['#0a84ff', 'Blue'], ['#0f9d7a', 'Teal'], ['#2f9e44', 'Green'],
  ['#e8590c', 'Orange'], ['#d6336c', 'Pink'], ['#9c36b5', 'Violet'], ['#f08c00', 'Amber'], ['#495057', 'Graphite']];
const COLO = {
  TXL: 'Berlin', BER: 'Berlin', FRA: 'Frankfurt', HAM: 'Hamburg', MUC: 'Munich', DUS: 'Düsseldorf', STR: 'Stuttgart',
  AMS: 'Amsterdam', LHR: 'London', MAN: 'Manchester', CDG: 'Paris', MRS: 'Marseille', BRU: 'Brussels', LUX: 'Luxembourg',
  ZRH: 'Zurich', GVA: 'Geneva', VIE: 'Vienna', PRG: 'Prague', WAW: 'Warsaw', BUD: 'Budapest', CPH: 'Copenhagen',
  ARN: 'Stockholm', OSL: 'Oslo', HEL: 'Helsinki', DUB: 'Dublin', MAD: 'Madrid', BCN: 'Barcelona', LIS: 'Lisbon',
  MXP: 'Milan', FCO: 'Rome', ATH: 'Athens', IST: 'Istanbul', KBP: 'Kyiv', RIX: 'Riga', VNO: 'Vilnius', TLL: 'Tallinn',
  ORD: 'Chicago', BOS: 'Boston', IAD: 'Ashburn', EWR: 'Newark', JFK: 'New York', LAX: 'Los Angeles', SJC: 'San Jose',
  SEA: 'Seattle', DFW: 'Dallas', ATL: 'Atlanta', MIA: 'Miami', DEN: 'Denver', PHX: 'Phoenix', YYZ: 'Toronto',
  YVR: 'Vancouver', GRU: 'São Paulo', SIN: 'Singapore', NRT: 'Tokyo', KIX: 'Osaka', HKG: 'Hong Kong', ICN: 'Seoul',
  SYD: 'Sydney', MEL: 'Melbourne', BOM: 'Mumbai', DEL: 'New Delhi', DXB: 'Dubai', JNB: 'Johannesburg', LAN: 'LAN / direct',
};
const KIND = { browser: 'People', player: 'Media players', embed: 'Link previews', bot: 'Bots & tools' };

/* ------------------------------------------------------------------ state + preferences */

const store = {
  get(k, d) { try { const v = localStorage.getItem('strata:' + k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem('strata:' + k, JSON.stringify(v)); } catch { /* private mode */ } },
};
// every key here is a preference: saved in this browser and, with Settings › Preferences › Sync on, in the account
const PREFS = {
  view: 'summary', deep: false, range: 'live', nobots: false, rate: 1000, widths: {}, fields: false, scale: null,
  scale100: false, reduceMotion: false, theme: 'auto', accent: null, density: 'normal', radius: 1, font: 'archivo',
  zebra: false, navCollapsed: false, navHidden: [], navPinned: [], landing: '', vitals: ['reqs', 'bytes', 'uniq', 'errors', 'latency', 'tunnel'],
  clock24: true, relTimes: true, hiddenPause: true, notify: false, savedFilters: [], syncPrefs: false, palRecent: [],
  confirmDelete: true, vitalsAll: false,
};
const S = {};
for (const [k, d] of Object.entries(PREFS)) S[k] = store.get(k, d);
Object.assign(S, {
  q: '', ipFilter: '', paused: false, scope: 'all', sel: null, selRow: null, insTab: 'request',
  rf: { status: '', method: '', host: '', country: '', kind: '', since: '', min_ms: '' },
  sort: { content: 'c' }, tab: { visitors: 'countries', security: 'scanners', compression: 'files' },
  menu: null, palette: false, pq: '', palIdx: 0, hover: null, dialog: null, dragOver: false, help: false,
  fpath: store.get('fpath', '/'), fsel: new Set(), fanchor: null, ftab: 'files', gkey: 0,
});
if (S.landing && VIEWS[S.landing] && !sessionStorage.getItem('strata:booted')) S.view = S.landing;
try { sessionStorage.setItem('strata:booted', '1'); } catch { /* ignore */ }
if (!VIEWS[S.view]) S.view = 'summary';
const D = { live: null, stats: null, req: null, hist: null, edge: null, ip: null, fresh: new Set(), maxId: 0,
  files: null, trash: null, audit: null, insights: null, comp: null, palFiles: null };
const U = []; // upload queue
let uploadSeq = 0;
let syncT = 0;
const persist = () => {
  Object.keys(PREFS).forEach((k) => store.set(k, S[k]));
  if (S.syncPrefs) { clearTimeout(syncT); syncT = setTimeout(pushPrefs, 1500); }
};
function prefsSnapshot() { const o = {}; Object.keys(PREFS).forEach((k) => { o[k] = S[k]; }); return o; }
async function pushPrefs() { try { await post('/api/prefs', { prefs: prefsSnapshot(), ts: Date.now() / 1000 }); } catch { /* offline: next change retries */ } }
async function pullPrefs() {
  try {
    const r = await get('/api/prefs');
    if (r && r.prefs && r.prefs.syncPrefs) {
      Object.entries(r.prefs).forEach(([k, v]) => { if (k in PREFS) S[k] = v; });
      const moved = scaleMigrate(r.prefs);
      Object.keys(PREFS).forEach((k) => store.set(k, S[k]));
      if (moved) pushPrefs();
      applyScale(); applyAppearance(); render(true);
    }
  } catch { /* not synced */ }
}

/* UI scale: CSS zoom on <html>, 100 % unless you pick another size. It applies as chosen on every window size, like
   browser zoom, except on phones. */
const SCALE_MIN = 0.75, SCALE_MAX = 2, SCALE_DEFAULT = 1;
const SCALE_PRESETS = [1, 1.15, 1.25, 1.3, 1.4, 1.5, 1.75];
const clampScale = (v) => Math.min(SCALE_MAX, Math.max(SCALE_MIN, Math.round(v * 100) / 100));
// 130 % was the default until October 2026 and was saved with every other preference: move those to the new default
// once. `prefs` is where the scale came from (this browser, or the account when preferences sync).
function scaleMigrate(prefs) {
  if (prefs.scale100) return false;
  if (S.scale === 1.3) S.scale = SCALE_DEFAULT;
  S.scale100 = true;
  return true;
}
if (typeof S.scale !== 'number') S.scale = SCALE_DEFAULT;
if (scaleMigrate({ scale100: S.scale100 })) { store.set('scale', S.scale); store.set('scale100', true); }
let zoomNow = 1;
function effectiveScale() {
  const z = innerWidth < 760 ? Math.min(S.scale, 1) : S.scale; // a desktop zoom synced to a phone would leave ~300 css px
  return Math.round(z * 1000) / 1000;
}
function applyScale() {
  zoomNow = effectiveScale();
  const r = document.documentElement;
  r.style.zoom = zoomNow === 1 ? '' : String(zoomNow);
  r.style.setProperty('--ui-zoom', String(zoomNow));
  r.classList.toggle('reduce-motion', !!S.reduceMotion);
  try { localStorage.setItem('strata:zoom', JSON.stringify(zoomNow)); } catch { /* login page just stays at 100 % */ }
}
const darkQuery = window.matchMedia ? matchMedia('(prefers-color-scheme: dark)') : null;
function applyAppearance() {
  const r = document.documentElement;
  const dark = S.theme === 'dark' || (S.theme === 'auto' && darkQuery && darkQuery.matches);
  r.dataset.theme = dark ? 'dark' : 'light';
  const acc = S.accent || INST.accent;
  if (acc && /^#[0-9a-f]{6}$/i.test(acc)) r.style.setProperty('--color-accent', acc); else r.style.removeProperty('--color-accent');
  r.dataset.density = S.density;
  r.dataset.radius = String(S.radius);
  r.dataset.font = S.font;
  const app = $('#app');
  if (app) app.classList.toggle('navc', !!S.navCollapsed);
  const tb = $('#themebtn');
  patch(tb, icon(S.theme === 'auto' ? 'monitor' : S.theme === 'dark' ? 'moon' : 'sun'));
  patch($('#navc'), icon(S.navCollapsed ? 'panel-left' : 'panel-left-close'));
}
if (darkQuery && darkQuery.addEventListener) darkQuery.addEventListener('change', () => { if (S.theme === 'auto') applyAppearance(); });
applyScale();

/* ------------------------------------------------------------------ formatting */

const fmt = {
  n: (v) => (v == null || isNaN(v) ? '—' : Math.round(v).toLocaleString('en-US')),
  n1: (v) => (v == null || isNaN(v) ? '—' : (+v).toFixed(1)),
  bytes(b, d = 1) {
    if (b == null || isNaN(b)) return '—';
    const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    let i = 0; b = +b;
    while (Math.abs(b) >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return (i ? b.toFixed(b >= 100 ? 0 : d) : Math.round(b)) + ' ' + u[i];
  },
  rate: (bps) => (bps == null ? '—' : fmt.bytes(bps) + '/s'),
  ms: (v) => (v == null || isNaN(v) ? '—' : v < 10 ? (+v).toFixed(2) + ' ms' : v < 100 ? (+v).toFixed(1) + ' ms' : fmt.n(v) + ' ms'),
  dur(s) {
    if (s == null || isNaN(s)) return '—';
    s = Math.max(0, s);
    if (s < 60) return Math.round(s) + ' s';
    if (s < 3600) return Math.round(s / 60) + ' m';
    if (s < 86400) return (s / 3600).toFixed(1) + ' h';
    return Math.floor(s / 86400) + ' d ' + String(Math.floor((s % 86400) / 3600)).padStart(2, '0') + ' h';
  },
  ago(ts) { if (!ts) return '—'; const s = Date.now() / 1000 - ts; if (!S.relTimes) return fmt.dt(ts); return s < 5 ? 'now' : s < 0 ? 'in ' + fmt.dur(-s) : fmt.dur(s) + ' ago'; },
  time: (ts) => new Date(ts * 1000).toLocaleTimeString(S.clock24 ? 'en-GB' : 'en-US'),
  hm: (ts) => new Date(ts * 1000).toLocaleTimeString(S.clock24 ? 'en-GB' : 'en-US', { hour: '2-digit', minute: '2-digit' }),
  dt(ts) {
    if (!ts) return '—';
    const d = new Date(ts * 1000);
    return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' }) + ' ' + fmt.hm(ts);
  },
  date: (ts) => (ts ? new Date(ts * 1000).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) : '—'),
  pct: (v) => (v == null || isNaN(v) ? '—' : (v >= 10 || v === 0 ? v.toFixed(0) : v.toFixed(1)) + ' %'),
};
const regionNames = (() => { try { return new Intl.DisplayNames(['en'], { type: 'region' }); } catch { return null; } })();
function cname(cc) {
  if (!cc || cc === 'XX') return 'Unknown';
  if (cc === 'T1') return 'Tor exit';
  try { return regionNames ? regionNames.of(cc) : cc; } catch { return cc; }
}
const coloName = (c) => COLO[String(c || '').slice(0, 3).toUpperCase()] || c || '—';
const share = (a, b) => (b ? (a / b) * 100 : 0);
const RANGE_LABEL = { live: 'last hour', '1h': 'last hour', '6h': 'last 6 h', '24h': 'last 24 h', '7d': 'last 7 days', '30d': 'last 30 days', '90d': 'last 90 days' };
const rangeLabel = () => RANGE_LABEL[S.range] || S.range;
const statsRange = () => (S.range === 'live' ? '1h' : S.range);
const bucketLabel = (step) => (step < 3600 ? step / 60 + ' min' : step < 86400 ? step / 3600 + ' h' : step / 86400 + ' d');

/* ------------------------------------------------------------------ drawing */

function niceMax(arr, floor = 1) {
  let m = floor;
  for (const v of arr || []) if (v != null && v > m) m = v;
  const p = Math.pow(10, Math.floor(Math.log10(m)));
  for (const s of [1, 2, 2.5, 5, 10]) if (s * p >= m) return s * p;
  return m;
}
function pts(arr, w, h, max) {
  const n = arr.length;
  if (n < 2) return '';
  return arr.map((v, i) => (i / (n - 1) * w).toFixed(1) + ',' + (h - Math.min(v || 0, max) / max * h).toFixed(1)).join(' ');
}
function areaPts(arr, w, h, max) { const p = pts(arr, w, h, max); return p ? `0,${h} ${p} ${w},${h}` : ''; }
function segs(v, n, warnAt, cls = '', hot) {
  const pctv = Math.max(0, Math.min(100, v || 0));
  const on = Math.round(pctv / 100 * n);
  const isHot = hot ?? pctv >= warnAt;
  let out = `<div class="segs ${cls}">`;
  for (let i = 0; i < n; i++) out += `<span class="${i < on ? (isHot ? 'warn' : 'on') : ''}"></span>`;
  return out + '</div>';
}
function sparkSvg(arr, { w = 240, h = 76, cls = 'spark', max, stroke = 'var(--color-text)' } = {}) {
  const a = (arr || []).map((v) => v ?? 0);
  const m = max ?? niceMax(a, 1e-9);
  return `<svg class="${cls}" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
    <line x1="0" y1="${h / 2}" x2="${w}" y2="${h / 2}" stroke="var(--color-neutral-300)" stroke-width="0.5"></line>
    <polygon points="${areaPts(a, w, h, m)}" fill="color-mix(in srgb, var(--color-text) 11%, transparent)"></polygon>
    <polyline points="${pts(a, w, h, m)}" fill="none" stroke="${stroke}" stroke-width="1.5" vector-effect="non-scaling-stroke"></polyline>
  </svg>`;
}
// multi-series line chart (Analyze › Growth, Network): series [{label, data: [[x, y]], color}]
function lineChart(series, { h = 180, fmtY = (v) => fmt.n(v), fmtX = (x) => fmt.date(x) } = {}) {
  const all = series.flatMap((s) => s.data);
  if (all.length < 2) return '<div class="empty">Not enough data yet: one point is added per day.</div>';
  const xs = all.map((p) => p[0]), ys = all.map((p) => p[1]);
  const x0 = Math.min(...xs), x1 = Math.max(...xs), y1 = niceMax(ys, 1), W = 600;
  const px = (x) => ((x - x0) / Math.max(1, x1 - x0) * W).toFixed(1), py = (y) => (h - (y / y1) * (h - 8)).toFixed(1);
  return `<svg class="linechart" viewBox="0 0 ${W} ${h}" preserveAspectRatio="none">
    ${[0.25, 0.5, 0.75].map((f) => `<line x1="0" x2="${W}" y1="${(h * f).toFixed(1)}" y2="${(h * f).toFixed(1)}" stroke="var(--color-neutral-300)" stroke-width="0.5"/>`).join('')}
    ${series.map((s) => `<polyline points="${s.data.map((p) => px(p[0]) + ',' + py(p[1])).join(' ')}" fill="none" stroke="${s.color || 'var(--color-text)'}" stroke-width="2" vector-effect="non-scaling-stroke"${s.dash ? ' stroke-dasharray="5 4"' : ''}><title>${esc(s.label)}</title></polyline>`).join('')}
  </svg><div class="axis"><span>${esc(fmtX(x0))}</span><span>max ${esc(fmtY(y1))}</span><span>${esc(fmtX(x1))}</span></div>
  <div class="legend mt-6">${series.map((s) => `<span><i style="background:${s.color || 'var(--color-text)'};height:3px"></i>${esc(s.label)}</span>`).join('')}</div>`;
}
const loading = (msg = 'Waiting for the collector…') => `<div class="empty"><span class="row">${icon('loader-circle', 'spin')} ${esc(msg)}</span></div>`;
const emptyState = (ic, title, text, extra = '') => `<div class="empty big">${icon(ic, 'xl')}<div class="h800 fs-15 c-text">${esc(title)}</div><div>${esc(text)}</div>${extra}</div>`;

/* ------------------------------------------------------------------ data */

async function get(url) {
  const r = await fetch(url, { cache: 'no-store', credentials: 'same-origin' });
  if (r.status === 401) { location.href = '/login'; throw new Error('login required'); }
  if (r.status === 428) { location.href = '/privacy'; throw new Error('privacy notice acceptance required'); }
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || 'HTTP ' + r.status);
  return r.json();
}
async function post(url, body) {
  const r = await fetch(url, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-Strata': '1' }, body: JSON.stringify(body || {}) });
  if (r.status === 401) { location.href = '/login'; throw new Error('login required'); }
  const j = await r.json().catch(() => ({}));
  if (r.status === 428) { location.href = '/privacy'; throw new Error('privacy notice acceptance required'); }
  if (!r.ok) throw new Error(j.error || 'HTTP ' + r.status);
  return j;
}
// Activity telemetry deliberately records view names and semantic action IDs only; it never records form values,
// keystrokes, clipboard payloads, editor contents, passwords or one-time codes.
let auditEvents = [], auditTimer = 0, auditCurrentView = '', auditViewAt = 0;
function auditQueueEvent(kind, target, seconds) {
  const clean = String(target || '').replace(/[^A-Za-z0-9:_./-]/g, '').slice(0, 120);
  if (!clean) return;
  auditEvents.push({ kind, target: clean, ...(seconds == null ? {} : { seconds }) });
  if (auditEvents.length >= 40) auditFlush();
  else if (!auditTimer) auditTimer = setTimeout(() => { auditTimer = 0; auditFlush(); }, 900);
}
function auditFlush(keepalive = false) {
  clearTimeout(auditTimer); auditTimer = 0;
  if (!auditEvents.length) return;
  const batch = auditEvents.splice(0, 100);
  fetch('/api/audit/events', { method: 'POST', credentials: 'same-origin', keepalive,
    headers: { 'Content-Type': 'application/json', 'X-Strata': '1' }, body: JSON.stringify({ events: batch })
  }).catch(() => { /* temporary offline events are not persisted in browser storage */ });
}
function auditView(view) {
  if (!view || view === auditCurrentView) return;
  if (auditCurrentView && auditViewAt) auditQueueEvent('view-duration', auditCurrentView, Math.round((Date.now() - auditViewAt) / 1000));
  auditCurrentView = view; auditViewAt = Date.now();
  auditQueueEvent('view', view);
}
document.addEventListener('click', (e) => {
  if (!e.target.closest('#app, #overlay')) return;
  const el = e.target.closest('[data-act]');
  const target = el ? 'action:' + el.dataset.act : e.target.closest('[id]') ? 'element:' + e.target.closest('[id]').id : 'element:' + e.target.tagName.toLowerCase();
  auditQueueEvent('click', target);
}, true);
document.addEventListener('change', (e) => {
  if (!e.target.closest('#app, #overlay')) return;
  const el = e.target, key = el.dataset.change || el.id || el.name || el.tagName.toLowerCase();
  auditQueueEvent('change', 'field:' + key);
}, true);
document.addEventListener('DOMContentLoaded', () => {
  const overlay = $('#overlay');
  if (!overlay || !window.MutationObserver) return;
  let wasOpen = !!overlay.firstElementChild;
  new MutationObserver(() => {
    const open = !!overlay.firstElementChild;
    if (open !== wasOpen) { auditQueueEvent('overlay', open ? 'overlay:open' : 'overlay:close'); wasOpen = open; }
  }).observe(overlay, { childList: true, subtree: false });
});
window.addEventListener('beforeunload', () => auditFlush(true));
const hidden = () => S.hiddenPause && document.visibilityState === 'hidden';
async function pollInsights() {
  try { D.insights = await get(`/api/insights?range=${statsRange()}${S.nobots ? '&nobots=1' : ''}`); render(); } catch { /* ignore */ }
}
async function pollCompression() {
  try { D.comp = await get(`/api/compression?range=${statsRange()}`); render(); } catch { /* ignore */ }
}
let online = true;
async function pollLive() {
  if (!S.paused && !hidden()) {
    const hadMe = !!D.me;
    if (!D.me || Date.now() - (D.meAt || 0) > 30000) { // permissions rarely change; the server enforces them anyway
      try { D.me = await get('/api/me'); D.meAt = Date.now(); } catch { /* protected views will redirect expired sessions */ }
    }
    const analytics = !D.me || D.me.role === 'root' || D.me.role === 'admin' ||
      (D.me.capabilities || []).includes('*') || (D.me.capabilities || []).includes('analytics.read');
    if (analytics) {
      try { D.live = await get('/api/live'); online = true; } catch (e) { online = !/access|permission/i.test(e.message); }
    } else { D.live = null; online = true; }
    if (D.me) {
      const accessible = visibleNav().flatMap(([, ids]) => ids);
      if (!accessible.includes(S.view)) { S.view = accessible[0] || 'settings'; persist(); auditView(S.view); }
    }
    renderNav();
    render(!hadMe && !!D.me && S.view === 'settings');
  }
  setTimeout(pollLive, S.rate);
}
let statsSeq = 0;
async function pollStats() {
  if (D.me && D.me.role !== 'root' && D.me.role !== 'admin' && !(D.me.capabilities || []).includes('analytics.read') && !(D.me.capabilities || []).includes('*')) return;
  const seq = ++statsSeq;
  try {
    const s = await get(`/api/stats?range=${statsRange()}${S.nobots ? '&nobots=1' : ''}`);
    if (seq === statsSeq) { D.stats = s; render(); }
  } catch { /* shown via the connection dot */ }
}
function reqParams(extra = {}) {
  const p = { limit: 250, scope: S.scope, q: S.q, ip: S.ipFilter };
  Object.entries(S.rf).forEach(([k, v]) => { if (v) p[k] = v; });
  Object.assign(p, extra);
  return Object.entries(p).filter(([, v]) => v !== '' && v != null).map(([k, v]) => k + '=' + enc(v)).join('&');
}
let reqSeq = 0;
async function pollRequests(force) {
  if (D.me && D.me.role !== 'root' && D.me.role !== 'admin' && !(D.me.capabilities || []).includes('analytics.read') && !(D.me.capabilities || []).includes('*')) return;
  if (S.view !== 'requests' || ((S.paused || hidden()) && !force)) return;
  if (D.req && D.req.older && !force) return; // the user is paging back: keep their rows
  const seq = ++reqSeq;
  try {
    const r = await get('/api/requests?' + reqParams());
    if (seq !== reqSeq) return;
    const prev = D.maxId;
    D.fresh = new Set(prev ? r.rows.filter((x) => x.id > prev).map((x) => x.id) : []);
    D.maxId = r.rows.reduce((m, x) => Math.max(m, x.id), prev);
    D.req = r;
    render();
    D.fresh = new Set();
  } catch { /* ignore */ }
}
async function loadOlder() {
  if (!D.req || !D.req.cursor) return;
  try {
    const r = await get('/api/requests?' + reqParams({ before: D.req.cursor, limit: 500 }));
    D.req = { rows: D.req.rows.concat(r.rows), more: r.more, cursor: r.cursor, older: true };
    render(true);
  } catch (e) { note(e.message, { err: true }); }
}
async function pollHistory() {
  try { D.hist = await get('/api/history'); render(); } catch { /* ignore */ }
}
async function pollEdge(force) {
  try { D.edge = await get('/api/edge' + (force ? '?force=1' : '')); render(); } catch { /* ignore */ }
}
async function loadIp(ip) {
  D.ip = null;
  try { const r = await get('/api/ip?ip=' + enc(ip)); if (S.selRow && S.selRow.ip === ip) { D.ip = r; render(); } } catch { /* ignore */ }
}
function refreshForView() {
  if (S.view === 'requests') pollRequests(true);
  if (S.view === 'history') pollHistory();
  if (S.view === 'edge' && !D.edge) pollEdge();
  if (VIEW_REFRESH[S.view]) VIEW_REFRESH[S.view]();
  if (S.view === 'insights') pollInsights();
  if (S.view === 'compression') pollCompression();
}

/* ------------------------------------------------------------------ chrome */

function navItem(id, badge, alert) {
  return `<button class="nav-item ${S.view === id ? 'on' : ''}" data-act="go" data-arg="${id}" data-menu="navitem" data-arg2="${id}" title="${esc(VIEWS[id][0])}"${S.view === id ? ' aria-current="page"' : ''}>
    <span class="mark"></span>${icon(VIEWS[id][2])}<span>${VIEWS[id][0]}</span><span class="badge ${alert ? 'alert' : ''}">${esc(badge ?? '')}</span></button>`;
}
// a view shows when the account holds any of its capabilities (the server enforces each request separately)
const VIEW_NEEDS = { summary: ['analytics.read'], requests: ['analytics.visitors'], logs: ['logs.runtime', 'logs.access', 'audit.read'],
  content: ['analytics.read'], visitors: ['analytics.visitors'], insights: ['analytics.read'], tunnel: ['analytics.read'],
  origins: ['analytics.read'], files: ['files.read'], upload: ['files.upload'], analyze: ['files.analyze'],
  serving: ['serving.read'], blacklist: ['serving.blacklist'], links: ['serving.read', 'serving.links'], alerts: ['alerts.read'],
  network: ['network.read'], media: ['media.read'], compression: ['analytics.read'], security: ['analytics.read'],
  latency: ['analytics.read'], history: ['analytics.read'], edge: ['analytics.read'], system: ['system.read'],
  accounts: ['accounts.manage'], ide: ['code.read'], office: ['office.view'] };
function canSeeView(v) {
  const caps = D.me && Array.isArray(D.me.capabilities) ? new Set(D.me.capabilities) : null;
  const need = VIEW_NEEDS[v];
  return !caps || !need || need.some((c) => caps.has(c));
}
function visibleNav() {
  const hiddenV = new Set(S.navHidden || []);
  const canSee = canSeeView;
  const groups = [];
  if ((S.navPinned || []).length) groups.push(['Pinned', S.navPinned.filter((v) => VIEWS[v] && canSee(v))]);
  for (const [title, ids, flag] of NAV_GROUPS) {
    const shown = ids.filter((v) => !hiddenV.has(v) && !(S.navPinned || []).includes(v) && canSee(v));
    // a collapsed group keeps its header (click to expand) as long as it has anything to show
    groups.push([title, flag === 'deep' && !S.deep && shown.length ? [] : shown, flag, shown.length]);
  }
  groups.push(['', ['settings']]);
  return groups.filter((g) => g[1].length || g[3]);
}
function renderNav() {
  const L = D.live, st = D.stats, t = L?.tunnel;
  const originsDown = (L?.origins || []).filter((o) => o.ok === false).length + (L?.storage || []).filter((s) => !s.ok).length;
  const b = {
    requests: L ? fmt.n(L.win5.reqs) : '',
    content: st ? fmt.n(st.totals.paths) : '',
    visitors: st ? fmt.n(st.totals.uniq) : '',
    tunnel: t?.up ? `${t.ha}/4` : 'down',
    origins: L ? (originsDown ? originsDown + ' down' : 'ok') : '',
    security: st ? fmt.n(st.scanners.length) : '',
    latency: st ? fmt.ms(st.totals.p95) : '',
    edge: D.edge && !D.edge.configured ? 'setup' : '',
    compression: L?.compress?.running ? 'running' : st && st.totals.reqs ? fmt.pct(share(st.totals.encoded, st.totals.reqs)) : '',
  };
  const alert = { tunnel: t && (!t.up || t.ha < 4), origins: originsDown > 0, security: st && st.scanners.length > 0 };
  for (const f of NAV_BADGES) { try { const x = f(); Object.assign(b, x.badges || {}); Object.assign(alert, x.alerts || {}); } catch { /* module not ready */ } }
  const navEl = $('#nav');
  const navTop = navEl ? navEl.scrollTop : 0;
  const head = (title, flag) => !title ? '' : flag === 'deep'
    ? `<button class="cap nav-h nav-toggle" data-act="deep" aria-expanded="${!!S.deep}">${esc(title)}${icon(S.deep ? 'chevron-down' : 'chevron-right', 'sm')}</button>`
    : `<div class="cap nav-h">${esc(title)}</div>`;
  patch(navEl, visibleNav().map(([title, ids, flag], gi) => `<div class="${gi ? 'nav-deep' : ''}">${head(title, flag)}` +
    ids.map((id) => navItem(id, b[id], alert[id])).join('') + '</div>').join(''));
  if (navEl && navEl.scrollTop !== navTop) navEl.scrollTop = navTop;

  const c = $('#conn');
  const connCls = 'conn' + (online ? (S.paused || hidden() ? ' paused' : '') : ' bad');
  if (c.className !== connCls) c.className = connCls;
  patch(c, `<i></i><span>${online ? (S.paused ? 'paused' : hidden() ? 'idle (tab hidden)' : 'live · ' + esc(location.host)) : 'collector unreachable'}</span>`);
  const who = D.me?.user || L?.user;
  patch($('#who'), who ? `<button class="who-me" data-act="go" data-arg="settings" title="Your profile and preferences">${avatar(who, D.me?.user === who ? D.me.avatar : '', 'sm', !String(who).startsWith('api:'))}<span class="ell">signed in as <b>${esc(who)}</b></span></button><button class="link" data-act="logout">Sign out</button>` : '');
}
function renderHeader() {
  const [title, sub, ic] = VIEWS[S.view];
  patch($('#title'), icon(ic) + esc(title));
  if ($('#sub').textContent !== sub) $('#sub').textContent = sub;
  patch($('#ranges'), RANGES.map(([k, l]) => `<button class="${S.range === k ? 'on' : ''}" data-act="range" data-arg="${k}" aria-pressed="${S.range === k}">${l}</button>`).join(''));
  $('#bots').classList.toggle('ink', S.nobots);
  const botsLbl = S.nobots ? 'Bots hidden' : 'Bots';
  if ($('#bots').querySelector('span').textContent !== botsLbl) $('#bots').querySelector('span').textContent = botsLbl;
  patch($('#pause'), icon(S.paused ? 'play' : 'pause'));
  $('#pause').classList.toggle('on', S.paused);
  document.title = title + ' · Strata · ' + (INST.name || location.host);
}
function vital(label, unit, val, bar, sub, menu, ic) {
  return `<div class="vital" data-menu="vital" data-arg="${esc(menu || '')}">
    <div class="cap">${ic ? icon(ic, 'sm') : ''}${esc(label)}</div><div class="small dim ell">${esc(unit)}</div>
    <div class="val">${val}</div>${bar}<div class="small dim ell">${sub}</div></div>`;
}
function splitUnit(s) { const i = s.lastIndexOf(' '); return i < 0 ? esc(s) : `${esc(s.slice(0, i))}<small>${esc(s.slice(i + 1))}</small>`; }
// the vitals strip is configurable (Settings › Vitals): each tile is one entry here
const VITALS = {
  reqs: ['Requests', (L, st) => { const w = L.win, rMax = niceMax(L.series.reqs, 1); return vital('Requests', 'req/s · last 60 s', esc(fmt.n1(w.rps)), segs(share(w.rps, rMax), 18, 101), `5 min ${fmt.n(L.win5.reqs)} · peak ${fmt.n(Math.max(0, ...L.series.reqs))}/s`, 'reqs', 'activity'); }],
  bytes: ['Bandwidth', (L) => { const t = L.tunnel || {}, bMax = Math.max(1, ...L.series.bytes); return vital('Bandwidth', 'served by Caddy · 60 s', splitUnit(fmt.rate(L.win.bps)), segs(share(L.win.bps, bMax), 18, 101), `tunnel ↑ ${esc(fmt.rate(t.tx_bps))} · ↓ ${esc(fmt.rate(t.rx_bps))}`, 'bytes', 'chart-area'); }],
  uniq: ['Visitors', (L, st) => vital('Visitors', 'unique IPs · 5 min', esc(fmt.n(L.win5.uniq)), segs(Math.min(100, L.win5.uniq * 5), 18, 101), st ? `${esc(rangeLabel())}: ${fmt.n(st.uniq)} · bots ${fmt.pct(share(st.bots, st.reqs))}` : '', 'uniq', 'users')],
  errors: ['Errors', (L, st) => vital('Errors', '4xx + 5xx · % · 60 s · excl. suspicious', esc(fmt.n1(L.win.err_pct)), segs(L.win.err_pct, 18, 25), st ? `${fmt.n(st.e4)} 4xx · ${fmt.n(st.e5)} 5xx · ${fmt.n(st.sus)} suspicious excluded` : '', 'errors', 'circle-alert')],
  latency: ['Latency', (L) => { const nas = (L.storage || [])[0]; return vital('Latency', 'p95 · 5 min · origin', splitUnit(fmt.ms(L.win5.p95)), segs(L.win5.p95 / 10, 18, 50), `p50 ${esc(fmt.ms(L.win5.p50))} · NAS ${esc(nas ? fmt.ms(nas.ms) : '—')}`, 'latency', 'timer'); }],
  tunnel: ['Tunnel', (L) => { const t = L.tunnel || {}, conns = (t.conns || []).map((c) => String(c.colo || '?').slice(0, 3).toUpperCase()); return vital('Tunnel', t.up ? `${t.ha}/4 edges · RTT` : 'cloudflared', t.up ? splitUnit(fmt.ms(t.rtt)) : '<span class="hot">down</span>', segs(share(t.ha || 0, 4), 18, 101, '', !t.up || t.ha < 4), t.up ? esc(conns.join(' · ')) : esc(t.error || ''), 'tunnel', 'cable'); }],
  cpu: ['Host CPU', (L) => { const h = L.host || {}; return vital('Host CPU', (h.name || 'this machine') + ' · ' + (h.cores || '?') + ' cores', splitUnit(fmt.pct(h.cpu)), segs(h.cpu || 0, 18, 85), 'Caddy ' + fmt.pct((L.caddy || {}).cpu) + ' · tunnel ' + fmt.pct((L.tunnel || {}).cpu), 'cpu', 'cpu'); }],
  memory: ['Memory', (L) => { const h = L.host || {}; const p = share(h.mem_used, h.mem_total); return vital('Memory', 'host RAM in use', splitUnit(fmt.pct(p)), segs(p, 18, 90), esc(fmt.bytes(h.mem_used, 0) + ' of ' + fmt.bytes(h.mem_total, 0)), 'memory', 'memory-stick'); }],
  storage: ['Storage', (L) => { const s = (L.storage || [])[0] || {}; const p = s.total ? share(s.used, s.total) : 0; return vital('Storage', s.path || 'first drive', s.ok ? splitUnit(fmt.bytes(s.free, 0)) : '<span class="hot">offline</span>', segs(p, 18, 90), s.ok ? fmt.pct(p) + ' used · ' + fmt.ms(s.ms) : esc(s.error || ''), 'storage', 'hard-drive'); }],
  alerts: ['Alerts', (L) => { const a = L.alerts || {}, n = (a.critical || 0) + (a.warning || 0); return vital('Alerts', 'open · warning and above', n ? `<span class="hot">${n}</span>` : '0', segs(Math.min(100, n * 20), 18, 1), `${fmt.n(a.critical || 0)} critical · ${fmt.n(a.info || 0)} info · ${fmt.n(L.blacklist)} blacklisted`, 'alerts', 'bell'); }],
  uploads: ['Uploads', () => { const act = U.filter((u) => ['queued', 'uploading', 'finishing'].includes(u.status)); const tot = act.reduce((a, u) => a + u.size, 0), sent = act.reduce((a, u) => a + (typeof sentOf === 'function' ? sentOf(u) : 0), 0); return vital('Uploads', 'this browser', act.length ? esc(fmt.pct(share(sent, tot))) : '—', segs(share(sent, tot || 1), 18, 101), act.length ? fmt.n(act.length) + ' active · ' + fmt.bytes(tot) : 'idle', 'uploads', 'upload'); }],
  edge: ['Edge cache', () => { const e = D.edge; if (!e || !e.ok) return vital('Edge cache', 'Cloudflare · 24 h', '—', segs(0, 18, 101), e && !e.configured ? 'token needed (Edge view)' : 'loading…', 'edge', 'cloud'); const hrs = e.hours || []; const r = hrs.reduce((a, x) => a + (x.sum.requests || 0), 0), c = hrs.reduce((a, x) => a + (x.sum.cachedRequests || 0), 0); return vital('Edge cache', 'Cloudflare hit ratio · 24 h', splitUnit(fmt.pct(share(c, r))), segs(share(c, r), 18, 101), fmt.n(r) + ' edge requests', 'edge', 'cloud'); }],
};
function renderVitals() {
  const L = D.live, st = D.stats?.totals;
  const list = (S.vitals || []).filter((k) => VITALS[k]).slice(0, 8);
  const el = $('#vitals');
  const app = $('#app');
  if (app && app.dataset.mode !== (workView() ? 'work' : 'monitor')) app.dataset.mode = workView() ? 'work' : 'monitor';
  el.style.setProperty('--vcols', String(Math.max(1, list.length)));
  const show = list.length && (!workView() || S.vitalsAll) && canSeeView('summary');
  el.style.display = show ? '' : 'none';
  if (!show) return;
  if (!L) {
    patch(el, list.map((k) => vital(VITALS[k][0], '', '—', segs(0, 18, 101), '')).join(''));
    return;
  }
  patch(el, list.map((k) => { try { return VITALS[k][1](L, st); } catch { return vital(VITALS[k][0], '', '—', segs(0, 18, 101), ''); } }).join(''));
}
function renderFooter() {
  const L = D.live;
  const c = L?.caddy || {}, t = L?.tunnel || {}, db = L?.db || {};
  patch($('#foot'), `
    <span class="row">${icon('database', 'sm')}${fmt.n(db.rows)} requests stored · ${esc(fmt.bytes(db.size))} · since ${esc(fmt.dt(db.first))}</span>
    <span>Caddy ${esc(c.version || '')} ${c.up ? '· up ' + esc(fmt.dur(c.uptime)) : '<b class="hot">unreachable</b>'}</span>
    <span>cloudflared ${esc(t.version || '')} ${t.up ? '· up ' + esc(fmt.dur(t.uptime)) : '<b class="hot">unreachable</b>'}</span>
    <div class="fill"></div>
    ${(INST.siblings || []).map((s) => `<button class="link" data-act="openSibling" data-arg="${esc(s.url)}" title="Open the ${esc(s.name)} dashboard">${esc(s.name)} ↗</button>`).join('')}
    <button class="link" data-act="cycleRate" data-menu="rate" title="Click to change the refresh rate, right-click to pick one">${S.paused ? 'paused · click to resume' : 'every ' + (S.rate < 1000 ? S.rate + ' ms' : S.rate / 1000 + ' s')}</button>
    <span class="clock">${fmt.time(Date.now() / 1000)}</span>`);
}

/* ------------------------------------------------------------------ building blocks */

const TABLES = {}; // key -> {labels, rows} of the last render (Copy / Export as CSV from the table's menu)
function table(key, labels, rows, opts = {}) {
  TABLES[key] = { labels, rows };
  const cols = labels.map((l, i) => (S.widths[key + ':' + i] ?? l.w) + 'px').join(' ') + ' 1fr';
  const head = `<div class="thead" style="grid-template-columns:${cols}">` + labels.map((l, i) =>
    `<div class="${l.a === 'r' ? 'r' : ''}"><button class="${l.sort && opts.sort === l.sort ? 'on' : ''}" ${l.sort ? `data-act="sort" data-arg="${key}:${l.sort}"` : 'tabindex="-1"'}>${l.h || esc(l.t)}${l.sort && opts.sort === l.sort ? icon(opts.desc === false ? 'chevron-up' : 'chevron-down', 'sm') : ''}</button>` +
    `<span class="grip" data-resize="${key}:${i}:${S.widths[key + ':' + i] ?? l.w}" title="Drag to resize · double-click to reset"></span></div>`).join('') + '<span></span></div>';
  const body = rows.length
    ? rows.map((r) => `<div class="trow ${r.cls || ''}" style="grid-template-columns:${cols}" ${r.attrs || ''}>` +
        r.cells.map((c) => `<span class="${c.c || ''}"${c.title != null ? ` title="${esc(c.title)}"` : ''}>${c.h ?? esc(c.t)}</span>`).join('') + '<span></span></div>').join('')
    : `<div class="empty">${esc(opts.empty || 'Nothing recorded in this range yet.')}</div>`;
  return `<div class="twrap ${S.zebra ? 'zebra' : ''}" data-scroll="${key}" data-menu="table" data-arg="${key}">${head}${body}</div>`;
}
function tableCsv(key) {
  const t = TABLES[key];
  if (!t) return '';
  const strip = (h) => { const d = document.createElement('div'); d.innerHTML = h; return d.textContent; };
  const q = (v) => { v = String(v ?? ''); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
  return [t.labels.map((l) => q(l.t)).join(',')].concat(t.rows.map((r) => r.cells.map((c) => q(c.title ?? c.t ?? (c.h ? strip(c.h) : ''))).join(','))).join('\n');
}
function saveFile(name, text, type = 'text/csv') {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}
function gauge(k, v, pct, warn = 80, hot) {
  const isHot = hot ?? pct >= warn;
  return `<div class="gauge"><div class="row"><span class="dim ell">${esc(k)}</span><b class="${isHot ? 'hot' : ''}">${esc(v)}</b></div>${segs(pct, 16, warn, 's7', isHot)}</div>`;
}
function auxPanel(a) {
  const log = (a.log || []).map((l) => `<div class="logline"><span title="${esc(l.a)}">${esc(l.a)}</span><span>${esc(l.b)}</span></div>`).join('');
  return `<aside class="aside">
    <div class="pad"><div class="cap red">${esc(a.kicker)}</div><h5>${esc(a.title)}</h5></div>
    ${a.svg || sparkSvg(a.series, { max: a.max })}
    <div class="px-16 pt-10 pb-4 flex-none">${(a.gauges || []).join('')}</div>
    <div class="bt-div px-16 pt-10 pb-6 flex-none"><div class="cap">${esc(a.logLabel)}</div></div>
    <div class="loglines">${log || '<div class="logline"><span>—</span><span></span></div>'}</div>
  </aside>`;
}
function tblView(o) {
  const tabs = o.tabs ? `<div class="tbar">${o.tabs.map((t) => `<button class="pill ${t.on ? 'on' : ''}" data-act="${t.act}" data-arg="${esc(t.arg)}">${t.icon ? icon(t.icon, 'sm') : ''}${esc(t.label)}</button>`).join('')}<div class="fill"></div><button class="pill" data-act="exportTable" data-arg="${esc(o.key)}" title="Download this table as CSV">${icon('download', 'sm')}CSV</button></div>` : '';
  return `<div class="split" style="grid-template-columns:1fr 300px">
    <section class="aside">
      <div class="ph ph-pad"><h5>${esc(o.title)}</h5><span class="small dim ell">${esc(o.note || '')}</span></div>
      <div class="bt-div"></div>${tabs}
      ${table(o.key, o.labels, o.rows, o)}
    </section>
    ${auxPanel(o.aux)}
  </div>`;
}
const cell = (t, c, title) => ({ t, c, title });
const hcell = (h, c, title) => ({ h, c, title });
const kindTag = (kind) => (kind === 'bot' ? 'dim' : '');
function statusCell(s) { return cell(s, s >= 500 ? 'hot h800' : s >= 400 ? 'hot' : '', ''); }
function statsReady() { return !!D.stats && D.stats.range === statsRange(); }
const engineNote = (o) => (o && o.engine === 'rollup' ? ' · aggregated' : '');

/* ------------------------------------------------------------------ views */

function trafficChart() {
  const live = S.range === 'live';
  const src = live ? D.live?.series : statsReady() ? D.stats.series : null;
  if (!src || !src.reqs.length) return '<div class="chart"></div>';
  const reqs = src.reqs, bytes = src.bytes, errs = src.e4.map((v, i) => v + src.e5[i]);
  const rMax = niceMax(reqs, live ? 2 : 5), bMax = Math.max(1, ...bytes);
  let hover = '';
  if (S.hover && S.hover.chart === 'traffic') {
    const x = S.hover.x, i = Math.max(0, Math.min(reqs.length - 1, Math.round(x * (reqs.length - 1))));
    const t = src.t0 + i * src.step;
    const side = x > 0.6 ? `right:${((1 - x) * 100 + 1).toFixed(2)}%` : `left:${(x * 100 + 1).toFixed(2)}%`;
    hover = `<div class="cross" style="left:${(x * 100).toFixed(2)}%"></div>
      <div class="tip" style="${side}">${esc(live ? fmt.time(t) : fmt.dt(t) + ' +' + bucketLabel(src.step))}<br>
      ${fmt.n(reqs[i])} requests · ${esc(fmt.bytes(bytes[i]))}<br>${fmt.n(errs[i])} errors${src.uniq && src.uniq[i] != null ? ' · ' + fmt.n(src.uniq[i]) + ' visitors' : ''}</div>`;
  }
  return `<div class="chart" data-hover="traffic">
    <svg viewBox="0 0 320 128" preserveAspectRatio="none">
      <line x1="0" y1="32" x2="320" y2="32" stroke="var(--color-neutral-300)" stroke-width="0.5"></line>
      <line x1="0" y1="64" x2="320" y2="64" stroke="var(--color-neutral-300)" stroke-width="0.5"></line>
      <line x1="0" y1="96" x2="320" y2="96" stroke="var(--color-neutral-300)" stroke-width="0.5"></line>
      <polygon points="${areaPts(bytes, 320, 128, bMax)}" fill="color-mix(in srgb, var(--color-text) 12%, transparent)"></polygon>
      <polyline points="${pts(reqs, 320, 128, rMax)}" fill="none" stroke="var(--color-text)" stroke-width="1.5" vector-effect="non-scaling-stroke"></polyline>
      <polyline points="${pts(errs, 320, 128, rMax)}" fill="none" stroke="var(--color-accent)" stroke-width="1.5" vector-effect="non-scaling-stroke"></polyline>
    </svg>
    <div class="ymax">${fmt.n(rMax)} req${live ? '/s' : ' / ' + bucketLabel(src.step)} · ${esc(fmt.bytes(bMax))} peak</div>${hover}
  </div>`;
}
function bigGraph(title, sub, val, arr, readouts, opts = {}) {
  return `<section class="big" data-menu="graph" data-arg="${esc(title)}">
    <div class="d-flex between items-baseline gap-8"><h5>${esc(title)}</h5>
      <span class="h800 ${opts.hot ? 'hot' : ''} fs-14 nowrap">${esc(val)}</span></div>
    <div class="small dim ell mx-0 mt-1 mb-6">${esc(sub)}</div>
    ${sparkSvg(arr, { w: 240, h: 64, cls: '', max: opts.max, stroke: opts.hot ? 'var(--color-accent)' : 'var(--color-text)' })}
    <div class="readouts">${readouts.map(([k, v]) => `<div><div class="cap">${esc(k)}</div><div>${esc(v)}</div></div>`).join('')}</div>
  </section>`;
}
function vSummary() {
  const L = D.live, st = statsReady() ? D.stats : null, live = S.range === 'live';
  const src = live ? L?.series : st?.series;
  const total = src ? src.reqs.reduce((a, b) => a + b, 0) : 0;
  const bytes = src ? src.bytes.reduce((a, b) => a + b, 0) : 0;
  const colos = (st?.colos || []).filter((c) => c.k);
  const cMax = Math.max(1, ...colos.map((c) => c.c));
  const strip = colos.slice(0, 16).map((c) => `<div class="chip" data-menu="colo" data-arg="${esc(c.k)}" title="${esc(coloName(c.k))} · ${fmt.n(c.c)} requests">
      <b>${esc(c.k)}</b><span class="dim ell">${esc(coloName(c.k))}</span>${segs(share(c.c, cMax), 8, 101, 's5')}</div>`).join('');
  const paths = (st?.paths || []).slice(0, 40);
  const cols = 'grid-template-columns:1fr 50px 64px';
  const top = paths.map((p) => `<div class="mini-r" style="${cols}" data-act="filterPath" data-arg="${esc(p.k)}" data-menu="path" data-arg2="${esc(p.host)}">
      <span class="ell" title="${esc(p.host + p.k)}">${esc(p.k)}</span><span class="r fw-600">${fmt.n(p.c)}</span><span class="r dim">${esc(fmt.bytes(p.b))}</span></div>`).join('');
  const H = L?.hist || {}, c = L?.caddy || {}, t = L?.tunnel || {}, h = L?.host || {}, nas = (L?.storage || [])[0] || {};
  const axis = live ? ['−5 min', '1 s buckets', 'now'] : src ? [fmt.dt(src.t0), bucketLabel(src.step) + ' buckets', 'now'] : ['', '', ''];
  return `<div class="col-fill">
    <div class="grid2 cols-135 bb-div fill">
      <section class="panel" data-menu="traffic">
        <div class="ph"><h5>${icon('activity')}Traffic</h5><span class="small dim ell">${live ? 'live · right-click for options' : esc(rangeLabel()) + engineNote(st)}</span>
          <span class="h800 fs-15 nowrap">${fmt.n(total)} req · ${esc(fmt.bytes(bytes))}</span></div>
        <div class="legend"><span><i></i>Requests</span><span><i class="bg-accent"></i>Errors</span>
          <span><i class="h-8 bg-faint"></i>Bandwidth (scaled)</span></div>
        ${trafficChart()}
        <div class="axis">${axis.map((a) => `<span>${esc(a)}</span>`).join('')}</div>
        <div class="strip">${strip || '<div class="rest">no edge traffic recorded yet</div>'}
          <div class="rest">${colos.length ? 'Cloudflare edge locations · ' + esc(rangeLabel()) : ''}</div></div>
      </section>
      <section class="panel">
        <div class="ph"><h5>${icon('file-text')}Top files</h5><span class="small dim">${st ? fmt.n(st.totals.paths) + ' paths · ' + esc(rangeLabel()) : ''}</span></div>
        <div class="mini-h" style="${cols}"><span>Path</span><span class="r">Hits</span><span class="r">Sent</span></div>
        <div class="scroll" data-scroll="top">${top || loading(st ? 'No successful requests in this range yet.' : undefined)}</div>
      </section>
    </div>
    <div class="bigs">
      ${bigGraph('Caddy', `origin process · % of ${h.cores || '?'} cores`, fmt.pct(c.cpu), H.caddy_cpu,
        [['Memory', fmt.bytes(c.rss)], ['Goroutines', fmt.n(c.goroutines)], ['In flight', fmt.n(c.in_flight)]], { hot: !c.up })}
      ${bigGraph('Tunnel', 'cloudflared egress · all hostnames', fmt.rate(t.tx_bps), H.tunnel_tx,
        [['RTT', fmt.ms(t.rtt)], ['Edges', t.up ? t.ha + ' / 4' : 'down'], ['CPU', fmt.pct(t.cpu)]], { hot: !t.up || t.ha < 4 })}
      ${bigGraph('Storage', 'NAS stat() latency · media share', fmt.ms(nas.ms), H.nas_ms,
        [['Used', nas.total ? fmt.pct(share(nas.used, nas.total)) : '—'], ['Free', fmt.bytes(nas.free)], ['State', nas.ok ? 'online' : nas.error || '—']], { hot: nas.ok === false })}
      ${bigGraph('Host', (h.name || 'this machine') + ' · CPU', fmt.pct(h.cpu), H.host_cpu,
        [['Memory', h.mem_total ? fmt.bytes(h.mem_used, 0) + ' / ' + fmt.bytes(h.mem_total, 0) : '—'], ['Cores', fmt.n(h.cores)], ['Uptime', fmt.dur(h.uptime)]], { max: 100 })}
    </div>
  </div>`;
}

const REQ_LABELS = [
  { t: 'Time', w: 66 }, { t: 'Status', w: 48 }, { t: 'Host', w: 150 }, { t: 'Path', w: 300 }, { t: 'Size', w: 72, a: 'r' },
  { t: 'Took', w: 70, a: 'r' }, { t: 'CC', w: 34 }, { t: 'Client', w: 128 }, { t: 'Agent', w: 130 },
];
const REQ_DEEP = [{ t: 'Edge', w: 44 }, { t: 'OS', w: 70 }, { t: 'Type', w: 120 }, { t: 'Enc', w: 50 }, { t: 'Saved', w: 70, a: 'r' }, { t: 'Referrer', w: 140 }, { t: 'Proto', w: 66 }, { t: 'Method', w: 60 }, { t: 'Flag', w: 80 }];
function reqFilterBar() {
  const sel = (id, opts, cur, title) => `<select id="${id}" class="input" title="${esc(title)}">${opts.map(([v, l]) => `<option value="${esc(v)}" ${String(cur) === String(v) ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select>`;
  const hosts = (D.stats?.hosts || []).map((h) => [h.k, h.k]);
  const active = Object.values(S.rf).filter(Boolean).length;
  return `<div class="tbar px-18 py-6">${icon('funnel', 'sm')}
    ${sel('rf_status', [['', 'any status'], ['2xx', '2xx ok'], ['3xx', '3xx'], ['4xx', '4xx'], ['5xx', '5xx'], ['404', '404'], ['403', '403'], ['429', '429']], S.rf.status, 'Status')}
    ${sel('rf_method', [['', 'any method'], ['GET', 'GET'], ['HEAD', 'HEAD'], ['POST', 'POST'], ['PUT', 'PUT'], ['OPTIONS', 'OPTIONS'], ['DELETE', 'DELETE']], S.rf.method, 'Method')}
    ${sel('rf_host', [['', 'any host']].concat(hosts), S.rf.host, 'Host')}
    ${sel('rf_kind', [['', 'any client'], ['browser', 'People'], ['player', 'Media players'], ['embed', 'Link previews'], ['bot', 'Bots & tools']], S.rf.kind, 'Client kind')}
    ${sel('rf_since', [['', 'any time'], ['300', 'last 5 min'], ['3600', 'last hour'], ['86400', 'last 24 h'], ['604800', 'last 7 days']], S.rf.since, 'Time window')}
    <input id="rf_country" class="input w-52" placeholder="CC" value="${esc(S.rf.country)}" title="Country code" maxlength="2">
    <input id="rf_min_ms" class="input w-64" placeholder="≥ ms" value="${esc(S.rf.min_ms)}" title="Slower than (ms)">
    ${active ? `<button class="pill" data-act="rfClear">${icon('x', 'sm')}Clear ${active}</button>` : ''}
    <div class="fill"></div>
    ${(S.savedFilters || []).map((f, i) => `<button class="pill" data-act="rfLoad" data-arg="${i}" data-menu="savedFilter" data-arg2="${i}" title="Saved filter · right-click to delete">${icon('bookmark', 'sm')}${esc(f.name)}</button>`).join('')}
    <button class="pill" data-act="rfSave" title="Save the current filters">${icon('star', 'sm')}Save</button>
  </div>`;
}
function vRequests() {
  const rows = D.req?.rows || [];
  const labels = S.fields ? REQ_LABELS.concat(REQ_DEEP) : REQ_LABELS;
  const key = S.fields ? 'reqDeep' : 'req';
  const trs = rows.map((r) => {
    const cells = [
      cell(fmt.time(r.ts), 'dim', fmt.dt(r.ts)), statusCell(r.status), cell(r.host, 'dim'),
      cell(r.path + (r.query ? '?…' : ''), '', r.path), cell(fmt.bytes(r.bytes), 'r dim'),
      cell(fmt.ms(r.dur), 'r ' + (r.dur > 500 ? 'hot' : 'dim')), cell(r.country || '—', 'dim', cname(r.country)),
      cell(r.ip, 'dim'), cell(r.agent, kindTag(r.kind), r.ua),
    ];
    if (S.fields) cells.push(cell(r.colo, 'dim', coloName(r.colo)), cell(r.os, 'dim'), cell(r.ctype, 'dim'), cell(r.enc || '—', r.enc ? '' : 'dim'),
      cell(r.saved ? fmt.bytes(r.saved) : '—', 'r dim'), cell(r.ref, 'dim'), cell(r.proto, 'dim'), cell(r.method, 'dim'), cell(r.sus || '', r.sus ? 'hot' : 'dim'));
    return { cells, cls: 'click' + (S.sel === r.id ? ' sel' : '') + (D.fresh.has(r.id) ? ' fresh' : ''), attrs: `data-act="selReq" data-arg="${r.id}" data-menu="req" data-arg2="${r.id}"` };
  });
  const scopes = [['all', 'All', 'list'], ['people', 'People', 'users'], ['media', 'Media', 'image'], ['compressed', 'Compressed', 'archive'], ['errors', 'Errors', 'circle-alert'], ['bots', 'Bots', 'bot'], ['scan', 'Probes', 'skull']];
  const ins = S.sel && S.selRow ? inspector(S.selRow) : '';
  return `<div class="split" style="grid-template-columns:${ins ? '1fr 360px' : '1fr'}">
    <section class="aside">
      <div class="tbar">
        ${scopes.map(([k, l, ic]) => `<button class="pill ${S.scope === k ? 'on' : ''}" data-act="scope" data-arg="${k}">${icon(ic, 'sm')}${l}</button>`).join('')}
        <button class="pill ${S.fields ? 'on' : ''}" data-act="fields">${icon('rows-3', 'sm')}Deep fields</button>
        ${S.ipFilter ? `<button class="pill on" data-act="clearIp" title="Clear client filter">client ${esc(S.ipFilter)} ${icon('x', 'sm')}</button>` : ''}
        ${S.q ? `<button class="pill on" data-act="clearQ" title="Clear text filter">“${esc(S.q)}” ${icon('x', 'sm')}</button>` : ''}
        <div class="fill"></div>
        <span class="small dim">${fmt.n(rows.length)} rows · ${D.req && D.req.older ? 'paged back' : S.paused ? 'paused' : 'tailing'}</span>
        <button class="pill" data-act="exportReq" data-arg="csv" title="Download the loaded rows">${icon('download', 'sm')}CSV</button>
        <button class="pill" data-act="exportReq" data-arg="json">${icon('file-braces', 'sm')}JSON</button>
      </div>
      ${reqFilterBar()}
      ${D.req ? table(key, labels, trs, { empty: 'No requests match. The log fills as traffic arrives through the tunnel.' }) : loading()}
      ${D.req && D.req.more ? `<div class="tbar jc-center bb-0 bt-div"><button class="pill" data-act="loadOlder">${icon('chevron-down', 'sm')}Load 500 older</button>${D.req.older ? `<button class="pill" data-act="reqLive">${icon('activity', 'sm')}Back to live</button>` : ''}</div>` : ''}
    </section>
    ${ins}
  </div>`;
}
function inspector(r) {
  const ip = D.ip;
  const url = 'https://' + r.host + r.path;
  const kv = (pairs) => `<div class="kv">${pairs.map(([k, v]) => `<span>${esc(k)}</span><span>${esc(v ?? '—')}</span>`).join('')}</div>`;
  let body;
  if (S.insTab === 'client') {
    body = !ip ? loading('Loading client history…') : kv([
      ['Client', r.ip], ['Country', cname(ip.country) + (ip.country ? ' (' + ip.country + ')' : '')],
      ['Requests', fmt.n(ip.c)], ['Errors', fmt.n(ip.err)], ['Probes', fmt.n(ip.scan)], ['Sent', fmt.bytes(ip.b)],
      ['First seen', fmt.dt(ip.first)], ['Last seen', fmt.ago(ip.last)],
      ['Agents', (ip.agents || []).map((a) => a.k + ' ×' + a.c).join(', ')],
      ...(ip.paths || []).map((p) => [p.status + ' ×' + p.c, p.k]),
    ]);
  } else {
    body = kv([
      ['Time', fmt.dt(r.ts) + ':' + String(new Date(r.ts * 1000).getSeconds()).padStart(2, '0')], ['URL', url + (r.query ? '?…' : '')],
      ['Method', r.method], ['Protocol', r.proto], ['Status', r.status], ['Content type', r.ctype], ['Sent', fmt.bytes(r.bytes)],
      ['Duration', fmt.ms(r.dur)], ['Client', r.ip], ['Country', cname(r.country)], ['Edge', r.colo + ' · ' + coloName(r.colo)],
      ['Referrer', r.ref], ['Client kind', KIND[r.kind] || r.kind], ['Agent', r.agent + (r.os && r.os !== '-' ? ' · ' + r.os : '')],
      ['User-Agent', r.ua || '(empty)'], ['Probe', r.scan ? 'yes, matches scanner patterns' : 'no'], ['Flagged', r.sus || 'no'],
      ['Modifiers', r.mods || '—'], ['Tag', r.tag || '—'], ['Blocked by', r.blocked || '—'],
    ]);
  }
  return `<aside class="aside">
    <div class="insp-head">
      <div class="cap red">${esc(r.method)} · ${esc(r.status)}</div>
      <h5 class="mx-0 mt-3 mb-2 fs-17 break-all">${esc(r.path)}</h5>
      <div class="small dim break-all">${esc(r.host)}</div>
      <div class="hrow mt-10 f-wrap">
        ${r.method === 'GET' && r.status < 400 ? `<button class="btn btn-primary fs-12 px-10 py-6" data-act="openReq">${icon('external-link', 'sm')}Open</button>` : ''}
        <button class="btn btn-secondary fs-12 px-10 py-6" data-act="filterIp" data-arg="${esc(r.ip)}">${icon('user', 'sm')}Only this client</button>
        <button class="btn btn-secondary fs-12 px-10 py-6" data-act="closeIns">${icon('x', 'sm')}Close</button>
      </div>
    </div>
    <div class="stats2">
      <div><div class="cap">Status</div><div class="v ${r.status >= 400 ? 'hot' : ''}">${esc(r.status)}</div></div>
      <div><div class="cap">Sent</div><div class="v">${esc(fmt.bytes(r.bytes))}</div></div>
      <div><div class="cap">Duration</div><div class="v">${esc(fmt.ms(r.dur))}</div></div>
      <div><div class="cap">From</div><div class="v">${esc(r.country || '—')} via ${esc(r.colo || '—')}</div></div>
    </div>
    <div class="tabs">${['request', 'client'].map((t) => `<button class="${S.insTab === t ? 'on' : ''}" data-act="insTab" data-arg="${t}">${t}</button>`).join('')}</div>
    ${body}
  </aside>`;
}

function vContent() {
  if (!statsReady()) return loading();
  const st = D.stats, T = st.totals, sort = S.sort.content;
  const paths = st.paths.slice().sort((a, b) => (b[sort] || 0) - (a[sort] || 0));
  const bmax = Math.max(1, ...paths.map((p) => p.b));
  const rows = paths.map((p) => ({
    cells: [cell(p.k, '', p.host + p.k), cell(p.host, 'dim'), cell(fmt.n(p.c), 'r h800'), cell(p.u == null ? '—' : fmt.n(p.u), 'r dim'),
      hcell(`<span class="bar" style="width:${Math.max(1, share(p.b, bmax) * 0.4).toFixed(1)}px"></span> ${esc(fmt.bytes(p.b))}`, 'r'),
      cell(fmt.ms(p.d), 'r dim'), cell(p.ctype, 'dim'), cell(fmt.ago(p.last), 'dim')],
    cls: 'click', attrs: `data-act="filterPath" data-arg="${esc(p.k)}" data-menu="path" data-arg2="${esc(p.host)}"`,
  }));
  const ok = Math.max(1, T.ok_bytes);
  return tblView({
    title: 'Most requested', note: `${fmt.n(T.paths)} distinct paths · ${fmt.n(T.ok)} successful requests · ${rangeLabel()}${engineNote(st)}`,
    key: 'content', sort, tabs: [],
    labels: [{ t: 'Path', w: 300 }, { t: 'Host', w: 140 }, { t: 'Hits', w: 64, a: 'r', sort: 'c' }, { t: 'Visitors', w: 70, a: 'r', sort: 'u' },
      { t: 'Sent', w: 120, a: 'r', sort: 'b' }, { t: 'Avg', w: 70, a: 'r', sort: 'd' }, { t: 'Type', w: 120 }, { t: 'Last hit', w: 84 }],
    rows,
    aux: {
      kicker: 'Egress', title: 'Bandwidth · ' + rangeLabel(), series: st.series.bytes,
      gauges: st.ctypes.slice(0, 5).map((c) => gauge(c.k, fmt.bytes(c.b) + ' · ' + fmt.pct(share(c.b, ok)), share(c.b, ok), 101)),
      logLabel: 'Heaviest files', log: st.heavy.map((p) => ({ a: p.k, b: fmt.bytes(p.b) + ' · ×' + fmt.n(p.c) })),
    },
  });
}

function vVisitors() {
  if (!statsReady()) return loading();
  const st = D.stats, T = st.totals, tab = S.tab.visitors;
  const bar = (v, max) => hcell(`<span class="bar" style="width:${Math.max(1, share(v, max) * 0.6).toFixed(1)}px"></span> ${fmt.pct(share(v, T.reqs))}`);
  const u = (v) => (v == null ? '—' : fmt.n(v));
  let labels, rows;
  if (tab === 'countries') {
    const m = Math.max(1, ...st.countries.map((c) => c.c));
    labels = [{ t: 'Country', w: 190 }, { t: 'Code', w: 48 }, { t: 'Requests', w: 80, a: 'r' }, { t: 'Visitors', w: 70, a: 'r' }, { t: 'Sent', w: 90, a: 'r' }, { t: 'Share', w: 120 }];
    rows = st.countries.map((c) => ({ cells: [cell(cname(c.k)), cell(c.k || '—', 'dim'), cell(fmt.n(c.c), 'r h800'), cell(u(c.u), 'r dim'), cell(fmt.bytes(c.b), 'r dim'), bar(c.c, m)], cls: 'click', attrs: `data-act="filterCountry" data-arg="${esc(c.k)}"` }));
  } else if (tab === 'clients') {
    const m = Math.max(1, ...st.agents.map((c) => c.c));
    labels = [{ t: 'Client', w: 190 }, { t: 'Kind', w: 110 }, { t: 'Requests', w: 80, a: 'r' }, { t: 'Visitors', w: 70, a: 'r' }, { t: 'Sent', w: 90, a: 'r' }, { t: 'Share', w: 120 }];
    rows = st.agents.map((c) => ({ cells: [cell(c.k), cell(KIND[c.kind] || c.kind, kindTag(c.kind)), cell(fmt.n(c.c), 'r h800'), cell(u(c.u), 'r dim'), cell(fmt.bytes(c.b), 'r dim'), bar(c.c, m)], cls: 'click', attrs: `data-act="filterText" data-arg="${esc(c.k)}"` }));
  } else if (tab === 'referrers') {
    const m = Math.max(1, ...st.referrers.map((c) => c.c));
    labels = [{ t: 'Referrer', w: 260 }, { t: 'Requests', w: 80, a: 'r' }, { t: 'Visitors', w: 70, a: 'r' }, { t: 'Sent', w: 90, a: 'r' }, { t: 'Share', w: 120 }];
    rows = st.referrers.map((c) => ({ cells: [cell(c.k), cell(fmt.n(c.c), 'r h800'), cell(u(c.u), 'r dim'), cell(fmt.bytes(c.b), 'r dim'), bar(c.c, m)], cls: 'click', attrs: `data-act="filterText" data-arg="${esc(c.k)}"` }));
  } else if (tab === 'hosts') {
    const m = Math.max(1, ...st.hosts.map((c) => c.c));
    labels = [{ t: 'Hostname', w: 240 }, { t: 'Requests', w: 80, a: 'r' }, { t: 'Visitors', w: 70, a: 'r' }, { t: 'Sent', w: 90, a: 'r' }, { t: 'Share', w: 120 }];
    rows = st.hosts.map((c) => ({ cells: [cell(c.k), cell(fmt.n(c.c), 'r h800'), cell(u(c.u), 'r dim'), cell(fmt.bytes(c.b), 'r dim'), bar(c.c, m)], cls: 'click', attrs: `data-act="filterHost" data-arg="${esc(c.k)}"` }));
  } else {
    const m = Math.max(1, ...st.os.map((c) => c.c));
    labels = [{ t: 'Operating system', w: 200 }, { t: 'Requests', w: 80, a: 'r' }, { t: 'Visitors', w: 70, a: 'r' }, { t: 'Sent', w: 90, a: 'r' }, { t: 'Share', w: 120 }];
    rows = st.os.map((c) => ({ cells: [cell(c.k), cell(fmt.n(c.c), 'r h800'), cell(u(c.u), 'r dim'), cell(fmt.bytes(c.b), 'r dim'), bar(c.c, m)] }));
  }
  const kinds = Object.fromEntries(st.kinds.map((k) => [k.k, k]));
  return tblView({
    title: 'Audience', note: `${fmt.n(T.uniq)} unique clients · ${rangeLabel()}${engineNote(st)}`, key: 'vis-' + tab, labels, rows,
    tabs: [['countries', 'Countries', 'earth'], ['clients', 'Clients', 'monitor'], ['referrers', 'Referrers', 'link-2'], ['hosts', 'Hostnames', 'globe'], ['os', 'Systems', 'cpu']].map(([k, l, ic]) => ({ label: l, icon: ic, act: 'tab', arg: 'visitors:' + k, on: tab === k })),
    empty: tab === 'referrers' ? 'No referrers yet. Most hits are direct links and embeds.' : undefined,
    aux: {
      kicker: 'Audience', title: 'Unique visitors · ' + rangeLabel(), series: st.series.uniq,
      gauges: ['browser', 'player', 'embed', 'bot'].map((k) => gauge(KIND[k], fmt.n(kinds[k]?.c || 0) + ' · ' + fmt.pct(share(kinds[k]?.c || 0, T.reqs)), share(kinds[k]?.c || 0, T.reqs), k === 'bot' ? 60 : 101)),
      logLabel: 'Methods', log: st.methods.map((m) => ({ a: m.k, b: fmt.n(m.c) })),
    },
  });
}

function vTunnel() {
  const t = D.live?.tunnel;
  if (!t) return loading();
  if (!t.up) return `<div class="setup"><h5 class="hot">cloudflared metrics unreachable</h5><p>${esc(t.error)}</p><p>Strata reads <code>${esc(INST.cloudflared_metrics === 'auto' ? 'http://127.0.0.1:20241-20250/metrics (auto)' : INST.cloudflared_metrics)}</code>. If cloudflared restarted on another port, set <code>cloudflared_metrics</code> in <code>${esc(INST.config)}</code>, or pin it with a fixed <code>metrics:</code> address in cloudflared’s config.yml. The Network view can restart the tunnel.</p></div>`;
  const codes = Object.entries(t.codes || {}).sort((a, b) => b[1] - a[1]);
  const tot = codes.reduce((a, [, v]) => a + v, 0);
  const rows = (t.conns || []).map((c) => ({
    cells: [cell('#' + c.id, 'h800'), cell(String(c.colo || '—').toUpperCase(), 'h800'), cell(coloName(c.colo), 'dim'),
      cell(fmt.ms(c.rtt), 'r ' + (c.rtt > 150 ? 'hot' : '')), cell(fmt.ms(c.srtt), 'r dim'), cell(fmt.ms(c.min_rtt), 'r dim'),
      cell(fmt.bytes(c.cwnd), 'r dim'), cell(fmt.n(c.mtu), 'r dim'), cell(fmt.n(c.lost), 'r dim'), cell(fmt.bytes(c.tx), 'r'), cell(fmt.bytes(c.rx), 'r dim')],
    attrs: `data-menu="conn" data-arg="${esc(c.colo)}"`,
  }));
  return tblView({
    title: 'Edge connections', note: `cloudflared ${t.version} · ${t.ha} of 4 HA connections · ${fmt.n(t.registrations)} registrations since start`,
    key: 'tunnel', rows, tabs: [{ label: 'Ingress & restart', icon: 'globe', act: 'go', arg: 'network', on: false }],
    labels: [{ t: 'Conn', w: 50 }, { t: 'Edge', w: 60 }, { t: 'Location', w: 110 }, { t: 'RTT', w: 70, a: 'r' }, { t: 'Smoothed', w: 76, a: 'r' },
      { t: 'Min', w: 64, a: 'r' }, { t: 'Cwnd', w: 70, a: 'r' }, { t: 'MTU', w: 50, a: 'r' }, { t: 'Lost pkts', w: 70, a: 'r' }, { t: 'Sent', w: 80, a: 'r' }, { t: 'Received', w: 80, a: 'r' }],
    aux: {
      kicker: 'cloudflared ' + t.version, title: 'Tunnel egress · last ' + Math.round((D.live.hist.tunnel_tx || []).length * 2 / 60) + ' min', series: D.live.hist.tunnel_tx,
      gauges: [
        gauge('HA connections', t.ha + ' / 4', share(t.ha, 4), 101, t.ha < 4),
        gauge('404 share since start', fmt.pct(share(t.codes?.['404'] || 0, tot)), share(t.codes?.['404'] || 0, tot), 50),
        gauge('Proxy errors', fmt.n(t.errors) + ' · ' + fmt.pct(share(t.errors, t.total)), share(t.errors, t.total) * 10, 50),
        gauge('Process CPU / memory', fmt.pct(t.cpu) + ' · ' + fmt.bytes(t.rss), t.cpu || 0, 50),
      ],
      logLabel: `Responses since start · ${fmt.n(t.total)} total`,
      log: codes.map(([k, v]) => ({ a: 'HTTP ' + k, b: fmt.n(v) + ' · ' + fmt.pct(share(v, tot)) })),
    },
  });
}

function vOrigins() {
  const L = D.live;
  if (!L) return loading();
  const rows = (L.origins || []).map((o) => ({
    cells: [cell(o.hostname, 'h800'), cell(o.service, 'dim'), cell(o.status ?? (o.service.startsWith('http_status') ? 'static' : '—'), o.ok === false ? 'hot' : ''),
      cell(o.ms == null ? '—' : fmt.ms(o.ms), 'r ' + (o.ms > 250 ? 'hot' : '')), hcell(o.ok == null ? '<span class="dim">catch-all</span>' : o.ok ? `<span class="ok">${icon('circle-check', 'sm')} reachable</span>` : `<span class="hot h800">${icon('circle-x', 'sm')} DOWN</span>`),
      hcell(o.hist && o.hist.length > 1 ? sparkSvg(o.hist, { w: 100, h: 16, cls: '', max: niceMax(o.hist, 1) }).replace('<svg ', '<svg style="width:100px;height:16px;display:block" ') : ''), cell(o.error, 'hot')],
    attrs: o.hostname !== '*' ? `data-menu="origin" data-arg="${esc(o.hostname)}"` : '',
  }));
  const st = L.storage || [];
  const nas = st[0] || {};
  return tblView({
    title: 'Tunnel ingress', note: `${rows.length} rules from cloudflared’s config.yml, checked every 15 s`, key: 'origins', rows,
    tabs: [{ label: 'Edit ingress', icon: 'pencil', act: 'go', arg: 'network', on: false }],
    labels: [{ t: 'Hostname', w: 220 }, { t: 'Service', w: 190 }, { t: 'HTTP', w: 56 }, { t: 'Latency', w: 76, a: 'r' }, { t: 'State', w: 100 }, { t: 'Trend', w: 110 }, { t: 'Error', w: 200 }],
    aux: {
      kicker: 'Storage', title: nas.path || 'media share', series: nas.hist,
      gauges: st.map((s) => gauge(s.path + (s.ok ? '' : ' · offline'),
        s.total ? fmt.bytes(s.used, 0) + ' / ' + fmt.bytes(s.total, 0) : s.error || '—', s.total ? share(s.used, s.total) : 100, 90, !s.ok)),
      logLabel: 'Volumes', log: st.map((s) => ({ a: s.path, b: s.ok ? fmt.bytes(s.free) + ' free · ' + fmt.ms(s.ms) : 'offline' })),
    },
  });
}

function vSecurity() {
  if (!statsReady()) return loading();
  const st = D.stats, T = st.totals, tab = S.tab.security;
  let labels, rows;
  const ipAttrs = (ip) => `data-act="filterIp" data-arg="${esc(ip)}" data-menu="ip" data-arg2="${esc(ip)}"`;
  if (tab === 'scanners') {
    labels = [{ t: 'Client', w: 130 }, { t: 'CC', w: 36 }, { t: 'Requests', w: 72, a: 'r' }, { t: 'Probes', w: 60, a: 'r' }, { t: 'Flagged as', w: 96 }, { t: 'First', w: 96 }, { t: 'Last', w: 80 }, { t: 'Agent', w: 140 }, { t: 'Sample probe', w: 260 }];
    rows = st.scanners.map((s) => ({ cells: [cell(s.k, 'h800'), cell(s.country || '—', 'dim', cname(s.country)), cell(fmt.n(s.c), 'r'), cell(fmt.n(s.scan), 'r hot h800'), cell(s.why || 'probes', s.why ? 'hot' : 'dim', `${fmt.n(s.sus)} requests left out of error rates`), cell(fmt.dt(s.first), 'dim'), cell(fmt.ago(s.last), 'dim'), cell(s.agent, 'dim'), cell(s.sample || '—', 'dim')], cls: 'click', attrs: ipAttrs(s.k) }));
  } else if (tab === 'notfound') {
    labels = [{ t: 'Path', w: 340 }, { t: 'Hits', w: 64, a: 'r' }, { t: 'Clients', w: 64, a: 'r' }, { t: 'Kind', w: 110 }, { t: 'Last', w: 90 }];
    rows = st.notfound.map((p) => ({ cells: [cell(p.k), cell(fmt.n(p.c), 'r h800'), cell(p.u == null ? '—' : fmt.n(p.u), 'r dim'), cell(p.scan ? 'probe' : 'missing file', p.scan ? 'hot' : 'dim'), cell(fmt.ago(p.last), 'dim')], cls: 'click', attrs: `data-act="filterPath" data-arg="${esc(p.k)}"` }));
  } else {
    labels = [{ t: 'Client', w: 130 }, { t: 'CC', w: 36 }, { t: 'Requests', w: 72, a: 'r' }, { t: 'Sent', w: 80, a: 'r' }, { t: 'Errors', w: 60, a: 'r' }, { t: 'Probes', w: 60, a: 'r' }, { t: 'Agent', w: 150 }, { t: 'Last', w: 80 }];
    rows = st.ips.map((s) => ({ cells: [cell(s.k, 'h800'), cell(s.country || '—', 'dim', cname(s.country)), cell(fmt.n(s.c), 'r'), cell(fmt.bytes(s.b), 'r dim'), cell(fmt.n(s.err), 'r ' + (s.err ? 'hot' : 'dim')), cell(fmt.n(s.scan), 'r ' + (s.scan ? 'hot' : 'dim')), cell(s.agent, kindTag(s.kind)), cell(fmt.ago(s.last), 'dim')], cls: 'click', attrs: ipAttrs(s.k) }));
  }
  const probed = st.notfound.filter((p) => p.scan);
  const blocked = (st.statuses.find((s) => s.k === 403) || {}).c || 0;
  return tblView({
    title: 'Threat surface', note: `${fmt.n(T.scans)} probe requests · ${fmt.n(T.sus)} suspicious from ${fmt.n(T.sus_ips)} clients (not in error rates) · ${rangeLabel()} · right-click a client to block it`,
    key: 'sec-' + tab, labels, rows,
    tabs: [['scanners', 'Scanners', 'skull'], ['notfound', 'Not found', 'search'], ['ips', 'Top clients', 'users']].map(([k, l, ic]) => ({ label: l, icon: ic, act: 'tab', arg: 'security:' + k, on: tab === k })),
    empty: tab === 'scanners' ? 'No scanners in this range. Probes for .env and the like show up here.' : undefined,
    aux: {
      kicker: 'Threats', title: 'Suspicious requests · ' + rangeLabel(), series: st.series.sus || st.series.e4,
      gauges: [
        gauge('Suspicious share', fmt.pct(share(T.sus, T.reqs)), share(T.sus, T.reqs), 101),
        gauge('4xx share (clean)', fmt.pct(share(T.e4, T.clean)), share(T.e4, T.clean), 40),
        gauge('Probe share', fmt.pct(share(T.scans, T.reqs)), share(T.scans, T.reqs), 20),
        gauge('Bot share', fmt.pct(share(T.bots, T.reqs)), share(T.bots, T.reqs), 60),
        gauge('Blocked (403)', fmt.n(blocked), share(blocked, T.reqs), 101),
      ],
      logLabel: 'Most probed paths', log: probed.map((p) => ({ a: p.k, b: '×' + fmt.n(p.c) + (p.u != null ? ' · ' + fmt.n(p.u) + ' clients' : '') })),
    },
  });
}

function vLatency() {
  if (!statsReady()) return loading();
  const st = D.stats, T = st.totals;
  const names = ['<1', '1–5', '5–10', '10–25', '25–50', '50–100', '100–250', '250–500', '0.5–1 s', '1–2.5 s', '>2.5 s'];
  const hist = names.map((_, i) => (st.latency_hist.find((h) => h.k === i) || {}).c || 0);
  const hmax = Math.max(1, ...hist);
  const bw = 240 / hist.length;
  const svg = `<svg class="spark" viewBox="0 0 240 76" preserveAspectRatio="none">${hist.map((v, i) =>
    `<rect x="${(i * bw + 1).toFixed(1)}" y="${(76 - v / hmax * 72).toFixed(1)}" width="${(bw - 2).toFixed(1)}" height="${(v / hmax * 72).toFixed(1)}" fill="${i >= 8 ? 'var(--color-accent)' : 'color-mix(in srgb, var(--color-text) ' + (35 + i * 5) + '%, transparent)'}"><title>${names[i]} ms: ${v}</title></rect>`).join('')}</svg>`;
  const rows = st.slowest.map((p) => ({
    cells: [cell(p.k, '', p.host + p.k), cell(p.host, 'dim'), cell(fmt.n(p.c), 'r'), cell(fmt.ms(p.avg), 'r h800 ' + (p.avg > 500 ? 'hot' : '')), cell(fmt.ms(p.max), 'r dim'), cell(fmt.bytes(p.b), 'r dim')],
    cls: 'click', attrs: `data-act="filterPath" data-arg="${esc(p.k)}" data-menu="path" data-arg2="${esc(p.host)}"`,
  }));
  return tblView({
    title: 'Slowest paths', note: `mean over ≥ 2 hits · p50 ${fmt.ms(T.p50)} · p95 ${fmt.ms(T.p95)} · p99 ${fmt.ms(T.p99)} · ${rangeLabel()}${engineNote(st)}`, key: 'latency', rows, tabs: [],
    labels: [{ t: 'Path', w: 320 }, { t: 'Host', w: 140 }, { t: 'Hits', w: 60, a: 'r' }, { t: 'Mean', w: 80, a: 'r' }, { t: 'Max', w: 80, a: 'r' }, { t: 'Sent', w: 80, a: 'r' }],
    aux: {
      kicker: 'Distribution', title: 'Response time · ' + rangeLabel(), svg,
      gauges: [gauge('p50', fmt.ms(T.p50), T.p50 / 10, 50), gauge('p95', fmt.ms(T.p95), T.p95 / 10, 50), gauge('p99', fmt.ms(T.p99), T.p99 / 10, 50)],
      logLabel: 'Buckets (ms) · per host', log: names.map((n, i) => ({ a: n + ' ms', b: fmt.n(hist[i]) + ' · ' + fmt.pct(share(hist[i], T.reqs)) }))
        .concat(st.latency_hosts.map((h) => ({ a: h.k, b: 'mean ' + fmt.ms(h.avg) + ' · max ' + fmt.ms(h.max) }))),
    },
  });
}

function vHistory() {
  const h = D.hist;
  if (!h) return loading();
  const hourLbl = (i) => fmt.hm(h.hours[i]) + '–' + fmt.hm(h.hours[i] + 3600);
  const band = (label, note, arr, fv, hotFn) => {
    const m = Math.max(1e-9, ...arr.map((v) => v || 0));
    const slabs = arr.map((v, i) => {
      const hot = v != null && hotFn && hotFn(v, i);
      const bg = hot ? 'var(--color-accent)' : `color-mix(in srgb,var(--color-text) ${(40 + (v || 0) / m * 50).toFixed(0)}%,transparent)`;
      return `<span title="${esc(hourLbl(i) + ' · ' + (v == null ? 'no data' : fv(v)))}" style="height:${v == null || v === 0 ? 0 : Math.max(3, v / m * 100).toFixed(1)}%;background:${bg}"></span>`;
    }).join('');
    return `<div class="band"><div class="d-flex between items-baseline mb-4">
      <span class="cap">${esc(label)}</span><span class="small dim">${esc(note)}</span></div>
      <div class="slabs">${slabs}</div>
      <div class="dim d-flex between fs-95 mt-3"><span>−24 h</span><span>−12 h</span><span>now</span></div></div>`;
  };
  const sum = (a) => a.reduce((x, y) => x + (y || 0), 0);
  const peak = (a) => { let bi = 0; a.forEach((v, i) => { if ((v || 0) > (a[bi] || 0)) bi = i; }); return bi; };
  const mean = (a) => { const v = a.filter((x) => x != null); return v.length ? sum(v) / v.length : null; };
  const pr = peak(h.reqs);
  return `<section class="col-fill px-18 py-16 oy-auto" data-scroll="hist">
    <div class="ph mb-12"><h5>${icon('clock-fading')}Last 24 hours</h5><span class="small dim">requests from the access log · vitals from minute samples${engineNote(h)}</span></div>
    ${band('Requests', `${fmt.n(sum(h.reqs))} total · peak ${fmt.n(h.reqs[pr])} at ${fmt.hm(h.hours[pr])}`, h.reqs, (v) => fmt.n(v) + ' requests')}
    ${band('Bandwidth', fmt.bytes(sum(h.bytes)) + ' sent', h.bytes, (v) => fmt.bytes(v))}
    ${band('Saved by Brotli', fmt.bytes(sum(h.saved)) + ' not sent thanks to precompression', h.saved, (v) => fmt.bytes(v))}
    ${band('Visitors', 'unique IPs per hour', h.uniq, (v) => fmt.n(v) + ' clients')}
    ${band('Errors', `${fmt.n(sum(h.err))} 4xx/5xx · red where errors exceed half the traffic`, h.err, (v) => fmt.n(v) + ' errors', (v, i) => v > h.reqs[i] / 2)}
    ${band('Latency', 'mean origin time per hour', h.dur, (v) => fmt.ms(v), (v) => v > 500)}
    ${band('Tunnel RTT', 'mean ' + fmt.ms(mean(h.tunnel_rtt)), h.tunnel_rtt, (v) => fmt.ms(v), (v) => v > 150)}
    ${band('NAS latency', 'mean ' + fmt.ms(mean(h.nas_ms)), h.nas_ms, (v) => fmt.ms(v), (v) => v > 250)}
    ${band('Caddy CPU', 'mean ' + fmt.pct(mean(h.caddy_cpu)), h.caddy_cpu, (v) => fmt.pct(v), (v) => v > 50)}
  </section>`;
}

function vEdge() {
  const e = D.edge;
  if (!e) return loading('Asking Cloudflare…');
  const setup = `<div class="setup">
    <h5>Connect Cloudflare edge analytics</h5>
    <p>Caddy only sees requests that <b>miss</b> Cloudflare’s cache. Connect Cloudflare to see the rest.</p>
    <ol>
      <li>Open <b>dash.cloudflare.com → My Profile → API Tokens → Create Token → Custom token</b>.</li>
      <li>Permissions: <code>Zone · Analytics · Read</code> and <code>Zone · Zone · Read</code>. Zone resources: <code>${esc(INST.zone)}</code> only.</li>
      <li>Put the token in <code>${esc(INST.config)}</code> (or the <code>${esc(INST.token_env)}</code> environment variable) and restart Strata:</li>
    </ol>
    <pre><code>{
  "cloudflare": { "api_token": "paste-token-here", "zone_name": "${esc(INST.zone)}" }
}</code></pre>
    <p class="dim">The Network view lists the other permissions Strata can use.</p>
    ${e.configured ? `<p class="hot"><b>Last attempt failed:</b> ${esc(e.error)}</p><button class="btn btn-secondary" data-act="edgeRetry">${icon('refresh-cw', 'sm')}Retry now</button>` : ''}
  </div>`;
  if (!e.configured || !e.ok) return setup;
  const hrs = e.hours || [], days = e.days || [];
  const sumH = (f) => hrs.reduce((a, x) => a + (f(x) || 0), 0);
  const req = sumH((x) => x.sum.requests), creq = sumH((x) => x.sum.cachedRequests);
  const byt = sumH((x) => x.sum.bytes), cbyt = sumH((x) => x.sum.cachedBytes), thr = sumH((x) => x.sum.threats);
  const uniq = Math.max(0, ...hrs.map((x) => x.uniq?.uniques || 0));
  const kpi = (k, v, sub, hot) => `<div><div class="cap">${esc(k)}</div><div class="val ${hot ? 'hot' : ''}">${esc(v)}</div><div class="small dim ell">${esc(sub)}</div></div>`;
  const bars = (list, total, cached, label) => {
    const m = Math.max(1, ...list.map(total));
    return `<div class="slabs min-h-90">${list.map((x) => {
      const t = total(x) || 0, c = cached(x) || 0;
      return `<span class="stack" title="${esc(label(x) + ' · ' + fmt.n(t) + ' requests · ' + fmt.pct(share(c, t)) + ' cached')}" style="height:${Math.max(t ? 3 : 0, t / m * 100).toFixed(1)}%">
        <span style="flex:${c};background:var(--color-text)"></span><span style="flex:${t - c};background:var(--color-accent)"></span></span>`;
    }).join('')}</div>`;
  };
  const countries = {};
  hrs.forEach((x) => (x.sum.countryMap || []).forEach((c) => {
    const o = countries[c.clientCountryName] || (countries[c.clientCountryName] = { r: 0, b: 0, t: 0 });
    o.r += c.requests; o.b += c.bytes; o.t += c.threats;
  }));
  const crow = Object.entries(countries).sort((a, b) => b[1].r - a[1].r).slice(0, 40)
    .map(([k, v]) => ({ cells: [cell(cname(k)), cell(k, 'dim'), cell(fmt.n(v.r), 'r h800'), cell(fmt.bytes(v.b), 'r dim'), cell(fmt.n(v.t), 'r ' + (v.t ? 'hot' : 'dim'))] }));
  return `<div class="col-fill">
    <div class="kpis">
      ${kpi('Requests · 24 h', fmt.n(req), 'at the Cloudflare edge')}
      ${kpi('Served from cache', fmt.pct(share(creq, req)), fmt.n(creq) + ' requests never hit Caddy')}
      ${kpi('Bandwidth · 24 h', fmt.bytes(byt), 'to visitors')}
      ${kpi('Cached bandwidth', fmt.pct(share(cbyt, byt)), fmt.bytes(cbyt) + ' saved on your uplink')}
      ${kpi('Threats', fmt.n(thr), 'blocked or challenged', thr > 0)}
      ${kpi('Unique visitors', fmt.n(uniq), 'peak hour · Cloudflare count')}
    </div>
    <div class="grid2 cols-135 fill">
      <section class="panel oy-auto">
        <div class="ph"><h5>Edge requests · 24 h</h5><span class="small dim">dark: cache hit · red: from origin · refreshed ${esc(fmt.ago(e.fetched))}</span></div>
        ${bars(hrs, (x) => x.sum.requests, (x) => x.sum.cachedRequests, (x) => fmt.dt(Date.parse(x.dimensions.datetime) / 1000))}
        <div class="axis"><span>−24 h</span><span>hourly</span><span>now</span></div>
        <div class="ph mt-18"><h5>Edge requests · 30 days</h5><span class="small dim">${fmt.n(days.reduce((a, x) => a + x.sum.requests, 0))} requests · ${esc(fmt.bytes(days.reduce((a, x) => a + x.sum.bytes, 0)))}</span></div>
        ${bars(days, (x) => x.sum.requests, (x) => x.sum.cachedRequests, (x) => x.dimensions.date)}
        <div class="axis"><span>−30 d</span><span>daily</span><span>today</span></div>
      </section>
      <section class="aside">
        <div class="ph ph-pad"><h5>Countries at the edge</h5><button class="pill" data-act="edgeRetry">${icon('refresh-cw', 'sm')}Refresh</button></div>
        <div class="bt-div"></div>
        ${table('edge', [{ t: 'Country', w: 170 }, { t: 'CC', w: 40 }, { t: 'Requests', w: 80, a: 'r' }, { t: 'Sent', w: 80, a: 'r' }, { t: 'Threats', w: 60, a: 'r' }], crow)}
      </section>
    </div>
  </div>`;
}

/* ---- insights */

function barList(rows, o) {
  const max = Math.max(1, ...rows.map(o.value));
  return rows.map((r) => `<div class="bl ${o.hot && o.hot(r) ? 'hot' : ''}" ${o.attrs ? o.attrs(r) : ''}><span class="ell" title="${esc(o.title ? o.title(r) : o.label(r))}">${o.labelHtml ? o.labelHtml(r) : esc(o.label(r))}</span>
    <span class="blbar"><i style="width:${share(o.value(r), max).toFixed(1)}%"></i></span><span class="r small">${esc(o.fmtv(r))}</span></div>`).join('') || '<div class="small dim">No data in this range yet.</div>';
}
const panel = (title, note, body, cls = '', ic = '') => `<section class="panel ${cls}"><div class="ph"><h5>${ic ? icon(ic) : ''}${esc(title)}</h5><span class="small dim ell">${esc(note || '')}</span></div><div class="scroll">${body}</div></section>`;
function vInsights() {
  const I = D.insights;
  if (!I || I.range !== statsRange()) return loading();
  const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const grid = Array.from({ length: 7 }, () => Array(24).fill(0));
  I.heat.forEach((h) => { grid[(h.d + 6) % 7][h.h] += h.c; });
  const hmax = Math.max(1, ...grid.flat());
  const heat = `<div class="heat"><span></span>${Array.from({ length: 24 }, (_, h) => `<span class="lbl jc-center">${h % 3 === 0 ? String(h).padStart(2, '0') : ''}</span>`).join('')}` +
    grid.map((row, d) => `<span class="lbl">${days[d]}</span>` + row.map((v, h) =>
      `<span title="${days[d]} ${String(h).padStart(2, '0')}:00 · ${fmt.n(v)} requests" style="background:${v ? `color-mix(in srgb,var(--color-accent) ${(8 + v / hmax * 82).toFixed(0)}%,var(--color-neutral-200))` : 'var(--color-neutral-200)'}"></span>`).join('')).join('') + '</div>';
  const cls = Object.fromEntries(I.classes.map((c) => [c.k, c.c]));
  const ctot = Math.max(1, I.classes.reduce((a, c) => a + c.c, 0));
  const classBar = `<div class="stackbar">${[[2, 'var(--color-text)'], [3, 'var(--color-neutral-500)'], [4, 'var(--color-accent)'], [5, 'var(--color-accent-800)']]
    .map(([k, col]) => cls[k] ? `<i title="${k}xx · ${fmt.n(cls[k])}" style="flex:${cls[k]};background:${col}"></i>` : '').join('')}</div>
    <div class="small dim">${[2, 3, 4, 5].map((k) => `${k}xx ${fmt.pct(share(cls[k] || 0, ctot))}`).join(' · ')}</div>`;
  const ret = `<div class="d-flex gap-26 mx-0 mt-4 mb-8"><div><div class="cap">Returning</div><div class="big-num">${fmt.n(I.returning)}</div></div>
    <div><div class="cap">New</div><div class="big-num">${fmt.n(I.visitors - I.returning)}</div></div></div>
    <div class="stackbar"><i style="flex:${I.returning || 0};background:var(--color-text)"></i><i style="flex:${(I.visitors - I.returning) || 0};background:var(--color-accent)"></i></div>
    <div class="small dim">Returning: seen before this range (data since ${esc(fmt.dt(D.live?.db?.first))}).</div>
    <div class="cap mt-16">Status classes</div>${classBar}
    <div class="cap mt-16">Protocols (Cloudflare → origin)</div><div class="small">${I.protos.map((p) => esc(p.k || '—') + ' ' + fmt.n(p.c)).join(' · ') || '—'}</div>`;
  const inv = I.inventory;
  const dailyRows = I.daily.slice().reverse().map((d) => ({ cells: [cell(d.k, 'h800'), cell(fmt.n(d.c), 'r'), cell(fmt.n(d.u), 'r dim'), cell(fmt.bytes(d.b), 'r dim'), cell(fmt.n(d.e), 'r ' + (d.e ? 'hot' : 'dim'))] }));
  return `<div class="ins">
    ${panel('Weekly rhythm', 'requests by weekday × hour · local time · ' + rangeLabel() + engineNote(I), heat, 'span2', 'calendar')}
    ${panel('Visitors & outcomes', rangeLabel(), ret, '', 'users')}
    <section class="panel"><div class="ph"><h5>${icon('calendar')}By day</h5><button class="pill" data-act="exportTable" data-arg="ins-daily">${icon('download', 'sm')}CSV</button></div>
      ${table('ins-daily', [{ t: 'Date', w: 90 }, { t: 'Requests', w: 70, a: 'r' }, { t: 'Visitors', w: 64, a: 'r' }, { t: 'Sent', w: 76, a: 'r' }, { t: 'Errors', w: 52, a: 'r' }], dailyRows)}</section>
    ${panel('File types', 'successful requests by extension', barList(I.exts, { label: (r) => r.k, value: (r) => r.c, fmtv: (r) => fmt.n(r.c) + ' · ' + fmt.bytes(r.b) }), '', 'file')}
    ${panel('Response sizes', 'bytes on the wire per response', barList(I.sizes.map((s) => ({ ...s, l: I.size_labels[s.k] })).sort((a, b) => a.k - b.k), { label: (r) => r.l, value: (r) => r.c, fmtv: (r) => fmt.n(r.c) + ' · ' + fmt.bytes(r.b) }), '', 'ruler')}
    ${panel('Heaviest clients', 'by bytes sent · right-click for actions', barList(I.clients, {
      label: (r) => r.k, title: (r) => r.k + ' · ' + cname(r.country) + ' · ' + r.agent,
      labelHtml: (r) => `${esc(r.k)} <span class="dim">${esc(r.country || '')} · ${esc(r.agent)}</span>`,
      value: (r) => r.b, fmtv: (r) => fmt.bytes(r.b), hot: (r) => r.kind === 'bot',
      attrs: (r) => `data-menu="ip" data-arg="${esc(r.k)}" data-act="filterIp" style="cursor:pointer"` }), '', 'user')}
    ${panel('Busiest hours', rangeLabel(), barList(I.busiest, { label: (r) => fmt.dt(r.t), value: (r) => r.c, fmtv: (r) => fmt.n(r.c) + ' req · ' + fmt.n(r.u) + ' vis' }), '', 'flame')}
    ${panel('Content categories', 'served, by bytes', barList(I.cats, { label: (r) => r.k, value: (r) => r.b, fmtv: (r) => fmt.bytes(r.b) + ' · ' + fmt.n(r.c) }), '', 'layers')}
    ${panel('Library by type', inv ? `${fmt.n(inv.files)} files · ${fmt.bytes(inv.bytes)} · scanned ${fmt.ago(inv.ts)}` : 'first scan pending',
      inv ? barList(inv.cats, { label: (r) => r.k + ' · ' + fmt.n(r.c), value: (r) => r.b, fmtv: (r) => fmt.bytes(r.b) }) : '', '', 'hard-drive')}
    ${panel('Library by folder', inv ? `${fmt.n(inv.variants)} Brotli variants · ${fmt.bytes(inv.variant_bytes)}` : '',
      inv ? barList(inv.folders, { label: (r) => r.k + ' · ' + fmt.n(r.c), value: (r) => r.b, fmtv: (r) => fmt.bytes(r.b), attrs: (r) => r.k !== '(root)' ? `data-act="fgo" data-arg="${esc('/' + r.k)}" style="cursor:pointer"` : '' }) : '', '', 'folder')}
    ${panel('Largest files', 'in storage', inv ? barList(inv.largest, { label: (r) => r.k, value: (r) => r.b, fmtv: (r) => fmt.bytes(r.b) }) : '', '', 'file-archive')}
  </div>`;
}

/* ---- compression */

function vCompression() {
  const C = D.comp;
  if (!C || C.range !== statsRange()) return loading();
  const tab = S.tab.compression, st = C.status || {}, o = C.originals || {};
  const br = (C.store || []).find((s) => s.k === 'br') || { files: 0, orig: 0, size: 0 };
  const served = Object.fromEntries((C.served || []).map((s) => [s.k, s]));
  const totReq = (C.served || []).reduce((a, s) => a + s.c, 0);
  const encReq = totReq - (served.identity?.c || 0);
  const savedTot = (C.served || []).reduce((a, s) => a + (s.saved || 0), 0);
  let labels, rows;
  if (tab === 'files') {
    labels = [{ t: 'File', w: 340 }, { t: 'Original', w: 86, a: 'r' }, { t: 'Brotli', w: 86, a: 'r' }, { t: 'Saving', w: 70, a: 'r' }, { t: 'Compressed', w: 110 }];
    rows = C.files.map((f) => ({ cells: [cell(f.k, '', f.k), cell(fmt.bytes(f.orig), 'r dim'), cell(fmt.bytes(f.br ?? f.best), 'r h800'), cell(fmt.pct(100 - share(f.best, f.orig)), 'r'), cell(fmt.ago(f.created), 'dim')],
      cls: 'click', attrs: `data-act="fgoFile" data-arg="${esc(f.k)}" data-menu="path" data-arg2="${esc(cdnHost())}"` }));
  } else if (tab === 'runs') {
    labels = [{ t: 'When', w: 110 }, { t: 'Trigger', w: 80 }, { t: 'Scanned', w: 70, a: 'r' }, { t: 'New', w: 50, a: 'r' }, { t: 'In → out', w: 150, a: 'r' }, { t: 'Skipped', w: 64, a: 'r' }, { t: 'Removed', w: 66, a: 'r' }, { t: 'Errors', w: 56, a: 'r' }, { t: 'Took', w: 64, a: 'r' }, { t: 'Note', w: 180 }];
    rows = C.runs.map((r) => ({ cells: [cell(fmt.dt(r.ts), 'dim'), cell(r.trigger), cell(fmt.n(r.scanned), 'r dim'), cell(fmt.n(r.compressed), 'r h800'),
      cell(r.bytes_in ? fmt.bytes(r.bytes_in) + ' → ' + fmt.bytes(r.bytes_out) : '—', 'r'), cell(fmt.n(r.skipped), 'r dim'), cell(fmt.n(r.removed), 'r dim'),
      cell(fmt.n(r.errors), 'r ' + (r.errors ? 'hot' : 'dim')), cell(fmt.n1(r.secs) + ' s', 'r dim'), cell(r.note, 'dim')] }));
  } else {
    labels = [{ t: 'Content type', w: 200 }, { t: 'Requests', w: 76, a: 'r' }, { t: 'Compressed', w: 90, a: 'r' }, { t: 'Sent', w: 86, a: 'r' }, { t: 'Saved (br)', w: 90, a: 'r' }];
    rows = C.by_type.map((t) => ({ cells: [cell(t.k), cell(fmt.n(t.c), 'r'), cell(fmt.pct(share(t.enc, t.c)), 'r h800'), cell(fmt.bytes(t.b), 'r dim'), cell(t.saved ? fmt.bytes(t.saved) : '—', 'r')] }));
  }
  const runLine = st.running ? `running (${st.trigger}) · ${fmt.n(st.scanned || 0)} scanned · ${fmt.n(st.done || 0)} compressed · ${st.current || ''}`
    : `idle · next scan ${st.next_scan ? 'in ' + fmt.dur(st.next_scan - Date.now() / 1000) : '—'}`;
  return tblView({
    title: 'Brotli precompression', note: runLine, key: 'comp-' + tab, labels, rows,
    tabs: [['files', 'Store', 'archive'], ['runs', 'Run log', 'list'], ['served', 'Served', 'send']].map(([k, l, ic]) => ({ label: l, icon: ic, act: 'tab', arg: 'compression:' + k, on: tab === k }))
      .concat([{ label: st.running ? 'Scanning…' : 'Scan now', icon: 'refresh-cw', act: 'compressRun', arg: '', on: false }]),
    empty: tab === 'files' ? 'Nothing precompressed yet. The first scan starts shortly after Strata does.' : undefined,
    aux: {
      kicker: 'Precompression', title: 'Bytes saved · ' + rangeLabel(), series: C.series.saved,
      gauges: [
        gauge('Store · ' + fmt.n(br.files) + ' files', fmt.bytes(br.orig) + ' → ' + fmt.bytes(br.size), 100 - share(br.size, br.orig), 101),
        gauge('Responses compressed', fmt.pct(share(encReq, totReq)), share(encReq, totReq), 101),
        gauge('Saved on the wire', fmt.bytes(savedTot), share(savedTot, savedTot + (served.br?.b || 0)), 101),
        gauge('Not worth compressing', fmt.n(C.skipped) + ' files', share(C.skipped, C.skipped + (o.files || 0)), 101),
      ],
      logLabel: 'Encodings served · ' + rangeLabel(),
      log: (C.served || []).map((s) => ({ a: s.k === 'identity' ? 'none (already compressed media)' : s.k + (s.k === 'br' ? ' · precompressed' : ' · on the fly'), b: fmt.n(s.c) + ' · ' + fmt.bytes(s.b) }))
        .concat((C.savers || []).slice(0, 10).map((s) => ({ a: s.k, b: 'saved ' + fmt.bytes(s.saved) }))),
    },
  });
}

/* ---- settings */

const seg = (items, cur, act) => `<div class="seg-row">${items.map(([v, l]) =>
  `<button class="${String(cur) === String(v) ? 'on' : ''}" data-act="${act}" data-arg="${esc(v)}">${l}</button>`).join('')}</div>`;
const toggle = (on, act) => `<label class="sw" title="${on ? 'On' : 'Off'}"><input type="checkbox" data-change="${act}" ${on ? 'checked' : ''}><b></b></label>`;
const setRow = (title, desc, control) => `<div class="set-row"><div class="min-w0"><div class="h800">${esc(title)}</div>
  <div class="small dim">${esc(desc)}</div></div><div class="set-ctl">${control}</div></div>`;
function vSettings() {
  const pct = Math.round(S.scale * 100), eff = Math.round(zoomNow * 100);
  const L = D.live || {}, c = L.caddy || {}, t = L.tunnel || {}, db = L.db || {}, cs = L.compress || {};
  const row = setRow;
  const effNote = eff !== pct
    ? `Showing ${eff} % here: narrow screens always use 100 %.`
    : `Applied. ${Math.round(innerWidth / zoomNow)} px of layout fit in this window.`;
  const acc = S.accent || INST.accent || '#ec3013';
  const allViews = NAV_GROUPS.flatMap(([g, ids]) => ids.map((v) => [g, v]));
  const navRows = NAV_GROUPS.map(([g, ids]) => `<div class="cap gh">${esc(g)}</div>` + ids.map((v) => {
    const hid = (S.navHidden || []).includes(v), pin = (S.navPinned || []).includes(v);
    return `<span class="row">${icon(VIEWS[v][2], 'sm')}${esc(VIEWS[v][0])}</span>
      <button class="pill ${pin ? 'on' : ''}" data-act="navPin" data-arg="${v}" title="Pin to the top">${icon(pin ? 'star' : 'star-off', 'sm')}</button>
      <button class="pill ${hid ? '' : 'on'}" data-act="navHide" data-arg="${v}" title="${hid ? 'Hidden' : 'Shown'}">${icon(hid ? 'eye-off' : 'eye', 'sm')}</button>
      <button class="pill" data-act="navMove" data-arg="${v}|-1" title="Move up" ${pin ? '' : 'disabled'}>${icon('chevron-up', 'sm')}</button>
      <button class="pill" data-act="navMove" data-arg="${v}|1" title="Move down" ${pin ? '' : 'disabled'}>${icon('chevron-down', 'sm')}</button>`;
  }).join('')).join('');
  const vitalSlots = Array.from({ length: 8 }, (_, i) => `<select class="input" data-change="vitalSlot" data-arg="${i}">
    <option value="">— empty —</option>${Object.entries(VITALS).map(([k, [l]]) => `<option value="${k}" ${(S.vitals || [])[i] === k ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select>`).join('');
  const kbd = [['Ctrl K', 'Command palette'], ['?', 'This list'], ['/', 'Filter requests'], ['g then s r f u a n …', 'Go to a view (first letter)'],
    ['1 – 9', 'Switch views (sidebar order)'], ['[', 'Collapse / expand the sidebar'], ['T', 'Cycle light / dark / system theme'], [',', 'Settings'],
    ['I', 'Show / hide Infrastructure'], ['B', 'Include / exclude bots'], ['D', 'Deep fields'], ['Space', 'Pause sampling · Files: preview'],
    ['Esc', 'Close menu / inspector / preview'], ['Del · F2', 'Files: trash · rename'], ['Backspace', 'Files: parent folder'], ['Ctrl A · C · X · V', 'Files: select all · copy · cut · paste'], ['Ctrl V (image)', 'Files / Upload: upload from the clipboard']];
  return `<div class="settings" data-scroll="settings">
    <section class="panel span2">
      <div class="ph"><h5>${icon('palette')}Appearance</h5><span class="small dim">applies instantly · ${S.syncPrefs ? 'synced to your account' : 'remembered in this browser'}</span></div>
      ${row('Theme', 'System follows your device’s setting.', seg([['auto', icon('monitor', 'sm') + 'System'], ['light', icon('sun', 'sm') + 'Light'], ['dark', icon('moon', 'sm') + 'Dark']], S.theme, 'setTheme'))}
      ${row('Accent colour', 'Highlights and charts. Default: this site’s colour' + (INST.accent ? ' (' + INST.accent + ')' : '') + '.',
        `<span class="row gap-6">${ACCENTS.map(([c, n]) => `<button class="swatch ${acc.toLowerCase() === c ? 'on' : ''}" style="background:${c}" data-act="setAccent" data-arg="${c}" title="${esc(n)}"></button>`).join('')}
         <input type="color" class="input" data-change="accentPick" value="${esc(acc)}" title="Any colour"><button class="pill" data-act="setAccent" data-arg="" title="Back to this site's colour">${icon('rotate-ccw', 'sm')}Site default</button></span>`)}
      ${row('Density', 'Row height and padding.', seg([['compact', 'Compact'], ['normal', 'Normal'], ['comfy', 'Comfortable']], S.density, 'setDensity'))}
      ${row('Corners', 'Soft is the default.', seg([[0, 'Sharp'], [1, 'Soft'], [2, 'Round']], S.radius, 'setRadius'))}
      ${row('Typeface', 'Archivo is the default.', seg([['archivo', 'Archivo'], ['system', 'System'], ['mono', 'Mono']], S.font, 'setFont'))}
      ${row('Striped tables', 'Shade every other row.', toggle(S.zebra, 'setZebra'))}
      ${row('Reduce motion', 'Turn off animations.', toggle(S.reduceMotion, 'reduceMotion'))}
    </section>
    <section class="panel span2">
      <div class="ph"><h5>${icon('maximize-2')}Interface scale</h5><span class="small dim">default ${Math.round(SCALE_DEFAULT * 100)} %</span></div>
      <div class="scale-hero">
        <div><div class="big-num" id="scale-val">${pct} %</div><div class="small dim">${esc(effNote)}</div></div>
        <div class="scale-demo">Aa<span>Strata body text at the current size</span></div>
      </div>
      <div class="scale-ctl">
        <button class="pill" data-act="scaleStep" data-arg="-5" title="Smaller">−</button>
        <input type="range" id="scale-range" min="${SCALE_MIN * 100}" max="${SCALE_MAX * 100}" step="5" value="${pct}" aria-label="Interface scale in percent">
        <button class="pill" data-act="scaleStep" data-arg="5" title="Larger">+</button>
      </div>
      <div class="presets">${SCALE_PRESETS.map((p) => `<button class="pill ${Math.round(p * 100) === pct ? 'on' : ''}" data-act="setScale" data-arg="${p}">${Math.round(p * 100)} %${p === SCALE_DEFAULT ? ' · default' : ''}</button>`).join('')}</div>
    </section>
    <section class="panel">
      <div class="ph"><h5>${icon('panel-left')}Navigation</h5><span class="small dim">pin, hide and order the sidebar</span></div>
      ${row('Start in', 'View opened when the dashboard loads.', `<select class="input" data-change="setLanding"><option value="">last used</option>${allViews.map(([, v]) => `<option value="${v}" ${S.landing === v ? 'selected' : ''}>${esc(VIEWS[v][0])}</option>`).join('')}</select>`)}
      ${row('Collapsed sidebar', 'Icons only (toggle with [ ).', toggle(S.navCollapsed, 'setNavCollapsed'))}
      ${row('Show Infrastructure', 'Show the tunnel, network and system pages.', toggle(S.deep, 'setDeep'))}
      <div class="navcfg mt-8">${navRows}</div>
    </section>
    <section class="panel">
      <div class="ph"><h5>${icon('gauge')}Vitals strip</h5><span class="small dim">the traffic tiles above the traffic pages</span></div>
      ${row('Show everywhere', 'Show them on every page, not only traffic.', toggle(S.vitalsAll, 'setVitalsAll'))}
      <div class="form cols-2 mt-8">${vitalSlots}</div>
      <div class="act-row"><button class="pill" data-act="vitalsReset">${icon('rotate-ccw', 'sm')}Default six</button><button class="pill" data-act="vitalsNone">${icon('eye-off', 'sm')}Hide the strip</button></div>
    </section>
    <section class="panel">
      <div class="ph"><h5>${icon('refresh-cw')}Data & refresh</h5></div>
      ${row('Refresh rate', 'How often live numbers refresh.', seg(RATES.map((r) => [r, r < 1000 ? r + ' ms' : r / 1000 + ' s']), S.rate, 'setRate'))}
      ${row('Pause in background tabs', 'Stop refreshing while this tab is hidden.', toggle(S.hiddenPause, 'setHiddenPause'))}
      ${row('Default range', 'For charts and tables.', `<select class="input" data-change="setRangeSel">${RANGES.map(([k, l]) => `<option value="${k}" ${S.range === k ? 'selected' : ''}>${l}</option>`).join('')}</select>`)}
      ${row('Include bots in stats', 'Count scanners, crawlers and scripts in totals.', toggle(!S.nobots, 'setBots'))}
      ${row('Deep fields', 'Extra columns in the request log.', toggle(S.fields, 'setFields'))}
      ${row('Column widths', Object.keys(S.widths).length + ' customised column(s).', `<button class="pill" data-act="resetWidths" ${Object.keys(S.widths).length ? '' : 'disabled'}>Reset</button>`)}
    </section>
    <section class="panel">
      <div class="ph"><h5>${icon('clock')}Time & notifications</h5></div>
      ${row('24-hour clock', 'Otherwise 12-hour with AM / PM.', toggle(S.clock24, 'setClock24'))}
      ${row('Relative times', '“5 m ago” instead of the date and time.', toggle(S.relTimes, 'setRelTimes'))}
      ${row('Ask before deleting', 'Confirm before moving files to the trash.', toggle(S.confirmDelete, 'setConfirmDelete'))}
      ${row('Desktop notifications', 'When uploads finish and alerts arrive.', toggle(S.notify, 'setNotify'))}
    </section>
    <section class="panel">
      <div class="ph"><h5>${icon('save')}Preferences</h5></div>
      ${row('Sync to my account', 'Use these preferences in every browser.', toggle(S.syncPrefs, 'setSync'))}
      ${row('Export / import', 'Save or load them as a JSON file.', `<button class="pill" data-act="prefsExport">${icon('download', 'sm')}Export</button><button class="pill" data-act="prefsImport">${icon('upload', 'sm')}Import…</button>`)}
      ${row('Reset everything', 'Back to the defaults in this browser.', `<button class="pill danger" data-act="resetPrefs">${icon('rotate-ccw', 'sm')}Reset</button>`)}
    </section>
    <section class="panel">
      <div class="ph"><h5>${icon('server')}Session & system</h5></div>
      ${row('Signed in', `${L.user || '—'} · ${fmt.n(L.sessions)} active session(s)`, `<button class="pill" data-act="logout">${icon('log-out', 'sm')}Sign out</button>`)}
      <div class="kv px-0 pt-10 pb-0">
        <span>Site</span><span>${esc(INST.name || '—')} · instance ${esc(INST.id || '—')}</span>
        <span>Caddy</span><span>${esc(c.version || '—')} · ${c.up ? 'up ' + esc(fmt.dur(c.uptime)) : 'unreachable'}</span>
        <span>cloudflared</span><span>${esc(t.version || '—')} · ${t.up ? t.ha + '/4 links · up ' + esc(fmt.dur(t.uptime)) : 'unreachable'}</span>
        <span>Database</span><span>${fmt.n(db.rows)} requests · ${esc(fmt.bytes(db.size))} · since ${esc(fmt.dt(db.first))}</span>
        <span>Compression</span><span>${cs.running ? 'scanning now' : 'idle'} · variants: ${esc((cs.variants || []).join(', ') || '—')}</span>
        <span>Public page</span><span>${esc(INST.stats_host || '—')} (redacted feed only)</span>
      </div>
      <div class="act-row"><button class="btn btn-secondary" data-act="go" data-arg="system">${icon('cpu', 'sm')}System view</button></div>
    </section>
    <section class="panel span2">
      <div class="ph"><h5>${icon('keyboard')}Keyboard</h5><span class="small dim">outside text fields</span></div>
      <div class="kbd cols-k170">${kbd.map(([k, v]) => `<span><kbd>${esc(k)}</kbd></span><span>${esc(v)}</span>`).join('')}</div>
    </section>
    ${SETTINGS_PANELS.map((f) => { try { return f(row, toggle, seg); } catch (e) { return `<section class="panel"><div class="empty">${esc(e.message)}</div></section>`; } }).join('')}
  </div>`;
}

const VIEWFN = { settings: vSettings, summary: vSummary, requests: vRequests, content: vContent, visitors: vVisitors, insights: vInsights, tunnel: vTunnel, origins: vOrigins, compression: vCompression, security: vSecurity, latency: vLatency, history: vHistory, edge: vEdge };

/* ------------------------------------------------------------------ render loop */

let pointerDown = false, dragging = null;
let userScrollingUntil = 0;

function onUserScroll() {
  userScrollingUntil = Date.now() + 650;
}
window.addEventListener('wheel', onUserScroll, { passive: true });
window.addEventListener('touchmove', onUserScroll, { passive: true });
window.addEventListener('scroll', onUserScroll, { passive: true, capture: true });

function isUserScrolling() {
  return Date.now() < userScrollingUntil;
}
window.isUserScrolling = isUserScrolling;

function mainBusy() {
  if (pointerDown || dragging) return true;
  if (isUserScrolling()) return true;
  const sel = window.getSelection();
  return !!(sel && !sel.isCollapsed && $('#main').contains(sel.anchorNode));
}
let rafId = 0, rafForce = false;
function frame(force) { // coalesce pointer-driven redraws to one per animation frame
  rafForce = rafForce || !!force;
  if (!rafId) rafId = requestAnimationFrame(() => { const f = rafForce; rafId = 0; rafForce = false; render(f); });
}
const AFTER_RENDER = []; // modules push () => void (e.g. virtual lists fill their rows)

/* DOM reconciliation / morphing: dynamically refreshes assets in-place without destroying
   scroll containers, active momentum, or image/video elements, eliminating flicker and scroll disruption. */
function nodeKey(node) {
  if (!node || node.nodeType !== Node.ELEMENT_NODE) return null;
  // getAttribute, not className: on SVG elements className is an SVGAnimatedString (no .split) - that threw on every
  // icon, made each render fall back to innerHTML and re-created every icon on every poll (the flicker).
  const cls = (node.getAttribute('class') || '').trim().split(/\s+/)[0];
  return node.id ||
         node.dataset?.drag ||
         node.dataset?.arg2 ||
         node.dataset?.arg ||
         node.dataset?.scroll ||
         node.dataset?.act ||
         (cls ? node.tagName + '.' + cls : null);
}

/* Profile picture: the account's own image when it has one (`ver` = version tag from the server, so a new picture is a
   new URL), else its initial on an accent tile. Pictures are re-encoded server-side; colleagues in the office see them.
   `dot` adds the presence dot (online / idle / offline, from the heartbeat in office.js) in a cut-out corner. */
const PRESENCE_LABEL = { online: 'Online', idle: 'Idle', offline: 'Offline' };
function presenceOf(user) {
  const p = (D.presence || {})[user] || (D.presence || {})[String(user).toLowerCase()];
  return p && PRESENCE_LABEL[p.s] ? p : { s: 'offline', seen: null };
}
function avatar(user, ver, size = '', dot = false) {
  const u = String(user || '?');
  const pic = ver ? `<img class="av ${size}" src="/api/avatar?user=${enc(u)}&v=${enc(ver)}" alt="" width="40" height="40" decoding="async" loading="lazy">`
    : `<span class="av ${size}" aria-hidden="true">${esc(u.replace(/^api:/, '').slice(0, 1).toUpperCase())}</span>`;
  if (!dot) return pic;
  const p = presenceOf(u), label = PRESENCE_LABEL[p.s] + (p.s === 'offline' && p.seen ? ' · last seen ' + fmt.ago(p.seen) : '');
  return `<span class="avw ${size} ps-${p.s}" title="${esc(label)}">${pic}<i class="pdot" role="img" aria-label="${esc(label)}"></i></span>`;
}

/* Update a persistent region (sidebar, header, vitals, footer) in place. Unchanged markup is a no-op; changed markup is
   morphed, so buttons survive a live refresh - a click whose button was replaced between pointerdown and pointerup
   never fires, which made sidebar / header icons randomly ignore clicks. */
function patch(el, html) {
  if (!el || el._html === html) return;
  el._html = html;
  if (!el.firstChild) { el.innerHTML = html; return; }
  const t = document.createElement('template');
  t.innerHTML = html;
  try { morphChildren(el, t.content); } catch (e) { console.error('patch failed', e); el.innerHTML = html; }
}

function nodesMatch(a, b) {
  if (a.nodeType !== b.nodeType) return false;
  if (a.nodeType === Node.TEXT_NODE) return true;
  if (a.nodeType === Node.ELEMENT_NODE) {
    if (a.tagName !== b.tagName) return false;
    const keyA = nodeKey(a);
    const keyB = nodeKey(b);
    if (keyA && keyB) return keyA === keyB;
    return true;
  }
  return false;
}

function morphNode(oldNode, newNode) {
  if (oldNode.nodeType === Node.TEXT_NODE) {
    if (newNode.nodeType === Node.TEXT_NODE && oldNode.textContent !== newNode.textContent) {
      oldNode.textContent = newNode.textContent;
    }
    return;
  }
  if (oldNode.nodeType !== Node.ELEMENT_NODE || newNode.nodeType !== Node.ELEMENT_NODE) return;

  // 1. Sync attributes
  const oldAttrs = oldNode.attributes;
  const newAttrs = newNode.attributes;
  for (let i = 0; i < newAttrs.length; i++) {
    const attr = newAttrs[i];
    if (oldNode.getAttribute(attr.name) !== attr.value) {
      oldNode.setAttribute(attr.name, attr.value);
    }
  }
  for (let i = oldAttrs.length - 1; i >= 0; i--) {
    const attr = oldAttrs[i];
    if (!newNode.hasAttribute(attr.name)) {
      oldNode.removeAttribute(attr.name);
    }
  }

  // 2. Form controls & media: update without losing focus, state, or re-decoding images
  const isInput = oldNode.tagName === 'INPUT' || oldNode.tagName === 'TEXTAREA';
  if (isInput) {
    if (oldNode !== document.activeElement && oldNode.value !== newNode.value) {
      oldNode.value = newNode.value;
    }
    if ((oldNode.type === 'checkbox' || oldNode.type === 'radio') && oldNode.checked !== newNode.checked) {
      oldNode.checked = newNode.checked;
    }
  } else if (oldNode.tagName === 'SELECT') {
    if (oldNode !== document.activeElement && oldNode.value !== newNode.value) {
      oldNode.value = newNode.value;
    }
  } else if (oldNode.tagName === 'IMG') {
    if (oldNode.getAttribute('src') !== newNode.getAttribute('src')) {
      oldNode.setAttribute('src', newNode.getAttribute('src') || '');
    }
  } else if (oldNode.tagName === 'IFRAME' || oldNode.tagName === 'VIDEO' || oldNode.tagName === 'AUDIO') {
    if (oldNode.getAttribute('src') !== newNode.getAttribute('src')) {
      oldNode.setAttribute('src', newNode.getAttribute('src') || '');
    }
  }

  // 3. Reconcile children
  morphChildren(oldNode, newNode);
}

function morphChildren(oldParent, newParent) {
  const newChildren = Array.from(newParent.childNodes);
  const oldChildren = Array.from(oldParent.childNodes);

  if (!oldChildren.length && !newChildren.length) return;
  if (!oldChildren.length) {
    for (const nc of newChildren) oldParent.appendChild(nc.cloneNode(true));
    return;
  }
  if (!newChildren.length) {
    oldParent.textContent = '';
    return;
  }

  const oldKeyMap = new Map();
  for (let i = 0; i < oldChildren.length; i++) {
    const k = nodeKey(oldChildren[i]);
    if (k && !oldKeyMap.has(k)) oldKeyMap.set(k, oldChildren[i]);
  }

  for (let newIndex = 0; newIndex < newChildren.length; newIndex++) {
    const newChild = newChildren[newIndex];
    const k = nodeKey(newChild);
    let curOld = oldParent.childNodes[newIndex];

    let match = null;
    if (k && oldKeyMap.has(k)) {
      match = oldKeyMap.get(k);
      oldKeyMap.delete(k);
    } else if (curOld && nodesMatch(curOld, newChild)) {
      match = curOld;
      const curK = nodeKey(curOld);
      if (curK) oldKeyMap.delete(curK);
    }

    if (match) {
      if (match !== curOld) {
        oldParent.insertBefore(match, curOld);
      }
      morphNode(match, newChild);
    } else {
      oldParent.insertBefore(newChild.cloneNode(true), curOld || null);
    }
  }

  while (oldParent.childNodes.length > newChildren.length) {
    oldParent.removeChild(oldParent.lastChild);
  }
}

function render(force) {
  renderNav(); renderHeader(); renderVitals(); renderFooter();
  if (!force && mainBusy()) return;
  // views with form controls only redraw when something changes (render(true)), not on every poll
  if (!force && STATIC_VIEWS.has(S.view) && $('#main').dataset.view === S.view) return;
  const keep = {};
  document.querySelectorAll('[data-scroll]').forEach((el) => { keep[el.dataset.scroll] = [el.scrollTop, el.scrollLeft]; });
  const ae = document.activeElement;
  const keepId = ae && ae.id && $('#main').contains(ae) ? ae.id : null;
  const caret = keepId && typeof ae.selectionStart === 'number' ? [ae.selectionStart, ae.selectionEnd] : null;

  const viewChanged = $('#main').dataset.view !== S.view;
  $('#main').dataset.view = S.view;
  let html;
  try { html = (VIEWFN[S.view] || vSummary)(); } catch (e) { html = `<div class="setup"><h5 class="hot">This view failed to draw</h5><pre class="code">${esc(e.stack || e.message)}</pre></div>`; console.error(e); }

  if (viewChanged || !$('#main').firstElementChild) {
    $('#main').innerHTML = html;
  } else {
    try {
      const tmpl = document.createElement('template');
      tmpl.innerHTML = html.trim();
      morphChildren($('#main'), tmpl.content);
    } catch (err) {
      console.warn('DOM morph failed, falling back to innerHTML:', err);
      $('#main').innerHTML = html;
    }
  }

  if (keepId) {
    const el = document.getElementById(keepId);
    if (el) { el.focus(); if (caret) { try { el.setSelectionRange(caret[0], caret[1]); } catch { /* not a text field */ } } }
  }
  document.querySelectorAll('[data-scroll]').forEach((el) => {
    const k = keep[el.dataset.scroll];
    if (k && (el.scrollTop !== k[0] || el.scrollLeft !== k[1])) {
      el.scrollTop = k[0];
      el.scrollLeft = k[1];
    }
  });
  for (const f of AFTER_RENDER) { try { f(); } catch (e) { console.error(e); } }
}
function renderOverlay() {
  let html = '';
  if (S.menu) {
    const m = S.menu;
    html += `<div class="scrim" data-act="closeMenu"><div class="menu" style="left:${m.x}px;top:${m.y}px" data-act="noop">
      <div class="mh"><div class="cap">${esc(m.kicker)}</div><div>${esc(m.title)}</div></div>
      ${m.items.map((it, i) => `<button class="${it.sep ? 'sep' : ''} ${it.danger ? 'danger' : ''}" data-act="menuItem" data-arg="${i}"><span class="lbl ell">${it.icon ? icon(it.icon, 'sm') : ''}<span class="ell">${esc(it.label)}</span></span><small>${esc(it.hint || '')}</small></button>`).join('')}
    </div></div>`;
  }
  if (S.palette) {
    const cmds = paletteCmds();
    S.palIdx = Math.min(S.palIdx, Math.max(0, cmds.length - 1));
    let lastGroup = null;
    html += `<div class="palbg" data-act="closePalette"><div class="pal" data-act="noop">
      <div class="pin">${icon('search')}<input id="pq" value="${esc(S.pq)}" placeholder="Go to, run, find a file…" autocomplete="off" spellcheck="false"><kbd>Esc</kbd></div>
      <div class="list">${cmds.map((c, i) => {
        const g = c.group !== lastGroup ? `<div class="cap grp">${esc(c.group || '')}</div>` : '';
        lastGroup = c.group;
        return g + `<button class="${i === S.palIdx ? 'hi' : ''}" data-act="palRun" data-arg="${i}"><span class="lbl">${icon(c.icon || 'chevron-right', 'sm')}<span class="ell">${c.hl || esc(c.label)}</span></span><small>${esc(c.hint || '')}</small></button>`;
      }).join('') || '<div class="empty">Nothing matches.</div>'}</div>
    </div></div>`;
  }
  if (S.dialog) {
    const d = S.dialog;
    html += `<div class="palbg" data-act="dlgCancel"><div class="dlg" data-act="noop" role="dialog" aria-modal="true">
      <div class="body"><div class="cap ${d.danger ? 'red' : ''}">${esc(d.kicker || '')}</div><h4>${esc(d.title || '')}</h4>
        ${d.text ? `<p>${esc(d.text)}</p>` : ''}${d.html || ''}${d.input != null ? `<input id="dlgin" class="input" value="${esc(d.input)}" autocomplete="off" spellcheck="false">` : ''}
        ${d.check ? `<label class="dlg-check"><input type="checkbox" id="dlgchk" ${d.checkDefault ? 'checked' : ''}> ${esc(d.check)}</label>` : ''}</div>
      <div class="acts"><button class="btn ${d.danger ? 'btn-primary' : 'btn-primary'}" data-act="dlgOk">${esc(d.ok || 'OK')}</button>
        ${d.alt ? `<button class="btn btn-secondary" data-act="dlgAlt">${esc(d.alt)}</button>` : ''}
        <div class="fill"></div><button class="btn btn-secondary" data-act="dlgCancel">Cancel</button></div></div></div>`;
  }
  if (S.help) {
    html += `<div class="palbg" data-act="helpClose"><div class="dlg w-560" data-act="noop"><div class="body"><div class="cap">Keyboard</div><h4>Shortcuts</h4>
      <div class="kbd cols-k150">${[['Ctrl K', 'Command palette'], ['/', 'Filter requests'], ['g + letter', 'Go to view: s summary · r requests · c content · v visitors · i insights · f files · u upload · a analyze · e serving · b blocklist · l links · n network · t tunnel · y system · x settings'],
        ['1 – 9', 'Views in sidebar order'], ['[', 'Sidebar'], ['T', 'Theme'], ['Space', 'Pause · Files: preview'], ['Esc', 'Close'], ['Del · F2 · Backspace', 'Files: trash · rename · up'], ['Ctrl V', 'Paste images to upload']].map(([k, v]) => `<span><kbd>${esc(k)}</kbd></span><span>${esc(v)}</span>`).join('')}</div></div>
      <div class="acts"><div class="fill"></div><button class="btn btn-secondary" data-act="helpClose">Close</button></div></div></div>`;
  }
  for (const f of OVERLAYS) { try { html += f() || ''; } catch (e) { console.error(e); } }
  if (S.dragOver) html += `<div class="drop"><div>${icon('upload', 'lg')}Drop to upload into ${esc(typeof dropLabel === 'function' ? dropLabel() : S.fpath)}</div></div>`;
  const dlgFocus = S.dialog && !$('#dlgin');
  const had = document.activeElement && document.activeElement.id === 'pq';
  const pos = had ? document.activeElement.selectionStart : null;
  $('#overlay').innerHTML = html;
  const pq = $('#pq');
  if (pq) { pq.focus(); if (pos != null) pq.setSelectionRange(pos, pos); else pq.select(); }
  const di = $('#dlgin');
  if (di && dlgFocus) {
    di.focus();
    const dot = di.value.lastIndexOf('.');
    di.setSelectionRange(0, dot > 0 ? dot : di.value.length); // select the name, not the extension
  } else if (dlgFocus) { const b = document.querySelector('.dlg [data-act="dlgOk"]'); if (b) b.focus(); }
}

/* toasts: note(msg) or note(msg, {err, ms, action: {label, run}}) - a stack in the corner, with an optional button */
let toastSeq = 0;
const TOASTS = new Map();
function note(msg, o = {}) {
  const id = ++toastSeq;
  const el = document.createElement('div');
  el.className = 'toast' + (o.err || /^(error|failed|cannot|could not)/i.test(String(msg)) ? ' err' : '');
  el.innerHTML = `<span>${esc(msg)}</span>${o.action ? `<button class="tb">${esc(o.action.label)}</button>` : ''}<button class="tx" title="Dismiss">${icon('x', 'sm')}</button>`;
  const close = () => { if (!TOASTS.has(id)) return; TOASTS.delete(id); el.remove(); };
  if (o.action) el.querySelector('.tb').onclick = () => { close(); o.action.run(); };
  el.querySelector('.tx').onclick = close;
  const box = $('#toasts');
  box.appendChild(el);
  TOASTS.set(id, el);
  while (TOASTS.size > 5) { const [k, v] = TOASTS.entries().next().value; TOASTS.delete(k); v.remove(); }
  setTimeout(close, o.ms || (o.action ? 9000 : 4000));
  return close;
}
function notifyDesktop(title, body) {
  if (!S.notify || !('Notification' in window) || Notification.permission !== 'granted' || document.visibilityState === 'visible') return;
  try { new Notification(title, { body, icon: '/favicon.ico' }); } catch { /* not allowed */ }
}
async function copy(text, what) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    try { await navigator.clipboard.writeText(text); note('Copied ' + what); return; } catch (e) { /* fall back */ }
  }
  try {
    const el = document.createElement('textarea');
    el.value = text;
    el.setAttribute('readonly', '');
    el.style.position = 'absolute';
    el.style.left = '-9999px';
    document.body.appendChild(el);
    el.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(el);
    note(ok ? 'Copied ' + what : 'Clipboard unavailable');
  } catch (e) {
    note('Clipboard unavailable');
  }
}

/* ------------------------------------------------------------------ actions */

function go(view) {
  if (!VIEWS[view] || !VIEWFN[view]) return;
  auditView(view);
  if (NAV2.includes(view)) S.deep = true;
  S.view = view; S.menu = null; S.palette = false;
  persist(); renderOverlay(); render(true); refreshForView();
}
function setRange(r) {
  S.range = r; persist(); render(); pollStats();
  if (S.view === 'insights') pollInsights();
  if (S.view === 'compression') pollCompression();
}
function showRequests(patch) {
  Object.assign(S, { scope: 'all', sel: null, selRow: null }, patch);
  D.req = null;
  $('#q').value = S.q;
  go('requests');
}
function openUrl(host, path) {
  if (!/^[a-z0-9.-]+$/i.test(host) || !String(path).startsWith('/')) return;
  window.open('https://' + host + path, '_blank', 'noopener');
}
function setPref(k, v, full = true) { S[k] = v; persist(); applyAppearance(); applyScale(); render(full); }
const ACT = {
  noop() {},
  go,
  range: setRange,
  deep() { S.deep = !S.deep; if (!S.deep && NAV2.includes(S.view)) S.view = 'summary'; persist(); render(true); },
  bots() { S.nobots = !S.nobots; persist(); render(); pollStats(); note(S.nobots ? 'Bots excluded from aggregate stats' : 'Bots included in aggregate stats'); },
  pause() { S.paused = !S.paused; render(); if (!S.paused) { pollStats(); pollRequests(true); } },
  fields() { S.fields = !S.fields; persist(); render(); },
  cycleRate() {
    if (S.paused) { S.paused = false; render(); return; }
    S.rate = RATES[(RATES.indexOf(S.rate) + 1) % RATES.length]; persist(); render(); note('Refreshing every ' + S.rate + ' ms');
  },
  themeCycle() { const order = ['auto', 'light', 'dark']; setPref('theme', order[(order.indexOf(S.theme) + 1) % 3]); note('Theme: ' + ({ auto: 'follows the system', light: 'light', dark: 'dark' }[S.theme])); },
  navCollapse() { setPref('navCollapsed', !S.navCollapsed); },
  help() { S.help = true; renderOverlay(); },
  helpClose(_, el, e) { if (!e || e.target === el || el.dataset.act === 'helpClose') { S.help = false; renderOverlay(); } },
  siteMenu(_, el, e) { const m = MENUS.site(); const r = el.getBoundingClientRect(); S.menu = Object.assign(m, { x: r.left / zoomNow, y: r.bottom / zoomNow + 4 }); renderOverlay(); },
  openSibling(url) { window.open(String(url).replace('{host}', location.hostname), '_blank', 'noopener'); },
  scope(k) { S.scope = k; D.req = null; render(); pollRequests(true); },
  sort(arg) { const [key, s] = arg.split(':'); S.sort[key] = s; render(true); },
  tab(arg) { const [view, t] = arg.split(':'); S.tab[view] = t; render(true); },
  selReq(id) {
    id = +id;
    if (S.sel === id) { S.sel = null; S.selRow = null; render(); return; }
    const row = (D.req?.rows || []).find((r) => r.id === id);
    if (!row) return;
    S.sel = id; S.selRow = row; render(); loadIp(row.ip);
  },
  closeIns() { S.sel = null; S.selRow = null; render(); },
  insTab(t) { S.insTab = t; render(); },
  openReq() { if (S.selRow) openUrl(S.selRow.host, S.selRow.path); },
  filterIp(ip) { showRequests({ ipFilter: ip, q: '' }); },
  filterPath(p) { showRequests({ q: p, ipFilter: '' }); },
  filterText(t) { showRequests({ q: t, ipFilter: '' }); },
  filterCountry(cc) { S.rf = Object.assign({}, S.rf, { country: cc }); showRequests({ q: '', ipFilter: '' }); },
  filterHost(h) { S.rf = Object.assign({}, S.rf, { host: h }); showRequests({ q: '', ipFilter: '' }); },
  clearIp() { S.ipFilter = ''; D.req = null; render(); pollRequests(true); },
  clearQ() { S.q = ''; $('#q').value = ''; D.req = null; render(); pollRequests(true); },
  rfClear() { Object.keys(S.rf).forEach((k) => { S.rf[k] = ''; }); D.req = null; render(true); pollRequests(true); },
  async rfSave() {
    const name = await ask({ kicker: 'Save filter', title: 'Name this filter', input: S.q || S.rf.status || 'my filter', ok: 'Save' });
    if (!name) return;
    S.savedFilters = (S.savedFilters || []).concat([{ name: name.slice(0, 30), q: S.q, scope: S.scope, ip: S.ipFilter, rf: Object.assign({}, S.rf) }]).slice(-12);
    persist(); render(true); note('Saved filter “' + name + '”');
  },
  rfLoad(i) {
    const f = (S.savedFilters || [])[+i]; if (!f) return;
    S.rf = Object.assign({ status: '', method: '', host: '', country: '', kind: '', since: '', min_ms: '' }, f.rf || {});
    showRequests({ q: f.q || '', scope: f.scope || 'all', ipFilter: f.ip || '' });
  },
  loadOlder,
  reqLive() { D.req = null; render(true); pollRequests(true); },
  exportReq(kind) {
    const rows = D.req?.rows || [];
    if (!rows.length) return note('Nothing loaded to export');
    const stamp = new Date().toISOString().slice(0, 16).replace(/[:T]/g, '-');
    if (kind === 'json') return saveFile(`requests-${stamp}.json`, JSON.stringify(rows, null, 1), 'application/json');
    const cols = ['id', 'ts', 'host', 'method', 'path', 'status', 'bytes', 'dur', 'ip', 'country', 'colo', 'agent', 'kind', 'os', 'ref', 'ctype', 'enc', 'sus', 'ua'];
    const q = (v) => { v = String(v ?? ''); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
    saveFile(`requests-${stamp}.csv`, [cols.join(',')].concat(rows.map((r) => cols.map((c) => q(c === 'ts' ? new Date(r.ts * 1000).toISOString() : r[c])).join(','))).join('\n'));
  },
  exportTable(key) { const csv = tableCsv(key); if (!csv) return note('Nothing to export'); saveFile(key + '.csv', csv); },
  edgeRetry() { D.edge = null; render(); pollEdge(true); },
  // settings
  setScale(v) { S.scale = clampScale(+v); applyScale(); persist(); render(true); },
  scaleStep(d) { ACT.setScale(S.scale + (+d) / 100); },
  reduceMotion(v) { setPref('reduceMotion', !!v); },
  setTheme(v) { setPref('theme', v); },
  setAccent(v) { setPref('accent', v || null); },
  accentPick(v) { setPref('accent', v); },
  setDensity(v) { setPref('density', v); },
  setRadius(v) { setPref('radius', +v); },
  setFont(v) { setPref('font', v); },
  setZebra(v) { setPref('zebra', !!v); },
  setLanding(v) { setPref('landing', v); },
  setNavCollapsed(v) { setPref('navCollapsed', !!v); },
  setRate(v) { S.rate = +v; persist(); render(true); },
  setRangeSel(v) { setRange(v); render(true); },
  setBots(v) { S.nobots = !v; persist(); pollStats(); render(true); },
  setDeep(v) { S.deep = !!v; persist(); render(true); },
  setFields(v) { S.fields = !!v; persist(); render(true); },
  setHiddenPause(v) { setPref('hiddenPause', !!v); },
  setVitalsAll(v) { S.vitalsAll = !!v; persist(); render(true); },
  setClock24(v) { setPref('clock24', !!v); },
  setRelTimes(v) { setPref('relTimes', !!v); },
  setConfirmDelete(v) { setPref('confirmDelete', !!v); },
  async setNotify(v) {
    if (v && 'Notification' in window && Notification.permission !== 'granted') {
      const p = await Notification.requestPermission().catch(() => 'denied');
      if (p !== 'granted') { note('This browser refused notifications'); return render(true); }
    }
    setPref('notify', !!v);
  },
  async setSync(v) { S.syncPrefs = !!v; persist(); if (v) { await pushPrefs(); note('Preferences now sync to your account'); } render(true); },
  vitalSlot(v, el) { const i = +el.dataset.arg; const list = (S.vitals || []).slice(); while (list.length <= i) list.push(''); list[i] = v; S.vitals = list.filter(Boolean); persist(); render(true); },
  vitalsReset() { S.vitals = PREFS.vitals.slice(); persist(); render(true); },
  vitalsNone() { S.vitals = []; persist(); render(true); },
  navPin(v) { const p = new Set(S.navPinned || []); p.has(v) ? p.delete(v) : p.add(v); S.navPinned = [...p]; persist(); render(true); },
  navHide(v) { const h = new Set(S.navHidden || []); h.has(v) ? h.delete(v) : h.add(v); S.navHidden = [...h]; persist(); render(true); },
  navMove(arg) {
    const [v, d] = arg.split('|'); const p = (S.navPinned || []).slice(); const i = p.indexOf(v), j = i + (+d);
    if (i < 0 || j < 0 || j >= p.length) return; [p[i], p[j]] = [p[j], p[i]]; S.navPinned = p; persist(); render(true);
  },
  resetWidths() { S.widths = {}; persist(); note('Column widths reset'); render(true); },
  prefsExport() { saveFile('strata-preferences.json', JSON.stringify(prefsSnapshot(), null, 2), 'application/json'); },
  prefsImport() {
    const inp = document.createElement('input'); inp.type = 'file'; inp.accept = '.json,application/json';
    inp.onchange = async () => {
      try { const o = JSON.parse(await inp.files[0].text()); Object.entries(o).forEach(([k, v]) => { if (k in PREFS) S[k] = v; }); persist(); applyScale(); applyAppearance(); render(true); note('Preferences imported'); } catch (e) { note('Not a Strata preferences file', { err: true }); }
    };
    inp.click();
  },
  async resetPrefs() {
    const ok = await ask({ kicker: 'Reset preferences', title: 'Reset every Strata preference in this browser?', ok: 'Reset', text: 'Everything on the Settings page goes back to its default. Only this browser changes.' });
    if (!ok) return;
    try { Object.keys(localStorage).filter((k) => k.startsWith('strata:')).forEach((k) => localStorage.removeItem(k)); } catch { /* ignore */ }
    if (S.syncPrefs) { try { await post('/api/prefs', { prefs: {}, ts: Date.now() / 1000 }); } catch { /* ignore */ } }
    location.reload();
  },
  async logout() {
    try { await fetch('/logout', { method: 'POST', credentials: 'same-origin', headers: { 'X-Strata': '1' } }); } finally { location.href = '/login'; }
  },
  async compressRun() {
    try { await post('/api/compress/run'); note('Compression scan queued'); setTimeout(pollCompression, 1500); } catch (e) { note(e.message, { err: true }); }
  },
  dlgOk() {
    const d = S.dialog; if (!d) return;
    const v = d.input != null ? ($('#dlgin')?.value ?? '') : true;
    const c = d.check ? !!$('#dlgchk')?.checked : undefined;
    S.dialog = null; renderOverlay();
    d.resolve(d.check ? { value: v, checked: c } : v);
  },
  dlgCancel(_, el, e) { if (e && el && e.target !== el && el.classList.contains('palbg')) return; const d = S.dialog; S.dialog = null; renderOverlay(); if (d) d.resolve(null); },
  dlgAlt() { const d = S.dialog; if (!d) return; S.dialog = null; renderOverlay(); d.resolve('alt'); },
  palette() { S.palette = true; S.pq = ''; S.palIdx = 0; S.menu = null; D.palFiles = null; renderOverlay(); },
  closePalette(_, el, e) { if (e.target === el) { S.palette = false; renderOverlay(); } },
  palRun(i) {
    const c = paletteCmds()[+i]; S.palette = false; renderOverlay();
    if (!c) return;
    if (c.label) S.palRecent = [c.label].concat((S.palRecent || []).filter((x) => x !== c.label)).slice(0, 8);
    persist(); c.run();
  },
  closeMenu(_, el, e) { if (e.target === el) { S.menu = null; renderOverlay(); } },
  menuItem(i) { const it = S.menu && S.menu.items[+i]; S.menu = null; renderOverlay(); if (it && it.run) it.run(); },
};

function ask(o) {
  return new Promise((resolve) => { S.dialog = Object.assign({}, o, { resolve }); S.menu = null; renderOverlay(); });
}

/* ------------------------------------------------------------------ context menus + palette */

const item = (label, hint, run, o = {}) => ({ label, hint, run, sep: o.sep, danger: o.danger, icon: o.icon });
const MENUS = {
  req(id) {
    const r = (D.req?.rows || []).find((x) => x.id === +id);
    if (!r) return null;
    return { kicker: 'Request · ' + r.status, title: r.path, items: [
      item('Inspect', '↵', () => { if (S.sel !== r.id) ACT.selReq(r.id); }, { icon: 'eye' }),
      item('Only this client', r.ip, () => ACT.filterIp(r.ip), { icon: 'user' }),
      item('Only this path', '', () => ACT.filterPath(r.path), { icon: 'file-text' }),
      item('Open in new tab', '', () => openUrl(r.host, r.path), { sep: true, icon: 'external-link' }),
      item('Copy URL', '', () => copy('https://' + r.host + r.path, 'URL'), { icon: 'copy' }),
      item('Copy client IP', '', () => copy(r.ip, r.ip), { icon: 'copy' }),
      item('Copy row as JSON', '', () => copy(JSON.stringify(r, null, 2), 'row as JSON'), { icon: 'file-braces' }),
    ] };
  },
  ip(ip) {
    return { kicker: 'Client', title: ip, items: [
      item('Show its requests', '', () => ACT.filterIp(ip), { icon: 'activity' }),
      item('Copy IP', '', () => copy(ip, ip), { icon: 'copy' }),
      item('Look up on AbuseIPDB', '↗', () => window.open('https://www.abuseipdb.com/check/' + enc(ip), '_blank', 'noopener'), { sep: true, icon: 'external-link' }),
      item('Copy Cloudflare WAF expression', '', () => copy(`(ip.src eq ${ip})`, 'WAF expression'), { icon: 'shield' }),
    ] };
  },
  path(p, host) {
    return { kicker: 'Path', title: p, items: [
      item('Show requests for this path', '', () => ACT.filterPath(p), { icon: 'activity' }),
      item('Open in new tab', '', () => openUrl(host || cdnHost(), p), { icon: 'external-link' }),
      item('Copy URL', '', () => copy('https://' + (host || cdnHost()) + p, 'URL'), { sep: true, icon: 'copy' }),
      item('Copy path', '', () => copy(p, 'path'), { icon: 'copy' }),
      item('Reveal in Files', '', () => { if (typeof ACT.fgoFile === 'function') ACT.fgoFile(decodeURIComponent(p)); }, { icon: 'folder-open' }),
    ] };
  },
  colo(c) {
    return { kicker: 'Cloudflare edge', title: c + ' · ' + coloName(c), items: [
      item('Filter requests via ' + c, '', () => { S.rf = Object.assign({}, S.rf, {}); showRequests({ q: c, ipFilter: '' }); }, { icon: 'funnel' }),
      item('Open Tunnel', '', () => go('tunnel'), { icon: 'cable' }),
    ] };
  },
  conn(c) { return MENUS.colo(String(c || '').slice(0, 3).toUpperCase()); },
  origin(h) {
    return { kicker: 'Ingress', title: h, items: [
      item('Open https://' + h, '↗', () => openUrl(h, '/'), { icon: 'external-link' }),
      item('Copy hostname', '', () => copy(h, h), { icon: 'copy' }),
      item('Edit ingress', '', () => go('network'), { icon: 'pencil' }),
    ] };
  },
  table(key) {
    return { kicker: 'Table', title: key, items: [
      item('Copy as CSV', '', () => copy(tableCsv(key), 'table as CSV'), { icon: 'clipboard-copy' }),
      item('Download CSV', '', () => ACT.exportTable(key), { icon: 'download' }),
      item('Reset column widths', '', () => { Object.keys(S.widths).filter((k) => k.startsWith(key + ':')).forEach((k) => delete S.widths[k]); persist(); render(true); }, { sep: true, icon: 'rotate-ccw' }),
    ] };
  },
  navitem(v) {
    const pin = (S.navPinned || []).includes(v);
    return { kicker: 'Sidebar', title: VIEWS[v][0], items: [
      item('Open', '', () => go(v), { icon: VIEWS[v][2] }),
      item(pin ? 'Unpin' : 'Pin to the top', '', () => ACT.navPin(v), { icon: pin ? 'star-off' : 'star' }),
      v !== 'settings' ? item('Hide from the sidebar', '', () => { ACT.navHide(v); note(VIEWS[v][0] + ' hidden · Settings › Navigation brings it back'); }, { icon: 'eye-off' }) : null,
      item(S.navCollapsed ? 'Expand the sidebar' : 'Collapse the sidebar', '[', () => ACT.navCollapse(), { sep: true, icon: 'panel-left' }),
    ].filter(Boolean) };
  },
  savedFilter(i) {
    const f = (S.savedFilters || [])[+i];
    if (!f) return null;
    return { kicker: 'Saved filter', title: f.name, items: [
      item('Apply', '', () => ACT.rfLoad(i), { icon: 'funnel' }),
      item('Delete', '', () => { S.savedFilters.splice(+i, 1); persist(); render(true); }, { danger: true, icon: 'trash' }),
    ] };
  },
  site() {
    return { kicker: 'Strata · ' + (INST.id || 'instance'), title: INST.name || location.host, items: [
      ...(INST.siblings || []).map((s) => item('Open ' + s.name, '↗', () => ACT.openSibling(s.url), { icon: 'external-link' })),
      item('Instance & system', '', () => go('system'), { sep: !!(INST.siblings || []).length, icon: 'cpu' }),
      item('Network & tunnel', '', () => go('network'), { icon: 'globe' }),
      item('Appearance', '', () => go('settings'), { icon: 'palette' }),
    ] };
  },
  graph(title) { return appMenu('Graph', title); },
  vital(key) {
    return { kicker: 'Vital', title: key, items: [
      item('Open Requests', '', () => go('requests'), { icon: 'activity' }),
      item('Open History', '', () => go('history'), { icon: 'clock-fading' }),
      item('Customise the strip…', '', () => go('settings'), { icon: 'sliders-horizontal' }),
      item(S.paused ? 'Resume sampling' : 'Freeze sampling', 'space', () => ACT.pause(), { sep: true, icon: S.paused ? 'play' : 'pause' }),
      item('Refresh rate…', S.rate + ' ms', () => ACT.cycleRate(), { icon: 'refresh-cw' }),
    ] };
  },
  traffic() {
    return { kicker: 'Traffic panel', title: S.range === 'live' ? 'Live · 5 minutes' : rangeLabel(), items: RANGES.map(([k, l]) => item(l + (S.range === k ? '  ·  current' : ''), '', () => setRange(k)))
      .concat([item('Copy series as CSV', '', () => copySeries(), { sep: true, icon: 'clipboard-copy' }), item(S.paused ? 'Resume sampling' : 'Freeze sampling', 'space', () => ACT.pause(), { icon: 'pause' })]) };
  },
  rate() {
    return { kicker: 'Refresh rate', title: 'Currently ' + S.rate + ' ms', items: RATES.map((r, i) => item(r + ' ms' + (r === S.rate ? '  ·  current' : ''), i === 0 ? 'fastest' : i === RATES.length - 1 ? 'calmest' : '', () => { S.rate = r; persist(); render(); })) };
  },
};
function appMenu(kicker = 'Strata', title = INST.name || 'CDN Monitor') {
  return { kicker, title, items: [
    item('Summary', 'g s', () => go('summary'), { icon: 'layout-dashboard' }), item('Requests', 'g r', () => go('requests'), { icon: 'activity' }), item('Files', 'g f', () => go('files'), { icon: 'folder-open' }),
    item(S.deep ? 'Hide infrastructure' : 'Show infrastructure', 'I', () => ACT.deep(), { sep: true, icon: 'gauge' }),
    item(S.nobots ? 'Include bots in stats' : 'Exclude bots from stats', 'B', () => ACT.bots(), { icon: 'bot' }),
    item(S.paused ? 'Resume sampling' : 'Freeze sampling', 'space', () => ACT.pause(), { icon: S.paused ? 'play' : 'pause' }),
    item('Theme: ' + S.theme, 'T', () => ACT.themeCycle(), { icon: 'palette' }),
    item('Copy snapshot as JSON', '', () => copy(JSON.stringify({ live: D.live, stats: D.stats?.totals }, null, 2), 'snapshot'), { sep: true, icon: 'clipboard-copy' }),
  ] };
}
function copySeries() {
  const src = S.range === 'live' ? D.live?.series : D.stats?.series;
  if (!src) return;
  const lines = ['time,requests,bytes,errors'].concat(src.reqs.map((v, i) => `${new Date((src.t0 + i * src.step) * 1000).toISOString()},${v},${src.bytes[i]},${src.e4[i] + src.e5[i]}`));
  copy(lines.join('\n'), src.reqs.length + ' rows as CSV');
}
// fuzzy match: every query character in order; score prefers word starts and contiguous runs
function fuzzy(q, s) {
  if (!q) return { score: 0, hl: esc(s) };
  const lq = q.toLowerCase(), ls = s.toLowerCase();
  let qi = 0, score = 0, last = -2, out = '';
  for (let i = 0; i < s.length; i++) {
    if (qi < lq.length && ls[i] === lq[qi]) {
      score += (i === last + 1 ? 3 : 1) + (i === 0 || /[\s/·:._-]/.test(s[i - 1]) ? 4 : 0);
      out += '<mark>' + esc(s[i]) + '</mark>'; last = i; qi++;
    } else out += esc(s[i]);
  }
  if (qi < lq.length) return null;
  if (ls.includes(lq)) score += 20;
  return { score: score - s.length * 0.02, hl: out };
}
let palFilesT = 0;
function paletteCmds() {
  const order = visibleNav().flatMap(([, ids]) => ids);
  const views = Object.keys(VIEWS).filter((v) => VIEWFN[v]).map((v) => ({ group: 'Go to', icon: VIEWS[v][2], label: VIEWS[v][0], hint: order.indexOf(v) >= 0 && order.indexOf(v) < 9 ? String(order.indexOf(v) + 1) : '', run: () => go(v) }));
  const actions = [
    { label: S.nobots ? 'Include bots in stats' : 'Exclude bots from stats', hint: 'B', icon: 'bot', run: () => ACT.bots() },
    { label: S.deep ? 'Hide infrastructure views' : 'Show infrastructure views', hint: 'I', icon: 'gauge', run: () => ACT.deep() },
    { label: S.fields ? 'Hide deep fields' : 'Show deep fields', hint: 'D', icon: 'rows-3', run: () => ACT.fields() },
    { label: S.paused ? 'Resume sampling' : 'Pause sampling', hint: 'space', icon: S.paused ? 'play' : 'pause', run: () => ACT.pause() },
    { label: 'Show probe requests', hint: 'requests', icon: 'skull', run: () => showRequests({ scope: 'scan', q: '', ipFilter: '' }) },
    { label: 'Show errors', hint: 'requests', icon: 'circle-alert', run: () => showRequests({ scope: 'errors', q: '', ipFilter: '' }) },
    { label: 'Show slow requests (≥ 500 ms)', hint: 'requests', icon: 'timer', run: () => { S.rf.min_ms = '500'; showRequests({ q: '', ipFilter: '' }); } },
    { label: 'Refresh Cloudflare edge data', hint: 'edge', icon: 'cloud', run: () => { go('edge'); ACT.edgeRetry(); } },
    { label: 'Upload files…', hint: 'U', icon: 'upload', run: () => { go('upload'); ACT.fpick && ACT.fpick('upf'); } },
    { label: 'Upload a folder…', hint: 'upload', icon: 'folder-input', run: () => { go('upload'); ACT.fpick && ACT.fpick('updir'); } },
    { label: 'Upload from a URL…', hint: 'upload', icon: 'cloud-download', run: () => { go('upload'); ACT.upFromUrl && ACT.upFromUrl(); } },
    { label: 'Open trash', hint: 'files', icon: 'trash', run: () => { go('files'); ACT.ftab && ACT.ftab('trash'); } },
    { label: 'Expose a local service…', hint: 'network', icon: 'plug', run: () => { go('network'); ACT.netTab && ACT.netTab('expose'); } },
    { label: 'Purge Cloudflare cache for URLs…', hint: 'network', icon: 'refresh-cw', run: () => ACT.cfPurgeUrls && ACT.cfPurgeUrls() },
    { label: 'Run compression scan now', hint: 'compression', icon: 'archive', run: () => ACT.compressRun() },
    { label: 'Copy snapshot as JSON', hint: '', icon: 'clipboard-copy', run: () => copy(JSON.stringify({ live: D.live, stats: D.stats?.totals }, null, 2), 'snapshot') },
    { label: 'Keyboard shortcuts', hint: '?', icon: 'keyboard', run: () => ACT.help() },
    { label: 'Sign out', hint: 'session', icon: 'log-out', run: () => ACT.logout() },
  ].map((c) => Object.assign({ group: 'Actions' }, c));
  const settings = [
    ...RANGES.map(([k, l]) => ({ label: 'Range: ' + l, hint: S.range === k ? 'current' : '', icon: 'calendar', run: () => setRange(k) })),
    ...['auto', 'light', 'dark'].map((t) => ({ label: 'Theme: ' + ({ auto: 'system', light: 'light', dark: 'dark' }[t]), hint: S.theme === t ? 'current' : '', icon: t === 'dark' ? 'moon' : t === 'light' ? 'sun' : 'monitor', run: () => ACT.setTheme(t) })),
    ...['compact', 'normal', 'comfy'].map((d) => ({ label: 'Density: ' + d, hint: S.density === d ? 'current' : '', icon: 'rows-3', run: () => ACT.setDensity(d) })),
    ...ACCENTS.map(([c, n]) => ({ label: 'Accent: ' + n, hint: c, icon: 'palette', run: () => ACT.setAccent(c) })),
    ...SCALE_PRESETS.map((p) => ({ label: 'Interface scale: ' + Math.round(p * 100) + ' %', hint: Math.round(S.scale * 100) === Math.round(p * 100) ? 'current' : '', icon: 'maximize-2', run: () => ACT.setScale(p) })),
    { label: S.navCollapsed ? 'Expand the sidebar' : 'Collapse the sidebar', hint: '[', icon: 'panel-left', run: () => ACT.navCollapse() },
  ].map((c) => Object.assign({ group: 'Settings' }, c));
  const extra = PALETTE_SOURCES.flatMap((f) => { try { return f(S.pq) || []; } catch { return []; } });
  const q = S.pq.trim();
  let all = views.concat(actions, settings, extra);
  if (!q) {
    const recent = (S.palRecent || []).map((l) => all.find((c) => c.label === l)).filter(Boolean).map((c) => Object.assign({}, c, { group: 'Recent' }));
    return recent.concat(views, actions.slice(0, 8));
  }
  // file search through the index (debounced; results arrive into D.palFiles)
  if (q.length >= 2 && typeof searchFilesForPalette === 'function') {
    clearTimeout(palFilesT);
    if (!D.palFiles || D.palFiles.q !== q) palFilesT = setTimeout(() => searchFilesForPalette(q), 250);
  }
  if (D.palFiles && D.palFiles.q === q) all = all.concat(D.palFiles.items);
  return all.map((c) => { const m = fuzzy(q, c.label); return m ? Object.assign({}, c, { hl: m.hl, score: m.score + (c.group === 'Go to' ? 5 : 0) }) : null; })
    .filter(Boolean).sort((a, b) => b.score - a.score).slice(0, 60)
    .sort((a, b) => ['Go to', 'Actions', 'Files', 'Settings'].indexOf(a.group) - ['Go to', 'Actions', 'Files', 'Settings'].indexOf(b.group));
}

/* ------------------------------------------------------------------ events */

document.addEventListener('click', (e) => {
  const el = e.target.closest('[data-act]');
  if (!el) return;
  const fn = ACT[el.dataset.act];
  if (!fn) return;
  if (el.dataset.act !== 'noop') e.preventDefault();
  if (el.dataset.act === 'noop') { e.stopPropagation(); return; }
  fn(el.dataset.arg, el, e);
});
// toggles / selects with data-change="action": the action gets the new value (checkbox -> boolean)
document.addEventListener('change', (e) => {
  const el = e.target.closest('[data-change]');
  if (!el || !ACT[el.dataset.change]) return;
  ACT[el.dataset.change](el.type === 'checkbox' ? el.checked : el.value, el, e);
});
document.addEventListener('contextmenu', (e) => {
  if (e.target.closest('input, textarea, .menu, .pal')) return;
  const sel = window.getSelection();
  if (sel && !sel.isCollapsed) return; // let the browser menu copy selected text
  const el = e.target.closest('[data-menu]');
  const m = el ? MENUS[el.dataset.menu] && MENUS[el.dataset.menu](el.dataset.arg, el.dataset.arg2) : (e.target.closest('#app') ? appMenu() : null);
  if (!m) return;
  e.preventDefault();
  // pointer coordinates are in screen px; the menu is positioned inside the zoomed page
  const z = zoomNow, w = 268, h = 62 + m.items.length * 30, vw = innerWidth / z, vh = innerHeight / z;
  S.menu = Object.assign(m, { x: Math.min(e.clientX / z, Math.max(8, vw - w - 8)), y: Math.min(e.clientY / z, Math.max(8, vh - h - 8)) });
  S.palette = false;
  renderOverlay();
});
document.addEventListener('pointerdown', (e) => {
  pointerDown = true;
  const g = e.target.closest('[data-resize]');
  if (g) {
    e.preventDefault();
    const [key, i, w0] = g.dataset.resize.split(':');
    dragging = { k: key + ':' + i, x0: e.clientX, w0: +w0 };
  }
});
document.addEventListener('pointermove', (e) => {
  if (dragging) {
    S.widths[dragging.k] = Math.max(34, Math.round(dragging.w0 + (e.clientX - dragging.x0) / zoomNow));
    frame(true);
    return;
  }
  const ch = e.target.closest('[data-hover]');
  if (ch) {
    const r = ch.getBoundingClientRect();
    S.hover = { chart: ch.dataset.hover, x: Math.max(0, Math.min(1, (e.clientX - r.left) / r.width)) };
    if (!pointerDown) frame();
  } else if (S.hover) { S.hover = null; frame(); }
});
const release = () => {
  pointerDown = false;
  if (dragging) { dragging = null; persist(); }
};
document.addEventListener('pointerup', release);
document.addEventListener('pointercancel', release);
window.addEventListener('blur', release);
document.addEventListener('dblclick', (e) => {
  const dbl = e.target.closest('[data-dbl]');
  if (dbl && ACT[dbl.dataset.dbl]) { ACT[dbl.dataset.dbl](dbl.dataset.arg, dbl, e); return; }
  const g = e.target.closest('[data-resize]');
  if (!g) return;
  const [key, i] = g.dataset.resize.split(':');
  delete S.widths[key + ':' + i]; persist(); render(true);
});

/* drag & drop from the PC (files and whole folders) anywhere on the page */
const dragHasFiles = (e) => e.dataTransfer && [...e.dataTransfer.types].includes('Files');
// Folder drops: the DataTransferItems must be turned into entries synchronously (inside the drop event); the walk
// itself is async. A folder becomes {file, rel: 'folder/sub/name'} items, like an <input webkitdirectory> pick.
function collectDropped(dt) {
  const items = [...(dt.items || [])];
  const picked = items.filter((i) => i.kind === 'file').map((item) => ({ entry: item.webkitGetAsEntry ? item.webkitGetAsEntry() : null, file: item.getAsFile ? item.getAsFile() : null }));
  const entries = picked.map((x) => x.entry).filter(Boolean);
  const loose = picked.filter((x) => !x.entry && x.file).map((x) => x.file);
  const plain = [...(dt.files || [])];
  return (async () => {
    if (!entries.length) return (loose.length ? loose : plain).map((f) => ({ file: f, rel: f.name }));
    const out = [];
    const walk = async (entry, prefix) => {
      if (entry.isFile) out.push({ file: await new Promise((res, rej) => entry.file(res, rej)), rel: prefix + entry.name });
      else if (entry.isDirectory) {
        const reader = entry.createReader();
        for (;;) { // readEntries returns at most ~100 entries per call
          const batch = await new Promise((res, rej) => reader.readEntries(res, rej));
          if (!batch.length) break;
          for (const c of batch) await walk(c, prefix + entry.name + '/');
        }
      }
    };
    for (const e of entries) await walk(e, '');
    for (const file of loose) if (!out.some((x) => x.file === file || (x.file.name === file.name && x.file.size === file.size && x.file.lastModified === file.lastModified))) out.push({ file, rel: file.name });
    return out;
  })();
}
document.addEventListener('dragover', (e) => {
  if (!dragHasFiles(e)) return;
  e.preventDefault();
  e.dataTransfer.dropEffect = 'copy';
  if (!S.dragOver) { S.dragOver = true; renderOverlay(); }
});
document.addEventListener('dragleave', (e) => {
  if (S.dragOver && !e.relatedTarget) { S.dragOver = false; renderOverlay(); }
});
document.addEventListener('drop', (e) => {
  if (!dragHasFiles(e)) return;
  e.preventDefault();
  S.dragOver = false; renderOverlay();
  const t = e.target.closest('[data-dropdir]');
  let p;
  try { p = collectDropped(e.dataTransfer); } catch (err) { note('Could not read dropped files: ' + err.message, { err: true }); return; }
  p.then((list) => { if (typeof onDropFiles === 'function') onDropFiles(list, t ? t.dataset.dropdir : null); })
    .catch((err) => note('Could not read dropped files: ' + err.message, { err: true }));
});
document.addEventListener('change', (e) => {
  if (e.target.id === 'scale-range') { ACT.setScale(+e.target.value / 100); const r = $('#scale-range'); if (r) r.focus(); return; }
  if (/^rf_/.test(e.target.id || '')) { S.rf[e.target.id.slice(3)] = e.target.value.trim(); D.req = null; render(true); pollRequests(true); return; }
  if (e.target.id !== 'upf' && e.target.id !== 'updir') return;
  const picked = [...e.target.files];
  if (picked.length && typeof onDropFiles === 'function') onDropFiles(picked.map((f) => ({ file: f, rel: f.webkitRelativePath || f.name })), null);
  else if (S.resumeFor) S.resumeFor = null;
  e.target.value = '';
});
document.addEventListener('paste', (e) => {
  if (!['files', 'upload'].includes(S.view) || (S.view === 'files' && S.ftab !== 'files') || S.editor || S.picker) return;
  if (/^(input|textarea|select)$/i.test(e.target.tagName) || e.target.isContentEditable) return;
  const cb = e.clipboardData;
  if (!cb) {
    if (S.view === 'files' && S.ftab === 'files' && S.clip) { S.clipPastePending = null; e.preventDefault(); ACT.fpaste(); }
    return;
  }
  const files = [...(cb.files || [])];
  if (!files.length && cb.items) {
    for (const item of cb.items) if (item.kind === 'file') {
      const file = item.getAsFile();
      if (file && !files.some((x) => x === file)) files.push(file);
    }
  }
  if (files.length) {
    S.clipPastePending = null;
    e.preventDefault();
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const list = files.map((file, i) => {
      const mimeExt = (file.type.split('/')[1] || 'bin').replace(/[^a-z0-9.+-]/gi, '').slice(0, 8) || 'bin';
      return { file, rel: file.name || `clipboard-${stamp}${files.length > 1 ? '-' + (i + 1) : ''}.${mimeExt}` };
    });
    if (typeof onDropFiles === 'function') onDropFiles(list, null);
    return;
  }
  if (S.view === 'files' && S.ftab === 'files' && S.clip) { S.clipPastePending = null; e.preventDefault(); ACT.fpaste(); }
});
window.addEventListener('beforeunload', (e) => {
  if (U.some((u) => u.status === 'uploading' || u.status === 'queued')) { e.preventDefault(); e.returnValue = ''; }
});
const GO_KEYS = { s: 'summary', r: 'requests', c: 'content', v: 'visitors', i: 'insights', f: 'files', u: 'upload', a: 'analyze', e: 'serving', b: 'blacklist', l: 'links', w: 'alerts', n: 'network', t: 'tunnel', o: 'origins', h: 'history', d: 'edge', y: 'system', x: 'settings', m: 'media', p: 'compression', k: 'security' };
document.addEventListener('keydown', (e) => {
  if (S.dialog) {
    if (e.key === 'Enter') { e.preventDefault(); ACT.dlgOk(); }
    if (e.key === 'Escape') { e.preventDefault(); ACT.dlgCancel(); }
    return;
  }
  const typing = /^(input|textarea|select)$/i.test(e.target.tagName) || e.target.isContentEditable;
  if (!typing && !S.menu && !S.palette && typeof fileKeys === 'function' && fileKeys(e)) return;
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); S.palette ? (S.palette = false, renderOverlay()) : ACT.palette(); return; }
  if (e.key === 'Escape') {
    if (S.fpreview) { e.preventDefault(); ACT.fpreviewClose(); return; }
    if (S.menu || S.palette || S.help) { S.menu = null; S.palette = false; S.help = false; renderOverlay(); }
    else if (typing) e.target.blur();
    else if (S.sel) ACT.closeIns();
    return;
  }
  if (S.palette && e.target.id === 'pq') {
    const n = paletteCmds().length;
    if (e.key === 'ArrowDown') { e.preventDefault(); S.palIdx = (S.palIdx + 1) % Math.max(1, n); renderOverlay(); }
    if (e.key === 'ArrowUp') { e.preventDefault(); S.palIdx = (S.palIdx - 1 + n) % Math.max(1, n); renderOverlay(); }
    if (e.key === 'Enter') { e.preventDefault(); ACT.palRun(S.palIdx); }
    return;
  }
  if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
  if (S.gkey && Date.now() - S.gkey < 1200) {
    S.gkey = 0;
    const v = GO_KEYS[e.key.toLowerCase()];
    if (v && VIEWS[v] && VIEWFN[v]) { e.preventDefault(); go(v); }
    return;
  }
  if (e.key === 'g') { S.gkey = Date.now(); return; }
  if (e.key === '/') { e.preventDefault(); $('#q').focus(); }
  else if (e.key === '?') { e.preventDefault(); ACT.help(); }
  else if (e.key === '[') ACT.navCollapse();
  else if (e.key.toLowerCase() === 't') ACT.themeCycle();
  else if (e.key === 'i') ACT.deep();
  else if (e.key === 'b') ACT.bots();
  else if (e.key === 'd') ACT.fields();
  else if (e.key === ' ') { e.preventDefault(); ACT.pause(); }
  else if (/^[1-9]$/.test(e.key)) { const v = visibleNav().flatMap(([, ids]) => ids)[+e.key - 1]; if (v) go(v); }
  else if (e.key === 'u' && S.view !== 'upload') go('upload');
  else if (e.key === ',') go('settings');
});
window.addEventListener('resize', () => {
  const before = zoomNow;
  applyScale();
  if (zoomNow !== before) { if (S.view === 'settings') render(true); else renderNav(); }
});
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') { pollStats(); refreshForView(); } renderNav(); });
let qTimer;
document.addEventListener('input', (e) => {
  if (e.target.id === 'scale-range') { // readout follows the thumb; zoom is applied on release ('change')
    const v = $('#scale-val'); if (v) v.textContent = e.target.value + ' %';
    return;
  }
  if (e.target.id === 'pq') { S.pq = e.target.value; S.palIdx = 0; renderOverlay(); return; }
  if (e.target.id === 'q') {
    S.q = e.target.value.trim();
    if (S.view !== 'requests') { S.view = 'requests'; persist(); }
    clearTimeout(qTimer);
    qTimer = setTimeout(() => { D.req = null; pollRequests(true); }, 220);
    render();
  }
});

/* ------------------------------------------------------------------ boot (after the other modules loaded) */

document.addEventListener('DOMContentLoaded', () => {
  applyAppearance();
  if (!VIEWS[S.view] || !VIEWFN[S.view]) S.view = 'summary';
  render(true);
  auditView(S.view);
  pollLive();
  pollStats();
  if (S.syncPrefs) pullPrefs();
  setInterval(() => { if (!S.paused && !hidden()) pollStats(); }, 10000);
  (function loopRequests() { pollRequests(); setTimeout(loopRequests, S.rate); })();
  setInterval(() => { if (S.view === 'history' && !S.paused && !hidden()) pollHistory(); }, 60000);
  setInterval(() => { if ((S.view === 'edge' || (S.vitals || []).includes('edge')) && !hidden()) pollEdge(); }, 300000);
  setInterval(() => { if (S.view === 'insights' && !S.paused && !hidden()) pollInsights(); }, 30000);
  setInterval(() => { if (S.view === 'compression' && !S.paused && !hidden()) pollCompression(); }, 5000);
  refreshForView();
  pollEdge();
});
