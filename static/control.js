'use strict';
/* Strata control: serving (drives, access rules, site, config history), blacklist, links, alerts, security settings.
   Loaded after app.js and storage.js. Every change goes through Strata's API, which validates the resulting Caddy
   config before applying it - an invalid change is refused and nothing is touched. */

['serving', 'blacklist', 'links', 'alerts'].forEach((v) => STATIC_VIEWS.add(v));
Object.assign(S, { srvTab: store.get('srvTab', 'drives'), blFilter: 'active', blQ: '', alFilter: 'open' });
Object.assign(D, { serv: null, cf: null, alerts: null, histView: null, testRes: null, twofa: null });
const CC_RE = /^[A-Z]{2}$/;
const EXPIRY = [['', 'never'], ['3600', '1 hour'], ['86400', '24 hours'], ['604800', '7 days'], ['2592000', '30 days'], ['custom', 'custom…']];
const ACTION_HELP = {
  allow: 'Always serves matches. Use it for exceptions to other rules.',
  hide: 'Answers 404, as if the file didn’t exist.',
  deny: 'Answers 403 Forbidden.',
  password: 'Asks for a username and password. Not cached by Cloudflare.',
  signed: 'Only signed links work, until they expire.',
  ip_allow: 'Only these addresses get in. Not cached by Cloudflare.',
  geo_allow: 'Only these countries get in. Not cached by Cloudflare.',
  geo_deny: 'Visitors from these countries get 403. Not cached by Cloudflare.',
  hotlink: 'Other sites can’t embed these files. Not cached by Cloudflare.',
  download: 'Browsers download the file instead of showing it.',
  cache: 'Sets caching for these paths, instead of the drive’s.',
  redirect: 'Sends visitors elsewhere (301 permanent or 302 temporary).',
  gallery: 'Folders open as a thumbnail gallery instead of a 404.',
  player: 'Desktop browsers get a player page for audio files. Tick “Purge” below so Cloudflare drops its cached copies.',
};

async function loadServ() {
  try { D.serv = await get('/api/serving'); } catch (e) { note(e.message); }
}
async function loadCf() {
  try { D.cf = await get('/api/cloudflare'); } catch { /* optional */ }
}
function refreshControl() { if (STATIC_VIEWS.has(S.view)) render(true); }
VIEW_REFRESH.serving = async () => { await loadServ(); refreshControl(); };
VIEW_REFRESH.blacklist = async () => { await loadServ(); refreshControl(); loadCf().then(refreshControl); if (!D.stats) pollStats(); };
VIEW_REFRESH.links = async () => { await loadServ(); refreshControl(); };
VIEW_REFRESH.alerts = async () => { try { D.alerts = await get('/api/alerts'); } catch (e) { note(e.message); } refreshControl(); };
setInterval(() => { if ((S.view === 'blacklist' || S.view === 'links') && !S.paused && !$('#sheet')) loadServ().then(refreshControl); }, 20000);
setInterval(() => { if (S.view === 'alerts' && !S.paused) VIEW_REFRESH.alerts(); }, 15000);

async function mutate(url, body, okMsg) {
  try {
    const r = await post(url, body);
    if (okMsg) note(okMsg + (r.apply && r.apply.changed ? ' · Caddy updated (' + r.apply.sha + ')' : ''));
    await loadServ();
    refreshControl();
    return r;
  } catch (e) { note(e.message); throw e; }
}
const mountOpts = (sel, withAll) => (withAll ? `<option value="">all drives</option>` : '') +
  (D.serv?.mounts || []).map((m) => `<option value="${m.id}" ${String(sel) === String(m.id) ? 'selected' : ''}>${esc(m.name)}</option>`).join('');
const mName = (id) => ((D.serv?.mounts || []).find((m) => m.id === id) || {}).name || (id ? 'drive ' + id : 'all drives');
// def: preselected lifetime in seconds when there is no expiry yet (new share links default to D.me.links.default_days)
function expiryFields(prefix, exp, def) {
  const pick = !exp && def && EXPIRY.some(([v]) => v === String(def)) ? String(def) : '';
  if (!exp && def && !pick) exp = Date.now() / 1000 + +def;
  return `<select id="${prefix}_exp" class="input">${EXPIRY.map(([v, l]) => `<option value="${v}" ${(!exp && v === pick) ? 'selected' : ''}>${l}</option>`).join('')}</select>
    <input id="${prefix}_expat" class="input" type="datetime-local" style="display:${exp ? 'inline-block' : 'none'}" value="${exp ? new Date(exp * 1000 - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16) : ''}">`;
}
function readExpiry(prefix) {
  const v = $('#' + prefix + '_exp').value, at = $('#' + prefix + '_expat').value;
  if (v === 'custom' || (!v && at && $('#' + prefix + '_expat').style.display !== 'none')) return at ? new Date(at).getTime() / 1000 : null;
  return v ? Date.now() / 1000 + +v : null;
}

/* ---- sheets (forms in their own DOM node) */

function openSheet(kicker, title, body, buttons, wide) {
  closeSheet();
  const el = document.createElement('div');
  el.id = 'sheet';
  el.className = 'palbg';
  el.innerHTML = `<div class="dlg sheet ${wide ? 'wide' : ''}" role="dialog" aria-modal="true"><div class="body"><div class="cap">${esc(kicker)}</div><h4>${esc(title)}</h4>${body}</div>
    <div class="acts">${buttons}<div class="fill"></div><button class="btn btn-secondary" data-act="sheetClose">Cancel</button></div></div>`;
  document.body.appendChild(el);
  const first = el.querySelector('input, select, textarea');
  if (first) first.focus();
}
function closeSheet() { const el = $('#sheet'); if (el) el.remove(); }
ACT.sheetClose = closeSheet;
document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && $('#sheet')) { e.stopImmediatePropagation(); closeSheet(); } }, true);
document.addEventListener('change', (e) => {
  const id = e.target.id || '';
  if (/_exp$/.test(id)) { const at = $('#' + id + 'at'); if (at) at.style.display = e.target.value === 'custom' ? 'inline-block' : 'none'; }
  if (id === 'r_action') { const box = $('#r_params'); if (box) box.innerHTML = ruleParams(e.target.value, {}); const h = $('#r_help'); if (h) h.textContent = ACTION_HELP[e.target.value] || ''; }
  // a preset select only fills in the text field next to it, then goes back to "presets…"
  if (id === 'r_cachepre' && e.target.value) { $('#p_cache').value = e.target.value; e.target.value = ''; }
  if (id === 'd_cachepre' && e.target.value) { $('#d_cache').value = e.target.value; e.target.value = ''; }
  if (id === 'd_edgepre' && e.target.value !== '-') { $('#d_edge').value = e.target.value; e.target.value = '-'; }
  if (id === 'd_kind') {
    const k = e.target.value;
    document.querySelectorAll('.d-files').forEach((x) => { x.style.display = k === 'files' ? '' : 'none'; });
    document.querySelectorAll('.d-local').forEach((x) => { x.style.display = k === 'proxy' ? 'none' : ''; });
    document.querySelectorAll('.d-proxy').forEach((x) => { x.style.display = k === 'proxy' ? '' : 'none'; });
    document.querySelectorAll('.d-prefix').forEach((x) => { x.style.display = k === 'page' ? 'none' : ''; });
  }
  if (id === 'g_mode') { const box = $('#g_login'); if (box) box.style.display = e.target.value === 'login' ? '' : 'none'; }
  if (id === 'bl_kind') blValueHint();
  if (id.startsWith('m_') || id.startsWith('l_')) linkPreview();
});
document.addEventListener('input', (e) => {
  const id = e.target.id || '';
  if (id.startsWith('m_') || id.startsWith('l_')) linkPreview();
  if (id === 'blq') { S.blQ = e.target.value.trim().toLowerCase(); clearTimeout(ACT._blq); ACT._blq = setTimeout(() => render(true), 200); }
});

/* ================================================================== serving */

function vServing() {
  const V = D.serv;
  if (!V) return loading('Loading serving config…');
  const tabs = [['drives', 'Drives'], ['rules', 'Access rules'], ['site', 'Site'], ['config', 'Caddy config & history'], ['test', 'Test a URL']];
  const sv = V.serving || {};
  let body;
  if (S.srvTab === 'rules') body = rulesTab(V);
  else if (S.srvTab === 'site') body = siteTab(V);
  else if (S.srvTab === 'config') body = configTab(V);
  else if (S.srvTab === 'test') body = testTab();
  else body = drivesTab(V);
  return `<div class="col-fill">
    <div class="tbar">${tabs.map(([k, l]) => `<button class="pill ${S.srvTab === k ? 'on' : ''}" data-act="srvTab" data-arg="${k}">${l}</button>`).join('')}
      <div class="fill"></div><span class="small dim">live config ${esc(sv.sha || '—')} · ${esc(sv.reason || '')} · ${esc(fmt.ago(sv.ts))}</span></div>
    <div class="ctab" data-scroll="srv-${S.srvTab}">${body}</div></div>`;
}
function drivesTab(V) {
  const rows = V.mounts.map((m) => ({
    cells: [cell(m.name, 'h800'), cell(m.kind === 'proxy' ? 'service' : m.kind, 'dim'), cell(m.path, m.error ? 'hot' : '', m.error || m.path), cell(m.kind === 'page' ? '/ only' : m.prefix, 'dim'),
      cell(m.hosts.join(', '), 'dim'), cell(m.kind === 'proxy' ? '—' : m.cache + (m.edge_cache ? ' · Cloudflare: ' + m.edge_cache : ''), 'dim'),
      m.kind === 'proxy' ? gateCell(m.gate) : cell([m.precompress ? 'br' : '', m.transforms ? 'modifiers' : '', m.browse ? 'listing' : ''].filter(Boolean).join(', ') || '—', 'dim'),
      cell(m.disk ? fmt.bytes(m.disk.free) + ' free' : m.kind === 'proxy' ? '' : 'offline', m.disk || m.kind === 'proxy' ? 'r dim' : 'r hot'),
      cell(m.index ? fmt.bytes(m.index.bytes) + ' · ' + fmt.n(m.index.files) : '—', 'r dim'), cell(m.enabled ? 'on' : 'off', m.enabled ? '' : 'hot'),
      hcell(`<button class="pill" data-act="driveEdit" data-arg="${m.id}">Edit</button> <button class="pill danger" data-act="driveDelete" data-arg="${m.id}">Remove</button>`)],
  }));
  return `<div class="tbar"><span class="small dim">Folders and services that Caddy serves.</span>
      <div class="fill"></div><button class="pill on" data-act="driveEdit" data-arg="">Add drive</button></div>` +
    table('srv-drives', [{ t: 'Name', w: 150 }, { t: 'Type', w: 60 }, { t: 'Folder / upstream', w: 240 }, { t: 'URL prefix', w: 80 }, { t: 'Hostnames', w: 220 },
      { t: 'Cache-Control', w: 200 }, { t: 'Features', w: 140 }, { t: 'Disk', w: 100, a: 'r' }, { t: 'Indexed', w: 120, a: 'r' }, { t: 'On', w: 40 }, { t: '', w: 150 }], rows);
}
function gateCell(g) {
  g = g || { mode: 'public', users: [] };
  if (g.mode !== 'login') return cell('public, no login', 'hot');
  const tf = g.users.filter((u) => u.totp).length;
  return cell(`login · ${g.users.length} user${g.users.length === 1 ? '' : 's'}${tf ? ' · 2FA ' + tf : ''}${(g.public || []).length ? ' · ' + g.public.length + ' public paths' : ''} · ${g.sessions || 0} signed in`, 'dim',
    g.users.map((u) => u.user + (u.totp ? ' (2FA)' : '')).concat((g.public || []).map((p) => 'public: ' + p)).join('\n'));
}
function gateUserRow(u) {
  return `<div class="g_row hrow mb-6 items-center"><input class="input g_user fill" placeholder="user" value="${esc(u.user || '')}" maxlength="40" autocomplete="off">
    <input class="input g_pass flex-13" type="password" placeholder="${u.user ? '(unchanged)' : 'password, 12+ characters'}" autocomplete="new-password">
    <label class="dlg-check" title="Ask for a code from an authenticator app (TOTP)"><input type="checkbox" class="g_totp" ${u.totp ? 'checked' : ''}> 2FA</label>
    <button class="link" data-act="gDelUser" title="Remove">✕</button></div>`;
}
function rulesTab(V) {
  const rows = V.rules.map((r, i) => {
    const p = r.params || {};
    const detail = r.action === 'password' ? (p.users || []).map((u) => u.user).join(', ') : r.action === 'ip_allow' ? (p.ips || []).join(', ')
      : r.action.startsWith('geo') ? (p.countries || []).join(', ') : r.action === 'hotlink' ? (p.domains || []).join(', ') : r.action === 'cache' ? p.value
      : r.action === 'redirect' ? p.code + ' → ' + p.to : r.action === 'player' && p.placeholders ? 'backgrounds: ' + p.placeholders : '';
    return {
      cells: [hcell(`<button class="link" data-act="ruleMove" data-arg="${r.id}|-1" ${i ? '' : 'disabled'}>▲</button> <button class="link" data-act="ruleMove" data-arg="${r.id}|1" ${i < V.rules.length - 1 ? '' : 'disabled'}>▼</button>`),
        cell(r.name, 'h800'), cell(mName(r.mount), 'dim'), cell(r.patterns.join('  '), '', r.patterns.join('\n')), hcell(`<span class="acc ${r.action === 'allow' ? 'dim' : 'hot'}">${esc(r.action)}</span>`),
        cell(detail || '', 'dim', detail), cell(fmt.n(r.hits), 'r'), cell(r.last_hit ? fmt.ago(r.last_hit) : '—', 'dim'), cell(r.expires ? (r.active ? 'until ' + fmt.dt(r.expires) : 'expired') : '', r.active ? 'dim' : 'hot'),
        hcell(`<button class="pill ${r.enabled ? 'on' : ''}" data-act="ruleToggle" data-arg="${r.id}">${r.enabled ? 'on' : 'off'}</button>`),
        hcell(`<button class="pill" data-act="ruleEdit" data-arg="${r.id}">Edit</button> ${r.builtin ? '' : `<button class="pill danger" data-act="ruleDelete" data-arg="${r.id}">Delete</button>`}`)],
    };
  });
  return `<div class="tbar"><span class="small dim">Rules apply top to bottom, after the blocklist. Patterns: <code>/folder/*</code>, <code>*.psd</code>, <code>/exact/file.png</code> or <code>re:</code> + regex. Hits are requests a rule refused.</span>
      <div class="fill"></div><button class="pill on" data-act="ruleEdit" data-arg="">Add rule</button><button class="pill" data-act="rulePreset" data-arg="only">Only serve selected folders…</button></div>` +
    table('srv-rules', [{ t: '', w: 50 }, { t: 'Name', w: 200 }, { t: 'Scope', w: 110 }, { t: 'Patterns', w: 230 }, { t: 'Action', w: 80 }, { t: 'Details', w: 200 },
      { t: 'Hits', w: 60, a: 'r' }, { t: 'Last', w: 80 }, { t: 'Expires', w: 120 }, { t: '', w: 50 }, { t: '', w: 140 }], rows, { empty: 'No rules yet.' });
}
function siteTab(V) {
  const s = V.site;
  return `<div class="settings cols-2"><section class="panel">
    <div class="ph"><h5>Error pages</h5></div>
    <div class="set-row"><div><div class="h800">Drive</div><div class="small dim">Where your error pages are stored.</div></div>
      <div class="set-ctl"><select id="s_emount" class="input">${mountOpts(s.error_mount)}</select></div></div>
    ${[['s_epage', '404 Not found', 'Missing and hidden files.', s.error_page, '404'], ['s_epage403', '403 Forbidden', 'Blocked requests and files in the trash.', s.error_page_403, '403']].map(([id, label, sub, val, code]) => `
    <div class="set-row"><div><div class="h800">${label}</div><div class="small dim">${sub}</div></div>
      <div class="set-ctl hrow"><input id="${id}" class="input w-180" value="${esc(val || '')}" placeholder="/errors/${code}.html"><button class="pill" data-act="errorPageEdit" data-arg="${id}" data-code="${code}">${icon('pencil', 'sm')} Edit</button></div></div>`).join('')}
    <div class="ph"><h5>Other hosts</h5></div>
    <div class="set-row"><div><div class="h800">Unknown hostname</div><div class="small dim">Text answered for hosts no drive serves.</div></div>
      <div class="set-ctl"><input id="s_unknown" class="input w-240" value="${esc(s.unknown_host)}"></div></div>
    <div class="ph"><h5>Responses</h5></div>
    <div class="set-row"><div><div class="h800">Response compression</div><div class="small dim">Compress responses on the fly.</div></div>
      <div class="set-ctl"><label class="dlg-check"><input type="checkbox" id="s_gzip" ${s.encode.includes('gzip') ? 'checked' : ''}> gzip</label><label class="dlg-check"><input type="checkbox" id="s_zstd" ${s.encode.includes('zstd') ? 'checked' : ''}> zstd</label></div></div>
    <div class="set-row"><div><div class="h800">Security headers</div><div class="small dim">Send nosniff and hide the Server header.</div></div>
      <div class="set-ctl"><label class="dlg-check"><input type="checkbox" id="s_nosniff" ${s.nosniff ? 'checked' : ''}> nosniff</label><label class="dlg-check"><input type="checkbox" id="s_hide" ${s.hide_server ? 'checked' : ''}> hide Server</label></div></div>
    <div class="act-row"><button class="btn btn-primary" data-act="siteSave">Save & apply</button></div>
  </section><section class="panel">
    <div class="ph"><h5>Not logged</h5><span class="small dim">polling paths left out of the stats</span></div>
    ${(s.quiet || []).map((q) => `<div class="logline"><span>${esc(q.host)}</span><span>${esc(q.paths.join(' '))}</span></div>`).join('')}
    <div class="ph mt-14"><h5>Log</h5></div><div class="small dim">${esc(s.log_file)} · roll ${esc(s.roll_size)} · keep ${esc(s.roll_keep)} files / ${esc(s.roll_keep_for)}</div>
    <div class="ph mt-14"><h5>Short-link prefix</h5></div><div class="small dim">${esc(s.link_prefix)}&lt;code&gt; on every CDN hostname</div>
  </section></div>`;
}
function configTab(V) {
  const shown = D.histView ? D.histView.content : V.generated;
  const rows = V.history.map((h) => ({ cells: [cell('#' + h.id, 'dim'), cell(fmt.dt(h.ts), 'dim'), cell(h.user, 'dim'), cell(h.reason), cell(h.sha, 'dim'), cell(h.ok ? 'applied' : 'refused', h.ok ? '' : 'hot', h.error),
    hcell(`<button class="pill" data-act="histView" data-arg="${h.id}">View</button> ${h.ok ? `<button class="pill" data-act="histRestore" data-arg="${h.id}">Restore</button>` : ''}`)] }));
  return `<div class="grid2 cols-12 fill min-h0">
    <section class="panel"><div class="ph"><h5>${D.histView ? 'Revision #' + D.histView.id : 'Live: generated/cdn.caddy'}</h5><span class="hrow">${D.histView ? '<button class="pill" data-act="histView" data-arg="">Show live</button>' : ''}<button class="pill" data-act="srvApply">Re-apply now</button><button class="pill" data-act="fcopy" data-arg="${esc(shown)}">Copy</button></span></div>
      <pre class="code" data-scroll="caddytext">${esc(shown)}</pre></section>
    <section class="panel"><div class="ph"><h5>History</h5><span class="small dim">every change, applied or refused</span></div>
      ${table('srv-hist', [{ t: '#', w: 50 }, { t: 'When', w: 110 }, { t: 'By', w: 80 }, { t: 'Change', w: 220 }, { t: 'SHA', w: 130 }, { t: 'Result', w: 70 }, { t: '', w: 140 }], rows)}</section></div>`;
}
function testTab() {
  const R = D.testRes;
  return `<div class="settings cols-2"><section class="panel">
    <div class="ph"><h5>What would happen?</h5><span class="small dim">evaluated against the current rules</span></div>
    <div class="set-row"><div class="h800">URL</div><div class="set-ctl"><input id="t_url" class="input w-360" value="${esc((R && R.url) || 'https://' + cdnHost() + '/')}"></div></div>
    <div class="set-row"><div class="h800">Client IP</div><div class="set-ctl"><input id="t_ip" class="input w-200" value="${esc((R && R.ip) || '')}" placeholder="e.g. 203.0.113.7"></div></div>
    <div class="set-row"><div class="h800">Country</div><div class="set-ctl"><input id="t_cc" class="input w-80" value="${esc((R && R.cc) || '')}" placeholder="DE"></div></div>
    <div class="set-row"><div class="h800">User agent</div><div class="set-ctl"><input id="t_ua" class="input w-300" value="${esc((R && R.ua) || 'Mozilla/5.0 Chrome/140')}"></div></div>
    <div class="set-row"><div class="h800">Referer</div><div class="set-ctl"><input id="t_ref" class="input w-300" value="${esc((R && R.ref) || '')}" placeholder="https://other.site/page"></div></div>
    <div class="act-row"><button class="btn btn-primary" data-act="srvTest">Test</button></div>
  </section><section class="panel"><div class="ph"><h5>Result</h5></div>
    ${R ? `<div class="big-num fs-24">${esc(R.result)}</div>${(R.steps || []).map((s) => `<div class="logline"><span>${esc(s)}</span><span></span></div>`).join('')}` : '<div class="empty">Enter a URL and press Test.</div>'}
  </section></div>`;
}

/* drive editor */
function driveEditor(m) {
  m = m || { kind: 'files', name: '', path: '', prefix: '/', hosts: (INST.hosts || []).filter((h) => h !== INST.stats_host), cache: 'public, no-cache', edge_cache: 'public, max-age=31536000', precompress: 1, transforms: 1, browse: 0, enabled: 1 };
  const g = m.gate || { mode: 'login', hours: 12, users: [] };
  const caches = [['public, no-cache', 'revalidate every time (deletes take effect at once)'], ['public, max-age=300', '5 minutes'], ['public, max-age=3600', '1 hour'], ['public, max-age=86400', '1 day'], ['public, max-age=31536000, immutable', '1 year, immutable (deleted files stay in browsers)'], ['no-store', 'never cache']];
  const edges = [['public, max-age=31536000', '1 year (purged on every change)'], ['public, max-age=86400', '1 day'], ['', 'same as Cache-Control']];
  openSheet(m.id ? 'Edit drive' : 'Add drive', m.id ? m.name : 'New drive', `
    <div class="form">
      <label>Type<select id="d_kind" class="input"><option value="files" ${m.kind === 'files' ? 'selected' : ''}>Folder: serve files</option><option value="page" ${m.kind === 'page' ? 'selected' : ''}>Page: only the bare / of each host</option><option value="proxy" ${m.kind === 'proxy' ? 'selected' : ''}>Proxy: forward to a local service</option></select></label>
      <label>Name<input id="d_name" class="input" value="${esc(m.name)}" placeholder="e.g. Archive disk"></label>
      <label class="wide">Folder, or the service’s LAN address (IP:port)<span class="hrow"><input id="d_path" class="input fill" value="${esc(m.path)}" placeholder="D:/media, //nas/share or 192.168.1.35:8080"><button class="pill d-local" data-act="fsBrowse" data-arg="${esc(m.path || '')}">Browse…</button></span></label>
      <div id="d_browse" class="wide"></div>
      <label class="d-prefix" style="${m.kind === 'page' ? 'display:none' : ''}">URL prefix<input id="d_prefix" class="input" value="${esc(m.prefix || '/')}" placeholder="/ (whole hostname) or /azura"></label>
      <label class="wide">Hostnames (space or comma separated)<input id="d_hosts" class="input" value="${esc(m.hosts.join(', '))}"></label>
      <div class="wide d-proxy form" style="padding:0;${m.kind === 'proxy' ? '' : 'display:none'}">
        <label class="dlg-check wide"><input type="checkbox" id="d_strip" ${m.strip === 0 ? '' : 'checked'}> Strip the URL prefix before forwarding (turn off only for apps set up for that base path)</label>
        <label>Access<select id="g_mode" class="input"><option value="login" ${g.mode !== 'public' ? 'selected' : ''}>Login required (Strata gate)</option><option value="public" ${g.mode === 'public' ? 'selected' : ''}>Public: anyone on the internet</option></select></label>
        <label>Session length (hours)<input id="g_hours" class="input" type="number" min="1" max="168" value="${esc(g.hours || 12)}"></label>
        <div id="g_login" class="wide" style="${g.mode === 'public' ? 'display:none' : ''}">
          <div class="small dim mb-6">Who may sign in. With 2FA, a QR code shows once after saving.</div>
          <div id="g_users">${(g.users.length ? g.users : [{}]).map(gateUserRow).join('')}</div>
          <button class="pill" data-act="gAddUser">+ user</button>
          <label class="wide mt-10">Paths open without login (one per line, * = wildcard)
            <textarea id="g_public" class="input" rows="3" placeholder="/listen/*&#10;/public/*">${esc((g.public || []).join('\n'))}</textarea></label></div>
      </div>
      <label class="wide d-local">Cache-Control (browsers)<span class="hrow"><select id="d_cachepre" class="input preset" aria-label="Cache-Control presets"><option value="">presets…</option>${caches.map(([v, l]) => `<option value="${esc(v)}">${esc(l)}</option>`).join('')}</select><input id="d_cache" class="input fill" aria-label="Cache-Control (browsers)" value="${esc(m.cache || '')}"></span></label>
      <label class="wide d-local">Cloudflare cache<span class="hrow"><select id="d_edgepre" class="input preset" aria-label="Cloudflare cache presets"><option value="-">presets…</option>${edges.map(([v, l]) => `<option value="${esc(v)}">${esc(l)}</option>`).join('')}</select><input id="d_edge" class="input fill" aria-label="Cloudflare cache" value="${esc(m.edge_cache || '')}" placeholder="empty: same as Cache-Control"></span></label>
      <div class="wide d-local d-flex gap-16 f-wrap">
        <label class="dlg-check"><input type="checkbox" id="d_pre" ${m.precompress ? 'checked' : ''}> Brotli precompression</label>
        <label class="dlg-check d-files"><input type="checkbox" id="d_tf" ${m.transforms ? 'checked' : ''}> Link modifiers (?w ?fm ?ver)</label>
        <label class="dlg-check d-files"><input type="checkbox" id="d_browse_on" ${m.browse ? 'checked' : ''}> Directory listing</label>
        <label class="dlg-check"><input type="checkbox" id="d_en" ${m.enabled ? 'checked' : ''}> Enabled</label></div>
      <label class="wide">Note<input id="d_note" class="input" value="${esc(m.note || '')}"></label>
    </div><p class="small dim">New hostnames also need a tunnel route and a DNS record: this only changes Caddy.</p>`,
  `<button class="btn btn-primary" data-act="driveSave" data-arg="${m.id || ''}">Save & apply</button>`, true);
}
async function fsBrowse(path) {
  const box = $('#d_browse'); if (!box) return;
  try {
    const [dr, ls] = await Promise.all([get('/api/drives'), path ? get('/api/fs?path=' + enc(path)) : Promise.resolve(null)]);
    box.innerHTML = `<div class="fsb"><div class="tbar px-0 py-6 border-0">${dr.drives.map((d) => `<button class="pill" data-act="fsBrowse" data-arg="${esc(d.path)}" title="${esc(d.kind)} ${d.total ? fmt.bytes(d.free) + ' free' : ''}">${esc(d.path)} ${esc(d.label || '')}</button>`).join('')}
      ${dr.served.map((s) => `<button class="pill" data-act="fsBrowse" data-arg="${esc(s.path)}">${esc(s.name)}</button>`).join('')}</div>
      ${ls ? `<div class="small h800 mx-0 my-4">${esc(ls.path)} <button class="link" data-act="fsPick" data-arg="${esc(ls.path)}">use this folder</button>${ls.parent ? ` · <button class="link" data-act="fsBrowse" data-arg="${esc(ls.parent)}">up</button>` : ''}</div>
        <div class="plist max-h-26vh">${ls.dirs.map((d) => `<button data-act="fsBrowse" data-arg="${esc(ls.path.replace(/[\\/]$/, '') + '\\' + d)}"><span class="fico dir"></span>${esc(d)}</button>`).join('') || '<div class="empty">No sub-folders.</div>'}</div>` : ''}</div>`;
  } catch (e) { box.innerHTML = `<div class="small hot">${esc(e.message)}</div>`; }
}

/* rule editor */
function ruleParams(action, p) {
  p = p || {};
  if (action === 'password') {
    const users = (p.users && p.users.length ? p.users : [{ user: '' }]);
    return `<label class="wide">Realm (shown in the login prompt)<input id="p_realm" class="input" value="${esc(p.realm || 'Protected')}"></label>
      <div class="wide" id="p_users">${users.map((u, i) => `<div class="hrow mb-6"><input class="input p_user fill" placeholder="user" value="${esc(u.user || '')}"><input class="input p_pass fill" type="password" placeholder="${u.user ? '(unchanged)' : 'password'}" autocomplete="new-password"></div>`).join('')}</div>
      <div class="wide"><button class="pill" data-act="pAddUser">+ user</button></div>`;
  }
  if (action === 'ip_allow') return `<label class="wide">Allowed IPs or ranges (one per line)<textarea id="p_ips" class="input" rows="4">${esc((p.ips || []).join('\n'))}</textarea></label>`;
  if (action === 'geo_allow' || action === 'geo_deny') return `<label class="wide">Country codes (DE, AT, US… T1 = Tor, XX = unknown)<input id="p_cc" class="input" value="${esc((p.countries || []).join(', '))}"></label>`;
  if (action === 'hotlink') return `<label class="wide">Other sites allowed to embed (one per line)<textarea id="p_domains" class="input" rows="3">${esc((p.domains || []).join('\n'))}</textarea></label>`;
  if (action === 'cache') return `<label class="wide">Cache-Control<span class="hrow"><select id="r_cachepre" class="input preset" aria-label="Cache-Control presets"><option value="">presets…</option><option>no-store</option><option>public, max-age=3600</option><option>public, max-age=86400</option><option>public, max-age=31536000, immutable</option></select><input id="p_cache" class="input fill" aria-label="Cache-Control" value="${esc(p.value || '')}"></span></label>`;
  if (action === 'redirect') return `<label class="wide">Target URL or path<input id="p_to" class="input" value="${esc(p.to || '')}" placeholder="https://… or /new/path"></label>
    <label>Type<select id="p_code" class="input"><option value="302" ${p.code !== 301 ? 'selected' : ''}>302 temporary</option><option value="301" ${p.code === 301 ? 'selected' : ''}>301 permanent</option></select></label>`;
  if (action === 'player') return `<label class="wide">Backgrounds for files without cover art (a folder on this drive)<input id="p_bg" class="input" value="${esc(p.placeholders || '')}" placeholder="/share/eric/placeholders"></label>`;
  return '';
}
function openRuleEditor(r) {
  r = Object.assign({ name: '', mount: '', patterns: [], action: 'deny', params: {}, enabled: 1, note: '' }, r || {});
  if (!D.serv) { loadServ().then(() => openRuleEditor(r)); return; }
  const protective = ['hide', 'deny', 'password', 'signed', 'ip_allow', 'geo_allow', 'geo_deny', 'hotlink'];
  openSheet(r.id ? 'Edit rule' : 'New access rule', r.id ? r.name : 'Rule', `
    <div class="form">
      <label class="wide">Name<input id="r_name" class="input" value="${esc(r.name)}" placeholder="e.g. Private client folders"></label>
      <label>Scope<select id="r_mount" class="input">${mountOpts(r.mount, true)}</select></label>
      <label>Action<select id="r_action" class="input">${Object.entries(D.serv.actions).map(([k, l]) => `<option value="${k}" ${r.action === k ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select></label>
      <div class="wide small dim" id="r_help">${esc(ACTION_HELP[r.action] || '')}</div>
      <label class="wide">Path patterns (one per line)<textarea id="r_pats" class="input" rows="3" placeholder="/clients/*&#10;*.psd">${esc(r.patterns.join('\n'))}</textarea></label>
      <div id="r_params" class="form wide p-0">${ruleParams(r.action, r.params)}</div>
      <label>Expires<span class="hrow">${expiryFields('r', r.expires)}</span></label>
      <label class="dlg-check self-end"><input type="checkbox" id="r_en" ${r.enabled ? 'checked' : ''}> Enabled</label>
      <label class="wide">Note<input id="r_note" class="input" value="${esc(r.note || '')}"></label>
      <label class="dlg-check wide"><input type="checkbox" id="r_purge" ${r.purge || (!r.id && protective.includes(r.action)) ? 'checked' : ''}> Purge matching files from Cloudflare’s cache</label>
    </div>`, `<button class="btn btn-primary" data-act="ruleSave" data-arg="${r.id || ''}">Save & apply</button>`, true);
}
window.openRuleEditor = openRuleEditor;
function readRule(id) {
  const action = $('#r_action').value;
  const params = {};
  if (action === 'password') {
    params.realm = $('#p_realm').value;
    params.users = [...document.querySelectorAll('#p_users > div')].map((row) => ({ user: row.querySelector('.p_user').value.trim(), password: row.querySelector('.p_pass').value })).filter((u) => u.user);
  } else if (action === 'ip_allow') params.ips = $('#p_ips').value;
  else if (action === 'geo_allow' || action === 'geo_deny') params.countries = $('#p_cc').value;
  else if (action === 'hotlink') params.domains = $('#p_domains').value;
  else if (action === 'cache') params.value = $('#p_cache').value;
  else if (action === 'redirect') { params.to = $('#p_to').value; params.code = $('#p_code').value; }
  else if (action === 'player') params.placeholders = $('#p_bg').value;
  return { id: id ? +id : undefined, name: $('#r_name').value, mount: $('#r_mount').value || null, action, patterns: $('#r_pats').value,
    params, expires: readExpiry('r'), enabled: $('#r_en').checked, note: $('#r_note').value, purge: $('#r_purge').checked };
}

Object.assign(ACT, {
  srvTab(t) { S.srvTab = t; store.set('srvTab', t); D.histView = null; render(true); },
  driveEdit(id) { driveEditor(id ? D.serv.mounts.find((m) => m.id === +id) : null); },
  fsBrowse(p) { fsBrowse(p); },
  fsPick(p) { $('#d_path').value = p.replace(/\\/g, '/'); $('#d_browse').innerHTML = ''; },
  async driveSave(id) {
    const body = { id: id ? +id : undefined, kind: $('#d_kind').value, name: $('#d_name').value, path: $('#d_path').value, prefix: $('#d_prefix') ? $('#d_prefix').value : '/',
      hosts: $('#d_hosts').value, cache: $('#d_cache').value, edge_cache: $('#d_edge') ? $('#d_edge').value : undefined, precompress: $('#d_pre').checked, transforms: $('#d_tf').checked, browse: $('#d_browse_on').checked,
      enabled: $('#d_en').checked, note: $('#d_note').value };
    if (body.kind === 'proxy') {
      body.strip = $('#d_strip').checked;
      body.gate = { mode: $('#g_mode').value, hours: +$('#g_hours').value || 12, public: $('#g_public').value,
        users: [...document.querySelectorAll('#g_users .g_row')].map((r) => ({ user: r.querySelector('.g_user').value.trim(), password: r.querySelector('.g_pass').value, totp: r.querySelector('.g_totp').checked })).filter((u) => u.user) };
      if (body.gate.mode === 'public') {
        const ok = await ask({ kicker: 'Public service', title: 'Anyone on the internet can open ' + (body.path || 'this service'), danger: true, ok: 'Make it public',
          text: 'Without the Strata login, anyone with the URL sees what it shows. Only do this for services meant to be public.' });
        if (!ok) return;
      }
    }
    try {
      const r = await mutate('/api/serving/mount', body, 'Drive saved');
      closeSheet(); loadDrives();
      if (r && r.enrol && r.enrol.length) {
        openSheet('Two-factor setup', 'Scan these now: they are shown only once', r.enrol.map((x) => `<div class="mx-0 my-10"><div class="h800">${esc(x.user)}</div>
          <div class="bg-white d-iblock p-6 r-8 w-190">${x.qr}</div>
          <div class="small dim break-all">${esc(x.secret)} · <button class="link" data-act="gCopy" data-arg="${esc(x.uri)}">copy otpauth link</button></div></div>`).join(''),
        '', true);
      }
    } catch { /* note shown */ }
  },
  gAddUser() { $('#g_users').insertAdjacentHTML('beforeend', gateUserRow({})); },
  gDelUser(_, el) { const row = el && el.closest('.g_row'); if (row) row.remove(); },
  gCopy(uri) { copy(uri, 'otpauth link'); },
  async driveDelete(id) {
    const m = D.serv.mounts.find((x) => x.id === +id);
    const ok = await ask({ kicker: 'Remove drive', title: 'Stop serving ' + m.name + '?', danger: true, ok: 'Remove', text: 'Caddy stops serving it and its rules are removed. The files on disk stay.' });
    if (ok) { try { await mutate('/api/serving/mount/delete', { id: +id }, 'Drive removed'); loadDrives(); } catch { /* shown */ } }
  },
  ruleEdit(id) { openRuleEditor(id ? JSON.parse(JSON.stringify(D.serv.rules.find((r) => r.id === +id))) : null); },
  async ruleSave(id) { try { await mutate('/api/serving/rule', readRule(id), 'Rule saved'); closeSheet(); if (S.view === 'files') pollFiles(true); } catch { /* shown */ } },
  async ruleDelete(id) {
    const r = D.serv.rules.find((x) => x.id === +id);
    const ok = await ask({ kicker: 'Delete rule', title: r.name, danger: true, ok: 'Delete' });
    if (ok) { try { await mutate('/api/serving/rule/delete', { id: +id }, 'Rule deleted'); } catch { /* shown */ } }
  },
  async ruleToggle(id) {
    const r = JSON.parse(JSON.stringify(D.serv.rules.find((x) => x.id === +id)));
    r.enabled = !r.enabled;
    if (r.action === 'password') r.params.users = r.params.users.map((u) => ({ user: u.user }));
    try { await mutate('/api/serving/rule', r, r.enabled ? 'Rule enabled' : 'Rule disabled'); } catch { /* shown */ }
  },
  async ruleMove(arg) { const [id, d] = arg.split('|'); try { await mutate('/api/serving/rule/move', { id: +id, delta: +d }, 'Order changed'); } catch { /* shown */ } },
  pAddUser() { $('#p_users').insertAdjacentHTML('beforeend', '<div class="hrow mb-6"><input class="input p_user fill" placeholder="user"><input class="input p_pass fill" type="password" placeholder="password" autocomplete="new-password"></div>'); },
  async rulePreset() {
    const m = await pickFolder({ title: 'Only serve this folder: the rest of the drive answers 404', mount: (D.serv.mounts.find((x) => x.kind === 'files') || {}).id, path: '/' });
    if (!m) return;
    try {
      await mutate('/api/serving/rule', { name: 'Only ' + m.path, mount: m.mount, action: 'allow', patterns: [m.path.replace(/\/$/, '') + '/*'] }, '');
      await mutate('/api/serving/rule', { name: 'Hide everything else', mount: m.mount, action: 'hide', patterns: ['/*'] }, 'Only ' + m.path + ' is served now');
    } catch { /* shown */ }
  },
  // opens an error page in the Files editor, creating it from a starter template the first time
  async errorPageEdit(id, el) {
    const code = el.dataset.code;
    const mount = $('#s_emount').value, input = $('#' + id);
    if (!input.value) input.value = `/errors/${code}.html`;
    const path = input.value;
    if (!mount) return note('Pick a drive first', { err: true });
    const title = code === '403' ? 'Access denied' : 'Page not found';
    const text = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${code} · ${title}</title>
<style>
  body { margin: 0; min-height: 100vh; display: grid; place-items: center; font: 16px/1.5 system-ui, sans-serif; background: #111; color: #eee; }
  main { text-align: center; padding: 24px; }
  h1 { font-size: 64px; margin: 0; }
  a { color: inherit; }
</style>
</head>
<body>
<main>
  <h1>${code}</h1>
  <p>${title}.</p>
  <p><a href="/">Back to the home page</a></p>
</main>
</body>
</html>
`;
    try { await post('/api/files/text', { mount, path, text, create: true }); note(`Created ${path}. Save the site settings to use it.`); }
    catch (e) { if (!/exists/.test(e.message)) return note(e.message, { err: true }); }
    openEditor(mount, path);
  },
  async siteSave() {
    const enc2 = [$('#s_gzip').checked ? 'gzip' : null, $('#s_zstd').checked ? 'zstd' : null].filter(Boolean);
    try { await mutate('/api/serving/site', { error_mount: $('#s_emount').value, error_page: $('#s_epage').value, error_page_403: $('#s_epage403').value, unknown_host: $('#s_unknown').value, encode: enc2, nosniff: $('#s_nosniff').checked, hide_server: $('#s_hide').checked }, 'Site settings saved'); } catch { /* shown */ }
  },
  async histView(id) {
    if (!id) { D.histView = null; return render(true); }
    try { const r = await get('/api/serving/history/' + id); D.histView = { id, content: r.content }; render(true); } catch (e) { note(e.message); }
  },
  async histRestore(id) {
    const ok = await ask({ kicker: 'Restore revision', title: 'Put revision #' + id + ' live?', ok: 'Restore', text: 'Caddy runs that config again. The next change rebuilds it from your current rules.' });
    if (!ok) return;
    try { const r = await post('/api/serving/rollback', { id: +id }); note(r.note); await loadServ(); render(true); } catch (e) { note(e.message); }
  },
  async srvApply() { try { const r = await post('/api/serving/apply', {}); note(r.changed ? 'Re-applied ' + r.sha : 'Already live'); await loadServ(); render(true); } catch (e) { note(e.message); } },
  async srvTest() {
    const q = { url: $('#t_url').value, ip: $('#t_ip').value, country: $('#t_cc').value, ua: $('#t_ua').value, referer: $('#t_ref').value };
    try { const r = await get('/api/serving/test?' + new URLSearchParams(q)); D.testRes = Object.assign(r, { url: q.url, ip: q.ip, cc: q.country, ua: q.ua, ref: q.referer }); render(true); } catch (e) { note(e.message); }
  },
});

/* ================================================================== blacklist */

function blValueHint() {
  const k = $('#bl_kind') && $('#bl_kind').value, v = $('#bl_value');
  if (!v) return;
  const lists = { agent: D.serv?.agent_classes, browser: D.serv?.browsers, os: D.serv?.oses };
  const dl = $('#bl_list');
  dl.innerHTML = (lists[k] || (k === 'country' ? ['CN', 'RU', 'KP', 'T1', 'XX'] : [])).map((x) => `<option value="${esc(x)}">`).join('');
  v.placeholder = { ip: '203.0.113.7', cidr: '198.51.100.0/24', country: 'two letters, e.g. RU', asn: 'e.g. 14061', ua_contains: 'text in the user agent', ua_regex: 'regex (RE2)',
    agent: 'bots / previews / players / empty', browser: 'e.g. Firefox', os: 'e.g. Android', referer: 'example.com', path: '*.php or /wp-*' }[k] || '';
}
function vBlacklist() {
  const V = D.serv;
  if (!V) return loading('Loading the blocklist…');
  const now = Date.now() / 1000;
  const act = (b) => b.enabled && (!b.expires || b.expires > now);
  const f = S.blFilter;
  let list = V.blacklist.filter((b) => f === 'all' || (f === 'active' && act(b)) || (f === 'auto' && b.source === 'autoban') || (f === 'expired' && b.expires && b.expires < now) || (f === 'off' && !b.enabled));
  if (S.blQ) list = list.filter((b) => (b.value + ' ' + (b.note || '') + ' ' + b.kind).toLowerCase().includes(S.blQ));
  const edge = V.edge || {};
  const rows = list.map((b) => ({ cells: [cell(V.bl_kinds[b.kind] || b.kind, 'dim'), cell(b.value + (b.kind === 'country' ? ' · ' + cname(b.value) : ''), 'h800'), cell(b.action, b.action === 'block' ? '' : 'dim'), cell(b.scope, 'dim'),
    cell(fmt.n(b.hits), 'r' + (b.hits ? ' h800' : ' dim')), cell(b.last_hit ? fmt.ago(b.last_hit) : '—', 'dim'), cell(b.source || '', b.source === 'autoban' ? 'hot' : 'dim'),
    cell(fmt.dt(b.created), 'dim'), cell(b.expires ? (b.expires > now ? fmt.dur(b.expires - now) + ' left' : 'expired') : 'never', b.expires && b.expires < now ? 'hot' : 'dim'), cell(b.note || '', 'dim', b.note),
    hcell(`<button class="pill ${b.enabled ? 'on' : ''}" data-act="blToggle" data-arg="${b.id}">${b.enabled ? 'on' : 'off'}</button> <button class="pill danger" data-act="blDelete" data-arg="${b.id}">✕</button>`)] }));
  const kinds = Object.entries(V.bl_kinds);
  const scanners = (D.stats?.scanners || []).filter((s) => !V.blacklist.some((b) => b.value === s.k && act(b))).slice(0, 12);
  const caps = D.cf?.caps || {};
  const ab = D.me?.autoban || {};
  return `<div class="split" style="grid-template-columns:1fr 330px"><section class="aside">
    <div class="tbar">
      <select id="bl_kind" class="input fs-12 p-4">${kinds.map(([k, l]) => `<option value="${k}">${esc(l)}</option>`).join('')}</select>
      <input id="bl_value" class="input w-190 fs-125 px-8 py-5" list="bl_list" placeholder="203.0.113.7"><datalist id="bl_list"></datalist>
      <select id="bl_action" class="input fs-12 p-4"><option value="block">block</option><option value="challenge">challenge (edge)</option></select>
      <select id="bl_scope" class="input fs-12 p-4"><option value="both">origin + edge</option><option value="origin">origin only</option><option value="edge">edge only</option></select>
      <span class="d-flex gap-4">${expiryFields('bl', null)}</span>
      <input id="bl_note" class="input w-130 fs-125 px-8 py-5" placeholder="note">
      <button class="pill on" data-act="blAdd">Add</button><button class="pill" data-act="blImport">Import list…</button>
    </div>
    <div class="tbar px-18 py-6">${[['active', 'Active'], ['auto', 'Auto-bans'], ['expired', 'Expired'], ['off', 'Disabled'], ['all', 'All']].map(([k, l]) => `<button class="pill ${f === k ? 'on' : ''}" data-act="blFilter" data-arg="${k}">${l}</button>`).join('')}
      <input id="blq" class="input w-160 fs-12 px-7 py-4" placeholder="filter…" value="${esc(S.blQ)}"><div class="fill"></div>
      <span class="small dim">${fmt.n(V.blacklist.filter(act).length)} active. Local network addresses are never blocked.</span></div>
    ${table('bl', [{ t: 'Type', w: 140 }, { t: 'Value', w: 220 }, { t: 'Action', w: 70 }, { t: 'Where', w: 70 }, { t: 'Blocked', w: 60, a: 'r' }, { t: 'Last', w: 80 }, { t: 'Source', w: 70 },
      { t: 'Added', w: 110 }, { t: 'Expires', w: 90 }, { t: 'Note', w: 200 }, { t: '', w: 90 }], rows, { empty: 'Nothing here. Add an entry above, or right-click a client in Requests / Security.' })}
  </section>
  <aside class="aside">
    <div class="pad"><div class="cap red">Cloudflare edge</div><h5>${edge.ok ? 'Synced ' + esc(fmt.ago(edge.ts)) : caps.lists && caps.lists.ok === false ? 'Needs token permissions' : edge.error ? 'Not synced' : 'Checking…'}</h5></div>
    <div class="small px-16 pt-0 pb-10">
      ${edge.ok ? `${fmt.n(edge.ips)} IPs in list <code>strata_blacklist</code> · ${fmt.n(edge.rules)} WAF rule(s)${edge.overflow ? ' · <span class="hot">expression too long, some entries origin-only</span>' : ''}` : `<span class="dim">${esc(edge.error || '')}</span>`}
      <p class="dim">Cloudflare can serve a banned visitor from its cache. Pushing the list to Cloudflare stops that.</p>
      ${['lists', 'waf', 'purge'].map((k) => caps[k] ? `<div class="logline"><span>${esc({ lists: 'IP list', waf: 'WAF custom rules', purge: 'Cache purge' }[k])}</span><span class="${caps[k].ok ? '' : 'hot'}">${caps[k].ok ? 'ok' : caps[k].ok === false ? 'missing' : 'untested'}</span></div>` : '').join('')}
      ${(caps.lists && !caps.lists.ok) || (caps.waf && !caps.waf.ok) ? `<p>Add to the API token (dash.cloudflare.com › My Profile › API Tokens › edit): <b>${esc(D.cf.perms.lists)}</b>, <b>${esc(D.cf.perms.waf)}</b>, <b>${esc(D.cf.perms.purge)}</b>.</p>` : ''}
      <div class="act-row"><button class="btn btn-secondary" data-act="cfSync">Sync now</button><button class="btn btn-secondary" data-act="cfRecheck">Re-check</button></div>
    </div>
    <div class="sect"><span class="cap">Auto-ban</span><span class="small ${ab.enabled ? '' : 'hot'}">${ab.enabled ? 'on' : 'off'}</span></div>
    <div class="small dim px-16 pt-0 pb-8">${ab.enabled ? `Bans IPs that send ${ab.probes} probes in ${ab.window_minutes} min, for ${ab.ban_hours} h.` : 'Scanners aren’t banned automatically.'} <button class="link" data-act="go" data-arg="settings">change</button></div>
    <div class="sect"><span class="cap">Top scanners (${esc(rangeLabel())})</span></div>
    <div class="loglines">${scanners.map((s) => `<div class="logline"><span title="${esc(s.agent || '')}">${esc(s.k)} ${esc(s.country || '')} · ${fmt.n(s.scan)} probes</span><span><button class="link" data-act="blQuick" data-arg="${esc('ip|' + s.k + '|86400')}">ban 24 h</button> · <button class="link" data-act="blQuick" data-arg="${esc('ip|' + s.k + '|')}">ban</button></span></div>`).join('') || '<div class="logline"><span class="dim">no unbanned scanners</span><span></span></div>'}</div>
  </aside></div>`;
}
Object.assign(ACT, {
  blFilter(f) { S.blFilter = f; render(true); },
  async blAdd() {
    const body = { kind: $('#bl_kind').value, value: $('#bl_value').value, action: $('#bl_action').value, scope: $('#bl_scope').value, expires: readExpiry('bl'), note: $('#bl_note').value };
    if (!body.value.trim()) return note('Enter what to block');
    try { await mutate('/api/serving/bl', body, 'Blocked ' + body.value); } catch { /* shown */ }
  },
  async blQuick(arg) {
    const [kind, value, secs] = arg.split('|');
    try { await mutate('/api/serving/bl', { kind, value, expires: secs ? Date.now() / 1000 + +secs : null, note: 'from the dashboard' }, 'Blocked ' + value); } catch { /* shown */ }
  },
  async blToggle(id) { const b = D.serv.blacklist.find((x) => x.id === +id); try { await mutate('/api/serving/bl/toggle', { id: +id, enabled: !b.enabled }, b.enabled ? 'Disabled' : 'Enabled'); } catch { /* shown */ } },
  async blDelete(id) { try { await mutate('/api/serving/bl/delete', { ids: [+id] }, 'Removed'); } catch { /* shown */ } },
  blImport() {
    openSheet('Import to the blocklist', 'Paste a list', `<div class="form">
      <label>Type<select id="bi_kind" class="input">${Object.entries(D.serv.bl_kinds).map(([k, l]) => `<option value="${k}" ${k === 'ip' ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select></label>
      <label>Expires<span class="hrow">${expiryFields('bi', null)}</span></label>
      <label class="wide">One entry per line (# starts a comment)<textarea id="bi_text" class="input" rows="10" placeholder="203.0.113.7&#10;198.51.100.0/24  # scanner range"></textarea></label>
      <label class="wide">Note<input id="bi_note" class="input" value="import ${new Date().toISOString().slice(0, 10)}"></label></div>`,
    '<button class="btn btn-primary" data-act="blImportGo">Import</button>');
  },
  async blImportGo() {
    try {
      const r = await post('/api/serving/bl/bulk', { kind: $('#bi_kind').value, text: $('#bi_text').value, note: $('#bi_note').value, expires: readExpiry('bi'), scope: 'both' });
      note('Imported ' + r.added + (r.errors.length ? ', ' + r.errors.length + ' rejected' : ''));
      if (r.errors.length) alert(r.errors.join('\n'));
      closeSheet(); await loadServ(); render(true);
    } catch (e) { note(e.message); }
  },
  async cfSync() { try { await post('/api/cloudflare/sync', {}); note('Cloudflare sync queued'); setTimeout(() => { loadServ().then(refreshControl); }, 6000); } catch (e) { note(e.message); } },
  async cfRecheck() { D.cf = null; render(true); await loadCf(); render(true); },
});
function ipRange(ip) {
  if (ip.includes(':')) return ip.split(':').slice(0, 3).join(':') + '::/48';
  const p = ip.split('.'); return p.length === 4 ? p.slice(0, 3).join('.') + '.0/24' : ip;
}
const baseIpMenu = MENUS.ip;
MENUS.ip = (ip) => {
  const m = baseIpMenu(ip);
  m.items = m.items.filter((i) => !/Caddy block rule|WAF expression/.test(i.label)).concat([
    item('Block ' + ip, '', () => ACT.blQuick('ip|' + ip + '|'), { sep: true, danger: true }),
    item('Block for 24 hours', '', () => ACT.blQuick('ip|' + ip + '|86400'), { danger: true }),
    item('Block range ' + ipRange(ip), '', () => ACT.blQuick('cidr|' + ipRange(ip) + '|'), { danger: true }),
  ]);
  return m;
};
const baseReqMenu = MENUS.req;
MENUS.req = (id) => {
  const m = baseReqMenu(id);
  const r = (D.req?.rows || []).find((x) => x.id === +id);
  if (!m || !r) return m;
  m.items = m.items.filter((i) => !/Caddy block rule/.test(i.label)).concat([
    item('Block client ' + r.ip, '', () => ACT.blQuick('ip|' + r.ip + '|'), { sep: true, danger: true }),
    item('Block range ' + ipRange(r.ip), '', () => ACT.blQuick('cidr|' + ipRange(r.ip) + '|'), { danger: true }),
    r.ua ? item('Block this user agent', '', () => ACT.blQuick('ua_contains|' + r.ua.slice(0, 120) + '|'), { danger: true }) : null,
    r.country && CC_RE.test(r.country) ? item('Block country ' + r.country, '', () => ACT.blQuick('country|' + r.country + '|'), { danger: true }) : null,
  ].filter(Boolean));
  return m;
};

/* ================================================================== links */

function vLinks() {
  const V = D.serv;
  if (!V) return loading('Loading links…');
  const rows = V.links.map((l) => ({ cells: [cell(l.code, 'h800'), cell(l.short, 'dim'), cell(l.url || (mName(l.mount) + ':' + l.path), '', l.target), cell(Object.entries(l.mods || {}).map(([k, v]) => k + '=' + v).join(' '), 'dim'),
    cell(fmt.n(l.clicks) + (l.max_clicks ? ' / ' + fmt.n(l.max_clicks) : ''), 'r h800'), cell(l.last_click ? fmt.ago(l.last_click) : '—', 'dim'),
    cell(l.status, l.status === 'active' ? '' : 'hot'), cell(l.expires ? fmt.dt(l.expires) : 'never', 'dim'), cell(l.note || '', 'dim'),
    hcell(`<button class="pill" data-act="fcopy" data-arg="${esc(l.short)}">Copy</button> <button class="pill" data-act="linkAlias" data-arg="${esc(l.code)}" title="Another random short code for the same target">Alias</button> <button class="pill" data-act="linkEdit" data-arg="${esc(l.code)}">Edit</button> <button class="pill" data-act="linkStats" data-arg="${esc(l.code)}">Clicks</button> <button class="pill danger" data-act="linkDelete" data-arg="${esc(l.code)}">✕</button>`)] }));
  return `<div class="col-fill">
    <div class="tbar"><span class="small dim">Short links count every click and can expire.</span>
      <div class="fill"></div><button class="pill on" data-act="linkEdit" data-arg="">New link</button></div>
    ${table('links', [{ t: 'Code', w: 90 }, { t: 'Short URL', w: 250 }, { t: 'Target', w: 300 }, { t: 'Modifiers', w: 150 }, { t: 'Clicks', w: 80, a: 'r' }, { t: 'Last', w: 80 },
      { t: 'Status', w: 80 }, { t: 'Expires', w: 110 }, { t: 'Note', w: 160 }, { t: '', w: 290 }], rows, { empty: 'No links yet. In Files, select a file and use Share…' })}</div>`;
}
function linkBase() {
  const lm = $('#l_kind') && $('#l_kind').value === 'url' ? null : D.serv?.mounts.find((m) => m.id === +($('#l_mount') || {}).value);
  if (!lm) return ($('#l_url') || {}).value || '';
  const host = (lm.hosts.find((h) => h.startsWith('cdn.')) || lm.hosts[0]);
  return 'https://' + host + (lm.prefix === '/' ? '' : lm.prefix) + encodeURI(($('#l_path') || {}).value || '/');
}
function linkMods() {
  const mods = {};
  ['w', 'h', 'q', 'ver', 'v', 't'].forEach((k) => { const el = $('#m_' + k); if (el && el.value.trim()) mods[k] = el.value.trim(); });
  ['fit', 'fm'].forEach((k) => { const el = $('#m_' + k); if (el && el.value) mods[k] = el.value; });
  if ($('#m_dl') && $('#m_dl').checked) mods.dl = '1';
  return mods;
}
function linkPreview() {
  const box = $('#l_preview'); if (!box) return;
  const q = new URLSearchParams(linkMods()).toString();
  const u = linkBase() + (q ? (linkBase().includes('?') ? '&' : '?') + q : '');
  box.textContent = u;
  const ext = $('#l_kind') && $('#l_kind').value === 'url';
  document.querySelectorAll('.l-int').forEach((x) => { x.style.display = ext ? 'none' : ''; });
  document.querySelectorAll('.l-ext').forEach((x) => { x.style.display = ext ? '' : 'none'; });
}
// default lifetime of a new share link (Settings > Share links; 0 = never)
const shareSeconds = () => Math.round(((D.me && D.me.links && D.me.links.default_days) ?? 7) * 86400) || null;
function randomCode(n = 7) { // no look-alikes (0/O, 1/l/I)
  const abc = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789', r = crypto.getRandomValues(new Uint32Array(n));
  return [...r].map((x) => abc[x % abc.length]).join('');
}
function openLinkEditor(o, retried) {
  // one load attempt only: retrying on failure re-requested /api/serving forever for accounts without access
  if (!D.serv) { if (!retried) loadServ().then(() => openLinkEditor(o, true)); return; }
  const l = o && o.code ? o : Object.assign({ code: '', mount: (o && o.mount) || (D.serv.mounts.find((m) => m.kind === 'files') || {}).id, path: (o && o.path) || '/', url: '', mods: {}, max_clicks: null, expires: null, note: '' }, o || {});
  const md = l.mods || {};
  const sel = (id, vals, cur) => `<select id="${id}" class="input">${vals.map(([v, t]) => `<option value="${v}" ${String(cur || '') === v ? 'selected' : ''}>${t}</option>`).join('')}</select>`;
  openSheet(l.code ? 'Edit link' : 'Share', l.code ? '/l/' + l.code : (l.path || 'New link'), `
    <div class="share-dialog-layout">
      <!-- Direct & Target info -->
      <div class="share-card share-target-card">
        <div class="share-card-head">
          <div class="cap">What to share</div>
          <div class="d-flex gap-10 items-center f-wrap">
            <label class="fill min-w-140">Target type<select id="l_kind" class="input mt-3"><option value="file" ${l.url ? '' : 'selected'}>File or folder</option>${!D.me || (D.me.capabilities || []).includes('serving.links') ? `<option value="url" ${l.url ? 'selected' : ''}>External URL</option>` : ''}</select></label>
            <label class="l-int fill min-w-140">Drive<select id="l_mount" class="input mt-3">${mountOpts(l.mount)}</select></label>
          </div>
          <label class="wide l-int mt-6">Path<input id="l_path" class="input mt-3" value="${esc(l.path || '')}"></label>
          <label class="wide l-ext" style="display:none;margin-top:6px">URL<input id="l_url" class="input mt-3" value="${esc(l.url || '')}" placeholder="https://…"></label>
        </div>
        <div class="share-url-box mt-6">
          <div class="code small ell fill px-10 py-8" id="l_preview"></div>
          <button class="btn btn-secondary flex-none" data-act="linkCopyDirect">Copy direct link</button>
        </div>
      </div>

      <!-- Short tracked link options -->
      <div class="share-card">
        <div class="share-card-head">
          <div class="cap">Short link</div>
          <div class="small dim">Counts clicks and can expire.</div>
        </div>
        <div class="share-grid mt-8">
          <label>Short code
            <span class="hrow"><input id="l_code" class="input fill" value="${esc(l.code || '')}" placeholder="Auto-generated"><button class="pill" data-act="linkRandom" title="Random code">🎲 Random</button></span>
          </label>
          <label>Expires
            <span class="hrow">${expiryFields('l', l.expires, l.code ? null : shareSeconds())}</span>
          </label>
          <label>Max clicks
            <input id="l_max" class="input" value="${esc(l.max_clicks || '')}" placeholder="Unlimited">
          </label>
          <label>Internal note
            <input id="l_note" class="input" value="${esc(l.note || '')}" placeholder="Optional reminder">
          </label>
        </div>
        <div class="mt-6">
          <label class="dlg-check pointer d-iflex gap-6 items-center fs-125"><input type="checkbox" id="m_dl" ${md.dl ? 'checked' : ''}> Download instead of opening in the browser</label>
        </div>
      </div>

      <!-- Signed time-limited link -->
      <div class="share-card l-int">
        <div class="share-card-head">
          <div class="cap">Signed link</div>
          <div class="small dim">Opens paths that allow signed links only.</div>
        </div>
        <div class="d-flex gap-8 items-center mt-8 f-wrap">
          ${sel('l_signdur', [['3600', 'for 1 hour'], ['86400', 'for 24 hours'], ['604800', 'for 7 days'], ['2592000', 'for 30 days']], ['3600', '86400', '604800', '2592000'].includes(String(shareSeconds())) ? String(shareSeconds()) : '604800')}
          <button class="btn btn-secondary" data-act="linkSign">Create signed link</button>
        </div>
        <div class="code small" id="l_signed" style="margin-top:8px;display:none"></div>
      </div>

      <!-- Optional image & CDN transformations -->
      <details class="share-card share-modifiers-card">
        <summary class="pointer fw-700 fs-12 c-text">Image and link modifiers</summary>
        <div class="share-grid mt-12">
          <label>Width<input id="m_w" class="input" value="${esc(md.w || '')}" placeholder="px"></label>
          <label>Height<input id="m_h" class="input" value="${esc(md.h || '')}" placeholder="px"></label>
          <label>Fit${sel('m_fit', [['', 'inside (default)'], ['cover', 'cover (crop)'], ['contain', 'contain (pad)'], ['fill', 'fill (stretch)']], md.fit)}</label>
          <label>Format${sel('m_fm', [['', 'original'], ['webp', 'WebP'], ['avif', 'AVIF'], ['jpeg', 'JPEG'], ['png', 'PNG']], md.fm)}</label>
          <label>Quality<input id="m_q" class="input" value="${esc(md.q || '')}" placeholder="1–100"></label>
          <label>Version<input id="m_ver" class="input" value="${esc(md.ver || '')}" placeholder="old version number"></label>
          <label>Cache-bust<input id="m_v" class="input" value="${esc(md.v || '')}" placeholder="?v="></label>
          <label>Tracking tag<input id="m_t" class="input" value="${esc(md.t || '')}" placeholder="?t=social"></label>
        </div>
      </details>
    </div>`, `<button class="btn btn-primary" data-act="linkSave" data-arg="${esc(l.code || '')}">${l.code ? 'Save link' : 'Create short link'}</button>`, true);
  linkPreview();
}
window.openLinkEditor = openLinkEditor;
Object.assign(ACT, {
  linkEdit(code) { openLinkEditor(code ? JSON.parse(JSON.stringify(D.serv.links.find((l) => l.code === code))) : null); },
  async linkSave(orig) {
    const ext = $('#l_kind').value === 'url';
    const body = { original_code: orig || undefined, code: $('#l_code').value.trim(), mount: ext ? null : +$('#l_mount').value, path: ext ? '' : $('#l_path').value,
      url: ext ? $('#l_url').value : '', mods: linkMods(), max_clicks: $('#l_max').value || null, expires: readExpiry('l'), note: $('#l_note').value };
    try {
      const r = await mutate('/api/serving/link', body, 'Link saved');
      const l = (D.serv.links || []).find((x) => x.code === r.result);
      if (l) copy(l.short, 'short link');
      closeSheet(); if (S.view === 'files') pollFiles(true);
    } catch { /* shown */ }
  },
  linkCopyDirect() { copy($('#l_preview').textContent, 'direct link'); },
  linkRandom() { const el = $('#l_code'); if (el) { el.value = randomCode(); el.focus(); } },
  async linkAlias(code) { // another random short code for the same target (default lifetime)
    try {
      const r = await mutate('/api/serving/link/alias', { code }, 'Alias created');
      const l = (D.serv.links || []).find((x) => x.code === r.result);
      if (l) copy(l.short, 'alias link');
    } catch { /* shown */ }
  },
  async linkSign() {
    try {
      const r = await post('/api/serving/sign', { mount: +$('#l_mount').value, path: $('#l_path').value, seconds: +$('#l_signdur').value, mods: linkMods() });
      $('#l_signed').textContent = r.url + '  (valid until ' + fmt.dt(r.expires) + ')';
      copy(r.url, 'signed link');
    } catch (e) { note(e.message); }
  },
  async linkDelete(code) { const ok = await ask({ kicker: 'Delete link', title: '/l/' + code, danger: true, ok: 'Delete', text: 'The short URL stops working.' }); if (ok) { try { await mutate('/api/serving/link/delete', { code }, 'Link deleted'); } catch { /* shown */ } } },
  linkStats(code) { showRequests({ q: '/l/' + code, ipFilter: '' }); },
});

/* ================================================================== alerts */

function vAlerts() {
  const A = D.alerts;
  if (!A) return loading('Loading alerts…');
  const list = A.alerts.filter((a) => S.alFilter === 'all' || !a.ack);
  const rows = list.map((a) => ({ cells: [cell(fmt.dt(a.ts), 'dim'), hcell(`<span class="acc ${a.severity === 'info' ? 'dim' : 'hot'}">${esc(a.severity)}</span>`), cell(a.kind, 'dim'), cell(a.title, 'h800', a.title),
    cell(a.detail, 'dim', a.detail), cell(a.sent === 1 ? 'e-mailed' : a.sent === 2 ? 'below threshold' : A.config.configured ? 'pending' : '—', 'dim'),
    hcell(a.ack ? '<span class="dim small">done</span>' : `<button class="pill" data-act="alAck" data-arg="${a.id}">Done</button>`)] }));
  const c = A.config;
  return `<div class="split" style="grid-template-columns:1fr 320px"><section class="aside">
    <div class="tbar">${[['open', 'Open'], ['all', 'All']].map(([k, l]) => `<button class="pill ${S.alFilter === k ? 'on' : ''}" data-act="alFilter" data-arg="${k}">${l}</button>`).join('')}
      <div class="fill"></div><button class="pill" data-act="alAckAll">Mark all done</button></div>
    ${table('alerts', [{ t: 'When', w: 110 }, { t: 'Level', w: 80 }, { t: 'Kind', w: 80 }, { t: 'Alert', w: 320 }, { t: 'Detail', w: 360 }, { t: 'Delivery', w: 110 }, { t: '', w: 70 }], rows,
      { empty: 'No open alerts. New problems show up here.' })}</section>
    <aside class="aside"><div class="pad"><div class="cap red">E-mail</div><h5>${c.configured ? 'Set up' : 'Not set up'}</h5></div>
      <div class="small px-16 py-0">${c.configured ? `To ${esc(c.to.join(', '))} from ${esc(c.from)} · ${esc(c.min_severity)} and above · ${esc(c.digest)} report` : 'Add a Resend API key in Settings to get alerts by e-mail.'}
      <div class="act-row"><button class="btn btn-secondary" data-act="go" data-arg="settings">Notification settings</button></div></div></aside></div>`;
}
Object.assign(ACT, {
  alFilter(f) { S.alFilter = f; render(true); },
  async alAck(id) { try { await post('/api/alerts/ack', { ids: [+id] }); VIEW_REFRESH.alerts(); } catch (e) { note(e.message); } },
  async alAckAll() { try { await post('/api/alerts/ack', { ids: 'all' }); VIEW_REFRESH.alerts(); } catch (e) { note(e.message); } },
});
NAV_BADGES.push(() => {
  const L = D.live || {};
  const al = L.alerts || {};
  const n = (al.critical || 0) + (al.warning || 0);
  return { badges: { alerts: n ? String(n) : al.info ? String(al.info) : '', blacklist: L.blacklist ? fmt.n(L.blacklist) : '' }, alerts: { alerts: n > 0 } };
});

/* ================================================================== settings panels */

SETTINGS_PANELS.push((row, toggle) => {
  const me = D.me;
  if (!me) { loadMe().then(() => { if (S.view === 'settings') render(true); }); return '<section class="panel span2"><div class="empty">Loading account settings…</div></section>'; }
  // each panel shows only when the account may save it (the server checks again)
  const can = (c) => (me.capabilities || []).includes(c), isRoot = me.role === 'root' || String(me.user || '').startsWith('api:');
  const a = D.alertsCfg;
  if (!a && can('alerts.config') && !D.alertsCfgLoading) { D.alertsCfgLoading = true; get('/api/alerts').then((r) => { D.alertsCfg = r.config; if (S.view === 'settings') render(true); }).catch(() => {}); }
  const cfg = a || {};
  const ab = me.autoban;
  const caps = D.cf?.caps;
  if (!D.cf && can('cdn.manage') && !D.cfLoading) { D.cfLoading = true; loadCf().then(() => { if (S.view === 'settings') render(true); }); }
  return `
  <section class="panel">
    <div class="ph"><h5>Security</h5><span class="small dim">your sign-in</span></div>
    ${isRoot ? row('Authenticator app', me.totp ? `Replaces the e-mailed code. ${me.recovery_left} recovery codes left.` : 'Use an app instead of e-mailed codes.',
      me.totp ? '<button class="pill" data-act="tfRecovery">New recovery codes</button> <button class="pill danger" data-act="tfDisable">Turn off</button>' : '<button class="pill on" data-act="tfBegin">Set up</button>') : ''}
    ${row('Password', 'Changing it signs out every session.', '<button class="pill" data-act="pwChange">Change…</button>')}
    ${row('Sessions', (isRoot ? fmt.n(me.sessions) + ' active' : 'Signed in') + (me.session_hours ? ', ' + esc(me.session_hours) + ' h at most' : ''), '<button class="pill" data-act="logout">Sign out</button>')}
  </section>
  ${can('alerts.config') ? `<section class="panel">
    <div class="ph"><h5>Notifications</h5><span class="small dim">via Resend</span></div>
    ${isRoot ? row('Resend API key', cfg.key_set ? 'set (hidden)' : 'not set: alerts stay in Alerts', `<input id="n_key" class="input w-170" type="password" placeholder="${cfg.key_set ? '•••••• (unchanged)' : 're_…'}" autocomplete="off">`) : ''}
    ${isRoot ? row('From', 'A sender on a domain verified in Resend', `<input id="n_from" class="input w-230" value="${esc(cfg.from || '')}" placeholder="Strata &lt;alerts@example.com&gt;">`) : ''}
    ${row('To', 'Comma separated', `<input id="n_to" class="input w-230" value="${esc((cfg.to || []).join(', '))}">`)}
    ${row('Send', 'Lowest level that gets e-mailed', `<select id="n_sev" class="input">${['info', 'warning', 'critical'].map((s) => `<option ${cfg.min_severity === s ? 'selected' : ''}>${s}</option>`).join('')}</select>`)}
    ${row('Report', 'Summary e-mail', `<select id="n_dig" class="input">${['off', 'daily', 'weekly'].map((s) => `<option ${cfg.digest === s ? 'selected' : ''}>${s}</option>`).join('')}</select> at <input id="n_hour" class="input w-44" value="${esc(cfg.digest_hour ?? 8)}">:00`)}
    <div class="act-row"><button class="btn btn-primary" data-act="nSave">Save</button><button class="btn btn-secondary" data-act="nTest" ${cfg.configured ? '' : 'disabled'}>Send test</button>${cfg.key_set && isRoot ? '<button class="btn btn-secondary" data-act="nClear">Remove key</button>' : ''}</div>
  </section>` : ''}
  ${can('system.settings') ? `<section class="panel">
    <div class="ph"><h5>Uploads & versions</h5></div>
    ${row('Chunk size', 'Per request. Keep it below 100 MB for Cloudflare.', `<input id="u_chunk" class="input w-60" value="${me.upload.chunk_mb}"> MiB`)}
    ${row('Parallel requests', 'How many chunks upload at once', `<input id="u_par" class="input w-60" value="${me.upload.parallel}">`)}
    ${row('Versions kept', 'Earlier versions kept per file', `<input id="u_keep" class="input w-60" value="${me.versions_keep}">`)}
    <div class="act-row"><button class="btn btn-primary" data-act="uSave">Save</button></div>
  </section>` : ''}
  ${can('security.autoban') ? `<section class="panel">
    <div class="ph"><h5>Auto-ban</h5><span class="small dim">bans scanners that probe for weak spots</span></div>
    ${row('Enabled', 'Bans at Caddy and, if allowed, at Cloudflare', toggle(ab.enabled, 'abToggle'))}
    ${row('Threshold', 'Probe requests from one IP…', `<input id="ab_probes" class="input w-60" value="${ab.probes}">`)}
    ${row('Window', '…within this many minutes', `<input id="ab_win" class="input w-60" value="${ab.window_minutes}"> min`)}
    ${row('Ban length', 'Bans expire on their own', `<input id="ab_hours" class="input w-60" value="${ab.ban_hours}"> h`)}
    <div class="act-row"><button class="btn btn-primary" data-act="abSave">Save</button></div>
  </section>` : ''}
  ${can('cdn.manage') ? `<section class="panel span2">
    <div class="ph"><h5>Cloudflare</h5><span class="small dim">uses the API token in strata.json</span></div>
    ${caps ? ['zone', 'lists', 'waf', 'purge'].map((k) => caps[k] ? row({ zone: 'Zone access', lists: 'IP list (blocklist)', waf: 'WAF custom rules (blocklist)', purge: 'Cache purge' }[k],
      caps[k].ok ? 'working' : caps[k].ok === false ? 'missing permission: ' + (caps[k].need || '') : 'not tested yet, checked at the first purge', `<span class="${caps[k].ok ? '' : 'hot'} h800">${caps[k].ok ? 'ok' : caps[k].ok === false ? 'missing' : '—'}</span>`) : '').join('') : '<div class="empty">Checking the token…</div>'}
    ${row('Blocklist at Cloudflare', 'Block listed visitors at Cloudflare too', toggle(D.cf ? D.cf.edge_enabled : true, 'cfEdge'))}
    ${row('Automatic purges', 'Purge a file from Cloudflare when it changes', toggle(D.cf ? D.cf.autopurge : true, 'cfAuto'))}
    ${D.cf?.queue ? row('Purge queue', D.cf.queue.pending ? `${fmt.n(D.cf.queue.pending)} waiting since ${fmt.dt(D.cf.queue.oldest)}${D.cf.queue.ok === false ? ': ' + D.cf.queue.error : ''}` : 'empty: every purge went through',
      `<span class="${D.cf.queue.pending && D.cf.queue.ok === false ? 'hot' : ''} h800">${fmt.n(D.cf.queue.pending)}</span> <button class="pill" data-act="cfPurgeRetry" ${D.cf.queue.pending ? '' : 'disabled'}>Retry now</button>`) : ''}
    ${row('Purge now', 'Single URLs or the whole cache', '<button class="pill" data-act="cfPurgeUrls">Purge URLs…</button> <button class="pill danger" data-act="cfPurgeAll">Purge everything</button>')}
  </section>` : ''}`;
});
// Smart-Sorting (uploads) and share-link lifetime / abuse guard
SETTINGS_PANELS.push((row, toggle) => {
  const me = D.me;
  if (!me || !me.smartsort || !(me.capabilities || []).includes('system.settings')) return '';
  const ss = me.smartsort, lk = me.links || {}, ab = lk.abuse || {};
  const drives = (typeof served === 'function' ? served() : []).filter((m) => m.kind !== 'page');
  if (!drives.length && typeof loadDrives === 'function' && !D.drives) loadDrives().then(() => { if (S.view === 'settings') render(true); });
  const num = (id, v, w = 64) => `<input id="${id}" class="input" value="${esc(v ?? '')}" style="width:${w}px">`;
  return `
  <section class="panel">
    <div class="ph"><h5>Smart-Sorting</h5><span class="small dim">sorts uploads into type folders</span></div>
    ${row('Home folder', 'Uploads to a drive root go here', `<select id="ss_mount" class="input">${drives.map((m) => `<option value="${m.mount}" ${ss.home && +ss.home.mount === m.mount ? 'selected' : ''}>${esc(m.name)}</option>`).join('')}</select> ${num('ss_home', ss.home ? ss.home.path : '', 150)}`)}
    ${row('Drive root → home', 'Off: uploads at the root stay at the root', toggle(ss.root_to_home, 'ssRoot'))}
    ${row('Assets folder', 'Elsewhere, uploads go to <folder>/this/<type>/', num('ss_assets', ss.assets || 'assets', 120))}
    <div class="form cols-3f">${Object.entries(ss.folders || {}).map(([c, f]) => `<label>${esc(c)}<input class="input ss_f" data-cat="${esc(c)}" value="${esc(f)}"></label>`).join('')}</div>
    <div class="act-row"><button class="btn btn-primary" data-act="ssSave">Save</button></div>
  </section>
  <section class="panel">
    <div class="ph"><h5>Share links</h5><span class="small dim">short /l/ links and signed links</span></div>
    ${row('Default lifetime', 'Days until new links expire (0 = never)', num('lk_days', lk.default_days ?? 7) + ' days')}
    ${row('Abuse guard', 'Expire links that look abused, with an alert', toggle(ab.enabled, 'lkGuard'))}
    ${row('One address', 'Clicks from a single IP within 10 minutes', num('lk_ip', ab.per_ip_10m))}
    ${row('Click flood', 'Clicks within 10 minutes', num('lk_flood', ab.clicks_10m))}
    ${row('Spread', 'Different countries within an hour', num('lk_cc', ab.countries_1h))}
    ${row('Bots', 'Share of bot clicks per hour (previews don’t count)',
      num('lk_botpct', Math.round((ab.bot_share ?? 0.8) * 100), 52) + ' % of ≥ ' + num('lk_botmin', ab.bot_min, 52))}
    <div class="act-row"><button class="btn btn-primary" data-act="lkSave">Save</button></div>
  </section>`;
});
Object.assign(ACT, {
  async ssSave() {
    const folders = {};
    document.querySelectorAll('.ss_f').forEach((el) => { folders[el.dataset.cat] = el.value.trim(); });
    const home = $('#ss_home').value.trim();
    try {
      D.me = await post('/api/settings/smartsort', { home: home ? { mount: +$('#ss_mount').value, path: home } : null, assets: $('#ss_assets').value.trim(), folders });
      note('Smart-Sorting saved'); render(true);
    } catch (e) { note(e.message); }
  },
  async ssRoot(v) { try { D.me = await post('/api/settings/smartsort', { root_to_home: v === '1' }); render(true); } catch (e) { note(e.message); } },
  async lkSave() {
    try {
      D.me = await post('/api/settings/links', { default_days: +$('#lk_days').value || 0, per_ip_10m: +$('#lk_ip').value, clicks_10m: +$('#lk_flood').value,
        countries_1h: +$('#lk_cc').value, bot_min: +$('#lk_botmin').value, bot_share: (+$('#lk_botpct').value || 80) / 100 });
      note('Share-link settings saved'); render(true);
    } catch (e) { note(e.message); }
  },
  async lkGuard(v) { try { D.me = await post('/api/settings/links', { abuse_enabled: v === '1' }); render(true); } catch (e) { note(e.message); } },
});
Object.assign(ACT, {
  async tfBegin() {
    try {
      const r = await post('/api/2fa/begin', {});
      openSheet('Authenticator app', 'Scan with your authenticator app', `<div class="twofa">${r.qr ? `<img alt="QR code" src="data:image/svg+xml;base64,${btoa(unescape(encodeURIComponent(r.qr)))}">` : ''}
        <div><p class="small">Or enter this key in the app:</p><div class="code">${esc(r.secret.replace(/(.{4})/g, '$1 ').trim())}</div>
        <label class="wide d-grid gap-5 mt-12">Code from the app<input id="tf_code" class="input fs-22 ls-code w-170" inputmode="numeric" autocomplete="one-time-code"></label></div></div>`,
      '<button class="btn btn-primary" data-act="tfEnable">Turn on</button>');
    } catch (e) { note(e.message); }
  },
  async tfEnable() {
    try {
      const r = await post('/api/2fa/enable', { code: $('#tf_code').value });
      openSheet('Authenticator app is on', 'Save your recovery codes', `<p class="small">If you lose your phone, each code works once instead of a code from the app. They are shown only now.</p><div class="code">${r.recovery.map(esc).join('<br>')}</div>`,
        `<button class="btn btn-primary" data-act="fcopy" data-arg="${esc(r.recovery.join('\n'))}">Copy codes</button>`);
      D.me = null; if (S.view === 'settings') render(true);
    } catch (e) { note(e.message); }
  },
  async tfDisable() {
    const code = await ask({ kicker: 'Turn off the authenticator app', title: 'Enter a current code or a recovery code', input: '', ok: 'Turn off', danger: true });
    if (!code) return;
    try { await post('/api/2fa/disable', { code }); note('Authenticator app is off'); D.me = null; render(true); } catch (e) { note(e.message); }
  },
  async tfRecovery() {
    const code = await ask({ kicker: 'New recovery codes', title: 'Enter a code from the app', input: '', ok: 'Create' });
    if (!code) return;
    try { const r = await post('/api/2fa/recovery', { code }); openSheet('Recovery codes', 'New codes (the old ones stop working)', `<div class="code">${r.recovery.map(esc).join('<br>')}</div>`, `<button class="btn btn-primary" data-act="fcopy" data-arg="${esc(r.recovery.join('\n'))}">Copy codes</button>`); D.me = null; } catch (e) { note(e.message); }
  },
  pwChange() {
    openSheet('Password', 'Change your password', `<div class="form"><label class="wide">Current password<input id="pw_cur" class="input" type="password" autocomplete="current-password"></label>
      <label class="wide">New password (12+ characters)<input id="pw_new" class="input" type="password" autocomplete="new-password"></label>
      <label class="wide">Repeat<input id="pw_new2" class="input" type="password" autocomplete="new-password"></label></div>`, '<button class="btn btn-primary" data-act="pwSave">Change password</button>');
  },
  async pwSave() {
    if ($('#pw_new').value !== $('#pw_new2').value) return note('The new passwords don’t match');
    try { await post('/api/password', { current: $('#pw_cur').value, new: $('#pw_new').value }); closeSheet(); location.href = '/login'; } catch (e) { note(e.message); }
  },
  async nSave() {
    const body = { to: $('#n_to').value, min_severity: $('#n_sev').value, digest: $('#n_dig').value, digest_hour: +$('#n_hour').value || 8 };
    if ($('#n_from')) body.from = $('#n_from').value; // sender + key: root only (they deliver sign-in codes)
    if ($('#n_key')?.value) body.resend_api_key = $('#n_key').value.trim();
    try { const r = await post('/api/alerts/config', body); D.alertsCfg = r.config; note('Notification settings saved'); render(true); } catch (e) { note(e.message); }
  },
  async nClear() { try { const r = await post('/api/alerts/config', { clear_key: true }); D.alertsCfg = r.config; render(true); } catch (e) { note(e.message); } },
  async nTest() { try { await post('/api/alerts/test', {}); note('Test e-mail sent'); } catch (e) { note(e.message); } },
  async uSave() { try { D.me = await post('/api/settings/upload', { chunk_mb: +$('#u_chunk').value, parallel: +$('#u_par').value, versions_keep: +$('#u_keep').value }); await loadMe(); note('Upload settings saved'); render(true); } catch (e) { note(e.message); } },
  async abToggle(v) { try { await post('/api/settings/autoban', { enabled: v === '1' }); await loadMe(); render(true); } catch (e) { note(e.message); } },
  async abSave() { try { await post('/api/settings/autoban', { probes: +$('#ab_probes').value, window_minutes: +$('#ab_win').value, ban_hours: +$('#ab_hours').value }); await loadMe(); note('Auto-ban saved'); render(true); } catch (e) { note(e.message); } },
  async cfEdge(v) { try { D.cf = await post('/api/cloudflare/settings', { edge_enabled: v === '1' }); render(true); } catch (e) { note(e.message); } },
  async cfAuto(v) { try { D.cf = await post('/api/cloudflare/settings', { autopurge: v === '1' }); render(true); } catch (e) { note(e.message); } },
  async cfPurgeRetry() {
    try {
      D.cf = await post('/api/cloudflare/purge-retry', {});
      const q = D.cf.queue || {};
      note(q.pending ? q.pending + ' purge(s) still waiting' + (q.ok === false ? ': ' + (q.error || '') : '') : 'Queued Cloudflare purges sent');
      if (S.ftab === 'trash' && typeof pollFiles === 'function') pollFiles(true);
      render(true);
    } catch (e) { note(e.message); }
  },
  cfPurgeUrls() { openSheet('Cloudflare', 'Purge URLs from the cache', '<div class="form"><label class="wide">One URL per line<textarea id="cf_urls" class="input" rows="8" placeholder="https://${esc(cdnHost())}/file.png"></textarea></label></div>', '<button class="btn btn-primary" data-act="cfPurgeGo">Purge</button>'); },
  async cfPurgeGo() { try { const r = await post('/api/cloudflare/purge', { urls: $('#cf_urls').value.split(/\s+/).filter(Boolean) }); note('Purged ' + r.purged + ' URL(s)'); closeSheet(); } catch (e) { note(e.message); } },
  async cfPurgeAll() { const ok = await ask({ kicker: 'Cloudflare', title: 'Purge the entire cache of the zone?', danger: true, ok: 'Purge everything', text: 'Every visitor hits the origin until the cache refills.' }); if (ok) { try { await post('/api/cloudflare/purge-all', {}); note('Cache purged'); } catch (e) { note(e.message); } } },
});

VIEWFN.serving = vServing;
VIEWFN.blacklist = vBlacklist;
VIEWFN.links = vLinks;
VIEWFN.alerts = vAlerts;
