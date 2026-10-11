'use strict';
/* Strata Network: Cloudflare zone controls, DNS, tunnel ingress and guarded service exposure.
   Loaded after app.js and control.js. API writes are explicit, reviewed in the UI, and errors stay visible. */

const NET_TABS = [['overview', 'Overview', 'globe'], ['settings', 'Zone settings', 'sliders-horizontal'],
  ['dns', 'DNS records', 'route'], ['tunnel', 'Tunnel routes', 'cable'], ['expose', 'Expose a service', 'plug'], ['cache', 'Cache', 'cloud']];
const NET_CAPS = [
  ['zone', 'Zone access', 'zone'], ['settings_read', 'Read zone settings', 'settings_read'],
  ['settings', 'Edit zone settings', 'settings'], ['dns_read', 'Read DNS records', 'dns_read'], ['dns', 'Edit DNS records', 'dns'],
];
const NET_SETTING_GROUPS = [
  ['Transport security', ['ssl', 'min_tls_version', 'tls_1_3', '0rtt', 'http3', 'ipv6', 'websockets']],
  ['Traffic protection', ['security_level', 'browser_check', 'challenge_ttl', 'always_use_https']],
  ['Cache and delivery', ['development_mode', 'cache_level', 'browser_cache_ttl', 'always_online', 'automatic_https_rewrites', 'early_hints']],
  ['Privacy and compatibility', ['email_obfuscation', 'hotlink_protection', 'opportunistic_encryption', 'rocket_loader']],
];
Object.assign(S, { netTab: store.get('networkTab', 'overview'), netDnsQ: '' });
if (!NET_TABS.some(([k]) => k === S.netTab)) S.netTab = 'overview';
Object.assign(D, { net: { status: null, settings: null, dns: null, ingress: null, listening: null, errors: {}, busy: '', loading: false,
  seq: 0, draft: null, exposure: null, test: null, pendingRestart: false } });
STATIC_VIEWS.add('network');

const netKeys = (tab = S.netTab) => ({
  overview: ['status', 'ingress', 'listening'], settings: ['status', 'settings'], dns: ['status', 'dns'],
  tunnel: ['status', 'ingress'], expose: ['status', 'ingress', 'listening'],
}[tab] || ['status']);
async function netRefresh(keys = netKeys(), force = false) {
  const n = D.net, seq = ++n.seq;
  n.loading = true;
  const routes = {
    status: '/api/network/status',
    settings: '/api/network/settings' + (force ? '?force=1' : ''),
    dns: '/api/network/dns' + (force ? '?force=1' : ''),
    ingress: '/api/network/ingress',
    listening: '/api/network/listening',
  };
  await Promise.all(keys.map(async (key) => {
    try { n[key] = await get(routes[key]); n.errors[key] = ''; }
    catch (e) { n.errors[key] = e.message || 'Could not load this section'; }
  }));
  if (seq !== n.seq) return;
  n.loading = false;
  if (S.view === 'network') render(true);
}
VIEW_REFRESH.network = () => netRefresh(netKeys());

const netEsc = (v) => esc(v == null ? '' : v);
const netDate = (s) => s ? fmt.dt(s) : '—';
function netPanel(title, detail, body, ic = '') {
  return `<section class="panel net-panel"><div class="ph"><h5>${ic ? icon(ic) : ''}${esc(title)}</h5>${detail ? `<span class="small dim">${esc(detail)}</span>` : ''}</div>${body}</section>`;
}
function netPill(ok, yes = 'Ready', no = 'Needs setup') {
  return `<span class="net-pill ${ok ? 'good' : 'bad'}"><i></i>${esc(ok ? yes : no)}</span>`;
}
function netError(key, title) {
  const e = D.net.errors[key];
  return e ? `<div class="net-callout error"><div class="row">${icon('circle-alert')}<b>${esc(title || 'Could not load this data')}</b></div><div class="small">${esc(e)}</div></div>` : '';
}
function netEmpty(key, title, detail, ic = 'cloud-off') {
  const err = D.net.errors[key];
  return err ? `<div class="net-callout error"><div class="row">${icon('circle-alert')}<b>${esc(title)}</b></div><div class="small">${esc(err)}</div><button class="pill" data-act="netReload">Try again</button></div>`
    : `<div class="net-empty">${icon(ic)}<b>${esc(title)}</b><span>${esc(detail)}</span></div>`;
}
function netTokenNotice() {
  const s = D.net.status;
  if (s?.token) return '';
  return `<div class="net-callout warn"><div class="row">${icon('key-round')}<b>Cloudflare API token is not configured</b></div>
    <div class="small">Zone settings and DNS controls need an API token stored in this Strata instance’s server configuration. The dashboard never asks for or stores the token in your browser. Tunnel routes and service exposure can still use cloudflared’s existing login.</div></div>`;
}
function netCapState(cap) {
  if (!cap || cap.ok == null) return ['pending', 'Not checked'];
  if (cap.ok) return ['good', 'Available'];
  return ['bad', 'Permission needed'];
}
function netPermissions() {
  const S0 = D.net.status;
  if (!S0) return netEmpty('status', 'Cloudflare permissions unavailable', 'Refresh to check the server token and zone access.');
  if (!S0.token) return netTokenNotice();
  return `<div class="net-caps">${NET_CAPS.map(([key, label, perm]) => {
    const [cls, status] = netCapState(S0.caps?.[key]);
    const error = S0.caps?.[key]?.error;
    return `<div class="net-cap"><div><b>${esc(label)}</b><span>${esc(S0.perms?.[perm] || '')}</span>${error ? `<small>${esc(error)}</small>` : ''}</div><span class="net-pill ${cls}"><i></i>${esc(status)}</span></div>`;
  }).join('')}</div>`;
}
function netHeader() {
  const s = D.net.status;
  const zone = s?.zone_name || INST.zone || 'Cloudflare zone';
  return `<div class="net-heading"><div><div class="net-eyebrow">Network control plane</div><h2>${icon('globe')}${esc(zone)}</h2>
    <p>Cloudflare, DNS, tunnel routing and protected local services for this Strata instance.</p></div>
    <div class="net-heading-actions">${D.net.loading ? `<span class="small dim row">${icon('loader-circle', 'spin')}Refreshing</span>` : ''}
      <button class="pill" data-act="netReload" title="Refresh this section">${icon('refresh-cw', 'sm')}Refresh</button></div></div>
    <div class="net-tabs" role="tablist">${NET_TABS.filter(([k]) => k !== 'cache' || meCan('cdn.manage')).map(([key, label, ic]) => `<button role="tab" aria-selected="${S.netTab === key}" class="${S.netTab === key ? 'on' : ''}" data-act="netTab" data-arg="${key}">${icon(ic, 'sm')}${esc(label)}</button>`).join('')}</div>`;
}
function netStatusCard(title, value, note, ic, state = '') {
  return `<div class="net-stat ${state}"><span class="net-stat-icon">${icon(ic)}</span><div><span class="cap">${esc(title)}</span><b>${esc(value)}</b><small>${esc(note)}</small></div></div>`;
}
function vNetwork() {
  const body = ({ overview: netOverview, settings: netZoneSettings, dns: netDns, tunnel: netTunnel, expose: netExpose, cache: () => cloudflarePanel(setRow, toggle) }[S.netTab] || netOverview)();
  return `<div class="net-page" data-scroll="network">${netHeader()}<div class="net-content">${body}</div></div>`;
}
function netOverview() {
  const n = D.net, s = n.status, ing = n.ingress, live = D.live?.tunnel, ports = n.listening?.ports || [];
  if (!s && !ing && !n.listening) return netEmpty('status', 'Network overview is loading', 'Cloudflare and tunnel status will appear here.');
  const cfg = ing?.restart || {};
  const rows = (ing?.rules || []).filter((r) => !r.catchall);
  const liveText = live ? (live.up ? `Connected · ${live.ha || 0}/4 links` : 'Tunnel is down') : 'Waiting for live status';
  const liveState = live ? (live.up ? 'good' : 'bad') : '';
  const capCount = s?.token ? NET_CAPS.filter(([, , k]) => s.caps?.[k]?.ok === true).length : 0;
  const capNote = s?.token ? `${capCount}/${NET_CAPS.length} permissions available` : 'Token not configured';
  const nonReserved = ports.filter((p) => !p.reserved).length;
  const cards = `<div class="net-stats">
    ${netStatusCard('Cloudflare token', s?.token ? 'Configured' : 'Not set', s?.zone_name || 'Configure on the Strata server', 'cloud', s?.token ? 'good' : 'warn')}
    ${netStatusCard('Tunnel', live ? (live.up ? 'Connected' : 'Offline') : 'Checking', liveText, 'cable', liveState)}
    ${netStatusCard('Ingress routes', fmt.n(rows.length), `${fmt.n(ing?.rules?.length || 0)} rules including catch-all`, 'route')}
    ${netStatusCard('Local services', fmt.n(nonReserved), `${fmt.n(ports.length - nonReserved)} reserved ports hidden from exposure`, 'plug')}
  </div>`;
  const routes = rows.slice(0, 5).map((r) => `<div class="net-route-preview"><div><b>${esc(r.hostname)}${r.path ? esc(r.path) : ''}</b><small>${esc(r.service)}</small></div>${r.extra ? `<span class="tag tag-neutral">origin options</span>` : ''}</div>`).join('');
  const routeBody = ing ? (rows.length ? `${routes}${rows.length > 5 ? `<button class="link" data-act="netTab" data-arg="tunnel">View ${fmt.n(rows.length - 5)} more routes →</button>` : ''}`
    : `<div class="small dim">No hostname routes configured yet.</div>`) : netError('ingress', 'Tunnel configuration unavailable');
  const connInfo = cfg.name ? `${cfg.kind || 'service'} · ${cfg.name}` : 'Tunnel restart target not configured';
  return `${cards}<div class="net-overview-grid">
    ${netPanel('Cloudflare permissions', capNote, netPermissions(), 'key-round')}
    ${netPanel('Tunnel routing', connInfo, routeBody + `<div class="act-row"><button class="pill" data-act="netTab" data-arg="tunnel">Manage routes</button><button class="pill" data-act="netTab" data-arg="expose">Expose a service</button></div>`, 'cable')}
    ${netPanel('Zone settings', 'HTTPS, cache, security and protocol options', `<p class="small dim">Changes are applied to the edge for this zone. Each value is read from Cloudflare before you edit it.</p><button class="btn btn-secondary" data-act="netTab" data-arg="settings">Review zone settings ${icon('arrow-right', 'sm')}</button>`, 'sliders-horizontal')}
    ${netPanel('DNS records', s?.zone_name ? `Managed zone · ${s.zone_name}` : 'Cloudflare zone records', `<p class="small dim">Review and edit supported A, AAAA, CNAME, TXT and MX records. Tunnel DNS records are identified in the list.</p><button class="btn btn-secondary" data-act="netTab" data-arg="dns">Manage DNS ${icon('arrow-right', 'sm')}</button>`, 'route')}
  </div><div class="net-footnote">${s?.token ? `Permission status last checked ${esc(netDate(s.caps?.zone?.ts))}.` : 'Cloudflare controls remain read-only until a server-side API token is configured.'} ${ing ? `Tunnel configuration: <code>${esc(ing.path || 'available')}</code>.` : ''}</div>`;
}

function netOptionLabel(s, value) {
  const words = { off: 'Off', on: 'On', zrt: 'On with 0-RTT', flexible: 'Flexible', full: 'Full', strict: 'Full (strict)',
    essentially_off: 'Essentially off', under_attack: 'Under attack', basic: 'Basic', simplified: 'Simplified', aggressive: 'Aggressive' };
  if (s.id === 'browser_cache_ttl') return +value === 0 ? 'Respect origin headers' : fmt.dur(+value);
  if (s.id === 'challenge_ttl') return fmt.dur(+value);
  return words[String(value)] || String(value);
}
function netControl(s) {
  const locked = !s.editable || !!D.net.busy;
  if (s.kind === 'toggle') return `<label class="sw" title="${s.value === 'on' ? 'On' : 'Off'}"><input type="checkbox" data-change="netSetting" data-arg="${esc(s.id)}" ${s.value === 'on' ? 'checked' : ''} ${locked ? 'disabled' : ''} aria-label="${esc(s.label)}"><b></b></label>`;
  return `<select class="input net-setting-select" data-change="netSetting" data-arg="${esc(s.id)}" ${locked ? 'disabled' : ''} aria-label="${esc(s.label)}">
    ${(s.choices || []).map((v) => `<option value="${esc(v)}" ${String(s.value) === String(v) ? 'selected' : ''}>${esc(netOptionLabel(s, v))}</option>`).join('')}</select>`;
}
function netZoneSettings() {
  const n = D.net, s = n.status;
  if (!n.settings) return `${netTokenNotice()}${netEmpty('settings', 'Zone settings are unavailable', 'Check that the Cloudflare token has Zone Settings Read permission.')}`;
  const settings = new Map((n.settings.settings || []).map((x) => [x.id, x]));
  const groups = NET_SETTING_GROUPS.map(([title, ids]) => {
    const items = ids.map((id) => settings.get(id)).filter(Boolean);
    if (!items.length) return '';
    const rows = items.map((item) => `<div class="net-setting-row"><div class="net-setting-copy"><b>${esc(item.label)}</b><span>${esc(item.help || '')}</span>${item.remaining ? `<small>Automatically expires in ${esc(fmt.dur(item.remaining))}</small>` : ''}</div>
      <div class="net-setting-control">${netControl(item)}</div></div>`).join('');
    return netPanel(title, `${items.length} available setting${items.length === 1 ? '' : 's'}`, rows, 'sliders-horizontal');
  }).join('');
  const unmapped = [...settings.values()].filter((item) => !NET_SETTING_GROUPS.some(([, ids]) => ids.includes(item.id)));
  const extra = unmapped.length ? netPanel('Other zone settings', '', unmapped.map((item) => `<div class="net-setting-row"><div class="net-setting-copy"><b>${esc(item.label)}</b><span>${esc(item.help || '')}</span></div><div class="net-setting-control">${netControl(item)}</div></div>`).join(''), 'settings') : '';
  return `${netTokenNotice()}${s?.token && s.caps?.settings_read?.ok === false ? netError('settings', 'Cloudflare settings permission required') : ''}
    <div class="net-settings-grid">${groups}${extra}</div><div class="net-footnote">Read from Cloudflare ${esc(netDate(n.settings.fetched))}. Selecting a value asks before sending the change.</div>`;
}

function netDnsForm() {
  const d = D.net.draft;
  if (!d) return '';
  const prox = ['A', 'AAAA', 'CNAME'].includes(d.type || 'A');
  return `<div class="net-dns-form"><div class="net-form-head"><div><b>${d.id ? 'Edit DNS record' : 'New DNS record'}</b><span>Names can be relative to the zone or full hostnames. “@” is the zone apex.</span></div><button class="icbtn sm" data-act="netDnsCancel" title="Close editor">${icon('x')}</button></div>
    <div class="net-fields">
      <label>Type<select id="nd_type" class="input"><option ${d.type === 'A' ? 'selected' : ''}>A</option><option ${d.type === 'AAAA' ? 'selected' : ''}>AAAA</option><option ${d.type === 'CNAME' ? 'selected' : ''}>CNAME</option><option ${d.type === 'TXT' ? 'selected' : ''}>TXT</option><option ${d.type === 'MX' ? 'selected' : ''}>MX</option></select></label>
      <label class="net-field-name">Name<input id="nd_name" class="input" value="${esc(d.name || '')}" placeholder="@ or cdn" autocomplete="off"></label>
      <label class="net-field-content">Content<input id="nd_content" class="input" value="${esc(d.content || '')}" placeholder="IP address, hostname or text" autocomplete="off"></label>
      <label>TTL (seconds)<input id="nd_ttl" class="input" type="number" min="1" max="2147483647" value="${esc(d.ttl && +d.ttl !== 1 ? d.ttl : '')}" placeholder="Auto"></label>
      <label>MX priority<input id="nd_priority" class="input" type="number" min="0" max="65535" value="${esc(d.priority || 10)}"></label>
      <label class="net-proxy-option"><span>Cloudflare proxy</span><span class="row"><input id="nd_proxied" type="checkbox" ${d.proxied !== false ? 'checked' : ''} ${prox ? '' : 'disabled'}> <span class="small dim">${prox ? 'Proxy HTTP traffic through Cloudflare' : 'Available for A, AAAA and CNAME only'}</span></span></label>
      <label class="net-field-comment">Comment<input id="nd_comment" class="input" maxlength="100" value="${esc(d.comment || '')}" placeholder="Optional note"></label>
    </div><div class="act-row"><button class="btn btn-primary" data-act="netDnsSave" ${D.net.busy ? 'disabled' : ''}>${icon('save', 'sm')}${d.id ? 'Save record' : 'Create record'}</button><button class="btn btn-secondary" data-act="netDnsCancel">Cancel</button></div></div>`;
}
function netDns() {
  const n = D.net, data = n.dns;
  if (!data) return `${netTokenNotice()}${netEmpty('dns', 'DNS records are unavailable', 'Cloudflare DNS Read permission is required to browse this zone.', 'route')}`;
  const q = S.netDnsQ.trim().toLowerCase();
  const rows = (data.records || []).filter((r) => !q || `${r.name} ${r.type} ${r.content} ${r.comment}`.toLowerCase().includes(q)).map((r) => {
    const editable = ['A', 'AAAA', 'CNAME', 'TXT', 'MX'].includes(r.type);
    const actions = `<span class="row net-row-actions">${editable ? `<button class="pill" data-act="netDnsEdit" data-arg="${esc(r.id)}" title="Edit ${esc(r.name)}">${icon('pencil', 'sm')}</button>` : '<span class="small dim">read only</span>'}<button class="pill danger" data-act="netDnsDelete" data-arg="${esc(r.id)}" title="Delete ${esc(r.name)}">${icon('trash', 'sm')}</button></span>`;
    const tags = [r.proxied ? '<span class="tag tag-accent">Proxied</span>' : '', r.mine ? '<span class="tag tag-neutral">This tunnel</span>' : '', !editable ? '<span class="tag tag-neutral">Read only</span>' : ''].filter(Boolean).join(' ');
    return { cells: [cell(r.type, 'h800'), hcell(`<span class="mono">${esc(r.name)}</span>${tags ? `<div class="net-dns-tags">${tags}</div>` : ''}`), cell(r.content, 'mono', r.content), cell(r.ttl === 1 ? 'Auto' : fmt.dur(r.ttl), 'dim'), hcell(actions)] };
  });
  const statusErr = n.status?.caps?.dns_read?.ok === false ? netError('dns', 'Cloudflare DNS permission required') : '';
  const recordTable = table('network-dns', [{ t: 'Type', w: 72 }, { t: 'Name', w: 240 }, { t: 'Content', w: 330 }, { t: 'TTL', w: 78 }, { t: 'Actions', w: 100 }], rows,
    { empty: q ? 'No records match this filter.' : 'No supported DNS records found in this zone.' });
  return `${netTokenNotice()}${statusErr}${netPanel('DNS records', `${fmt.n(data.records?.length || 0)} supported records · fetched ${fmt.ago(data.fetched)}`,
    `<div class="net-toolbar"><label class="qwrap">${icon('search')}<input id="net-dns-q" class="input" value="${esc(S.netDnsQ)}" placeholder="Filter by name, type or content…" autocomplete="off"></label>
      <div class="grow"></div><button class="pill" data-act="netDnsNew" ${D.net.busy ? 'disabled' : ''}>${icon('plus', 'sm')}Add record</button><button class="pill" data-act="netReload">${icon('refresh-cw', 'sm')}Refresh</button></div>
      ${netDnsForm()}${recordTable}<div class="net-footnote">${data.tunnel_id ? `Tunnel target <code>${esc(data.tunnel_id)}.cfargotunnel.com</code>; matching records are tagged.` : 'No tunnel ID could be read from the local cloudflared configuration.'} DNS changes apply at Cloudflare and may take time to propagate.</div>`, 'route')}`;
}

function netTunnel() {
  const n = D.net, ing = n.ingress;
  if (!ing) return netEmpty('ingress', 'Tunnel configuration is unavailable', 'Check this instance’s cloudflared config path and try again.', 'cable');
  const cfg = ing.restart || {};
  const rules = (ing.rules || []).map((r, idx, all) => {
    const isLast = !!r.catchall;
    const actions = isLast ? '<span class="small dim">required</span>' : `<span class="row net-row-actions"><button class="pill" data-act="netMoveIngress" data-arg="${r.i}|-1" ${idx === 0 || D.net.busy ? 'disabled' : ''} title="Move up">${icon('chevron-up', 'sm')}</button><button class="pill" data-act="netMoveIngress" data-arg="${r.i}|1" ${idx >= all.length - 2 || D.net.busy ? 'disabled' : ''} title="Move down">${icon('chevron-down', 'sm')}</button><button class="pill danger" data-act="netDeleteIngress" data-arg="${r.i}" ${D.net.busy ? 'disabled' : ''} title="Remove route">${icon('trash', 'sm')}</button></span>`;
    return { cells: [hcell(`<b>${esc(isLast ? 'All other hosts' : r.hostname)}</b>${r.path ? `<small class="net-route-path">${esc(r.path)}</small>` : ''}`), cell(r.service, 'mono', r.service), cell(r.extra ? 'custom origin options' : isLast ? 'fallback' : '—', 'dim'), hcell(actions)] };
  });
  const restart = cfg.name ? `${cfg.kind || 'service'} · ${cfg.name}` : 'No restart task or service configured';
  const form = `<div class="net-inline-form"><div class="net-form-head"><div><b>Add tunnel route</b><span>Routes are checked by cloudflared before they are saved. A saved edit needs a tunnel restart to take effect.</span></div></div>
    <div class="net-fields net-route-fields"><label>Hostname<input id="ni_host" class="input" placeholder="app.${esc(D.net.status?.zone_name || 'example.com')}" autocomplete="off"></label>
      <label>Forward to<input id="ni_service" class="input" value="${esc(ing.cdn || '')}" placeholder="http://localhost:8080" list="net-services" autocomplete="off"><datalist id="net-services">${[...new Set((ing.rules || []).map((r) => r.service).filter(Boolean))].map((v) => `<option value="${esc(v)}"></option>`).join('')}</datalist></label>
      <label>Path match (optional)<input id="ni_path" class="input" placeholder="/api/*" autocomplete="off"></label>
    </div><div class="net-inline-warning">${icon('info')}Direct routes to an app bypass Strata’s login gate. For a protected service, expose it through the wizard instead.</div>
    <div class="act-row"><button class="btn btn-primary" data-act="netAddIngress" ${D.net.busy ? 'disabled' : ''}>${icon('plus', 'sm')}Add tunnel route</button></div></div>`;
  const tableView = table('network-ingress', [{ t: 'Hostname / path', w: 255 }, { t: 'Tunnel service', w: 290 }, { t: 'Notes', w: 140 }, { t: 'Order / actions', w: 130 }], rules, { empty: 'No ingress rules found.' });
  const test = n.test ? `<div class="net-test-result ${n.test.ok ? 'good' : 'bad'}"><b>${n.test.ok ? 'Rule matched' : 'No matching route'}</b><pre>${esc(n.test.output || '')}</pre></div>` : '';
  return `<div class="net-tunnel-layout">${netPanel('Ingress rules', `${fmt.n(rules.length)} total · catch-all remains last`, `${netError('ingress', 'Tunnel configuration unavailable')}${tableView}${form}`, 'route')}
    ${netPanel('Tunnel controls', 'Applies to every hostname using this tunnel', `<div class="net-detail"><span>Configuration</span><code>${esc(ing.path || '—')}</code><span>Restart target</span><b>${esc(restart)}</b><span>Default Strata upstream</span><code>${esc(ing.cdn || '—')}</code></div>
      <div class="net-callout warn compact">Restarting interrupts all tunnelled hostnames briefly. A saved route change is not active until the restart succeeds.</div>
      <button class="btn btn-danger" data-act="netRestartTunnel" ${D.net.busy || !cfg.name ? 'disabled' : ''}>${icon('refresh-cw', 'sm')}Restart tunnel</button>
      ${n.pendingRestart ? '<div class="net-callout warn compact">You have unsaved-in-runtime route changes. Restart the tunnel to apply them.</div>' : ''}
      <div class="net-test"><b>Test a URL against ingress rules</b><span>Cloudflared reports which rule would handle it.</span><div class="row"><input id="ni_test" class="input" value="${esc(n.testUrl || '')}" placeholder="https://app.${esc(D.net.status?.zone_name || 'example.com')}/" autocomplete="off"><button class="pill" data-act="netTestIngress">Test</button></div>${test}</div>`, 'cable')}
  </div>`;
}

function netExpose() {
  const n = D.net, zone = n.status?.zone_name || 'example.com';
  const ports = (n.listening?.ports || []).filter((p) => !p.reserved);
  const exposure = n.exposure;
  const result = exposure ? `<div class="net-result ${exposure.steps?.every((s) => s.ok) ? 'good' : 'warn'}"><div class="net-result-title">${icon(exposure.steps?.every((s) => s.ok) ? 'circle-check' : 'triangle-alert')}<b>${exposure.steps?.every((s) => s.ok) ? 'Service setup completed' : 'Service setup needs attention'}</b></div>
      <div class="net-result-steps">${(exposure.steps || []).map((s) => `<div class="net-result-step ${s.ok ? 'good' : 'bad'}"><span>${icon(s.ok ? 'check' : 'circle-x', 'sm')}</span><div><b>${esc(s.step)}</b><small>${esc(s.note)}</small></div></div>`).join('')}</div>
      ${exposure.url ? `<div class="row net-result-url"><code>${esc(exposure.url)}</code><button class="pill" data-act="netOpenExposure">${icon('external-link', 'sm')}Open</button><button class="pill" data-act="netCopyExposure">${icon('copy', 'sm')}Copy URL</button></div>` : ''}
      <div class="small dim">A later failure can leave an earlier step in place. Review each step before retrying.</div></div>` : '';
  return `${n.status?.token ? '' : netTokenNotice()}${netError('listening', 'Could not inspect local listening ports')}
    <div class="net-expose-grid"><section class="panel net-panel net-wizard"><div class="ph"><h5>${icon('plug')}Expose a local service</h5><span class="small dim">Caddy proxy · Cloudflare Tunnel · optional DNS</span></div>
      <p class="small dim">Route a LAN or localhost app through this Strata instance. Strata validates the upstream, updates Caddy, adds the tunnel route and DNS, then can restart cloudflared.</p>
      <div class="net-fields">
        <label>Service name<input id="ne_name" class="input" placeholder="My app" maxlength="60" autocomplete="off"></label>
        <label>Upstream address<input id="ne_upstream" class="input" placeholder="127.0.0.1:1234" list="net-port-options" autocomplete="off"><datalist id="net-port-options">${ports.map((p) => `<option value="127.0.0.1:${p.port}">${esc(p.process || 'local process')} · ${esc(p.addr)}:${p.port}</option>`).join('')}</datalist></label>
        <label>Hostname<input id="ne_host" class="input" placeholder="app.${esc(zone)}" autocomplete="off"><small>Subdomain is enough; Strata adds .${esc(zone)}.</small></label>
        <label>URL prefix<input id="ne_prefix" class="input" value="/" placeholder="/app"><small>Use / to serve the entire hostname, or /app to share a host.</small></label>
      </div>
      ${ports.length ? `<div class="net-port-picks"><span class="cap">Detected local services</span>${ports.slice(0, 12).map((p, i) => `<button class="pill" data-act="netUsePort" data-arg="${i}" title="${esc(p.addr)}:${p.port} · pid ${p.pid}">${icon('plug', 'sm')}${esc(p.process || 'Process')} · ${p.port}</button>`).join('')}${n.listening?.ports?.some((p) => p.reserved) ? `<small class="dim">${fmt.n(n.listening.ports.filter((p) => p.reserved).length)} system ports are reserved and cannot be selected.</small>` : ''}</div>` : '<div class="small dim">No unreserved local TCP listeners found. You can still enter an address manually.</div>'}
      <div class="net-access"><b>Access policy</b><div class="net-access-options"><label class="net-access-option"><input type="radio" name="ne_gate" value="login" checked><span><b>Require Strata login</b><small>Recommended. Visitors sign in before the app loads.</small></span></label>
        <label class="net-access-option public"><input type="radio" name="ne_gate" value="public"><span><b>Public</b><small>Anyone with the URL can use this service.</small></span></label></div>
        <div class="net-fields net-gate-fields"><label>Gate username<input id="ne_user" class="input" maxlength="40" placeholder="Choose a username" autocomplete="username"></label><label>Gate password<input id="ne_pass" class="input" type="password" minlength="12" maxlength="200" placeholder="At least 12 characters" autocomplete="new-password"></label></div></div>
      <details class="net-advanced"><summary>Advanced routing</summary><div class="net-checks"><label><input id="ne_ingress" type="checkbox" checked> Add tunnel ingress</label><label><input id="ne_dns" type="checkbox" checked> Create proxied DNS record</label><label><input id="ne_restart" type="checkbox" checked> Restart tunnel after changes</label><label><input id="ne_strip" type="checkbox" checked> Strip the URL prefix before forwarding</label></div></details>
      <div class="net-callout warn compact">Reserved Strata, Caddy, monitoring and remote-access ports are blocked. Use an app port such as 127.0.0.1:1234.</div>
      <div class="act-row"><button class="btn btn-primary" data-act="netExposeService" ${D.net.busy ? 'disabled' : ''}>${D.net.busy === 'expose' ? icon('loader-circle', 'sm spin') : icon('plug', 'sm')}Review and expose</button></div>
      ${result}</section>
      ${netPanel('What this changes', 'A short checklist before publishing the route', `<div class="net-flow"><div><i>1</i><span><b>Strata drive</b><small>Caddy proxies to the local or LAN app; login gate is the default.</small></span></div><div><i>2</i><span><b>Tunnel ingress</b><small>Cloudflared forwards the chosen hostname to this Strata instance.</small></span></div><div><i>3</i><span><b>DNS</b><small>A proxied hostname record points at the tunnel.</small></span></div><div><i>4</i><span><b>Restart</b><small>Cloudflared reloads the validated route; the tunnel blips briefly.</small></span></div></div>
        <div class="net-callout info compact">The API rejects public Internet addresses, hostnames, Cloudflare metadata addresses and this host’s reserved ports. Use a private IP or loopback address.</div>
        <button class="pill" data-act="netTab" data-arg="tunnel">Review tunnel configuration ${icon('arrow-right', 'sm')}</button>`, 'shield-check')}
    </div>`;
}

function netNeed(n, message) { if (D.net.busy) { note('A Network operation is already in progress'); return true; } if (!n) { note(message, { err: true }); return true; } return false; }
async function netApply(url, body, keys, success, opts = {}) {
  if (D.net.busy) return note('A Network operation is already in progress');
  D.net.busy = opts.busy || 'saving';
  render(true);
  try {
    const r = await post(url, body);
    if (opts.onResult) opts.onResult(r);
    D.net.busy = '';
    if (opts.pendingRestart) D.net.pendingRestart = true;
    await netRefresh(keys, true);
    if (success) note(success);
    return r;
  } catch (e) {
    D.net.busy = '';
    render(true);
    note(e.message || 'Network change failed', { err: true });
    return null;
  }
}

Object.assign(ACT, {
  netTab(tab) {
    if (!NET_TABS.some(([k]) => k === tab)) return;
    S.netTab = tab; store.set('networkTab', tab); render(true); netRefresh(netKeys(tab));
  },
  netReload() { netRefresh(netKeys(), true); },
  async netSetting(value, el) {
    const item = (D.net.settings?.settings || []).find((s) => s.id === el.dataset.arg);
    if (!item || !item.editable) return render(true);
    const old = item.kind === 'toggle' ? item.value === 'on' : item.value;
    let next = item.kind === 'toggle' ? (value ? 'on' : 'off') : value;
    if (String(old) === String(next)) return;
    if (item.choices && item.choices.length && item.choices.every((x) => Number.isInteger(x))) next = +next;
    const ok = await ask({ kicker: 'Cloudflare zone setting', title: `Apply “${item.label}”?`, ok: 'Apply at Cloudflare',
      text: `${item.label}: ${netOptionLabel(item, old)} → ${netOptionLabel(item, next)}. ${item.help || ''} This change applies to the zone at Cloudflare.` });
    if (!ok) { render(true); return; }
    await netApply('/api/network/setting', { id: item.id, value: next }, ['settings', 'status'], `${item.label} updated.`, { busy: 'setting' });
  },
  netDnsNew() { D.net.draft = { type: 'A', name: '', content: '', proxied: true, ttl: 1, priority: 10, comment: '' }; render(true); },
  netDnsCancel() { D.net.draft = null; render(true); },
  netDnsEdit(id) {
    const r = (D.net.dns?.records || []).find((x) => x.id === id);
    if (!r || !['A', 'AAAA', 'CNAME', 'TXT', 'MX'].includes(r.type)) return;
    D.net.draft = Object.assign({}, r); render(true);
    const sel = $('#nd_type'); if (sel) sel.value = r.type;
  },
  async netDnsSave() {
    if (D.net.busy) return;
    const d = { ...(D.net.draft || {}), type: $('#nd_type')?.value || 'A', name: $('#nd_name')?.value.trim() || '', content: $('#nd_content')?.value.trim() || '',
      ttl: $('#nd_ttl')?.value || 1, priority: $('#nd_priority')?.value || 10, proxied: !!$('#nd_proxied')?.checked, comment: $('#nd_comment')?.value.trim() || '' };
    if (!d.name || !d.content) return note('Enter both a DNS name and content', { err: true });
    const isEdit = !!d.id;
    const ok = await ask({ kicker: 'Cloudflare DNS', title: `${isEdit ? 'Update' : 'Create'} ${d.type} record ${d.name}?`, ok: isEdit ? 'Update record' : 'Create record',
      text: `${d.name} → ${d.content}${d.proxied && ['A', 'AAAA', 'CNAME'].includes(d.type) ? ' · Cloudflare proxy on' : ''}. DNS changes apply at the edge and may take time to propagate.` });
    if (!ok) return;
    const r = await netApply('/api/network/dns', d, ['dns', 'status'], isEdit ? 'DNS record updated.' : 'DNS record created.', { busy: 'dns', onResult: () => { D.net.draft = null; } });
    if (r) D.net.draft = null;
  },
  async netDnsDelete(id) {
    const r = (D.net.dns?.records || []).find((x) => x.id === id);
    if (!r || D.net.busy) return;
    const ok = await ask({ kicker: 'Cloudflare DNS', title: `Delete ${r.type} record for ${r.name}?`, danger: true, ok: 'Delete DNS record',
      text: `This removes ${r.name} → ${r.content} from Cloudflare. The change may take time to propagate.` });
    if (ok) await netApply('/api/network/dns/delete', { id }, ['dns', 'status'], `Deleted the DNS record for ${r.name}.`, { busy: 'dns' });
  },
  async netAddIngress() {
    if (D.net.busy) return;
    const zone = D.net.status?.zone_name || '';
    let hostname = ($('#ni_host')?.value || '').trim().toLowerCase();
    if (hostname && !hostname.includes('.') && zone) hostname += '.' + zone;
    const service = ($('#ni_service')?.value || '').trim(), path = ($('#ni_path')?.value || '').trim();
    if (!hostname || !service) return note('Enter a hostname and tunnel service', { err: true });
    const direct = service !== (D.net.ingress?.cdn || '');
    const ok = await ask({ kicker: 'Cloudflare Tunnel', title: `Add route for ${hostname}?`, ok: 'Save tunnel route',
      text: `Requests to ${hostname}${path || ''} will be forwarded to ${service}. The validated config is saved, but this route is not active until the tunnel restarts. ${direct ? 'This direct route bypasses Strata’s login gate and can make the upstream reachable to anyone who can reach this tunnel hostname.' : 'If this hostname already has DNS, visitors may reach the Strata Caddy origin after restart.'}` });
    if (ok) await netApply('/api/network/ingress/add', { hostname, service, path }, ['ingress', 'status'], 'Validated tunnel route saved. Restart the tunnel to apply it.', { busy: 'ingress', pendingRestart: true });
  },
  async netDeleteIngress(index) {
    const r = (D.net.ingress?.rules || []).find((x) => x.i === +index);
    if (!r || r.catchall || D.net.busy) return;
    const ok = await ask({ kicker: 'Cloudflare Tunnel', title: `Remove route for ${r.hostname}?`, danger: true, ok: 'Remove route',
      text: 'The route will be removed from the validated config. If this hostname already has DNS, it will stop routing through this tunnel after restart.' });
    if (ok) await netApply('/api/network/ingress/delete', { index: +index }, ['ingress'], 'Tunnel route removed from the config. Restart the tunnel to apply it.', { busy: 'ingress', pendingRestart: true });
  },
  async netMoveIngress(arg) {
    if (D.net.busy) return;
    const [index, delta] = arg.split('|').map(Number);
    const r = (D.net.ingress?.rules || []).find((x) => x.i === index);
    if (!r || r.catchall) return;
    await netApply('/api/network/ingress/move', { index, delta }, ['ingress'], 'Tunnel route order updated. Restart the tunnel to apply it.', { busy: 'ingress', pendingRestart: true });
  },
  async netRestartTunnel() {
    if (D.net.busy) return;
    const ok = await ask({ kicker: 'Cloudflare Tunnel', title: 'Restart this tunnel?', danger: true, ok: 'Restart tunnel',
      text: 'All hostnames using this tunnel will briefly disconnect while cloudflared restarts.' });
    if (ok) {
      const r = await netApply('/api/network/restart', {}, ['ingress', 'status'], 'Tunnel restart requested.', { busy: 'restart' });
      if (r?.restarted) D.net.pendingRestart = false;
      else if (r?.note) note(r.note);
      render(true);
    }
  },
  async netTestIngress() {
    const url = ($('#ni_test')?.value || '').trim();
    if (!url) return note('Enter a full URL to test', { err: true });
    try { D.net.test = await post('/api/network/ingress/test', { url }); D.net.testUrl = url; render(true); }
    catch (e) { note(e.message || 'Could not test the ingress rule', { err: true }); }
  },
  netUsePort(index) {
    const p = D.net.listening?.ports?.filter((x) => !x.reserved)[+index];
    const input = $('#ne_upstream');
    if (p && input) { input.value = `127.0.0.1:${p.port}`; input.focus(); }
  },
  async netExposeService() {
    if (D.net.busy) return;
    let upstream = ($('#ne_upstream')?.value || '').trim();
    if (/^localhost:/i.test(upstream)) upstream = '127.0.0.1:' + upstream.slice(upstream.indexOf(':') + 1);
    let hostname = ($('#ne_host')?.value || '').trim().toLowerCase();
    const zone = D.net.status?.zone_name || '';
    if (hostname && !hostname.includes('.') && zone) hostname += '.' + zone;
    const prefix = ($('#ne_prefix')?.value || '/').trim() || '/';
    const mode = document.querySelector('input[name="ne_gate"]:checked')?.value || 'login';
    const user = ($('#ne_user')?.value || '').trim(), password = $('#ne_pass')?.value || '';
    if (!upstream || !hostname) return note('Enter an upstream address and hostname', { err: true });
    if (mode === 'login' && (!user || password.length < 12)) return note('Login protection needs a username and a password of at least 12 characters', { err: true });
    const body = { name: ($('#ne_name')?.value || '').trim(), upstream, hostname, prefix,
      gate: mode === 'login' ? { mode, hours: 12, users: [{ user, password }], public: [] } : { mode: 'public', hours: 12, users: [], public: [] },
      ingress: !!$('#ne_ingress')?.checked, dns: !!$('#ne_dns')?.checked, restart: !!$('#ne_restart')?.checked, strip: !!$('#ne_strip')?.checked };
    const publicMode = mode === 'public';
    const ok = await ask({ kicker: 'Review service exposure', title: `Expose ${hostname}${prefix === '/' ? '' : prefix}?`, danger: publicMode, ok: publicMode ? 'Expose publicly' : 'Expose behind login',
      text: `${upstream} will be served through this Strata instance${body.ingress ? ' and routed through Cloudflare Tunnel' : ''}${body.dns ? ' with a proxied DNS record' : ''}. ${publicMode ? 'Public access is enabled: anyone with the URL can use this service without signing in.' : `Visitors must sign in as “${user}”. The password is sent once to this Strata server to create the gate.`}${body.restart ? ' The tunnel will briefly disconnect during restart.' : ''}` });
    if (!ok) return;
    const result = await netApply('/api/network/expose', body, ['status', 'ingress', 'listening'], '', { busy: 'expose', onResult: (r) => { D.net.exposure = r; }, pendingRestart: false });
    if (result) {
      const complete = (result.steps || []).every((s) => s.ok);
      note(complete ? 'Service exposure completed' : 'Service was partly configured; review the step results', { err: !complete });
      if (result.steps?.some((s) => s.step === 'restart' && s.ok)) D.net.pendingRestart = false;
      render(true);
    }
  },
  netOpenExposure() { if (D.net.exposure?.url) window.open(D.net.exposure.url, '_blank', 'noopener'); },
  netCopyExposure() { if (D.net.exposure?.url) copy(D.net.exposure.url, 'service URL'); },
});

document.addEventListener('input', (e) => {
  if (e.target.id === 'net-dns-q') { S.netDnsQ = e.target.value; render(true); }
});
document.addEventListener('change', (e) => {
  if (e.target.id !== 'nd_type' || !D.net.draft) return;
  D.net.draft.type = e.target.value;
  render(true);
  const select = $('#nd_type'); if (select) select.value = D.net.draft.type;
});

NAV_BADGES.push(() => {
  const s = D.net.status;
  const bad = s && s.token && (s.caps?.zone?.ok === false || s.caps?.dns_read?.ok === false || s.caps?.settings_read?.ok === false);
  return { badges: { network: bad ? 'setup' : '' }, alerts: { network: !!bad } };
});
VIEWFN.network = vNetwork;
