'use strict';
/* Strata administration views: system health, log explorer, source IDE and staff access control. */
(() => {
  const A = D.admin = {
    system: null, logs: null, logSource: 'runtime', logSearch: '', logUser: '', logAction: '', logBefore: null,
    accounts: null, accountSelected: '', accountQuery: '', activationLink: '', activationUser: '',
    ide: { tree: null, search: '', path: '', text: '', saved: '', sha: '', mode: '', editor: null, drafts: {}, loading: false, error: '' },
  };
  ['system', 'logs', 'accounts', 'ide'].forEach((v) => STATIC_VIEWS.add(v));

  // /api/me lists exactly what the server will allow (root-only capabilities are absent for administrators)
  const has = (cap) => !!D.me && (D.me.capabilities || []).includes(cap);
  const stamp = (ts) => ts ? new Date(ts * 1000).toLocaleString() : '—';
  const status = (ok, yes = 'Healthy', no = 'Unavailable') => `<span class="sys-status ${ok ? 'ok' : 'hot'}"><i></i>${ok ? yes : no}</span>`;
  const stat = (label, value, sub = '', title = '') => `<div class="sys-stat"${title ? ` title="${esc(title)}"` : ''}><span class="cap">${esc(label)}</span><span><b>${esc(value)}</b>${sub ? `<small>${esc(sub)}</small>` : ''}</span></div>`;
  const adminErr = (msg) => `<section class="panel"><div class="empty big">${icon('shield-alert', 'xl')}<b>${esc(msg || 'This view is unavailable for this account.')}</b></div></section>`;

  async function loadSystem() {
    try { A.system = await get('/api/system'); render(true); }
    catch (e) { A.systemError = e.message; render(true); }
  }
  function vSystem() {
    if (!has('system.read')) return adminErr('This account can’t see system health. Ask an administrator for access.');
    if (!A.system) { if (!A.systemError) loadSystem(); return `<div class="sys-page">${loading('Reading instance health…')}</div>`; }
    const s = A.system, c = s.counts || {}, r = s.runtime_log || {};
    const services = (s.processes || []).map((p) => `<div class="sys-row"><div><b>${esc(p.name)}</b><small>${esc(p.addr || 'no listener configured')}</small></div>${status(!!p.up, 'Online', 'Offline')}</div>`).join('');
    const tables = (s.tables || []).map((t) => `<tr><td>${esc(t.name)}</td><td class="r">${fmt.bytes(t.bytes)}</td></tr>`).join('');
    const counts = Object.entries(c).map(([k, v]) => `<div class="sys-count"><span>${esc(k.replaceAll('_', ' '))}</span><b>${fmt.n(v)}</b></div>`).join('');
    return `<div class="sys-page">
      <section class="panel sys-overview"><div class="ph"><h5>${icon('cpu')} ${esc(s.instance?.name || 'Strata')}</h5><button class="pill" data-act="sysRefresh">${icon('refresh-cw', 'sm')}Refresh</button></div>
        <div class="sys-stats">${stat('Database', fmt.bytes(s.db?.size), fmt.n(s.db?.rows) + ' requests')}${stat('Running', fmt.dur(Date.now() / 1000 - s.started), 'PID ' + s.pid + ' · Python ' + s.python)}${stat('Runtime log', fmt.bytes(r.bytes), r.path ? r.path.split(/[\\/]/).pop() : 'not created yet', r.path)}</div></section>
      <div class="sys-grid"><section class="panel sys-panel"><div class="ph"><h5>${icon('activity')} Service health</h5><span class="small dim">local listeners</span></div><div class="sys-services">${services || '<div class="empty">No local services are configured.</div>'}</div></section>
        <section class="panel sys-panel"><div class="ph"><h5>${icon('database')} Stored records</h5><span class="small dim">live table counts</span></div><div class="sys-counts">${counts}</div></section>
        ${tables ? `<section class="panel sys-panel"><div class="ph"><h5>${icon('hard-drive')} Largest database tables</h5><span class="small dim">SQLite page allocation</span></div><div class="admin-table-wrap"><table class="admin-table"><thead><tr><th>Table</th><th class="r">Allocated</th></tr></thead><tbody>${tables}</tbody></table></div></section>` : ''}
        <section class="panel sys-panel"><div class="ph"><h5>${icon('settings')} Retention & maintenance</h5><span class="small dim">database controls</span></div>
          <p class="small dim">Raw requests are capped at ${fmt.n(s.raw_max)} retained rows. Rollups keep longer-range charts efficient.</p>
          <div class="sys-retention"><label>Raw request days<input id="sys-raw-days" class="input" type="number" min="1" max="3650" value="${esc(s.raw_retention_days ?? 30)}" ${has('system.retention') ? '' : 'disabled'}></label><label>Aggregate days<input id="sys-agg-days" class="input" type="number" min="7" max="3650" value="${esc(s.retention_days ?? 400)}" ${has('system.retention') ? '' : 'disabled'}></label></div>
          <div class="admin-actions">${has('system.retention') ? '<button class="btn btn-primary" data-act="sysRetention">Save retention</button>' : ''}${has('system.optimize') ? '<button class="btn btn-secondary" data-act="sysOptimize">Optimize database</button>' : ''}${has('system.retention') || has('system.optimize') ? '' : '<span class="small dim">You have read-only system access.</span>'}</div>
          <p class="small dim">Database optimization runs SQLite ANALYZE and a WAL checkpoint. Keep a current backup before changing retention.</p></section>
        ${versionsPanel()}
        ${meOwner() ? backupPanel() : ''}
      </div></div>`;
  }
  function backupPanel() {
    return `<section class="panel sys-panel"><div class="ph"><h5>${icon('archive')} Backup</h5><span class="small dim">owner only</span></div>
      <p class="small dim">Settings without keys or passwords, plus the database. The database holds password hashes, so keep the file private.</p>
      <div class="admin-actions"><a class="btn btn-primary" href="/api/backup" download>${icon('download', 'sm')} Download backup</a><label class="btn btn-secondary ${A.restoreBusy ? 'disabled' : ''}">${icon('upload', 'sm')}<span>${A.restoreBusy ? 'Restoring…' : 'Restore…'}</span><input type="file" accept=".zip,application/zip" data-change="sysRestore" hidden ${A.restoreBusy ? 'disabled' : ''}></label></div></section>`;
  }
  // moved here from Settings: what this instance runs
  function versionsPanel() {
    const L = D.live || {}, c = L.caddy || {}, t = L.tunnel || {}, cs = L.compress || {};
    return `<section class="panel sys-panel"><div class="ph"><h5>${icon('server')} Versions</h5><span class="small dim">this instance</span></div>
      <div class="kv" style="padding:4px 0 0">
        <span>Strata</span><span>${esc(INST.version || '—')}${INST.update ? `, <a href="${esc(INST.update.url)}" target="_blank" rel="noopener">${esc(INST.update.tag)} available</a>` : ''}</span>
        <span>Site</span><span>${esc(INST.name || '—')}, instance ${esc(INST.id || '—')}</span>
        <span>Caddy</span><span>${esc(c.version || '—')}, ${c.up ? 'up ' + esc(fmt.dur(c.uptime)) : 'unreachable'}</span>
        <span>cloudflared</span><span>${esc(t.version || '—')}, ${t.up ? t.ha + '/4 links, up ' + esc(fmt.dur(t.uptime)) : 'unreachable'}</span>
        <span>Compression</span><span>${cs.running ? 'scanning now' : 'idle'}, variants: ${esc((cs.variants || []).join(', ') || '—')}</span>
        <span>Public page</span><span>${esc(INST.stats_host || '—')} (redacted feed)</span>
      </div></section>`;
  }

  async function loadLogs(reset = true) {
    if (reset) A.logBefore = null;
    const p = new URLSearchParams({ source: A.logSource, limit: '250' });
    if (A.logSearch) p.set(A.logSource === 'access' ? 'q' : 'search', A.logSearch);
    if (A.logSource === 'access') { p.set('since', '604800'); if (A.logBefore) p.set('before', A.logBefore); }
    else if (A.logSource === 'activity') {
      if (A.logBefore) p.set('before', A.logBefore);
      if (A.logUser) p.set('user', A.logUser);
      if (A.logAction) p.set('action', A.logAction);
    }
    try {
      const response = await get('/api/logs?' + p.toString());
      if (A.logSource === 'runtime' || reset || !A.logs) A.logs = response;
      else A.logs = { ...response, rows: [...(A.logs.rows || []), ...(response.rows || [])] };
      A.logError = '';
      render(true);
    } catch (e) { A.logError = e.message; render(true); }
  }
  // one tab per log the account may read (logs.read is an old grant that the server expands into the first two)
  function logTabs() {
    return [['runtime', 'Runtime', 'logs.runtime'], ['access', 'Website requests', 'logs.access'], ['activity', 'Account activity', 'audit.read']]
      .filter(([, , cap]) => has(cap));
  }
  function logToolbar(meta) {
    const ph = { runtime: 'Search process log', access: 'Search paths, IPs, hosts, user agents', activity: 'Search events, IPs, targets' }[A.logSource];
    return `<div class="tbar">${logTabs().map(([id, label]) => `<button class="pill ${A.logSource === id ? 'on' : ''}" data-act="logSource" data-arg="${id}">${esc(label)}</button>`).join('')}
      <input id="log-search" class="input" value="${esc(A.logSearch)}" placeholder="${ph}" autocomplete="off">
      ${A.logSource === 'activity' ? `<input id="log-user" class="input" value="${esc(A.logUser)}" placeholder="Account"><input id="log-action" class="input" value="${esc(A.logAction)}" placeholder="Action">` : ''}
      <button class="pill" data-act="logSearch">${icon('search', 'sm')}Search</button>
      <span class="small dim ell log-meta">${esc(meta)}</span><button class="pill" data-act="logRefresh">${icon('refresh-cw', 'sm')}Refresh</button></div>`;
  }
  function vLogs() {
    const tabs = logTabs();
    if (!tabs.length) return adminErr('This account can’t see logs. Ask an administrator for access.');
    if (!tabs.some(([id]) => id === A.logSource)) A.logSource = tabs[0][0];
    if (!A.logs && !A.logError) loadLogs();
    const source = A.logs;
    let body = '', meta = '';
    if (A.logError) body = `<div class="empty">${esc(A.logError)}</div>`;
    else if (!source) body = loading('Loading ' + A.logSource + ' log…');
    else if (A.logSource === 'runtime') {
      meta = `${source.path || 'Strata process log'} · newest ${fmt.n(source.lines?.length)} lines${source.truncated ? ' · older rotated lines omitted' : ''}`;
      body = `<pre class="runtime-log">${(source.lines || []).map(esc).join('\n') || 'No process log lines match this filter.'}</pre>`;
    } else if (A.logSource === 'activity') {
      meta = `Append-only · ${fmt.n(source.rows?.length)} shown${source.append_only ? ' · deletion disabled' : ''}`;
      body = `<table class="admin-table log-table"><thead><tr><th>When</th><th>Account</th><th>Action</th><th>Source IP</th><th>Target / detail</th><th>Result</th></tr></thead><tbody>${(source.rows || []).map((r) => `<tr><td>${esc(stamp(r.ts))}</td><td>${esc(r.user || 'anonymous')}</td><td class="mono">${esc(r.action)}</td><td class="mono">${esc(r.ip)}</td><td class="log-target" title="${esc([r.target, r.note].filter(Boolean).join(' · '))}">${esc([r.target, r.note].filter(Boolean).join(' · '))}</td><td>${status(!!r.ok, 'OK', 'Denied')}</td></tr>`).join('') || '<tr><td colspan="6">No account events match this filter.</td></tr>'}</tbody></table>`;
    } else {
      meta = `Caddy requests · last 7 days · ${fmt.n(source.rows?.length)} shown`;
      body = `<table class="admin-table log-table"><thead><tr><th>When</th><th>Request</th><th>Path</th><th>Status</th><th>Bytes</th><th>Duration</th><th>IP / region</th><th>Client</th></tr></thead><tbody>${(source.rows || []).map((r) => `<tr><td>${esc(stamp(r.ts))}</td><td class="mono">${esc(r.method)} ${esc(r.host)}</td><td class="log-target" title="${esc(r.path)}">${esc(r.path)}</td><td class="${r.status >= 400 ? 'hot' : ''}">${esc(r.status)}</td><td>${fmt.bytes(r.bytes)}</td><td>${fmt.ms(r.dur)}</td><td class="mono">${esc(r.ip)} · ${esc(r.country || '—')}</td><td title="${esc(r.ua)}">${esc(r.agent || r.ua || '—')}</td></tr>`).join('') || '<tr><td colspan="8">No website requests match this filter.</td></tr>'}</tbody></table>`;
    }
    const more = A.logSource === 'activity' ? source?.next : source?.more ? source?.cursor : null;
    return `<div class="split" style="grid-template-columns:1fr"><section class="aside">${logToolbar(meta)}
      <div class="log-body">${body}${more ? `<div class="admin-more"><button class="pill" data-act="logMore">Load older entries</button></div>` : ''}</div></section></div>`;
  }

  /* ---------------------------------------------------------------- accounts (root only; the server enforces it) */

  const PRESET_ORDER = ['read_only', 'uploader', 'contributor', 'file_manager', 'analyst', 'custom', 'admin'];
  const presetsById = () => Object.fromEntries((A.accounts?.presets || []).map((p) => [p.id, p]));
  const presetLabel = (id) => presetsById()[id]?.name || (id === 'custom' ? 'Custom' : id);
  const permLabel = (id) => (A.accounts?.permissions || []).find((p) => p.id === id)?.label || id;
  const presetOf = (perms) => {
    const s = [...perms].sort().join(',');
    const hit = Object.values(presetsById()).find((p) => !['admin', 'custom'].includes(p.id) && [...p.permissions].sort().join(',') === s);
    return hit ? hit.id : 'custom';
  };
  const sameSet = (a, b) => a.size === b.size && [...a].every((x) => b.has(x));
  // <input type="date"> <-> unix seconds (the chosen day, until its end in local time)
  const dateIn = (ts) => { if (!ts) return ''; const d = new Date(ts * 1000); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; };
  const dateOut = (v) => (v ? Math.floor(new Date(v + 'T23:59:59').getTime() / 1000) : null);
  const day = (ts) => (ts ? new Date(ts * 1000).toLocaleDateString() : '');

  async function loadAccounts() {
    try {
      const [acc, signups] = await Promise.all([get('/api/accounts'), get('/api/settings/signups').catch(() => null)]);
      A.accounts = acc; A.signups = signups; A.accountsError = '';
      const list = acc.accounts || [];
      if (!list.some((u) => u.user === A.accountSelected)) A.accountSelected = list[0]?.user || '';
      A.draft = null; A.zoneEdit = null;
      render(true);
    } catch (e) { A.accountsError = e.message; render(true); }
  }
  async function busy(name, fn) {
    if (A.busy) return; // one account action at a time: no double submissions
    A.busy = name; render(true);
    try { await fn(); } catch (e) { note(e.message, { err: true }); } finally { A.busy = ''; render(true); }
  }
  const btn = (act, label, o = {}) => `<button class="btn ${o.primary ? 'btn-primary' : 'btn-secondary'} ${o.danger ? 'danger' : ''} ${o.small ? 'sm' : ''}" data-act="${act}"${o.arg != null ? ` data-arg="${esc(o.arg)}"` : ''}${A.busy || o.disabled ? ' disabled' : ''}${o.title ? ` title="${esc(o.title)}"` : ''}>${o.icon ? icon(o.icon, 'sm') : ''}<span>${A.busy === act ? 'Working…' : esc(label)}</span></button>`;
  const fileDrives = () => (A.accounts.drives?.served || []).filter((x) => x.kind === 'files'); // zones live on file drives only

  function draftFor(sel) {
    if (!A.draft || A.draft.user !== sel.user) {
      const perms = new Set((sel.permissions || []).filter((p) => p !== '*'));
      A.draft = { user: sel.user, preset: sel.role === 'admin' ? 'admin' : presetOf(perms), perms };
    }
    return A.draft;
  }
  function draftDirty(sel) {
    const d = A.draft;
    if (!d || d.user !== sel.user) return false;
    if ((d.preset === 'admin') !== (sel.role === 'admin')) return true;
    return d.preset !== 'admin' && !sameSet(d.perms, new Set((sel.permissions || []).filter((p) => p !== '*')));
  }

  function accountCard(u) {
    const state = !u.enabled ? (u.pending ? ['Invite pending', 'warn'] : ['Disabled', 'hot']) : u.expired ? ['Access ended', 'hot']
      : u.email_verified ? ['Active', 'ok'] : ['E-mail unverified', 'warn'];
    return `<button class="account-card ${u.user === A.accountSelected ? 'on' : ''}" data-act="accountSelect" data-arg="${esc(u.user)}" aria-pressed="${u.user === A.accountSelected}" title="${esc(u.user + (u.email ? ' · ' + u.email : ''))}">
      ${avatar(u.user, u.avatar, '', u.enabled && !u.pending)}
      <span class="account-main"><b>${esc(u.user)}</b><small>${esc(u.email || 'no e-mail address')}</small>
        <span class="account-tags"><span class="tag">${esc(u.role === 'root' ? 'Owner' : presetLabel(u.preset))}</span>${u.administrative && u.role !== 'root' ? '<span class="tag tag-accent">Moderator</span>' : ''}<span class="account-state ${state[1]}">${state[0]}</span></span></span>
    </button>`;
  }

  function identitySection(sel) {
    const isRoot = sel.role === 'root', self = sel.user.toLowerCase() === String(D.me?.user || '').toLowerCase();
    const facts = [['E-mail', sel.email ? `${esc(sel.email)} <span class="${sel.email_verified ? 'ok' : 'warn'}">· ${sel.email_verified ? 'verified' : 'not verified yet'}</span>` : '<span class="warn">none: needed for sign-in codes</span>'],
      ['Status', !sel.enabled ? (sel.pending ? '<span class="warn">Waiting for activation</span>' : '<span class="hot">Disabled</span>') : sel.expired ? '<span class="hot">Access period ended</span>' : '<span class="ok">Enabled</span>'],
      ['Last sign-in', esc(stamp(sel.last_login))], ['Created', esc(stamp(sel.created))],
      ['Home folder', sel.home ? `<code>${esc(sel.home.path)}</code>` : '<span class="dim">no storage assigned</span>']];
    if (!isRoot) {
      facts.push(['Access until', sel.expires ? `<span class="${sel.expired ? 'hot' : ''}">${esc(day(sel.expires))}</span>` : '<span class="dim">no end date</span>']);
      facts.push(['Networks', sel.allowed_ips?.length ? `<code>${esc(sel.allowed_ips.join(', '))}</code>` : '<span class="dim">any</span>']);
    }
    const actions = isRoot ? `<span class="admin-callout inline">${icon('shield-check', 'sm')} The owner account is protected. Change its password and e-mail in Settings › Account, or from the server CLI.</span>`
      : `${sel.pending ? '' : btn('accountStatus', sel.enabled ? 'Disable' : 'Enable', { arg: sel.enabled ? '0' : '1', icon: sel.enabled ? 'user-x' : 'user-check', disabled: self })}
         ${btn('accountRevokeSessions', 'Sign out everywhere', { icon: 'log-out' })}
         ${btn('accountPasswordReset', sel.pending ? 'New activation link' : 'Password reset link', { icon: 'key-round' })}
         ${btn('accountDelete', 'Delete account', { icon: 'trash-2', danger: true, disabled: self })}`;
    const adminBox = isRoot ? '' : `<label class="acct-admin-flag ${sel.administrative ? 'on' : ''}"><input type="checkbox" data-change="accountAdministrative" ${sel.administrative ? 'checked' : ''} ${A.busy || self ? 'disabled' : ''}>
        <span><b>Team moderator</b><small>Moderates the noticeboard and notes and manages colleagues’ Team access. Grants nothing outside Team.</small></span></label>`;
    return `<section class="panel acct-sec"><div class="acct-ident">${avatar(sel.user, sel.avatar, 'lg', sel.enabled && !sel.pending)}<div><div class="cap">Identity &amp; status</div><h4 class="acct-name">${esc(sel.user)}</h4>
        ${sel.avatar && !self ? btn('accountAvatarRemove', 'Remove picture', { small: true, icon: 'x', title: 'Remove this profile picture' }) : ''}</div></div>
      <dl class="acct-facts">${facts.map(([k, v]) => `<div><dt>${k}</dt><dd>${v}</dd></div>`).join('')}</dl>
      ${adminBox}
      ${sel.note ? `<p class="acct-note"><b>Note:</b> ${esc(sel.note)}</p>` : ''}
      <div class="acct-actions">${actions}</div></section>`;
  }

  function permissionSection(sel) {
    if (sel.role === 'root') {
      return `<section class="panel acct-sec"><div class="acct-sec-head"><div><div class="cap">Role &amp; permissions</div><h5>Owner</h5></div></div>
        <p class="acct-note">The owner can do everything, including what no other account can be given: managing accounts, editing Strata’s code and the sign-in e-mail sender.</p></section>`;
    }
    const d = draftFor(sel), dirty = draftDirty(sel), isAdmin = d.preset === 'admin';
    const perms = A.accounts.permissions || [], groups = A.accounts.groups || {};
    const grid = Object.entries(groups).map(([g, title]) => {
      const items = perms.filter((p) => p.group === g);
      if (!items.length) return '';
      const on = items.filter((p) => d.perms.has(p.id)).length;
      return `<fieldset class="perm-group"><legend>${esc(title)} <span class="dim">${on}/${items.length}</span></legend>
        <div class="perm-tools">${btn('accountPermGroup', 'All', { arg: g + ':1', small: true, disabled: isAdmin })}${btn('accountPermGroup', 'None', { arg: g + ':0', small: true, disabled: isAdmin })}</div>
        <div class="perm-grid">${items.map((p) => `<label class="perm-option ${d.perms.has(p.id) || isAdmin ? 'on' : ''}"><input type="checkbox" data-change="accountPerm" value="${esc(p.id)}" ${d.perms.has(p.id) || isAdmin ? 'checked' : ''} ${isAdmin ? 'disabled' : ''}><span><b>${esc(p.label)}</b><small>${esc(p.description)}</small><code>${esc(p.id)}</code></span></label>`).join('')}</div></fieldset>`;
    }).join('');
    const eff = isAdmin ? 'Everything except account management, code editing and the e-mail sender. Those stay with the owner.'
      : d.perms.size ? [...d.perms].sort().map((p) => `<span class="tag" title="${esc(p)}">${esc(permLabel(p))}</span>`).join(' ') : '<span class="warn">No capabilities - this account can sign in but sees nothing.</span>';
    const fileNote = !isAdmin && [...d.perms].some((p) => p.startsWith('files.')) ? '<p class="acct-note">File capabilities only apply inside the storage zones below, and each zone can narrow them further.</p>' : '';
    return `<section class="panel acct-sec"><div class="acct-sec-head"><div><div class="cap">Role &amp; permissions</div><h5>${esc(presetLabel(d.preset))}</h5></div>
        <label class="acct-preset">Preset<select class="input" id="account-preset" data-change="accountPreset">${PRESET_ORDER.filter((k) => presetsById()[k] || k === 'custom').map((k) => `<option value="${k}" ${d.preset === k ? 'selected' : ''}>${esc(presetLabel(k))}</option>`).join('')}</select></label></div>
      ${isAdmin ? '<p class="admin-callout">Administrators can change everything except accounts, code and the e-mail sender. They sign in only from the local network.</p>' : grid + fileNote}
      <div class="acct-effective"><span class="cap">Effective access</span><div class="tags">${eff}</div></div>
      <div class="acct-savebar ${dirty ? 'dirty' : ''}"><span class="small">${dirty ? 'Unsaved changes. Saving signs this account out.' : 'No unsaved changes'}</span><div class="grow"></div>
        ${btn('accountDiscard', 'Discard', { disabled: !dirty })}${btn('accountSave', 'Save permissions', { primary: true, icon: 'check', disabled: !dirty })}</div></section>`;
  }

  function capChecks(name, selected, held) {
    const fileCaps = (A.accounts.permissions || []).filter((p) => p.group === 'files');
    return `<div class="cap-checks">${fileCaps.map((p) => `<label class="cap-check ${held && !held.has(p.id) ? 'lack' : ''}" title="${esc(p.description + (held && !held.has(p.id) ? ': not in this account’s permissions, so it has no effect yet' : ''))}"><input type="checkbox" name="${name}" value="${esc(p.id)}" ${selected.has(p.id) ? 'checked' : ''} ${p.id === 'files.read' ? 'disabled checked' : ''}><span>${esc(p.label)}</span></label>`).join('')}</div>`;
  }

  function zoneSection(sel) {
    if (sel.role === 'root' || sel.role === 'admin') {
      return `<section class="panel acct-sec"><div class="acct-sec-head"><div><div class="cap">Storage access</div><h5>All drives</h5></div></div><p class="acct-note">${sel.role === 'root' ? 'The owner' : 'Administrators'} can reach every drive. Storage zones only limit members.</p></section>`;
    }
    const drives = fileDrives();
    const driveName = (m) => drives.find((x) => String(x.mount) === String(m))?.name || 'Drive ' + m;
    const held = new Set((sel.permissions || []).filter((p) => p.startsWith('files.')));
    const zones = sel.zones || [];
    const rows = zones.map((z) => {
      if (A.zoneEdit && A.zoneEdit.id === z.id) {
        return `<div class="zone-row editing"><div class="zone-where"><b>${esc(driveName(z.mount))}</b><code>${esc(z.path)}</code></div>
          ${capChecks('zone-edit-cap', new Set(z.caps), held)}
          <div class="zone-edit-foot"><label>Access until<input class="input" type="date" id="zone-edit-exp" value="${esc(dateIn(z.expires))}"></label><div class="grow"></div>
            ${btn('zoneEditCancel', 'Cancel')}${btn('zoneEditSave', 'Save zone', { primary: true, icon: 'check', arg: z.id })}</div></div>`;
      }
      const lacking = z.caps.filter((c) => !held.has(c));
      return `<div class="zone-row ${z.expired ? 'expired' : ''}"><span class="zone-where"><b>${esc(driveName(z.mount))}</b><code>${esc(z.path)}</code>${sel.home && sel.home.path === z.path && String(sel.home.mount) === String(z.mount) ? '<span class="tag">home</span>' : ''}${z.expired ? '<span class="tag tag-hot">ended</span>' : z.expires ? `<span class="tag">until ${esc(day(z.expires))}</span>` : ''}</span>
        <span class="zone-caps">${z.caps.map((c) => `<span class="tag ${held.has(c) ? '' : 'tag-dim'}" title="${held.has(c) ? '' : 'not in the account permissions, so no effect'}">${esc(permLabel(c))}</span>`).join('')}</span>
        <span class="zone-btns"><button class="icbtn" data-act="zoneEdit" data-arg="${esc(z.id)}" title="Change what is allowed in ${esc(z.path)}" aria-label="Edit access to ${esc(z.path)}"${A.busy ? ' disabled' : ''}>${icon('pencil', 'sm')}</button>
        <button class="icbtn" data-act="zoneDelete" data-arg="${esc(z.id)}" title="Remove access to ${esc(z.path)}" aria-label="Remove access to ${esc(z.path)}"${A.busy ? ' disabled' : ''}>${icon('trash-2', 'sm')}</button></span>
        ${lacking.length && !z.expired ? `<small class="zone-hint">${lacking.length} allowed action${lacking.length === 1 ? '' : 's'} here ${lacking.length === 1 ? 'is' : 'are'} not in the account permissions and ${lacking.length === 1 ? 'has' : 'have'} no effect.</small>` : ''}</div>`;
    }).join('');
    return `<section class="panel acct-sec"><div class="acct-sec-head"><div><div class="cap">Storage access</div><h5>${zones.length} storage zone${zones.length === 1 ? '' : 's'}</h5></div></div>
      <p class="acct-note">A folder this account may use, and what it may do there.</p>
      <div class="zone-list">${rows || '<div class="admin-callout">No storage yet: this account can’t see any files.</div>'}</div>
      ${drives.length ? `<div class="zone-add"><div class="cap">Add a zone</div>
        <div class="zone-form"><label>Drive<select class="input" id="zone-mount">${drives.map((x) => `<option value="${esc(x.mount)}">${esc(x.name)}</option>`).join('')}</select></label>
          <label>Folder<input class="input" id="zone-path" value="/users/${esc(sel.user)}" autocomplete="off" spellcheck="false"></label>
          <label>Access until (optional)<input class="input" type="date" id="zone-exp"></label></div>
        ${capChecks('zone-new-cap', new Set(['files.read', 'files.download']), held)}
        <div class="acct-actions">${btn('zoneAdd', 'Add zone', { icon: 'plus' })}<span class="small dim">Granting a folder that already has a zone replaces its actions.</span></div></div>` : '<p class="acct-note warn">No file drives yet. Add one under Serving.</p>'}</section>`;
  }

  function limitsSection(sel) {
    if (sel.role === 'root') return '';
    return `<section class="panel acct-sec"><div class="acct-sec-head"><div><div class="cap">Sign-in limits</div><h5>When and from where</h5></div></div>
      <div class="limits-grid">
        <label>Access until<input class="input" type="date" id="lim-exp" value="${esc(dateIn(sel.expires))}"><small>Sign-in ends after this day. Empty: no end.</small></label>
        <label>Longest session (hours)<input class="input" type="number" min="0.25" max="2160" step="0.25" id="lim-hours" value="${esc(sel.session_hours ?? '')}" placeholder="instance default"><small>Counted from sign-in.</small></label>
        <label class="wide">Allowed networks<textarea class="input" id="lim-ips" rows="2" spellcheck="false" placeholder="any network, e.g. 192.168.1.0/24, 10.8.0.5">${esc((sel.allowed_ips || []).join(', '))}</textarea><small>Addresses or ranges, comma separated. Empty: any network.</small></label>
        <label class="wide">Note for administrators<textarea class="input" id="lim-note" rows="2" maxlength="500" placeholder="e.g. contractor for the Q4 relaunch">${esc(sel.note || '')}</textarea></label>
      </div>
      <div class="acct-actions">${btn('accountLimitsSave', 'Save limits', { primary: true, icon: 'check' })}<span class="small dim">Saving signs the account out.</span></div></section>`;
  }

  function createSection() {
    if (!A.createOpen) return '';
    const drives = fileDrives();
    return `<section class="panel acct-sec acct-create" aria-label="Create account"><div class="acct-sec-head"><div><div class="cap">New account</div><h5>Create an account</h5></div>${btn('accountCreateToggle', 'Close', { icon: 'x' })}</div>
      <p class="acct-note">They set their password with a link that works once, for 24 hours. Sign-in codes go to their e-mail.</p>
      <div class="create-grid">
        <label>Username<input id="invite-user" class="input" autocomplete="off" spellcheck="false" maxlength="60" placeholder="e.g. alex" value="${esc(A.createUser || '')}"><small>2–60 letters, digits, dot, dash, underscore</small></label>
        <label>E-mail<input id="invite-email" class="input" type="email" autocomplete="off" placeholder="name@example.com" value="${esc(A.createEmail || '')}"><small>Receives the link and sign-in codes</small></label>
        <label>Preset<select id="invite-preset" class="input">${PRESET_ORDER.filter((k) => presetsById()[k] && k !== 'custom').map((k) => `<option value="${k}" title="${esc(presetsById()[k].description)}">${esc(presetLabel(k))}</option>`).join('')}</select><small>Fine-tune afterwards under Role &amp; permissions</small></label>
        ${drives.length ? `<label>Home drive<select id="invite-mount" class="input">${drives.map((x) => `<option value="${esc(x.mount)}">${esc(x.name)}</option>`).join('')}</select><small>A private <code>/users/&lt;name&gt;</code> folder is created there</small></label>` : ''}
      </div>
      ${A.createError ? `<p class="acct-error" role="alert">${esc(A.createError)}</p>` : ''}
      <div class="acct-actions">${btn('accountInvite', 'Create account', { primary: true, icon: 'user-plus' })}</div></section>`;
  }

  function vAccounts() {
    if (!has('accounts.manage')) return adminErr('Only the owner can manage accounts.');
    if (!A.accounts && !A.accountsError) loadAccounts();
    if (A.accountsError) return `<div class="admin-page">${adminErr(A.accountsError)}<div class="acct-actions">${btn('accountLoad', 'Try again', { icon: 'refresh-cw' })}</div></div>`;
    if (!A.accounts) return `<div class="admin-page">${loading('Loading accounts…')}</div>`;
    const list = A.accounts.accounts || [];
    const q = (A.accountQuery || '').toLowerCase();
    const filtered = list.filter((u) => !q || u.user.toLowerCase().includes(q) || (u.email || '').toLowerCase().includes(q));
    const sel = list.find((x) => x.user === A.accountSelected);
    const link = A.activationLink ? `<section class="panel acct-link" role="status"><div class="acct-sec-head"><div><div class="cap">Single-use link · valid 24 hours</div><h5>${esc(A.activationKind)} for ${esc(A.activationUser)}</h5></div>${btn('dismissActivation', 'Done', { icon: 'check' })}</div>
      <p class="acct-note">${A.activationMailed ? 'It was e-mailed to the account address. ' : ''}Anyone with this link can set the password: share it only with that person. It’s shown once.</p>
      <div class="acct-linkrow"><input id="act-link-box" class="input" value="${esc(A.activationLink)}" readonly data-act="selectField" aria-label="Activation link">${btn('copyActivationLink', 'Copy', { icon: 'copy' })}</div></section>` : '';
    const policy = A.signups ? `<section class="panel acct-sec"><div class="acct-sec-head"><div><div class="cap">Registration</div><h5>${A.signups.allowed ? 'Open registration is ON' : 'Invite only'}</h5></div>
      ${A.signups.locked_by_env ? '<span class="small dim">locked by the ALLOW_SIGNUPS environment variable</span>' : btn('toggleSignups', A.signups.allowed ? 'Switch to invite only' : 'Allow open registration', { arg: A.signups.allowed ? '0' : '1' })}</div>
      <p class="acct-note">Invite only is recommended: then only the owner can create accounts, here.</p></section>` : '';
    return `<div class="admin-page acct-page">
      <div class="admin-page-head"><div><div class="cap">Administration · identity &amp; access</div><h3>Accounts</h3><p>Who can sign in, and what they can do.</p></div>
        <div class="acct-actions">${btn('accountLoad', 'Refresh', { icon: 'refresh-cw' })}${btn('accountCreateToggle', A.createOpen ? 'Close form' : 'New account', { primary: !A.createOpen, icon: A.createOpen ? 'x' : 'user-plus' })}</div></div>
      ${link}${createSection()}
      <div class="account-layout">
        <aside class="account-list" aria-label="Accounts"><div class="account-list-head"><b>${fmt.n(list.length)} account${list.length === 1 ? '' : 's'}</b>
          <input id="account-search" class="input" type="search" placeholder="Search name or e-mail" value="${esc(A.accountQuery || '')}" autocomplete="off" aria-label="Search accounts"></div>
          <div class="account-cards">${filtered.map(accountCard).join('') || '<div class="empty">No account matches.</div>'}</div></aside>
        <div class="account-detail">${sel ? identitySection(sel) + permissionSection(sel) + zoneSection(sel) + limitsSection(sel) : '<section class="panel"><div class="empty">Choose an account.</div></section>'}</div>
      </div>
      ${policy}
    </div>`;
  }
  function ideMode(path) {
    const ext = (path.split('.').pop() || '').toLowerCase();
    return ({ py: 'python', js: 'javascript', mjs: 'javascript', cjs: 'javascript', css: 'css', html: 'htmlmixed', htm: 'htmlmixed',
      json: 'javascript', md: 'markdown', svg: 'htmlmixed', xml: 'xml', txt: 'text' })[ext] || 'text';
  }
  function treeMarkup() {
    const entries = A.ide.tree?.files || [];
    const root = { dirs: new Map(), files: [] };
    for (const e of entries) {
      const parts = e.path.split('/'); let node = root;
      parts.forEach((part, i) => {
        if (i === parts.length - 1 && !e.dir) node.files.push({ path: e.path, name: part });
        else { if (!node.dirs.has(part)) node.dirs.set(part, { path: parts.slice(0, i + 1).join('/'), dirs: new Map(), files: [] }); node = node.dirs.get(part); }
      });
    }
    const query = A.ide.search.toLowerCase();
    const renderNode = (node, depth = 0) => [...node.dirs.values()].sort((a, b) => a.path.localeCompare(b.path)).map((d) => {
      const child = renderNode(d, depth + 1);
      if (query && !d.path.toLowerCase().includes(query) && !child.includes('ide-file')) return child;
      return `<div class="ide-folder" style="--depth:${depth}">${icon('folder', 'sm')}<span>${esc(d.path.split('/').pop())}</span></div>${child}`;
    }).join('') + [...node.files].sort((a, b) => a.path.localeCompare(b.path)).filter((f) => !query || f.path.toLowerCase().includes(query)).map((f) => `<button class="ide-file ${A.ide.path === f.path ? 'on' : ''}" style="--depth:${depth}" data-act="ideOpen" data-arg="${esc(f.path)}">${icon(ideIcon(f.path), 'sm')}<span title="${esc(f.path)}">${esc(f.name)}</span></button>`).join('');
    return renderNode(root);
  }
  function ideIcon(path) {
    const ext = path.split('.').pop().toLowerCase();
    return ({ py: 'file-code', js: 'file-code', mjs: 'file-code', html: 'file-code', css: 'file-code', md: 'file-text', json: 'file-braces' })[ext] || 'file';
  }
  async function loadIdeTree() {
    try { A.ide.tree = await get('/api/ide/tree'); A.ide.error = ''; render(true); }
    catch (e) { A.ide.error = e.message; render(true); }
  }
  function rememberIdeDraft() {
    if (A.ide.editor && A.ide.path) A.ide.drafts[A.ide.path] = { text: A.ide.editor.getValue(), sha: A.ide.sha, saved: A.ide.saved };
  }
  async function ideOpen(path) {
    rememberIdeDraft(); A.ide.path = path; A.ide.loading = true; A.ide.error = ''; render(true);
    try {
      const doc = await get('/api/ide/read?path=' + enc(path));
      const draft = A.ide.drafts[path];
      A.ide.text = draft ? draft.text : doc.text; A.ide.saved = draft ? draft.saved : doc.text; A.ide.sha = draft ? draft.sha : doc.sha256;
      A.ide.mode = ideMode(path); A.ide.loading = false; A.ide.error = ''; render(true);
    } catch (e) { A.ide.loading = false; A.ide.error = e.message; render(true); }
  }
  function updateIdeStatus() {
    const cm = A.ide.editor, statusEl = $('#ide-state'), saveBtn = $('#ide-save');
    if (!statusEl || !cm) return;
    const text = cm.getValue(), dirty = text !== A.ide.saved;
    statusEl.textContent = dirty ? 'Unsaved changes' : 'Saved · ' + text.split('\n').length + ' lines';
    statusEl.className = 'ide-state ' + (dirty ? 'warn' : 'ok');
    if (saveBtn) saveBtn.disabled = !dirty || !has('code.write');
    if (A.ide.path) A.ide.drafts[A.ide.path] = { text, sha: A.ide.sha, saved: A.ide.saved };
  }
  function initIdeEditor() {
    const host = $('#ide-editor');
    if (!host || !A.ide.path || A.ide.loading || !window.CodeMirror) return;
    if (A.ide.editor?.getWrapperElement()?.isConnected && host.contains(A.ide.editor.getWrapperElement())) return;
    const cm = CodeMirror(host, { value: A.ide.text, mode: A.ide.mode === 'text' ? null : A.ide.mode,
      lineNumbers: true, lineWrapping: false, matchBrackets: true, autoCloseBrackets: true, styleActiveLine: true,
      matchTags: { bothTags: true }, indentUnit: 4, tabSize: 4, indentWithTabs: false,
      readOnly: !has('code.write'), viewportMargin: 40, inputStyle: 'contenteditable',
      extraKeys: { 'Ctrl-S': () => ideSave(), 'Cmd-S': () => ideSave(), 'Ctrl-F': 'findPersistent', 'Cmd-F': 'findPersistent',
        'Ctrl-H': 'replace', 'Cmd-Alt-F': 'replace', 'Tab': (editor) => editor.execCommand('indentMore'), 'Shift-Tab': (editor) => editor.execCommand('indentLess') },
    });
    A.ide.editor = cm;
    cm.on('change', updateIdeStatus);
    updateIdeStatus();
  }
  async function ideSave() {
    if (!A.ide.path || !A.ide.editor || !has('code.write')) return;
    const text = A.ide.editor.getValue();
    try {
      const result = await post('/api/ide/save', { path: A.ide.path, text, expect_sha: A.ide.sha });
      A.ide.sha = result.sha256; A.ide.text = text; A.ide.saved = text;
      A.ide.drafts[A.ide.path] = { text, sha: result.sha256, saved: text };
      note('Saved ' + A.ide.path + (result.backup ? ', previous version backed up' : ''));
      updateIdeStatus(); render(true);
    } catch (e) { note(e.message + (e.message.includes('changed since') ? '. Your text is still here: reload to see the version on disk.' : ''), { err: true }); }
  }
  function vIde() {
    if (!has('code.read')) return adminErr('This account can’t see the source code. Ask the owner for access.');
    if (!A.ide.tree && !A.ide.error) loadIdeTree();
    if (A.ide.editor) rememberIdeDraft();
    const write = has('code.write'), path = A.ide.path;
    const state = A.ide.error ? `<div class="empty">${esc(A.ide.error)}</div>` : !A.ide.tree ? loading('Indexing source files…') : treeMarkup() || '<div class="empty">No source files are in the IDE scope.</div>';
    const editor = A.ide.loading ? loading('Opening source file…') : path ? `<div class="ide-filebar"><div><b>${esc(path)}</b><small>${esc(A.ide.mode || 'text')} · ${write ? 'editable' : 'read only'}</small></div><span id="ide-state" class="ide-state"></span><button id="ide-save" class="btn btn-primary" data-act="ideSave" ${write ? '' : 'disabled'}>${icon('save', 'sm')} Save <kbd>Ctrl S</kbd></button><button class="btn btn-secondary" data-act="ideReload">Reload</button></div><div id="ide-editor" class="ide-editor-host"></div>` : `<div class="ide-welcome">${icon('code', 'xl')}<h4>Select a source file</h4><p>Edit Strata’s own source files.</p><p>${write ? 'Every save keeps a backup first.' : 'This account can only read the source.'}</p></div>`;
    return `<div class="admin-page ide-page"><div class="admin-page-head"><div><div class="cap">Administration · source</div><h3>Strata web IDE</h3><p>Source changes apply to every Strata instance using this shared code folder.</p></div><div class="ide-head-actions"><button class="btn btn-secondary" data-act="ideRefresh">${icon('refresh-cw', 'sm')} Refresh tree</button>${write ? '<span class="admin-callout inline">Write access is local-network-only</span>' : ''}</div></div>
      <div class="ide-workspace"><aside class="ide-sidebar"><div class="ide-tree-head">${icon('folder-tree', 'sm')} Source files</div><input class="input" id="ide-search" placeholder="Filter files…" value="${esc(A.ide.search)}"><div class="ide-tree">${state}</div></aside><section class="ide-main">${editor}</section></div></div>`;
  }

  async function emailBegin() {
    try {
      const r = await post('/api/account/email/begin', { email: $('#profile-email')?.value || '', current: $('#profile-password')?.value || '' });
      A.emailPending = r.email; note('Verification code sent to ' + r.email); render(true);
    } catch (e) { note(e.message, { err: true }); }
  }
  async function emailVerify() {
    try { const r = await post('/api/account/email/verify', { code: $('#profile-code')?.value || '' }); D.me.email = r.email; D.me.email_verified = true; A.emailPending = ''; note('Sign-in e-mail updated'); render(true); }
    catch (e) { note(e.message, { err: true }); }
  }
  function accountSettingsPanel() {
    if (!D.me) return '<section class="panel span2"><div class="empty">Loading account profile…</div></section>';
    const isKey = String(D.me.user || '').startsWith('api:');
    const role = { root: 'Owner', admin: 'Administrator' }[D.me.role] || 'Member';
    return `<section class="panel span2">
      <div class="ph"><h5>${icon('user')} Account profile</h5><span class="small dim">${esc(role)} · ${D.me.email_verified ? 'e-mail verified' : 'e-mail not verified'}</span></div>
      ${isKey ? '' : `<div class="profile-pic">${avatar(D.me.user, D.me.avatar, 'lg')}<div>
        <b>Profile picture</b><p class="small dim">PNG, JPEG, WebP, GIF or AVIF up to 8 MB. Shown to your team.</p>
        <div class="acct-actions"><label class="btn btn-secondary ${A.avatarBusy ? 'disabled' : ''}">${icon('upload', 'sm')}<span>${A.avatarBusy ? 'Uploading…' : D.me.avatar ? 'Change picture' : 'Upload picture'}</span><input type="file" id="profile-avatar" accept="image/png,image/jpeg,image/webp,image/gif,image/avif" data-change="avatarPick" hidden ${A.avatarBusy ? 'disabled' : ''}></label>
          ${D.me.avatar ? `<button class="btn btn-secondary" data-act="avatarRemove" ${A.avatarBusy ? 'disabled' : ''}>${icon('x', 'sm')}<span>Remove</span></button>` : ''}</div></div></div>`}
      ${D.me.expires || D.me.session_hours ? `<p class="small dim">${D.me.expires ? 'Your access ends on ' + esc(new Date(D.me.expires * 1000).toLocaleDateString()) + '. ' : ''}${D.me.session_hours ? 'Sessions last at most ' + esc(D.me.session_hours) + ' h.' : ''}</p>` : ''}
      <p class="small dim">To change your sign-in e-mail, confirm a code sent to the new address.</p>
      <div class="profile-grid">
        <label>Sign-in e-mail<input class="input" id="profile-email" type="email" value="${esc(A.emailPending || D.me.email || '')}" autocomplete="email"></label>
        <label>Current password<input class="input" id="profile-password" type="password" autocomplete="current-password"></label>
        <button class="btn btn-secondary" data-act="profileEmailBegin">Send verification code</button>
        ${A.emailPending ? `<label>Six-digit e-mail code<input class="input" id="profile-code" inputmode="numeric" autocomplete="one-time-code"></label><button class="btn btn-primary" data-act="profileEmailVerify">Verify new address</button>` : ''}
      </div>
    </section>
`;
  }
  SETTINGS_PANELS.push(accountSettingsPanel);

  Object.assign(ACT, {
    sysRefresh() { A.system = null; A.systemError = ''; loadSystem(); },
    async sysRetention() {
      try { A.system = await post('/api/settings/retention', { raw_retention_days: +$('#sys-raw-days').value, retention_days: +$('#sys-agg-days').value }); note('Retention settings saved'); render(true); }
      catch (e) { note(e.message, { err: true }); }
    },
    async sysRestore(_, el) {
      const file = el.files && el.files[0];
      if (!file) return;
      const ok = await ask({ kicker: 'Restore backup', title: 'Replace this instance’s data with ' + file.name + '?', danger: true, ok: 'Restore',
        text: 'Accounts, drives, rules, links and statistics are replaced, and the settings in the backup are applied. Keys and passwords on this machine stay. Restart Strata afterwards.' });
      if (!ok) { el.value = ''; return; }
      A.restoreBusy = true; render(true);
      try {
        const r = await fetch('/api/backup/restore', { method: 'POST', body: file, credentials: 'same-origin', headers: { 'X-Strata': '1', 'Content-Type': 'application/zip' } });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.error || 'Restore failed (' + r.status + ')');
        note('Backup restored. Restart Strata to finish.');
      } catch (e) { note('Couldn’t restore: ' + e.message, { err: true }); } finally { A.restoreBusy = false; el.value = ''; render(true); }
    },
    async sysOptimize() {
      try { A.system = await post('/api/system/optimize', {}); note('Database optimization finished'); render(true); }
      catch (e) { note(e.message, { err: true }); }
    },
    logSource(source) { if (source === 'activity' && !has('audit.read')) return; A.logSource = source; A.logs = null; A.logError = ''; loadLogs(); },
    logSearch() { A.logSearch = $('#log-search')?.value.trim() || ''; A.logUser = $('#log-user')?.value.trim() || ''; A.logAction = $('#log-action')?.value.trim() || ''; A.logs = null; loadLogs(); },
    logRefresh() { A.logs = null; A.logError = ''; loadLogs(); },
    logMore() { const cursor = A.logs?.next || A.logs?.cursor; if (cursor) { A.logBefore = cursor; loadLogs(false); } },
    async accountSelect(user) {
      const sel = A.accounts?.accounts?.find((x) => x.user === A.accountSelected);
      if (sel && user !== sel.user && draftDirty(sel)) {
        const ok = await ask({ kicker: 'Unsaved permissions', title: `Discard the changes for ${sel.user}?`, danger: true, ok: 'Discard changes', text: 'The permission changes you made have not been saved.' });
        if (!ok) return;
      }
      A.accountSelected = user; A.draft = null; A.zoneEdit = null; render(true);
    },
    accountLoad() { A.accounts = null; A.accountsError = ''; loadAccounts(); },
    accountCreateToggle() { A.createOpen = !A.createOpen; A.createError = ''; render(true); if (A.createOpen) setTimeout(() => $('#invite-user')?.focus(), 0); },
    dismissActivation() { A.activationLink = ''; A.activationUser = ''; render(true); },
    selectField(_, el) { el.select(); },
    copyActivationLink() { if (A.activationLink) copy(A.activationLink, 'activation link'); },
    accountPreset(value) {
      const sel = A.accounts?.accounts?.find((x) => x.user === A.accountSelected);
      if (!sel) return;
      const d = draftFor(sel), p = presetsById()[value];
      d.preset = value;
      if (p && value !== 'admin' && value !== 'custom') d.perms = new Set(p.permissions);
      render(true);
    },
    accountPerm(checked, el) {
      const sel = A.accounts?.accounts?.find((x) => x.user === A.accountSelected);
      if (!sel) return;
      const d = draftFor(sel);
      if (checked) d.perms.add(el.value); else d.perms.delete(el.value);
      d.preset = presetOf(d.perms); // editing a box never leaves a preset that would override it on save
      render(true);
    },
    accountPermGroup(arg) {
      const sel = A.accounts?.accounts?.find((x) => x.user === A.accountSelected);
      if (!sel) return;
      const [g, on] = arg.split(':'), d = draftFor(sel);
      (A.accounts.permissions || []).filter((p) => p.group === g).forEach((p) => { if (on === '1') d.perms.add(p.id); else d.perms.delete(p.id); });
      d.preset = presetOf(d.perms);
      render(true);
    },
    accountDiscard() { A.draft = null; render(true); },
    accountSave() {
      const sel = A.accounts?.accounts?.find((x) => x.user === A.accountSelected);
      if (!sel || !A.draft) return;
      const d = A.draft;
      return busy('accountSave', async () => {
        await post('/api/accounts/permissions', { user: sel.user, role: d.preset === 'admin' ? 'admin' : 'employee',
          preset: d.preset, permissions: d.preset === 'admin' ? [] : [...d.perms] });
        note(`Permissions saved for ${sel.user} · their sessions were signed out`);
        await loadAccounts();
      });
    },
    accountLimitsSave() {
      const user = A.accountSelected;
      const body = { user, expires: dateOut($('#lim-exp')?.value), session_hours: $('#lim-hours')?.value || null,
        allowed_ips: $('#lim-ips')?.value || '', note: $('#lim-note')?.value || '' };
      return busy('accountLimitsSave', async () => { await post('/api/accounts/constraints', body); note(`Sign-in limits saved for ${user}`); await loadAccounts(); });
    },
    accountAdministrative(checked) {
      const user = A.accountSelected;
      return busy('accountAdministrative', async () => {
        await post('/api/accounts/administrative', { user, administrative: !!checked });
        note(checked ? `${user} is now a team moderator` : `${user} is no longer a team moderator`);
        await loadAccounts();
      });
    },
    async accountAvatarRemove() {
      const user = A.accountSelected;
      if (!(await ask({ kicker: 'Profile picture', title: `Remove ${user}'s profile picture?`, ok: 'Remove', text: 'They can upload a new one at any time.' }))) return;
      return busy('accountAvatarRemove', async () => { await post('/api/accounts/avatar/delete', { user }); note('Profile picture removed'); await loadAccounts(); });
    },
    async toggleSignups(val) {
      if (val === '1' && !(await ask({ kicker: 'Registration', title: 'Allow open registration?', danger: true, ok: 'Allow', text: 'Anyone who can reach the sign-in page could create an account. Invite only is safer.' }))) return;
      return busy('toggleSignups', async () => { await post('/api/settings/signups', { allowed: val === '1' }); note(val === '1' ? 'Open registration enabled' : 'Invite only'); await loadAccounts(); });
    },
    accountInvite() {
      const username = $('#invite-user')?.value.trim() || '', email = $('#invite-email')?.value.trim() || '';
      const preset = $('#invite-preset')?.value || 'read_only', mount = $('#invite-mount')?.value;
      A.createUser = username; A.createEmail = email;
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]{1,59}$/.test(username)) { A.createError = 'Use 2–60 letters, digits, dots, dashes or underscores, starting with a letter or digit.'; return render(true); }
      if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) { A.createError = 'That e-mail address doesn’t look valid.'; return render(true); }
      A.createError = '';
      return busy('accountInvite', async () => {
        try {
          const res = await post('/api/accounts/invite', { user: username, email, preset, mount: mount != null ? +mount : undefined });
          Object.assign(A, { activationLink: res.link, activationUser: username, activationKind: 'Activation link', activationMailed: !!res.email_sent,
            accountSelected: username, createOpen: false, createUser: '', createEmail: '' });
          note(`Account ${username} created`);
          await loadAccounts();
        } catch (e) { A.createError = e.message; }
      });
    },
    async accountStatus(enable) {
      const user = A.accountSelected;
      const ok = await ask({ kicker: enable === '1' ? 'Enable account' : 'Disable account', title: `${enable === '1' ? 'Enable' : 'Disable'} ${user}?`, danger: enable !== '1',
        ok: enable === '1' ? 'Enable' : 'Disable', text: enable === '1' ? 'The account can sign in again with its password and an e-mail code.' : 'Signs the account out and blocks sign-in until you enable it.' });
      if (!ok) return;
      return busy('accountStatus', async () => { await post('/api/accounts/status', { user, enabled: enable === '1' }); note(enable === '1' ? `${user} enabled` : `${user} disabled and signed out`); await loadAccounts(); });
    },
    async accountRevokeSessions() {
      const user = A.accountSelected;
      if (!(await ask({ kicker: 'Sessions', title: `Sign ${user} out everywhere?`, ok: 'Sign out', text: 'Every browser signed in as this account has to sign in again.' }))) return;
      return busy('accountRevokeSessions', async () => { await post('/api/accounts/sessions/revoke', { user }); note(`${user} was signed out everywhere`); });
    },
    async accountPasswordReset() {
      const user = A.accountSelected;
      if (!(await ask({ kicker: 'Password reset', title: `Create a password reset link for ${user}?`, ok: 'Create link', text: 'The link sets a new password once, within 24 hours. It doesn’t enable a disabled account.' }))) return;
      return busy('accountPasswordReset', async () => {
        const res = await post('/api/accounts/password-reset', { user });
        Object.assign(A, { activationLink: res.link, activationUser: user, activationKind: 'Password reset link', activationMailed: !!res.email_sent });
      });
    },
    async accountDelete() {
      const user = A.accountSelected;
      const res = await ask({ kicker: 'Delete account', title: `Delete ${user} permanently?`, danger: true, ok: 'Delete account',
        text: `Removes the sign-in, permissions, storage zones, profile picture and sessions. Type ${user} to confirm.`, input: '',
        check: `Also delete the private folder /users/${user} and its files` });
      if (!res) return;
      if (res.value !== user) return note('Not deleted: the name you typed didn’t match', { err: true });
      return busy('accountDelete', async () => {
        await post('/api/accounts/delete', { user, storage_action: res.checked ? 'delete' : 'retain' });
        note(`${user} deleted${res.checked ? ' with their private folder' : ' · files kept'}`);
        A.accountSelected = ''; await loadAccounts();
      });
    },
    zoneAdd() {
      const mount = +$('#zone-mount')?.value, path = $('#zone-path')?.value.trim() || '/', expires = dateOut($('#zone-exp')?.value);
      const caps = ['files.read', ...[...document.querySelectorAll('input[name="zone-new-cap"]:checked')].map((x) => x.value)];
      return busy('zoneAdd', async () => { await post('/api/accounts/zone', { user: A.accountSelected, mount, path, caps: [...new Set(caps)], expires }); note('Storage zone saved'); await loadAccounts(); });
    },
    zoneEdit(id) { A.zoneEdit = { id: +id }; render(true); },
    zoneEditCancel() { A.zoneEdit = null; render(true); },
    zoneEditSave(id) {
      const caps = ['files.read', ...[...document.querySelectorAll('input[name="zone-edit-cap"]:checked')].map((x) => x.value)];
      const expires = dateOut($('#zone-edit-exp')?.value);
      return busy('zoneEditSave', async () => { await post('/api/accounts/zone/update', { id: +id, caps: [...new Set(caps)], expires }); note('Zone updated'); A.zoneEdit = null; await loadAccounts(); });
    },
    async zoneDelete(id) {
      const sel = A.accounts?.accounts?.find((x) => x.user === A.accountSelected);
      const z = (sel?.zones || []).find((x) => String(x.id) === String(id));
      if (!(await ask({ kicker: 'Storage access', title: `Remove ${sel?.user || 'this account'}'s access to ${z?.path || 'this folder'}?`, danger: true, ok: 'Remove access', text: 'The files stay where they are; only the access is removed.' }))) return;
      return busy('zoneDelete', async () => { await post('/api/accounts/zone/delete', { id: +id }); note('Storage zone removed'); await loadAccounts(); });
    },
    ideRefresh() { A.ide.tree = null; A.ide.error = ''; loadIdeTree(); },
    ideOpen(path) { ideOpen(path); },
    ideSave,
    async ideReload() {
      if (!A.ide.path) return;
      if (A.ide.editor && A.ide.editor.getValue() !== A.ide.saved) {
        const ok = await ask({ kicker: 'Discard editor changes', title: 'Reload from disk?', danger: true, ok: 'Discard and reload', text: 'Your unsaved editor text will be replaced by the current file on disk.' });
        if (!ok) return;
      }
      delete A.ide.drafts[A.ide.path]; ideOpen(A.ide.path);
    },
    profileEmailBegin: emailBegin,
    profileEmailVerify: emailVerify,
    async avatarPick(_, el) {
      const file = el?.files?.[0];
      if (!file || A.avatarBusy) return;
      if (file.size > 8 * 1024 * 1024) { el.value = ''; return note('Choose an image up to 8 MB', { err: true }); }
      A.avatarBusy = true; render(true);
      try {
        const r = await fetch('/api/account/avatar', { method: 'POST', body: file, credentials: 'same-origin',
          headers: { 'X-Strata': '1', 'Content-Type': file.type || 'application/octet-stream' } });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.error || 'Upload failed (' + r.status + ')');
        D.me.avatar = j.avatar; note('Profile picture updated');
      } catch (e) { note(e.message, { err: true }); } finally { A.avatarBusy = false; el.value = ''; render(true); }
    },
    async avatarRemove() {
      if (A.avatarBusy) return;
      A.avatarBusy = true; render(true);
      try { await post('/api/account/avatar/delete', {}); D.me.avatar = ''; note('Profile picture removed'); }
      catch (e) { note(e.message, { err: true }); } finally { A.avatarBusy = false; render(true); }
    },
  });

  VIEWFN.system = vSystem;
  VIEWFN.logs = vLogs;
  VIEWFN.accounts = vAccounts;
  VIEWFN.ide = vIde;
  VIEW_REFRESH.system = loadSystem;
  VIEW_REFRESH.logs = () => { if (!A.logs) loadLogs(); };
  VIEW_REFRESH.accounts = () => { if (!A.accounts) loadAccounts(); };
  VIEW_REFRESH.ide = () => { if (!A.ide.tree) loadIdeTree(); };
  AFTER_RENDER.push(initIdeEditor);
  document.addEventListener('input', (e) => {
    if (e.target.id === 'ide-search') { A.ide.search = e.target.value; render(true); return; }
    if (e.target.id === 'account-search') { A.accountQuery = e.target.value; render(true); return; }
    if (e.target.id === 'log-search') A.logSearch = e.target.value;
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && ['log-search', 'log-user', 'log-action'].includes(e.target.id)) { e.preventDefault(); ACT.logSearch(); }
  });
  window.addEventListener('beforeunload', (e) => {
    if (A.ide.editor && A.ide.editor.getValue() !== A.ide.saved) { e.preventDefault(); e.returnValue = ''; }
  });
  document.addEventListener('DOMContentLoaded', () => {
    loadMe().then(() => { renderNav(); if (S.view === 'settings') render(true); });
  });
})();
