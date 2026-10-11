'use strict';
/* Strata office: colleagues, presence, the noticeboard and notes on profiles (server side: office.py).
   Presence: every open dashboard sends a heartbeat (30 s, and at once when the tab wakes up or input resumes) saying
   "active" (input in the last 5 minutes, tab visible) or "idle"; the answer carries everyone's presence (with office
   access) and the unread counts for the nav badge. Notes are plain text: everything reaches the DOM through esc(). */
(() => {
  const O = D.office = { state: null, board: null, notes: {}, sel: '', q: '', drafts: {}, priv: false, edit: null,
    editProfile: false, busy: '', error: '' };
  D.presence = D.presence || {};
  STATIC_VIEWS.add('office');

  const has = (cap) => !!D.me && (D.me.capabilities || []).includes(cap);
  const me = () => String(D.me?.user || '');
  const isMe = (u) => u && u.toLowerCase() === me().toLowerCase();
  const person = (u) => (O.state?.people || []).find((p) => p.user.toLowerCase() === String(u).toLowerCase());

  /* ---------------------------------------------------------------- heartbeat */

  const TAB = Math.random().toString(36).slice(2, 12);
  const IDLE_AFTER = 5 * 60 * 1000;
  let lastInput = Date.now(), lastSent = '', beatT = 0;
  const stateNow = () => (document.visibilityState === 'visible' && Date.now() - lastInput < IDLE_AFTER ? 'active' : 'idle');
  async function beat() {
    clearTimeout(beatT);
    beatT = setTimeout(beat, 30000);
    if (!D.me || String(D.me.user || '').startsWith('api:')) return;
    const state = stateNow();
    lastSent = state;
    try {
      const r = await post('/api/presence', { tab: TAB, state });
      D.presence = r.presence || {};
      if (r.unread) O.unread = r.unread;
      renderNav();
      if (S.view === 'office' || S.view === 'accounts') render(true);
    } catch (e) {
      // a Strata process older than the office answers 404 / 403: ask again in 10 minutes instead of every 30 s
      if (/not found|permission|access/i.test(e.message)) { lastSent = 'off'; clearTimeout(beatT); beatT = setTimeout(beat, 600000); }
    }
  }
  const wake = () => { lastInput = Date.now(); if (lastSent === 'idle') beat(); };
  ['pointerdown', 'keydown', 'wheel', 'touchstart'].forEach((ev) => addEventListener(ev, wake, { passive: true, capture: true }));
  let moveT = 0;
  addEventListener('pointermove', () => { const n = Date.now(); if (n - moveT > 5000) { moveT = n; wake(); } }, { passive: true });
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') lastInput = Date.now(); if (lastSent !== 'off') beat(); });
  addEventListener('pagehide', () => {
    try { fetch('/api/presence', { method: 'POST', keepalive: true, credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-Strata': '1' }, body: JSON.stringify({ tab: TAB, leave: true }) }); } catch { /* best effort */ }
  });
  (function firstBeat() { if (D.me) beat(); else setTimeout(firstBeat, 500); })();

  NAV_BADGES.push(() => {
    const u = O.unread || O.state?.unread || {};
    const n = (u.board || 0) + (u.notes || 0);
    return { badges: { office: n ? String(n) : '' }, alerts: { office: !!u.notes } };
  });

  /* ---------------------------------------------------------------- data */

  async function loadState() {
    try { O.state = await get('/api/office'); O.unread = O.state.unread; O.error = ''; } catch (e) { O.error = e.message; }
    render(true);
  }
  async function loadBoard() {
    try {
      O.board = await get('/api/office/board');
      if ((O.unread?.board || 0) > 0 && !O.sel) { const r = await post('/api/office/seen', { what: 'board' }); O.unread = r.unread; renderNav(); }
    } catch (e) { O.error = e.message; }
    render(true);
  }
  async function loadNotes(user) {
    try {
      O.notes[user.toLowerCase()] = await get('/api/office/notes?user=' + enc(user));
      if (isMe(user) && (O.unread?.notes || 0) > 0) { const r = await post('/api/office/seen', { what: 'notes' }); O.unread = r.unread; renderNav(); }
    } catch (e) { note(e.message, { err: true }); }
    render(true);
  }
  function refresh() { loadState(); if (O.sel) loadNotes(O.sel); else loadBoard(); }
  VIEW_REFRESH.office = refresh;
  setInterval(() => { if (S.view === 'office' && !hidden() && !O.busy && !O.edit) refresh(); }, 20000);

  /* ---------------------------------------------------------------- rendering */

  // plain text -> safe HTML: escape first, then links (http/https only) and line breaks
  function rich(text) {
    return esc(text).replace(/\bhttps?:\/\/[^\s<>"']+[^\s<>"'.,;:!?)\]]/g, (u) => `<a class="link" href="${u}" target="_blank" rel="noopener noreferrer nofollow">${u}</a>`)
      .replace(/(^|\s)@([A-Za-z0-9][A-Za-z0-9._-]{1,59})/g, (m, pre, name) => person(name) ? `${pre}<button class="mention" data-act="officeOpen" data-arg="${esc(person(name).user)}">@${esc(name)}</button>` : m)
      .replace(/\n/g, '<br>');
  }
  const who = (u) => { const p = person(u); return p ? p : { user: u, avatar: '', gone: true }; };
  const badgeFor = (p) => [p.role !== 'Team member' ? `<span class="tag">${esc(p.role)}</span>` : '', p.administrative && p.role === 'Team member' ? '<span class="tag tag-accent">Moderator</span>' : ''].join('');

  function personRow(p) {
    const pr = p.presence || presenceOf(p.user);
    const line = [p.title, p.department].filter(Boolean).join(' · ');
    return `<button class="op-row ${O.sel && O.sel.toLowerCase() === p.user.toLowerCase() ? 'on' : ''} ${pr.s}" data-act="officeOpen" data-arg="${esc(p.user)}" title="${esc(p.user)}${p.status ? ' · ' + esc(p.status) : ''}">
      ${avatar(p.user, p.avatar, '', true)}
      <span class="op-main"><b class="ell">${esc(p.user)}${isMe(p.user) ? ' <span class="dim">(you)</span>' : ''}</b>
        <small class="ell">${p.status ? `<i>${esc(p.status)}</i>` : esc(line || p.role)}</small></span></button>`;
  }
  function peoplePanel() {
    const all = O.state?.people || [];
    const q = O.q.toLowerCase();
    const list = all.filter((p) => !q || [p.user, p.title, p.department, p.status].some((x) => String(x || '').toLowerCase().includes(q)));
    const groups = [['online', 'Online'], ['idle', 'Idle'], ['offline', 'Offline']].map(([s, label]) => {
      const rows = list.filter((p) => (D.presence[p.user]?.s || p.presence?.s || 'offline') === s);
      return rows.length ? `<div class="cap op-group">${label} · ${rows.length}</div>${rows.map(personRow).join('')}` : '';
    }).join('');
    const on = all.filter((p) => (D.presence[p.user]?.s || p.presence?.s) !== 'offline').length;
    return `<aside class="aside office-people" aria-label="People">
      <div class="op-head"><div><div class="cap">People</div><b>${fmt.n(all.length)} ${all.length === 1 ? 'person' : 'people'} · ${fmt.n(on)} around</b></div></div>
      <div class="op-search"><input id="office-q" class="input" type="search" placeholder="Search people" value="${esc(O.q)}" autocomplete="off"></div>
      <div class="op-list" data-scroll="office-people">${groups || '<div class="empty">Nobody matches.</div>'}</div>
    </aside>`;
  }

  function noteCard(n, onProfile) {
    const a = who(n.author);
    const editing = O.edit === n.id;
    const tools = [n.can_pin ? `<button class="icbtn sm" data-act="officePin" data-arg="${n.id}" title="${n.pinned ? 'Unpin' : 'Pin to the top'}">${icon(n.pinned ? 'star-off' : 'pin', 'sm')}</button>` : '',
      n.can_edit && !editing ? `<button class="icbtn sm" data-act="officeEdit" data-arg="${n.id}" title="Edit">${icon('pencil', 'sm')}</button>` : '',
      n.can_delete ? `<button class="icbtn sm" data-act="officeDelete" data-arg="${n.id}" title="Remove">${icon('trash-2', 'sm')}</button>` : ''].join('');
    const body = editing
      ? `<textarea id="office-edit-${n.id}" class="input office-text" rows="3" maxlength="2000">${esc(O.drafts['edit:' + n.id] ?? n.body)}</textarea>
         <div class="office-compose-foot"><div class="grow"></div><button class="btn btn-secondary sm" data-act="officeEditCancel">Cancel</button><button class="btn btn-primary sm" data-act="officeEditSave" data-arg="${n.id}">Save</button></div>`
      : `<div class="note-body">${rich(n.body)}</div>`;
    return `<article class="note-card ${n.pinned ? 'pinned' : ''} ${n.private ? 'private' : ''}">
      <header>${a.gone ? avatar(n.author, '', 'sm') : `<button class="note-who" data-act="officeOpen" data-arg="${esc(a.user)}">${avatar(a.user, a.avatar, 'sm', true)}</button>`}
        <div class="note-meta"><b>${a.gone ? esc(n.author) + ' <span class="dim">(former member)</span>' : `<button class="link plain" data-act="officeOpen" data-arg="${esc(a.user)}">${esc(a.user)}</button>`}</b>
          <small class="dim" title="${esc(new Date(n.ts * 1000).toLocaleString())}">${esc(fmt.ago(n.ts))}${n.edited ? ' · edited' : ''}${n.pinned ? ' · pinned' : ''}${n.private ? ' · private' : ''}</small></div>
        <div class="note-tools">${tools}</div></header>
      ${body}</article>`;
  }

  function composer(key, placeholder, target) {
    const canPrivate = !!target;
    return `<div class="office-compose">
      <textarea id="office-draft-${esc(key)}" class="input office-text" rows="3" maxlength="2000" placeholder="${esc(placeholder)}" data-draft="${esc(key)}">${esc(O.drafts[key] || '')}</textarea>
      <div class="office-compose-foot">
        ${canPrivate ? `<label class="dlg-check"><input type="checkbox" data-change="officePriv" ${O.priv ? 'checked' : ''}> ${icon('lock', 'sm')} Private: only ${esc(target)} and you</label>` : '<span class="small dim">Everyone on the team sees this · @name mentions someone</span>'}
        <div class="grow"></div>
        <button class="btn btn-primary sm" data-act="officeSend" data-arg="${esc(key)}"${O.busy ? ' disabled' : ''}>${icon('send', 'sm')} ${target ? 'Leave note' : 'Post'}</button>
      </div></div>`;
  }

  function boardPanel() {
    const B = O.board;
    const head = `<div class="office-head"><div><div class="cap">Team</div><h3>Noticeboard</h3><p class="small dim">Pinned posts stay on top.</p></div></div>`;
    if (!B) return head + loading('Loading the noticeboard…');
    const posts = [...B.pinned, ...B.posts];
    return `${head}${has('office.post') ? composer('board', 'Share something with the team…', '') : '<p class="small dim office-pad">You can read the noticeboard but not post to it.</p>'}
      <div class="note-list">${posts.map((n) => noteCard(n, false)).join('') || emptyState('megaphone', 'Nothing posted yet', 'Be the first to say hello.')}</div>
      ${B.next ? `<div class="office-pad"><button class="btn btn-secondary" data-act="officeMore">Older posts</button></div>` : ''}`;
  }

  function profileForm() {
    const p = D.me?.profile || {};
    return `<div class="office-card office-form">
      <div class="cap">Your profile</div>
      <div class="form">
        <label>Job title<input class="input" id="op-title" maxlength="60" value="${esc(p.title || '')}" placeholder="e.g. Video editor"></label>
        <label>Department<input class="input" id="op-dept" maxlength="60" value="${esc(p.department || '')}" placeholder="e.g. Post-production"></label>
        <label class="wide">Status<input class="input" id="op-status" maxlength="80" value="${esc(p.status || '')}" placeholder="e.g. On holiday until Friday · In the studio"></label>
        <label class="wide">About<textarea class="input" id="op-about" rows="3" maxlength="600" placeholder="What you work on, how to reach you, working hours…">${esc(p.about || '')}</textarea></label>
        <label class="dlg-check wide"><input type="checkbox" id="op-email" ${p.show_email ? 'checked' : ''}> Show my e-mail address to colleagues</label>
      </div>
      <div class="office-compose-foot"><span class="small dim">Change your picture in Settings › Account.</span><div class="grow"></div>
        <button class="btn btn-secondary sm" data-act="officeProfileCancel">Cancel</button><button class="btn btn-primary sm" data-act="officeProfileSave"${O.busy ? ' disabled' : ''}>Save profile</button></div></div>`;
  }

  function manageCard(p) {
    if (!p.office_caps || !O.state) return '';
    const perms = O.state.office_permissions || [];
    const held = new Set(p.office_caps);
    const dis = p.manageable ? '' : ' disabled';
    return `<div class="office-card office-manage"><div class="cap">${icon('shield', 'sm')} ${esc(p.user)}'s team access</div>
      ${p.manageable ? '' : '<p class="small dim">Only the owner can change another moderator.</p>'}
      <div class="cap-checks">${perms.map((x) => `<label class="cap-check" title="${esc(x.description)}"><input type="checkbox" name="om-cap" value="${esc(x.id)}" ${held.has(x.id) ? 'checked' : ''}${dis}><span>${esc(x.label)}</span></label>`).join('')}</div>
      <div class="form smt-2">
        <label>Job title<input class="input" id="om-title" maxlength="60" value="${esc(p.title || '')}"${dis}></label>
        <label>Department<input class="input" id="om-dept" maxlength="60" value="${esc(p.department || '')}"${dis}></label>
      </div>
      <div class="office-compose-foot"><span class="small dim">Only affects Team. Other permissions are under Accounts.</span><div class="grow"></div>
        <button class="btn btn-primary sm" data-act="officeManageSave" data-arg="${esc(p.user)}"${O.busy || !p.manageable ? ' disabled' : ''}>Save</button></div></div>`;
  }

  function profilePanel(user) {
    const p = person(user);
    if (!p) return `<div class="office-pad">${emptyState('user-x', 'Not on the team', 'This account is disabled, not activated yet, or deleted.')}</div>`;
    const pr = D.presence[p.user] || p.presence || { s: 'offline' };
    const N = O.notes[p.user.toLowerCase()];
    const facts = [p.department && ['Team', esc(p.department)], p.email && ['E-mail', `<a class="link" href="mailto:${esc(p.email)}">${esc(p.email)}</a>`],
      ['Presence', `${esc(PRESENCE_LABEL[pr.s] || 'Offline')}${pr.s === 'offline' && pr.seen ? ' · last seen ' + esc(fmt.ago(pr.seen)) : ''}`],
      p.last_login && ['Last sign-in', esc(fmt.ago(p.last_login))]].filter(Boolean);
    const self = isMe(p.user);
    return `<div class="office-profile">
      <div class="op-hero">${avatar(p.user, p.avatar, 'lg', true)}
        <div class="op-hero-txt"><div class="row" style="flex-wrap:wrap;gap:6px"><h3>${esc(p.user)}</h3>${badgeFor(p)}</div>
          <div class="op-title">${esc(p.title || (self ? 'Add a job title' : p.role))}</div>
          ${p.status ? `<div class="op-status">${esc(p.status)}</div>` : ''}</div>
        <div class="op-hero-act">${self && !O.editProfile ? `<button class="btn btn-secondary sm" data-act="officeProfileEdit">${icon('pencil', 'sm')} Edit profile</button>` : ''}
          <button class="btn btn-secondary sm" data-act="officeClose">${icon('megaphone', 'sm')} Noticeboard</button></div></div>
      ${self && O.editProfile ? profileForm() : ''}
      <dl class="op-facts">${facts.map(([k, v]) => `<div><dt>${k}</dt><dd>${v}</dd></div>`).join('')}</dl>
      ${p.about ? `<div class="office-card op-about">${rich(p.about)}</div>` : ''}
      ${manageCard(p)}
      <div class="office-sub"><h5>${icon('sticky-note', 'sm')} Notes${self ? ' for you' : ' on ' + esc(p.user) + "'s profile"}</h5><span class="small dim">${self ? 'You can remove any of these.' : 'Visible to the whole team unless marked private.'}</span></div>
      ${!self && has('office.notes') ? composer('note:' + p.user.toLowerCase(), `Leave a note for ${p.user}…`, p.user) : ''}
      <div class="note-list">${!N ? loading('Loading notes…') : N.notes.map((n) => noteCard(n, true)).join('') || `<div class="empty">${self ? 'No notes yet.' : 'No notes on this profile yet.'}</div>`}</div>
    </div>`;
  }

  function vOffice() {
    if (!has('office.view')) return `<section class="panel">${emptyState('users', 'You don’t have access to Team', 'Ask a moderator for the “View the team” permission.')}</section>`;
    if (!O.state && !O.error) { loadState(); loadBoard(); }
    if (O.error && !O.state) return `<section class="panel">${emptyState('circle-alert', 'Couldn’t load the team', O.error)}</section>`;
    if (!O.state) return loading('Loading…');
    return `<div class="split office" style="grid-template-columns:1fr 300px">
      <section class="aside office-main" data-scroll="office-main">${O.sel ? profilePanel(O.sel) : boardPanel()}</section>
      ${peoplePanel()}
    </div>`;
  }
  VIEWFN.office = vOffice;

  /* ---------------------------------------------------------------- actions */

  async function busy(name, fn) {
    if (O.busy) return;
    O.busy = name; render(true);
    try { await fn(); } catch (e) { note(e.message, { err: true }); } finally { O.busy = ''; render(true); }
  }
  Object.assign(ACT, {
    officeOpen(user) {
      if (S.view !== 'office') go('office');
      O.sel = user; O.edit = null; O.editProfile = false; O.priv = false; render(true); loadNotes(user);
      const m = document.querySelector('[data-scroll="office-main"]'); if (m) m.scrollTop = 0;
    },
    officeClose() { O.sel = ''; O.edit = null; O.editProfile = false; render(true); loadBoard(); },
    officePriv(checked) { O.priv = !!checked; },
    officeSend(key) {
      const body = (O.drafts[key] || '').trim();
      if (!body) return note('Write something first', { err: true });
      const target = key.startsWith('note:') ? (person(key.slice(5)) || {}).user : '';
      return busy('send', async () => {
        await post('/api/office/post', { body, target: target || '', private: !!(target && O.priv) });
        O.drafts[key] = ''; O.priv = false;
        if (target) await loadNotes(target); else await loadBoard();
        note(target ? 'Note left for ' + target : 'Posted to the noticeboard');
      });
    },
    officeEdit(id) { O.edit = +id; render(true); setTimeout(() => $('#office-edit-' + id)?.focus(), 0); },
    officeEditCancel() { delete O.drafts['edit:' + O.edit]; O.edit = null; render(true); },
    officeEditSave(id) {
      const body = (O.drafts['edit:' + id] ?? $('#office-edit-' + id)?.value ?? '').trim();
      return busy('edit', async () => { await post('/api/office/post/edit', { id: +id, body }); delete O.drafts['edit:' + id]; O.edit = null; refresh(); });
    },
    async officeDelete(id) {
      if (!(await ask({ kicker: 'Team', title: 'Remove this post?', danger: true, ok: 'Remove', text: 'It’s removed for everyone. This can’t be undone.' }))) return;
      return busy('delete', async () => { await post('/api/office/post/delete', { id: +id }); note('Removed'); refresh(); });
    },
    officePin(id) {
      const n = [...(O.board?.pinned || []), ...(O.board?.posts || [])].find((x) => x.id === +id);
      return busy('pin', async () => { await post('/api/office/post/pin', { id: +id, pinned: !(n && n.pinned) }); await loadBoard(); });
    },
    async officeMore() {
      if (!O.board?.next) return;
      try { const r = await get('/api/office/board?before=' + enc(O.board.next)); O.board = { ...O.board, posts: [...O.board.posts, ...r.posts], next: r.next }; render(true); } catch (e) { note(e.message, { err: true }); }
    },
    officeProfileEdit() { O.editProfile = true; render(true); setTimeout(() => $('#op-title')?.focus(), 0); },
    officeProfileCancel() { O.editProfile = false; render(true); },
    officeProfileSave() {
      const body = { title: $('#op-title')?.value || '', department: $('#op-dept')?.value || '', status: $('#op-status')?.value || '',
        about: $('#op-about')?.value || '', show_email: !!$('#op-email')?.checked };
      return busy('profile', async () => { const r = await post('/api/office/profile', body); if (D.me) D.me.profile = r.profile; O.editProfile = false; note('Profile saved'); await loadState(); });
    },
    officeManageSave(user) {
      const caps = [...document.querySelectorAll('input[name="om-cap"]:checked')].map((x) => x.value);
      if (caps.length && !caps.includes('office.view')) return note('The other team permissions need “View the team”', { err: true });
      return busy('manage', async () => {
        await post('/api/office/member', { user, caps, title: $('#om-title')?.value || '', department: $('#om-dept')?.value || '' });
        note(`Saved ${user}’s team access`); await loadState();
      });
    },
  });
  PALETTE_SOURCES.push((q) => (!VIEWS.office ? [] : O.state?.people || []).filter((p) => !q || p.user.toLowerCase().includes(q.toLowerCase())).slice(0, 8)
    .map((p) => ({ label: p.user, hint: p.title || p.role, icon: 'user', group: 'People', run: () => ACT.officeOpen(p.user) })));

  document.addEventListener('input', (e) => {
    const t = e.target;
    if (t.id === 'office-q') { O.q = t.value; render(true); return; }
    if (t.dataset && t.dataset.draft) { O.drafts[t.dataset.draft] = t.value; return; }
    if (t.id && t.id.startsWith('office-edit-')) O.drafts['edit:' + t.id.slice(12)] = t.value;
  });
  document.addEventListener('keydown', (e) => {
    const t = e.target;
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && t.dataset && t.dataset.draft) { e.preventDefault(); ACT.officeSend(t.dataset.draft); }
  });
})();
