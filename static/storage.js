'use strict';
/* Strata storage: file manager for every drive, chunked + resumable uploader, file analyser. Loaded after app.js.
   Everything shown from the server passes through esc(); file names are user data. */

['files', 'upload', 'analyze'].forEach((v) => STATIC_VIEWS.add(v));
Object.assign(S, {
  fmount: store.get('fmount', 1), fgrid: store.get('fgrid', false), ftree: store.get('ftree', false), ftreeExpanded: new Set(['/']), fq: '', clip: null, finsTab: 'details',
  fOffset: Math.max(0, Math.floor(Number(store.get('fOffset', 0)) || 0)), fPageSize: Number(store.get('fPageSize', 250)) || 250,
  upMount: store.get('upMount', 1), upPath: store.get('upPath', '/'), upPolicy: store.get('upPolicy', 'ask'),
  anMount: store.get('anMount', 'all'), anPath: '/', anTab: 'types', anColor: 'extension', editor: null, picker: null, resumeFor: null,
});
if (![100, 250, 500].includes(S.fPageSize)) S.fPageSize = 250;
S.sort.files = S.sort.files || 'name';
S.sortDir = S.sortDir || { files: 1 };
Object.assign(D, { drives: null, uploadsSrv: null, an: null, anTree: null, anList: null, dupes: null, jobs: null, me: null,
  fsearch: null, info: null, vers: null, filePreview: null, folderTree: Object.create(null) });
const MiB = 1048576;
const UPCFG = { chunk: 32 * MiB, parallel: 3 };
const CAT_COLOR = { image: 'var(--color-text)', video: 'var(--color-accent)', audio: 'var(--color-accent-700)',
  '3d': 'var(--color-neutral-700)', web: 'var(--color-neutral-500)', text: 'var(--color-neutral-400)',
  font: 'var(--color-neutral-600)', archive: 'var(--color-accent-400)', document: 'var(--color-neutral-800)',
  other: 'var(--color-neutral-300)', page: 'var(--color-neutral-400)' };
const DARK_CATS = new Set(['image', 'video', 'audio', '3d', 'document', 'font']);
const ACCESS = { hide: ['hidden', 'dim'], deny: ['403', 'hot'], password: ['login', 'hot'], signed: ['signed', 'hot'],
  ip_allow: ['IP only', 'hot'], geo_allow: ['geo', 'hot'], geo_deny: ['geo', 'hot'], hotlink: ['hotlink', 'hot'] };

const joinPath = (dir, name) => (dir === '/' || !dir ? '' : dir.replace(/\/$/, '')) + '/' + name;
const parentOf = (p) => p.replace(/\/[^/]*$/, '') || '/';
const rawUrl = (mount, path, dl, ver) => `/api/files/raw?mount=${mount}&path=${enc(path)}${dl ? '&download=1' : ''}${ver ? '&ver=' + ver : ''}`;
const thumbUrl = (mount, path, w) => `/api/files/thumb?mount=${mount}&path=${enc(path)}&w=${w || 240}`;
const served = () => (D.drives?.served || []);
const mountName = (id) => (served().find((m) => m.mount === +id) || {}).name || 'drive ' + id;
const isRootAccount = () => ['root', 'admin'].includes(D.me?.role);
// account-wide capability (/api/me lists exactly what the server allows)
const hasCap = (cap) => !!D.me && (isRootAccount() || (D.me.capabilities || []).includes(cap));
function zoneRoots(mount) {
  if (isRootAccount()) return [{ path: '/', access: 'write', caps: null }];
  return (D.me?.zones || []).filter((z) => +z.mount === +mount).map((z) => ({ path: z.path || '/', access: z.access || 'read', caps: z.effective || [] }));
}
function pathWithin(path, prefix) {
  path = ('/' + String(path || '').split('/').filter(Boolean).join('/')).replace(/\/$/, '') || '/';
  prefix = ('/' + String(prefix || '').split('/').filter(Boolean).join('/')).replace(/\/$/, '') || '/';
  return prefix === '/' || path === prefix || path.startsWith(prefix + '/');
}
// File capabilities at a folder: the union of the zones containing it, each already intersected with the account's
// own grants by the server. null = unrestricted (root / administrators). The server checks every request again.
function fileCaps(path = S.fpath, mount = S.fmount) {
  if (isRootAccount()) return null;
  const caps = new Set();
  zoneRoots(mount).forEach((z) => { if (pathWithin(path, z.path)) z.caps.forEach((c) => caps.add(c)); });
  return caps;
}
const fcan = (cap, path = S.fpath, mount = S.fmount) => { const c = fileCaps(path, mount); return c === null || c.has(cap); };
function activeZoneRoot(path = S.fpath, mount = S.fmount) {
  const roots = zoneRoots(mount);
  return roots.filter((z) => pathWithin(path, z.path)).sort((a, b) => b.path.length - a.path.length)[0] || roots[0] || { path: '/', access: 'read' };
}
function canWriteZone(path = S.fpath, mount = S.fmount) { return fcan('files.upload', path, mount); } // upload destinations
function fullDriveZone(mount = S.fmount) {
  return isRootAccount() || zoneRoots(mount).some((z) => z.path === '/' || !z.path);
}
function writableServed() {
  return served().filter((m) => isRootAccount() || zoneRoots(m.mount).some((z) => z.caps.includes('files.upload')));
}
const fileByName = (n) => (D.files?.files || []).find((f) => f.name === n);
const dirByName = (n) => (D.files?.dirs || []).find((d) => d.name === n);
const save = () => { persist(); ['fmount', 'fgrid', 'ftree', 'fOffset', 'fPageSize', 'upMount', 'upPath', 'upPolicy', 'anMount'].forEach((k) => store.set(k, S[k])); };

async function loadDrives() {
  try {
    if (!D.me) await loadMe(); // zone roots come from /api/me: without it an employee would be left at "/" (403)
    D.drives = await get('/api/drives');
    if (!served().some((m) => m.mount === +S.fmount) && served().length) S.fmount = served()[0].mount;
    const froot = activeZoneRoot(S.fpath, S.fmount).path;
    if (!pathWithin(S.fpath, froot)) S.fpath = froot;
    const writable = writableServed();
    if (!writable.some((m) => m.mount === +S.upMount) && writable.length) S.upMount = writable[0].mount;
    const uroots = zoneRoots(S.upMount).filter((z) => z.access === 'write');
    const uroot = uroots.find((z) => pathWithin(S.upPath, z.path)) || uroots[0];
    if (uroot && !pathWithin(S.upPath, uroot.path)) S.upPath = uroot.path;
  } catch { /* shown by the views */ }
}
async function loadMe() {
  try {
    D.me = await get('/api/me');
    UPCFG.chunk = Math.max(1, Math.min(95, D.me.upload.chunk_mb)) * MiB;
    UPCFG.parallel = Math.max(1, Math.min(8, D.me.upload.parallel));
  } catch { /* defaults */ }
}

/* ================================================================== file manager */

let filesSig = '';
async function pollFiles(force, focus = '') {
  try {
    if (!D.drives) await loadDrives();
    if (D.me && !isRootAccount() && !zoneRoots(S.fmount).some((z) => pathWithin(S.fpath, z.path))) S.fpath = activeZoneRoot(S.fpath, S.fmount).path;
    if (S.ftab === 'trash') D.trash = await get(`/api/files/trash?mount=${S.fmount}`);
    else {
      const focused = focus ? `&focus=${enc(focus)}` : '';
      const f = await get(`/api/files?mount=${S.fmount}&path=${enc(S.fpath)}&sort=${enc(S.sort.files || 'name')}&desc=${S.sortDir.files === -1 ? 1 : 0}&offset=${S.fOffset}&limit=${S.fPageSize}${focused}`);
      if (f.limit && f.offset >= f.total && f.offset > 0) {
        S.fOffset = Math.max(0, Math.floor((f.total - 1) / f.limit) * f.limit);
        store.set('fOffset', S.fOffset);
        return pollFiles(true);
      }
      if (focus) {
        S.fOffset = f.offset || 0;
        store.set('fOffset', S.fOffset);
        const found = f.dirs.some((entry) => entry.name === focus) || f.files.some((entry) => entry.name === focus);
        if (!found) S.fsel.delete(focus);
        else if (f.files.some((entry) => entry.name === focus)) { loadInfo(joinPath(S.fpath, focus)); loadFilePreview(joinPath(S.fpath, focus), f.files.find((entry) => entry.name === focus)); }
      }
      D.files = f;
    }
    [D.audit, D.jobs] = await Promise.all([get('/api/audit'), get('/api/jobs')]);
    const sig = JSON.stringify([D.files, D.trash, D.jobs]);
    if (force || sig !== filesSig) {
      filesSig = sig;
      if (S.view === 'files') {
        if (!force && typeof isUserScrolling === 'function' && isUserScrolling()) {
          setTimeout(() => { if (S.view === 'files') render(true); }, 400);
        } else {
          render(true);
        }
      }
    }

  } catch (e) {
    const root = activeZoneRoot(S.fpath, S.fmount).path;
    if (/not found/.test(e.message) && S.fpath !== root) { S.fpath = root; return pollFiles(true); }
    if (/unknown drive/.test(e.message) && served().length) { S.fmount = served()[0].mount; S.fpath = activeZoneRoot('/', S.fmount).path; return pollFiles(true); }
    note(e.message);
  }
}
VIEW_REFRESH.files = async () => { if (!D.me) await loadMe(); if (!D.drives) await loadDrives(); pollFiles(true); };
setInterval(() => { if (S.view === 'files' && !S.paused && !S.editor && !S.picker && !S.dialog) pollFiles(); }, 12000);

function accessBadge(state) {
  const a = ACCESS[state];
  return a ? `<span class="acc ${a[1]}">${esc(a[0])}</span>` : '';
}
function extras(f) {
  const x = [];
  if (f.variants && f.variants.br) x.push(`<span class="chip" title="Brotli variant ${esc(fmt.bytes(f.variants.br))}">br −${Math.round(100 - share(f.variants.br, f.size))}%</span>`);
  if (f.versions) x.push(`<span class="chip" title="${f.versions} earlier version(s)">v${f.versions + 1}</span>`);
  if (f.links) x.push(`<span class="chip" title="${f.links} short link(s)">${f.links} link${f.links > 1 ? 's' : ''}</span>`);
  return x.join('');
}
function sortedEntries() {
  const F = D.files;
  return { dirs: F.dirs, files: F.files };
}
function filePager() {
  const F = D.files;
  if (!F) return '';
  const total = F.total || 0, size = F.limit || S.fPageSize, offset = F.offset || 0;
  const first = total ? offset + 1 : 0, last = Math.min(total, offset + size);
  return `<div class="file-pager"><span>${fmt.n(first)}–${fmt.n(last)} of ${fmt.n(total)} items</span><div class="grow"></div>
    <label>Rows <select class="input" data-change="fPageSize" aria-label="Items per page">${[100, 250, 500].map((n) => `<option value="${n}" ${n === size ? 'selected' : ''}>${n}</option>`).join('')}</select></label>
    <button class="pill" data-act="fpage" data-arg="-1" ${offset <= 0 ? 'disabled' : ''} aria-label="Previous page">${icon('chevron-left', 'sm')}Previous</button>
    <button class="pill" data-act="fpage" data-arg="1" ${offset + size >= total ? 'disabled' : ''} aria-label="Next page">Next${icon('chevron-right', 'sm')}</button></div>`;
}
function crumbs(parts, act = 'fgo') {
  const root = activeZoneRoot(S.fpath, S.fmount).path;
  const base = root.split('/').filter(Boolean), tail = parts.slice(base.length);
  let current = root;
  return `<span class="crumbs"><button data-act="${act}" data-arg="${esc(root)}" title="Your storage zone">${esc(mountName(S.fmount))}${root !== '/' ? ' · ' + esc(root) : ''}</button>` +
    tail.map((p) => { current = joinPath(current, p); return `<span class="dim">/</span><button data-act="${act}" data-arg="${esc(current)}" data-dropdir="${esc(current)}">${esc(p)}</button>`; }).join('') + '</span>';
}
function vFiles() {
  if (!D.drives) return loading('Loading drives…');
  const roots = zoneRoots(S.fmount), root = activeZoneRoot(S.fpath, S.fmount).path;
  const tabs = served().map((m) => `<button class="pill ${m.mount === +S.fmount ? 'on' : ''}" data-act="fmount" data-arg="${m.mount}" title="${esc(m.path || (m.zone_roots || []).map((z) => z.path).join(', '))}">${esc(m.name)}${m.online === false ? ' · offline' : ''}</button>`).join('');
  const zoneTabs = roots.length > 1 ? `<span class="zone-tabs">${roots.map((z) => `<button class="pill ${z.path === root ? 'on' : ''}" data-act="fgo" data-arg="${esc(z.path)}" title="${esc(z.caps ? 'Allowed here: ' + z.caps.map((c) => c.replace('files.', '')).join(', ') : 'Full access')}">${esc(z.path)}</button>`).join('')}</span>` : '';
  const home = smartCfg().home;
  const topbar = `<div class="tbar ftopbar">
    <div class="ftopbar-drives">${tabs}${zoneTabs}</div>
    <div class="ftopbar-controls">
      <input id="fsearch" class="input fs-125 px-8 py-4 min-w-130 max-w-200" placeholder="Search this drive…" value="${esc(S.fq)}" autocomplete="off" spellcheck="false">
      <button class="pill ${S.smartSort ? 'on' : ''}" data-act="fsmart" title="${esc(S.smartSort
        ? 'On: uploads are sorted into type folders'
        : 'Off: uploads land where you drop them')}${esc(home ? '. Uploads to the drive root go to ' + home.path + '/<type>/' : '')}">Smart-Sort${S.smartSort ? ' ✓' : ''}</button>
      <button class="pill ${S.fgrid ? '' : 'on'}" data-act="fgrid" data-arg="0" title="List">List</button><button class="pill ${S.fgrid ? 'on' : ''}" data-act="fgrid" data-arg="1" title="Thumbnails">Grid</button>
      ${S.ftab === 'files' ? `<button class="pill ${S.ftree ? 'on' : ''}" data-act="ftree" title="Toggle folder navigation">${icon('folder-open', 'sm')} Folders</button>` : ''}
      ${fullDriveZone(S.fmount) && (fcan('files.restore', '/') || fcan('files.purge', '/')) ? `<button class="pill ${S.ftab === 'trash' ? 'on' : ''}" data-act="ftab" data-arg="${S.ftab === 'trash' ? 'files' : 'trash'}">Trash</button>` : ''}
      ${typeof sheetBtn === 'function' && meCan('system.settings') ? sheetBtn('files') : ''}
    </div></div>`;
  if (S.ftab === 'trash') return `<div class="split" style="grid-template-columns:1fr"><section class="aside fmain-aside">${topbar}${trashBody()}</section></div>`;
  const F = D.files;
  const parts = F ? F.parts : S.fpath.split('/').filter(Boolean);
  const n = S.fsel.size, one = n === 1 ? fileByName([...S.fsel][0]) : null, oneDir = n === 1 ? dirByName([...S.fsel][0]) : null;
  const clip = S.clip && fcan(S.clip.mode === 'cut' ? 'files.move' : 'files.copy') ? `<button class="pill on" data-act="fpaste" title="${esc(S.clip.paths.join('\n'))}">Paste ${S.clip.paths.length} (${S.clip.mode})</button>` : '';
  const actions = `<div class="tbar fbar">
    <div class="fbar-nav">${crumbs(parts)}
      <button class="pill" data-act="fup" ${S.fpath === root ? 'disabled' : ''} title="Parent folder (Backspace)">↑</button>
    </div>
    <div class="fbar-actions">
      ${fcan('files.mkdir') ? `<button class="pill" data-act="fmkdir">${icon('folder-plus', 'sm')} Folder</button>` : ''}
      ${fcan('files.edit') ? `<button class="pill" data-act="fnewfile">${icon('file-plus', 'sm')} File</button>` : ''}
      ${fcan('files.upload') ? `<button class="pill on" data-act="fpick" data-arg="upf">${icon('upload', 'sm')} Upload</button>` : ''}
      <span class="fbar-sep"></span>
      ${fcan('files.move') ? `<button class="pill" data-act="fclip" data-arg="cut" ${n ? '' : 'disabled'} title="Ctrl X">Cut</button>` : ''}
      <button class="pill" data-act="fclip" data-arg="copy" ${n ? '' : 'disabled'} title="Ctrl C">Copy</button>${clip}
      ${fcan('files.move') || fcan('files.copy') ? `<button class="pill" data-act="fmoveto" ${n ? '' : 'disabled'}>Move…</button>` : ''}
      ${fcan('files.rename') ? `<button class="pill" data-act="frename" ${n === 1 ? '' : 'disabled'} title="F2">Rename</button>` : ''}
      ${fcan('files.download') ? `<button class="pill" data-act="fdownload" ${n ? '' : 'disabled'}>Download</button>` : ''}
      ${fcan('files.delete') ? `<button class="pill danger" data-act="fdelete" ${n ? '' : 'disabled'} title="Delete">Delete${n > 1 ? ' ' + n : ''}</button>` : ''}
    </div></div>`;
  let body;
  if (S.fq && D.fsearch) body = searchBody();
  else if (!F) body = loading('Opening folder…');
  else body = S.fgrid ? gridBody() : listBody();
  if (S.ftree) ensureFolderTree();
  // the inspector is a resizable side panel (layout.js); its default grows with the window instead of a fixed 340 px
  const avail = innerWidth / (zoomNow || 1) - (S.navCollapsed ? 58 : 224) - (S.ftree ? 240 : 0);
  const insp = Math.round(Math.min(480, Math.max(320, avail * 0.3)));
  return `<div class="split has-inspector ${S.ftree ? 'has-ftree' : ''}" data-pane="inspector" style="grid-template-columns:${S.ftree ? '240px ' : ''}minmax(0,1fr) ${insp}px">
    ${S.ftree ? folderTree() : ''}<section class="aside fmain-aside">${topbar}${actions}${body}</section>
    ${one && !S.fq ? fileInspector(one) : oneDir && !S.fq ? folderInspector(oneDir) : folderAside()}
  </div>`;
}
function listBody() {
  const { dirs, files: fl } = sortedEntries();
  const rows = [];
  for (const d of dirs) {
    const p = joinPath(S.fpath, d.name);
    rows.push({ cells: [hcell(`<span class="fico dir"></span>${esc(d.name)}`, 'h800'), cell(d.size == null ? '—' : fmt.bytes(d.size), 'r dim', d.files != null ? fmt.n(d.files) + ' files' : ''),
      cell(fmt.dt(d.mtime), 'dim'), cell('folder', 'dim'), hcell(accessBadge(d.access)), cell(d.hits ? fmt.n(d.hits) : '—', 'r'), cell(d.sent ? fmt.bytes(d.sent) : '—', 'r dim'), cell('', '')],
      cls: 'click' + (S.fsel.has(d.name) ? ' sel' : '') + (d.hidden ? ' hid' : ''),
      attrs: `data-act="fsel" data-arg="${esc(d.name)}" data-menu="fitem" data-arg2="${esc(d.name)}" draggable="true" data-drag="${esc(d.name)}" data-dropdir="${esc(p)}"` });
  }
  for (const f of fl) {
    rows.push({ cells: [hcell(`<span class="fico ${esc(f.cat)}"></span>${esc(f.name)}`, '', f.name), cell(fmt.bytes(f.size), 'r'), cell(fmt.dt(f.mtime), 'dim'),
      cell(f.cat, 'dim'), hcell(accessBadge(f.access)), cell(f.hits ? fmt.n(f.hits) : '—', 'r' + (f.hits ? ' h800' : ' dim')), cell(f.sent ? fmt.bytes(f.sent) : '—', 'r dim'), hcell(extras(f))],
      cls: 'click' + (S.fsel.has(f.name) ? ' sel' : '') + (f.hidden ? ' hid' : ''),
      attrs: `data-act="fsel" data-arg="${esc(f.name)}" data-menu="fitem" data-arg2="${esc(f.name)}" draggable="true" data-drag="${esc(f.name)}"` });
  }
  const F = D.files;
  const summary = `${fmt.n(F.total ?? (F.dirs.length + F.files.length))} items · ${fmt.bytes(F.total_bytes ?? (F.files.reduce((a, f) => a + f.size, 0) + F.dirs.reduce((a, d) => a + (d.size || 0), 0)))}`;
  return `<div class="tbar px-18 py-5"><span class="small dim">${esc(summary)} · drag onto a folder to move it, hold Ctrl to copy</span></div>` +
    table('files', [{ t: 'Name', w: 260, sort: 'name' }, { t: 'Size', w: 80, a: 'r', sort: 'size' }, { t: 'Modified', w: 105, sort: 'mtime' }, { t: 'Type', w: 55 },
      { t: 'Access', w: 65 }, { t: 'Hits 30 d', w: 70, a: 'r', sort: 'hits' }, { t: 'Sent 30 d', w: 75, a: 'r', sort: 'sent' }, { t: '', w: 120 }], rows,
    { sort: S.sort.files, desc: S.sortDir.files !== 1, empty: 'Empty folder. Drop files here or use Upload.' }) + filePager();
}
function gridBody() {
  const { dirs, files: fl } = sortedEntries();
  const tile = (x, isDir) => {
    const p = joinPath(S.fpath, x.name);
    const artIcon = isDir ? 'folder-open' : x.cat === 'image' ? 'file-image' : x.cat === 'video' ? 'file-video-camera' : x.cat === 'audio' ? 'file-volume'
      : x.cat === 'web' ? 'file-code' : x.cat === 'text' ? 'file-text' : x.cat === 'archive' ? 'file-archive' : x.cat === 'document' ? 'file-type' : 'file';
    const ext = (x.name.split('.').pop() || '').slice(0, 6).toUpperCase();
    const inner = isDir ? `<div class="file-art folder-art">${icon(artIcon, 'xl')}</div>` : x.cat === 'image'
      ? `<img loading="lazy" alt="Preview of ${esc(x.name)}" src="${esc(thumbUrl(S.fmount, p, 240))}">`
      : `<div class="file-art ${esc(x.cat || 'other')}-art">${icon(artIcon, 'xl')}<span>${esc(ext || 'FILE')}</span></div>`;
    return `<div class="tile ${S.fsel.has(x.name) ? 'sel' : ''} ${x.hidden ? 'hid' : ''}" data-act="fsel" data-arg="${esc(x.name)}" data-menu="fitem" data-arg2="${esc(x.name)}" draggable="true" data-drag="${esc(x.name)}" ${isDir ? `data-dropdir="${esc(p)}"` : ''}>
      <div class="thumb">${inner}${accessBadge(x.access)}</div><div class="tname ell" title="${esc(x.name)}">${esc(x.name)}</div><div class="small dim">${isDir ? (x.size != null ? fmt.bytes(x.size) : 'folder') : fmt.bytes(x.size)}</div></div>`;
  };
  return `<div class="fgrid" data-scroll="fgrid">${dirs.map((d) => tile(d, true)).join('')}${fl.map((f) => tile(f, false)).join('') || (dirs.length ? '' : '<div class="empty">Empty folder.</div>')}</div>` + filePager();
}
function searchBody() {
  const R = D.fsearch;
  const rows = (R.dirs || []).map((d) => ({ cells: [hcell(`<span class="fico dir"></span>${esc(d.path)}`, 'h800'), cell(fmt.bytes(d.size), 'r dim'), cell(fmt.n(d.files) + ' files', 'dim')],
    cls: 'click', attrs: `data-act="fgo" data-arg="${esc(d.path)}"` }))
    .concat((R.files || []).map((f) => ({ cells: [hcell(`<span class="fico ${esc(f.cat)}"></span>${esc(f.path)}`), cell(fmt.bytes(f.size), 'r'), cell(fmt.dt(f.mtime), 'dim')],
      cls: 'click', attrs: `data-act="freveal" data-arg="${esc(f.path)}" data-menu="fpath" data-arg2="${esc(f.path)}"` })));
  return `<div class="tbar" style="padding:5px 18px"><span class="small dim">${fmt.n((R.files || []).length)} files and ${fmt.n((R.dirs || []).length)} folders matching “${esc(S.fq)}” below ${esc(S.fpath)} (from the index) · click to reveal</span>
    <div class="grow"></div><button class="pill" data-act="fsearchclear">Clear search</button></div>` +
    table('fsearch', [{ t: 'Path', w: 520 }, { t: 'Size', w: 90, a: 'r' }, { t: 'Modified', w: 120 }], rows, { empty: 'Nothing found.' });
}
// what happened to Cloudflare's cached copies after a delete / empty (r.cdn from the API)
function cdnNote(c) {
  if (!c) return '';
  if (!c.queued) return c.enabled ? '' : ' · Cloudflare purging is off';
  if (c.pending && c.ok === false) return ' · ⚠ Cloudflare still has cached copies: ' + (c.error || 'purge failed') + ' (queued, retrying)';
  return c.pending ? ' · Cloudflare purge queued' : ' · Cloudflare cache purged';
}
function purgeWarning(c) {
  if (!c || !c.pending || c.ok !== false) return '';
  return `<div class="tbar"><span class="small hot">⚠ ${fmt.n(c.pending)} Cloudflare purge${c.pending === 1 ? '' : 's'} waiting since ${esc(fmt.dt(c.oldest))}: ${esc(c.error || 'purge failed')}.
    Until they go through, deleted files can still be served from Cloudflare’s cache. Queued purges are sent automatically once the token works (restart Strata after editing strata.json).</span>
    <div class="grow"></div><button class="pill" data-act="cfPurgeRetry">Retry now</button></div>`;
}
function trashBody() {
  const T = D.trash;
  const rows = (T?.items || []).map((i) => ({
    cells: [hcell(`<span class="fico ${i.dir ? 'dir' : ''}"></span>${esc(i.path)}`), cell(i.dir ? fmt.bytes(i.size) + ' (folder)' : fmt.bytes(i.size), 'r dim'), cell(fmt.dt(i.ts), 'dim'), cell(i.user || '', 'dim'),
      cell(i.versions && i.versions.length ? i.versions.length + ' with history' : '', 'dim'), hcell(`<button class="pill" data-act="frestore" data-arg="${esc(i.batch + '|' + i.path)}">Restore</button>`)],
  }));
  return `<div class="tbar"><span class="h800" style="font-size:13px">Trash · ${esc(mountName(S.fmount))}</span><span class="small dim">${T ? fmt.n(T.items.length) + ' items · ' + esc(fmt.bytes(T.bytes)) : ''} · their URLs answer 403 until restored, and 404 once the trash is emptied</span>
    <div class="grow"></div><button class="pill danger" data-act="femptytrash" ${T && T.items.length ? '' : 'disabled'}>Empty trash</button></div>` + purgeWarning(T?.cdn) +
    (T ? table('trash', [{ t: 'Original path', w: 420 }, { t: 'Size', w: 120, a: 'r' }, { t: 'Deleted', w: 120 }, { t: 'By', w: 90 }, { t: 'History', w: 110 }, { t: '', w: 90 }], rows, { empty: 'The trash is empty.' }) : loading());
}
function fileInspector(f) {
  const path = joinPath(S.fpath, f.name);
  const ext = f.name.includes('.') ? f.name.split('.').pop().toLowerCase() : '';
  const P = D.filePreview && D.filePreview.path === path ? D.filePreview : null;
  let prev = '';
  if (f.cat === 'image') prev = `<img src="${esc(f.size < 6 * MiB ? rawUrl(S.fmount, path) : thumbUrl(S.fmount, path, 640))}" alt="">`;
  else if (f.cat === 'video') prev = `<video src="${esc(rawUrl(S.fmount, path))}" controls preload="metadata"></video>`;
  else if (f.cat === 'audio') prev = `<audio src="${esc(rawUrl(S.fmount, path))}" controls preload="none"></audio>`;
  else if (['html', 'htm'].includes(ext) && f.size <= 8 * MiB) prev = `<iframe class="html-preview" title="${esc(f.name)} preview" sandbox="" referrerpolicy="no-referrer" src="${esc(rawUrl(S.fmount, path))}"></iframe>`;
  else if (f.text && P && P.text != null) prev = `<div class="code-preview"><div class="code-preview-head"><span>${esc(ext || 'text')} preview</span><span>${P.text.length > 4000 ? 'first 4,000 characters' : 'text preview'}</span></div><pre><code>${esc(P.text.slice(0, 4000))}${P.text.length > 4000 ? '…' : ''}</code></pre></div>`;
  else if (f.text && P && P.error) prev = `<div class="preview-empty">${esc(P.error)}</div>`;
  else if (f.text && f.size > 2 * MiB) prev = '<div class="preview-empty">No preview for text files over 2 MiB.</div>';
  else if (f.text) prev = '<div class="preview-empty">Loading preview…</div>';
  const I = D.info && D.info.path === path ? D.info : null;
  const kv = (pairs) => `<div class="kv">${pairs.filter(Boolean).map(([k, v]) => `<span>${esc(k)}</span><span>${v && v.html ? v.html : esc(v ?? '—')}</span>`).join('')}</div>`;
  const tab = S.finsTab;
  let body = '';
  if (tab === 'versions') {
    const V = D.vers && D.vers.path === path ? D.vers : null;
    body = !V ? loading('Loading versions…') : `<div class="kv cols-1-auto"><span><b>current</b> · ${esc(fmt.bytes(V.current?.size))} · ${esc(fmt.dt(V.current?.mtime))}</span><span></span>
      ${(V.versions || []).map((v) => `<span>v${v.n} · ${esc(fmt.bytes(v.size))} · ${esc(fmt.dt(v.created))} <span class="dim">${esc(v.note || '')}</span></span>
        <span><button class="link" data-act="fvdl" data-arg="${v.n}">download</button> · <button class="link" data-act="fvcopy" data-arg="${esc(v.url)}">link</button> · <button class="link" data-act="fvrestore" data-arg="${v.n}">restore</button> · <button class="link" data-act="fvdel" data-arg="${v.n}">delete</button></span>`).join('') || '<span class="dim">No earlier versions yet. Replacing or editing the file keeps one.</span><span></span>'}
      </div><div class="small dim px-16 pt-0 pb-12">Public link to an old version: add <code>?ver=N</code> to the file URL.</div>`;
  } else if (tab === 'access') {
    const rs = I ? I.access.rules : f.rules || [];
    body = `<div class="kv"><span>State</span><span>${esc(f.access === 'public' ? 'public: anyone can open it' : (ACCESS[f.access] || [f.access])[0])}</span>
      ${rs.map((r) => `<span>Rule</span><span>${esc(r.name)} <span class="dim">(${esc(r.action)})</span></span>`).join('')}</div>
      <div class="act-row px-16 pt-0 pb-14">
        <button class="btn btn-secondary" data-act="fquickrule" data-arg="hide">Hide</button>
        <button class="btn btn-secondary" data-act="fquickrule" data-arg="deny">Forbid</button>
        <button class="btn btn-secondary" data-act="fquickrule" data-arg="password">Password…</button>
        <button class="btn btn-secondary" data-act="fquickrule" data-arg="signed">Signed links only</button>
        <button class="btn btn-secondary" data-act="fquickrule" data-arg="download">Force download</button>
      </div>`;
  } else if (tab === 'preview') {
    body = linkPreviewPanel(path, false);
  } else if (tab === 'links') {
    const ls = I ? I.links : [];
    body = `<div class="kv">${ls.map((l) => `<span>/l/${esc(l.code)}</span><span>${fmt.n(l.clicks)} clicks${l.max_clicks ? ' of ' + l.max_clicks : ''}${l.expires ? ' · until ' + esc(fmt.dt(l.expires)) : ''}</span>`).join('') || '<span class="dim">No short links yet.</span><span></span>'}</div>
      <div class="act-row px-16 pt-0 pb-14"><button class="btn btn-primary" data-act="fshare">New link…</button></div>`;
  } else {
    const img = I && I.image && !I.image.error ? `${I.image.width} × ${I.image.height} ${I.image.format || ''}${I.image.frames > 1 ? ' · ' + I.image.frames + ' frames' : ''}` : null;
    const daily = I && I.daily && I.daily.length ? { html: `<span class="bars-mini">${I.daily.map((d) => `<i title="${esc(d.d)}: ${d.c}" style="height:${Math.max(8, share(d.c, Math.max(...I.daily.map((x) => x.c)))).toFixed(0)}%"></i>`).join('')}</span>` } : 'no hits in 30 days';
    body = kv([['Public URL', { html: `<a class="link" href="${esc(f.url)}" target="_blank" rel="noopener">${esc(f.url)}</a>` }], ['Modified', fmt.dt(f.mtime)],
      img && ['Image', img], ['Hits by day', daily], ['Last hit', f.last ? fmt.ago(f.last) : 'never (30 d, origin)'],
      I && I.referrers && I.referrers.length && ['Referrers', I.referrers.map((r) => r.k + ' ×' + r.c).join(', ')],
      ['SHA-256', I && I.sha256 ? I.sha256 : { html: '<button class="link" data-act="fhash">compute</button>' }],
      I && I.duplicates && I.duplicates.length && ['Duplicates', I.duplicates.join(', ')],
      ['Brotli', f.variants && f.variants.br ? fmt.bytes(f.variants.br) + ' (−' + fmt.pct(100 - share(f.variants.br, f.size)) + ')' : 'none'],
      ['Caching', f.access !== 'public' ? 'private, no-store (protected)' : 'browsers revalidate, Cloudflare 1 year (purged on change)']]);
  }
  return `<aside class="aside finspector" data-scroll="finspector-all">
    <div class="insp-head">
      <div class="cap red">${esc(f.cat)}${ext ? ' · .' + esc(ext) : ''} ${accessBadge(f.access)}</div>
      <h5 class="fins-name" title="${esc(f.name)}">${esc(f.name)}</h5>
      <div class="small dim break-all">${esc(mountName(S.fmount))} · ${esc(path)}</div>
      <div class="inspector-actions">
        <button class="btn btn-primary" data-act="fopenurl" data-arg="${esc(f.url)}">${icon('external-link', 'sm')} Open ↗</button>
        <button class="btn btn-secondary" data-act="fpreview">${icon('eye', 'sm')} Preview</button>
        <button class="btn btn-secondary" data-act="fshare">${icon('share-2', 'sm')} Share…</button>
        <button class="btn btn-secondary" data-act="fcopy" data-arg="${esc(f.url)}">${icon('copy', 'sm')} Copy link</button>
        <button class="btn btn-secondary" data-act="fdownload">${icon('download', 'sm')} Download</button>
        ${f.text ? `<button class="btn btn-secondary" data-act="fedit">${icon('pencil', 'sm')} Edit</button>` : ''}
      </div>
    </div>
    ${prev ? `<div class="preview">${prev}</div>` : ''}
    <div class="stats2">
      <div><div class="cap">Size</div><div class="v">${esc(fmt.bytes(f.size))}</div></div>
      <div><div class="cap">Versions</div><div class="v">${f.versions ? f.versions + ' earlier' : '—'}</div></div>
      <div><div class="cap">Hits · 30 d</div><div class="v">${esc(fmt.n(f.hits))}</div></div>
      <div><div class="cap">Sent · 30 d</div><div class="v">${esc(fmt.bytes(f.sent))}</div></div>
    </div>
    <div class="tabs">${['details', 'versions', 'access', 'links', 'preview'].map((t) => `<button class="${tab === t ? 'on' : ''}" data-act="finstab" data-arg="${t}">${t === 'preview' ? 'embed' : t}</button>`).join('')}</div>
    <div class="fins-body">${body}</div>
  </aside>`;
}
OVERLAYS.push(() => {
  const P = S.fpreview;
  if (!P) return '';
  const f = fileByName(P.name), path = P.path;
  if (!f) return `<div class="file-preview-overlay" data-act="fpreviewClose"><div class="file-preview-dialog" data-act="noop"><div class="file-preview-head"><b>${esc(P.name)}</b><button class="icbtn" data-act="fpreviewClose" aria-label="Close preview">${icon('x')}</button></div><div class="preview-empty">This file is no longer in this folder.</div></div></div>`;
  const ext = (f.name.split('.').pop() || '').toLowerCase();
  let content;
  if (f.cat === 'image') content = `<img src="${esc(f.size < 6 * MiB ? rawUrl(S.fmount, path) : thumbUrl(S.fmount, path, 1600))}" alt="${esc(f.name)}">`;
  else if (f.cat === 'video') content = `<video src="${esc(rawUrl(S.fmount, path))}" controls autoplay></video>`;
  else if (f.cat === 'audio') content = `<audio src="${esc(rawUrl(S.fmount, path))}" controls autoplay></audio>`;
  else if (['html', 'htm'].includes(ext) && f.size <= 8 * MiB) content = `<iframe title="${esc(f.name)} preview" sandbox="" referrerpolicy="no-referrer" src="${esc(rawUrl(S.fmount, path))}"></iframe>`;
  else if (f.text && D.filePreview?.path === path && D.filePreview.text != null) content = `<pre><code>${esc(D.filePreview.text.slice(0, 100000))}${D.filePreview.text.length > 100000 ? '\n… (first 100,000 characters)' : ''}</code></pre>`;
  else if (f.text && D.filePreview?.path === path && D.filePreview.loading) content = '<div class="preview-empty">Loading text preview…</div>';
  else if (f.text && D.filePreview?.path === path && D.filePreview.error) content = `<div class="preview-empty">${esc(D.filePreview.error)}</div>`;
  else content = `<div class="preview-empty">No preview for this file type. Open it in a new tab.</div>`;
  return `<div class="file-preview-overlay" data-act="fpreviewClose"><div class="file-preview-dialog" role="dialog" aria-modal="true" aria-label="Preview ${esc(f.name)}" data-act="noop">
    <div class="file-preview-head"><div class="ell"><b>${esc(f.name)}</b><span class="small dim">${esc(fmt.bytes(f.size))}</span></div><div class="act-row"><button class="btn btn-secondary" data-act="fpreviewOpen">Open in new tab</button><button class="icbtn" data-act="fpreviewClose" aria-label="Close preview">${icon('x')}</button></div></div>
    <div class="file-preview-content">${content}</div></div></div>`;
});
// one folder selected: what is inside, clickable - folders open, files open in their folder (selected)
function folderInspector(d) {
  const path = joinPath(S.fpath, d.name);
  const baseUrl = D.files && D.files.base_url;
  const folderUrl = baseUrl ? baseUrl.replace(/\/?$/, '/') + path.split('/').filter(Boolean).map(encodeURIComponent).join('/') + '/' : '';
  const P = D.peek && D.peek.path === path ? D.peek : null;
  const dirs = P && P.dirs ? P.dirs : [], fl = P && P.files ? P.files : [];
  const imgs = fl.filter((f) => f.cat === 'image').slice(0, 8);
  const entry = (x, isDir) => `<div class="logline pointer" data-act="${isDir ? 'fgo' : 'freveal'}" data-arg="${esc(joinPath(path, x.name))}" title="${esc(isDir ? 'Open ' + x.name : 'Show ' + x.name)}">
      <span class="ell"><span class="fico ${isDir ? 'dir' : esc(x.cat)}"></span>${esc(x.name)}</span><span>${isDir ? (x.files != null ? fmt.n(x.files) + ' files' : 'folder') : esc(fmt.bytes(x.size))}</span></div>`;
  const list = !P || P.loading ? '<div class="empty">Loading…</div>' : P.error ? `<div class="empty hot">${esc(P.error)}</div>`
    : (dirs.map((x) => entry(x, true)).join('') + fl.map((x) => entry(x, false)).join('')) || '<div class="empty">Empty folder.</div>';
  return `<aside class="aside finspector" data-scroll="finspector-all">
    <div class="insp-head">
      <div class="cap red">folder ${accessBadge(d.access)}</div>
      <h5 class="fins-name" title="${esc(d.name)}">${esc(d.name)}</h5>
      <div class="small dim break-all">${esc(mountName(S.fmount))} · ${esc(path)}</div>
      <div class="inspector-actions">
        <button class="btn btn-primary" data-act="fgo" data-arg="${esc(path)}">${icon('folder', 'sm')} Open folder</button>
        <button class="btn btn-secondary" data-act="fshare">${icon('share-2', 'sm')} Share folder…</button>
        ${folderUrl ? `<button class="btn btn-secondary" data-act="fcopy" data-arg="${esc(folderUrl)}">${icon('copy', 'sm')} Copy URL</button>` : ''}
        <button class="btn btn-secondary" data-act="fdownload">${icon('download', 'sm')} Download</button>
        <button class="btn btn-secondary" data-act="frename">${icon('pencil', 'sm')} Rename</button>
      </div>
    </div>
    <div class="stats2">
      <div><div class="cap">Size</div><div class="v">${d.size != null ? esc(fmt.bytes(d.size)) : '—'}</div></div>
      <div><div class="cap">Files</div><div class="v">${d.files != null ? esc(fmt.n(d.files)) : '—'}</div></div>
      <div><div class="cap">Hits · 30 d</div><div class="v">${esc(fmt.n(d.hits))}</div></div>
      <div><div class="cap">Modified</div><div class="v">${esc(fmt.ago(d.mtime))}</div></div>
    </div>
    ${imgs.length ? `<div class="d-grid cols-4f gap-6 px-16 py-10 flex-none">${imgs.map((f) =>
      `<img loading="lazy" alt="${esc(f.name)}" title="${esc(f.name)}" src="${esc(thumbUrl(S.fmount, joinPath(path, f.name), 160))}" data-act="freveal" data-arg="${esc(joinPath(path, f.name))}" class="w-full square cover r-6 pointer">`).join('')}</div>` : ''}
    <div class="sect"><span class="cap">Link preview</span></div>
    ${linkPreviewPanel(path, true)}
    <div class="sect"><span class="cap">Contents</span><span class="small dim">${P && !P.loading && !P.error ? `${fmt.n(P.total || 0)} total · showing ${fmt.n(dirs.length + fl.length)}` : ''}</span></div>
    <div class="loglines fins-body" data-scroll="fpeek">${list}</div>
  </aside>`;
}
async function loadPeek(path) {
  D.peek = { path, loading: true };
  try {
    const r = await get(`/api/files?mount=${S.fmount}&path=${enc(path)}&sort=name&limit=200`);
    if (D.peek && D.peek.path === path) { D.peek = Object.assign(r, { path }); render(true); }
  } catch (e) { if (D.peek && D.peek.path === path) { D.peek = { path, error: e.message }; render(true); } }
}
function folderTreeKey(path) { return `${S.fmount}:${path}`; }
function treePathList(path) {
  const root = activeZoneRoot(path, S.fmount).path;
  const base = root.split('/').filter(Boolean), parts = path.split('/').filter(Boolean).slice(base.length);
  const out = [root]; let cur = root;
  for (const part of parts) { cur = joinPath(cur, part); out.push(cur); }
  return out;
}
function loadFolderBranch(path) {
  const key = folderTreeKey(path), old = D.folderTree[key];
  if (old && (old.loading || (old.dirs && Date.now() - old.at < 15000))) return;
  D.folderTree[key] = { loading: true };
  get(`/api/files/tree?mount=${S.fmount}&path=${enc(path)}`).then((r) => {
    D.folderTree[key] = { dirs: r.dirs || [], at: Date.now() };
    if (S.view === 'files' && S.ftree) render(true);
  }).catch((e) => {
    D.folderTree[key] = { error: e.message, dirs: [], at: Date.now() };
    if (S.view === 'files' && S.ftree) render(true);
  });
}
function invalidateFolderTree(path, mount = S.fmount) {
  if (+mount !== +S.fmount) return;
  for (const p of treePathList(path || '/')) delete D.folderTree[`${mount}:${p}`];
}
function ensureFolderTree() {
  const root = activeZoneRoot(S.fpath, S.fmount).path;
  S.ftreeExpanded.add(root);
  for (const path of treePathList(S.fpath)) if (S.ftreeExpanded.has(path)) loadFolderBranch(path);
}
function folderTreeBranch(path, depth = 0) {
  if (!S.ftreeExpanded.has(path)) return '';
  const state = D.folderTree[folderTreeKey(path)];
  if (!state || state.loading) return `<div class="ftree-note" style="padding-left:${12 + depth * 15}px">Loading folders…</div>`;
  if (state.error) return `<div class="ftree-note hot" style="padding-left:${12 + depth * 15}px">${esc(state.error)}</div>`;
  return state.dirs.map((d) => {
    const open = S.ftreeExpanded.has(d.path), hasChildren = d.sub !== 0;
    return `<div class="ftree-node"><div class="ftree-row" style="--tree-depth:${depth}">
      ${hasChildren ? `<button class="ftree-toggle" data-act="ftoggle" data-arg="${esc(d.path)}" aria-label="${open ? 'Collapse' : 'Expand'} ${esc(d.name)}">${icon(open ? 'chevron-down' : 'chevron-right', 'sm')}</button>` : '<span class="ftree-toggle-spacer"></span>'}
      <button class="ftree-name ${S.fpath === d.path ? 'on' : ''}" data-act="fgo" data-arg="${esc(d.path)}" data-dropdir="${esc(d.path)}" title="${esc(d.path)}">${icon('folder', 'sm')}<span class="ell">${esc(d.name)}</span>${d.bytes != null ? `<small>${esc(fmt.bytes(d.bytes))}</small>` : ''}</button>
      </div>${open ? folderTreeBranch(d.path, depth + 1) : ''}</div>`;
  }).join('') || `<div class="ftree-note" style="padding-left:${12 + depth * 15}px">No subfolders</div>`;
}
function folderTree() {
  const root = activeZoneRoot(S.fpath, S.fmount).path, rootOpen = S.ftreeExpanded.has(root);
  return `<aside class="aside ftree"><div class="ph"><h5>Folders</h5><button class="pill" data-act="fgo" data-arg="${esc(root)}">Root</button></div>
    <div class="ftree-scroll" data-scroll="ftree"><div class="ftree-row root ${S.fpath === root ? 'on' : ''}">
      <button class="ftree-toggle" data-act="ftoggle" data-arg="${esc(root)}" aria-label="${rootOpen ? 'Collapse' : 'Expand'} root">${icon(rootOpen ? 'chevron-down' : 'chevron-right', 'sm')}</button>
      <button class="ftree-name ${S.fpath === root ? 'on' : ''}" data-act="fgo" data-arg="${esc(root)}" data-dropdir="${esc(root)}" title="Your storage zone">${icon('hard-drive', 'sm')}<span class="ell">${esc(mountName(S.fmount))}${root !== '/' ? ' · ' + esc(root) : ''}</span></button>
      </div>${folderTreeBranch(root)}</div><div class="ftree-foot small dim">Pick a folder in your storage zone.</div></aside>`;
}
function folderAside() {
  const F = D.files, disk = F?.disk, inv = F?.inventory;
  const sel = [...S.fsel];
  const selBytes = sel.reduce((a, n) => a + ((fileByName(n) || {}).size || (dirByName(n) || {}).size || 0), 0);
  const act = (D.audit?.rows || []).slice(0, 25).map((r) => ({ a: (r.ok ? '' : '✕ ') + r.action + (r.target ? ' · ' + r.target : ''), b: fmt.ago(r.ts) }));
  const jobs = (D.jobs?.jobs || []).filter((j) => j.status === 'running' || Date.now() / 1000 - (j.finished || 0) < 300).slice(0, 5);
  const active = U.filter((u) => ['queued', 'uploading', 'paused', 'exists'].includes(u.status));
  return `<aside class="aside">
    <div class="pad"><div class="cap red">${esc(mountName(S.fmount))}</div><h5>${disk ? esc(fmt.pct(share(disk.used, disk.total))) + ' used' : 'Drive'}</h5></div>
    <div style="padding:0 16px 10px;flex:none">${disk ? segs(share(disk.used, disk.total), 24, 90, 's7') : ''}
      <div class="small dim smt-1">${disk ? esc(fmt.bytes(disk.free)) + ' free of ' + esc(fmt.bytes(disk.total)) : ''}</div></div>
    ${sel.length ? `<div class="sect"><span class="cap">Selection</span><span class="small dim">${sel.length} item(s) · ${esc(fmt.bytes(selBytes))}</span></div>` : ''}
    <div class="sect"><span class="cap">Uploads</span><button class="link small" data-act="go" data-arg="upload">open uploader →</button></div>
    <div class="uploads" id="fupmini">${miniQueue()}</div>
    ${jobs.length ? `<div class="sect"><span class="cap">Jobs</span></div><div class="uploads">${jobs.map((j) => `<div class="up ${j.status === 'error' ? 'err' : ''}"><div class="row"><span class="ell">${esc(j.title)}</span><b>${esc(j.status === 'running' ? fmt.pct(share(j.bytes, j.bytes_total || 1)) : j.status)}</b></div>${j.error ? `<div class="small hot">${esc(j.error)}</div>` : ''}<div class="bar2"><i style="width:${(j.status === 'done' ? 100 : share(j.bytes, j.bytes_total || 1)).toFixed(1)}%"></i></div></div>`).join('')}</div>` : ''}
    <div class="sect"><span class="cap">Library · ${inv ? fmt.n(inv.files) + ' files' : 'scanning'}</span><span class="small dim">${inv ? esc(fmt.bytes(inv.bytes)) : ''}</span></div>
    <div class="px-16 pt-0 pb-6 flex-none">${(inv?.cats || []).slice(0, 6).map((c) => gauge(c.k + ' · ' + fmt.n(c.c), fmt.bytes(c.b), share(c.b, inv.bytes), 101)).join('')}</div>
    <div class="sect"><span class="cap">Activity</span></div>
    <div class="loglines" data-scroll="faside">${act.map((l) => `<div class="logline"><span title="${esc(l.a)}">${esc(l.a)}</span><span>${esc(l.b)}</span></div>`).join('') || '<div class="logline"><span>—</span><span></span></div>'}</div>
    ${active.length ? '' : ''}

  </aside>`;
}

/* ---- selection + navigation */

async function loadInfo(path) {
  D.info = null; D.vers = null;
  try {
    const i = await get(`/api/files/info?mount=${S.fmount}&path=${enc(path)}`);
    if (S.fsel.size === 1 && joinPath(S.fpath, [...S.fsel][0]) === path) { D.info = i; render(true); }
  } catch { /* inspector still shows the listing data */ }
}
async function loadFilePreview(path, file) {
  if (!file || !file.text || file.size > 2 * MiB || ['html', 'htm'].includes((file.name.split('.').pop() || '').toLowerCase())) return;
  if (D.filePreview && D.filePreview.path === path && (D.filePreview.loading || D.filePreview.text != null || D.filePreview.error)) return;
  D.filePreview = { path, loading: true };
  try {
    const r = await get(`/api/files/text?mount=${S.fmount}&path=${enc(path)}`);
    if (S.fsel.size === 1 && joinPath(S.fpath, [...S.fsel][0]) === path) { D.filePreview = { path, text: r.text }; render(true); }
  } catch (e) {
    if (S.fsel.size === 1 && joinPath(S.fpath, [...S.fsel][0]) === path) { D.filePreview = { path, error: e.message }; render(true); }
  }
}
async function loadVersions(path) {
  try { D.vers = Object.assign(await get(`/api/files/versions?mount=${S.fmount}&path=${enc(path)}`), { path }); render(true); } catch (e) { note(e.message); }
}
function selectedPaths() { return [...S.fsel].map((n) => joinPath(S.fpath, n)); }
function one() { return S.fsel.size === 1 ? [...S.fsel][0] : null; }

Object.assign(ACT, {
  fmount(id) { S.fmount = +id; S.fpath = activeZoneRoot('/', +id).path; S.fOffset = 0; S.fsel = new Set(); S.fq = ''; D.fsearch = null; D.files = null; save(); render(true); pollFiles(true); },
  fgo(path) {
    if (S.view !== 'files') { S.view = 'files'; }
    path = path || '/';
    if (path === '/') path = activeZoneRoot(S.fpath, S.fmount).path;
    if (!isRootAccount() && !(D.me?.zones || []).some((z) => +z.mount === +S.fmount && pathWithin(path, z.path))) {
      note('That folder is outside your storage zones. Ask an administrator for access.', { err: true }); return;
    }
    S.fpath = path; S.fOffset = 0; S.fsel = new Set(); S.fanchor = null; S.ftab = 'files'; S.fq = ''; D.fsearch = null; D.files = null;
    treePathList(S.fpath).forEach((p) => S.ftreeExpanded.add(p));
    store.set('fpath', S.fpath); save(); render(true); pollFiles(true);
  },
  freveal(path) {
    const i = path.lastIndexOf('/'), name = path.slice(i + 1);
    S.view = 'files'; S.fpath = path.slice(0, i) || '/'; S.fOffset = 0; S.fsel = new Set([name]); S.fanchor = name;
    S.ftab = 'files'; S.fq = ''; S.finsTab = 'details'; D.fsearch = null; D.files = null; D.peek = null;
    store.set('fpath', S.fpath); save(); render(true); pollFiles(true, name);
  },
  fup() { const root = activeZoneRoot(S.fpath, S.fmount).path; if (S.fpath !== root) ACT.fgo(parentOf(S.fpath)); },
  fgrid(v) { S.fgrid = v === '1'; save(); render(true); },
  ftree() { S.ftree = !S.ftree; save(); render(true); },
  ftoggle(path) {
    if (S.ftreeExpanded.has(path)) S.ftreeExpanded.delete(path);
    else { S.ftreeExpanded.add(path); loadFolderBranch(path); }
    render(true);
  },
  ftab(t) { S.ftab = t; S.fOffset = 0; S.fsel = new Set(); save(); render(true); pollFiles(true); },
  fpage(delta) {
    const F = D.files; if (!F || S.fq) return;
    const size = F.limit || S.fPageSize, max = Math.max(0, Math.floor(Math.max(0, F.total - 1) / size) * size);
    S.fOffset = Math.max(0, Math.min(max, S.fOffset + Math.sign(+delta) * size));
    store.set('fOffset', S.fOffset); D.files = null; render(true); pollFiles(true);
  },
  fPageSize(value) {
    const size = +value; if (![100, 250, 500].includes(size)) return;
    S.fPageSize = size; S.fOffset = 0; save(); D.files = null; render(true); pollFiles(true);
  },
  fsel(name, el, e) {
    // double click detected here: the first click re-renders the list, so the browser's dblclick often never fires
    const t = Date.now(), multi = !!(e && (e.shiftKey || e.ctrlKey || e.metaKey));
    const lc = S.lastClick;
    S.lastClick = multi ? null : { name, path: S.fpath, t };
    if (!multi && lc && lc.name === name && lc.path === S.fpath && t - lc.t < 450) { S.lastClick = null; return ACT.fopen(name); }
    const all = sortedEntries().dirs.map((d) => d.name).concat(sortedEntries().files.map((f) => f.name));
    if (e && e.shiftKey && S.fanchor != null) {
      const a = all.indexOf(S.fanchor), b = all.indexOf(name);
      S.fsel = new Set(all.slice(Math.min(a, b), Math.max(a, b) + 1));
    } else if (e && (e.ctrlKey || e.metaKey)) {
      S.fsel.has(name) ? S.fsel.delete(name) : S.fsel.add(name);
      S.fanchor = name;
    } else { S.fsel = new Set([name]); S.fanchor = name; }
    S.finsTab = S.fsel.size === 1 ? S.finsTab : 'details';
    render(true);
    if (S.fsel.size === 1 && fileByName(name)) { loadInfo(joinPath(S.fpath, name)); loadFilePreview(joinPath(S.fpath, name), fileByName(name)); if (S.finsTab === 'versions') loadVersions(joinPath(S.fpath, name)); }
    if (S.fsel.size === 1 && dirByName(name) && !(D.peek && D.peek.path === joinPath(S.fpath, name))) loadPeek(joinPath(S.fpath, name));
  },
  fsmart() {
    S.smartSort = !S.smartSort; store.set('smartSort', S.smartSort);
    note(S.smartSort ? 'Smart-Sorting on: uploads go into type folders' : 'Smart-Sorting off: uploads land where you drop them' +
      (smartCfg().home && smartCfg().root_to_home ? ' (drive-root uploads still go to ' + smartCfg().home.path + ')' : ''));
    render(true);
  },
  finstab(t) { S.finsTab = t; render(true); const n = one(); if (n && t === 'versions') loadVersions(joinPath(S.fpath, n)); },
  fopen(name) {
    if (dirByName(name)) return ACT.fgo(joinPath(S.fpath, name));
    const f = fileByName(name);
    if (!f) return;
    if (['html', 'htm'].includes((f.name.split('.').pop() || '').toLowerCase())) return ACT.fpreview();
    if (f.text && f.size < 2 * MiB) return openEditor(S.fmount, joinPath(S.fpath, name));
    window.open(rawUrl(S.fmount, joinPath(S.fpath, name)), '_blank', 'noopener');
  },
  fpreview() {
    const name = one(), f = name && fileByName(name);
    if (!f) return;
    const path = joinPath(S.fpath, name);
    S.fpreview = { name, path };
    if (f.text) loadFilePreview(path, f);
    renderOverlay();
  },
  fpreviewClose() { S.fpreview = null; renderOverlay(); },
  fpreviewOpen() {
    const P = S.fpreview;
    if (!P) return;
    const f = fileByName(P.name);
    const url = f && f.access === 'public' && /^https:\/\/[a-z0-9.-]+\//i.test(f.url) ? f.url : rawUrl(S.fmount, P.path);
    window.open(url, '_blank', 'noopener');
  },
  fpick(id) { $('#' + id).click(); },
  fopenurl(url) { if (/^https:\/\/[a-z0-9.-]+\//i.test(url)) window.open(url, '_blank', 'noopener'); },
  fcopy(url) { copy(url, 'link'); },
  fvcopy(url) { copy(url, 'version link'); },
  fvdl(n) { const f = one(); if (f) download(rawUrl(S.fmount, joinPath(S.fpath, f), true, n)); },
  async fvrestore(n) {
    const f = one(); if (!f) return;
    const ok = await ask({ kicker: 'Restore version', title: 'Restore v' + n + ' of ' + f + '?', ok: 'Restore', text: 'The current file becomes a new version first, so nothing is lost.' });
    if (!ok) return;
    try { await post('/api/files/version/restore', { mount: S.fmount, path: joinPath(S.fpath, f), n: +n }); note('Restored v' + n); loadVersions(joinPath(S.fpath, f)); pollFiles(true); } catch (e) { note(e.message); }
  },
  async fvdel(n) {
    const f = one(); if (!f) return;
    const ok = await ask({ kicker: 'Delete version', title: 'Permanently delete v' + n + '?', danger: true, ok: 'Delete version', text: 'The current file is not affected.' });
    if (!ok) return;
    try { await post('/api/files/version/delete', { mount: S.fmount, path: joinPath(S.fpath, f), n: +n }); loadVersions(joinPath(S.fpath, f)); pollFiles(true); } catch (e) { note(e.message); }
  },
  async fhash() { const f = one(); if (!f) return; note('Hashing…'); try { await post('/api/files/hash', { mount: S.fmount, path: joinPath(S.fpath, f) }); loadInfo(joinPath(S.fpath, f)); } catch (e) { note(e.message); } },
  async fdownload() {
    const paths = selectedPaths();
    if (!paths.length) return;
    if (paths.length === 1 && fileByName([...S.fsel][0])) return download(rawUrl(S.fmount, paths[0], true));
    try { const z = await post('/api/files/zip', { mount: S.fmount, paths }); download('/api/files/zip/' + z.token); note('Preparing ' + z.name + ' …'); } catch (e) { note(e.message); }
  },
  async fmkdir() {
    const name = await ask({ kicker: 'New folder', title: 'Create a folder in ' + S.fpath, input: '', ok: 'Create' });
    if (!name) return;
    try { const p = joinPath(S.fpath, name.trim()); await post('/api/files/mkdir', { mount: S.fmount, path: p }); invalidateFolderTree(p); note('Folder created'); pollFiles(true); } catch (e) { note(e.message); }
  },
  async fnewfile() {
    const name = await ask({ kicker: 'New text file', title: 'Create a file in ' + S.fpath, input: 'untitled.txt', ok: 'Create & edit' });
    if (!name) return;
    const p = joinPath(S.fpath, name.trim());
    try { await post('/api/files/text', { mount: S.fmount, path: p, text: '', create: true }); pollFiles(true); openEditor(S.fmount, p); } catch (e) { note(e.message); }
  },
  async frename() {
    const old = one(); if (!old) return;
    const f = fileByName(old) || dirByName(old);
    const r = await ask({ kicker: 'Rename or move', title: old, input: old, ok: 'Rename',
      text: 'Type a new name, or a path starting with / to move it.',
      check: f && f.hits ? 'Leave a redirect from the old URL (' + f.hits + ' hits in 30 days)' : null, checkDefault: !!(f && f.hits) });
    const val = r && typeof r === 'object' ? r.value : r;
    if (!val || val === old) return;
    const to = val.startsWith('/') ? val : joinPath(S.fpath, val);
    try { const from = joinPath(S.fpath, old); await post('/api/files/rename', { mount: S.fmount, from, to, redirect: !!(r && r.checked) }); invalidateFolderTree(from); invalidateFolderTree(to); S.fsel = new Set(); note('Renamed to ' + to); pollFiles(true); } catch (e) { note(e.message); }
  },
  async fdelete() {
    const paths = selectedPaths(); if (!paths.length) return;
    const ok = await ask({ kicker: 'Move to trash', title: paths.length === 1 ? paths[0] : paths.length + ' items', danger: true, ok: 'Move to trash',
      text: 'They go to the trash with their versions, and can be restored from there.' });
    if (!ok) return;
    try { const r = await post('/api/files/delete', { mount: S.fmount, paths }); paths.forEach((p) => invalidateFolderTree(p)); S.fsel = new Set(); note('Moved ' + r.moved.length + ' item(s) to trash' + cdnNote(r.cdn)); pollFiles(true); } catch (e) { note(e.message); }
  },
  fclip(mode) { const paths = selectedPaths(); if (!paths.length) return; S.clip = { mode, mount: S.fmount, paths }; note(paths.length + ' item(s) ' + (mode === 'cut' ? 'cut' : 'copied') + '. Open the target folder and paste.'); render(true); },
  async fpaste() {
    const c = S.clip; if (!c) return;
    if (c.mount === S.fmount && c.paths.some((p) => S.fpath === p || S.fpath.startsWith(p + '/'))) return note('Can’t paste a folder into itself');
    if (c.mount === S.fmount && c.paths.every((p) => parentOf(p) === S.fpath)) return note('Items are already in this folder');
    try {
      const r = await post(c.mode === 'cut' ? '/api/files/move' : '/api/files/copy', { mount: c.mount, paths: c.paths, dest_mount: S.fmount, dest: S.fpath });
      c.paths.forEach((p) => invalidateFolderTree(p, c.mount)); invalidateFolderTree(S.fpath);
      if (c.mode === 'cut') S.clip = null;
      note(r.job ? 'Working in the background. Progress is under Jobs.' : 'Done'); pollFiles(true);
      if (r.job) setTimeout(() => pollFiles(true), 1500);
    } catch (e) { note(e.message); }
  },
  async fmoveto() {
    const paths = selectedPaths(); if (!paths.length) return;
    const dest = await pickFolder({ title: 'Move ' + paths.length + ' item(s) to…', mount: S.fmount, path: S.fpath, allowCopy: true });
    if (!dest) return;
    try { const r = await post(dest.copy ? '/api/files/copy' : '/api/files/move', { mount: S.fmount, paths, dest_mount: dest.mount, dest: dest.path }); paths.forEach((p) => invalidateFolderTree(p)); invalidateFolderTree(dest.path, dest.mount); S.fsel = new Set(); note(r.job ? 'Working in the background. Progress is under Jobs.' : 'Moved'); pollFiles(true); } catch (e) { note(e.message); }
  },
  async frestore(arg) {
    const i = arg.indexOf('|');
    try { const r = await post('/api/files/restore', { mount: S.fmount, batch: arg.slice(0, i), path: arg.slice(i + 1) }); invalidateFolderTree(r.path || arg.slice(i + 1)); note('Restored ' + r.path); pollFiles(true); } catch (e) { note(e.message); }
  },
  async femptytrash() {
    const ok = await ask({ kicker: 'Empty trash', title: 'Permanently delete everything in the trash of ' + mountName(S.fmount) + '?', danger: true, ok: 'Delete permanently', text: 'This can’t be undone, and their version history goes too.' });
    if (!ok) return;
    try { const r = await post('/api/files/empty-trash', { mount: S.fmount }); note('Trash emptied, ' + fmt.bytes(r.freed) + ' freed' + cdnNote(r.cdn)); pollFiles(true); } catch (e) { note(e.message); }
  },
  fedit() { const f = one(); if (f) openEditor(S.fmount, joinPath(S.fpath, f)); },
  fshare() { const f = one(); if (f && typeof openLinkEditor === 'function') openLinkEditor({ mount: S.fmount, path: joinPath(S.fpath, f) }); },
  fquickrule(action) {
    const f = one(); if (!f || typeof openRuleEditor !== 'function') return;
    const p = joinPath(S.fpath, f);
    openRuleEditor({ action, mount: S.fmount, patterns: [p], name: ({ hide: 'Hide ', deny: 'Forbid ', password: 'Password: ', signed: 'Signed only: ', download: 'Download: ' }[action] || '') + f, purge: true });
  },
  fsearchclear() { S.fq = ''; S.fOffset = 0; store.set('fOffset', 0); D.fsearch = null; render(true); },
});
const baseSort = ACT.sort;
ACT.sort = (arg, el, e) => {
  const [key, s] = arg.split(':');
  if (key !== 'files') return baseSort(arg, el, e);
  S.sortDir.files = S.sort.files === s ? -(S.sortDir.files || 1) : (s === 'name' ? 1 : -1);
  S.sort.files = s;
  S.fOffset = 0; store.set('fOffset', 0); persist(); D.files = null; render(true); pollFiles(true);
};
function download(url) { const a = document.createElement('a'); a.href = url; a.rel = 'noopener'; document.body.appendChild(a); a.click(); a.remove(); }

MENUS.fitem = (name) => {
  if (!S.fsel.has(name)) { S.fsel = new Set([name]); S.fanchor = name; render(true); }
  const d = dirByName(name), f = fileByName(name), path = joinPath(S.fpath, name), multi = S.fsel.size > 1;
  const canShare = fcan('files.share', path);

  const items = d ? [
    item('Open folder', '↵', () => ACT.fgo(path)),
    canShare ? item('Share folder…', '', () => ACT.fshare()) : null,
    fcan('files.analyze', '/') && fullDriveZone() ? item('Analyze this folder', '', () => { S.anMount = S.fmount; S.anPath = path; go('analyze'); }) : null
  ].filter(Boolean) : [
    item('Preview / open', '↵', () => ACT.fopen(name)),
    item('Open public URL', '↗', () => ACT.fopenurl(f.url)),
    item('Copy public link', '', () => copy(f.url, 'link')),
    canShare ? item('Share…', '', () => ACT.fshare()) : null,
    (f.text && fcan('files.edit', path)) ? item('Edit text', '', () => openEditor(S.fmount, path)) : null,
    hasCap('analytics.visitors') ? item('Show requests for this file', '', () => ACT.filterPath(encodeURI(path))) : null
  ].filter(Boolean);

  const extra = [];
  if (fcan('files.download', path)) extra.push(item('Download' + (multi || d ? ' as ZIP' : ''), '', () => ACT.fdownload(), { sep: true }));
  if (fcan('files.move', path)) extra.push(item('Cut', 'Ctrl X', () => ACT.fclip('cut')));
  extra.push(item('Copy', 'Ctrl C', () => ACT.fclip('copy')));
  if (fcan('files.move', path) || fcan('files.copy', path)) extra.push(item('Move / copy to…', '', () => ACT.fmoveto()));
  if (fcan('files.rename', path)) extra.push(item('Rename…', 'F2', () => ACT.frename()));
  if (fcan('files.delete', path)) extra.push(item(multi ? `Move ${S.fsel.size} items to trash` : 'Move to trash', 'Del', () => ACT.fdelete(), { sep: true, danger: true }));

  return { kicker: d ? 'Folder' : 'File · ' + (f ? fmt.bytes(f.size) : ''), title: multi ? S.fsel.size + ' selected' : name, items: items.concat(extra) };
};
MENUS.fpath = (path) => ({ kicker: 'Search result', title: path, items: [item('Reveal in folder', '', () => ACT.freveal(path)), item('Open', '', () => window.open(rawUrl(S.fmount, path), '_blank', 'noopener'))] });

function fileKeys(e) {
  if (S.view !== 'files' || S.ftab !== 'files' || S.editor || S.picker) return false;
  const k = e.key.toLowerCase(), ctrl = e.ctrlKey || e.metaKey;
  if (e.key === 'Delete' && S.fsel.size) { e.preventDefault(); ACT.fdelete(); return true; }
  if (e.key === 'F2' && S.fsel.size === 1) { e.preventDefault(); ACT.frename(); return true; }
  if (e.key === 'Backspace') { e.preventDefault(); ACT.fup(); return true; }
  if (e.key === 'Enter' && S.fsel.size === 1) { e.preventDefault(); ACT.fopen([...S.fsel][0]); return true; }
  if (e.key === ' ' && S.fsel.size === 1) { e.preventDefault(); ACT.fpreview(); return true; }
  if (ctrl && k === 'a') { e.preventDefault(); S.fsel = new Set(sortedEntries().dirs.map((d) => d.name).concat(sortedEntries().files.map((f) => f.name))); render(true); return true; }
  if (ctrl && k === 'c' && S.fsel.size) { e.preventDefault(); ACT.fclip('copy'); return true; }
  if (ctrl && k === 'x' && S.fsel.size) { e.preventDefault(); ACT.fclip('cut'); return true; }
  if (ctrl && k === 'v' && S.clip) {
    const pending = {};
    S.clipPastePending = pending;
    setTimeout(() => { if (S.clipPastePending === pending) { S.clipPastePending = null; ACT.fpaste(); } }, 0);
    return false; // let the paste event give OS files/images priority over Strata's clipboard
  }
  return false;
}

/* internal drag & drop: rows onto folders = move (Ctrl = copy) */
const STRATA_DND = 'application/x-strata-items';
document.addEventListener('dragstart', (e) => {
  const r = e.target.closest && e.target.closest('[data-drag]');
  if (!r || S.view !== 'files') return;
  const name = r.dataset.drag;
  if (!S.fsel.has(name)) S.fsel = new Set([name]);
  e.dataTransfer.setData(STRATA_DND, JSON.stringify({ mount: S.fmount, paths: selectedPaths() }));
  e.dataTransfer.effectAllowed = 'copyMove';
});
document.addEventListener('dragover', (e) => {
  if (!e.dataTransfer || ![...e.dataTransfer.types].includes(STRATA_DND)) return;
  const t = e.target.closest('[data-dropdir]');
  document.querySelectorAll('.dropping').forEach((x) => x !== t && x.classList.remove('dropping'));
  if (!t) return;
  e.preventDefault();
  e.dataTransfer.dropEffect = e.ctrlKey ? 'copy' : 'move';
  t.classList.add('dropping');
});
document.addEventListener('drop', async (e) => {
  if (!e.dataTransfer || ![...e.dataTransfer.types].includes(STRATA_DND)) return;
  const t = e.target.closest('[data-dropdir]');
  document.querySelectorAll('.dropping').forEach((x) => x.classList.remove('dropping'));
  if (!t) return;
  e.preventDefault();
  const d = JSON.parse(e.dataTransfer.getData(STRATA_DND) || '{}');
  const dest = t.dataset.dropdir;
  if (!d.paths || d.paths.some((p) => dest === p || dest.startsWith(p + '/'))) return note('Can’t move a folder into itself');
  if (d.paths.every((p) => parentOf(p) === dest)) return;
  try { const r = await post(e.ctrlKey ? '/api/files/copy' : '/api/files/move', { mount: d.mount, paths: d.paths, dest_mount: S.fmount, dest }); d.paths.forEach((p) => invalidateFolderTree(p, d.mount)); invalidateFolderTree(dest); S.fsel = new Set(); note((e.ctrlKey ? 'Copied ' : 'Moved ') + d.paths.length + ' item(s) to ' + dest + (r.job ? ' (in the background)' : '')); pollFiles(true); } catch (err) { note(err.message); }
});

/* ---- link preview: what Discord, Slack, Telegram... show for a shared link, and this file's or folder's own
   settings (a "preview" rule naming exactly this path; wider rules live in Serving › Access rules) */
const LP_KINDS = [['', 'Automatic'], ['text', 'Code and text'], ['archive', 'Archive'], ['pdf', 'PDF'], ['audio', 'Audio'],
  ['warning', 'Caution'], ['file', 'Other file']];
const lpKey = (path) => S.fmount + '|' + path;
async function loadLinkPreview(path) {
  const k = lpKey(path);
  D.lp = { key: k, path, loading: true };
  try {
    const meta = await get('/api/files/preview?' + new URLSearchParams({ mount: S.fmount, path, meta: 1 }));
    if (D.lp?.key !== k) return;
    D.lp = { key: k, path, meta, draft: Object.assign({}, meta.rule?.params || {}), nonce: Date.now(), dirty: false };
  } catch (e) { if (D.lp?.key === k) D.lp = { key: k, path, error: e.message }; }
  render(true);
}
function lpImageUrl(L) {
  const p = { mount: S.fmount, path: L.path, n: L.nonce };
  if (L.dirty) {  // unsaved: the draft stands in for this path's own rule
    p.draft = JSON.stringify(L.draft);
    if (L.meta.rule) p.skip = L.meta.rule.id;
  }
  return '/api/files/preview?' + new URLSearchParams(p);
}
function linkPreviewPanel(path, isDir) {
  const L = D.lp && D.lp.key === lpKey(path) ? D.lp : null;
  if (!L) { loadLinkPreview(path); return loading('Loading link preview…'); }
  if (L.loading) return loading('Loading link preview…');
  if (L.error) return `<div class="empty hot">${esc(L.error)}</div>`;
  const M = L.meta, dr = L.draft;
  if (M.native) return '<div class="small dim lp-note">Discord, Slack and the others show pictures, videos and web pages themselves, so Strata adds no card.</div>';
  if (M.folder_without_gallery) return '<div class="small dim lp-note">Folders get a link preview only inside a Gallery rule. Everywhere else the folder URL is a 404.</div>';
  const off = dr.off === true || (dr.off == null && M.settings.off === true && !M.rule);
  const title = dr.title || M.title, desc = dr.description || M.description;
  const mock = off ? '<div class="lp-off">No preview: the link shows as plain text.</div>'
    : `<div class="lp-mock" style="--lp:${esc(/^#[0-9a-f]{6}$/i.test(dr.color || '') ? dr.color : M.color || '#5865f2')}">
      <div class="lp-site">${esc(M.host)}</div><div class="lp-title">${esc(title)}</div>${desc ? `<div class="lp-desc">${esc(desc)}</div>` : ''}
      ${dr.image ? `<div class="lp-imgnote small">Image: ${esc(dr.image)}</div>` : `<img class="lp-img" alt="Preview card" src="${esc(lpImageUrl(L))}">`}</div>`;
  if (!meCan('serving.rules')) return mock;
  return `${mock}
    <div class="form lp-form">
      <label class="dlg-check wide"><input type="checkbox" id="lp_on" ${off ? '' : 'checked'}> Show a link preview</label>
      <label class="wide">Title<input id="lp_title" class="input" value="${esc(dr.title || '')}" placeholder="${esc(M.title || '')}"></label>
      <label class="wide">Description<textarea id="lp_desc" class="input" rows="2" placeholder="${esc(M.description || '')}">${esc(dr.description || '')}</textarea></label>
      <label>Colour<input id="lp_color" class="input" value="${esc(dr.color || '')}" placeholder="${esc(M.color || '#5865f2')}"></label>
      ${isDir ? '' : `<label>Card type<select id="lp_kind" class="input">${LP_KINDS.map(([v, l]) => `<option value="${v}" ${(dr.kind || '') === v ? 'selected' : ''}>${l}</option>`).join('')}</select></label>`}
      <label class="wide">Image instead of the card<input id="lp_image" class="input" value="${esc(dr.image || '')}" placeholder="https://… or /path/on/this/site.png"></label>
    </div>
    <div class="act-row lp-acts"><button class="btn btn-secondary" data-act="lpUpdate">Update preview</button><button class="btn btn-primary" data-act="lpSave" data-arg="${isDir ? 1 : 0}">Save</button>${M.rule ? '<button class="btn btn-secondary" data-act="lpReset">Back to automatic</button>' : ''}</div>
    <div class="small dim lp-note">Saved as a Link preview rule for this ${isDir ? 'folder' : 'file'}. Title, description and image apply here only; rules under Serving › Access rules can set colour, card type or switch previews off for whole folders and drives.</div>`;
}
Object.assign(ACT, {
  lpUpdate() { if (!D.lp?.draft) return; D.lp.dirty = true; D.lp.nonce = Date.now(); render(true); },
  async lpSave(isDir) {
    const L = D.lp; if (!L?.meta) return;
    const dr = L.draft, params = {};
    for (const k of ['title', 'description', 'color', 'image', 'kind']) if ((dr[k] || '').trim()) params[k] = dr[k].trim();
    if (dr.off === true) params.off = true;
    else if (L.meta.settings.off === true && !L.meta.rule) params.off = false;  // switch it back on under a folder that has it off
    const name = L.path.split('/').filter(Boolean).pop() || L.path;
    try {
      if (!Object.keys(params).length) { if (L.meta.rule) await post('/api/serving/rule/delete', { id: L.meta.rule.id }); }
      else await post('/api/serving/rule', { id: L.meta.rule?.id, name: 'Link preview: ' + name, mount: S.fmount, action: 'preview',
        patterns: [+isDir ? L.meta.url_path.replace(/\/$/, '') : L.meta.url_path], params });
      note('Link preview saved. Discord and the others refresh their copy within a few hours.');
      loadLinkPreview(L.path);
    } catch (e) { note(e.message); }
  },
  async lpReset() {
    const L = D.lp; if (!L?.meta?.rule) return;
    try { await post('/api/serving/rule/delete', { id: L.meta.rule.id }); note('Back to the automatic link preview'); loadLinkPreview(L.path); } catch (e) { note(e.message); }
  },
});
document.addEventListener('change', (e) => {
  if (!D.lp?.draft) return;
  if (e.target.id === 'lp_on') { D.lp.draft.off = e.target.checked ? undefined : true; render(true); }
  if (e.target.id === 'lp_kind') { D.lp.draft.kind = e.target.value; D.lp.dirty = true; D.lp.nonce = Date.now(); render(true); }
});
let searchT;
document.addEventListener('input', (e) => {
  if (e.target.id === 'fsearch') {
    S.fq = e.target.value.trim(); S.fOffset = 0; store.set('fOffset', 0); S.fsel = new Set();
    clearTimeout(searchT);
    if (S.fq.length < 2) { D.fsearch = null; render(true); return; }
    searchT = setTimeout(async () => {
      try { D.fsearch = await get(`/api/files/search?mount=${S.fmount}&q=${enc(S.fq)}&within=${enc(S.fpath)}`); render(true); } catch (err) { note(err.message); }
    }, 280);
  } else if (e.target.id === 'updest') {
    S.upPath = '/' + e.target.value.replace(/^\/+/, ''); save();
  } else if (/^lp_(title|desc|color|image)$/.test(e.target.id) && D.lp?.draft) {
    D.lp.draft[{ lp_title: 'title', lp_desc: 'description', lp_color: 'color', lp_image: 'image' }[e.target.id]] = e.target.value;
  } else if (e.target.id === 'edtext' && S.editor) {
    S.editor.text = e.target.value;
    const d = $('#eddirty'); if (d) d.textContent = S.editor.text !== S.editor.orig ? '● unsaved' : 'saved';
  }
});
document.addEventListener('keydown', (e) => {
  if (e.target && e.target.id === 'pickSearch' && e.key === 'Enter') {
    e.preventDefault(); ACT.pickApplySearch();
  }
});

/* ---- folder picker (move to / upload destination) */

function pickFolder(o) {
  return new Promise((resolve) => {
    S.picker = { title: o.title, mount: o.mount, path: o.path || '/', dirs: null, total: 0, offset: 0, limit: 200,
      q: '', loadId: 0, resolve, allowCopy: o.allowCopy, copy: false };
    renderOverlay(); pickerLoad();
  });
}
async function pickerLoad() {
  const P = S.picker; if (!P) return;
  const loadId = ++P.loadId;
  P.dirs = null; P.error = ''; renderOverlay();
  try {
    const r = await get(`/api/files?mount=${P.mount}&path=${enc(P.path)}&cat=folder&q=${enc(P.q)}&sort=name&offset=${P.offset}&limit=${P.limit}`);
    if (S.picker === P && loadId === P.loadId) { P.dirs = r.dirs.map((d) => d.name); P.total = r.total || 0; P.offset = r.offset || 0; renderOverlay(); }
  } catch (e) { if (S.picker === P && loadId === P.loadId) { P.error = e.message; P.dirs = []; renderOverlay(); } }
}
OVERLAYS.push(() => {
  const P = S.picker; if (!P) return '';
  const parts = P.path.split('/').filter(Boolean);
  const last = Math.min(P.total, P.offset + P.limit);
  return `<div class="palbg" data-act="pickCancel"><div class="dlg picker" data-act="noop">
    <div class="body"><div class="cap">Choose a folder</div><h4>${esc(P.title)}</h4>
      <div class="tbar px-0 py-6 border-0">${served().map((m) => `<button class="pill ${m.mount === +P.mount ? 'on' : ''}" data-act="pickMount" data-arg="${m.mount}">${esc(m.name)}</button>`).join('')}</div>
      <div class="crumbs mx-0 my-6"><button data-act="pickGo" data-arg="/">${esc(mountName(P.mount))}</button>${parts.map((p, i) => `<span class="dim">/</span><button data-act="pickGo" data-arg="${esc('/' + parts.slice(0, i + 1).join('/'))}">${esc(p)}</button>`).join('')}</div>
      <div class="picker-search"><input id="pickSearch" class="input" value="${esc(P.q)}" placeholder="Find a folder here…" aria-label="Find a folder"><button class="pill on" data-act="pickApplySearch">Search</button>${P.q ? '<button class="pill" data-act="pickClearSearch">Clear</button>' : ''}</div>
      <div class="plist">${P.dirs == null ? '<div class="empty">Loading…</div>' : P.error ? `<div class="empty hot">${esc(P.error)}</div>` : P.dirs.map((d) => `<button data-act="pickGo" data-arg="${esc(joinPath(P.path, d))}"><span class="fico dir"></span>${esc(d)}</button>`).join('') || '<div class="empty">No matching folders here.</div>'}</div>
      <div class="picker-pages"><span class="small dim">${P.dirs == null || P.error ? '' : `${fmt.n(P.total ? P.offset + 1 : 0)}–${fmt.n(last)} of ${fmt.n(P.total)} folders`}</span><div class="grow"></div><button class="pill" data-act="pickPage" data-arg="-1" ${P.offset <= 0 ? 'disabled' : ''}>Previous</button><button class="pill" data-act="pickPage" data-arg="1" ${P.offset + P.limit >= P.total ? 'disabled' : ''}>Next</button></div>
      ${P.allowCopy ? `<label class="dlg-check"><input type="checkbox" id="pickcopy" ${P.copy ? 'checked' : ''}> Copy instead of move</label>` : ''}
    </div>
    <div class="acts"><button class="btn btn-primary" data-act="pickOk">Choose ${esc(mountName(P.mount))}:${esc(P.path)}</button><button class="btn btn-secondary" data-act="pickNew">New folder here</button>
      <div class="grow"></div><button class="btn btn-secondary" data-act="pickCancel">Cancel</button></div></div></div>`;
});
Object.assign(ACT, {
  pickMount(id) { S.picker.mount = +id; S.picker.path = '/'; S.picker.offset = 0; S.picker.q = ''; pickerLoad(); },
  pickGo(p) { S.picker.path = p; S.picker.offset = 0; S.picker.q = ''; pickerLoad(); },
  pickApplySearch() { const P = S.picker; if (!P) return; P.q = ($('#pickSearch')?.value || '').trim(); P.offset = 0; pickerLoad(); },
  pickClearSearch() { const P = S.picker; if (!P) return; P.q = ''; P.offset = 0; pickerLoad(); },
  pickPage(delta) {
    const P = S.picker; if (!P) return;
    const max = Math.max(0, Math.floor(Math.max(0, P.total - 1) / P.limit) * P.limit);
    P.offset = Math.max(0, Math.min(max, P.offset + Math.sign(+delta) * P.limit)); pickerLoad();
  },
  async pickNew() {
    const P = S.picker;
    const name = prompt('New folder name'); // simple native prompt keeps the picker open underneath
    if (!name) return;
    try { const path = joinPath(P.path, name.trim()); await post('/api/files/mkdir', { mount: P.mount, path }); invalidateFolderTree(path, P.mount); P.path = path; pickerLoad(); } catch (e) { note(e.message); }
  },
  pickOk() { const P = S.picker; S.picker = null; renderOverlay(); P.resolve({ mount: P.mount, path: P.path, copy: !!($('#pickcopy') && $('#pickcopy').checked) }); },
  pickCancel(_, el, e) { if (e && el && el.classList.contains('palbg') && e.target !== el) return; const P = S.picker; S.picker = null; renderOverlay(); if (P) P.resolve(null); },
});

/* ---- text editor (own DOM node so typing never gets re-rendered away) */

async function openEditor(mount, path) {
  try {
    const t = await get(`/api/files/text?mount=${mount}&path=${enc(path)}`);
    S.editor = { mount, path, text: t.text, orig: t.text, mtime: t.mtime, enc: t.encoding };
    let el = $('#editor');
    if (!el) { el = document.createElement('div'); el.id = 'editor'; document.body.appendChild(el); }
    el.innerHTML = `<div class="editor"><div class="edhead"><div style="min-width:0"><div class="cap red">${esc(mountName(mount))}</div><div class="h800 ell">${esc(path)}</div></div>
        <div class="grow"></div><span class="small dim" id="eddirty">saved</span>
        <button class="btn btn-primary" data-act="edSave">Save (Ctrl S)</button><button class="btn btn-secondary" data-act="edClose">Close</button></div>
      <textarea id="edtext" spellcheck="false" wrap="off"></textarea>
      <div class="edfoot small dim">${esc(t.encoding)} · ${esc(fmt.bytes(t.size))} · each save keeps the previous version</div></div>`;
    $('#edtext').value = t.text;
    $('#edtext').focus();
  } catch (e) { note(e.message); }
}
Object.assign(ACT, {
  async edSave() {
    const E = S.editor; if (!E) return;
    try {
      const r = await post('/api/files/text', { mount: E.mount, path: E.path, text: E.text, expect_mtime: E.mtime });
      E.orig = E.text; E.mtime = r.mtime;
      const d = $('#eddirty'); if (d) d.textContent = 'saved ' + fmt.time(Date.now() / 1000);
      note('Saved'); if (S.view === 'files') pollFiles(true);
    } catch (e) { note(e.message); }
  },
  async edClose() {
    const E = S.editor; if (!E) return;
    if (E.text !== E.orig && !confirm('Discard unsaved changes?')) return;
    S.editor = null; const el = $('#editor'); if (el) el.remove();
  },
});
document.addEventListener('keydown', (e) => {
  if (!S.editor) return;
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') { e.preventDefault(); ACT.edSave(); }
  if (e.key === 'Escape') { e.preventDefault(); e.stopImmediatePropagation(); ACT.edClose(); }
  if (e.key === 'Tab' && e.target.id === 'edtext') {
    e.preventDefault();
    const t = e.target, s = t.selectionStart;
    t.setRangeText('\t', s, t.selectionEnd, 'end');
    S.editor.text = t.value;
  }
}, true);

/* ================================================================== Smart-Sorting */
/* Where uploads land by type, and rewriting a website's references when its files move apart.
   'home'    — a drive root (or the home itself / one of its type folders): <home>/<type>/…  (D.me.smartsort.home)
   'project' — any other folder while the Files toggle is on: html stays, <dir>/css, <dir>/js, <dir>/<assets>/<type>/
   Dropped folders are asked about: split by type (references rewritten to the files' new public CDN URLs) or kept. */

const SORT_EXT = {
  gif: 'gif',
  image: 'jpg jpeg jfif pjpeg png apng webp avif bmp ico cur tif tiff heic heif svg psd tga jxl',
  video: 'mp4 m4v webm mkv mov avi wmv flv ts m2ts mts m3u8 ogv 3gp',
  audio: 'mp3 flac wav ogg oga opus m4a aac wma mid midi alac amr wv ape',
  archive: 'zip 7z rar tar gz tgz bz2 xz zst lz4 mrpack jar apk iso',
  html: 'html htm xhtml shtml',
  css: 'css scss sass less',
  js: 'js mjs cjs jsx ts tsx map wasm',
  data: 'json jsonc xml webmanifest yml yaml toml csv tsv',
  font: 'woff woff2 ttf otf eot',
  document: 'pdf doc docx xls xlsx ppt pptx odt ods odp epub rtf',
  '3d': 'blend blend1 fbx obj mtl glb gltf stl ply 3ds dae usd usdz',
  text: 'txt md log srt vtt ass ini cfg conf',
};
const EXT_CAT = {};
Object.entries(SORT_EXT).forEach(([cat, exts]) => exts.split(' ').forEach((x) => { EXT_CAT[x] = cat; }));
const REWRITE_EXT = new Set(['html', 'htm', 'xhtml', 'shtml', 'css', 'js', 'mjs', 'cjs', 'json', 'webmanifest', 'svg', 'xml']);
const MARKUP_EXT = new Set(['html', 'htm', 'xhtml', 'shtml', 'svg', 'xml']);
// folder names that only say "what kind of file" - dropped when a site is split, since the type folder replaces them
const TYPE_DIRS = new Set(['assets', 'asset', 'static', 'img', 'imgs', 'image', 'images', 'pics', 'css', 'style', 'styles',
  'stylesheets', 'js', 'script', 'scripts', 'font', 'fonts', 'media', 'video', 'videos', 'audio', 'sound', 'sounds',
  'gif', 'gifs', 'data', 'json', 'res', 'resources']);
S.smartSort = store.get('smartSort', true);
const extOf = (name) => (name.includes('.') ? name.split('.').pop().toLowerCase() : '');
const sortCat = (name) => EXT_CAT[extOf(name)] || 'other';
const smartCfg = () => (D.me && D.me.smartsort) || { folders: {}, assets: 'assets', root_to_home: true, home: null };
const typeFolder = (cat) => (smartCfg().folders || {})[cat] || cat;

function smartMode(mount, dir) {
  const ss = smartCfg(), h = ss.home;
  if (h && +h.mount === +mount) {
    const typeDirs = Object.keys(SORT_EXT).concat('other').map((c) => joinPath(h.path, typeFolder(c)));
    if ((dir === '/' && ss.root_to_home) || (S.smartSort && (dir === h.path || typeDirs.includes(dir)))) return { mode: 'home', base: h.path };
  }
  return S.smartSort && dir !== '/' ? { mode: 'project', base: dir } : { mode: 'plain', base: dir };
}
function typeDir(mode, cat) {
  if (mode === 'home') return typeFolder(cat);
  if (cat === 'html') return '';
  if (cat === 'css' || cat === 'js' || cat === 'data') return typeFolder(cat);
  return (smartCfg().assets || 'assets') + '/' + typeFolder(cat);
}
function uniqueDest(dest, used) {
  let d = dest, i = 0;
  const dot = dest.lastIndexOf('.') > dest.lastIndexOf('/') ? dest.lastIndexOf('.') : dest.length;
  while (used.has(d.toLowerCase())) d = dest.slice(0, dot) + ` (${++i})` + dest.slice(dot);
  used.add(d.toLowerCase());
  return d;
}
// [{file, rel}] -> [{file, rel, dest, cat}]. split=false keeps dropped folders as they are (below base).
function sortPlan(list, mode, base, split) {
  const used = new Set();
  return list.map((it) => {
    const segs = it.rel.split('/').filter(Boolean), name = segs.pop(), cat = sortCat(name);
    let dest;
    if (segs.length && !split) dest = joinPath(base, segs.concat(name).join('/'));
    else {
      const group = segs.length && mode === 'home' ? [segs[0]] : []; // home: <type>/<site>/…, project: the site is the folder
      const inner = segs.slice(1).filter((s) => !TYPE_DIRS.has(s.toLowerCase()));
      dest = '/' + [base.replace(/^\/+|\/+$/g, ''), typeDir(mode, cat), ...group, ...inner, name].filter(Boolean).join('/');
    }
    return Object.assign({}, it, { dest: uniqueDest(dest, used), cat });
  });
}

function posixResolve(dir, ref) {
  const out = [];
  for (const s of (dir ? dir + '/' : '').concat(ref).split('/')) {
    if (!s || s === '.') continue;
    if (s === '..') out.pop(); else out.push(s);
  }
  return out.join('/');
}
const encPath = (p) => p.split('/').map((s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase())).join('/');
// Replace every reference in the batch's HTML/CSS/JS/JSON/SVG that points at another file of the batch with that
// file's public CDN URL - so the pieces keep finding each other after being sorted into different folders.
async function rewriteBatch(items, mount) {
  const base = ((served().find((m) => m.mount === +mount) || {}).base_url || '').replace(/\/+$/, '');
  if (!base) return { files: 0, refs: 0 };
  const byRel = new Map(), byLower = new Map();
  for (const it of items) {
    const k = it.rel.split('/').filter(Boolean).join('/'), url = base + encPath(it.dest);
    byRel.set(k, url); byLower.set(k.toLowerCase(), url);
  }
  let files = 0, refs = 0;
  for (const it of items) {
    const ext = extOf(it.file.name);
    if (!REWRITE_EXT.has(ext) || it.file.size > 4 * MiB) continue;
    const segs = it.rel.split('/').filter(Boolean); segs.pop();
    const dir = segs.join('/'), root = segs[0] || '';
    let n = 0;
    const map = (raw) => {
      const ref = raw.trim(), m = /^([^?#]*)([?#].*)?$/.exec(ref);
      if (!m || !m[1] || /^(?:[a-z][a-z0-9+.-]*:|\/\/|#)/i.test(ref) || ref.length > 400) return null;
      let p = m[1];
      try { p = decodeURIComponent(p); } catch { /* keep the raw form */ }
      // relative to the referring file, then (JS fetches, root-absolute /paths) relative to the dropped folder
      const tries = p.startsWith('/') ? [posixResolve(root, p.slice(1))] : [posixResolve(dir, p), posixResolve(root, p)];
      for (const k of tries) {
        const hit = byRel.get(k) || byLower.get(k.toLowerCase());
        if (hit) { n++; return hit + (m[2] || ''); }
      }
      return null;
    };
    const orig = await it.file.text();
    let text = orig;
    const inner = (whole, pre, ref, post) => { const r = map(ref); return r ? pre + r + post : whole; };
    const css = (t) => t.replace(/(url\(\s*['"]?)([^'")\s]+)(['"]?\s*\))/gi, inner).replace(/(@import\s+['"])([^'"]+)(['"])/gi, inner);
    if (MARKUP_EXT.has(ext)) {
      text = text.replace(/(\s(?:src|href|poster|data-src|data-href|action|data|xlink:href|content)\s*=\s*)(["'])([^"']*)\2/gi,
        (whole, pre, q, v) => { const r = map(v); return r ? pre + q + r + q : whole; });
      text = text.replace(/(\s(?:srcset|data-srcset)\s*=\s*)(["'])([^"']*)\2/gi, (whole, pre, q, v) =>
        pre + q + v.split(',').map((c) => { const m = /^(\s*)(\S+)(.*)$/.exec(c); const r = m && map(m[2]); return r ? m[1] + r + m[3] : c; }).join(',') + q);
      text = css(text);
    } else if (ext === 'css') text = css(text);
    // quoted strings: inline scripts, JS modules / fetches, JSON and web manifests (only strings naming a batch file)
    if (ext !== 'css') text = text.replace(/(["'`])([^"'`\s<>{}()]{1,400}?)(\1)/g, inner);
    if (text !== orig) {
      it.file = new File([text], it.file.name, { type: it.file.type || 'text/plain', lastModified: it.file.lastModified });
      files++; refs += n;
    }
  }
  return { files, refs };
}
function planSummary(items) {
  const dirs = [...new Set(items.map((it) => parentOf(it.dest)))];
  return dirs.slice(0, 4).join(', ') + (dirs.length > 4 ? ` +${dirs.length - 4} more` : '');
}

/* ================================================================== uploader */

let inflight = 0;
function onDropFiles(list, dir) {
  if (!list.length) return;
  if (S.resumeFor) {
    const s = S.resumeFor; S.resumeFor = null;
    const f = list.length === 1 ? list[0].file : null;
    if (f && f.size === s.size && f.name === s.path.split('/').pop())
      return queueUploads([{ file: f, rel: s.path.split('/').pop() }], s.mount, parentOf(s.path), s.policy === 'ask' ? 'replace' : s.policy);
    note('That file doesn’t match the interrupted upload, so it uploads as a new file.');
  }
  let mount, base;
  if (S.view === 'files' && S.ftab === 'files') { mount = S.fmount; base = dir || S.fpath; }
  else { mount = S.upMount; base = dir || S.upPath; }
  smartQueue(list, mount, base).catch((e) => note('Smart-Sorting failed: ' + e.message));
}
async function smartQueue(list, mount, dir) {
  if (!D.me) await loadMe();
  const sm = smartMode(mount, dir);
  if (sm.mode === 'plain') return queueUploads(list, mount, dir, S.upPolicy);
  const folders = [...new Set(list.filter((x) => x.rel.includes('/')).map((x) => x.rel.split('/')[0]))];
  let split = true;
  if (folders.length) {
    const site = list.some((x) => x.rel.includes('/') && sortCat(x.rel) === 'html');
    const preview = sortPlan(list, sm.mode, sm.base, true);
    const r = await ask({ kicker: 'Smart-Sorting', title: `Split ${folders.length === 1 ? folders[0] : folders.length + ' folders'} into type folders?`,
      text: `${site ? 'This looks like a website. ' : ''}Split puts the files into ${planSummary(preview)} and rewrites the links between them. ` +
        `Keep uploads them unchanged to ${mountName(mount)}:${joinPath(sm.base, folders[0])}${folders.length > 1 ? ' (and the others beside it)' : ''}.`,
      ok: 'Split & rewrite', alt: 'Keep structure' });
    if (!r) return;
    split = r !== 'alt';
  }
  const items = sortPlan(list, sm.mode, sm.base, split);
  const rw = split && items.length > 1 ? await rewriteBatch(items, mount) : { files: 0, refs: 0 };
  queueItems(items, mount, S.upPolicy, `Smart-Sorting: ${items.length} file(s) → ${mountName(mount)}:${planSummary(items)}` +
    (rw.refs ? ` · rewrote ${rw.refs} link(s) in ${rw.files} file(s)` : ''));
}
function dropLabel() {
  const [mount, dir] = S.view === 'files' && S.ftab === 'files' ? [S.fmount, S.fpath] : [S.upMount, S.upPath];
  const sm = smartMode(mount, dir);
  return mountName(mount) + ':' + (sm.mode === 'home' ? sm.base + ' (sorted by type)' : dir + (sm.mode === 'project' ? ' (Smart-Sorting)' : ''));
}
function queueUploads(list, mount, dir, policy) {
  queueItems(list.map((x) => ({ file: x.file, dest: joinPath(dir, x.rel) })), mount, policy, `Queued ${list.length} file(s) for ${mountName(mount)}:${dir}`);
}
function queueItems(items, mount, policy, msg) {
  if (!D.me) loadMe();
  for (const { file, dest } of items) {
    U.push({ id: ++uploadSeq, file, mount: +mount, dest, size: file.size, sent: 0, status: 'queued', policy: policy || 'ask',
      err: '', tries: {}, pending: [], xhrs: {}, prog: {}, sess: null, t0: 0, done: 0 });
  }
  note(msg);
  if (S.view !== 'files' && S.view !== 'upload') go('upload');
  upPump();
}
function upPump() {
  const P = UPCFG.parallel;
  for (const u of U) {
    if (inflight >= P) break;
    if (u.status !== 'uploading' || u.paused || !u.sess) continue;
    while (inflight < P && u.pending.length) sendChunk(u, u.pending.shift());
  }
  for (const u of U) {
    if (inflight >= P) break;
    if (u.status === 'queued') startUpload(u);
  }
  liveSoon();
}
const TRANSIENT = new Set([0, 408, 422, 425, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524]);
function backoff(n) { return Math.min(30000, 1000 * 2 ** n); }
async function startUpload(u) {
  u.status = 'uploading'; u.t0 = u.t0 || Date.now(); u.err = '';
  if (u.size <= UPCFG.chunk) return singlePut(u);
  inflight++;
  try {
    const s = await post('/api/upload/init', { mount: u.mount, path: u.dest, size: u.size, mtime: u.file.lastModified, name: u.file.name, policy: u.policy, chunk_mb: UPCFG.chunk / MiB });
    inflight--;
    if (s.skipped) { u.status = 'skipped'; upPump(); return; }
    u.sess = s; u.dest = s.path; u.chunk = s.chunk;
    const got = new Set(s.received);
    u.pending = [];
    for (let i = 0; i < s.chunks; i++) if (!got.has(i)) u.pending.push(i);
    u.done = got.size;
    u.sent = [...got].reduce((a, i) => a + Math.min(s.chunk, u.size - i * s.chunk), 0);
    if (s.resumed && got.size) note(`Resuming ${u.file.name} at ${fmt.pct(share(u.sent, u.size))}`);
    if (!u.pending.length) finishUpload(u);
  } catch (e) {
    inflight--;
    if (e.message === 'exists') u.status = 'exists';
    else if (/login/.test(e.message)) return;
    else { u.status = 'error'; u.err = e.message; }
  }
  upPump();
}
function xhrPut(url, body, onprog, done) {
  const x = new XMLHttpRequest();
  x.open('PUT', url);
  x.setRequestHeader('X-Strata', '1');
  x.setRequestHeader('Content-Type', 'application/octet-stream');
  x.upload.onprogress = (e) => onprog(e.loaded);
  x.onload = () => { let j = {}; try { j = JSON.parse(x.responseText || '{}'); } catch { /* not json */ } done(x.status, j); };
  x.onerror = () => done(0, { error: 'network error' });
  x.onabort = () => done(-1, { error: 'aborted' });
  x.send(body);
  return x;
}
function sendChunk(u, i) {
  inflight++;
  const start = i * u.chunk, end = Math.min(u.size, start + u.chunk);
  u.xhrs[i] = xhrPut(`/api/upload/${u.sess.id}/${i}`, u.file.slice(start, end), (n) => { u.prog[i] = n; liveSoon(); }, (st, j) => {
    inflight--; delete u.xhrs[i]; delete u.prog[i];
    if (st === 200) { u.done++; u.sent += end - start; if (u.done === u.sess.chunks) finishUpload(u); }
    else if (st === 401) { location.href = '/login'; return; }
    else if (st === -1) { if (u.status === 'uploading' || u.paused) u.pending.unshift(i); }
    else if (st === 404) { u.sess = null; u.status = 'queued'; u.sent = 0; u.done = 0; Object.values(u.xhrs).forEach((x) => x.abort()); }
    else if (TRANSIENT.has(st) && (u.tries[i] = (u.tries[i] || 0) + 1) <= 6) {
      u.err = `Chunk ${i + 1} failed (${j.error || 'HTTP ' + st}). Retrying…`;
      setTimeout(() => { u.pending.unshift(i); upPump(); }, backoff(u.tries[i]));
    } else { u.status = 'error'; u.err = j.error || 'HTTP ' + st; Object.values(u.xhrs).forEach((x) => x.abort()); }
    upPump();
  });
}
function singlePut(u) {
  inflight++;
  u.sent = 0;
  u.xhrs.single = xhrPut(`/api/files/upload?mount=${u.mount}&path=${enc(u.dest)}&policy=${u.policy}`, u.file, (n) => { u.prog.single = n; liveSoon(); }, (st, j) => {
    inflight--; delete u.xhrs.single; delete u.prog.single;
    if (st === 200) { u.sent = u.size; uploadDone(u, j); }
    else if (st === 401) { location.href = '/login'; return; }
    else if (st === -1) { if (!u.paused) u.status = 'cancelled'; }
    else if (st === 409 && j.error === 'exists') u.status = 'exists';
    else if (TRANSIENT.has(st) && (u.tries.single = (u.tries.single || 0) + 1) <= 5) {
      u.err = 'Upload failed (' + (j.error || 'HTTP ' + st) + '). Retrying…'; u.status = 'queued-retry';
      setTimeout(() => { if (u.status === 'queued-retry') { u.status = 'queued'; upPump(); } }, backoff(u.tries.single));
    } else { u.status = 'error'; u.err = j.error || 'HTTP ' + st; }
    upPump();
  });
}
async function finishUpload(u) {
  inflight++;
  u.status = 'finishing';
  try { const r = await post(`/api/upload/${u.sess.id}/complete`, {}); inflight--; uploadDone(u, r); }
  catch (e) { inflight--; u.status = 'error'; u.err = e.message; }
  upPump();
}
let refreshT;
function uploadDone(u, r) {
  u.status = r && r.skipped ? 'skipped' : 'done'; u.url = r && r.url; u.dest = (r && r.path) || u.dest; u.finished = Date.now();
  if (u.status === 'done') invalidateFolderTree(u.dest, u.mount);
  u.file = null; // let the browser drop the File reference
  clearTimeout(refreshT);
  refreshT = setTimeout(() => { if (S.view === 'files') pollFiles(true); if (S.view === 'upload') loadUploadsSrv(); }, 500);
}
function sentOf(u) { return u.sent + Object.values(u.prog).reduce((a, b) => a + b, 0); }
const speed = { t: 0, b: 0, v: 0 };
let liveT = 0;
function liveSoon() {
  if (liveT) return;
  liveT = setTimeout(() => { liveT = 0; renderUploadsLive(); }, 250);
}
function renderUploadsLive() {
  const total = U.reduce((a, u) => a + sentOf(u), 0);
  const now = Date.now();
  if (speed.t) { const dt = (now - speed.t) / 1000; if (dt > 0.2) { speed.v = speed.v * 0.6 + Math.max(0, (total - speed.b) / dt) * 0.4; speed.t = now; speed.b = total; } }
  else { speed.t = now; speed.b = total; }
  const q = $('#upqueue'); if (q) q.innerHTML = queueRows();
  const t = $('#uptotals'); if (t) t.innerHTML = totalsLine();
  const m = $('#fupmini'); if (m) m.innerHTML = miniQueue();
  renderNav();
}
function statusText(u) {
  const p = share(sentOf(u), u.size || 1);
  return { queued: 'queued', 'queued-retry': 'waiting to retry', uploading: u.paused ? 'paused ' + fmt.pct(p) : fmt.pct(p), finishing: 'finishing', done: 'done', skipped: 'skipped (exists)',
    error: 'failed', exists: 'already exists', cancelled: 'cancelled' }[u.status] || u.status;
}
function rowActions(u) {
  if (u.status === 'exists') return `<button class="link" data-act="upPolicy" data-arg="${u.id}|replace">replace</button> · <button class="link" data-act="upPolicy" data-arg="${u.id}|rename">keep both</button> · <button class="link" data-act="upSkip" data-arg="${u.id}">skip</button>`;
  if (u.status === 'error') return u.file ? `<button class="link" data-act="upRetry" data-arg="${u.id}">retry</button> · <button class="link" data-act="upCancel" data-arg="${u.id}">remove</button>` : '';
  if (u.status === 'uploading' || u.status === 'queued' || u.status === 'queued-retry') return (u.sess && !u.paused ? `<button class="link" data-act="upPause" data-arg="${u.id}">pause</button> · ` : u.paused ? `<button class="link" data-act="upResume" data-arg="${u.id}">resume</button> · ` : '') + `<button class="link" data-act="upCancel" data-arg="${u.id}">cancel</button>`;
  if (u.status === 'done' && u.url) return `<button class="link" data-act="fcopy" data-arg="${esc(u.url)}">copy link</button>`;
  return '';
}
function queueRows() {
  if (!U.length) return '<div class="empty">Nothing queued. Drop files or folders anywhere on this page.</div>';
  return U.slice().reverse().slice(0, 300).map((u) => {
    const p = share(sentOf(u), u.size || 1);
    const chunks = u.sess ? `${u.done}/${u.sess.chunks} chunks · ` : '';
    return `<div class="upq ${u.status === 'error' ? 'err' : u.status}"><div class="row"><span class="ell" title="${esc(u.dest)}"><b>${esc(u.dest.split('/').pop())}</b> <span class="dim">${esc(mountName(u.mount))}:${esc(parentOf(u.dest))}</span></span>
      <span class="small nowrap">${esc(chunks)}${esc(fmt.bytes(u.size))} · <b>${esc(statusText(u))}</b></span><span class="small nowrap">${rowActions(u)}</span></div>
      ${u.err ? `<div class="small hot">${esc(u.err)}</div>` : ''}<div class="bar2"><i style="width:${(u.status === 'done' ? 100 : p).toFixed(1)}%"></i></div></div>`;
  }).join('');
}
function totalsLine() {
  const act = U.filter((u) => !['done', 'skipped', 'cancelled'].includes(u.status));
  const bytes = act.reduce((a, u) => a + u.size, 0), sent = act.reduce((a, u) => a + sentOf(u), 0);
  const eta = speed.v > 1 ? (bytes - sent) / speed.v : null;
  return act.length ? `${fmt.n(act.length)} active · ${esc(fmt.bytes(sent))} of ${esc(fmt.bytes(bytes))} · ${esc(fmt.rate(speed.v))}${eta != null ? ' · ' + esc(fmt.dur(eta)) + ' left' : ''}`
    : U.length ? `${fmt.n(U.filter((u) => u.status === 'done').length)} uploaded this session` : 'idle';
}
function miniQueue() {
  const act = U.filter((u) => ['queued', 'queued-retry', 'uploading', 'finishing', 'exists', 'error'].includes(u.status));
  if (!act.length) return `<div class="small dim px-0 pt-4 pb-8">${U.length ? totalsLine() : 'Drop files here to upload them to this folder.'}</div>`;
  return `<div class="small px-0 pt-2 pb-6">${totalsLine()}</div>` + act.slice(0, 6).map((u) => `<div class="up ${u.status === 'error' ? 'err' : ''}"><div class="row"><span class="ell">${esc(u.dest.split('/').pop())}</span><b>${esc(statusText(u))}</b></div><div class="bar2"><i style="width:${share(sentOf(u), u.size || 1).toFixed(1)}%"></i></div></div>`).join('');
}
Object.assign(ACT, {
  upPolicy(arg) { const [id, p] = arg.split('|'); const u = U.find((x) => x.id === +id); if (u) { u.policy = p; u.status = 'queued'; u.err = ''; upPump(); } },
  upSkip(id) { const u = U.find((x) => x.id === +id); if (u) { u.status = 'skipped'; u.file = null; liveSoon(); } },
  upRetry(id) { const u = U.find((x) => x.id === +id); if (u && u.file) { u.status = u.sess ? 'uploading' : 'queued'; u.err = ''; u.tries = {}; if (u.sess && !u.pending.length) { u.sess = null; u.status = 'queued'; } upPump(); } },
  upPause(id) { const u = U.find((x) => x.id === +id); if (u) { u.paused = true; Object.values(u.xhrs).forEach((x) => x.abort()); liveSoon(); } },
  upResume(id) { const u = U.find((x) => x.id === +id); if (u) { u.paused = false; upPump(); } },
  async upCancel(id) {
    const u = U.find((x) => x.id === +id); if (!u) return;
    u.status = 'cancelled'; u.paused = false; Object.values(u.xhrs).forEach((x) => x.abort());
    if (u.sess) { try { await post(`/api/upload/${u.sess.id}/abort`, {}); } catch { /* already gone */ } }
    u.file = null; liveSoon();
  },
  upPauseAll() { U.forEach((u) => { if (u.status === 'uploading' && u.sess) ACT.upPause(u.id); }); },
  upResumeAll() { U.forEach((u) => { if (u.paused) u.paused = false; }); upPump(); },
  upClear() { for (let i = U.length - 1; i >= 0; i--) if (['done', 'skipped', 'cancelled', 'error'].includes(U[i].status)) U.splice(i, 1); liveSoon(); render(true); },
  upMount(id) { S.upMount = +id; S.upPath = zoneRoots(S.upMount).find((z) => z.access === 'write')?.path || '/'; save(); render(true); },
  upPolicyDefault(p) { S.upPolicy = p; save(); render(true); },
  async upBrowse() { const d = await pickFolder({ title: 'Upload destination', mount: S.upMount, path: S.upPath }); if (d) { if (!canWriteZone(d.path, d.mount)) return note('You can’t upload there. Choose a folder you can write to.', { err: true }); S.upMount = d.mount; S.upPath = d.path; save(); render(true); } },
  upHere() { S.upMount = S.fmount; S.upPath = S.fpath; save(); go('upload'); },
  upOpenDest() { S.fmount = S.upMount; ACT.fgo(S.upPath); go('files'); },
  upResumeSrv(id) { const s = (D.uploadsSrv?.sessions || []).find((x) => x.id === id); if (!s) return; S.resumeFor = s; note('Select the same file again to resume ' + s.path.split('/').pop()); $('#upf').click(); },
  async upDiscardSrv(id) { try { await post(`/api/upload/${id}/abort`, {}); loadUploadsSrv(); } catch (e) { note(e.message); } },
});
async function loadUploadsSrv() {
  try { D.uploadsSrv = await get('/api/uploads'); if (S.view === 'upload') render(true); } catch { /* ignore */ }
}
VIEW_REFRESH.upload = async () => { if (!D.me) await loadMe(); if (!D.drives) await loadDrives(); loadUploadsSrv(); try { D.audit = await get('/api/audit'); } catch { /* ignore */ } render(true); };
function vUpload() {
  if (!D.drives) { if (!D.me) loadMe(); loadDrives(); return loading('Loading your storage zones…'); }
  if (!writableServed().length) return `<div class="admin-page"><section class="panel"><div class="empty big">${icon('shield-alert', 'xl')}<b>You can’t upload anywhere yet.</b><span>Ask an administrator for a storage zone with upload access.</span></div></section></div>`;
  const srv = (D.uploadsSrv?.sessions || []).filter((s) => !U.some((u) => u.sess && u.sess.id === s.id));
  const recent = (D.audit?.rows || []).filter((r) => r.action === 'upload' && r.ok).slice(0, 15);
  const pol = [['ask', 'Ask'], ['replace', 'Replace (keeps a version)'], ['rename', 'Keep both'], ['skip', 'Skip']];
  return `<div class="upview" data-scroll="upview">
    <section class="panel span2">
      <div class="updrop" data-act="fpick" data-arg="upf" data-dropdir="${esc(S.upPath)}">
        <div class="updrop-icon">${icon('upload', 'lg')}</div>
        <div><div class="h800 fs-20">Drop files or folders here</div>
          <div class="small dim">or choose them, or paste with Ctrl+V</div></div>
      </div>
      <div class="act-row"><button class="btn btn-primary" data-act="fpick" data-arg="upf">Choose files…</button><button class="btn btn-secondary" data-act="fpick" data-arg="updir">Choose folder…</button></div>
      <div class="set-row up-destination"><div><div class="h800">Upload to</div><div class="small dim">${esc(mountName(S.upMount))}: enter a path or browse.</div></div>
        <div class="set-ctl hrow items-center f-wrap jc-end">
          ${served().map((m) => `<button class="pill ${m.mount === +S.upMount ? 'on' : ''}" data-act="upMount" data-arg="${m.mount}">${esc(m.name)}</button>`).join('')}
          <input id="updest" class="input w-240 fs-125 px-8 py-5" value="${esc(S.upPath)}" spellcheck="false">
          <button class="pill" data-act="upBrowse">Browse…</button><button class="pill" data-act="upOpenDest">Open</button></div></div>
      <details class="up-options"><summary>More options <span class="small dim">· ${S.smartSort ? 'Smart-Sorting on' : 'Smart-Sorting off'} · collisions: ${esc(S.upPolicy)}</span></summary>
      <div class="up-option-body"><div class="set-row"><div><div class="h800">Smart-Sorting</div><div class="small dim">${esc((() => {
        const sm = smartMode(S.upMount, S.upPath);
        return sm.mode === 'home' ? 'Uploads go into type folders in ' + sm.base + '/.'
          : sm.mode === 'project' ? 'Uploads into ' + S.upPath + ' are sorted by type.'
            : 'Off: files land in the destination as they are.';
      })())}</div></div>
        <div class="set-ctl"><button class="pill ${S.smartSort ? 'on' : ''}" data-act="fsmart">${S.smartSort ? 'On ✓' : 'Off'}</button></div></div>
      <div class="set-row"><div><div class="h800">If a file already exists</div><div class="small dim">“Replace” keeps the old file as a version.</div></div>
        <div class="set-ctl"><div class="seg-row">${pol.map(([k, l]) => `<button class="${S.upPolicy === k ? 'on' : ''}" data-act="upPolicyDefault" data-arg="${k}">${l}</button>`).join('')}</div></div></div>
      <p class="small dim mx-0 mt-10 mb-0">Large files upload in ${UPCFG.chunk / MiB} MiB chunks, ${UPCFG.parallel} at a time, and resume if interrupted. Change this in Settings.</p></div></details>
    </section>
    <section class="panel span2 min-h-260">
      <div class="ph"><h5>Queue</h5><span class="small" id="uptotals">${totalsLine()}</span>
        <span class="srow"><button class="pill" data-act="upPauseAll">Pause all</button><button class="pill" data-act="upResumeAll">Resume all</button><button class="pill" data-act="upClear">Clear finished</button></span></div>
      <div id="upqueue" class="scroll" data-scroll="upqueue">${queueRows()}</div>
    </section>
    <section class="panel">
      <div class="ph"><h5>Unfinished uploads</h5><span class="small dim">kept for ${D.me ? D.me.upload.stale_hours : 48} h</span></div>
      ${srv.length ? srv.map((s) => `<div class="upq"><div class="row"><span class="ell"><b>${esc(s.path.split('/').pop())}</b> <span class="dim">${esc(mountName(s.mount))}:${esc(parentOf(s.path))}</span></span>
        <span class="small">${esc(fmt.bytes(s.bytes_done))} of ${esc(fmt.bytes(s.size))} · ${esc(fmt.ago(s.updated))}</span>
        <span class="small"><button class="link" data-act="upResumeSrv" data-arg="${esc(s.id)}">resume…</button> · <button class="link" data-act="upDiscardSrv" data-arg="${esc(s.id)}">discard</button></span></div>
        <div class="bar2"><i style="width:${share(s.bytes_done, s.size).toFixed(1)}%"></i></div></div>`).join('') : '<div class="empty">None. Interrupted uploads show up here, ready to resume.</div>'}
    </section>
    <section class="panel">
      <div class="ph"><h5>Recently uploaded</h5></div>
      ${recent.map((r) => `<div class="logline"><span title="${esc(r.target)}">${esc(r.target)}</span><span>${esc(r.note || '')} · ${esc(fmt.ago(r.ts))}</span></div>`).join('') || '<div class="empty">Nothing yet.</div>'}
    </section>
  </div>`;
}
NAV_BADGES.push(() => {
  const act = U.filter((u) => ['queued', 'uploading', 'finishing', 'queued-retry'].includes(u.status));
  const bad = U.filter((u) => u.status === 'error' || u.status === 'exists').length;
  const sent = act.reduce((a, u) => a + sentOf(u), 0), tot = act.reduce((a, u) => a + u.size, 0);
  return { badges: { upload: act.length ? fmt.pct(share(sent, tot || 1)) : bad ? bad + ' need you' : '' }, alerts: { upload: bad > 0 } };
});

/* ================================================================== analyser */

async function pollAnalyze() {
  try {
    if (!D.me) await loadMe();
    if (!D.drives) await loadDrives();
    if (!isRootAccount()) {
      const full = served().filter((d) => fullDriveZone(d.mount));
      if (!full.length) { D.an = null; D.anError = 'Analysis needs access to a whole drive. Ask an administrator for one.'; render(true); return; }
      if (S.anMount === 'all' || !full.some((d) => +d.mount === +S.anMount)) S.anMount = full[0].mount;
    }
    const m = S.anMount;
    D.anError = '';
    D.an = await get('/api/analyze/overview' + (m !== 'all' ? '?mount=' + m : ''));
    const tm = m !== 'all' ? m : (served().find((x) => x.online !== false) || {}).mount;
    if (tm) D.anTree = await get(`/api/analyze/tree?mount=${tm}&path=${enc(S.anPath)}`);
    if (S.anTab === 'dupes') D.dupes = await get('/api/analyze/dupes' + (m !== 'all' ? '?mount=' + m : ''));
    if (S.anTab === 'cold') D.anList = await get('/api/analyze/list?kind=cold' + (m !== 'all' ? '&mount=' + m : ''));
    if (S.view === 'analyze') render(true);
  } catch (e) { note(e.message); }
}
VIEW_REFRESH.analyze = pollAnalyze;
setInterval(() => { if (S.view === 'analyze' && D.live?.compress?.running) pollAnalyze(); }, 10000);

function squarify(nodes, W, H) {
  const out = [];
  let items = nodes.filter((n) => n.size > 0);
  const total = items.reduce((a, n) => a + n.size, 0);
  if (!total) return out;
  const scale = (W * H) / total;
  items = items.map((n) => ({ n, a: n.size * scale }));
  let x = 0, y = 0, w = W, h = H, row = [];
  const worst = (r, side) => {
    const s = r.reduce((a, i) => a + i.a, 0), mx = Math.max(...r.map((i) => i.a)), mn = Math.min(...r.map((i) => i.a));
    return Math.max((side * side * mx) / (s * s), (s * s) / (side * side * mn));
  };
  const lay = (r) => {
    const s = r.reduce((a, i) => a + i.a, 0);
    if (w >= h) { const cw = s / h; let yy = y; for (const i of r) { const hh = i.a / cw; out.push({ x, y: yy, w: cw, h: hh, n: i.n }); yy += hh; } x += cw; w -= cw; }
    else { const rh = s / w; let xx = x; for (const i of r) { const ww = i.a / rh; out.push({ x: xx, y, w: ww, h: rh, n: i.n }); xx += ww; } y += rh; h -= rh; }
  };
  for (const it of items) {
    const side = Math.min(w, h);
    if (!row.length || worst(row.concat([it]), side) <= worst(row, side)) row.push(it);
    else { lay(row); row = [it]; }
  }
  if (row.length) lay(row);
  return out;
}
function treemap() {
  const T = D.anTree;
  if (!T || !T.nodes) return '<div class="empty">No index yet. The first scan runs shortly after Strata starts.</div>';
  const W = 240, H = 100;
  const nodes = T.nodes.slice(0, 300);
  const rects = squarify(nodes, W, H);
  const tot = nodes.reduce((a, n) => a + n.size, 0) || 1;
  return `<div class="treemap">${rects.map((r) => {
    const n = r.n, big = r.w > 14 && r.h > 9, ext = treeExt(n), cat = n.cat || 'other';
    const title = `${n.path}\n${fmt.bytes(n.size)} · ${fmt.pct(share(n.size, tot))} of shown items · ${n.dir ? 'folder · ' + fmt.n(n.files) + ' files' : '.' + ext + ' · ' + cat}\n${fmt.n(n.hits || 0)} origin hits · ${fmt.bytes(n.sent || 0)} sent in 30 days`;
    return `<button class="tm ${n.dir ? 'dir' : ''}" style="left:${(r.x / W * 100).toFixed(3)}%;top:${(r.y / H * 100).toFixed(3)}%;width:${(r.w / W * 100).toFixed(3)}%;height:${(r.h / H * 100).toFixed(3)}%;background:${treemapColor(n)}"
      data-act="${n.dir ? 'anGo' : 'anReveal'}" data-arg="${esc(n.path)}" title="${esc(title)}" aria-label="${esc(title)}">${big ? `<b>${esc(n.name)}</b><span>${esc(fmt.bytes(n.size))}</span>` : ''}</button>`;
  }).join('')}</div>`;
}
function treeExt(n) { return n.dir ? (n.cat || 'folder').toLowerCase() : (n.name.includes('.') ? n.name.split('.').pop().toLowerCase() : 'no extension'); }
function hueFor(value) {
  let h = 0;
  for (const ch of String(value)) h = ((h * 31) + ch.charCodeAt(0)) | 0;
  return Math.abs(h) % 360;
}
function treemapColor(n) {
  const maxHits = Math.max(1, ...(D.anTree?.nodes || []).map((x) => x.hits || 0));
  if (S.anColor === 'traffic') {
    const heat = Math.log1p(n.hits || 0) / Math.log1p(maxHits);
    return `hsl(${205 - 165 * heat} 72% ${88 - 42 * heat}%)`;
  }
  const key = S.anColor === 'category' || n.dir ? (n.cat || 'other') : treeExt(n);
  return `hsl(${hueFor(key)} 62% 76%)`;
}
function treemapLegend(nodes) {
  if (S.anColor === 'traffic') return '<span><i class="key-cool"></i>few origin hits</span><span><i class="key-warm"></i>many origin hits (30 days)</span>';
  const totals = new Map();
  for (const n of nodes) { const k = S.anColor === 'category' || n.dir ? (n.cat || 'other') : treeExt(n); totals.set(k, (totals.get(k) || 0) + n.size); }
  return [...totals].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([k]) => `<span><i style="background:hsl(${hueFor(k)} 62% 76%)"></i>${S.anColor === 'extension' && k !== 'no extension' && k !== 'folder' ? '.' : ''}${esc(k)}</span>`).join('');
}
function vAnalyze() {
  const A = D.an;
  if (D.anError) return `<div class="admin-page"><section class="panel"><div class="empty big">${icon('shield-alert', 'xl')}<b>Analyze scope required</b><span>${esc(D.anError)}</span></div></section></div>`;
  if (!A) return loading('Reading the index…');
  const t = A.totals, ov = A.overhead || {};
  const overBytes = Object.values(ov).reduce((a, v) => a + (v.bytes || 0), 0);
  const tm = S.anMount !== 'all' ? S.anMount : (served().find((x) => x.online !== false) || {}).mount;
  const parts = S.anPath.split('/').filter(Boolean);
  const kpi = (k, v, sub, hot) => `<div><div class="cap">${esc(k)}</div><div class="val ${hot ? 'hot' : ''}">${esc(v)}</div><div class="small dim ell">${esc(sub)}</div></div>`;
  const tabs = [['types', 'Types'], ['largest', 'Largest files'], ['folders', 'Largest folders'], ['dupes', 'Duplicates'], ['cold', 'Cold data'], ['cleanup', 'Cleanup'],
    ['delivery', 'Delivery'], ['age', 'Age & sizes'], ['hot', 'Hot files'], ['drives', 'Drives']];
  const sc = D.live?.compress || {};
  const here = D.anTree?.self || {};
  const cats = Object.entries(here.cats || {}).sort((a, b) => b[1] - a[1]);
  return `<div class="col-fill">
    <div class="tbar"><span class="cap">Drive</span>${isRootAccount() ? `<button class="pill ${S.anMount === 'all' ? 'on' : ''}" data-act="anMount" data-arg="all">All</button>` : ''}
      ${served().map((m) => `<button class="pill ${String(m.mount) === String(S.anMount) ? 'on' : ''}" data-act="anMount" data-arg="${m.mount}">${esc(m.name)}</button>`).join('')}
      <div class="grow"></div><span class="small dim">${sc.running ? 'scanning… ' + fmt.n(sc.scanned || 0) + ' files' : sc.hashing ? 'hashing duplicate candidates…' : 'index from ' + fmt.ago((A.drives[0] || {}).scanned)}</span>
      <button class="pill" data-act="compressRun">Rescan now</button></div>
    <div class="kpis">
      ${kpi('Stored', fmt.bytes(t.bytes), fmt.n(t.files) + ' files · ' + fmt.n(t.folders) + ' folders')}
      ${kpi('Largest file', fmt.bytes(t.largest), (A.largest[0] || {}).path || '')}
      ${kpi('Duplicates', fmt.bytes(A.duplicates.wasted), fmt.n(A.duplicates.groups) + ' groups · ' + fmt.n(A.duplicates.hashed) + '/' + fmt.n(A.duplicates.candidates) + ' candidates hashed', A.duplicates.wasted > 0)}
      ${kpi('Cold at origin', fmt.pct(share(A.cold.b, t.bytes)), fmt.bytes(A.cold.b) + ' not requested in 90 days')}
      ${kpi('Strata overhead', fmt.bytes(overBytes), 'versions ' + fmt.bytes(ov.versions?.bytes) + ' · trash ' + fmt.bytes(ov.trash?.bytes))}
      ${kpi('Over the cache limit', fmt.n(A.delivery.over_cache_limit.c), fmt.bytes(A.delivery.over_cache_limit.b) + ' · > 512 MB, never cached by Cloudflare', A.delivery.over_cache_limit.c > 0)}
    </div>
    <div class="grid2 angrid">
      <section class="panel">
        <div class="ph"><h5>Where the space goes</h5><span class="crumbs"><button data-act="anGo" data-arg="/">${esc(mountName(tm))}</button>${parts.map((p, i) => `<span class="dim">/</span><button data-act="anGo" data-arg="${esc('/' + parts.slice(0, i + 1).join('/'))}">${esc(p)}</button>`).join('')}</span>
          <button class="pill" data-act="anColor" title="Change treemap colors">Color: ${S.anColor === 'extension' ? 'file type' : S.anColor === 'category' ? 'category' : 'origin hits'}</button></div>
        ${treemap()}
        <div class="keyrow2">${treemapLegend(D.anTree?.nodes || [])}<span class="dim">Area is size. Click a folder to zoom in${D.anTree?.more ? `; ${fmt.n(D.anTree.more)} more items not shown` : ''}.</span></div>
      </section>
      <section class="panel">
        <div class="ph"><h5>This folder</h5><span class="small dim">${esc(fmt.bytes(here.bytes))} · ${fmt.n(here.files)} files · ${fmt.n(here.dirs)} folders</span></div>
        <div class="scroll" data-scroll="an-details">${barList(cats.map(([k, v]) => ({ k, v })), { label: (r) => r.k, value: (r) => r.v, fmtv: (r) => fmt.bytes(r.v) + ' · ' + fmt.pct(share(r.v, here.bytes)) })}
          <div class="cap mx-0 mt-14 mb-4">Items here</div>
          ${table('anhere', [
            { t: 'Type', w: 36 },
            { t: 'Name', w: 320, sort: 'name' },
            { t: 'Size', w: 100, a: 'r', sort: 'size' }
          ], (D.anTree?.nodes || []).map(r => ({
            cells: [
              hcell(icon(r.dir ? 'folder' : 'file', 'sm'), 'dim'),
              hcell(`<button class="link ell" data-act="${r.dir ? 'anGo' : 'anReveal'}" data-arg="${esc(r.path)}">${esc(r.name)}</button>`),
              cell(fmt.bytes(r.size), 'r h800')
            ]
          })), { empty: 'Empty folder', sort: S.sort?.anhere || 'size', desc: S.sortDir?.anhere !== 1 })}
          <div class="act-row"><button class="btn btn-secondary" data-act="anOpenFiles">Open in Files</button></div></div>
      </section>
    </div>
    <div class="tbar">${tabs.map(([k, l]) => `<button class="pill ${S.anTab === k ? 'on' : ''}" data-act="anTab" data-arg="${k}">${l}</button>`).join('')}</div>
    <div class="antab" data-scroll="antab">${anTabBody()}</div>
  </div>`;
}
function pathRows(rows, extra) {
  return rows.map((r) => ({ cells: [cell(mountName(r.mount), 'dim'), cell(r.path, '', r.path), cell(fmt.bytes(r.size), 'r h800'), cell(fmt.dt(r.mtime), 'dim'), cell(r.cat || '', 'dim')].concat(extra ? extra(r) : []),
    cls: 'click', attrs: `data-act="anRevealM" data-arg="${esc(r.mount + '|' + r.path)}"` }));
}
const PATH_LABELS = [{ t: 'Drive', w: 110 }, { t: 'Path', w: 460 }, { t: 'Size', w: 90, a: 'r' }, { t: 'Modified', w: 120 }, { t: 'Type', w: 70 }];
function anTabBody() {
  const A = D.an, tab = S.anTab;
  if (tab === 'types') {
    return `<div class="grid2 cols-2">
      <section class="panel"><div class="ph"><h5>Categories</h5></div>${barList(A.cats, { label: (r) => r.k + ' · ' + fmt.n(r.c) + ' files', value: (r) => r.b, fmtv: (r) => fmt.bytes(r.b) + ' · ' + fmt.pct(share(r.b, A.totals.bytes)), attrs: (r) => `data-act="anList" data-arg="cat|${esc(r.k)}" style="cursor:pointer"` })}</section>
      <section class="panel"><div class="ph"><h5>Extensions</h5><span class="small dim">click for the files</span></div>${barList(A.exts, { label: (r) => (r.k ? '.' + r.k : '(none)') + ' · ' + fmt.n(r.c), value: (r) => r.b, fmtv: (r) => fmt.bytes(r.b), attrs: (r) => `data-act="anList" data-arg="ext|${esc(r.k)}" style="cursor:pointer"` })}</section>
    </div>` + (D.anList && D.anList.title ? `<div class="ph px-18 py-10"><h5>${esc(D.anList.title)}</h5></div>` + table('anlist', PATH_LABELS, pathRows(D.anList.rows)) : '');
  }
  if (tab === 'largest') return table('anlargest', PATH_LABELS, pathRows(A.largest));
  if (tab === 'folders') {
    return table('anfolders', [{ t: 'Drive', w: 110 }, { t: 'Folder', w: 380 }, { t: 'Size', w: 90, a: 'r' }, { t: 'Files', w: 70, a: 'r' }, { t: 'Newest', w: 110 }, { t: 'Mix', w: 200 }],
      A.folders.map((f) => ({ cells: [cell(mountName(f.mount), 'dim'), cell(f.path), cell(fmt.bytes(f.bytes), 'r h800'), cell(fmt.n(f.files), 'r dim'), cell(fmt.dt(f.newest), 'dim'),
        hcell(`<span class="mix">${Object.entries(f.cats || {}).sort((a, b) => b[1] - a[1]).map(([c, b]) => `<i title="${esc(c)} ${esc(fmt.bytes(b))}" style="flex:${b};background:${CAT_COLOR[c] || CAT_COLOR.other}"></i>`).join('')}</span>`)],
        cls: 'click', attrs: `data-act="anGoM" data-arg="${esc(f.mount + '|' + f.path)}"` })));
  }
  if (tab === 'dupes') {
    const G = D.dupes;
    if (!G) return loading('Grouping duplicates…');
    if (!G.groups.length) return `<div class="empty">No duplicates among ${fmt.n(A.duplicates.hashed)} hashed files.</div>`;
    return G.groups.map((g) => `<div class="dupe"><div class="ph"><h5>${fmt.n(g.n)} copies · ${esc(fmt.bytes(g.size))} each</h5><span class="small hot">${esc(fmt.bytes(g.wasted))} wasted</span></div>
      ${g.items.map((it, i) => `<div class="logline"><span title="${esc(it.path)}">${i === 0 ? '<b>oldest</b> · ' : ''}${esc(it.drive || '')}:${esc(it.path)}</span><span><button class="link" data-act="anRevealM" data-arg="${esc(it.mount + '|' + it.path)}">reveal</button>${i ? ` · <button class="link" data-act="anTrash" data-arg="${esc(it.mount + '|' + it.path)}">move to trash</button>` : ''}</span></div>`).join('')}</div>`).join('');
  }
  if (tab === 'cold') {
    const L = D.anList && D.anList.kind === 'cold' ? D.anList : null;
    return `<div class="tbar" style="border:0"><span class="small dim">Files nobody requested from the origin in 90 days, largest first. Cloudflare answers cached files without asking the origin, so popular cached media can look cold here. Check Health › Edge before deleting.</span></div>` +
      (L ? table('ancold', PATH_LABELS, pathRows(L.rows)) : loading());
  }
  if (tab === 'cleanup') {
    return Object.entries(A.cleanup).map(([name, c]) => `<div class="dupe"><div class="ph"><h5>${esc(name)} · ${fmt.n(c.c)}</h5><span class="small dim">${esc(fmt.bytes(c.b))} · ${esc(c.why)}</span>
      ${c.items.length && !c.items[0].dir ? `<button class="pill danger" data-act="anTrashMany" data-arg="${esc(name)}">Move listed to trash</button>` : ''}</div>
      ${c.items.slice(0, 40).map((it) => `<div class="logline"><span title="${esc(it.path)}">${esc(mountName(it.mount))}:${esc(it.path)}</span><span>${it.dir ? 'folder' : esc(fmt.bytes(it.size))} · <button class="link" data-act="anRevealM" data-arg="${esc(it.mount + '|' + it.path)}">reveal</button></span></div>`).join('') || '<div class="small dim">Nothing found.</div>'}</div>`).join('');
  }
  if (tab === 'delivery') {
    const d = A.delivery;
    return `<div class="grid2 cols-3">
      <section class="panel"><div class="ph"><h5>Too big for Cloudflare’s cache</h5></div><div class="big-num">${fmt.n(d.over_cache_limit.c)}</div><div class="small dim">${esc(fmt.bytes(d.over_cache_limit.b))} in files over 512 MB. Cloudflare never caches these, so the origin serves every download.</div>
        <div class="act-row"><button class="btn btn-secondary" data-act="anList" data-arg="over_cache_limit|">List them</button></div></section>
      <section class="panel"><div class="ph"><h5>Video</h5></div><div class="big-num">${fmt.n(d.video.c)}</div><div class="small dim">${esc(fmt.bytes(d.video.b))}. Cloudflare’s terms limit serving video through its regular CDN; Stream or R2 are the allowed routes if this grows. <a class="link" href="https://developers.cloudflare.com/fundamentals/reference/policies-compliances/delivering-videos-with-cloudflare/" target="_blank" rel="noopener">Cloudflare’s policy ↗</a></div>
        <div class="act-row"><button class="btn btn-secondary" data-act="anList" data-arg="video|">List them</button></div></section>
      <section class="panel"><div class="ph"><h5>Over 100 MB</h5></div><div class="big-num">${fmt.n(d.over_upload_limit.c)}</div><div class="small dim">${esc(fmt.bytes(d.over_upload_limit.b))}. Too large for one Cloudflare request. The uploader splits them into chunks.</div></section>
    </div>` + (D.anList && D.anList.title ? `<div class="ph" style="padding:10px 18px"><h5>${esc(D.anList.title)}</h5></div>` + table('anlist', PATH_LABELS, pathRows(D.anList.rows)) : '');
  }
  if (tab === 'age') {
    return `<div class="grid2 cols-2">
      <section class="panel"><div class="ph"><h5>By last modified</h5></div>${barList(A.ages, { label: (r) => r.k + ' · ' + fmt.n(r.c), value: (r) => r.b, fmtv: (r) => fmt.bytes(r.b) })}</section>
      <section class="panel"><div class="ph"><h5>By file size</h5></div>${barList(A.sizes, { label: (r) => r.k + ' · ' + fmt.n(r.c), value: (r) => r.b, fmtv: (r) => fmt.bytes(r.b) })}</section></div>`;
  }
  if (tab === 'hot') {
    return `<div class="tbar border-0"><span class="small dim">Most bytes served by the origin in 90 days, cache hits not counted.</span></div>` +
      table('anhot', PATH_LABELS.concat([{ t: 'Requests', w: 80, a: 'r' }, { t: 'Sent', w: 90, a: 'r' }]), pathRows(A.hot, (r) => [cell(fmt.n(r.hits), 'r'), cell(fmt.bytes(r.sent), 'r h800')]));
  }
  return `<div class="grid2" style="grid-template-columns:repeat(3,minmax(0,1fr))">${A.drives.map((d) => `<section class="panel"><div class="ph"><h5>${esc(d.name)}</h5><span class="small dim">${esc(d.kind)}${d.enabled ? '' : ' · disabled'}</span></div>
      <div class="small dim" style="word-break:break-all">${esc(d.path)}</div>
      ${d.disk ? segs(share(d.disk.used, d.disk.total), 24, 90, 's7') + `<div class="small dim smt-1">${esc(fmt.bytes(d.disk.free))} free of ${esc(fmt.bytes(d.disk.total))}</div>` : '<div class="small hot">offline</div>'}
      <div class="cap smt-2">Indexed</div><div class="h800">${esc(fmt.bytes(d.bytes))} · ${fmt.n(d.files)} files</div>
      <span class="mix smt-2">${Object.entries(d.cats || {}).sort((a, b) => b[1] - a[1]).map(([c, b]) => `<i title="${esc(c)} ${esc(fmt.bytes(b))}" style="flex:${b};background:${CAT_COLOR[c] || CAT_COLOR.other}"></i>`).join('')}</span>
      <div class="small dim smt-2">scanned ${esc(fmt.ago(d.scanned))}</div></section>`).join('')}</div>`;
}
Object.assign(ACT, {
  anMount(m) {
    if (!isRootAccount()) {
      const allowed = served().filter((d) => fullDriveZone(d.mount));
      if (m === 'all') m = allowed[0]?.mount;
      else if (!allowed.some((d) => +d.mount === +m)) return note('You can’t analyze that drive. Ask an administrator for access.', { err: true });
    }
    S.anMount = m === 'all' ? 'all' : +m; S.anPath = '/'; D.anList = null; D.dupes = null; save(); pollAnalyze();
  },
  anGo(p) { S.anPath = p || '/'; pollAnalyze(); },
  anColor() { S.anColor = ({ extension: 'category', category: 'traffic', traffic: 'extension' })[S.anColor] || 'extension'; render(true); },
  anGoM(arg) { const i = arg.indexOf('|'); S.anMount = +arg.slice(0, i); S.anPath = arg.slice(i + 1); save(); pollAnalyze(); },
  anReveal(p) { const tm = S.anMount !== 'all' ? S.anMount : (served().find((x) => x.online !== false) || {}).mount; S.fmount = tm; go('files'); ACT.freveal(p); },
  anRevealM(arg) { const i = arg.indexOf('|'); S.fmount = +arg.slice(0, i); go('files'); ACT.freveal(arg.slice(i + 1)); },
  anOpenFiles() { const tm = S.anMount !== 'all' ? S.anMount : (served().find((x) => x.online !== false) || {}).mount; S.fmount = tm; go('files'); ACT.fgo(S.anPath); },
  async anTab(t) {
    S.anTab = t; D.anList = null; render(true);
    try {
      if (t === 'dupes') D.dupes = await get('/api/analyze/dupes' + (S.anMount !== 'all' ? '?mount=' + S.anMount : ''));
      if (t === 'cold') D.anList = Object.assign(await get('/api/analyze/list?kind=cold' + (S.anMount !== 'all' ? '&mount=' + S.anMount : '')), { kind: 'cold' });
      render(true);
    } catch (e) { note(e.message); }
  },
  async anList(arg) {
    const [kind, value] = arg.split('|');
    try {
      const r = await get(`/api/analyze/list?kind=${kind}&value=${enc(value)}` + (S.anMount !== 'all' ? '&mount=' + S.anMount : ''));
      D.anList = Object.assign(r, { kind, title: { ext: 'Files with .' + value, cat: 'Category: ' + value, over_cache_limit: 'Files over 512 MB', video: 'Video files' }[kind] });
      render(true);
    } catch (e) { note(e.message); }
  },
  async anTrash(arg) {
    const i = arg.indexOf('|'), mount = +arg.slice(0, i), p = arg.slice(i + 1);
    const ok = await ask({ kicker: 'Duplicate', title: 'Move this copy to the trash?', text: p, danger: true, ok: 'Move to trash' });
    if (!ok) return;
    try { await post('/api/files/delete', { mount, paths: [p] }); note('Moved to trash'); ACT.anTab('dupes'); } catch (e) { note(e.message); }
  },
  async anTrashMany(name) {
    const c = D.an.cleanup[name]; if (!c) return;
    const items = c.items.filter((x) => !x.dir);
    const ok = await ask({ kicker: 'Cleanup', title: `Move ${items.length} ${name.toLowerCase()} to the trash?`, danger: true, ok: 'Move to trash', text: 'They can be restored from each drive’s trash until you empty it.' });
    if (!ok) return;
    const by = {};
    items.forEach((x) => { (by[x.mount] = by[x.mount] || []).push(x.path); });
    try { for (const [m, paths] of Object.entries(by)) await post('/api/files/delete', { mount: +m, paths }); note('Moved ' + items.length + ' file(s) to trash'); pollAnalyze(); } catch (e) { note(e.message); }
  },
});

VIEWFN.files = vFiles;
VIEWFN.upload = vUpload;
VIEWFN.analyze = vAnalyze;
MENUS.upload = () => null;
loadDrives();
