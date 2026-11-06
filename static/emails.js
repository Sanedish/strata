/* Settings › E-mails (mailtpl.py): every message Corium sends, in the look of the error pages with this site's name
   and accent colour. The owner can replace any part of each one (subject, HTML, CSS, plain text) and sees a live
   preview on sample data. Owner only: a template sees the sign-in codes and reset links it carries. */

const EM = { data: null, loading: false, kind: null, cms: {}, tab: 'html', scheme: 'light', width: 'desktop', view: 'html',
  timer: 0, seq: 0, last: null, focus: 'cm', drafts: {} };
const EM_PARTS = [['html', 'HTML', 'htmlmixed'], ['css', 'CSS', 'css'], ['text', 'Plain text', null]];
const emCan = () => meOwner() || meCan('mail.manage');
const emKind = (id) => (EM.data?.kinds || []).find((k) => k.id === id);
const emTag = (v) => v.html ? '{{{' + v.name + '}}}' : '{{' + v.name + '}}';

async function emLoad() { EM.data = await get('/api/emails'); }

function emailsPanel(row) {
  if (!emCan()) return '';
  if (!EM.data) {
    if (!EM.loading) {
      EM.loading = true;
      emLoad().catch((e) => note('Couldn’t load the e-mails: ' + e.message)).finally(() => { EM.loading = false; if (S.view === 'settings') render(true); });
    }
    return '<section class="panel span2"><div class="empty">Loading the e-mails…</div></section>';
  }
  const d = EM.data;
  const rows = d.kinds.map((k) => {
    const parts = Object.keys(k.custom || {});
    return row(k.label, k.desc, `<span class="em-state ${parts.length ? 'on' : ''}">${parts.length ? 'Customised: ' + esc(parts.join(', ')) : 'Default'}</span>
      <button class="pill" data-act="emEdit" data-arg="${k.id}">${icon('pencil', 'sm')}Edit</button>
      <button class="pill" data-act="emTest" data-arg="${k.id}" ${d.mail_ready && d.test_to ? '' : 'disabled'} title="Send it with sample data to ${esc(d.test_to || 'your address')}">${icon('send', 'sm')}Test</button>
      <button class="pill" data-act="emReset" data-arg="${k.id}" ${parts.length ? '' : 'disabled'} title="Back to the built-in e-mail">${icon('rotate-ccw', 'sm')}Default</button>`);
  }).join('');
  return `<section class="panel span2">
    <div class="ph"><h5>${icon('mail')}E-mails</h5><span class="small dim">${d.mail_ready ? 'tests go to ' + esc(d.test_to || 'nobody: add an address to your account') : 'delivery isn’t set up (Alerts › Delivery)'}</span></div>
    <p class="small dim em-intro">Every message Corium sends, in the look of the error pages with this site’s name and accent colour. Change any part of one; the parts you leave alone stay built-in and follow updates.</p>
    ${rows}</section>`;
}

function emBody(k, cur) {
  const seg = (items, cur, act) => `<div class="seg-row">${items.map(([v, l]) => `<button class="${cur === v ? 'on' : ''}" data-act="${act}" data-arg="${v}">${l}</button>`).join('')}</div>`;
  return `<div class="em-ed">
    <div class="em-src">
      <div class="em-bar"><label class="em-subj">Subject<input id="em_subject" class="input" value="${esc(cur.subject)}" spellcheck="false" autocomplete="off"></label>
        <button class="pill" data-act="emPartDefault" data-arg="subject" title="The built-in subject">${icon('rotate-ccw', 'sm')}<i class="em-dot" data-part="subject"></i></button></div>
      <div class="em-bar"><div class="seg-row" id="em_tabs">${EM_PARTS.map(([p, l]) => `<button class="${EM.tab === p ? 'on' : ''}" data-act="emTab" data-arg="${p}">${l}<i class="em-dot" data-part="${p}"></i></button>`).join('')}</div>
        <div class="grow"></div><button class="pill" data-act="emPartDefault" title="Put the built-in version of this part in the editor">${icon('rotate-ccw', 'sm')}Built-in version</button></div>
      ${EM_PARTS.map(([p]) => `<div class="em-cm" id="em_cm_${p}" ${EM.tab === p ? '' : 'hidden'}></div>`).join('')}
      <details class="em-help" open><summary>Variables</summary>
        <div class="em-vars">${k.vars.map((v) => `<button class="em-var" data-act="emInsert" data-arg="${esc(v.name)}" title="Insert at the cursor"><code>${esc(emTag(v))}</code><span>${esc(v.desc)}</span></button>`).join('')}</div>
        <p class="small dim">{{name}} is escaped in the HTML (as is in the subject and text); {{{name}}} works only for the lists Corium builds itself. {{#name}}…{{/name}} shows when the variable is set, {{^name}}…{{/name}} when it isn’t.
          Simple CSS rules (tag, .class, #id) are copied into style attributes when the e-mail goes out; @media rules (dark mode, phones) stay in a style block. Use public https:// addresses for images.</p></details>
    </div>
    <div class="em-prev">
      <div class="em-bar">${seg([['light', icon('sun', 'sm') + 'Light'], ['dark', icon('moon', 'sm') + 'Dark']], EM.scheme, 'emScheme')}
        ${seg([['desktop', icon('monitor', 'sm') + 'Wide'], ['phone', 'Phone']], EM.width, 'emWidth')}
        ${seg([['html', icon('code', 'sm') + 'HTML'], ['text', icon('file-text', 'sm') + 'Text']], EM.view, 'emView')}</div>
      <div class="em-psubj"><b>Subject</b><span id="em_psubj">…</span></div>
      <div class="em-warn" id="em_warn" hidden></div>
      <div class="em-frame"><iframe id="em_frame" sandbox="" title="Preview of the e-mail" referrerpolicy="no-referrer" class="${EM.width === 'phone' ? 'phone' : ''}" ${EM.view === 'html' ? '' : 'hidden'}></iframe><pre id="em_ptext" ${EM.view === 'text' ? '' : 'hidden'}></pre></div>
      <p class="small dim">Sample data. The preview shows images only when they are embedded (data:).</p>
    </div></div>`;
}

function emFields() {
  const f = { subject: $('#em_subject')?.value ?? '' };
  for (const [p] of EM_PARTS) f[p] = EM.cms[p] ? EM.cms[p].getValue() : '';
  return f;
}
function emDots() {
  const k = emKind(EM.kind), f = emFields();
  if (!k) return;
  document.querySelectorAll('#sheet .em-dot').forEach((d) => { d.hidden = f[d.dataset.part] === k.default[d.dataset.part]; d.title = 'Changed from the built-in version'; });
}
function emChanged() {
  if (!EM.kind || !$('#em_subject')) return;
  EM.drafts[EM.kind] = emFields();
  emDots();
  clearTimeout(EM.timer);
  EM.timer = setTimeout(emPreview, 300);
}
async function emPreview() {
  if (!EM.kind || !$('#em_frame')) return;
  const seq = ++EM.seq;
  try {
    const r = await post('/api/emails/preview', Object.assign({ kind: EM.kind }, emFields()));
    if (seq !== EM.seq) return;
    EM.last = r; emShow();
  } catch (e) { const w = $('#em_warn'); if (w) { w.hidden = false; w.textContent = 'No preview: ' + e.message; } }
}
function emShow() {
  const r = EM.last, frame = $('#em_frame');
  if (!r || !frame) return;
  // the dark-mode rules follow the switch here, not this computer's setting
  frame.srcdoc = r.html.replace(/prefers-color-scheme\s*:\s*dark/g, EM.scheme === 'dark' ? 'min-width: 0px' : 'max-width: 0px');
  frame.className = EM.width === 'phone' ? 'phone' : '';
  frame.hidden = EM.view !== 'html';
  const pre = $('#em_ptext'); pre.textContent = r.text; pre.hidden = EM.view !== 'text';
  $('#em_psubj').textContent = r.subject;
  const w = $('#em_warn');
  w.hidden = !r.unknown?.length;
  w.textContent = r.unknown?.length ? 'Not a variable of this e-mail (left empty): ' + r.unknown.join(', ') : '';
}
const emSeg = (el) => el?.parentElement?.querySelectorAll('button').forEach((b) => b.classList.toggle('on', b === el));
function emPost(path, body) { return post(path, body).then((r) => { if (r?.kinds) EM.data = r; return r; }); }

Object.assign(ACT, {
  async emEdit(id) {
    try { if (!EM.data) await emLoad(); } catch (e) { return note('Couldn’t load the e-mails: ' + e.message); }
    const k = emKind(id);
    if (!k) return;
    const draft = EM.drafts[id], cur = draft || k.current;
    EM.kind = id; EM.tab = 'html'; EM.last = null; EM.cms = {};
    openSheet('E-mails', k.label, emBody(k, cur), `<button class="btn btn-primary" data-act="emSave">Save</button>
      <button class="btn btn-secondary" data-act="emTestDraft" ${EM.data.mail_ready && EM.data.test_to ? '' : 'disabled'} title="To ${esc(EM.data.test_to || 'your address')}, as it is in the editor">Send test</button>
      <button class="btn btn-secondary" data-act="emResetOpen" ${Object.keys(k.custom || {}).length ? '' : 'disabled'}>Reset to default</button>`, true);
    $('#sheet .dlg')?.classList.add('em-sheet');
    for (const [p, , mode] of EM_PARTS) {
      const host = $('#em_cm_' + p);
      if (!host) continue;
      if (!window.CodeMirror) {  // the editor library failed to load: a plain text area still works
        host.innerHTML = `<textarea class="input mono em-ta" spellcheck="false">${esc(cur[p])}</textarea>`;
        const ta = host.firstChild;
        EM.cms[p] = { getValue: () => ta.value, setValue: (v) => { ta.value = v; emChanged(); }, refresh() {}, focus: () => ta.focus(),
          replaceSelection: (t) => { ta.setRangeText(t, ta.selectionStart, ta.selectionEnd, 'end'); emChanged(); } };
        ta.addEventListener('input', emChanged); ta.addEventListener('focus', () => { EM.focus = 'cm'; });
        continue;
      }
      const cm = CodeMirror(host, { value: cur[p], mode, lineNumbers: true, lineWrapping: true, matchBrackets: true,
        matchTags: mode === 'htmlmixed' ? { bothTags: true } : false, indentUnit: 2, tabSize: 2, styleActiveLine: true,
        inputStyle: 'contenteditable', extraKeys: { 'Ctrl-S': () => ACT.emSave(), 'Cmd-S': () => ACT.emSave() } });
      cm.on('change', emChanged); cm.on('focus', () => { EM.focus = 'cm'; });
      EM.cms[p] = cm;
    }
    const subj = $('#em_subject');
    subj.addEventListener('input', emChanged); subj.addEventListener('focus', () => { EM.focus = 'subject'; });
    EM.focus = 'cm';
    EM.cms.html?.focus();
    emDots(); emPreview();
    if (draft) note('Your unsaved changes to this e-mail are back. Reset to default or Built-in version undo them.');
  },
  emTab(p, el) {
    EM.tab = p; emSeg(el);
    for (const [q] of EM_PARTS) { const h = $('#em_cm_' + q); if (h) h.hidden = q !== p; }
    EM.cms[p]?.refresh(); EM.cms[p]?.focus(); EM.focus = 'cm';
  },
  emScheme(v, el) { EM.scheme = v; emSeg(el); emShow(); },
  emWidth(v, el) { EM.width = v; emSeg(el); emShow(); },
  emView(v, el) { EM.view = v; emSeg(el); emShow(); },
  emInsert(name) {
    const v = emKind(EM.kind)?.vars.find((x) => x.name === name);
    if (!v) return;
    const subj = $('#em_subject');
    if (EM.focus === 'subject' && subj) {
      subj.setRangeText('{{' + name + '}}', subj.selectionStart, subj.selectionEnd, 'end'); subj.focus(); emChanged(); return;
    }
    const cm = EM.cms[EM.tab];
    if (!cm) return;
    cm.replaceSelection(EM.tab === 'html' ? emTag(v) : '{{' + name + '}}');
    cm.focus();
  },
  emPartDefault(part) {
    const k = emKind(EM.kind);
    if (!k) return;
    if (part === 'subject') { $('#em_subject').value = k.default.subject; emChanged(); return; }
    EM.cms[EM.tab]?.setValue(k.default[EM.tab]);
  },
  async emSave() {
    if (!EM.kind || !$('#em_subject')) return;
    try {
      await emPost('/api/emails/save', Object.assign({ kind: EM.kind }, emFields()));
      delete EM.drafts[EM.kind];
      note(emKind(EM.kind).label + ' e-mail saved');
      closeSheet(); if (S.view === 'settings') render(true);
    } catch (e) { note('Couldn’t save: ' + e.message); }
  },
  async emTestDraft() {
    try { const r = await post('/api/emails/test', Object.assign({ kind: EM.kind }, emFields())); note('Test sent to ' + r.to); }
    catch (e) { note('Couldn’t send the test: ' + e.message); }
  },
  async emTest(id) {
    try { const r = await post('/api/emails/test', { kind: id }); note('Test sent to ' + r.to); }
    catch (e) { note('Couldn’t send the test: ' + e.message); }
  },
  async emReset(id) {
    const k = emKind(id);
    if (!k || !(await ask({ kicker: 'E-mails', title: `Reset the ${k.label} e-mail?`, danger: true, ok: 'Reset',
      text: 'Its subject, HTML, CSS and text go back to the built-in version. Your changes are deleted.' }))) return false;
    try {
      await emPost('/api/emails/reset', { kind: id });
      delete EM.drafts[id];
      note(k.label + ' e-mail is back to the default');
      if (S.view === 'settings') render(true);
      return true;
    } catch (e) { note('Couldn’t reset: ' + e.message); return false; }
  },
  async emResetOpen() { if (await ACT.emReset(EM.kind)) closeSheet(); },
});
