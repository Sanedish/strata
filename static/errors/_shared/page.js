// Renders an error page from info.md: frontmatter holds the facts, "## " sections hold the text.
// _shared/site.md holds defaults for every page. Open a page with ?demo to load demo.md instead.

const esc = s => s.replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);

// ponytail: tiny markdown subset. Paragraphs, "- " lists, **bold**, *italic*, `code`, [links](url).
// Swap in a real parser if info.md ever needs tables or nesting.
const inline = s => esc(s)
  .replace(/`([^`]+)`/g, '<code>$1</code>')
  .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
  .replace(/\*([^*]+)\*/g, '<em>$1</em>')
  .replace(/\[([^\]]+)\]\(((?:https?:\/\/|mailto:|\/|#)[^)\s]*)\)/g, '<a href="$2">$1</a>');

const md = src => src.split(/\n\s*\n/).map(b => b.trim()).filter(Boolean).map(b => {
  const lines = b.split('\n').map(l => l.trim());
  return lines.every(l => /^[-*] /.test(l))
    ? `<ul>${lines.map(l => `<li>${inline(l.slice(2))}</li>`).join('')}</ul>`
    : `<p>${inline(lines.join(' '))}</p>`;
}).join('');

function parse(text) {
  text = text.replace(/^﻿/, '').replace(/\r/g, '');
  const fm = text.match(/^---\n([\s\S]*?)\n---\n?/);
  const meta = {};
  for (const line of fm ? fm[1].split('\n') : []) {
    const i = line.indexOf(':');
    if (i > 0) meta[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  const body = text.slice(fm ? fm[0].length : 0).replace(/<!--[\s\S]*?-->/g, '');
  const sections = body.split(/^## +/m).slice(1).map(s => {
    const [head, ...rest] = s.split('\n');
    return { title: head.trim(), html: md(rest.join('\n')) };
  });
  return { meta, sections };
}

// Image fields take bare names from _shared/img ("kcat_4") or paths. A list ("kcat_2 kcat_3") picks one per load.
const pick = list => {
  const all = list.split(/[\s,]+/).filter(Boolean);
  const src = all[Math.floor(Math.random() * all.length)];
  return src.includes('/') ? src : `../_shared/img/${src}.webp`;
};

// Shared gradients and badges, referenced by the node art below
const DEFS = `<svg width="0" height="0" style="position:absolute" aria-hidden="true"><defs>
  <linearGradient id="face" x1="0" y1="0" x2="0" y2="1"><stop offset="0" class="f0"/><stop offset="1" class="f1"/></linearGradient>
  <radialGradient id="cloud" cx=".38" cy=".25" r=".85"><stop offset="0" class="c0"/><stop offset=".6" class="c1"/><stop offset="1" class="c2"/></radialGradient>
  <linearGradient id="g-ok" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#b3dc5a"/><stop offset="1" stop-color="#86b52c"/></linearGradient>
  <linearGradient id="g-err" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#d9393f"/><stop offset="1" stop-color="#a51d22"/></linearGradient>
  <linearGradient id="g-warn" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#f6c344"/><stop offset="1" stop-color="#d99a0b"/></linearGradient>
  <symbol id="ok" viewBox="0 0 34 34"><circle cx="17" cy="17" r="15.5" fill="url(#g-ok)" class="ring"/><path d="M10.5 17.5l4.5 4.5 8.5-9.5" fill="none" stroke="#fff" stroke-width="3.4" stroke-linecap="round" stroke-linejoin="round"/></symbol>
  <symbol id="err" viewBox="0 0 34 34"><circle cx="17" cy="17" r="15.5" fill="url(#g-err)" class="ring"/><path d="M11.5 11.5l11 11M22.5 11.5l-11 11" stroke="#fff" stroke-width="3.4" stroke-linecap="round"/></symbol>
  <symbol id="warn" viewBox="0 0 34 34"><circle cx="17" cy="17" r="15.5" fill="url(#g-warn)" class="ring"/><path d="M17 9.5V17l5 3" fill="none" stroke="#fff" stroke-width="3.4" stroke-linecap="round" stroke-linejoin="round"/></symbol>
  <symbol id="both" viewBox="0 0 60 24"><path d="M2 12l12-10v6h32V2l12 10-12 10v-6H14v6z" class="arrow"/></symbol>
</defs></svg>`;

const ART = {
  browser: `<g class="ln">
      <polygon points="12,24 16,21 98,21 94,24" class="top"/><polygon points="94,24 98,21 98,79 94,82" class="side"/>
      <rect x="12" y="24" width="82" height="58" rx="1.5" class="front"/>
      <path d="M13.5 24h79a1.5 1.5 0 0 1 1.5 1.5V36H12V25.5a1.5 1.5 0 0 1 1.5-1.5z" class="bar"/></g>
    <circle cx="19" cy="30" r="2.1" class="dot"/><circle cx="25.5" cy="30" r="2.1" class="dot"/><circle cx="32" cy="30" r="2.1" class="dot"/>
    <rect x="40" y="27.5" width="46" height="5" rx="2.5" class="url"/>
    <g class="txt"><rect x="20" y="44" width="40" height="5" rx="1.5"/><rect x="20" y="54" width="66" height="3" rx="1.5"/><rect x="20" y="61" width="60" height="3" rx="1.5"/><rect x="20" y="68" width="48" height="3" rx="1.5"/></g>`,
  network: `<path transform="translate(-4,0)" d="M30 76h52a17 17 0 0 0 1-34 24 24 0 0 0-46-6 19 19 0 0 0-7 40z" fill="url(#cloud)" class="ln"/>
    <path transform="translate(-4,0)" d="M41 40a19 19 0 0 1 30-6" class="shine"/>`,
  host: `<g class="ln">${[18, 41, 64].map(y => `
      <polygon points="18,${y} 25,${y - 5} 83,${y - 5} 76,${y}" class="top"/><polygon points="76,${y} 83,${y - 5} 83,${y + 13} 76,${y + 18}" class="side"/>
      <rect x="18" y="${y}" width="58" height="18" fill="url(#face)"/>`).join('')}</g>
    <g class="dot">${[27, 50, 73].map(y => `<circle cx="26" cy="${y}" r="2.3"/><rect x="50" y="${y - 1.5}" width="19" height="3" rx="1.5"/>`).join('')}</g>`,
};

// Lucide icons (ISC): monitor, sun, moon
const THEMES = {
  system: '<rect width="20" height="14" x="2" y="3" rx="2"/><path d="M8 21h8M12 17v4"/>',
  light: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/>',
  dark: '<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/>',
};

// system follows prefers-color-scheme, light and dark pin it via data-theme
function setTheme(t) {
  if (t === 'system') delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = t;
  try { localStorage.setItem('theme', t); } catch {}
  document.querySelectorAll('.theme button').forEach(b => b.setAttribute('aria-pressed', b.value === t));
}

function savedTheme() {
  try { return THEMES[localStorage.getItem('theme')] ? localStorage.getItem('theme') : 'system'; } catch { return 'system'; }
}

// What the server says about this response, in its Server-Timing header. Corium sets it on every error page:
//   corium  its version, for the note in the footer
//   reason  why this page shows: base64url JSON {what, who, eta, code, mode}
//   ray     the Cloudflare Ray ID of the request
// The pages are plain files, never server-side templates. Browsers only expose Server-Timing over HTTPS (and on
// localhost); elsewhere, in previews and on a direct visit the page shows without these.
function timing(name) {
  try {
    const e = performance.getEntriesByType('navigation')[0]?.serverTiming?.find(x => x.name === name);
    return e?.description || '';
  } catch { return ''; }
}

const rayId = () => { const r = timing('ray'); return /^[0-9a-f]{8,32}(-[A-Z]{3})?$/i.test(r) ? r : ''; };
const version = () => { const v = timing('corium'); return /^[0-9][0-9A-Za-z.+-]{0,30}$/.test(v) ? v : ''; };

function reason() {
  const raw = timing('reason');
  if (!/^[A-Za-z0-9_-]+$/.test(raw)) return null;
  try {
    const bin = atob(raw.replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(new TextDecoder().decode(Uint8Array.from(bin, c => c.charCodeAt(0))));
  } catch { return null; } // malformed, show the page without it
}

const etaText = iso => {
  const t = new Date(iso);
  if (isNaN(t)) return '';
  const when = t.toLocaleString(undefined, { weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
  const min = Math.round((t - Date.now()) / 60000);
  const rel = min <= 0 ? 'Any moment now.' : min < 90 ? `In about ${min} minutes.`
    : min < 2880 ? `In about ${Math.round(min / 60)} hours.` : `In about ${Math.round(min / 1440)} days.`;
  return `Expected back **${when}**. ${rel}`;
};

// The reason's texts replace the matching sections, or add them. Maintenance turns the page amber.
function applyReason(meta, sections, r) {
  if (!r) return;
  const put = (match, title, text, first) => {
    const s = sections.find(x => match.test(x.title));
    if (s) s.html = md(text);
    else sections[first ? 'unshift' : 'push']({ title, html: md(text) });
  };
  if (r.mode === 'maintenance') {
    meta.state = 'Maintenance';
    meta.down = meta.down || 'host';
    if (!/maint/i.test(meta.title || '')) meta.title = 'Scheduled maintenance';
  }
  if (r.code) meta.code = String(r.code);
  if (r.what) put(/what happened/i, 'What happened?', r.what, true);
  if (r.who) put(/who is affected/i, 'Who is affected?', r.who);
  if (r.eta && etaText(r.eta)) put(/when will it return/i, 'When will it return?', etaText(r.eta));
}

function render({ meta, sections }) {
  const state = meta.state || 'Offline';
  const tone = /maintenance/i.test(state) ? 'warn' : 'err';
  const nodes = [
    ['browser', 'You', 'Browser'],
    ['network', 'Edge network', 'Network'],
    ['host', meta.host || location.hostname || 'localhost', 'Host'],
  ];
  const rid = rayId();
  const now = new Date().toISOString().slice(0, 19).replace('T', ' ') + ' UTC';
  const sec = s => `<section><h2>${inline(s.title)}</h2>${s.html}</section>`;
  const [first, ...rest] = sections;
  const ver = version();
  const powered = `<a class="powered" href="https://github.com/Sanedish/corium" target="_blank" rel="noopener">Powered by Corium${ver ? ` (v${esc(ver)})` : ''}</a>`;
  const foot = [meta.org && esc(meta.org), meta.updated && `Updated <time>${esc(meta.updated)}</time>`, powered].filter(Boolean);
  const link = '<div class="link"><svg viewBox="0 0 60 24" aria-hidden="true"><use href="#both"/></svg></div>';
  const warn = meta.down && tone === 'warn';
  const who = (warn && meta.mascot_warn) || meta.mascot;
  const mascot = who && pick(who);
  const scene = meta.background && pick(meta.background);

  document.title = [meta.title, meta.code].filter(Boolean).join(' | ') || 'Error';
  document.getElementById('app').innerHTML = `
    <header><div class="wrap">
      ${mascot ? `<img class="mascot${warn && meta.mascot_warn ? ' warm' : ''}" src="${esc(mascot)}" alt="" aria-hidden="true">` : ''}
      <h1><span>Error${meta.code ? ` <span class="code">${esc(meta.code)}</span>` : ''}</span>
        <span class="ray">${rid ? `<span>Ray ID ${esc(rid)}</span>` : ''}<span>${now}</span>${+meta.code >= 500 ? '<span id="watch" hidden></span>' : ''}</span></h1>
      <p class="subtitle">${esc(meta.title || 'Details unavailable')}</p>
      <div class="theme" role="group" aria-label="Theme">${Object.entries(THEMES).map(([t, icon]) => `
        <button type="button" value="${t}" aria-label="${t[0].toUpperCase() + t.slice(1)}" title="${t[0].toUpperCase() + t.slice(1)}"aria-pressed="${t === savedTheme()}">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${icon}</svg>
        </button>`).join('')}
      </div>
    </div></header>
    ${meta.code ? `<section class="status"${scene ? ` data-scene="${esc(scene.split('/').pop().replace(/\.\w+$/, ''))}" style="--scene: url(${esc(JSON.stringify(scene))})"` : ''}>${DEFS}<div class="wrap">${nodes.map(([key, label, who]) => {
      const down = key === meta.down;
      return `<div class="node${down ? ` source ${tone}` : ''}">
        <div class="icon">
          <svg class="art" viewBox="0 0 110 96" aria-hidden="true">${ART[key]}</svg>
          <svg class="badge" viewBox="0 0 34 34" aria-hidden="true"><use href="#${down ? tone : 'ok'}"/></svg>
        </div>
        <div class="label">${esc(label)}</div>
        <div class="who">${who}</div>
        <div class="state">${down ? esc(state) : 'Working'}</div>
      </div>`;
    }).join(link)}</div></section>` : ''}
    <section class="text"><div class="wrap">
      <div class="col">${first ? sec(first) : ''}</div>
      <div class="col">${rest.map(sec).join('')}</div>
    </div></section>
    <footer><div class="wrap">${foot.map(s => `<span>${s}</span>`).join('')}</div></footer>`;
  document.querySelector('.theme').addEventListener('click', e => {
    const b = e.target.closest('button');
    if (b) setTheme(b.value);
  });
}

// 5xx pages re-request the original URL every 30s and reload once it answers 2xx again.
// ponytail: a page that recovers into a 4xx keeps polling. Cheap, so left as is.
function watch() {
  const el = document.getElementById('watch');
  const nav = performance.getEntriesByType('navigation')[0];
  // Served as 200 means a direct visit or a preview, not a live outage. Firefox and Safari report 0 and always poll.
  if (!el || new URLSearchParams(location.search).has('demo') || (nav?.responseStatus > 0 && nav.responseStatus < 500)) return;
  let left = 30;
  const show = text => { el.textContent = text; el.hidden = false; };
  const check = async () => {
    left = Infinity;
    show('Checking');
    try {
      const r = await fetch(location.href, { method: 'HEAD', cache: 'no-store' });
      if (r.ok) { show('Back online'); return location.reload(); }
    } catch {} // still down or offline
    left = 30;
    show(`Next check ${left}s`);
  };
  show(`Next check ${left}s`);
  setInterval(() => { if (--left <= 0) check(); else if (left < Infinity) show(`Next check ${left}s`); }, 1000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden && left < Infinity) left = 1; });
}

async function get(src) {
  try {
    const r = await fetch(src, { cache: 'no-cache' });
    return r.ok ? r.text() : '';
  } catch { return ''; } // file:// or offline
}

// <meta name=fallback> in index.html names a self-contained page shown instead when info.md cannot be loaded
async function fallback() {
  const src = document.querySelector('meta[name=fallback]')?.content;
  const html = src && await get(src);
  if (!html) return false;
  document.open(); document.write(html); document.close();
  return true;
}

async function load() {
  setTheme(savedTheme()); // before the fetches, so a pinned theme paints first
  const demo = new URLSearchParams(location.search).has('demo');
  const [site, page] = await Promise.all([get('../_shared/site.md'), demo && get('demo.md')]);
  const text = page || await get('info.md');
  if (!text && await fallback()) return;
  const { meta, sections } = text ? parse(text) : { meta: {}, sections: [] };
  const all = { ...parse(site).meta, ...Object.fromEntries(Object.entries(meta).filter(([, v]) => v)) };
  applyReason(all, sections, reason());
  render({ meta: all, sections });
  watch();
}

if (typeof module !== 'undefined') module.exports = { parse, pick, applyReason };
else load();
