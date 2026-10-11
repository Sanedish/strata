'use strict';
/* Strata layout: resizable side panels. Every view laid out as .split with an inline "1fr <N>px" template (the
   request inspector, file/folder inspector, gauges + log asides, blacklist and alert panels) gets a grip on the
   divider: drag it to widen or narrow the panel, double-click to reset, or focus it and use the arrow keys.
   Widths are remembered per view and panel in this browser. Loaded last; app.js re-renders #main on every poll,
   so the saved width is re-applied after each render (a microtask, before the browser paints). */

(() => {
  const KEY = 'strata:paneWidths';
  const MIN_PANEL = 220, MIN_MAIN = 380, STEP = 24;
  let widths = {};
  try { widths = JSON.parse(localStorage.getItem(KEY)) || {}; } catch { /* private mode: defaults only */ }
  const saveWidths = () => { try { localStorage.setItem(KEY, JSON.stringify(widths)); } catch { /* ignore */ } };
  const zoom = () => (typeof zoomNow === 'number' && zoomNow > 0 ? zoomNow : 1);
  const viewName = () => (typeof S === 'object' && S && S.view) || 'view';

  // "1fr 340px" -> ['1fr', 340], "240px minmax(0, 1fr) 380px" -> ['240px minmax(0, 1fr)', 380]: the last column is
  // the resizable panel; anything else (one column, fr/fr grids) is left alone
  function parse(tpl) {
    const m = /^(.*\S)\s+(\d+(?:\.\d+)?)px$/.exec(String(tpl || '').trim());
    return m && /fr\b/.test(m[1]) ? [m[1], +m[2]] : null;
  }
  function clamp(split, w) {
    const max = Math.max(MIN_PANEL, split.clientWidth - MIN_MAIN);
    return Math.round(Math.min(max, Math.max(MIN_PANEL, w)));
  }
  function setWidth(split, w) {
    split.style.gridTemplateColumns = split.dataset.paneMain + ' ' + w + 'px';
    const g = split.querySelector(':scope > .pane-grip');
    // the grip covers the 2 px divider plus 8 px of the panel's padding, clear of the main column's scrollbar
    if (g) { g.style.right = (w - 8) + 'px'; g.setAttribute('aria-valuenow', String(w)); }
  }

  function fit(split) {
    if (split.dataset.paneKey) return; // already handled (same element, not re-rendered)
    const p = parse(split.style.gridTemplateColumns);
    if (!p || split.children.length < 2) return;
    const [main, def] = p;
    // the default width tells panels of one view apart (Requests with / without the inspector); a split whose default
    // follows the window size names its panel instead (data-pane), so the saved width survives a resize
    split.dataset.paneKey = viewName() + ':' + (split.dataset.pane || def);
    split.dataset.paneMain = main;
    split.dataset.paneDef = String(def);
    const g = document.createElement('div');
    g.className = 'pane-grip';
    g.tabIndex = 0;
    g.title = 'Drag to resize this panel · double-click to reset';
    g.setAttribute('role', 'separator');
    g.setAttribute('aria-orientation', 'vertical');
    g.setAttribute('aria-label', 'Resize side panel');
    split.appendChild(g);
    const saved = widths[split.dataset.paneKey];
    setWidth(split, saved ? clamp(split, saved) : def);
  }
  function fitAll() { document.querySelectorAll('#main .split').forEach(fit); }

  function commit(split, w) {
    const key = split.dataset.paneKey, def = +split.dataset.paneDef;
    if (w === def) delete widths[key]; else widths[key] = w;
    saveWidths();
  }

  let drag = null;
  document.addEventListener('pointerdown', (e) => {
    const g = e.target.closest && e.target.closest('.pane-grip');
    if (!g || e.button !== 0) return;
    const split = g.parentElement;
    e.preventDefault();
    drag = { g, split, x0: e.clientX, w0: parseFloat(g.getAttribute('aria-valuenow')) || +split.dataset.paneDef, w: null };
    g.classList.add('drag');
    document.documentElement.classList.add('pane-dragging');
    try { g.setPointerCapture(e.pointerId); } catch { /* old browser */ }
  });
  document.addEventListener('pointermove', (e) => {
    if (!drag) return;
    // pointer coordinates are screen px; the layout is zoomed (same conversion as the column grips in app.js)
    drag.w = clamp(drag.split, drag.w0 + (drag.x0 - e.clientX) / zoom());
    setWidth(drag.split, drag.w);
  });
  const end = () => {
    if (!drag) return;
    const { g, split, w } = drag;
    drag = null;
    g.classList.remove('drag');
    document.documentElement.classList.remove('pane-dragging');
    if (w != null) commit(split, w);
  };
  document.addEventListener('pointerup', end);
  document.addEventListener('pointercancel', end);
  window.addEventListener('blur', end);

  document.addEventListener('dblclick', (e) => {
    const g = e.target.closest && e.target.closest('.pane-grip');
    if (!g) return;
    const split = g.parentElement, def = +split.dataset.paneDef;
    setWidth(split, def);
    commit(split, def);
  });
  document.addEventListener('keydown', (e) => {
    const g = e.target.closest && e.target.closest('.pane-grip');
    if (!g || !['ArrowLeft', 'ArrowRight', 'Home'].includes(e.key)) return;
    e.preventDefault();
    e.stopPropagation();
    const split = g.parentElement, cur = parseFloat(g.getAttribute('aria-valuenow')) || +split.dataset.paneDef;
    const w = e.key === 'Home' ? +split.dataset.paneDef : clamp(split, cur + (e.key === 'ArrowLeft' ? STEP : -STEP));
    setWidth(split, w);
    commit(split, w);
  }, true);

  const main = document.getElementById('main');
  if (main) new MutationObserver(fitAll).observe(main, { childList: true, subtree: true });
  window.addEventListener('resize', () => document.querySelectorAll('#main .split[data-pane-key]').forEach((s) => {
    const w = parseFloat((s.querySelector(':scope > .pane-grip') || {}).getAttribute?.('aria-valuenow')) || +s.dataset.paneDef;
    setWidth(s, clamp(s, w));
  }));
  fitAll();
})();
