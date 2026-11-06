/* motion.js - UI motion on top of app.js and control.js without changing them: it wraps renderOverlay, openSheet,
   closeSheet, render, renderVitals and ACT.themeCycle. Overlays and sheets animate in and out (a closed one stays
   behind for a moment as an inert, id-less "ghost"), view switches slide in, changed live numbers roll, dismissed
   toasts slide away and close their gap, theme changes cross-fade. The look lives in motion.css.
   Settings › Reduce motion (html.reduce-motion) turns all of it off. Load after every other script. */
(() => {
  const still = () => document.documentElement.classList.contains('reduce-motion');
  const MOTION = ['m-enter', 'm-leave'];
  // what an overlay child "is", so a re-render of the same overlay does not replay its entrance
  const keyOf = (el) => {
    const cls = (n) => [...n.classList].filter((c) => !MOTION.includes(c)).join('.');
    const p = el.firstElementChild;
    return cls(el) + '|' + el.id + '|' + (p ? cls(p) + '|' + (p.getAttribute('aria-label') || '') : '');
  };
  const replay = (el, cls) => { el.classList.remove(cls); void el.offsetWidth; el.classList.add(cls); };
  const settle = (el) => Promise.race([
    Promise.all(el.getAnimations({ subtree: true }).map((a) => a.finished.catch(() => {}))),
    new Promise((r) => setTimeout(r, 700)),
  ]);

  // a closed overlay, put back as a non-interactive copy that plays m-leave and removes itself
  function ghost(el, parent, before) {
    if (still() || el.querySelector('iframe, video, audio, embed, object')) return; // re-inserting media reloads it
    el.querySelectorAll('[id]').forEach((n) => n.removeAttribute('id'));
    el.querySelectorAll('[role], [aria-modal], [data-act]').forEach((n) => { n.removeAttribute('role'); n.removeAttribute('aria-modal'); n.removeAttribute('data-act'); });
    el.removeAttribute('data-act');
    el.classList.remove('m-enter');
    el.classList.add('m-leave');
    el.inert = true;
    el.setAttribute('aria-hidden', 'true');
    parent.insertBefore(el, before || null);
    settle(el).then(() => el.remove());
  }

  /* ---- #overlay: menus, palette, dialogs, help, the file preview, the folder picker, the drop zone */
  const renderOverlay0 = renderOverlay;
  renderOverlay = function () {
    const box = document.getElementById('overlay');
    const before = new Map();
    for (const el of box.children) if (!el.classList.contains('m-leave')) before.set(keyOf(el), el);
    const r = renderOverlay0.apply(this, arguments);
    const now = new Set();
    for (const el of box.children) {
      const k = keyOf(el);
      now.add(k);
      if (!before.has(k) && !still()) el.classList.add('m-enter');
    }
    for (const [k, el] of before) if (!now.has(k)) ghost(el, box);
    return r;
  };

  /* ---- #sheet forms (control.js). A sheet ghost keeps id="sheet" for its styles, so the live sheet goes in front of it */
  const isGhost = (el) => el && el.classList.contains('m-leave');
  const openSheet0 = openSheet, closeSheet0 = closeSheet;
  closeSheet = function () {
    const el = document.getElementById('sheet');
    if (isGhost(el)) return;
    const r = closeSheet0.apply(this, arguments);
    if (el && !el.isConnected) ghost(el, document.body);
    return r;
  };
  ACT.sheetClose = closeSheet;
  openSheet = function () {
    const r = openSheet0.apply(this, arguments);
    const live = [...document.querySelectorAll('body > #sheet')].find((n) => !isGhost(n));
    if (live) {
      const first = [...document.querySelectorAll('body > #sheet')].find(isGhost);
      if (first && first.compareDocumentPosition(live) & Node.DOCUMENT_POSITION_FOLLOWING) {
        const f = document.activeElement;
        document.body.insertBefore(live, first);
        if (f && live.contains(f)) f.focus();
      }
      if (!still()) live.classList.add('m-enter');
    }
    return r;
  };

  /* ---- live numbers: a vitals / KPI value that changed rolls into place */
  function ticks() {
    if (still()) return;
    document.querySelectorAll('.vital .val, .kpis .val').forEach((el) => {
      const t = el.textContent;
      if (el._mv !== undefined && el._mv !== t) replay(el, 'm-tick');
      el._mv = t;
    });
  }
  const renderVitals0 = renderVitals;
  renderVitals = function () { const r = renderVitals0.apply(this, arguments); ticks(); return r; };

  /* ---- view switches */
  let viewTimer = 0;
  const render0 = render;
  render = function () {
    const main = document.getElementById('main');
    const from = main && main.dataset.view;
    const r = render0.apply(this, arguments);
    if (main && main.dataset.view !== from && !still()) {
      replay(main, 'm-view');
      clearTimeout(viewTimer);
      // only the switch animates: later polls that add top-level blocks must not
      viewTimer = setTimeout(() => main.classList.remove('m-view'), 600);
    }
    ticks();
    return r;
  };

  /* ---- toasts: a removed toast slides out, then its slot shrinks so the stack closes up smoothly */
  const toasts = document.getElementById('toasts');
  if (toasts && window.MutationObserver) {
    new MutationObserver((list) => {
      if (still()) return;
      for (const m of list) {
        for (const n of m.removedNodes) {
          if (n.nodeType !== 1 || !n.classList.contains('toast') || n.classList.contains('m-leave')) continue;
          n.classList.add('m-leave');
          n.inert = true;
          toasts.insertBefore(n, m.nextSibling && m.nextSibling.parentNode === toasts ? m.nextSibling : null);
          const h = n.offsetHeight;
          n.animate([{ opacity: 1, transform: 'none' }, { opacity: 0, transform: 'translateX(24px) scale(.96)' }],
            { duration: 180, easing: 'cubic-bezier(.5, 0, .75, 0)', fill: 'forwards' }).finished
            .then(() => n.animate([{ height: h + 'px', marginTop: '0px' }, { height: '0px', marginTop: '-8px', paddingTop: '0px', paddingBottom: '0px' }],
              { duration: 160, easing: 'ease-out', fill: 'forwards' }).finished)
            .catch(() => {})
            .then(() => n.remove());
        }
      }
    }).observe(toasts, { childList: true });
  }

  /* ---- sidebar categories: entries unfold from the header and fold back into it, the chevron turns.
     Folding puts the removed entries back as inert ghosts until they have shrunk; the next renderNav morph drops them anyway */
  const OUT = 'cubic-bezier(.16, 1, .3, 1)';
  const grow = (el, open, delay) => {
    const cs = getComputedStyle(el);
    const full = { height: el.offsetHeight + 'px', paddingTop: cs.paddingTop, paddingBottom: cs.paddingBottom, opacity: 1 };
    const none = { height: '0px', paddingTop: '0px', paddingBottom: '0px', opacity: 0 };
    el.classList.add('m-fold');
    const a = el.animate(open ? [none, full] : [full, none], { duration: open ? 320 : 220, delay, easing: open ? OUT : 'cubic-bezier(.4, 0, .2, 1)', fill: open ? 'backwards' : 'both' });
    return a.finished.catch(() => {}).then(() => el.classList.remove('m-fold'));
  };
  const navToggle0 = ACT.navToggle;
  ACT.navToggle = function (h) {
    const group = () => document.getElementById('navgrp-' + h);
    const kids = (g) => [...g.querySelectorAll(':scope > .nav-child')];
    const before = group() && !still() ? kids(group()) : [];
    const r = navToggle0.apply(this, arguments);
    const g = group();
    if (!g || still()) return r;
    const open = g.querySelector('.nav-drop')?.getAttribute('aria-expanded') === 'true';
    const chev = g.querySelector('.nav-drop .chev');
    if (chev) chev.animate([{ transform: `rotate(${open ? -90 : 90}deg)` }, { transform: 'none' }], { duration: 300, easing: OUT });
    if (open) {
      kids(g).forEach((el, i) => grow(el, true, i * 18));
      g.animate([{ paddingBottom: '0px' }, { paddingBottom: getComputedStyle(g).paddingBottom }], { duration: 320, easing: OUT });
    } else if (before.length && !before[0].isConnected) {
      const pad = getComputedStyle(g).paddingBottom;
      before.forEach((el) => {
        el.querySelectorAll('[data-act]').forEach((n) => n.removeAttribute('data-act'));
        el.removeAttribute('data-act');
        el.inert = true;
        g.appendChild(el);
      });
      Promise.all(before.map((el, i) => grow(el, false, (before.length - 1 - i) * 12))).then(() => before.forEach((el) => el.remove()));
      g.animate([{ paddingBottom: '4px' }, { paddingBottom: pad }], { duration: 220 + before.length * 12, easing: 'ease-out' });
    }
    return r;
  };

  /* ---- theme: cross-fade the whole page */
  const themeCycle0 = ACT.themeCycle;
  ACT.themeCycle = function () {
    if (!document.startViewTransition || still() || matchMedia('(prefers-reduced-motion: reduce)').matches) return themeCycle0.apply(this, arguments);
    document.startViewTransition(() => themeCycle0.apply(this, arguments));
  };
})();
