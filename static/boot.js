'use strict';
/* Applies the saved appearance before the first paint (theme, accent, density, corners, font, zoom). Loaded in <head>
   of every page; the dashboard's Settings › Appearance writes these keys, the instance's own accent is the default. */
(() => {
  const r = document.documentElement;
  const get = (k, d) => { try { const v = localStorage.getItem('strata:' + k); return v == null ? d : JSON.parse(v); } catch { return d; } };
  const meta = document.querySelector('meta[name="strata-accent"]');
  const inst = meta && /^#[0-9a-f]{6}$/i.test(meta.content) ? meta.content : null;
  const theme = get('theme', 'auto');
  const dark = theme === 'dark' || (theme === 'auto' && window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches);
  r.dataset.theme = dark ? 'dark' : 'light';
  const accent = get('accent', null) || inst;
  if (accent && /^#[0-9a-f]{6}$/i.test(accent)) r.style.setProperty('--color-accent', accent);
  r.dataset.density = get('density', 'normal');
  r.dataset.radius = String(get('radius', 0));
  r.dataset.font = get('font', 'archivo');
  const z = get('zoom', 1);
  if (typeof z === 'number' && z !== 1 && z >= 0.5 && z <= 3) { r.style.zoom = String(z); r.style.setProperty('--ui-zoom', String(z)); }
})();
