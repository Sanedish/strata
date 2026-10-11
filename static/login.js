// Match the interface scale chosen in Strata's Settings (saved by app.js) on the sign-in page too.
try {
  const z = JSON.parse(localStorage.getItem('strata:zoom') || '1');
  if (typeof z === 'number' && z >= 0.5 && z <= 3 && z !== 1) {
    document.documentElement.style.zoom = String(z);
    document.documentElement.style.setProperty('--z', String(z)); // zoom scales vh too; the CSS divides it back out
  }
} catch { /* storage blocked - stay at 100 % */ }
