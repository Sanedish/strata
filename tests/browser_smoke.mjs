/* Read-only UI smoke test against an isolated, already signed-in demo.
   node tests/browser_smoke.mjs http://127.0.0.1:8292 [screenshot-directory]
   Set STRATA_BROWSER to a Chromium executable on platforms without Microsoft Edge. */
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import assert from 'node:assert/strict';

const base = process.argv[2] || 'http://127.0.0.1:8292';
assert(['127.0.0.1', 'localhost', '[::1]'].includes(new URL(base).hostname), 'local test instances only');
const output = process.argv[3] && resolve(process.argv[3]);
if (output) await mkdir(output, { recursive: true });
const profile = await mkdtemp(join(tmpdir(), 'strata-browser-audit-'));
const exe = process.env.STRATA_BROWSER || 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const browser = spawn(exe, ['--headless=new', '--disable-gpu', '--remote-debugging-port=0',
  `--user-data-dir=${profile}`, '--window-size=1600,1000', 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true });
let ws;
const errors = [], failures = [], pages = [];
let current = 'boot';
try {
  const endpoint = await new Promise((done, reject) => {
    let stderr = '';
    const timer = setTimeout(() => reject(new Error('browser startup timed out')), 15000);
    browser.on('error', reject);
    browser.stderr.on('data', (data) => {
      stderr += data;
      const match = stderr.match(/DevTools listening on (ws:\/\/[^\s]+)/);
      if (match) { clearTimeout(timer); done(match[1]); }
    });
  });
  const host = new URL(endpoint).host;
  const tabs = await (await fetch(`http://${host}/json`)).json();
  ws = new WebSocket(tabs.find((tab) => tab.type === 'page').webSocketDebuggerUrl);
  await new Promise((done, reject) => { ws.onopen = done; ws.onerror = reject; });
  let id = 0;
  const pending = new Map();
  ws.onmessage = ({ data }) => {
    const message = JSON.parse(data);
    if (message.id) {
      const call = pending.get(message.id);
      if (call) { clearTimeout(call.timer); pending.delete(message.id); message.error ? call.reject(message.error) : call.done(message.result); }
    } else if (message.method === 'Runtime.exceptionThrown') {
      errors.push({ view: current, error: message.params.exceptionDetails.exception?.description || message.params.exceptionDetails.text });
    } else if (message.method === 'Network.responseReceived' && message.params.response.status >= 400 && message.params.response.url.startsWith(base)) {
      failures.push({ view: current, status: message.params.response.status, url: message.params.response.url });
    }
  };
  const call = (method, params = {}) => new Promise((done, reject) => {
    const next = ++id;
    const timer = setTimeout(() => { pending.delete(next); reject(new Error(method + ' timed out')); }, 15000);
    pending.set(next, { done, reject, timer });
    ws.send(JSON.stringify({ id: next, method, params }));
  });
  const evaluate = async (expression) => {
    const result = await call('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
    return result.result.value;
  };
  await call('Page.enable');
  await call('Runtime.enable');
  await call('Network.enable');
  await call('Page.navigate', { url: base });
  for (let n = 0; n < 80; n++) {
    if (await evaluate('typeof D !== "undefined" && !!D.me && !!D.stats')) break;
    await sleep(100);
  }
  assert(await evaluate('typeof D !== "undefined" && !!D.me && !!D.stats'), 'demo did not finish booting');
  const views = await evaluate('Object.keys(VIEWFN).filter(v => VIEWS[v] && canSeeView(v))');
  for (const mobile of [false, true]) {
    await call('Emulation.setDeviceMetricsOverride', { width: mobile ? 390 : 1600, height: mobile ? 844 : 1000, deviceScaleFactor: 1, mobile });
    for (const view of views) {
      current = `${mobile ? 'mobile' : 'desktop'}:${view}`;
      await evaluate(`go(${JSON.stringify(view)}); true`);
      await sleep(500);
      const page = await evaluate(`({ view: S.view, text: document.querySelector('#main').innerText.slice(0, 160),
        width: document.documentElement.clientWidth, scrollWidth: document.documentElement.scrollWidth,
        height: document.querySelector('#main').clientHeight })`);
      assert(page.text.trim(), current + ' rendered no content');
      assert.equal(page.view, view, current + ' navigation failed');
      assert(page.height > 100, current + ' content collapsed');
      pages.push({ name: current, ...page });
      if (output && ['summary', 'files', 'settings', 'insights', 'accounts'].includes(view)) {
        const shot = await call('Page.captureScreenshot', { format: 'png' });
        await writeFile(join(output, current.replace(':', '-') + '.png'), Buffer.from(shot.data, 'base64'));
      }
    }
  }
  current = 'keyboard:settings';
  await evaluate('go("settings"); true');
  await call('Input.dispatchKeyEvent', { type: 'keyDown', key: '/', code: 'Slash', windowsVirtualKeyCode: 191 });
  await call('Input.dispatchKeyEvent', { type: 'keyUp', key: '/', code: 'Slash', windowsVirtualKeyCode: 191 });
  await sleep(100);
  current = 'keyboard:modal';
  await evaluate(`(() => {
    const trigger = document.querySelector('[data-act="go"][data-arg="settings"]');
    trigger.focus();
    openSheet('Audit', 'Keyboard test', '<input id="audit-first" aria-label="Test input">', '<button class="btn">Test button</button>');
    document.querySelector('#sheet [data-act="sheetClose"]').focus();
  })()`);
  await call('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 });
  assert.equal(await evaluate('document.activeElement.id'), 'audit-first', 'Tab must wrap inside the modal');
  await call('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9, modifiers: 8 });
  assert.equal(await evaluate('document.activeElement.dataset.act'), 'sheetClose', 'Shift+Tab must wrap inside the modal');
  await evaluate('closeSheet(); true');
  assert.equal(await evaluate('document.activeElement.dataset.arg'), 'settings', 'closing a sheet must restore focus');
  current = 'uploads:cancellation';
  const uploads = await evaluate(`(async () => {
    const original = { post, upPump, xhrPut, setTimeout: window.setTimeout, inflight };
    const results = {};
    try {
      upPump = () => {};
      let release;
      const requests = [];
      post = (url) => { requests.push(url); return url.endsWith('/init') ? new Promise(resolve => release = resolve) : Promise.resolve({}); };
      const make = () => ({ size: UPCFG.chunk + 1, file: { name: 'audit', lastModified: 0, slice: () => ({}) }, mount: 1, dest: '/audit',
        status: 'queued', policy: 'rename', pending: [], xhrs: {}, prog: {}, tries: {}, sent: 0, done: 0, chunk: 4, sess: { id: 'old', chunks: 2 } });
      const u = make();
      const work = startUpload(u);
      u.status = 'cancelled'; u.file = null;
      release({ id: 'cancelled-init', path: '/audit', received: [], chunk: 4, chunks: 2 });
      await work;
      results.cancelInit = u.status === 'cancelled' && requests.includes('/api/upload/cancelled-init/abort') && inflight === original.inflight;
      const callbacks = [], timers = [];
      xhrPut = (url, body, progress, done) => { callbacks.push(done); return { abort() {} }; };
      window.setTimeout = fn => { timers.push(fn); return 1; };
      const retry = make(); retry.status = 'uploading';
      sendChunk(retry, 0); callbacks.shift()(500, { error: 'temporary' });
      retry.status = 'cancelled'; timers.shift()();
      results.cancelRetry = retry.pending.length === 0 && inflight === original.inflight;
      const expired = make(); expired.status = 'uploading';
      sendChunk(expired, 0); sendChunk(expired, 1);
      callbacks.shift()(404, {}); callbacks.shift()(200, {});
      results.staleChunk = expired.status === 'queued' && expired.sess === null && inflight === original.inflight;
    } finally { post = original.post; upPump = original.upPump; xhrPut = original.xhrPut; window.setTimeout = original.setTimeout; inflight = original.inflight; }
    return results;
  })()`);
  for (const [name, passed] of Object.entries(uploads)) assert(passed, 'upload regression: ' + name);
  current = 'connection:failure-and-recovery';
  const connection = await evaluate(`(async () => {
    const original = { get, setTimeout: window.setTimeout, online };
    try {
      window.setTimeout = () => 0;
      D.meAt = Date.now();
      get = async (url) => { if (url === '/api/live') throw new Error('Network unavailable'); return original.get(url); };
      await pollLive();
      const offline = !online;
      get = original.get;
      await pollLive();
      return { offline, recovered: online };
    } finally { get = original.get; window.setTimeout = original.setTimeout; online = original.online; }
  })()`);
  assert(connection.offline && connection.recovered, 'connection indicator must reflect failure and recovery');
  const report = { pages, errors, failures, uploads, connection, modalKeyboard: true };
  if (output) await writeFile(join(output, 'browser-results.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify({ views: views.length, pages: pages.length, errors, failures, uploads, connection, modalKeyboard: true,
    overflow: pages.filter((page) => page.scrollWidth > page.width + 1).map((page) => page.name) }, null, 2));
  assert.equal(errors.length, 0, 'uncaught browser exceptions');
  assert.equal(failures.length, 0, 'failed local HTTP responses');
} finally {
  if (ws) ws.close();
  browser.kill();
  await new Promise((done) => browser.exitCode !== null ? done() : browser.once('exit', done));
  for (let retry = 0; retry < 10; retry++) {
    try { await rm(profile, { recursive: true, force: true }); break; } catch { await sleep(100); }
  }
}
