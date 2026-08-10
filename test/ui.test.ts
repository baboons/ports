import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseHTML } from 'linkedom';

const uiDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src', 'ui');

/**
 * Boot the real index.html and app.js inside a DOM, with a stubbed EventSource
 * we can drive. This exercises the actual shipped UI rather than a copy of its
 * logic, so filter and render regressions show up here.
 */
async function boot(records: unknown[]) {
  const html = await readFile(path.join(uiDir, 'index.html'), 'utf8');
  const script = await readFile(path.join(uiDir, 'app.js'), 'utf8');
  const { window, document } = parseHTML(html);

  const listeners: Record<string, ((e: { data: string }) => void) | null> = {};

  class StubEventSource {
    onopen: (() => void) | null = null;
    onerror: (() => void) | null = null;
    set onmessage(fn: (e: { data: string }) => void) {
      listeners['message'] = fn;
    }
    constructor(_url: string) {
      queueMicrotask(() => this.onopen?.());
    }
  }

  const store = new Map<string, string>();
  Object.assign(window, {
    EventSource: StubEventSource,
    localStorage: {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => void store.set(k, v),
    },
    requestAnimationFrame: (fn: () => void) => setTimeout(fn, 0),
    matchMedia: () => ({ matches: false }),
    fetch: () => Promise.resolve({ ok: true }),
  });

  // The module runs against globals, matching how a browser loads it.
  const fn = new Function(
    'window',
    'document',
    'localStorage',
    'EventSource',
    'requestAnimationFrame',
    'fetch',
    script,
  );
  fn(
    window,
    document,
    window.localStorage,
    StubEventSource,
    window.requestAnimationFrame,
    window.fetch,
  );

  listeners['message']?.({
    data: JSON.stringify({
      type: 'snapshot',
      records,
      progress: { phase: 'done', scanned: 0, total: 0, found: 0, startedAt: 0, done: true },
    }),
  });

  // Let the queued render frame run.
  await new Promise((r) => setTimeout(r, 10));
  return { document, window };
}

function server(port: number, status: number, over: Record<string, unknown> = {}) {
  return {
    id: String(port),
    port,
    addresses: ['127.0.0.1'],
    probedAddress: '127.0.0.1',
    alive: true,
    protocol: 'http',
    tier: 'lsof',
    stale: false,
    isSelf: false,
    firstSeen: 1,
    lastSeen: 1,
    lastProbed: 1,
    consecutiveStable: 0,
    http: { status },
    meta: { title: `Server ${port}` },
    ...over,
  };
}

test('4xx and 5xx servers are hidden by default', async () => {
  const { document } = await boot([
    server(3000, 200),
    server(3001, 404),
    server(3002, 500),
    server(3003, 302),
  ]);

  const rows = document.querySelectorAll('#board .row');
  const ports = [...rows].map((r) => r.getAttribute('data-port'));

  assert.deepEqual(ports, ['3000', '3003'], 'only 2xx/3xx should be listed');
});

test('hidden servers are announced rather than silently dropped', async () => {
  const { document } = await boot([server(3000, 200), server(3001, 404), server(3002, 503)]);

  const bar = document.getElementById('hidden-bar');
  assert.equal(bar?.hasAttribute('hidden'), false, 'the hidden-count bar must be shown');
  assert.match(document.getElementById('hidden-text')!.textContent!, /2 servers hidden/);
});

test('clicking the hidden bar reveals the error servers', async () => {
  const { document, window } = await boot([server(3000, 200), server(3001, 404)]);

  assert.equal(document.querySelectorAll('#board .row').length, 1);

  // Must be the DOM's own Event class, not Node's global one.
  document.getElementById('hidden-bar')!.dispatchEvent(new window.Event('click'));
  await new Promise((r) => setTimeout(r, 10));

  assert.equal(document.querySelectorAll('#board .row').length, 2);
  assert.equal(
    document.querySelector('.seg button[data-filter="err"]')?.getAttribute('aria-pressed'),
    'true',
    'the toggle must reflect the change',
  );
});

test('web servers render as real anchors pointing at the right origin', async () => {
  const { document } = await boot([server(5173, 200), server(8443, 200, { protocol: 'https' })]);

  const http = document.querySelector('#board .row[data-port="5173"]');
  assert.equal(http?.tagName, 'A');
  assert.equal(http?.getAttribute('href'), 'http://127.0.0.1:5173/');
  assert.equal(http?.getAttribute('target'), '_blank');

  const https = document.querySelector('#board .row[data-port="8443"]');
  assert.equal(https?.getAttribute('href'), 'https://127.0.0.1:8443/');
});

test('non-HTTP listeners go to their own drawer and are not links', async () => {
  const { document } = await boot([
    server(3000, 200),
    server(7265, 0, { protocol: 'tcp', http: undefined, meta: undefined }),
  ]);

  assert.equal(document.querySelectorAll('#board .row').length, 1);

  const drawer = document.getElementById('tcp-drawer');
  assert.equal(drawer?.hasAttribute('hidden'), false);

  const row = document.querySelector('#tcp-board .row[data-port="7265"]');
  assert.equal(row?.tagName, 'DIV', 'a non-HTTP listener must not be clickable');
});

test('dead ports move to history and are not shown as live', async () => {
  const { document } = await boot([server(3000, 200), server(4000, 200, { alive: false })]);

  assert.equal(document.querySelectorAll('#board .row').length, 1);
  assert.equal(document.getElementById('history-drawer')?.hasAttribute('hidden'), false);
  assert.equal(document.querySelectorAll('#history-board .row').length, 1);
});

test('favicon hashes resolve to the same-origin proxy route', async () => {
  const { document } = await boot([
    server(3000, 200, { meta: { title: 'App', faviconHash: 'abc123def4567890' } }),
  ]);

  const img = document.querySelector('#board .row[data-port="3000"] .mark img');
  assert.equal(img?.getAttribute('src'), '/api/favicon/abc123def4567890');
});
