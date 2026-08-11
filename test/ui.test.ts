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
async function boot(records: unknown[], search = '', hostname = '127.0.0.1') {
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
    // linkedom has no location; the app reads it for ?view= overrides.
    location: { search, hostname, href: `http://${hostname}:7373/${search}` },
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
    'URLSearchParams',
    script,
  );
  fn(
    window,
    document,
    window.localStorage,
    StubEventSource,
    window.requestAnimationFrame,
    window.fetch,
    URLSearchParams,
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

test('links follow the host the board was opened on, not the probe address', async () => {
  // Served on 0.0.0.0 and opened from another machine: links must point at the
  // machine running the scanner, never the viewer's own loopback.
  // ?local=1 keeps loopback-bound rows visible; this test is about the href,
  // not the reachability filter.
  const { document } = await boot(
    [server(5173, 200, { probedAddress: '127.0.0.1' })],
    '?local=1',
    'nas.local',
  );

  assert.equal(
    document.querySelector('#board .row[data-port="5173"]')?.getAttribute('href'),
    'http://nas.local:5173/',
  );
});

test('an IPv6 host stays bracketed in generated links', async () => {
  const { document } = await boot([server(5173, 200)], '?local=1', '[fd00::1]');
  assert.equal(
    document.querySelector('#board .row[data-port="5173"]')?.getAttribute('href'),
    'http://[fd00::1]:5173/',
  );
});

test('loopback-only services are flagged when viewed remotely', async () => {
  const remote = await boot(
    [server(5173, 200, { addresses: ['127.0.0.1'] }), server(5174, 200, { addresses: ['0.0.0.0'] })],
    '?local=1',
    'nas.local',
  );
  const tags = [...remote.document.querySelectorAll('#board .row[data-port="5173"] .tag')].map(
    (t) => t.textContent,
  );
  assert.ok(tags.includes('loopback only'), 'a 127.0.0.1-only service is unreachable remotely');

  const wildcard = [...remote.document.querySelectorAll('#board .row[data-port="5174"] .tag')].map(
    (t) => t.textContent,
  );
  assert.ok(!wildcard.includes('loopback only'), 'a 0.0.0.0 bind is reachable');

  // Viewed locally the warning is noise.
  const local = await boot([server(5173, 200, { addresses: ['127.0.0.1'] })], '', '127.0.0.1');
  const localTags = [...local.document.querySelectorAll('#board .row .tag')].map(
    (t) => t.textContent,
  );
  assert.ok(!localTags.includes('loopback only'));
});

test('loopback-only servers are filtered out when viewed remotely', async () => {
  const { document } = await boot(
    [
      server(5173, 200, { addresses: ['127.0.0.1'] }),
      server(5174, 200, { addresses: ['0.0.0.0'] }),
    ],
    '',
    'nas.local',
  );

  const ports = [...document.querySelectorAll('#board .row')].map((r) =>
    r.getAttribute('data-port'),
  );
  assert.deepEqual(ports, ['5174'], 'only the reachable one is listed');
  assert.match(
    document.getElementById('hidden-text')!.textContent!,
    /unreachable from here/,
    'and the reason is stated',
  );
});

test('loopback-only servers are shown when viewed locally', async () => {
  // Everything is loopback on the machine itself; filtering by default there
  // would leave an empty board.
  const { document } = await boot([server(5173, 200, { addresses: ['127.0.0.1'] })], '', '127.0.0.1');
  assert.equal(document.querySelectorAll('#board .row').length, 1);
  assert.equal(document.getElementById('filter-local')?.hasAttribute('hidden'), true);
});

test('?local=1 overrides the remote default', async () => {
  const { document } = await boot(
    [server(5173, 200, { addresses: ['127.0.0.1'] })],
    '?local=1',
    'nas.local',
  );
  assert.equal(document.querySelectorAll('#board .row').length, 1);
});

test('curated records move to the hidden drawer with a restore control', async () => {
  const { document } = await boot([
    server(3000, 200),
    server(6463, 200, { hidden: true, hiddenBy: 'port' }),
  ]);

  const board = [...document.querySelectorAll('#board .row')].map((r) =>
    r.getAttribute('data-port'),
  );
  assert.deepEqual(board, ['3000'], 'hidden entries leave the main board');

  assert.equal(document.getElementById('curated-drawer')?.hasAttribute('hidden'), false);
  assert.equal(document.getElementById('count-curated')?.textContent, '1');
  assert.equal(
    document.querySelector('#curated-board .curate')?.textContent,
    '+',
    'the control offers to restore rather than hide again',
  );
});

test('the curate button is a sibling of the link, never nested inside it', async () => {
  const { document } = await boot([server(3000, 200)]);

  // A <button> inside an <a> is invalid and swallows the link's own clicks.
  assert.equal(document.querySelector('#board a.row button'), null);
  assert.ok(document.querySelector('#board .row-wrap > .curate'));
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

test('a captured page shows its thumbnail in the default list view', async () => {
  const { document } = await boot([
    server(3000, 200, {
      screenshot: { hash: 'aaaabbbbccccdddd', capturedAt: 1, width: 640, height: 400 },
    }),
    server(3001, 200),
  ]);

  // Regression guard: thumbnails used to exist only in grid view, so the
  // default screen never showed one.
  const thumb = document.querySelector('#board .row[data-port="3000"] img.thumb');
  assert.equal(thumb?.getAttribute('src'), '/api/screenshot/aaaabbbbccccdddd');
  assert.equal(
    document.querySelector('#board .row[data-port="3001"] img.thumb'),
    null,
    'a server without a capture gets no thumbnail',
  );
});

test('grid view renders cards with a shot or a placeholder', async () => {
  const { document } = await boot(
    [
      server(3000, 200, {
        screenshot: { hash: 'aaaabbbbccccdddd', capturedAt: 1, width: 640, height: 400 },
      }),
      server(3001, 200),
    ],
    '?view=grid',
  );

  assert.equal(document.getElementById('board')?.classList.contains('as-grid'), true);
  assert.equal(
    document.querySelector('#board .row[data-port="3000"] img.shot')?.getAttribute('src'),
    '/api/screenshot/aaaabbbbccccdddd',
  );
  assert.ok(
    document.querySelector('#board .row[data-port="3001"] .shot-placeholder'),
    'a server with no capture falls back to a placeholder',
  );
});

test('query parameters override saved view and filter state', async () => {
  const { document } = await boot([server(3000, 200), server(3001, 404)], '?errors=1');
  assert.equal(document.querySelectorAll('#board .row').length, 2, '?errors=1 reveals 4xx');
});

test('favicon hashes resolve to the same-origin proxy route', async () => {
  const { document } = await boot([
    server(3000, 200, { meta: { title: 'App', faviconHash: 'abc123def4567890' } }),
  ]);

  const img = document.querySelector('#board .row[data-port="3000"] .mark img');
  assert.equal(img?.getAttribute('src'), '/api/favicon/abc123def4567890');
});
