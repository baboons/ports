import test from 'node:test';
import assert from 'node:assert/strict';
import { SCREENSHOT_TTL, shouldCapture } from '../src/scan/capture.ts';
import type { HttpInfo, PortRecord } from '../src/shared/types.ts';

function record(http: HttpInfo | undefined, over: Partial<PortRecord> = {}): PortRecord {
  return {
    id: '3000',
    port: 3000,
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
    ...(http ? { http } : {}),
    meta: { title: 'Something' },
    ...over,
  };
}

test('a plain 2xx html page is captured', () => {
  assert.equal(
    shouldCapture(record({ status: 200, contentType: 'text/html; charset=utf-8' })),
    true,
  );
});

test('a redirect that resolves to 2xx on this machine is captured', () => {
  // The common dev-server shape: / -> /login or / -> /dashboard.
  assert.equal(
    shouldCapture(
      record({
        status: 302,
        finalStatus: 200,
        finalUrl: 'http://127.0.0.1:3000/dashboard',
        redirectTo: '/dashboard',
        contentType: 'text/html',
      }),
    ),
    true,
  );

  assert.equal(
    shouldCapture(record({ status: 301, finalStatus: 200, contentType: 'text/html' })),
    true,
  );
});

test('a redirect leaving this machine is never captured', () => {
  // fetchHead only follows within loopback, so a missing finalStatus on a 3xx
  // means the chain pointed somewhere external. Chrome would happily follow
  // it, so refusing here is what stops us photographing a public website.
  assert.equal(
    shouldCapture(record({ status: 302, redirectTo: 'https://example.com/', contentType: '' })),
    false,
  );
});

test('a redirect that lands on an error page is not captured', () => {
  assert.equal(
    shouldCapture(record({ status: 302, finalStatus: 404, contentType: 'text/html' })),
    false,
  );
});

test('plain error responses are not captured', () => {
  for (const status of [400, 401, 403, 404, 500, 502]) {
    assert.equal(shouldCapture(record({ status, contentType: 'text/html' })), false, `${status}`);
  }
});

test('non-html responses are not captured', () => {
  assert.equal(
    shouldCapture(record({ status: 200, contentType: 'application/json' })),
    false,
    'a JSON API is a wall of text, not a picture',
  );
});

test('non-http listeners and dead ports are not captured', () => {
  assert.equal(shouldCapture(record({ status: 200 }, { protocol: 'tcp' })), false);
  assert.equal(shouldCapture(record({ status: 200 }, { alive: false })), false);
  assert.equal(shouldCapture(record(undefined)), false);
});

test('an existing capture is reused until the page changes or the TTL passes', () => {
  const now = 1_000_000;
  const base = record({ status: 200, contentType: 'text/html' }, { fingerprint: 'abc' });

  const fresh = {
    ...base,
    screenshot: { hash: 'h', capturedAt: now - 1000, width: 640, height: 400, fingerprint: 'abc' },
  };
  assert.equal(shouldCapture(fresh, now), false, 'unchanged and recent');

  const changed = {
    ...base,
    screenshot: { hash: 'h', capturedAt: now - 1000, width: 640, height: 400, fingerprint: 'old' },
  };
  assert.equal(shouldCapture(changed, now), true, 'page changed');

  const stale = {
    ...base,
    screenshot: {
      hash: 'h',
      capturedAt: now - SCREENSHOT_TTL - 1,
      width: 640,
      height: 400,
      fingerprint: 'abc',
    },
  };
  assert.equal(shouldCapture(stale, now), true, 'past the TTL');
});
