import test from 'node:test';
import assert from 'node:assert/strict';
import {
  FULL_SWEEP_TTL,
  fingerprintOf,
  isSweepDue,
  markMissing,
  mergeRecord,
  needsProbe,
  probeTtl,
} from '../src/scan/scheduler.ts';
import type { PortRecord } from '../src/shared/types.ts';

function record(over: Partial<PortRecord> = {}): PortRecord {
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
    firstSeen: 1000,
    lastSeen: 1000,
    lastProbed: 1000,
    consecutiveStable: 0,
    ...over,
  };
}

test('fingerprint ignores timestamps but reacts to what is served', () => {
  const base = record({ http: { status: 200 }, meta: { title: 'App' } });
  const later = record({
    http: { status: 200 },
    meta: { title: 'App' },
    lastSeen: 99999,
    lastProbed: 99999,
    probeMs: 412,
  });
  assert.equal(fingerprintOf(base), fingerprintOf(later));

  const changed = record({ http: { status: 500 }, meta: { title: 'App' } });
  assert.notEqual(fingerprintOf(base), fingerprintOf(changed));
});

test('probe TTL backs off as a port proves stable, and is capped', () => {
  const first = probeTtl(record({ consecutiveStable: 0 }));
  const settled = probeTtl(record({ consecutiveStable: 4 }));
  const veteran = probeTtl(record({ consecutiveStable: 500 }));

  assert.ok(settled > first, 'stable ports should be checked less often');
  assert.ok(veteran <= 60_000, 'backoff must stay bounded');
  assert.equal(veteran, probeTtl(record({ consecutiveStable: 50 })), 'cap is flat');
});

test('non-http and dead ports get long TTLs', () => {
  assert.ok(probeTtl(record({ protocol: 'tcp' })) >= 120_000);
  assert.ok(probeTtl(record({ alive: false })) >= 300_000);
});

test('needsProbe always fires for never-probed or unclassified ports', () => {
  assert.equal(needsProbe(record({ lastProbed: 0 }), 1000), true);
  assert.equal(needsProbe(record({ protocol: 'unknown' }), 1000), true);
  // Freshly probed and stable: leave it alone.
  assert.equal(needsProbe(record({ lastProbed: 1000 }), 1500), false);
  // Past its TTL.
  assert.equal(needsProbe(record({ lastProbed: 1000 }), 100_000), true);
});

test('sweep TTL gates the expensive tier', () => {
  const t = 1_700_000_000_000;
  // A cache that has never completed a sweep must always run one.
  assert.equal(isSweepDue(0, t), true);
  assert.equal(isSweepDue(t, t + FULL_SWEEP_TTL - 1), false);
  assert.equal(isSweepDue(t, t + FULL_SWEEP_TTL), true);
});

test('merge preserves first-seen history and unions addresses', () => {
  const prev = record({ firstSeen: 500, addresses: ['127.0.0.1'] });
  const next = record({ firstSeen: 9000, addresses: ['::1'] });

  const merged = mergeRecord(prev, next, 9000);
  assert.equal(merged.firstSeen, 500);
  assert.deepEqual(merged.addresses.sort(), ['127.0.0.1', '::1']);
});

test('merge counts consecutive identical observations', () => {
  let prev = mergeRecord(undefined, record({ http: { status: 200 } }));
  assert.equal(prev.consecutiveStable, 0);

  prev = mergeRecord(prev, record({ http: { status: 200 } }));
  assert.equal(prev.consecutiveStable, 1);

  prev = mergeRecord(prev, record({ http: { status: 200 } }));
  assert.equal(prev.consecutiveStable, 2);

  // A change resets confidence.
  prev = mergeRecord(prev, record({ http: { status: 503 } }));
  assert.equal(prev.consecutiveStable, 0);
});

test('merge keeps process detail a probe-only pass did not collect', () => {
  const prev = record({ process: { pid: 42, projectName: 'acme' } });
  const merged = mergeRecord(prev, record({ process: undefined }));
  assert.equal(merged.process?.projectName, 'acme');
});

test('markMissing retires only ports that were actually searched', () => {
  const known = [
    record({ port: 3000, id: '3000' }),
    record({ port: 8021, id: '8021' }),
  ];

  // 3000 was searched and not found; 8021 was never looked at this pass.
  const changed = markMissing(known, new Set<number>(), new Set([3000]), 5000);

  assert.equal(changed.length, 1);
  assert.equal(changed[0]?.port, 3000);
  assert.equal(known[0]?.alive, false);
  assert.equal(known[1]?.alive, true, 'unsearched ports must not be declared dead');
});

test('markMissing leaves ports that were seen alone', () => {
  const known = [record({ port: 3000 })];
  const changed = markMissing(known, new Set([3000]), new Set([3000]), 5000);
  assert.equal(changed.length, 0);
  assert.equal(known[0]?.alive, true);
});
