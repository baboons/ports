import test from 'node:test';
import assert from 'node:assert/strict';
import {
  emptyCuration,
  hideReasonFor,
  isHidden,
  parseRange,
  withHidden,
  withoutHidden,
} from '../src/config/curation.ts';
import type { PortRecord } from '../src/shared/types.ts';

function record(port: number, process?: PortRecord['process']): Pick<PortRecord, 'port' | 'process'> {
  return { port, ...(process ? { process } : {}) };
}

test('parseRange accepts sane ranges and rejects the rest', () => {
  assert.deepEqual(parseRange('44000-44999'), [44000, 44999]);
  assert.deepEqual(parseRange(' 100 - 200 '), [100, 200]);
  assert.equal(parseRange('200-100'), undefined, 'reversed');
  assert.equal(parseRange('0-100'), undefined, 'port 0');
  assert.equal(parseRange('1-70000'), undefined, 'out of range');
  assert.equal(parseRange('nonsense'), undefined);
});

test('an exact port rule hides only that port', () => {
  const curation = withHidden(emptyCuration(), 6463);
  assert.equal(hideReasonFor(record(6463), curation), 'port');
  assert.equal(hideReasonFor(record(6464), curation), undefined);
});

test('a range rule hides its whole span, inclusive', () => {
  const curation = { ...emptyCuration(), hiddenRanges: ['44000-44999'] };
  assert.equal(isHidden(record(44000), curation), true);
  assert.equal(isHidden(record(44500), curation), true);
  assert.equal(isHidden(record(44999), curation), true);
  assert.equal(isHidden(record(45000), curation), false);
});

test('a command rule matches the process name or full command, case-insensitively', () => {
  const curation = { ...emptyCuration(), hiddenCommands: ['discord'] };

  assert.equal(hideReasonFor(record(1, { pid: 1, name: 'Discord Helper' }), curation), 'command');
  assert.equal(
    hideReasonFor(record(2, { pid: 2, command: '/Applications/Discord.app/x' }), curation),
    'command',
  );
  assert.equal(hideReasonFor(record(3, { pid: 3, name: 'node' }), curation), undefined);
  // No process info at all must not match everything.
  assert.equal(hideReasonFor(record(4), curation), undefined);
});

test('un-hiding removes a port rule but leaves broader rules alone', () => {
  // A range the user wrote by hand is a deliberate statement; one small button
  // must not silently rewrite it.
  const curation = {
    ...emptyCuration(),
    hiddenPorts: [44100],
    hiddenRanges: ['44000-44999'],
  };

  const after = withoutHidden(curation, 44100);
  assert.deepEqual(after.hiddenPorts, []);
  assert.deepEqual(after.hiddenRanges, ['44000-44999']);
  assert.equal(
    hideReasonFor(record(44100), after),
    'range',
    'still hidden, and the reason says why',
  );
});

test('hiding the same port twice does not duplicate it', () => {
  let curation = withHidden(emptyCuration(), 3000);
  curation = withHidden(curation, 3000);
  assert.deepEqual(curation.hiddenPorts, [3000]);
});

test('hidden ports stay sorted, so the config file reads sensibly', () => {
  let curation = emptyCuration();
  for (const port of [8080, 3000, 44450]) curation = withHidden(curation, port);
  assert.deepEqual(curation.hiddenPorts, [3000, 8080, 44450]);
});

test('an empty curation hides nothing', () => {
  const curation = emptyCuration();
  assert.equal(isHidden(record(3000, { pid: 1, name: 'node' }), curation), false);
});
