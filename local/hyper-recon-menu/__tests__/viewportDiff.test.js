const test = require('node:test');
const assert = require('node:assert/strict');

const { diffVisibleRows } = require('../viewportDiff');

test('diffVisibleRows returns only changed/new/removed rows', () => {
  const prev = new Map([
    [100, { vr: 0, text: 'alpha' }],
    [101, { vr: 1, text: 'beta' }],
    [102, { vr: 2, text: 'gamma' }],
  ]);

  const next = new Map([
    [101, { vr: 0, text: 'beta' }],
    [102, { vr: 1, text: 'GAMMA' }],
    [103, { vr: 2, text: 'delta' }],
  ]);

  const diff = diffVisibleRows(prev, next);

  assert.deepEqual(diff.remove, [100]);
  assert.deepEqual(diff.update, [101, 102, 103]);
  assert.deepEqual(diff.keep, []);
});

test('diffVisibleRows keeps stable rows untouched', () => {
  const prev = new Map([
    [201, { vr: 0, text: 'same' }],
  ]);

  const next = new Map([
    [201, { vr: 0, text: 'same' }],
  ]);

  const diff = diffVisibleRows(prev, next);

  assert.deepEqual(diff.remove, []);
  assert.deepEqual(diff.update, []);
  assert.deepEqual(diff.keep, [201]);
});
