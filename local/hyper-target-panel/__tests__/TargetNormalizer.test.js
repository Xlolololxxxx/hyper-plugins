'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { normalizeTarget } = require('../lib/TargetNormalizer');

test('normalizes URL to host only and lowercases domain', () => {
  assert.equal(normalizeTarget('https://Example.com/path?q=1#x'), 'example.com');
});

test('strips port from ipv4 input', () => {
  assert.equal(normalizeTarget('10.10.10.10:8443'), '10.10.10.10');
});
