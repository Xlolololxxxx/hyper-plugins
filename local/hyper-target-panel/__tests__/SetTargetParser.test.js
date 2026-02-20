'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { extractSetTarget } = require('../lib/SetTargetParser');

test('extracts simple set_target argument', () => {
  assert.equal(extractSetTarget('set_target example.com\n'), 'example.com');
});

test('extracts quoted set_target argument', () => {
  assert.equal(extractSetTarget("set_target 'https://Example.com/path?q=1'"), 'https://Example.com/path?q=1');
});

test('extracts first argument in chained command', () => {
  assert.equal(extractSetTarget('set_target app.example.com; echo done'), 'app.example.com');
});
