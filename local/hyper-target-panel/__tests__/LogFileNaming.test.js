'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { getLogExtForTool, buildLogFileName } = require('../lib/LogFileNaming');

test('uses txt for gobuster tools to avoid unsupported format errors', () => {
  assert.equal(getLogExtForTool({ id: 'gobuster_dir', parser: 'gobuster' }), 'txt');
  assert.equal(buildLogFileName('example.com', { id: 'gobuster_dir', parser: 'gobuster' }), 'example.com_gobuster_dir.txt');
});

test('uses log by default for other tools', () => {
  assert.equal(getLogExtForTool({ id: 'nmap', parser: 'nmap' }), 'log');
  assert.equal(buildLogFileName('example.com', { id: 'nmap', parser: 'nmap' }), 'example.com_nmap.log');
});
