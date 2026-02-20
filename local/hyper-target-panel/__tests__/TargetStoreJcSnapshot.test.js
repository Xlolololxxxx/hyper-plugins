'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const TargetStore = require('../lib/storage/TargetStore');

function mkTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'tp-jc-'));
}

test('stores jc snapshot in target logs directory', () => {
  const dir = mkTempDir();
  const store = new TargetStore({ baseDir: dir, forceJson: true });

  store.storeJcSnapshot('Example.com', [{ x: 1 }], {
    toolId: 'dig-any',
    runId: 'run123',
    jcParser: 'dig',
    logFile: '/tmp/sample.log',
  });

  const logsDir = path.join(dir, 'targets', 'example.com', 'logs');
  const files = fs.readdirSync(logsDir);
  assert.equal(files.length, 1);
  const payload = JSON.parse(fs.readFileSync(path.join(logsDir, files[0]), 'utf8'));
  assert.equal(payload.target, 'example.com');
  assert.equal(payload.toolId, 'dig-any');
  assert.equal(payload.parser, 'dig');
});
