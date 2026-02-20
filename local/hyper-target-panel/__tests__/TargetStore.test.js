'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const TargetStore = require('../lib/storage/TargetStore');

function mkTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'tp-store-'));
}

test('stores target runs and findings per target', () => {
  const dir = mkTempDir();
  const store = new TargetStore({ baseDir: dir });

  store.saveLastTarget('https://Example.com/path');
  assert.equal(store.loadLastTarget(), 'example.com');

  store.mergeFindings('example.com', { ports: ['80/tcp'], vulns: ['CVE-2023-1'], paths: [], domains: [] }, 'nmap');
  store.recordRun({ target: 'example.com', toolId: 'nmap', toolName: 'Nmap', status: 'started', transport: 'hyper_new_tab' });

  const data = store.getTargetData('example.com');
  assert.deepEqual(data.ports, ['80/tcp']);
  assert.equal(data.vulns[0], 'CVE-2023-1');
  assert.equal(store.getRecentRuns('example.com', 1)[0].tool_id, 'nmap');
});
