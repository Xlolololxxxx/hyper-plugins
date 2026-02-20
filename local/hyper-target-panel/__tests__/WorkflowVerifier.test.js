'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { verifyWorkflows, buildAutomationHints } = require('../lib/WorkflowVerifier');

test('verifies dependency ordering from {log:tool_id} references', () => {
  const tools = [
    { id: 'a', command: 'subfinder -d {target} -o {log_file}' },
    { id: 'b', command: 'httpx -l {log:a} -o {log_file}' }
  ];
  const workflows = [
    { id: 'wf', tools: ['a', 'b'] }
  ];
  const report = verifyWorkflows(tools, workflows);
  assert.equal(report.issues.length, 0);
});

test('builds automation hints for dependency chains', () => {
  const tools = [
    { id: 'subfinder', command: 'subfinder -o {log_file}' },
    { id: 'httpx', command: 'httpx -l {log:subfinder} -o {log_file}' }
  ];
  const hints = buildAutomationHints(tools);
  assert.ok(hints.some((h) => h.from === 'subfinder' && h.to === 'httpx'));
});
