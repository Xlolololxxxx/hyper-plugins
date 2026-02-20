'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');

const tools = require('../config/tools.json');
const workflows = require('../config/workflows.json');
const { renderCommand } = require('../lib/CommandRenderer');
const { verifyWorkflows } = require('../lib/WorkflowVerifier');

function isInternal(tool) {
  return tool && tool.runner === 'internal';
}

test('tools config renders commands for Juice Shop target without unresolved placeholders', () => {
  const target = '127.0.0.1:42000';
  const unresolved = [];

  for (const tool of tools) {
    if (isInternal(tool)) continue;
    const cmd = renderCommand(tool.command, {
      target,
      tool,
      schemeOverride: 'http',
      logFile: '/tmp/tool.log',
      tempDir: '/tmp',
      wordlistFile: '/tmp/wordlist.txt',
      logPathByToolId: (toolId) => `/tmp/${toolId}.log`,
    });
    if (/\{(?:target|target_safe|log_file|wordlist_file|log:[a-zA-Z0-9_-]+)\}/.test(cmd)) {
      unresolved.push({ id: tool.id, command: cmd });
    }
  }

  assert.deepEqual(unresolved, []);
});

test('nuclei commands do not use interact.sh and include no-interact mode', () => {
  const nucleiTools = tools.filter((tool) => String(tool.id).startsWith('nuclei_'));
  assert.ok(nucleiTools.length >= 3);

  for (const tool of nucleiTools) {
    const command = String(tool.command || '');
    assert.equal(/interact\.sh|interactsh/i.test(command), false, `unexpected interact reference in ${tool.id}`);
    assert.equal(/\s-ni(\s|$)/.test(command), true, `missing -ni flag in ${tool.id}`);
  }
});

test('workflow references are valid and dependency order checks pass', () => {
  const report = verifyWorkflows(tools, workflows);
  assert.deepEqual(report.issues, []);
});

test('tool ids are unique', () => {
  const ids = tools.map((tool) => tool.id);
  const unique = new Set(ids);
  assert.equal(unique.size, ids.length);
});

test('tools config file remains valid JSON', () => {
  const resolved = path.join(__dirname, '..', 'config', 'tools.json');
  const raw = require('fs').readFileSync(resolved, 'utf8');
  assert.doesNotThrow(() => JSON.parse(raw));
});
