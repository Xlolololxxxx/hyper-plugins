'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { resolveJcPlan } = require('../../lib/jc/JcRegistry');

const TOOLS_PATH = '/home/xlo/.hyper_plugins/local/hyper-target-panel/config/tools.json';
const ADAPTER_DIR = '/home/xlo/.hyper_plugins/local/hyper-target-panel/lib/jc-adapters';

function isInternalActionTool(tool) {
  const cmd = String((tool && tool.command) || '').trim();
  if (!cmd) return true;
  if (cmd === '{target}') return true;
  if (/^https?:\/\//i.test(cmd)) return true;
  return false;
}

test('every adapter-routed tool uses a dedicated module named by tool id', () => {
  const tools = JSON.parse(fs.readFileSync(TOOLS_PATH, 'utf8'));
  const parseable = tools.filter((tool) => !isInternalActionTool(tool));

  const adapterTools = [];
  for (const tool of parseable) {
    const plan = resolveJcPlan(tool);
    if (plan && plan.engine === 'adapter') adapterTools.push({ tool, plan });
  }

  assert.equal(adapterTools.length, 36);

  for (const { tool, plan } of adapterTools) {
    assert.equal(plan.parser, tool.id, `expected dedicated parser for ${tool.id}`);
    const modFile = path.join(ADAPTER_DIR, `${tool.id}.js`);
    assert.equal(fs.existsSync(modFile), true, `missing adapter module ${modFile}`);
  }
});

