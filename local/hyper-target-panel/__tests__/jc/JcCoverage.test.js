'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

const { resolveJcPlan } = require('../../lib/jc/JcRegistry');

const TOOLS_PATH = '/home/xlo/.hyper_plugins/local/hyper-target-panel/config/tools.json';

function isInternalActionTool(tool) {
  const cmd = String((tool && tool.command) || '').trim();
  if (!cmd) return true;
  if (cmd === '{target}') return true;
  if (/^https?:\/\//i.test(cmd)) return true;
  return false;
}

test('all parseable tools resolve through jc or adapter engines', () => {
  const tools = JSON.parse(fs.readFileSync(TOOLS_PATH, 'utf8'));
  const parseable = tools.filter((tool) => !isInternalActionTool(tool));

  const unresolved = [];
  const builtins = [];
  const adapters = [];

  for (const tool of parseable) {
    const plan = resolveJcPlan(tool);
    if (!plan) {
      unresolved.push(tool.id);
      continue;
    }
    if (plan.engine === 'jc') builtins.push(tool.id);
    if (plan.engine === 'adapter') adapters.push(tool.id);
  }

  assert.deepEqual(unresolved, []);
  assert.equal(parseable.length, 42);
  assert.equal(builtins.length, 6);
  assert.equal(adapters.length, 36);
});

