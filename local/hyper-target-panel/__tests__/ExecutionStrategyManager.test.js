'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const ExecutionStrategyManager = require('../lib/execution/ExecutionStrategyManager');

test('falls back to external terminal when hyper strategy fails', async () => {
  const manager = new ExecutionStrategyManager([
    {
      name: 'hyper_new_tab',
      launch: async () => ({ started: false, error: 'no session created' })
    },
    {
      name: 'external_terminal',
      launch: async () => ({ started: true, transport: 'external_terminal', pid: 1234 })
    }
  ]);

  const result = await manager.launch({ command: 'echo hi' });
  assert.equal(result.started, true);
  assert.equal(result.transport, 'external_terminal');
});
