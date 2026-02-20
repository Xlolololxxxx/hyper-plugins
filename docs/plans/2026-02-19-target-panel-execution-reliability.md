# Target Panel Execution Reliability Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make sidebar and popup tool launches reliably execute commands in a separate tab/window, while enforcing normalized `set_target` behavior and persistent per-target storage.

**Architecture:** Refactor `ToolRunner` into target normalization, command rendering, and execution strategy components, then add a fallback chain (`hyper_new_tab` -> `external_terminal` -> `detached_shell`) with explicit run-state recording in SQLite. Keep `hyper-recon-menu` focused on detection/UI dispatch and move target/runs persistence into a DB-backed store with legacy JSON import.

**Tech Stack:** CommonJS Node modules, Hyper plugin APIs (`window.rpc`, `window.store`), `better-sqlite3`, `child_process`, Jest for unit/integration logic tests.

---

### Task 1: Add Test Harness For Target Panel

**Files:**
- Modify: `package.json`
- Create: `local/hyper-target-panel/jest.config.cjs`
- Create: `local/hyper-target-panel/__tests__/setup-globals.test.js`

**Step 1: Write the failing test**

```js
'use strict';

test('window globals are available for target-panel tests', () => {
  expect(global.window).toBeDefined();
  expect(global.window.rpc).toBeDefined();
});
```

**Step 2: Run test to verify it fails**

Run: `npx jest local/hyper-target-panel/__tests__/setup-globals.test.js -c local/hyper-target-panel/jest.config.cjs`
Expected: FAIL because Jest config and globals are not defined yet.

**Step 3: Write minimal implementation**

```js
// jest.config.cjs
module.exports = {
  testEnvironment: 'node',
  setupFilesAfterEnv: ['<rootDir>/__tests__/setup-env.js'],
};
```

```js
// __tests__/setup-env.js
global.window = {
  rpc: { emit: jest.fn() },
  store: { getState: jest.fn(), dispatch: jest.fn() }
};
```

**Step 4: Run test to verify it passes**

Run: `npx jest local/hyper-target-panel/__tests__/setup-globals.test.js -c local/hyper-target-panel/jest.config.cjs`
Expected: PASS.

**Step 5: Commit**

```bash
git add package.json local/hyper-target-panel/jest.config.cjs local/hyper-target-panel/__tests__
git commit -m "test: add target-panel jest harness"
```

### Task 2: Extract and Test Target Normalization

**Files:**
- Create: `local/hyper-target-panel/lib/TargetNormalizer.js`
- Create: `local/hyper-target-panel/__tests__/TargetNormalizer.test.js`
- Modify: `local/hyper-target-panel/index.js`
- Modify: `local/hyper-target-panel/lib/ToolRunner.js`

**Step 1: Write the failing test**

```js
'use strict';

const { normalizeTarget } = require('../lib/TargetNormalizer');

test('normalizes URL input to host only', () => {
  expect(normalizeTarget('https://Example.com/path?q=1')).toBe('example.com');
});

test('keeps ipv4 and strips port', () => {
  expect(normalizeTarget('10.10.10.10:8443')).toBe('10.10.10.10');
});
```

**Step 2: Run test to verify it fails**

Run: `npx jest local/hyper-target-panel/__tests__/TargetNormalizer.test.js -c local/hyper-target-panel/jest.config.cjs`
Expected: FAIL because module does not exist.

**Step 3: Write minimal implementation**

```js
'use strict';

function normalizeTarget(raw) {
  if (!raw || typeof raw !== 'string') return null;
  let value = raw.trim();
  value = value.replace(/^https?:\/\//i, '');
  value = value.split(/[/?#]/)[0];
  value = value.replace(/:\d+$/, '');
  value = value.replace(/\/+$/, '');
  if (!value) return null;
  return /^\d+\.\d+\.\d+\.\d+$/.test(value) ? value : value.toLowerCase();
}

module.exports = { normalizeTarget };
```

**Step 4: Run test to verify it passes**

Run: `npx jest local/hyper-target-panel/__tests__/TargetNormalizer.test.js -c local/hyper-target-panel/jest.config.cjs`
Expected: PASS.

**Step 5: Commit**

```bash
git add local/hyper-target-panel/lib/TargetNormalizer.js local/hyper-target-panel/__tests__/TargetNormalizer.test.js local/hyper-target-panel/index.js local/hyper-target-panel/lib/ToolRunner.js
git commit -m "feat: centralize target normalization"
```

### Task 3: Introduce SQLite Persistence Layer With Legacy Import

**Files:**
- Create: `local/hyper-target-panel/lib/storage/Database.js`
- Create: `local/hyper-target-panel/lib/storage/migrations.js`
- Create: `local/hyper-target-panel/lib/storage/LegacyImporter.js`
- Create: `local/hyper-target-panel/__tests__/Database.test.js`
- Modify: `local/hyper-target-panel/index.js`
- Modify: `local/hyper-target-panel/lib/OutputProcessor.js`

**Step 1: Write the failing test**

```js
'use strict';

const Database = require('../lib/storage/Database');

test('creates target and stores run row', () => {
  const db = new Database(':memory:');
  const targetId = db.upsertTarget('example.com');
  const runId = db.insertRun({ targetId, toolId: 'nmap', status: 'queued' });
  const run = db.getRun(runId);
  expect(run.status).toBe('queued');
});
```

**Step 2: Run test to verify it fails**

Run: `npx jest local/hyper-target-panel/__tests__/Database.test.js -c local/hyper-target-panel/jest.config.cjs`
Expected: FAIL because DB layer is missing.

**Step 3: Write minimal implementation**

```js
'use strict';
const Database = require('better-sqlite3');

class TargetStore {
  constructor(file) { this.db = new Database(file); this.init(); }
  init() { this.db.exec('CREATE TABLE IF NOT EXISTS targets (...)'); }
  upsertTarget(target) { /* insert or get */ }
  insertRun(run) { /* insert run */ }
  getRun(id) { /* select */ }
}

module.exports = TargetStore;
```

**Step 4: Run test to verify it passes**

Run: `npx jest local/hyper-target-panel/__tests__/Database.test.js -c local/hyper-target-panel/jest.config.cjs`
Expected: PASS.

**Step 5: Commit**

```bash
git add local/hyper-target-panel/lib/storage local/hyper-target-panel/__tests__/Database.test.js local/hyper-target-panel/index.js local/hyper-target-panel/lib/OutputProcessor.js
git commit -m "feat: add sqlite persistence and legacy import"
```

### Task 4: Refactor Command Rendering And Protocol Resolution

**Files:**
- Create: `local/hyper-target-panel/lib/CommandRenderer.js`
- Create: `local/hyper-target-panel/__tests__/CommandRenderer.test.js`
- Modify: `local/hyper-target-panel/lib/ToolRunner.js`

**Step 1: Write the failing test**

```js
'use strict';

const { renderCommand } = require('../lib/CommandRenderer');

test('prefers https when 443 is present', () => {
  const cmd = renderCommand('nikto -h http://{target}', { target: 'a.com', ports: [443] });
  expect(cmd).toContain('https://a.com');
});
```

**Step 2: Run test to verify it fails**

Run: `npx jest local/hyper-target-panel/__tests__/CommandRenderer.test.js -c local/hyper-target-panel/jest.config.cjs`
Expected: FAIL because renderer is missing.

**Step 3: Write minimal implementation**

```js
'use strict';

function renderCommand(template, ctx) {
  const hasTls = (ctx.ports || []).map(String).includes('443');
  let cmd = template;
  if (cmd.includes('http://{target}') && hasTls) cmd = cmd.replace('http://{target}', 'https://{target}');
  return cmd.replace(/{target}/g, ctx.target);
}

module.exports = { renderCommand };
```

**Step 4: Run test to verify it passes**

Run: `npx jest local/hyper-target-panel/__tests__/CommandRenderer.test.js -c local/hyper-target-panel/jest.config.cjs`
Expected: PASS.

**Step 5: Commit**

```bash
git add local/hyper-target-panel/lib/CommandRenderer.js local/hyper-target-panel/__tests__/CommandRenderer.test.js local/hyper-target-panel/lib/ToolRunner.js
git commit -m "feat: add command renderer with protocol resolution"
```

### Task 5: Implement Execution Strategy Manager With Fallback Chain

**Files:**
- Create: `local/hyper-target-panel/lib/execution/HyperTabStrategy.js`
- Create: `local/hyper-target-panel/lib/execution/ExternalTerminalStrategy.js`
- Create: `local/hyper-target-panel/lib/execution/DetachedShellStrategy.js`
- Create: `local/hyper-target-panel/lib/execution/ExecutionStrategyManager.js`
- Create: `local/hyper-target-panel/__tests__/ExecutionStrategyManager.test.js`
- Modify: `local/hyper-target-panel/lib/ToolRunner.js`

**Step 1: Write the failing test**

```js
'use strict';

const Manager = require('../lib/execution/ExecutionStrategyManager');

test('falls back to external terminal when hyper strategy fails', async () => {
  const manager = new Manager([
    { name: 'hyper_new_tab', launch: jest.fn().mockResolvedValue({ started: false, error: 'no session' }) },
    { name: 'external_terminal', launch: jest.fn().mockResolvedValue({ started: true, transport: 'external_terminal', pid: 123 }) }
  ]);
  const res = await manager.launch({ command: 'echo hi' });
  expect(res.transport).toBe('external_terminal');
});
```

**Step 2: Run test to verify it fails**

Run: `npx jest local/hyper-target-panel/__tests__/ExecutionStrategyManager.test.js -c local/hyper-target-panel/jest.config.cjs`
Expected: FAIL because manager/strategies do not exist.

**Step 3: Write minimal implementation**

```js
'use strict';

class ExecutionStrategyManager {
  constructor(strategies) { this.strategies = strategies; }
  async launch(ctx) {
    let lastError = null;
    for (const strategy of this.strategies) {
      const result = await strategy.launch(ctx);
      if (result && result.started) return result;
      lastError = result && result.error;
    }
    return { started: false, transport: 'none', error: lastError || 'all strategies failed' };
  }
}

module.exports = ExecutionStrategyManager;
```

**Step 4: Run test to verify it passes**

Run: `npx jest local/hyper-target-panel/__tests__/ExecutionStrategyManager.test.js -c local/hyper-target-panel/jest.config.cjs`
Expected: PASS.

**Step 5: Commit**

```bash
git add local/hyper-target-panel/lib/execution local/hyper-target-panel/__tests__/ExecutionStrategyManager.test.js local/hyper-target-panel/lib/ToolRunner.js
git commit -m "feat: add execution strategy fallback manager"
```

### Task 6: Add Popup `Set Target` And Unified Launch Payload

**Files:**
- Modify: `local/hyper-recon-menu/index.js`
- Modify: `local/hyper-target-panel/index.js`
- Create: `local/hyper-target-panel/__tests__/selector-payload.test.js`

**Step 1: Write the failing test**

```js
'use strict';

test('popup selector payload includes set-target action metadata', () => {
  const payload = buildSelectorPayload({ target: 'https://A.com/path', type: 'url' });
  expect(payload.actions.map(a => a.id)).toContain('set_target');
  expect(payload.target).toBe('a.com');
});
```

**Step 2: Run test to verify it fails**

Run: `npx jest local/hyper-target-panel/__tests__/selector-payload.test.js -c local/hyper-target-panel/jest.config.cjs`
Expected: FAIL until selector payload helper/action is added.

**Step 3: Write minimal implementation**

```js
const actions = [{ id: 'set_target', label: 'Set Target' }].concat(toolActions);
window.dispatchEvent(new CustomEvent('hyper-target-panel:open-tool-selector', {
  detail: { target: normalizeTarget(matchText), type, actions }
}));
```

**Step 4: Run test to verify it passes**

Run: `npx jest local/hyper-target-panel/__tests__/selector-payload.test.js -c local/hyper-target-panel/jest.config.cjs`
Expected: PASS.

**Step 5: Commit**

```bash
git add local/hyper-recon-menu/index.js local/hyper-target-panel/index.js local/hyper-target-panel/__tests__/selector-payload.test.js
git commit -m "feat: add popup set-target action and unified selector payload"
```

### Task 7: Surface Run Status And Errors In Sidebar UI

**Files:**
- Modify: `local/hyper-target-panel/index.js`
- Modify: `local/hyper-target-panel/lib/ToolRunner.js`
- Create: `local/hyper-target-panel/__tests__/run-status-view.test.js`

**Step 1: Write the failing test**

```js
'use strict';

test('renders failed run message when strategy chain fails', () => {
  const state = makeState({ runs: [{ status: 'failed', error: 'all strategies failed' }] });
  const ui = renderRunStatus(state);
  expect(ui).toContain('all strategies failed');
});
```

**Step 2: Run test to verify it fails**

Run: `npx jest local/hyper-target-panel/__tests__/run-status-view.test.js -c local/hyper-target-panel/jest.config.cjs`
Expected: FAIL until run-status rendering exists.

**Step 3: Write minimal implementation**

```js
if (latestRun.status === 'failed') {
  return `Run failed (${latestRun.transport}): ${latestRun.error}`;
}
```

**Step 4: Run test to verify it passes**

Run: `npx jest local/hyper-target-panel/__tests__/run-status-view.test.js -c local/hyper-target-panel/jest.config.cjs`
Expected: PASS.

**Step 5: Commit**

```bash
git add local/hyper-target-panel/index.js local/hyper-target-panel/lib/ToolRunner.js local/hyper-target-panel/__tests__/run-status-view.test.js
git commit -m "feat: expose run status and error details in panel"
```

### Task 8: End-to-End Verification And Cleanup

**Files:**
- Modify (if needed): `docs/plans/2026-02-19-target-panel-execution-reliability.md`
- Modify (if needed): `AGENTS.md` (only if test command docs need update)

**Step 1: Run targeted tests**

Run: `npx jest local/hyper-target-panel/__tests__ -c local/hyper-target-panel/jest.config.cjs`
Expected: PASS.

**Step 2: Run repository syntax check**

Run: `find local -name "*.js" -print0 | xargs -0 -I {} node -c {}`
Expected: no output, exit code 0.

**Step 3: Manual runtime checks in Hyper**

Run and verify:
- Click sidebar tool with current target -> opens separate tab/window and runs command.
- Click recon icon, choose preset -> command launches and status shows `running`.
- Use popup `Set Target` on URL with scheme/path -> sidebar target becomes normalized host.
- Restart Hyper -> target and per-target history/runs persist.

Expected: all checks pass.

**Step 4: Final commit**

```bash
git add local/hyper-target-panel local/hyper-recon-menu package.json docs/plans/2026-02-19-target-panel-execution-reliability.md
git commit -m "feat: harden target-panel execution and target persistence"
```
