# Target Panel Command Overhaul Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace brittle command behavior with typed command definitions, correct scheme handling, and real local wordlist selection.

**Architecture:** Centralize behavior in target-panel config + renderer metadata. Keep recon-menu as detector/event source only. Add UI state for scheme override and wordlist selection modal. Implement deterministic filtering from local `~/Wordlists` names.

**Tech Stack:** Node.js CommonJS, Hyper plugin React APIs, node:test.

---

### Task 1: Lock command rendering contract

**Files:**
- Modify: `local/hyper-target-panel/__tests__/CommandRenderer.test.js`
- Modify: `local/hyper-target-panel/lib/CommandRenderer.js`

1. Write failing tests for `input_mode` based rendering and scheme override behavior.
2. Run tests and verify failures.
3. Implement minimal renderer changes.
4. Run tests to green.

### Task 2: Add wordlist catalog + tests

**Files:**
- Create: `local/hyper-target-panel/lib/WordlistCatalog.js`
- Create: `local/hyper-target-panel/__tests__/WordlistCatalog.test.js`

1. Write failing tests for scanning and category mapping.
2. Run tests and verify failures.
3. Implement catalog builder with deterministic category labels.
4. Run tests to green.

### Task 3: Update target-panel UI flow

**Files:**
- Modify: `local/hyper-target-panel/index.js`

1. Add state for scheme override and wordlist modal.
2. Route tool launches needing wordlist through selector modal.
3. Add OVERRIDE controls and all-caps wordlist sections.
4. Keep selector actions and tool list separated.
5. Run syntax check on modified plugin file.

### Task 4: Overhaul tool definitions and workflows

**Files:**
- Modify: `local/hyper-target-panel/config/tools.json`
- Modify: `local/hyper-target-panel/config/workflows.json`

1. Replace weak/invalid commands with validated definitions.
2. Add `input_mode` and `wordlist` metadata.
3. Align workflows to available tools and `{log:tool}` dependencies.
4. Run JSON parse validation.

### Task 5: Final verification

**Files:**
- Verify: `local/hyper-target-panel/**`

1. Run command renderer and wordlist catalog tests.
2. Run existing target-panel tests.
3. Run repo syntax check command for all plugins.
4. Summarize any residual risks.
