# Auto-Chain Orchestration Future Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add reliable, context-aware auto-chain execution (tool dependencies like `{log:tool}`) with clear control, safe defaults, visible state, and deterministic recovery.

**Architecture:** Introduce a small orchestration subsystem that reads dependency relationships, compiles an execution graph per target/workflow, runs nodes with strict state transitions, and records every decision and result. Keep orchestration separate from parsing, rendering, and transport execution so failures are isolated and debuggable.

**Tech Stack:** CommonJS modules, existing `ToolRunner`, `TargetStore`, `WorkflowVerifier`, optional in-memory queue, persistent run metadata in `TargetStore`.

---

## 0. Terminology and Intent

The word you were reaching for is usually one of these:
- **SOP (Standard Operating Procedure)**
- **Algorithmic specification**
- **Executable runbook**

This plan is written as an SOP-style algorithmic runbook.

---

## 1. Preconditions (Do Before Any Code)

### 1.1 Freeze Scope
1. Open `local/hyper-target-panel/config/tools.json`.
2. Open `local/hyper-target-panel/config/workflows.json`.
3. Confirm initial MVP scope:
   - dependency-aware ordering only
   - no AI-driven inference
   - no parallel node execution in v1
   - no cross-target fan-out in v1
4. Write these scope locks into a comment block at top of new plan implementation checklist file.
5. Branch to next step:
   - If scope changed: update this plan first, then continue.
   - If scope unchanged: continue to 1.2.

### 1.2 Define Non-Negotiables
1. Declare invariants:
   - No chain step runs without a normalized target.
   - No dependent step runs unless upstream terminal state is `succeeded` or explicitly `allowed_on_failed_dependency`.
   - Every transition is persisted.
   - User can stop chain at any point.
2. Branch to next step:
   - If any invariant is disputed: resolve before coding.
   - If all accepted: continue to 2.0.

---

## 2. Data Contract Design

### 2.1 Define Chain Session Schema
1. Create `docs/specs/auto-chain-session-schema.md`.
2. Define fields:
   - `chain_id`
   - `target`
   - `origin` (`workflow`, `manual`, `suggested`)
   - `created_at`, `started_at`, `ended_at`
   - `status` (`queued`, `running`, `paused`, `failed`, `succeeded`, `canceled`)
   - `nodes[]` with `node_id`, `tool_id`, `depends_on[]`, `status`, `attempt`, timestamps
3. Add exact allowed values and transition matrix.
4. Branch:
   - If any field is ambiguous: clarify now.
   - If unambiguous: continue 2.2.

### 2.2 Define Node Execution Result Contract
1. Specify run result payload required from `ToolRunner`:
   - `started`, `transport`, `target`, `toolId`, `logFile`, `error`, `sessionUid/pid`
2. Specify parser completion signal contract:
   - `parse_complete` event with `target`, `toolId`, counts, timestamp
3. Specify timeout contract:
   - command dispatch timeout
   - parser idle timeout
4. Branch:
   - If any producer cannot emit required fields: add adapter task before 3.0.
   - Else continue 3.0.

---

## 3. Dependency Graph Compiler

### 3.1 Build Static Dependency Extractor
1. Implement dependency extraction from each tool command (`{log:<tool_id>}` tokens).
2. Produce map:
   - `tool_id -> depends_on[]`
3. Validate each dependency references a real tool.
4. Branch:
   - On missing dependency: mark compile error and stop.
   - On success: continue 3.2.

### 3.2 Build Workflow Graph Compiler
1. Input: workflow tool list + dependency map.
2. Build DAG nodes and edges.
3. Detect cycles with deterministic algorithm (Kahn or DFS with colors).
4. Emit topological order if acyclic.
5. Branch:
   - If cycle found: fail compile, display exact cycle path.
   - If acyclic: continue 3.3.

### 3.3 Build Execution Plan Object
1. Create immutable plan object:
   - ordered nodes
   - dependency metadata
   - policy flags per node (`skip_on_failed_dep`, `max_retries`)
2. Persist draft chain session with status `queued`.
3. Branch:
   - Persist failed: abort + UI error.
   - Persist success: continue 4.0.

---

## 4. Orchestrator Runtime (Sequential MVP)

### 4.1 Create Orchestrator Service
1. Add `ChainOrchestrator` module.
2. Add internal queue keyed by `target`.
3. Guarantee single active chain per target in v1.
4. Branch:
   - If another chain active for target: return `already_running`.
   - Else enqueue and continue 4.2.

### 4.2 Start Chain Session
1. Mark chain `running`.
2. Emit UI event `chain_started`.
3. Select first runnable node:
   - node with dependencies all terminal and passing policy.
4. Branch:
   - If none runnable and all terminal: finalize chain.
   - If none runnable and non-terminal remain: fail chain as deadlock.
   - If runnable node exists: continue 4.3.

### 4.3 Execute One Node
1. Mark node `running`.
2. Invoke `ToolRunner.launch` with target + tool.
3. Wait for start confirmation timeout.
4. Branch:
   - If not started: mark node `failed`, continue policy step 4.4.
   - If started: monitor parse/idle timeout and continue 4.4.

### 4.4 Resolve Node Terminal State
1. Determine node terminal state:
   - `succeeded`
   - `failed`
   - `canceled`
   - `timed_out`
2. Persist node terminal record.
3. Apply retry policy if configured and attempts remain.
4. Branch:
   - Retry eligible: re-enter 4.3 for same node.
   - Retry exhausted: continue 4.5.

### 4.5 Schedule Next Node
1. Recompute runnable set using latest terminal states.
2. If runnable node exists, execute next node (4.3).
3. If none runnable:
   - If all terminal: finalize chain (4.6).
   - Else fail chain as orchestration inconsistency.

### 4.6 Finalize Chain
1. Aggregate stats:
   - total, succeeded, failed, skipped, duration
2. Set chain status:
   - `succeeded` if all required nodes succeeded
   - `failed` otherwise
3. Emit UI event `chain_completed`.
4. Persist summary row.
5. End.

---

## 5. Context-Aware Policy Layer (Controlled Complexity)

### 5.1 Define Policy Inputs
1. Inputs allowed in v1.1:
   - prior node status
   - finding counts by kind
   - known open ports
   - tool/category metadata
2. Inputs not allowed yet:
   - LLM suggestions
   - arbitrary regex on raw logs in scheduler
3. Branch:
   - If requested input is outside list: backlog it; do not add now.
   - Else continue 5.2.

### 5.2 Define Gating Rules DSL (Minimal)
1. Add rule structure per node:
   - `requires.findings.domains.min = 1`
   - `requires.ports.any_of = [80,443,8080]`
2. Evaluate rules before node becomes runnable.
3. Branch:
   - Rule unmet: mark node `skipped_unmet_prereq`.
   - Rule met: node may run.

### 5.3 Define Quality Boost Rules
1. Encode examples:
   - `httpx_from_subfinder` requires `subfinder` output lines > 0
   - `nuclei_from_httpx` requires `httpx_from_subfinder` success + URL count > 0
2. Emit explanatory reason strings into run metadata.
3. Branch:
   - If explanation missing: treat as bug.
   - If explanation present: continue.

---

## 6. UI and Control Surface

### 6.1 Add Chain Controls
1. Add sidebar controls:
   - `Start Chain`
   - `Pause`
   - `Resume`
   - `Cancel`
2. Disable controls based on chain state matrix.
3. Branch:
   - Invalid action requested: show deterministic message.
   - Valid action: dispatch orchestrator command.

### 6.2 Add Chain Timeline View
1. Show per-node row:
   - tool name
   - status
   - start/end timestamps
   - reason on skip/fail
2. Add drilldown for error and command.
3. Branch:
   - Missing data: show `unknown` with warning badge.
   - Data present: normal render.

### 6.3 Add Recommendations Panel (Non-Autonomous)
1. Show “automation hints” as suggestions, not forced runs.
2. Example:
   - “Run `httpx_from_subfinder` after `subfinder` to reduce false positives before nuclei.”
3. Branch:
   - User accepts suggestion: compile and run chain.
   - User dismisses: no action.

---

## 7. Reliability and Recovery

### 7.1 Crash Recovery
1. On plugin startup, query chains with `running` state.
2. For each:
   - mark as `failed_recovered`
   - append recovery note
3. Optional later: resume heuristics.

### 7.2 Idempotency Guards
1. Prevent duplicate enqueue by `(target, workflow_id, active_status)` unique guard.
2. If duplicate request arrives:
   - return existing chain id.

### 7.3 Timeouts and Heartbeats
1. Define defaults:
   - start timeout
   - parse idle timeout
   - max chain duration
2. Persist heartbeat timestamps.
3. If heartbeat stale: transition to timed-out terminal.

---

## 8. Testing Plan (Deterministic)

### 8.1 Unit Tests
1. Dependency extractor tests.
2. Cycle detection tests.
3. Runnable node selection tests.
4. Gating rules evaluation tests.
5. Status transition matrix tests.

### 8.2 Integration Tests
1. Simulated workflow: success path.
2. Simulated upstream failure with skip policy.
3. Timeout path.
4. Cancel while node running.
5. Recovery on startup path.

### 8.3 Manual Runtime Tests
1. Start workflow from sidebar.
2. Observe node-by-node progression.
3. Force one node failure.
4. Verify downstream behavior matches policy.
5. Restart Hyper mid-chain and verify recovery behavior.

---

## 9. Rollout Strategy

### 9.1 Feature Flag
1. Add `auto_chain_enabled` config flag default `false`.
2. Hide controls until enabled.

### 9.2 Phased Enablement
1. Phase A: dependency compile + warnings only.
2. Phase B: manual start chain sequential runtime.
3. Phase C: policy-gated context-aware skips.
4. Phase D: retries + resume options.

### 9.3 Observability
1. Add structured logs for every transition.
2. Add chain summary telemetry counters (local only).
3. Keep last N chain sessions visible in UI.

---

## 10. File-Level Execution Map (When You Implement)

1. Create `local/hyper-target-panel/lib/orchestration/ChainOrchestrator.js`.
2. Create `local/hyper-target-panel/lib/orchestration/GraphCompiler.js`.
3. Create `local/hyper-target-panel/lib/orchestration/PolicyEngine.js`.
4. Create `local/hyper-target-panel/lib/orchestration/TransitionGuard.js`.
5. Create `local/hyper-target-panel/lib/orchestration/ChainEvents.js`.
6. Modify `local/hyper-target-panel/lib/ToolRunner.js` to support node-level callbacks.
7. Modify `local/hyper-target-panel/lib/storage/TargetStore.js` for chain tables/records.
8. Modify `local/hyper-target-panel/index.js` for controls + timeline UI.
9. Add tests under `local/hyper-target-panel/__tests__/orchestration/`.
10. Update `docs/plans/` with implementation progress checklist.

---

## 11. Definition of Done

A build is done only when all are true:
1. Graph compile rejects invalid workflows with explicit reason.
2. Sequential chain executes deterministically with persisted states.
3. Dependent tools never run before prerequisites.
4. UI can start/pause/resume/cancel and reflects real state.
5. Failures are explicit and diagnosable.
6. Tests pass (unit + integration + syntax checks).
7. Feature can be disabled with one flag.

---

## 12. Immediate Next Actions (No Code Yet)

1. Review this plan and trim/expand scope.
2. Confirm v1 excludes parallel node execution.
3. Confirm desired default policy on dependency failure:
   - strict skip downstream (recommended)
   - allow optional downstream
4. Once confirmed, generate an implementation plan from this future plan and execute in phases.
