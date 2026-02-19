# Target Panel Execution Reliability Design

Date: 2026-02-19
Scope: `local/hyper-target-panel`, `local/hyper-recon-menu`

## Goals
- Make tool execution from sidebar and popup menu reliably run.
- Preserve separate command execution context (new tab/window), not copy-paste behavior.
- Add explicit `Set Target` support in popup and keep sidebar target editable.
- Normalize/sanitize targets consistently for per-target persistent storage.
- Improve architecture for dynamic, resilient execution with visible run status/errors.

## Non-Goals
- Redesign visual style of current panels.
- Replace all existing parser behavior in this phase.

## Problem Summary
Current flow reaches command generation and log watcher startup, but execution often does not dispatch to a real terminal session. The present queue/session coupling depends on brittle Hyper event behavior and can silently fail after preset selection.

## Approach Options Considered
1. Event-first reliable dispatch with fallback chain (recommended)
- Keep Hyper tab execution as preferred path.
- Validate that a real session/tab was created before marking success.
- Fallback to external terminal launch, then detached shell if required.

2. Hyper store/action only path
- Cleaner but higher risk across Hyper version/action differences.

3. External process first
- Reliable independence but weaker Hyper-native experience.

Chosen: Option 1.

## Architecture
### Execution backend strategies
Tool launches use a strategy manager with ordered failover:
1. `hyper_new_tab`
2. `external_terminal`
3. `detached_shell`

A launch attempt returns a structured result:
- `started`
- `transport`
- `target`
- `sessionUid` or `pid`
- `logFile`
- `error`

### Component responsibilities
- `hyper-recon-menu`: detection and tool-selector dispatch only.
- `hyper-target-panel`: target state, command launch requests, UI status.
- `ToolRunner` split into:
  - `TargetNormalizer`
  - `CommandRenderer`
  - `ExecutionStrategyManager`
  - `RunRecorder`

## Target Model and `set_target`
### Entry points
- Popup menu always includes `Set Target` action for detected item.
- Sidebar target remains inline editable.

### Normalization pipeline
Single shared target normalizer:
1. trim
2. strip `http://`/`https://`
3. strip path/query/fragment
4. strip trailing slash and optional port
5. lowercase domains; preserve IP format
6. reject empty/invalid normalized result

### Protocol application
Command rendering resolves protocol dynamically when needed:
- if tool needs scheme, choose `https` when TLS evidence exists; else `http`
- avoid duplicate scheme insertion

## Persistence
Use SQLite (`better-sqlite3`) for per-target persistence.

### Schema
- `targets` (`id`, `target`, `created_at`, `updated_at`)
- `findings` (`id`, `target_id`, `kind`, `value`, `source_tool`, `created_at`)
- `history` (`id`, `target_id`, `value`, `created_at`)
- `runs` (`id`, `target_id`, `tool_id`, `command`, `transport`, `status`, `error`, `log_file`, `started_at`, `ended_at`)

### Compatibility
On first access to a target, import from legacy `findings_<target>.json` if present.

## Data Flow
1. User clicks sidebar tool or popup preset/tool.
2. Target is normalized and persisted.
3. Command is rendered from tool template/placeholders.
4. Strategy manager executes with fallback chain.
5. Run status persisted (`queued`/`running`/`failed`/`succeeded`).
6. UI updates with visible status and errors.

## Error Handling
- No silent failures; every failed attempt becomes UI-visible state.
- Record strategy, message, timestamp in `runs.error` fields.
- Launch timeout marks failed state and triggers fallback.

## Testing and Verification
- Unit tests:
  - target normalization
  - command rendering/protocol resolution
- Integration-style tests (mocked Hyper failure):
  - fallback ordering and final result handling
- Existing repo JS syntax check remains required.

## Success Criteria
- Sidebar tool click reliably starts execution.
- Popup preset selection reliably starts execution.
- Popup `Set Target` and sidebar edit persist to same normalized target key.
- Findings/history/runs are isolated per target and persist across restarts.
- Launch failures are visible in UI and recorded with cause.

## Risks and Mitigations
- Hyper internal API variability: mitigated by strategy fallback and explicit session validation.
- External terminal command differences by OS: detect platform and use adapter commands.
- Migration edge cases from JSON: import-on-access with idempotent checks.
