# Agent-06 - subfinder

## Scope
- Tool ID: `subfinder`
- Tool Name: `SUBFINDER`
- Base Command: `subfinder`
- Parser Hint in tools.json: `generic`
- Input Mode: `domain`
- Types: domain

## Command Template
`subfinder -d {target} -o {log_file}`

## Goal
Implement a custom JC-compatible parser module for this tool so raw output can be transformed into stable structured JSON for storage and UI.

## Deliverables
- New parser module in `local/hyper-target-panel/lib/jc-adapters/` named `subfinder.js`
- Parser unit tests in `local/hyper-target-panel/__tests__/jc-adapters/subfinder.test.js`
- 5 baseline fixtures from real tool output under `local/hyper-target-panel/data/jc-baseline/subfinder/`
- Registry wiring in `local/hyper-target-panel/lib/jc/JcRegistry.js`

## Acceptance Criteria
- Parses full raw output without throwing.
- Returns deterministic schema with documented keys.
- Handles empty output and partial/error output.
- Test suite includes happy path + malformed/noise line coverage.
- Output can be persisted by `TargetStore.storeJcSnapshot(...)`.

## Notes
- Keep raw structured output as source of truth; UI adaptation comes later.
- Do not depend on current UI rendering assumptions.
