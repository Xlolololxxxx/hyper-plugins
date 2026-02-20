# Agent-07 - amass_passive

## Scope
- Tool ID: `amass_passive`
- Tool Name: `AMASS PASSIVE`
- Base Command: `amass`
- Parser Hint in tools.json: `generic`
- Input Mode: `domain`
- Types: domain

## Command Template
`amass enum -passive -d {target} -o {log_file}`

## Goal
Implement a custom JC-compatible parser module for this tool so raw output can be transformed into stable structured JSON for storage and UI.

## Deliverables
- New parser module in `local/hyper-target-panel/lib/jc-adapters/` named `amass_passive.js`
- Parser unit tests in `local/hyper-target-panel/__tests__/jc-adapters/amass_passive.test.js`
- 5 baseline fixtures from real tool output under `local/hyper-target-panel/data/jc-baseline/amass_passive/`
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
