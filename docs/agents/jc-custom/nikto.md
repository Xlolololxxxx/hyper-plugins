# Agent-14 - nikto

## Scope
- Tool ID: `nikto`
- Tool Name: `NIKTO`
- Base Command: `nikto`
- Parser Hint in tools.json: `nikto`
- Input Mode: `url`
- Types: url, domain, domain_port, ip_port, ipv4

## Command Template
`nikto -h {target} -output {log_file}`

## Goal
Implement a custom JC-compatible parser module for this tool so raw output can be transformed into stable structured JSON for storage and UI.

## Deliverables
- New parser module in `local/hyper-target-panel/lib/jc-adapters/` named `nikto.js`
- Parser unit tests in `local/hyper-target-panel/__tests__/jc-adapters/nikto.test.js`
- 5 baseline fixtures from real tool output under `local/hyper-target-panel/data/jc-baseline/nikto/`
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
