# Agent-11 - whatweb

## Scope
- Tool ID: `whatweb`
- Tool Name: `WHATWEB`
- Base Command: `whatweb`
- Parser Hint in tools.json: `generic`
- Input Mode: `url`
- Types: url, domain, domain_port, ip_port, ipv4

## Command Template
`whatweb {target} | tee {log_file}`

## Goal
Implement a custom JC-compatible parser module for this tool so raw output can be transformed into stable structured JSON for storage and UI.

## Deliverables
- New parser module in `local/hyper-target-panel/lib/jc-adapters/` named `whatweb.js`
- Parser unit tests in `local/hyper-target-panel/__tests__/jc-adapters/whatweb.test.js`
- 5 baseline fixtures from real tool output under `local/hyper-target-panel/data/jc-baseline/whatweb/`
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
