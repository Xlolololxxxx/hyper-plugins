# Agent-10 - nuclei_from_httpx

## Scope
- Tool ID: `nuclei_from_httpx`
- Tool Name: `NUCLEI FROM HTTPX`
- Base Command: `nuclei`
- Parser Hint in tools.json: `nuclei`
- Input Mode: `domain`
- Types: domain

## Command Template
`nuclei -l {log:httpx_from_subfinder} -o {log_file}`

## Goal
Implement a custom JC-compatible parser module for this tool so raw output can be transformed into stable structured JSON for storage and UI.

## Deliverables
- New parser module in `local/hyper-target-panel/lib/jc-adapters/` named `nuclei_from_httpx.js`
- Parser unit tests in `local/hyper-target-panel/__tests__/jc-adapters/nuclei_from_httpx.test.js`
- 5 baseline fixtures from real tool output under `local/hyper-target-panel/data/jc-baseline/nuclei_from_httpx/`
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
