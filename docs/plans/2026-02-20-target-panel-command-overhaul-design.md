# Target Panel Command Overhaul Design

## Problem
The current target panel command catalog has inaccurate syntax, weak target typing, invalid wordlist assumptions, and confusing modal behavior (duplicate/irrelevant entries).

## Goals
- Make `hyper-target-panel` the single source of truth for tool definitions and filtering.
- Ensure each tool receives the correct target form (`domain` vs `url`).
- Add explicit scheme override (`AUTO`/`HTTPS`/`HTTP`) for URL tools.
- Add practical wordlist selection from actual local files in `~/Wordlists`.
- Keep recon-menu as detector/launcher only.

## Non-Goals
- No on-disk wordlist file renaming.
- No guessed fallback wordlist paths.

## Design
### Tool metadata
Each tool definition will declare:
- `input_mode`: `domain` or `url`
- `types`: compatible detected token types
- `wordlist`: optional object describing required wordlist category and placeholder

### Target rendering
Command rendering will stop using heuristics and instead use metadata:
- `domain` tools always get normalized host/IP (no scheme).
- `url` tools always get full URL; scheme chosen by override (default HTTPS).

### Wordlist flow
For tools that require wordlists:
- Clicking tool opens a second popup with categorized entries from `~/Wordlists`.
- Categories use clear, all-caps labels.
- Only real files are shown; `.git` and hidden files excluded.

### UI updates
Top section adds:
- `OVERRIDE` heading
- scheme selector buttons: `AUTO`, `HTTPS`, `HTTP`

Tool modal updates:
- keep action buttons separate from tool list
- keep category grouping
- apply strict compatibility filtering

### Verification
Add tests for:
- mode-driven target rendering
- scheme override behavior
- wordlist placeholder substitution
- compatibility filtering helpers
