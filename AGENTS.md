# Repository Guidelines

## Project Structure & Module Organization
This repository is a workspace of local Hyper plugins plus supporting artifacts.

- `local/`: Each plugin lives in its own folder (for example `local/hyper-secret-sniffer/`). Typical layout is `package.json` + `index.js` entrypoint.
- `cache/`: Generated caches (do not hand-edit).
- `reports/`: Generated scan or export outputs.
- `cve-audit/`: Security auditing notes and inventories.
- `.phrase/`: Internal planning and change tracking docs.
- `.github/workflows/ci.yml`: CI checks (Node syntax validation).

## Build, Test, and Development Commands
There is no build step; plugins are loaded by Hyper from the `local/` directory. The repo keeps a minimal Node setup for CI.

- `npm install`: Installs dependencies used by CI (even if none are currently declared).
- `find local -name "*.js" -print0 | xargs -0 -I {} node -c {}`: Syntax-check all plugin JavaScript files (matches CI).

## Coding Style & Naming Conventions
- JavaScript is written in CommonJS with `'use strict'`, `require(...)`, semicolons, and single quotes.
- Indentation is 2 spaces.
- Plugin folder names are `hyper-<name>` and should match the `name` field in each `package.json`.
- Entry file should remain `index.js` unless a plugin explicitly documents otherwise.

## Testing Guidelines
There is no formal test framework in this repo. The minimum bar is a clean syntax check on all plugin files.

- Run the CI command above locally before pushing.
- If you add a test harness, document it here and in the plugin’s `package.json` scripts.

## Commit & Pull Request Guidelines
Commit history is mixed, but recent work uses Conventional Commit prefixes (`feat:`, `fix:`) alongside imperative summaries. Prefer Conventional Commits for new changes.

PRs should include:
- A short summary of behavior changes.
- Any relevant `local/<plugin>/` paths touched.
- Verification notes (for example “ran syntax check”).
- Screenshots or GIFs if you change a UI panel.

## Security & Configuration Notes
- Avoid committing secrets; several plugins scan for credentials.
- Keep generated outputs in `reports/` and caches in `cache/`.
