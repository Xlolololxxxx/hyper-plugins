#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MIN_NODE_MAJOR=22
RUN_INSTALL=1

if [[ "${1:-}" == "--skip-install" ]]; then
  RUN_INSTALL=0
fi

log() {
  printf '[setup] %s\n' "$*"
}

fail() {
  printf '[setup] ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

node_major() {
  node -p "Number(process.versions.node.split('.')[0])"
}

require_cmd node
require_cmd npm
require_cmd find
require_cmd xargs

NODE_MAJOR="$(node_major)"
if (( NODE_MAJOR < MIN_NODE_MAJOR )); then
  fail "Node ${MIN_NODE_MAJOR}+ is required (found $(node -v)). This repo uses node:sqlite in hyper-target-panel."
fi

log "Repository: $ROOT_DIR"
log "Node: $(node -v)"
log "npm: $(npm -v)"

if (( RUN_INSTALL == 1 )); then
  log "Installing workspace dependencies"
  npm install
else
  log "Skipping npm install (--skip-install)"
fi

log "Running syntax check for all plugins (CI parity)"
find local -name "*.js" -print0 | xargs -0 -I {} node -c "{}"

TARGET_PANEL_TEST_DIR="local/hyper-target-panel/__tests__"
if [[ -d "$TARGET_PANEL_TEST_DIR" ]]; then
  log "Running hyper-target-panel test suite (node:test)"
  node --test \
    local/hyper-target-panel/__tests__/*.test.js \
    local/hyper-target-panel/__tests__/jc/*.test.js
fi

cat <<'EOF'

[setup] Environment ready.

Recommended workflow for Codex (web):
  1) Edit plugin code under local/<plugin>/.
  2) Re-run quick validation:
       find local -name "*.js" -print0 | xargs -0 -I {} node -c {}
  3) Re-run target-panel tests when touching target-panel logic:
       node --test local/hyper-target-panel/__tests__/*.test.js local/hyper-target-panel/__tests__/jc/*.test.js

EOF
