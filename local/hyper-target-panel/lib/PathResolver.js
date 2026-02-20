'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const PLUGIN_ROOT = path.resolve(__dirname, '..');
const WORKSPACE_ROOT = path.resolve(PLUGIN_ROOT, '..', '..');
const DATA_DIR = path.join(PLUGIN_ROOT, 'data');
const IMPORTS_DIR = path.join(DATA_DIR, 'imports');
const LEGACY_DIR = path.join(DATA_DIR, 'legacy');

function expandHome(inputPath) {
  const value = String(inputPath || '').trim();
  if (!value) return '';
  if (value === '~') return os.homedir();
  if (value.startsWith('~/')) return path.join(os.homedir(), value.slice(2));
  return value;
}

function isWithin(parentDir, candidate) {
  const parent = path.resolve(parentDir);
  const resolved = path.resolve(candidate);
  const rel = path.relative(parent, resolved);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

function resolveExistingPath(inputPath) {
  const expanded = expandHome(inputPath);
  if (!expanded) return '';

  const candidates = [];
  if (path.isAbsolute(expanded)) {
    candidates.push(expanded);
  } else {
    candidates.push(path.resolve(process.cwd(), expanded));
    candidates.push(path.resolve(WORKSPACE_ROOT, expanded));
  }

  for (const candidate of candidates) {
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
      return candidate;
    }
  }
  return expanded;
}

function ensureWorkspaceFile(inputPath, options) {
  const opts = options || {};
  const sourcePath = resolveExistingPath(inputPath);
  if (!sourcePath || !fs.existsSync(sourcePath)) return inputPath;
  if (isWithin(WORKSPACE_ROOT, sourcePath)) return sourcePath;

  const destRoot = opts.destDir || IMPORTS_DIR;
  fs.mkdirSync(destRoot, { recursive: true });

  const parsed = path.parse(sourcePath);
  const hash = crypto.createHash('sha1').update(sourcePath).digest('hex').slice(0, 10);
  const safeBase = parsed.name.replace(/[^a-zA-Z0-9._-]/g, '_') || 'file';
  const destPath = path.join(destRoot, `${safeBase}_${hash}${parsed.ext}`);

  try {
    const srcStat = fs.statSync(sourcePath);
    const needsCopy = !fs.existsSync(destPath) || fs.statSync(destPath).mtimeMs < srcStat.mtimeMs;
    if (needsCopy) fs.copyFileSync(sourcePath, destPath);
  } catch (_e) {
    return inputPath;
  }

  return destPath;
}

function getWordlistRoots() {
  const fromEnv = String(process.env.HYPER_WORDLIST_ROOTS || '')
    .split(path.delimiter)
    .map((item) => item.trim())
    .filter(Boolean);

  const defaults = [
    path.join(DATA_DIR, 'wordlists'),
    path.join(WORKSPACE_ROOT, 'cache', 'wordlists', 'vendor'),
    path.join(WORKSPACE_ROOT, 'cache', 'wordlists'),
    path.join(os.homedir(), 'Wordlists'),
    path.join(os.homedir(), 'Wordlist'),
  ];

  return [...new Set([...fromEnv, ...defaults])];
}

function getLegacyFindingsPath(safeTarget) {
  const fileName = `findings_${safeTarget}.json`;
  const workspacePath = path.join(LEGACY_DIR, fileName);
  fs.mkdirSync(LEGACY_DIR, { recursive: true });

  const oldPath = path.join(os.homedir(), '.gemini/tmp', fileName);
  if (!fs.existsSync(workspacePath) && fs.existsSync(oldPath)) {
    try {
      fs.copyFileSync(oldPath, workspacePath);
    } catch (_e) {
      return oldPath;
    }
  }

  return workspacePath;
}

module.exports = {
  DATA_DIR,
  WORKSPACE_ROOT,
  getWordlistRoots,
  ensureWorkspaceFile,
  getLegacyFindingsPath,
};
