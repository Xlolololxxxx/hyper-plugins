'use strict';

function stripAnsi(str) {
  return String(str || '')
    .replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '')
    .replace(/\x1b\][^\x07]*\x07/g, '')
    .replace(/\x1b[()][AB012]/g, '')
    .replace(/\x1b[\[?]?[0-9;]*[a-zA-Z]/g, '');
}

function extractSetTarget(raw) {
  if (!raw) return null;
  const clean = stripAnsi(raw).replace(/[^\x20-\x7E\r\n\t]/g, ' ');
  const lines = clean.split(/\r?\n/);

  for (const line of lines) {
    const m = line.match(/\bset_target\s+(?:"([^"]+)"|'([^']+)'|([^\s;|&]+))/i);
    if (!m) continue;
    const value = (m[1] || m[2] || m[3] || '').trim();
    if (value) return value;
  }

  return null;
}

module.exports = {
  stripAnsi,
  extractSetTarget,
};
