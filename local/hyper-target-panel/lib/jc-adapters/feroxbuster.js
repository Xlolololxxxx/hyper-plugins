'use strict';

const { lines, uniq, baseOutput, normalizePath } = require('./common');

function parse(raw) {
  const paths = [];
  const records = [];

  lines(raw).forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    const m = trimmed.match(/\b(\d{3})\b\s+\S+\s+\S+\s+(https?:\/\/\S+)/i);
    if (m) {
      try {
        const u = new URL(m[2]);
        const path = normalizePath(u.pathname);
        if (path) paths.push(path);
        records.push({ type: 'path', status: Number(m[1]), path: path || u.pathname });
      } catch (_e) {}
    }
  });

  return baseOutput('feroxbuster', raw, records, {
    findings: { paths: uniq(paths) },
  });
}

module.exports = { parse };
