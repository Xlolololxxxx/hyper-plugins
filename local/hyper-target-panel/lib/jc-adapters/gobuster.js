'use strict';

const { lines, uniq, baseOutput, normalizePath } = require('./common');

function parse(raw) {
  const paths = [];
  const records = [];

  lines(raw).forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    const pathMatch = trimmed.match(/^(\/[^\s]+)\s+\(Status:\s*(\d{3})\)/i);
    if (pathMatch) {
      const path = normalizePath(pathMatch[1]);
      if (path) paths.push(path);
      records.push({ type: 'path', path: path || pathMatch[1], status: Number(pathMatch[2]) });
      return;
    }

    const alt = trimmed.match(/Found:\s*(https?:\/\/\S+)/i);
    if (alt) {
      try {
        const u = new URL(alt[1]);
        const path = normalizePath(u.pathname);
        if (path) paths.push(path);
        records.push({ type: 'path', path: path || '/', status: null });
      } catch (_e) {}
    }
  });

  return baseOutput('gobuster', raw, records, {
    findings: {
      paths: uniq(paths),
    },
    summary: {
      discovered_paths: uniq(paths).length,
    },
  });
}

module.exports = { parse };
