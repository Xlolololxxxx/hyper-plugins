'use strict';

const { lines, uniq, baseOutput, normalizePath } = require('./common');

function parse(raw) {
  const paths = [];
  const records = [];

  lines(raw).forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    const m = trimmed.match(/\[(\d{3})\]\s+\S+\s+-\s+\d+\w*\s+-\s+(\/\S+)/);
    if (m) {
      const path = normalizePath(m[2]);
      if (path) paths.push(path);
      records.push({ type: 'path', status: Number(m[1]), path: path || m[2] });
    }
  });

  return baseOutput('dirsearch', raw, records, {
    findings: { paths: uniq(paths) },
  });
}

module.exports = { parse };
