'use strict';

const { lines, uniq, baseOutput, normalizePath } = require('./common');

function parse(raw) {
  const paths = [];
  const vulns = [];
  const records = [];

  lines(raw).forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    const p = trimmed.match(/\+\s+([^:\s]+):\s*(.*)$/);
    if (p) {
      const path = normalizePath(p[1]);
      if (path) paths.push(path);
      records.push({ type: 'finding', path: path || p[1], detail: p[2] || '' });
    }

    const cves = trimmed.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || [];
    cves.forEach((cve) => vulns.push(cve.toUpperCase()));
  });

  return baseOutput('nikto', raw, records, {
    findings: {
      paths: uniq(paths),
      vulns: uniq(vulns),
    },
  });
}

module.exports = { parse };
