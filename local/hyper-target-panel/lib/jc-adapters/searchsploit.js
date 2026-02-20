'use strict';

const { lines, uniq, baseOutput } = require('./common');

function parse(raw) {
  const vulns = [];
  const records = [];

  lines(raw).forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    const cves = trimmed.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || [];
    cves.forEach((cve) => {
      const id = cve.toUpperCase();
      vulns.push(id);
      records.push({ type: 'cve', id, line: trimmed });
    });

    if (/\|/.test(trimmed)) {
      records.push({ type: 'entry', line: trimmed });
    }
  });

  return baseOutput('searchsploit', raw, records, {
    findings: { vulns: uniq(vulns) },
  });
}

module.exports = { parse };
