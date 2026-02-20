'use strict';

const { lines, uniq, baseOutput } = require('./common');

function parse(raw) {
  const vulns = [];
  const records = [];

  lines(raw).forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    const param = trimmed.match(/parameter\s+['\"]?([\w.-]+)['\"]?\s+is\s+vulnerable/i);
    if (param) {
      const finding = `sqli:${param[1]}`;
      vulns.push(finding);
      records.push({ type: 'sqli', parameter: param[1], line: trimmed });
    }

    const cves = trimmed.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || [];
    cves.forEach((cve) => vulns.push(cve.toUpperCase()));
  });

  return baseOutput('sqlmap', raw, records, {
    findings: { vulns: uniq(vulns) },
  });
}

module.exports = { parse };
