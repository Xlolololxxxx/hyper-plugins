'use strict';

const { lines, uniq, baseOutput, extractPortToken } = require('./common');

function parse(raw) {
  const textLines = lines(raw);
  const records = [];
  const ports = [];
  const vulns = [];

  textLines.forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    const p = extractPortToken(trimmed);
    if (p && /\bopen\b/i.test(trimmed)) {
      ports.push(p);
      records.push({ type: 'port', port: p, line: trimmed });
    }

    const cves = trimmed.match(/CVE-\d{4}-\d{4,7}/gi) || [];
    cves.forEach((cve) => {
      const normalized = cve.toUpperCase();
      vulns.push(normalized);
      records.push({ type: 'vuln', id: normalized, line: trimmed });
    });
  });

  return baseOutput('nmap', raw, records, {
    findings: {
      ports: uniq(ports),
      vulns: uniq(vulns),
    },
    summary: {
      open_port_count: uniq(ports).length,
    },
  });
}

module.exports = { parse };
