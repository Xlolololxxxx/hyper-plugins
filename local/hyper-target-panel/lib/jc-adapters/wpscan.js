'use strict';

const { lines, uniq, baseOutput, normalizePath } = require('./common');

function parse(raw) {
  const vulns = [];
  const paths = [];
  const domains = [];
  const records = [];

  lines(raw).forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    if (/^\[\+\]\s+URL:\s+/i.test(trimmed)) {
      const target = trimmed.replace(/^\[\+\]\s+URL:\s+/i, '').trim();
      try {
        const u = new URL(target);
        domains.push(u.hostname);
        const p = normalizePath(u.pathname);
        if (p) paths.push(p);
      } catch (_e) {}
      records.push({ type: 'target', value: target });
    }

    if (trimmed.includes('Interesting Entry:')) {
      const entry = trimmed.split('Interesting Entry:')[1].trim();
      const p = normalizePath(entry);
      if (p) paths.push(p);
      records.push({ type: 'path', value: p || entry });
    }

    const cves = trimmed.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || [];
    cves.forEach((cve) => vulns.push(cve.toUpperCase()));

    if (/^\[\!\]\s+/i.test(trimmed)) {
      records.push({ type: 'finding', value: trimmed.replace(/^\[\!\]\s+/i, '').trim() });
    }
  });

  return baseOutput('wpscan', raw, records, {
    findings: {
      vulns: uniq(vulns),
      paths: uniq(paths),
      domains: uniq(domains),
    },
  });
}

module.exports = { parse };
