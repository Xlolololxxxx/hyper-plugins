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

    if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
      try {
        const obj = JSON.parse(trimmed);
        const vulnId = String(obj['template-id'] || obj.template || obj.info?.name || '').trim();
        const protocol = String(obj.type || obj.protocol || '').trim();
        const severity = String(obj.info?.severity || obj.severity || '').trim().toLowerCase();
        const target = String(obj['matched-at'] || obj.host || obj.url || '').trim();
        if (vulnId) vulns.push(vulnId);
        if (target.startsWith('http://') || target.startsWith('https://')) {
          try {
            const u = new URL(target);
            domains.push(u.hostname);
            const p = normalizePath(u.pathname);
            if (p) paths.push(p);
          } catch (_e) {}
        }
        records.push({ type: 'finding', id: vulnId, protocol, severity, target });
        return;
      } catch (_e) {}
    }

    const m = trimmed.match(/^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.+)$/);
    if (m) {
      const vulnId = String(m[1] || '').trim();
      const protocol = String(m[2] || '').trim();
      const severity = String(m[3] || '').trim().toLowerCase();
      const target = String(m[4] || '').trim();
      if (vulnId) vulns.push(vulnId);
      if (target.startsWith('http://') || target.startsWith('https://')) {
        try {
          const u = new URL(target);
          domains.push(u.hostname);
          const p = normalizePath(u.pathname);
          if (p) paths.push(p);
        } catch (_e) {}
      }
      records.push({ type: 'finding', id: vulnId, protocol, severity, target });
      return;
    }

    const cves = trimmed.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || [];
    cves.forEach((cve) => vulns.push(cve.toUpperCase()));
  });

  return baseOutput('nuclei', raw, records, {
    findings: {
      vulns: uniq(vulns),
      domains: uniq(domains),
      paths: uniq(paths),
    },
    summary: {
      nuclei_findings: records.length,
    },
  });
}

module.exports = { parse };
