'use strict';

const { lines, uniq, baseOutput } = require('./common');

function parse(raw) {
  const domains = [];
  const records = [];

  lines(raw).forEach((line) => {
    const trimmed = line.trim().toLowerCase();
    if (!trimmed) return;
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(trimmed)) return;
    domains.push(trimmed);
    records.push({ type: 'subdomain', value: trimmed });
  });

  return baseOutput('subdomains', raw, records, {
    findings: { domains: uniq(domains) },
    summary: { subdomain_count: uniq(domains).length },
  });
}

module.exports = { parse };
