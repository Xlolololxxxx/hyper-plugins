'use strict';

const { lines, uniq, baseOutput } = require('./common');

function parse(raw) {
  const records = [];
  const domains = [];

  lines(raw).forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    const dm = trimmed.match(/^(Domain Name|domain):\s*(\S+)/i);
    if (dm) {
      domains.push(dm[2].toLowerCase());
      records.push({ type: 'domain', value: dm[2].toLowerCase(), line: trimmed });
    }

    const ns = trimmed.match(/^Name Server:\s*(\S+)/i);
    if (ns) records.push({ type: 'ns', value: ns[1].toLowerCase(), line: trimmed });
  });

  return baseOutput('whois', raw, records, {
    findings: { domains: uniq(domains) },
  });
}

module.exports = { parse };
