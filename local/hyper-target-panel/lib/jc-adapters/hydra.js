'use strict';

const { lines, uniq, baseOutput } = require('./common');

function parse(raw) {
  const credentials = [];
  const records = [];

  lines(raw).forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    const m = trimmed.match(/login:\s*(\S+)\s+password:\s*(\S+)/i);
    if (m) {
      const pair = `${m[1]}:${m[2]}`;
      credentials.push(pair);
      records.push({ type: 'credential', login: m[1], password: m[2] });
    }
  });

  return baseOutput('hydra', raw, records, {
    derived: { credentials: uniq(credentials) },
    summary: { credential_count: uniq(credentials).length },
  });
}

module.exports = { parse };
