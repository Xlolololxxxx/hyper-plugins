'use strict';

const { lines, uniq, baseOutput } = require('./common');

function parse(raw) {
  const params = [];
  const records = [];

  lines(raw).forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    const m = trimmed.match(/\b(?:param(?:eter)?s?)\b[:\s]+([a-zA-Z0-9_\-]+)/i);
    if (m) {
      params.push(m[1]);
      records.push({ type: 'param', name: m[1] });
      return;
    }

    if (/^[a-zA-Z0-9_\-]+$/.test(trimmed) && trimmed.length < 48) {
      params.push(trimmed);
      records.push({ type: 'param', name: trimmed });
    }
  });

  return baseOutput('arjun', raw, records, {
    derived: { params: uniq(params) },
    summary: { param_count: uniq(params).length },
  });
}

module.exports = { parse };
