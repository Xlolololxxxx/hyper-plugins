'use strict';

const { lines, uniq, baseOutput, normalizePath } = require('./common');

function parse(raw) {
  const paths = [];
  const vulns = [];
  const records = [];

  lines(raw).forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    const u = trimmed.match(/https?:\/\/\S+/i);
    if (u) {
      try {
        const url = new URL(u[0]);
        const path = normalizePath(url.pathname);
        if (path) paths.push(path);
      } catch (_e) {}
    }

    if (/\bXSS\b/i.test(trimmed)) {
      vulns.push('xss');
      records.push({ type: 'xss', line: trimmed });
    }
  });

  return baseOutput('dalfox', raw, records, {
    findings: {
      paths: uniq(paths),
      vulns: uniq(vulns),
    },
  });
}

module.exports = { parse };
