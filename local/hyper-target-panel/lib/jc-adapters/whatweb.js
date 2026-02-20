'use strict';

const { lines, uniq, baseOutput } = require('./common');

function parse(raw) {
  const records = [];
  const paths = [];

  lines(raw).forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    const u = trimmed.match(/^(https?:\/\/\S+)/i);
    if (u) {
      try {
        const url = new URL(u[1]);
        if (url.pathname) paths.push(url.pathname);
        records.push({ type: 'url', value: u[1] });
      } catch (_e) {}
    }

    const plugins = trimmed.split(',').map((p) => p.trim()).filter(Boolean);
    if (plugins.length > 1) records.push({ type: 'tech', plugins });
  });

  return baseOutput('whatweb', raw, records, {
    findings: { paths: uniq(paths) },
  });
}

module.exports = { parse };
