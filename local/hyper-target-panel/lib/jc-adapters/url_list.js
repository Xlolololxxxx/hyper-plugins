'use strict';

const { lines, uniq, baseOutput, normalizePath } = require('./common');

function parse(raw) {
  const urls = [];
  const domains = [];
  const paths = [];
  const records = [];

  lines(raw).forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    if (!/^https?:\/\//i.test(trimmed)) return;

    urls.push(trimmed);
    try {
      const u = new URL(trimmed);
      domains.push(u.hostname);
      const p = normalizePath(u.pathname);
      if (p) paths.push(p);
      records.push({ type: 'url', url: trimmed, host: u.hostname, path: p || '/' });
    } catch (_e) {
      records.push({ type: 'url', url: trimmed });
    }
  });

  return baseOutput('url_list', raw, records, {
    findings: {
      domains: uniq(domains),
      paths: uniq(paths),
    },
    derived: {
      urls: uniq(urls),
    },
  });
}

module.exports = { parse };
