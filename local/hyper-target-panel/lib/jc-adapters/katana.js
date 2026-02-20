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

    let url = null;
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
      try {
        const obj = JSON.parse(trimmed);
        url = obj.url || obj.request || obj.endpoint || null;
      } catch (_e) {}
    }

    if (!url && /^https?:\/\//i.test(trimmed)) url = trimmed;
    if (!url) return;

    urls.push(url);
    try {
      const u = new URL(url);
      domains.push(u.hostname);
      const p = normalizePath(u.pathname);
      if (p) paths.push(p);
      records.push({ type: 'url', url, host: u.hostname, path: p || '/' });
    } catch (_e) {
      records.push({ type: 'url', url });
    }
  });

  return baseOutput('katana', raw, records, {
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
