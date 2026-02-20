'use strict';

const { lines, uniq, baseOutput, normalizePath } = require('./common');

function parseJson(raw) {
  try {
    const obj = JSON.parse(String(raw || '{}'));
    if (!obj || !Array.isArray(obj.results)) return null;

    const records = [];
    const paths = [];
    const domains = [];

    obj.results.forEach((row) => {
      const url = row.url || row.input?.FUZZ || row.redirectlocation || '';
      if (!url) return;
      try {
        const u = new URL(url);
        domains.push(u.hostname);
        const path = normalizePath(u.pathname);
        if (path) paths.push(path);
      } catch (_e) {}
      records.push({
        type: 'result',
        status: row.status,
        length: row.length,
        words: row.words,
        lines: row.lines,
        url,
      });
    });

    return baseOutput('ffuf', raw, records, {
      findings: { domains: uniq(domains), paths: uniq(paths) },
      summary: { ffuf_results: records.length },
    });
  } catch (_e) {
    return null;
  }
}

function parseText(raw) {
  const records = [];
  const paths = [];

  lines(raw).forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    const m = trimmed.match(/\[Status:\s*(\d+),.*\]\s+(\S+)/i);
    if (m) {
      const target = m[2];
      let path = null;
      try {
        const u = new URL(target);
        path = normalizePath(u.pathname);
      } catch (_e) {}
      if (path) paths.push(path);
      records.push({ type: 'result', status: Number(m[1]), target, path });
    }
  });

  return baseOutput('ffuf', raw, records, {
    findings: { paths: uniq(paths) },
    summary: { ffuf_results: records.length },
  });
}

function parse(raw) {
  return parseJson(raw) || parseText(raw);
}

module.exports = { parse };
