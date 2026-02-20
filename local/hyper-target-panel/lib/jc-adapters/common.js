'use strict';

const DOMAIN_RE = /\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g;
const URL_RE = /https?:\/\/[^\s"'<>]+/g;
const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
const PORT_RE = /\b(\d{1,5})\/(tcp|udp)\b/i;

function uniq(items) {
  return Array.from(new Set((items || []).filter(Boolean).map((v) => String(v).trim())));
}

function lines(raw) {
  return String(raw || '').split(/\r?\n/);
}

function matchAll(text, re) {
  const out = [];
  const str = String(text || '');
  const flags = re.flags.includes('g') ? re.flags : `${re.flags}g`;
  const rg = new RegExp(re.source, flags);
  let m;
  while ((m = rg.exec(str)) !== null) {
    out.push(m[0]);
  }
  return out;
}

function normalizePath(value) {
  const raw = String(value || '').trim();
  if (!raw) return null;
  if (raw.startsWith('http://') || raw.startsWith('https://')) {
    try {
      const u = new URL(raw);
      return u.pathname || '/';
    } catch (_e) {
      return null;
    }
  }
  if (raw.startsWith('/')) return raw;
  return null;
}

function baseOutput(parser, raw, records, extra) {
  const text = String(raw || '');
  const allDomains = uniq(matchAll(text, DOMAIN_RE));
  const allCves = uniq(matchAll(text, CVE_RE).map((v) => v.toUpperCase()));
  const allUrls = uniq(matchAll(text, URL_RE));
  const findings = Object.assign({
    ports: [],
    vulns: allCves,
    paths: [],
    domains: allDomains,
  }, extra && extra.findings ? extra.findings : {});

  return {
    parser,
    engine: 'jc-adapter',
    summary: Object.assign({
      line_count: lines(text).filter(Boolean).length,
      record_count: Array.isArray(records) ? records.length : 0,
      domain_count: allDomains.length,
      url_count: allUrls.length,
      vuln_count: allCves.length,
    }, extra && extra.summary ? extra.summary : {}),
    findings,
    records: Array.isArray(records) ? records : [],
    derived: Object.assign({
      urls: allUrls,
      domains: allDomains,
      cves: allCves,
    }, extra && extra.derived ? extra.derived : {}),
  };
}

function extractPortToken(line) {
  const m = PORT_RE.exec(String(line || ''));
  if (!m) return null;
  const port = Number(m[1]);
  if (!Number.isFinite(port) || port < 1 || port > 65535) return null;
  return `${port}/${String(m[2] || '').toLowerCase()}`;
}

module.exports = {
  uniq,
  lines,
  matchAll,
  normalizePath,
  baseOutput,
  extractPortToken,
  DOMAIN_RE,
  URL_RE,
  CVE_RE,
};
