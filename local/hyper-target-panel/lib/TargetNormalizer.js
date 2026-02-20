'use strict';

function isIpv4(value) {
  const parts = value.split('.');
  if (parts.length !== 4) return false;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return false;
    const n = Number(p);
    if (n < 0 || n > 255) return false;
  }
  return true;
}

function normalizeTarget(raw) {
  if (raw === null || raw === undefined) return null;

  let value = String(raw).trim();
  if (!value) return null;

  // Strip scheme, path/query/fragment, trailing slash, and optional port.
  value = value.replace(/^https?:\/\//i, '');
  value = value.split(/[/?#]/)[0];
  value = value.replace(/\/+$/, '');
  value = value.replace(/:(\d{1,5})$/, '');

  if (!value) return null;

  if (isIpv4(value)) return value;

  // Preserve non-host tokens (email/hash/cve/text) for tool actions.
  const hostLike = /^[a-zA-Z0-9.-]+$/.test(value);
  return hostLike ? value.toLowerCase() : value;
}

module.exports = {
  normalizeTarget,
  isIpv4,
};
