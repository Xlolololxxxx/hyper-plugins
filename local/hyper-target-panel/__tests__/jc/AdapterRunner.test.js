'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const AdapterRunner = require('../../lib/jc/AdapterRunner');

test('runs nmap adapter parser and extracts ports/cves', () => {
  const runner = new AdapterRunner();
  const raw = [
    '80/tcp open http',
    '443/tcp open https',
    '|_CVE-2024-12345: sample vuln',
  ].join('\n');

  const result = runner.parse('nmap', raw, { toolId: 'nmap_service' });
  assert.equal(result.ok, true);
  assert.deepEqual(result.data.findings.ports, ['80/tcp', '443/tcp']);
  assert.deepEqual(result.data.findings.vulns, ['CVE-2024-12345']);
});

test('runs ffuf adapter parser against json output', () => {
  const runner = new AdapterRunner();
  const raw = JSON.stringify({
    results: [
      { url: 'http://example.com/admin', status: 200, length: 120 },
      { url: 'http://example.com/api', status: 403, length: 20 },
    ],
  });

  const result = runner.parse('ffuf', raw, { toolId: 'ffuf_dir' });
  assert.equal(result.ok, true);
  assert.deepEqual(result.data.findings.paths, ['/admin', '/api']);
});

test('returns error when adapter is missing', () => {
  const runner = new AdapterRunner();
  const result = runner.parse('not_real_parser', 'x', {});
  assert.equal(result.ok, false);
});

test('runs nuclei adapter parser against jsonl output', () => {
  const runner = new AdapterRunner();
  const raw = [
    JSON.stringify({
      'template-id': 'exposed-panels',
      info: { severity: 'high' },
      type: 'http',
      host: 'http://127.0.0.1:42000/admin',
    }),
    JSON.stringify({
      'template-id': 'CVE-2025-12345',
      info: { severity: 'critical' },
      type: 'http',
      'matched-at': 'http://127.0.0.1:42000/rest/user/login',
    }),
  ].join('\n');

  const result = runner.parse('nuclei', raw, { toolId: 'nuclei_url' });
  assert.equal(result.ok, true);
  assert.deepEqual(result.data.findings.domains, ['127.0.0.1']);
  assert.deepEqual(result.data.findings.paths, ['/admin', '/rest/user/login']);
  assert.deepEqual(result.data.findings.vulns, ['exposed-panels', 'CVE-2025-12345']);
});

test('runs wpscan adapter parser and extracts paths/cves', () => {
  const runner = new AdapterRunner();
  const raw = [
    '[+] URL: https://example.com/',
    '[+] Found By: Headers (Passive Detection)',
    ' | Interesting Entry: /wp-login.php',
    '[!] Title: WordPress <= 6.3 - Sample Vulnerability',
    ' | Reference: https://wpscan.com/vulnerability/CVE-2024-12345',
  ].join('\n');

  const result = runner.parse('wpscan', raw, { toolId: 'wpscan' });
  assert.equal(result.ok, true);
  assert.equal(result.data.parser, 'wpscan');
  assert.equal(result.data.findings.paths.includes('/wp-login.php'), true);
  assert.equal(result.data.findings.vulns.includes('CVE-2024-12345'), true);
});
