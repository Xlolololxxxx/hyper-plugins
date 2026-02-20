'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { buildWordlistCatalog } = require('../lib/WordlistCatalog');

function mkTmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'wordlist-catalog-'));
}

test('builds all-caps category groups from real files', () => {
  const dir = mkTmpDir();
  fs.writeFileSync(path.join(dir, 'web_discovery_common_files_dirs.txt'), 'admin\n');
  fs.writeFileSync(path.join(dir, 'subdomains.txt'), 'www\n');
  fs.writeFileSync(path.join(dir, 'payloads_sql_injection.txt'), '\' OR 1=1\n');
  fs.writeFileSync(path.join(dir, '.hidden.txt'), 'ignore\n');
  fs.mkdirSync(path.join(dir, '.git'));
  fs.writeFileSync(path.join(dir, '.git', 'config'), '[core]\n');

  const catalog = buildWordlistCatalog({
    roots: [dir],
    profile: 'dir_enum'
  });

  assert.ok(catalog.sections.some((section) => section.id === 'DIR ENUM'));
  const section = catalog.sections.find((entry) => entry.id === 'DIR ENUM');
  assert.equal(section.files.length, 1);
  assert.match(section.files[0].name, /web_discovery_common_files_dirs\.txt$/);
});

test('returns only matching profile files and stable labels', () => {
  const dir = mkTmpDir();
  fs.writeFileSync(path.join(dir, 'payloads_xss_injection.txt'), '<script>\n');
  fs.writeFileSync(path.join(dir, 'payloads_sqli_custom.txt'), '1 OR 1=1\n');
  fs.writeFileSync(path.join(dir, 'subdomains_permutations.txt'), 'dev\n');

  const xss = buildWordlistCatalog({ roots: [dir], profile: 'xss_payloads' });
  assert.equal(xss.sections.length, 1);
  assert.equal(xss.sections[0].id, 'XSS PAYLOADS');
  assert.equal(xss.sections[0].files.length, 1);
  assert.match(xss.sections[0].files[0].name, /payloads_xss_injection\.txt$/);
});

