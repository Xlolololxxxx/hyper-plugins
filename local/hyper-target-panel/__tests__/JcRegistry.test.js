'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { resolveJcParser, resolveJcPlan } = require('../lib/jc/JcRegistry');

test('maps builtin-supported tools to jc parsers', () => {
  assert.equal(resolveJcParser({ id: 'curl_headers', command: 'curl -sI {target}' }), 'curl_head');
  assert.equal(resolveJcParser({ id: 'dig_any', command: 'dig {target} ANY' }), 'dig');
  assert.equal(resolveJcParser({ id: 'ping', command: 'ping -c 4 {target}' }), 'ping');
  assert.equal(resolveJcParser({ id: 'traceroute', command: 'traceroute {target}' }), 'traceroute');
});

test('maps unsupported jc tools to adapter parser plans', () => {
  assert.deepEqual(resolveJcPlan({ id: 'nmap_service', command: 'nmap -sV {target}' }), { engine: 'adapter', parser: 'nmap_service' });
  assert.deepEqual(resolveJcPlan({ id: 'gobuster_dir', command: 'gobuster dir -u http://{target}' }), { engine: 'adapter', parser: 'gobuster_dir' });
  assert.deepEqual(resolveJcPlan({ id: 'ffuf_dir', command: 'ffuf -u http://{target}/FUZZ -w wordlist' }), { engine: 'adapter', parser: 'ffuf_dir' });
});

test('returns null for non-parsable internal actions', () => {
  assert.equal(resolveJcPlan({ id: 'copy_target', command: '{target}' }), null);
  assert.equal(resolveJcPlan({ id: 'open_nvd', command: 'https://nvd.nist.gov/vuln/detail/{target}' }), null);
});
