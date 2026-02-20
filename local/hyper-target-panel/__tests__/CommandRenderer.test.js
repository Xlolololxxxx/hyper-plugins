'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { renderCommand } = require('../lib/CommandRenderer');

test('renders log references', () => {
  const cmd = renderCommand('nuclei -l {log:httpx_from_subfinder} -o {log_file}', {
    target: 'example.com',
    targetSafe: 'example.com',
    logFile: '/tmp/new.log',
    tempDir: '/tmp',
  });

  assert.equal(cmd, 'nuclei -l /tmp/example.com_httpx_from_subfinder.log -o /tmp/new.log');
});

test('renders domain input mode as bare host', () => {
  const cmd = renderCommand('nmap -sV {target}', {
    target: 'https://Example.com/path?q=1',
    tool: { id: 'nmap', input_mode: 'domain' },
  });

  assert.equal(cmd, 'nmap -sV example.com');
});

test('renders url input mode with default https', () => {
  const cmd = renderCommand('sqlmap -u "{target}" --batch', {
    target: 'example.com',
    tool: { id: 'sqlmap', input_mode: 'url' },
  });

  assert.equal(cmd, 'sqlmap -u "https://example.com" --batch');
});

test('applies explicit http override for url input mode', () => {
  const cmd = renderCommand('ffuf -u {target}/FUZZ -w {wordlist_file}', {
    target: 'example.com',
    tool: { id: 'ffuf', input_mode: 'url' },
    schemeOverride: 'http',
    wordlistFile: '/tmp/dirs.txt',
  });

  assert.equal(cmd, 'ffuf -u http://example.com/FUZZ -w /tmp/dirs.txt');
});

test('replaces scheme when explicit override conflicts with incoming target', () => {
  const cmd = renderCommand('curl -skI {target}', {
    target: 'https://example.com',
    tool: { id: 'curl_headers', input_mode: 'url' },
    schemeOverride: 'http',
  });

  assert.equal(cmd, 'curl -skI http://example.com');
});
