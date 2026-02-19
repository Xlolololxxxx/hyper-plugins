'use strict';

const { EventEmitter } = require('events');

// Mock window and document before requiring the module
global.window = {
  __hyperRecon: {
    events: new EventEmitter(),
    targets: new Map(),
    findings: [],
    sessions: new Map(),
    hud: null,
  }
};

global.document = {
  createElement: jest.fn(() => ({
    style: {},
    appendChild: jest.fn(),
    addEventListener: jest.fn(),
    remove: jest.fn(),
    head: { appendChild: jest.fn() },
    body: { appendChild: jest.fn() },
  })),
  head: {
    appendChild: jest.fn(),
  },
  body: {
    appendChild: jest.fn(),
  },
  removeEventListener: jest.fn(),
  addEventListener: jest.fn(),
};

global.getComputedStyle = jest.fn(() => ({
  position: 'static',
}));

global.requestAnimationFrame = jest.fn((cb) => cb());

// Set NODE_ENV to test to enable exports
process.env.NODE_ENV = 'test';

const httpLens = require('./index.js');

describe('Hyper HTTP Lens - Utility Functions', () => {
  test('stripAnsi should remove ANSI escape codes', () => {
    const input = '\x1b[31mError\x1b[0m: \x1b[1mBold text\x1b[22m';
    const expected = 'Error: Bold text';
    expect(httpLens.stripAnsi(input)).toBe(expected);
  });

  test('statusColor should return correct colors for status ranges', () => {
    expect(httpLens.statusColor(200)).toBe('#3fb950'); // green
    expect(httpLens.statusColor(301)).toBe('#d29922'); // yellow
    expect(httpLens.statusColor(401)).toBe('#f85149'); // auth issue
    expect(httpLens.statusColor(404)).toBe('#f97316'); // orange
    expect(httpLens.statusColor(500)).toBe('#da3633'); // dark red
    expect(httpLens.statusColor(101)).toBe('#8b949e'); // gray
  });

  test('guessUrl should reconstruct URL from headers', () => {
    expect(httpLens.guessUrl({ host: 'example.com' })).toBe('https://example.com');
    expect(httpLens.guessUrl({ 'location': 'http://redirect.com' })).toBe('http://redirect.com');
    expect(httpLens.guessUrl({})).toBe('(unknown)');
  });

  test('extractServerInfo should extract relevant headers', () => {
    const headers = {
      'server': 'nginx',
      'x-powered-by': 'PHP/8.0',
      'x-varnish': '12345'
    };
    const info = httpLens.extractServerInfo(headers);
    expect(info.server).toBe('nginx');
    expect(info.poweredBy).toBe('PHP/8.0');
    expect(info.varnish).toBe('12345');
  });

  test('parseSingleCookie should correctly parse cookie flags', () => {
    const raw = 'session=123; Secure; HttpOnly; SameSite=Lax; Path=/';
    const cookie = httpLens.parseSingleCookie(raw);
    expect(cookie.name).toBe('session');
    expect(cookie.value).toBe('123');
    expect(cookie.flags.secure).toBe(true);
    expect(cookie.flags.httpOnly).toBe(true);
    expect(cookie.flags.sameSite).toBe('Lax');
    expect(cookie.flags.path).toBe('/');
    expect(cookie.issues).toHaveLength(0);
  });

  test('parseSingleCookie should identify missing security flags', () => {
    const raw = 'session=123';
    const cookie = httpLens.parseSingleCookie(raw);
    expect(cookie.issues).toContain('Missing Secure');
    expect(cookie.issues).toContain('Missing HttpOnly');
    expect(cookie.issues).toContain('Missing SameSite');
  });
});

describe('Hyper HTTP Lens - Advanced Utilities', () => {
  test('analyzeSecurityHeaders should identify interesting headers', () => {
    const headers = {
      'server': 'nginx',
      'x-powered-by': 'PHP'
    };
    const result = httpLens.analyzeSecurityHeaders(headers);
    expect(result.present.map(h => h.key)).toContain('server');
    expect(result.present.map(h => h.key)).toContain('x-powered-by');
  });

  test('detectWAF should detect Cloudflare', () => {
    const headers = { 'cf-ray': '123456789', 'server': 'cloudflare' };
    const cookies = [{ name: '__cfduid', value: 'xyz' }];
    const body = 'Attention Required! Cloudflare';
    const waf = httpLens.detectWAF(headers, cookies, body);
    expect(waf[0].name).toBe('Cloudflare');
    expect(waf[0].confidence).toBeGreaterThanOrEqual(40);
  });

  test('detectWAF should detect AWS WAF', () => {
    const headers = { 'x-amzn-requestid': 'abc' };
    const cookies = [{ name: 'awsalb', value: '123' }];
    const waf = httpLens.detectWAF(headers, [], '');
    expect(waf[0].name).toBe('AWS WAF');
  });

  test('parseCookies should handle multiple Set-Cookie headers', () => {
    // In our implementation, multiple cookies are joined by \n
    const headers = {
      'set-cookie': 'c1=v1; Secure\nc2=v2; HttpOnly'
    };
    const cookies = httpLens.parseCookies(headers);
    expect(cookies).toHaveLength(2);
    expect(cookies[0].name).toBe('c1');
    expect(cookies[1].name).toBe('c2');
  });

  test('findHttpStatusInLine should find HTTP status lines', () => {
    const line = 'HTTP/1.1 200 OK';
    const match = httpLens.findHttpStatusInLine(line);
    expect(match).not.toBeNull();
    expect(match.code).toBe(200);
    expect(match.text).toBe('OK');
  });
});

describe('Hyper HTTP Lens - Parsing Logic (feedPtyData)', () => {
  const uid = 'session-1';

  beforeEach(() => {
    jest.useFakeTimers();
    httpLens.resetSessionBuffer(uid);
    // Clear captured responses
    httpLens.capturedResponses.length = 0;
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  test('should parse a complete HTTP response', () => {
    const rawData = [
      '> HTTP/1.1 200 OK',
      '> Date: Mon, 27 Jul 2009 12:28:53 GMT',
      '> Server: Apache',
      '> Content-Type: text/html',
      '> ',
      '<html>body</html>',
      '$ ' // Simple prompt that matches the regex
    ].join('\r\n');

    httpLens.feedPtyData(uid, rawData);

    expect(httpLens.capturedResponses).toHaveLength(1);
    const resp = httpLens.capturedResponses[0];
    expect(resp.statusCode).toBe(200);
    expect(resp.headers['server']).toBe('Apache');
    expect(resp.body.trim()).toBe('<html>body</html>');
  });

  test('should handle multiple responses in the same session', () => {
    httpLens.feedPtyData(uid, 'HTTP/1.1 301 Moved\r\nLocation: /new\r\n\r\n');
    httpLens.feedPtyData(uid, 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello\r\n$ ');

    expect(httpLens.capturedResponses).toHaveLength(2);
    expect(httpLens.capturedResponses[0].statusCode).toBe(200);
    expect(httpLens.capturedResponses[1].statusCode).toBe(301);
  });

  test('should finalize response after timeout', () => {
    httpLens.feedPtyData(uid, 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nPartial body...');

    expect(httpLens.capturedResponses).toHaveLength(0);

    // Fast-forward 3 seconds (BUFFER_TIMEOUT_MS)
    jest.advanceTimersByTime(3000);

    expect(httpLens.capturedResponses).toHaveLength(1);
    expect(httpLens.capturedResponses[0].body).toContain('Partial body...');
  });

  test('should strip ANSI before parsing', () => {
    // \x1b[32m is green
    httpLens.feedPtyData(uid, '\x1b[32mHTTP/1.1 200 OK\x1b[0m\r\nServer: \x1b[1mnginx\x1b[0m\r\n\r\n');

    jest.advanceTimersByTime(3000);

    expect(httpLens.capturedResponses).toHaveLength(1);
    expect(httpLens.capturedResponses[0].statusCode).toBe(200);
    expect(httpLens.capturedResponses[0].headers['server']).toBe('nginx');
  });
});
