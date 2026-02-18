'use strict';

// ======================================================================
//  HYPER HTTP LENS
//  Auto-parse HTTP responses from curl/wget/httpie output.
//  Provides security header analysis, status code highlighting,
//  WAF detection, cookie inspection, and sandboxed HTML preview.
//  Registers HUD tab and overlays inline status badges on terminal.
// ======================================================================

const EventEmitter = require('events');

// ------ Shared Recon Namespace ----------------------------------------

function getRecon() {
  if (!window.__hyperRecon) {
    window.__hyperRecon = {
      events: new EventEmitter(),
      targets: new Map(),
      findings: [],
      sessions: new Map(),
      hud: null,
    };
    window.__hyperRecon.events.setMaxListeners(50);
  }
  return window.__hyperRecon;
}

// ------ Constants -----------------------------------------------------

const BODY_CAPTURE_LIMIT = 50 * 1024; // 50KB max per response body
const MAX_RESPONSES = 100;             // Keep last N responses in memory
const BUFFER_TIMEOUT_MS = 3000;        // Flush buffer after no new data
const MAX_BUFFER_LINES = 2000;         // Max lines buffered per session

// ------ ANSI Stripping ------------------------------------------------

function stripAnsi(str) {
  return str
    .replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '')
    .replace(/\x1b\][^\x07]*\x07/g, '')
    .replace(/\x1b[()][AB012]/g, '')
    .replace(/\x1b[\[>=]/g, '')
    .replace(/[\x00-\x08\x0e-\x1f]/g, '');
}

// ------ Security Headers to Check -------------------------------------

const SECURITY_HEADERS = [
  { name: 'Content-Security-Policy', key: 'content-security-policy', severity: 'high', abbr: 'CSP' },
  { name: 'X-Frame-Options', key: 'x-frame-options', severity: 'medium', abbr: 'XFO' },
  { name: 'X-Content-Type-Options', key: 'x-content-type-options', severity: 'medium', abbr: 'XCTO' },
  { name: 'Strict-Transport-Security', key: 'strict-transport-security', severity: 'high', abbr: 'HSTS' },
  { name: 'X-XSS-Protection', key: 'x-xss-protection', severity: 'low', abbr: 'XSS' },
  { name: 'Referrer-Policy', key: 'referrer-policy', severity: 'low', abbr: 'RP' },
  { name: 'Permissions-Policy', key: 'permissions-policy', severity: 'medium', abbr: 'PP' },
  { name: 'Access-Control-Allow-Origin', key: 'access-control-allow-origin', severity: 'info', abbr: 'CORS' },
];

// ------ WAF Signatures ------------------------------------------------

const WAF_SIGNATURES = [
  {
    name: 'Cloudflare',
    headerChecks: [
      { key: 'cf-ray', match: /.+/ },
      { key: 'server', match: /cloudflare/i },
    ],
    cookieNames: ['__cfduid', '__cf_bm', 'cf_clearance'],
    bodyPatterns: [/Attention Required.*Cloudflare/i, /cf-browser-verification/i],
  },
  {
    name: 'AWS WAF',
    headerChecks: [
      { key: 'x-amzn-requestid', match: /.+/ },
      { key: 'x-amzn-trace-id', match: /.+/ },
      { key: 'x-amz-cf-id', match: /.+/ },
    ],
    cookieNames: ['awsalb', 'awsalbcors'],
    bodyPatterns: [],
  },
  {
    name: 'Akamai',
    headerChecks: [
      { key: 'server', match: /AkamaiGHost/i },
      { key: 'x-akamai-transformed', match: /.+/ },
    ],
    cookieNames: ['akamai_generated', 'AkamaiAnalytics'],
    bodyPatterns: [/Reference\s*#\d+\.\w+\.\d+/i],
  },
  {
    name: 'ModSecurity',
    headerChecks: [
      { key: 'server', match: /mod_security|modsecurity/i },
    ],
    cookieNames: [],
    bodyPatterns: [/ModSecurity/i, /mod_security/i, /NOYB/i],
  },
  {
    name: 'Incapsula/Imperva',
    headerChecks: [
      { key: 'x-cdn', match: /Incapsula/i },
      { key: 'x-iinfo', match: /.+/ },
    ],
    cookieNames: ['incap_ses', 'visid_incap', 'nlbi_'],
    bodyPatterns: [/Incapsula incident/i, /_Incapsula_Resource/i],
  },
  {
    name: 'Sucuri',
    headerChecks: [
      { key: 'server', match: /Sucuri/i },
      { key: 'x-sucuri-id', match: /.+/ },
    ],
    cookieNames: ['sucuri_cloudproxy'],
    bodyPatterns: [/Sucuri WebSite Firewall/i],
  },
  {
    name: 'F5 BIG-IP',
    headerChecks: [
      { key: 'server', match: /BIG-?IP/i },
    ],
    cookieNames: ['BIGipServer', 'TS0'],
    bodyPatterns: [],
  },
  {
    name: 'Barracuda',
    headerChecks: [
      { key: 'server', match: /Barracuda/i },
    ],
    cookieNames: ['barra_counter_session'],
    bodyPatterns: [],
  },
];

// ------ HTTP Response Parsing -----------------------------------------

const HTTP_STATUS_RE = /^(?:[<>*]\s*)?HTTP\/[\d.]+ (\d{3})\s*(.*)/;
const HEADER_RE = /^(?:[<>*]\s*)?([A-Za-z][\w-]*)\s*:\s*(.*)/;
const CURL_VERBOSE_PREFIX_RE = /^[<>*]\s*/;

// State machine states for parsing
const PARSE_STATE = {
  IDLE: 0,
  HEADERS: 1,
  BODY: 2,
};

// ------ Per-session buffer tracking -----------------------------------

const sessionBuffers = new Map();

function getSessionBuffer(uid) {
  if (!sessionBuffers.has(uid)) {
    sessionBuffers.set(uid, {
      state: PARSE_STATE.IDLE,
      statusCode: 0,
      statusText: '',
      headers: {},
      headerOrder: [],
      rawHeaders: [],
      bodyLines: [],
      bodySize: 0,
      flushTimer: null,
      lineBuffer: [],
    });
  }
  return sessionBuffers.get(uid);
}

function resetSessionBuffer(uid) {
  const buf = getSessionBuffer(uid);
  buf.state = PARSE_STATE.IDLE;
  buf.statusCode = 0;
  buf.statusText = '';
  buf.headers = {};
  buf.headerOrder = [];
  buf.rawHeaders = [];
  buf.bodyLines = [];
  buf.bodySize = 0;
}

// ------ Captured Responses Store --------------------------------------

const capturedResponses = [];
let responseIdCounter = 0;
let hudApi = null;
let renderCallback = null;
let activeUid = null;

function addResponse(resp) {
  capturedResponses.unshift(resp);
  if (capturedResponses.length > MAX_RESPONSES) {
    capturedResponses.length = MAX_RESPONSES;
  }
  updateBadge();
  triggerRender();

  // Emit to shared event bus
  const recon = getRecon();
  recon.events.emit('http:response', {
    url: resp.url,
    status: resp.statusCode,
    headers: resp.headers,
    body: resp.body,
    securityIssues: resp.missingHeaders,
    waf: resp.waf,
  });
}

function updateBadge() {
  if (!hudApi) return;
  const issueCount = capturedResponses.filter(r => r.missingHeaders.length > 0).length;
  hudApi.updateBadge('http-lens', issueCount > 0 ? issueCount : null);
}

function triggerRender() {
  if (renderCallback) renderCallback();
}

// ------ Response Analysis Functions -----------------------------------

function analyzeSecurityHeaders(headers) {
  const present = [];
  const missing = [];

  for (const sh of SECURITY_HEADERS) {
    if (headers[sh.key]) {
      present.push({ ...sh, value: headers[sh.key] });
    } else {
      // CORS is informational, not a "missing" warning
      if (sh.key !== 'access-control-allow-origin') {
        missing.push(sh);
      }
    }
  }

  return { present, missing };
}

function detectWAF(headers, cookies, body) {
  const detected = [];

  for (const waf of WAF_SIGNATURES) {
    let score = 0;

    // Check headers
    for (const check of waf.headerChecks) {
      const val = headers[check.key];
      if (val && check.match.test(val)) {
        score += 2;
      }
    }

    // Check cookies
    for (const cookieName of waf.cookieNames) {
      for (const c of cookies) {
        if (c.name.toLowerCase().startsWith(cookieName.toLowerCase())) {
          score += 1;
        }
      }
    }

    // Check body patterns
    for (const pat of waf.bodyPatterns) {
      if (pat.test(body)) {
        score += 2;
      }
    }

    if (score >= 2) {
      detected.push({ name: waf.name, confidence: Math.min(score * 20, 100) });
    }
  }

  return detected;
}

function parseCookies(headers) {
  const cookies = [];
  // Collect all Set-Cookie values (headers are stored lowercase)
  const setCookieKey = 'set-cookie';
  const raw = headers[setCookieKey];
  if (!raw) return cookies;

  // May be multiple Set-Cookie joined by newlines
  const cookieLines = raw.split(/\n/);
  for (const line of cookieLines) {
    const cookie = parseSingleCookie(line.trim());
    if (cookie) cookies.push(cookie);
  }

  return cookies;
}

function parseSingleCookie(str) {
  if (!str) return null;
  const parts = str.split(';').map(s => s.trim());
  const first = parts[0];
  const eqIdx = first.indexOf('=');
  if (eqIdx < 0) return null;

  const name = first.substring(0, eqIdx).trim();
  const value = first.substring(eqIdx + 1).trim();

  const flags = {
    secure: false,
    httpOnly: false,
    sameSite: null,
    path: null,
    domain: null,
    expires: null,
    maxAge: null,
  };

  for (let i = 1; i < parts.length; i++) {
    const p = parts[i];
    const lower = p.toLowerCase();
    if (lower === 'secure') {
      flags.secure = true;
    } else if (lower === 'httponly') {
      flags.httpOnly = true;
    } else if (lower.startsWith('samesite=')) {
      flags.sameSite = p.split('=')[1] || null;
    } else if (lower.startsWith('path=')) {
      flags.path = p.split('=')[1] || null;
    } else if (lower.startsWith('domain=')) {
      flags.domain = p.split('=')[1] || null;
    } else if (lower.startsWith('expires=')) {
      flags.expires = p.substring(8).trim();
    } else if (lower.startsWith('max-age=')) {
      flags.maxAge = p.split('=')[1] || null;
    }
  }

  const issues = [];
  if (!flags.secure) issues.push('Missing Secure');
  if (!flags.httpOnly) issues.push('Missing HttpOnly');
  if (!flags.sameSite) issues.push('Missing SameSite');

  return { name, value, flags, issues, raw: str };
}

function extractServerInfo(headers) {
  const info = {};
  if (headers['server']) info.server = headers['server'];
  if (headers['x-powered-by']) info.poweredBy = headers['x-powered-by'];
  if (headers['x-aspnet-version']) info.aspnet = headers['x-aspnet-version'];
  if (headers['x-generator']) info.generator = headers['x-generator'];
  if (headers['x-drupal-cache']) info.drupal = true;
  if (headers['x-varnish']) info.varnish = headers['x-varnish'];
  if (headers['x-cache']) info.cache = headers['x-cache'];
  if (headers['via']) info.via = headers['via'];
  return info;
}

function guessUrl(headers) {
  // Try to reconstruct URL from headers
  const host = headers['host'] || headers[':authority'] || '';
  const location = headers['location'] || '';
  if (location && /^https?:\/\//i.test(location)) return location;
  if (host) return 'https://' + host;
  return '(unknown)';
}

function statusColor(code) {
  if (code >= 200 && code < 300) return '#3fb950'; // green
  if (code >= 300 && code < 400) return '#d29922'; // yellow
  if (code >= 400 && code < 500) return '#f97316'; // orange
  if (code >= 500) return '#f85149';                // red
  return '#8b949e';
}

// ------ HTTP Response Parsing State Machine ---------------------------

function feedPtyData(uid, rawData) {
  const buf = getSessionBuffer(uid);
  const cleaned = stripAnsi(rawData);
  const lines = cleaned.split(/\r?\n/);

  for (const rawLine of lines) {
    const line = rawLine.replace(CURL_VERBOSE_PREFIX_RE, '').trimEnd();

    // Track lines for context
    buf.lineBuffer.push(rawLine);
    if (buf.lineBuffer.length > MAX_BUFFER_LINES) {
      buf.lineBuffer = buf.lineBuffer.slice(-MAX_BUFFER_LINES);
    }

    switch (buf.state) {
      case PARSE_STATE.IDLE: {
        const statusMatch = rawLine.match(HTTP_STATUS_RE);
        if (statusMatch) {
          // Start new HTTP response capture
          buf.statusCode = parseInt(statusMatch[1], 10);
          buf.statusText = statusMatch[2].trim();
          buf.headers = {};
          buf.headerOrder = [];
          buf.rawHeaders = [];
          buf.bodyLines = [];
          buf.bodySize = 0;
          buf.state = PARSE_STATE.HEADERS;
        }
        break;
      }

      case PARSE_STATE.HEADERS: {
        // Check for status line again (HTTP/2 may have pseudo-headers, or
        // curl -v may output multiple responses like 301 -> 200)
        const statusMatch = rawLine.match(HTTP_STATUS_RE);
        if (statusMatch) {
          // Finalize previous response if it had headers
          if (buf.headerOrder.length > 0) {
            finalizeResponse(uid, buf);
          }
          buf.statusCode = parseInt(statusMatch[1], 10);
          buf.statusText = statusMatch[2].trim();
          buf.headers = {};
          buf.headerOrder = [];
          buf.rawHeaders = [];
          buf.bodyLines = [];
          buf.bodySize = 0;
          break;
        }

        const headerMatch = rawLine.match(HEADER_RE);
        if (headerMatch) {
          const key = headerMatch[1].toLowerCase();
          const val = headerMatch[2].trim();
          // For Set-Cookie, append with newline so we keep all values
          if (buf.headers[key] && key === 'set-cookie') {
            buf.headers[key] += '\n' + val;
          } else {
            buf.headers[key] = val;
          }
          buf.headerOrder.push(headerMatch[1]);
          buf.rawHeaders.push(rawLine.trim());
          break;
        }

        // Empty line (or blank after stripping verbose prefix) signals end of headers
        if (line.trim() === '' && buf.headerOrder.length > 0) {
          // Check content type to decide if we should capture body
          const ct = buf.headers['content-type'] || '';
          if (ct.includes('html') || ct.includes('json') || ct.includes('xml') ||
              ct.includes('text') || ct.includes('javascript')) {
            buf.state = PARSE_STATE.BODY;
          } else {
            // No body capture for binary content types
            finalizeResponse(uid, buf);
          }
          break;
        }

        // If we get a non-header, non-empty line while expecting headers,
        // it might be the body starting without an empty line separator
        if (line.trim() !== '' && buf.headerOrder.length > 0) {
          // Treat as start of body
          buf.state = PARSE_STATE.BODY;
          buf.bodyLines.push(rawLine);
          buf.bodySize += rawLine.length;
          break;
        }

        // If no headers collected yet and no match, bail
        if (buf.headerOrder.length === 0 && line.trim() !== '') {
          buf.state = PARSE_STATE.IDLE;
        }
        break;
      }

      case PARSE_STATE.BODY: {
        // Detect start of new HTTP response in body stream
        const statusMatch = rawLine.match(HTTP_STATUS_RE);
        if (statusMatch) {
          finalizeResponse(uid, buf);
          buf.statusCode = parseInt(statusMatch[1], 10);
          buf.statusText = statusMatch[2].trim();
          buf.headers = {};
          buf.headerOrder = [];
          buf.rawHeaders = [];
          buf.bodyLines = [];
          buf.bodySize = 0;
          buf.state = PARSE_STATE.HEADERS;
          break;
        }

        // Detect shell prompt (end of response)
        if (/^[a-zA-Z0-9._~\-]*[$#%>]\s*$/.test(line.trim()) && buf.bodyLines.length > 0) {
          finalizeResponse(uid, buf);
          break;
        }

        // Accumulate body up to limit
        if (buf.bodySize < BODY_CAPTURE_LIMIT) {
          buf.bodyLines.push(rawLine);
          buf.bodySize += rawLine.length;
        }
        break;
      }
    }
  }

  // Set a flush timer to finalize partial responses after timeout
  if (buf.flushTimer) clearTimeout(buf.flushTimer);
  if (buf.state !== PARSE_STATE.IDLE) {
    buf.flushTimer = setTimeout(() => {
      if (buf.state !== PARSE_STATE.IDLE && buf.headerOrder.length > 0) {
        finalizeResponse(uid, buf);
      }
    }, BUFFER_TIMEOUT_MS);
  }
}

function finalizeResponse(uid, buf) {
  if (buf.statusCode === 0 && buf.headerOrder.length === 0) {
    resetSessionBuffer(uid);
    return;
  }

  const body = buf.bodyLines.join('\n').substring(0, BODY_CAPTURE_LIMIT);
  const cookies = parseCookies(buf.headers);
  const security = analyzeSecurityHeaders(buf.headers);
  const waf = detectWAF(buf.headers, cookies, body);
  const serverInfo = extractServerInfo(buf.headers);
  const url = guessUrl(buf.headers);

  const resp = {
    id: ++responseIdCounter,
    timestamp: Date.now(),
    uid,
    statusCode: buf.statusCode,
    statusText: buf.statusText,
    headers: { ...buf.headers },
    headerOrder: [...buf.headerOrder],
    rawHeaders: [...buf.rawHeaders],
    body,
    hasBody: buf.bodyLines.length > 0,
    cookies,
    security,
    missingHeaders: security.missing,
    presentHeaders: security.present,
    waf,
    serverInfo,
    url,
    expanded: false,
    showHeaders: false,
    showCookies: false,
  };

  addResponse(resp);
  resetSessionBuffer(uid);
}

// ------ Inline overlay helpers ----------------------------------------

// Detect HTTP status lines in visible terminal buffer for overlay badges
const INLINE_HTTP_RE = /HTTP\/[\d.]+ (\d{3})\s*([\w\s]*)/;

function findHttpStatusInLine(text) {
  const m = text.match(INLINE_HTTP_RE);
  if (!m) return null;
  return {
    col: m.index,
    len: m[0].length,
    code: parseInt(m[1], 10),
    text: m[2].trim() || '',
  };
}

// ------ Page Preview Popup -------------------------------------------

let _previewPopup = null;

function dismissPreview() {
  if (_previewPopup) {
    _previewPopup.remove();
    _previewPopup = null;
  }
  document.removeEventListener('mousedown', _onPreviewBlur, true);
  document.removeEventListener('keydown', _onPreviewEsc, true);
}

function _onPreviewBlur(e) {
  if (_previewPopup && !_previewPopup.contains(e.target)) dismissPreview();
}

function _onPreviewEsc(e) {
  if (e.key === 'Escape') dismissPreview();
}

function showPagePreview(htmlBody, title) {
  dismissPreview();

  const popup = document.createElement('div');
  popup.style.cssText =
    'position:fixed;z-index:100000;width:520px;height:420px;' +
    'background:#1e1e1e;border:1px solid #444;border-radius:8px;' +
    'box-shadow:0 8px 32px rgba(0,0,0,0.7);display:flex;flex-direction:column;' +
    'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;' +
    'top:50%;left:50%;transform:translate(-50%,-50%);';

  // Title bar
  const titleBar = document.createElement('div');
  titleBar.style.cssText =
    'display:flex;align-items:center;justify-content:space-between;' +
    'padding:8px 12px;background:#161b22;border-bottom:1px solid #333;' +
    'border-radius:8px 8px 0 0;flex-shrink:0;';

  const titleLabel = document.createElement('span');
  titleLabel.textContent = title || 'Page Preview';
  titleLabel.style.cssText = 'color:#c9d1d9;font-size:12px;font-weight:600;';

  const closeBtn = document.createElement('span');
  closeBtn.textContent = '\u2715';
  closeBtn.style.cssText =
    'color:#8b949e;font-size:14px;cursor:pointer;padding:2px 6px;' +
    'border-radius:4px;transition:background 0.15s;';
  closeBtn.addEventListener('mouseenter', () => { closeBtn.style.background = '#333'; });
  closeBtn.addEventListener('mouseleave', () => { closeBtn.style.background = 'none'; });
  closeBtn.addEventListener('click', () => dismissPreview());

  titleBar.appendChild(titleLabel);
  titleBar.appendChild(closeBtn);
  popup.appendChild(titleBar);

  // Sandboxed iframe
  const iframe = document.createElement('iframe');
  iframe.sandbox = 'allow-same-origin'; // NO allow-scripts for safety
  iframe.srcdoc = htmlBody || '<html><body style="color:#666;font-family:sans-serif;padding:20px;">No HTML body captured.</body></html>';
  iframe.style.cssText = 'width:100%;flex:1;border:none;background:white;border-radius:0 0 8px 8px;';
  popup.appendChild(iframe);

  document.body.appendChild(popup);
  _previewPopup = popup;

  setTimeout(() => {
    document.addEventListener('mousedown', _onPreviewBlur, true);
    document.addEventListener('keydown', _onPreviewEsc, true);
  }, 0);
}

// ------ Header Detail Popup ------------------------------------------

let _headerPopup = null;

function dismissHeaderPopup() {
  if (_headerPopup) {
    _headerPopup.remove();
    _headerPopup = null;
  }
  document.removeEventListener('mousedown', _onHeaderBlur, true);
  document.removeEventListener('keydown', _onHeaderEsc, true);
}

function _onHeaderBlur(e) {
  if (_headerPopup && !_headerPopup.contains(e.target)) dismissHeaderPopup();
}

function _onHeaderEsc(e) {
  if (e.key === 'Escape') dismissHeaderPopup();
}

function showHeaderDetail(resp) {
  dismissHeaderPopup();

  const popup = document.createElement('div');
  popup.style.cssText =
    'position:fixed;z-index:100000;width:560px;max-height:500px;' +
    'background:#1e1e1e;border:1px solid #444;border-radius:8px;' +
    'box-shadow:0 8px 32px rgba(0,0,0,0.7);display:flex;flex-direction:column;' +
    'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;' +
    'top:50%;left:50%;transform:translate(-50%,-50%);';

  // Title bar
  const titleBar = document.createElement('div');
  titleBar.style.cssText =
    'display:flex;align-items:center;justify-content:space-between;' +
    'padding:8px 12px;background:#161b22;border-bottom:1px solid #333;' +
    'border-radius:8px 8px 0 0;flex-shrink:0;';

  const titleLabel = document.createElement('span');
  titleLabel.textContent = 'HTTP ' + resp.statusCode + ' - Header Analysis';
  titleLabel.style.cssText = 'color:#c9d1d9;font-size:12px;font-weight:600;';

  const closeBtn = document.createElement('span');
  closeBtn.textContent = '\u2715';
  closeBtn.style.cssText =
    'color:#8b949e;font-size:14px;cursor:pointer;padding:2px 6px;' +
    'border-radius:4px;transition:background 0.15s;';
  closeBtn.addEventListener('mouseenter', () => { closeBtn.style.background = '#333'; });
  closeBtn.addEventListener('mouseleave', () => { closeBtn.style.background = 'none'; });
  closeBtn.addEventListener('click', () => dismissHeaderPopup());

  titleBar.appendChild(titleLabel);
  titleBar.appendChild(closeBtn);
  popup.appendChild(titleBar);

  // Content area
  const content = document.createElement('div');
  content.style.cssText =
    'overflow-y:auto;padding:10px 14px;font-size:11px;color:#c9d1d9;' +
    'flex:1;line-height:1.6;';

  // Security headers scorecard
  let html = '<div style="margin-bottom:12px;">';
  html += '<div style="font-weight:700;color:#58a6ff;margin-bottom:6px;font-size:12px;">Security Headers</div>';

  for (const sh of SECURITY_HEADERS) {
    const found = resp.headers[sh.key];
    const icon = found ? '\u2705' : '\u274C';
    const color = found ? '#3fb950' : '#f85149';
    const val = found ? (' = ' + escHtml(truncate(found, 60))) : ' (missing)';
    html += '<div style="display:flex;gap:6px;align-items:flex-start;padding:2px 0;">';
    html += '<span style="color:' + color + ';flex-shrink:0;">' + icon + '</span>';
    html += '<span style="font-weight:600;flex-shrink:0;">' + escHtml(sh.name) + '</span>';
    html += '<span style="color:#8b949e;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + val + '</span>';
    html += '</div>';
  }
  html += '</div>';

  // WAF detection
  if (resp.waf.length > 0) {
    html += '<div style="margin-bottom:12px;">';
    html += '<div style="font-weight:700;color:#d29922;margin-bottom:6px;font-size:12px;">WAF Detected</div>';
    for (const w of resp.waf) {
      html += '<div style="padding:2px 0;">\uD83D\uDEE1\uFE0F ' + escHtml(w.name) + ' (confidence: ' + w.confidence + '%)</div>';
    }
    html += '</div>';
  }

  // Server info
  const si = resp.serverInfo;
  if (Object.keys(si).length > 0) {
    html += '<div style="margin-bottom:12px;">';
    html += '<div style="font-weight:700;color:#a78bfa;margin-bottom:6px;font-size:12px;">Server / Technology</div>';
    for (const [k, v] of Object.entries(si)) {
      html += '<div style="padding:2px 0;"><span style="color:#8b949e;">' + escHtml(k) + ':</span> ' + escHtml(String(v)) + '</div>';
    }
    html += '</div>';
  }

  // Cookies
  if (resp.cookies.length > 0) {
    html += '<div style="margin-bottom:12px;">';
    html += '<div style="font-weight:700;color:#f97316;margin-bottom:6px;font-size:12px;">Cookies (' + resp.cookies.length + ')</div>';
    for (const c of resp.cookies) {
      const flagColor = c.issues.length > 0 ? '#f85149' : '#3fb950';
      html += '<div style="padding:3px 0;border-bottom:1px solid #21262d;">';
      html += '<div><span style="font-weight:600;">' + escHtml(c.name) + '</span>';
      html += ' <span style="color:#8b949e;">= ' + escHtml(truncate(c.value, 40)) + '</span></div>';

      const flagsArr = [];
      if (c.flags.secure) flagsArr.push('<span style="color:#3fb950;">Secure</span>');
      else flagsArr.push('<span style="color:#f85149;">!Secure</span>');
      if (c.flags.httpOnly) flagsArr.push('<span style="color:#3fb950;">HttpOnly</span>');
      else flagsArr.push('<span style="color:#f85149;">!HttpOnly</span>');
      if (c.flags.sameSite) flagsArr.push('<span style="color:#3fb950;">SameSite=' + escHtml(c.flags.sameSite) + '</span>');
      else flagsArr.push('<span style="color:#f85149;">!SameSite</span>');
      html += '<div style="font-size:10px;margin-top:2px;">' + flagsArr.join(' | ') + '</div>';
      html += '</div>';
    }
    html += '</div>';
  }

  // Raw headers
  html += '<div style="margin-bottom:8px;">';
  html += '<div style="font-weight:700;color:#8b949e;margin-bottom:6px;font-size:12px;">Raw Headers (' + resp.rawHeaders.length + ')</div>';
  html += '<div style="background:#0d1117;border:1px solid #21262d;border-radius:4px;padding:6px 8px;' +
    'font-family:monospace;font-size:10px;max-height:150px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;color:#8b949e;">';
  html += escHtml('HTTP/' + (resp.headers[':status'] ? '2 ' : '1.1 ') + resp.statusCode + ' ' + resp.statusText) + '\n';
  for (const rh of resp.rawHeaders) {
    html += escHtml(rh) + '\n';
  }
  html += '</div></div>';

  content.innerHTML = html;
  popup.appendChild(content);

  document.body.appendChild(popup);
  _headerPopup = popup;

  setTimeout(() => {
    document.addEventListener('mousedown', _onHeaderBlur, true);
    document.addEventListener('keydown', _onHeaderEsc, true);
  }, 0);
}

// ------ Utility Helpers -----------------------------------------------

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function truncate(str, max) {
  if (!str) return '';
  return str.length > max ? str.substring(0, max - 3) + '...' : str;
}

// ======================================================================
//  HUD TAB RENDER FUNCTION
// ======================================================================

function renderHttpTab(React) {
  const h = React.createElement;

  if (capturedResponses.length === 0) {
    return h('div', {
      style: {
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        height: '100%', color: '#484f58', fontSize: '12px', fontStyle: 'italic',
      },
    }, 'No HTTP responses captured. Use curl -i, curl -v, wget, or httpie to see results.');
  }

  return h('div', { style: { display: 'flex', flexDirection: 'column', gap: '4px' } },
    // Header row
    h('div', {
      style: {
        display: 'flex', alignItems: 'center', gap: '8px',
        padding: '4px 8px', marginBottom: '4px',
        borderBottom: '1px solid #21262d',
        fontSize: '10px', color: '#484f58', fontWeight: 600,
        textTransform: 'uppercase', letterSpacing: '0.5px',
      },
    },
      h('span', { style: { width: '52px', flexShrink: 0 } }, 'Status'),
      h('span', { style: { flex: 1, minWidth: 0 } }, 'URL / Host'),
      h('span', { style: { width: '100px', flexShrink: 0 } }, 'Server'),
      h('span', { style: { width: '60px', flexShrink: 0, textAlign: 'center' } }, 'Missing'),
      h('span', { style: { width: '80px', flexShrink: 0 } }, 'WAF'),
      h('span', { style: { width: '100px', flexShrink: 0, textAlign: 'right' } }, 'Actions'),
    ),

    // Response rows
    ...capturedResponses.map(resp => renderResponseRow(React, resp))
  );
}

function renderResponseRow(React, resp) {
  const h = React.createElement;
  const sc = statusColor(resp.statusCode);
  const missingCount = resp.missingHeaders.length;
  const wafStr = resp.waf.map(w => w.name).join(', ') || '-';
  const serverStr = resp.serverInfo.server || '-';
  const urlStr = truncate(resp.url, 50);

  // Inject styles if needed
  injectStyles();

  return h('div', {
    key: resp.id,
    className: 'http-lens-row',
    style: {
      display: 'flex', alignItems: 'center', gap: '8px',
      padding: '5px 8px',
      background: '#161b22',
      border: '1px solid #21262d',
      borderRadius: '4px',
      fontSize: '11px',
      transition: 'border-color 0.15s',
    },
  },
    // Status badge
    h('span', {
      style: {
        width: '52px', flexShrink: 0,
        fontWeight: 700, fontSize: '11px',
        padding: '2px 6px', borderRadius: '4px', textAlign: 'center',
        background: sc + '18', color: sc,
        border: '1px solid ' + sc + '44',
        fontFamily: 'monospace',
      },
    }, String(resp.statusCode)),

    // URL
    h('span', {
      style: {
        flex: 1, minWidth: 0, color: '#c9d1d9',
        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        fontFamily: 'monospace', fontSize: '10px',
      },
      title: resp.url,
    }, urlStr),

    // Server
    h('span', {
      style: {
        width: '100px', flexShrink: 0, color: '#a78bfa',
        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        fontSize: '10px',
      },
      title: serverStr,
    }, truncate(serverStr, 16)),

    // Missing headers count
    h('span', {
      style: {
        width: '60px', flexShrink: 0, textAlign: 'center',
        fontWeight: 600, fontSize: '10px',
        color: missingCount > 4 ? '#f85149' : missingCount > 2 ? '#f97316' : missingCount > 0 ? '#d29922' : '#3fb950',
      },
    }, missingCount > 0 ? missingCount + ' / ' + (SECURITY_HEADERS.length - 1) : '\u2713'),

    // WAF
    h('span', {
      style: {
        width: '80px', flexShrink: 0,
        color: resp.waf.length > 0 ? '#d29922' : '#484f58',
        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        fontSize: '10px',
      },
      title: wafStr,
    }, resp.waf.length > 0 ? resp.waf[0].name : '-'),

    // Action buttons
    h('span', {
      style: {
        width: '100px', flexShrink: 0,
        display: 'flex', gap: '4px', justifyContent: 'flex-end',
      },
    },
      // Preview button
      resp.hasBody && h('span', {
        className: 'http-lens-btn',
        style: {
          cursor: 'pointer', padding: '2px 6px', borderRadius: '3px',
          fontSize: '9px', fontWeight: 600,
          background: '#58a6ff22', color: '#58a6ff',
          border: '1px solid #58a6ff44',
          transition: 'background 0.15s',
        },
        onClick: (e) => {
          e.stopPropagation();
          showPagePreview(resp.body, 'HTTP ' + resp.statusCode + ' - ' + truncate(resp.url, 40));
        },
        title: 'Preview rendered page',
      }, 'Preview'),

      // Headers button
      h('span', {
        className: 'http-lens-btn',
        style: {
          cursor: 'pointer', padding: '2px 6px', borderRadius: '3px',
          fontSize: '9px', fontWeight: 600,
          background: '#a78bfa22', color: '#a78bfa',
          border: '1px solid #a78bfa44',
          transition: 'background 0.15s',
        },
        onClick: (e) => {
          e.stopPropagation();
          showHeaderDetail(resp);
        },
        title: 'View header analysis',
      }, 'Headers'),
    ),
  );
}

// ------ Inject CSS Styles -------------------------------------------

let stylesInjected = false;

function injectStyles() {
  if (stylesInjected) return;
  if (typeof document === 'undefined') return;
  stylesInjected = true;

  const style = document.createElement('style');
  style.id = 'http-lens-styles';
  style.textContent = `
    .http-lens-row:hover {
      border-color: #30363d !important;
    }
    .http-lens-btn:hover {
      filter: brightness(1.3);
    }
    @keyframes http-lens-flash {
      0% { opacity: 1; }
      50% { opacity: 0.3; }
      100% { opacity: 1; }
    }
    .http-lens-badge:hover {
      opacity: 1 !important;
      transform: scale(1.15) !important;
      z-index: 20 !important;
    }
  `;
  document.head.appendChild(style);
}

// ======================================================================
//  HUD REGISTRATION
// ======================================================================

let hudRegistered = false;

function registerHud() {
  if (hudRegistered) return;
  const recon = getRecon();

  const renderFn = (React) => renderHttpTab(React);

  if (recon.hud) {
    hudApi = recon.hud;
    recon.hud.registerTab('http-lens', 'HTTP', null, renderFn);
    hudRegistered = true;
    updateBadge();
  } else {
    recon.events.on('hud:ready', (hud) => {
      hudApi = hud;
      hud.registerTab('http-lens', 'HTTP', null, renderFn);
      hudRegistered = true;
      updateBadge();
    });
  }
}

// ======================================================================
//  HYPER PLUGIN EXPORTS
// ======================================================================

// Middleware: intercept SESSION_PTY_DATA for HTTP response parsing

exports.middleware = (store) => (next) => (action) => {
  const recon = getRecon();

  switch (action.type) {
    case 'SESSION_SET_ACTIVE':
      activeUid = action.uid;
      break;

    case 'SESSION_ADD':
      if (!activeUid) activeUid = action.uid;
      break;

    case 'SESSION_PTY_DATA': {
      const uid = action.uid;
      const data = action.data;
      feedPtyData(uid, data);
      break;
    }

    case 'SESSION_PTY_EXIT':
    case 'SESSION_USER_EXIT': {
      // Finalize any in-progress response for this session
      const buf = sessionBuffers.get(action.uid);
      if (buf && buf.state !== PARSE_STATE.IDLE && buf.headerOrder.length > 0) {
        finalizeResponse(action.uid, buf);
      }
      sessionBuffers.delete(action.uid);
      if (action.uid === activeUid) activeUid = null;
      break;
    }
  }

  return next(action);
};

// decorateHyper: register HUD tab

exports.decorateHyper = (Hyper, { React }) => {
  return class HttpLensHyper extends React.Component {
    constructor(props) {
      super(props);
      this._mounted = false;
    }

    componentDidMount() {
      this._mounted = true;

      renderCallback = () => {
        if (this._mounted) {
          this.forceUpdate();
          updateBadge();
        }
      };

      registerHud();
    }

    componentWillUnmount() {
      this._mounted = false;
      renderCallback = null;
    }

    render() {
      return React.createElement(Hyper, this.props);
    }
  };
};

// decorateTerm: overlay inline status badges on HTTP response lines

exports.decorateTerm = (Term, { React }) => {
  return class HttpLensTerm extends React.Component {
    constructor(props) {
      super(props);
      this._onDecorated = this._onDecorated.bind(this);
      this._xterm = null;
      this._overlay = null;
      this._scanTimer = null;
      this._disposables = [];
      this._cache = new Map();
    }

    _onDecorated(term) {
      if (this.props.onDecorated) this.props.onDecorated(term);
      if (!term || !term.term) return;

      this._xterm = term.term;

      const tryInit = (attempts) => {
        if (attempts <= 0) return;
        const screen = this._xterm.element && this._xterm.element.querySelector('.xterm-screen');
        if (screen) {
          this._init(screen);
        } else {
          requestAnimationFrame(() => tryInit(attempts - 1));
        }
      };
      requestAnimationFrame(() => tryInit(10));
    }

    _init(screen) {
      this._overlay = document.createElement('div');
      this._overlay.className = 'http-lens-overlay';
      this._overlay.style.cssText =
        'position:absolute;top:0;left:0;width:100%;height:100%;' +
        'pointer-events:none;overflow:visible;z-index:10;';

      if (getComputedStyle(screen).position === 'static') {
        screen.style.position = 'relative';
      }
      screen.appendChild(this._overlay);

      this._disposables.push(
        this._xterm.onRender(() => this._queueScan()),
        this._xterm.onScroll(() => this._queueScan()),
        this._xterm.onResize(() => { this._cache.clear(); this._queueScan(); }),
      );

      injectStyles();
      this._queueScan();
    }

    _queueScan() {
      if (this._scanTimer) return;
      this._scanTimer = setTimeout(() => {
        this._scanTimer = null;
        requestAnimationFrame(() => this._scan());
      }, 150);
    }

    _cellSize() {
      const xterm = this._xterm;
      try {
        const d = xterm._core._renderService.dimensions;
        return { w: d.css.cell.width, h: d.css.cell.height };
      } catch {
        const scr = xterm.element && xterm.element.querySelector('.xterm-screen');
        return {
          w: scr ? scr.clientWidth / xterm.cols : 8,
          h: scr ? scr.clientHeight / xterm.rows : 17,
        };
      }
    }

    _scan() {
      if (!this._xterm || !this._overlay) return;

      const xterm = this._xterm;
      const buf = xterm.buffer.active;
      const cell = this._cellSize();

      this._overlay.innerHTML = '';

      for (let vr = 0; vr < xterm.rows; vr++) {
        const br = buf.viewportY + vr;
        const line = buf.getLine(br);
        if (!line) continue;

        const text = line.translateToString(true);
        if (!text.trim()) continue;

        // Check cache
        const key = br + ':' + text;
        let match = this._cache.get(key);
        if (match === undefined) {
          match = findHttpStatusInLine(text);
          this._cache.set(key, match);
          if (this._cache.size > 500) {
            this._cache.delete(this._cache.keys().next().value);
          }
        }

        if (match) {
          this._placeBadge(vr, match, cell);
        }
      }
    }

    _placeBadge(viewRow, match, cell) {
      const code = match.code;
      const sc = statusColor(code);

      let top = viewRow * cell.h - 13;
      if (top < 0) top = viewRow * cell.h + 2;

      const el = document.createElement('div');
      el.className = 'http-lens-badge';
      el.style.cssText =
        'position:absolute;' +
        'left:' + Math.max(0, (match.col + match.len + 1) * cell.w) + 'px;' +
        'top:' + top + 'px;' +
        'pointer-events:auto;cursor:pointer;display:flex;align-items:center;gap:3px;' +
        'padding:1px 5px;height:12px;border-radius:3px;' +
        'background:rgba(20,20,20,0.92);border:1px solid ' + sc + '55;' +
        'opacity:0.55;transition:opacity 0.12s,transform 0.12s;' +
        'font-family:-apple-system,sans-serif;font-size:8px;color:' + sc + ';' +
        'white-space:nowrap;font-weight:700;letter-spacing:0.3px;';

      // HTTP icon SVG (small globe)
      el.innerHTML =
        '<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8" viewBox="0 0 24 24" ' +
        'fill="none" stroke="' + sc + '" stroke-width="2.5" stroke-linecap="round" ' +
        'stroke-linejoin="round"><circle cx="12" cy="12" r="10"/>' +
        '<path d="M2 12h20"/>' +
        '<path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>' +
        '</svg>' +
        '<span>' + code + (match.text ? ' ' + truncate(match.text, 12) : '') + '</span>';

      el.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        // Find matching captured response or show what we know
        const resp = capturedResponses.find(r => r.statusCode === code);
        if (resp) {
          showHeaderDetail(resp);
        } else {
          // Create a minimal inline popup
          showMinimalStatus(code, match.text, e.clientX, e.clientY);
        }
      });

      this._overlay.appendChild(el);
    }

    componentWillUnmount() {
      if (this._scanTimer) { clearTimeout(this._scanTimer); this._scanTimer = null; }
      for (const d of this._disposables) d.dispose();
      this._disposables = [];
      if (this._overlay) { this._overlay.remove(); this._overlay = null; }
      this._cache.clear();
    }

    render() {
      return React.createElement(Term, Object.assign({}, this.props, {
        onDecorated: this._onDecorated,
      }));
    }
  };
};

// ------ Minimal status popup for uncaptured responses -----------------

let _miniPopup = null;

function showMinimalStatus(code, text, x, y) {
  if (_miniPopup) { _miniPopup.remove(); _miniPopup = null; }

  const sc = statusColor(code);
  const popup = document.createElement('div');
  popup.style.cssText =
    'position:fixed;z-index:100000;padding:10px 14px;' +
    'background:#1e1e1e;border:1px solid #444;border-radius:6px;' +
    'box-shadow:0 4px 20px rgba(0,0,0,0.6);' +
    'font-family:-apple-system,sans-serif;font-size:12px;color:#c9d1d9;' +
    'max-width:280px;';

  popup.innerHTML =
    '<div style="font-weight:700;color:' + sc + ';font-size:14px;margin-bottom:6px;">' +
    'HTTP ' + code + (text ? ' ' + escHtml(text) : '') + '</div>' +
    '<div style="color:#8b949e;font-size:10px;">Full header analysis available when response is captured via curl -i or curl -v</div>';

  // Position near click
  popup.style.left = Math.min(x, window.innerWidth - 300) + 'px';
  popup.style.top = Math.min(y + 10, window.innerHeight - 100) + 'px';

  document.body.appendChild(popup);
  _miniPopup = popup;

  const dismiss = (e) => {
    if (_miniPopup && !_miniPopup.contains(e.target)) {
      _miniPopup.remove();
      _miniPopup = null;
      document.removeEventListener('mousedown', dismiss, true);
    }
  };
  const dismissEsc = (e) => {
    if (e.key === 'Escape' && _miniPopup) {
      _miniPopup.remove();
      _miniPopup = null;
      document.removeEventListener('keydown', dismissEsc, true);
    }
  };
  setTimeout(() => {
    document.addEventListener('mousedown', dismiss, true);
    document.addEventListener('keydown', dismissEsc, true);
  }, 0);
}
