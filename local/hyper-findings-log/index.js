'use strict';

// ======================================================================
//  HYPER FINDINGS LOG
//  Auto-captures security findings from terminal output.
//  Tags by severity and type. Provides a scrollable findings log in
//  the HUD tab. Export to markdown/JSON for reports.
// ======================================================================

const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

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

const RECON_DIR = path.join(os.homedir(), '.hyper_recon');
const FINDINGS_FILE = path.join(RECON_DIR, 'findings.json');
const LINE_BUFFER_LIMIT = 100;   // Context lines kept per session

// ------ ANSI Stripping ------------------------------------------------

function stripAnsi(str) {
  return str
    .replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '')
    .replace(/\x1b\][^\x07]*\x07/g, '')
    .replace(/\x1b[()][AB012]/g, '')
    .replace(/\x1b[\[>=]/g, '')
    .replace(/[\x00-\x08\x0e-\x1f]/g, '');
}

// ------ Persistence ---------------------------------------------------

function ensureDir() {
  try {
    if (!fs.existsSync(RECON_DIR)) {
      fs.mkdirSync(RECON_DIR, { recursive: true });
    }
  } catch (e) {
    // Silently ignore
  }
}

function loadFindings() {
  try {
    if (fs.existsSync(FINDINGS_FILE)) {
      const raw = fs.readFileSync(FINDINGS_FILE, 'utf8');
      const data = JSON.parse(raw);
      if (Array.isArray(data)) return data;
    }
  } catch (e) {
    // Corrupt file, start fresh
  }
  return [];
}

function saveFindings(findings) {
  try {
    ensureDir();
    fs.writeFileSync(FINDINGS_FILE, JSON.stringify(findings, null, 2), 'utf8');
  } catch (e) {
    // Silently ignore
  }
}

// Debounced save to avoid thrashing disk
let _saveTimer = null;
function debouncedSave(findings) {
  if (_saveTimer) clearTimeout(_saveTimer);
  _saveTimer = setTimeout(() => {
    _saveTimer = null;
    saveFindings(findings);
  }, 2000);
}

// ------ Deduplication -------------------------------------------------

const _seenHashes = new Set();

function findingHash(title, target, type) {
  const key = (title || '') + '|' + (target || '') + '|' + (type || '');
  return crypto.createHash('md5').update(key).digest('hex');
}

function isDuplicate(title, target, type) {
  const h = findingHash(title, target, type);
  return _seenHashes.has(h);
}

function markSeen(title, target, type) {
  const h = findingHash(title, target, type);
  _seenHashes.add(h);
}

// ------ Finding State -------------------------------------------------

let findings = [];
let nextId = 1;
let hudApi = null;
let hudRegistered = false;
let renderCallback = null;

// Per-session line buffers for context
const sessionBuffers = new Map(); // uid -> string[]

function getSessionBuffer(uid) {
  if (!sessionBuffers.has(uid)) {
    sessionBuffers.set(uid, []);
  }
  return sessionBuffers.get(uid);
}

function appendToBuffer(uid, rawData) {
  const buf = getSessionBuffer(uid);
  const cleaned = stripAnsi(rawData);
  const lines = cleaned.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.length > 0) {
      buf.push(trimmed);
    }
  }
  // Enforce limit
  if (buf.length > LINE_BUFFER_LIMIT) {
    buf.splice(0, buf.length - LINE_BUFFER_LIMIT);
  }
}

// ------ Initialize from Disk ------------------------------------------

function initFindings() {
  findings = loadFindings();
  // Rebuild dedup set and nextId
  for (const f of findings) {
    markSeen(f.title, f.target, f.type);
    if (f.id >= nextId) nextId = f.id + 1;
  }
  // Share with recon namespace
  const recon = getRecon();
  recon.findings = findings;
}

// ------ Add Finding ---------------------------------------------------

function addFinding(severity, type, title, detail, source, target, sessionUid) {
  if (isDuplicate(title, target, type)) return null;
  markSeen(title, target, type);

  const finding = {
    id: nextId++,
    timestamp: Date.now(),
    severity,
    type,
    title,
    detail: (detail || '').substring(0, 500),
    source,
    target: target || 'unknown',
    sessionUid: sessionUid || 'unknown',
  };

  findings.unshift(finding);
  const recon = getRecon();
  recon.findings = findings;

  // Emit event for other plugins
  recon.events.emit('finding:new', finding);

  // Persist
  debouncedSave(findings);

  // Update HUD badge
  updateBadge();
  triggerRender();

  // Notify
  if (hudApi) {
    const severityLabels = { critical: 'CRIT', high: 'HIGH', medium: 'MED', low: 'LOW', info: 'INFO' };
    hudApi.notify('[' + (severityLabels[severity] || severity) + '] ' + title, severity === 'critical' ? 'error' : 'info');
  }

  return finding;
}

function clearFindings() {
  findings = [];
  nextId = 1;
  _seenHashes.clear();
  const recon = getRecon();
  recon.findings = findings;
  saveFindings(findings);
  updateBadge();
  triggerRender();
}

function updateBadge() {
  if (!hudApi) return;
  const count = findings.length;
  hudApi.updateBadge('findings', count > 0 ? count : null);
}

function triggerRender() {
  if (renderCallback) renderCallback();
}

// ======================================================================
//  DETECTION PATTERNS
//  Each pattern: { test: RegExp, severity, type, title (string|fn),
//                  source, extractTarget?: RegExp }
// ======================================================================

// Helper: try to extract target from recent buffer lines
function guessTarget(uid) {
  const buf = getSessionBuffer(uid);
  if (!buf || buf.length === 0) return 'unknown';

  // Look backward through buffer for command invocations with targets
  for (let i = buf.length - 1; i >= Math.max(0, buf.length - 20); i--) {
    const line = buf[i];

    // URL targets
    const urlMatch = line.match(/https?:\/\/[^\s"'<>]+/);
    if (urlMatch) return urlMatch[0].substring(0, 120);

    // IP targets
    const ipMatch = line.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
    if (ipMatch) return ipMatch[1];

    // Domain targets
    const domMatch = line.match(/-(?:h|u|target|host)\s+(https?:\/\/\S+|\S+\.\S+)/i);
    if (domMatch) return domMatch[1].substring(0, 120);
  }

  return 'unknown';
}

// Source detection from buffer context
function guessSource(uid) {
  const buf = getSessionBuffer(uid);
  if (!buf || buf.length === 0) return 'unknown';

  const toolPatterns = [
    { re: /sqlmap/i, name: 'sqlmap' },
    { re: /nmap/i, name: 'nmap' },
    { re: /nikto/i, name: 'nikto' },
    { re: /hydra/i, name: 'hydra' },
    { re: /ffuf/i, name: 'ffuf' },
    { re: /gobuster/i, name: 'gobuster' },
    { re: /dirb\b/i, name: 'dirb' },
    { re: /wfuzz/i, name: 'wfuzz' },
    { re: /masscan/i, name: 'masscan' },
    { re: /metasploit|msfconsole|msf/i, name: 'metasploit' },
    { re: /burp/i, name: 'burp' },
    { re: /curl\s/i, name: 'curl' },
    { re: /whatweb/i, name: 'whatweb' },
    { re: /wpscan/i, name: 'wpscan' },
  ];

  // Scan recent lines for tool signatures
  for (let i = buf.length - 1; i >= Math.max(0, buf.length - 30); i--) {
    for (const tp of toolPatterns) {
      if (tp.re.test(buf[i])) return tp.name;
    }
  }

  return 'unknown';
}

// ------ Detection Rules -----------------------------------------------

const DETECTION_RULES = [

  // ═══ CRITICAL: SQLi confirmed ═══

  {
    test: /is vulnerable/i,
    severity: 'critical',
    type: 'sqli',
    title: function (match, line) {
      // sqlmap: "Parameter 'id' is vulnerable"
      const paramMatch = line.match(/Parameter\s+'([^']+)'\s+is\s+vulnerable/i);
      if (paramMatch) return 'SQL Injection in parameter: ' + paramMatch[1];
      return 'SQL Injection confirmed (vulnerable parameter detected)';
    },
    sourceHint: 'sqlmap',
  },
  {
    test: /SQL injection/i,
    severity: 'critical',
    type: 'sqli',
    title: function (match, line) {
      const paramMatch = line.match(/(?:parameter|param)\s*[:\s'"]*(\w+)/i);
      if (paramMatch) return 'SQL Injection: ' + paramMatch[1];
      return 'SQL Injection detected';
    },
    sourceHint: 'sqlmap',
  },

  // ═══ CRITICAL: RCE indicators ═══

  {
    test: /uid=\d+\([^)]+\)\s+gid=\d+/,
    severity: 'critical',
    type: 'rce',
    title: function (match, line) {
      const uidMatch = line.match(/uid=\d+\(([^)]+)\)/);
      const user = uidMatch ? uidMatch[1] : 'unknown';
      return 'RCE confirmed: command execution as ' + user;
    },
    sourceHint: 'manual',
  },
  {
    test: /root:x:0:0:/,
    severity: 'critical',
    type: 'rce',
    title: 'RCE confirmed: /etc/passwd contents leaked',
    sourceHint: 'manual',
  },

  // ═══ CRITICAL: Shell obtained ═══

  {
    test: /www-data@\S+/,
    severity: 'critical',
    type: 'rce',
    title: function (match, line) {
      const hostMatch = line.match(/www-data@(\S+)/);
      const host = hostMatch ? hostMatch[1].replace(/:.*/, '') : 'target';
      return 'Shell obtained: www-data@' + host;
    },
    sourceHint: 'manual',
  },
  {
    test: /root@\S+[:#]/,
    severity: 'critical',
    type: 'rce',
    title: function (match, line) {
      const hostMatch = line.match(/root@(\S+)/);
      const host = hostMatch ? hostMatch[1].replace(/[:#].*/, '') : 'target';
      return 'Root shell obtained: root@' + host;
    },
    sourceHint: 'manual',
  },
  {
    test: /meterpreter\s*>/,
    severity: 'critical',
    type: 'rce',
    title: 'Meterpreter session established',
    sourceHint: 'metasploit',
  },

  // ═══ HIGH: Open admin panels with 200 status ═══

  {
    test: /(?:\/admin|\/manager|\/console).*(?:200|Status:\s*200|HTTP\/[\d.]+\s+200)/,
    severity: 'high',
    type: 'info-disclosure',
    title: function (match, line) {
      const pathMatch = line.match(/(\/(?:admin|manager|console)\S*)/i);
      const p = pathMatch ? pathMatch[1] : '/admin';
      return 'Admin panel accessible: ' + p.substring(0, 80);
    },
    sourceHint: null,
  },
  {
    // Reverse order: status code then path
    test: /(?:200|Status:\s*200|HTTP\/[\d.]+\s+200).*(?:\/admin|\/manager|\/console)/,
    severity: 'high',
    type: 'info-disclosure',
    title: function (match, line) {
      const pathMatch = line.match(/(\/(?:admin|manager|console)\S*)/i);
      const p = pathMatch ? pathMatch[1] : '/admin';
      return 'Admin panel accessible: ' + p.substring(0, 80);
    },
    sourceHint: null,
  },

  // ═══ HIGH: Default credentials / valid creds found ═══

  {
    test: /\[VALID\]/i,
    severity: 'high',
    type: 'credential',
    title: function (match, line) {
      // Try to extract credential info
      const credMatch = line.match(/login:\s*(\S+).*password:\s*(\S+)/i);
      if (credMatch) return 'Valid credentials found: ' + credMatch[1] + ':' + credMatch[2];
      return 'Valid credentials found';
    },
    sourceHint: null,
  },
  {
    test: /login:\s*\S+\s+password:\s*\S+/i,
    severity: 'high',
    type: 'credential',
    title: function (match, line) {
      const credMatch = line.match(/login:\s*(\S+)\s+password:\s*(\S+)/i);
      if (credMatch) return 'Credentials found: ' + credMatch[1] + ':' + credMatch[2];
      return 'Credentials discovered via brute force';
    },
    sourceHint: 'hydra',
  },

  // ═══ HIGH: File read (sensitive files) ═══

  {
    test: /\/etc\/shadow/,
    severity: 'high',
    type: 'info-disclosure',
    title: '/etc/shadow file contents exposed',
    sourceHint: 'manual',
  },

  // ═══ HIGH: OSVDB findings from nikto ═══

  {
    test: /OSVDB-\d+/,
    severity: 'high',
    type: 'misc',
    title: function (match, line) {
      const osvdbMatch = line.match(/OSVDB-(\d+)/);
      const id = osvdbMatch ? osvdbMatch[1] : '?';
      // Get the description after the OSVDB reference
      const descMatch = line.match(/OSVDB-\d+:\s*(.+)/);
      const desc = descMatch ? descMatch[1].substring(0, 100).trim() : '';
      return 'OSVDB-' + id + (desc ? ': ' + desc : '');
    },
    sourceHint: 'nikto',
  },

  // ═══ MEDIUM: XSS reflected ═══

  {
    test: /alert\s*\(/,
    severity: 'medium',
    type: 'xss',
    title: function (match, line) {
      const payloadMatch = line.match(/(alert\([^)]*\))/);
      const payload = payloadMatch ? payloadMatch[1] : 'alert()';
      return 'Potential XSS: ' + payload.substring(0, 60);
    },
    sourceHint: null,
  },
  {
    test: /<script>/i,
    severity: 'medium',
    type: 'xss',
    title: 'Potential XSS: <script> tag found in response',
    sourceHint: null,
  },

  // ═══ MEDIUM: Directory listing ═══

  {
    test: /Index of \//,
    severity: 'medium',
    type: 'info-disclosure',
    title: function (match, line) {
      const dirMatch = line.match(/Index of (\/\S*)/);
      const dir = dirMatch ? dirMatch[1] : '/';
      return 'Directory listing enabled: ' + dir.substring(0, 80);
    },
    sourceHint: null,
  },

  // ═══ MEDIUM: Information disclosure - version strings ═══

  {
    test: /(?:Server|X-Powered-By):\s*\S+\/[\d.]+/i,
    severity: 'medium',
    type: 'info-disclosure',
    title: function (match, line) {
      const headerMatch = line.match(/((?:Server|X-Powered-By):\s*\S+)/i);
      if (headerMatch) return 'Version disclosure: ' + headerMatch[1].substring(0, 80);
      return 'Server version disclosed in headers';
    },
    sourceHint: null,
  },

  // ═══ MEDIUM: Stack traces ═══

  {
    test: /(?:Traceback \(most recent call last\)|at \S+\.java:\d+|Exception in thread|Fatal error:.*on line \d+)/,
    severity: 'medium',
    type: 'info-disclosure',
    title: function (match, line) {
      if (/Traceback/.test(line)) return 'Stack trace exposed: Python traceback';
      if (/\.java:/.test(line)) return 'Stack trace exposed: Java exception';
      if (/Fatal error/.test(line)) return 'Stack trace exposed: PHP fatal error';
      return 'Stack trace / error details exposed';
    },
    sourceHint: null,
  },

  // ═══ MEDIUM: Missing security headers ═══

  {
    test: /(?:Missing header|The (?:anti-clickjacking|X-Frame-Options|X-Content-Type-Options|Content-Security-Policy) header)/i,
    severity: 'medium',
    type: 'misc',
    title: function (match, line) {
      const headerMatch = line.match(/(X-Frame-Options|X-Content-Type-Options|Content-Security-Policy|Strict-Transport-Security|X-XSS-Protection)/i);
      if (headerMatch) return 'Missing security header: ' + headerMatch[1];
      return 'Missing security header detected';
    },
    sourceHint: 'nikto',
  },

  // ═══ LOW: Open ports from nmap ═══

  {
    test: /^\s*(\d{1,5})\/(?:tcp|udp)\s+open\s+(\S+)/,
    severity: 'low',
    type: 'open-port',
    title: function (match, line) {
      const portMatch = line.match(/(\d{1,5})\/(tcp|udp)\s+open\s+(\S+)/);
      if (portMatch) {
        const version = line.match(/open\s+\S+\s+(.+)/);
        const ver = version ? version[1].trim().substring(0, 60) : '';
        return 'Port ' + portMatch[1] + '/' + portMatch[2] + ' open: ' + portMatch[3] + (ver ? ' (' + ver + ')' : '');
      }
      return 'Open port discovered';
    },
    sourceHint: 'nmap',
  },

  // ═══ LOW/INFO: Discovered paths (ffuf/gobuster with status codes) ═══

  {
    // ffuf output: URL [Status: 200, Size: 1234, ...]
    test: /\[Status:\s*(200|301|302|403)\b/,
    severity: 'info',
    type: 'path',
    title: function (match, line) {
      const urlMatch = line.match(/(https?:\/\/\S+)/);
      const statusMatch = line.match(/\[Status:\s*(\d+)/);
      const status = statusMatch ? statusMatch[1] : '?';
      const url = urlMatch ? urlMatch[0].substring(0, 80) : 'path';
      return 'Path discovered [' + status + ']: ' + url;
    },
    sourceHint: 'ffuf',
  },
  {
    // gobuster output: /path (Status: 200) [Size: 1234]
    test: /\(Status:\s*(200|301|302|403)\)/,
    severity: 'info',
    type: 'path',
    title: function (match, line) {
      const pathMatch = line.match(/(\/\S+)\s+\(Status:\s*(\d+)\)/);
      if (pathMatch) return 'Path discovered [' + pathMatch[2] + ']: ' + pathMatch[1].substring(0, 80);
      return 'Path discovered';
    },
    sourceHint: 'gobuster',
  },

  // ═══ INFO: DNS records ═══

  {
    test: /\b(?:IN\s+(?:A|AAAA|MX|NS|CNAME|TXT|SOA|SRV|PTR)\s+)/,
    severity: 'info',
    type: 'misc',
    title: function (match, line) {
      const typeMatch = line.match(/IN\s+(A|AAAA|MX|NS|CNAME|TXT|SOA|SRV|PTR)\s+(\S+)/);
      if (typeMatch) return 'DNS ' + typeMatch[1] + ' record: ' + typeMatch[2].substring(0, 80);
      return 'DNS record discovered';
    },
    sourceHint: 'manual',
  },

  // ═══ INFO: SSL certificate info ═══

  {
    test: /(?:subject:\s*CN\s*=|issuer:\s*CN\s*=|SSL certificate)/i,
    severity: 'info',
    type: 'misc',
    title: function (match, line) {
      const cnMatch = line.match(/CN\s*=\s*(\S+)/);
      if (cnMatch) return 'SSL certificate: CN=' + cnMatch[1].substring(0, 60);
      return 'SSL certificate information';
    },
    sourceHint: null,
  },

  // ═══ INFO: Server headers ═══

  {
    test: /^Server:\s+(.+)/i,
    severity: 'info',
    type: 'info-disclosure',
    title: function (match, line) {
      const serverMatch = line.match(/^Server:\s+(.+)/i);
      if (serverMatch) return 'Server header: ' + serverMatch[1].trim().substring(0, 80);
      return 'Server header detected';
    },
    sourceHint: null,
  },
];

// ======================================================================
//  DETECTION ENGINE
// ======================================================================

function processData(uid, rawData) {
  const cleaned = stripAnsi(rawData);
  const lines = cleaned.split(/\r?\n/);

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.length < 3) continue;

    for (const rule of DETECTION_RULES) {
      if (rule.test.test(trimmed)) {
        const title = typeof rule.title === 'function'
          ? rule.title(trimmed.match(rule.test), trimmed)
          : rule.title;

        const source = rule.sourceHint || guessSource(uid);
        const target = guessTarget(uid);

        addFinding(
          rule.severity,
          rule.type,
          title,
          trimmed,
          source,
          target,
          uid
        );

        // Only match first rule per line to avoid duplicates
        break;
      }
    }
  }
}

// ======================================================================
//  EXPORT FUNCTIONS
// ======================================================================

function exportMarkdown() {
  const now = new Date().toISOString().replace('T', ' ').replace(/\.\d+Z/, ' UTC');
  const sections = ['critical', 'high', 'medium', 'low', 'info'];
  const sectionLabels = {
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
    info: 'Informational',
  };

  let md = '# Security Findings Report\n';
  md += 'Generated: ' + now + '\n\n';

  // Summary
  const counts = {};
  for (const sev of sections) counts[sev] = 0;
  for (const f of findings) {
    if (counts[f.severity] !== undefined) counts[f.severity]++;
  }
  md += '## Summary\n';
  md += '| Severity | Count |\n';
  md += '|----------|-------|\n';
  for (const sev of sections) {
    md += '| ' + sectionLabels[sev] + ' | ' + counts[sev] + ' |\n';
  }
  md += '\n---\n\n';

  for (const sev of sections) {
    const items = findings.filter(f => f.severity === sev);
    if (items.length === 0) continue;

    md += '## ' + sectionLabels[sev] + ' (' + items.length + ')\n\n';
    for (const f of items) {
      md += '### ' + f.title + '\n';
      md += '- **Severity:** ' + f.severity + '\n';
      md += '- **Type:** ' + f.type + '\n';
      md += '- **Target:** ' + f.target + '\n';
      md += '- **Source:** ' + f.source + '\n';
      md += '- **Time:** ' + new Date(f.timestamp).toISOString() + '\n';
      if (f.detail) {
        md += '- **Detail:** `' + f.detail.replace(/`/g, "'") + '`\n';
      }
      md += '\n';
    }
  }

  return md;
}

function exportHTML() {
  const now = new Date().toISOString().replace('T', ' ').replace(/\.\d+Z/, ' UTC');
  const sections = ['critical', 'high', 'medium', 'low', 'info'];
  const sectionColors = {
    critical: '#f85149',
    high: '#f97316',
    medium: '#fbbf24',
    low: '#58a6ff',
    info: '#8b949e',
  };

  function escapeHtml(str) {
    if (typeof str !== 'string') return String(str);
    return str.replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;')
              .replace(/'/g, '&#039;');
  }

  let html = `<!DOCTYPE html>
<html>
<head>
<title>Security Findings Report</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }
h1 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
h2 { color: #c9d1d9; margin-top: 30px; border-bottom: 1px solid #21262d; padding-bottom: 5px; }
.summary-table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
.summary-table th, .summary-table td { text-align: left; padding: 8px; border-bottom: 1px solid #30363d; }
.finding { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 15px; margin-bottom: 15px; border-left-width: 5px; }
.title { font-size: 16px; font-weight: bold; color: #e6edf3; display: flex; align-items: center; justify-content: space-between; }
.meta { font-size: 12px; color: #8b949e; margin-top: 5px; font-family: monospace; }
.detail { background: #0d1117; padding: 10px; border-radius: 4px; margin-top: 10px; font-family: monospace; font-size: 12px; white-space: pre-wrap; word-break: break-all; color: #8b949e; border: 1px solid #21262d; }
.badge { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: bold; text-transform: uppercase; color: #fff; }
</style>
</head>
<body>
<h1>Security Findings Report</h1>
<p>Generated: ${now}</p>
<h2>Summary</h2>
<table class="summary-table">
<tr><th>Severity</th><th>Count</th></tr>
`;

  const counts = {};
  for (const sev of sections) counts[sev] = 0;
  for (const f of findings) {
    if (counts[f.severity] !== undefined) counts[f.severity]++;
  }

  for (const sev of sections) {
    html += `<tr><td><span class="badge" style="background:${sectionColors[sev]}">${sev}</span></td><td>${counts[sev]}</td></tr>`;
  }
  html += `</table>`;

  for (const sev of sections) {
    const items = findings.filter(f => f.severity === sev);
    if (items.length === 0) continue;

    html += `<h2>${sev.toUpperCase()} Findings (${items.length})</h2>`;
    for (const f of items) {
      const color = sectionColors[sev];
      html += `
<div class="finding" style="border-left-color: ${color}">
  <div class="title">
    <span>${escapeHtml(f.title)}</span>
    <span class="badge" style="background:${color}">${sev}</span>
  </div>
  <div class="meta">
    Type: ${escapeHtml(f.type)} | Target: <span style="color:#58a6ff">${escapeHtml(f.target)}</span> | Source: ${escapeHtml(f.source)} | Time: ${new Date(f.timestamp).toISOString()}
  </div>
  ${f.detail ? `<div class="detail">${escapeHtml(f.detail)}</div>` : ''}
</div>`;
    }
  }

  html += `</body></html>`;
  return html;
}

function exportJSON() {
  return JSON.stringify({
    generated: new Date().toISOString(),
    count: findings.length,
    findings: findings,
  }, null, 2);
}

function saveExport(content, ext) {
  ensureDir();
  const ts = new Date().toISOString().replace(/[:.]/g, '-').replace('T', '_').replace(/Z$/, '');
  const filename = 'findings_' + ts + '.' + ext;
  const filepath = path.join(RECON_DIR, filename);
  try {
    fs.writeFileSync(filepath, content, 'utf8');
    if (hudApi) {
      hudApi.notify('Exported to ' + filepath, 'info');
    }
    return filepath;
  } catch (e) {
    if (hudApi) {
      hudApi.notify('Export failed: ' + e.message, 'error');
    }
    return null;
  }
}

// ======================================================================
//  HUD TAB RENDER
// ======================================================================

// UI state
let filterSeverity = 'all';
let expandedId = null;

// Severity colors
const SEVERITY_COLORS = {
  critical: '#f85149',
  high:     '#f97316',
  medium:   '#fbbf24',
  low:      '#58a6ff',
  info:     '#8b949e',
};

// Type icons (unicode)
const TYPE_ICONS = {
  sqli:             '\u{1F4A5}',
  rce:              '\u{1F4A3}',
  xss:              '\u26A0',
  auth:             '\u{1F511}',
  'info-disclosure': '\u{1F441}',
  'open-port':      '\u{1F6AA}',
  path:             '\u{1F4C2}',
  credential:       '\u{1F512}',
  misc:             '\u{1F4CB}',
};

function renderFindingsTab(React) {
  const h = React.createElement;

  // Inject styles if not already done
  if (typeof document !== 'undefined' && !document.getElementById('findings-log-styles')) {
    const style = document.createElement('style');
    style.id = 'findings-log-styles';
    style.textContent = [
      '.findings-filter-btn { transition: background 0.15s, color 0.15s, border-color 0.15s; }',
      '.findings-filter-btn:hover { border-color: #58a6ff !important; color: #c9d1d9 !important; }',
      '.findings-row { transition: border-color 0.15s, background 0.15s; }',
      '.findings-row:hover { border-color: #30363d !important; background: #1c2128 !important; }',
      '.findings-action-btn { transition: background 0.15s, color 0.15s; }',
      '.findings-action-btn:hover { background: #21262d !important; color: #f0f6fc !important; }',
      '.findings-export-btn:hover { background: #238636 !important; border-color: #2ea043 !important; }',
      '.findings-clear-btn:hover { background: #da3633 !important; border-color: #f85149 !important; }',
    ].join('\n');
    document.head.appendChild(style);
  }

  // Filter buttons
  const severities = ['all', 'critical', 'high', 'medium', 'low', 'info'];
  const filterBar = h('div', {
    style: {
      display: 'flex', alignItems: 'center', gap: '4px',
      marginBottom: '8px', flexWrap: 'wrap',
    },
  },
    // Severity filter buttons
    ...severities.map(sev => {
      const isActive = filterSeverity === sev;
      const color = sev === 'all' ? '#c9d1d9' : (SEVERITY_COLORS[sev] || '#8b949e');
      const count = sev === 'all' ? findings.length : findings.filter(f => f.severity === sev).length;

      return h('span', {
        key: sev,
        className: 'findings-filter-btn',
        style: {
          padding: '2px 8px',
          borderRadius: '10px',
          fontSize: '10px',
          fontWeight: isActive ? 700 : 400,
          cursor: 'pointer',
          userSelect: 'none',
          background: isActive ? color + '22' : 'transparent',
          color: isActive ? color : '#8b949e',
          border: '1px solid ' + (isActive ? color + '66' : '#21262d'),
        },
        onClick: () => {
          filterSeverity = sev;
          triggerRender();
        },
      }, (sev === 'all' ? 'All' : sev.charAt(0).toUpperCase() + sev.slice(1)) + ' (' + count + ')');
    }),

    // Spacer
    h('div', { style: { flex: 1 } }),

    // Export MD
    h('span', {
      className: 'findings-action-btn findings-export-btn',
      style: {
        padding: '2px 8px', borderRadius: '4px', fontSize: '10px',
        cursor: 'pointer', userSelect: 'none', color: '#3fb950',
        border: '1px solid #238636', background: 'transparent',
      },
      onClick: () => {
        const md = exportMarkdown();
        saveExport(md, 'md');
      },
      title: 'Export findings as Markdown',
    }, 'Export MD'),

    // Export JSON
    h('span', {
      className: 'findings-action-btn findings-export-btn',
      style: {
        padding: '2px 8px', borderRadius: '4px', fontSize: '10px',
        cursor: 'pointer', userSelect: 'none', color: '#3fb950',
        border: '1px solid #238636', background: 'transparent',
      },
      onClick: () => {
        const json = exportJSON();
        saveExport(json, 'json');
      },
      title: 'Export findings as JSON',
    }, 'Export JSON'),

    // Export HTML
    h('span', {
      className: 'findings-action-btn findings-export-btn',
      style: {
        padding: '2px 8px', borderRadius: '4px', fontSize: '10px',
        cursor: 'pointer', userSelect: 'none', color: '#3fb950',
        border: '1px solid #238636', background: 'transparent',
      },
      onClick: () => {
        const html = exportHTML();
        saveExport(html, 'html');
      },
      title: 'Export findings as HTML',
    }, 'Export HTML'),

    // Clear
    h('span', {
      className: 'findings-action-btn findings-clear-btn',
      style: {
        padding: '2px 8px', borderRadius: '4px', fontSize: '10px',
        cursor: 'pointer', userSelect: 'none', color: '#f85149',
        border: '1px solid #da3633', background: 'transparent',
      },
      onClick: () => {
        clearFindings();
      },
      title: 'Clear all findings',
    }, 'Clear')
  );

  // Filtered findings
  const filtered = filterSeverity === 'all'
    ? findings
    : findings.filter(f => f.severity === filterSeverity);

  // Empty state
  if (filtered.length === 0) {
    return h('div', { style: { display: 'flex', flexDirection: 'column', height: '100%' } },
      filterBar,
      h('div', {
        style: {
          flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
          color: '#484f58', fontSize: '12px', fontStyle: 'italic',
        },
      }, filterSeverity === 'all'
        ? 'No findings detected yet. Run security scans to auto-capture results.'
        : 'No ' + filterSeverity + ' findings.')
    );
  }

  // Findings list
  const list = h('div', {
    style: {
      flex: 1, overflowY: 'auto', display: 'flex',
      flexDirection: 'column', gap: '3px',
    },
  },
    filtered.map(finding => renderFindingRow(React, finding))
  );

  return h('div', { style: { display: 'flex', flexDirection: 'column', height: '100%' } },
    filterBar,
    list
  );
}

function renderFindingRow(React, finding) {
  const h = React.createElement;
  const isExpanded = expandedId === finding.id;
  const color = SEVERITY_COLORS[finding.severity] || '#8b949e';
  const icon = TYPE_ICONS[finding.type] || '\u2022';
  const timeStr = new Date(finding.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const dateStr = new Date(finding.timestamp).toLocaleDateString([], { month: 'short', day: 'numeric' });

  return h('div', {
    key: finding.id,
    className: 'findings-row',
    style: {
      background: '#161b22',
      border: '1px solid #21262d',
      borderLeft: '3px solid ' + color,
      borderRadius: '4px',
      padding: '5px 8px',
      cursor: 'pointer',
    },
    onClick: () => {
      expandedId = isExpanded ? null : finding.id;
      triggerRender();
    },
  },
    // Main row
    h('div', {
      style: {
        display: 'flex', alignItems: 'center', gap: '6px',
      },
    },
      // Severity badge
      h('span', {
        style: {
          fontSize: '8px', fontWeight: 700, padding: '1px 5px',
          borderRadius: '6px', textTransform: 'uppercase',
          letterSpacing: '0.3px', flexShrink: 0,
          background: color + '22',
          color: color,
          border: '1px solid ' + color + '44',
          minWidth: '36px', textAlign: 'center',
        },
      }, finding.severity === 'critical' ? 'CRIT'
        : finding.severity === 'medium' ? 'MED'
        : finding.severity.toUpperCase()),

      // Type icon
      h('span', {
        style: { fontSize: '11px', flexShrink: 0, width: '16px', textAlign: 'center' },
        title: finding.type,
      }, icon),

      // Title
      h('span', {
        style: {
          fontSize: '11px', color: '#e6edf3', flex: 1,
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        },
        title: finding.title,
      }, finding.title),

      // Target (truncated)
      finding.target !== 'unknown' && h('span', {
        style: {
          fontSize: '9px', color: '#58a6ff', flexShrink: 0,
          maxWidth: '150px', overflow: 'hidden', textOverflow: 'ellipsis',
          whiteSpace: 'nowrap', fontFamily: 'monospace',
        },
        title: finding.target,
      }, finding.target),

      // Source badge
      h('span', {
        style: {
          fontSize: '8px', color: '#8b949e', flexShrink: 0,
          padding: '0 4px', background: '#21262d', borderRadius: '3px',
        },
      }, finding.source),

      // Timestamp
      h('span', {
        style: {
          fontSize: '9px', color: '#484f58', flexShrink: 0,
          fontFamily: 'monospace', whiteSpace: 'nowrap',
        },
      }, dateStr + ' ' + timeStr),

      // Expand indicator
      h('span', {
        style: { fontSize: '9px', color: '#484f58', flexShrink: 0 },
      }, isExpanded ? '\u25B2' : '\u25BC')
    ),

    // Expanded detail
    isExpanded && h('div', {
      style: {
        marginTop: '6px', padding: '6px 8px',
        background: '#0d1117', border: '1px solid #21262d',
        borderRadius: '4px', fontSize: '10px',
        fontFamily: '"Cascadia Code", "Fira Code", "JetBrains Mono", monospace',
        lineHeight: 1.6, color: '#8b949e',
      },
      onClick: (e) => e.stopPropagation(),
    },
      h('div', null,
        h('span', { style: { color: '#484f58' } }, 'ID: '),
        h('span', null, String(finding.id))
      ),
      h('div', null,
        h('span', { style: { color: '#484f58' } }, 'Type: '),
        h('span', null, finding.type)
      ),
      h('div', null,
        h('span', { style: { color: '#484f58' } }, 'Target: '),
        h('span', { style: { color: '#58a6ff' } }, finding.target)
      ),
      h('div', null,
        h('span', { style: { color: '#484f58' } }, 'Source: '),
        h('span', null, finding.source)
      ),
      h('div', null,
        h('span', { style: { color: '#484f58' } }, 'Session: '),
        h('span', null, finding.sessionUid)
      ),
      h('div', null,
        h('span', { style: { color: '#484f58' } }, 'Time: '),
        h('span', null, new Date(finding.timestamp).toISOString())
      ),
      finding.detail && h('div', { style: { marginTop: '4px' } },
        h('span', { style: { color: '#484f58' } }, 'Detail: '),
        h('div', {
          style: {
            marginTop: '2px', padding: '4px 6px',
            background: '#161b22', borderRadius: '3px',
            whiteSpace: 'pre-wrap', wordBreak: 'break-all',
            color: '#c9d1d9', maxHeight: '120px', overflowY: 'auto',
          },
        }, finding.detail)
      )
    )
  );
}

// ======================================================================
//  HUD REGISTRATION
// ======================================================================

function registerHud() {
  if (hudRegistered) return;
  const recon = getRecon();

  const renderFn = (React) => renderFindingsTab(React);

  if (recon.hud) {
    hudApi = recon.hud;
    recon.hud.registerTab('findings', 'Findings', null, renderFn);
    hudRegistered = true;
    updateBadge();
  } else {
    recon.events.on('hud:ready', (hud) => {
      hudApi = hud;
      hud.registerTab('findings', 'Findings', null, renderFn);
      hudRegistered = true;
      updateBadge();
    });
  }
}

// ======================================================================
//  LISTEN FOR OUTPUT PARSER EVENTS
// ======================================================================

function listenForParsedEvents() {
  const recon = getRecon();
  recon.events.on('parsed:any', (data) => {
    // If the output-parser emits structured parsed events, we can ingest them
    if (data && data.type && data.detail) {
      const severity = data.severity || 'info';
      const type = data.findingType || 'misc';
      const title = data.title || data.type + ' detected';
      addFinding(severity, type, title, data.detail, data.source || 'output-parser', data.target || 'unknown', data.uid || 'unknown');
    }
  });
}

// ======================================================================
//  HYPER PLUGIN EXPORTS
// ======================================================================

// Middleware: intercept PTY data for auto-detection

exports.middleware = (store) => (next) => (action) => {
  switch (action.type) {
    case 'SESSION_ADD': {
      // Initialize findings on first session
      if (findings.length === 0 && _seenHashes.size === 0) {
        initFindings();
      }
      break;
    }

    case 'SESSION_PTY_DATA': {
      const uid = action.uid;
      const data = action.data;

      // Feed line buffer
      appendToBuffer(uid, data);

      // Run detection engine
      processData(uid, data);
      break;
    }

    case 'SESSION_PTY_EXIT':
    case 'SESSION_USER_EXIT': {
      sessionBuffers.delete(action.uid);
      break;
    }
  }

  return next(action);
};

// decorateHyper: register HUD tab

exports.decorateHyper = (Hyper, { React }) => {
  return class FindingsLogHyper extends React.Component {
    constructor(props) {
      super(props);
      this._mounted = false;
    }

    componentDidMount() {
      this._mounted = true;

      // Initialize from disk
      initFindings();

      renderCallback = () => {
        if (this._mounted) {
          this.forceUpdate();
          updateBadge();
        }
      };

      registerHud();
      listenForParsedEvents();
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
