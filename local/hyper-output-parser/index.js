'use strict';

// ══════════════════════════════════════════════════════════════
//  HYPER OUTPUT PARSER
//  Real-time parser for security tool output in the terminal.
//  Watches SESSION_PTY_DATA, strips ANSI, buffers lines, runs
//  tool-specific parsers, and emits structured data on the
//  shared __hyperRecon event bus for other plugins to consume.
// ══════════════════════════════════════════════════════════════

const { clipboard } = require('electron');
const EventEmitter = require('events');

// ─── Constants ─────────────────────────────────────────────────
const MAX_BUFFER_LINES = 200;
const PARSE_DEBOUNCE_MS = 80;
const MAX_HISTORY = 500;

// ─── Shared Recon Namespace ────────────────────────────────────
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

// ─── ANSI Stripping ────────────────────────────────────────────
function stripAnsi(str) {
  return str
    .replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '')
    .replace(/\x1b\][^\x07]*\x07/g, '')
    .replace(/\x1b[()][AB012]/g, '')
    .replace(/\x1b\[[\?]?[0-9;]*[hlm]/g, '')
    .replace(/\r/g, '');
}


// ══════════════════════════════════════════════════════════════
//  TOOL PARSERS
//  Each parser has: detect(), parse(lines), and returns
//  structured result objects to be emitted on the event bus.
// ══════════════════════════════════════════════════════════════

// ─── Nmap Parser ───────────────────────────────────────────────
const nmapParser = {
  name: 'nmap',

  detect(line) {
    return /^Starting Nmap\b/i.test(line) ||
           /^Nmap scan report for\b/i.test(line);
  },

  parse(lines) {
    const results = [];
    let target = null;
    let ports = [];
    let os = null;
    let scripts = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Target extraction
      const targetMatch = line.match(/Nmap scan report for\s+(\S+)/i);
      if (targetMatch) {
        // Flush previous target if exists
        if (target && (ports.length || os || scripts.length)) {
          results.push({ tool: 'nmap', target, ports: [...ports], os, scripts: [...scripts] });
        }
        target = targetMatch[1].replace(/[()]/g, '');
        ports = [];
        os = null;
        scripts = [];
        continue;
      }

      // Starting Nmap line — extract target if embedded
      const startMatch = line.match(/Starting Nmap\b/i);
      if (startMatch && !target) {
        // Target may appear later; just mark that nmap is running
        continue;
      }

      // Port lines: PORT/PROTO STATE SERVICE [VERSION]
      // e.g. "22/tcp   open  ssh     OpenSSH 8.2p1"
      // e.g. "80/tcp   open  http    Apache httpd 2.4.41"
      const portMatch = line.match(
        /^(\d{1,5})\/(tcp|udp)\s+(open|closed|filtered|open\|filtered)\s+(\S+)(?:\s+(.+))?$/
      );
      if (portMatch) {
        ports.push({
          port: parseInt(portMatch[1], 10),
          proto: portMatch[2],
          state: portMatch[3],
          service: portMatch[4],
          version: portMatch[5] ? portMatch[5].trim() : '',
        });
        continue;
      }

      // OS detection
      const osMatch = line.match(/^OS details:\s*(.+)/i) ||
                       line.match(/^Running:\s*(.+)/i);
      if (osMatch) {
        os = osMatch[1].trim();
        continue;
      }

      // Script output (NSE)
      const scriptMatch = line.match(/^\|[_ ](\S+):\s*(.*)$/);
      if (scriptMatch) {
        scripts.push({
          id: scriptMatch[1].replace(/^_/, ''),
          output: scriptMatch[2].trim(),
        });
        continue;
      }

      // Continuation of script output (indented |  lines)
      const scriptCont = line.match(/^\|\s{2,}(.+)$/);
      if (scriptCont && scripts.length > 0) {
        scripts[scripts.length - 1].output += ' ' + scriptCont[1].trim();
        continue;
      }
    }

    // Flush last target
    if (target && (ports.length || os || scripts.length)) {
      results.push({ tool: 'nmap', target, ports, os, scripts });
    }

    return results;
  },
};


// ─── Nikto Parser ──────────────────────────────────────────────
const niktoParser = {
  name: 'nikto',

  detect(line) {
    return /^- Nikto v/i.test(line) ||
           /^\+ Target IP:/i.test(line) ||
           /^\+ Target Hostname:/i.test(line);
  },

  parse(lines) {
    const results = [];
    let target = null;
    let findings = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Target extraction
      const targetIp = line.match(/^\+ Target IP:\s*(\S+)/i);
      if (targetIp) {
        target = targetIp[1];
        continue;
      }

      const targetHost = line.match(/^\+ Target Hostname:\s*(\S+)/i);
      if (targetHost) {
        target = targetHost[1];
        continue;
      }

      // OSVDB finding: "+ OSVDB-3268: /icons/: Directory indexing found."
      const osvdbMatch = line.match(/^\+\s+(OSVDB-\d+):\s+(\S+):\s+(.+)/);
      if (osvdbMatch) {
        findings.push({
          id: osvdbMatch[1],
          path: osvdbMatch[2],
          description: osvdbMatch[3].trim(),
          severity: guessSeverity(osvdbMatch[3]),
        });
        continue;
      }

      // Generic finding: "+ /path: description..."
      const genericMatch = line.match(/^\+\s+(\/\S+):\s+(.+)/);
      if (genericMatch) {
        // Skip non-finding lines (e.g. banner info)
        const desc = genericMatch[2].trim();
        if (desc.length > 5 && !/^Start Time:|^End Time:|^\d+ host/i.test(desc)) {
          findings.push({
            id: null,
            path: genericMatch[1],
            description: desc,
            severity: guessSeverity(desc),
          });
        }
        continue;
      }

      // Finding without path: "+ The X-XSS-Protection header is not defined..."
      const findingNoPath = line.match(/^\+\s+(?!Target|Start|End|Nikto|Server)(.{10,})/);
      if (findingNoPath && !line.match(/^\+ \d+ (host|item)/)) {
        const desc = findingNoPath[1].trim();
        // Only capture meaningful findings
        if (/header|vulnerability|injection|xss|csrf|security|leak|exposure|disclosure|traversal/i.test(desc)) {
          findings.push({
            id: null,
            path: null,
            description: desc,
            severity: guessSeverity(desc),
          });
        }
      }
    }

    if (target && findings.length) {
      results.push({ tool: 'nikto', target, findings });
    }

    return results;
  },
};

function guessSeverity(desc) {
  const d = desc.toLowerCase();
  if (/remote code|rce|command injection|sql injection|arbitrary file|critical/i.test(d)) return 'critical';
  if (/xss|cross-site|csrf|traversal|directory listing|upload|lfi|rfi/i.test(d)) return 'high';
  if (/header|cookie|clickjack|information|version|disclosure|leak/i.test(d)) return 'medium';
  return 'low';
}


// ─── SQLMap Parser ─────────────────────────────────────────────
const sqlmapParser = {
  name: 'sqlmap',

  detect(line) {
    return /\[INFO\]\s*testing/i.test(line) ||
           /sqlmap identified/i.test(line) ||
           /\[INFO\]\s*the back-end DBMS is/i.test(line);
  },

  parse(lines) {
    const results = [];
    let target = null;
    let injectable = [];
    let databases = [];
    let tables = [];
    let dbms = null;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Target URL
      const urlMatch = line.match(/\[INFO\]\s*testing\s+'([^']+)'/i) ||
                        line.match(/\[INFO\]\s*testing\s+(?:connection to the target )?URL\s+'?(\S+)/i) ||
                        line.match(/URL:\s*(\S+)/i);
      if (urlMatch && !target) {
        target = urlMatch[1].replace(/'/g, '');
      }

      // Target from resumed session
      const resumeTarget = line.match(/\[INFO\]\s*resuming back-end DBMS.*URL\s+'?(\S+)/i);
      if (resumeTarget) {
        target = resumeTarget[1].replace(/'/g, '');
      }

      // Injectable parameter
      // "Parameter: id (GET)"
      // "Parameter: user (POST)"
      const paramMatch = line.match(/Parameter:\s*(\S+)\s*\((\w+)\)/i);
      if (paramMatch) {
        const param = paramMatch[1];
        const method = paramMatch[2];

        // Look ahead for technique details
        let technique = '';
        for (let j = i + 1; j < Math.min(i + 5, lines.length); j++) {
          const techMatch = lines[j].match(/Type:\s*(.+)/i);
          if (techMatch) {
            technique = techMatch[1].trim();
            break;
          }
        }

        // Avoid duplicates
        if (!injectable.find(x => x.param === param && x.type === method)) {
          injectable.push({ param, type: method, technique });
        }
        continue;
      }

      // "sqlmap identified the following injection point(s)"
      if (/sqlmap identified/i.test(line)) {
        // Parsing will be handled by Parameter lines above
        continue;
      }

      // Database names: "[*] dbname"
      const dbMatch = line.match(/^\[\*\]\s+(\S+)$/);
      if (dbMatch) {
        const name = dbMatch[1];
        if (!/^---/.test(name) && name.length > 0) {
          databases.push(name);
        }
        continue;
      }

      // Table names from "Database: xxx" + "| tablename |"
      const tableMatch = line.match(/^\|\s+(\S+)\s+\|$/);
      if (tableMatch) {
        const t = tableMatch[1];
        if (t !== 'Table' && !/^-+$/.test(t)) {
          tables.push(t);
        }
        continue;
      }

      // DBMS identification
      const dbmsMatch = line.match(/\[INFO\]\s*the back-end DBMS is\s+(.+)/i);
      if (dbmsMatch) {
        dbms = dbmsMatch[1].trim();
        continue;
      }
    }

    // If no explicit target, try to find from testing lines
    if (!target) {
      for (const line of lines) {
        const m = line.match(/\[INFO\]\s*testing\s+connection to the target\s+URL\s+'?(\S+)/i);
        if (m) { target = m[1].replace(/'/g, ''); break; }
      }
    }

    if (target || injectable.length || databases.length) {
      results.push({
        tool: 'sqlmap',
        target: target || 'unknown',
        injectable,
        databases,
        tables,
        dbms,
      });
    }

    return results;
  },
};


// ─── FFuf / Gobuster Parser ───────────────────────────────────
const ffufGobusterParser = {
  name: 'ffuf/gobuster',

  detect(line) {
    return /^:: Method\s*:/i.test(line) ||        // ffuf header
           /^:: URL\s*:/i.test(line) ||            // ffuf header
           /^\s*Gobuster v/i.test(line) ||         // gobuster banner
           /^={10,}/i.test(line) && false ||        // separator (skip alone)
           /^\/\S+\s+\(Status:\s*\d+\)/i.test(line); // gobuster result line
  },

  parse(lines) {
    const results = [];
    let tool = null;
    let target = null;
    let paths = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // FFuf detection
      if (/^:: Method\s*:/i.test(line) || /^:: URL\s*:/i.test(line)) {
        tool = 'ffuf';
        const urlMatch = line.match(/^:: URL\s*:\s*(\S+)/i);
        if (urlMatch) {
          target = urlMatch[1].replace(/FUZZ/g, '*');
        }
        continue;
      }

      // FFuf target from URL line
      const ffufUrl = line.match(/^:: URL\s*:\s*(\S+)/i);
      if (ffufUrl) {
        tool = 'ffuf';
        target = ffufUrl[1].replace(/FUZZ/g, '*');
        continue;
      }

      // Gobuster detection
      if (/Gobuster v/i.test(line)) {
        tool = 'gobuster';
        continue;
      }

      // Gobuster URL
      const goUrl = line.match(/^\[.+\]\s*(?:Starting|Scanning):\s*(\S+)/i) ||
                     line.match(/^Url:\s*(\S+)/i);
      if (goUrl) {
        target = goUrl[1];
        continue;
      }

      // FFuf result lines: "path  [Status: 200, Size: 1234, Words: 56, Lines: 12]"
      const ffufMatch = line.match(
        /^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)(?:,\s*Words:\s*(\d+))?/
      );
      if (ffufMatch) {
        tool = tool || 'ffuf';
        paths.push({
          path: ffufMatch[1],
          status: parseInt(ffufMatch[2], 10),
          size: parseInt(ffufMatch[3], 10),
        });
        continue;
      }

      // Gobuster result: "/path (Status: 200) [Size: 1234]"
      // or: "/path                 (Status: 200) [Size: 1234]"
      const goMatch = line.match(
        /^(\/\S+)\s+\(Status:\s*(\d+)\)\s*(?:\[Size:\s*(\d+)\])?/
      );
      if (goMatch) {
        tool = tool || 'gobuster';
        paths.push({
          path: goMatch[1],
          status: parseInt(goMatch[2], 10),
          size: goMatch[3] ? parseInt(goMatch[3], 10) : 0,
        });
        continue;
      }

      // Gobuster v7+ / alternate format: "Found: /path  [200] [Size: 1234]"
      const goAlt = line.match(/^Found:\s*(\/\S+)\s+\[(\d+)\](?:\s*\[Size:\s*(\d+)\])?/i);
      if (goAlt) {
        tool = tool || 'gobuster';
        paths.push({
          path: goAlt[1],
          status: parseInt(goAlt[2], 10),
          size: goAlt[3] ? parseInt(goAlt[3], 10) : 0,
        });
        continue;
      }
    }

    if (paths.length) {
      results.push({
        tool: tool || 'ffuf',
        target: target || 'unknown',
        paths,
      });
    }

    return results;
  },
};


// ─── Hydra Parser ──────────────────────────────────────────────
const hydraParser = {
  name: 'hydra',

  detect(line) {
    return /^Hydra v/i.test(line) ||
           /^\[DATA\]/i.test(line) ||
           /^\[\d+\]\[/i.test(line);
  },

  parse(lines) {
    const results = [];
    let target = null;
    let creds = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Hydra banner — sometimes includes target info
      if (/^Hydra v/i.test(line)) {
        continue;
      }

      // "[DATA] attacking ..." lines for target
      const dataMatch = line.match(/^\[DATA\]\s+attacking\s+(\S+):\/\/(\S+)/i);
      if (dataMatch) {
        target = dataMatch[2].replace(/:\d+$/, '') || dataMatch[2];
        continue;
      }

      // "[DATA] max N tasks per N servers ..."
      // Skip — no useful data

      // Credential found:
      // "[22][ssh] host: 192.168.1.1   login: root   password: toor"
      // "[80][http-post-form] host: 10.0.0.1   login: admin   password: admin123"
      const credMatch = line.match(
        /^\[(\d+)\]\[(\S+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(.+)$/i
      );
      if (credMatch) {
        creds.push({
          port: parseInt(credMatch[1], 10),
          service: credMatch[2],
          host: credMatch[3],
          login: credMatch[4],
          password: credMatch[5].trim(),
        });
        if (!target) target = credMatch[3];
        continue;
      }

      // Alternate format from older Hydra: "[ssh] host: IP login: U password: P"
      const credAlt = line.match(
        /^\[(\S+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(.+)$/i
      );
      if (credAlt) {
        creds.push({
          port: null,
          service: credAlt[1],
          host: credAlt[2],
          login: credAlt[3],
          password: credAlt[4].trim(),
        });
        if (!target) target = credAlt[2];
        continue;
      }
    }

    if (creds.length) {
      results.push({
        tool: 'hydra',
        target: target || 'unknown',
        creds,
      });
    }

    return results;
  },
};


// ─── Parser Registry ───────────────────────────────────────────
const PARSERS = [nmapParser, niktoParser, sqlmapParser, ffufGobusterParser, hydraParser];


// ══════════════════════════════════════════════════════════════
//  LINE BUFFER & PARSE ENGINE
//  Buffers raw PTY data per session, assembles lines, debounces
//  parsing, and emits structured results.
// ══════════════════════════════════════════════════════════════

// Per-session state
const sessionBuffers = new Map();

function getSession(uid) {
  if (!sessionBuffers.has(uid)) {
    sessionBuffers.set(uid, {
      partial: '',       // Incomplete line accumulator
      lines: [],         // Complete lines ring buffer
      activeTool: null,  // Currently detected tool (for context)
      parseTimer: null,  // Debounce timer
      dirty: false,      // Lines added since last parse
    });
  }
  return sessionBuffers.get(uid);
}

function destroySession(uid) {
  const sess = sessionBuffers.get(uid);
  if (sess && sess.parseTimer) clearTimeout(sess.parseTimer);
  sessionBuffers.delete(uid);
}

function feedData(uid, rawData) {
  const sess = getSession(uid);
  const clean = stripAnsi(typeof rawData === 'string' ? rawData : rawData.toString('utf8'));

  // Append to partial buffer and split into lines
  const combined = sess.partial + clean;
  const parts = combined.split('\n');

  // Last element is either empty (line ended with \n) or a partial line
  sess.partial = parts.pop() || '';

  for (const part of parts) {
    const trimmed = part.trim();
    if (trimmed.length === 0) continue;
    sess.lines.push(trimmed);
    // Enforce ring buffer limit
    if (sess.lines.length > MAX_BUFFER_LINES) {
      sess.lines.shift();
    }
  }

  sess.dirty = true;

  // Debounce parse
  if (!sess.parseTimer) {
    sess.parseTimer = setTimeout(() => {
      sess.parseTimer = null;
      if (sess.dirty) {
        sess.dirty = false;
        runParsers(uid, sess);
      }
    }, PARSE_DEBOUNCE_MS);
  }
}

function runParsers(uid, sess) {
  const recon = getRecon();
  const lines = sess.lines;

  // Detect which tools are active based on recent lines
  // We check the last ~50 lines for tool signatures, then parse all buffered lines
  const recentLines = lines.slice(-50);
  const activeTools = new Set();

  for (const line of recentLines) {
    for (const parser of PARSERS) {
      if (parser.detect(line)) {
        activeTools.add(parser.name);
      }
    }
  }

  // Run parsers for detected tools
  for (const parser of PARSERS) {
    if (!activeTools.has(parser.name)) continue;

    try {
      const results = parser.parse(lines);
      for (const result of results) {
        const eventName = 'parsed:' + result.tool;

        // Store in recon.findings for other plugins
        recon.findings.push({
          ...result,
          sessionUid: uid,
          timestamp: Date.now(),
        });

        // Trim findings history
        if (recon.findings.length > MAX_HISTORY) {
          recon.findings.splice(0, recon.findings.length - MAX_HISTORY);
        }

        // Update targets map
        if (result.target && result.target !== 'unknown') {
          if (!recon.targets.has(result.target)) {
            recon.targets.set(result.target, { tools: new Set(), firstSeen: Date.now() });
          }
          recon.targets.get(result.target).tools.add(result.tool);
        }

        // Emit tool-specific event
        recon.events.emit(eventName, result);

        // Emit generic event
        recon.events.emit('parsed:any', {
          tool: result.tool,
          target: result.target,
          data: result,
        });
      }
    } catch (err) {
      // Silently ignore parse errors to avoid breaking terminal
    }
  }
}


// ══════════════════════════════════════════════════════════════
//  MIDDLEWARE — Intercepts SESSION_PTY_DATA
// ══════════════════════════════════════════════════════════════

let activeUid = null;

exports.middleware = (store) => (next) => (action) => {
  switch (action.type) {
    case 'SESSION_SET_ACTIVE':
      activeUid = action.uid;
      break;

    case 'SESSION_ADD':
      if (!activeUid) activeUid = action.uid;
      break;

    case 'SESSION_PTY_DATA':
      if (action.uid && action.data) {
        feedData(action.uid, action.data);
      }
      break;

    case 'SESSION_PTY_EXIT':
    case 'SESSION_USER_EXIT':
      if (action.uid === activeUid) activeUid = null;
      destroySession(action.uid);
      break;
  }

  return next(action);
};


// ══════════════════════════════════════════════════════════════
//  HUD TAB — Live Feed of Parsed Results
//  Registers with the HUD framework if available.
// ══════════════════════════════════════════════════════════════

// Severity colors
const SEV_COLORS = {
  critical: '#ff4444',
  high: '#ff8c00',
  medium: '#ffd700',
  low: '#88cc88',
  info: '#88aaff',
};

// Tool colors and icons
const TOOL_META = {
  nmap:     { color: '#58a6ff', icon: '\u{1F50D}', label: 'Nmap' },
  nikto:    { color: '#f97583', icon: '\u{1F6E1}', label: 'Nikto' },
  sqlmap:   { color: '#d2a8ff', icon: '\u{1F489}', label: 'SQLMap' },
  ffuf:     { color: '#79c0ff', icon: '\u{1F4C2}', label: 'FFuf' },
  gobuster: { color: '#56d364', icon: '\u{1F4C1}', label: 'Gobuster' },
  hydra:    { color: '#f0883e', icon: '\u{1F511}', label: 'Hydra' },
};

// Tracks parsed data for display
let parsedFeed = [];
let feedVersion = 0;
let hudRegistered = false;

function addToFeed(entry) {
  parsedFeed.push(entry);
  if (parsedFeed.length > 200) parsedFeed.shift();
  feedVersion++;
}

function tryRegisterHud() {
  if (hudRegistered) return;
  const recon = getRecon();

  const doRegister = (hud) => {
    if (hudRegistered) return;
    hudRegistered = true;

    hud.registerTab('output-parser', 'Parser', null, (React) => renderHudTab(React));

    // Listen for all parsed events and update badge + feed
    recon.events.on('parsed:any', (evt) => {
      addToFeed(evt);
      hud.updateBadge('output-parser', parsedFeed.length);
    });
  };

  if (recon.hud) {
    doRegister(recon.hud);
  } else {
    recon.events.on('hud:ready', doRegister);
  }
}


// ─── HUD Tab Renderer ─────────────────────────────────────────
function renderHudTab(React) {
  const h = React.createElement;
  const entries = parsedFeed.slice().reverse();

  // Count per tool
  const counts = {};
  for (const e of parsedFeed) {
    counts[e.tool] = (counts[e.tool] || 0) + 1;
  }

  // Tool badge bar
  const toolBadges = Object.keys(TOOL_META).map(tool => {
    const meta = TOOL_META[tool];
    const count = counts[tool] || 0;
    return h('span', {
      key: tool,
      style: {
        display: 'inline-flex',
        alignItems: 'center',
        gap: '4px',
        padding: '2px 8px',
        borderRadius: '10px',
        background: count > 0 ? meta.color + '22' : '#222',
        border: '1px solid ' + (count > 0 ? meta.color + '66' : '#333'),
        color: count > 0 ? meta.color : '#555',
        fontSize: '10px',
        fontWeight: 600,
        cursor: 'default',
      },
    },
      h('span', null, meta.label),
      h('span', {
        style: {
          background: count > 0 ? meta.color : '#444',
          color: count > 0 ? '#000' : '#666',
          borderRadius: '8px',
          padding: '0 5px',
          fontSize: '9px',
          fontWeight: 700,
          minWidth: '14px',
          textAlign: 'center',
        },
      }, String(count))
    );
  });

  // Feed entries
  const feedItems = entries.slice(0, 100).map((entry, idx) => {
    return renderFeedEntry(h, entry, idx);
  });

  return h('div', { style: { fontFamily: 'monospace, sans-serif' } },
    // Tool count badges
    h('div', {
      style: {
        display: 'flex',
        flexWrap: 'wrap',
        gap: '6px',
        marginBottom: '10px',
        padding: '6px 0',
        borderBottom: '1px solid #21262d',
      },
    }, ...toolBadges),

    // Feed
    entries.length === 0
      ? h('div', {
          style: { color: '#484f58', fontStyle: 'italic', padding: '20px 0', textAlign: 'center' },
        }, 'Waiting for tool output... (nmap, nikto, sqlmap, ffuf, gobuster, hydra)')
      : h('div', { style: { display: 'flex', flexDirection: 'column', gap: '4px' } }, ...feedItems)
  );
}


function renderFeedEntry(h, entry, idx) {
  const meta = TOOL_META[entry.tool] || { color: '#888', icon: '', label: entry.tool };
  const data = entry.data || entry;

  // Header
  const header = h('div', {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      padding: '4px 8px',
      background: '#161b22',
      borderRadius: '4px 4px 0 0',
      borderLeft: '3px solid ' + meta.color,
      cursor: 'pointer',
    },
    title: 'Click to copy JSON',
    onClick: () => {
      try { clipboard.writeText(JSON.stringify(data, null, 2)); } catch {}
    },
  },
    h('span', { style: { color: meta.color, fontWeight: 700, fontSize: '11px' } }, meta.label),
    h('span', { style: { color: '#8b949e', fontSize: '10px' } }, entry.target || ''),
    h('span', { style: { flex: 1 } }),
    h('span', { style: { color: '#484f58', fontSize: '9px' } }, 'click to copy')
  );

  // Body: render per-tool detail
  const body = renderToolBody(h, entry.tool, data, meta);

  return h('div', {
    key: idx,
    style: {
      marginBottom: '4px',
      border: '1px solid #21262d',
      borderRadius: '4px',
      overflow: 'hidden',
    },
  }, header, body);
}


function renderToolBody(h, tool, data, meta) {
  const rowStyle = {
    padding: '2px 12px',
    fontSize: '11px',
    color: '#c9d1d9',
    borderBottom: '1px solid #0d111722',
    cursor: 'pointer',
  };

  const dimStyle = { color: '#8b949e', fontSize: '10px' };

  switch (tool) {
    case 'nmap': {
      const ports = (data.ports || []).slice(0, 20);
      const items = ports.map((p, i) =>
        h('div', {
          key: i,
          style: { ...rowStyle, display: 'flex', gap: '12px' },
          title: 'Click to copy',
          onClick: () => copyText(`${p.port}/${p.proto}`),
        },
          h('span', { style: { color: p.state === 'open' ? '#56d364' : '#f97583', fontWeight: 600, minWidth: '55px' } },
            p.port + '/' + p.proto),
          h('span', { style: { color: '#58a6ff', minWidth: '40px' } }, p.state),
          h('span', { style: { minWidth: '80px' } }, p.service),
          h('span', { style: dimStyle }, p.version || '')
        )
      );
      if (data.os) {
        items.push(h('div', { key: 'os', style: { ...rowStyle, color: '#d2a8ff' } },
          h('span', { style: { fontWeight: 600 } }, 'OS: '), data.os));
      }
      if (data.scripts && data.scripts.length) {
        data.scripts.slice(0, 10).forEach((s, i) => {
          items.push(h('div', {
            key: 'script-' + i,
            style: { ...rowStyle, color: '#79c0ff', fontSize: '10px' },
            title: 'Click to copy',
            onClick: () => copyText(s.id + ': ' + s.output),
          },
            h('span', { style: { fontWeight: 600 } }, s.id + ': '),
            h('span', null, s.output)
          ));
        });
      }
      return h('div', { style: { background: '#0d1117' } }, ...items);
    }

    case 'nikto': {
      const findings = (data.findings || []).slice(0, 30);
      const items = findings.map((f, i) =>
        h('div', {
          key: i,
          style: { ...rowStyle, display: 'flex', gap: '8px', alignItems: 'flex-start' },
          title: 'Click to copy',
          onClick: () => copyText(f.description),
        },
          h('span', {
            style: {
              color: SEV_COLORS[f.severity] || '#888',
              fontWeight: 700,
              fontSize: '9px',
              textTransform: 'uppercase',
              minWidth: '50px',
              flexShrink: 0,
            },
          }, f.severity || 'info'),
          f.id && h('span', { style: { color: '#f97583', fontSize: '10px', minWidth: '90px', flexShrink: 0 } }, f.id),
          f.path && h('span', { style: { color: '#79c0ff', minWidth: '80px', flexShrink: 0 } }, f.path),
          h('span', { style: { flex: 1 } }, f.description)
        )
      );
      return h('div', { style: { background: '#0d1117' } }, ...items);
    }

    case 'sqlmap': {
      const items = [];
      if (data.dbms) {
        items.push(h('div', { key: 'dbms', style: { ...rowStyle, color: '#d2a8ff' } },
          h('span', { style: { fontWeight: 600 } }, 'DBMS: '), data.dbms));
      }
      (data.injectable || []).forEach((inj, i) => {
        items.push(h('div', {
          key: 'inj-' + i,
          style: { ...rowStyle, display: 'flex', gap: '10px', color: '#f97583' },
          title: 'Click to copy',
          onClick: () => copyText(`Parameter: ${inj.param} (${inj.type})`),
        },
          h('span', { style: { fontWeight: 700 } }, 'INJECTABLE'),
          h('span', null, inj.param),
          h('span', { style: dimStyle }, inj.type),
          inj.technique && h('span', { style: { color: '#d2a8ff', fontSize: '10px' } }, inj.technique)
        ));
      });
      if (data.databases && data.databases.length) {
        items.push(h('div', { key: 'dbs', style: { ...rowStyle, color: '#56d364' } },
          h('span', { style: { fontWeight: 600 } }, 'Databases: '),
          data.databases.join(', ')
        ));
      }
      if (data.tables && data.tables.length) {
        items.push(h('div', { key: 'tables', style: { ...rowStyle, color: '#79c0ff' } },
          h('span', { style: { fontWeight: 600 } }, 'Tables: '),
          data.tables.join(', ')
        ));
      }
      return h('div', { style: { background: '#0d1117' } }, ...items);
    }

    case 'ffuf':
    case 'gobuster': {
      const paths = (data.paths || []).slice(0, 40);
      const items = paths.map((p, i) => {
        const statusColor = p.status < 300 ? '#56d364' : p.status < 400 ? '#58a6ff' : p.status < 500 ? '#f0883e' : '#f97583';
        return h('div', {
          key: i,
          style: { ...rowStyle, display: 'flex', gap: '10px' },
          title: 'Click to copy path',
          onClick: () => copyText(p.path),
        },
          h('span', { style: { color: statusColor, fontWeight: 600, minWidth: '30px' } }, String(p.status)),
          h('span', { style: { color: '#79c0ff', flex: 1 } }, p.path),
          h('span', { style: dimStyle }, p.size ? p.size + 'B' : '')
        );
      });
      return h('div', { style: { background: '#0d1117' } }, ...items);
    }

    case 'hydra': {
      const creds = (data.creds || []).slice(0, 20);
      const items = creds.map((c, i) =>
        h('div', {
          key: i,
          style: {
            ...rowStyle,
            display: 'flex',
            gap: '10px',
            background: '#1a0a0a',
          },
          title: 'Click to copy credentials',
          onClick: () => copyText(`${c.login}:${c.password}`),
        },
          h('span', { style: { color: '#f0883e', fontWeight: 700, minWidth: '60px' } }, c.service),
          h('span', { style: { color: '#8b949e', minWidth: '100px' } }, c.host),
          h('span', { style: { color: '#56d364', fontWeight: 600 } }, c.login),
          h('span', { style: { color: '#484f58' } }, ':'),
          h('span', { style: { color: '#f97583', fontWeight: 600 } }, c.password)
        )
      );
      return h('div', { style: { background: '#0d1117' } }, ...items);
    }

    default:
      return h('div', { style: { padding: '4px 12px', color: '#484f58', fontSize: '10px' } },
        JSON.stringify(data).slice(0, 200));
  }
}

function copyText(text) {
  try { clipboard.writeText(text); } catch {}
}


// ══════════════════════════════════════════════════════════════
//  HYPER COMPONENT DECORATORS
// ══════════════════════════════════════════════════════════════

exports.decorateHyper = (Hyper, { React }) => {
  return class ParserHyper extends React.Component {
    componentDidMount() {
      tryRegisterHud();
    }

    render() {
      return React.createElement(Hyper, this.props);
    }
  };
};


// ─── Reducer: map plugin state into props ─────────────────────
exports.mapTermsState = (state, map) => {
  return Object.assign({}, map, { parserVersion: feedVersion });
};

exports.getTermGroupProps = (uid, parentProps, props) => {
  return Object.assign({}, props, { parserVersion: parentProps.parserVersion });
};

exports.getTermProps = (uid, parentProps, props) => {
  return Object.assign({}, props, { parserVersion: parentProps.parserVersion });
};
