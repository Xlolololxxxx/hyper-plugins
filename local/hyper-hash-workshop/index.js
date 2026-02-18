'use strict';

// ======================================================================
//  HYPER HASH WORKSHOP
//  Hash identification and cracking workflow manager.
//  Detects hashes in terminal output, identifies probable algorithms,
//  offers local (hashcat/john) and online cracking, tracks status.
//  Registers a "Hashes" tab in the HUD framework.
// ======================================================================

const fs = require('fs');
const path = require('path');
const os = require('os');
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

// ------ Shell Helpers -------------------------------------------------

let activeUid = null;

function esc(str) {
  return "'" + str.replace(/'/g, "'\\''") + "'";
}

function exec(cmd) {
  const recon = getRecon();
  const uid = recon.activeUid || activeUid;
  if (!uid) return;
  window.rpc.emit('data', { uid, data: cmd + '\n', escaped: false });
}

function copy(text) {
  require('electron').clipboard.writeText(text);
}

function autoPost(action, fields) {
  const escHtml = (s) => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
  const inputs = Object.entries(fields)
    .map(([n, v]) => `<input type="hidden" name="${escHtml(n)}" value="${escHtml(v)}">`)
    .join('');
  const html = `<!DOCTYPE html><html><body><form id="f" method="POST" action="${escHtml(action)}">${inputs}</form><script>document.getElementById('f').submit();</script></body></html>`;
  const tmp = path.join(os.tmpdir(), `hash-post-${Date.now()}.html`);
  fs.writeFileSync(tmp, html);
  require('electron').shell.openExternal(`file://${tmp}`);
  setTimeout(() => { try { fs.unlinkSync(tmp); } catch {} }, 15000);
}

// ------ ANSI Stripping -----------------------------------------------

function stripAnsi(str) {
  return str.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '')
            .replace(/\x1b\][^\x07]*\x07/g, '')
            .replace(/\x1b[()][AB012]/g, '')
            .replace(/\x1b[\[>=]/g, '')
            .replace(/[\x00-\x08\x0e-\x1f]/g, '');
}

// ------ Hash Type Mappings -------------------------------------------

const HASH_TYPES = {
  32:  ['MD5', 'NTLM', 'MD4', 'LM'],
  40:  ['SHA-1', 'MySQL5', 'RIPEMD-160'],
  64:  ['SHA-256', 'SHA3-256', 'BLAKE2s'],
  96:  ['SHA-384'],
  128: ['SHA-512', 'Whirlpool', 'BLAKE2b'],
};

// Hashcat -m mode mapping
const HASHCAT_MODES = {
  'MD5':            0,
  'MD4':            900,
  'NTLM':           1000,
  'LM':             3000,
  'SHA-1':          100,
  'MySQL5':         300,
  'RIPEMD-160':     6000,
  'SHA-256':        1400,
  'SHA3-256':       17400,
  'BLAKE2s':        600,
  'SHA-384':        10800,
  'SHA-512':        1700,
  'Whirlpool':      6100,
  'BLAKE2b':        600,
  'SHA3-512':       17600,
  'bcrypt':         3200,
  'MD5-crypt':      500,
  'SHA-256-crypt':  7400,
  'SHA-512-crypt':  1800,
  'argon2':         null,   // argon2 not directly supported in older hashcat
};

// John format mapping
const JOHN_FORMATS = {
  'MD5':            'raw-md5',
  'MD4':            'raw-md4',
  'NTLM':           'nt',
  'LM':             'lm',
  'SHA-1':          'raw-sha1',
  'MySQL5':         'mysql-sha1',
  'RIPEMD-160':     'ripemd-160',
  'SHA-256':        'raw-sha256',
  'SHA-384':        'raw-sha384',
  'SHA-512':        'raw-sha512',
  'Whirlpool':      'whirlpool',
  'bcrypt':         'bcrypt',
  'MD5-crypt':      'md5crypt',
  'SHA-256-crypt':  'sha256crypt',
  'SHA-512-crypt':  'sha512crypt',
};

// Common wordlists
const WORDLISTS = [
  { label: 'rockyou.txt',           path: '/usr/share/wordlists/rockyou.txt' },
  { label: 'common.txt (dirb)',     path: '/usr/share/wordlists/dirb/common.txt' },
  { label: 'fasttrack.txt',         path: '/usr/share/wordlists/fasttrack.txt' },
  { label: 'SecLists passwords',    path: '/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt' },
  { label: 'SecLists darkweb',      path: '/usr/share/seclists/Passwords/darkweb2017-top10000.txt' },
];

// ------ Persistence ---------------------------------------------------

const PERSIST_DIR = path.join(os.homedir(), '.hyper_recon');
const PERSIST_FILE = path.join(PERSIST_DIR, 'hashes.json');

function loadHashes() {
  try {
    if (fs.existsSync(PERSIST_FILE)) {
      const data = JSON.parse(fs.readFileSync(PERSIST_FILE, 'utf8'));
      if (Array.isArray(data)) {
        return new Map(data.map(h => [h.hash, h]));
      }
    }
  } catch {}
  return new Map();
}

function saveHashes() {
  try {
    if (!fs.existsSync(PERSIST_DIR)) {
      fs.mkdirSync(PERSIST_DIR, { recursive: true });
    }
    const arr = Array.from(hashStore.values());
    fs.writeFileSync(PERSIST_FILE, JSON.stringify(arr, null, 2), 'utf8');
  } catch {}
}

// Debounce persistence writes
let saveTimer = null;
function debouncedSave() {
  if (saveTimer) clearTimeout(saveTimer);
  saveTimer = setTimeout(saveHashes, 2000);
}

// ------ Hash Store ----------------------------------------------------

// hash entry shape:
// {
//   hash: string,          // the raw hash value
//   type: string,          // 'hex' | 'bcrypt' | 'argon2' | 'md5-crypt' | 'sha256-crypt' | 'sha512-crypt' | 'mysql5'
//   possible: string[],    // probable algorithm names
//   status: string,        // 'detected' | 'cracking' | 'cracked' | 'not-found'
//   plaintext: string|null,
//   detectedAt: number,
//   crackedAt: number|null,
// }

let hashStore = loadHashes();
let hudApi = null;
let renderCallback = null;
let currentFilter = 'all'; // 'all' | 'uncracked' | 'cracked'

function getUncracked() {
  let count = 0;
  for (const entry of hashStore.values()) {
    if (entry.status !== 'cracked') count++;
  }
  return count;
}

function updateBadge() {
  if (!hudApi) return;
  const count = getUncracked();
  hudApi.updateBadge('hashes', count > 0 ? count : null);
}

function triggerRender() {
  if (renderCallback) renderCallback();
}

function addHash(hash, type, possible) {
  if (hashStore.has(hash)) return;
  const entry = {
    hash,
    type,
    possible,
    status: 'detected',
    plaintext: null,
    detectedAt: Date.now(),
    crackedAt: null,
  };
  hashStore.set(hash, entry);
  updateBadge();
  triggerRender();
  debouncedSave();

  // Emit event
  const recon = getRecon();
  recon.events.emit('hash:detected', { hash, type, possible });
}

function markCracked(hash, plaintext) {
  const entry = hashStore.get(hash);
  if (!entry) return;
  entry.status = 'cracked';
  entry.plaintext = plaintext;
  entry.crackedAt = Date.now();
  updateBadge();
  triggerRender();
  debouncedSave();

  const recon = getRecon();
  recon.events.emit('hash:cracked', { hash, plaintext });
}

function removeHash(hash) {
  hashStore.delete(hash);
  updateBadge();
  triggerRender();
  debouncedSave();
}

function clearAllHashes() {
  hashStore.clear();
  updateBadge();
  triggerRender();
  debouncedSave();
}

// ------ Hash Detection Patterns ---------------------------------------

// Hex hash patterns: standalone hex strings of exact lengths bounded by non-hex chars
const HEX_LENGTHS = [32, 40, 64, 96, 128];
const HEX_PATTERNS = HEX_LENGTHS.map(len => ({
  len,
  regex: new RegExp('(?<![a-fA-F0-9])[a-fA-F0-9]{' + len + '}(?![a-fA-F0-9])', 'g'),
}));

// Format hash patterns
const FORMAT_PATTERNS = [
  {
    type: 'bcrypt',
    regex: /\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}/g,
    identify: () => ['bcrypt'],
  },
  {
    type: 'argon2',
    regex: /\$argon2(?:i|d|id)\$[^\s]+/g,
    identify: () => ['argon2'],
  },
  {
    type: 'md5-crypt',
    regex: /\$1\$[^\s$]+\$[./A-Za-z0-9]+/g,
    identify: () => ['MD5-crypt'],
  },
  {
    type: 'sha256-crypt',
    regex: /\$5\$[^\s$]+\$[./A-Za-z0-9]+/g,
    identify: () => ['SHA-256-crypt'],
  },
  {
    type: 'sha512-crypt',
    regex: /\$6\$[^\s$]+\$[./A-Za-z0-9]+/g,
    identify: () => ['SHA-512-crypt'],
  },
  {
    type: 'mysql5',
    regex: /\*[a-fA-F0-9]{40}(?![a-fA-F0-9])/g,
    identify: () => ['MySQL5'],
  },
];

// Cracked pair detection: hash:plaintext from cracking tool output
const CRACKED_PAIR_REGEX = /([a-fA-F0-9]{32,128}):(.{1,128})$/gm;
const CRACKED_BCRYPT_PAIR = /(\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}):(.+)$/gm;

// Dedup buffer: avoid reprocessing the same data chunk
let recentChunks = [];
const MAX_RECENT = 32;

function isDuplicate(chunk) {
  const key = chunk.length > 200 ? chunk.slice(0, 200) : chunk;
  if (recentChunks.includes(key)) return true;
  recentChunks.push(key);
  if (recentChunks.length > MAX_RECENT) recentChunks.shift();
  return false;
}

// Common false positive hex strings to ignore
function isLikelyFalsePositive(hex) {
  // All same character
  if (/^(.)\1+$/.test(hex)) return true;
  // Sequential patterns
  if (hex === '0'.repeat(hex.length)) return true;
  if (hex === 'f'.repeat(hex.length) || hex === 'F'.repeat(hex.length)) return true;
  // Common ANSI color codes or terminal artifacts
  if (/^0{20,}/.test(hex)) return true;
  return false;
}

function scanForHashes(rawData) {
  if (isDuplicate(rawData)) return;

  const cleaned = stripAnsi(rawData);
  const lines = cleaned.split(/\r?\n/);

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.length < 16) continue;

    // 1. Check for cracked pairs (hash:plaintext)
    CRACKED_PAIR_REGEX.lastIndex = 0;
    let pairMatch;
    while ((pairMatch = CRACKED_PAIR_REGEX.exec(trimmed)) !== null) {
      const hash = pairMatch[1].toLowerCase();
      const plaintext = pairMatch[2];
      if (hashStore.has(hash)) {
        markCracked(hash, plaintext);
      } else if (hashStore.has(pairMatch[1])) {
        markCracked(pairMatch[1], plaintext);
      }
    }

    CRACKED_BCRYPT_PAIR.lastIndex = 0;
    let bcryptPair;
    while ((bcryptPair = CRACKED_BCRYPT_PAIR.exec(trimmed)) !== null) {
      const hash = bcryptPair[1];
      const plaintext = bcryptPair[2];
      if (hashStore.has(hash)) {
        markCracked(hash, plaintext);
      }
    }

    // 2. Check format hashes
    for (const fp of FORMAT_PATTERNS) {
      fp.regex.lastIndex = 0;
      let m;
      while ((m = fp.regex.exec(trimmed)) !== null) {
        addHash(m[0], fp.type, fp.identify());
      }
    }

    // 3. Check hex hashes
    for (const hp of HEX_PATTERNS) {
      hp.regex.lastIndex = 0;
      let m;
      while ((m = hp.regex.exec(trimmed)) !== null) {
        const hex = m[0];
        if (isLikelyFalsePositive(hex)) continue;
        const possible = HASH_TYPES[hp.len] || ['Unknown'];
        addHash(hex, 'hex', possible);
      }
    }
  }
}

// ------ Bulk Operations -----------------------------------------------

function saveAllToFile() {
  const entries = Array.from(hashStore.values());
  if (entries.length === 0) return;

  const outDir = path.join(os.homedir(), '.hyper_recon');
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const outFile = path.join(outDir, `hashes-${ts}.txt`);

  const lines = entries.map(e => e.hash);
  fs.writeFileSync(outFile, lines.join('\n') + '\n', 'utf8');

  if (hudApi) hudApi.notify('Saved ' + entries.length + ' hashes to ' + outFile, 'info');
  return outFile;
}

function hashcatAll(modeOverride, wordlistPath) {
  const entries = Array.from(hashStore.values()).filter(e => e.status !== 'cracked');
  if (entries.length === 0) {
    if (hudApi) hudApi.notify('No uncracked hashes to crack', 'info');
    return;
  }

  const outFile = saveAllToFile();
  if (!outFile) return;

  const wordlist = wordlistPath || '/usr/share/wordlists/rockyou.txt';
  let mode = modeOverride;
  if (mode == null && entries.length > 0) {
    // Use the first hash's best guess mode
    const first = entries[0];
    if (first.possible && first.possible.length > 0) {
      mode = HASHCAT_MODES[first.possible[0]];
    }
  }
  if (mode == null) mode = 0; // fallback to MD5

  exec(`hashcat -m ${mode} ${esc(outFile)} ${esc(wordlist)}`);
  entries.forEach(e => { e.status = 'cracking'; });
  triggerRender();
  debouncedSave();
}

function johnAll(formatOverride) {
  const entries = Array.from(hashStore.values()).filter(e => e.status !== 'cracked');
  if (entries.length === 0) {
    if (hudApi) hudApi.notify('No uncracked hashes to crack', 'info');
    return;
  }

  const outFile = saveAllToFile();
  if (!outFile) return;

  let format = formatOverride;
  if (!format && entries.length > 0) {
    const first = entries[0];
    if (first.possible && first.possible.length > 0) {
      format = JOHN_FORMATS[first.possible[0]];
    }
  }

  const fmtFlag = format ? ` --format=${esc(format)}` : '';
  exec(`john${fmtFlag} ${esc(outFile)}`);
  entries.forEach(e => { e.status = 'cracking'; });
  triggerRender();
  debouncedSave();
}

// ------ Per-Hash Actions ----------------------------------------------

function crackSingleHashcat(entry, wordlistPath) {
  const wordlist = wordlistPath || '/usr/share/wordlists/rockyou.txt';
  let mode = null;
  if (entry.possible && entry.possible.length > 0) {
    mode = HASHCAT_MODES[entry.possible[0]];
  }
  if (mode == null) mode = 0;

  // Write single hash to temp file
  const tmpFile = path.join(os.tmpdir(), `hash-single-${Date.now()}.txt`);
  fs.writeFileSync(tmpFile, entry.hash + '\n', 'utf8');

  exec(`hashcat -m ${mode} ${esc(tmpFile)} ${esc(wordlist)}`);
  entry.status = 'cracking';
  triggerRender();
  debouncedSave();
}

function crackSingleJohn(entry) {
  let format = null;
  if (entry.possible && entry.possible.length > 0) {
    format = JOHN_FORMATS[entry.possible[0]];
  }

  const tmpFile = path.join(os.tmpdir(), `hash-single-${Date.now()}.txt`);
  fs.writeFileSync(tmpFile, entry.hash + '\n', 'utf8');

  const fmtFlag = format ? ` --format=${esc(format)}` : '';
  exec(`john${fmtFlag} ${esc(tmpFile)}`);
  entry.status = 'cracking';
  triggerRender();
  debouncedSave();
}

function identifyHash(entry) {
  exec(`hashid ${esc(entry.hash)}`);
}

function lookupCrackStation(entry) {
  autoPost('https://crackstation.net/', { hash: entry.hash });
}

function lookupHashesCom(entry) {
  autoPost('https://hashes.com/en/decrypt/hash', { hash: entry.hash });
}

// ======================================================================
//  HUD TAB RENDER
// ======================================================================

function renderHashesTab(React) {
  const h = React.createElement;
  const entries = Array.from(hashStore.values());

  // Apply filter
  let filtered = entries;
  if (currentFilter === 'uncracked') {
    filtered = entries.filter(e => e.status !== 'cracked');
  } else if (currentFilter === 'cracked') {
    filtered = entries.filter(e => e.status === 'cracked');
  }

  // Sort: detected first, then cracking, then cracked
  const statusOrder = { detected: 0, cracking: 1, 'not-found': 2, cracked: 3 };
  filtered.sort((a, b) => (statusOrder[a.status] || 0) - (statusOrder[b.status] || 0) || b.detectedAt - a.detectedAt);

  // Inject CSS if not already present
  if (typeof document !== 'undefined' && !document.getElementById('hash-workshop-styles')) {
    const style = document.createElement('style');
    style.id = 'hash-workshop-styles';
    style.textContent = `
      .hw-row:hover { border-color: #30363d !important; background: #1c2129 !important; }
      .hw-btn { cursor: pointer; padding: 2px 6px; border-radius: 3px; font-size: 9px;
                 font-weight: 600; border: 1px solid transparent; transition: all 0.12s;
                 user-select: none; display: inline-flex; align-items: center; gap: 2px; }
      .hw-btn:hover { filter: brightness(1.3); }
      .hw-btn-crack { background: #23863622; color: #3fb950; border-color: #23863644; }
      .hw-btn-crack:hover { background: #238636; color: #fff; }
      .hw-btn-copy { background: #58a6ff22; color: #58a6ff; border-color: #58a6ff44; }
      .hw-btn-copy:hover { background: #58a6ff; color: #fff; }
      .hw-btn-online { background: #f9731622; color: #f97316; border-color: #f9731644; }
      .hw-btn-online:hover { background: #f97316; color: #fff; }
      .hw-btn-danger { background: #f8514922; color: #f85149; border-color: #f8514944; }
      .hw-btn-danger:hover { background: #f85149; color: #fff; }
      .hw-btn-neutral { background: #8b949e22; color: #8b949e; border-color: #8b949e44; }
      .hw-btn-neutral:hover { background: #8b949e; color: #fff; }
      .hw-filter-btn { cursor: pointer; padding: 2px 8px; border-radius: 10px; font-size: 10px;
                        font-weight: 600; border: 1px solid transparent; transition: all 0.12s;
                        user-select: none; }
      .hw-filter-active { background: #58a6ff33; color: #58a6ff; border-color: #58a6ff66; }
      .hw-filter-inactive { background: transparent; color: #484f58; border-color: #21262d; }
      .hw-filter-inactive:hover { color: #8b949e; border-color: #30363d; }
    `;
    document.head.appendChild(style);
  }

  // Build UI
  return h('div', { style: { display: 'flex', flexDirection: 'column', gap: '8px', height: '100%' } },

    // Toolbar
    h('div', {
      style: {
        display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap',
        paddingBottom: '6px', borderBottom: '1px solid #21262d',
      },
    },
      // Filters
      h('span', { style: { color: '#8b949e', fontSize: '10px', fontWeight: 600, marginRight: '2px' } }, 'FILTER:'),
      renderFilterBtn(h, 'All', 'all'),
      renderFilterBtn(h, 'Uncracked', 'uncracked'),
      renderFilterBtn(h, 'Cracked', 'cracked'),

      // Spacer
      h('div', { style: { flex: 1 } }),

      // Stats
      h('span', { style: { color: '#484f58', fontSize: '10px', marginRight: '8px' } },
        entries.length + ' total | ' + getUncracked() + ' uncracked'
      ),

      // Bulk actions
      h('span', {
        className: 'hw-btn hw-btn-neutral',
        onClick: () => {
          const f = saveAllToFile();
          if (f && hudApi) hudApi.notify('Saved to ' + f, 'info');
        },
        title: 'Save all hashes to file',
      }, 'Save All'),

      h('span', {
        className: 'hw-btn hw-btn-crack',
        onClick: () => hashcatAll(null, null),
        title: 'Run hashcat on all uncracked hashes',
      }, 'Hashcat All'),

      h('span', {
        className: 'hw-btn hw-btn-crack',
        onClick: () => johnAll(null),
        title: 'Run john on all uncracked hashes',
      }, 'John All'),

      h('span', {
        className: 'hw-btn hw-btn-danger',
        onClick: () => { clearAllHashes(); },
        title: 'Clear all hashes',
      }, 'Clear'),
    ),

    // Hash list
    filtered.length === 0
      ? h('div', {
          style: {
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            flex: 1, color: '#484f58', fontSize: '12px', fontStyle: 'italic',
          },
        }, currentFilter === 'all'
          ? 'No hashes detected yet. Hashes will appear automatically from terminal output.'
          : 'No ' + currentFilter + ' hashes.')
      : h('div', {
          style: {
            display: 'flex', flexDirection: 'column', gap: '4px',
            overflow: 'auto', flex: 1,
          },
        },
          filtered.map(entry => renderHashRow(React, entry))
        ),
  );
}

function renderFilterBtn(h, label, filterKey) {
  const isActive = currentFilter === filterKey;
  return h('span', {
    className: 'hw-filter-btn ' + (isActive ? 'hw-filter-active' : 'hw-filter-inactive'),
    onClick: () => {
      currentFilter = filterKey;
      triggerRender();
    },
  }, label);
}

function renderHashRow(React, entry) {
  const h = React.createElement;

  // Status icon and color
  const statusConfig = {
    detected:  { icon: '\u25CB', color: '#8b949e', label: 'DETECTED' },
    cracking:  { icon: '\u25D4', color: '#f0883e', label: 'CRACKING' },
    cracked:   { icon: '\u25CF', color: '#3fb950', label: 'CRACKED' },
    'not-found': { icon: '\u2717', color: '#f85149', label: 'NOT FOUND' },
  };
  const sc = statusConfig[entry.status] || statusConfig.detected;

  // Truncate hash for display
  const displayHash = entry.hash.length > 48
    ? entry.hash.slice(0, 24) + '...' + entry.hash.slice(-12)
    : entry.hash;

  // Type badge color
  const typeColors = {
    hex: '#58a6ff',
    bcrypt: '#f97316',
    argon2: '#a78bfa',
    'md5-crypt': '#f97316',
    'sha256-crypt': '#f97316',
    'sha512-crypt': '#f97316',
    mysql5: '#22d3ee',
  };
  const typeColor = typeColors[entry.type] || '#8b949e';

  // Possible algorithms display
  const algoStr = entry.possible ? entry.possible.join(', ') : 'Unknown';

  // Get best hashcat mode for display
  let bestMode = null;
  if (entry.possible && entry.possible.length > 0) {
    bestMode = HASHCAT_MODES[entry.possible[0]];
  }

  const rowStyle = {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '6px 8px',
    background: '#161b22',
    border: '1px solid #21262d',
    borderRadius: '5px',
    transition: 'all 0.12s',
    flexWrap: 'nowrap',
    minHeight: '28px',
  };

  return h('div', {
    key: entry.hash,
    className: 'hw-row',
    style: rowStyle,
  },

    // Status icon
    h('span', {
      style: {
        color: sc.color,
        fontSize: '12px',
        flexShrink: 0,
        width: '14px',
        textAlign: 'center',
      },
      title: sc.label,
    }, sc.icon),

    // Hash value
    h('span', {
      style: {
        fontFamily: '"Cascadia Code", "Fira Code", "JetBrains Mono", monospace',
        fontSize: '10px',
        color: entry.status === 'cracked' ? '#3fb950' : '#c9d1d9',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
        minWidth: '100px',
        maxWidth: '320px',
        flex: 1,
      },
      title: entry.hash,
    }, displayHash),

    // Plaintext (if cracked)
    entry.status === 'cracked' && entry.plaintext && h('span', {
      style: {
        fontFamily: 'monospace',
        fontSize: '10px',
        color: '#3fb950',
        fontWeight: 700,
        maxWidth: '120px',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
        flexShrink: 0,
      },
      title: 'Plaintext: ' + entry.plaintext,
    }, '\u2192 ' + entry.plaintext),

    // Type badge
    h('span', {
      style: {
        fontSize: '8px',
        fontWeight: 700,
        padding: '1px 5px',
        borderRadius: '6px',
        background: typeColor + '22',
        color: typeColor,
        border: '1px solid ' + typeColor + '33',
        textTransform: 'uppercase',
        letterSpacing: '0.3px',
        flexShrink: 0,
        whiteSpace: 'nowrap',
      },
    }, entry.type),

    // Algorithm guesses
    h('span', {
      style: {
        fontSize: '9px',
        color: '#8b949e',
        flexShrink: 0,
        maxWidth: '160px',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
      },
      title: algoStr,
    }, algoStr),

    // Hashcat mode indicator
    bestMode != null && h('span', {
      style: {
        fontSize: '8px',
        color: '#484f58',
        flexShrink: 0,
        fontFamily: 'monospace',
      },
      title: 'Hashcat mode: -m ' + bestMode,
    }, '-m ' + bestMode),

    // Action buttons
    entry.status !== 'cracked' && h('span', {
      className: 'hw-btn hw-btn-crack',
      onClick: (e) => { e.stopPropagation(); crackSingleHashcat(entry, null); },
      title: 'Crack with hashcat',
    }, 'Crack'),

    entry.status !== 'cracked' && h('span', {
      className: 'hw-btn hw-btn-online',
      onClick: (e) => { e.stopPropagation(); lookupCrackStation(entry); },
      title: 'Lookup on CrackStation',
    }, 'Online'),

    h('span', {
      className: 'hw-btn hw-btn-copy',
      onClick: (e) => {
        e.stopPropagation();
        copy(entry.hash);
        if (hudApi) hudApi.notify('Hash copied to clipboard', 'info');
      },
      title: 'Copy hash to clipboard',
    }, 'Copy'),

    // More actions dropdown (hashid, john, hashes.com, remove)
    h('span', {
      className: 'hw-btn hw-btn-neutral',
      onClick: (e) => {
        e.stopPropagation();
        const rect = e.target.getBoundingClientRect();
        showHashMenu(entry, rect.left, rect.bottom + 2);
      },
      title: 'More actions',
    }, '\u22EF'),
  );
}

// ------ Per-Hash Context Menu -----------------------------------------

let _menuEl = null;

function _dismissMenu() {
  if (_menuEl) { _menuEl.remove(); _menuEl = null; }
  document.removeEventListener('mousedown', _onMenuBlur, true);
  document.removeEventListener('keydown', _onMenuEsc, true);
}

function _onMenuBlur(e) {
  if (_menuEl && !_menuEl.contains(e.target)) _dismissMenu();
}

function _onMenuEsc(e) {
  if (e.key === 'Escape') _dismissMenu();
}

function showHashMenu(entry, x, y) {
  _dismissMenu();

  const items = [];

  items.push({ label: '-- Identify --', enabled: false });
  items.push({ label: 'hashid', click: () => identifyHash(entry) });
  items.push({ label: 'hash-identifier', click: () => exec(`echo ${esc(entry.hash)} | hash-identifier`) });
  items.push({ type: 'separator' });

  if (entry.status !== 'cracked') {
    items.push({ label: '-- Crack (Local) --', enabled: false });

    // Hashcat with wordlist options
    for (const wl of WORDLISTS) {
      let mode = null;
      if (entry.possible && entry.possible.length > 0) {
        mode = HASHCAT_MODES[entry.possible[0]];
      }
      if (mode == null) mode = 0;
      items.push({
        label: 'hashcat -m ' + mode + ' w/ ' + wl.label,
        click: () => crackSingleHashcat(entry, wl.path),
      });
    }

    items.push({ type: 'separator' });

    // John with format options
    items.push({ label: '-- John the Ripper --', enabled: false });
    items.push({ label: 'john (auto-detect)', click: () => crackSingleJohn(entry) });
    if (entry.possible) {
      for (const algo of entry.possible) {
        const fmt = JOHN_FORMATS[algo];
        if (fmt) {
          items.push({
            label: 'john --format=' + fmt,
            click: () => {
              const tmpFile = path.join(os.tmpdir(), `hash-single-${Date.now()}.txt`);
              fs.writeFileSync(tmpFile, entry.hash + '\n', 'utf8');
              exec(`john --format=${esc(fmt)} ${esc(tmpFile)}`);
              entry.status = 'cracking';
              triggerRender();
              debouncedSave();
            },
          });
        }
      }
    }

    items.push({ type: 'separator' });

    items.push({ label: '-- Online Lookup --', enabled: false });
    items.push({ label: 'CrackStation', click: () => lookupCrackStation(entry) });
    items.push({ label: 'Hashes.com', click: () => lookupHashesCom(entry) });

    items.push({ type: 'separator' });

    items.push({
      label: 'Mark as Not Found',
      click: () => {
        entry.status = 'not-found';
        triggerRender();
        debouncedSave();
      },
    });
  }

  if (entry.status === 'cracked' && entry.plaintext) {
    items.push({ label: 'Copy Plaintext', click: () => copy(entry.plaintext) });
  }

  items.push({ type: 'separator' });
  items.push({
    label: 'Remove',
    click: () => removeHash(entry.hash),
  });

  // Render popup menu
  const menu = document.createElement('div');
  menu.style.cssText = `
    position:fixed; z-index:100000; min-width:240px; max-height:70vh; overflow-y:auto;
    background:#1e1e1e; border:1px solid #444; border-radius:6px; padding:4px 0;
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; font-size:12px;
    color:#ddd; box-shadow:0 4px 20px rgba(0,0,0,0.6); backdrop-filter:blur(8px);
  `;

  for (const item of items) {
    if (item.type === 'separator') {
      const s = document.createElement('div');
      s.style.cssText = 'height:1px;background:#333;margin:4px 8px;';
      menu.appendChild(s);
      continue;
    }
    const row = document.createElement('div');
    row.textContent = item.label;
    if (item.enabled === false) {
      row.style.cssText = 'padding:4px 16px;color:#777;font-size:11px;font-weight:600;cursor:default;';
    } else {
      row.style.cssText = 'padding:5px 16px;cursor:pointer;border-radius:3px;margin:1px 4px;';
      row.addEventListener('mouseenter', () => { row.style.background = '#333'; });
      row.addEventListener('mouseleave', () => { row.style.background = 'none'; });
      row.addEventListener('click', (e) => {
        e.stopPropagation();
        _dismissMenu();
        if (item.click) item.click();
      });
    }
    menu.appendChild(row);
  }

  document.body.appendChild(menu);
  const rect = menu.getBoundingClientRect();
  if (x + rect.width > window.innerWidth) x = window.innerWidth - rect.width - 8;
  if (y + rect.height > window.innerHeight) y = window.innerHeight - rect.height - 8;
  if (x < 0) x = 4;
  if (y < 0) y = 4;
  menu.style.left = x + 'px';
  menu.style.top = y + 'px';

  _menuEl = menu;
  setTimeout(() => {
    document.addEventListener('mousedown', _onMenuBlur, true);
    document.addEventListener('keydown', _onMenuEsc, true);
  }, 0);
}

// ======================================================================
//  HUD REGISTRATION
// ======================================================================

let hudRegistered = false;

function registerHud() {
  if (hudRegistered) return;
  const recon = getRecon();

  const renderFn = (React) => renderHashesTab(React);

  if (recon.hud) {
    hudApi = recon.hud;
    recon.hud.registerTab('hashes', 'Hashes', null, renderFn);
    hudRegistered = true;
    updateBadge();
  } else {
    recon.events.on('hud:ready', (hud) => {
      hudApi = hud;
      hud.registerTab('hashes', 'Hashes', null, renderFn);
      hudRegistered = true;
      updateBadge();
    });
  }
}

// ======================================================================
//  HYPER PLUGIN EXPORTS
// ======================================================================

// Middleware: intercept PTY data to scan for hashes
exports.middleware = (store) => (next) => (action) => {
  switch (action.type) {
    case 'SESSION_SET_ACTIVE':
      activeUid = action.uid;
      break;

    case 'SESSION_ADD':
      if (!activeUid) activeUid = action.uid;
      break;

    case 'SESSION_PTY_DATA':
      scanForHashes(action.data);
      break;

    case 'SESSION_PTY_EXIT':
    case 'SESSION_USER_EXIT':
      if (action.uid === activeUid) activeUid = null;
      break;
  }

  return next(action);
};

// decorateHyper: register HUD tab
exports.decorateHyper = (Hyper, { React }) => {
  return class HashWorkshopHyper extends React.Component {
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

      // Listen for hash events from other plugins
      const recon = getRecon();
      recon.events.on('hash:detected', (data) => {
        if (data && data.hash && data.type && data.possible) {
          addHash(data.hash, data.type, data.possible);
        }
      });
      recon.events.on('hash:cracked', (data) => {
        if (data && data.hash && data.plaintext) {
          markCracked(data.hash, data.plaintext);
        }
      });
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
