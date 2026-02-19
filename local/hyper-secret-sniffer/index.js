'use strict';

// ======================================================================
//  HYPER SECRET SNIFFER
//  Detects secrets, credentials, API keys, and tokens in terminal output.
//  Watches all SESSION_PTY_DATA for secret patterns and logs findings
//  to the shared recon HUD with masked display and export capabilities.
// ======================================================================

const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { clipboard } = require('electron');

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
const SECRETS_FILE = path.join(RECON_DIR, 'secrets.json');
const DEBOUNCE_MS = 150;
const MAX_CONTEXT_LEN = 120;
const MAX_SECRETS = 2000;

// ------ ANSI Stripping -----------------------------------------------

function stripAnsi(str) {
  return str
    .replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '')
    .replace(/\x1b\][^\x07]*\x07/g, '')
    .replace(/\x1b[()][AB012]/g, '')
    .replace(/\x1b[\[?]?[0-9;]*[a-zA-Z]/g, '');
}

// ------ Display Masking -----------------------------------------------

function maskSecret(value) {
  if (!value || value.length <= 8) return '****';
  return value.slice(0, 4) + '****' + value.slice(-4);
}

// ------ Persistence ---------------------------------------------------

function ensureDir() {
  try {
    if (!fs.existsSync(RECON_DIR)) {
      fs.mkdirSync(RECON_DIR, { recursive: true, mode: 0o700 });
    }
  } catch (e) { /* ignore */ }
}

function loadSecrets() {
  try {
    if (fs.existsSync(SECRETS_FILE)) {
      const raw = fs.readFileSync(SECRETS_FILE, 'utf8');
      const data = JSON.parse(raw);
      if (Array.isArray(data)) return data;
    }
  } catch (e) { /* ignore corrupted file */ }
  return [];
}

function saveSecrets(secrets) {
  try {
    ensureDir();
    const data = JSON.stringify(secrets, null, 2);
    fs.writeFileSync(SECRETS_FILE, data, { encoding: 'utf8', mode: 0o600 });
  } catch (e) { /* ignore */ }
}

// ------ Secret Detection Patterns -------------------------------------

const SECRET_PATTERNS = [
  // === API Keys ===
  {
    name: 'AWS Access Key',
    type: 'api_key',
    provider: 'aws',
    regex: /AKIA[0-9A-Z]{16}/g,
    extract: (m) => m[0],
  },
  {
    name: 'AWS Secret Key',
    type: 'api_key',
    provider: 'aws',
    regex: /(?:aws.{0,20}(?:secret|key|token)|SecretAccessKey)\s*[:='"]\s*([a-zA-Z0-9/+=]{40})/gi,
    extract: (m) => m[1],
  },
  {
    name: 'GitHub Token',
    type: 'api_key',
    provider: 'github',
    regex: /gh[pousr]_[A-Za-z0-9_]{36,}/g,
    extract: (m) => m[0],
  },
  {
    name: 'GitLab Token',
    type: 'api_key',
    provider: 'gitlab',
    regex: /glpat-[A-Za-z0-9\-]{20,}/g,
    extract: (m) => m[0],
  },
  {
    name: 'Slack Token',
    type: 'api_key',
    provider: 'slack',
    regex: /xox[baprs]-[0-9a-zA-Z\-]+/g,
    extract: (m) => m[0],
  },
  {
    name: 'Stripe Secret Key',
    type: 'api_key',
    provider: 'stripe',
    regex: /sk_live_[0-9a-zA-Z]{24,}/g,
    extract: (m) => m[0],
  },
  {
    name: 'Google API Key',
    type: 'api_key',
    provider: 'google',
    regex: /AIza[0-9A-Za-z\-_]{35}/g,
    extract: (m) => m[0],
  },
  {
    name: 'Heroku API Key',
    type: 'api_key',
    provider: 'heroku',
    regex: /(?:heroku|HEROKU).{0,20}[:=]\s*['"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['"]?/g,
    extract: (m) => m[1],
  },
  {
    name: 'Generic API Key',
    type: 'api_key',
    provider: 'generic',
    regex: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{16,})['"]?/gi,
    extract: (m) => m[1],
  },

  // === Tokens ===
  {
    name: 'JWT Token',
    type: 'token',
    provider: null,
    regex: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g,
    extract: (m) => m[0],
  },
  {
    name: 'Bearer Token',
    type: 'token',
    provider: null,
    regex: /Bearer\s+([a-zA-Z0-9\-._~+/]+=*)/g,
    extract: (m) => m[1],
  },
  {
    name: 'Session/Auth Token',
    type: 'token',
    provider: null,
    regex: /(?:session|token|auth)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{20,})['"]?/gi,
    extract: (m) => m[1],
  },

  // === Credentials ===
  {
    name: 'Basic Auth',
    type: 'credential',
    provider: null,
    regex: /Basic\s+([A-Za-z0-9+/]+=*)/g,
    extract: (m) => m[1],
    decode: (val) => {
      try {
        return Buffer.from(val, 'base64').toString('utf8');
      } catch { return null; }
    },
  },
  {
    name: 'Password in URL',
    type: 'credential',
    provider: null,
    regex: /:\/\/([^:]+):([^@]+)@/g,
    extract: (m) => m[2],
    contextExtra: (m) => `user: ${m[1]}`,
  },
  {
    name: 'Password Field',
    type: 'credential',
    provider: null,
    regex: /(?:password|passwd|pwd|pass)\s*[:=]\s*['"]?([^\s'"&]+)['"]?/gi,
    extract: (m) => m[1],
  },
  {
    name: 'Connection String',
    type: 'connection_string',
    provider: null,
    regex: /(?:mysql|postgres|postgresql|mongodb|mongodb\+srv|redis):\/\/[^:]+:[^@]+@[^\s'"]+/gi,
    extract: (m) => m[0],
  },

  // === Private Keys ===
  {
    name: 'RSA/EC/DSA Private Key',
    type: 'private_key',
    provider: null,
    regex: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g,
    extract: (m) => m[0],
  },
  {
    name: 'OpenSSH Private Key',
    type: 'private_key',
    provider: null,
    regex: /-----BEGIN OPENSSH PRIVATE KEY-----/g,
    extract: (m) => m[0],
  },

  // === Cloud Metadata ===
  {
    name: 'AWS Metadata AccessKeyId',
    type: 'api_key',
    provider: 'aws',
    regex: /"AccessKeyId"\s*:\s*"([^"]+)"/g,
    extract: (m) => m[1],
  },
  {
    name: 'AWS Metadata SecretAccessKey',
    type: 'api_key',
    provider: 'aws',
    regex: /"SecretAccessKey"\s*:\s*"([^"]+)"/g,
    extract: (m) => m[1],
  },
  {
    name: 'AWS Metadata Token',
    type: 'token',
    provider: 'aws',
    regex: /"Token"\s*:\s*"([^"]+)"/g,
    extract: (m) => m[1],
  },
];

// ------ Secret Store --------------------------------------------------

let _secrets = [];
let _nextId = 1;
let _seenValues = new Set();
let _loaded = false;
let _saveTimer = null;

function _initStore() {
  if (_loaded) return;
  _loaded = true;
  _secrets = loadSecrets();
  if (_secrets.length > 0) {
    _nextId = Math.max(..._secrets.map(s => s.id || 0)) + 1;
    for (const s of _secrets) {
      _seenValues.add(s.value);
    }
  }
}

function addSecret(secret) {
  _initStore();
  if (_seenValues.has(secret.value)) return null;
  _seenValues.add(secret.value);

  secret.id = _nextId++;
  secret.timestamp = Date.now();
  _secrets.push(secret);

  // Cap at max
  if (_secrets.length > MAX_SECRETS) {
    const removed = _secrets.splice(0, _secrets.length - MAX_SECRETS);
    for (const r of removed) _seenValues.delete(r.value);
  }

  // Debounced save
  if (_saveTimer) clearTimeout(_saveTimer);
  _saveTimer = setTimeout(() => {
    _saveTimer = null;
    saveSecrets(_secrets);
  }, 2000);

  return secret;
}

function getSecrets() {
  _initStore();
  return _secrets;
}

function clearSecrets() {
  _secrets = [];
  _nextId = 1;
  _seenValues.clear();
  saveSecrets(_secrets);
}

// ------ Line Buffer Per Session ---------------------------------------

const _lineBuffers = new Map();

function getLineBuffer(uid) {
  if (!_lineBuffers.has(uid)) {
    _lineBuffers.set(uid, '');
  }
  return _lineBuffers.get(uid);
}

function setLineBuffer(uid, val) {
  _lineBuffers.set(uid, val);
}

function removeLineBuffer(uid) {
  _lineBuffers.delete(uid);
}

// ------ Secret Scanner ------------------------------------------------

function extractContext(line, matchIndex, matchLen) {
  const start = Math.max(0, matchIndex - 30);
  const end = Math.min(line.length, matchIndex + matchLen + 30);
  let ctx = line.slice(start, end).trim();
  if (ctx.length > MAX_CONTEXT_LEN) {
    ctx = ctx.slice(0, MAX_CONTEXT_LEN - 3) + '...';
  }
  return ctx;
}

function scanLine(line, sessionUid) {
  const recon = getRecon();
  const clean = stripAnsi(line);
  if (clean.length < 8) return;

  for (const pat of SECRET_PATTERNS) {
    pat.regex.lastIndex = 0;
    let m;
    while ((m = pat.regex.exec(clean)) !== null) {
      const value = pat.extract(m);
      if (!value || value.length < 6) continue;

      // Skip obvious false positives
      if (/^[=\-_\s]+$/.test(value)) continue;
      if (/^(true|false|null|undefined|none|yes|no)$/i.test(value)) continue;

      let context = extractContext(clean, m.index, m[0].length);
      if (pat.contextExtra) {
        const extra = pat.contextExtra(m);
        if (extra) context = extra + ' | ' + context;
      }

      let decoded = null;
      if (pat.decode) {
        decoded = pat.decode(value);
      }

      const secret = {
        type: pat.type,
        provider: pat.provider,
        name: pat.name,
        value: value,
        decoded: decoded,
        context: context,
        sessionUid: sessionUid,
      };

      const added = addSecret(secret);
      if (added) {
        recon.events.emit('secret:found', added);
      }
    }
  }
}

// ------ Debounced Parsing Per Session ---------------------------------

const _parseTimers = new Map();

function debouncedParse(uid, data) {
  const existing = getLineBuffer(uid);
  const combined = existing + stripAnsi(data);

  // Split into lines, keeping the last partial line in the buffer
  const lines = combined.split(/\r?\n/);
  const lastLine = lines.pop() || '';
  setLineBuffer(uid, lastLine);

  // Scan complete lines
  for (const line of lines) {
    if (line.trim().length > 0) {
      scanLine(line, uid);
    }
  }

  // Also scan partial line with debounce in case data ends without newline
  if (lastLine.trim().length > 0) {
    if (_parseTimers.has(uid)) clearTimeout(_parseTimers.get(uid));
    _parseTimers.set(uid, setTimeout(() => {
      _parseTimers.delete(uid);
      const buf = getLineBuffer(uid);
      if (buf.trim().length > 0) {
        scanLine(buf, uid);
        // Don't clear buffer - more data might come
      }
    }, DEBOUNCE_MS));
  }
}

// ------ Provider Icons (inline SVG paths for 24x24 viewBox) -----------

const PROVIDER_ICONS = {
  aws:     { color: '#ff9900', svg: '<path d="M6.5 17.5c-1.5-.7-2.5-1.5-3-2.5"/><path d="M3 12c0-5 4-9 9-9s9 4 9 9"/><path d="M17.5 17.5c1.5-.7 2.5-1.5 3-2.5"/><path d="M7 21l5-3 5 3"/>' },
  github:  { color: '#f0f6fc', svg: '<path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.4 5.4 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65S8.93 17.38 9 18v4"/><path d="M9 18c-4.51 2-5-2-7-2"/>' },
  gitlab:  { color: '#fc6d26', svg: '<path d="m22 13.29-3.33-10a.42.42 0 0 0-.14-.18.38.38 0 0 0-.22-.11.39.39 0 0 0-.23.07.42.42 0 0 0-.14.18l-2.26 6.67H8.32L6.1 3.26a.42.42 0 0 0-.1-.18.38.38 0 0 0-.26-.08.39.39 0 0 0-.23.07.42.42 0 0 0-.14.18L2 13.29a.74.74 0 0 0 .27.83L12 21l9.69-6.88a.71.71 0 0 0 .31-.83Z"/>' },
  slack:   { color: '#e01e5a', svg: '<rect x="13" y="2" width="3" height="8" rx="1.5"/><path d="M19 8.5V10h1.5A1.5 1.5 0 1 0 19 8.5"/><rect x="8" y="14" width="3" height="8" rx="1.5"/><path d="M5 15.5V14H3.5A1.5 1.5 0 1 0 5 15.5"/><rect x="14" y="13" width="8" height="3" rx="1.5"/><path d="M15.5 19H14v1.5a1.5 1.5 0 1 0 1.5-1.5"/><rect x="2" y="8" width="8" height="3" rx="1.5"/><path d="M8.5 5H10V3.5A1.5 1.5 0 1 0 8.5 5"/>' },
  stripe:  { color: '#635bff', svg: '<path d="M2 10h20v8a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-8Z"/><path d="M22 6a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2v4h20V6Z"/>' },
  google:  { color: '#4285f4', svg: '<circle cx="12" cy="12" r="10"/><path d="M12 8v8"/><path d="M8 12h8"/>' },
  heroku:  { color: '#430098', svg: '<path d="M4 2h16a1 1 0 0 1 1 1v18a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1z"/><path d="M7 18l3-3-3-3"/><path d="M14 10V6"/>' },
  azure:   { color: '#0078d4', svg: '<path d="M13 2L4 22h7l2-5 3 5h5L13 2z"/>' },
  generic: { color: '#8b949e', svg: '<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>' },
};

const TYPE_BADGES = {
  api_key:           { label: 'API KEY',     color: '#f97316', bg: '#f9731622' },
  token:             { label: 'TOKEN',       color: '#a78bfa', bg: '#a78bfa22' },
  credential:        { label: 'CREDENTIAL',  color: '#ef4444', bg: '#ef444422' },
  private_key:       { label: 'PRIV KEY',    color: '#f43f5e', bg: '#f43f5e22' },
  connection_string: { label: 'CONN STR',    color: '#38bdf8', bg: '#38bdf822' },
  financial:         { label: 'FINANCIAL',   color: '#3fb950', bg: '#3fb95022' },
  unknown:           { label: 'UNKNOWN',     color: '#8b949e', bg: '#8b949e22' },
};

// ======================================================================
//  MIDDLEWARE -- intercept SESSION_PTY_DATA for scanning
// ======================================================================

exports.middleware = (store) => (next) => (action) => {
  switch (action.type) {
    case 'SESSION_PTY_DATA':
      if (action.data && action.uid) {
        debouncedParse(action.uid, action.data);
      }
      break;
    case 'SESSION_PTY_EXIT':
    case 'SESSION_USER_EXIT':
      // Flush remaining buffer
      {
        const buf = getLineBuffer(action.uid);
        if (buf && buf.trim().length > 0) {
          scanLine(buf, action.uid);
        }
        removeLineBuffer(action.uid);
        if (_parseTimers.has(action.uid)) {
          clearTimeout(_parseTimers.get(action.uid));
          _parseTimers.delete(action.uid);
        }
      }
      break;
  }
  return next(action);
};

// ======================================================================
//  HUD TAB -- Register "Secrets" tab with the HUD framework
// ======================================================================

exports.decorateHyper = (Hyper, { React }) => {
  const h = React.createElement;

  return class SecretSnifferHyper extends React.Component {
    constructor(props) {
      super(props);
      this._registered = false;
      this._filterType = 'all';
      this._revealedIds = new Set();
      this._confirmingReveal = null;
      this._forceUpdate = null;
    }

    componentDidMount() {
      const recon = getRecon();
      const self = this;

      // Store a force-update handle for re-rendering HUD content
      this._forceUpdate = () => this.forceUpdate();

      const tryRegister = () => {
        if (self._registered) return;
        if (!recon.hud) return;
        self._registered = true;

        recon.hud.registerTab(
          'secrets',
          'Secrets',
          '\uD83D\uDD12',
          (React) => self._renderPanel(React)
        );

        recon.hud.updateBadge('secrets', getSecrets().length || null);
      };

      // Listen for new secrets to update badge
      recon.events.on('secret:found', () => {
        if (recon.hud) {
          recon.hud.updateBadge('secrets', getSecrets().length || null);
        }
        if (self._forceUpdate) self._forceUpdate();
      });

      // Register immediately if HUD is ready, or wait
      if (recon.hud) {
        tryRegister();
      }
      recon.events.on('hud:ready', tryRegister);
    }

    componentWillUnmount() {
      const recon = getRecon();
      if (recon.hud && this._registered) {
        recon.hud.removeTab('secrets');
      }
      this._registered = false;
    }

    // ------ Panel Rendering -------------------------------------------

    _renderPanel(React) {
      const h = React.createElement;
      const secrets = getSecrets();
      const filtered = this._filterType === 'all'
        ? secrets
        : secrets.filter(s => s.type === this._filterType);

      const types = ['all', ...new Set(secrets.map(s => s.type))];

      return h('div', { style: { display: 'flex', flexDirection: 'column', height: '100%', gap: '6px' } },
        // Header bar
        this._renderHeader(h, types, secrets.length, filtered.length),
        // Secret list
        this._renderSecretList(h, filtered),
        // Reveal confirmation overlay
        this._confirmingReveal !== null && this._renderConfirmOverlay(h)
      );
    }

    _renderHeader(h, types, total, filtered) {
      const filterBtnStyle = (active) => ({
        padding: '2px 8px',
        borderRadius: '3px',
        border: '1px solid ' + (active ? '#58a6ff' : '#30363d'),
        background: active ? '#58a6ff22' : 'transparent',
        color: active ? '#58a6ff' : '#8b949e',
        cursor: 'pointer',
        fontSize: '10px',
        fontWeight: active ? 600 : 400,
        textTransform: 'uppercase',
      });

      const actionBtnStyle = {
        padding: '2px 10px',
        borderRadius: '3px',
        border: '1px solid #30363d',
        background: 'transparent',
        color: '#8b949e',
        cursor: 'pointer',
        fontSize: '10px',
      };

      return h('div', {
        style: {
          display: 'flex', alignItems: 'center', gap: '6px',
          padding: '4px 0', borderBottom: '1px solid #21262d',
          flexWrap: 'wrap', flexShrink: 0,
        }
      },
        // Filters
        ...types.map(type =>
          h('span', {
            key: type,
            style: filterBtnStyle(this._filterType === type),
            onClick: () => { this._filterType = type; this.forceUpdate(); },
          }, type === 'all' ? `All (${total})` : `${(TYPE_BADGES[type] || {}).label || type} (${getSecrets().filter(s => s.type === type).length})`)
        ),
        // Spacer
        h('div', { style: { flex: 1 } }),
        // Export button
        h('span', {
          style: actionBtnStyle,
          onClick: () => this._exportSecrets(),
          title: 'Export all secrets to file',
        }, 'Export'),
        // Clear button
        h('span', {
          style: { ...actionBtnStyle, color: '#f85149', borderColor: '#f8514933' },
          onClick: () => this._clearSecrets(),
          title: 'Clear all detected secrets',
        }, 'Clear')
      );
    }

    _renderSecretList(h, secrets) {
      if (secrets.length === 0) {
        return h('div', {
          style: {
            flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: '#484f58', fontSize: '12px', fontStyle: 'italic',
          }
        }, 'No secrets detected yet. Monitoring terminal output...');
      }

      // Show newest first
      const sorted = [...secrets].reverse();

      return h('div', {
        style: {
          flex: 1, overflow: 'auto', display: 'flex',
          flexDirection: 'column', gap: '2px',
        }
      },
        ...sorted.map(secret => this._renderSecretRow(h, secret))
      );
    }

    _renderSecretRow(h, secret) {
      const badge = TYPE_BADGES[secret.type] || { label: secret.type, color: '#8b949e', bg: '#8b949e22' };
      const isRevealed = this._revealedIds.has(secret.id);
      const displayValue = isRevealed ? secret.value : maskSecret(secret.value);
      const provIcon = PROVIDER_ICONS[secret.provider] || PROVIDER_ICONS.generic;
      const ts = new Date(secret.timestamp);
      const timeStr = ts.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });

      const rowStyle = {
        display: 'flex', alignItems: 'center', gap: '8px',
        padding: '5px 8px', borderRadius: '4px',
        background: '#161b2233', border: '1px solid #21262d',
        cursor: 'default', fontSize: '11px',
        transition: 'background 0.1s',
      };

      return h('div', {
        key: secret.id,
        style: rowStyle,
        onMouseEnter: (e) => { e.currentTarget.style.background = '#161b22aa'; },
        onMouseLeave: (e) => { e.currentTarget.style.background = '#161b2233'; },
      },
        // Type badge
        h('span', {
          style: {
            padding: '1px 6px', borderRadius: '3px', fontSize: '9px',
            fontWeight: 700, color: badge.color, background: badge.bg,
            whiteSpace: 'nowrap', minWidth: '55px', textAlign: 'center',
            letterSpacing: '0.3px',
          }
        }, badge.label),

        // Provider icon
        h('span', {
          style: { display: 'inline-flex', flexShrink: 0 },
          title: secret.provider || 'unknown',
          dangerouslySetInnerHTML: {
            __html: `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="${provIcon.color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${provIcon.svg}</svg>`,
          },
        }),

        // Masked value (click to reveal with confirmation)
        h('span', {
          style: {
            fontFamily: 'monospace', color: isRevealed ? '#f0f6fc' : '#c9d1d9',
            cursor: 'pointer', minWidth: '120px', maxWidth: '200px',
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            background: isRevealed ? '#f8514922' : 'transparent',
            padding: '1px 4px', borderRadius: '2px',
          },
          title: isRevealed ? 'Click to hide' : 'Click to reveal (with confirmation)',
          onClick: () => {
            if (isRevealed) {
              this._revealedIds.delete(secret.id);
              this.forceUpdate();
            } else {
              this._confirmingReveal = secret.id;
              this.forceUpdate();
            }
          },
        }, displayValue),

        // Decoded value for Basic Auth
        secret.decoded && h('span', {
          style: {
            fontFamily: 'monospace', color: '#f97316', fontSize: '10px',
            maxWidth: '120px', overflow: 'hidden', textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          },
          title: 'Decoded: ' + secret.decoded,
        }, '\u2192 ' + (isRevealed ? secret.decoded : maskSecret(secret.decoded))),

        // Separator
        h('span', { style: { color: '#30363d' } }, '|'),

        // Context
        h('span', {
          style: {
            flex: 1, color: '#484f58', fontSize: '10px',
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            fontFamily: 'monospace',
          },
          title: secret.context,
        }, secret.context),

        // Separator
        h('span', { style: { color: '#30363d' } }, '|'),

        // Timestamp
        h('span', {
          style: { color: '#484f58', fontSize: '10px', whiteSpace: 'nowrap', flexShrink: 0 },
        }, timeStr),

        // Action buttons
        h('span', {
          style: {
            display: 'flex', gap: '4px', flexShrink: 0,
          }
        },
          // Copy button
          h('span', {
            style: {
              padding: '1px 6px', borderRadius: '3px', cursor: 'pointer',
              border: '1px solid #30363d', color: '#8b949e', fontSize: '9px',
              background: 'transparent',
            },
            title: 'Copy secret value',
            onClick: (e) => {
              e.stopPropagation();
              clipboard.writeText(secret.value);
              const recon = getRecon();
              if (recon.hud) recon.hud.notify('Secret copied to clipboard', 'info');
            },
            onMouseEnter: (e) => { e.target.style.borderColor = '#58a6ff'; e.target.style.color = '#58a6ff'; },
            onMouseLeave: (e) => { e.target.style.borderColor = '#30363d'; e.target.style.color = '#8b949e'; },
          }, 'Copy'),

          // Copy Decoded button (for Basic Auth)
          secret.decoded && h('span', {
            style: {
              padding: '1px 6px', borderRadius: '3px', cursor: 'pointer',
              border: '1px solid #30363d', color: '#8b949e', fontSize: '9px',
              background: 'transparent',
            },
            title: 'Copy decoded value',
            onClick: (e) => {
              e.stopPropagation();
              clipboard.writeText(secret.decoded);
              const recon = getRecon();
              if (recon.hud) recon.hud.notify('Decoded value copied', 'info');
            },
            onMouseEnter: (e) => { e.target.style.borderColor = '#f97316'; e.target.style.color = '#f97316'; },
            onMouseLeave: (e) => { e.target.style.borderColor = '#30363d'; e.target.style.color = '#8b949e'; },
          }, 'Decoded')
        )
      );
    }

    _renderConfirmOverlay(h) {
      const overlayStyle = {
        position: 'absolute', top: 0, left: 0, right: 0, bottom: 0,
        background: 'rgba(0,0,0,0.7)', display: 'flex',
        alignItems: 'center', justifyContent: 'center',
        zIndex: 1000,
      };

      const dialogStyle = {
        background: '#161b22', border: '1px solid #30363d',
        borderRadius: '8px', padding: '16px 24px',
        textAlign: 'center', maxWidth: '320px',
      };

      const btnBase = {
        padding: '4px 16px', borderRadius: '4px', cursor: 'pointer',
        fontSize: '12px', fontWeight: 600, border: 'none',
        margin: '0 6px',
      };

      return h('div', { style: overlayStyle, onClick: () => { this._confirmingReveal = null; this.forceUpdate(); } },
        h('div', { style: dialogStyle, onClick: (e) => e.stopPropagation() },
          h('div', { style: { color: '#f0f6fc', fontSize: '13px', marginBottom: '4px', fontWeight: 600 } },
            'Reveal Secret?'),
          h('div', { style: { color: '#8b949e', fontSize: '11px', marginBottom: '16px' } },
            'This will show the full secret value. Ensure your screen is not being shared.'),
          h('div', null,
            h('button', {
              style: { ...btnBase, background: '#da3633', color: '#fff' },
              onClick: () => {
                this._revealedIds.add(this._confirmingReveal);
                this._confirmingReveal = null;
                this.forceUpdate();
              },
            }, 'Reveal'),
            h('button', {
              style: { ...btnBase, background: '#30363d', color: '#c9d1d9' },
              onClick: () => { this._confirmingReveal = null; this.forceUpdate(); },
            }, 'Cancel')
          )
        )
      );
    }

    // ------ Actions ---------------------------------------------------

    _exportSecrets() {
      const secrets = getSecrets();
      if (secrets.length === 0) return;

      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const exportPath = path.join(RECON_DIR, `secrets-export-${timestamp}.json`);

      try {
        ensureDir();
        const exportData = {
          exported: new Date().toISOString(),
          count: secrets.length,
          secrets: secrets.map(s => ({
            id: s.id,
            timestamp: s.timestamp,
            type: s.type,
            provider: s.provider,
            name: s.name,
            value: s.value,
            decoded: s.decoded || null,
            context: s.context,
            sessionUid: s.sessionUid,
          })),
        };
        fs.writeFileSync(exportPath, JSON.stringify(exportData, null, 2), { encoding: 'utf8', mode: 0o600 });

        const recon = getRecon();
        if (recon.hud) recon.hud.notify(`Exported ${secrets.length} secrets to ${exportPath}`, 'info');
      } catch (e) {
        const recon = getRecon();
        if (recon.hud) recon.hud.notify('Export failed: ' + e.message, 'error');
      }
    }

    _clearSecrets() {
      clearSecrets();
      this._revealedIds.clear();
      this._confirmingReveal = null;
      const recon = getRecon();
      if (recon.hud) {
        recon.hud.updateBadge('secrets', null);
        recon.hud.notify('All secrets cleared', 'info');
      }
      this.forceUpdate();
    }

    // ------ Render wrapper --------------------------------------------

    render() {
      return React.createElement(Hyper, this.props);
    }
  };
};
