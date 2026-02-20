'use strict';
const { diffVisibleRows } = require('./viewportDiff');

// ══════════════════════════════════════════════════════════════
//  HYPER RECON MENU
//  Inline icon detection for security testing & bug bounty
//  Scans terminal buffer, overlays clickable icons on patterns
//  (Delegates actions to hyper-target-panel)
// ══════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════════
//  PATTERN CLASSIFICATION (anchored regexes for validating matches)
// ══════════════════════════════════════════════════════════════

const HASH_TYPES = {
  8:   ['CRC32', 'Adler-32'],
  16:  ['MySQL323', 'Half-MD5', 'FNV-164'],
  32:  ['MD5', 'NTLM', 'MD4', 'LM', 'Domain Cached Creds'],
  40:  ['SHA-1', 'MySQL5', 'RIPEMD-160', 'HAVAL-160'],
  48:  ['Tiger-192', 'HAVAL-192'],
  56:  ['SHA-224', 'SHA3-224', 'Keccak-224'],
  64:  ['SHA-256', 'SHA3-256', 'RIPEMD-256', 'Keccak-256', 'BLAKE2s'],
  96:  ['SHA-384', 'SHA3-384', 'Keccak-384'],
  128: ['SHA-512', 'SHA3-512', 'Whirlpool', 'BLAKE2b', 'Keccak-512'],
};

const PATTERNS = [
  {
    type: 'url',
    regex: /^https?:\/\/\S+$/i,
    parse: (m, s) => {
      try {
        const u = new URL(s);
        return { full: s, host: u.hostname, path: u.pathname, port: u.port };
      } catch { return { full: s }; }
    }
  },
  {
    type: 'email',
    regex: /^([a-zA-Z0-9._%+\-]+)@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})$/,
    parse: (m) => ({ full: m[0], user: m[1], domain: m[2] })
  },
  {
    type: 'cve',
    regex: /^CVE-\d{4}-\d{4,}$/i,
    parse: (m) => ({ full: m[0], id: m[0].toUpperCase() })
  },
  {
    type: 'ip_port',
    regex: /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})$/,
    parse: (m) => ({ full: m[0], ip: m[1], port: m[2] })
  },
  {
    type: 'cidr',
    regex: /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/,
    parse: (m) => ({ full: m[0], ip: m[1], prefix: m[2] })
  },
  {
    type: 'ipv4',
    regex: /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/,
    parse: (m) => {
      const octets = [+m[1], +m[2], +m[3], +m[4]];
      if (octets.some(o => o > 255)) return null;
      return { full: m[0], ip: m[0] };
    }
  },
  {
    type: 'domain_port',
    regex: /^((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}):(\d{1,5})$/,
    parse: (m) => ({ full: m[0], domain: m[1], port: m[2] })
  },
  {
    type: 'domain',
    regex: /^((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})$/,
    parse: (m) => ({ full: m[0], domain: m[1] })
  },
  { type: 'hash_format', regex: /^(\$2[aby]?\$\d{2}\$.{53})$/, parse: (m) => ({ full: m[0], algo: 'bcrypt' }) },
  { type: 'hash_format', regex: /^(\$argon2(?:i|d|id)\$.+)$/, parse: (m) => ({ full: m[0], algo: 'argon2' }) },
  {
    type: 'hash_format',
    regex: /^(\$[156]\$.+)$/,
    parse: (m) => {
      const t = m[0][1];
      const algos = { '1': 'MD5-crypt', '5': 'SHA-256-crypt', '6': 'SHA-512-crypt' };
      return { full: m[0], algo: algos[t] || 'unix-crypt' };
    }
  },
  { type: 'hash_hex', regex: /^\*([a-fA-F0-9]{40})$/, parse: (m) => ({ full: m[0], hash: m[1], len: 40, possible: ['MySQL5'] }) },
  { type: 'hash_hex', regex: /^([a-fA-F0-9]{128})$/, parse: (m) => ({ full: m[0], hash: m[1], len: 128, possible: HASH_TYPES[128] || ['Unknown'] }) },
  { type: 'hash_hex', regex: /^([a-fA-F0-9]{96})$/, parse: (m) => ({ full: m[0], hash: m[1], len: 96, possible: HASH_TYPES[96] || ['Unknown'] }) },
  { type: 'hash_hex', regex: /^([a-fA-F0-9]{64})$/, parse: (m) => ({ full: m[0], hash: m[1], len: 64, possible: HASH_TYPES[64] || ['Unknown'] }) },
  { type: 'hash_hex', regex: /^([a-fA-F0-9]{56})$/, parse: (m) => ({ full: m[0], hash: m[1], len: 56, possible: HASH_TYPES[56] || ['Unknown'] }) },
  { type: 'hash_hex', regex: /^([a-fA-F0-9]{40})$/, parse: (m) => ({ full: m[0], hash: m[1], len: 40, possible: HASH_TYPES[40] || ['Unknown'] }) },
  { type: 'hash_hex', regex: /^([a-fA-F0-9]{32})$/, parse: (m) => ({ full: m[0], hash: m[1], len: 32, possible: HASH_TYPES[32] || ['Unknown'] }) },
  { type: 'hash_hex', regex: /^([a-fA-F0-9]{16})$/, parse: (m) => ({ full: m[0], hash: m[1], len: 16, possible: HASH_TYPES[16] || ['Unknown'] }) },
];

function tryBase64Decode(str) {
  if (str.length < 6) return null;
  if (!/^[A-Za-z0-9+/]+=*$/.test(str)) return null;
  if (/^[a-fA-F0-9]+$/.test(str)) return null;
  try {
    const buf = Buffer.from(str, 'base64');
    const decoded = buf.toString('utf8');
    if (Buffer.from(decoded, 'utf8').toString('base64').replace(/=+$/, '') !== str.replace(/=+$/, '')) return null;
    const printable = decoded.replace(/[^\x20-\x7E\n\r\t]/g, '');
    if (printable.length / decoded.length < 0.6) return null;
    return decoded;
  } catch { return null; }
}

function tryDoubleBase64(str) {
  const first = tryBase64Decode(str);
  if (!first) return null;
  const second = tryBase64Decode(first.trim());
  if (!second) return null;
  return { first, second };
}

function classify(text) {
  const clean = text.trim();
  if (!clean || clean.includes('\n') || clean.length > 2048) {
    return { type: 'text', parsed: { full: clean } };
  }
  for (const pat of PATTERNS) {
    const m = clean.match(pat.regex);
    if (m) {
      const parsed = pat.parse(m, clean);
      if (parsed) return { type: pat.type, parsed };
    }
  }
  const b64double = tryDoubleBase64(clean);
  if (b64double) {
    return { type: 'base64_double', parsed: { full: clean, first: b64double.first, second: b64double.second } };
  }
  const b64single = tryBase64Decode(clean);
  if (b64single) {
    return { type: 'base64', parsed: { full: clean, decoded: b64single } };
  }
  return { type: 'text', parsed: { full: clean } };
}


// ══════════════════════════════════════════════════════════════
//  INLINE SCANNERS (non-anchored, for terminal buffer scanning)
//  Ordered by priority — higher priority patterns consume chars first
// ══════════════════════════════════════════════════════════════

const MAX_MATCHES_PER_LINE = 10;

const INLINE_SCANNERS = [
  // 1. URLs (highest priority — captures IPs/domains within URLs)
  /https?:\/\/[^\s<>"']+[^\s<>"'.,;:!?)}\]]/g,
  // 2. Email addresses
  /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g,
  // 3. CVE identifiers
  /\bCVE-\d{4}-\d{4,}\b/gi,
  // 4. IP:Port
  /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}\b/g,
  // 5. CIDR notation
  /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}\b/g,
  // 6. IPv4 addresses
  /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,
  // 7. Domain:Port (common TLDs)
  /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+(?:com|org|net|io|dev|co|me|info|gov|edu|mil|uk|de|ru|cn|jp|fr|au|ca|se|nl|ch|xyz|onion|local|internal):\d{1,5}\b/g,
  // 8. Domains with subdomains (sub.domain.tld)
  /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?\.){2,}(?:com|org|net|io|dev|co|me|info|gov|edu|mil|uk|de|ru|cn|jp|fr|au|ca|se|nl|ch|xyz|onion|local|internal)\b/g,
  // 9. Bare domains (restrictive TLD list)
  /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+(?:com|org|net|io|dev|gov|edu|mil)\b/g,
  // 10. Format hashes (bcrypt)
  /\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}/g,
  // 11. Format hashes (argon2)
  /\$argon2(?:i|d|id)\$[^\s]+/g,
  // 12. Format hashes (unix crypt)
  /\$[156]\$[^\s]+/g,
  // 13-17. Hex hashes (longest first to avoid partial matches)
  /(?<![a-fA-F0-9])[a-fA-F0-9]{128}(?![a-fA-F0-9])/g,
  /(?<![a-fA-F0-9])[a-fA-F0-9]{96}(?![a-fA-F0-9])/g,
  /(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])/g,
  /(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])/g,
  /(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])/g,
];

function findMatchesInLine(text) {
  const matches = [];
  const used = new Set();

  for (const scanner of INLINE_SCANNERS) {
    scanner.lastIndex = 0;
    let m;
    while ((m = scanner.exec(text)) !== null) {
      if (matches.length >= MAX_MATCHES_PER_LINE) return matches;

      const start = m.index;
      const end = start + m[0].length;

      // Skip if overlapping with already consumed characters
      let overlap = false;
      for (let i = start; i < end; i++) {
        if (used.has(i)) { overlap = true; break; }
      }
      if (overlap) continue;

      // Validate through classify
      const result = classify(m[0]);
      if (result.type === 'text') continue;

      // Mark range as consumed
      for (let i = start; i < end; i++) used.add(i);

      matches.push({
        col: start,
        len: m[0].length,
        type: result.type,
        text: m[0],
        parsed: result.parsed,
      });
    }
  }

  return matches;
}


// ══════════════════════════════════════════════════════════════
//  TYPE ICONS
// ══════════════════════════════════════════════════════════════

const TYPE_ICONS = {
  url:           { svg: '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>', color: '#60a5fa' },
  email:         { svg: '<rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>', color: '#f59e0b' },
  cve:           { svg: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>', color: '#ef4444' },
  ip_port:       { svg: '<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="6" cy="6" r="1"/><circle cx="6" cy="18" r="1"/>', color: '#34d399' },
  cidr:          { svg: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>', color: '#a78bfa' },
  ipv4:          { svg: '<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="6" cy="6" r="1"/><circle cx="6" cy="18" r="1"/>', color: '#34d399' },
  domain_port:   { svg: '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>', color: '#38bdf8' },
  domain:        { svg: '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>', color: '#38bdf8' },
  hash_format:   { svg: '<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>', color: '#fb923c' },
  hash_hex:      { svg: '<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>', color: '#fb923c' },
  base64:        { svg: '<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/><line x1="14" y1="4" x2="10" y2="20"/>', color: '#c084fc' },
  base64_double: { svg: '<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/><line x1="14" y1="4" x2="10" y2="20"/>', color: '#e879f9' },
  text:          { svg: '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>', color: '#94a3b8' },
};

const TYPE_LABELS = {
  url: 'URL', email: 'Email', cve: 'CVE', ip_port: 'IP:Port',
  cidr: 'CIDR', ipv4: 'IPv4', domain_port: 'Host:Port', domain: 'Domain',
  hash_format: 'Hash', hash_hex: 'Hash', base64: 'Base64',
  base64_double: '2xBase64', text: 'Lookup',
};


// ══════════════════════════════════════════════════════════════
//  PLUGIN EXPORTS
// ══════════════════════════════════════════════════════════════

exports.decorateTerm = (Term, { React }) => {
  return class ReconTerm extends React.Component {
    constructor(props) {
      super(props);
      this._onDecorated = this._onDecorated.bind(this);
      this._xterm = null;
      this._overlay = null;
      this._scanTimer = null;
      this._disposables = [];
      this._cache = new Map();
      this._visibleRows = new Map();
      this._iconsByRow = new Map();
      this._cellSig = '';
    }

    _onDecorated(term) {
      if (this.props.onDecorated) this.props.onDecorated(term);
      if (!term || !term.term) return;

      this._xterm = term.term;

      // Wait for DOM to be ready
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
      // Create overlay container
      this._overlay = document.createElement('div');
      this._overlay.className = 'recon-overlay';
      this._overlay.style.cssText =
        'position:absolute;top:0;left:0;width:100%;height:100%;' +
        'pointer-events:none;overflow:visible;z-index:10;';

      // Ensure screen is positioned for absolute children
      if (getComputedStyle(screen).position === 'static') {
        screen.style.position = 'relative';
      }
      screen.appendChild(this._overlay);

      // Subscribe to xterm events
      const xterm = this._xterm;
      this._disposables.push(
        xterm.onRender(() => this._queueScan()),
        xterm.onScroll(() => this._queueScan()),
        xterm.onResize(() => {
          this._cache.clear();
          this._cellSig = '';
          this._queueScan();
        }),
      );

      this._queueScan();
    }

    _queueScan() {
      if (this._scanTimer) return;
      this._scanTimer = setTimeout(() => {
        this._scanTimer = null;
        requestAnimationFrame(() => this._scan());
      }, 120);
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
      const nextRows = new Map();

      for (let vr = 0; vr < xterm.rows; vr++) {
        const br = buf.viewportY + vr;
        const line = buf.getLine(br);
        if (!line) continue;
        nextRows.set(br, { vr, text: line.translateToString(true) });
      }

      const diff = diffVisibleRows(this._visibleRows, nextRows);
      const updateSet = new Set(diff.update);
      const nextCellSig = `${cell.w}:${cell.h}`;
      const geometryChanged = this._cellSig !== nextCellSig;
      this._cellSig = nextCellSig;

      if (geometryChanged) {
        for (const br of nextRows.keys()) updateSet.add(br);
      }

      for (const br of diff.remove) this._removeRowIcons(br);

      for (const br of updateSet) {
        const row = nextRows.get(br);
        this._removeRowIcons(br);
        if (!row || !row.text || !row.text.trim()) continue;

        // Cache by buffer row + content so unchanged rows skip regex work.
        const key = `${br}:${row.text}`;
        let matches = this._cache.get(key);
        if (!matches) {
          matches = findMatchesInLine(row.text);
          this._cache.set(key, matches);
          if (this._cache.size > 500) {
            this._cache.delete(this._cache.keys().next().value);
          }
        }

        if (!matches.length) continue;
        const rowIcons = [];
        for (const match of matches) {
          rowIcons.push(this._placeIcon(row.vr, match, cell));
        }
        this._iconsByRow.set(br, rowIcons);
      }

      this._visibleRows = nextRows;
    }

    _removeRowIcons(br) {
      const icons = this._iconsByRow.get(br);
      if (!icons) return;
      for (const el of icons) {
        if (el && el.remove) el.remove();
      }
      this._iconsByRow.delete(br);
    }

    _placeIcon(viewRow, match, cell) {
      const { col, type, text: matchText, parsed } = match;
      const ic = TYPE_ICONS[type] || TYPE_ICONS.text;
      const lbl = TYPE_LABELS[type] || '';

      // Position: above and to the left of the first character
      let top = viewRow * cell.h - 11;
      if (top < 0) top = viewRow * cell.h + 2; // fallback for first row

      const el = document.createElement('div');
      el.style.cssText =
        `position:absolute;left:${Math.max(0, col * cell.w - 2)}px;top:${top}px;` +
        'pointer-events:auto;cursor:pointer;display:flex;align-items:center;gap:1px;' +
        `padding:0 3px;height:10px;border-radius:2px;` +
        `background:rgba(20,20,20,0.88);border:1px solid ${ic.color}55;` +
        'opacity:0.5;transition:opacity 0.12s,transform 0.12s;' +
        `font-family:-apple-system,sans-serif;font-size:7px;color:${ic.color};white-space:nowrap;`;

      el.innerHTML =
        `<svg xmlns="http://www.w3.org/2000/svg" width="7" height="7" viewBox="0 0 24 24" ` +
        `fill="none" stroke="${ic.color}" stroke-width="2.5" stroke-linecap="round" ` +
        `stroke-linejoin="round">${ic.svg}</svg><span>${lbl}</span>`;

      el.addEventListener('mouseenter', () => {
        el.style.opacity = '1';
        el.style.transform = 'scale(1.2)';
        el.style.zIndex = '20';
      });
      el.addEventListener('mouseleave', () => {
        el.style.opacity = '0.5';
        el.style.transform = 'none';
        el.style.zIndex = '';
      });
      el.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();

        let target = matchText;
        if (type === 'hash_hex' && parsed && parsed.hash) {
            target = parsed.hash;
        } else if (type === 'email' && parsed && parsed.full) {
            target = parsed.full;
        } else if (type === 'cve' && parsed && parsed.id) {
            target = parsed.id;
        }

        window.dispatchEvent(new CustomEvent('hyper-target-panel:open-tool-selector', {
            detail: {
              target: target,
              type: type,
              actions: [
                { id: 'set_target', label: 'Set Target' }
              ]
            }
        }));
      });

      this._overlay.appendChild(el);
      return el;
    }

    componentWillUnmount() {
      if (this._scanTimer) { clearTimeout(this._scanTimer); this._scanTimer = null; }
      for (const d of this._disposables) d.dispose();
      this._disposables = [];
      if (this._overlay) { this._overlay.remove(); this._overlay = null; }
      this._cache.clear();
      this._visibleRows.clear();
      this._iconsByRow.clear();
    }

    render() {
      return React.createElement(Term, Object.assign({}, this.props, {
        onDecorated: this._onDecorated,
      }));
    }
  };
};
