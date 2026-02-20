'use strict';

// ══════════════════════════════════════════════════════════════
//  HYPER TARGET BOOK
//  Combined target scope manager + discovered services notebook
//  Auto-captures ports/services from nmap/masscan terminal output
//  Provides HUD tab, right-click integration, import/export
// ══════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const os = require('os');
const { shell, clipboard } = require('electron');

// ─── Constants ───────────────────────────────────────────────
const WORKSPACE_ROOT = path.resolve(__dirname, '..', '..');
const RECON_DIR = process.env.HYPER_RECON_DIR || path.join(WORKSPACE_ROOT, 'cache', 'hyper-recon');
const LEGACY_RECON_DIR = path.join(os.homedir(), '.hyper_recon');
const TARGETS_FILE = path.join(RECON_DIR, 'targets.json');
const SAVE_DEBOUNCE_MS = 1500;
const PTY_BUFFER_MAX = 8192;
const WORDLIST_DIR = path.join(WORKSPACE_ROOT, 'cache', 'wordlists', 'vendor');
const WEB_WORDLIST = process.env.HYPER_WORDLIST_WEB || path.join(WORDLIST_DIR, 'common.txt');
const PASSWORD_LIST = process.env.HYPER_PASSWORD_LIST || path.join(WORDLIST_DIR, 'rockyou.txt');

try {
  fs.mkdirSync(RECON_DIR, { recursive: true });
  if (!fs.existsSync(TARGETS_FILE) && fs.existsSync(path.join(LEGACY_RECON_DIR, 'targets.json'))) {
    fs.copyFileSync(path.join(LEGACY_RECON_DIR, 'targets.json'), TARGETS_FILE);
  }
} catch (_e) {}

// ─── Shared Recon Namespace ──────────────────────────────────
function getRecon() {
  if (!window.__hyperRecon) {
    const EventEmitter = require('events');
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

// ─── Shell Safety ────────────────────────────────────────────
function esc(str) {
  return "'" + String(str).replace(/'/g, "'\\''") + "'";
}

// ─── Session Tracking ────────────────────────────────────────
let activeUid = null;

function execInTerminal(cmd) {
  const recon = getRecon();
  const uid = recon.activeUid || activeUid;
  if (!uid) return;
  window.rpc.emit('data', { uid, data: cmd + '\n', escaped: false });
}


// ══════════════════════════════════════════════════════════════
//  TARGET STORE
//  In-memory store with JSON persistence to disk
// ══════════════════════════════════════════════════════════════

/*
  targetStore shape:
  {
    targets: Map<string, TargetEntry>
  }

  TargetEntry:
  {
    address: string,       // IP, domain, or CIDR
    type: 'ipv4'|'domain'|'cidr',
    inScope: boolean,
    tags: string[],
    addedAt: number,       // timestamp
    services: Map<string, ServiceEntry>   // key: "port/proto"
  }

  ServiceEntry:
  {
    port: number,
    proto: string,         // tcp, udp
    state: string,         // open, filtered, closed
    service: string,       // ssh, http, etc.
    version: string,       // Apache/2.4.41, OpenSSH 8.2p1, etc.
    discoveredAt: number,
    source: string,        // 'nmap', 'masscan', 'manual'
  }
*/

const targetStore = {
  targets: new Map(),
  _saveTimer: null,
  _dirty: false,

  // ─── Persistence ─────────────────────────────────────────
  ensureDir() {
    try {
      if (!fs.existsSync(RECON_DIR)) {
        fs.mkdirSync(RECON_DIR, { recursive: true });
      }
    } catch (e) {
      console.error('[target-book] Cannot create recon dir:', e.message);
    }
  },

  load() {
    try {
      if (!fs.existsSync(TARGETS_FILE)) return;
      const raw = fs.readFileSync(TARGETS_FILE, 'utf8');
      const data = JSON.parse(raw);
      if (!Array.isArray(data.targets)) return;
      this.targets.clear();
      for (const t of data.targets) {
        const services = new Map();
        if (Array.isArray(t.services)) {
          for (const s of t.services) {
            services.set(`${s.port}/${s.proto}`, s);
          }
        }
        this.targets.set(t.address, {
          address: t.address,
          type: t.type || classifyTarget(t.address),
          inScope: t.inScope !== false,
          tags: Array.isArray(t.tags) ? t.tags : [],
          addedAt: t.addedAt || Date.now(),
          services,
        });
      }
    } catch (e) {
      console.error('[target-book] Load error:', e.message);
    }
  },

  save() {
    this._dirty = true;
    if (this._saveTimer) return;
    this._saveTimer = setTimeout(() => {
      this._saveTimer = null;
      this._dirty = false;
      this._writeToDisk();
    }, SAVE_DEBOUNCE_MS);
  },

  saveNow() {
    if (this._saveTimer) {
      clearTimeout(this._saveTimer);
      this._saveTimer = null;
    }
    this._dirty = false;
    this._writeToDisk();
  },

  _writeToDisk() {
    try {
      this.ensureDir();
      const data = {
        version: 1,
        savedAt: new Date().toISOString(),
        targets: Array.from(this.targets.values()).map(t => ({
          address: t.address,
          type: t.type,
          inScope: t.inScope,
          tags: t.tags,
          addedAt: t.addedAt,
          services: Array.from(t.services.values()),
        })),
      };
      fs.writeFileSync(TARGETS_FILE, JSON.stringify(data, null, 2), 'utf8');
    } catch (e) {
      console.error('[target-book] Save error:', e.message);
    }
  },

  // ─── Target Operations ───────────────────────────────────
  addTarget(address, opts = {}) {
    const addr = address.trim();
    if (!addr) return null;
    if (this.targets.has(addr)) return this.targets.get(addr);
    const entry = {
      address: addr,
      type: opts.type || classifyTarget(addr),
      inScope: opts.inScope !== false,
      tags: opts.tags || [],
      addedAt: Date.now(),
      services: new Map(),
    };
    this.targets.set(addr, entry);
    this.save();
    this._notify();
    return entry;
  },

  removeTarget(address) {
    if (this.targets.delete(address)) {
      this.save();
      this._notify();
      return true;
    }
    return false;
  },

  toggleScope(address) {
    const t = this.targets.get(address);
    if (t) {
      t.inScope = !t.inScope;
      this.save();
      this._notify();
    }
  },

  addService(targetAddr, serviceInfo) {
    let target = this.targets.get(targetAddr);
    if (!target) {
      target = this.addTarget(targetAddr);
    }
    const key = `${serviceInfo.port}/${serviceInfo.proto || 'tcp'}`;
    const existing = target.services.get(key);
    if (existing) {
      // Update if new data is richer
      let changed = false;
      if (serviceInfo.state && serviceInfo.state !== existing.state) {
        existing.state = serviceInfo.state;
        changed = true;
      }
      if (serviceInfo.service && serviceInfo.service !== existing.service) {
        existing.service = serviceInfo.service;
        changed = true;
      }
      if (serviceInfo.version && serviceInfo.version.length > (existing.version || '').length) {
        existing.version = serviceInfo.version;
        changed = true;
      }
      if (changed) {
        this.save();
        this._notify();
      }
      return;
    }
    target.services.set(key, {
      port: serviceInfo.port,
      proto: serviceInfo.proto || 'tcp',
      state: serviceInfo.state || 'open',
      service: serviceInfo.service || 'unknown',
      version: serviceInfo.version || '',
      discoveredAt: Date.now(),
      source: serviceInfo.source || 'manual',
    });
    this.save();
    this._notify();
  },

  getTargets() {
    return Array.from(this.targets.values());
  },

  getInScope() {
    return this.getTargets().filter(t => t.inScope);
  },

  totalServices() {
    let count = 0;
    for (const t of this.targets.values()) count += t.services.size;
    return count;
  },

  _notify() {
    try {
      const recon = getRecon();
      recon.targets = this.targets;
      recon.events.emit('targets:updated', this.targets);
      if (recon.hud) {
        const total = this.targets.size;
        recon.hud.updateBadge('target-book', total > 0 ? total : null);
      }
    } catch (e) {
      // Ignore if recon not ready yet
    }
  },

  // ─── Import/Export ───────────────────────────────────────
  importFromText(text) {
    const lines = text.split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith('#'));
    let added = 0;
    for (const line of lines) {
      // Could be "ip" or "ip,tag1,tag2"
      const parts = line.split(/[,\t]/);
      const addr = parts[0].trim();
      if (!addr) continue;
      const tags = parts.slice(1).map(t => t.trim()).filter(Boolean);
      if (!this.targets.has(addr)) {
        this.addTarget(addr, { tags });
        added++;
      }
    }
    return added;
  },

  exportAsJSON() {
    const data = {
      exportedAt: new Date().toISOString(),
      targets: this.getTargets().map(t => ({
        address: t.address,
        type: t.type,
        inScope: t.inScope,
        tags: t.tags,
        services: Array.from(t.services.values()),
      })),
    };
    return JSON.stringify(data, null, 2);
  },

  exportAsMarkdown() {
    const lines = [];
    lines.push('# Target Book Export');
    lines.push(`> Exported: ${new Date().toISOString()}`);
    lines.push('');

    const targets = this.getTargets();
    if (targets.length === 0) {
      lines.push('_No targets._');
      return lines.join('\n');
    }

    for (const t of targets) {
      const scope = t.inScope ? 'IN SCOPE' : 'OUT OF SCOPE';
      const tagsStr = t.tags.length > 0 ? ` [${t.tags.join(', ')}]` : '';
      lines.push(`## ${t.address} (${t.type}) - ${scope}${tagsStr}`);
      lines.push('');

      const svcs = Array.from(t.services.values());
      if (svcs.length === 0) {
        lines.push('_No services discovered._');
      } else {
        lines.push('| Port | State | Service | Version | Source |');
        lines.push('|------|-------|---------|---------|--------|');
        for (const s of svcs.sort((a, b) => a.port - b.port)) {
          lines.push(`| ${s.port}/${s.proto} | ${s.state} | ${s.service} | ${s.version || '-'} | ${s.source} |`);
        }
      }
      lines.push('');
    }

    return lines.join('\n');
  },
};

// ─── Target Classification ───────────────────────────────────
function classifyTarget(addr) {
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(addr)) return 'cidr';
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(addr)) return 'ipv4';
  return 'domain';
}


// ══════════════════════════════════════════════════════════════
//  TERMINAL OUTPUT PARSER
//  Watches SESSION_PTY_DATA for nmap/masscan output patterns
// ══════════════════════════════════════════════════════════════

const outputParser = {
  // Per-session buffer to accumulate partial lines
  _buffers: new Map(),
  // Current scan target per session (from "Nmap scan report for X")
  _scanTargets: new Map(),

  // Nmap patterns
  _reNmapReport: /Nmap scan report for\s+(\S+?)(?:\s+\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\))?/,
  _reNmapPort: /^(\d{1,5})\/(tcp|udp)\s+(open|filtered|closed|open\|filtered)\s+(\S+)(?:\s+(.*))?$/,
  // Masscan patterns
  _reMasscanOpen: /Discovered open port\s+(\d{1,5})\/(tcp|udp)\s+on\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/,

  feed(uid, rawData) {
    // Accumulate data and process complete lines
    let buf = this._buffers.get(uid) || '';
    buf += rawData;

    // Prevent unbounded buffer growth
    if (buf.length > PTY_BUFFER_MAX) {
      buf = buf.slice(-PTY_BUFFER_MAX);
    }

    const lines = buf.split(/\r?\n/);
    // Keep the last incomplete line in the buffer
    this._buffers.set(uid, lines.pop() || '');

    for (const line of lines) {
      this._parseLine(uid, stripAnsi(line));
    }
  },

  _parseLine(uid, line) {
    const trimmed = line.trim();
    if (!trimmed) return;

    // Check for nmap scan report header
    const reportMatch = trimmed.match(this._reNmapReport);
    if (reportMatch) {
      // Prefer the IP in parens if available, otherwise the hostname
      const target = reportMatch[2] || reportMatch[1];
      this._scanTargets.set(uid, target);
      // Also ensure the hostname target exists if different
      if (reportMatch[2] && reportMatch[1] !== reportMatch[2]) {
        // Store domain mapping — add both
        targetStore.addTarget(reportMatch[1]);
        targetStore.addTarget(reportMatch[2]);
      } else {
        targetStore.addTarget(target);
      }
      return;
    }

    // Check for nmap port lines
    const portMatch = trimmed.match(this._reNmapPort);
    if (portMatch) {
      const currentTarget = this._scanTargets.get(uid);
      if (currentTarget) {
        targetStore.addService(currentTarget, {
          port: parseInt(portMatch[1], 10),
          proto: portMatch[2],
          state: portMatch[3],
          service: portMatch[4],
          version: (portMatch[5] || '').trim(),
          source: 'nmap',
        });
      }
      return;
    }

    // Check for masscan output
    const masscanMatch = trimmed.match(this._reMasscanOpen);
    if (masscanMatch) {
      targetStore.addService(masscanMatch[3], {
        port: parseInt(masscanMatch[1], 10),
        proto: masscanMatch[2],
        state: 'open',
        service: 'unknown',
        version: '',
        source: 'masscan',
      });
      return;
    }
  },

  cleanup(uid) {
    this._buffers.delete(uid);
    this._scanTargets.delete(uid);
  },
};

// Strip ANSI escape sequences from terminal data
function stripAnsi(str) {
  // eslint-disable-next-line no-control-regex
  return str.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '')
            .replace(/\x1b\][^\x07]*\x07/g, '')
            .replace(/\x1b[()][AB012]/g, '')
            .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, '');
}


// ══════════════════════════════════════════════════════════════
//  QUICK ACTIONS — service-targeted scan commands
// ══════════════════════════════════════════════════════════════

function getQuickActions(target, service) {
  const addr = esc(target.address);
  const port = service.port;
  const svc = (service.service || '').toLowerCase();
  const actions = [];

  // Universal actions
  actions.push({
    label: 'Nmap Deep Scan',
    cmd: `nmap -sV -sC -p ${port} ${addr}`,
  });

  // HTTP/HTTPS services
  if (svc === 'http' || svc === 'https' || svc === 'http-proxy' || svc === 'ssl/http' ||
      svc === 'http-alt' || port === 80 || port === 443 || port === 8080 || port === 8443) {
    const scheme = (port === 443 || port === 8443 || svc === 'https' || svc === 'ssl/http') ? 'https' : 'http';
    const urlBase = `${scheme}://${target.address}:${port}`;
    actions.push(
      { label: 'Nikto', cmd: `nikto -h ${esc(urlBase)}` },
      { label: 'Gobuster', cmd: `gobuster dir -u ${esc(urlBase)} -w ${esc(WEB_WORDLIST)}` },
      { label: 'Whatweb', cmd: `whatweb ${esc(urlBase)}` },
      { label: 'cURL Headers', cmd: `curl -sIk ${esc(urlBase)}` },
      { label: 'SQLMap (GET)', cmd: `sqlmap -u ${esc(urlBase + '/')} --batch --crawl=2` },
      { label: 'Open in Browser', browse: urlBase },
    );
  }

  // SSH
  if (svc === 'ssh' || port === 22) {
    actions.push(
      { label: 'SSH Banner', cmd: `nmap -sV -p ${port} --script ssh2-enum-algos,ssh-hostkey ${addr}` },
      { label: 'Hydra SSH', cmd: `hydra -l root -P ${esc(PASSWORD_LIST)} ${addr} ssh -s ${port} -t 4` },
    );
  }

  // FTP
  if (svc === 'ftp' || port === 21) {
    actions.push(
      { label: 'FTP Anon Check', cmd: `nmap -sV -p ${port} --script ftp-anon ${addr}` },
      { label: 'Hydra FTP', cmd: `hydra -l anonymous -P ${esc(PASSWORD_LIST)} ${addr} ftp -s ${port} -t 4` },
    );
  }

  // SMB
  if (svc === 'microsoft-ds' || svc === 'netbios-ssn' || port === 445 || port === 139) {
    actions.push(
      { label: 'Enum4linux', cmd: `enum4linux -a ${addr}` },
      { label: 'SMB Shares', cmd: `smbclient -L //${target.address} -N` },
      { label: 'Nmap SMB Scripts', cmd: `nmap -p ${port} --script smb-enum-shares,smb-enum-users,smb-vuln* ${addr}` },
    );
  }

  // MySQL
  if (svc === 'mysql' || port === 3306) {
    actions.push(
      { label: 'MySQL Nmap Scripts', cmd: `nmap -sV -p ${port} --script mysql-info,mysql-enum ${addr}` },
      { label: 'Hydra MySQL', cmd: `hydra -l root -P ${esc(PASSWORD_LIST)} ${addr} mysql -s ${port}` },
    );
  }

  // RDP
  if (svc === 'ms-wbt-server' || port === 3389) {
    actions.push(
      { label: 'RDP Nmap Scripts', cmd: `nmap -sV -p ${port} --script rdp-enum-encryption,rdp-vuln-ms12-020 ${addr}` },
    );
  }

  // SMTP
  if (svc === 'smtp' || port === 25 || port === 587) {
    actions.push(
      { label: 'SMTP User Enum', cmd: `nmap -p ${port} --script smtp-enum-users ${addr}` },
    );
  }

  // DNS
  if (svc === 'domain' || port === 53) {
    actions.push(
      { label: 'DNS Zone Transfer', cmd: `dig axfr @${target.address} ${esc(target.address)}` },
      { label: 'DNS Enum', cmd: `nmap -p ${port} --script dns-brute ${addr}` },
    );
  }

  // SNMP
  if (svc === 'snmp' || port === 161) {
    actions.push(
      { label: 'SNMP Walk', cmd: `snmpwalk -v2c -c public ${addr}` },
      { label: 'Nmap SNMP Scripts', cmd: `nmap -sU -p ${port} --script snmp-brute,snmp-info ${addr}` },
    );
  }

  // LDAP
  if (svc === 'ldap' || port === 389 || port === 636) {
    actions.push(
      { label: 'LDAP Search', cmd: `ldapsearch -x -H ldap://${target.address}:${port} -b '' -s base` },
    );
  }

  // Redis
  if (svc === 'redis' || port === 6379) {
    actions.push(
      { label: 'Redis Info', cmd: `redis-cli -h ${target.address} -p ${port} info` },
    );
  }

  // Copy port info
  actions.push({
    label: 'Copy Port Info',
    copy: `${target.address}:${port} ${service.state} ${service.service} ${service.version}`.trim(),
  });

  return actions;
}


// ══════════════════════════════════════════════════════════════
//  POPUP MENU (DOM-based, for right-click / quick-actions)
// ══════════════════════════════════════════════════════════════

let _menuEl = null;

function dismissMenu() {
  if (_menuEl) { _menuEl.remove(); _menuEl = null; }
  document.removeEventListener('mousedown', _onMenuBlur, true);
  document.removeEventListener('keydown', _onMenuEsc, true);
}

function _onMenuBlur(e) {
  if (_menuEl && !_menuEl.contains(e.target)) dismissMenu();
}

function _onMenuEsc(e) {
  if (e.key === 'Escape') dismissMenu();
}

function showActionMenu(items, x, y) {
  dismissMenu();
  const menu = document.createElement('div');
  menu.style.cssText = `
    position:fixed;z-index:100000;min-width:200px;max-height:70vh;overflow-y:auto;
    background:#1a1a2e;border:1px solid #444;border-radius:6px;padding:4px 0;
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:12px;
    color:#ddd;box-shadow:0 4px 20px rgba(0,0,0,0.6);
  `;

  for (const item of items) {
    if (item.separator) {
      const s = document.createElement('div');
      s.style.cssText = 'height:1px;background:#333;margin:4px 8px;';
      menu.appendChild(s);
      continue;
    }
    const row = document.createElement('div');
    row.textContent = item.label;
    row.style.cssText = 'padding:5px 14px;cursor:pointer;border-radius:3px;margin:1px 4px;';
    row.addEventListener('mouseenter', () => { row.style.background = '#2a2a4e'; });
    row.addEventListener('mouseleave', () => { row.style.background = 'none'; });
    row.addEventListener('click', (e) => {
      e.stopPropagation();
      dismissMenu();
      if (item.cmd) execInTerminal(item.cmd);
      if (item.browse) shell.openExternal(item.browse);
      if (item.copy) clipboard.writeText(item.copy);
      if (item.fn) item.fn();
    });
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


// ══════════════════════════════════════════════════════════════
//  STANDALONE OVERLAY FALLBACK
//  Used when no HUD framework is available
// ══════════════════════════════════════════════════════════════

let _overlayEl = null;
let _overlayVisible = false;

function createStandaloneOverlay() {
  if (_overlayEl) return;
  _overlayEl = document.createElement('div');
  _overlayEl.id = 'target-book-overlay';
  _overlayEl.style.cssText = `
    position:fixed;bottom:0;left:0;right:0;height:0;
    background:#0d1117;border-top:2px solid #58a6ff;
    z-index:99999;overflow:hidden;transition:height 0.2s ease;
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',monospace;
    font-size:12px;color:#c9d1d9;
  `;

  // Toggle button
  const toggle = document.createElement('div');
  toggle.style.cssText = `
    position:fixed;bottom:6px;right:12px;z-index:100001;
    background:#0d1117;border:1px solid #58a6ff;border-radius:4px;
    padding:4px 10px;cursor:pointer;font-size:10px;color:#58a6ff;
    font-family:-apple-system,sans-serif;user-select:none;
  `;
  toggle.textContent = 'Targets';
  toggle.addEventListener('click', () => {
    _overlayVisible = !_overlayVisible;
    _overlayEl.style.height = _overlayVisible ? '220px' : '0';
    if (_overlayVisible) renderOverlayContent();
  });

  document.body.appendChild(_overlayEl);
  document.body.appendChild(toggle);
}

function renderOverlayContent() {
  if (!_overlayEl) return;
  const React = { createElement: fakeCreateElement };
  const vdom = renderTargetBook(React);
  _overlayEl.innerHTML = '';
  _overlayEl.style.overflow = 'auto';
  _overlayEl.style.padding = '8px 12px';
  const html = vdomToHTML(vdom);
  _overlayEl.innerHTML = html;
  bindOverlayEvents(_overlayEl);
}

// Minimal vdom-to-HTML for standalone fallback
function fakeCreateElement(tag, props, ...children) {
  return { tag, props: props || {}, children: children.flat().filter(c => c != null && c !== false) };
}

function vdomToHTML(node) {
  if (node == null || node === false) return '';
  if (typeof node === 'string' || typeof node === 'number') return escapeHTML(String(node));
  if (Array.isArray(node)) return node.map(vdomToHTML).join('');

  const { tag, props, children } = node;
  if (typeof tag === 'function') return ''; // Skip function components in fallback

  let attrs = '';
  const style = props.style;
  if (style && typeof style === 'object') {
    const css = Object.entries(style).map(([k, v]) => {
      const prop = k.replace(/([A-Z])/g, '-$1').toLowerCase();
      return `${prop}:${v}`;
    }).join(';');
    attrs += ` style="${escapeHTML(css)}"`;
  }
  if (props.className) attrs += ` class="${escapeHTML(props.className)}"`;
  if (props.title) attrs += ` title="${escapeHTML(props.title)}"`;
  if (props['data-action']) attrs += ` data-action="${escapeHTML(props['data-action'])}"`;
  if (props['data-addr']) attrs += ` data-addr="${escapeHTML(props['data-addr'])}"`;
  if (props['data-port']) attrs += ` data-port="${escapeHTML(props['data-port'])}"`;

  const inner = children.map(vdomToHTML).join('');
  return `<${tag}${attrs}>${inner}</${tag}>`;
}

function escapeHTML(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function bindOverlayEvents(container) {
  // Minimal event binding for standalone mode
  container.querySelectorAll('[data-action]').forEach(el => {
    el.style.cursor = 'pointer';
    el.addEventListener('click', (e) => {
      const action = el.getAttribute('data-action');
      const addr = el.getAttribute('data-addr');
      if (action === 'remove' && addr) {
        targetStore.removeTarget(addr);
        renderOverlayContent();
      } else if (action === 'toggle-scope' && addr) {
        targetStore.toggleScope(addr);
        renderOverlayContent();
      }
    });
  });
}


// ══════════════════════════════════════════════════════════════
//  HUD TAB RENDERER (React.createElement based)
// ══════════════════════════════════════════════════════════════

// Persistent UI state
const uiState = {
  expandedTargets: new Set(),
  addInput: '',
  filter: 'all', // 'all', 'in-scope', 'out-of-scope'
  importMode: false,
  importText: '',
};

function renderTargetBook(React) {
  const h = React.createElement;
  const targets = targetStore.getTargets();

  // Filter targets
  let filtered = targets;
  if (uiState.filter === 'in-scope') filtered = targets.filter(t => t.inScope);
  if (uiState.filter === 'out-of-scope') filtered = targets.filter(t => !t.inScope);

  // Styles
  const containerStyle = {
    display: 'flex',
    flexDirection: 'column',
    gap: '6px',
    height: '100%',
  };

  const toolbarStyle = {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    flexShrink: 0,
    flexWrap: 'wrap',
  };

  const inputStyle = {
    background: '#161b22',
    border: '1px solid #30363d',
    borderRadius: '4px',
    padding: '3px 8px',
    color: '#c9d1d9',
    fontSize: '11px',
    fontFamily: 'inherit',
    outline: 'none',
    flex: '1',
    minWidth: '120px',
  };

  const btnStyle = {
    background: '#21262d',
    border: '1px solid #30363d',
    borderRadius: '4px',
    padding: '3px 10px',
    color: '#c9d1d9',
    fontSize: '10px',
    cursor: 'pointer',
    fontFamily: 'inherit',
    whiteSpace: 'nowrap',
  };

  const btnPrimaryStyle = {
    ...btnStyle,
    background: '#238636',
    borderColor: '#2ea043',
    color: '#fff',
  };

  const filterBtnStyle = (active) => ({
    ...btnStyle,
    background: active ? '#1f6feb' : '#21262d',
    borderColor: active ? '#388bfd' : '#30363d',
    color: active ? '#fff' : '#8b949e',
    fontSize: '9px',
    padding: '2px 6px',
  });

  const statStyle = {
    fontSize: '10px',
    color: '#8b949e',
    marginLeft: '4px',
  };

  // Build children
  const children = [];

  // Stats bar
  children.push(
    h('div', { style: { display: 'flex', alignItems: 'center', gap: '12px', fontSize: '10px', color: '#8b949e' } },
      h('span', null, `${targets.length} target${targets.length !== 1 ? 's' : ''}`),
      h('span', null, `${targetStore.totalServices()} service${targetStore.totalServices() !== 1 ? 's' : ''}`),
      h('span', null, `${targets.filter(t => t.inScope).length} in scope`),
    )
  );

  // Toolbar: Add input + buttons
  children.push(
    h('div', { style: toolbarStyle },
      h('input', {
        style: inputStyle,
        placeholder: 'Add target (IP, domain, CIDR)...',
        value: uiState.addInput,
        onChange: (e) => { uiState.addInput = e.target.value; },
        onKeyDown: (e) => {
          if (e.key === 'Enter' && uiState.addInput.trim()) {
            targetStore.addTarget(uiState.addInput.trim());
            uiState.addInput = '';
            triggerRender();
          }
        },
      }),
      h('button', {
        style: btnPrimaryStyle,
        onClick: () => {
          if (uiState.addInput.trim()) {
            targetStore.addTarget(uiState.addInput.trim());
            uiState.addInput = '';
            triggerRender();
          }
        },
      }, '+ Add'),
      h('button', {
        style: btnStyle,
        onClick: () => {
          uiState.importMode = !uiState.importMode;
          triggerRender();
        },
      }, uiState.importMode ? 'Cancel' : 'Import'),
      h('button', {
        style: btnStyle,
        onClick: () => {
          const json = targetStore.exportAsJSON();
          clipboard.writeText(json);
          const recon = getRecon();
          if (recon.hud) recon.hud.notify('Exported JSON to clipboard', 'info');
        },
      }, 'Export JSON'),
      h('button', {
        style: btnStyle,
        onClick: () => {
          const md = targetStore.exportAsMarkdown();
          clipboard.writeText(md);
          const recon = getRecon();
          if (recon.hud) recon.hud.notify('Exported Markdown to clipboard', 'info');
        },
      }, 'Export MD'),
    )
  );

  // Import area (shown when importMode is true)
  if (uiState.importMode) {
    children.push(
      h('div', { style: { display: 'flex', gap: '6px', alignItems: 'flex-start' } },
        h('textarea', {
          style: {
            ...inputStyle,
            flex: 1,
            height: '50px',
            resize: 'vertical',
            fontFamily: 'monospace',
            fontSize: '10px',
          },
          placeholder: 'Paste targets (one per line). Lines starting with # are ignored.\nFormat: address or address,tag1,tag2',
          value: uiState.importText,
          onChange: (e) => { uiState.importText = e.target.value; },
        }),
        h('button', {
          style: btnPrimaryStyle,
          onClick: () => {
            const count = targetStore.importFromText(uiState.importText);
            uiState.importText = '';
            uiState.importMode = false;
            const recon = getRecon();
            if (recon.hud) recon.hud.notify(`Imported ${count} target${count !== 1 ? 's' : ''}`, 'info');
            triggerRender();
          },
        }, 'Import'),
      )
    );
  }

  // Filter buttons
  children.push(
    h('div', { style: { display: 'flex', gap: '4px' } },
      h('button', { style: filterBtnStyle(uiState.filter === 'all'), onClick: () => { uiState.filter = 'all'; triggerRender(); } }, `All (${targets.length})`),
      h('button', { style: filterBtnStyle(uiState.filter === 'in-scope'), onClick: () => { uiState.filter = 'in-scope'; triggerRender(); } }, `In Scope (${targets.filter(t => t.inScope).length})`),
      h('button', { style: filterBtnStyle(uiState.filter === 'out-of-scope'), onClick: () => { uiState.filter = 'out-of-scope'; triggerRender(); } }, `Out (${targets.filter(t => !t.inScope).length})`),
    )
  );

  // Target list
  if (filtered.length === 0) {
    children.push(
      h('div', { style: { color: '#484f58', fontStyle: 'italic', padding: '12px 0', textAlign: 'center' } },
        'No targets. Add targets manually or run nmap to auto-capture.'
      )
    );
  } else {
    const listItems = filtered.map(target => renderTargetRow(React, target));
    children.push(
      h('div', { style: { flex: 1, overflow: 'auto' } }, ...listItems)
    );
  }

  return h('div', { style: containerStyle }, ...children);
}

function renderTargetRow(React, target) {
  const h = React.createElement;
  const isExpanded = uiState.expandedTargets.has(target.address);
  const svcCount = target.services.size;

  const scopeColor = target.inScope ? '#3fb950' : '#8b949e';
  const scopeLabel = target.inScope ? 'IN' : 'OUT';

  const typeColors = {
    ipv4: '#58a6ff',
    domain: '#d2a8ff',
    cidr: '#79c0ff',
  };
  const typeColor = typeColors[target.type] || '#8b949e';

  const rowStyle = {
    background: '#161b22',
    border: '1px solid #21262d',
    borderRadius: '4px',
    marginBottom: '3px',
    overflow: 'hidden',
  };

  const headerStyle = {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '4px 8px',
    cursor: 'pointer',
    userSelect: 'none',
    fontSize: '11px',
  };

  const chevron = isExpanded ? '\u25BC' : '\u25B6';

  const headerChildren = [
    // Expand chevron
    h('span', { style: { color: '#484f58', fontSize: '8px', width: '10px' } }, chevron),
    // Scope indicator
    h('span', {
      style: {
        background: scopeColor + '22',
        color: scopeColor,
        padding: '1px 5px',
        borderRadius: '3px',
        fontSize: '8px',
        fontWeight: 700,
        cursor: 'pointer',
        border: `1px solid ${scopeColor}44`,
      },
      title: 'Toggle scope',
      onClick: (e) => {
        e.stopPropagation();
        targetStore.toggleScope(target.address);
        triggerRender();
      },
    }, scopeLabel),
    // Type badge
    h('span', {
      style: {
        color: typeColor,
        fontSize: '8px',
        fontWeight: 600,
        opacity: 0.7,
      },
    }, target.type.toUpperCase()),
    // Address
    h('span', {
      style: { color: '#f0f6fc', fontWeight: 600, fontFamily: 'monospace' },
    }, target.address),
    // Tags
    ...target.tags.map(tag =>
      h('span', {
        key: tag,
        style: {
          background: '#30363d',
          color: '#8b949e',
          padding: '0 4px',
          borderRadius: '2px',
          fontSize: '8px',
        },
      }, tag)
    ),
    // Service count
    svcCount > 0 && h('span', {
      style: {
        background: '#1f6feb22',
        color: '#58a6ff',
        padding: '1px 5px',
        borderRadius: '3px',
        fontSize: '8px',
        marginLeft: 'auto',
      },
    }, `${svcCount} svc`),
    // Remove button
    h('span', {
      style: {
        color: '#f8514966',
        cursor: 'pointer',
        fontSize: '11px',
        padding: '0 4px',
        marginLeft: svcCount > 0 ? '4px' : 'auto',
      },
      title: 'Remove target',
      onClick: (e) => {
        e.stopPropagation();
        targetStore.removeTarget(target.address);
        uiState.expandedTargets.delete(target.address);
        triggerRender();
      },
    }, '\u2715'),
  ];

  const children = [
    h('div', {
      style: headerStyle,
      onClick: () => {
        if (isExpanded) {
          uiState.expandedTargets.delete(target.address);
        } else {
          uiState.expandedTargets.add(target.address);
        }
        triggerRender();
      },
    }, ...headerChildren),
  ];

  // Expanded service table
  if (isExpanded) {
    children.push(renderServiceTable(React, target));
  }

  return h('div', { style: rowStyle, key: target.address }, ...children);
}

function renderServiceTable(React, target) {
  const h = React.createElement;
  const services = Array.from(target.services.values()).sort((a, b) => a.port - b.port);

  const tableStyle = {
    padding: '0 8px 6px 28px',
    fontSize: '10px',
  };

  if (services.length === 0) {
    return h('div', { style: { ...tableStyle, color: '#484f58', fontStyle: 'italic' } },
      'No services discovered. Run a scan to auto-capture.'
    );
  }

  const thStyle = {
    textAlign: 'left',
    padding: '2px 8px',
    color: '#8b949e',
    fontWeight: 600,
    borderBottom: '1px solid #21262d',
    fontSize: '9px',
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
  };

  const tdStyle = {
    padding: '3px 8px',
    borderBottom: '1px solid #161b22',
  };

  const stateColors = {
    open: '#3fb950',
    filtered: '#d29922',
    closed: '#f85149',
    'open|filtered': '#d29922',
  };

  const rows = services.map(svc => {
    const stateColor = stateColors[svc.state] || '#8b949e';
    return h('tr', {
      key: `${svc.port}/${svc.proto}`,
      style: { cursor: 'pointer' },
      onContextMenu: (e) => {
        e.preventDefault();
        e.stopPropagation();
        const actions = getQuickActions(target, svc);
        showActionMenu(actions, e.clientX, e.clientY);
      },
      onClick: (e) => {
        const actions = getQuickActions(target, svc);
        showActionMenu(actions, e.clientX, e.clientY);
      },
    },
      h('td', { style: { ...tdStyle, fontFamily: 'monospace', color: '#79c0ff' } }, `${svc.port}/${svc.proto}`),
      h('td', { style: { ...tdStyle, color: stateColor, fontWeight: 600 } }, svc.state),
      h('td', { style: { ...tdStyle, color: '#d2a8ff' } }, svc.service),
      h('td', { style: { ...tdStyle, color: '#8b949e', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } }, svc.version || '-'),
      h('td', { style: { ...tdStyle, color: '#484f58', fontSize: '9px' } }, svc.source),
      h('td', { style: { ...tdStyle } },
        h('span', {
          style: {
            color: '#58a6ff',
            cursor: 'pointer',
            fontSize: '9px',
            padding: '1px 4px',
            borderRadius: '2px',
            border: '1px solid #1f6feb44',
          },
          title: 'Quick actions',
          onClick: (e) => {
            e.stopPropagation();
            const actions = getQuickActions(target, svc);
            const rect = e.target.getBoundingClientRect();
            showActionMenu(actions, rect.right + 4, rect.top);
          },
        }, '\u26A1')
      ),
    );
  });

  return h('div', { style: tableStyle },
    h('table', { style: { width: '100%', borderCollapse: 'collapse' } },
      h('thead', null,
        h('tr', null,
          h('th', { style: thStyle }, 'Port'),
          h('th', { style: thStyle }, 'State'),
          h('th', { style: thStyle }, 'Service'),
          h('th', { style: thStyle }, 'Version'),
          h('th', { style: thStyle }, 'Source'),
          h('th', { style: { ...thStyle, width: '30px' } }, ''),
        )
      ),
      h('tbody', null, ...rows),
    )
  );
}


// ══════════════════════════════════════════════════════════════
//  HUD REGISTRATION + RENDER TRIGGER
// ══════════════════════════════════════════════════════════════

let _hudRegistered = false;
let _forceRenderFn = null;

// Called when the HUD needs to re-render our tab content
function triggerRender() {
  if (_forceRenderFn) {
    _forceRenderFn();
  } else if (_overlayVisible) {
    renderOverlayContent();
  }
}

function registerHudTab() {
  if (_hudRegistered) return;
  const recon = getRecon();

  // The render function that the HUD will call
  const renderFn = (React, forceUpdate) => {
    // Store the forceUpdate callback so we can trigger re-renders
    if (forceUpdate) _forceRenderFn = forceUpdate;
    return renderTargetBook(React);
  };

  const doRegister = (hud) => {
    if (_hudRegistered) return;
    _hudRegistered = true;
    hud.registerTab('target-book', 'Targets', null, renderFn);
    // Update badge with initial count
    const total = targetStore.targets.size;
    if (total > 0) hud.updateBadge('target-book', total);
  };

  if (recon.hud) {
    doRegister(recon.hud);
  } else {
    recon.events.on('hud:ready', doRegister);
    // If no HUD after a delay, use standalone overlay
    setTimeout(() => {
      if (!_hudRegistered) {
        createStandaloneOverlay();
      }
    }, 3000);
  }

  // Share targets data
  recon.targets = targetStore.targets;

  // Listen for external target additions
  recon.events.on('target:add', (addr, opts) => {
    targetStore.addTarget(addr, opts);
    triggerRender();
  });

  // Listen for external service additions
  recon.events.on('service:add', (targetAddr, svcInfo) => {
    targetStore.addService(targetAddr, svcInfo);
    triggerRender();
  });
}


// ══════════════════════════════════════════════════════════════
//  PLUGIN EXPORTS
// ══════════════════════════════════════════════════════════════

// Redux middleware — intercepts PTY data for auto-capture
exports.middleware = (store) => (next) => (action) => {
  switch (action.type) {
    case 'SESSION_SET_ACTIVE':
      activeUid = action.uid;
      break;
    case 'SESSION_ADD':
      if (!activeUid) activeUid = action.uid;
      break;
    case 'SESSION_PTY_DATA':
      // Feed terminal output to the parser for auto-capture
      if (action.uid && action.data) {
        try {
          outputParser.feed(action.uid, action.data);
        } catch (e) {
          // Never let parsing errors break the terminal
          console.error('[target-book] Parse error:', e.message);
        }
      }
      break;
    case 'SESSION_PTY_EXIT':
    case 'SESSION_USER_EXIT':
      if (action.uid === activeUid) activeUid = null;
      outputParser.cleanup(action.uid);
      break;
  }
  return next(action);
};

// decorateHyper — injects initialization into the Hyper component lifecycle
exports.decorateHyper = (Hyper, { React }) => {
  return class TargetBookHyper extends React.Component {
    constructor(props) {
      super(props);
      this._initialized = false;
    }

    componentDidMount() {
      if (!this._initialized) {
        this._initialized = true;
        // Load persisted targets
        targetStore.ensureDir();
        targetStore.load();
        // Register with HUD framework
        registerHudTab();
      }
    }

    componentWillUnmount() {
      // Ensure data is saved on teardown
      targetStore.saveNow();
    }

    render() {
      return React.createElement(Hyper, this.props);
    }
  };
};

// decorateTerm — adds right-click context menu integration for service entries
exports.decorateTerm = (Term, { React }) => {
  return class TargetBookTerm extends React.Component {
    constructor(props) {
      super(props);
      this._onDecorated = this._onDecorated.bind(this);
      this._xterm = null;
    }

    _onDecorated(term) {
      if (this.props.onDecorated) this.props.onDecorated(term);
      if (!term || !term.term) return;
      this._xterm = term.term;

      // Add right-click handler on the terminal element
      const el = this._xterm.element;
      if (el) {
        el.addEventListener('contextmenu', this._onContextMenu.bind(this), true);
      }
    }

    _onContextMenu(e) {
      // Get selected text from terminal
      const selection = this._xterm.getSelection ? this._xterm.getSelection() : '';
      if (!selection) return;

      const trimmed = selection.trim();
      if (!trimmed) return;

      // Check if selection matches a known target
      const target = targetStore.targets.get(trimmed);
      if (target) {
        e.preventDefault();
        e.stopPropagation();

        const items = [];
        items.push({ label: `Target: ${trimmed}`, separator: false });
        items.push({ separator: true });

        if (target.services.size > 0) {
          for (const svc of target.services.values()) {
            items.push({
              label: `${svc.port}/${svc.proto} ${svc.service} \u2192 Actions`,
              fn: () => {
                const actions = getQuickActions(target, svc);
                setTimeout(() => showActionMenu(actions, e.clientX + 10, e.clientY), 50);
              },
            });
          }
          items.push({ separator: true });
        }

        items.push({
          label: target.inScope ? 'Mark Out-of-Scope' : 'Mark In-Scope',
          fn: () => { targetStore.toggleScope(trimmed); triggerRender(); },
        });
        items.push({
          label: 'Remove from Targets',
          fn: () => { targetStore.removeTarget(trimmed); triggerRender(); },
        });
        items.push({ separator: true });
        items.push({
          label: 'Nmap Quick Scan',
          cmd: `nmap -sV -sC ${esc(trimmed)}`,
        });
        items.push({
          label: 'Nmap All Ports',
          cmd: `nmap -p- --min-rate 1000 ${esc(trimmed)}`,
        });

        showActionMenu(items, e.clientX, e.clientY);
        return;
      }

      // Check if selection looks like a target we could add
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?$/.test(trimmed) ||
          /^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(trimmed)) {
        // Don't prevent default — let other plugins handle it too
        // But add our "Add to targets" items to existing recon menu if possible
        const recon = getRecon();
        if (!targetStore.targets.has(trimmed)) {
          // Only intercept if not already handled by another plugin
          // We add to the native context menu via decorateMenu instead
        }
      }
    }

    render() {
      return React.createElement(Term, Object.assign({}, this.props, {
        onDecorated: this._onDecorated,
      }));
    }
  };
};

// decorateMenu — adds "Add to Target Book" to the right-click menu
exports.decorateMenu = (menu) => {
  return menu.map(item => {
    // We extend the menu when it's shown
    return item;
  });
};

// getTermProps — pass down any needed props
exports.getTermProps = (uid, parentProps, props) => {
  return Object.assign({}, props, { uid });
};

// mapTermsState — expose targets in redux state for other plugins
exports.mapTermsState = (state, map) => {
  return Object.assign({}, map, {
    targetBook: {
      targets: targetStore.getTargets(),
      totalServices: targetStore.totalServices(),
    },
  });
};

// ─── Reduce for state management ─────────────────────────────
exports.reduceUI = (state, action) => {
  switch (action.type) {
    case 'TARGET_BOOK_REFRESH':
      return state.set('targetBookRevision', Date.now());
    default:
      return state;
  }
};

// Make targetStore available for other plugins
exports.targetStore = targetStore;
