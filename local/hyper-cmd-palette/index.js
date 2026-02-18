'use strict';

// ══════════════════════════════════════════════════════════════
//  HYPER CMD PALETTE
//  Hotkey-triggered command palette for building security tool
//  commands interactively. Press Ctrl+Shift+P to open.
// ══════════════════════════════════════════════════════════════

const { clipboard } = require('electron');

// ─── Session Tracking ────────────────────────────────────────
let activeUid = null;

// ─── Shell Safety ────────────────────────────────────────────
function esc(str) {
  if (!str) return "''";
  return "'" + str.replace(/'/g, "'\\''") + "'";
}

function execCmd(cmd) {
  if (!activeUid) return;
  window.rpc.emit('data', { uid: activeUid, data: cmd + '\n', escaped: false });
}


// ══════════════════════════════════════════════════════════════
//  TOOL TEMPLATES
//  Each tool has: name, description, icon (emoji), category,
//  and a fields array defining the interactive form.
//
//  Field types:
//    text     — free text input
//    select   — dropdown with options [{value, label}]
//    check    — boolean toggle
//    multi    — multi-select checkboxes
//    group    — visual grouping label (no value)
// ══════════════════════════════════════════════════════════════

const TOOLS = [
  // ──────────────────────────────────────────────────────────
  //  1. NMAP
  // ──────────────────────────────────────────────────────────
  {
    name: 'nmap',
    description: 'Network scanner — port scanning, service detection, OS fingerprinting',
    icon: 'N',
    category: 'Scanning',
    fields: [
      { id: 'target', label: 'Target (IP/host/CIDR)', type: 'text', placeholder: '10.10.10.1 or example.com', required: true },
      { id: 'scan_type', label: 'Scan Type', type: 'select', default: 'quick', options: [
        { value: 'quick', label: 'Quick — -sV -sC (top 1000)' },
        { value: 'allports', label: 'All Ports — -p-' },
        { value: 'udp', label: 'UDP — -sU --top-ports 50' },
        { value: 'ping', label: 'Ping Sweep — -sn' },
        { value: 'stealth', label: 'Stealth SYN — -sS' },
        { value: 'vuln', label: 'Vuln Scripts — --script vuln' },
        { value: 'custom', label: 'Custom (manual flags)' },
      ]},
      { id: 'timing', label: 'Timing', type: 'select', default: '-T4', options: [
        { value: '', label: 'Default' },
        { value: '-T0', label: '-T0 Paranoid' },
        { value: '-T1', label: '-T1 Sneaky' },
        { value: '-T2', label: '-T2 Polite' },
        { value: '-T3', label: '-T3 Normal' },
        { value: '-T4', label: '-T4 Aggressive' },
        { value: '-T5', label: '-T5 Insane' },
      ]},
      { id: 'ports', label: 'Ports (override)', type: 'text', placeholder: 'e.g. 80,443,8080 or 1-1024', default: '' },
      { id: 'scripts', label: 'NSE Scripts', type: 'text', placeholder: 'e.g. http-enum,smb-vuln*', default: '' },
      { id: 'output', label: 'Output Format', type: 'select', default: '', options: [
        { value: '', label: 'Terminal only' },
        { value: '-oN', label: '-oN Normal' },
        { value: '-oX', label: '-oX XML' },
        { value: '-oG', label: '-oG Grepable' },
        { value: '-oA', label: '-oA All formats' },
      ]},
      { id: 'outfile', label: 'Output Filename', type: 'text', placeholder: 'scan_result', default: '' },
      { id: 'sudo', label: 'Run with sudo', type: 'check', default: false },
      { id: 'extra', label: 'Extra Flags', type: 'text', placeholder: '--min-rate 1000 -Pn', default: '' },
    ],
    build: function(v) {
      const parts = [];
      if (v.sudo) parts.push('sudo');
      parts.push('nmap');
      switch (v.scan_type) {
        case 'quick': parts.push('-sV', '-sC'); break;
        case 'allports': parts.push('-p-', '--min-rate', '1000'); break;
        case 'udp': parts.push('-sU', '--top-ports', '50'); break;
        case 'ping': parts.push('-sn'); break;
        case 'stealth': parts.push('-sS'); break;
        case 'vuln': parts.push('--script', 'vuln'); break;
      }
      if (v.timing) parts.push(v.timing);
      if (v.ports) parts.push('-p', esc(v.ports));
      if (v.scripts) parts.push('--script', esc(v.scripts));
      if (v.output && v.outfile) parts.push(v.output, esc(v.outfile));
      else if (v.output && !v.outfile) parts.push(v.output, 'nmap_out');
      if (v.extra) parts.push(v.extra);
      parts.push(esc(v.target));
      return parts.join(' ');
    },
  },

  // ──────────────────────────────────────────────────────────
  //  2. SQLMAP
  // ──────────────────────────────────────────────────────────
  {
    name: 'sqlmap',
    description: 'Automatic SQL injection and database takeover tool',
    icon: 'S',
    category: 'Exploitation',
    fields: [
      { id: 'url', label: 'Target URL', type: 'text', placeholder: 'http://target.com/page?id=1', required: true },
      { id: 'data', label: 'POST Data', type: 'text', placeholder: 'user=admin&pass=test', default: '' },
      { id: 'cookie', label: 'Cookie', type: 'text', placeholder: 'PHPSESSID=abc123', default: '' },
      { id: 'level', label: 'Level (1-5)', type: 'select', default: '1', options: [
        { value: '1', label: '1 — Default' },
        { value: '2', label: '2 — Cookie tests' },
        { value: '3', label: '3 — User-Agent/Referer' },
        { value: '4', label: '4' },
        { value: '5', label: '5 — Comprehensive' },
      ]},
      { id: 'risk', label: 'Risk (1-3)', type: 'select', default: '1', options: [
        { value: '1', label: '1 — Default (safe)' },
        { value: '2', label: '2 — Heavy queries' },
        { value: '3', label: '3 — OR-based (risky)' },
      ]},
      { id: 'technique', label: 'Technique', type: 'text', placeholder: 'BEUSTQ (all)', default: '' },
      { id: 'tamper', label: 'Tamper Scripts', type: 'text', placeholder: 'space2comment,between', default: '' },
      { id: 'action', label: 'Enumeration', type: 'select', default: '--dbs', options: [
        { value: '', label: 'Detection only' },
        { value: '--dbs', label: '--dbs (list databases)' },
        { value: '--tables', label: '--tables (list tables)' },
        { value: '--dump', label: '--dump (dump data)' },
        { value: '--dump-all', label: '--dump-all (dump everything)' },
        { value: '--os-shell', label: '--os-shell (OS shell)' },
      ]},
      { id: 'dbms', label: 'Force DBMS', type: 'select', default: '', options: [
        { value: '', label: 'Auto-detect' },
        { value: 'mysql', label: 'MySQL' },
        { value: 'postgresql', label: 'PostgreSQL' },
        { value: 'mssql', label: 'MSSQL' },
        { value: 'oracle', label: 'Oracle' },
        { value: 'sqlite', label: 'SQLite' },
      ]},
      { id: 'batch', label: 'Non-interactive (--batch)', type: 'check', default: true },
      { id: 'extra', label: 'Extra Flags', type: 'text', placeholder: '--threads 5 --random-agent', default: '' },
    ],
    build: function(v) {
      const parts = ['sqlmap', '-u', esc(v.url)];
      if (v.data) parts.push('--data', esc(v.data));
      if (v.cookie) parts.push('--cookie', esc(v.cookie));
      if (v.level !== '1') parts.push('--level', esc(v.level));
      if (v.risk !== '1') parts.push('--risk', esc(v.risk));
      if (v.technique) parts.push('--technique', esc(v.technique));
      if (v.tamper) parts.push('--tamper', esc(v.tamper));
      if (v.action) parts.push(v.action);
      if (v.dbms) parts.push('--dbms', esc(v.dbms));
      if (v.batch) parts.push('--batch');
      if (v.extra) parts.push(v.extra);
      return parts.join(' ');
    },
  },

  // ──────────────────────────────────────────────────────────
  //  3. NIKTO
  // ──────────────────────────────────────────────────────────
  {
    name: 'nikto',
    description: 'Web server scanner — misconfigurations, vulnerabilities, outdated software',
    icon: 'K',
    category: 'Scanning',
    fields: [
      { id: 'host', label: 'Host', type: 'text', placeholder: 'http://target.com or 10.10.10.1', required: true },
      { id: 'port', label: 'Port', type: 'text', placeholder: '80 (default)', default: '' },
      { id: 'ssl', label: 'Force SSL (-ssl)', type: 'check', default: false },
      { id: 'tuning', label: 'Tuning', type: 'text', placeholder: '0-9,a-e (e.g. 1236a)', default: '' },
      { id: 'evasion', label: 'Evasion', type: 'select', default: '', options: [
        { value: '', label: 'None' },
        { value: '1', label: '1 — Random URI encoding' },
        { value: '2', label: '2 — Directory self-reference /./' },
        { value: '3', label: '3 — Premature URL ending' },
        { value: '4', label: '4 — Long random string' },
        { value: '7', label: '7 — Random case' },
        { value: '8', label: '8 — Use backslashes' },
      ]},
      { id: 'auth', label: 'Auth (user:pass)', type: 'text', placeholder: 'admin:password', default: '' },
      { id: 'output', label: 'Output Format', type: 'select', default: '', options: [
        { value: '', label: 'Terminal only' },
        { value: '-Format htm', label: 'HTML' },
        { value: '-Format csv', label: 'CSV' },
        { value: '-Format txt', label: 'Text' },
        { value: '-Format xml', label: 'XML' },
      ]},
      { id: 'outfile', label: 'Output Filename', type: 'text', placeholder: 'nikto_report', default: '' },
      { id: 'extra', label: 'Extra Flags', type: 'text', placeholder: '-timeout 10 -Pause 2', default: '' },
    ],
    build: function(v) {
      const parts = ['nikto', '-h', esc(v.host)];
      if (v.port) parts.push('-p', esc(v.port));
      if (v.ssl) parts.push('-ssl');
      if (v.tuning) parts.push('-Tuning', esc(v.tuning));
      if (v.evasion) parts.push('-evasion', esc(v.evasion));
      if (v.auth) parts.push('-id', esc(v.auth));
      if (v.output) parts.push(v.output);
      if (v.outfile) parts.push('-o', esc(v.outfile));
      if (v.extra) parts.push(v.extra);
      return parts.join(' ');
    },
  },

  // ──────────────────────────────────────────────────────────
  //  4. FFUF
  // ──────────────────────────────────────────────────────────
  {
    name: 'ffuf',
    description: 'Fast web fuzzer — directory/file/parameter discovery',
    icon: 'F',
    category: 'Fuzzing',
    fields: [
      { id: 'url', label: 'URL (use FUZZ keyword)', type: 'text', placeholder: 'http://target.com/FUZZ', required: true },
      { id: 'wordlist', label: 'Wordlist', type: 'select', default: '/usr/share/wordlists/dirb/common.txt', options: [
        { value: '/usr/share/wordlists/dirb/common.txt', label: 'dirb/common.txt' },
        { value: '/usr/share/wordlists/dirb/big.txt', label: 'dirb/big.txt' },
        { value: '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt', label: 'dirbuster medium' },
        { value: '/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt', label: 'dirbuster small' },
        { value: '/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt', label: 'raft-medium-words' },
        { value: '/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt', label: 'raft-large-words' },
        { value: 'custom', label: 'Custom path...' },
      ]},
      { id: 'wordlist_custom', label: 'Custom Wordlist Path', type: 'text', placeholder: '/path/to/wordlist.txt', default: '' },
      { id: 'extensions', label: 'Extensions', type: 'text', placeholder: '.php,.html,.txt,.bak', default: '' },
      { id: 'mc', label: 'Match Status Codes', type: 'text', placeholder: '200,301,302,403 (default: all)', default: '' },
      { id: 'fc', label: 'Filter Status Codes', type: 'text', placeholder: '404,500', default: '' },
      { id: 'fs', label: 'Filter Size', type: 'text', placeholder: 'e.g. 4242', default: '' },
      { id: 'fw', label: 'Filter Words', type: 'text', placeholder: 'e.g. 12', default: '' },
      { id: 'fl', label: 'Filter Lines', type: 'text', placeholder: 'e.g. 5', default: '' },
      { id: 'threads', label: 'Threads', type: 'text', placeholder: '40 (default)', default: '' },
      { id: 'recursion', label: 'Recursion', type: 'check', default: false },
      { id: 'recursion_depth', label: 'Recursion Depth', type: 'text', placeholder: '2', default: '' },
      { id: 'headers', label: 'Headers (-H)', type: 'text', placeholder: 'Cookie: session=abc', default: '' },
      { id: 'extra', label: 'Extra Flags', type: 'text', placeholder: '-ac -timeout 10', default: '' },
    ],
    build: function(v) {
      const parts = ['ffuf'];
      const wl = v.wordlist === 'custom' ? v.wordlist_custom : v.wordlist;
      parts.push('-w', esc(wl));
      parts.push('-u', esc(v.url));
      if (v.extensions) parts.push('-e', esc(v.extensions));
      if (v.mc) parts.push('-mc', esc(v.mc));
      if (v.fc) parts.push('-fc', esc(v.fc));
      if (v.fs) parts.push('-fs', esc(v.fs));
      if (v.fw) parts.push('-fw', esc(v.fw));
      if (v.fl) parts.push('-fl', esc(v.fl));
      if (v.threads) parts.push('-t', esc(v.threads));
      if (v.recursion) {
        parts.push('-recursion');
        if (v.recursion_depth) parts.push('-recursion-depth', esc(v.recursion_depth));
      }
      if (v.headers) parts.push('-H', esc(v.headers));
      if (v.extra) parts.push(v.extra);
      return parts.join(' ');
    },
  },

  // ──────────────────────────────────────────────────────────
  //  5. GOBUSTER
  // ──────────────────────────────────────────────────────────
  {
    name: 'gobuster',
    description: 'Directory/DNS/vhost brute-forcing tool',
    icon: 'G',
    category: 'Fuzzing',
    fields: [
      { id: 'mode', label: 'Mode', type: 'select', default: 'dir', options: [
        { value: 'dir', label: 'dir — Directory/file brute-force' },
        { value: 'dns', label: 'dns — Subdomain brute-force' },
        { value: 'vhost', label: 'vhost — Virtual host brute-force' },
      ]},
      { id: 'url', label: 'URL / Domain', type: 'text', placeholder: 'http://target.com or target.com', required: true },
      { id: 'wordlist', label: 'Wordlist', type: 'select', default: '/usr/share/wordlists/dirb/common.txt', options: [
        { value: '/usr/share/wordlists/dirb/common.txt', label: 'dirb/common.txt' },
        { value: '/usr/share/wordlists/dirb/big.txt', label: 'dirb/big.txt' },
        { value: '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt', label: 'dirbuster medium' },
        { value: '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt', label: 'subdomains top 5k' },
        { value: '/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt', label: 'subdomains top 20k' },
        { value: 'custom', label: 'Custom path...' },
      ]},
      { id: 'wordlist_custom', label: 'Custom Wordlist Path', type: 'text', placeholder: '/path/to/wordlist.txt', default: '' },
      { id: 'extensions', label: 'Extensions (dir mode)', type: 'text', placeholder: 'php,html,txt', default: '' },
      { id: 'status_codes', label: 'Status Codes', type: 'text', placeholder: '200,204,301,302,307,401,403', default: '' },
      { id: 'threads', label: 'Threads', type: 'text', placeholder: '10 (default)', default: '' },
      { id: 'no_tls', label: 'Skip TLS verification (-k)', type: 'check', default: false },
      { id: 'expanded', label: 'Expanded mode', type: 'check', default: false },
      { id: 'extra', label: 'Extra Flags', type: 'text', placeholder: '--delay 100ms --timeout 10s', default: '' },
    ],
    build: function(v) {
      const parts = ['gobuster', v.mode];
      if (v.mode === 'dns') {
        parts.push('-d', esc(v.url));
      } else {
        parts.push('-u', esc(v.url));
      }
      const wl = v.wordlist === 'custom' ? v.wordlist_custom : v.wordlist;
      parts.push('-w', esc(wl));
      if (v.extensions && v.mode === 'dir') parts.push('-x', esc(v.extensions));
      if (v.status_codes && v.mode !== 'dns') parts.push('-s', esc(v.status_codes));
      if (v.threads) parts.push('-t', esc(v.threads));
      if (v.no_tls) parts.push('-k');
      if (v.expanded && v.mode === 'dir') parts.push('-e');
      if (v.extra) parts.push(v.extra);
      return parts.join(' ');
    },
  },

  // ──────────────────────────────────────────────────────────
  //  6. SUBFINDER
  // ──────────────────────────────────────────────────────────
  {
    name: 'subfinder',
    description: 'Passive subdomain discovery tool',
    icon: 'D',
    category: 'Recon',
    fields: [
      { id: 'domain', label: 'Domain', type: 'text', placeholder: 'example.com', required: true },
      { id: 'sources', label: 'Sources', type: 'text', placeholder: 'crtsh,virustotal,shodan (comma-separated)', default: '' },
      { id: 'exclude_sources', label: 'Exclude Sources', type: 'text', placeholder: 'archiveis,dnsdumpster', default: '' },
      { id: 'recursive', label: 'Recursive', type: 'check', default: false },
      { id: 'silent', label: 'Silent (clean output)', type: 'check', default: true },
      { id: 'output', label: 'Output File', type: 'text', placeholder: 'subdomains.txt', default: '' },
      { id: 'extra', label: 'Extra Flags', type: 'text', placeholder: '-t 10 -timeout 30', default: '' },
    ],
    build: function(v) {
      const parts = ['subfinder', '-d', esc(v.domain)];
      if (v.sources) parts.push('-sources', esc(v.sources));
      if (v.exclude_sources) parts.push('-es', esc(v.exclude_sources));
      if (v.recursive) parts.push('-recursive');
      if (v.silent) parts.push('-silent');
      if (v.output) parts.push('-o', esc(v.output));
      if (v.extra) parts.push(v.extra);
      return parts.join(' ');
    },
  },

  // ──────────────────────────────────────────────────────────
  //  7. HTTPX
  // ──────────────────────────────────────────────────────────
  {
    name: 'httpx',
    description: 'HTTP probing toolkit — alive checking, tech detection, screenshots',
    icon: 'H',
    category: 'Recon',
    fields: [
      { id: 'input_mode', label: 'Input Method', type: 'select', default: 'stdin', options: [
        { value: 'stdin', label: 'Pipe from stdin (e.g. cat domains.txt |)' },
        { value: 'list', label: 'File list (-l)' },
        { value: 'single', label: 'Single target (-u)' },
      ]},
      { id: 'input', label: 'Input (file path or URL)', type: 'text', placeholder: 'domains.txt or https://target.com', default: '' },
      { id: 'pipe_cmd', label: 'Pipe Command', type: 'text', placeholder: 'cat subdomains.txt', default: '' },
      { id: 'status_code', label: 'Show status code', type: 'check', default: true },
      { id: 'title', label: 'Show title', type: 'check', default: true },
      { id: 'tech_detect', label: 'Tech detection', type: 'check', default: false },
      { id: 'follow_redirects', label: 'Follow redirects', type: 'check', default: true },
      { id: 'content_length', label: 'Show content length', type: 'check', default: false },
      { id: 'web_server', label: 'Show web server', type: 'check', default: false },
      { id: 'method', label: 'HTTP method', type: 'text', placeholder: 'GET (default)', default: '' },
      { id: 'mc', label: 'Match status codes', type: 'text', placeholder: '200,301,302', default: '' },
      { id: 'fc', label: 'Filter status codes', type: 'text', placeholder: '404,500', default: '' },
      { id: 'threads', label: 'Threads', type: 'text', placeholder: '50 (default)', default: '' },
      { id: 'output', label: 'Output File', type: 'text', placeholder: 'alive.txt', default: '' },
      { id: 'silent', label: 'Silent mode', type: 'check', default: false },
      { id: 'extra', label: 'Extra Flags', type: 'text', placeholder: '-timeout 10 -retries 2', default: '' },
    ],
    build: function(v) {
      const parts = [];
      if (v.input_mode === 'stdin' && v.pipe_cmd) {
        parts.push(v.pipe_cmd, '|');
      }
      parts.push('httpx');
      if (v.input_mode === 'list' && v.input) parts.push('-l', esc(v.input));
      if (v.input_mode === 'single' && v.input) parts.push('-u', esc(v.input));
      if (v.status_code) parts.push('-status-code');
      if (v.title) parts.push('-title');
      if (v.tech_detect) parts.push('-tech-detect');
      if (v.follow_redirects) parts.push('-follow-redirects');
      if (v.content_length) parts.push('-content-length');
      if (v.web_server) parts.push('-web-server');
      if (v.method) parts.push('-method', esc(v.method));
      if (v.mc) parts.push('-mc', esc(v.mc));
      if (v.fc) parts.push('-fc', esc(v.fc));
      if (v.threads) parts.push('-threads', esc(v.threads));
      if (v.output) parts.push('-o', esc(v.output));
      if (v.silent) parts.push('-silent');
      if (v.extra) parts.push(v.extra);
      return parts.join(' ');
    },
  },

  // ──────────────────────────────────────────────────────────
  //  8. HYDRA
  // ──────────────────────────────────────────────────────────
  {
    name: 'hydra',
    description: 'Online password brute-forcing for SSH, FTP, HTTP, and more',
    icon: 'Y',
    category: 'Exploitation',
    fields: [
      { id: 'target', label: 'Target', type: 'text', placeholder: '10.10.10.1', required: true },
      { id: 'service', label: 'Service', type: 'select', default: 'ssh', options: [
        { value: 'ssh', label: 'SSH' },
        { value: 'ftp', label: 'FTP' },
        { value: 'http-post-form', label: 'HTTP POST Form' },
        { value: 'http-get-form', label: 'HTTP GET Form' },
        { value: 'http-get', label: 'HTTP Basic Auth' },
        { value: 'smb', label: 'SMB' },
        { value: 'rdp', label: 'RDP' },
        { value: 'mysql', label: 'MySQL' },
        { value: 'telnet', label: 'Telnet' },
        { value: 'vnc', label: 'VNC' },
        { value: 'pop3', label: 'POP3' },
        { value: 'imap', label: 'IMAP' },
        { value: 'smtp', label: 'SMTP' },
      ]},
      { id: 'port', label: 'Port (override)', type: 'text', placeholder: 'auto-detected', default: '' },
      { id: 'user_mode', label: 'Username Mode', type: 'select', default: 'single', options: [
        { value: 'single', label: 'Single username (-l)' },
        { value: 'list', label: 'Username list (-L)' },
      ]},
      { id: 'username', label: 'Username / User List', type: 'text', placeholder: 'admin or /path/to/users.txt', required: true },
      { id: 'pass_mode', label: 'Password Mode', type: 'select', default: 'list', options: [
        { value: 'single', label: 'Single password (-p)' },
        { value: 'list', label: 'Password list (-P)' },
      ]},
      { id: 'password', label: 'Password / Pass List', type: 'text', placeholder: '/usr/share/wordlists/rockyou.txt', required: true, default: '/usr/share/wordlists/rockyou.txt' },
      { id: 'http_path', label: 'HTTP Form Path (http-*-form)', type: 'text', placeholder: '/login:user=^USER^&pass=^PASS^:F=incorrect', default: '' },
      { id: 'threads', label: 'Threads', type: 'text', placeholder: '16 (default)', default: '' },
      { id: 'verbose', label: 'Verbose (-V)', type: 'check', default: false },
      { id: 'extra', label: 'Extra Flags', type: 'text', placeholder: '-e nsr -o results.txt', default: '' },
    ],
    build: function(v) {
      const parts = ['hydra'];
      if (v.user_mode === 'single') parts.push('-l', esc(v.username));
      else parts.push('-L', esc(v.username));
      if (v.pass_mode === 'single') parts.push('-p', esc(v.password));
      else parts.push('-P', esc(v.password));
      if (v.port) parts.push('-s', esc(v.port));
      if (v.threads) parts.push('-t', esc(v.threads));
      if (v.verbose) parts.push('-V');
      if (v.extra) parts.push(v.extra);
      parts.push(esc(v.target));
      if (v.service.startsWith('http-') && v.http_path) {
        parts.push(v.service, esc(v.http_path));
      } else {
        parts.push(v.service);
      }
      return parts.join(' ');
    },
  },

  // ──────────────────────────────────────────────────────────
  //  9. WHATWEB
  // ──────────────────────────────────────────────────────────
  {
    name: 'whatweb',
    description: 'Web technology fingerprinting — CMS, frameworks, plugins',
    icon: 'W',
    category: 'Recon',
    fields: [
      { id: 'target', label: 'Target URL', type: 'text', placeholder: 'http://target.com', required: true },
      { id: 'aggression', label: 'Aggression Level', type: 'select', default: '1', options: [
        { value: '1', label: '1 — Stealthy (one request)' },
        { value: '3', label: '3 — Aggressive (more requests)' },
        { value: '4', label: '4 — Heavy (lots of requests)' },
      ]},
      { id: 'verbose', label: 'Verbose', type: 'check', default: true },
      { id: 'color', label: 'Color output', type: 'check', default: true },
      { id: 'extra', label: 'Extra Flags', type: 'text', placeholder: '--user-agent "Mozilla/5.0"', default: '' },
    ],
    build: function(v) {
      const parts = ['whatweb'];
      if (v.aggression !== '1') parts.push('-a', v.aggression);
      if (v.verbose) parts.push('-v');
      if (!v.color) parts.push('--color=never');
      if (v.extra) parts.push(v.extra);
      parts.push(esc(v.target));
      return parts.join(' ');
    },
  },

  // ──────────────────────────────────────────────────────────
  //  10. WFUZZ
  // ──────────────────────────────────────────────────────────
  {
    name: 'wfuzz',
    description: 'Web fuzzer — brute-force parameters, directories, headers',
    icon: 'Z',
    category: 'Fuzzing',
    fields: [
      { id: 'url', label: 'URL (use FUZZ keyword)', type: 'text', placeholder: 'http://target.com/FUZZ', required: true },
      { id: 'wordlist', label: 'Wordlist', type: 'text', placeholder: '/usr/share/wordlists/dirb/common.txt', default: '/usr/share/wordlists/dirb/common.txt' },
      { id: 'hc', label: 'Hide Status Codes', type: 'text', placeholder: '404,500', default: '404' },
      { id: 'hw', label: 'Hide Word Count', type: 'text', placeholder: 'e.g. 12', default: '' },
      { id: 'hl', label: 'Hide Line Count', type: 'text', placeholder: 'e.g. 5', default: '' },
      { id: 'hh', label: 'Hide Chars', type: 'text', placeholder: 'e.g. 4242', default: '' },
      { id: 'sc', label: 'Show Status Codes', type: 'text', placeholder: '200,301', default: '' },
      { id: 'threads', label: 'Threads', type: 'text', placeholder: '10 (default)', default: '' },
      { id: 'cookie', label: 'Cookie (-b)', type: 'text', placeholder: 'PHPSESSID=abc123', default: '' },
      { id: 'header', label: 'Header (-H)', type: 'text', placeholder: 'Authorization: Bearer tok', default: '' },
      { id: 'postdata', label: 'POST Data (-d)', type: 'text', placeholder: 'user=FUZZ&pass=test', default: '' },
      { id: 'extra', label: 'Extra Flags', type: 'text', placeholder: '--follow -L', default: '' },
    ],
    build: function(v) {
      const parts = ['wfuzz'];
      if (v.hc) parts.push('--hc', esc(v.hc));
      if (v.hw) parts.push('--hw', esc(v.hw));
      if (v.hl) parts.push('--hl', esc(v.hl));
      if (v.hh) parts.push('--hh', esc(v.hh));
      if (v.sc) parts.push('--sc', esc(v.sc));
      if (v.threads) parts.push('-t', esc(v.threads));
      if (v.cookie) parts.push('-b', esc(v.cookie));
      if (v.header) parts.push('-H', esc(v.header));
      if (v.postdata) parts.push('-d', esc(v.postdata));
      if (v.extra) parts.push(v.extra);
      parts.push('-w', esc(v.wordlist));
      parts.push(esc(v.url));
      return parts.join(' ');
    },
  },

  // ──────────────────────────────────────────────────────────
  //  11. DIRB
  // ──────────────────────────────────────────────────────────
  {
    name: 'dirb',
    description: 'URL brute-forcing tool for web content discovery',
    icon: 'B',
    category: 'Fuzzing',
    fields: [
      { id: 'url', label: 'Target URL', type: 'text', placeholder: 'http://target.com/', required: true },
      { id: 'wordlist', label: 'Wordlist', type: 'text', placeholder: '/usr/share/dirb/wordlists/common.txt', default: '/usr/share/dirb/wordlists/common.txt' },
      { id: 'extensions', label: 'Extensions (-X)', type: 'text', placeholder: '.php,.html,.txt', default: '' },
      { id: 'cookie', label: 'Cookie (-c)', type: 'text', placeholder: 'PHPSESSID=abc123', default: '' },
      { id: 'auth', label: 'Auth (-u user:pass)', type: 'text', placeholder: 'admin:password', default: '' },
      { id: 'agent', label: 'User-Agent (-a)', type: 'text', placeholder: 'Custom UA string', default: '' },
      { id: 'non_recursive', label: 'Non-recursive (-r)', type: 'check', default: false },
      { id: 'show_not_found', label: 'Show NOT_FOUND (-v)', type: 'check', default: false },
      { id: 'ignore_case', label: 'Case-insensitive (-z)', type: 'check', default: false },
      { id: 'output', label: 'Output File (-o)', type: 'text', placeholder: 'dirb_results.txt', default: '' },
      { id: 'extra', label: 'Extra Flags', type: 'text', placeholder: '-S -N 403', default: '' },
    ],
    build: function(v) {
      const parts = ['dirb', esc(v.url), esc(v.wordlist)];
      if (v.extensions) parts.push('-X', esc(v.extensions));
      if (v.cookie) parts.push('-c', esc(v.cookie));
      if (v.auth) parts.push('-u', esc(v.auth));
      if (v.agent) parts.push('-a', esc(v.agent));
      if (v.non_recursive) parts.push('-r');
      if (v.show_not_found) parts.push('-v');
      if (v.ignore_case) parts.push('-z');
      if (v.output) parts.push('-o', esc(v.output));
      if (v.extra) parts.push(v.extra);
      return parts.join(' ');
    },
  },

  // ──────────────────────────────────────────────────────────
  //  12. CURL
  // ──────────────────────────────────────────────────────────
  {
    name: 'curl',
    description: 'HTTP client — flexible requests, headers, auth, data',
    icon: 'C',
    category: 'Utility',
    fields: [
      { id: 'url', label: 'URL', type: 'text', placeholder: 'http://target.com/api/endpoint', required: true },
      { id: 'method', label: 'Method', type: 'select', default: 'GET', options: [
        { value: 'GET', label: 'GET' },
        { value: 'POST', label: 'POST' },
        { value: 'PUT', label: 'PUT' },
        { value: 'DELETE', label: 'DELETE' },
        { value: 'PATCH', label: 'PATCH' },
        { value: 'HEAD', label: 'HEAD' },
        { value: 'OPTIONS', label: 'OPTIONS' },
      ]},
      { id: 'data', label: 'Data (-d)', type: 'text', placeholder: '{"key":"value"} or key=value', default: '' },
      { id: 'content_type', label: 'Content-Type', type: 'select', default: '', options: [
        { value: '', label: 'None / auto' },
        { value: 'application/json', label: 'application/json' },
        { value: 'application/x-www-form-urlencoded', label: 'application/x-www-form-urlencoded' },
        { value: 'multipart/form-data', label: 'multipart/form-data' },
        { value: 'text/xml', label: 'text/xml' },
      ]},
      { id: 'headers', label: 'Headers (-H)', type: 'text', placeholder: 'Authorization: Bearer token123', default: '' },
      { id: 'cookie', label: 'Cookie (-b)', type: 'text', placeholder: 'session=abc123', default: '' },
      { id: 'auth', label: 'Auth (-u user:pass)', type: 'text', placeholder: 'admin:password', default: '' },
      { id: 'insecure', label: 'Insecure / skip TLS (-k)', type: 'check', default: false },
      { id: 'verbose', label: 'Verbose (-v)', type: 'check', default: false },
      { id: 'follow', label: 'Follow redirects (-L)', type: 'check', default: false },
      { id: 'silent', label: 'Silent (-s)', type: 'check', default: false },
      { id: 'head_only', label: 'Headers only (-I)', type: 'check', default: false },
      { id: 'proxy', label: 'Proxy (-x)', type: 'text', placeholder: 'http://127.0.0.1:8080', default: '' },
      { id: 'output', label: 'Output File (-o)', type: 'text', placeholder: 'response.html', default: '' },
      { id: 'extra', label: 'Extra Flags', type: 'text', placeholder: '--max-time 30 --retry 3', default: '' },
    ],
    build: function(v) {
      const parts = ['curl'];
      if (v.method !== 'GET') parts.push('-X', v.method);
      if (v.content_type) parts.push('-H', esc('Content-Type: ' + v.content_type));
      if (v.headers) {
        v.headers.split('\n').forEach(function(h) {
          h = h.trim();
          if (h) parts.push('-H', esc(h));
        });
      }
      if (v.data) parts.push('-d', esc(v.data));
      if (v.cookie) parts.push('-b', esc(v.cookie));
      if (v.auth) parts.push('-u', esc(v.auth));
      if (v.insecure) parts.push('-k');
      if (v.verbose) parts.push('-v');
      if (v.follow) parts.push('-L');
      if (v.silent) parts.push('-s');
      if (v.head_only) parts.push('-I');
      if (v.proxy) parts.push('-x', esc(v.proxy));
      if (v.output) parts.push('-o', esc(v.output));
      if (v.extra) parts.push(v.extra);
      parts.push(esc(v.url));
      return parts.join(' ');
    },
  },

  // ──────────────────────────────────────────────────────────
  //  13. DIG
  // ──────────────────────────────────────────────────────────
  {
    name: 'dig',
    description: 'DNS lookup utility — query records, trace resolution, reverse lookups',
    icon: 'Q',
    category: 'Utility',
    fields: [
      { id: 'domain', label: 'Domain / IP', type: 'text', placeholder: 'example.com or 8.8.8.8', required: true },
      { id: 'record', label: 'Record Type', type: 'select', default: 'A', options: [
        { value: 'A', label: 'A — IPv4 address' },
        { value: 'AAAA', label: 'AAAA — IPv6 address' },
        { value: 'MX', label: 'MX — Mail exchange' },
        { value: 'NS', label: 'NS — Name servers' },
        { value: 'TXT', label: 'TXT — Text records' },
        { value: 'CNAME', label: 'CNAME — Canonical name' },
        { value: 'SOA', label: 'SOA — Start of authority' },
        { value: 'SRV', label: 'SRV — Service locator' },
        { value: 'PTR', label: 'PTR — Reverse lookup' },
        { value: 'ANY', label: 'ANY — All records' },
        { value: 'AXFR', label: 'AXFR — Zone transfer' },
      ]},
      { id: 'server', label: 'DNS Server (@)', type: 'text', placeholder: '8.8.8.8 (default: system)', default: '' },
      { id: 'short', label: 'Short output (+short)', type: 'check', default: false },
      { id: 'trace', label: 'Trace resolution (+trace)', type: 'check', default: false },
      { id: 'reverse', label: 'Reverse lookup (-x)', type: 'check', default: false },
      { id: 'extra', label: 'Extra Flags', type: 'text', placeholder: '+noall +answer', default: '' },
    ],
    build: function(v) {
      const parts = ['dig'];
      if (v.server) parts.push(esc('@' + v.server));
      if (v.reverse) {
        parts.push('-x', esc(v.domain));
      } else {
        parts.push(esc(v.domain), esc(v.record));
      }
      if (v.short) parts.push('+short');
      if (v.trace) parts.push('+trace');
      if (v.extra) parts.push(v.extra);
      return parts.join(' ');
    },
  },

  // ──────────────────────────────────────────────────────────
  //  14. WHOIS
  // ──────────────────────────────────────────────────────────
  {
    name: 'whois',
    description: 'Domain/IP registration lookup',
    icon: 'I',
    category: 'Utility',
    fields: [
      { id: 'target', label: 'Domain / IP', type: 'text', placeholder: 'example.com or 93.184.216.34', required: true },
      { id: 'server', label: 'Whois Server (-h)', type: 'text', placeholder: 'auto-detect', default: '' },
      { id: 'extra', label: 'Extra Flags', type: 'text', placeholder: '', default: '' },
    ],
    build: function(v) {
      const parts = ['whois'];
      if (v.server) parts.push('-h', esc(v.server));
      if (v.extra) parts.push(v.extra);
      parts.push(esc(v.target));
      return parts.join(' ');
    },
  },
];


// ══════════════════════════════════════════════════════════════
//  CATEGORIES (for grouping in the palette)
// ══════════════════════════════════════════════════════════════

const CATEGORIES = ['Scanning', 'Recon', 'Fuzzing', 'Exploitation', 'Utility'];


// ══════════════════════════════════════════════════════════════
//  STYLES
// ══════════════════════════════════════════════════════════════

const COLORS = {
  bg: '#0d1117',
  bgOverlay: 'rgba(0, 0, 0, 0.65)',
  panel: '#161b22',
  panelBorder: '#30363d',
  inputBg: '#0d1117',
  inputBorder: '#30363d',
  inputFocus: '#58a6ff',
  text: '#c9d1d9',
  textMuted: '#8b949e',
  textBright: '#f0f6fc',
  accent: '#58a6ff',
  accentHover: '#79c0ff',
  green: '#3fb950',
  red: '#f85149',
  orange: '#d29922',
  categoryScanning: '#58a6ff',
  categoryRecon: '#3fb950',
  categoryFuzzing: '#d29922',
  categoryExploitation: '#f85149',
  categoryUtility: '#8b949e',
  toolHover: '#21262d',
  toolSelected: '#1f6feb22',
  btnPrimary: '#238636',
  btnPrimaryHover: '#2ea043',
  btnSecondary: '#21262d',
  btnSecondaryHover: '#30363d',
  scrollThumb: '#484f58',
  scrollTrack: 'transparent',
};

function categoryColor(cat) {
  switch (cat) {
    case 'Scanning': return COLORS.categoryScanning;
    case 'Recon': return COLORS.categoryRecon;
    case 'Fuzzing': return COLORS.categoryFuzzing;
    case 'Exploitation': return COLORS.categoryExploitation;
    case 'Utility': return COLORS.categoryUtility;
    default: return COLORS.textMuted;
  }
}


// ══════════════════════════════════════════════════════════════
//  PALETTE UI (all DOM manipulation, no JSX)
// ══════════════════════════════════════════════════════════════

let _paletteEl = null;
let _paletteState = {
  view: 'list',      // 'list' | 'form'
  search: '',
  selectedTool: null,
  selectedIndex: 0,
  formValues: {},
  previewCmd: '',
};

function _closePalette() {
  if (_paletteEl) {
    _paletteEl.remove();
    _paletteEl = null;
  }
  _paletteState.view = 'list';
  _paletteState.search = '';
  _paletteState.selectedTool = null;
  _paletteState.selectedIndex = 0;
  _paletteState.formValues = {};
  _paletteState.previewCmd = '';
}

function _openPalette() {
  if (_paletteEl) { _closePalette(); return; }
  _paletteState.view = 'list';
  _paletteState.search = '';
  _paletteState.selectedIndex = 0;
  _renderPalette();
}

function _filteredTools() {
  const q = _paletteState.search.toLowerCase().trim();
  if (!q) return TOOLS;
  return TOOLS.filter(function(t) {
    return t.name.toLowerCase().includes(q)
      || t.description.toLowerCase().includes(q)
      || t.category.toLowerCase().includes(q);
  });
}

function _selectTool(tool) {
  _paletteState.view = 'form';
  _paletteState.selectedTool = tool;
  // Initialize form values from defaults
  const vals = {};
  tool.fields.forEach(function(f) {
    if (f.type === 'check') vals[f.id] = f.default || false;
    else if (f.type === 'group') return;
    else vals[f.id] = f.default || '';
  });
  _paletteState.formValues = vals;
  _paletteState.previewCmd = tool.build(vals);
  _renderPalette();
}

function _updateFormValue(id, value) {
  _paletteState.formValues[id] = value;
  _paletteState.previewCmd = _paletteState.selectedTool.build(_paletteState.formValues);
  // Only update the preview, not the entire palette
  var preview = _paletteEl && _paletteEl.querySelector('[data-preview]');
  if (preview) {
    preview.textContent = _paletteState.previewCmd;
  }
}

function _executeCommand() {
  const cmd = _paletteState.previewCmd;
  if (!cmd) return;
  _closePalette();
  execCmd(cmd);
}

function _copyCommand() {
  const cmd = _paletteState.previewCmd;
  if (!cmd) return;
  clipboard.writeText(cmd);
  // Flash the copy button
  var btn = _paletteEl && _paletteEl.querySelector('[data-copy-btn]');
  if (btn) {
    var orig = btn.textContent;
    btn.textContent = 'Copied!';
    btn.style.borderColor = COLORS.green;
    setTimeout(function() {
      if (btn) { btn.textContent = orig; btn.style.borderColor = COLORS.panelBorder; }
    }, 1200);
  }
}


// ── Palette rendering ─────────────────────────────────────

function _renderPalette() {
  // Remove existing
  if (_paletteEl) _paletteEl.remove();

  // Backdrop overlay
  var overlay = document.createElement('div');
  overlay.style.cssText =
    'position:fixed;top:0;left:0;width:100%;height:100%;z-index:99999;' +
    'background:' + COLORS.bgOverlay + ';display:flex;align-items:flex-start;' +
    'justify-content:center;padding-top:60px;font-family:-apple-system,BlinkMacSystemFont,' +
    '"Segoe UI",Helvetica,Arial,sans-serif;font-size:13px;color:' + COLORS.text + ';';

  overlay.addEventListener('mousedown', function(e) {
    if (e.target === overlay) _closePalette();
  });

  // Main panel
  var panel = document.createElement('div');
  panel.style.cssText =
    'background:' + COLORS.panel + ';border:1px solid ' + COLORS.panelBorder + ';' +
    'border-radius:12px;width:620px;max-height:calc(100vh - 120px);display:flex;' +
    'flex-direction:column;box-shadow:0 8px 40px rgba(0,0,0,0.7),' +
    '0 0 0 1px rgba(255,255,255,0.04);overflow:hidden;';

  if (_paletteState.view === 'list') {
    _renderListView(panel);
  } else {
    _renderFormView(panel);
  }

  overlay.appendChild(panel);
  document.body.appendChild(overlay);
  _paletteEl = overlay;

  // Keyboard handler for the overlay
  overlay.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
      if (_paletteState.view === 'form') {
        _paletteState.view = 'list';
        _paletteState.selectedTool = null;
        _renderPalette();
      } else {
        _closePalette();
      }
      e.preventDefault();
      e.stopPropagation();
    }
  });
}


// ── List view ─────────────────────────────────────────────

function _renderListView(panel) {
  // Header
  var header = document.createElement('div');
  header.style.cssText =
    'padding:16px 16px 0 16px;flex-shrink:0;';

  var title = document.createElement('div');
  title.style.cssText =
    'font-size:11px;font-weight:600;color:' + COLORS.textMuted + ';text-transform:uppercase;' +
    'letter-spacing:0.8px;margin-bottom:10px;';
  title.textContent = 'Command Palette';
  header.appendChild(title);

  // Search input
  var searchWrap = document.createElement('div');
  searchWrap.style.cssText =
    'position:relative;margin-bottom:8px;';

  var searchIcon = document.createElement('span');
  searchIcon.style.cssText =
    'position:absolute;left:10px;top:50%;transform:translateY(-50%);color:' + COLORS.textMuted + ';' +
    'font-size:14px;pointer-events:none;';
  searchIcon.innerHTML = '&#x1F50D;&#xFE0E;';  // magnifying glass text style
  searchWrap.appendChild(searchIcon);

  var searchInput = document.createElement('input');
  searchInput.type = 'text';
  searchInput.placeholder = 'Search tools... (nmap, sqlmap, ffuf, etc.)';
  searchInput.value = _paletteState.search;
  searchInput.style.cssText =
    'width:100%;box-sizing:border-box;padding:10px 12px 10px 34px;' +
    'background:' + COLORS.inputBg + ';border:1px solid ' + COLORS.inputBorder + ';' +
    'border-radius:6px;color:' + COLORS.textBright + ';font-size:14px;outline:none;' +
    'font-family:inherit;';
  searchInput.addEventListener('focus', function() { searchInput.style.borderColor = COLORS.inputFocus; });
  searchInput.addEventListener('blur', function() { searchInput.style.borderColor = COLORS.inputBorder; });
  searchInput.addEventListener('input', function() {
    _paletteState.search = searchInput.value;
    _paletteState.selectedIndex = 0;
    _renderToolList(listContainer);
  });
  searchInput.addEventListener('keydown', function(e) {
    var filtered = _filteredTools();
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      _paletteState.selectedIndex = Math.min(_paletteState.selectedIndex + 1, filtered.length - 1);
      _renderToolList(listContainer);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      _paletteState.selectedIndex = Math.max(_paletteState.selectedIndex - 1, 0);
      _renderToolList(listContainer);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (filtered[_paletteState.selectedIndex]) {
        _selectTool(filtered[_paletteState.selectedIndex]);
      }
    }
  });
  searchWrap.appendChild(searchInput);
  header.appendChild(searchWrap);
  panel.appendChild(header);

  // Tool list container
  var listContainer = document.createElement('div');
  listContainer.style.cssText =
    'flex:1;overflow-y:auto;padding:0 8px 8px 8px;' +
    'scrollbar-width:thin;scrollbar-color:' + COLORS.scrollThumb + ' ' + COLORS.scrollTrack + ';';
  _renderToolList(listContainer);
  panel.appendChild(listContainer);

  // Footer hint
  var footer = document.createElement('div');
  footer.style.cssText =
    'padding:8px 16px;border-top:1px solid ' + COLORS.panelBorder + ';' +
    'font-size:11px;color:' + COLORS.textMuted + ';flex-shrink:0;display:flex;gap:16px;';
  footer.innerHTML =
    '<span><kbd style="background:#21262d;padding:1px 5px;border-radius:3px;border:1px solid #30363d;' +
    'font-size:10px;font-family:monospace;">&#x2191;&#x2193;</kbd> navigate</span>' +
    '<span><kbd style="background:#21262d;padding:1px 5px;border-radius:3px;border:1px solid #30363d;' +
    'font-size:10px;font-family:monospace;">Enter</kbd> select</span>' +
    '<span><kbd style="background:#21262d;padding:1px 5px;border-radius:3px;border:1px solid #30363d;' +
    'font-size:10px;font-family:monospace;">Esc</kbd> close</span>';
  panel.appendChild(footer);

  // Focus the search input
  setTimeout(function() { searchInput.focus(); }, 10);
}

function _renderToolList(container) {
  container.innerHTML = '';
  var tools = _filteredTools();

  if (tools.length === 0) {
    var empty = document.createElement('div');
    empty.style.cssText = 'padding:24px;text-align:center;color:' + COLORS.textMuted + ';';
    empty.textContent = 'No tools match your search.';
    container.appendChild(empty);
    return;
  }

  // Group by category
  var grouped = {};
  CATEGORIES.forEach(function(c) { grouped[c] = []; });
  tools.forEach(function(t) {
    if (!grouped[t.category]) grouped[t.category] = [];
    grouped[t.category].push(t);
  });

  var globalIdx = 0;
  CATEGORIES.forEach(function(cat) {
    var catTools = grouped[cat];
    if (!catTools || catTools.length === 0) return;

    // Category header
    var catHeader = document.createElement('div');
    catHeader.style.cssText =
      'padding:8px 8px 4px 8px;font-size:11px;font-weight:600;color:' + categoryColor(cat) + ';' +
      'text-transform:uppercase;letter-spacing:0.6px;';
    catHeader.textContent = cat;
    container.appendChild(catHeader);

    catTools.forEach(function(tool) {
      var idx = globalIdx++;
      var row = document.createElement('div');
      var isSelected = idx === _paletteState.selectedIndex;
      row.style.cssText =
        'display:flex;align-items:center;padding:8px 10px;cursor:pointer;border-radius:6px;' +
        'margin:1px 0;transition:background 0.1s;' +
        'background:' + (isSelected ? COLORS.toolSelected : 'transparent') + ';' +
        (isSelected ? 'outline:1px solid ' + COLORS.accent + '33;' : '');

      // Icon badge
      var badge = document.createElement('div');
      badge.style.cssText =
        'width:28px;height:28px;border-radius:6px;display:flex;align-items:center;justify-content:center;' +
        'background:' + categoryColor(tool.category) + '18;color:' + categoryColor(tool.category) + ';' +
        'font-weight:700;font-size:13px;font-family:"SF Mono",Monaco,Menlo,Consolas,monospace;' +
        'flex-shrink:0;margin-right:10px;';
      badge.textContent = tool.icon;
      row.appendChild(badge);

      // Name + description
      var info = document.createElement('div');
      info.style.cssText = 'flex:1;min-width:0;';

      var nameEl = document.createElement('div');
      nameEl.style.cssText =
        'font-weight:600;color:' + COLORS.textBright + ';font-size:13px;' +
        'font-family:"SF Mono",Monaco,Menlo,Consolas,monospace;';
      nameEl.textContent = tool.name;
      info.appendChild(nameEl);

      var descEl = document.createElement('div');
      descEl.style.cssText =
        'font-size:11px;color:' + COLORS.textMuted + ';margin-top:1px;white-space:nowrap;' +
        'overflow:hidden;text-overflow:ellipsis;';
      descEl.textContent = tool.description;
      info.appendChild(descEl);

      row.appendChild(info);

      // Category pill
      var pill = document.createElement('span');
      pill.style.cssText =
        'font-size:9px;padding:2px 6px;border-radius:10px;' +
        'background:' + categoryColor(tool.category) + '18;' +
        'color:' + categoryColor(tool.category) + ';font-weight:600;flex-shrink:0;margin-left:8px;';
      pill.textContent = tool.category;
      row.appendChild(pill);

      row.addEventListener('mouseenter', function() {
        if (!isSelected) row.style.background = COLORS.toolHover;
      });
      row.addEventListener('mouseleave', function() {
        row.style.background = isSelected ? COLORS.toolSelected : 'transparent';
      });
      row.addEventListener('click', function() {
        _selectTool(tool);
      });

      if (isSelected) {
        // Scroll into view after render
        setTimeout(function() {
          row.scrollIntoView({ block: 'nearest' });
        }, 0);
      }

      container.appendChild(row);
    });
  });
}


// ── Form view ─────────────────────────────────────────────

function _renderFormView(panel) {
  var tool = _paletteState.selectedTool;
  if (!tool) return;

  // Header with back button
  var header = document.createElement('div');
  header.style.cssText =
    'padding:14px 16px;border-bottom:1px solid ' + COLORS.panelBorder + ';' +
    'display:flex;align-items:center;gap:10px;flex-shrink:0;';

  var backBtn = document.createElement('button');
  backBtn.style.cssText =
    'background:none;border:1px solid ' + COLORS.panelBorder + ';border-radius:6px;' +
    'color:' + COLORS.textMuted + ';cursor:pointer;padding:4px 8px;font-size:12px;' +
    'font-family:inherit;display:flex;align-items:center;gap:4px;transition:all 0.15s;';
  backBtn.innerHTML = '&#x2190; Back';
  backBtn.addEventListener('mouseenter', function() {
    backBtn.style.borderColor = COLORS.accent;
    backBtn.style.color = COLORS.accent;
  });
  backBtn.addEventListener('mouseleave', function() {
    backBtn.style.borderColor = COLORS.panelBorder;
    backBtn.style.color = COLORS.textMuted;
  });
  backBtn.addEventListener('click', function() {
    _paletteState.view = 'list';
    _paletteState.selectedTool = null;
    _renderPalette();
  });
  header.appendChild(backBtn);

  var titleBadge = document.createElement('div');
  titleBadge.style.cssText =
    'width:24px;height:24px;border-radius:5px;display:flex;align-items:center;justify-content:center;' +
    'background:' + categoryColor(tool.category) + '18;color:' + categoryColor(tool.category) + ';' +
    'font-weight:700;font-size:12px;font-family:"SF Mono",Monaco,Menlo,Consolas,monospace;';
  titleBadge.textContent = tool.icon;
  header.appendChild(titleBadge);

  var titleText = document.createElement('div');
  titleText.style.cssText = 'font-weight:600;color:' + COLORS.textBright + ';font-size:14px;flex:1;';
  titleText.textContent = tool.name;
  header.appendChild(titleText);

  var catPill = document.createElement('span');
  catPill.style.cssText =
    'font-size:9px;padding:2px 6px;border-radius:10px;' +
    'background:' + categoryColor(tool.category) + '18;' +
    'color:' + categoryColor(tool.category) + ';font-weight:600;';
  catPill.textContent = tool.category;
  header.appendChild(catPill);

  panel.appendChild(header);

  // Form fields scrollable area
  var formArea = document.createElement('div');
  formArea.style.cssText =
    'flex:1;overflow-y:auto;padding:12px 16px;' +
    'scrollbar-width:thin;scrollbar-color:' + COLORS.scrollThumb + ' ' + COLORS.scrollTrack + ';';

  tool.fields.forEach(function(field) {
    if (field.type === 'group') {
      var groupLabel = document.createElement('div');
      groupLabel.style.cssText =
        'font-size:11px;font-weight:600;color:' + COLORS.accent + ';text-transform:uppercase;' +
        'letter-spacing:0.5px;margin:12px 0 6px 0;padding-top:8px;' +
        'border-top:1px solid ' + COLORS.panelBorder + ';';
      groupLabel.textContent = field.label;
      formArea.appendChild(groupLabel);
      return;
    }

    var row = document.createElement('div');
    row.style.cssText = 'margin-bottom:10px;';

    // Label
    var label = document.createElement('label');
    label.style.cssText =
      'display:block;font-size:11px;color:' + COLORS.textMuted + ';margin-bottom:4px;font-weight:500;';
    label.textContent = field.label;
    if (field.required) {
      var req = document.createElement('span');
      req.style.cssText = 'color:' + COLORS.red + ';margin-left:3px;';
      req.textContent = '*';
      label.appendChild(req);
    }
    row.appendChild(label);

    if (field.type === 'text') {
      var input = document.createElement('input');
      input.type = 'text';
      input.placeholder = field.placeholder || '';
      input.value = _paletteState.formValues[field.id] || '';
      input.style.cssText =
        'width:100%;box-sizing:border-box;padding:7px 10px;' +
        'background:' + COLORS.inputBg + ';border:1px solid ' + COLORS.inputBorder + ';' +
        'border-radius:6px;color:' + COLORS.textBright + ';font-size:12px;outline:none;' +
        'font-family:"SF Mono",Monaco,Menlo,Consolas,monospace;transition:border-color 0.15s;';
      input.addEventListener('focus', function() { input.style.borderColor = COLORS.inputFocus; });
      input.addEventListener('blur', function() { input.style.borderColor = COLORS.inputBorder; });
      input.addEventListener('input', function() {
        _updateFormValue(field.id, input.value);
      });
      // Handle Enter to run
      input.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
          e.preventDefault();
          _executeCommand();
        }
      });
      row.appendChild(input);

    } else if (field.type === 'select') {
      var select = document.createElement('select');
      select.style.cssText =
        'width:100%;box-sizing:border-box;padding:7px 10px;' +
        'background:' + COLORS.inputBg + ';border:1px solid ' + COLORS.inputBorder + ';' +
        'border-radius:6px;color:' + COLORS.textBright + ';font-size:12px;outline:none;' +
        'font-family:"SF Mono",Monaco,Menlo,Consolas,monospace;cursor:pointer;' +
        'appearance:auto;transition:border-color 0.15s;';
      select.addEventListener('focus', function() { select.style.borderColor = COLORS.inputFocus; });
      select.addEventListener('blur', function() { select.style.borderColor = COLORS.inputBorder; });
      field.options.forEach(function(opt) {
        var option = document.createElement('option');
        option.value = opt.value;
        option.textContent = opt.label;
        option.style.cssText = 'background:' + COLORS.bg + ';color:' + COLORS.text + ';';
        if (opt.value === (_paletteState.formValues[field.id] || field.default || '')) {
          option.selected = true;
        }
        select.appendChild(option);
      });
      select.addEventListener('change', function() {
        _updateFormValue(field.id, select.value);
      });
      row.appendChild(select);

    } else if (field.type === 'check') {
      var checkWrap = document.createElement('label');
      checkWrap.style.cssText =
        'display:flex;align-items:center;gap:8px;cursor:pointer;padding:3px 0;';

      var checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.checked = !!_paletteState.formValues[field.id];
      checkbox.style.cssText =
        'width:16px;height:16px;accent-color:' + COLORS.accent + ';cursor:pointer;';
      checkbox.addEventListener('change', function() {
        _updateFormValue(field.id, checkbox.checked);
      });
      checkWrap.appendChild(checkbox);

      var checkLabel = document.createElement('span');
      checkLabel.style.cssText = 'font-size:12px;color:' + COLORS.text + ';';
      checkLabel.textContent = 'Enabled';
      checkWrap.appendChild(checkLabel);

      row.appendChild(checkWrap);
    }

    formArea.appendChild(row);
  });

  panel.appendChild(formArea);

  // Command preview + action buttons
  var previewArea = document.createElement('div');
  previewArea.style.cssText =
    'border-top:1px solid ' + COLORS.panelBorder + ';padding:12px 16px;flex-shrink:0;';

  var previewLabel = document.createElement('div');
  previewLabel.style.cssText =
    'font-size:10px;font-weight:600;color:' + COLORS.textMuted + ';text-transform:uppercase;' +
    'letter-spacing:0.6px;margin-bottom:6px;';
  previewLabel.textContent = 'Command Preview';
  previewArea.appendChild(previewLabel);

  var previewBox = document.createElement('div');
  previewBox.style.cssText =
    'background:' + COLORS.bg + ';border:1px solid ' + COLORS.panelBorder + ';' +
    'border-radius:6px;padding:10px 12px;font-family:"SF Mono",Monaco,Menlo,Consolas,monospace;' +
    'font-size:12px;color:' + COLORS.green + ';word-break:break-all;white-space:pre-wrap;' +
    'max-height:80px;overflow-y:auto;line-height:1.5;user-select:all;' +
    'scrollbar-width:thin;scrollbar-color:' + COLORS.scrollThumb + ' ' + COLORS.scrollTrack + ';';
  previewBox.setAttribute('data-preview', '1');
  previewBox.textContent = _paletteState.previewCmd;
  previewArea.appendChild(previewBox);

  // Buttons
  var btnRow = document.createElement('div');
  btnRow.style.cssText =
    'display:flex;gap:8px;margin-top:10px;';

  var runBtn = document.createElement('button');
  runBtn.style.cssText =
    'flex:1;padding:8px 16px;border:none;border-radius:6px;cursor:pointer;' +
    'background:' + COLORS.btnPrimary + ';color:#fff;font-size:13px;font-weight:600;' +
    'font-family:inherit;transition:background 0.15s;';
  runBtn.textContent = 'Run';
  runBtn.addEventListener('mouseenter', function() { runBtn.style.background = COLORS.btnPrimaryHover; });
  runBtn.addEventListener('mouseleave', function() { runBtn.style.background = COLORS.btnPrimary; });
  runBtn.addEventListener('click', _executeCommand);
  btnRow.appendChild(runBtn);

  var copyBtn = document.createElement('button');
  copyBtn.setAttribute('data-copy-btn', '1');
  copyBtn.style.cssText =
    'padding:8px 16px;border:1px solid ' + COLORS.panelBorder + ';border-radius:6px;cursor:pointer;' +
    'background:' + COLORS.btnSecondary + ';color:' + COLORS.text + ';font-size:13px;font-weight:500;' +
    'font-family:inherit;transition:all 0.15s;';
  copyBtn.textContent = 'Copy';
  copyBtn.addEventListener('mouseenter', function() { copyBtn.style.background = COLORS.btnSecondaryHover; });
  copyBtn.addEventListener('mouseleave', function() { copyBtn.style.background = COLORS.btnSecondary; });
  copyBtn.addEventListener('click', _copyCommand);
  btnRow.appendChild(copyBtn);

  previewArea.appendChild(btnRow);

  // Keyboard hint
  var hint = document.createElement('div');
  hint.style.cssText =
    'font-size:10px;color:' + COLORS.textMuted + ';margin-top:8px;text-align:center;';
  hint.innerHTML =
    '<kbd style="background:#21262d;padding:1px 5px;border-radius:3px;border:1px solid #30363d;' +
    'font-size:9px;font-family:monospace;">Ctrl+Enter</kbd> run &nbsp; ' +
    '<kbd style="background:#21262d;padding:1px 5px;border-radius:3px;border:1px solid #30363d;' +
    'font-size:9px;font-family:monospace;">Esc</kbd> back';
  previewArea.appendChild(hint);

  panel.appendChild(previewArea);

  // Focus the first text input after render
  setTimeout(function() {
    var firstInput = formArea.querySelector('input[type="text"]');
    if (firstInput) firstInput.focus();
  }, 10);
}


// ══════════════════════════════════════════════════════════════
//  HUD INTEGRATION (optional)
// ══════════════════════════════════════════════════════════════

function _tryHudRegister() {
  if (window.__hyperRecon && window.__hyperRecon.hud) {
    window.__hyperRecon.hud.registerTab('cmd-palette', 'Commands', null, function(container) {
      container.innerHTML = '';
      container.style.cssText = 'padding:8px 12px;color:' + COLORS.text + ';font-size:12px;' +
        'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;';

      var hint = document.createElement('div');
      hint.style.cssText = 'display:flex;align-items:center;gap:8px;margin-bottom:8px;';
      hint.innerHTML = '<span style="color:' + COLORS.textMuted + ';">Press</span>' +
        '<kbd style="background:#21262d;padding:2px 8px;border-radius:4px;border:1px solid #30363d;' +
        'font-family:monospace;font-size:11px;color:' + COLORS.accent + ';">Ctrl+Shift+P</kbd>' +
        '<span style="color:' + COLORS.textMuted + ';">to open the command palette</span>';
      container.appendChild(hint);

      // Quick-launch buttons
      var grid = document.createElement('div');
      grid.style.cssText = 'display:flex;flex-wrap:wrap;gap:4px;';
      TOOLS.forEach(function(tool) {
        var btn = document.createElement('button');
        btn.style.cssText =
          'padding:3px 8px;border:1px solid ' + COLORS.panelBorder + ';border-radius:4px;' +
          'background:' + COLORS.bg + ';color:' + categoryColor(tool.category) + ';' +
          'cursor:pointer;font-size:11px;font-family:"SF Mono",Monaco,Menlo,Consolas,monospace;' +
          'font-weight:500;transition:all 0.12s;';
        btn.textContent = tool.name;
        btn.addEventListener('mouseenter', function() {
          btn.style.background = COLORS.toolHover;
          btn.style.borderColor = categoryColor(tool.category);
        });
        btn.addEventListener('mouseleave', function() {
          btn.style.background = COLORS.bg;
          btn.style.borderColor = COLORS.panelBorder;
        });
        btn.addEventListener('click', function() {
          _openPalette();
          setTimeout(function() { _selectTool(tool); }, 50);
        });
        grid.appendChild(btn);
      });
      container.appendChild(grid);
    });
  }
}


// ══════════════════════════════════════════════════════════════
//  PLUGIN EXPORTS
// ══════════════════════════════════════════════════════════════

exports.middleware = function(store) {
  return function(next) {
    return function(action) {
      switch (action.type) {
        case 'SESSION_SET_ACTIVE':
          activeUid = action.uid;
          break;
        case 'SESSION_ADD':
          if (!activeUid) activeUid = action.uid;
          break;
        case 'SESSION_PTY_EXIT':
        case 'SESSION_USER_EXIT':
          if (action.uid === activeUid) activeUid = null;
          break;
      }
      return next(action);
    };
  };
};

exports.decorateTerm = function(Term, _ref) {
  var React = _ref.React;

  return class CmdPaletteTerm extends React.Component {
    constructor(props) {
      super(props);
      this._onDecorated = this._onDecorated.bind(this);
      this._keyHandler = null;
    }

    _onDecorated(term) {
      if (this.props.onDecorated) this.props.onDecorated(term);
      if (!term || !term.term) return;

      // Hotkey listener: Ctrl+Shift+P
      this._keyHandler = function(e) {
        if (e.ctrlKey && e.shiftKey && e.code === 'KeyP') {
          e.preventDefault();
          e.stopPropagation();
          _openPalette();
        }
      };
      window.addEventListener('keydown', this._keyHandler, true);

      // Try HUD registration after a short delay
      setTimeout(_tryHudRegister, 500);
    }

    componentWillUnmount() {
      if (this._keyHandler) {
        window.removeEventListener('keydown', this._keyHandler, true);
        this._keyHandler = null;
      }
    }

    render() {
      return React.createElement(Term, Object.assign({}, this.props, {
        onDecorated: this._onDecorated,
      }));
    }
  };
};
