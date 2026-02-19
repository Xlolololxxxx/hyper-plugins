'use strict';

// ======================================================================
//  HYPER SQLI ASSISTANT
//  SQLMap workflow companion for Hyper terminal
//  Tracks SQL injection testing progress per parameter, suggests next
//  commands, and shows injection status in a HUD tab.
// ======================================================================

// -- Shared Recon Namespace -------------------------------------------

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

// -- Shell Safety -----------------------------------------------------

function esc(str) {
  return "'" + str.replace(/'/g, "'\\''") + "'";
}

// -- Active Session ---------------------------------------------------

let activeUid = null;

function execCmd(cmd) {
  const recon = getRecon();
  const uid = activeUid || recon.activeUid;
  if (!uid) return;
  if (typeof recon.exec === 'function') {
    recon.exec(cmd, uid);
  } else {
    window.rpc.emit('data', { uid, data: cmd + '\n', escaped: false });
  }
}

// ======================================================================
//  STATE STORE
//  Central state for all SQLi tracking data
// ======================================================================

const SENSITIVE_PATTERNS = ['password', 'pass', 'pwd', 'card', 'api', 'token', 'secret', 'key', 'ssn', 'email', 'credit', 'balance', 'amount', 'auth'];

const STATE = {
  // Current target URL being tested
  targetUrl: '',

  // Map of parameter name -> { status, technique, dbms }
  // status: 'untested' | 'testing' | 'vulnerable' | 'not-vulnerable'
  params: new Map(),

  // Detected back-end DBMS
  dbms: '',

  // Discovered databases
  databases: [],

  // Discovered tables per database: Map<dbName, string[]>
  tables: new Map(),

  // Discovered columns per table: Map<"db.table", string[]>
  columns: new Map(),

  // Set of sensitive columns found: Set<"db.table.column">
  sensitiveColumns: new Set(),

  // Current workflow phase
  // 'idle' | 'detecting' | 'detected' | 'enumerating-dbs' | 'enumerating-tables' |
  // 'enumerating-columns' | 'dumping' | 'complete'
  phase: 'idle',

  // Last sqlmap command that was run
  lastCommand: '',

  // Render version bump — forces React re-render
  version: 0,
};

function bump() {
  STATE.version++;
  const recon = getRecon();
  recon.events.emit('sqli:updated', STATE);
}

function resetState() {
  STATE.targetUrl = '';
  STATE.params.clear();
  STATE.dbms = '';
  STATE.databases = [];
  STATE.tables.clear();
  STATE.columns.clear();
  STATE.sensitiveColumns.clear();
  STATE.phase = 'idle';
  STATE.lastCommand = '';
  bump();
}

// ======================================================================
//  SQLMAP OUTPUT PARSER
//  Parses PTY data lines for sqlmap patterns
// ======================================================================

// ANSI escape code stripper
function stripAnsi(str) {
  return str.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '').replace(/\r/g, '');
}

// Buffer for partial lines per session
const lineBuffers = new Map();

function parseSqlmapLine(line) {
  const clean = stripAnsi(line).trim();
  if (!clean) return;

  // -- Detect target URL from sqlmap command invocation --
  const cmdMatch = clean.match(/sqlmap\s.*?-u\s+['"]?(\S+?)['"]?(?:\s|$)/);
  if (cmdMatch) {
    const url = cmdMatch[1];
    if (url !== STATE.targetUrl) {
      resetState();
      STATE.targetUrl = url;
      STATE.phase = 'detecting';
      STATE.lastCommand = clean;

      // Extract URL parameters
      try {
        const u = new URL(url.startsWith('http') ? url : 'http://' + url);
        for (const [key] of u.searchParams) {
          if (!STATE.params.has(key)) {
            STATE.params.set(key, { status: 'untested', technique: '', dbms: '' });
          }
        }
      } catch (_) { /* not a parseable URL */ }

      bump();
      return;
    }
    STATE.lastCommand = clean;
  }

  // -- Parameter testing started --
  const testingMatch = clean.match(/\[INFO\]\s+testing\s+['"]?(\w+)['"]?\s+parameter/i) ||
                       clean.match(/\[INFO\]\s+testing\s+.*?parameter\s+['"](\w+)['"]/i);
  if (testingMatch) {
    const param = testingMatch[1];
    STATE.params.set(param, {
      status: 'testing',
      technique: STATE.params.has(param) ? STATE.params.get(param).technique : '',
      dbms: STATE.params.has(param) ? STATE.params.get(param).dbms : '',
    });
    STATE.phase = 'detecting';
    bump();
    return;
  }

  // -- Parameter is vulnerable --
  const vulnMatch = clean.match(/parameter\s+['"](\w+)['"]\s+is\s+vulnerable/i) ||
                    clean.match(/['"](\w+)['"]\s+.*?injectable/i);
  if (vulnMatch) {
    const param = vulnMatch[1];
    const existing = STATE.params.get(param) || {};
    STATE.params.set(param, {
      status: 'vulnerable',
      technique: existing.technique || '',
      dbms: existing.dbms || STATE.dbms,
    });
    STATE.phase = 'detected';
    bump();

    // Update HUD badge
    const recon = getRecon();
    if (recon.hud) {
      const vulnCount = Array.from(STATE.params.values()).filter(p => p.status === 'vulnerable').length;
      recon.hud.updateBadge('sqli', vulnCount);
    }
    return;
  }

  // -- Parameter not injectable --
  const notVulnMatch = clean.match(/\[WARNING\]\s+.*?parameter\s+['"](\w+)['"]\s+does\s+not\s+seem\s+to\s+be\s+injectable/i) ||
                       clean.match(/parameter\s+['"](\w+)['"]\s+.*?not\s+injectable/i);
  if (notVulnMatch) {
    const param = notVulnMatch[1];
    const existing = STATE.params.get(param) || {};
    STATE.params.set(param, {
      status: 'not-vulnerable',
      technique: existing.technique || '',
      dbms: existing.dbms || '',
    });
    bump();
    return;
  }

  // -- Injection technique identified --
  const techMatch = clean.match(/Type:\s+(.+)/i);
  if (techMatch) {
    const technique = techMatch[1].trim();
    // Apply to the most recently testing or vulnerable param
    for (const [name, info] of STATE.params) {
      if (info.status === 'testing' || info.status === 'vulnerable') {
        info.technique = technique;
        break;
      }
    }
    bump();
    return;
  }

  // -- DBMS detection --
  const dbmsMatch = clean.match(/\[INFO\]\s+the\s+back-end\s+DBMS\s+is\s+(.+)/i);
  if (dbmsMatch) {
    STATE.dbms = dbmsMatch[1].trim();
    // Apply DBMS to all vulnerable params
    for (const [, info] of STATE.params) {
      if (info.status === 'vulnerable' || info.status === 'testing') {
        info.dbms = STATE.dbms;
      }
    }
    bump();
    return;
  }

  // -- Database enumeration results --
  const dbListMatch = clean.match(/available\s+databases/i);
  if (dbListMatch) {
    STATE.phase = 'enumerating-dbs';
    STATE.databases = [];
    bump();
    return;
  }

  // Capture individual database names (lines starting with [*])
  const dbNameMatch = clean.match(/^\[\*\]\s+(.+)$/);
  if (dbNameMatch && (STATE.phase === 'enumerating-dbs' || STATE.phase === 'enumerating-tables' ||
      STATE.phase === 'enumerating-columns')) {
    const name = dbNameMatch[1].trim();
    if (STATE.phase === 'enumerating-dbs' && name && !STATE.databases.includes(name)) {
      STATE.databases.push(name);
      bump();
      return;
    }
  }

  // -- Table enumeration results --
  const tableHeaderMatch = clean.match(/Database:\s+(\S+)/i);
  if (tableHeaderMatch) {
    const dbName = tableHeaderMatch[1];
    if (!STATE.tables.has(dbName)) {
      STATE.tables.set(dbName, []);
    }
    STATE.phase = 'enumerating-tables';
    STATE._currentDb = dbName;
    bump();
    return;
  }

  // Capture table names (lines starting with | tablename |)
  const tableRowMatch = clean.match(/^\|\s+(\S+)\s+\|$/);
  if (tableRowMatch && STATE._currentDb) {
    const tbl = tableRowMatch[1].trim();
    if (tbl && !tbl.match(/^[-+]+$/) && tbl.toLowerCase() !== 'table') {
      const tables = STATE.tables.get(STATE._currentDb) || [];
      if (!tables.includes(tbl)) {
        tables.push(tbl);
        STATE.tables.set(STATE._currentDb, tables);
        bump();
      }
    }
    return;
  }

  // -- Column enumeration results --
  const colHeaderMatch = clean.match(/Table:\s+(\S+)/i);
  if (colHeaderMatch && STATE._currentDb) {
    const tbl = colHeaderMatch[1];
    const key = STATE._currentDb + '.' + tbl;
    if (!STATE.columns.has(key)) {
      STATE.columns.set(key, []);
    }
    STATE._currentTable = tbl;
    STATE.phase = 'enumerating-columns';
    bump();
    return;
  }

  // Capture column names
  const colRowMatch = clean.match(/^\|\s+(\S+)\s+\|\s+(\S+)\s+\|$/);
  if (colRowMatch && STATE._currentDb && STATE._currentTable) {
    const col = colRowMatch[1].trim();
    if (col && !col.match(/^[-+]+$/) && col.toLowerCase() !== 'column') {
      const key = STATE._currentDb + '.' + STATE._currentTable;
      const cols = STATE.columns.get(key) || [];
      if (!cols.includes(col)) {
        cols.push(col);
        STATE.columns.set(key, cols);

        // Check for sensitive patterns
        const lowerCol = col.toLowerCase();
        if (SENSITIVE_PATTERNS.some(p => lowerCol.includes(p))) {
          STATE.sensitiveColumns.add(key + '.' + col);

          // Notify HUD
          const recon = getRecon();
          if (recon.hud) {
            recon.hud.notify(`Sensitive column found: ${col} in ${key}`, 'warn');
          }
        }

        bump();
      }
    }
    return;
  }

  // -- Dump in progress --
  if (clean.match(/dumping\s+entries/i) || clean.match(/\[INFO\]\s+fetching\s+entries/i)) {
    STATE.phase = 'dumping';
    bump();
    return;
  }

  // -- sqlmap finished --
  if (clean.match(/\[INFO\]\s+fetched\s+data\s+logged/i) || clean.match(/shutting\s+down/i)) {
    if (STATE.phase === 'detecting') {
      STATE.phase = 'detected';
    }
    bump();
    return;
  }
}

function processPtyData(uid, rawData) {
  const data = typeof rawData === 'string' ? rawData : rawData.toString('utf8');
  const buf = (lineBuffers.get(uid) || '') + data;
  const lines = buf.split('\n');

  // Keep the last chunk if it doesn't end with newline (partial line)
  if (!data.endsWith('\n')) {
    lineBuffers.set(uid, lines.pop());
  } else {
    lineBuffers.set(uid, '');
    lines.pop(); // remove trailing empty
  }

  for (const line of lines) {
    parseSqlmapLine(line);
  }
}


// ======================================================================
//  TAMPER SCRIPTS REFERENCE
// ======================================================================

const TAMPER_SCRIPTS = [
  { name: 'space2comment', desc: 'Replace spaces with /**/' },
  { name: 'between', desc: 'Replace = with NOT BETWEEN 0 AND / BETWEEN AND' },
  { name: 'charencode', desc: 'URL-encode each character in payload' },
  { name: 'randomcase', desc: 'Random upper/lower case for SQL keywords' },
  { name: 'apostrophemask', desc: 'Replace apostrophe with UTF-8 fullwidth equivalent' },
  { name: 'equaltolike', desc: 'Replace = operator with LIKE' },
  { name: 'space2hash', desc: 'MySQL space bypass with # and newline' },
  { name: 'base64encode', desc: 'Base64-encode the entire payload' },
  { name: 'chardoubleencode', desc: 'Double URL-encode non-encoded characters' },
  { name: 'space2plus', desc: 'Replace spaces with plus signs' },
  { name: 'space2randomblank', desc: 'Replace spaces with random blank chars' },
  { name: 'unionalltounion', desc: 'Replace UNION ALL SELECT with UNION SELECT' },
  { name: 'percentage', desc: 'Add percent sign before each character' },
  { name: 'modsecurityversioned', desc: 'Embrace query with versioned MySQL comment' },
  { name: 'halfversionedmorekeywords', desc: 'Add versioned MySQL comment around keywords' },
];


// ======================================================================
//  COMMAND SUGGESTION ENGINE
// ======================================================================

function suggestNextCommand() {
  const url = STATE.targetUrl;
  if (!url) return null;

  const safeUrl = esc(url);
  const vulnParams = [];
  for (const [name, info] of STATE.params) {
    if (info.status === 'vulnerable') vulnParams.push(name);
  }

  // Phase-based suggestions
  if (STATE.phase === 'idle' || STATE.phase === 'detecting') {
    if (STATE.params.size === 0 || vulnParams.length === 0) {
      return {
        label: 'Test for SQL injection',
        cmd: 'sqlmap -u ' + safeUrl + ' --batch',
      };
    }
  }

  if (STATE.phase === 'detected' && vulnParams.length > 0 && STATE.databases.length === 0) {
    return {
      label: 'Enumerate databases',
      cmd: 'sqlmap -u ' + safeUrl + ' --dbs --batch',
    };
  }

  if (STATE.databases.length > 0) {
    // Find a database without tables enumerated
    for (const db of STATE.databases) {
      if (db === 'information_schema' || db === 'mysql' || db === 'performance_schema' || db === 'sys') continue;
      if (!STATE.tables.has(db) || STATE.tables.get(db).length === 0) {
        return {
          label: 'Enumerate tables in ' + db,
          cmd: 'sqlmap -u ' + safeUrl + ' --tables -D ' + esc(db) + ' --batch',
        };
      }
    }

    // Find a table without columns enumerated
    for (const [db, tables] of STATE.tables) {
      for (const tbl of tables) {
        const key = db + '.' + tbl;
        if (!STATE.columns.has(key) || STATE.columns.get(key).length === 0) {
          return {
            label: 'Enumerate columns in ' + db + '.' + tbl,
            cmd: 'sqlmap -u ' + safeUrl + ' --columns -T ' + esc(tbl) + ' -D ' + esc(db) + ' --batch',
          };
        }
      }
    }

    // Suggest dump for a table with known columns
    for (const [key, cols] of STATE.columns) {
      if (cols.length > 0) {
        const parts = key.split('.');
        const db = parts[0];
        const tbl = parts.slice(1).join('.');
        const colList = cols.slice(0, 10).join(',');
        return {
          label: 'Dump ' + db + '.' + tbl,
          cmd: 'sqlmap -u ' + safeUrl + ' --dump -T ' + esc(tbl) + ' -D ' + esc(db) + ' -C ' + esc(colList) + ' --batch',
        };
      }
    }
  }

  // Fallback: if we have vulnerable params, suggest dbs or shell
  if (vulnParams.length > 0) {
    // Prioritize high impact RCE checks if not just attempted
    if (!STATE.lastCommand.includes('--os-shell') && !STATE.lastCommand.includes('--sql-shell')) {
      return {
        label: 'Attempt OS Shell',
        cmd: 'sqlmap -u ' + safeUrl + ' --os-shell --batch',
      };
    }

    return {
      label: 'Enumerate databases',
      cmd: 'sqlmap -u ' + safeUrl + ' --dbs --batch',
    };
  }

  return null;
}


// ======================================================================
//  QUICK COMMAND TEMPLATES
// ======================================================================

function getQuickCommands() {
  const url = STATE.targetUrl || '<URL>';
  const safeUrl = STATE.targetUrl ? esc(url) : "'<URL>'";

  return [
    { label: 'Test URL', icon: '\u25B6', cmd: 'sqlmap -u ' + safeUrl + ' --batch', color: '#58a6ff' },
    { label: 'Aggressive', icon: '\u26A1', cmd: 'sqlmap -u ' + safeUrl + ' --level=5 --risk=3 --batch', color: '#f0883e' },
    { label: 'Enum DBs', icon: '\u26C1', cmd: 'sqlmap -u ' + safeUrl + ' --dbs --batch', color: '#56d364' },
    { label: 'Privileges', icon: '\uD83D\uDC51', cmd: 'sqlmap -u ' + safeUrl + ' --privileges --batch', color: '#d29922' },
    { label: 'OS Shell', icon: '\u2318', cmd: 'sqlmap -u ' + safeUrl + ' --os-shell', color: '#da3633' },
    { label: 'WAF Bypass', icon: '\u2694', cmd: 'sqlmap -u ' + safeUrl + ' --tamper=space2comment,between --random-agent', color: '#bc8cff' },
    { label: 'Forms', icon: '\u2611', cmd: 'sqlmap -u ' + safeUrl + ' --forms --batch --crawl=2', color: '#79c0ff' },
  ];
}


// ======================================================================
//  HUD TAB RENDERER (React.createElement only)
// ======================================================================

let _renderRef = null;

function renderHudTab(React) {
  const h = React.createElement;

  // -- Styles --
  const sSection = {
    marginBottom: '12px',
  };

  const sSectionTitle = {
    fontSize: '10px',
    fontWeight: 700,
    textTransform: 'uppercase',
    letterSpacing: '0.8px',
    color: '#8b949e',
    marginBottom: '6px',
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
  };

  const sTargetUrl = {
    fontFamily: 'monospace',
    fontSize: '12px',
    color: '#58a6ff',
    background: '#161b22',
    padding: '6px 10px',
    borderRadius: '4px',
    border: '1px solid #21262d',
    wordBreak: 'break-all',
    marginBottom: '10px',
  };

  const sNoTarget = {
    color: '#484f58',
    fontStyle: 'italic',
    fontSize: '12px',
    padding: '6px 0',
  };

  const sProgress = {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    marginBottom: '10px',
    fontSize: '12px',
  };

  const sProgressBar = {
    flex: 1,
    height: '6px',
    background: '#21262d',
    borderRadius: '3px',
    overflow: 'hidden',
    position: 'relative',
  };

  const sGrid = {
    display: 'grid',
    gridTemplateColumns: '120px 110px 1fr 80px',
    gap: '1px',
    background: '#21262d',
    borderRadius: '4px',
    overflow: 'hidden',
    fontSize: '11px',
    marginBottom: '10px',
  };

  const sGridHeader = {
    background: '#161b22',
    padding: '5px 8px',
    fontWeight: 700,
    color: '#8b949e',
    fontSize: '10px',
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
  };

  const sGridCell = {
    background: '#0d1117',
    padding: '5px 8px',
    color: '#c9d1d9',
    fontFamily: 'monospace',
    fontSize: '11px',
  };

  const sSuggest = {
    background: '#161b22',
    border: '1px solid #1f6feb44',
    borderRadius: '6px',
    padding: '10px 12px',
    marginBottom: '10px',
  };

  const sSuggestLabel = {
    fontSize: '10px',
    color: '#8b949e',
    marginBottom: '4px',
    fontWeight: 600,
  };

  const sSuggestCmd = {
    fontFamily: 'monospace',
    fontSize: '11px',
    color: '#79c0ff',
    wordBreak: 'break-all',
    marginBottom: '8px',
  };

  const sBtn = {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '4px',
    padding: '4px 12px',
    borderRadius: '4px',
    border: '1px solid #30363d',
    background: '#21262d',
    color: '#c9d1d9',
    fontSize: '11px',
    fontWeight: 500,
    cursor: 'pointer',
    transition: 'background 0.1s, border-color 0.1s',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
  };

  const sBtnPrimary = {
    ...sBtn,
    background: '#1f6feb',
    borderColor: '#1f6feb',
    color: '#fff',
    fontWeight: 600,
  };

  const sQuickRow = {
    display: 'flex',
    flexWrap: 'wrap',
    gap: '6px',
    marginBottom: '10px',
  };

  const sTamperGrid = {
    display: 'grid',
    gridTemplateColumns: '1fr 1fr',
    gap: '4px',
    fontSize: '11px',
  };

  const sTamperItem = {
    display: 'flex',
    gap: '6px',
    padding: '3px 6px',
    borderRadius: '3px',
    background: '#161b22',
    alignItems: 'flex-start',
  };

  const sTamperName = {
    fontFamily: 'monospace',
    color: '#f0883e',
    fontWeight: 600,
    whiteSpace: 'nowrap',
    fontSize: '10px',
    minWidth: '90px',
  };

  const sTamperDesc = {
    color: '#8b949e',
    fontSize: '10px',
  };

  // -- Status color helper --
  function statusColor(status) {
    switch (status) {
      case 'vulnerable': return '#da3633';
      case 'not-vulnerable': return '#3fb950';
      case 'testing': return '#d29922';
      case 'untested': default: return '#484f58';
    }
  }

  function statusLabel(status) {
    switch (status) {
      case 'vulnerable': return '\u2B24 VULNERABLE';
      case 'not-vulnerable': return '\u25CB Not Vuln';
      case 'testing': return '\u29BF Testing...';
      case 'untested': default: return '\u25CC Untested';
    }
  }

  // -- Compute stats --
  const total = STATE.params.size;
  const tested = Array.from(STATE.params.values()).filter(p => p.status !== 'untested').length;
  const injectable = Array.from(STATE.params.values()).filter(p => p.status === 'vulnerable').length;
  const progress = total > 0 ? (tested / total) * 100 : 0;

  const suggestion = suggestNextCommand();
  const quickCmds = getQuickCommands();

  // -- Build sections --
  const sections = [];

  // Target URL
  sections.push(
    h('div', { style: sSection, key: 'target' },
      h('div', { style: sSectionTitle }, '\u{1F3AF} TARGET'),
      STATE.targetUrl
        ? h('div', { style: sTargetUrl }, STATE.targetUrl)
        : h('div', { style: sNoTarget }, 'No target URL detected. Run sqlmap -u <URL> to begin.')
    )
  );

  // Progress dashboard
  if (total > 0) {
    const barFillVuln = injectable > 0 ? (injectable / total) * 100 : 0;
    const barFillSafe = total > 0 ? (Array.from(STATE.params.values()).filter(p => p.status === 'not-vulnerable').length / total) * 100 : 0;
    const barFillTest = total > 0 ? (Array.from(STATE.params.values()).filter(p => p.status === 'testing').length / total) * 100 : 0;

    sections.push(
      h('div', { style: sSection, key: 'progress' },
        h('div', { style: sSectionTitle }, '\u{1F4CA} PROGRESS'),
        h('div', { style: sProgress },
          h('span', { style: { color: '#c9d1d9', fontWeight: 600 } },
            tested + '/' + total + ' params tested'
          ),
          injectable > 0 && h('span', {
            style: {
              color: '#da3633',
              fontWeight: 700,
              background: '#da363322',
              padding: '1px 8px',
              borderRadius: '10px',
              fontSize: '11px',
            }
          }, injectable + ' injectable'),
          STATE.dbms && h('span', {
            style: {
              color: '#f0883e',
              background: '#f0883e22',
              padding: '1px 8px',
              borderRadius: '10px',
              fontSize: '11px',
            }
          }, STATE.dbms)
        ),
        h('div', { style: sProgressBar },
          h('div', {
            style: {
              position: 'absolute', left: 0, top: 0, height: '100%',
              width: barFillVuln + '%',
              background: '#da3633',
              borderRadius: '3px',
              transition: 'width 0.3s',
              zIndex: 3,
            }
          }),
          h('div', {
            style: {
              position: 'absolute', left: barFillVuln + '%', top: 0, height: '100%',
              width: barFillTest + '%',
              background: '#d29922',
              transition: 'width 0.3s',
              zIndex: 2,
            }
          }),
          h('div', {
            style: {
              position: 'absolute', left: (barFillVuln + barFillTest) + '%', top: 0, height: '100%',
              width: barFillSafe + '%',
              background: '#3fb950',
              transition: 'width 0.3s',
              zIndex: 1,
            }
          })
        )
      )
    );
  }

  // Parameter grid
  if (total > 0) {
    const gridItems = [
      h('div', { style: sGridHeader, key: 'hdr-param' }, 'Parameter'),
      h('div', { style: sGridHeader, key: 'hdr-status' }, 'Status'),
      h('div', { style: sGridHeader, key: 'hdr-technique' }, 'Technique'),
      h('div', { style: sGridHeader, key: 'hdr-dbms' }, 'DBMS'),
    ];

    let idx = 0;
    for (const [name, info] of STATE.params) {
      const rowBg = idx % 2 === 0 ? '#0d1117' : '#0d1117dd';
      gridItems.push(
        h('div', { style: { ...sGridCell, background: rowBg, fontWeight: 600 }, key: 'p-' + name }, name),
        h('div', {
          style: {
            ...sGridCell,
            background: rowBg,
            color: statusColor(info.status),
            fontWeight: 600,
            fontSize: '10px',
          },
          key: 's-' + name,
        }, statusLabel(info.status)),
        h('div', {
          style: { ...sGridCell, background: rowBg, fontSize: '10px', color: '#8b949e' },
          key: 't-' + name,
        }, info.technique || '\u2014'),
        h('div', {
          style: { ...sGridCell, background: rowBg, fontSize: '10px', color: '#f0883e' },
          key: 'd-' + name,
        }, info.dbms || '\u2014')
      );
      idx++;
    }

    sections.push(
      h('div', { style: sSection, key: 'params' },
        h('div', { style: sSectionTitle }, '\u{1F50D} PARAMETERS'),
        h('div', { style: sGrid }, ...gridItems)
      )
    );
  }

  // Discovered databases
  if (STATE.databases.length > 0) {
    sections.push(
      h('div', { style: sSection, key: 'dbs' },
        h('div', { style: sSectionTitle },
          '\u{1F5C4} DATABASES (',
          h('span', { style: { color: '#56d364' } }, STATE.databases.length),
          ')'
        ),
        h('div', { style: { display: 'flex', flexWrap: 'wrap', gap: '4px' } },
          ...STATE.databases.map(db =>
            h('span', {
              key: 'db-' + db,
              style: {
                background: '#161b22',
                border: '1px solid #21262d',
                borderRadius: '4px',
                padding: '2px 8px',
                fontFamily: 'monospace',
                fontSize: '11px',
                color: '#56d364',
                cursor: 'pointer',
              },
              title: 'Click to enumerate tables in ' + db,
              onClick: () => {
                execCmd('sqlmap -u ' + esc(STATE.targetUrl) + ' --tables -D ' + esc(db) + ' --batch');
              },
            }, db)
          )
        )
      )
    );
  }

  // Discovered tables
  if (STATE.tables.size > 0) {
    const tableItems = [];
    for (const [db, tables] of STATE.tables) {
      if (tables.length === 0) continue;
      tableItems.push(
        h('div', {
          key: 'tbl-hdr-' + db,
          style: { fontSize: '10px', fontWeight: 700, color: '#58a6ff', marginTop: tableItems.length > 0 ? '6px' : 0 }
        }, db + ':'),
        h('div', {
          key: 'tbl-list-' + db,
          style: { display: 'flex', flexWrap: 'wrap', gap: '4px', marginTop: '2px' }
        },
          ...tables.map(tbl =>
            h('span', {
              key: 'tbl-' + db + '-' + tbl,
              style: {
                background: '#161b22',
                border: '1px solid #21262d',
                borderRadius: '4px',
                padding: '2px 8px',
                fontFamily: 'monospace',
                fontSize: '11px',
                color: '#d2a8ff',
                cursor: 'pointer',
              },
              title: 'Click to enumerate columns in ' + db + '.' + tbl,
              onClick: () => {
                execCmd('sqlmap -u ' + esc(STATE.targetUrl) + ' --columns -T ' + esc(tbl) + ' -D ' + esc(db) + ' --batch');
              },
            }, tbl)
          )
        )
      );
    }

    if (tableItems.length > 0) {
      sections.push(
        h('div', { style: sSection, key: 'tables' },
          h('div', { style: sSectionTitle }, '\u{1F4CB} TABLES'),
          ...tableItems
        )
      );
    }
  }

  // Discovered columns
  if (STATE.columns.size > 0) {
    const colItems = [];
    for (const [key, cols] of STATE.columns) {
      if (cols.length === 0) continue;
      const parts = key.split('.');
      const db = parts[0];
      const tbl = parts.slice(1).join('.');
      colItems.push(
        h('div', {
          key: 'col-hdr-' + key,
          style: { fontSize: '10px', fontWeight: 700, color: '#58a6ff', marginTop: colItems.length > 0 ? '6px' : 0 }
        }, db + '.' + tbl + ':'),
        h('div', {
          key: 'col-list-' + key,
          style: { display: 'flex', flexWrap: 'wrap', gap: '4px', marginTop: '2px' }
        },
          ...cols.map(col => {
            const isSensitive = STATE.sensitiveColumns.has(key + '.' + col);
            return h('span', {
              key: 'col-' + key + '-' + col,
              style: {
                background: isSensitive ? '#da363322' : '#161b22',
                border: '1px solid ' + (isSensitive ? '#da3633' : '#21262d'),
                borderRadius: '4px',
                padding: '2px 6px',
                fontFamily: 'monospace',
                fontSize: '10px',
                color: isSensitive ? '#f85149' : '#79c0ff',
                fontWeight: isSensitive ? 700 : 400,
              },
            }, col);
          })
        )
      );
    }

    if (colItems.length > 0) {
      sections.push(
        h('div', { style: sSection, key: 'columns' },
          h('div', { style: sSectionTitle }, '\u{1F4DD} COLUMNS'),
          ...colItems
        )
      );
    }
  }

  // Suggested next command
  if (suggestion) {
    sections.push(
      h('div', { style: sSection, key: 'suggest' },
        h('div', { style: sSectionTitle }, '\u{1F4A1} SUGGESTED NEXT'),
        h('div', { style: sSuggest },
          h('div', { style: sSuggestLabel }, suggestion.label),
          h('div', { style: sSuggestCmd }, suggestion.cmd),
          h('div', { style: { display: 'flex', gap: '8px' } },
            h('button', {
              style: sBtnPrimary,
              onClick: () => execCmd(suggestion.cmd),
              onMouseEnter: (e) => { e.target.style.background = '#388bfd'; },
              onMouseLeave: (e) => { e.target.style.background = '#1f6feb'; },
            }, '\u25B6 Run'),
            h('button', {
              style: sBtn,
              onClick: () => {
                const { clipboard } = require('electron');
                clipboard.writeText(suggestion.cmd);
              },
              onMouseEnter: (e) => { e.target.style.background = '#30363d'; },
              onMouseLeave: (e) => { e.target.style.background = '#21262d'; },
            }, '\u2398 Copy')
          )
        )
      )
    );
  }

  // Quick action buttons
  sections.push(
    h('div', { style: sSection, key: 'quick' },
      h('div', { style: sSectionTitle }, '\u26A1 QUICK ACTIONS'),
      h('div', { style: sQuickRow },
        ...quickCmds.map(qc =>
          h('button', {
            key: 'qc-' + qc.label,
            style: {
              ...sBtn,
              borderColor: qc.color + '55',
              color: qc.color,
              fontSize: '10px',
              padding: '4px 10px',
            },
            onClick: () => {
              if (qc.cmd.includes("'<URL>'") && !STATE.targetUrl) {
                const recon = getRecon();
                if (recon.hud) recon.hud.notify('Set a target URL first by running sqlmap -u <URL>', 'warn');
                return;
              }
              execCmd(qc.cmd);
            },
            onMouseEnter: (e) => { e.target.style.background = qc.color + '22'; },
            onMouseLeave: (e) => { e.target.style.background = '#21262d'; },
            title: qc.cmd,
          }, qc.icon + ' ' + qc.label)
        )
      )
    )
  );

  // Tamper scripts reference (always shown, compact)
  sections.push(
    h('div', { style: sSection, key: 'tamper' },
      h('div', { style: sSectionTitle }, '\u{1F6E1} TAMPER SCRIPTS'),
      h('div', { style: sTamperGrid },
        ...TAMPER_SCRIPTS.map(ts =>
          h('div', {
            key: 'ts-' + ts.name,
            style: {
              ...sTamperItem,
              cursor: 'pointer',
            },
            title: 'Click to add --tamper=' + ts.name + ' to clipboard',
            onClick: () => {
              const { clipboard } = require('electron');
              clipboard.writeText('--tamper=' + ts.name);
              const recon = getRecon();
              if (recon.hud) recon.hud.notify('Copied: --tamper=' + ts.name, 'info');
            },
          },
            h('span', { style: sTamperName }, ts.name),
            h('span', { style: sTamperDesc }, ts.desc)
          )
        )
      )
    )
  );

  // Reset button
  if (STATE.targetUrl) {
    sections.push(
      h('div', {
        style: { textAlign: 'right', marginTop: '4px', paddingTop: '8px', borderTop: '1px solid #21262d' },
        key: 'reset',
      },
        h('button', {
          style: { ...sBtn, fontSize: '10px', color: '#da3633', borderColor: '#da363355' },
          onClick: () => { resetState(); },
          onMouseEnter: (e) => { e.target.style.background = '#da363322'; },
          onMouseLeave: (e) => { e.target.style.background = '#21262d'; },
        }, '\u21BA Reset Session')
      )
    );
  }

  return h('div', {
    style: { lineHeight: '1.4' },
    ref: (el) => { _renderRef = el; },
  }, ...sections);
}


// ======================================================================
//  HUD TAB REGISTRATION
// ======================================================================

let hudRegistered = false;
let hudReadyUnsub = null;

function registerHudTab() {
  if (hudRegistered) return;
  const recon = getRecon();

  if (recon.hud) {
    recon.hud.registerTab('sqli', 'SQLi', '\u{1F489}', renderHudTab);
    hudRegistered = true;

    // Set up re-render on state changes
    recon.events.on('sqli:updated', () => {
      if (recon.hud && recon.hud._forceUpdate) {
        recon.hud._forceUpdate();
      }
    });
  } else {
    // Wait for HUD framework to be ready
    const onReady = (hud) => {
      hud.registerTab('sqli', 'SQLi', '\u{1F489}', renderHudTab);
      hudRegistered = true;

      recon.events.on('sqli:updated', () => {
        if (recon.hud && recon.hud._forceUpdate) {
          recon.hud._forceUpdate();
        }
      });
    };
    recon.events.once('hud:ready', onReady);
    hudReadyUnsub = () => recon.events.removeListener('hud:ready', onReady);
  }
}


// ======================================================================
//  HYPER PLUGIN EXPORTS
// ======================================================================

// -- Middleware: intercept PTY data for sqlmap output parsing ----------

exports.middleware = (store) => (next) => (action) => {
  switch (action.type) {
    case 'SESSION_SET_ACTIVE':
      activeUid = action.uid;
      break;
    case 'SESSION_ADD':
      if (!activeUid) activeUid = action.uid;
      break;
    case 'SESSION_PTY_DATA':
      // Parse sqlmap output from terminal data
      if (action.data) {
        processPtyData(action.uid, action.data);
      }
      break;
    case 'SESSION_PTY_EXIT':
    case 'SESSION_USER_EXIT':
      if (action.uid === activeUid) activeUid = null;
      lineBuffers.delete(action.uid);
      break;
  }
  return next(action);
};


// -- decorateHyper: register HUD tab when component mounts -----------

exports.decorateHyper = (Hyper, { React }) => {
  return class SqliHyper extends React.Component {
    constructor(props) {
      super(props);
      this._interval = null;
      this._lastVersion = -1;
    }

    componentDidMount() {
      registerHudTab();

      // Listen for parsed:sqlmap events from output-parser plugin if available
      const recon = getRecon();
      this._onParsedSqlmap = (data) => {
        if (data && data.raw) {
          parseSqlmapLine(data.raw);
        }
      };
      recon.events.on('parsed:sqlmap', this._onParsedSqlmap);

      // Poll for state changes to force re-render of HUD panel
      // The HUD framework re-calls renderFn when the tab is active,
      // so we just need to trigger re-render on the HUD component.
      this._interval = setInterval(() => {
        if (STATE.version !== this._lastVersion) {
          this._lastVersion = STATE.version;
          this.forceUpdate();
        }
      }, 500);
    }

    componentWillUnmount() {
      if (this._interval) clearInterval(this._interval);
      if (this._onParsedSqlmap) {
        const recon = getRecon();
        recon.events.removeListener('parsed:sqlmap', this._onParsedSqlmap);
      }
      if (hudReadyUnsub) hudReadyUnsub();
    }

    render() {
      return React.createElement(Hyper, this.props);
    }
  };
};
