'use strict';

// ======================================================================
//  HYPER VULN CHECKLIST
//  Interactive vulnerability testing checklists based on WooYun methodology
//  (88,636 real-world cases). Pick a vuln category, get step-by-step items.
//  Tracks completion per target. Persists to ~/.hyper_recon/checklists.json.
// ======================================================================

const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');
const os = require('os');

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

// ======================================================================
//  CHECKLIST DATA (WooYun methodology)
// ======================================================================

const CHECKLISTS = [
  {
    id: 'sqli',
    name: 'SQL Injection',
    cases: 27732,
    color: '#ef4444',
    icon: '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>',
    items: [
      "Test string terminators: ' \" ) ') \") -- # /*",
      'Test numeric params with arithmetic: id=1+1, id=2-1',
      'Test UNION-based: ORDER BY to find columns, then UNION SELECT',
      'Test error-based: AND 1=CONVERT(int,@@version)',
      'Test blind boolean: AND 1=1 vs AND 1=2',
      "Test blind time: AND SLEEP(5), AND WAITFOR DELAY '0:0:5'",
      'Test all parameters (GET, POST, Cookie, Headers)',
      'Fingerprint DBMS: @@version, version(), v$version',
      'Test WAF bypass: space2comment, between, case variation',
      'Test second-order injection points',
      'Check for stacked queries',
    ],
  },
  {
    id: 'xss',
    name: 'XSS',
    cases: 7532,
    color: '#f59e0b',
    icon: '<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/><line x1="14" y1="4" x2="10" y2="20"/>',
    items: [
      'Test reflected XSS in all input fields',
      'Test stored XSS in profile fields (name, bio, etc.)',
      'Test DOM XSS via URL fragments',
      'Test in different contexts: HTML, attribute, JS, URL',
      'Test event handlers: onerror, onload, onfocus, onmouseover',
      'Test encoding bypasses: HTML entities, Unicode, URL encoding',
      'Test tag mutation: <ScRiPt>, <script/x>, <script\\n>',
      'Check CSP policy and bypasses',
      'Test in file upload filenames',
    ],
  },
  {
    id: 'cmdi',
    name: 'Command Execution',
    cases: 6826,
    color: '#22d3ee',
    icon: '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>',
    items: [
      'Identify system command wrappers (ping, nslookup, etc.)',
      'Test chaining: ; | || && ` $()',
      'Test blind command injection with sleep/ping',
      'Test whitespace bypass: ${IFS}, $IFS, %09, <, <>',
      "Test keyword bypass: ca\\t, ca''t, c$@at, /???/??t",
      'Test encoding bypass: hex, base64, printf',
      'Check for eval/assert/preg_replace(/e) in PHP',
      'Test framework vulns: Struts2, WebLogic, JBoss',
    ],
  },
  {
    id: 'upload',
    name: 'File Upload',
    cases: 2711,
    color: '#a78bfa',
    icon: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>',
    items: [
      'Test extension bypass: .php5, .phtml, .pht, .php.',
      'Test Content-Type bypass: image/gif with PHP body',
      'Test magic bytes: GIF89a + PHP code',
      'Test null byte: file.php%00.jpg',
      'Test double extension: file.php.jpg',
      'Test .htaccess upload',
      'Check parser discrepancies (IIS, Apache, Nginx)',
      'Test race conditions in upload validation',
      'Verify upload directory is not executable',
    ],
  },
  {
    id: 'unauth',
    name: 'Unauthorized Access',
    cases: 14377,
    color: '#f97316',
    icon: '<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    items: [
      'Check admin panel exposure: /admin, /manager, /console',
      'Test IDOR: enumerate IDs in URLs and APIs',
      'Check API authentication on all endpoints',
      'Test horizontal privilege escalation',
      'Test vertical privilege escalation',
      'Check exposed services: Redis, MongoDB, Elasticsearch, Docker',
      'Test default credentials',
      'Check session management weaknesses',
    ],
  },
  {
    id: 'lfi',
    name: 'Path Traversal',
    cases: 2854,
    color: '#34d399',
    icon: '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>',
    items: [
      'Test basic: ../../../etc/passwd',
      'Test encoded: %2e%2e%2f, ..%252f, %c0%ae/',
      'Test null byte: ../../etc/passwd%00.jpg',
      'Test Windows: ..\\\\..\\\\..\\\\windows\\\\win.ini',
      'Test absolute paths: /etc/passwd',
      'Check high-risk params: file, path, template, page, include',
      'Test double encoding',
    ],
  },
  {
    id: 'ssrf',
    name: 'SSRF',
    cases: 0,
    color: '#f472b6',
    icon: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
    items: [
      'Test internal IPs: 127.0.0.1, 10.x, 172.16.x, 192.168.x',
      'Test cloud metadata: 169.254.169.254',
      'Test protocols: file://, gopher://, dict://',
      'Test DNS rebinding',
      'Test URL parser bypass: @, #, ?',
    ],
  },
  {
    id: 'logic',
    name: 'Business Logic',
    cases: 0,
    color: '#fbbf24',
    icon: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
    items: [
      'Test payment amount tampering',
      'Test quantity manipulation',
      'Test coupon/code reuse',
      'Test password reset flow bypass',
      'Test step skipping in multi-step flows',
      'Test race conditions (coupon, transfer)',
      'Test CAPTCHA bypass/reuse',
    ],
  },
];

// Total WooYun cases for display
const TOTAL_CASES = 88636;

// ======================================================================
//  PERSISTENCE
// ======================================================================

const RECON_DIR = path.join(os.homedir(), '.hyper_recon');
const DATA_FILE = path.join(RECON_DIR, 'checklists.json');

// State shape: { targets: { [targetName]: { [checklistId]: { [itemIndex]: true } } } }
let state = { targets: {} };

function ensureDir() {
  try {
    if (!fs.existsSync(RECON_DIR)) {
      fs.mkdirSync(RECON_DIR, { recursive: true });
    }
  } catch (e) {
    // ignore
  }
}

function loadState() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const raw = fs.readFileSync(DATA_FILE, 'utf8');
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed.targets === 'object') {
        state = parsed;
      }
    }
  } catch (e) {
    // Start fresh on error
    state = { targets: {} };
  }
}

function saveState() {
  ensureDir();
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(state, null, 2), 'utf8');
  } catch (e) {
    // ignore write errors
  }
}

// Debounce save to avoid excessive disk writes
let saveTimer = null;
function debouncedSave() {
  if (saveTimer) clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    saveTimer = null;
    saveState();
  }, 500);
}

// ======================================================================
//  STATE HELPERS
// ======================================================================

function getTargetData(target) {
  if (!state.targets[target]) {
    state.targets[target] = {};
  }
  return state.targets[target];
}

function getChecklistState(target, checklistId) {
  const td = getTargetData(target);
  if (!td[checklistId]) {
    td[checklistId] = {};
  }
  return td[checklistId];
}

function isChecked(target, checklistId, itemIdx) {
  const cs = getChecklistState(target, checklistId);
  return cs[itemIdx] === true;
}

function toggleItem(target, checklistId, itemIdx) {
  const cs = getChecklistState(target, checklistId);
  if (cs[itemIdx]) {
    delete cs[itemIdx];
  } else {
    cs[itemIdx] = true;
  }
  debouncedSave();
}

function getCategoryProgress(target, checklistId) {
  const checklist = CHECKLISTS.find(c => c.id === checklistId);
  if (!checklist) return { done: 0, total: 0, pct: 0 };
  const total = checklist.items.length;
  const cs = getChecklistState(target, checklistId);
  const done = Object.keys(cs).filter(k => cs[k] === true).length;
  return { done, total, pct: total > 0 ? Math.round((done / total) * 100) : 0 };
}

function getOverallProgress(target) {
  let done = 0;
  let total = 0;
  for (const cl of CHECKLISTS) {
    const p = getCategoryProgress(target, cl.id);
    done += p.done;
    total += p.total;
  }
  return { done, total, pct: total > 0 ? Math.round((done / total) * 100) : 0 };
}

function resetChecklist(target, checklistId) {
  const td = getTargetData(target);
  if (checklistId) {
    td[checklistId] = {};
  } else {
    state.targets[target] = {};
  }
  debouncedSave();
}

function getAllTargets() {
  return Object.keys(state.targets).sort();
}

function exportChecklist(target) {
  const lines = [];
  lines.push('# Vulnerability Checklist Report');
  lines.push('# Target: ' + target);
  lines.push('# Generated: ' + new Date().toISOString());
  const overall = getOverallProgress(target);
  lines.push('# Overall: ' + overall.done + '/' + overall.total + ' (' + overall.pct + '%)');
  lines.push('');

  for (const cl of CHECKLISTS) {
    const prog = getCategoryProgress(target, cl.id);
    lines.push('## ' + cl.name + (cl.cases > 0 ? ' (' + cl.cases.toLocaleString() + ' WooYun cases)' : ''));
    lines.push('## Progress: ' + prog.done + '/' + prog.total + ' (' + prog.pct + '%)');
    lines.push('');
    for (let i = 0; i < cl.items.length; i++) {
      const checked = isChecked(target, cl.id, i);
      lines.push((checked ? '[x] ' : '[ ] ') + cl.items[i]);
    }
    lines.push('');
  }

  return lines.join('\n');
}

// ======================================================================
//  UI STATE (in-memory, not persisted)
// ======================================================================

let currentTarget = '';
let currentCategory = 'sqli';
let targetInputValue = '';
let hudApi = null;
let renderCallback = null;
let hudRegistered = false;

function triggerRender() {
  if (renderCallback) renderCallback();
}

function updateBadge() {
  if (!hudApi) return;
  if (!currentTarget) {
    hudApi.updateBadge('vuln-checklist', null);
    return;
  }
  const overall = getOverallProgress(currentTarget);
  if (overall.total === 0) {
    hudApi.updateBadge('vuln-checklist', null);
  } else if (overall.pct === 100) {
    hudApi.updateBadge('vuln-checklist', '100%');
  } else {
    const remaining = overall.total - overall.done;
    hudApi.updateBadge('vuln-checklist', remaining + ' left');
  }
}

// ======================================================================
//  HUD TAB RENDER
// ======================================================================

function renderChecklistTab(React) {
  const h = React.createElement;

  // Inject styles once
  if (typeof document !== 'undefined' && !document.getElementById('vuln-checklist-styles')) {
    const style = document.createElement('style');
    style.id = 'vuln-checklist-styles';
    style.textContent = [
      '.vcl-cat-tab:hover { opacity: 1 !important; }',
      '.vcl-item-row:hover { background: #161b22 !important; }',
      '.vcl-checkbox:hover { border-color: #58a6ff !important; }',
      '.vcl-btn:hover { opacity: 1 !important; background: #21262d !important; }',
      '.vcl-target-btn:hover { background: #21262d !important; }',
      '.vcl-export-btn:hover { background: #238636 !important; color: #fff !important; }',
      '.vcl-reset-btn:hover { background: #da3633 !important; color: #fff !important; }',
      '.vcl-input:focus { border-color: #58a6ff !important; outline: none; }',
    ].join('\n');
    document.head.appendChild(style);
  }

  // ---------- Container ----------
  return h('div', {
    style: {
      display: 'flex', flexDirection: 'column', height: '100%',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    },
  },
    // Top bar: target selector + overall progress + actions
    renderTopBar(React),
    // Main content
    currentTarget
      ? h('div', { style: { display: 'flex', flex: 1, overflow: 'hidden', gap: '0' } },
          renderCategorySidebar(React),
          renderChecklistContent(React),
        )
      : renderNoTarget(React),
  );
}

// ---------- No Target Placeholder ----------

function renderNoTarget(React) {
  const h = React.createElement;
  return h('div', {
    style: {
      display: 'flex', flexDirection: 'column', alignItems: 'center',
      justifyContent: 'center', flex: 1, color: '#484f58', gap: '8px',
    },
  },
    h('div', { style: { fontSize: '13px', fontStyle: 'italic' } },
      'Enter a target above to start your vulnerability checklist.'),
    h('div', { style: { fontSize: '10px', color: '#30363d' } },
      'Based on WooYun methodology \u2014 ' + TOTAL_CASES.toLocaleString() + ' real-world cases'),
  );
}

// ---------- Top Bar ----------

function renderTopBar(React) {
  const h = React.createElement;
  const targets = getAllTargets();
  const overall = currentTarget ? getOverallProgress(currentTarget) : null;

  const barStyle = {
    display: 'flex', alignItems: 'center', gap: '6px',
    padding: '4px 0', borderBottom: '1px solid #21262d',
    flexShrink: 0, flexWrap: 'wrap',
  };

  return h('div', { style: barStyle },
    // Target label
    h('span', {
      style: { fontSize: '10px', color: '#8b949e', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px', flexShrink: 0 },
    }, 'Target:'),

    // Target input
    h('input', {
      className: 'vcl-input',
      type: 'text',
      placeholder: 'e.g. example.com',
      value: targetInputValue,
      onChange: (e) => {
        targetInputValue = e.target.value;
        triggerRender();
      },
      onKeyDown: (e) => {
        if (e.key === 'Enter' && targetInputValue.trim()) {
          currentTarget = targetInputValue.trim();
          getTargetData(currentTarget);
          debouncedSave();
          updateBadge();
          triggerRender();
        }
      },
      style: {
        background: '#0d1117', border: '1px solid #30363d', borderRadius: '4px',
        padding: '3px 8px', color: '#c9d1d9', fontSize: '11px', width: '160px',
        fontFamily: 'monospace', outline: 'none', transition: 'border-color 0.15s',
      },
    }),

    // Set button
    h('span', {
      className: 'vcl-btn',
      style: {
        cursor: 'pointer', fontSize: '10px', padding: '3px 8px', borderRadius: '4px',
        background: '#161b22', border: '1px solid #30363d', color: '#58a6ff',
        fontWeight: 600, opacity: 0.8, transition: 'opacity 0.1s, background 0.1s',
        flexShrink: 0, userSelect: 'none',
      },
      onClick: () => {
        if (targetInputValue.trim()) {
          currentTarget = targetInputValue.trim();
          getTargetData(currentTarget);
          debouncedSave();
          updateBadge();
          triggerRender();
        }
      },
    }, 'Set'),

    // Saved targets dropdown (if any)
    targets.length > 0 && h('select', {
      style: {
        background: '#0d1117', border: '1px solid #30363d', borderRadius: '4px',
        padding: '3px 6px', color: '#8b949e', fontSize: '10px', cursor: 'pointer',
        outline: 'none', maxWidth: '140px',
      },
      value: currentTarget || '',
      onChange: (e) => {
        if (e.target.value) {
          currentTarget = e.target.value;
          targetInputValue = e.target.value;
          updateBadge();
          triggerRender();
        }
      },
    },
      h('option', { value: '' }, '-- saved --'),
      ...targets.map(t => h('option', { key: t, value: t }, t)),
    ),

    // Spacer
    h('div', { style: { flex: 1 } }),

    // Overall progress (only if target set)
    overall && h('div', {
      style: { display: 'flex', alignItems: 'center', gap: '6px', flexShrink: 0 },
    },
      // Progress bar
      h('div', {
        style: {
          width: '80px', height: '6px', background: '#21262d', borderRadius: '3px',
          overflow: 'hidden', flexShrink: 0,
        },
      },
        h('div', {
          style: {
            width: overall.pct + '%', height: '100%', borderRadius: '3px',
            background: overall.pct === 100 ? '#3fb950' : '#58a6ff',
            transition: 'width 0.3s ease',
          },
        }),
      ),
      // Percentage text
      h('span', {
        style: {
          fontSize: '10px', fontWeight: 700, fontFamily: 'monospace', flexShrink: 0,
          color: overall.pct === 100 ? '#3fb950' : '#c9d1d9',
        },
      }, overall.pct + '%'),
      // Count
      h('span', {
        style: { fontSize: '9px', color: '#484f58', flexShrink: 0 },
      }, overall.done + '/' + overall.total),
    ),

    // Export button
    currentTarget && h('span', {
      className: 'vcl-export-btn',
      style: {
        cursor: 'pointer', fontSize: '9px', padding: '3px 8px', borderRadius: '4px',
        background: '#161b22', border: '1px solid #238636', color: '#3fb950',
        fontWeight: 600, transition: 'background 0.15s, color 0.15s',
        flexShrink: 0, userSelect: 'none',
      },
      onClick: () => {
        const text = exportChecklist(currentTarget);
        const recon = getRecon();
        const uid = recon.activeUid;
        if (uid) {
          const tmpFile = path.join(os.tmpdir(), 'vuln-checklist-' + currentTarget.replace(/[^a-zA-Z0-9._-]/g, '_') + '.md');
          try {
            fs.writeFileSync(tmpFile, text, 'utf8');
            window.rpc.emit('data', { uid, data: 'cat ' + tmpFile + '\n', escaped: false });
            if (hudApi) hudApi.notify('Checklist exported to ' + tmpFile, 'info');
          } catch (e) {
            if (hudApi) hudApi.notify('Export failed: ' + e.message, 'info');
          }
        }
      },
      title: 'Export checklist to terminal',
    }, 'Export'),

    // Reset button
    currentTarget && h('span', {
      className: 'vcl-reset-btn',
      style: {
        cursor: 'pointer', fontSize: '9px', padding: '3px 8px', borderRadius: '4px',
        background: '#161b22', border: '1px solid #da3633', color: '#f85149',
        fontWeight: 600, transition: 'background 0.15s, color 0.15s',
        flexShrink: 0, userSelect: 'none',
      },
      onClick: () => {
        resetChecklist(currentTarget);
        updateBadge();
        triggerRender();
        if (hudApi) hudApi.notify('Checklist reset for ' + currentTarget, 'info');
      },
      title: 'Reset all checklists for this target',
    }, 'Reset'),
  );
}

// ---------- Category Sidebar ----------

function renderCategorySidebar(React) {
  const h = React.createElement;

  const sidebarStyle = {
    width: '170px', flexShrink: 0, borderRight: '1px solid #21262d',
    overflowY: 'auto', padding: '4px 0',
  };

  return h('div', { style: sidebarStyle },
    CHECKLISTS.map(cl => {
      const isActive = cl.id === currentCategory;
      const prog = getCategoryProgress(currentTarget, cl.id);

      const tabStyle = {
        display: 'flex', alignItems: 'center', gap: '6px',
        padding: '6px 10px', cursor: 'pointer',
        background: isActive ? '#161b22' : 'transparent',
        borderLeft: isActive ? ('2px solid ' + cl.color) : '2px solid transparent',
        opacity: isActive ? 1 : 0.7,
        transition: 'background 0.1s, opacity 0.1s',
      };

      return h('div', {
        key: cl.id,
        className: 'vcl-cat-tab',
        style: tabStyle,
        onClick: () => {
          currentCategory = cl.id;
          triggerRender();
        },
      },
        // Icon
        h('span', {
          style: { display: 'inline-flex', flexShrink: 0 },
          dangerouslySetInnerHTML: {
            __html: '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" '
              + 'fill="none" stroke="' + cl.color + '" stroke-width="2" stroke-linecap="round" '
              + 'stroke-linejoin="round">' + cl.icon + '</svg>',
          },
        }),

        // Name + progress
        h('div', { style: { flex: 1, minWidth: 0 } },
          h('div', {
            style: {
              fontSize: '10px', fontWeight: isActive ? 700 : 400,
              color: isActive ? '#f0f6fc' : '#8b949e', whiteSpace: 'nowrap',
              overflow: 'hidden', textOverflow: 'ellipsis',
            },
          }, cl.name),
          h('div', {
            style: {
              display: 'flex', alignItems: 'center', gap: '4px', marginTop: '2px',
            },
          },
            // Mini progress bar
            h('div', {
              style: {
                flex: 1, height: '3px', background: '#21262d', borderRadius: '2px',
                overflow: 'hidden',
              },
            },
              h('div', {
                style: {
                  width: prog.pct + '%', height: '100%', borderRadius: '2px',
                  background: prog.pct === 100 ? '#3fb950' : cl.color,
                  transition: 'width 0.3s ease',
                },
              }),
            ),
            // Count
            h('span', {
              style: { fontSize: '8px', color: '#484f58', flexShrink: 0, fontFamily: 'monospace' },
            }, prog.done + '/' + prog.total),
          ),
        ),
      );
    }),

    // WooYun credit at bottom
    h('div', {
      style: {
        padding: '8px 10px', marginTop: '8px', borderTop: '1px solid #21262d',
        fontSize: '8px', color: '#30363d', lineHeight: '1.4',
      },
    },
      'WooYun Methodology',
      h('br'),
      TOTAL_CASES.toLocaleString() + ' cases analyzed',
    ),
  );
}

// ---------- Checklist Content ----------

function renderChecklistContent(React) {
  const h = React.createElement;
  const cl = CHECKLISTS.find(c => c.id === currentCategory);
  if (!cl) return h('div', null, 'Unknown category');

  const prog = getCategoryProgress(currentTarget, cl.id);

  const contentStyle = {
    flex: 1, overflowY: 'auto', padding: '8px 12px',
    display: 'flex', flexDirection: 'column', gap: '2px',
  };

  return h('div', { style: contentStyle },
    // Category header
    h('div', {
      style: {
        display: 'flex', alignItems: 'center', gap: '8px',
        paddingBottom: '6px', borderBottom: '1px solid #21262d', marginBottom: '4px',
      },
    },
      // Icon
      h('span', {
        style: { display: 'inline-flex' },
        dangerouslySetInnerHTML: {
          __html: '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" '
            + 'fill="none" stroke="' + cl.color + '" stroke-width="2" stroke-linecap="round" '
            + 'stroke-linejoin="round">' + cl.icon + '</svg>',
        },
      }),
      // Name
      h('span', {
        style: { fontSize: '12px', fontWeight: 700, color: cl.color },
      }, cl.name),
      // Cases badge
      cl.cases > 0 && h('span', {
        style: {
          fontSize: '9px', padding: '1px 6px', borderRadius: '8px',
          background: cl.color + '22', color: cl.color, border: '1px solid ' + cl.color + '44',
          fontWeight: 600,
        },
      }, cl.cases.toLocaleString() + ' cases'),
      // Spacer
      h('div', { style: { flex: 1 } }),
      // Progress
      h('div', {
        style: { display: 'flex', alignItems: 'center', gap: '6px' },
      },
        h('div', {
          style: {
            width: '60px', height: '5px', background: '#21262d', borderRadius: '3px',
            overflow: 'hidden',
          },
        },
          h('div', {
            style: {
              width: prog.pct + '%', height: '100%', borderRadius: '3px',
              background: prog.pct === 100 ? '#3fb950' : cl.color,
              transition: 'width 0.3s ease',
            },
          }),
        ),
        h('span', {
          style: {
            fontSize: '10px', fontWeight: 700, fontFamily: 'monospace',
            color: prog.pct === 100 ? '#3fb950' : '#c9d1d9',
          },
        }, prog.pct + '%'),
      ),
      // Category reset
      h('span', {
        className: 'vcl-btn',
        style: {
          cursor: 'pointer', fontSize: '9px', padding: '2px 6px', borderRadius: '3px',
          background: 'transparent', border: '1px solid #30363d', color: '#484f58',
          opacity: 0.6, transition: 'opacity 0.1s, background 0.1s',
          userSelect: 'none',
        },
        onClick: () => {
          resetChecklist(currentTarget, cl.id);
          updateBadge();
          triggerRender();
        },
        title: 'Reset this category',
      }, 'Reset'),
    ),

    // Checklist items
    ...cl.items.map((item, idx) => {
      const checked = isChecked(currentTarget, cl.id, idx);
      return renderChecklistItem(React, cl, idx, item, checked);
    }),
  );
}

function renderChecklistItem(React, cl, idx, text, checked) {
  const h = React.createElement;

  const rowStyle = {
    display: 'flex', alignItems: 'flex-start', gap: '8px',
    padding: '5px 6px', borderRadius: '4px', cursor: 'pointer',
    transition: 'background 0.1s', background: 'transparent',
    userSelect: 'none',
  };

  // Custom checkbox
  const checkboxStyle = {
    width: '14px', height: '14px', borderRadius: '3px', flexShrink: 0,
    border: checked ? ('2px solid ' + cl.color) : '2px solid #30363d',
    background: checked ? cl.color : 'transparent',
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    marginTop: '1px', transition: 'border-color 0.15s, background 0.15s',
    cursor: 'pointer',
  };

  const textStyle = {
    fontSize: '11px', lineHeight: '1.5',
    color: checked ? '#484f58' : '#c9d1d9',
    textDecoration: checked ? 'line-through' : 'none',
    fontFamily: 'monospace',
    flex: 1,
    transition: 'color 0.15s',
  };

  return h('div', {
    key: idx,
    className: 'vcl-item-row',
    style: rowStyle,
    onClick: () => {
      toggleItem(currentTarget, cl.id, idx);
      updateBadge();
      triggerRender();
    },
  },
    // Checkbox
    h('div', {
      className: 'vcl-checkbox',
      style: checkboxStyle,
    },
      checked && h('span', {
        dangerouslySetInnerHTML: {
          __html: '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" '
            + 'fill="none" stroke="#fff" stroke-width="3" stroke-linecap="round" '
            + 'stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
        },
      }),
    ),

    // Item number
    h('span', {
      style: {
        fontSize: '9px', color: '#30363d', fontFamily: 'monospace',
        minWidth: '16px', textAlign: 'right', flexShrink: 0, marginTop: '2px',
      },
    }, String(idx + 1) + '.'),

    // Item text
    h('span', { style: textStyle }, text),
  );
}

// ======================================================================
//  HUD REGISTRATION
// ======================================================================

function registerHud() {
  if (hudRegistered) return;
  const recon = getRecon();

  const renderFn = (React) => {
    return renderChecklistTab(React);
  };

  if (recon.hud) {
    hudApi = recon.hud;
    recon.hud.registerTab('vuln-checklist', 'Checklists', null, renderFn);
    hudRegistered = true;
    updateBadge();
  } else {
    recon.events.on('hud:ready', (hud) => {
      hudApi = hud;
      hud.registerTab('vuln-checklist', 'Checklists', null, renderFn);
      hudRegistered = true;
      updateBadge();
    });
  }
}

// ======================================================================
//  HYPER PLUGIN EXPORTS
// ======================================================================

// Middleware: track active session for terminal output
exports.middleware = (store) => (next) => (action) => {
  const recon = getRecon();
  switch (action.type) {
    case 'SESSION_SET_ACTIVE':
      recon.activeUid = action.uid;
      break;
    case 'SESSION_ADD':
      if (!recon.activeUid) recon.activeUid = action.uid;
      break;
    case 'SESSION_PTY_EXIT':
    case 'SESSION_USER_EXIT':
      if (action.uid === recon.activeUid) recon.activeUid = null;
      break;
  }
  return next(action);
};

// decorateHyper: register HUD tab, load state, wire up re-render
exports.decorateHyper = (Hyper, { React }) => {
  return class VulnChecklistHyper extends React.Component {
    constructor(props) {
      super(props);
      this._mounted = false;
    }

    componentDidMount() {
      this._mounted = true;

      // Load persisted state
      loadState();

      // If there are saved targets, auto-select the first one
      const targets = getAllTargets();
      if (targets.length > 0 && !currentTarget) {
        currentTarget = targets[0];
        targetInputValue = targets[0];
      }

      // Store render callback so internal state changes re-render the HUD
      renderCallback = () => {
        if (this._mounted) {
          this.forceUpdate();
          updateBadge();
        }
      };

      registerHud();

      // Listen for target changes from other plugins
      const recon = getRecon();
      recon.events.on('target:set', (target) => {
        if (target && typeof target === 'string') {
          currentTarget = target;
          targetInputValue = target;
          getTargetData(currentTarget);
          debouncedSave();
          updateBadge();
          triggerRender();
        }
      });
    }

    componentWillUnmount() {
      this._mounted = false;
      renderCallback = null;
      // Flush any pending save
      if (saveTimer) {
        clearTimeout(saveTimer);
        saveTimer = null;
        saveState();
      }
    }

    render() {
      return React.createElement(Hyper, this.props);
    }
  };
};
