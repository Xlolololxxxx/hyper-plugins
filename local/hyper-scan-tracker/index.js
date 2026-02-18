'use strict';

// ======================================================================
//  HYPER SCAN TRACKER
//  Detects, tracks, and manages long-running security scans in Hyper.
//  Registers a "Scans" tab in the HUD framework with live preview,
//  click-to-output, and kill functionality.
// ======================================================================

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

// ------ Constants -----------------------------------------------------

const BUFFER_LIMIT = 500;          // Max lines buffered per scan
const PREVIEW_LINES = 8;           // Lines shown in preview area
const TICK_INTERVAL = 1000;        // Elapsed-time refresh (ms)
const PROMPT_RE = /[$#%>]\s*$/;    // Generic shell prompt pattern

// ------ Scan Detection Patterns ---------------------------------------
// Each entry: { name, detect: RegExp, completionPatterns: [RegExp] }

const SCAN_TOOLS = [
  {
    name: 'nmap',
    detect: /(?:^|\n)\s*(?:sudo\s+)?nmap\s+/,
    extractTarget: /nmap\s+(?:-[^\s]+\s+)*(\S+)/,
    completion: [/Nmap done:/i, /Nmap scan report/i],
  },
  {
    name: 'nikto',
    detect: /(?:^|\n)\s*(?:sudo\s+)?nikto\s+-h/,
    extractTarget: /nikto\s+(?:-[^\s]+\s+)*-h\s+(\S+)/,
    completion: [/host\(s\)\s+tested/i],
  },
  {
    name: 'sqlmap',
    detect: /(?:^|\n)\s*(?:sudo\s+)?sqlmap\s+(?:-u|-r)/,
    extractTarget: /sqlmap\s+(?:-[^\s]+\s+)*(?:-u\s+(\S+)|-r\s+(\S+))/,
    completion: [/shutting down/i, /\[\*\]\s*ending/i],
  },
  {
    name: 'ffuf',
    detect: /(?:^|\n)\s*(?:sudo\s+)?ffuf\s+-u/,
    extractTarget: /ffuf\s+(?:-[^\s]+\s+)*-u\s+(\S+)/,
    completion: [/::\s*Progress\s*::\s*\[.*100\.00%/i],
  },
  {
    name: 'gobuster',
    detect: /(?:^|\n)\s*(?:sudo\s+)?gobuster\s+/,
    extractTarget: /gobuster\s+\S+\s+(?:-[^\s]+\s+)*-u\s+(\S+)/,
    completion: [/Finished/i],
  },
  {
    name: 'masscan',
    detect: /(?:^|\n)\s*(?:sudo\s+)?masscan\s+/,
    extractTarget: /masscan\s+(?:-[^\s]+\s+)*(\S+)/,
    completion: [/rate:\s*0\.00-kpps/i, /Scanning\s+\d+.*done/i],
  },
  {
    name: 'wfuzz',
    detect: /(?:^|\n)\s*(?:sudo\s+)?wfuzz\s+/,
    extractTarget: /wfuzz\s+(?:-[^\s]+\s+)*-u\s+(\S+)/,
    completion: [/Processed Requests:/i, /Total time:/i],
  },
  {
    name: 'dirb',
    detect: /(?:^|\n)\s*(?:sudo\s+)?dirb\s+/,
    extractTarget: /dirb\s+(\S+)/,
    completion: [/END_TIME:/i, /DOWNLOADED:/i],
  },
  {
    name: 'hydra',
    detect: /(?:^|\n)\s*(?:sudo\s+)?hydra\s+/,
    extractTarget: /hydra\s+(?:-[^\s]+\s+)*(\S+)/,
    completion: [/\d+\s+valid\s+password/i, /host.*login.*password/i],
  },
];

// ------ Tool Icons (SVG paths for 24x24 viewBox) ----------------------

const TOOL_ICONS = {
  nmap:     { color: '#58a6ff', svg: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>' },
  nikto:    { color: '#f97316', svg: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>' },
  sqlmap:   { color: '#ef4444', svg: '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>' },
  ffuf:     { color: '#22d3ee', svg: '<path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>' },
  gobuster: { color: '#a78bfa', svg: '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>' },
  masscan:  { color: '#f472b6', svg: '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>' },
  wfuzz:    { color: '#fbbf24', svg: '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>' },
  dirb:     { color: '#34d399', svg: '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>' },
  hydra:    { color: '#fb923c', svg: '<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>' },
  default:  { color: '#8b949e', svg: '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>' },
};

// ------ Scan Tracker State --------------------------------------------

const scans = new Map();   // scanId -> scan object
let scanIdCounter = 0;
let activeUid = null;
let hudApi = null;
let tickTimer = null;
let renderCallback = null; // stored so HUD can re-render

// Scan object shape:
// {
//   id, uid, tool, target, command,
//   startTime, status ('running'|'completed'|'killed'),
//   buffer: [],           // Array of strings (lines)
//   previewExpanded: false,
//   lastDataTime: number,
//   promptCount: number,   // consecutive prompt-like lines
// }

// ------ Helpers -------------------------------------------------------

function elapsed(ms) {
  const s = Math.floor(ms / 1000);
  if (s < 60) return s + 's';
  const m = Math.floor(s / 60);
  const rs = s % 60;
  if (m < 60) return m + 'm ' + rs + 's';
  const h = Math.floor(m / 60);
  const rm = m % 60;
  return h + 'h ' + rm + 'm';
}

function stripAnsi(str) {
  // Remove ANSI escape sequences for cleaner display
  return str.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '')
            .replace(/\x1b\][^\x07]*\x07/g, '')
            .replace(/\x1b[()][AB012]/g, '')
            .replace(/\x1b[\[>=]/g, '')
            .replace(/[\x00-\x08\x0e-\x1f]/g, '');
}

function addToBuffer(scan, rawData) {
  const cleaned = stripAnsi(rawData);
  const lines = cleaned.split(/\r?\n/);
  for (const line of lines) {
    if (line.trim().length > 0) {
      scan.buffer.push(line);
    }
  }
  // Enforce buffer limit
  if (scan.buffer.length > BUFFER_LIMIT) {
    scan.buffer = scan.buffer.slice(scan.buffer.length - BUFFER_LIMIT);
  }
  scan.lastDataTime = Date.now();
}

function checkCompletion(scan, rawData) {
  const tool = SCAN_TOOLS.find(t => t.name === scan.tool);
  if (!tool) return false;
  const cleaned = stripAnsi(rawData);
  for (const pat of tool.completion) {
    if (pat.test(cleaned)) return true;
  }
  return false;
}

function checkPromptReturn(scan, rawData) {
  const cleaned = stripAnsi(rawData);
  const lines = cleaned.split(/\r?\n/);
  for (const line of lines) {
    if (PROMPT_RE.test(line.trim()) && line.trim().length < 200) {
      scan.promptCount = (scan.promptCount || 0) + 1;
      // Require 2 consecutive prompt-like outputs with a gap to avoid false positives
      if (scan.promptCount >= 2 && (Date.now() - scan.startTime) > 3000) {
        return true;
      }
    } else if (line.trim().length > 0) {
      scan.promptCount = 0;
    }
  }
  return false;
}

function getActiveCount() {
  let count = 0;
  for (const scan of scans.values()) {
    if (scan.status === 'running') count++;
  }
  return count;
}

function updateBadge() {
  if (!hudApi) return;
  const count = getActiveCount();
  hudApi.updateBadge('scans', count > 0 ? count : null);
}

function triggerRender() {
  if (renderCallback) renderCallback();
}

// ------ Scan Detection from PTY Data ----------------------------------

function detectScan(uid, rawData) {
  const cleaned = stripAnsi(rawData);
  for (const tool of SCAN_TOOLS) {
    if (tool.detect.test(cleaned)) {
      // Avoid duplicate detection for the same session if already running same tool
      let alreadyTracking = false;
      for (const scan of scans.values()) {
        if (scan.uid === uid && scan.tool === tool.name && scan.status === 'running') {
          alreadyTracking = true;
          break;
        }
      }
      if (alreadyTracking) return null;

      // Extract target
      let target = '(unknown)';
      const targetMatch = cleaned.match(tool.extractTarget);
      if (targetMatch) {
        target = targetMatch[1] || targetMatch[2] || '(unknown)';
      }

      // Extract the command line (first line containing the tool name)
      let command = '';
      const cmdLines = cleaned.split(/\r?\n/);
      for (const ln of cmdLines) {
        if (tool.detect.test('\n' + ln) || tool.detect.test(ln)) {
          command = ln.trim();
          break;
        }
      }

      const scan = {
        id: ++scanIdCounter,
        uid,
        tool: tool.name,
        target,
        command: command || tool.name,
        startTime: Date.now(),
        status: 'running',
        buffer: [],
        previewExpanded: false,
        lastDataTime: Date.now(),
        promptCount: 0,
      };

      scans.set(scan.id, scan);
      updateBadge();
      triggerRender();

      // Notify via HUD
      if (hudApi) {
        hudApi.notify(tool.name + ' scan started: ' + target, 'info');
      }

      return scan;
    }
  }
  return null;
}

// ------ Feed PTY Data into Tracked Scans ------------------------------

function feedData(uid, rawData) {
  for (const scan of scans.values()) {
    if (scan.uid === uid && scan.status === 'running') {
      addToBuffer(scan, rawData);

      // Check for tool-specific completion patterns
      if (checkCompletion(scan, rawData)) {
        scan.status = 'completed';
        updateBadge();
        if (hudApi) {
          hudApi.notify(scan.tool + ' scan completed: ' + scan.target, 'info');
        }
      }
      // Check for prompt return (general completion)
      else if (checkPromptReturn(scan, rawData)) {
        scan.status = 'completed';
        updateBadge();
        if (hudApi) {
          hudApi.notify(scan.tool + ' scan completed: ' + scan.target, 'info');
        }
      }

      triggerRender();
    }
  }
}

// ------ Kill a Scan ---------------------------------------------------

function killScan(scanId) {
  const scan = scans.get(scanId);
  if (!scan || scan.status !== 'running') return;
  // Send Ctrl+C to the session
  window.rpc.emit('data', { uid: scan.uid, data: '\x03', escaped: false });
  scan.status = 'killed';
  scan.buffer.push('[scan-tracker] Scan killed by user');
  updateBadge();
  triggerRender();
  if (hudApi) {
    hudApi.notify(scan.tool + ' scan killed: ' + scan.target, 'info');
  }
}

// ------ Output Scan to Terminal ---------------------------------------

function outputScan(scanId) {
  const scan = scans.get(scanId);
  if (!scan) return;
  const recon = getRecon();
  const uid = recon.activeUid || activeUid;
  if (!uid) return;

  // Build output header + buffer content
  const header = [
    '',
    '# ── Scan Output: ' + scan.tool + ' ──────────────────────────────────',
    '# Target:  ' + scan.target,
    '# Status:  ' + scan.status,
    '# Started: ' + new Date(scan.startTime).toLocaleString(),
    '# Lines:   ' + scan.buffer.length,
    '# ──────────────────────────────────────────────────────────',
    '',
  ];

  const fullOutput = header.concat(scan.buffer).join('\n') + '\n';

  // Inject into terminal via heredoc so the output is printed cleanly
  window.rpc.emit('data', { uid, data: 'cat << \'__SCAN_OUTPUT_EOF__\'\n' + fullOutput + '__SCAN_OUTPUT_EOF__\n', escaped: false });
}

// ------ Remove a Scan from Tracking -----------------------------------

function removeScan(scanId) {
  scans.delete(scanId);
  updateBadge();
  triggerRender();
}

// ------ Elapsed Time Ticker -------------------------------------------

function startTick() {
  if (tickTimer) return;
  tickTimer = setInterval(() => {
    let hasRunning = false;
    for (const scan of scans.values()) {
      if (scan.status === 'running') { hasRunning = true; break; }
    }
    if (hasRunning) triggerRender();
  }, TICK_INTERVAL);
}

function stopTick() {
  if (tickTimer) { clearInterval(tickTimer); tickTimer = null; }
}

// ======================================================================
//  HUD TAB RENDER FUNCTION
// ======================================================================

function renderScansTab(React) {
  const h = React.createElement;
  const scanList = Array.from(scans.values()).sort((a, b) => b.startTime - a.startTime);

  if (scanList.length === 0) {
    return h('div', {
      style: {
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        height: '100%', color: '#484f58', fontSize: '12px', fontStyle: 'italic',
      },
    }, 'No scans detected. Run nmap, nikto, sqlmap, ffuf, gobuster, masscan, wfuzz, dirb, or hydra to track.');
  }

  return h('div', { style: { display: 'flex', flexDirection: 'column', gap: '6px' } },
    scanList.map(scan => renderScanRow(React, scan))
  );
}

function renderScanRow(React, scan) {
  const h = React.createElement;
  const now = Date.now();
  const isRunning = scan.status === 'running';
  const isCompleted = scan.status === 'completed';
  const isKilled = scan.status === 'killed';
  const icon = TOOL_ICONS[scan.tool] || TOOL_ICONS.default;
  const elapsedStr = elapsed(now - scan.startTime);
  const previewLines = scan.buffer.slice(-PREVIEW_LINES);

  // Status indicator
  const statusColors = {
    running:   '#3fb950',
    completed: '#58a6ff',
    killed:    '#f85149',
  };
  const statusColor = statusColors[scan.status] || '#8b949e';

  // Row container
  const rowStyle = {
    background: '#161b22',
    border: '1px solid #21262d',
    borderRadius: '6px',
    padding: '8px 10px',
    opacity: isRunning ? 1 : 0.7,
    cursor: (isCompleted || isKilled) ? 'pointer' : 'default',
    transition: 'opacity 0.2s, border-color 0.2s',
    position: 'relative',
  };

  // Pulsing animation for running scans (using inline keyframe trick)
  const pulseStyle = isRunning ? {
    width: '8px', height: '8px', borderRadius: '50%',
    background: statusColor,
    boxShadow: '0 0 6px ' + statusColor,
    animation: 'scan-pulse 1.5s ease-in-out infinite',
    flexShrink: 0,
  } : {
    width: '8px', height: '8px', borderRadius: '50%',
    background: statusColor, flexShrink: 0,
  };

  // Inject keyframes into document if not already done
  if (typeof document !== 'undefined' && !document.getElementById('scan-tracker-styles')) {
    const style = document.createElement('style');
    style.id = 'scan-tracker-styles';
    style.textContent = `
      @keyframes scan-pulse {
        0%, 100% { opacity: 1; transform: scale(1); }
        50% { opacity: 0.4; transform: scale(0.7); }
      }
      .scan-row:hover { border-color: #30363d !important; }
      .scan-row-clickable:hover { border-color: #58a6ff !important; opacity: 1 !important; }
      .scan-kill-btn:hover { background: #f85149 !important; color: #fff !important; }
      .scan-preview-toggle:hover { color: #c9d1d9 !important; }
      .scan-remove-btn:hover { background: #da3633 !important; color: #fff !important; }
    `;
    document.head.appendChild(style);
  }

  const onRowClick = (isCompleted || isKilled) ? () => outputScan(scan.id) : undefined;

  return h('div', {
    key: scan.id,
    className: 'scan-row' + ((isCompleted || isKilled) ? ' scan-row-clickable' : ''),
    style: rowStyle,
    onClick: onRowClick,
    title: (isCompleted || isKilled) ? 'Click to output scan results to terminal' : '',
  },
    // Header row
    h('div', {
      style: {
        display: 'flex', alignItems: 'center', gap: '8px',
        marginBottom: previewLines.length > 0 ? '6px' : 0,
      },
    },
      // Pulse indicator
      h('div', { style: pulseStyle }),

      // Tool icon
      h('span', {
        style: { display: 'inline-flex', flexShrink: 0 },
        dangerouslySetInnerHTML: {
          __html: '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" '
            + 'fill="none" stroke="' + icon.color + '" stroke-width="2" stroke-linecap="round" '
            + 'stroke-linejoin="round">' + icon.svg + '</svg>',
        },
      }),

      // Tool name
      h('span', {
        style: {
          fontWeight: 700, color: icon.color, fontSize: '11px',
          textTransform: 'uppercase', letterSpacing: '0.5px', flexShrink: 0,
        },
      }, scan.tool),

      // Target
      h('span', {
        style: {
          color: '#c9d1d9', fontSize: '11px', overflow: 'hidden',
          textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1,
          fontFamily: 'monospace',
        },
        title: scan.target,
      }, scan.target),

      // Elapsed time
      h('span', {
        style: {
          color: '#8b949e', fontSize: '10px', flexShrink: 0,
          fontFamily: 'monospace', minWidth: '50px', textAlign: 'right',
        },
      }, elapsedStr),

      // Status badge
      h('span', {
        style: {
          fontSize: '9px', fontWeight: 600, padding: '1px 6px',
          borderRadius: '8px', flexShrink: 0, textTransform: 'uppercase',
          letterSpacing: '0.3px',
          background: statusColor + '22',
          color: statusColor,
          border: '1px solid ' + statusColor + '44',
        },
      }, scan.status),

      // Buffer line count
      h('span', {
        style: { color: '#484f58', fontSize: '9px', flexShrink: 0 },
      }, scan.buffer.length + ' ln'),

      // Preview toggle button
      h('span', {
        className: 'scan-preview-toggle',
        style: {
          cursor: 'pointer', color: '#484f58', fontSize: '10px',
          padding: '2px 4px', flexShrink: 0, userSelect: 'none',
        },
        onClick: (e) => {
          e.stopPropagation();
          scan.previewExpanded = !scan.previewExpanded;
          triggerRender();
        },
        title: scan.previewExpanded ? 'Collapse preview' : 'Expand preview',
      }, scan.previewExpanded ? '\u25B2' : '\u25BC'),

      // Kill button (only for running scans)
      isRunning && h('span', {
        className: 'scan-kill-btn',
        style: {
          cursor: 'pointer', color: '#f85149', fontSize: '11px',
          fontWeight: 700, padding: '1px 5px', borderRadius: '3px',
          border: '1px solid #f8514933', background: 'transparent',
          flexShrink: 0, lineHeight: '14px', userSelect: 'none',
          transition: 'background 0.15s, color 0.15s',
        },
        onClick: (e) => {
          e.stopPropagation();
          killScan(scan.id);
        },
        title: 'Kill scan (Ctrl+C)',
      }, '\u2715'),

      // Remove button (only for completed/killed scans)
      !isRunning && h('span', {
        className: 'scan-remove-btn',
        style: {
          cursor: 'pointer', color: '#484f58', fontSize: '9px',
          padding: '1px 5px', borderRadius: '3px', flexShrink: 0,
          border: '1px solid transparent', background: 'transparent',
          lineHeight: '14px', userSelect: 'none',
          transition: 'background 0.15s, color 0.15s',
        },
        onClick: (e) => {
          e.stopPropagation();
          removeScan(scan.id);
        },
        title: 'Remove from list',
      }, '\u2715'),
    ),

    // Preview area (always visible but toggleable height)
    scan.previewExpanded && previewLines.length > 0 && h('div', {
      style: {
        background: '#0d1117',
        border: '1px solid #21262d',
        borderRadius: '4px',
        padding: '4px 8px',
        maxHeight: '120px',
        overflowY: 'auto',
        fontFamily: '"Cascadia Code", "Fira Code", "JetBrains Mono", monospace',
        fontSize: '10px',
        lineHeight: '1.5',
        color: '#8b949e',
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-all',
      },
      onClick: (e) => e.stopPropagation(),
    },
      previewLines.map((line, i) =>
        h('div', {
          key: i,
          style: {
            borderBottom: i < previewLines.length - 1 ? '1px solid #161b2211' : 'none',
            padding: '1px 0',
          },
        }, line)
      )
    ),

    // Mini preview (last 2 lines when collapsed, only for running scans)
    !scan.previewExpanded && isRunning && previewLines.length > 0 && h('div', {
      style: {
        fontFamily: 'monospace', fontSize: '9px', color: '#484f58',
        whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
        lineHeight: '1.4', marginTop: '2px',
      },
    },
      previewLines.slice(-2).map((line, i) =>
        h('div', {
          key: i,
          style: { overflow: 'hidden', textOverflow: 'ellipsis' },
        }, line)
      )
    ),
  );
}

// ======================================================================
//  HUD REGISTRATION
// ======================================================================

let hudRegistered = false;

function registerHud() {
  if (hudRegistered) return;
  const recon = getRecon();

  // The renderFn is called by the HUD framework with React as the argument.
  // We wrap it so the HUD can trigger re-renders by invoking the tab's renderFn.
  const renderFn = (React) => {
    return renderScansTab(React);
  };

  if (recon.hud) {
    hudApi = recon.hud;
    recon.hud.registerTab('scans', 'Scans', null, renderFn);
    hudRegistered = true;
    updateBadge();
  } else {
    recon.events.on('hud:ready', (hud) => {
      hudApi = hud;
      hud.registerTab('scans', 'Scans', null, renderFn);
      hudRegistered = true;
      updateBadge();
    });
  }
}

// ======================================================================
//  HYPER PLUGIN EXPORTS
// ======================================================================

// Middleware: intercept PTY data and session events

exports.middleware = (store) => (next) => (action) => {
  const recon = getRecon();

  switch (action.type) {
    case 'SESSION_SET_ACTIVE':
      activeUid = action.uid;
      break;

    case 'SESSION_ADD':
      if (!activeUid) activeUid = action.uid;
      break;

    case 'SESSION_PTY_DATA': {
      const uid = action.uid;
      const data = action.data;

      // Try to detect a new scan starting
      detectScan(uid, data);

      // Feed data to any running scans on this session
      feedData(uid, data);
      break;
    }

    case 'SESSION_PTY_EXIT':
    case 'SESSION_USER_EXIT': {
      // Mark any running scans for this session as completed
      for (const scan of scans.values()) {
        if (scan.uid === action.uid && scan.status === 'running') {
          scan.status = 'completed';
          scan.buffer.push('[scan-tracker] Session exited');
        }
      }
      if (action.uid === activeUid) activeUid = null;
      updateBadge();
      triggerRender();
      break;
    }
  }

  return next(action);
};

// decorateHyper: register HUD tab and start tick timer

exports.decorateHyper = (Hyper, { React }) => {
  return class ScanTrackerHyper extends React.Component {
    constructor(props) {
      super(props);
      this._mounted = false;
    }

    componentDidMount() {
      this._mounted = true;

      // Store a render callback that forces React state update in the HUD
      // The HUD framework calls renderFn(React) each time it renders,
      // so we force the HUD to re-render by toggling our own state.
      renderCallback = () => {
        if (this._mounted) {
          this.forceUpdate();
          // Also nudge the HUD to re-render by touching badge
          updateBadge();
        }
      };

      registerHud();
      startTick();
    }

    componentWillUnmount() {
      this._mounted = false;
      renderCallback = null;
      stopTick();
    }

    render() {
      return React.createElement(Hyper, this.props);
    }
  };
};
