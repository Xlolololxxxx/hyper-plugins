'use strict';

// ══════════════════════════════════════════════════════════════
//  HYPER FILE SHUTTLE
//  Streamlined netcat-based file transfer interface
//  One-click setup for send/receive between machines
//  Generates commands for both ends, copies remote cmd to clipboard
// ══════════════════════════════════════════════════════════════

const { clipboard } = require('electron');

// ─── Shared Recon Namespace ─────────────────────────────────
function getRecon() {
  if (!window.__hyperRecon) {
    const EventEmitter = require('events');
    window.__hyperRecon = { events: new EventEmitter(), targets: new Map(), findings: [], hud: null };
    window.__hyperRecon.events.setMaxListeners(50);
  }
  return window.__hyperRecon;
}

// ─── Session Tracking ───────────────────────────────────────
let activeUid = null;

// ─── Shell Helpers ──────────────────────────────────────────
function esc(str) {
  return "'" + str.replace(/'/g, "'\\''") + "'";
}

function exec(cmd) {
  if (!activeUid) return;
  window.rpc.emit('data', { uid: activeUid, data: cmd + '\n', escaped: false });
}

function copyText(text) {
  clipboard.writeText(text);
}

// ─── Transfer Modes ─────────────────────────────────────────
const MODES = {
  SEND_FILE:    { id: 'send_file',    label: 'Send File',    icon: '\u2191', isDir: false, isSend: true  },
  RECV_FILE:    { id: 'recv_file',    label: 'Receive File', icon: '\u2193', isDir: false, isSend: false },
  SEND_DIR:     { id: 'send_dir',     label: 'Send Dir',     icon: '\u21D1', isDir: true,  isSend: true  },
  RECV_DIR:     { id: 'recv_dir',     label: 'Receive Dir',  icon: '\u21D3', isDir: true,  isSend: false },
};

const MODE_LIST = [MODES.SEND_FILE, MODES.RECV_FILE, MODES.SEND_DIR, MODES.RECV_DIR];

// ─── Transfer State ─────────────────────────────────────────
let shuttleState = {
  mode: MODES.SEND_FILE,
  filePath: '',
  port: '5555',
  targetIp: '',
  useSSL: false,
  history: [],
  generated: null,       // { localCmd, remoteCmd, checksumLocal, checksumRemote }
  notification: null,    // { text, type, ts }
};

let _renderCallback = null;

function updateState(patch) {
  Object.assign(shuttleState, patch);
  if (_renderCallback) _renderCallback();
}

function notify(text, type) {
  updateState({ notification: { text, type: type || 'info', ts: Date.now() } });
  setTimeout(() => {
    if (shuttleState.notification && Date.now() - shuttleState.notification.ts >= 2800) {
      updateState({ notification: null });
    }
  }, 3000);
}

// ─── Command Generation ─────────────────────────────────────
function generateCommands() {
  const { mode, filePath, port, targetIp, useSSL } = shuttleState;

  if (!filePath.trim()) { notify('File/directory path is required', 'error'); return; }
  if (!port.trim() || isNaN(Number(port))) { notify('Valid port number is required', 'error'); return; }
  if (!targetIp.trim()) { notify('Target IP is required', 'error'); return; }

  const p = port.trim();
  const ip = targetIp.trim();
  const f = filePath.trim();
  const ncBin = useSSL ? 'ncat --ssl' : 'nc';
  const ncBinRemote = useSSL ? 'ncat --ssl' : 'nc';

  let localCmd = '';
  let remoteCmd = '';
  let checksumLocal = '';
  let checksumRemote = '';

  if (mode.isDir) {
    // Directory transfer with tar
    if (mode.isSend) {
      // Send directory: local tars and listens, remote connects and untars
      localCmd = 'tar czf - -C ' + esc(f) + ' . | ' + ncBin + ' -lvnp ' + p;
      remoteCmd = ncBinRemote + ' ' + ip + ' ' + p + ' | tar xzf - -C ' + esc(f);
    } else {
      // Receive directory: local listens and untars, remote tars and sends
      localCmd = ncBin + ' -lvnp ' + p + ' | tar xzf - -C ' + esc(f);
      remoteCmd = 'tar czf - -C ' + esc(f) + ' . | ' + ncBinRemote + ' ' + ip + ' ' + p;
    }
    // No single-file checksum for directories
    checksumLocal = 'find ' + esc(f) + ' -type f -exec md5sum {} + | sort -k2 | md5sum';
    checksumRemote = 'find ' + esc(f) + ' -type f -exec md5sum {} + | sort -k2 | md5sum';
  } else {
    // Single file transfer
    if (mode.isSend) {
      // Send file: local listens with file as input, remote connects and writes
      localCmd = ncBin + ' -lvnp ' + p + ' < ' + esc(f);
      remoteCmd = ncBinRemote + ' ' + ip + ' ' + p + ' > ' + esc(f);
    } else {
      // Receive file: local listens and writes to file, remote sends
      localCmd = ncBin + ' -lvnp ' + p + ' > ' + esc(f);
      remoteCmd = ncBinRemote + ' ' + ip + ' ' + p + ' < ' + esc(f);
    }
    checksumLocal = 'md5sum ' + esc(f);
    checksumRemote = 'md5sum ' + esc(f);
  }

  const generated = { localCmd, remoteCmd, checksumLocal, checksumRemote };

  // Add to history
  const entry = {
    ts: Date.now(),
    mode: mode.label,
    filePath: f,
    port: p,
    targetIp: ip,
    ssl: useSSL,
    localCmd,
    remoteCmd,
  };
  const history = [entry, ...shuttleState.history].slice(0, 50);

  updateState({ generated, history });
  notify('Commands generated', 'success');
}

function copyRemoteCmd() {
  if (!shuttleState.generated) { notify('Generate commands first', 'error'); return; }
  copyText(shuttleState.generated.remoteCmd);
  notify('Remote command copied to clipboard', 'success');
}

function executeLocal() {
  if (!shuttleState.generated) { notify('Generate commands first', 'error'); return; }
  exec(shuttleState.generated.localCmd);
  notify('Local command sent to terminal', 'success');
}

function executeChecksum() {
  if (!shuttleState.generated) { notify('Generate commands first', 'error'); return; }
  exec(shuttleState.generated.checksumLocal);
  notify('Checksum command sent to terminal', 'success');
}


// ══════════════════════════════════════════════════════════════
//  HUD TAB RENDERER
// ══════════════════════════════════════════════════════════════

function renderShuttleTab(React) {
  const h = React.createElement;
  const st = shuttleState;

  // ─── Styles ──────────────────────────────────────────────
  const containerStyle = {
    display: 'flex',
    flexDirection: 'column',
    gap: '10px',
    height: '100%',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    fontSize: '12px',
    color: '#c9d1d9',
  };

  const rowStyle = {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    flexWrap: 'wrap',
  };

  const modeBtnBase = {
    padding: '4px 10px',
    border: '1px solid #30363d',
    borderRadius: '4px',
    cursor: 'pointer',
    fontSize: '11px',
    fontWeight: 600,
    transition: 'all 0.12s',
    userSelect: 'none',
  };

  const inputStyle = {
    background: '#161b22',
    border: '1px solid #30363d',
    borderRadius: '4px',
    padding: '4px 8px',
    color: '#c9d1d9',
    fontSize: '12px',
    fontFamily: 'monospace',
    outline: 'none',
    flex: 1,
    minWidth: '80px',
  };

  const labelStyle = {
    fontSize: '10px',
    color: '#8b949e',
    fontWeight: 600,
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
    minWidth: '50px',
  };

  const cmdBoxStyle = {
    background: '#0d1117',
    border: '1px solid #21262d',
    borderRadius: '4px',
    padding: '6px 10px',
    fontFamily: '"Cascadia Code", "Fira Code", "JetBrains Mono", monospace',
    fontSize: '11px',
    color: '#58a6ff',
    wordBreak: 'break-all',
    lineHeight: '1.5',
    position: 'relative',
    cursor: 'text',
    userSelect: 'all',
  };

  const btnStyle = {
    padding: '4px 10px',
    border: '1px solid #30363d',
    borderRadius: '4px',
    cursor: 'pointer',
    fontSize: '11px',
    fontWeight: 600,
    background: '#21262d',
    color: '#c9d1d9',
    transition: 'all 0.12s',
    userSelect: 'none',
    whiteSpace: 'nowrap',
  };

  const btnPrimaryStyle = Object.assign({}, btnStyle, {
    background: '#238636',
    borderColor: '#2ea043',
    color: '#fff',
  });

  const btnSecondaryStyle = Object.assign({}, btnStyle, {
    background: '#1f6feb',
    borderColor: '#388bfd',
    color: '#fff',
  });

  const btnWarningStyle = Object.assign({}, btnStyle, {
    background: '#9e6a03',
    borderColor: '#d29922',
    color: '#fff',
  });

  const sslCheckStyle = {
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
    cursor: 'pointer',
    fontSize: '11px',
    userSelect: 'none',
    color: st.useSSL ? '#3fb950' : '#8b949e',
    padding: '4px 8px',
    borderRadius: '4px',
    border: st.useSSL ? '1px solid #238636' : '1px solid #30363d',
    background: st.useSSL ? '#0d2818' : 'transparent',
  };

  const historyItemStyle = {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '3px 6px',
    borderRadius: '3px',
    fontSize: '10px',
    color: '#8b949e',
    fontFamily: 'monospace',
    cursor: 'pointer',
    transition: 'background 0.1s',
  };

  const sectionTitleStyle = {
    fontSize: '10px',
    fontWeight: 700,
    color: '#8b949e',
    textTransform: 'uppercase',
    letterSpacing: '0.8px',
    marginTop: '4px',
  };

  const notifStyle = st.notification ? {
    padding: '4px 10px',
    borderRadius: '4px',
    fontSize: '11px',
    fontWeight: 600,
    background: st.notification.type === 'error' ? '#3d1114' : st.notification.type === 'success' ? '#0d2818' : '#0d1d36',
    color: st.notification.type === 'error' ? '#f85149' : st.notification.type === 'success' ? '#3fb950' : '#58a6ff',
    border: '1px solid ' + (st.notification.type === 'error' ? '#f8514933' : st.notification.type === 'success' ? '#3fb95033' : '#58a6ff33'),
  } : null;

  // ─── Build Elements ──────────────────────────────────────
  const children = [];

  // Notification
  if (st.notification) {
    children.push(h('div', { key: 'notif', style: notifStyle }, st.notification.text));
  }

  // Mode selector row
  const modeButtons = MODE_LIST.map(m => {
    const isActive = st.mode.id === m.id;
    const style = Object.assign({}, modeBtnBase, {
      background: isActive ? '#1f6feb' : '#21262d',
      borderColor: isActive ? '#388bfd' : '#30363d',
      color: isActive ? '#fff' : '#8b949e',
    });
    return h('div', {
      key: m.id,
      style: style,
      onClick: () => updateState({ mode: m, generated: null }),
      onMouseEnter: function(e) { if (!isActive) { e.currentTarget.style.background = '#30363d'; e.currentTarget.style.color = '#c9d1d9'; } },
      onMouseLeave: function(e) { if (!isActive) { e.currentTarget.style.background = '#21262d'; e.currentTarget.style.color = '#8b949e'; } },
    }, m.icon + ' ' + m.label);
  });

  children.push(h('div', { key: 'modes', style: rowStyle }, ...modeButtons));

  // Input fields row
  const pathLabel = st.mode.isDir ? 'Directory' : 'File Path';
  children.push(
    h('div', { key: 'inputs', style: Object.assign({}, rowStyle, { gap: '8px' }) },
      // File/Dir path
      h('span', { style: labelStyle }, pathLabel),
      h('input', {
        style: Object.assign({}, inputStyle, { minWidth: '180px' }),
        placeholder: st.mode.isDir ? '/path/to/directory' : '/path/to/file',
        value: st.filePath,
        onChange: function(e) { updateState({ filePath: e.target.value, generated: null }); },
        spellCheck: false,
      }),
      // Port
      h('span', { style: labelStyle }, 'Port'),
      h('input', {
        style: Object.assign({}, inputStyle, { maxWidth: '70px', minWidth: '50px', flex: 'none' }),
        placeholder: '5555',
        value: st.port,
        onChange: function(e) { updateState({ port: e.target.value, generated: null }); },
        spellCheck: false,
      }),
      // Target IP
      h('span', { style: labelStyle }, 'Target IP'),
      h('input', {
        style: Object.assign({}, inputStyle, { maxWidth: '140px', minWidth: '100px' }),
        placeholder: '10.10.14.1',
        value: st.targetIp,
        onChange: function(e) { updateState({ targetIp: e.target.value, generated: null }); },
        spellCheck: false,
      }),
      // SSL toggle
      h('div', {
        style: sslCheckStyle,
        onClick: function() { updateState({ useSSL: !st.useSSL, generated: null }); },
        title: 'Use ncat --ssl for encrypted transfer',
      },
        h('span', { style: { fontSize: '13px' } }, st.useSSL ? '\u2611' : '\u2610'),
        'SSL'
      ),
      // Generate button
      h('div', {
        style: btnPrimaryStyle,
        onClick: generateCommands,
        onMouseEnter: function(e) { e.currentTarget.style.background = '#2ea043'; },
        onMouseLeave: function(e) { e.currentTarget.style.background = '#238636'; },
      }, 'Generate')
    )
  );

  // Generated commands display
  if (st.generated) {
    // Local command
    children.push(
      h('div', { key: 'local-section', style: sectionTitleStyle }, 'Local Command (this machine)'),
      h('div', { key: 'local-cmd', style: cmdBoxStyle }, st.generated.localCmd)
    );

    // Remote command
    children.push(
      h('div', { key: 'remote-section', style: sectionTitleStyle }, 'Remote Command (target machine)'),
      h('div', { key: 'remote-cmd', style: Object.assign({}, cmdBoxStyle, { color: '#f0883e' }) }, st.generated.remoteCmd)
    );

    // Checksum commands
    children.push(
      h('div', { key: 'checksum-section', style: sectionTitleStyle }, 'Verification (run on both sides)'),
      h('div', { key: 'checksum-cmd', style: Object.assign({}, cmdBoxStyle, { color: '#a5d6ff', fontSize: '10px' }) },
        'Local:  ' + st.generated.checksumLocal + '\nRemote: ' + st.generated.checksumRemote
      )
    );

    // Action buttons
    children.push(
      h('div', { key: 'actions', style: Object.assign({}, rowStyle, { marginTop: '2px' }) },
        h('div', {
          style: btnSecondaryStyle,
          onClick: copyRemoteCmd,
          onMouseEnter: function(e) { e.currentTarget.style.background = '#388bfd'; },
          onMouseLeave: function(e) { e.currentTarget.style.background = '#1f6feb'; },
          title: 'Copy the command the remote machine needs to run',
        }, '\u2398 Copy Remote Cmd'),
        h('div', {
          style: btnPrimaryStyle,
          onClick: executeLocal,
          onMouseEnter: function(e) { e.currentTarget.style.background = '#2ea043'; },
          onMouseLeave: function(e) { e.currentTarget.style.background = '#238636'; },
          title: 'Execute the local listener/sender in the active terminal',
        }, '\u25B6 Execute Local'),
        h('div', {
          style: btnWarningStyle,
          onClick: executeChecksum,
          onMouseEnter: function(e) { e.currentTarget.style.background = '#bb8009'; },
          onMouseLeave: function(e) { e.currentTarget.style.background = '#9e6a03'; },
          title: 'Run the checksum verification command in terminal',
        }, '\u2714 Verify Checksum'),
        h('div', {
          style: btnStyle,
          onClick: function() {
            if (st.generated) copyText(st.generated.localCmd);
            notify('Local command copied', 'success');
          },
          onMouseEnter: function(e) { e.currentTarget.style.background = '#30363d'; },
          onMouseLeave: function(e) { e.currentTarget.style.background = '#21262d'; },
        }, 'Copy Local Cmd'),
        h('div', {
          style: btnStyle,
          onClick: function() {
            if (st.generated) copyText(st.generated.checksumRemote);
            notify('Checksum command copied', 'success');
          },
          onMouseEnter: function(e) { e.currentTarget.style.background = '#30363d'; },
          onMouseLeave: function(e) { e.currentTarget.style.background = '#21262d'; },
        }, 'Copy Checksum Cmd')
      )
    );
  }

  // Transfer history
  if (st.history.length > 0) {
    children.push(
      h('div', { key: 'hist-title', style: Object.assign({}, sectionTitleStyle, { marginTop: '8px' }) },
        'Transfer History (' + st.history.length + ')'
      )
    );

    const histItems = st.history.map(function(entry, i) {
      const timeStr = new Date(entry.ts).toLocaleTimeString();
      const sslBadge = entry.ssl ? ' [SSL]' : '';
      const summary = entry.mode + sslBadge + '  ' + entry.filePath + '  \u2194  ' + entry.targetIp + ':' + entry.port;
      return h('div', {
        key: 'hist-' + i,
        style: historyItemStyle,
        onClick: function() {
          updateState({
            mode: MODE_LIST.find(function(m) { return m.label === entry.mode; }) || MODES.SEND_FILE,
            filePath: entry.filePath,
            port: entry.port,
            targetIp: entry.targetIp,
            useSSL: entry.ssl,
            generated: { localCmd: entry.localCmd, remoteCmd: entry.remoteCmd, checksumLocal: '', checksumRemote: '' },
          });
          // Re-generate to get checksum commands too
          setTimeout(generateCommands, 50);
        },
        onMouseEnter: function(e) { e.currentTarget.style.background = '#161b22'; },
        onMouseLeave: function(e) { e.currentTarget.style.background = 'transparent'; },
        title: 'Click to restore this transfer configuration',
      },
        h('span', { style: { color: '#484f58', fontSize: '9px', minWidth: '60px' } }, timeStr),
        h('span', { style: { color: entry.mode.includes('Send') ? '#3fb950' : '#f0883e' } },
          entry.mode.includes('Send') ? '\u2191' : '\u2193'
        ),
        h('span', null, summary)
      );
    });

    children.push(
      h('div', { key: 'hist-list', style: { maxHeight: '120px', overflowY: 'auto' } }, ...histItems)
    );

    // Clear history button
    children.push(
      h('div', { key: 'hist-clear', style: rowStyle },
        h('div', {
          style: Object.assign({}, btnStyle, { fontSize: '10px', padding: '2px 8px' }),
          onClick: function() { updateState({ history: [] }); notify('History cleared', 'info'); },
          onMouseEnter: function(e) { e.currentTarget.style.background = '#30363d'; },
          onMouseLeave: function(e) { e.currentTarget.style.background = '#21262d'; },
        }, 'Clear History')
      )
    );
  }

  return h('div', { style: containerStyle }, ...children);
}


// ══════════════════════════════════════════════════════════════
//  HUD TAB REGISTRATION
// ══════════════════════════════════════════════════════════════

let _hudRegistered = false;

function tryRegisterHud() {
  if (_hudRegistered) return;
  const recon = getRecon();
  if (recon.hud && typeof recon.hud.registerTab === 'function') {
    recon.hud.registerTab('file-shuttle', 'Transfer', null, function(React) {
      return renderShuttleTab(React);
    });
    _hudRegistered = true;
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

  return class ShuttleTerm extends React.Component {
    constructor(props) {
      super(props);
      this._onDecorated = this._onDecorated.bind(this);
    }

    _onDecorated(term) {
      if (this.props.onDecorated) this.props.onDecorated(term);

      // Attempt HUD registration once terminal is ready
      tryRegisterHud();

      // Also listen for late HUD ready event
      const recon = getRecon();
      if (!_hudRegistered) {
        const onReady = function() {
          tryRegisterHud();
          recon.events.removeListener('hud:ready', onReady);
        };
        recon.events.on('hud:ready', onReady);
      }

      // Wire up forced re-render for state changes
      if (!_renderCallback) {
        const self = this;
        _renderCallback = function() {
          // Force the HUD to re-render by emitting a panel update signal
          // The HUD framework re-calls renderFn on each React render cycle,
          // so we trigger that by toggling a badge
          const r = getRecon();
          if (r.hud && typeof r.hud.updateBadge === 'function') {
            r.hud.updateBadge('file-shuttle', shuttleState.generated ? null : null);
          }
          // Force component re-render for any wrapping component
          try { self.forceUpdate(); } catch (_) {}
        };
      }
    }

    render() {
      return React.createElement(Term, Object.assign({}, this.props, {
        onDecorated: this._onDecorated,
      }));
    }
  };
};
