'use strict';

// ======================================================================
//  HYPER SESSION SCRIBE
//  Records terminal sessions with timestamps, auto-annotations,
//  bookmarks, search, and export for evidence/reports.
//  Zero dependencies. Single file. React.createElement only.
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

// ------ Constants -----------------------------------------------------

const SESSIONS_DIR = path.join(os.homedir(), '.hyper_recon', 'sessions');
const INDEX_FILE = path.join(SESSIONS_DIR, 'index.json');
const MAX_MEMORY_LINES = 10000;
const FLUSH_THRESHOLD = 8000;
const FLUSH_INTERVAL = 30000;
const PROMPT_RE = /[$#%>]\s*$/;

// ------ ANSI Stripping -----------------------------------------------

function stripAnsi(str) {
  return str
    .replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '')
    .replace(/\x1b\][^\x07]*\x07/g, '')
    .replace(/\x1b\(B/g, '')
    .replace(/\r/g, '');
}

// ------ Filesystem Helpers --------------------------------------------

function ensureDir() {
  try {
    fs.mkdirSync(SESSIONS_DIR, { recursive: true });
  } catch (e) {
    // already exists
  }
}

function loadIndex() {
  try {
    const raw = fs.readFileSync(INDEX_FILE, 'utf8');
    return JSON.parse(raw);
  } catch {
    return { sessions: [] };
  }
}

function saveIndex(index) {
  ensureDir();
  try {
    fs.writeFileSync(INDEX_FILE, JSON.stringify(index, null, 2), 'utf8');
  } catch (e) {
    console.error('[session-scribe] Failed to save index:', e.message);
  }
}

function sessionFilePath(sessionId) {
  return path.join(SESSIONS_DIR, `${sessionId}.json`);
}

function loadSessionFromDisk(sessionId) {
  try {
    const raw = fs.readFileSync(sessionFilePath(sessionId), 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function saveSessionToDisk(session) {
  ensureDir();
  try {
    const data = {
      sessionId: session.sessionId,
      started: session.started,
      ended: session.ended,
      entries: session.flushedEntries.concat(session.entries),
    };
    fs.writeFileSync(sessionFilePath(session.sessionId), JSON.stringify(data, null, 2), 'utf8');
  } catch (e) {
    console.error('[session-scribe] Failed to save session:', e.message);
  }
}

// ------ UID Generation ------------------------------------------------

function uid() {
  const ts = Date.now().toString(36);
  const rand = Math.random().toString(36).slice(2, 8);
  return `scribe-${ts}-${rand}`;
}

// ------ Auto-Annotation Patterns --------------------------------------

const ANNOTATION_PATTERNS = [
  { regex: /nmap\s+-/i, label: 'Nmap scan started', type: 'scan_start' },
  { regex: /Nmap done:/i, label: 'Nmap scan completed', type: 'scan_complete' },
  { regex: /nikto\s+-h/i, label: 'Nikto scan started', type: 'scan_start' },
  { regex: /host\(s\)\s+tested/i, label: 'Nikto scan completed', type: 'scan_complete' },
  { regex: /gobuster\s+dir/i, label: 'Gobuster scan started', type: 'scan_start' },
  { regex: /Finished/i, label: 'Gobuster completed', type: 'scan_complete' },
  { regex: /sqlmap\s+/i, label: 'SQLMap started', type: 'scan_start' },
  { regex: /ffuf\s+-u/i, label: 'FFUF scan started', type: 'scan_start' },
  { regex: /hydra\s+/i, label: 'Hydra attack started', type: 'scan_start' },
  { regex: /masscan\s+/i, label: 'Masscan started', type: 'scan_start' },
  { regex: /\bVULNERABLE\b/i, label: 'Vulnerability detected', type: 'finding' },
  { regex: /\bCRITICAL\b.*found/i, label: 'Critical finding', type: 'finding' },
  { regex: /\bSQL\s*injection\b/i, label: 'SQL Injection detected', type: 'finding' },
  { regex: /\bXSS\b.*found/i, label: 'XSS detected', type: 'finding' },
  { regex: /\bRCE\b/i, label: 'RCE detected', type: 'finding' },
  { regex: /\bopen\s+\d+\/tcp\b/i, label: 'Open port found', type: 'finding' },
  { regex: /password\s*[:=]\s*\S+/i, label: 'Password exposure', type: 'secret' },
  { regex: /token\s*[:=]\s*\S+/i, label: 'Token exposure', type: 'secret' },
  { regex: /CVE-\d{4}-\d{4,}/i, label: 'CVE reference', type: 'finding' },
];

// ------ Session Manager -----------------------------------------------

const activeSessions = new Map();  // hyperUid -> scribe session
let currentHyperUid = null;

function createSession(hyperUid) {
  const session = {
    sessionId: uid(),
    hyperUid: hyperUid,
    started: Date.now(),
    ended: null,
    entries: [],
    flushedEntries: [],
    state: 'recording',    // 'recording' | 'paused' | 'stopped'
    bookmarkCount: 0,
    pendingLine: '',
    lastAnnotationTs: 0,
    flushTimer: null,
  };

  session.flushTimer = setInterval(() => flushSession(session), FLUSH_INTERVAL);
  activeSessions.set(hyperUid, session);
  updateIndex(session);
  return session;
}

function getSession(hyperUid) {
  return activeSessions.get(hyperUid);
}

function getCurrentSession() {
  if (!currentHyperUid) return null;
  return activeSessions.get(currentHyperUid);
}

function addEntry(session, entry) {
  if (!session || session.state !== 'recording') return;
  session.entries.push(entry);
  if (entry.type === 'bookmark') session.bookmarkCount++;

  // Memory management: flush to disk if too many entries in memory
  if (session.entries.length > MAX_MEMORY_LINES) {
    flushSession(session);
  }
}

function flushSession(session) {
  if (!session || session.entries.length < FLUSH_THRESHOLD / 2) return;

  // Move older entries to flushedEntries and save to disk
  const toFlush = session.entries.splice(0, session.entries.length - 1000);
  session.flushedEntries = session.flushedEntries.concat(toFlush);
  saveSessionToDisk(session);
}

function stopSession(session) {
  if (!session) return;
  session.state = 'stopped';
  session.ended = Date.now();
  if (session.flushTimer) {
    clearInterval(session.flushTimer);
    session.flushTimer = null;
  }
  saveSessionToDisk(session);
  updateIndex(session);
}

function updateIndex(session) {
  const index = loadIndex();
  const existing = index.sessions.findIndex(s => s.sessionId === session.sessionId);
  const meta = {
    sessionId: session.sessionId,
    started: session.started,
    ended: session.ended,
    state: session.state,
    bookmarkCount: session.bookmarkCount,
    entryCount: session.flushedEntries.length + session.entries.length,
  };
  if (existing >= 0) {
    index.sessions[existing] = meta;
  } else {
    index.sessions.unshift(meta);
  }
  // Keep index manageable
  if (index.sessions.length > 200) {
    index.sessions = index.sessions.slice(0, 200);
  }
  saveIndex(index);
}

function addBookmark(session, label, auto) {
  if (!session) return;
  const wasRecording = session.state;
  // Allow bookmarks even when paused
  const entry = {
    ts: Date.now(),
    type: 'bookmark',
    label: label,
    auto: !!auto,
  };
  // Directly push — bypass state check for bookmarks
  session.entries.push(entry);
  session.bookmarkCount++;
  session.state = wasRecording;  // Restore state
}

// ------ PTY Data Processing -------------------------------------------

function processPtyData(hyperUid, rawData) {
  const session = getSession(hyperUid);
  if (!session || session.state !== 'recording') return;

  const stripped = stripAnsi(rawData);
  const now = Date.now();

  // Split into lines
  const combined = session.pendingLine + stripped;
  const lines = combined.split('\n');
  session.pendingLine = lines.pop() || '';

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    // Detect commands (text after a prompt-like pattern)
    const promptMatch = trimmed.match(/^.*?[$#%>]\s*(.+)$/);
    if (promptMatch && promptMatch[1] && promptMatch[1].length > 1) {
      const cmd = promptMatch[1].trim();
      // Only record if it looks like an actual command (not just output)
      if (cmd.length < 500 && /^[a-zA-Z0-9./_\-]/.test(cmd)) {
        addEntry(session, { ts: now, type: 'command', content: cmd });
      }
    }

    // Store as data entry
    addEntry(session, { ts: now, type: 'data', content: trimmed });

    // Auto-annotations (debounced — at most one per pattern per 2 seconds)
    if (now - session.lastAnnotationTs > 2000) {
      for (const pattern of ANNOTATION_PATTERNS) {
        if (pattern.regex.test(trimmed)) {
          addBookmark(session, pattern.label, true);
          session.lastAnnotationTs = now;
          break;
        }
      }
    }
  }
}

// ------ Export Functions -----------------------------------------------

function getAllEntries(session) {
  if (!session) return [];
  // Combine flushed + in-memory
  const all = session.flushedEntries.concat(session.entries);
  // Also try to read from disk for stopped sessions
  if (session.state === 'stopped' && all.length === 0) {
    const fromDisk = loadSessionFromDisk(session.sessionId);
    if (fromDisk && fromDisk.entries) return fromDisk.entries;
  }
  return all;
}

function getAllEntriesById(sessionId) {
  // Check active sessions first
  for (const [, session] of activeSessions) {
    if (session.sessionId === sessionId) {
      return getAllEntries(session);
    }
  }
  // Load from disk
  const fromDisk = loadSessionFromDisk(sessionId);
  return fromDisk ? (fromDisk.entries || []) : [];
}

function getSessionMeta(sessionId) {
  for (const [, session] of activeSessions) {
    if (session.sessionId === sessionId) {
      return {
        sessionId: session.sessionId,
        started: session.started,
        ended: session.ended,
        state: session.state,
        bookmarkCount: session.bookmarkCount,
      };
    }
  }
  const fromDisk = loadSessionFromDisk(sessionId);
  if (fromDisk) {
    return {
      sessionId: fromDisk.sessionId,
      started: fromDisk.started,
      ended: fromDisk.ended,
      state: 'stopped',
      bookmarkCount: (fromDisk.entries || []).filter(e => e.type === 'bookmark').length,
    };
  }
  return null;
}

function formatTimestamp(ts) {
  const d = new Date(ts);
  return d.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, '');
}

function formatDuration(ms) {
  if (!ms || ms < 0) return '0s';
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  const h = Math.floor(m / 60);
  if (h > 0) return `${h}h ${m % 60}m ${s % 60}s`;
  if (m > 0) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

function exportTxt(sessionId) {
  const entries = getAllEntriesById(sessionId);
  const meta = getSessionMeta(sessionId);
  if (!meta) return '';

  const lines = [];
  lines.push(`Session: ${meta.sessionId}`);
  lines.push(`Started: ${formatTimestamp(meta.started)}`);
  if (meta.ended) lines.push(`Ended: ${formatTimestamp(meta.ended)}`);
  lines.push(`Duration: ${formatDuration((meta.ended || Date.now()) - meta.started)}`);
  lines.push('='.repeat(72));
  lines.push('');

  for (const e of entries) {
    const ts = formatTimestamp(e.ts);
    switch (e.type) {
      case 'bookmark':
        lines.push(`[${ts}] *** BOOKMARK: ${e.label} ${e.auto ? '(auto)' : '(manual)'} ***`);
        break;
      case 'command':
        lines.push(`[${ts}] $ ${e.content}`);
        break;
      case 'data':
        lines.push(`[${ts}]   ${e.content}`);
        break;
    }
  }

  return lines.join('\n');
}

function exportMarkdown(sessionId) {
  const entries = getAllEntriesById(sessionId);
  const meta = getSessionMeta(sessionId);
  if (!meta) return '';

  const lines = [];
  lines.push(`# Session Recording: ${meta.sessionId}`);
  lines.push('');
  lines.push(`| Field | Value |`);
  lines.push(`|-------|-------|`);
  lines.push(`| Started | ${formatTimestamp(meta.started)} |`);
  if (meta.ended) lines.push(`| Ended | ${formatTimestamp(meta.ended)} |`);
  lines.push(`| Duration | ${formatDuration((meta.ended || Date.now()) - meta.started)} |`);
  lines.push(`| Bookmarks | ${meta.bookmarkCount} |`);
  lines.push('');

  // Table of contents from bookmarks
  const bookmarks = entries.filter(e => e.type === 'bookmark');
  if (bookmarks.length > 0) {
    lines.push('## Bookmarks');
    lines.push('');
    for (let i = 0; i < bookmarks.length; i++) {
      const b = bookmarks[i];
      lines.push(`${i + 1}. **${b.label}** - ${formatTimestamp(b.ts)} ${b.auto ? '_(auto)_' : '_(manual)_'}`);
    }
    lines.push('');
  }

  // Sections around each bookmark
  lines.push('## Session Log');
  lines.push('');

  let bookmarkIndex = 0;
  let inSection = false;

  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (e.type === 'bookmark') {
      bookmarkIndex++;
      if (inSection) {
        lines.push('```');
        lines.push('');
      }
      lines.push(`### Bookmark ${bookmarkIndex}: ${e.label}`);
      lines.push(`> ${formatTimestamp(e.ts)} ${e.auto ? '(auto-detected)' : '(manual)'}`);
      lines.push('');
      lines.push('```');
      inSection = true;

      // Show surrounding context (5 entries before this bookmark)
      const contextStart = Math.max(0, i - 5);
      for (let j = contextStart; j < i; j++) {
        const ce = entries[j];
        if (ce.type === 'data') lines.push(`  ${ce.content}`);
        if (ce.type === 'command') lines.push(`$ ${ce.content}`);
      }

      // Show next 10 entries after bookmark
      const contextEnd = Math.min(entries.length, i + 11);
      for (let j = i + 1; j < contextEnd; j++) {
        const ce = entries[j];
        if (ce.type === 'bookmark') break;
        if (ce.type === 'data') lines.push(`  ${ce.content}`);
        if (ce.type === 'command') lines.push(`$ ${ce.content}`);
      }
    }
  }

  if (inSection) {
    lines.push('```');
    lines.push('');
  }

  // Full raw log
  lines.push('## Full Log');
  lines.push('');
  lines.push('```');
  for (const e of entries) {
    const ts = formatTimestamp(e.ts);
    if (e.type === 'bookmark') lines.push(`[${ts}] *** ${e.label} ***`);
    else if (e.type === 'command') lines.push(`[${ts}] $ ${e.content}`);
    else lines.push(`[${ts}]   ${e.content}`);
  }
  lines.push('```');

  return lines.join('\n');
}

function exportRaw(sessionId) {
  const entries = getAllEntriesById(sessionId);
  const lines = [];

  for (const e of entries) {
    if (e.type === 'data' || e.type === 'command') {
      lines.push(e.content);
    }
  }

  return lines.join('\n');
}

function searchSessions(query) {
  if (!query || query.length < 2) return [];

  const results = [];
  const lowerQuery = query.toLowerCase();
  const index = loadIndex();

  for (const meta of index.sessions.slice(0, 50)) {
    const entries = getAllEntriesById(meta.sessionId);
    const matches = [];

    for (let i = 0; i < entries.length; i++) {
      const e = entries[i];
      const text = e.content || e.label || '';
      if (text.toLowerCase().includes(lowerQuery)) {
        matches.push({ index: i, entry: e });
        if (matches.length >= 10) break;
      }
    }

    if (matches.length > 0) {
      results.push({ sessionId: meta.sessionId, started: meta.started, matches });
    }
    if (results.length >= 20) break;
  }

  return results;
}

// ------ File Save Dialog -----------------------------------------------

function saveToFile(content, defaultName) {
  const { dialog } = require('electron').remote || require('@electron/remote') || {};
  if (dialog) {
    try {
      const result = dialog.showSaveDialogSync({
        defaultPath: path.join(os.homedir(), defaultName),
        filters: [
          { name: 'All Files', extensions: ['*'] },
        ],
      });
      if (result) {
        fs.writeFileSync(result, content, 'utf8');
        const recon = getRecon();
        if (recon.hud) recon.hud.notify(`Exported to ${path.basename(result)}`, 'info');
        return true;
      }
    } catch (e) {
      // Fallback: save to home directory
    }
  }

  // Fallback: save to ~/.hyper_recon/exports/
  const exportDir = path.join(os.homedir(), '.hyper_recon', 'exports');
  try { fs.mkdirSync(exportDir, { recursive: true }); } catch {}
  const filePath = path.join(exportDir, defaultName);
  fs.writeFileSync(filePath, content, 'utf8');
  const recon = getRecon();
  if (recon.hud) recon.hud.notify(`Saved to ${filePath}`, 'info');
  return true;
}


// ======================================================================
//  HUD TAB — Session Scribe Panel
// ======================================================================

let _hudRegistered = false;
let _forceRender = null;

function registerHudTab() {
  const recon = getRecon();
  if (!recon.hud || _hudRegistered) return;
  _hudRegistered = true;

  recon.hud.registerTab('session-scribe', 'Scribe', null, (React) => {
    return React.createElement(ScribePanel, { React });
  });

  // Update badge when recording
  setInterval(() => {
    const session = getCurrentSession();
    if (session && session.state === 'recording') {
      recon.hud.updateBadge('session-scribe', 'REC');
    } else if (session && session.state === 'paused') {
      recon.hud.updateBadge('session-scribe', 'II');
    } else {
      recon.hud.updateBadge('session-scribe', null);
    }
  }, 2000);
}

// ------ Scribe Panel Component ----------------------------------------

function ScribePanel({ React }) {
  // This is a render function, so we build the UI tree with createElement
  return React.createElement(ScribePanelClass, { React });
}

class ScribePanelInner {
  // This is managed manually since we're using createElement
}

// We'll use a stateful approach with a wrapper
function makeScribePanel(React) {
  return class ScribePanelImpl extends React.Component {
    constructor(props) {
      super(props);
      this.state = {
        view: 'main',        // 'main' | 'detail' | 'search'
        selectedSession: null,
        selectedBookmark: null,
        searchQuery: '',
        searchResults: [],
        bookmarkLabel: '',
        showBookmarkInput: false,
        tick: 0,
      };
      this._timer = null;
      _forceRender = () => this.setState(prev => ({ tick: prev.tick + 1 }));
    }

    componentDidMount() {
      this._timer = setInterval(() => {
        this.setState(prev => ({ tick: prev.tick + 1 }));
      }, 2000);
    }

    componentWillUnmount() {
      if (this._timer) clearInterval(this._timer);
      _forceRender = null;
    }

    _renderStatus(session) {
      const R = React.createElement;
      if (!session) {
        return R('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' } },
          R('span', { style: { color: '#6e7681', fontSize: '11px' } }, 'No active recording'),
          R('button', {
            style: btnStyle('#238636'),
            onClick: () => {
              if (currentHyperUid) {
                const s = createSession(currentHyperUid);
                this.forceUpdate();
              }
            },
          }, 'Record')
        );
      }

      const stateColors = { recording: '#da3633', paused: '#d29922', stopped: '#6e7681' };
      const stateLabels = { recording: 'REC', paused: 'PAUSED', stopped: 'STOPPED' };
      const dotColor = stateColors[session.state] || '#6e7681';
      const elapsed = formatDuration((session.ended || Date.now()) - session.started);

      return R('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px', flexWrap: 'wrap' } },
        // Status indicator
        R('span', { style: { display: 'flex', alignItems: 'center', gap: '4px' } },
          R('span', {
            style: {
              width: '8px', height: '8px', borderRadius: '50%',
              background: dotColor, display: 'inline-block',
              animation: session.state === 'recording' ? 'scribePulse 1.5s ease infinite' : 'none',
            },
          }),
          R('span', {
            style: { color: dotColor, fontWeight: 700, fontSize: '11px', letterSpacing: '0.5px' },
          }, stateLabels[session.state])
        ),

        // Duration
        R('span', { style: { color: '#8b949e', fontSize: '11px' } }, elapsed),

        // Entry count
        R('span', { style: { color: '#6e7681', fontSize: '10px' } },
          `${session.flushedEntries.length + session.entries.length} entries`
        ),

        // Bookmark count
        R('span', { style: { color: '#d29922', fontSize: '10px' } },
          `${session.bookmarkCount} bookmarks`
        ),

        // Spacer
        R('div', { style: { flex: 1 } }),

        // Controls
        session.state === 'recording' && R('button', {
          style: btnStyle('#d29922'),
          onClick: () => { session.state = 'paused'; this.forceUpdate(); },
        }, 'Pause'),

        session.state === 'paused' && R('button', {
          style: btnStyle('#238636'),
          onClick: () => { session.state = 'recording'; this.forceUpdate(); },
        }, 'Resume'),

        session.state !== 'stopped' && R('button', {
          style: btnStyle('#da3633'),
          onClick: () => { stopSession(session); this.forceUpdate(); },
        }, 'Stop'),

        R('button', {
          style: btnStyle('#1f6feb'),
          onClick: () => {
            this.setState({ showBookmarkInput: !this.state.showBookmarkInput });
          },
        }, 'Bookmark'),
      );
    }

    _renderBookmarkInput(session) {
      const R = React.createElement;
      if (!this.state.showBookmarkInput) return null;

      return R('div', {
        style: {
          display: 'flex', gap: '6px', marginBottom: '8px',
          padding: '6px 8px', background: '#161b22', borderRadius: '6px',
          border: '1px solid #30363d',
        },
      },
        R('input', {
          type: 'text',
          placeholder: 'Bookmark label...',
          value: this.state.bookmarkLabel,
          onChange: (e) => this.setState({ bookmarkLabel: e.target.value }),
          onKeyDown: (e) => {
            if (e.key === 'Enter' && this.state.bookmarkLabel.trim()) {
              addBookmark(session, this.state.bookmarkLabel.trim(), false);
              this.setState({ bookmarkLabel: '', showBookmarkInput: false });
            }
            if (e.key === 'Escape') {
              this.setState({ showBookmarkInput: false, bookmarkLabel: '' });
            }
          },
          style: {
            flex: 1, background: '#0d1117', border: '1px solid #30363d',
            borderRadius: '4px', padding: '4px 8px', color: '#c9d1d9',
            fontSize: '11px', outline: 'none', fontFamily: 'inherit',
          },
        }),
        R('button', {
          style: btnStyle('#238636'),
          onClick: () => {
            if (this.state.bookmarkLabel.trim()) {
              addBookmark(session, this.state.bookmarkLabel.trim(), false);
              this.setState({ bookmarkLabel: '', showBookmarkInput: false });
            }
          },
        }, 'Add'),
      );
    }

    _renderTimeline(session) {
      const R = React.createElement;
      if (!session) return null;

      const allEntries = session.entries.slice(-200);
      const bookmarks = allEntries.filter(e => e.type === 'bookmark');
      if (bookmarks.length === 0) {
        return R('div', { style: { color: '#6e7681', fontSize: '10px', marginBottom: '8px' } },
          'No bookmarks yet'
        );
      }

      const started = session.started;
      const now = session.ended || Date.now();
      const duration = now - started;

      return R('div', {
        style: {
          position: 'relative', height: '24px', background: '#161b22',
          borderRadius: '4px', marginBottom: '8px', overflow: 'hidden',
          border: '1px solid #21262d',
        },
      },
        // Timeline bar
        R('div', {
          style: {
            position: 'absolute', top: '11px', left: '4px', right: '4px',
            height: '2px', background: '#30363d',
          },
        }),
        // Bookmark markers
        ...bookmarks.map((b, i) => {
          const pos = duration > 0 ? ((b.ts - started) / duration) * 100 : 50;
          const clampedPos = Math.max(2, Math.min(98, pos));
          return R('div', {
            key: i,
            title: `${b.label} (${formatTimestamp(b.ts)})`,
            onClick: () => this.setState({ selectedBookmark: b }),
            style: {
              position: 'absolute',
              left: `${clampedPos}%`,
              top: '5px',
              width: '8px', height: '14px',
              background: b.auto ? '#d29922' : '#58a6ff',
              borderRadius: '2px',
              cursor: 'pointer',
              transform: 'translateX(-4px)',
              transition: 'transform 0.1s',
              zIndex: 5,
            },
            onMouseEnter: (e) => { e.target.style.transform = 'translateX(-4px) scale(1.3)'; },
            onMouseLeave: (e) => { e.target.style.transform = 'translateX(-4px)'; },
          });
        })
      );
    }

    _renderBookmarkDetail() {
      const R = React.createElement;
      const b = this.state.selectedBookmark;
      if (!b) return null;

      const session = getCurrentSession() || this._getSelectedSessionObj();
      if (!session) return null;

      const allEntries = getAllEntries(session) || getAllEntriesById(session.sessionId);
      const idx = allEntries.findIndex(e => e.ts === b.ts && e.type === 'bookmark' && e.label === b.label);
      const contextStart = Math.max(0, idx - 10);
      const contextEnd = Math.min(allEntries.length, idx + 11);
      const context = allEntries.slice(contextStart, contextEnd);

      return R('div', {
        style: {
          background: '#161b22', borderRadius: '6px', padding: '8px',
          marginBottom: '8px', border: '1px solid #30363d',
        },
      },
        R('div', { style: { display: 'flex', justifyContent: 'space-between', marginBottom: '6px' } },
          R('span', { style: { color: '#d29922', fontWeight: 700, fontSize: '11px' } },
            `Bookmark: ${b.label}`
          ),
          R('span', {
            style: { color: '#6e7681', fontSize: '10px', cursor: 'pointer' },
            onClick: () => this.setState({ selectedBookmark: null }),
          }, 'Close')
        ),
        R('div', { style: { color: '#8b949e', fontSize: '10px', marginBottom: '6px' } },
          `${formatTimestamp(b.ts)} | ${b.auto ? 'Auto-detected' : 'Manual'}`
        ),
        R('div', {
          style: {
            background: '#0d1117', borderRadius: '4px', padding: '6px',
            maxHeight: '120px', overflowY: 'auto', fontFamily: 'monospace',
            fontSize: '10px', lineHeight: '1.5',
          },
        },
          ...context.map((e, i) => {
            let color = '#8b949e';
            let prefix = '  ';
            if (e.type === 'bookmark') { color = '#d29922'; prefix = '** '; }
            else if (e.type === 'command') { color = '#58a6ff'; prefix = '$ '; }
            return R('div', { key: i, style: { color } }, prefix + (e.content || e.label || ''));
          })
        )
      );
    }

    _getSelectedSessionObj() {
      if (!this.state.selectedSession) return null;
      for (const [, session] of activeSessions) {
        if (session.sessionId === this.state.selectedSession) return session;
      }
      return { sessionId: this.state.selectedSession };
    }

    _renderSessionList() {
      const R = React.createElement;
      const index = loadIndex();
      const sessions = index.sessions || [];

      if (sessions.length === 0) {
        return R('div', { style: { color: '#6e7681', fontSize: '11px' } },
          'No recorded sessions yet.'
        );
      }

      return R('div', { style: { maxHeight: '200px', overflowY: 'auto' } },
        ...sessions.slice(0, 30).map((meta, i) => {
          const isActive = activeSessions.has(meta.sessionId);
          const duration = formatDuration(((meta.ended || Date.now()) - meta.started));
          const date = formatTimestamp(meta.started);
          const selected = this.state.selectedSession === meta.sessionId;

          return R('div', {
            key: meta.sessionId,
            onClick: () => this.setState({
              view: 'detail',
              selectedSession: meta.sessionId,
              selectedBookmark: null,
            }),
            style: {
              display: 'flex', alignItems: 'center', gap: '8px',
              padding: '5px 8px', cursor: 'pointer',
              background: selected ? '#161b22' : 'transparent',
              borderRadius: '4px', borderLeft: selected ? '2px solid #58a6ff' : '2px solid transparent',
              marginBottom: '2px',
            },
            onMouseEnter: (e) => { if (!selected) e.currentTarget.style.background = '#0d1117'; },
            onMouseLeave: (e) => { if (!selected) e.currentTarget.style.background = 'transparent'; },
          },
            // State dot
            R('span', {
              style: {
                width: '6px', height: '6px', borderRadius: '50%',
                background: meta.state === 'recording' ? '#da3633' :
                            meta.state === 'paused' ? '#d29922' : '#30363d',
                flexShrink: 0,
              },
            }),
            // Date
            R('span', { style: { color: '#c9d1d9', fontSize: '10px', width: '130px', flexShrink: 0 } }, date),
            // Duration
            R('span', { style: { color: '#8b949e', fontSize: '10px', width: '60px', flexShrink: 0 } }, duration),
            // Bookmarks
            R('span', { style: { color: '#d29922', fontSize: '10px' } },
              `${meta.bookmarkCount || 0} bookmarks`
            ),
            // Entries
            R('span', { style: { color: '#6e7681', fontSize: '10px' } },
              `${meta.entryCount || 0} entries`
            ),
          );
        })
      );
    }

    _renderDetailView() {
      const R = React.createElement;
      const sessionId = this.state.selectedSession;
      if (!sessionId) return null;

      const meta = getSessionMeta(sessionId);
      if (!meta) {
        return R('div', { style: { color: '#da3633', fontSize: '11px' } }, 'Session not found');
      }

      const entries = getAllEntriesById(sessionId);
      const bookmarks = entries.filter(e => e.type === 'bookmark');

      return R('div', null,
        // Header
        R('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' } },
          R('span', {
            style: { color: '#58a6ff', fontSize: '11px', cursor: 'pointer' },
            onClick: () => this.setState({ view: 'main', selectedSession: null, selectedBookmark: null }),
          }, 'Back'),
          R('span', { style: { color: '#6e7681' } }, '|'),
          R('span', { style: { color: '#c9d1d9', fontSize: '11px', fontWeight: 600 } },
            `Session: ${sessionId.slice(0, 20)}...`
          ),
        ),

        // Meta
        R('div', {
          style: {
            display: 'flex', gap: '16px', marginBottom: '8px',
            fontSize: '10px', color: '#8b949e',
          },
        },
          R('span', null, `Started: ${formatTimestamp(meta.started)}`),
          meta.ended && R('span', null, `Ended: ${formatTimestamp(meta.ended)}`),
          R('span', null, `Duration: ${formatDuration((meta.ended || Date.now()) - meta.started)}`),
          R('span', null, `Entries: ${entries.length}`),
          R('span', null, `Bookmarks: ${bookmarks.length}`),
        ),

        // Export buttons
        R('div', { style: { display: 'flex', gap: '6px', marginBottom: '8px' } },
          R('button', {
            style: btnStyle('#1f6feb'),
            onClick: () => {
              const content = exportTxt(sessionId);
              saveToFile(content, `session-${sessionId}.txt`);
            },
          }, 'Export TXT'),
          R('button', {
            style: btnStyle('#8b5cf6'),
            onClick: () => {
              const content = exportMarkdown(sessionId);
              saveToFile(content, `session-${sessionId}.md`);
            },
          }, 'Export MD'),
          R('button', {
            style: btnStyle('#6e7681'),
            onClick: () => {
              const content = exportRaw(sessionId);
              saveToFile(content, `session-${sessionId}.raw.txt`);
            },
          }, 'Export Raw'),
        ),

        // Bookmark detail (if selected)
        this._renderBookmarkDetail(),

        // Bookmarks list
        bookmarks.length > 0 && R('div', { style: { marginBottom: '8px' } },
          R('div', { style: { color: '#c9d1d9', fontSize: '11px', fontWeight: 600, marginBottom: '4px' } },
            'Bookmarks'
          ),
          R('div', {
            style: {
              maxHeight: '120px', overflowY: 'auto', background: '#161b22',
              borderRadius: '4px', border: '1px solid #21262d',
            },
          },
            ...bookmarks.map((b, i) => {
              return R('div', {
                key: i,
                onClick: () => this.setState({ selectedBookmark: b }),
                style: {
                  display: 'flex', alignItems: 'center', gap: '6px',
                  padding: '4px 8px', cursor: 'pointer', fontSize: '10px',
                  borderBottom: '1px solid #21262d',
                },
                onMouseEnter: (e) => { e.currentTarget.style.background = '#0d1117'; },
                onMouseLeave: (e) => { e.currentTarget.style.background = 'transparent'; },
              },
                R('span', {
                  style: {
                    width: '6px', height: '6px', borderRadius: '50%',
                    background: b.auto ? '#d29922' : '#58a6ff',
                    flexShrink: 0,
                  },
                }),
                R('span', { style: { color: '#c9d1d9' } }, b.label),
                R('span', { style: { color: '#6e7681', marginLeft: 'auto' } }, formatTimestamp(b.ts)),
              );
            })
          )
        ),

        // Recent log tail
        R('div', { style: { color: '#c9d1d9', fontSize: '11px', fontWeight: 600, marginBottom: '4px' } },
          'Session Output (last 50 lines)'
        ),
        R('div', {
          style: {
            background: '#0d1117', borderRadius: '4px', padding: '6px',
            maxHeight: '150px', overflowY: 'auto', fontFamily: 'monospace',
            fontSize: '10px', lineHeight: '1.5', border: '1px solid #21262d',
          },
        },
          ...entries.slice(-50).map((e, i) => {
            let color = '#8b949e';
            let text = '';
            if (e.type === 'bookmark') {
              color = '#d29922';
              text = `*** ${e.label} ***`;
            } else if (e.type === 'command') {
              color = '#58a6ff';
              text = `$ ${e.content}`;
            } else {
              text = e.content || '';
            }
            return R('div', { key: i, style: { color, whiteSpace: 'pre-wrap', wordBreak: 'break-all' } }, text);
          })
        )
      );
    }

    _renderSearchView() {
      const R = React.createElement;

      return R('div', null,
        R('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' } },
          R('span', {
            style: { color: '#58a6ff', fontSize: '11px', cursor: 'pointer' },
            onClick: () => this.setState({ view: 'main', searchResults: [], searchQuery: '' }),
          }, 'Back'),
          R('span', { style: { color: '#c9d1d9', fontSize: '11px', fontWeight: 600 } }, 'Search Sessions'),
        ),
        R('div', { style: { display: 'flex', gap: '6px', marginBottom: '8px' } },
          R('input', {
            type: 'text',
            placeholder: 'Search session content...',
            value: this.state.searchQuery,
            onChange: (e) => this.setState({ searchQuery: e.target.value }),
            onKeyDown: (e) => {
              if (e.key === 'Enter') {
                const results = searchSessions(this.state.searchQuery);
                this.setState({ searchResults: results });
              }
            },
            style: {
              flex: 1, background: '#0d1117', border: '1px solid #30363d',
              borderRadius: '4px', padding: '4px 8px', color: '#c9d1d9',
              fontSize: '11px', outline: 'none', fontFamily: 'inherit',
            },
          }),
          R('button', {
            style: btnStyle('#1f6feb'),
            onClick: () => {
              const results = searchSessions(this.state.searchQuery);
              this.setState({ searchResults: results });
            },
          }, 'Search'),
        ),

        // Results
        this.state.searchResults.length > 0 && R('div', {
          style: { maxHeight: '250px', overflowY: 'auto' },
        },
          ...this.state.searchResults.map((result, ri) => {
            return R('div', {
              key: ri,
              style: {
                background: '#161b22', borderRadius: '4px', padding: '6px 8px',
                marginBottom: '6px', border: '1px solid #21262d',
              },
            },
              R('div', {
                style: {
                  display: 'flex', justifyContent: 'space-between', marginBottom: '4px',
                  alignItems: 'center',
                },
              },
                R('span', {
                  style: { color: '#58a6ff', fontSize: '10px', cursor: 'pointer' },
                  onClick: () => this.setState({
                    view: 'detail',
                    selectedSession: result.sessionId,
                  }),
                }, `Session: ${result.sessionId.slice(0, 24)}...`),
                R('span', { style: { color: '#6e7681', fontSize: '10px' } },
                  formatTimestamp(result.started)
                ),
              ),
              ...result.matches.slice(0, 5).map((m, mi) => {
                const text = m.entry.content || m.entry.label || '';
                const lower = text.toLowerCase();
                const qLower = this.state.searchQuery.toLowerCase();
                const idx = lower.indexOf(qLower);
                const before = text.slice(Math.max(0, idx - 30), idx);
                const match = text.slice(idx, idx + this.state.searchQuery.length);
                const after = text.slice(idx + this.state.searchQuery.length, idx + this.state.searchQuery.length + 30);

                return R('div', {
                  key: mi,
                  style: {
                    fontFamily: 'monospace', fontSize: '10px', color: '#8b949e',
                    padding: '2px 4px', whiteSpace: 'nowrap', overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  },
                },
                  R('span', null, before),
                  R('span', { style: { background: '#d29922', color: '#000', borderRadius: '2px', padding: '0 2px' } }, match),
                  R('span', null, after),
                );
              })
            );
          })
        ),

        this.state.searchResults.length === 0 && this.state.searchQuery.length > 0 && R('div', {
          style: { color: '#6e7681', fontSize: '11px', textAlign: 'center', padding: '20px' },
        }, 'No results found. Press Enter or click Search to search.'),
      );
    }

    render() {
      const R = React.createElement;
      const session = getCurrentSession();

      if (this.state.view === 'detail') return this._renderDetailView();
      if (this.state.view === 'search') return this._renderSearchView();

      return R('div', { style: { display: 'flex', flexDirection: 'column', height: '100%' } },
        // Status + controls
        this._renderStatus(session),

        // Bookmark input
        session && this._renderBookmarkInput(session),

        // Timeline
        session && this._renderTimeline(session),

        // Bookmark detail
        this._renderBookmarkDetail(),

        // Action row
        R('div', { style: { display: 'flex', gap: '6px', marginBottom: '8px' } },
          R('button', {
            style: btnStyle('#1f6feb'),
            onClick: () => this.setState({ view: 'search' }),
          }, 'Search'),
          session && session.state !== 'stopped' && R('button', {
            style: btnStyle('#238636'),
            onClick: () => {
              if (currentHyperUid && !getSession(currentHyperUid)) {
                createSession(currentHyperUid);
              }
              this.forceUpdate();
            },
          }, 'New Session'),
          session && R('button', {
            style: btnStyle('#8b5cf6'),
            onClick: () => {
              const content = exportTxt(session.sessionId);
              saveToFile(content, `session-${session.sessionId}.txt`);
            },
          }, 'Export TXT'),
          session && R('button', {
            style: btnStyle('#d29922'),
            onClick: () => {
              const content = exportMarkdown(session.sessionId);
              saveToFile(content, `session-${session.sessionId}.md`);
            },
          }, 'Export MD'),
        ),

        // Current session live tail (if recording)
        session && R('div', {
          style: {
            flex: 1, background: '#0d1117', borderRadius: '4px', padding: '6px',
            overflowY: 'auto', fontFamily: 'monospace', fontSize: '10px',
            lineHeight: '1.5', border: '1px solid #21262d', minHeight: '60px',
          },
        },
          ...session.entries.slice(-30).map((e, i) => {
            let color = '#8b949e';
            let text = '';
            if (e.type === 'bookmark') {
              color = '#d29922';
              text = `*** ${e.label} ***`;
            } else if (e.type === 'command') {
              color = '#58a6ff';
              text = `$ ${e.content}`;
            } else {
              text = e.content || '';
            }
            return R('div', {
              key: i,
              style: { color, whiteSpace: 'pre-wrap', wordBreak: 'break-all' },
            }, text);
          })
        ),

        // Session list header
        R('div', {
          style: {
            color: '#c9d1d9', fontSize: '11px', fontWeight: 600,
            marginTop: '8px', marginBottom: '4px',
          },
        }, 'Recorded Sessions'),

        // Session list
        this._renderSessionList(),
      );
    }
  };
}

// Singleton class cache
let _ScribePanelClass = null;
function ScribePanelClass(props) {
  // Lazy-create the class with React reference
  const React = props.React;
  if (!_ScribePanelClass) {
    _ScribePanelClass = makeScribePanel(React);
  }
  return React.createElement(_ScribePanelClass, props);
}

// ------ Button Style Helper -------------------------------------------

function btnStyle(bg) {
  return {
    background: bg,
    color: '#fff',
    border: 'none',
    borderRadius: '4px',
    padding: '3px 10px',
    fontSize: '10px',
    fontWeight: 600,
    cursor: 'pointer',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    lineHeight: '18px',
    whiteSpace: 'nowrap',
  };
}


// ======================================================================
//  PLUGIN EXPORTS
// ======================================================================

// ------ Middleware: Intercept PTY data & session events ----------------

exports.middleware = (store) => (next) => (action) => {
  const recon = getRecon();

  switch (action.type) {
    case 'SESSION_SET_ACTIVE':
      currentHyperUid = action.uid;
      break;

    case 'SESSION_ADD':
      if (!currentHyperUid) currentHyperUid = action.uid;
      // Auto-start recording for new sessions
      if (!getSession(action.uid)) {
        createSession(action.uid);
      }
      break;

    case 'SESSION_PTY_DATA':
      processPtyData(action.uid, action.data);
      break;

    case 'SESSION_PTY_EXIT':
    case 'SESSION_USER_EXIT': {
      const session = getSession(action.uid);
      if (session) {
        stopSession(session);
        activeSessions.delete(action.uid);
      }
      if (action.uid === currentHyperUid) currentHyperUid = null;
      break;
    }
  }

  return next(action);
};

// ------ decorateHyper: Register HUD tab on load -----------------------

exports.decorateHyper = (Hyper, { React }) => {
  return class ScribeHyper extends React.Component {
    componentDidMount() {
      const recon = getRecon();

      // Register once HUD is ready
      const tryRegister = () => {
        if (recon.hud) {
          registerHudTab();
        }
      };

      tryRegister();
      recon.events.on('hud:ready', tryRegister);

      // Listen for findings to auto-bookmark
      recon.events.on('finding:new', (finding) => {
        const session = getCurrentSession();
        if (session) addBookmark(session, `Finding: ${finding.title || finding.type || 'Unknown'}`, true);
      });

      recon.events.on('secret:found', (secret) => {
        const session = getCurrentSession();
        if (session) addBookmark(session, `Secret detected: ${secret.type || 'Unknown'}`, true);
      });

      recon.events.on('scan:started', (scan) => {
        const session = getCurrentSession();
        if (session) addBookmark(session, `Scan started: ${scan.tool || scan.name || 'Unknown'}`, true);
      });

      recon.events.on('scan:completed', (scan) => {
        const session = getCurrentSession();
        if (session) addBookmark(session, `Scan completed: ${scan.tool || scan.name || 'Unknown'}`, true);
      });

      // Inject CSS animation for the recording pulse
      if (!document.getElementById('scribe-style')) {
        const style = document.createElement('style');
        style.id = 'scribe-style';
        style.textContent = `
          @keyframes scribePulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
          }
        `;
        document.head.appendChild(style);
      }
    }

    render() {
      return React.createElement(Hyper, this.props);
    }
  };
};

// ------ decorateKeymaps: Ctrl+Shift+B for bookmark --------------------

exports.decorateKeymaps = (keymaps) => {
  return Object.assign({}, keymaps, {
    'scribe:bookmark': 'ctrl+shift+b',
  });
};

// ------ onRendererWindow: Global keyboard listener --------------------

exports.onRendererWindow = (win) => {
  // Ensure sessions directory exists
  ensureDir();

  // Listen for the bookmark hotkey via keydown (fallback if decorateKeymaps
  // doesn't trigger the Hyper command system properly)
  win.document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.shiftKey && e.key === 'B') {
      e.preventDefault();
      const session = getCurrentSession();
      if (!session) return;

      // Prompt for label using a simple approach
      const label = win.prompt('Bookmark label:');
      if (label && label.trim()) {
        addBookmark(session, label.trim(), false);
        if (_forceRender) _forceRender();
        const recon = getRecon();
        if (recon.hud) recon.hud.notify(`Bookmark added: ${label.trim()}`, 'info');
      }
    }
  });
};
