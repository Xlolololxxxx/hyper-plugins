'use strict';

// ══════════════════════════════════════════════════════════════
//  HYPER HUD FRAMEWORK
//  Shared bottom bar + event bus for Hyper security plugins
//  Other plugins register tabs via window.__hyperRecon.hud
// ══════════════════════════════════════════════════════════════

const EventEmitter = require('events');

// ─── Shared Namespace ────────────────────────────────────────
function initRecon() {
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

// ─── Session Tracking ────────────────────────────────────────
let activeUid = null;

exports.middleware = (store) => (next) => (action) => {
  const recon = initRecon();
  switch (action.type) {
    case 'SESSION_SET_ACTIVE':
      activeUid = action.uid;
      recon.activeUid = action.uid;
      recon.events.emit('session:active', action.uid);
      break;
    case 'SESSION_ADD':
      if (!activeUid) { activeUid = action.uid; recon.activeUid = action.uid; }
      recon.sessions.set(action.uid, { started: Date.now() });
      recon.events.emit('session:add', action.uid);
      break;
    case 'SESSION_PTY_DATA':
      recon.events.emit('pty:data', { uid: action.uid, data: action.data });
      break;
    case 'SESSION_PTY_EXIT':
    case 'SESSION_USER_EXIT':
      if (action.uid === activeUid) { activeUid = null; recon.activeUid = null; }
      recon.sessions.delete(action.uid);
      recon.events.emit('session:exit', action.uid);
      break;
  }
  return next(action);
};

// ─── Exec helper exposed globally ────────────────────────────
function execInTerminal(cmd, uid) {
  const target = uid || activeUid;
  if (!target) return;
  window.rpc.emit('data', { uid: target, data: cmd + '\n', escaped: false });
}

// ══════════════════════════════════════════════════════════════
//  HUD BAR — React component added to Hyper footer
// ══════════════════════════════════════════════════════════════

exports.decorateHyper = (Hyper, { React }) => {
  return class HudHyper extends React.Component {
    constructor(props) {
      super(props);
      this.state = {
        tabs: [],
        activeTab: null,
        collapsed: true,
        panelHeight: 180,
      };
      this._hudApi = null;
      this._resizing = false;
      this._startY = 0;
      this._startH = 0;
    }

    componentDidMount() {
      const recon = initRecon();
      const self = this;

      // Expose HUD API
      this._hudApi = {
        registerTab(id, label, icon, renderFn) {
          self.setState(prev => {
            if (prev.tabs.find(t => t.id === id)) return null;
            return { tabs: [...prev.tabs, { id, label, icon, renderFn, badge: null }] };
          });
        },

        removeTab(id) {
          self.setState(prev => ({
            tabs: prev.tabs.filter(t => t.id !== id),
            activeTab: prev.activeTab === id ? null : prev.activeTab,
          }));
        },

        updateBadge(tabId, badge) {
          self.setState(prev => ({
            tabs: prev.tabs.map(t => t.id === tabId ? { ...t, badge } : t),
          }));
        },

        notify(message, type = 'info') {
          recon.events.emit('hud:notify', { message, type, ts: Date.now() });
        },

        setActiveTab(id) {
          self.setState({ activeTab: id, collapsed: false });
        },

        exec: execInTerminal,
      };

      recon.hud = this._hudApi;
      recon.exec = execInTerminal;
      recon.events.emit('hud:ready', this._hudApi);
    }

    componentWillUnmount() {
      const recon = initRecon();
      recon.hud = null;
    }

    _onTabClick(id) {
      this.setState(prev => {
        if (prev.activeTab === id && !prev.collapsed) {
          return { collapsed: true };
        }
        return { activeTab: id, collapsed: false };
      });
    }

    _onResizeStart(e) {
      this._resizing = true;
      this._startY = e.clientY;
      this._startH = this.state.panelHeight;
      const onMove = (ev) => {
        if (!this._resizing) return;
        const delta = this._startY - ev.clientY;
        this.setState({ panelHeight: Math.max(80, Math.min(500, this._startH + delta)) });
      };
      const onUp = () => {
        this._resizing = false;
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
      };
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    }

    render() {
      const { tabs, activeTab, collapsed, panelHeight } = this.state;
      const activeTabObj = tabs.find(t => t.id === activeTab);

      const tabBarStyle = {
        display: 'flex',
        alignItems: 'center',
        height: '28px',
        background: '#0d1117',
        borderTop: '1px solid #21262d',
        padding: '0 8px',
        gap: '2px',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
        fontSize: '11px',
        color: '#8b949e',
        flexShrink: 0,
        zIndex: 100,
      };

      const panelStyle = {
        height: collapsed ? 0 : panelHeight,
        overflow: 'hidden',
        background: '#0d1117',
        borderTop: collapsed ? 'none' : '1px solid #21262d',
        transition: 'height 0.15s ease',
        position: 'relative',
      };

      const resizeHandleStyle = {
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        height: '4px',
        cursor: 'ns-resize',
        zIndex: 10,
      };

      const panelContentStyle = {
        height: '100%',
        overflow: 'auto',
        padding: '8px 12px',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", monospace',
        fontSize: '12px',
        color: '#c9d1d9',
      };

      return React.createElement('div', { style: { display: 'flex', flexDirection: 'column', height: '100%' } },
        // Main Hyper content
        React.createElement('div', { style: { flex: 1, overflow: 'hidden', position: 'relative' } },
          React.createElement(Hyper, this.props)
        ),

        // Panel content area
        React.createElement('div', { style: panelStyle },
          !collapsed && React.createElement('div', {
            style: resizeHandleStyle,
            onMouseDown: (e) => this._onResizeStart(e),
          }),
          !collapsed && activeTabObj && React.createElement('div', { style: panelContentStyle },
            typeof activeTabObj.renderFn === 'function'
              ? activeTabObj.renderFn(React)
              : React.createElement('div', null, 'No content')
          )
        ),

        // Tab bar
        tabs.length > 0 && React.createElement('div', { style: tabBarStyle },
          // Logo
          React.createElement('span', {
            style: { fontWeight: 700, color: '#58a6ff', marginRight: '8px', fontSize: '10px', letterSpacing: '0.5px' }
          }, 'RECON'),

          // Tabs
          ...tabs.map(tab => {
            const isActive = tab.id === activeTab && !collapsed;
            const tabStyle = {
              padding: '3px 10px',
              borderRadius: '4px 4px 0 0',
              cursor: 'pointer',
              background: isActive ? '#161b22' : 'transparent',
              color: isActive ? '#f0f6fc' : '#8b949e',
              fontWeight: isActive ? 600 : 400,
              fontSize: '11px',
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
              transition: 'background 0.1s',
              borderBottom: isActive ? '2px solid #58a6ff' : '2px solid transparent',
              userSelect: 'none',
            };

            return React.createElement('div', {
              key: tab.id,
              style: tabStyle,
              onClick: () => this._onTabClick(tab.id),
              onMouseEnter: (e) => { if (!isActive) e.target.style.color = '#c9d1d9'; },
              onMouseLeave: (e) => { if (!isActive) e.target.style.color = '#8b949e'; },
            },
              tab.icon && React.createElement('span', { style: { fontSize: '10px' } }, tab.icon),
              tab.label,
              tab.badge != null && React.createElement('span', {
                style: {
                  background: '#da3633',
                  color: '#fff',
                  borderRadius: '8px',
                  padding: '0 5px',
                  fontSize: '9px',
                  fontWeight: 700,
                  minWidth: '14px',
                  textAlign: 'center',
                }
              }, String(tab.badge))
            );
          }),

          // Spacer
          React.createElement('div', { style: { flex: 1 } }),

          // Collapse toggle
          !collapsed && React.createElement('span', {
            style: { cursor: 'pointer', padding: '2px 6px', borderRadius: '3px', fontSize: '10px' },
            onClick: () => this.setState({ collapsed: true }),
            title: 'Collapse',
          }, '\u25BC')
        )
      );
    }
  };
};
