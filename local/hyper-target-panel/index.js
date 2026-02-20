'use strict';
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const { shell, clipboard } = require('electron');
const ToolRunner = require('./lib/ToolRunner');
const { normalizeTarget } = require('./lib/TargetNormalizer');
const { buildWordlistCatalog } = require('./lib/WordlistCatalog');
const TargetStore = require('./lib/storage/TargetStore');
const { verifyWorkflows, buildAutomationHints } = require('./lib/WorkflowVerifier');
const { extractSetTarget } = require('./lib/SetTargetParser');
const { DATA_DIR, getLegacyFindingsPath } = require('./lib/PathResolver');

// Ensure directory exists
try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
} catch (e) {}

function sanitizeTarget(target) {
  const normalized = normalizeTarget(target);
  return normalized || 'None';
}

function isToolCompatibleWithType(tool, selectorType) {
  if (!selectorType) return true;
  if (!tool || !Array.isArray(tool.types) || tool.types.length === 0) return false;
  return tool.types.includes(selectorType);
}

function resolveLegacyFindingsPath(target) {
  const safeTarget = sanitizeTarget(target).replace(/[^a-zA-Z0-9.-]/g, '_');
  return getLegacyFindingsPath(safeTarget);
}

const CONFIG_DIR = path.join(__dirname, 'config');
const TOOLS_FILE = path.join(CONFIG_DIR, 'tools.json');
const WORKFLOWS_FILE = path.join(CONFIG_DIR, 'workflows.json');

// Command Queue for robust execution
const pendingCommands = [];

if (typeof window !== 'undefined') {
    window.__hyperTargetPanel_queue = (item) => {
        pendingCommands.push(item);
    };
    window.__hyperTargetPanel_cancelQueued = (id) => {
        const idx = pendingCommands.findIndex((entry) => entry && entry.id === id);
        if (idx >= 0) pendingCommands.splice(idx, 1);
    };
}

// Middleware to intercept SESSION_ADD and execute pending commands
exports.middleware = (store) => (next) => (action) => {
    if (action.type === 'SESSION_ADD') {
        if (typeof window !== 'undefined') {
            window.__hyperTargetPanel_lastSessionAddAt = Date.now();
        }
        if (pendingCommands.length > 0) {
            const queued = pendingCommands.shift();
            const cmd = typeof queued === 'string' ? queued : queued && queued.cmd;
            const id = typeof queued === 'string' ? null : queued && queued.id;
            if (!cmd) return next(action);
            // Execute cmd in action.uid with a small delay to ensure shell readiness
            setTimeout(() => {
                window.rpc.emit('data', { uid: action.uid, data: cmd + '\n', escaped: false });
                if (typeof window !== 'undefined' && typeof window.__hyperTargetPanel_onCommandDispatched === 'function' && id) {
                    window.__hyperTargetPanel_onCommandDispatched(id, action.uid);
                }
            }, 500);
        }
    } else if (action.type === 'SESSION_PTY_DATA') {
        const target = extractSetTarget(action.data);
        if (target && typeof window !== 'undefined') {
            window.dispatchEvent(new CustomEvent('hyper-target-panel:set-target', { detail: { target } }));
        }
    }
    return next(action);
};

// Hacker Colors
const C = {
  bg: '#1e1e24',
  text: '#dcdcdc',
  accent: '#bd93f9',
  border: '#44475a',
  header: '#6272a4',
  port: '#50fa7b',
  vuln: '#ff5555',
  path: '#f1fa8c',
  target: '#8be9fd',
  tool: '#ff79c6',
  workflow: '#ffb86c',
  history: '#8be9fd',
  modalBg: 'rgba(30, 30, 36, 0.95)',
  buttonBg: '#44475a',
  buttonHover: '#6272a4'
};

exports.decorateTerm = (Term, { React, notify }) => {
  return class extends React.Component {
    constructor(props, context) {
      super(props, context);
      this.onTerminal = this.onTerminal.bind(this);
      this._inputBuf = '';
      this._inputDisposable = null;
    }

    onTerminal(term) {
      if (this.props.onTerminal) this.props.onTerminal(term);
      
      // Register Link Provider for IPs
      if (term.registerLinkProvider) {
          term.registerLinkProvider({
              provideLinks: (bufferLineNumber, callback) => {
                  const line = term.buffer.active.getLine(bufferLineNumber - 1);
                  if (!line) return;
                  const text = line.translateToString(true);
                  
                  // Regex for IPv4
                  const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
                  const links = [];
                  let match;
                  
                  while ((match = ipRegex.exec(text)) !== null) {
                      const ip = match[0];
                      // Verify octets
                      const parts = ip.split('.').map(Number);
                      if (parts.some(p => p > 255)) continue;

                      links.push({
                          range: {
                              start: { x: match.index + 1, y: bufferLineNumber },
                              end: { x: match.index + ip.length, y: bufferLineNumber }
                          },
                          text: ip,
                          activate: (event, text) => {
                              // Dispatch event to open modal
                              window.dispatchEvent(new CustomEvent('hyper-target-panel:open-tool-selector', { 
                                  detail: { target: text } 
                              }));
                          }
                      });
                  }
                  callback(links);
              }
          });
      }

      if (!this._inputDisposable && term.onData) {
          this._inputDisposable = term.onData((data) => {
              if (!data) return;
              for (let i = 0; i < data.length; i++) {
                  const ch = data[i];
                  if (ch === '\r' || ch === '\n') {
                      const line = this._inputBuf;
                      this._inputBuf = '';
                      const target = extractSetTarget(line);
                      if (target && typeof window !== 'undefined') {
                          window.dispatchEvent(new CustomEvent('hyper-target-panel:set-target', { detail: { target } }));
                      }
                  } else if (ch === '\x7f' || ch === '\b') {
                      if (this._inputBuf.length > 0) {
                          this._inputBuf = this._inputBuf.slice(0, -1);
                      }
                  } else if (ch >= ' ') {
                      this._inputBuf += ch;
                  }
              }
          });
      }
    }

    componentWillUnmount() {
      if (this._inputDisposable && this._inputDisposable.dispose) {
          this._inputDisposable.dispose();
      }
    }

    render() {
      return React.createElement(Term, Object.assign({}, this.props, {
        onTerminal: this.onTerminal
      }));
    }
  }
};

exports.decorateTerms = (Terms, { React }) => {
  return class extends React.Component {
    constructor(props, context) {
      super(props, context);
      this.state = {
        data: { target: 'None', ports: [], vulns: [], paths: [], history: [] },
        tools: [],
        workflows: [],
        activeTool: null,
        toolSelectorOpen: false,
        selectorType: null,
        selectorTarget: null,
        selectorActions: [],
        schemeOverride: 'auto',
        wordlistModalOpen: false,
        wordlistTool: null,
        wordlistSections: [],
        targetEditing: false,
        targetDraft: '',
        runStatus: null,
        recentRuns: [],
        workflowIssues: [],
        automationHints: [],
        storageMode: 'json'
      };
      this.targetStore = new TargetStore({ baseDir: DATA_DIR });
      this.toolRunner = new ToolRunner(window.rpc, window.store, {
        onRunStatus: (runStatus) => {
          if (runStatus && runStatus.target) {
            this.targetStore.recordRun(runStatus);
          }
          const activeTarget = this.state.data && this.state.data.target;
          const recentRuns = activeTarget ? this.targetStore.getRecentRuns(activeTarget, 8) : [];
          this.setState({ runStatus, recentRuns });
        },
        onFindings: (target, findings, context) => {
          this.targetStore.mergeFindings(target, findings, context && context.toolId);
          const activeTarget = this.state.data && this.state.data.target;
          if (activeTarget && sanitizeTarget(activeTarget) === sanitizeTarget(target)) {
            this.reloadFindings(activeTarget);
          }
        },
        onJcOutput: (target, jcData, context) => {
          this.targetStore.storeJcSnapshot(target, jcData, context || {});
        }
      });
      this.handleOpenToolSelector = this.handleOpenToolSelector.bind(this);
      this.handleSetTarget = this.handleSetTarget.bind(this);
    }

    componentDidMount() {
      this.loadConfig();
      this.loadTargetConfig();
      
      window.addEventListener('hyper-target-panel:open-tool-selector', this.handleOpenToolSelector);
      window.addEventListener('hyper-target-panel:set-target', this.handleSetTarget);
    }

    componentWillUnmount() {
      window.removeEventListener('hyper-target-panel:open-tool-selector', this.handleOpenToolSelector);
      window.removeEventListener('hyper-target-panel:set-target', this.handleSetTarget);
      if (this.toolRunner) this.toolRunner.stop();
    }

    handleOpenToolSelector(e) {
        const { target, type, actions } = e.detail || {};
        const rawTarget = String(target || '').trim();
        const normalized = sanitizeTarget(rawTarget);
        if (normalized && normalized !== 'None') this.setTarget(normalized);
        this.setState({
          toolSelectorOpen: true,
          selectorType: type,
          selectorTarget: rawTarget || normalized,
          selectorActions: Array.isArray(actions) ? actions : []
        });
    }

    handleSetTarget(e) {
        const { target } = e.detail || {};
        if (target) this.setTarget(target);
    }

    loadConfig() {
      fs.readFile(TOOLS_FILE, 'utf8', (err, content) => {
        if (!err) {
          try {
            const tools = JSON.parse(content);
            this.setState({ tools });
            this.refreshWorkflowInsights(tools, this.state.workflows);
          } catch (e) { console.error("Failed to parse tools.json", e); }
        }
      });

      fs.readFile(WORKFLOWS_FILE, 'utf8', (err, content) => {
        if (!err) {
          try {
            const workflows = JSON.parse(content);
            this.setState({ workflows });
            this.refreshWorkflowInsights(this.state.tools, workflows);
          } catch (e) { console.error("Failed to parse workflows.json", e); }
        }
      });
    }

    refreshWorkflowInsights(tools, workflows) {
      const listTools = Array.isArray(tools) ? tools : [];
      const listWorkflows = Array.isArray(workflows) ? workflows : [];
      const report = verifyWorkflows(listTools, listWorkflows);
      const hints = buildAutomationHints(listTools);
      this.setState({
        workflowIssues: report.issues || [],
        automationHints: hints.slice(0, 6),
      });
    }

    loadTargetConfig() {
        const savedTarget = this.targetStore.loadLastTarget();
        this.fetchData(savedTarget || 'None');
    }

    fetchData(target) {
      const currentTarget = target || this.state.data.target || 'None';
      const findingsFile = resolveLegacyFindingsPath(currentTarget);
      this.targetStore.importLegacyFindings(currentTarget, findingsFile);
      this.reloadFindings(currentTarget);
    }

    reloadFindings(target) {
        const safeTarget = sanitizeTarget(target || this.state.data.target || 'None');
        const data = this.targetStore.getTargetData(safeTarget);
        const recentRuns = this.targetStore.getRecentRuns(safeTarget, 8);
        this.setState({
          data,
          recentRuns,
          storageMode: this.targetStore.getMode()
        });
    }

    setTarget(rawTarget) {
      const newTarget = sanitizeTarget(rawTarget);
      if (newTarget === 'None') return;
      if (newTarget === this.state.data.target) return;

      this.targetStore.saveLastTarget(newTarget);
      this.targetStore.addHistory(newTarget, newTarget);
      this.fetchData(newTarget);
    }

    launchTool(tool, contextTarget = null) {
      // If triggered from tool selector, close it first
      this.setState({ toolSelectorOpen: false });

      if (tool.wordlist && tool.wordlist.profile) {
        const catalog = buildWordlistCatalog({ profile: tool.wordlist.profile });
        this.setState({
          wordlistModalOpen: true,
          wordlistTool: tool,
          wordlistSections: catalog.sections || [],
          selectorTarget: contextTarget || this.state.selectorTarget
        });
        return;
      }

      if (tool.presets && tool.presets.length > 0) {
        this.setState({ activeTool: tool });
      } else {
        this.executeTool(tool, null, '', contextTarget);
      }
    }

    executeTool(tool, preset = null, wordlistFile = '', contextTarget = null) {
      const { data } = this.state;
      const resolvedTarget = String(contextTarget || this.state.selectorTarget || data.target || '').trim() || data.target;
      const commandToRun = preset ? preset.command : tool.command;
      const toolToRun = { ...tool, command: commandToRun };
      const runData = {
        ...data,
        target: resolvedTarget,
        schemeOverride: this.state.schemeOverride,
        wordlistFile
      };
      this.targetStore.addHistory(resolvedTarget, resolvedTarget);
      
      if (tool.runner === 'internal') {
          const command = commandToRun
            .replace(/{target}/g, runData.target || '')
            .replace(/{wordlist_file}/g, wordlistFile || '');

          if (tool.action === 'open-browser') {
             shell.openExternal(command);
          } else if (tool.action === 'copy') {
             clipboard.writeText(command);
          }
          this.setState({ activeTool: null, toolSelectorOpen: false });
          return;
      }

      this.toolRunner.launch(toolToRun, runData);
      this.setState({ activeTool: null, toolSelectorOpen: false, wordlistModalOpen: false, wordlistTool: null, wordlistSections: [] });
    }
    
    closeModal() {
      this.setState({
        activeTool: null,
        toolSelectorOpen: false,
        selectorActions: [],
        wordlistModalOpen: false,
        wordlistTool: null,
        wordlistSections: []
      });
    }

    launchWorkflow(workflow) {
      const { tools, data } = this.state;
      const sequence = workflow.tools.map(id => tools.find(t => t.id === id)).filter(Boolean);
      this.toolRunner.launchWorkflow(sequence, data);
      this.setState({ toolSelectorOpen: false });
    }

    openConfig() {
      exec(`xdg-open "${CONFIG_DIR}" || open "${CONFIG_DIR}"`);
    }

    renderSection(title, items, color) {
        if (!items || items.length === 0) return null;
        return React.createElement('div', { key: title }, [
            React.createElement('div', {
                style: {
                    color: C.header,
                    fontSize: '11px',
                    fontWeight: 'bold',
                    marginBottom: '5px',
                    marginTop: '20px',
                    borderBottom: `1px solid ${C.border}`
                }
            }, title),
            items.map((item, i) => 
                React.createElement('div', {
                    key: i,
                    style: {
                        color: color,
                        marginBottom: '2px',
                        wordBreak: 'break-all'
                    }
                }, item)
            )
        ]);
    }

    getRecommendedTools(tools, data) {
      if (!data || !data.ports) return [];
      const recs = [];
      const portsStr = data.ports.join(' ');

      // Heuristic 1: If HTTP/HTTPS ports open (80, 443, 8080), recommend Web tools
      if (/80|443|8080|3000|5000|8000/.test(portsStr)) {
          recs.push(...tools.filter(t => ['gobuster_dir', 'nikto', 'whatweb', 'wpscan', 'ffuf_dir', 'nuclei_url'].includes(t.id)));
      }

      // Heuristic 2: If SMB ports open (139, 445), recommend Enum4Linux
      if (/139|445/.test(portsStr)) {
          recs.push(...tools.filter(t => t.id === 'nmap_vuln'));
      }

      // Heuristic 3: If SQL mentioned or port 3306, recommend SQLMap
      if (/3306|5432|1433/.test(portsStr) || /sql/i.test(portsStr)) {
          recs.push(...tools.filter(t => t.id === 'sqlmap'));
      }

      // Remove duplicates
      return [...new Set(recs)];
    }

    render() {
      const {
        data,
        tools,
        workflows,
        activeTool,
        toolSelectorOpen,
        selectorType,
        selectorTarget,
        selectorActions,
        runStatus,
        workflowIssues,
        automationHints,
        storageMode,
        schemeOverride,
        wordlistModalOpen,
        wordlistTool,
        wordlistSections
      } = this.state;
      const sidebarWidth = 280;
      const bottomHeight = 150;

      const toolsByCategory = tools.reduce((acc, tool) => {
        const cat = tool.category || 'Other';
        if (!acc[cat]) acc[cat] = [];
        acc[cat].push(tool);
        return acc;
      }, {});

      const recommendedTools = this.getRecommendedTools(tools, data);

      const children = [
          React.createElement(
            'div',
            {
              key: 'top-area',
              style: { display: 'flex', flex: 1, minHeight: 0 }
            },
            [
              React.createElement(
                'div',
                {
                  key: 'terms',
                  style: { flex: 1, position: 'relative', height: '100%' }
                },
                React.createElement(Terms, this.props)
              ),
              React.createElement(
                'div',
                {
                  key: 'sidebar',
                  style: {
                    width: sidebarWidth,
                    backgroundColor: C.bg,
                    borderLeft: `1px solid ${C.border}`,
                    color: C.text,
                    fontFamily: '"Fira Code", monospace',
                    fontSize: '12px',
                    padding: '10px',
                    overflowY: 'auto',
                    boxSizing: 'border-box'
                  }
                },
                [
                  React.createElement('div', {
                    style: {
                      fontSize: '12px',
                      fontWeight: 'bold',
                      color: C.target,
                      marginBottom: '10px',
                      borderBottom: `2px solid ${C.accent}`,
                      paddingBottom: '5px'
                    }
                  }, 
                  this.state.targetEditing
                    ? React.createElement('input', {
                        autoFocus: true,
                        value: this.state.targetDraft,
                        placeholder: 'Set target (domain/IP)',
                        style: {
                          width: '100%',
                          backgroundColor: C.bg,
                          color: C.target,
                          border: `1px solid ${C.border}`,
                          borderRadius: '4px',
                          padding: '4px 6px',
                          fontFamily: '"Fira Code", monospace',
                          fontSize: '11px',
                          boxSizing: 'border-box'
                        },
                        onChange: (e) => this.setState({ targetDraft: e.target.value }),
                        onBlur: () => {
                          const val = this.state.targetDraft.trim();
                          if (val) this.setTarget(val);
                          this.setState({ targetEditing: false, targetDraft: '' });
                        },
                        onKeyDown: (e) => {
                          if (e.key === 'Enter') {
                            const val = this.state.targetDraft.trim();
                            if (val) this.setTarget(val);
                            this.setState({ targetEditing: false, targetDraft: '' });
                          } else if (e.key === 'Escape') {
                            this.setState({ targetEditing: false, targetDraft: '' });
                          }
                        }
                      })
                    : React.createElement('span', {
                        style: { cursor: 'pointer' },
                        onClick: () => this.setState({ targetEditing: true, targetDraft: data.target })
                      }, `🎯 ${data.target}`)
                  ),
                  React.createElement('div', {
                    style: {
                      color: C.header,
                      fontSize: '10px',
                      fontWeight: 'bold',
                      marginTop: '8px',
                      marginBottom: '4px',
                      borderBottom: `1px solid ${C.border}`
                    }
                  }, 'OVERRIDE'),
                  React.createElement('div', { style: { display: 'flex', gap: '4px', marginBottom: '8px' } }, [
                    ['auto', 'AUTO'],
                    ['https', 'HTTPS'],
                    ['http', 'HTTP']
                  ].map(([value, label]) =>
                    React.createElement('div', {
                      key: value,
                      style: {
                        color: schemeOverride === value ? C.bg : C.target,
                        backgroundColor: schemeOverride === value ? C.target : C.buttonBg,
                        border: `1px solid ${C.border}`,
                        borderRadius: '3px',
                        padding: '2px 6px',
                        cursor: 'pointer',
                        fontSize: '10px',
                        fontWeight: 'bold'
                      },
                      onClick: () => this.setState({ schemeOverride: value })
                    }, label)
                  )),
                  runStatus && React.createElement('div', {
                    style: {
                      marginBottom: '10px',
                      fontSize: '10px',
                      color: runStatus.status === 'failed' ? C.vuln : C.port,
                      border: `1px solid ${C.border}`,
                      borderRadius: '4px',
                      padding: '4px 6px',
                      wordBreak: 'break-word'
                    }
                  }, runStatus.status === 'failed'
                    ? `Last run failed (${runStatus.transport || 'none'}): ${runStatus.error || 'unknown error'}`
                    : `Last run ${runStatus.status} via ${runStatus.transport || 'pending'}: ${runStatus.toolName || runStatus.toolId || 'tool'}`),
                  React.createElement('div', {
                    style: {
                      marginBottom: '8px',
                      fontSize: '10px',
                      color: C.header
                    }
                  }, `Storage: ${storageMode}`),

                   React.createElement('div', {
                    style: {
                      color: C.header,
                      fontSize: '10px',
                      fontWeight: 'bold',
                      marginBottom: '5px',
                      marginTop: '10px',
                      borderBottom: `1px solid ${C.border}`
                    }
                  }, 'WORKFLOWS'),
                  
                  React.createElement('div', { style: { display: 'flex', flexWrap: 'wrap', gap: '4px' } },
                    workflows.map((wf, i) =>
                      React.createElement('div', {
                        key: `wf-${i}`,
                        style: {
                          color: C.workflow,
                          cursor: 'pointer',
                          padding: '2px 4px',
                          fontWeight: 'bold',
                          fontSize: '10px',
                          border: `1px solid ${C.border}`,
                          borderRadius: '3px',
                          flex: '1 0 45%'
                        },
                        onClick: () => this.launchWorkflow(wf),
                        title: wf.description
                      }, `⚡ ${wf.name}`)
                    )
                  ),
                  workflowIssues.length > 0 && React.createElement('div', { key: 'workflow-issues' }, [
                    React.createElement('div', {
                      style: {
                        color: C.vuln,
                        fontSize: '10px',
                        fontWeight: 'bold',
                        marginBottom: '4px',
                        marginTop: '10px'
                      }
                    }, 'WORKFLOW WARNINGS'),
                    React.createElement('div', {
                      style: { color: C.vuln, fontSize: '10px', lineHeight: '1.4' }
                    }, workflowIssues.slice(0, 3).map((issue) =>
                      `${issue.workflowId}: ${issue.type} ${issue.toolId || ''} ${issue.dependency || ''}`
                    ).join(' | '))
                  ]),
                  automationHints.length > 0 && React.createElement('div', { key: 'automation-hints' }, [
                    React.createElement('div', {
                      style: {
                        color: C.port,
                        fontSize: '10px',
                        fontWeight: 'bold',
                        marginBottom: '4px',
                        marginTop: '10px'
                      }
                    }, 'AUTOMATION HINTS'),
                    React.createElement('div', {
                      style: { color: C.port, fontSize: '10px', lineHeight: '1.4' }
                    }, automationHints.slice(0, 3).map((hint) => `${hint.from} -> ${hint.to}`).join(' | '))
                  ]),

                  // Recommended Tools Section
                  recommendedTools.length > 0 && React.createElement('div', { key: 'recommended' }, [
                      React.createElement('div', {
                        style: {
                          color: '#50fa7b', // Green for recommended
                          fontSize: '10px',
                          fontWeight: 'bold',
                          marginBottom: '5px',
                          marginTop: '15px',
                          borderBottom: `1px solid #50fa7b`
                        }
                      }, 'RECOMMENDED'),

                      React.createElement('div', { style: { display: 'flex', flexWrap: 'wrap', gap: '4px' } },
                        recommendedTools.map((tool, i) =>
                          React.createElement('div', {
                            key: `rec-${tool.id}`,
                            style: {
                              color: C.tool,
                              cursor: 'pointer',
                              padding: '2px 4px',
                              fontSize: '10px',
                              border: `1px solid ${C.port}`, // Green border
                              borderRadius: '3px',
                              flex: '1 0 45%',
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                              backgroundColor: 'rgba(80, 250, 123, 0.1)'
                            },
                            onClick: () => this.launchTool(tool, data.target)
                          }, tool.name)
                        )
                      )
                  ]),

                  Object.keys(toolsByCategory).map(cat => 
                    React.createElement('div', { key: cat }, [
                      React.createElement('div', {
                        style: {
                          color: C.header,
                          fontSize: '10px',
                          fontWeight: 'bold',
                          marginBottom: '5px',
                          marginTop: '15px',
                          borderBottom: `1px solid ${C.border}`
                        }
                      }, cat.toUpperCase()),
                      
                      React.createElement('div', { style: { display: 'flex', flexWrap: 'wrap', gap: '4px' } },
                        toolsByCategory[cat].map((tool, i) =>
                          React.createElement('div', {
                            key: tool.id,
                            style: {
                              color: C.tool,
                              cursor: 'pointer',
                              padding: '2px 4px',
                              fontSize: '10px',
                              border: `1px solid ${C.border}`,
                              borderRadius: '3px',
                              flex: '1 0 45%',
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap'
                            },
                            onClick: () => this.launchTool(tool, data.target)
                          }, tool.name)
                        )
                      )
                    ])
                  ),

                  this.renderSection('OPEN PORTS', data.ports, C.port),
                  this.renderSection('DOMAINS / SUBDOMAINS', data.domains, C.path),
                  this.renderSection('VULNERABILITIES', data.vulns, C.vuln),
                ]
              )
            ]
          ),
          
          React.createElement(
            'div',
            {
              key: 'bottom-panel',
              style: {
                height: bottomHeight,
                backgroundColor: C.bg,
                borderTop: `1px solid ${C.border}`,
                color: C.text,
                fontFamily: '"Fira Code", monospace',
                fontSize: '12px',
                padding: '10px',
                overflowY: 'auto',
                boxSizing: 'border-box'
              }
            },
            [
              React.createElement('div', {
                 style: {
                   color: C.header,
                   fontWeight: 'bold',
                   marginBottom: '5px',
                   position: 'sticky',
                   top: 0,
                   backgroundColor: C.bg
                 }
              }, 'TARGET HISTORY / URLS'),
              
              React.createElement('div', {
                style: {
                   display: 'flex',
                   flexWrap: 'wrap',
                   gap: '10px'
                }
              }, 
                (data.history && data.history.length > 0 ? data.history : []).map((item, i) => 
                  React.createElement('div', {
                    key: i,
                    style: {
                      padding: '4px 8px',
                      backgroundColor: C.border,
                      color: C.history,
                      borderRadius: '4px',
                      cursor: 'pointer',
                      maxWidth: '300px',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap'
                    },
                    onClick: () => this.setTarget(item)
                  }, item)
                )
              )
            ]
          )
      ];

      // Tool Selector Modal
      if (toolSelectorOpen) {
          const filteredTools = tools.filter((t) => isToolCompatibleWithType(t, selectorType));
          const modalToolsByCategory = filteredTools.reduce((acc, tool) => {
            const cat = tool.category || 'Other';
            if (!acc[cat]) acc[cat] = [];
            acc[cat].push(tool);
            return acc;
          }, {});

          children.push(React.createElement('div', {
              key: 'tool-selector-overlay',
              style: {
                  position: 'absolute',
                  top: 0,
                  left: 0,
                  right: 0,
                  bottom: 0,
                  backgroundColor: 'rgba(0,0,0,0.8)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  zIndex: 9998
              },
              onClick: () => this.closeModal()
          }, 
          React.createElement('div', {
              style: {
                  backgroundColor: C.bg,
                  border: `1px solid ${C.target}`,
                  padding: '20px',
                  width: '600px',
                  maxHeight: '80%',
                  overflowY: 'auto',
                  borderRadius: '8px',
                  boxShadow: '0 0 30px rgba(0,0,0,0.7)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '15px'
              },
              onClick: (e) => e.stopPropagation()
          }, [
              React.createElement('div', {
                  style: { fontSize: '20px', fontWeight: 'bold', color: C.target, textAlign: 'center', borderBottom: `1px solid ${C.border}`, paddingBottom: '10px' }
              }, `Select Tool for ${data.target}` + (selectorType ? ` (${selectorType})` : '')),

              selectorActions.length > 0 && React.createElement('div', {
                  style: { display: 'flex', gap: '10px', justifyContent: 'center', flexWrap: 'wrap' }
              },
                selectorActions.map((action) =>
                  React.createElement('div', {
                    key: action.id,
                    style: {
                      backgroundColor: C.buttonBg,
                      padding: '6px 10px',
                      borderRadius: '4px',
                      cursor: 'pointer',
                      color: C.target,
                      fontWeight: 'bold',
                      fontSize: '11px'
                    },
                    onClick: () => {
                      if (action.id === 'set_target' && selectorTarget) {
                        this.setTarget(selectorTarget);
                        this.setState({ toolSelectorOpen: false });
                      }
                    },
                    onMouseEnter: (e) => e.currentTarget.style.backgroundColor = C.buttonHover,
                    onMouseLeave: (e) => e.currentTarget.style.backgroundColor = C.buttonBg
                  }, action.label || action.id)
                )
              ),

              // Workflows
              React.createElement('div', { style: { color: C.header, fontWeight: 'bold' } }, "WORKFLOWS"),
              React.createElement('div', { style: { display: 'flex', flexWrap: 'wrap', gap: '10px' } }, 
                  workflows.map(wf => 
                      React.createElement('div', {
                          key: wf.id,
                          style: {
                              backgroundColor: C.buttonBg,
                              padding: '8px 12px',
                              borderRadius: '4px',
                              cursor: 'pointer',
                              color: C.workflow,
                              fontWeight: 'bold',
                              flex: '1 0 45%'
                          },
                          onClick: () => this.launchWorkflow(wf),
                          onMouseEnter: (e) => e.currentTarget.style.backgroundColor = C.buttonHover,
                          onMouseLeave: (e) => e.currentTarget.style.backgroundColor = C.buttonBg
                      }, `⚡ ${wf.name}`)
                  )
              ),

              // Tools
              ...Object.keys(modalToolsByCategory).map(cat =>
                  React.createElement('div', { key: cat }, [
                      React.createElement('div', {
                          style: { color: C.header, fontWeight: 'bold', marginTop: '10px', borderBottom: `1px solid ${C.border}` }
                      }, cat.toUpperCase()),
                      React.createElement('div', { style: { display: 'flex', flexWrap: 'wrap', gap: '10px', marginTop: '5px' } }, 
                          modalToolsByCategory[cat].map(tool =>
                              React.createElement('div', {
                                  key: tool.id,
                                  style: {
                                      backgroundColor: C.buttonBg,
                                      padding: '8px 12px',
                                      borderRadius: '4px',
                                      cursor: 'pointer',
                                      color: C.tool,
                                      flex: '1 0 30%'
                                  },
                                  onClick: () => this.launchTool(tool, selectorTarget || data.target),
                                  onMouseEnter: (e) => e.currentTarget.style.backgroundColor = C.buttonHover,
                                  onMouseLeave: (e) => e.currentTarget.style.backgroundColor = C.buttonBg
                              }, tool.name)
                          )
                      )
                  ])
              ),

              React.createElement('div', {
                  style: {
                      color: '#aaa',
                      textAlign: 'center',
                      cursor: 'pointer',
                      marginTop: '10px',
                      fontSize: '12px'
                  },
                  onClick: () => this.closeModal()
              }, "Cancel")
          ])
        ));
      }

      if (wordlistModalOpen && wordlistTool) {
        children.push(React.createElement('div', {
          key: 'wordlist-selector-overlay',
          style: {
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(0,0,0,0.85)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 9999
          },
          onClick: () => this.closeModal()
        },
        React.createElement('div', {
          style: {
            backgroundColor: C.bg,
            border: `1px solid ${C.target}`,
            padding: '18px',
            width: '680px',
            maxHeight: '80%',
            overflowY: 'auto',
            borderRadius: '8px'
          },
          onClick: (e) => e.stopPropagation()
        }, [
          React.createElement('div', {
            key: 'wordlist-header',
            style: {
              fontSize: '18px',
              fontWeight: 'bold',
              color: C.target,
              borderBottom: `1px solid ${C.border}`,
              paddingBottom: '8px',
              marginBottom: '10px'
            }
          }, `SELECT WORDLIST - ${wordlistTool.name}`),
          ...wordlistSections.map((section) =>
            React.createElement('div', { key: `wl-${section.id}`, style: { marginBottom: '12px' } }, [
              React.createElement('div', {
                key: `wl-title-${section.id}`,
                style: {
                  color: C.header,
                  fontWeight: 'bold',
                  fontSize: '12px',
                  borderBottom: `1px solid ${C.border}`,
                  marginBottom: '6px'
                }
              }, section.id),
              React.createElement('div', {
                key: `wl-files-${section.id}`,
                style: { display: 'flex', flexWrap: 'wrap', gap: '8px' }
              }, (section.files || []).map((file) =>
                React.createElement('div', {
                  key: file.path,
                  style: {
                    backgroundColor: C.buttonBg,
                    color: C.path,
                    borderRadius: '4px',
                    padding: '8px 10px',
                    cursor: 'pointer',
                    fontSize: '11px',
                    flex: '1 0 45%'
                  },
                  onClick: () => this.executeTool(wordlistTool, null, file.path, selectorTarget || data.target),
                  onMouseEnter: (e) => e.currentTarget.style.backgroundColor = C.buttonHover,
                  onMouseLeave: (e) => e.currentTarget.style.backgroundColor = C.buttonBg,
                  title: file.path
                }, file.name)
              ))
            ])
          ),
          wordlistSections.every((section) => !section.files || section.files.length === 0) && React.createElement('div', {
            key: 'wordlist-empty',
            style: { color: C.vuln, fontSize: '12px', marginTop: '8px' }
          }, 'No matching wordlist files found in ~/Wordlists or ~/Wordlist.'),
          React.createElement('div', {
            key: 'wordlist-cancel',
            style: {
              color: '#aaa',
              textAlign: 'center',
              cursor: 'pointer',
              marginTop: '8px',
              fontSize: '12px'
            },
            onClick: () => this.closeModal()
          }, 'Cancel')
        ])));
      }

      // Preset Modal (Existing)
      if (activeTool) {
          children.push(React.createElement('div', {
              key: 'modal-overlay',
              style: {
                  position: 'absolute',
                  top: 0,
                  left: 0,
                  right: 0,
                  bottom: 0,
                  backgroundColor: 'rgba(0,0,0,0.7)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  zIndex: 9999
              },
              onClick: () => this.closeModal()
          }, 
          React.createElement('div', {
              style: {
                  backgroundColor: C.bg,
                  border: `1px solid ${C.accent}`,
                  padding: '20px',
                  width: '400px',
                  borderRadius: '8px',
                  boxShadow: '0 0 20px rgba(0,0,0,0.5)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '10px'
              },
              onClick: (e) => e.stopPropagation()
          }, [
              React.createElement('div', {
                  style: { fontSize: '18px', fontWeight: 'bold', color: C.accent, marginBottom: '10px' }
              }, `Launch ${activeTool.name}`),
              
              ...(activeTool.presets || []).map(preset => 
                  React.createElement('div', {
                      key: preset.name,
                      style: {
                          backgroundColor: C.buttonBg,
                          padding: '10px',
                          borderRadius: '4px',
                          cursor: 'pointer',
                          display: 'flex',
                          flexDirection: 'column'
                      },
                      onClick: () => this.executeTool(activeTool, preset, '', selectorTarget || data.target),
                      onMouseEnter: (e) => e.currentTarget.style.backgroundColor = C.buttonHover,
                      onMouseLeave: (e) => e.currentTarget.style.backgroundColor = C.buttonBg
                  }, [
                      React.createElement('div', { style: { fontWeight: 'bold', color: C.text } }, preset.name),
                      React.createElement('div', { style: { fontSize: '10px', color: '#aaa' } }, preset.description)
                  ])
              ),

              React.createElement('div', {
                  style: {
                      backgroundColor: C.buttonBg,
                      padding: '10px',
                      borderRadius: '4px',
                      cursor: 'pointer',
                      marginTop: '10px',
                      textAlign: 'center',
                      fontWeight: 'bold'
                  },
                  onClick: () => this.executeTool(activeTool, null, '', selectorTarget || data.target),
                  onMouseEnter: (e) => e.currentTarget.style.backgroundColor = C.buttonHover,
                  onMouseLeave: (e) => e.currentTarget.style.backgroundColor = C.buttonBg
              }, "Run Default Command"),

              React.createElement('div', {
                  style: {
                      color: '#aaa',
                      textAlign: 'center',
                      cursor: 'pointer',
                      marginTop: '5px',
                      fontSize: '12px'
                  },
                  onClick: () => this.closeModal()
              }, "Cancel")
          ])
        ));
      }

      return React.createElement(
        'div',
        {
          style: {
            display: 'flex',
            flexDirection: 'column',
            width: '100%',
            height: '100%',
            position: 'relative'
          }
        },
        children
      );
    }
  };
};
