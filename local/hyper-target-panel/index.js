'use strict';
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const { shell, clipboard } = require('electron');
const ToolRunner = require('./lib/ToolRunner');

const FINDINGS_FILE = '/home/xlo/.gemini/tmp/target_findings.json';
const CONFIG_DIR = path.join(__dirname, 'config');
const TOOLS_FILE = path.join(CONFIG_DIR, 'tools.json');
const WORKFLOWS_FILE = path.join(CONFIG_DIR, 'workflows.json');

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
        selectorType: null
      };
      this.toolRunner = new ToolRunner(window.rpc, window.store);
      this.handleOpenToolSelector = this.handleOpenToolSelector.bind(this);
    }

    componentDidMount() {
      this.fetchData();
      this.loadConfig();
      
      window.addEventListener('hyper-target-panel:open-tool-selector', this.handleOpenToolSelector);

      try {
        let timeout;
        this.watcher = fs.watch(FINDINGS_FILE, (eventType, filename) => {
          if (timeout) clearTimeout(timeout);
          timeout = setTimeout(() => this.fetchData(), 100);
        });
      } catch (e) {
        if (!fs.existsSync(FINDINGS_FILE)) {
            fs.writeFileSync(FINDINGS_FILE, JSON.stringify({ target: 'None', ports: [], domains: [], vulns: [], paths: [], history: [] }));
            this.watcher = fs.watch(FINDINGS_FILE, () => this.fetchData());
        }
      }
    }

    componentWillUnmount() {
      window.removeEventListener('hyper-target-panel:open-tool-selector', this.handleOpenToolSelector);
      if (this.watcher) this.watcher.close();
      if (this.toolRunner) this.toolRunner.stop();
    }

    handleOpenToolSelector(e) {
        const { target, type } = e.detail;
        this.setTarget(target);
        this.setState({ toolSelectorOpen: true, selectorType: type });
    }

    loadConfig() {
      fs.readFile(TOOLS_FILE, 'utf8', (err, content) => {
        if (!err) {
          try {
            this.setState({ tools: JSON.parse(content) });
          } catch (e) { console.error("Failed to parse tools.json", e); }
        }
      });

      fs.readFile(WORKFLOWS_FILE, 'utf8', (err, content) => {
        if (!err) {
          try {
            this.setState({ workflows: JSON.parse(content) });
          } catch (e) { console.error("Failed to parse workflows.json", e); }
        }
      });
    }

    fetchData() {
      fs.readFile(FINDINGS_FILE, 'utf8', (err, content) => {
        if (!err) {
          try {
            const data = JSON.parse(content);
            if (!data.history) data.history = [];
            if (!data.domains) data.domains = [];
            this.setState({ data });
          } catch (e) {}
        }
      });
    }

    setTarget(newTarget) {
      const { data } = this.state;
      const newData = { ...data, target: newTarget };
      if (!newData.history.includes(newTarget)) {
        newData.history = [newTarget, ...newData.history].slice(0, 200);
      }
      
      this.setState({ data: newData });
      fs.writeFile(FINDINGS_FILE, JSON.stringify(newData, null, 2), () => {});
    }

    launchTool(tool) {
      // If triggered from tool selector, close it first
      this.setState({ toolSelectorOpen: false });

      if (tool.presets && tool.presets.length > 0) {
        this.setState({ activeTool: tool });
      } else {
        this.executeTool(tool);
      }
    }

    executeTool(tool, preset = null) {
      const { data } = this.state;
      const commandToRun = preset ? preset.command : tool.command;
      const toolToRun = { ...tool, command: commandToRun };
      
      if (tool.runner === 'internal') {
          const target = data.target || '';
          // Simple substitution for internal commands
          const command = commandToRun.replace(/{target}/g, target);

          if (tool.action === 'open-browser') {
             shell.openExternal(command);
          } else if (tool.action === 'copy') {
             clipboard.writeText(command);
          }
          this.setState({ activeTool: null, toolSelectorOpen: false });
          return;
      }

      this.toolRunner.launch(toolToRun, data.target || 'localhost');
      this.setState({ activeTool: null, toolSelectorOpen: false });
    }
    
    closeModal() {
      this.setState({ activeTool: null, toolSelectorOpen: false });
    }

    launchWorkflow(workflow) {
      const { tools, data } = this.state;
      const target = data.target || 'localhost';
      const sequence = workflow.tools.map(id => tools.find(t => t.id === id)).filter(Boolean);
      sequence.forEach(tool => {
        this.toolRunner.launch(tool, target);
      });
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
          recs.push(...tools.filter(t => ['gobuster_dir', 'nikto', 'whatweb', 'wpscan', 'ffuf', 'nuclei'].includes(t.id)));
      }

      // Heuristic 2: If SMB ports open (139, 445), recommend Enum4Linux
      if (/139|445/.test(portsStr)) {
          recs.push(...tools.filter(t => t.id === 'enum4linux'));
      }

      // Heuristic 3: If SQL mentioned or port 3306, recommend SQLMap
      if (/3306|5432|1433/.test(portsStr) || /sql/i.test(portsStr)) {
          recs.push(...tools.filter(t => t.id === 'sqlmap'));
      }

      // Remove duplicates
      return [...new Set(recs)];
    }

    render() {
      const { data, tools, workflows, activeTool, toolSelectorOpen, selectorType } = this.state;
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
                      paddingBottom: '5px',
                      cursor: 'pointer'
                    },
                    onClick: () => {
                         const newTarget = prompt("Set Target IP/URL:", data.target);
                         if (newTarget) this.setTarget(newTarget);
                    }
                  }, `🎯 ${data.target}`),

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
                            onClick: () => this.launchTool(tool)
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
                            onClick: () => this.launchTool(tool)
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
          const filteredTools = tools.filter(t => !selectorType || !t.types || t.types.includes(selectorType));
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
                                  onClick: () => this.launchTool(tool),
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
                      onClick: () => this.executeTool(activeTool, preset),
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
                  onClick: () => this.executeTool(activeTool),
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

