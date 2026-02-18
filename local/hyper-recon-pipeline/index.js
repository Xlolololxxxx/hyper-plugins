'use strict';

// ======================================================================
//  HYPER RECON PIPELINE
//  Automated multi-step reconnaissance chain orchestrator.
//  Define pipelines where each step's output feeds the next.
//  Visual progress in HUD tab. Pause/skip/branch at any step.
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

const TICK_MS = 1000;
const OUTPUT_BUFFER_MAX = 2000;
const MAX_CONCURRENT_FANOUT = 3;
const PROMPT_PATTERNS = [
  /[$#]\s*$/,
  /\u250c\u2500\u2500/,             // box-drawing: top-left corner
  /\u276f\s*$/,                      // heavy right-pointing angle
  />\s*$/,
  /\]\$\s*$/,
  /\]#\s*$/,
];

// ------ Shell Safety --------------------------------------------------

function esc(str) {
  if (typeof str !== 'string') str = String(str);
  return "'" + str.replace(/'/g, "'\\''") + "'";
}

function stripAnsi(str) {
  return str
    .replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '')
    .replace(/\x1b\][^\x07]*\x07/g, '')
    .replace(/\x1b[()][AB012]/g, '')
    .replace(/\x1b\[[\?]?[0-9;]*[hlm]/g, '')
    .replace(/\r/g, '');
}

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

// ------ Unique ID Generator -------------------------------------------

let _idCounter = 0;
function nextId() { return 'pl-' + (++_idCounter) + '-' + Date.now().toString(36); }

// ======================================================================
//  OUTPUT PARSERS
//  Each parser extracts targets from a step's output for the next step.
// ======================================================================

const outputParsers = {
  // subfinder: one subdomain per line
  subfinder(lines) {
    const results = [];
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      if (/^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(trimmed)) {
        results.push(trimmed);
      }
    }
    return [...new Set(results)];
  },

  // httpx: URL [STATUS] [TITLE] [TECH] -- extract URLs
  httpx(lines) {
    const results = [];
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      // httpx outputs: https://example.com [200] [Title] or just URL
      const urlMatch = trimmed.match(/^(https?:\/\/\S+)/);
      if (urlMatch) {
        results.push(urlMatch[1]);
      }
    }
    return [...new Set(results)];
  },

  // nmap: parse open ports and services
  nmap(lines) {
    const ports = [];
    let currentTarget = null;
    for (const line of lines) {
      const targetMatch = line.match(/Nmap scan report for\s+(\S+)/i);
      if (targetMatch) {
        currentTarget = targetMatch[1].replace(/[()]/g, '');
        continue;
      }
      const portMatch = line.match(/^(\d{1,5})\/(tcp|udp)\s+(open)\s+(\S+)/);
      if (portMatch) {
        const port = parseInt(portMatch[1], 10);
        const service = portMatch[4];
        const isHttp = /^https?$/.test(service) || /http/i.test(service) || port === 80 || port === 443 || port === 8080 || port === 8443;
        ports.push({
          port,
          proto: portMatch[2],
          service,
          isHttp,
          target: currentTarget,
        });
      }
    }
    return ports;
  },

  // nmap_http: extract only HTTP service URLs from nmap output
  nmap_http(lines) {
    const parsed = outputParsers.nmap(lines);
    const urls = [];
    for (const p of parsed) {
      if (p.isHttp && p.target) {
        const scheme = (p.port === 443 || p.port === 8443) ? 'https' : 'http';
        const portSuffix = (p.port === 80 || p.port === 443) ? '' : ':' + p.port;
        urls.push(scheme + '://' + p.target + portSuffix);
      }
    }
    return [...new Set(urls)];
  },

  // nmap_ports: extract all open port numbers
  nmap_ports(lines) {
    const parsed = outputParsers.nmap(lines);
    return parsed.map(p => ({ target: p.target, port: p.port, service: p.service, isHttp: p.isHttp }));
  },

  // whatweb: pass-through (not typically parsed for next step)
  whatweb(lines) {
    return lines.filter(l => l.trim().length > 0);
  },

  // gobuster: extract found paths
  gobuster(lines) {
    const results = [];
    for (const line of lines) {
      // /path (Status: 200) [Size: 1234]
      const m = line.match(/^(\/\S+)\s+\(Status:\s*(\d+)\)/);
      if (m && parseInt(m[2], 10) < 400) {
        results.push(m[1]);
      }
      // Found: /path [200]
      const m2 = line.match(/^Found:\s*(\/\S+)\s+\[(\d+)\]/i);
      if (m2 && parseInt(m2[2], 10) < 400) {
        results.push(m2[1]);
      }
    }
    return [...new Set(results)];
  },

  // line: one item per line (generic)
  line(lines) {
    return lines.map(l => l.trim()).filter(l => l.length > 0);
  },
};

// ======================================================================
//  PRE-BUILT PIPELINE TEMPLATES
// ======================================================================

const PIPELINE_TEMPLATES = {
  domain: {
    name: 'Domain Recon',
    description: 'Subdomains -> Live hosts -> Port scan -> Vuln scan',
    targetLabel: 'Domain (e.g. example.com)',
    steps: [
      {
        name: 'Subfinder',
        cmdTemplate: 'subfinder -d {target} -silent',
        parser: 'subfinder',
        fanout: false,
        description: 'Enumerate subdomains',
      },
      {
        name: 'HTTPX',
        cmdTemplate: 'echo {targets_newline} | httpx -silent -status-code -title -tech-detect',
        parser: 'httpx',
        fanout: false,
        inputMode: 'pipe_all',
        description: 'Probe live HTTP hosts',
      },
      {
        name: 'Nmap',
        cmdTemplate: 'nmap -sV -sC -p- --min-rate 1000 {target}',
        parser: 'nmap_http',
        fanout: true,
        inputField: 'host_from_url',
        description: 'Full port scan per live host',
      },
      {
        name: 'Nikto',
        cmdTemplate: 'nikto -h {target}',
        parser: 'line',
        fanout: true,
        description: 'Vulnerability scan on HTTP services',
      },
    ],
  },

  ip: {
    name: 'IP Recon',
    description: 'Services -> Fingerprint -> Dir scan -> Vuln scan',
    targetLabel: 'IP Address (e.g. 10.10.10.1)',
    steps: [
      {
        name: 'Nmap',
        cmdTemplate: 'nmap -sV -sC {target}',
        parser: 'nmap_ports',
        fanout: false,
        description: 'Service enumeration',
      },
      {
        name: 'WhatWeb',
        cmdTemplate: 'whatweb http://{target}:{port}',
        parser: 'whatweb',
        fanout: true,
        inputFilter: 'http_only',
        description: 'Technology fingerprinting',
      },
      {
        name: 'Gobuster',
        cmdTemplate: 'gobuster dir -u http://{target}:{port} -w /usr/share/wordlists/dirb/common.txt',
        parser: 'gobuster',
        fanout: true,
        inputFilter: 'http_only',
        description: 'Directory enumeration',
      },
      {
        name: 'Nikto',
        cmdTemplate: 'nikto -h http://{target}:{port}',
        parser: 'line',
        fanout: true,
        inputFilter: 'http_only',
        description: 'Vulnerability scanning',
      },
    ],
  },

  webapp: {
    name: 'Web App Recon',
    description: 'Fingerprint -> Dirs -> Vulns -> SQLi',
    targetLabel: 'URL (e.g. http://target.com)',
    steps: [
      {
        name: 'WhatWeb',
        cmdTemplate: 'whatweb {target}',
        parser: 'whatweb',
        fanout: false,
        description: 'Technology fingerprinting',
      },
      {
        name: 'Gobuster',
        cmdTemplate: 'gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -x php,html,js,txt',
        parser: 'gobuster',
        fanout: false,
        description: 'Directory enumeration',
      },
      {
        name: 'Nikto',
        cmdTemplate: 'nikto -h {target}',
        parser: 'line',
        fanout: false,
        description: 'Vulnerability scan',
      },
      {
        name: 'SQLMap',
        cmdTemplate: 'sqlmap -u {target} --batch --crawl=2',
        parser: 'line',
        fanout: false,
        description: 'SQL injection testing',
      },
    ],
  },

  custom: {
    name: 'Custom Pipeline',
    description: 'Define your own steps',
    targetLabel: 'Target',
    steps: [],
  },
};

// ======================================================================
//  PIPELINE ENGINE
// ======================================================================

let activeUid = null;
let hudApi = null;
let hudRegistered = false;
let renderCallback = null;
let tickTimer = null;
let promptRegex = null;   // user-configurable

const pipelines = new Map();        // id -> pipeline state
const ptyBuffers = new Map();       // uid -> { partial, collecting, pipeline }
let customStepDraft = [];           // for custom pipeline builder

function isPromptLine(line) {
  if (promptRegex) {
    try { return promptRegex.test(line); } catch { /* fall through */ }
  }
  for (const pat of PROMPT_PATTERNS) {
    if (pat.test(line)) return true;
  }
  return false;
}

function execCmd(cmd, uid) {
  const target = uid || activeUid;
  if (!target) return;
  window.rpc.emit('data', { uid: target, data: cmd + '\n', escaped: false });
}

// Build actual command from template + variables
function buildCommand(template, vars) {
  let cmd = template;
  for (const [key, val] of Object.entries(vars)) {
    const placeholder = '{' + key + '}';
    if (cmd.includes(placeholder)) {
      if (key === 'targets_newline') {
        // For pipe mode, join with actual newlines inside printf
        const escaped = val.map(v => esc(v)).join('\\n');
        cmd = cmd.replace(placeholder, escaped);
        // Rewrite: echo 'a'\n'b' | ... -> printf 'a\nb\n' | ...
        cmd = cmd.replace(/^echo\s+/, 'printf \'');
        // find the pipe
        const pipeIdx = cmd.indexOf('|');
        if (pipeIdx > 0) {
          const before = cmd.substring(0, pipeIdx).replace(/'\s*$/, '');
          const after = cmd.substring(pipeIdx);
          // Rebuild with printf
          const targets = val.map(v => v.replace(/'/g, "")).join('\\n');
          cmd = "printf '" + targets + "\\n' " + after;
        }
      } else {
        cmd = cmd.split(placeholder).join(esc(val));
      }
    }
  }
  return cmd;
}

// Extract host from URL
function hostFromUrl(url) {
  try {
    const u = new URL(url);
    return u.hostname;
  } catch {
    return url.replace(/^https?:\/\//, '').replace(/[:\/].*$/, '');
  }
}

// Create a new pipeline from a template
function createPipeline(templateKey, target, customSteps) {
  const tpl = PIPELINE_TEMPLATES[templateKey];
  if (!tpl) return null;

  const steps = (templateKey === 'custom' && customSteps)
    ? customSteps.map((s, i) => ({
        name: s.name || ('Step ' + (i + 1)),
        cmdTemplate: s.cmd,
        parser: s.parser || 'line',
        fanout: !!s.fanout,
        description: s.description || '',
        status: 'pending',
        output: [],
        targets: [],
        elapsed: 0,
        currentTarget: null,
        fanoutQueue: [],
        fanoutCompleted: 0,
        fanoutTotal: 0,
      }))
    : tpl.steps.map(s => ({
        ...s,
        status: 'pending',
        output: [],
        targets: [],
        elapsed: 0,
        currentTarget: null,
        fanoutQueue: [],
        fanoutCompleted: 0,
        fanoutTotal: 0,
      }));

  const pipeline = {
    id: nextId(),
    name: tpl.name,
    templateKey,
    target,
    steps,
    currentStep: -1,
    status: 'pending',
    startTime: null,
    endTime: null,
    expanded: true,
  };

  pipelines.set(pipeline.id, pipeline);
  return pipeline;
}

// Start or resume a pipeline
function startPipeline(pipeline) {
  if (pipeline.status === 'running') return;
  pipeline.status = 'running';
  pipeline.startTime = pipeline.startTime || Date.now();

  const recon = getRecon();
  recon.events.emit('pipeline:start', { pipeline });

  advanceStep(pipeline);
  updateBadge();
  triggerRender();
}

// Advance to the next step
function advanceStep(pipeline) {
  if (pipeline.status === 'cancelled' || pipeline.status === 'paused') return;

  const nextStepIdx = pipeline.currentStep + 1;
  if (nextStepIdx >= pipeline.steps.length) {
    completePipeline(pipeline);
    return;
  }

  pipeline.currentStep = nextStepIdx;
  const step = pipeline.steps[nextStepIdx];
  step.status = 'running';
  step.startTime = Date.now();

  const recon = getRecon();
  recon.events.emit('pipeline:step', { pipeline, step, status: 'running' });

  // Determine targets for this step
  let targets = [];
  if (nextStepIdx === 0) {
    targets = [pipeline.target];
  } else {
    const prevStep = pipeline.steps[nextStepIdx - 1];
    targets = prevStep.targets.length > 0 ? prevStep.targets : [pipeline.target];
  }

  // For IP Recon pipeline: nmap_ports parser returns objects with port info
  // Filter for HTTP-only if needed
  if (step.inputFilter === 'http_only' && targets.length > 0 && typeof targets[0] === 'object') {
    targets = targets.filter(t => t.isHttp);
  }

  if (step.fanout && targets.length > 0) {
    // Fan-out mode: run command for each target
    let resolvedTargets;
    if (typeof targets[0] === 'object' && targets[0].port !== undefined) {
      // nmap_ports results
      resolvedTargets = targets.map(t => ({
        target: t.target || pipeline.target,
        port: t.port,
        raw: t,
      }));
    } else if (step.inputField === 'host_from_url') {
      resolvedTargets = targets.map(t => ({ target: hostFromUrl(t), raw: t }));
    } else {
      resolvedTargets = targets.map(t => ({ target: typeof t === 'string' ? t : String(t), raw: t }));
    }

    step.fanoutQueue = resolvedTargets.slice();
    step.fanoutTotal = resolvedTargets.length;
    step.fanoutCompleted = 0;
    step.fanoutActive = 0;

    // Process fan-out queue with concurrency limit
    processFanoutQueue(pipeline, step);
  } else if (step.inputMode === 'pipe_all') {
    // Pipe all targets together
    const targetList = targets.map(t => typeof t === 'string' ? t : String(t));
    const cmd = buildPipeAllCommand(step.cmdTemplate, targetList);
    executeStepCommand(pipeline, step, cmd, targetList.join(', '));
  } else {
    // Single target mode
    const targetStr = typeof targets[0] === 'string' ? targets[0] : String(targets[0]);
    const vars = { target: targetStr };
    const cmd = buildCommand(step.cmdTemplate, vars);
    executeStepCommand(pipeline, step, cmd, targetStr);
  }

  triggerRender();
}

function buildPipeAllCommand(template, targets) {
  // printf 'a\nb\n' | httpx ...
  const escaped = targets.map(t => t.replace(/'/g, "")).join('\\n');
  const pipeIdx = template.indexOf('|');
  if (pipeIdx > 0 && template.includes('{targets_newline}')) {
    const after = template.substring(pipeIdx);
    return "printf '" + escaped + "\\n' " + after;
  }
  // Fallback: just substitute
  let cmd = template;
  cmd = cmd.replace('{targets_newline}', escaped);
  cmd = cmd.replace('{target}', esc(targets[0] || ''));
  return cmd;
}

function processFanoutQueue(pipeline, step) {
  if (pipeline.status !== 'running' || step.status !== 'running') return;

  while (step.fanoutActive < MAX_CONCURRENT_FANOUT && step.fanoutQueue.length > 0) {
    const item = step.fanoutQueue.shift();
    step.fanoutActive++;

    const vars = { target: item.target };
    if (item.port !== undefined) vars.port = String(item.port);

    const cmd = buildCommand(step.cmdTemplate, vars);
    step.currentTarget = item.target + (item.port ? ':' + item.port : '');

    // For fan-out, we execute sequentially by waiting for prompt after each
    executeStepCommand(pipeline, step, cmd, step.currentTarget, true);
    // Only start one at a time for sequential execution
    break;
  }
}

function executeStepCommand(pipeline, step, cmd, displayTarget, isFanout) {
  step.currentTarget = displayTarget;
  step.currentCmd = cmd;
  step._isFanout = !!isFanout;

  // Setup output capture
  const uid = activeUid;
  if (!uid) {
    step.status = 'error';
    step.output.push('[pipeline] No active terminal session');
    advanceStep(pipeline);
    return;
  }

  pipeline._activeUid = uid;

  // Initialize PTY buffer collector
  ptyBuffers.set(uid, {
    collecting: true,
    pipelineId: pipeline.id,
    stepIdx: pipeline.currentStep,
    buffer: [],
    cmdSent: false,
    promptCount: 0,
    lastDataTime: Date.now(),
    isFanout: !!isFanout,
  });

  // Send the command
  execCmd(cmd, uid);

  // Mark as sent after a tick (the command echo will appear first)
  setTimeout(() => {
    const buf = ptyBuffers.get(uid);
    if (buf && buf.pipelineId === pipeline.id) {
      buf.cmdSent = true;
    }
  }, 500);

  triggerRender();
}

// Handle PTY data for active pipeline
function handlePtyData(uid, rawData) {
  const buf = ptyBuffers.get(uid);
  if (!buf || !buf.collecting) return;

  const pipeline = pipelines.get(buf.pipelineId);
  if (!pipeline || pipeline.status !== 'running') {
    ptyBuffers.delete(uid);
    return;
  }

  const step = pipeline.steps[buf.stepIdx];
  if (!step || step.status !== 'running') return;

  const cleaned = stripAnsi(rawData);
  const lines = cleaned.split(/\n/);

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    // Skip the command echo itself
    if (!buf.cmdSent) continue;

    // Check for prompt (command completion)
    if (isPromptLine(trimmed) && trimmed.length < 300) {
      buf.promptCount++;
      // Require seeing the prompt after some actual output or time
      const hasOutput = buf.buffer.length > 0;
      const timeElapsed = (Date.now() - buf.lastDataTime) > 1000;
      if (buf.promptCount >= 1 && (hasOutput || timeElapsed)) {
        onStepCommandComplete(pipeline, step, buf, uid);
        return;
      }
    } else {
      buf.promptCount = 0;
      buf.buffer.push(trimmed);
      // Enforce buffer limit
      if (buf.buffer.length > OUTPUT_BUFFER_MAX) {
        buf.buffer = buf.buffer.slice(-OUTPUT_BUFFER_MAX);
      }
    }
  }

  buf.lastDataTime = Date.now();
  triggerRender();
}

function onStepCommandComplete(pipeline, step, buf, uid) {
  // Capture output
  const capturedLines = buf.buffer.slice();
  step.output.push(...capturedLines);

  // Enforce output limit on step
  if (step.output.length > OUTPUT_BUFFER_MAX) {
    step.output = step.output.slice(-OUTPUT_BUFFER_MAX);
  }

  ptyBuffers.delete(uid);

  if (buf.isFanout) {
    step.fanoutCompleted++;
    step.fanoutActive--;

    // Parse output for targets using this step's parser
    const parser = outputParsers[step.parser] || outputParsers.line;
    const parsed = parser(capturedLines);
    for (const t of parsed) {
      if (!step.targets.includes(t)) {
        step.targets.push(t);
      }
    }

    // Process next in fan-out queue
    if (step.fanoutQueue.length > 0 && pipeline.status === 'running') {
      processFanoutQueue(pipeline, step);
    } else if (step.fanoutActive <= 0) {
      // All fan-out tasks completed
      step.status = 'completed';
      step.elapsed = Date.now() - (step.startTime || pipeline.startTime);
      step.currentTarget = null;

      const recon = getRecon();
      recon.events.emit('pipeline:step', { pipeline, step, status: 'completed' });

      advanceStep(pipeline);
    }
  } else {
    // Single command step completed
    const parser = outputParsers[step.parser] || outputParsers.line;
    step.targets = parser(step.output);
    step.status = 'completed';
    step.elapsed = Date.now() - (step.startTime || pipeline.startTime);
    step.currentTarget = null;

    const recon = getRecon();
    recon.events.emit('pipeline:step', { pipeline, step, status: 'completed' });

    advanceStep(pipeline);
  }

  updateBadge();
  triggerRender();
}

function completePipeline(pipeline) {
  pipeline.status = 'completed';
  pipeline.endTime = Date.now();

  const recon = getRecon();
  recon.events.emit('pipeline:complete', { pipeline });

  if (hudApi) {
    hudApi.notify('Pipeline complete: ' + pipeline.name + ' -> ' + pipeline.target, 'info');
  }

  updateBadge();
  triggerRender();
}

// Pause: wait for current step to finish, then hold
function pausePipeline(pipelineId) {
  const pipeline = pipelines.get(pipelineId);
  if (!pipeline || pipeline.status !== 'running') return;
  pipeline.status = 'paused';

  const recon = getRecon();
  recon.events.emit('pipeline:step', { pipeline, step: pipeline.steps[pipeline.currentStep], status: 'paused' });

  updateBadge();
  triggerRender();
}

// Resume a paused pipeline
function resumePipeline(pipelineId) {
  const pipeline = pipelines.get(pipelineId);
  if (!pipeline || pipeline.status !== 'paused') return;
  pipeline.status = 'running';

  const step = pipeline.steps[pipeline.currentStep];
  if (step && step.status === 'completed') {
    advanceStep(pipeline);
  } else if (step && step.status === 'running') {
    // Step was still running when paused, it will continue
  }

  updateBadge();
  triggerRender();
}

// Skip current step and move to next
function skipStep(pipelineId) {
  const pipeline = pipelines.get(pipelineId);
  if (!pipeline || pipeline.status === 'cancelled' || pipeline.status === 'completed') return;

  const step = pipeline.steps[pipeline.currentStep];
  if (step) {
    step.status = 'skipped';
    step.elapsed = Date.now() - (step.startTime || pipeline.startTime);
    // Send Ctrl+C if actively running
    if (pipeline._activeUid) {
      window.rpc.emit('data', { uid: pipeline._activeUid, data: '\x03', escaped: false });
      ptyBuffers.delete(pipeline._activeUid);
    }
  }

  // If paused, set back to running
  if (pipeline.status === 'paused') pipeline.status = 'running';

  advanceStep(pipeline);
  updateBadge();
  triggerRender();
}

// Cancel pipeline entirely
function cancelPipeline(pipelineId) {
  const pipeline = pipelines.get(pipelineId);
  if (!pipeline) return;

  pipeline.status = 'cancelled';
  pipeline.endTime = Date.now();

  const step = pipeline.steps[pipeline.currentStep];
  if (step && step.status === 'running') {
    step.status = 'cancelled';
    // Send Ctrl+C
    if (pipeline._activeUid) {
      window.rpc.emit('data', { uid: pipeline._activeUid, data: '\x03', escaped: false });
      ptyBuffers.delete(pipeline._activeUid);
    }
  }

  updateBadge();
  triggerRender();
}

// Remove completed/cancelled pipeline from list
function removePipeline(pipelineId) {
  pipelines.delete(pipelineId);
  updateBadge();
  triggerRender();
}

// ------ Badge + Render Helpers ----------------------------------------

function getActiveCount() {
  let count = 0;
  for (const p of pipelines.values()) {
    if (p.status === 'running' || p.status === 'paused') count++;
  }
  return count;
}

function updateBadge() {
  if (!hudApi) return;
  const count = getActiveCount();
  hudApi.updateBadge('pipeline', count > 0 ? count : null);
}

function triggerRender() {
  if (renderCallback) renderCallback();
}

// ======================================================================
//  HUD TAB UI
// ======================================================================

// Inject CSS styles
function injectStyles() {
  if (typeof document === 'undefined') return;
  if (document.getElementById('recon-pipeline-styles')) return;
  const style = document.createElement('style');
  style.id = 'recon-pipeline-styles';
  style.textContent = `
    @keyframes pipeline-pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.4; }
    }
    @keyframes pipeline-spin {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }
    .pl-btn { transition: background 0.15s, opacity 0.15s; cursor: pointer; user-select: none; }
    .pl-btn:hover { opacity: 0.85; }
    .pl-btn:active { opacity: 0.7; }
    .pl-step-circle { transition: background 0.2s, border-color 0.2s, box-shadow 0.2s; }
    .pl-card:hover { border-color: #30363d !important; }
    .pl-expand:hover { color: #c9d1d9 !important; }
    .pl-output-line:hover { background: #21262d; }
  `;
  document.head.appendChild(style);
}

// ------ State for the pipeline creator form ----------------------------
let formState = {
  selectedTemplate: 'domain',
  targetInput: '',
  customSteps: [{ name: '', cmd: '', parser: 'line', fanout: false, description: '' }],
  showForm: true,
};

function renderPipelineTab(React) {
  injectStyles();
  const h = React.createElement;

  const pipelineList = Array.from(pipelines.values()).sort((a, b) => (b.startTime || 0) - (a.startTime || 0));

  return h('div', { style: { fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif", fontSize: '12px' } },
    // Pipeline creator form
    renderCreatorForm(h),
    // Separator
    pipelineList.length > 0 && h('div', { style: { borderBottom: '1px solid #21262d', margin: '10px 0' } }),
    // Pipeline list
    pipelineList.length > 0
      ? h('div', { style: { display: 'flex', flexDirection: 'column', gap: '8px' } },
          ...pipelineList.map(p => renderPipelineCard(h, p))
        )
      : null
  );
}

function renderCreatorForm(h) {
  const templates = [
    { key: 'domain', label: 'Domain Recon', icon: '\u{1F310}' },
    { key: 'ip', label: 'IP Recon', icon: '\u{1F5A5}' },
    { key: 'webapp', label: 'Web App', icon: '\u{1F578}' },
    { key: 'custom', label: 'Custom', icon: '\u{2699}' },
  ];

  const tpl = PIPELINE_TEMPLATES[formState.selectedTemplate];

  return h('div', null,
    // Template selector buttons
    h('div', { style: { display: 'flex', gap: '4px', marginBottom: '8px', flexWrap: 'wrap' } },
      ...templates.map(t => {
        const isActive = formState.selectedTemplate === t.key;
        return h('div', {
          key: t.key,
          className: 'pl-btn',
          style: {
            padding: '5px 12px',
            borderRadius: '6px',
            fontSize: '11px',
            fontWeight: isActive ? 700 : 400,
            background: isActive ? '#1f6feb' : '#21262d',
            color: isActive ? '#fff' : '#8b949e',
            border: '1px solid ' + (isActive ? '#388bfd' : '#30363d'),
            display: 'flex',
            alignItems: 'center',
            gap: '4px',
          },
          onClick: () => {
            formState.selectedTemplate = t.key;
            triggerRender();
          },
        },
          h('span', null, t.icon),
          t.label
        );
      })
    ),

    // Template description + steps preview
    tpl && formState.selectedTemplate !== 'custom' && h('div', {
      style: {
        padding: '6px 10px',
        background: '#161b22',
        borderRadius: '4px',
        marginBottom: '8px',
        fontSize: '10px',
        color: '#8b949e',
        border: '1px solid #21262d',
      },
    },
      h('div', { style: { marginBottom: '4px', fontWeight: 600, color: '#c9d1d9' } }, tpl.description),
      h('div', { style: { display: 'flex', gap: '6px', flexWrap: 'wrap' } },
        ...tpl.steps.map((s, i) =>
          h('span', {
            key: i,
            style: {
              padding: '2px 6px',
              background: '#0d1117',
              borderRadius: '3px',
              border: '1px solid #30363d',
              fontSize: '9px',
              color: '#58a6ff',
            },
          }, (i + 1) + '. ' + s.name)
        )
      )
    ),

    // Custom steps editor
    formState.selectedTemplate === 'custom' && renderCustomStepEditor(h),

    // Target input + Start button
    h('div', { style: { display: 'flex', gap: '6px', alignItems: 'center' } },
      h('input', {
        type: 'text',
        placeholder: tpl ? tpl.targetLabel : 'Target',
        value: formState.targetInput,
        onChange: (e) => { formState.targetInput = e.target.value; triggerRender(); },
        onKeyDown: (e) => { if (e.key === 'Enter' && formState.targetInput.trim()) onStartPipeline(); },
        style: {
          flex: 1,
          padding: '6px 10px',
          background: '#0d1117',
          border: '1px solid #30363d',
          borderRadius: '6px',
          color: '#c9d1d9',
          fontSize: '12px',
          outline: 'none',
          fontFamily: 'monospace',
        },
      }),
      h('div', {
        className: 'pl-btn',
        style: {
          padding: '6px 16px',
          background: '#238636',
          color: '#fff',
          borderRadius: '6px',
          fontWeight: 700,
          fontSize: '11px',
          border: '1px solid #2ea043',
          opacity: formState.targetInput.trim() ? 1 : 0.4,
          pointerEvents: formState.targetInput.trim() ? 'auto' : 'none',
        },
        onClick: () => onStartPipeline(),
      }, 'Start')
    )
  );
}

function renderCustomStepEditor(h) {
  const steps = formState.customSteps;

  return h('div', {
    style: {
      padding: '8px',
      background: '#161b22',
      border: '1px solid #21262d',
      borderRadius: '6px',
      marginBottom: '8px',
    },
  },
    h('div', { style: { fontWeight: 600, marginBottom: '6px', color: '#c9d1d9', fontSize: '11px' } }, 'Custom Steps'),
    ...steps.map((step, idx) =>
      h('div', {
        key: idx,
        style: {
          display: 'flex',
          gap: '4px',
          marginBottom: '4px',
          alignItems: 'center',
        },
      },
        h('span', { style: { color: '#484f58', fontSize: '10px', minWidth: '16px' } }, (idx + 1) + '.'),
        h('input', {
          placeholder: 'Step name',
          value: step.name,
          onChange: (e) => { steps[idx].name = e.target.value; triggerRender(); },
          style: inputStyle('80px'),
        }),
        h('input', {
          placeholder: 'Command (use {target})',
          value: step.cmd,
          onChange: (e) => { steps[idx].cmd = e.target.value; triggerRender(); },
          style: inputStyle('1'),
        }),
        h('select', {
          value: step.parser,
          onChange: (e) => { steps[idx].parser = e.target.value; triggerRender(); },
          style: { ...selectStyle(), minWidth: '70px' },
        },
          h('option', { value: 'line' }, 'line'),
          h('option', { value: 'subfinder' }, 'subfinder'),
          h('option', { value: 'httpx' }, 'httpx'),
          h('option', { value: 'nmap' }, 'nmap'),
          h('option', { value: 'nmap_http' }, 'nmap_http'),
          h('option', { value: 'nmap_ports' }, 'nmap_ports'),
          h('option', { value: 'gobuster' }, 'gobuster'),
          h('option', { value: 'whatweb' }, 'whatweb')
        ),
        h('label', {
          style: { display: 'flex', alignItems: 'center', gap: '2px', color: '#8b949e', fontSize: '9px', cursor: 'pointer' },
        },
          h('input', {
            type: 'checkbox',
            checked: step.fanout,
            onChange: (e) => { steps[idx].fanout = e.target.checked; triggerRender(); },
            style: { width: '12px', height: '12px' },
          }),
          'fan'
        ),
        // Remove step button
        steps.length > 1 && h('span', {
          className: 'pl-btn',
          style: { color: '#f85149', fontSize: '12px', padding: '0 4px', fontWeight: 700 },
          onClick: () => { steps.splice(idx, 1); triggerRender(); },
        }, '\u2715')
      )
    ),
    // Add step button
    h('div', {
      className: 'pl-btn',
      style: {
        marginTop: '4px',
        padding: '3px 10px',
        background: '#21262d',
        borderRadius: '4px',
        color: '#8b949e',
        fontSize: '10px',
        display: 'inline-block',
        border: '1px solid #30363d',
      },
      onClick: () => {
        steps.push({ name: '', cmd: '', parser: 'line', fanout: false, description: '' });
        triggerRender();
      },
    }, '+ Add Step')
  );
}

function inputStyle(flexOrWidth) {
  const base = {
    padding: '4px 6px',
    background: '#0d1117',
    border: '1px solid #30363d',
    borderRadius: '4px',
    color: '#c9d1d9',
    fontSize: '10px',
    outline: 'none',
    fontFamily: 'monospace',
  };
  if (flexOrWidth === '1') {
    base.flex = 1;
  } else {
    base.width = flexOrWidth;
  }
  return base;
}

function selectStyle() {
  return {
    padding: '4px 4px',
    background: '#0d1117',
    border: '1px solid #30363d',
    borderRadius: '4px',
    color: '#c9d1d9',
    fontSize: '10px',
    outline: 'none',
  };
}

function onStartPipeline() {
  const target = formState.targetInput.trim();
  if (!target) return;

  let pipeline;
  if (formState.selectedTemplate === 'custom') {
    const validSteps = formState.customSteps.filter(s => s.cmd.trim());
    if (validSteps.length === 0) return;
    pipeline = createPipeline('custom', target, validSteps);
  } else {
    pipeline = createPipeline(formState.selectedTemplate, target);
  }

  if (!pipeline) return;

  formState.targetInput = '';
  startPipeline(pipeline);
}

// ------ Pipeline Card Rendering ---------------------------------------

function renderPipelineCard(h, pipeline) {
  const isRunning = pipeline.status === 'running';
  const isPaused = pipeline.status === 'paused';
  const isActive = isRunning || isPaused;

  const statusColors = {
    pending: '#484f58',
    running: '#3fb950',
    paused: '#d29922',
    completed: '#58a6ff',
    cancelled: '#f85149',
  };
  const statusColor = statusColors[pipeline.status] || '#8b949e';

  return h('div', {
    className: 'pl-card',
    style: {
      background: '#161b22',
      border: '1px solid #21262d',
      borderRadius: '6px',
      overflow: 'hidden',
      opacity: isActive ? 1 : 0.8,
    },
  },
    // Card header
    h('div', {
      style: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        padding: '8px 10px',
        borderBottom: pipeline.expanded ? '1px solid #21262d' : 'none',
        cursor: 'pointer',
      },
      onClick: () => { pipeline.expanded = !pipeline.expanded; triggerRender(); },
    },
      // Status indicator
      h('div', {
        style: {
          width: '8px',
          height: '8px',
          borderRadius: '50%',
          background: statusColor,
          flexShrink: 0,
          animation: isRunning ? 'pipeline-pulse 1.5s ease-in-out infinite' : 'none',
          boxShadow: isRunning ? '0 0 6px ' + statusColor : 'none',
        },
      }),

      // Pipeline name
      h('span', { style: { fontWeight: 700, color: '#c9d1d9', fontSize: '11px' } }, pipeline.name),

      // Target
      h('span', {
        style: {
          color: '#58a6ff',
          fontSize: '11px',
          fontFamily: 'monospace',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
          flex: 1,
        },
      }, pipeline.target),

      // Step progress
      h('span', {
        style: { color: '#8b949e', fontSize: '10px', fontFamily: 'monospace', flexShrink: 0 },
      }, (pipeline.currentStep + 1) + '/' + pipeline.steps.length),

      // Elapsed time
      pipeline.startTime && h('span', {
        style: { color: '#8b949e', fontSize: '10px', fontFamily: 'monospace', flexShrink: 0, minWidth: '45px', textAlign: 'right' },
      }, elapsed((pipeline.endTime || Date.now()) - pipeline.startTime)),

      // Status badge
      h('span', {
        style: {
          fontSize: '9px',
          fontWeight: 600,
          padding: '1px 6px',
          borderRadius: '8px',
          textTransform: 'uppercase',
          letterSpacing: '0.3px',
          background: statusColor + '22',
          color: statusColor,
          border: '1px solid ' + statusColor + '44',
          flexShrink: 0,
        },
      }, pipeline.status),

      // Expand/collapse
      h('span', {
        className: 'pl-expand',
        style: { color: '#484f58', fontSize: '10px', flexShrink: 0 },
      }, pipeline.expanded ? '\u25B2' : '\u25BC')
    ),

    // Expanded content
    pipeline.expanded && h('div', { style: { padding: '8px 10px' } },
      // Step progress visualization
      renderStepProgress(h, pipeline),

      // Current step details
      isActive && pipeline.currentStep >= 0 && renderCurrentStep(h, pipeline),

      // Controls
      isActive && renderControls(h, pipeline),

      // Completed step outputs
      (!isActive || pipeline.expanded) && renderStepOutputs(h, pipeline)
    )
  );
}

// Step progress circles connected by lines
function renderStepProgress(h, pipeline) {
  const steps = pipeline.steps;

  return h('div', {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '0',
      padding: '8px 0',
      marginBottom: '8px',
      overflowX: 'auto',
    },
  },
    ...steps.flatMap((step, idx) => {
      const items = [];

      const statusColors = {
        pending: { bg: '#21262d', border: '#30363d', text: '#484f58' },
        running: { bg: '#0d4429', border: '#3fb950', text: '#3fb950' },
        completed: { bg: '#0d2d6e', border: '#58a6ff', text: '#58a6ff' },
        skipped: { bg: '#2d1f00', border: '#d29922', text: '#d29922' },
        cancelled: { bg: '#3d0e0e', border: '#f85149', text: '#f85149' },
        error: { bg: '#3d0e0e', border: '#f85149', text: '#f85149' },
      };
      const colors = statusColors[step.status] || statusColors.pending;

      // Step circle
      items.push(
        h('div', {
          key: 'step-' + idx,
          className: 'pl-step-circle',
          style: {
            width: '28px',
            height: '28px',
            borderRadius: '50%',
            background: colors.bg,
            border: '2px solid ' + colors.border,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0,
            position: 'relative',
            boxShadow: step.status === 'running' ? '0 0 8px ' + colors.border + '66' : 'none',
          },
          title: step.name + ' - ' + step.status,
        },
          // Step number or checkmark
          h('span', {
            style: { fontSize: '9px', fontWeight: 700, color: colors.text },
          }, step.status === 'completed' ? '\u2713' : step.status === 'skipped' ? '\u2192' : String(idx + 1)),
          // Step name below
          h('span', {
            style: {
              position: 'absolute',
              top: '30px',
              fontSize: '8px',
              color: colors.text,
              whiteSpace: 'nowrap',
              textAlign: 'center',
              maxWidth: '60px',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
            },
          }, step.name)
        )
      );

      // Connecting line
      if (idx < steps.length - 1) {
        const nextStep = steps[idx + 1];
        const lineComplete = step.status === 'completed';
        items.push(
          h('div', {
            key: 'line-' + idx,
            style: {
              flex: 1,
              height: '2px',
              minWidth: '16px',
              background: lineComplete ? '#58a6ff' : '#30363d',
              transition: 'background 0.3s',
            },
          })
        );
      }

      return items;
    })
  );
}

function renderCurrentStep(h, pipeline) {
  const step = pipeline.steps[pipeline.currentStep];
  if (!step) return null;

  const stepElapsed = step.startTime ? elapsed(Date.now() - step.startTime) : '0s';
  const fanoutInfo = step.fanout && step.fanoutTotal > 0
    ? ' (' + step.fanoutCompleted + '/' + step.fanoutTotal + ' targets)'
    : '';

  return h('div', {
    style: {
      background: '#0d1117',
      border: '1px solid #21262d',
      borderRadius: '6px',
      padding: '8px 10px',
      marginBottom: '8px',
    },
  },
    // Step header
    h('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' } },
      // Spinner
      h('div', {
        style: {
          width: '12px',
          height: '12px',
          border: '2px solid #30363d',
          borderTop: '2px solid #3fb950',
          borderRadius: '50%',
          animation: pipeline.status === 'running' ? 'pipeline-spin 0.8s linear infinite' : 'none',
          flexShrink: 0,
        },
      }),
      h('span', { style: { fontWeight: 700, color: '#c9d1d9', fontSize: '11px' } },
        'Step ' + (pipeline.currentStep + 1) + ': ' + step.name),
      h('span', { style: { flex: 1 } }),
      h('span', {
        style: { color: '#8b949e', fontSize: '10px', fontFamily: 'monospace' },
      }, stepElapsed + fanoutInfo)
    ),

    // Command
    step.currentCmd && h('div', {
      style: {
        fontFamily: '"Cascadia Code", "Fira Code", monospace',
        fontSize: '10px',
        color: '#79c0ff',
        background: '#010409',
        padding: '4px 8px',
        borderRadius: '4px',
        marginBottom: '6px',
        overflowX: 'auto',
        whiteSpace: 'nowrap',
      },
    }, '$ ' + step.currentCmd),

    // Current target
    step.currentTarget && h('div', { style: { fontSize: '10px', color: '#8b949e', marginBottom: '4px' } },
      h('span', { style: { color: '#484f58' } }, 'Target: '),
      h('span', { style: { color: '#c9d1d9', fontFamily: 'monospace' } }, step.currentTarget)
    ),

    // Output preview (last 6 lines)
    step.output.length > 0 && h('div', {
      style: {
        maxHeight: '100px',
        overflowY: 'auto',
        fontFamily: 'monospace',
        fontSize: '9px',
        color: '#8b949e',
        lineHeight: '1.5',
        borderTop: '1px solid #21262d',
        paddingTop: '4px',
        marginTop: '4px',
      },
    },
      ...step.output.slice(-8).map((line, i) =>
        h('div', {
          key: i,
          className: 'pl-output-line',
          style: { padding: '1px 4px', borderRadius: '2px' },
        }, line)
      )
    )
  );
}

function renderControls(h, pipeline) {
  const isRunning = pipeline.status === 'running';
  const isPaused = pipeline.status === 'paused';

  const btnBase = {
    padding: '4px 12px',
    borderRadius: '4px',
    fontSize: '10px',
    fontWeight: 600,
    border: 'none',
    display: 'inline-flex',
    alignItems: 'center',
    gap: '4px',
  };

  return h('div', {
    style: { display: 'flex', gap: '6px', marginBottom: '8px' },
  },
    // Pause / Resume
    isRunning && h('div', {
      className: 'pl-btn',
      style: { ...btnBase, background: '#d29922', color: '#000' },
      onClick: () => pausePipeline(pipeline.id),
    }, '\u23F8 Pause'),

    isPaused && h('div', {
      className: 'pl-btn',
      style: { ...btnBase, background: '#238636', color: '#fff' },
      onClick: () => resumePipeline(pipeline.id),
    }, '\u25B6 Resume'),

    // Skip
    h('div', {
      className: 'pl-btn',
      style: { ...btnBase, background: '#21262d', color: '#c9d1d9', border: '1px solid #30363d' },
      onClick: () => skipStep(pipeline.id),
    }, '\u23ED Skip Step'),

    // Cancel
    h('div', {
      className: 'pl-btn',
      style: { ...btnBase, background: '#3d0e0e', color: '#f85149', border: '1px solid #f8514944' },
      onClick: () => cancelPipeline(pipeline.id),
    }, '\u2715 Cancel'),

    // Spacer
    h('div', { style: { flex: 1 } }),

    // Remove (only for non-active)
    !isRunning && !isPaused && h('div', {
      className: 'pl-btn',
      style: { ...btnBase, background: 'transparent', color: '#484f58', fontSize: '9px' },
      onClick: () => removePipeline(pipeline.id),
    }, 'Remove')
  );
}

function renderStepOutputs(h, pipeline) {
  const completedSteps = pipeline.steps.filter(s =>
    s.status === 'completed' || s.status === 'skipped' || s.status === 'cancelled'
  );

  if (completedSteps.length === 0) return null;

  return h('div', { style: { display: 'flex', flexDirection: 'column', gap: '4px' } },
    ...pipeline.steps.map((step, idx) => {
      if (step.status === 'pending' || step.status === 'running') return null;

      const statusColors = {
        completed: '#58a6ff',
        skipped: '#d29922',
        cancelled: '#f85149',
        error: '#f85149',
      };
      const color = statusColors[step.status] || '#8b949e';

      const hasOutput = step.output.length > 0;
      const hasTargets = step.targets.length > 0;

      return h('div', {
        key: idx,
        style: {
          background: '#0d1117',
          border: '1px solid #21262d',
          borderRadius: '4px',
          overflow: 'hidden',
        },
      },
        // Step header
        h('div', {
          style: {
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            padding: '4px 8px',
            cursor: hasOutput ? 'pointer' : 'default',
            borderLeft: '3px solid ' + color,
          },
          onClick: () => {
            step._expanded = !step._expanded;
            triggerRender();
          },
        },
          h('span', { style: { fontSize: '9px', color, fontWeight: 700 } },
            step.status === 'completed' ? '\u2713' : step.status === 'skipped' ? '\u2192' : '\u2715'),
          h('span', { style: { fontWeight: 600, color: '#c9d1d9', fontSize: '10px' } },
            (idx + 1) + '. ' + step.name),
          h('span', { style: { color: '#484f58', fontSize: '9px' } }, step.description || ''),
          h('span', { style: { flex: 1 } }),
          step.elapsed > 0 && h('span', {
            style: { color: '#484f58', fontSize: '9px', fontFamily: 'monospace' },
          }, elapsed(step.elapsed)),
          hasOutput && h('span', {
            style: { color: '#484f58', fontSize: '9px' },
          }, step.output.length + ' lines'),
          hasTargets && h('span', {
            style: {
              color: '#3fb950',
              fontSize: '9px',
              background: '#0d442922',
              padding: '0 5px',
              borderRadius: '6px',
            },
          }, step.targets.length + ' targets'),
          hasOutput && h('span', {
            className: 'pl-expand',
            style: { color: '#484f58', fontSize: '9px' },
          }, step._expanded ? '\u25B2' : '\u25BC')
        ),

        // Expanded output
        step._expanded && hasOutput && h('div', {
          style: {
            maxHeight: '150px',
            overflowY: 'auto',
            padding: '4px 8px',
            fontFamily: '"Cascadia Code", "Fira Code", monospace',
            fontSize: '9px',
            lineHeight: '1.5',
            color: '#8b949e',
            borderTop: '1px solid #21262d',
          },
        },
          ...step.output.slice(-100).map((line, i) =>
            h('div', {
              key: i,
              className: 'pl-output-line',
              style: { padding: '1px 4px', borderRadius: '2px' },
            }, line)
          )
        ),

        // Extracted targets preview (if has targets)
        step._expanded && hasTargets && h('div', {
          style: {
            padding: '4px 8px',
            borderTop: '1px solid #21262d',
            fontSize: '9px',
          },
        },
          h('div', { style: { color: '#3fb950', fontWeight: 600, marginBottom: '2px' } },
            'Extracted targets (' + step.targets.length + '):'),
          h('div', {
            style: {
              maxHeight: '60px',
              overflowY: 'auto',
              fontFamily: 'monospace',
              color: '#8b949e',
              lineHeight: '1.4',
            },
          },
            ...step.targets.slice(0, 30).map((t, i) => {
              const display = typeof t === 'object' ? JSON.stringify(t) : String(t);
              return h('div', { key: i, style: { padding: '0 4px' } }, display);
            }),
            step.targets.length > 30 && h('div', { style: { color: '#484f58', fontStyle: 'italic' } },
              '... and ' + (step.targets.length - 30) + ' more')
          )
        )
      );
    })
  );
}

// ======================================================================
//  HUD REGISTRATION
// ======================================================================

function registerHud() {
  if (hudRegistered) return;
  const recon = getRecon();

  const renderFn = (React) => renderPipelineTab(React);

  const doRegister = (hud) => {
    if (hudRegistered) return;
    hudApi = hud;
    hud.registerTab('pipeline', 'Pipeline', null, renderFn);
    hudRegistered = true;
    updateBadge();
  };

  if (recon.hud) {
    doRegister(recon.hud);
  } else {
    recon.events.on('hud:ready', doRegister);
  }
}

// ======================================================================
//  TICK TIMER for elapsed-time updates
// ======================================================================

function startTick() {
  if (tickTimer) return;
  tickTimer = setInterval(() => {
    let hasActive = false;
    for (const p of pipelines.values()) {
      if (p.status === 'running' || p.status === 'paused') { hasActive = true; break; }
    }
    if (hasActive) triggerRender();
  }, TICK_MS);
}

function stopTick() {
  if (tickTimer) { clearInterval(tickTimer); tickTimer = null; }
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
      recon.activeUid = action.uid;
      break;

    case 'SESSION_ADD':
      if (!activeUid) {
        activeUid = action.uid;
        recon.activeUid = action.uid;
      }
      break;

    case 'SESSION_PTY_DATA': {
      const uid = action.uid;
      const data = action.data;
      handlePtyData(uid, data);
      break;
    }

    case 'SESSION_PTY_EXIT':
    case 'SESSION_USER_EXIT': {
      // Cancel any running pipelines on this session
      for (const pipeline of pipelines.values()) {
        if (pipeline._activeUid === action.uid && pipeline.status === 'running') {
          pipeline.status = 'cancelled';
          pipeline.endTime = Date.now();
          const step = pipeline.steps[pipeline.currentStep];
          if (step && step.status === 'running') {
            step.status = 'cancelled';
          }
        }
      }
      ptyBuffers.delete(action.uid);
      if (action.uid === activeUid) {
        activeUid = null;
        recon.activeUid = null;
      }
      updateBadge();
      triggerRender();
      break;
    }
  }

  return next(action);
};

// decorateHyper: register HUD tab and start tick timer
exports.decorateHyper = (Hyper, { React }) => {
  return class PipelineHyper extends React.Component {
    constructor(props) {
      super(props);
      this._mounted = false;
    }

    componentDidMount() {
      this._mounted = true;

      renderCallback = () => {
        if (this._mounted) {
          this.forceUpdate();
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

// Propagate render updates through Hyper's React tree
exports.mapTermsState = (state, map) => {
  return Object.assign({}, map, {
    pipelineVersion: _idCounter + pipelines.size + getActiveCount(),
  });
};

exports.getTermGroupProps = (uid, parentProps, props) => {
  return Object.assign({}, props, { pipelineVersion: parentProps.pipelineVersion });
};

exports.getTermProps = (uid, parentProps, props) => {
  return Object.assign({}, props, { pipelineVersion: parentProps.pipelineVersion });
};
