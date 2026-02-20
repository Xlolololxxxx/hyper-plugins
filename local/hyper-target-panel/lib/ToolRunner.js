'use strict';

const path = require('path');
const fs = require('fs');
const OutputProcessor = require('./OutputProcessor');
const { normalizeTarget } = require('./TargetNormalizer');
const { renderCommand } = require('./CommandRenderer');
const { buildLogFileName } = require('./LogFileNaming');
const { resolveJcPlan } = require('./jc/JcRegistry');
const ExecutionStrategyManager = require('./execution/ExecutionStrategyManager');
const ExternalTerminalStrategy = require('./execution/ExternalTerminalStrategy');
const { DATA_DIR } = require('./PathResolver');

const RUNTIME_LOG_DIR = path.join(DATA_DIR, 'runtime');
fs.mkdirSync(RUNTIME_LOG_DIR, { recursive: true });

class ToolRunner {
  constructor(rpc, store, callbacks) {
    this.rpc = rpc;
    this.store = store;
    this.onRunStatus = null;
    this.onFindings = null;
    if (typeof callbacks === 'function') {
      this.onRunStatus = callbacks;
    } else if (callbacks && typeof callbacks === 'object') {
      this.onRunStatus = typeof callbacks.onRunStatus === 'function' ? callbacks.onRunStatus : null;
      this.onFindings = typeof callbacks.onFindings === 'function' ? callbacks.onFindings : null;
    }
    this.onJcOutput = null;
    if (callbacks && typeof callbacks === 'object') {
      this.onJcOutput = typeof callbacks.onJcOutput === 'function' ? callbacks.onJcOutput : null;
    }
    this.processor = new OutputProcessor({
      onFindings: (target, findings, context) => {
        if (this.onFindings) this.onFindings(target, findings, context);
      },
      onJcOutput: (target, jcData, context) => {
        if (this.onJcOutput) this.onJcOutput(target, jcData, context);
      }
    });
    this.launching = false;
    this.queue = [];

    this.externalStrategy = new ExternalTerminalStrategy({
      terminal: 'konsole',
      shell: 'fish',
      defaultMode: 'window',
    });
    this.strategyManager = new ExecutionStrategyManager([this.externalStrategy]);
  }

  stop() {
    if (this.processor) this.processor.stopAll();
  }

  sanitizeTargetForFile(target) {
    return String(target || 'target').replace(/[^a-zA-Z0-9._-]/g, '_');
  }

  emitRunStatus(event) {
    if (this.onRunStatus) {
      this.onRunStatus(event);
    }

    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('hyper-target-panel:run-status', { detail: event }));
    }
  }

  launch(tool, data) {
    if (this.launching) {
      this.queue.push({ tool, data });
      return;
    }

    this.launching = true;
    this.launchInternal(tool, data)
      .catch((err) => {
        this.emitRunStatus({
          toolId: tool && tool.id,
          toolName: tool && tool.name,
          status: 'failed',
          transport: 'none',
          error: err && err.message ? err.message : String(err),
        });
      })
      .finally(() => {
        this.launching = false;
        this.processQueue();
      });
  }

  launchWorkflow(tools, data) {
    if (this.launching) {
      this.queue.push({ workflow: true, tools, data });
      return;
    }

    this.launching = true;
    this.launchWorkflowInternal(tools, data)
      .catch((err) => {
        this.emitRunStatus({
          toolId: 'workflow',
          toolName: 'Workflow',
          status: 'failed',
          transport: 'external_terminal',
          error: err && err.message ? err.message : String(err),
        });
      })
      .finally(() => {
        this.launching = false;
        this.processQueue();
      });
  }

  prepareExecution(tool, data) {
    let target = 'localhost';
    let ports = [];
    let schemeOverride = 'auto';
    let wordlistFile = '';
    if (typeof data === 'string') {
      target = data;
    } else if (data && typeof data === 'object') {
      target = data.target || 'localhost';
      ports = Array.isArray(data.ports) ? data.ports : [];
      schemeOverride = data.schemeOverride || 'auto';
      wordlistFile = data.wordlistFile || '';
    }
    const inputMode = tool && tool.input_mode ? String(tool.input_mode) : 'domain';
    const normalizedTarget = normalizeTarget(target) || 'localhost';
    const effectiveTarget = inputMode === 'url'
      ? String(target || '').trim() || normalizedTarget
      : normalizedTarget;
    const targetSafe = this.sanitizeTargetForFile(normalizedTarget);
    const logFile = path.join(RUNTIME_LOG_DIR, buildLogFileName(targetSafe, tool));
    const jcPlan = resolveJcPlan(tool);
    const jcParser = jcPlan ? jcPlan.parser : null;
    const jcEngine = jcPlan ? jcPlan.engine : null;
    const runId = `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

    const command = renderCommand(tool.command, {
      target: normalizedTarget,
      rawTarget: effectiveTarget,
      ports,
      targetSafe,
      logFile,
      tempDir: RUNTIME_LOG_DIR,
      tool,
      schemeOverride,
      wordlistFile,
      logPathByToolId: (toolId) => path.join(RUNTIME_LOG_DIR, buildLogFileName(targetSafe, { id: toolId })),
    });

    return { normalizedTarget, effectiveTarget, logFile, command, jcParser, jcEngine, runId };
  }

  async launchInternal(tool, data) {
    const { normalizedTarget, logFile, command, jcParser, jcEngine, runId } = this.prepareExecution(tool, data);

    this.emitRunStatus({
      toolId: tool.id,
      toolName: tool.name,
      target: normalizedTarget,
      command,
      logFile,
      status: 'running',
      transport: 'pending',
      startedAt: Date.now(),
    });

    if (this.processor && this.processor.watch) {
      this.processor.watch(logFile, tool.parser || 'generic', {
        target: normalizedTarget,
        toolId: tool.id,
        toolName: tool.name,
        jcParser,
        jcEngine,
        runId,
      });
    }

    const result = await this.strategyManager.launch({
      command,
      target: normalizedTarget,
      tool,
      logFile,
      konsoleMode: 'window',
    });

    if (result && result.started) {
      this.emitRunStatus({
        toolId: tool.id,
        toolName: tool.name,
        target: normalizedTarget,
        command,
        logFile,
        status: 'started',
        transport: result.transport,
        sessionUid: result.sessionUid,
        pid: result.pid,
        startedAt: Date.now(),
      });
      return;
    }

    this.emitRunStatus({
      toolId: tool.id,
      toolName: tool.name,
      target: normalizedTarget,
      command,
      logFile,
      status: 'failed',
      transport: (result && result.transport) || 'none',
      error: (result && result.error) || 'unable to launch command',
      endedAt: Date.now(),
    });
  }

  async launchWorkflowInternal(tools, data) {
    const list = Array.isArray(tools) ? tools : [];
    for (let i = 0; i < list.length; i++) {
      const tool = list[i];
      if (!tool || !tool.command) continue;
      const prepared = this.prepareExecution(tool, data);

      this.emitRunStatus({
        toolId: tool.id,
        toolName: tool.name,
        target: prepared.normalizedTarget,
        command: prepared.command,
        logFile: prepared.logFile,
        status: 'running',
        transport: 'pending',
        startedAt: Date.now(),
      });

      if (this.processor && this.processor.watch) {
        this.processor.watch(prepared.logFile, tool.parser || 'generic', {
          target: prepared.normalizedTarget,
          toolId: tool.id,
          toolName: tool.name,
          jcParser: prepared.jcParser,
          jcEngine: prepared.jcEngine,
          runId: prepared.runId,
        });
      }

      const result = await this.externalStrategy.launch({
        command: prepared.command,
        konsoleMode: i === 0 ? 'window' : 'tab',
      });

      if (result && result.started) {
        this.emitRunStatus({
          toolId: tool.id,
          toolName: tool.name,
          target: prepared.normalizedTarget,
          command: prepared.command,
          logFile: prepared.logFile,
          status: 'started',
          transport: result.transport,
          pid: result.pid,
          startedAt: Date.now(),
        });
      } else {
        this.emitRunStatus({
          toolId: tool.id,
          toolName: tool.name,
          target: prepared.normalizedTarget,
          command: prepared.command,
          logFile: prepared.logFile,
          status: 'failed',
          transport: (result && result.transport) || 'external_terminal',
          error: (result && result.error) || 'unable to launch workflow command',
          endedAt: Date.now(),
        });
      }

      // Let Konsole fully register the window/tab before issuing the next tab request.
      await new Promise((resolve) => setTimeout(resolve, i === 0 ? 260 : 180));
    }
  }

  processQueue() {
    if (this.queue.length === 0) return;
    const next = this.queue.shift();
    if (next.workflow) {
      this.launchWorkflow(next.tools, next.data);
      return;
    }
    this.launch(next.tool, next.data);
  }
}

module.exports = ToolRunner;
