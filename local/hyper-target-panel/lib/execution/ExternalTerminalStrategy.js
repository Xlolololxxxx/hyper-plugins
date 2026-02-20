'use strict';

const { spawn } = require('child_process');

function fishCommand(command) {
  return `${command}; echo; echo "[hyper-target-panel] command finished"; exec fish`;
}

function launchWith(bin, args) {
  return new Promise((resolve) => {
    let done = false;
    try {
      const child = spawn(bin, args, { detached: true, stdio: 'ignore' });
      child.once('error', (err) => {
        if (done) return;
        done = true;
        resolve({ started: false, error: err.message });
      });
      child.unref();
      setTimeout(() => {
        if (done) return;
        done = true;
        resolve({ started: true, pid: child.pid });
      }, 40);
    } catch (err) {
      resolve({ started: false, error: err.message });
    }
  });
}

class ExternalTerminalStrategy {
  constructor(opts) {
    const options = opts || {};
    this.shell = options.shell || 'fish';
    this.terminal = options.terminal || 'konsole';
    this.defaultMode = options.defaultMode || 'window';
  }

  async launch(context) {
    const command = context && context.command;
    if (!command) {
      return { started: false, transport: 'external_terminal', error: 'missing command' };
    }

    const wrapped = this.shell === 'fish'
      ? fishCommand(command)
      : `${command}; echo; echo "[hyper-target-panel] command finished"`;
    const mode = (context && context.konsoleMode) || this.defaultMode;
    const args = [];
    if (mode === 'tab') {
      args.push('--new-tab');
    } else {
      args.push('--separate');
    }
    args.push('-e', this.shell, '-ic', wrapped);

    const result = await launchWith(this.terminal, args);
    if (result.started) {
      return {
        started: true,
        transport: 'external_terminal',
        pid: result.pid,
      };
    }
    return {
      started: false,
      transport: 'external_terminal',
      error: result.error || `failed to launch ${this.terminal}`,
    };
  }
}

module.exports = ExternalTerminalStrategy;
