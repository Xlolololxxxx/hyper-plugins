'use strict';

const { spawn } = require('child_process');

class DetachedShellStrategy {
  async launch(context) {
    const command = context && context.command;
    if (!command) {
      return { started: false, transport: 'detached_shell', error: 'missing command' };
    }

    try {
      const child = spawn('bash', ['-lc', command], { detached: true, stdio: 'ignore' });
      child.unref();
      return {
        started: true,
        transport: 'detached_shell',
        pid: child.pid,
      };
    } catch (err) {
      return {
        started: false,
        transport: 'detached_shell',
        error: err.message,
      };
    }
  }
}

module.exports = DetachedShellStrategy;
