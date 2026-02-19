const path = require('path');
const os = require('os');
const { exec } = require('child_process');
const OutputProcessor = require('./OutputProcessor');

const TEMP_DIR = path.join(os.homedir(), '.gemini/tmp');

class ToolRunner {
  constructor(rpc, store) {
    this.rpc = rpc;
    this.store = store;
    this.processor = new OutputProcessor();
    this.launching = false;
    this.queue = [];
  }

  stop() {
    if (this.processor) this.processor.stopAll();
  }

  sanitizeTarget(target) {
    if (!target) return 'target';
    // Remove protocol and sanitize for filename
    return target.replace(/^https?:\/\//, '').replace(/[\/:]/g, '_');
  }

  launch(tool, data) {
    if (this.launching) {
        this.queue.push({ tool, data });
        return;
    }
    this.launching = true;

    // Refresh rpc/store references if needed
    const activeRpc = this.rpc || window.rpc;
    const activeStore = this.store || window.store;

    if (!activeRpc || !activeStore) {
      console.error("Hyper Target Panel: RPC or Store not available!");
      // Retry acquiring from window
      this.rpc = window.rpc;
      this.store = window.store;

      if (!this.rpc || !this.store) {
          console.error("Hyper Target Panel: RPC or Store still not available after retry.");
          this.launching = false;
          return;
      }
    }

    // Extract target and ports
    let target = 'localhost';
    let ports = [];
    if (typeof data === 'string') {
        target = data;
    } else {
        target = data.target || 'localhost';
        ports = data.ports || [];
    }

    const targetSafe = this.sanitizeTarget(target);
    const logFile = path.join(TEMP_DIR, `${targetSafe}_${tool.id}.log`);
    
    let cmd = tool.command;
    let finalTarget = target;

    // Intelligent Protocol Switching
    // If command template expects HTTP but we have HTTPS port open (443), switch to HTTPS
    if (cmd.includes('http://{target}')) {
        if (ports.includes(443) || ports.includes('443')) {
            cmd = cmd.replace('http://{target}', 'https://{target}');
        }
    }

    // Handle duplicated protocol if target already has it and command also adds it
    // (Though index.js strips protocol now, we keep this for safety or if user manually enters http://)
    if (cmd.includes('http://{target}')) {
        if (finalTarget.startsWith('http://') || finalTarget.startsWith('https://')) {
            cmd = cmd.replace('http://{target}', '{target}');
        }
    } else if (cmd.includes('https://{target}')) {
        if (finalTarget.startsWith('http://') || finalTarget.startsWith('https://')) {
            cmd = cmd.replace('https://{target}', '{target}');
        }
    }

    cmd = cmd
      .replace(/{target}/g, finalTarget)
      .replace(/{target_safe}/g, targetSafe)
      .replace(/{log_file}/g, logFile);

    // Support for {log:TOOL_ID}
    cmd = cmd.replace(/{log:([a-zA-Z0-9_-]+)}/g, (match, toolId) => {
        return path.join(TEMP_DIR, `${targetSafe}_${toolId}.log`);
    });

    console.log(`Launching ${tool.name}: ${cmd}`);

    // Start watching output
    if (this.processor && this.processor.watch) {
        this.processor.watch(logFile, tool.parser || 'generic');
    }

    // Execute in new tab
    let oldActiveUid = null;
    try {
        const state = activeStore.getState();
        if (state && state.termgroups) {
            oldActiveUid = state.termgroups.activeUid;
        }
    } catch (e) {
        console.warn("Hyper Target Panel: Could not get old activeUid", e);
    }

    activeRpc.emit('termgroups:new');
    
    // Wait for the new tab to be active
    let attempts = 0;
    // Small delay to allow React state to update
    setTimeout(() => {
        const checkActive = setInterval(() => {
            try {
                // Always check current store
                const currentStore = this.store || window.store;
                const state = currentStore ? currentStore.getState() : null;
                
                if (!state || !state.termgroups) {
                     attempts++;
                     if (attempts > 50) {
                         clearInterval(checkActive);
                         this.launching = false;
                         this.processQueue();
                     }
                     return;
                }

                const activeUid = state.termgroups.activeUid;

                // Check if activeUid changed AND is valid
                if (activeUid && activeUid !== oldActiveUid) {
                    clearInterval(checkActive);

                    // Send the command with a slight delay to ensure shell is ready
                    setTimeout(() => {
                        activeRpc.emit('data', { uid: activeUid, data: cmd + '\n' });

                        // Done, move to next after a small delay to let tab settle
                        setTimeout(() => {
                            this.launching = false;
                            this.processQueue();
                        }, 500);
                    }, 300);

                } else if (attempts > 50) { // 5 seconds timeout
                    clearInterval(checkActive);
                    console.error("Hyper Target Panel: No active terminal found after creating new tab (timeout).");
                    // Fallback: try the current active one if we really have to
                    if (activeUid) {
                        activeRpc.emit('data', { uid: activeUid, data: cmd + '\n' });
                    }
                    this.launching = false;
                    this.processQueue();
                }
                attempts++;
            } catch (e) {
                clearInterval(checkActive);
                console.error("Hyper Target Panel: Error sending command to terminal", e);
                this.launching = false;
                this.processQueue();
            }
        }, 100);
    }, 50);
  }

  processQueue() {
      if (this.queue.length > 0) {
          const { tool, data } = this.queue.shift();
          this.launch(tool, data);
      }
  }
}

module.exports = ToolRunner;
