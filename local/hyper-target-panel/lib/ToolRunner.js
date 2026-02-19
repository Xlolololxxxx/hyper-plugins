const path = require('path');
const { exec } = require('child_process');
const OutputProcessor = require('./OutputProcessor');

const TEMP_DIR = '/home/xlo/.gemini/tmp';

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
    return target.replace(/^https?:\/\//, '').replace(/[\/:]/g, '_');
  }

  launch(tool, target) {
    if (this.launching) {
        this.queue.push({ tool, target });
        return;
    }
    this.launching = true;

    const rpc = this.rpc || window.rpc;
    const store = this.store || window.store;

    if (!rpc || !store) {
      console.error("Hyper Target Panel: RPC or Store not available!");
      // Retry acquiring from window
      const rpcRetry = window.rpc;
      const storeRetry = window.store;

      if (!rpcRetry || !storeRetry) {
          console.error("Hyper Target Panel: RPC or Store still not available after retry.");
          this.launching = false;
          return;
      }
      // Update instance properties
      if (!this.rpc) this.rpc = rpcRetry;
      if (!this.store) this.store = storeRetry;
    }

    const activeRpc = this.rpc || window.rpc;
    const activeStore = this.store || window.store;

    const targetSafe = this.sanitizeTarget(target);
    const logFile = path.join(TEMP_DIR, `${targetSafe}_${tool.id}.log`);
    
    // Construct command with advanced substitution
    let cmd = tool.command
      .replace(/{target}/g, target || 'localhost')
      .replace(/{target_safe}/g, targetSafe)
      .replace(/{log_file}/g, logFile);

    // Support for {log:TOOL_ID} to reference another tool's output file
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
        oldActiveUid = activeStore.getState().termgroups.activeUid;
    } catch (e) {
        console.warn("Hyper Target Panel: Could not get old activeUid", e);
    }

    activeRpc.emit('termgroups:new');
    
    // Wait for the new tab to be active
    let attempts = 0;
    const checkActive = setInterval(() => {
        try {
            const state = activeStore.getState();
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
  }

  processQueue() {
      if (this.queue.length > 0) {
          const { tool, target } = this.queue.shift();
          this.launch(tool, target);
      }
  }
}

module.exports = ToolRunner;

