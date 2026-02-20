const fs = require('fs');
const JcRunner = require('./jc/JcRunner');
const AdapterRunner = require('./jc/AdapterRunner');

class OutputProcessor {
  constructor(callbacks) {
    this.parsers = {
      nmap: require('./parsers/nmap').parse,
      generic: require('./parsers/generic').parse,
      nuclei: require('./parsers/nuclei').parse,
      nikto: require('./parsers/nikto').parse,
      gobuster: require('./parsers/gobuster').parse,
      ffuf: require('./parsers/ffuf').parse,
      katana: require('./parsers/katana').parse,
      dirsearch: require('./parsers/dirsearch').parse,
      gitleaks: require('./parsers/gitleaks').parse,
      wpscan: require('./parsers/wpscan').parse,
      sqlmap: require('./parsers/sqlmap').parse
    };
    this.watchers = {};
    this.onFindings = null;
    this.onJcOutput = null;
    if (typeof callbacks === 'function') {
      this.onFindings = callbacks;
    } else if (callbacks && typeof callbacks === 'object') {
      this.onFindings = typeof callbacks.onFindings === 'function' ? callbacks.onFindings : null;
      this.onJcOutput = typeof callbacks.onJcOutput === 'function' ? callbacks.onJcOutput : null;
    }
    this.jcRunner = new JcRunner();
    this.adapterRunner = new AdapterRunner();
    this.pendingFindings = { ports: new Set(), vulns: new Set(), paths: new Set(), domains: new Set() };
    this.writeTimeout = null;
  }

  // Register a file to watch and parse
  watch(filePath, parserType = 'generic', context = {}) {
    if (this.watchers[filePath]) return;

    try {
      if (!fs.existsSync(filePath)) {
        fs.writeFileSync(filePath, '');
      }

      let debounceTimeout;
      const watcher = fs.watch(filePath, (eventType) => {
        if (eventType === 'change') {
          if (debounceTimeout) clearTimeout(debounceTimeout);
          debounceTimeout = setTimeout(() => this.processFile(filePath, parserType), 500);
          this.refreshExpiry(filePath);
        }
      });

      this.watchers[filePath] = {
        watcher,
        parserType,
        context,
        lastPos: 0,
        remainder: '',
        expiry: setTimeout(() => this.stop(filePath), 600000) // 10m auto-stop
      };
      
      console.log(`[Processor] Watching ${filePath}`);
    } catch (e) {
      console.error(`Failed to watch file ${filePath}:`, e);
    }
  }

  refreshExpiry(filePath) {
    if (this.watchers[filePath]) {
      clearTimeout(this.watchers[filePath].expiry);
      this.watchers[filePath].expiry = setTimeout(() => this.stop(filePath), 600000);
    }
  }

  stop(filePath) {
    if (this.watchers[filePath]) {
      this.watchers[filePath].watcher.close();
      clearTimeout(this.watchers[filePath].expiry);
      delete this.watchers[filePath];
      console.log(`[Processor] Stopped watching ${filePath}`);
    }
  }

  stopAll() {
    Object.keys(this.watchers).forEach(path => this.stop(path));
    if (this.writeTimeout) clearTimeout(this.writeTimeout);
  }

  processFile(filePath, parserType) {
    fs.stat(filePath, (err, stats) => {
      if (err) return;
      
      const watcher = this.watchers[filePath];
      if (!watcher) return;
      
      const lastPos = watcher.lastPos || 0;
      if (stats.size < lastPos) {
        // File was truncated or overwritten
        watcher.lastPos = 0;
        this.processFile(filePath, parserType); // Re-process from start
        return;
      }
      
      if (stats.size > lastPos) {
        this.processJcSnapshot(filePath, watcher.context || {});

        const bytesToRead = stats.size - lastPos;
        const buffer = Buffer.alloc(bytesToRead);
        
        fs.open(filePath, 'r', (err, fd) => {
          if (err) return;
          fs.read(fd, buffer, 0, bytesToRead, lastPos, (err, bytesRead) => {
            fs.close(fd, () => {});
            if (err || bytesRead === 0) return;
            
            watcher.lastPos = lastPos + bytesRead;
            const content = watcher.remainder + buffer.toString('utf8');
            
            // Handle line boundaries: find the last newline
            const lastNewline = content.lastIndexOf('\n');
            if (lastNewline !== -1) {
                const completeLines = content.substring(0, lastNewline + 1);
                watcher.remainder = content.substring(lastNewline + 1);
                
                const parser = this.parsers[parserType] || this.parsers.generic;
                this.updateFindings(parser(completeLines), watcher.context || {});
            } else {
                // No newline yet, buffer the whole content
                watcher.remainder = content;
            }
          });
        });
      }
    });
  }

  processJcSnapshot(filePath, context) {
    const jcParser = context && context.jcParser;
    const jcEngine = context && context.jcEngine;
    if (!jcParser || !this.onJcOutput) return;

    fs.readFile(filePath, 'utf8', (err, content) => {
      if (err || !content) return;
      const result = jcEngine === 'adapter'
        ? this.adapterRunner.parse(jcParser, content, context || {})
        : this.jcRunner.parse(jcParser, content);
      if (!result || !result.ok) return;
      this.onJcOutput(context.target, result.data, Object.assign({}, context, { jcParser, jcEngine: jcEngine || 'jc' }));
    });
  }

  updateFindings(newFindings, context) {
    if (!newFindings) return;

    if (this.onFindings && context && context.target) {
      this.onFindings(context.target, newFindings, context);
      return;
    }
    
    // Add to pending batch
    if (newFindings.ports) newFindings.ports.forEach(p => this.pendingFindings.ports.add(p));
    if (newFindings.vulns) newFindings.vulns.forEach(v => this.pendingFindings.vulns.add(v));
    if (newFindings.paths) newFindings.paths.forEach(p => this.pendingFindings.paths.add(p));
    if (newFindings.domains) newFindings.domains.forEach(d => this.pendingFindings.domains.add(d));

    // Debounce write to 1 second
    if (this.writeTimeout) clearTimeout(this.writeTimeout);
    this.writeTimeout = setTimeout(() => this.commitFindings(), 1000);
  }

  commitFindings() {
    // Keep backward compatibility when no live callback is supplied.
    this.pendingFindings = { ports: new Set(), vulns: new Set(), paths: new Set(), domains: new Set() };
  }
}

module.exports = OutputProcessor;
