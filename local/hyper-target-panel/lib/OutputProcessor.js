const fs = require('fs');
const path = require('path');

const FINDINGS_FILE = '/home/xlo/.gemini/tmp/target_findings.json';

class OutputProcessor {
  constructor() {
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
    this.pendingFindings = { ports: new Set(), vulns: new Set(), paths: new Set(), domains: new Set() };
    this.writeTimeout = null;
  }

  // Register a file to watch and parse
  watch(filePath, parserType = 'generic') {
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
                this.updateFindings(parser(completeLines));
            } else {
                // No newline yet, buffer the whole content
                watcher.remainder = content;
            }
          });
        });
      }
    });
  }

  updateFindings(newFindings) {
    if (!newFindings) return;
    
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
    const batch = {
      ports: Array.from(this.pendingFindings.ports),
      vulns: Array.from(this.pendingFindings.vulns),
      paths: Array.from(this.pendingFindings.paths),
      domains: Array.from(this.pendingFindings.domains)
    };
    
    // Clear buffer for next cycle
    this.pendingFindings = { ports: new Set(), vulns: new Set(), paths: new Set(), domains: new Set() };

    fs.readFile(FINDINGS_FILE, 'utf8', (err, content) => {
      let data = { target: 'None', ports: [], vulns: [], paths: [], history: [], domains: [] };
      if (!err && content) {
        try {
          data = JSON.parse(content);
        } catch (e) {}
      }

      let changed = false;

      // Merge from batch
      ['ports', 'vulns', 'paths', 'domains'].forEach(key => {
        if (batch[key]) {
          if (!data[key]) data[key] = [];
          batch[key].forEach(item => {
            if (!data[key].includes(item)) {
              data[key].push(item);
              changed = true;
            }
          });
        }
      });

      if (changed) {
        fs.writeFile(FINDINGS_FILE, JSON.stringify(data, null, 2), () => {});
      }
    });
  }
}

module.exports = OutputProcessor;

