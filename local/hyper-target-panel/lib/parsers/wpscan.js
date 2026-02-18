(function (exports, require, module, __filename, __dirname, process, global, Buffer) { return function (exports, require, module, __filename, __dirname) { exports.parse = (content) => {
  const vulns = [];
  const info = [];
  const plugins = [];
  const themes = [];
  
  // WPScan output sections:
  // [+] Plugin Name
  // | Latest Version: 1.2
  // | Last Updated: ...
  // |
  // | [!] Vulnerability Title
  // |     References: ...
  
  // 1. Extract Interesting Findings
  // [+] Headers
  // [+] XML-RPC
  const findingRegex = /^\[\+\]\s+(.*)/gm;
  let match;
  while ((match = findingRegex.exec(content)) !== null) {
      const line = match[1].trim();
      // Filter out section headers like "Enumerating Plugins"
      if (!line.startsWith('Enumerating') && !line.startsWith('Finished') && !line.startsWith('URL:')) {
          if (line.includes('Vulnerability')) {
              vulns.push(line);
          } else {
              info.push(line);
          }
      }
  }

  // 2. Extract Plugins with versions
  // [i] Plugin(s) Identified:
  // [+] akismet
  // | Location: ...
  // | Version: 4.1.9 (80% confidence)
  // | Latest Version: 4.2.1
  
  // This is hard to regex perfectly line-by-line without state, but let's try to capture "Version" lines if they follow a plugin name.
  // Or just look for specific patterns.
  
  const versionRegex = /\|\s+Version:\s+([0-9.]+)/g;
  // This captures all versions, not associated with plugin name easily in stateless regex.
  // Better to just capture lines with [!] or specific vuln markers.
  
  const vulnMarkerRegex = /\[!\]\s+(.*)/gm;
  while ((match = vulnMarkerRegex.exec(content)) !== null) {
      vulns.push(`[!] ${match[1].trim()}`);
  }

  // 3. Extract outdated items
  if (content.includes('out of date')) {
      info.push('Some components are out of date.');
  }

  return { vulns, info, plugins, themes };
};

}.call(this, exports, require, module, __filename, __dirname); });