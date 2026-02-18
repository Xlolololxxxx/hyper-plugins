(function (exports, require, module, __filename, __dirname, process, global, Buffer) { return function (exports, require, module, __filename, __dirname) { exports.parse = (content) => {
  const vulns = [];
  const paths = [];
  const info = [];

  // Nuclei output examples:
  // [2026-02-17 21:00:00] [info-vulnerability] [info] http://example.com
  // [template-id] [protocol] [severity] url
  // [cve-2021-44228] [http] [critical] http://example.com
  
  // Regex to match: [id] [proto] [severity] url
  // Note: timestamps are optional and sometimes present.
  
  const nucleiRegex = /\[([^\]]+)\]\s+\[(http|tcp|dns|javascript|file|ssl|network)\]\s+\[(info|low|medium|high|critical|unknown)\]\s+([^\s]+)/gi;
  
  let match;
  while ((match = nucleiRegex.exec(content)) !== null) {
    const template = match[1];
    const protocol = match[2];
    const severity = match[3].toLowerCase();
    const url = match[4];
    
    const finding = `[${severity.toUpperCase()}] ${template} (${protocol}) - ${url}`;
    
    if (['high', 'critical'].includes(severity)) {
        vulns.push(finding);
    } else if (['medium', 'low'].includes(severity)) {
        vulns.push(finding);
    } else {
        info.push(finding);
    }
    
    if (url.startsWith('http')) {
        if (!paths.includes(url)) paths.push(url);
    }
  }

  // Handle JSON output if detected?
  // Usually users cat log files.
  
  return { vulns, paths, info };
};

}.call(this, exports, require, module, __filename, __dirname); });