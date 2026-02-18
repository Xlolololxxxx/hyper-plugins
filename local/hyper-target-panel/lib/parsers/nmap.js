(function (exports, require, module, __filename, __dirname, process, global, Buffer) { return function (exports, require, module, __filename, __dirname) { exports.parse = (content) => {
  const ports = [];
  const vulns = [];
  const os = [];
  const scripts = [];

  // 1. Extract Open Ports with Service Versions
  // Format: 80/tcp open http Apache httpd 2.4.49
  const portRegex = /^(\d+)\/(tcp|udp)\s+open\s+([^\n]+)/gm;
  let match;
  while ((match = portRegex.exec(content)) !== null) {
    const port = match[1];
    const proto = match[2];
    const serviceInfo = match[3].trim();
    ports.push(`${port}/${proto} (${serviceInfo})`);
  }

  // 2. Extract OS Detection
  // Format: OS details: Linux 3.2 - 4.9
  const osRegex = /^OS details:\s+(.*)/gm;
  let osMatch;
  while ((osMatch = osRegex.exec(content)) !== null) {
    if (!os.includes(osMatch[1])) os.push(osMatch[1]);
  }
  
  // Format: Service Info: OS: Windows; CPE: ...
  const serviceOsRegex = /^Service Info:\s+OS:\s+([^;]+)/gm;
  let sOsMatch;
  while ((sOsMatch = serviceOsRegex.exec(content)) !== null) {
      if (!os.includes(sOsMatch[1])) os.push(sOsMatch[1]);
  }

  // 3. Extract NSE Script Output
  // Format: |  script-name: output
  //         |_ script-name: output
  const scriptRegex = /^[|]\s*([_]?)([\w-]+):\s+(.*)/gm;
  let scMatch;
  while ((scMatch = scriptRegex.exec(content)) !== null) {
    const scriptName = scMatch[2];
    const output = scMatch[3].trim();
    
    // Filter out common informational scripts if needed, but usually all are interesting
    if (output && output.length > 0) {
        scripts.push(`${scriptName}: ${output}`);
        
        // Check for specific vuln keywords in script output
        if (/vulnerable|exploit|cve-/i.test(output)) {
            vulns.push(`[Script] ${scriptName}: ${output}`);
        }
    }
  }

  // 4. Extract Explicit Vulnerabilities (e.g. from vulners script)
  // Format: | vulners: 
  //         |   cpe:/a:apache:http_server:2.4.49: 
  //         |       CVE-2021-41773 7.5 https://vulners.com/...
  const cveRegex = /(CVE-\d{4}-\d+)\s+([\d.]+)\s+(https?:\/\/[^\s]+)/g;
  let cveMatch;
  while ((cveMatch = cveRegex.exec(content)) !== null) {
      vulns.push(`[CVE] ${cveMatch[1]} (CVSS: ${cveMatch[2]}) - ${cveMatch[3]}`);
  }

  return { ports, vulns, os, scripts };
};

}.call(this, exports, require, module, __filename, __dirname); });