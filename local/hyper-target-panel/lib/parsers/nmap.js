(function (exports, require, module, __filename, __dirname, process, global, Buffer) { return function (exports, require, module, __filename, __dirname) { exports.parse = (content) => {
  const ports = [];
  const vulns = [];
  const os = [];
  const scripts = [];

  // 1. Extract Open Ports with Service Versions
  // Format: 80/tcp open http Apache httpd 2.4.49
  // Enhanced to clean up multiple spaces and better formatting
  const portRegex = /^(\d+)\/(tcp|udp)\s+open\s+([^\n]+)/gm;
  let match;
  while ((match = portRegex.exec(content)) !== null) {
    const port = match[1];
    const proto = match[2];
    let serviceInfo = match[3].trim().replace(/\s+/g, ' ');

    // Attempt to separate service name from version info
    // e.g. "http Apache httpd 2.4.49" -> Service: http, Version: Apache httpd 2.4.49
    const parts = serviceInfo.split(' ');
    let serviceName = parts[0];
    let version = parts.slice(1).join(' ');

    if (version) {
        ports.push(`${port} (${serviceName}) - ${version}`);
    } else {
        ports.push(`${port} (${serviceName})`);
    }
  }

  // 2. Extract OS Detection
  // Format: OS details: Linux 3.2 - 4.9
  const osRegex = /^OS details:\s+(.*)/gm;
  let osMatch;
  while ((osMatch = osRegex.exec(content)) !== null) {
    const osName = osMatch[1].trim();
    if (!os.includes(osName)) os.push(osName);
  }
  
  // Format: Service Info: OS: Windows; CPE: ...
  const serviceOsRegex = /^Service Info:\s+OS:\s+([^;]+)/gm;
  let sOsMatch;
  while ((sOsMatch = serviceOsRegex.exec(content)) !== null) {
      const osName = sOsMatch[1].trim();
      if (!os.includes(osName)) os.push(osName);
  }

  // Format: Running: Linux 3.X|4.X
  const runningOsRegex = /^Running:\s+(.*)/gm;
  let rOsMatch;
  while ((rOsMatch = runningOsRegex.exec(content)) !== null) {
      const osName = rOsMatch[1].trim();
      if (!os.includes(osName)) os.push(osName);
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
    if (output && output.length > 0 && !output.includes("ERROR:")) {
        scripts.push(`${scriptName}: ${output}`);
        
        // Check for specific vuln keywords in script output
        // Exclude some false positives or informational only
        if (/vulnerable|exploit|cve-|sql injection|rce|remote code/i.test(output)) {
            // Clean up output for display
            const cleanOutput = output.length > 60 ? output.substring(0, 57) + '...' : output;
            vulns.push(`[Script] ${scriptName}: ${cleanOutput}`);
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
      vulns.push(`[CVE] ${cveMatch[1]} (CVSS: ${cveMatch[2]})`);
  }

  // 5. Extract http-title
  const titleRegex = /\|_http-title:\s+(.*)/gm;
  let titleMatch;
  while ((titleMatch = titleRegex.exec(content)) !== null) {
      // Add to ports info or as a separate finding if possible, but here we only have specific categories.
      // We can append it to the last added port if we tracked which port we are in, but the regex global approach loses context.
      // Instead, we can try to find the port block context, but keeping it simple for now.
      // Maybe add to paths/domains if relevant?
      // For now, let's just leave it, or add to scripts.
  }

  return { ports, vulns, os, scripts };
};

}.call(this, exports, require, module, __filename, __dirname); });