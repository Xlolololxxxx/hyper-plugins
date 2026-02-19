exports.parse = (content) => {
  const paths = [];
  const ports = [];
  const domains = [];
  const vulns = [];
  const emails = [];
  const ips = [];

  // 1. Extract URLs (http, https, ftp, ssh, etc.)
  // Matches protocols followed by :// and non-whitespace characters
  const urlRegex = /\b(https?|ftp|ssh|telnet|file|git):\/\/[^\s()"']+/gi;
  let match;
  while ((match = urlRegex.exec(content)) !== null) {
    // Remove trailing punctuation often captured (.,;)
    const cleanUrl = match[0].replace(/[.,;]$/, '');
    if (!paths.includes(cleanUrl)) paths.push(cleanUrl);
  }

  // 2. Extract IPv4 Addresses
  const ipRegex = /\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  let ipMatch;
  while ((ipMatch = ipRegex.exec(content)) !== null) {
      if (!ips.includes(ipMatch[0])) ips.push(ipMatch[0]);
  }

  // 3. Extract Emails
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
  let eMatch;
  while ((eMatch = emailRegex.exec(content)) !== null) {
      if (!emails.includes(eMatch[0])) emails.push(eMatch[0]);
  }

  // 4. Extract Potential Subdomains/Domains
  // Exclude common file extensions to reduce noise
  const domainRegex = /\b([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;
  const ignoredExtensions = ['.png', '.jpg', '.jpeg', '.gif', '.css', '.js', '.html', '.php', '.json', '.xml', '.txt', '.log', '.zip', '.tar', '.gz'];
  
  let dMatch;
  while ((dMatch = domainRegex.exec(content)) !== null) {
    const d = dMatch[0].toLowerCase();
    const hasIgnoredExt = ignoredExtensions.some(ext => d.endsWith(ext));
    
    // Simple heuristic: valid domains usually don't look like versions (1.0.2) or simple numbers
    const isVersion = /^\d+(\.\d+)+$/.test(d);
    // Ignore purely numeric or small alphanumeric noise
    const isNoise = d.length < 4 || /^\d+$/.test(d.replace(/\./g,''));

    if (!hasIgnoredExt && !isVersion && !isNoise && !ips.includes(d)) {
        if (!domains.includes(d)) domains.push(d);
    }
  }
  
  // 5. Extract Potential Ports (80/tcp, 443/udp, or just "Port 80")
  const portRegex = /\b(\d{1,5})\/(tcp|udp)\b/gi; // 80/tcp
  const portSimpleRegex = /\bPort\s+(\d{1,5})\b/gi; // Port 80
  
  let pMatch;
  while ((pMatch = portRegex.exec(content)) !== null) {
    const p = `${pMatch[1]}/${pMatch[2].toLowerCase()}`;
    if (!ports.includes(p)) ports.push(p);
  }
  while ((pMatch = portSimpleRegex.exec(content)) !== null) {
      const p = `${pMatch[1]}/tcp`; // Assume TCP if unspecified
      if (!ports.includes(p)) ports.push(p);
  }

  // 6. Extract Potential Vulnerabilities/Findings
  // Looks for common keywords indicating severity or findings
  // Enhanced to capture bracket styles like [+] or [!]
  const vulnRegex = /(?:^|\s)(?:\[\+\]|\[!\]|VULNERABLE|EXPLOITABLE|CRITICAL|HIGH|MEDIUM|LOW|CVE-\d{4}-\d+)[ \t]+(.*)/gim;
  let vMatch;
  while ((vMatch = vulnRegex.exec(content)) !== null) {
    const matchFull = vMatch[0].trim();
    // Clean up
    if (!vulns.includes(matchFull) && matchFull.length > 5) {
        // Truncate very long lines
        vulns.push(matchFull.length > 100 ? matchFull.substring(0, 97) + '...' : matchFull);
    }
  }
  
  return { paths, ports, domains, vulns, emails, ips };
};

