exports.parse = (content) => {
  const vulns = [];
  const paths = [];
  const info = [];
  const methods = [];
  
  // Nikto output:
  // + OSVDB-3092: /admin/: This might be interesting.
  // + /admin/: Interesting directory
  // + HEAD: The anti-clickjacking X-Frame-Options header is not present.
  // + OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, OPTIONS
  
  // 1. Extract OSVDB findings
  const osvdbRegex = /\+ OSVDB-(\d+):\s+([^:]+):\s+(.*)/g;
  let match;
  while ((match = osvdbRegex.exec(content)) !== null) {
    const finding = `[OSVDB-${match[1]}] ${match[3].trim()}`;
    if (!vulns.includes(finding)) vulns.push(finding);
    if (match[2].startsWith('/')) {
        if (!paths.includes(match[2])) paths.push(match[2]);
    }
  }

  // 2. Extract specific HTTP methods
  const methodsRegex = /Allowed HTTP Methods:\s+(.*)/i;
  const mmatch = methodsRegex.exec(content);
  if (mmatch) {
      methods.push(...mmatch[1].split(',').map(m => m.trim()));
  }

  // 3. Extract other findings (start with +)
  const plainRegex = /^\+\s+([^:]+):\s+(.*)/gm;
  let pMatch;
  while ((pMatch = plainRegex.exec(content)) !== null) {
    const key = pMatch[1].trim();
    const val = pMatch[2].trim();
    
    // Avoid re-matching OSVDB lines
    if (!key.startsWith('OSVDB-')) {
        if (key.startsWith('/')) {
             if (!paths.includes(key)) paths.push(key);
             vulns.push(`${key}: ${val}`);
        } else if (key === 'Target IP') {
            info.push(`Target IP: ${val}`);
        } else if (key === 'Target Hostname') {
            info.push(`Target Hostname: ${val}`);
        } else {
            // General finding
            vulns.push(`${key}: ${val}`);
        }
    }
  }

  return { vulns, paths, info, methods };
};

