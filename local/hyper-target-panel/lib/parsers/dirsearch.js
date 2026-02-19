exports.parse = (content) => {
  const paths = [];
  
  // Dirsearch output examples:
  // [19:44:00] 200 -   512B - /admin
  // [19:44:01] 301 -   0B   - /login  ->  /auth/login
  // [19:44:02] 403 -  1.2KB - /secret
  
  const dirsearchRegex = /\[\d{2}:\d{2}:\d{2}\]\s+(\d{3})\s+-\s+([0-9.]+[KMG]?B)\s+-\s+([^\s]+)(?:\s+->\s+([^\s]+))?/gm;
  
  let match;
  while ((match = dirsearchRegex.exec(content)) !== null) {
    const status = match[1];
    const size = match[2];
    const path = match[3];
    const redirect = match[4] ? ` -> ${match[4]}` : '';
    
    // Status filter
    if (['200', '201', '204', '301', '302', '307', '401', '403', '405', '500'].includes(status)) {
        paths.push(`${path} [${status}] (${size})${redirect}`);
    }
  }

  return { paths };
};

