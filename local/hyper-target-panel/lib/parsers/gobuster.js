(function (exports, require, module, __filename, __dirname, process, global, Buffer) { return function (exports, require, module, __filename, __dirname) { exports.parse = (content) => {
  const paths = [];
  const domains = [];
  
  // Gobuster Directory Mode:
  // /admin (Status: 200) [Size: 512]
  // /login (Status: 302) [Size: 0] [--> /auth/login]
  const dirRegex = /^\/([^\s]+)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\](?:.*\[-->\s+([^\s\]]+)\])?/gm;
  
  // Gobuster DNS/VHost Mode:
  // Found: sub.example.com (Status: 200) [Size: 123]
  const dnsRegex = /Found:\s+([^\s]+)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\]/gm;
  
  let match;
  while ((match = dirRegex.exec(content)) !== null) {
    const path = match[1];
    const status = match[2];
    const size = match[3];
    const redirect = match[4] ? ` -> ${match[4]}` : '';
    
    // Status 200-299, 301, 302, 401, 403, 500 are interesting
    if (['200', '204', '301', '302', '307', '401', '403', '405', '500'].includes(status)) {
        paths.push(`/${path} [${status}] (Size: ${size})${redirect}`);
    }
  }

  while ((match = dnsRegex.exec(content)) !== null) {
      const domain = match[1];
      const status = match[2];
      const size = match[3];
      domains.push(`${domain} [${status}] (Size: ${size})`);
  }

  return { paths, domains };
};

}.call(this, exports, require, module, __filename, __dirname); });