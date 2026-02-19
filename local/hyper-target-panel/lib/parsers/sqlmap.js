exports.parse = (content) => {
  const vulns = [];
  const info = [];
  
  // Sqlmap finding: Parameter: id (GET)
  const paramRegex = /\[\+\]\s+Parameter:\s+([^\s]+)\s+\((GET|POST|COOKIE|HEADER)\)/g;
  let match;
  while ((match = paramRegex.exec(content)) !== null) {
    vulns.push(`[Parameter] ${match[1]} (${match[2]})`);
  }

  // Type: boolean-based blind
  const typeRegex = /\s+Type:\s+(.*)/g;
  while ((match = typeRegex.exec(content)) !== null) {
      if (!vulns.includes(`[Type] ${match[1].trim()}`)) {
          vulns.push(`[Type] ${match[1].trim()}`);
      }
  }

  // Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
  const titleRegex = /\s+Title:\s+(.*)/g;
  while ((match = titleRegex.exec(content)) !== null) {
      vulns.push(`[Title] ${match[1].trim()}`);
  }

  // Payload: id=1' AND SLEEP(5)--
  const payloadRegex = /\s+Payload:\s+(.*)/g;
  while ((match = payloadRegex.exec(content)) !== null) {
      vulns.push(`[Payload] ${match[1].trim()}`);
  }

  // web server operating system: Linux Ubuntu 20.04
  const osRegex = /web server operating system:\s+(.*)/i;
  const osMatch = osRegex.exec(content);
  if (osMatch) info.push(`OS: ${osMatch[1].trim()}`);

  // web application technology: Nginx 1.18.0, PHP 7.4.3
  const techRegex = /web application technology:\s+(.*)/i;
  const techMatch = techRegex.exec(content);
  if (techMatch) info.push(`Tech: ${techMatch[1].trim()}`);

  // back-end DBMS: MySQL >= 5.0.12
  const dbmsRegex = /back-end DBMS:\s+(.*)/i;
  const dbmsMatch = dbmsRegex.exec(content);
  if (dbmsMatch) info.push(`DBMS: ${dbmsMatch[1].trim()}`);

  return { vulns, info };
};

