exports.parse = (content) => {
  const vulns = [];
  
  // Gitleaks output format (text):
  // Finding:     password
  // Secret:      SuperSecret123
  // RuleID:      generic-api-key
  // Entropy:     3.45
  // File:        config/db.json
  // Line:        42
  // Commit:      abc1234
  // Author:      John Doe
  // Date:        ...
  
  // We process it block by block or regex by regex. Since content is a blob, regex is easier but we need to group them.
  // Actually, typical output is a block. Let's try to extract as much as possible per finding.
  
  // Split by "Finding:" or similar separator if possible, but regex global match is safer for unstructured text.
  
  const findingRegex = /RuleID:\s+([^\n]+)[\s\S]*?File:\s+([^\n]+)[\s\S]*?Line:\s+(\d+)/g;
  
  let match;
  // If the standard text format matches
  while ((match = findingRegex.exec(content)) !== null) {
    const rule = match[1].trim();
    const file = match[2].trim();
    const line = match[3].trim();
    vulns.push(`[${rule}] ${file}:${line}`);
  }

  // Fallback or additional: match JSON format if provided? 
  // Often users paste JSON array.
  try {
      if (content.trim().startsWith('[') && content.trim().endsWith(']')) {
          const json = JSON.parse(content);
          json.forEach(finding => {
              if (finding.RuleID && finding.File) {
                  vulns.push(`[${finding.RuleID}] ${finding.File}:${finding.StartLine}`);
              }
          });
          return { vulns };
      }
  } catch (e) {
      // Not JSON
  }
  
  // If regex failed (different format), try a simpler one just for RuleID/File
  if (vulns.length === 0) {
      const simpleRegex = /RuleID:\s+([^\s]+)/g;
      const fileRegex = /File:\s+([^\s]+)/g;
      
      // This is less accurate as it doesn't group them, but better than nothing
      // The original code did this, but it's risky to mismatch. 
      // Let's iterate line by line to keep context if possible, or just unique rules.
      
      const uniqueRules = new Set();
      while ((match = simpleRegex.exec(content)) !== null) {
          uniqueRules.add(match[1]);
      }
      if (uniqueRules.size > 0) {
          uniqueRules.forEach(r => vulns.push(`[SECRET] ${r} (File/Line parsing failed)`));
      }
  }

  return { vulns };
};

