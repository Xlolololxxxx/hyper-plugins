(function (exports, require, module, __filename, __dirname, process, global, Buffer) { return function (exports, require, module, __filename, __dirname) { exports.parse = (content) => {
  const paths = [];
  
  // Ffuf output examples:
  // [Status: 200, Size: 1234, Words: 56, Lines: 78, Duration: 90ms]
  //     * FUZZ: admin
  //
  // Or compact:
  // admin [Status: 200, Size: 123, Words: 45, Lines: 67, Duration: 89ms]
  
  // Regex for standard CLI output
  // [Status: 200, Size: 1234, Words: 56, Lines: 78]    path
  // Also handle color codes if present (though usually stripped)
  const ffufRegex = /\[Status:\s+(\d+),\s+Size:\s+(\d+),\s+Words:\s+(\d+),\s+Lines:\s+(\d+)(?:,\s+Duration:\s+[\d]+ms)?\]\s+([^\s]+)/gm;
  
  let match;
  while ((match = ffufRegex.exec(content)) !== null) {
    const status = match[1];
    const size = match[2];
    const words = match[3];
    const lines = match[4];
    const path = match[5].trim();
    
    // Interesting statuses
    if (['200', '204', '301', '302', '307', '401', '403', '405', '500'].includes(status)) {
        paths.push(`${path} [${status}] (Size: ${size}, W: ${words}, L: ${lines})`);
    }
  }

  return { paths };
};

}.call(this, exports, require, module, __filename, __dirname); });