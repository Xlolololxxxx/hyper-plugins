(function (exports, require, module, __filename, __dirname, process, global, Buffer) { return function (exports, require, module, __filename, __dirname) { exports.parse = (content) => {
  const paths = [];
  const endpoints = [];
  const files = [];
  const js = [];

  // Katana output is typically just a list of URLs, sometimes with status codes or other info depending on flags.
  // Standard: http://example.com/admin
  
  const urlRegex = /https?:\/\/[^\s]+/g;
  let match;
  while ((match = urlRegex.exec(content)) !== null) {
    const url = match[0];
    
    // Categorize
    if (url.endsWith('.js') || url.endsWith('.map')) {
        if (!js.includes(url)) js.push(url);
    } else if (/\.(jpg|jpeg|png|gif|css|svg|ico|woff|ttf)$/i.test(url)) {
        if (!files.includes(url)) files.push(url);
    } else {
        // Likely an endpoint or page
        if (!endpoints.includes(url)) endpoints.push(url);
    }
    
    if (!paths.includes(url)) paths.push(url);
  }

  // Also extract relative paths if present (rare in default katana, but possible)
  // /api/v1/user
  const relPathRegex = /^\/[a-zA-Z0-9/_.-]+$/gm;
  while ((match = relPathRegex.exec(content)) !== null) {
      if (!paths.includes(match[0])) paths.push(match[0]);
  }
  
  return { paths, endpoints, files, js };
};

}.call(this, exports, require, module, __filename, __dirname); });