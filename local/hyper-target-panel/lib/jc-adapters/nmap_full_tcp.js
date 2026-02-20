'use strict';

const family = require('./nmap');

function parse(raw, context) {
  return family.parse(raw, context || {});
}

module.exports = { parse };
