'use strict';

const family = require('./subdomains');

function parse(raw, context) {
  return family.parse(raw, context || {});
}

module.exports = { parse };
