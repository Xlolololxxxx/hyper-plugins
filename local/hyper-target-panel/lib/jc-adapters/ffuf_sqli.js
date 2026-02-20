'use strict';

const family = require('./ffuf');

function parse(raw, context) {
  return family.parse(raw, context || {});
}

module.exports = { parse };
