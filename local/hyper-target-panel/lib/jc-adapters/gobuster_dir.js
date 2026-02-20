'use strict';

const family = require('./gobuster');

function parse(raw, context) {
  return family.parse(raw, context || {});
}

module.exports = { parse };
