'use strict';

const family = require('./arjun');

function parse(raw, context) {
  return family.parse(raw, context || {});
}

module.exports = { parse };
