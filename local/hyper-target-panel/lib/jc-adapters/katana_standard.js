'use strict';

const family = require('./katana');

function parse(raw, context) {
  return family.parse(raw, context || {});
}

module.exports = { parse };
