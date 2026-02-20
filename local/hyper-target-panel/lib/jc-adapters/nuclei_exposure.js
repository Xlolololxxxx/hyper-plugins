'use strict';

const family = require('./nuclei');

function parse(raw, context) {
  return family.parse(raw, context || {});
}

module.exports = { parse };
