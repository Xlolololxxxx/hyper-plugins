'use strict';

const family = require('./hydra');

function parse(raw, context) {
  return family.parse(raw, context || {});
}

module.exports = { parse };
