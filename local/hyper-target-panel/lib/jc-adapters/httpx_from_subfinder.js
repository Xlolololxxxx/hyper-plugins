'use strict';

const family = require('./url_list');

function parse(raw, context) {
  return family.parse(raw, context || {});
}

module.exports = { parse };
