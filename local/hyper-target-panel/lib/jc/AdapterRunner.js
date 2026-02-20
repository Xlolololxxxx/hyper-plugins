'use strict';

const path = require('path');

class AdapterRunner {
  constructor(opts) {
    const options = opts || {};
    this.baseDir = options.baseDir || path.resolve(__dirname, '../jc-adapters');
    this.cache = {};
  }

  load(parser) {
    if (!parser) return null;
    if (this.cache[parser]) return this.cache[parser];

    try {
      const mod = require(path.join(this.baseDir, parser));
      if (!mod || typeof mod.parse !== 'function') return null;
      this.cache[parser] = mod;
      return mod;
    } catch (_e) {
      return null;
    }
  }

  parse(parser, rawText, context) {
    const mod = this.load(parser);
    if (!mod) return { ok: false, error: `missing adapter parser: ${parser}` };

    try {
      const data = mod.parse(String(rawText || ''), context || {});
      return { ok: true, parser, data };
    } catch (e) {
      return { ok: false, error: e && e.message ? e.message : String(e) };
    }
  }
}

module.exports = AdapterRunner;
