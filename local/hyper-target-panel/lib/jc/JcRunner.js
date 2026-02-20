'use strict';

const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawnSync } = require('child_process');

class JcRunner {
  constructor(opts) {
    const options = opts || {};
    this.pythonBin = options.pythonBin || 'python3';
    this.repoRoot = options.repoRoot || path.resolve(__dirname, '../../../../');
    this.scriptPath = options.scriptPath || path.resolve(__dirname, '../../scripts/jc_parse.py');
    this.jcSourceDir = options.jcSourceDir || path.join(this.repoRoot, 'ParsingGlobal/jc');
  }

  parse(parser, rawText) {
    if (!parser) return { ok: false, error: 'missing parser' };

    const env = Object.assign({}, process.env, {
      JC_SOURCE_DIR: this.jcSourceDir,
    });

    const tmpFile = path.join(os.tmpdir(), `jc_input_${Date.now()}_${Math.random().toString(36).slice(2, 8)}.out`);
    fs.writeFileSync(tmpFile, String(rawText || ''), 'utf8');

    const res = spawnSync(this.pythonBin, [this.scriptPath, parser, tmpFile], {
      encoding: 'utf8',
      env,
      timeout: 12000,
      maxBuffer: 8 * 1024 * 1024,
    });
    try { fs.unlinkSync(tmpFile); } catch (_e) {}

    if (res.error) {
      return { ok: false, error: res.error.message };
    }

    const stdout = (res.stdout || '').trim();
    if (!stdout) {
      return { ok: false, error: (res.stderr || '').trim() || 'empty jc output' };
    }

    try {
      const parsed = JSON.parse(stdout);
      if (!parsed || parsed.ok !== true) {
        return { ok: false, error: parsed && parsed.error ? parsed.error : 'jc parse failed' };
      }
      return { ok: true, parser: parsed.parser || parser, data: parsed.data };
    } catch (e) {
      return { ok: false, error: `invalid jc json: ${e.message}` };
    }
  }
}

module.exports = JcRunner;
