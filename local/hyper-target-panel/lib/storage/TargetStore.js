'use strict';

const fs = require('fs');
const path = require('path');
const { normalizeTarget } = require('../TargetNormalizer');
const { DATA_DIR } = require('../PathResolver');

class TargetStore {
  constructor(options) {
    const opts = options || {};
    this.baseDir = opts.baseDir || DATA_DIR;
    this.configFile = path.join(this.baseDir, 'target_config.json');
    this.jsonDir = path.join(this.baseDir, 'targets');

    fs.mkdirSync(this.baseDir, { recursive: true });
    fs.mkdirSync(this.jsonDir, { recursive: true });

    this.mode = 'json';
    this.db = null;

    if (!opts.forceJson) {
      try {
        const { DatabaseSync } = require('node:sqlite');
        const dbPath = path.join(this.baseDir, 'target_panel.db');
        this.db = new DatabaseSync(dbPath);
        this._initSqlite();
        this.mode = 'sqlite';
      } catch (_e) {
        this.mode = 'json';
      }
    }
  }

  getMode() {
    return this.mode;
  }

  _safeTarget(rawTarget) {
    const normalized = normalizeTarget(rawTarget);
    return normalized || 'None';
  }

  _safeFilePart(target) {
    return String(target || 'None').replace(/[^a-zA-Z0-9._-]/g, '_');
  }

  _targetFile(target) {
    return path.join(this.jsonDir, `${this._safeFilePart(target)}.json`);
  }

  _runsFile(target) {
    return path.join(this.jsonDir, `${this._safeFilePart(target)}_runs.json`);
  }

  _targetDir(target) {
    return path.join(this.jsonDir, this._safeFilePart(target));
  }

  _initSqlite() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS targets (
        id INTEGER PRIMARY KEY,
        target TEXT UNIQUE NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY,
        target_id INTEGER NOT NULL,
        kind TEXT NOT NULL,
        value TEXT NOT NULL,
        source_tool TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        UNIQUE(target_id, kind, value),
        FOREIGN KEY(target_id) REFERENCES targets(id)
      );
      CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY,
        target_id INTEGER NOT NULL,
        value TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        UNIQUE(target_id, value),
        FOREIGN KEY(target_id) REFERENCES targets(id)
      );
      CREATE TABLE IF NOT EXISTS runs (
        id INTEGER PRIMARY KEY,
        target_id INTEGER NOT NULL,
        tool_id TEXT,
        tool_name TEXT,
        command TEXT,
        transport TEXT,
        status TEXT,
        error TEXT,
        log_file TEXT,
        started_at TEXT,
        ended_at TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(target_id) REFERENCES targets(id)
      );
    `);
  }

  saveLastTarget(target) {
    const safe = this._safeTarget(target);
    fs.writeFileSync(this.configFile, JSON.stringify({ lastTarget: safe }, null, 2));
    return safe;
  }

  loadLastTarget() {
    try {
      const parsed = JSON.parse(fs.readFileSync(this.configFile, 'utf8'));
      return this._safeTarget(parsed.lastTarget);
    } catch (_e) {
      return null;
    }
  }

  _sqliteTargetId(target) {
    const safe = this._safeTarget(target);
    const upsert = this.db.prepare(`
      INSERT INTO targets(target, updated_at) VALUES (?, datetime('now'))
      ON CONFLICT(target) DO UPDATE SET updated_at = datetime('now')
    `);
    upsert.run(safe);
    const row = this.db.prepare('SELECT id FROM targets WHERE target = ?').get(safe);
    return row ? row.id : null;
  }

  addHistory(target, value) {
    const safeTarget = this._safeTarget(target);
    const safeValue = this._safeTarget(value);
    if (!safeValue || safeValue === 'None') return;

    if (this.mode === 'sqlite') {
      const targetId = this._sqliteTargetId(safeTarget);
      this.db.prepare('INSERT OR IGNORE INTO history(target_id, value) VALUES (?, ?)').run(targetId, safeValue);
      return;
    }

    const current = this.getTargetData(safeTarget);
    if (!current.history.includes(safeValue)) current.history.unshift(safeValue);
    fs.writeFileSync(this._targetFile(safeTarget), JSON.stringify(current, null, 2));
  }

  mergeFindings(target, findings, sourceTool) {
    const safeTarget = this._safeTarget(target);
    const payload = findings || {};
    const keys = ['ports', 'vulns', 'paths', 'domains'];

    if (this.mode === 'sqlite') {
      const targetId = this._sqliteTargetId(safeTarget);
      const insert = this.db.prepare('INSERT OR IGNORE INTO findings(target_id, kind, value, source_tool) VALUES (?, ?, ?, ?)');
      for (const key of keys) {
        const vals = Array.isArray(payload[key]) ? payload[key] : [];
        for (const val of vals) insert.run(targetId, key, String(val), sourceTool || null);
      }
      return;
    }

    const current = this.getTargetData(safeTarget);
    for (const key of keys) {
      if (!current[key]) current[key] = [];
      const vals = Array.isArray(payload[key]) ? payload[key] : [];
      for (const val of vals) {
        if (!current[key].includes(val)) current[key].push(val);
      }
    }
    fs.writeFileSync(this._targetFile(safeTarget), JSON.stringify(current, null, 2));
  }

  recordRun(run) {
    const target = this._safeTarget(run && run.target);
    if (!target || target === 'None') return;

    if (this.mode === 'sqlite') {
      const targetId = this._sqliteTargetId(target);
      this.db.prepare(`
        INSERT INTO runs(target_id, tool_id, tool_name, command, transport, status, error, log_file, started_at, ended_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        targetId,
        run.toolId || null,
        run.toolName || null,
        run.command || null,
        run.transport || null,
        run.status || null,
        run.error || null,
        run.logFile || null,
        run.startedAt ? new Date(run.startedAt).toISOString() : null,
        run.endedAt ? new Date(run.endedAt).toISOString() : null
      );
      return;
    }

    let rows = [];
    const f = this._runsFile(target);
    try { rows = JSON.parse(fs.readFileSync(f, 'utf8')); } catch (_e) {}
    rows.unshift({
      tool_id: run.toolId || null,
      tool_name: run.toolName || null,
      command: run.command || null,
      transport: run.transport || null,
      status: run.status || null,
      error: run.error || null,
      log_file: run.logFile || null,
      created_at: new Date().toISOString(),
    });
    fs.writeFileSync(f, JSON.stringify(rows.slice(0, 200), null, 2));
  }

  getRecentRuns(target, limit) {
    const safeTarget = this._safeTarget(target);
    const take = limit || 8;

    if (this.mode === 'sqlite') {
      const row = this.db.prepare('SELECT id FROM targets WHERE target = ?').get(safeTarget);
      if (!row) return [];
      return this.db.prepare(`
        SELECT tool_id, tool_name, command, transport, status, error, log_file, created_at
        FROM runs
        WHERE target_id = ?
        ORDER BY id DESC
        LIMIT ?
      `).all(row.id, take);
    }

    try {
      const rows = JSON.parse(fs.readFileSync(this._runsFile(safeTarget), 'utf8'));
      return rows.slice(0, take);
    } catch (_e) {
      return [];
    }
  }

  getTargetData(target) {
    const safeTarget = this._safeTarget(target);
    const empty = { target: safeTarget, ports: [], vulns: [], paths: [], domains: [], history: [] };

    if (this.mode === 'sqlite') {
      const row = this.db.prepare('SELECT id FROM targets WHERE target = ?').get(safeTarget);
      if (!row) return empty;

      const findings = this.db.prepare('SELECT kind, value FROM findings WHERE target_id = ?').all(row.id);
      for (const f of findings) {
        if (!empty[f.kind]) empty[f.kind] = [];
        empty[f.kind].push(f.value);
      }

      const history = this.db.prepare('SELECT value FROM history WHERE target_id = ? ORDER BY id DESC LIMIT 100').all(row.id);
      empty.history = history.map((h) => h.value);
      return empty;
    }

    try {
      const parsed = JSON.parse(fs.readFileSync(this._targetFile(safeTarget), 'utf8'));
      parsed.target = safeTarget;
      parsed.ports = parsed.ports || [];
      parsed.vulns = parsed.vulns || [];
      parsed.paths = parsed.paths || [];
      parsed.domains = parsed.domains || [];
      parsed.history = parsed.history || [];
      return parsed;
    } catch (_e) {
      return empty;
    }
  }

  importLegacyFindings(target, legacyPath) {
    const safeTarget = this._safeTarget(target);
    if (!legacyPath || !fs.existsSync(legacyPath)) return;

    try {
      const legacy = JSON.parse(fs.readFileSync(legacyPath, 'utf8'));
      this.mergeFindings(safeTarget, {
        ports: legacy.ports || [],
        vulns: legacy.vulns || [],
        paths: legacy.paths || [],
        domains: legacy.domains || [],
      }, 'legacy');

      if (Array.isArray(legacy.history)) {
        for (const h of legacy.history) this.addHistory(safeTarget, h);
      }
    } catch (_e) {}
  }

  storeJcSnapshot(target, jcData, context) {
    const safeTarget = this._safeTarget(target);
    if (!safeTarget || safeTarget === 'None') return;

    const targetDir = this._targetDir(safeTarget);
    const logsDir = path.join(targetDir, 'logs');
    fs.mkdirSync(logsDir, { recursive: true });

    const toolId = context && context.toolId ? this._safeFilePart(context.toolId) : 'tool';
    const runId = context && context.runId ? this._safeFilePart(context.runId) : `${Date.now()}`;
    const parser = context && context.jcParser ? this._safeFilePart(context.jcParser) : 'jc';
    const fileName = `${runId}__${toolId}__${parser}.json`;
    const filePath = path.join(logsDir, fileName);

    const payload = {
      target: safeTarget,
      toolId: context && context.toolId ? context.toolId : null,
      toolName: context && context.toolName ? context.toolName : null,
      parser: context && context.jcParser ? context.jcParser : null,
      parserEngine: context && context.jcEngine ? context.jcEngine : 'jc',
      runId: context && context.runId ? context.runId : null,
      sourceLogFile: context && context.logFile ? context.logFile : null,
      capturedAt: new Date().toISOString(),
      data: jcData,
    };

    fs.writeFileSync(filePath, JSON.stringify(payload, null, 2));
  }
}

module.exports = TargetStore;
