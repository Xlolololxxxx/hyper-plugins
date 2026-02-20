'use strict';

function hasScheme(target) {
  return /^https?:\/\//i.test(String(target || ''));
}

function stripToHost(target) {
  let value = String(target || '').trim();
  if (!value) return '';
  value = value.replace(/^https?:\/\//i, '');
  value = value.split(/[/?#]/)[0];
  return value.toLowerCase();
}

function stripToDomain(target) {
  return stripToHost(target).replace(/:(\d{1,5})$/, '');
}

function applyScheme(target, scheme) {
  const host = stripToHost(target);
  if (!host) return '';
  return `${scheme}://${host}`;
}

function resolveTargetValue(target, tool, schemeOverride) {
  const mode = tool && tool.input_mode ? String(tool.input_mode) : 'domain';
  const override = String(schemeOverride || 'auto').toLowerCase();

  if (mode === 'url') {
    if (override === 'http' || override === 'https') {
      return applyScheme(target, override);
    }
    if (hasScheme(target)) return String(target).trim();
    return applyScheme(target, 'https');
  }

  return stripToDomain(target);
}

function renderCommand(template, context) {
  const target = context && context.target ? context.target : 'localhost';
  const targetSafe = context && context.targetSafe ? context.targetSafe : target.replace(/[/:]/g, '_');
  const logFile = context && context.logFile ? context.logFile : '';
  const tool = context && context.tool ? context.tool : null;
  const schemeOverride = context && context.schemeOverride ? context.schemeOverride : 'auto';
  const wordlistFile = context && context.wordlistFile ? context.wordlistFile : '';
  const logPathByToolId = context && typeof context.logPathByToolId === 'function'
    ? context.logPathByToolId
    : null;

  let cmd = String(template || '');
  const targetValue = resolveTargetValue(target, tool, schemeOverride);

  cmd = cmd
    .replace(/https?:\/\/\{target\}/g, '{target}')
    .replace(/{target}/g, targetValue)
    .replace(/{target_safe}/g, targetSafe)
    .replace(/{log_file}/g, logFile)
    .replace(/{wordlist_file}/g, wordlistFile);

  // Support references to other tool logs.
  cmd = cmd.replace(/{log:([a-zA-Z0-9_-]+)}/g, (_m, toolId) => {
    if (logPathByToolId) return logPathByToolId(toolId);
    const baseDir = context && context.tempDir ? context.tempDir : '';
    return baseDir ? `${baseDir}/${targetSafe}_${toolId}.log` : `${targetSafe}_${toolId}.log`;
  });

  return cmd;
}

module.exports = {
  renderCommand,
};
