'use strict';

function getLogExtForTool(tool) {
  const id = tool && tool.id ? String(tool.id) : '';
  const parser = tool && tool.parser ? String(tool.parser) : '';
  if (id.includes('gobuster') || parser === 'gobuster') {
    return 'txt';
  }
  return 'log';
}

function buildLogFileName(targetSafe, tool) {
  const ext = getLogExtForTool(tool);
  const id = tool && tool.id ? String(tool.id) : 'tool';
  return `${targetSafe}_${id}.${ext}`;
}

module.exports = {
  getLogExtForTool,
  buildLogFileName,
};
