'use strict';

function extractDeps(command) {
  const text = String(command || '');
  return [...text.matchAll(/\{log:([a-zA-Z0-9_-]+)\}/g)].map((m) => m[1]);
}

function verifyWorkflows(tools, workflows) {
  const toolMap = new Map((tools || []).map((t) => [t.id, t]));
  const issues = [];

  for (const wf of workflows || []) {
    const steps = Array.isArray(wf.tools) ? wf.tools : [];
    const index = new Map(steps.map((id, i) => [id, i]));

    for (const toolId of steps) {
      const tool = toolMap.get(toolId);
      if (!tool) {
        issues.push({ workflowId: wf.id, type: 'missing_tool', toolId });
        continue;
      }

      const deps = extractDeps(tool.command);
      for (const dep of deps) {
        if (!index.has(dep)) {
          issues.push({ workflowId: wf.id, type: 'missing_dependency', toolId, dependency: dep });
        } else if (index.get(dep) > index.get(toolId)) {
          issues.push({ workflowId: wf.id, type: 'dependency_order', toolId, dependency: dep });
        }
      }
    }
  }

  return { issues };
}

function buildAutomationHints(tools) {
  const hints = [];
  for (const tool of tools || []) {
    const deps = extractDeps(tool.command);
    for (const dep of deps) {
      hints.push({
        from: dep,
        to: tool.id,
        reason: `${tool.id} consumes log output from ${dep}`,
      });
    }
  }
  return hints;
}

module.exports = {
  extractDeps,
  verifyWorkflows,
  buildAutomationHints,
};
