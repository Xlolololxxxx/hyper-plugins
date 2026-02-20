'use strict';

function diffVisibleRows(prevRows, nextRows) {
  const remove = [];
  const update = [];
  const keep = [];

  for (const [br, prev] of prevRows.entries()) {
    const next = nextRows.get(br);
    if (!next) {
      remove.push(br);
      continue;
    }

    if (prev.text !== next.text || prev.vr !== next.vr) {
      update.push(br);
    } else {
      keep.push(br);
    }
  }

  for (const br of nextRows.keys()) {
    if (!prevRows.has(br)) update.push(br);
  }

  return { remove, update, keep };
}

module.exports = { diffVisibleRows };
