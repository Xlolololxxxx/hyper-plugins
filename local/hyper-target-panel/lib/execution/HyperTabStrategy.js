'use strict';

function collectSessionUids(state) {
  if (!state || typeof state !== 'object') return new Set();
  const uids = new Set();
  const containers = [state.sessions, state.ui, state.termGroups, state];

  for (const c of containers) {
    if (!c || typeof c !== 'object') continue;

    if (c.sessions && typeof c.sessions === 'object') {
      Object.keys(c.sessions).forEach((k) => uids.add(k));
    }

    if (Array.isArray(c.sessionUids)) {
      c.sessionUids.forEach((uid) => uid && uids.add(uid));
    }

    if (c.activeUid) uids.add(c.activeUid);
  }

  return uids;
}

function getActiveUid(state) {
  if (!state || typeof state !== 'object') return null;
  const candidates = [
    state.termgroups && state.termgroups.activeUid,
    state.termGroups && state.termGroups.activeUid,
    state.sessions && state.sessions.activeUid,
    state.ui && state.ui.activeUid,
    state.activeUid,
  ];
  for (const uid of candidates) {
    if (uid) return uid;
  }
  return null;
}

class HyperTabStrategy {
  constructor(opts) {
    this.timeoutMs = (opts && opts.timeoutMs) || 2800;
    this.pollMs = (opts && opts.pollMs) || 80;
  }

  async launch(context) {
    const rpc = context && context.rpc;
    const store = context && context.store;
    const command = context && context.command;

    if (!rpc || !store || !command) {
      return { started: false, transport: 'hyper_new_tab', error: 'missing rpc/store/command' };
    }

    const getState = typeof store.getState === 'function' ? store.getState.bind(store) : null;
    const dispatch = typeof store.dispatch === 'function' ? store.dispatch.bind(store) : null;
    if (!getState || !dispatch) {
      return { started: false, transport: 'hyper_new_tab', error: 'invalid store API' };
    }

    const before = collectSessionUids(getState());
    const beforeActive = getActiveUid(getState());
    const startedAt = Date.now();

    // Primary path: use plugin middleware queue + SESSION_ADD dispatch callback.
    if (typeof window !== 'undefined' && typeof window.__hyperTargetPanel_queue === 'function') {
      const cmdId = `hqs_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
      let settled = false;

      const queuedResult = await new Promise((resolve) => {
        const prev = window.__hyperTargetPanel_onCommandDispatched;
        const timeout = setTimeout(() => {
          if (settled) return;
          settled = true;
          if (typeof window.__hyperTargetPanel_cancelQueued === 'function') {
            window.__hyperTargetPanel_cancelQueued(cmdId);
          }
          window.__hyperTargetPanel_onCommandDispatched = prev;
          resolve(null);
        }, this.timeoutMs);

        window.__hyperTargetPanel_onCommandDispatched = (id, uid) => {
          try {
            if (typeof prev === 'function') prev(id, uid);
          } catch (_e) {}
          if (id !== cmdId || settled) return;
          settled = true;
          clearTimeout(timeout);
          window.__hyperTargetPanel_onCommandDispatched = prev;
          resolve({
            started: true,
            transport: 'hyper_new_tab',
            sessionUid: uid || null,
          });
        };

        window.__hyperTargetPanel_queue({ id: cmdId, cmd: command });

        try {
          dispatch({ type: 'TERM_GROUP_ADD_REQ' });
          dispatch({ type: 'TERM_GROUP_ADD' });
          dispatch({ type: 'TERM_GROUP_ADD_REQUEST' });
        } catch (_e) {}

        if (rpc && typeof rpc.emit === 'function') {
          ['termgroups:new', 'termgroup:new', 'termgroup add req', 'termgroup add'].forEach((evt, idx) => {
            setTimeout(() => {
              try { rpc.emit(evt); } catch (_e) {}
            }, idx * 90);
          });
        }
      });

      if (queuedResult && queuedResult.started) {
        return queuedResult;
      }
    }

    try {
      dispatch({ type: 'TERM_GROUP_ADD' });
      dispatch({ type: 'TERM_GROUP_ADD_REQ' });
      dispatch({ type: 'TERM_GROUP_ADD_REQUEST' });
    } catch (e) {}

    if (rpc && typeof rpc.emit === 'function') {
      ['termgroup add req', 'termgroup add', 'termgroups:new', 'termgroup:new'].forEach((evt) => {
        try { rpc.emit(evt); } catch (e) {}
      });
    }

    while (Date.now() - startedAt < this.timeoutMs) {
      await new Promise((resolve) => setTimeout(resolve, this.pollMs));
      const after = collectSessionUids(getState());
      let targetUid = null;
      for (const uid of after) {
        if (!before.has(uid)) {
          targetUid = uid;
          break;
        }
      }

      // Fallback: in some Hyper states, only activeUid changes while sessions map is delayed.
      if (!targetUid) {
        const activeNow = getActiveUid(getState());
        if (activeNow && activeNow !== beforeActive) {
          targetUid = activeNow;
        }
      }

      if (targetUid) {
        rpc.emit('data', { uid: targetUid, data: `${command}\n`, escaped: false });
        return {
          started: true,
          transport: 'hyper_new_tab',
          sessionUid: targetUid,
        };
      }
    }

    return {
      started: false,
      transport: 'hyper_new_tab',
      error: 'no new hyper session created',
    };
  }
}

module.exports = HyperTabStrategy;
