'use strict';

class ExecutionStrategyManager {
  constructor(strategies) {
    this.strategies = Array.isArray(strategies) ? strategies : [];
  }

  async launch(context) {
    let lastError = null;
    for (const strategy of this.strategies) {
      try {
        const result = await strategy.launch(context);
        if (result && result.started) return result;
        lastError = result && result.error ? result.error : lastError;
      } catch (err) {
        lastError = err && err.message ? err.message : String(err);
      }
    }

    return {
      started: false,
      transport: 'none',
      error: lastError || 'all strategies failed',
    };
  }
}

module.exports = ExecutionStrategyManager;
