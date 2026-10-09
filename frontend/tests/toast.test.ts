import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { transitionToast, TOAST_COPY, type ConnectionState } from '../src/api/health.js';

// The deduplication policy is where outages go wrong: one toast per real
// transition means a sustained outage must be announced exactly once, while
// flap (offline <-> degraded) must not spam.
describe('outage notification policy', () => {
  it('a sustained outage (offline -> offline) never re-announces', () => {
    assert.equal(transitionToast('offline', 'offline'), 'none');
  });
  it('a sustained degraded state never re-announces', () => {
    assert.equal(transitionToast('degraded', 'degraded'), 'none');
  });
  it('flap between degraded and offline produces at most one message each way', () => {
    const seq: ReturnType<typeof transitionToast>[] = [
      transitionToast('online', 'degraded'),
      transitionToast('degraded', 'offline'),
      transitionToast('offline', 'offline'),
      transitionToast('offline', 'online'),
    ];
    assert.deepEqual(seq, ['warn-degraded', 'warn-lost', 'none', 'info-recovered']);
  });
  it('degraded -> offline warns about the connection, not the dependency', () => {
    assert.equal(transitionToast('degraded', 'offline'), 'warn-lost');
    assert.notEqual(transitionToast('degraded', 'offline'), 'warn-degraded');
  });
  it('unknown is a stable silent state, never a storm source', () => {
    assert.equal(transitionToast('unknown', 'unknown'), 'none');
    assert.equal(transitionToast('unknown', 'unknown'), 'none');
  });
  it('every announced tone pairs warning->connection/dependency, info->recovery only', () => {
    const tones = Object.values(TOAST_COPY).map((c) => c.tone);
    assert.ok(tones.includes('warning'));
    assert.ok(tones.includes('info'));
    for (const [k, c] of Object.entries(TOAST_COPY)) {
      const isRecovery = k.startsWith('info');
      if (isRecovery) assert.match(c.message, /recovered|restored/i, `${k} must sound like recovery`);
      else assert.ok(!/restored/i.test(c.message), `${k} must not claim recovery`);
    }
  });
});

describe('state machine totality: every adjacent pair has a decision', () => {
  const states: ConnectionState[] = ['checking', 'online', 'degraded', 'offline', 'unknown'];
  it('no transition throws and none silently returns a bogus value', () => {
    for (const a of states) {
      for (const b of states) {
        const d = transitionToast(a, b);
        assert.ok(['none', 'warn-lost', 'info-recovered', 'warn-degraded', 'info-recovered-db'].includes(d), `${a}->${b} gave ${d}`);
      }
    }
  });
});
