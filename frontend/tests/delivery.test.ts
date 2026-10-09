import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  DELIVERY_TIMEOUT_MS,
  deliveryTimeoutNote,
  withTimeout,
} from '../src/api/errors.js';

// NOTE: api.emailReport/api.telegramReport themselves need fetch + vite env,
// so they are verified in staging. What is unit-testable here: the timeout
// budget, the unknown-outcome copy, and the timeout plumbing they share.
describe('delivery timeout contract', () => {
  it('budgets 60s per channel', () => {
    assert.equal(DELIVERY_TIMEOUT_MS, 60_000);
  });
  it('timeout copy states unknown outcome per channel, never success/failure', () => {
    for (const channel of ['email', 'telegram'] as const) {
      const note = deliveryTimeoutNote(channel);
      assert.match(note, /unknown/);
      assert.match(note, /before trying again/);
      assert.ok(!/fail/i.test(note), `must not imply conclusive failure: ${note}`);
      assert.ok(
        !/delivered \(|already sent/i.test(note),
        `must not imply an outcome: ${note}`,
      );
    }
    assert.match(deliveryTimeoutNote('email'), /account email/);
    assert.match(deliveryTimeoutNote('telegram'), /Telegram chat/);
  });
  it('timeout plumbing surfaces the channel note with 408', async () => {
    const err = await withTimeout(
      async (signal) =>
        new Promise<never>((_, reject) => {
          signal.addEventListener('abort', () => reject(new DOMException('x', 'AbortError')));
        }),
      10,
      'Email delivery',
      deliveryTimeoutNote('email'),
    ).catch((e) => e);
    assert.equal(err.code, 'timeout');
    assert.equal(err.status, 408);
    assert.match(err.message, /unknown/);
    assert.match(err.message, /Email delivery/);
  });
  it('successful delivery responses pass through untouched', async () => {
    const res = await withTimeout(async () => ({ status: 'sent' }), 1000, 'X', 'note');
    assert.deepEqual(res, { status: 'sent' });
  });
  it('ordinary API failures pass through (only timeouts become 408)', async () => {
    const apiErr = { code: 'server_error' };
    const err = await withTimeout(async () => { throw apiErr; }, 1000, 'X', 'note').catch(
      (e) => e,
    );
    assert.equal(err, apiErr);
  });
});
