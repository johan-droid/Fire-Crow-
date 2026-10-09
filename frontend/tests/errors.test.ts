import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { extractDetail, toApiError, withTimeout } from '../src/api/errors.js';

describe('extractDetail (backend envelope is always {detail})', () => {
  it('reads detail from JSON', () => {
    assert.equal(extractDetail('{"detail":"Bad SHA"}'), 'Bad SHA');
  });
  it('returns null for malformed, empty, or non-envelope JSON', () => {
    assert.equal(extractDetail('not json {{{'), null);
    assert.equal(extractDetail(''), null);
    assert.equal(extractDetail('   '), null);
    assert.equal(extractDetail('[1,2]'), null);
    assert.equal(extractDetail('{"x":1}'), null);
  });
});

describe('toApiError status mapping', () => {
  it('keeps the backend detail message when present', async () => {
    const e = await toApiError(new Response('{"detail":"Token expired"}', { status: 401 }));
    assert.equal(e.code, 'unauthorized');
    assert.equal(e.message, 'Token expired');
    assert.equal(e.retryable, false);
  });
  it('maps 404/409/422/429/5xx', async () => {
    assert.equal((await toApiError(new Response('', { status: 404 }))).code, 'not_found');
    assert.equal((await toApiError(new Response('', { status: 409 }))).code, 'conflict');
    assert.equal((await toApiError(new Response('{"x":1}', { status: 422 }))).code, 'validation');
    const rate = await toApiError(new Response('', { status: 429 }));
    assert.equal(rate.code, 'rate_limited');
    assert.equal(rate.retryable, true);
    assert.equal((await toApiError(new Response('', { status: 500 }))).code, 'server_error');
  });
  it('never surfaces raw HTML error pages', async () => {
    const e = await toApiError(new Response('<html>oops</html>', { status: 500 }));
    assert.ok(!e.message.includes('<html>'));
  });
});

describe('withTimeout', () => {
  it('resolves when the work finishes in time', async () => {
    const v = await withTimeout(async () => 'done', 1000, 'X');
    assert.equal(v, 'done');
  });
  it('aborts and throws a 408 ApiError on timeout', async () => {
    let seenAborted = false;
    const err = await withTimeout(async (signal) => {
      await new Promise((_, reject) => {
        signal.addEventListener('abort', () => {
          seenAborted = true;
          reject(new DOMException('aborted', 'AbortError'));
        });
      });
    }, 20, 'Narrative generation').catch((e) => e);
    assert.equal(seenAborted, true);
    assert.match(err.message, /deterministic report is unchanged/);
    assert.equal(err.code, 'timeout');
    assert.equal(err.status, 408);
  });
  it('passes through non-timeout failures untouched', async () => {
    const boom = new Error('boom');
    const err = await withTimeout(async () => { throw boom; }, 1000, 'X').catch((e) => e);
    assert.equal(err, boom);
  });
  it('uses the default blast-radius note when none is given', async () => {
    const err = await withTimeout(
      async (signal) =>
        new Promise<never>((_, reject) => {
          signal.addEventListener('abort', () => reject(new DOMException('x', 'AbortError')));
        }),
      10,
      'Narrative generation',
    ).catch((e) => e);
    assert.match(err.message, /deterministic report is unchanged/);
  });
});
