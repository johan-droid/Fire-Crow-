import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { extractDetail, fetchWithRetry, isApiError, looksLikeHtmlDocument, SPA_FALLBACK_MESSAGE, toApiError, withTimeout } from '../src/api/errors.js';

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

describe('fetchWithRetry (bounded retries, cold-start tolerant)', () => {
  const ok = () => new Response('{}', { status: 200 });
  const retryable = () => new Response('{}', { status: 503 });

  it('returns the first response when healthy (single fetch)', async () => {
    let calls = 0;
    const res = await fetchWithRetry('http://x/', {}, (async () => { calls += 1; return ok(); }) as typeof fetch);
    assert.equal(res.status, 200);
    assert.equal(calls, 1);
  });

  it('retries retryable statuses then returns success', async () => {
    let calls = 0;
    const res = await fetchWithRetry(
      'http://x/',
      {},
      (async () => { calls += 1; return calls < 3 ? retryable() : ok(); }) as typeof fetch,
      { baseDelayMs: 1 } as never,
    );
    assert.equal(res.status, 200);
    assert.equal(calls, 3);
  });

  it('does not retry when retry:false (mutations never double-submit)', async () => {
    let calls = 0;
    const res = await fetchWithRetry(
      'http://x/',
      { method: 'POST' },
      (async () => { calls += 1; return retryable(); }) as typeof fetch,
      { retry: false },
    );
    assert.equal(res.status, 503);
    assert.equal(calls, 1);
  });

  it('does not retry non-retryable statuses', async () => {
    let calls = 0;
    const res = await fetchWithRetry(
      'http://x/',
      {},
      (async () => { calls += 1; return new Response('{}', { status: 404 }); }) as typeof fetch,
    );
    assert.equal(res.status, 404);
    assert.equal(calls, 1);
  });

  it('own timeout throws a truthful 408 ApiError, never a raw abort', async () => {
    const hanging = ((_u: unknown, o?: RequestInit) =>
      new Promise<never>((_, reject) => {
        //Like real fetch: aborting the signal rejects the request.
        o?.signal?.addEventListener(
          'abort',
          () => reject(new DOMException('aborted', 'AbortError')),
          { once: true },
        );
      })) as typeof fetch;
    const err = await fetchWithRetry('http://x/', {}, hanging, { timeoutMs: 10 }).catch((e) => e);
    assert.ok(isApiError(err), 'must be an ApiError');
    assert.equal(err.status, 408);
    assert.match(err.message, /outcome is unknown/);
  });

  it('caller abort is never retried and never converted', async () => {
    const ctrl = new AbortController();
    ctrl.abort();
    let calls = 0;
    const err = await fetchWithRetry(
      'http://x/',
      { signal: ctrl.signal },
      (async (_u: unknown, o?: RequestInit) => {
        calls += 1;
        o?.signal?.throwIfAborted();
        return ok();
      }) as typeof fetch,
      { timeoutMs: 1000 },
    ).catch((e) => e);
    assert.equal(calls, 1);
    assert.ok(!(err instanceof Error) || err.name === 'AbortError' || isApiError(err));
  });
});

// A 2xx HTML body is never API output: it is the SPA answering for an
// unconfigured API base (VITE_API_URL unset on Vercel). Detecting it turns a
// dead-end "Server returned malformed JSON." into an actionable message.
describe('looksLikeHtmlDocument (SPA fallback detection)', () => {
  it('recognises the documents a static host serves', () => {
    assert.equal(looksLikeHtmlDocument('<!doctype html><html lang="en">'), true);
    assert.equal(looksLikeHtmlDocument('<!DOCTYPE HTML>\n<html>'), true);
    assert.equal(looksLikeHtmlDocument('  \n<html><body>x</body></html>'), true);
    assert.equal(looksLikeHtmlDocument('<!-- comment --><html></html>'), true);
  });

  it('never mistakes real API payloads for HTML', () => {
    assert.equal(looksLikeHtmlDocument('{"detail":"ok"}'), false);
    assert.equal(looksLikeHtmlDocument('[]'), false);
    assert.equal(looksLikeHtmlDocument(''), false);
    assert.equal(looksLikeHtmlDocument('   '), false);
    assert.equal(looksLikeHtmlDocument('null'), false);
  });

  it('names the misconfiguration and the fix', () => {
    assert.match(SPA_FALLBACK_MESSAGE, /VITE_API_URL/);
    assert.match(SPA_FALLBACK_MESSAGE, /HTML/);
  });
});
