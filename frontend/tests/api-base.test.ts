import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { validateApiBaseUrl, resolveApiBase } from '../src/api/api-base.js';

// FC-DEP-05: a malformed VITE_API_URL must be rejected loudly instead of
// silently producing requests to a wrong or guessed target. These tests pin
// that contract; getApiBase() itself reads import.meta.env (Vite-only), so the
// pure validator is the testable seam.

describe('validateApiBaseUrl', () => {
  it('accepts a bare https origin', () => {
    assert.equal(validateApiBaseUrl('https://api.firecrow.dev'), null);
  });

  it('accepts an origin that already carries the /api/v1 prefix', () => {
    assert.equal(validateApiBaseUrl('https://api.firecrow.dev/api/v1'), null);
  });

  it('accepts a plain http origin (local development)', () => {
    assert.equal(validateApiBaseUrl('http://localhost:8080'), null);
  });

  it('accepts an onrender.com host', () => {
    assert.equal(validateApiBaseUrl('https://firecrow-backend.onrender.com'), null);
  });

  it('treats unset/blank as the documented same-origin default', () => {
    assert.equal(validateApiBaseUrl(''), null);
    assert.equal(validateApiBaseUrl('   '), null);
  });

  it('rejects a non-URL string', () => {
    const reason = validateApiBaseUrl('not-a-url');
    assert.ok(reason, 'a non-URL must be rejected');
    assert.match(reason!, /not a valid absolute URL/);
  });

  it('rejects a protocol-relative URL', () => {
    assert.ok(validateApiBaseUrl('//api.example.com'));
  });

  it('rejects a relative path', () => {
    assert.ok(validateApiBaseUrl('/api/v1'));
  });

  it('rejects a non-http scheme', () => {
    const reason = validateApiBaseUrl('ftp://api.example.com');
    assert.ok(reason);
    assert.match(reason!, /must use http or https/);
  });

  it('rejects a javascript: scheme (never a request target)', () => {
    assert.ok(validateApiBaseUrl('javascript:alert(1)'));
  });

  it('never throws on hostile input', () => {
    for (const bad of ['', ' ', '\n', 'http://', 'https://', '::::', 'http://[', 'a'.repeat(5000)]) {
      assert.doesNotThrow(() => validateApiBaseUrl(bad));
    }
  });
});

describe('resolveApiBase', () => {
  it('returns the same-origin default when unset', () => {
    assert.equal(resolveApiBase(undefined), '/api/v1');
    assert.equal(resolveApiBase(''), '/api/v1');
    assert.equal(resolveApiBase('   '), '/api/v1');
  });

  it('appends exactly one /api/v1 to a bare origin', () => {
    assert.equal(resolveApiBase('https://api.example.com'), 'https://api.example.com/api/v1');
  });

  it('does not double the /api/v1 prefix', () => {
    assert.equal(
      resolveApiBase('https://api.example.com/api/v1'),
      'https://api.example.com/api/v1',
    );
  });

  it('strips a trailing slash before appending', () => {
    assert.equal(resolveApiBase('https://api.example.com/'), 'https://api.example.com/api/v1');
  });

  it('throws (never guesses a target) on a malformed value', () => {
    assert.throws(() => resolveApiBase('not-a-url'), /not a valid absolute URL/);
    assert.throws(() => resolveApiBase('ftp://api.example.com'), /must use http or https/);
    assert.throws(() => resolveApiBase('//api.example.com'));
  });
});
