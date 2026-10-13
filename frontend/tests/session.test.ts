import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// Session-verification contract (backend auth_rate_limits.rs): a throttled or
// failed session read (429/5xx/network) is indeterminate, never proof of
// sign-out. Only an explicit 401 may clear the user. Static guard so a future
// edit cannot reintroduce a catch-all sign-out in checkSession.
const app = readFileSync(join(process.cwd(), 'src', 'App.tsx'), 'utf8');

describe('session verification sign-out contract', () => {
  it('signs out only on an explicit 401 from the session check', () => {
    assert.ok(
      app.includes('err instanceof ApiError && err.status === 401'),
      '401-only sign-out guard missing from session verification',
    );
    assert.ok(
      app.includes('Session verification indeterminate'),
      'indeterminate session reads must surface error, not sign-out',
    );
  });
  it('never clears the user on an indeterminate session read', () => {
    const idx = app.indexOf('Session verification indeterminate');
    assert.ok(idx > 0, 'indeterminate branch missing');
    // The indeterminate branch must not null the user: the next 25 lines
    // after the marker may set error state but never setUser(null).
    const window = app.slice(idx, idx + 1200);
    assert.ok(
      !window.includes('setUser(null)'),
      'indeterminate session read must not clear the signed-in user',
    );
  });
});
