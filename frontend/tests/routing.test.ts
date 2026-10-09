import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { verifyRouting, isRoutingSafe, extractApiUpstream } from '../src/api/deploy.js';

const STAGING_OK = {
  rewrites: [{ source: '/api/:match*', destination: 'https://firecrow-backend-staging.onrender.com/api/:match*' }],
};
const STAGING_WRONG_PREFIX = {
  rewrites: [{ source: '/api/:match*', destination: 'https://firecrow-backend-staging.onrender.com/:match*' }],
};
const DOUBLE_PREFIX = {
  rewrites: [{ source: '/api/:match*', destination: 'https://stg.example.com/api/v1/api/v1/:match*' }],
};
const COPY_OF_PROD = {
  rewrites: [{ source: '/api/:match*', destination: 'https://firecrow-backend.onrender.com/api/:match*' }],
};
const RELATIVE_DEST = { rewrites: [{ source: '/api/:path*', destination: '/index.html' }] };
const NO_API_ROUTE = { rewrites: [{ source: '/(.*)', destination: '/index.html' }] };
const EMPTY_REWRITES = { rewrites: [] };

describe('verifyRouting: staging mode', () => {
  it('passes a properly isolated staging upstream', () => {
    assert.deepEqual(verifyRouting(STAGING_OK, 'staging'), []);
    assert.equal(isRoutingSafe(STAGING_OK, 'staging'), true);
  });
  it('rejects a staging config that targets the known production host', () => {
    const v = verifyRouting(COPY_OF_PROD, 'staging');
    assert.ok(v.some((x) => x.code === 'production-host-in-staging'), JSON.stringify(v));
  });
  it('rejects a staging upstream missing the /api/v1 version prefix', () => {
    const v = verifyRouting(STAGING_WRONG_PREFIX, 'staging');
    assert.ok(v.some((x) => x.code === 'missing-api-v1'), JSON.stringify(v));
  });
  it('detects a duplicated /api path prefix', () => {
    const v = verifyRouting(DOUBLE_PREFIX, 'staging');
    assert.ok(v.some((x) => x.code === 'double-api-prefix'), JSON.stringify(v));
  });
  it('rejects a relative destination (would serve the SPA instead of the API)', () => {
    const v = verifyRouting(RELATIVE_DEST, 'staging');
    assert.ok(v.some((x) => x.code === 'malformed-destination'), JSON.stringify(v));
  });
  it('rejects configs with no /api rewrite', () => {
    const v = verifyRouting(NO_API_ROUTE, 'staging');
    assert.ok(v.some((x) => x.code === 'missing-api-upstream' || x.code === 'malformed-destination'), JSON.stringify(v));
  });
  it('rejects empty/missing rewrites', () => {
    assert.ok(verifyRouting(EMPTY_REWRITES, 'staging').some((x) => x.code === 'no-rewrites'));
    assert.ok(verifyRouting({}, 'staging').some((x) => x.code === 'no-rewrites'));
  });
  it('rejects a destination with no recognizable scheme', () => {
    const v = verifyRouting({ rewrites: [{ source: '/api/:x', destination: 'firecrow-staging:8080/api/v1' }] }, 'staging');
    assert.ok(v.some((x) => x.code === 'malformed-destination'), JSON.stringify(v));
  });
});

describe('verifyRouting: production mode', () => {
  it('accepts the existing production upstream', () => {
    assert.equal(isRoutingSafe(COPY_OF_PROD, 'production'), true);
  });
  it('still rejects relative/empty upstreams', () => {
    assert.equal(isRoutingSafe(RELATIVE_DEST, 'production'), false);
    assert.equal(isRoutingSafe(EMPTY_REWRITES, 'production'), false);
  });
  it('rejects an unreviewed production host (allow-list enforced)', () => {
    const v = verifyRouting(
      { rewrites: [{ source: '/api/:match*', destination: 'https://evil.example.com/api/:match*' }] },
      'production',
    );
    assert.ok(v.some((x) => x.code === 'unreviewed-host'), JSON.stringify(v));
  });
  it('a production allow-list never leaks into staging or preview', () => {
    assert.ok(
      verifyRouting(COPY_OF_PROD, 'staging').some((x) => x.code === 'production-host-in-staging'),
      'staging must still reject the production host',
    );
    assert.ok(
      verifyRouting(COPY_OF_PROD, 'preview').some((x) => x.code === 'external-upstream-in-preview'),
      'preview must still reject any external upstream',
    );
  });
});

describe('verifyRouting: preview mode (fail-closed, Phase 24)', () => {
  const SPA_ONLY = { rewrites: [{ source: '/(.*)', destination: '/index.html' }] };
  it('accepts a config with no /api rewrite (nothing can leak)', () => {
    assert.deepEqual(verifyRouting(SPA_ONLY, 'preview'), []);
    assert.equal(isRoutingSafe(SPA_ONLY, 'preview'), true);
  });
  it('rejects ANY external /api upstream, production host or not', () => {
    for (const cfg of [COPY_OF_PROD, STAGING_OK]) {
      const v = verifyRouting(cfg, 'preview');
      assert.ok(v.some((x) => x.code === 'external-upstream-in-preview'), JSON.stringify(v));
      assert.equal(isRoutingSafe(cfg, 'preview'), false);
    }
  });
  it('still demands at least one rewrite rule', () => {
    assert.ok(verifyRouting(EMPTY_REWRITES, 'preview').some((x) => x.code === 'no-rewrites'));
    assert.ok(verifyRouting({}, 'preview').some((x) => x.code === 'no-rewrites'));
  });
});

describe('verifyRouting: missing staging configuration', () => {
  it('no isolated staging backend exists: fail closed, never invent one', () => {
    // There is no staging host to check against — the only safe staging
    // verdict for a production copy is rejection.
    const v = verifyRouting(COPY_OF_PROD, 'staging');
    assert.ok(v.some((x) => x.code === 'production-host-in-staging'), JSON.stringify(v));
    assert.equal(isRoutingSafe(COPY_OF_PROD, 'staging'), false);
  });
  it('a malformed staging URL is rejected, not defaulted', () => {
    const v = verifyRouting(
      { rewrites: [{ source: '/api/:match*', destination: 'not a url at all' }] },
      'staging',
    );
    assert.ok(v.some((x) => x.code === 'malformed-destination'), JSON.stringify(v));
  });
});

describe('extractApiUpstream', () => {
  it('finds the first /api* source, ignoring SPA fallback rules', () => {
    assert.equal(
      extractApiUpstream({
        rewrites: [{ source: '/(.*)', destination: '/index.html' }, { source: '/api/:p*', destination: 'https://x.dev/api/v1/:p*' }],
      }),
      'https://x.dev/api/v1/:p*',
    );
  });
  it('returns null when nothing serves /api', () => {
    assert.equal(extractApiUpstream(NO_API_ROUTE), null);
  });
  it('ignores an object destination (Vercel service form) safely', () => {
    const d = extractApiUpstream({ rewrites: [{ source: '/api/:p*', destination: { service: 'x' } }] });
    assert.equal(typeof d === 'object', true);
    assert.equal(isRoutingSafe({ rewrites: [{ source: '/api/:p*', destination: { service: 'x' } }] }, 'staging'), false);
  });
});
