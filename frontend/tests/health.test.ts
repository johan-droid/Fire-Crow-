import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  classifyHealth,
  CONNECTION_STYLES,
  HEALTH_TIMEOUT_MS,
  probeBackend,
  transitionToast,
  TOAST_COPY,
} from '../src/api/health.js';
import { verifyRouting } from '../src/api/deploy.js';

const OK_READY = { status: 200, body: { status: 'ready', database: 'connected' }, transportError: false };
const OK_UP = { status: 200, body: { status: 'up', database: 'connected' }, transportError: false };

describe('classifyHealth — truthful online/degraded/offline/unknown', () => {
  it('ready + 200 is online', () => {
    assert.equal(classifyHealth(OK_READY, 'ready'), 'online');
  });
  it('/health up + 200 is online (reachability)', () => {
    assert.equal(classifyHealth(OK_UP, 'simple'), 'online');
  });
  it('503 degraded payload is degraded, not offline', () => {
    assert.equal(classifyHealth({ status: 503, body: { status: 'degraded' }, transportError: false }, 'ready'), 'degraded');
  });
  it('200 with degraded payload is degraded', () => {
    assert.equal(classifyHealth({ status: 200, body: { status: 'degraded' }, transportError: false }, 'ready'), 'degraded');
  });
  it('transport failure is offline', () => {
    assert.equal(classifyHealth({ status: null, body: null, transportError: true }, 'ready'), 'offline');
  });
  it('2xx with an uninterpretable body is unknown — never a false green', () => {
    assert.equal(classifyHealth({ status: 200, body: { nope: 1 }, transportError: false }, 'ready'), 'unknown');
    assert.equal(classifyHealth({ status: 200, body: null, transportError: false }, 'ready'), 'unknown');
    assert.equal(classifyHealth({ status: 204, body: null, transportError: false }, 'ready'), 'unknown');
  });
  it('HTML SPA fallback at an /api path is unknown (proves proxying, not health)', () => {
    assert.equal(classifyHealth({ status: 200, body: null, transportError: false }, 'ready'), 'unknown');
  });
  it('4xx is unknown: contract/route problem, not a reachability verdict', () => {
    assert.equal(classifyHealth({ status: 404, body: { detail: 'x' }, transportError: false }, 'ready'), 'unknown');
    assert.equal(classifyHealth({ status: 401, body: { detail: 'x' }, transportError: false }, 'ready'), 'unknown');
  });
  it('any 5xx the service reports is degraded', () => {
    assert.equal(classifyHealth({ status: 500, body: null, transportError: false }, 'ready'), 'degraded');
  });
  it('no state text may be inferred from /health freshness fields (unimplemented)', () => {
    // jitter: unknown keys must not synthesize online
    assert.equal(classifyHealth({ status: 200, body: { uptime: 5 }, transportError: false }, 'simple'), 'unknown');
  });
});

describe('state labels always carry text + scanner disclaimer', () => {
  it('every state has a visible text label', () => {
    for (const s of ['checking', 'online', 'degraded', 'offline', 'unknown'] as const) {
      assert.ok(CONNECTION_STYLES[s].label.length > 0, `${s} needs a label`);
      assert.ok(CONNECTION_STYLES[s].ariaLabel.length > 0, `${s} needs aria text`);
    }
  });
  it('online never claims scanner readiness', () => {
    assert.match(CONNECTION_STYLES.online.ariaLabel, /no claim about scan engines/i);
  });
});

describe('polling budget is conservative', () => {
  it('interval is 30-60s and timeout bounded', () => {
    assert.ok(HEALTH_TIMEOUT_MS >= 3000 && HEALTH_TIMEOUT_MS <= 15_000, 'timeout must be bounded');
  });
});

describe('transitionToast — one toast per real change', () => {
  it('never announces the initial checking/unknown state', () => {
    for (const next of ['online', 'degraded', 'offline', 'unknown'] as const) {
      assert.equal(transitionToast('checking', next), 'none', `checking->${next} must be silent`);
    }
    assert.equal(transitionToast('unknown', 'offline'), 'none', 'unknown->offline must be silent');
  });
  it('same state is always silent', () => {
    for (const s of ['online', 'degraded', 'offline'] as const) {
      assert.equal(transitionToast(s, s), 'none');
    }
  });
  it('online -> offline warns; offline -> online recovers', () => {
    assert.equal(transitionToast('online', 'offline'), 'warn-lost');
    assert.equal(transitionToast('offline', 'online'), 'info-recovered');
  });
  it('online -> degraded warns about the dependency, not the connection', () => {
    assert.equal(transitionToast('online', 'degraded'), 'warn-degraded');
    assert.equal(transitionToast('degraded', 'online'), 'info-recovered-db');
  });
  it('offline -> degraded does not claim recovery (still not usable)', () => {
    // The connection returned but the dependency is unhealthy: a recovery
    // toast would be false, so the dependency alert wins.
    assert.equal(transitionToast('offline', 'degraded'), 'warn-degraded');
  });
  it('every non-none decision has copy without sensitive data', () => {
    for (const d of ['warn-lost', 'info-recovered', 'warn-degraded', 'info-recovered-db'] as const) {
      const copy = TOAST_COPY[d];
      assert.ok(copy.message.length > 0);
      assert.ok(!/http|token|secret|key|url/i.test(copy.message), `${d} must not leak internals`);
    }
  });
});

describe('probeBackend — timeout, malformed, and unreachable paths', () => {
  it('a ready payload is returned structurally, never thrown', async () => {
    const fake = (async () => ({ ok: true, status: 200, json: async () => ({ status: 'ready' }) })) as unknown as typeof fetch;
    const r = await probeBackend('https://x.dev/api/v1/health/ready', fake);
    assert.equal(r.transportError, false);
    assert.equal(r.status, 200);
    assert.deepEqual(r.body, { status: 'ready' });
  });
  it('an aborted/hanging probe is a transport failure (offline), not a hang', async () => {
    const fake = (async () => { throw new DOMException('aborted', 'AbortError'); }) as unknown as typeof fetch;
    const r = await probeBackend('https://x.dev/api/v1/health/ready', fake);
    assert.equal(r.transportError, true);
    assert.equal(r.status, null);
  });
  it('a non-JSON body (SPA fallback) yields status but null body', async () => {
    const fake = (async () => ({ ok: true, status: 200, json: async () => { throw new SyntaxError('not json'); } })) as unknown as typeof fetch;
    const r = await probeBackend('https://x.dev/api/v1/health/ready', fake);
    assert.equal(r.status, 200);
    assert.equal(r.body, null);
    // 200 + uninterpretable -> unknown: the badge must not turn green
    assert.equal(classifyHealth({ status: r.status, body: r.body, transportError: false }, 'ready'), 'unknown');
  });
  it('a 503 degraded payload is surfaced for the degraded badge', async () => {
    const fake = (async () => ({ ok: false, status: 503, json: async () => ({ status: 'degraded' }) })) as unknown as typeof fetch;
    const r = await probeBackend('https://x.dev/api/v1/health/ready', fake);
    assert.equal(classifyHealth({ status: r.status, body: r.body, transportError: false }, 'ready'), 'degraded');
  });
});

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
function loadVercelConfig(p: string): any {
  return JSON.parse(readFileSync(join(root, p), 'utf8'));
}

describe('committed deployment configs: Preview can no longer reach production (Phase 24 fail-closed)', () => {
  for (const file of ['vercel.json', 'frontend/vercel.json']) {
    it(`${file} declares no external /api rewrite`, () => {
      const cfg = loadVercelConfig(file);
      const dest = JSON.stringify(cfg.rewrites?.find((r: any) => r.source?.startsWith('/api'))?.destination ?? '');
      assert.ok(
        !/firecrow-backend\.onrender\.com/.test(dest),
        `hazard regression: ${file} routes /api to production: ${dest}`,
      );
    });

    it(`${file} passes the preview check (fail-closed)`, () => {
      const cfg = loadVercelConfig(file);
      assert.deepEqual(
        verifyRouting(cfg, 'preview'),
        [],
        `expected no preview violations, got ${JSON.stringify(verifyRouting(cfg, 'preview'))}`,
      );
    });
  }

  it('the old production rewrite would still fail preview AND staging (guard regression check)', () => {
    const prodLike = {
      rewrites: [{ source: '/api/:match*', destination: 'https://firecrow-backend.onrender.com/api/:match*' }],
    };
    assert.ok(
      verifyRouting(prodLike, 'preview').some((v) => v.code === 'external-upstream-in-preview'),
      'preview must reject the old production rewrite',
    );
    assert.ok(
      verifyRouting(prodLike, 'staging').some((v) => v.code === 'production-host-in-staging'),
      'staging must reject the old production rewrite',
    );
  });
});
