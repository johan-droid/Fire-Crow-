import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// Dry run of the shipped frontend deployment config.
//
// Two traps motivate this file, both of the same shape — configuration that is
// *present* but silently ineffective:
//   1. There are two `vercel.json` files (repo root and `frontend/`) and only
//      one is live, depending on the project's configured root directory. A fix
//      applied to the wrong one changes nothing, so the two must not drift.
//   2. The CSP is applied to every response, including the platform's. A CSP
//      that blocks the app's own assets, or that was loosened to silence an
//      unrelated error page, fails silently in production.
//
// These read the real config files, not fixtures: fixture-based tests cannot
// catch an edit to what actually ships.

const cwd = process.cwd();
const read = (p: string) => readFileSync(join(cwd, p), 'utf8');

interface VercelConfig {
  cleanUrls?: boolean;
  rewrites?: Array<{ source?: string; destination?: unknown }>;
  headers?: Array<{ source?: string; headers?: Array<{ key: string; value: string }> }>;
}

const CONFIGS = [
  { file: 'vercel.json', cfg: JSON.parse(read('vercel.json')) as VercelConfig },
  { file: join('..', 'vercel.json'), cfg: JSON.parse(read(join('..', 'vercel.json'))) as VercelConfig },
];

/** Header values keyed by name, order-insensitive (the files legitimately differ in order). */
const securityHeaders = (cfg: VercelConfig): Record<string, string> => {
  const block = cfg.headers?.find((h) => h.source === '/(.*)');
  const out: Record<string, string> = {};
  for (const h of block?.headers ?? []) out[h.key] = h.value;
  return out;
};

const cspOf = (cfg: VercelConfig): string => securityHeaders(cfg)['Content-Security-Policy'] ?? '';

function parseCsp(csp: string): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const part of csp.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length) map.set(tokens[0], tokens.slice(1));
  }
  return map;
}

/** Does `source` (a CSP source expression list) permit `url`? */
function permitted(directive: string[] | undefined, url: string, selfOrigin: string): boolean {
  if (!directive || directive.length === 0) return false;
  if (directive.includes('*')) return true;
  let parsed: URL;
  try {
    parsed = new URL(url, selfOrigin);
  } catch {
    return false;
  }
  const isSelf = parsed.origin === selfOrigin;
  for (const src of directive) {
    if (src === "'self'" && isSelf) return true;
    if (src === parsed.protocol) return true; // scheme-source, e.g. `https:`
    if (src === parsed.origin) return true; // host-source, exact origin
    if (src.endsWith('//' + parsed.host) || src === parsed.host) return true;
  }
  return false;
}

const SELF_ORIGIN = 'https://example.test';

describe('the two shipped vercel.json files never drift', () => {
  it('declares the same rewrite set, including the SPA fallback', () => {
    const [a, b] = CONFIGS.map((c) => JSON.stringify(c.cfg.rewrites ?? []));
    assert.equal(a, b, 'vercel.json and frontend/vercel.json disagree on rewrites — only one of them is live');
    assert.equal(
      (CONFIGS[0].cfg.rewrites ?? []).some((r) => r.source === '/(.*)'),
      true,
      'SPA fallback missing: deep links will 404',
    );
  });

  it('declares the same security headers, so a fix to one is not silently ignored', () => {
    const a = securityHeaders(CONFIGS[0].cfg);
    const b = securityHeaders(CONFIGS[1].cfg);
    assert.deepEqual(a, b, 'security headers differ between the two vercel.json files');
  });
});

describe('the shipped CSP stays strict and does not break our own page', () => {
  const csp = cspOf(CONFIGS[0].cfg);
  const directives = parseCsp(csp);
  const html = read(join('index.html'));

  it('is present and forbids inline script', () => {
    assert.ok(csp, 'no Content-Security-Policy header is configured');
    const scriptSrc = directives.get('script-src') ?? [];
    assert.ok(!scriptSrc.includes("'unsafe-inline'"), "script-src must not allow 'unsafe-inline'");
    assert.ok(!scriptSrc.includes("'unsafe-eval'"), "script-src must not allow 'unsafe-eval'");
    assert.ok(!csp.includes("'unsafe-hashes'"), "'unsafe-hashes' weakens the policy; fix the page instead");
  });

  it('index.html has no inline script or inline event handler to block', () => {
    const inlineScripts = [...html.matchAll(/<script\b(?![^>]*\bsrc=)[^>]*>[\s\S]*?<\/script>/gi)];
    assert.deepEqual(
      inlineScripts.map((m) => m[0].slice(0, 60)),
      [],
      'index.html contains an inline <script> that the shipped CSP will block',
    );
    assert.ok(!/\son[a-z]+\s*=/i.test(html), 'index.html contains an inline event handler that the CSP will block');
  });

  it('permits every external resource index.html references', () => {
    const refs: Array<{ url: string; directive: string }> = [];
    for (const m of html.matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["']/gi)) {
      refs.push({ url: m[1], directive: 'script-src' });
    }
    for (const tag of html.matchAll(/<link\b[^>]*>/gi)) {
      const href = tag[0].match(/href=["']([^"']+)["']/)?.[1];
      const rel = (tag[0].match(/rel=["']([^"']+)["']/)?.[1] ?? '').toLowerCase();
      if (!href) continue;
      // preconnect/dns-prefetch are connection hints, governed by connect-src.
      if (rel === 'stylesheet') refs.push({ url: href, directive: 'style-src' });
      else if (rel === 'preconnect' || rel === 'dns-prefetch') refs.push({ url: href, directive: 'connect-src' });
    }
    assert.ok(refs.length > 0, 'expected index.html to reference at least one resource');
    for (const { url, directive } of refs) {
      assert.ok(
        permitted(directives.get(directive), url, SELF_ORIGIN),
        `${directive} does not permit ${url} — the shipped CSP would block our own page`,
      );
    }
  });
});
