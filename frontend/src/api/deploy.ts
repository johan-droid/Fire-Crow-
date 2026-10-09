// Static deployment-routing verification. Pure functions over parsed config
// objects — no network, no probing of real services.
//
// Phase 24 posture (fail-closed): neither committed `vercel.json` declares an
// /api rewrite. Vercel rewrites do NOT interpolate environment variables, so
// any hardcoded external upstream would silently route every Preview
// deployment at that config to whatever host is written in the file (Phase
// 22A: both files pointed at the production backend). With no /api rewrite in
// the repo, a Preview deployment cannot reach ANY backend through the
// same-origin path — API traffic is wired per environment via the VITE_API_URL
// dashboard variable instead. These checks make a regression (any external
// /api rewrite, production host or otherwise) statically detectable.

export interface RewriteRule {
  source?: string;
  destination?: unknown;
}

export interface VercelConfig {
  rewrites?: RewriteRule[];
  [key: string]: unknown;
}

/** Hostnames that must never appear in a non-production deployment config. */
export const PRODUCTION_HOSTS = ['firecrow-backend.onrender.com'] as const;

export interface RoutingViolation {
  code:
    | 'production-host-in-staging'
    | 'external-upstream-in-preview'
    | 'missing-api-upstream'
    | 'malformed-destination'
    | 'double-api-prefix'
    | 'missing-api-v1'
    | 'no-rewrites'
    | 'unreviewed-host';
  detail: string;
}

export function extractApiUpstream(config: VercelConfig): string | null {
  const rewrites = config.rewrites ?? [];
  for (const rule of rewrites) {
    const source = typeof rule?.source === 'string' ? rule.source : '';
    if (source.startsWith('/api')) {
      return rule.destination as string;
    }
  }
  return null;
}

/**
 * Verify one deployment config against the intent recorded in `mode`.
 *
 * mode 'production' — upstream must be an explicit origin, never empty. A
 *                     known production host is accepted ONLY here.
 * mode 'staging'    — upstream must exist, parse, carry exactly one /api/v1
 *                     prefix, and point at a host that is not a known
 *                     production host (unless explicitly allow-listed).
 * mode 'preview'    — fail-closed: NO external /api upstream may exist. Any
 *                     absolute-URL /api rewrite is a violation, whatever host
 *                     it points at, because Vercel cannot scope a committed
 *                     rewrite to one environment. This is the mode the two
 *                     committed `vercel.json` files must satisfy.
 */
export function verifyRouting(
  config: VercelConfig,
  mode: 'production' | 'staging' | 'preview',
  allowedProductionHosts: readonly string[] = PRODUCTION_HOSTS,
): RoutingViolation[] {
  const violations: RoutingViolation[] = [];
  const rewrites = config.rewrites;
  if (!Array.isArray(rewrites) || rewrites.length === 0) {
    violations.push({ code: 'no-rewrites', detail: 'config declares no rewrites: /api/* would fall through to the SPA' });
    return violations;
  }

  const upstream = extractApiUpstream(config);
  if (upstream === null) {
    // No /api rewrite: fail-closed for preview (nothing can leak), a
    // missing upstream for staging/production (nothing can reach the API).
    // Callers decide which verdict applies via `mode`.
    if (mode === 'preview') return violations;
    violations.push({ code: 'missing-api-upstream', detail: `no rewrite covers an /api* path (sources: ${describe(rewrites)})` });
    return violations;
  }
  if (typeof upstream !== 'string' || upstream.trim() === '') {
    violations.push({ code: 'malformed-destination', detail: '/api rewrite destination is not a non-empty string' });
    return violations;
  }

  if (/\/api\/v1\/api\/v1/.test(upstream) || /\/api\/api\b/.test(upstream)) {
    violations.push({ code: 'double-api-prefix', detail: `duplicated path prefix in destination: ${upstream}` });
  }

  let host = '';
  try {
    const parsed = new URL(upstream);
    host = parsed.hostname;
    const path = parsed.pathname;
    if (mode === 'preview') {
      // Any absolute-URL /api rewrite escapes the Preview deployment to an
      // external backend — fail regardless of which host it names. Vercel
      // cannot scope a committed rewrite per environment, so the only safe
      // committed Preview posture is no external /api rewrite at all.
      violations.push({
        code: 'external-upstream-in-preview',
        detail: `preview config carries an external /api upstream (host ${host || '(unparseable)'}): ${upstream}`,
      });
      return violations;
    }
    if (mode === 'staging') {
      // The /api path prefix must survive the rewrite. Vercel's wildcard form
      // is `/api/:match*` -> `https://host/api/:match*`: the literal string
      // need not contain "/api/v1" (the version is supplied at request time),
      // but a destination that strips "/api" (e.g. `https://host/:match*`)
      // forwards `/v1/health` and 404s every call.
      if (!path.startsWith('/api/')) {
        violations.push({ code: 'missing-api-v1', detail: `staging upstream strips the /api prefix: ${upstream}` });
      }
      // ...and must not duplicate it.
      if (/\/api(\/v1)?\/api(\/v1)?\//.test(path)) {
        violations.push({ code: 'double-api-prefix', detail: `duplicated path prefix in destination: ${upstream}` });
      }
      for (const prod of PRODUCTION_HOSTS) {
        if (host === prod) {
          violations.push({
            code: 'production-host-in-staging',
            detail: `staging config targets production host ${prod}`,
          });
        }
      }
      if (!host) {
        violations.push({ code: 'malformed-destination', detail: `staging upstream has no hostname: ${upstream}` });
      }
    }
    if (mode === 'production' && !host) {
      violations.push({ code: 'malformed-destination', detail: `production upstream has no hostname: ${upstream}` });
    }
    if (mode === 'production' && host) {
      // Production-host allowance lives ONLY in production context: the same
      // upstream checked under staging/preview must still fail (staging via
      // production-host-in-staging, preview via external-upstream-in-preview).
      const allowed = allowedProductionHosts.some((h) => h === host);
      if (!allowed) {
        violations.push({ code: 'unreviewed-host', detail: `production upstream host is not allow-listed: ${host}` });
      }
    }
  } catch {
    violations.push({ code: 'malformed-destination', detail: `destination is not an absolute URL: ${upstream}` });
  }

  return violations;
}

function describe(rewrites: RewriteRule[]): string {
  return rewrites.map((r) => String(r?.source ?? '(no source)')).join(', ');
}

/** True when a deployment config can safely be used for the given mode. */
export function isRoutingSafe(
  config: VercelConfig,
  mode: 'production' | 'staging' | 'preview',
  allowedProductionHosts?: readonly string[],
): boolean {
  return verifyRouting(config, mode, allowedProductionHosts).length === 0;
}
