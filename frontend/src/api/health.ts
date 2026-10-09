// Backend connection-status semantics. Pure and unit-tested: no fetch, no React,
// no browser globals — that keeps it compilable under both the app config and
// the tests config (which has no DOM lib).
//
// What the existing public health endpoints prove (verified live in Phase 20):
//   GET /api/v1/health      -> always 200 `{status:"up",database:"connected"|"disconnected"}`
//   GET /api/v1/health/ready-> 200 `{status:"ready"}` or 503 `{status:"degraded"}`
//   GET /api/v1/health/deep -> 200/503, adds storage + circuit-breaker detail
//
// The indicator must never claim scanner readiness: no endpoint reports it, and
// scanner execution has never been proven in any deployed environment.


export type ConnectionState = 'checking' | 'online' | 'degraded' | 'offline' | 'unknown';

export interface HealthObservation {
  /** HTTP status of the health request, or null when the request never completed. */
  status: number | null;
  /** Parsed JSON body when it was a readable object; null otherwise. */
  body: Record<string, unknown> | null;
  /** True when the request failed at transport level (DNS, refused, timeout, abort). */
  transportError: boolean;
}

/**
 * Classify one health observation. Truthful by construction:
 * - A 200 /health proves reachability only; it never implies the database or scanners.
 * - /ready's own verdict decides online vs degraded (503/degraded means the
 *   dependency check failed, the service is not ready to audit).
 * - An uninterpretable 2xx is `unknown`, never `online`: absence of proof of
 *   failure is not proof of health, and a green badge must be earned.
 */
export function classifyHealth(obs: HealthObservation, which: 'simple' | 'ready' = 'ready'): ConnectionState {
  if (obs.transportError) return 'offline';
  if (obs.status === null) return 'unknown';

  // Any 5xx (503 included): the service answered, and itself reports it is not
  // healthy. Only a 4xx means the route/method/contract is wrong.
  if (obs.status >= 500) return 'degraded';
  if (obs.status >= 400 && obs.status < 500) return 'unknown';

  if (!obs.body || typeof obs.body !== 'object' || Array.isArray(obs.body)) return 'unknown';

  const status = typeof obs.body.status === 'string' ? obs.body.status.trim().toLowerCase() : '';
  if (which === 'ready') {
    if (status === 'ready') return 'online';
    if (status === 'degraded') return 'degraded';
    return 'unknown';
  }
  if (status === 'up' || status === 'healthy' || status === 'ok') return 'online';
  if (status === 'unhealthy') return 'degraded';
  return 'unknown';
}

export interface StateStyle {
  /** Short visible label — text always accompanies the dot (never color alone). */
  label: string;
  /** CSS class for the dot. */
  dotClass: string;
  /** Screen-reader text: states exactly what is and is not proven. */
  ariaLabel: string;
}

export const CONNECTION_STYLES: Record<ConnectionState, StateStyle> = {
  checking: {
    label: 'Checking',
    dotClass: 'status-dot status-dot-bs-checking',
    ariaLabel: 'Backend status: Checking connection',
  },
  online: {
    label: 'Online',
    dotClass: 'status-dot status-dot-live',
    ariaLabel: 'Backend status: Online. API reachable; no claim about scan engines.',
  },
  degraded: {
    label: 'Degraded',
    dotClass: 'status-dot status-dot-bs-degraded',
    ariaLabel: 'Backend status: Degraded. API responds but reports a dependency unhealthy.',
  },
  offline: {
    label: 'Offline',
    dotClass: 'status-dot status-dot-down',
    ariaLabel: 'Backend status: Offline. Health request failed or timed out.',
  },
  unknown: {
    label: 'Unknown',
    dotClass: 'status-dot status-dot-bs-unknown',
    ariaLabel: 'Backend status: Unknown. No reliable health result yet.',
  },
};

/** Conservative polling cadence: no request storm, no overlap. */
export const HEALTH_POLL_MS = 45_000;
export const HEALTH_TIMEOUT_MS = 8_000;

export interface ProbeResult {
  ok: boolean;
  status: number | null;
  body: Record<string, unknown> | null;
  transportError: boolean;
}

/**
 * One health probe against the readiness endpoint. Never throws: failures
 * come back as a structured result so the UI degrades instead of crashing.
 * `fetchImpl` is injected so tests exercise the timeout/malformed-body paths
 * without a network. The URL is supplied by the caller (the component knows
 * the resolved API base); this module stays free of browser globals.
 */
export async function probeBackend(
  url: string,
  fetchImpl: typeof fetch,
  signal?: AbortSignal,
): Promise<ProbeResult> {
  try {
    const res = await fetchImpl(url, { signal, credentials: 'include' });
    let body: Record<string, unknown> | null = null;
    try {
      const parsed: unknown = await res.json();
      body = parsed && typeof parsed === 'object' && !Array.isArray(parsed)
        ? (parsed as Record<string, unknown>)
        : null;
    } catch {
      body = null; // non-JSON body (SPA fallback): reachable but uninterpretable
    }
    return { ok: res.ok, status: res.status, body, transportError: false };
  } catch {
    return { ok: false, status: null, body: null, transportError: true };
  }
}

export type ToastDecision = 'none' | 'warn-lost' | 'info-recovered' | 'warn-degraded' | 'info-recovered-db';

/**
 * Which user-facing toast a state transition warrants.
 * Transitions in, not states out: one toast per real change, never per poll.
 * The initial unknown/checking state is never announced.
 *
 * Ordering encodes the honesty rules:
 * - Anything landing on `offline` is a connection-loss alert, including
 *   degraded -> offline (a genuine worsening, worth saying once).
 * - Anything landing on `degraded` is a dependency alert, including
 *   offline -> degraded: the connection came back, but claiming recovery
 *   would be false, so the dependency truth wins.
 * - Only a landing on `online` reports recovery.
 */
export function transitionToast(prev: ConnectionState, next: ConnectionState): ToastDecision {
  if (prev === next) return 'none';
  // Never announce the initial checking/unknown state as a problem.
  if (prev === 'checking' || next === 'checking') return 'none';
  if (prev === 'unknown') return 'none';
  if (next === 'offline') return 'warn-lost';
  if (next === 'degraded') return 'warn-degraded';
  if (prev === 'offline') return 'info-recovered';
  if (prev === 'degraded' && next === 'online') return 'info-recovered-db';
  return 'none';
}

export const TOAST_COPY: Record<Exclude<ToastDecision, 'none'>, { tone: 'warning' | 'info'; message: string }> = {
  'warn-lost': { tone: 'warning', message: 'Backend connection lost — data shown may be stale.' },
  'info-recovered': { tone: 'info', message: 'Backend connection restored.' },
  'warn-degraded': { tone: 'warning', message: 'Backend reports a dependency unhealthy — new audits may fail.' },
  'info-recovered-db': { tone: 'info', message: 'Backend dependency recovered.' },
};
