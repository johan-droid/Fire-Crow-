// Live backend connection indicator.
//
// Truthfulness rules (Phase 23 §4), enforced by api/health.ts:
// - "Online" means the health endpoint answered and reported ready. It never
//   claims scanners are operational: no endpoint reports that, and scanner
//   execution is unproven in every deployed environment.
// - "Degraded" means the service answered but reports a dependency unhealthy.
// - "Offline" means the request failed/timed out.
// - "Unknown" means a 2xx arrived but could not be interpreted as health
//   (e.g. an HTML SPA body returned for an /api path).
//
// Polling: conservative interval, single in-flight request, pause while hidden,
// cleanup on unmount, late responses discarded (guarded by a request id).
import { useEffect, useRef, useState } from 'react';
import {
  classifyHealth,
  CONNECTION_STYLES,
  HEALTH_POLL_MS,
  HEALTH_TIMEOUT_MS,
  probeBackend,
  type ConnectionState,
} from './health';
import { getApiBase } from './client';

export function BackendStatusIndicator({
  fetchImpl = fetch,
  intervalMs = HEALTH_POLL_MS,
  onTransition,
}: {
  fetchImpl?: typeof fetch;
  intervalMs?: number;
  onTransition?: (prev: ConnectionState, next: ConnectionState) => void;
}) {
  const [state, setState] = useState<ConnectionState>('checking');
  const inFlight = useRef(false);
  const requestId = useRef(0);
  const prevState = useRef<ConnectionState>('checking');
  const handler = useRef(onTransition);
  handler.current = onTransition;

  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setInterval> | null = null;

    const run = async () => {
      // Never overlap: a slow probe must not spawn a second request.
      if (inFlight.current || document.visibilityState === 'hidden') return;
      inFlight.current = true;
      const id = ++requestId.current;
      const ctrl = new AbortController();
      const timeout = setTimeout(() => ctrl.abort(), HEALTH_TIMEOUT_MS);
      try {
        const probe = await probeBackend(`${getApiBase()}/health/ready`, fetchImpl, ctrl.signal);
        // Late response guard: discard if a newer probe started or we unmounted.
        if (!alive || id !== requestId.current) return;
        const next = classifyHealth(
          { status: probe.status, body: probe.body, transportError: probe.transportError },
          'ready',
        );
        setState((cur) => {
          if (cur === next) return cur;
          const prev = prevState.current;
          prevState.current = next;
          handler.current?.(prev, next);
          return next;
        });
      } finally {
        clearTimeout(timeout);
        inFlight.current = false;
      }
    };

    void run();
    timer = setInterval(() => void run(), intervalMs);
    const onVisible = () => { if (document.visibilityState === 'visible') void run(); };
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      alive = false;
      if (timer) clearInterval(timer);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [fetchImpl, intervalMs]);

  const style = CONNECTION_STYLES[state];
  return (
    <div className={`backend-status backend-status-${state}`} title={style.ariaLabel}>
      <span className={style.dotClass} />
      <span className="backend-status-label">{style.label}</span>
      <span className="sr-only" role="status" aria-live="polite">{style.ariaLabel}</span>
    </div>
  );
}
