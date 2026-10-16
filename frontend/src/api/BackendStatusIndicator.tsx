// Live backend connection indicator.
//
// Truthfulness rules (Phase 23 §4), enforced by api/health.ts:
// - "Online" means the health endpoint answered and reported ready. It never
//   claims scanners are operational: no endpoint reports that, and scanner
//   execution is unproven in every deployed environment.
// - "Degraded" means the service answered but reports a dependency unhealthy.
// - "Waking up" (FC-OPS-EMAIL-001) means our own bounded timeout fired: on a
//   free-tier host that may be a cold start or an outage, and the label says
//   exactly that ambiguity. It never claims the platform put the backend to
//   sleep or that it crashed. Three consecutive timeouts escalate it to
//   "Offline" — that duration is no longer explained by a cold start.
// - "Offline" means the request failed outright (refused, DNS).
// - "Unknown" means a 2xx arrived but could not be interpreted as health
//   (e.g. an HTML SPA body returned for an /api path).
//
// Polling: conservative interval with bounded backoff after consecutive
// failures (returns to normal on the first success), single in-flight request,
// pause while hidden, cleanup on unmount (including the in-flight abort),
// late responses discarded (guarded by a request id).
import { useEffect, useRef, useState } from 'react';
import {
  classifyHealth,
  CONNECTION_STYLES,
  HEALTH_POLL_MS,
  HEALTH_TIMEOUT_MS,
  nextPollDelay,
  probeBackend,
  relativeCheckLabel,
  WAKING_TIMEOUT_ESCALATION,
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
  const [, setTick] = useState(0);
  const [lastOkAt, setLastOkAt] = useState<number | null>(null);
  const inFlight = useRef(false);
  const requestId = useRef(0);
  const prevState = useRef<ConnectionState>('checking');
  const failures = useRef(0);
  const timeouts = useRef(0);
  const ctrlRef = useRef<AbortController | null>(null);
  const runRef = useRef<() => void>(() => {});
  const handler = useRef(onTransition);
  handler.current = onTransition;

  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | null = null;

    const schedule = (delay: number) => {
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => void run(), delay);
    };

    const run = async () => {
      // FC-RELEASE-017 (review finding 4): `alive` is checked FIRST and the
      // reschedule is guarded — otherwise the `finally` below resurrects the
      // poller after unmount (a probe in flight at LoginPage unmount used to
      // leave a background /health/ready loop alive for the SPA session).
      if (!alive) return;
      // Never overlap: a slow probe must not spawn a second request.
      if (inFlight.current || document.visibilityState === 'hidden') return;
      inFlight.current = true;
      const id = ++requestId.current;
      const ctrl = new AbortController();
      ctrlRef.current = ctrl;
      const timeout = setTimeout(() => ctrl.abort(), HEALTH_TIMEOUT_MS);
      try {
        const probe = await probeBackend(`${getApiBase()}/health/ready`, fetchImpl, ctrl.signal);
        // Late response guard: discard if a newer probe started or we unmounted.
        if (!alive || id !== requestId.current) return;
        let next = classifyHealth(
          {
            status: probe.status,
            body: probe.body,
            transportError: probe.transportError,
            timedOut: probe.timedOut,
          },
          'ready',
        );
        if (next === 'waking') {
          timeouts.current += 1;
          if (timeouts.current >= WAKING_TIMEOUT_ESCALATION) next = 'offline';
        } else {
          timeouts.current = 0;
        }
        if (next === 'offline' || next === 'waking') {
          failures.current += 1;
        } else {
          failures.current = 0;
        }
        if (next === 'online') setLastOkAt(Date.now());
        setState((cur) => {
          if (cur === next) return cur;
          const prev = prevState.current;
          prevState.current = next;
          handler.current?.(prev, next);
          return next;
        });
        // Re-render every cycle so the "last ok Xm ago" label stays truthful
        // even while the badge itself does not change.
        setTick((t) => t + 1);
      } finally {
        clearTimeout(timeout);
        inFlight.current = false;
        // Guarded: an unmounted component schedules nothing. The timer owns
        // the cadence, and `schedule` keeps exactly one pending timer alive.
        if (alive) schedule(nextPollDelay(failures.current, intervalMs));
      }
    };
    runRef.current = () => {
      // A manual retry resets the backoff — unless a probe is already in
      // flight, in which case resetting would silently discard the backoff
      // state without issuing a request (FC-RELEASE-017 review nit). The
      // in-flight probe's own completion reschedules normally, so a
      // mid-flight retry is a no-op rather than a state corruption.
      if (inFlight.current) return;
      failures.current = 0;
      timeouts.current = 0;
      void run();
    };

    void run();
    const onVisible = () => { if (document.visibilityState === 'visible') void run(); };
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      alive = false;
      if (timer) clearTimeout(timer);
      ctrlRef.current?.abort();
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [fetchImpl, intervalMs]);

  const style = CONNECTION_STYLES[state];
  const showRetry = state === 'offline' || state === 'waking' || state === 'unknown';
  const agoLabel = lastOkAt === null ? null : relativeCheckLabel(lastOkAt, Date.now());
  return (
    <div
      className={`backend-status backend-status-${state}`}
      title={style.ariaLabel + (agoLabel ? ` · last successful check ${agoLabel}` : '')}
    >
      <span className={style.dotClass} />
      <span className="backend-status-label">{style.label}</span>
      {agoLabel && <span className="backend-status-ago">{agoLabel}</span>}
      {showRetry && (
        <button
          type="button"
          className="backend-status-retry"
          onClick={() => runRef.current()}
          aria-label="Retry backend status check now"
          title="Retry now"
        >
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" aria-hidden="true">
            <path d="M21 12a9 9 0 1 1-2.64-6.36" />
            <polyline points="21 3 21 9 15 9" />
          </svg>
        </button>
      )}
      <span className="sr-only" role="status" aria-live="polite">{style.ariaLabel}</span>
    </div>
  );
}
