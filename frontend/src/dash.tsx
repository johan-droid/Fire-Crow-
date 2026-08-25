/**
 * Dashboard state & visualization primitives.
 * Typed against the Fire Crow REST API (documentation/API_DOCUMENTATION.md).
 */

export type LoadState = 'loading' | 'ready' | 'error';

export interface JobStatusInfo {
  label: string;
  cls: string;
  pulse?: boolean;
}

/** Map API job status → badge styling. */
export function jobStatusInfo(status: string): JobStatusInfo {
  switch (status) {
    case 'queued': return { label: 'QUEUED', cls: 'badge-neutral', pulse: true };
    case 'running': return { label: 'RUNNING', cls: 'badge-info', pulse: true };
    case 'completed': return { label: 'COMPLETED', cls: 'badge-success' };
    case 'failed': return { label: 'FAILED', cls: 'badge-critical' };
    case 'cancelled': return { label: 'CANCELLED', cls: 'badge-medium' };
    case 'partial': return { label: 'PARTIAL', cls: 'badge-medium' };
    default: return { label: status.toUpperCase(), cls: 'badge-neutral' };
  }
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = typeof SEVERITY_ORDER[number];

export function severityClass(s: string): string {
  switch ((s || '').toLowerCase()) {
    case 'critical': return 'badge-critical';
    case 'high': return 'badge-high';
    case 'medium': return 'badge-medium';
    case 'low': return 'badge-low';
    default: return 'badge-neutral';
  }
}

/** Backend stores naive-UTC timestamps; render them in the viewer's locale. */
export function fmtUtc(value?: string | null): string {
  if (!value) return '—';
  const normalized = value.includes('T') ? value : value.replace(' ', 'T');
  const withZone = /[zZ+]|-\d{2}:?\d{2}$/.test(normalized) ? normalized : `${normalized}Z`;
  const d = new Date(withZone);
  return isNaN(d.getTime()) ? value : d.toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  });
}

export function timeAgo(value?: string | null): string {
  if (!value) return '';
  const normalized = value.includes('T') ? value : value.replace(' ', 'T');
  const withZone = /[zZ+]|-\d{2}:?\d{2}$/.test(normalized) ? normalized : `${normalized}Z`;
  const then = new Date(withZone).getTime();
  if (isNaN(then)) return '';
  const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

/** Panel body that renders loading skeletons, an error retry block, or content. */
export function PanelState({
  state, error, empty, emptyIcon, onRetry, children, rows = 3,
}: {
  state: LoadState;
  error?: string | null;
  empty?: boolean;
  emptyIcon?: string;
  onRetry?: () => void;
  children: React.ReactNode;
  rows?: number;
}) {
  if (state === 'loading') {
    return (
      <div className="state-skeleton" aria-busy="true">
        {Array.from({ length: rows }).map((_, i) => (
          <div key={i} className="skeleton-row" style={{ animationDelay: `${i * 0.12}s`, width: `${92 - i * 9}%` }} />
        ))}
      </div>
    );
  }
  if (state === 'error') {
    return (
      <div className="state-error">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
        </svg>
        <span>{error || 'Failed to load data.'}</span>
        {onRetry && <button className="btn btn-secondary btn-sm" onClick={onRetry}>Retry</button>}
      </div>
    );
  }
  if (empty) {
    return (
      <div className="state-empty">
        <span className="state-empty-icon">{emptyIcon ?? '◌'}</span>
        {children}
      </div>
    );
  }
  return <>{children}</>;
}

/** Security score donut (0–10 scale from JobResponse.security_score). */
export function ScoreRing({ score, size = 54 }: { score: number | null; size?: number }) {
  const value = Math.max(0, Math.min(10, score ?? 0));
  const stroke = size >= 54 ? 5 : 4;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const filled = score == null ? 0 : (value / 10) * c;
  const color = score == null ? 'rgba(255,255,255,0.15)'
    : value >= 8 ? '#30d158'
    : value >= 5 ? '#ffd60a'
    : value >= 3 ? '#ff8533'
    : '#ff453a';
  return (
    <div className="score-ring" style={{ width: size, height: size }} title={score == null ? 'No score' : `Security score ${value}/10`}>
      <svg width={size} height={size}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth={stroke} />
        <circle
          cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={stroke}
          strokeLinecap="round" strokeDasharray={`${filled} ${c}`}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          style={{ transition: 'stroke-dasharray .8s cubic-bezier(.16,1,.3,1)' }}
        />
      </svg>
      <span className="score-ring-value" style={{ color, fontSize: size * 0.26 }}>
        {score == null ? '—' : value.toFixed(1)}
      </span>
    </div>
  );
}

/** Severity distribution mini bar chart from Finding[]. */
export function SeverityBars({ findings }: { findings: { severity: string }[] }) {
  const counts = SEVERITY_ORDER.map((s) => ({
    sev: s,
    n: findings.filter((f) => (f.severity || '').toLowerCase() === s).length,
  }));
  const max = Math.max(1, ...counts.map((c) => c.n));
  const colors: Record<string, string> = {
    critical: '#ff453a', high: '#ff8533', medium: '#ffd60a', low: '#2997ff', info: 'rgba(255,255,255,0.25)',
  };
  return (
    <div className="sev-bars">
      {counts.map(({ sev, n }) => (
        <div key={sev} className="sev-col" title={`${n} ${sev}`}>
          <div className="sev-bar-track">
            <div
              className="sev-bar-fill"
              style={{
                height: `${Math.max(n > 0 ? 8 : 0, (n / max) * 100)}%`,
                background: colors[sev],
                boxShadow: n > 0 ? `0 0 8px ${colors[sev]}55` : 'none',
              }}
            />
          </div>
          <span className="sev-count">{n}</span>
          <span className="sev-label">{sev.slice(0, 3).toUpperCase()}</span>
        </div>
      ))}
    </div>
  );
}

/** System health widget per API docs §14: service dots + circuit breaker badges. */
export function HealthWidget({ deep }: { deep: DeepHealth | null }) {
  if (!deep) {
    return <div className="health-widget"><span className="health-loading">Probing system telemetry…</span></div>;
  }
  const dot = (ok: boolean | null, disabled = false) =>
    `status-dot ${disabled ? '' : ok ? 'status-dot-live' : 'status-dot-down'}`;
  const dbOk = deep.database === 'ok' || deep.database === 'connected';
  const lsOk = deep.local_storage === 'ok';
  const osRaw = deep.object_storage;
  const osOk = osRaw === 'ok';
  const osDisabled = osRaw === 'disabled' || osRaw == null;
  const breakers = Object.entries(deep.circuit_breakers || {});
  const breakerCls = (s: string) => s === 'closed' ? 'breaker-closed' : s === 'half-open' ? 'breaker-half' : 'breaker-open';
  const breakerLabel = (s: string) => s === 'closed' ? 'ACTIVE' : s === 'half-open' ? 'RECONNECTING' : 'TRIPPED';

  return (
    <div className="health-widget">
      <div className="health-services">
        <div className="health-service"><span className={dot(dbOk)} />Database<span className="health-val">{deep.database}</span></div>
        <div className="health-service"><span className={dot(lsOk)} />LocalStorage<span className="health-val">{deep.local_storage}</span></div>
        <div className="health-service"><span className={`status-dot ${osDisabled ? '' : osOk ? 'status-dot-live' : 'status-dot-down'}`} />Object Storage<span className="health-val">{osDisabled ? 'disabled' : osRaw}</span></div>
      </div>
      {breakers.length > 0 && (
        <div className="health-breakers">
          {breakers.map(([name, cb]) => (
            <span key={name} className={`breaker-badge ${breakerCls(cb.state)}`} title={`failures: ${cb.failures}${cb.last_failure ? ` • last: ${cb.last_failure}` : ''}`}>
              {name.toUpperCase()} · {breakerLabel(cb.state)}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── API response shapes (API_DOCUMENTATION.md §8, §14) ──────────

export interface DeepHealth {
  status: string;
  database: string;
  local_storage?: string;
  object_storage?: string;
  circuit_breakers?: Record<string, { state: string; failures: number; last_failure?: string | null }>;
  shutting_down?: boolean;
}
