import { useMemo } from 'react';

export interface SeverityItem {
  id: string;
  label: string;
  count: number;
  color: string;
}

export interface SeverityBreakdownProps {
  findings?: Array<{ severity: string }>;
  auditTitle?: string;
  className?: string;
  jobs?: unknown;
}

export function SeverityBreakdown({
  findings = [],
  auditTitle,
  className = '',
}: SeverityBreakdownProps) {
  // Aggregate real finding counts strictly from passed findings
  const { counts, total } = useMemo(() => {
    const res = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    findings.forEach((f) => {
      const s = (f.severity || '').toLowerCase();
      if (s === 'critical') res.critical++;
      else if (s === 'high') res.high++;
      else if (s === 'medium') res.medium++;
      else if (s === 'low') res.low++;
      else res.info++;
    });

    const tot = res.critical + res.high + res.medium + res.low + res.info;
    return { counts: res, total: tot };
  }, [findings]);

  const categories = [
    { id: 'critical', label: 'Critical', count: counts.critical, color: '#ef4444' },
    { id: 'high', label: 'High', count: counts.high, color: '#f97316' },
    { id: 'medium', label: 'Medium', count: counts.medium, color: '#f59e0b' },
    { id: 'low', label: 'Low', count: counts.low, color: '#3b82f6' },
    { id: 'info', label: 'Info / Other', count: counts.info, color: '#71717a' },
  ].filter((c) => total === 0 || c.count > 0 || c.id !== 'info');

  return (
    <div className={`fc-panel fc-severity-panel ${className}`}>
      <div className="fc-panel-header">
        <div>
          <h2 className="fc-panel-title">Finding Severity Breakdown</h2>
          <p className="fc-panel-subtitle">
            {auditTitle || 'Findings grouped by severity'}
          </p>
        </div>
        <span className="fc-severity-total-badge">
          {total} {total === 1 ? 'finding' : 'findings'}
        </span>
      </div>

      <div className="fc-panel-body">
        {total > 0 ? (
          <div className="fc-severity-content">
            {/* Horizontal stacked distribution bar */}
            <div className="fc-stacked-bar" role="progressbar" aria-label="Findings severity distribution">
              {categories.map((cat) => {
                if (cat.count === 0) return null;
                const pct = ((cat.count / total) * 100).toFixed(1);
                return (
                  <div
                    key={cat.id}
                    className="fc-stacked-bar-seg"
                    style={{ width: `${pct}%`, backgroundColor: cat.color }}
                    title={`${cat.label}: ${cat.count} (${pct}%)`}
                  />
                );
              })}
            </div>

            {/* Compact legend metrics */}
            <div className="fc-severity-pills-row">
              {categories.map((cat) => {
                const pct = total > 0 ? ((cat.count / total) * 100).toFixed(0) : '0';
                return (
                  <div key={cat.id} className="fc-severity-pill">
                    <span className="fc-pill-dot" style={{ backgroundColor: cat.color }} />
                    <span className="fc-pill-label">{cat.label}</span>
                    <span className="fc-pill-count">{cat.count}</span>
                    <span className="fc-pill-pct">({pct}%)</span>
                  </div>
                );
              })}
            </div>
          </div>
        ) : (
          <div className="fc-severity-empty">
            <p className="fc-severity-empty-text">
              No findings loaded for this scope. Select an audit to inspect confirmed vulnerabilities
              and remediation details.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

export default SeverityBreakdown;
