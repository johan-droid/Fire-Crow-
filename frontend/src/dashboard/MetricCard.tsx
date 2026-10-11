import React from 'react';

export interface MetricCardProps {
  label: string;
  value: number | string;
  hint?: string;
  icon?: React.ReactNode;
  tone?: 'neutral' | 'accent' | 'health' | 'crit';
  statusBadge?: string;
  onClick?: () => void;
  className?: string;
}

export function MetricCard({
  label,
  value,
  hint,
  icon,
  tone = 'neutral',
  statusBadge,
  onClick,
  className = '',
}: MetricCardProps) {
  const toneClass = `tone-${tone}`;

  return (
    <div
      className={`fc-metric-card ${toneClass} ${onClick ? 'is-clickable' : ''} ${className}`}
      onClick={onClick}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
    >
      <div className="fc-metric-header">
        <div className="fc-metric-label-group">
          {icon && <span className="fc-metric-icon" aria-hidden="true">{icon}</span>}
          <span className="fc-metric-label">{label}</span>
        </div>
        {statusBadge && (
          <span className={`fc-metric-status-badge ${toneClass}`}>
            {statusBadge}
          </span>
        )}
      </div>

      <div className="fc-metric-body">
        <span className="fc-metric-value">{value}</span>
      </div>

      {hint && (
        <div className="fc-metric-footer">
          <span className="fc-metric-hint">{hint}</span>
        </div>
      )}
    </div>
  );
}

export default MetricCard;
