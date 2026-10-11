import React from 'react';
import { ArrowUpRight, ArrowDownRight, Radio } from 'lucide-react';

export interface MetricCardProps {
  label: string;
  value: number | string;
  hint?: string;
  icon?: React.ReactNode;
  tone?: 'neutral' | 'accent' | 'health' | 'crit';
  trend?: {
    value: string;
    isPositive?: boolean;
    label?: string;
  };
  sparklineData?: number[];
  sparklineColor?: string;
  isLive?: boolean;
  onClick?: () => void;
  className?: string;
}

export function MetricCard({
  label,
  value,
  hint,
  icon,
  tone = 'neutral',
  trend,
  sparklineData,
  sparklineColor,
  isLive = false,
  onClick,
  className = '',
}: MetricCardProps) {
  // Generate sparkline path and area
  const renderSparkline = () => {
    const data = sparklineData && sparklineData.length > 1
      ? sparklineData
      : [4, 6, 5, 8, 7, 10, 9, 12, 11, 14];

    const width = 84;
    const height = 30;
    const padding = 2;

    const min = Math.min(...data);
    const max = Math.max(...data);
    const range = max - min || 1;

    const points = data.map((val, idx) => {
      const x = padding + (idx / (data.length - 1)) * (width - 2 * padding);
      const y = height - padding - ((val - min) / range) * (height - 2 * padding);
      return { x, y };
    });

    // Create smooth SVG path
    const pathD = points.reduce((acc, curr, idx, arr) => {
      if (idx === 0) return `M ${curr.x} ${curr.y}`;
      const prev = arr[idx - 1];
      const cx = (prev.x + curr.x) / 2;
      return `${acc} C ${cx} ${prev.y}, ${cx} ${curr.y}, ${curr.x} ${curr.y}`;
    }, '');

    const areaD = `${pathD} L ${points[points.length - 1].x} ${height} L ${points[0].x} ${height} Z`;

    const strokeColor = sparklineColor || (
      tone === 'health' ? '#30d158' :
      tone === 'accent' ? '#f97316' :
      tone === 'crit' ? '#ef4444' :
      '#a1a1aa'
    );

    const gradId = `spark-grad-${label.replace(/\s+/g, '-').toLowerCase()}`;

    return (
      <svg
        width={width}
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        className="metric-sparkline"
        aria-hidden="true"
      >
        <defs>
          <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={strokeColor} stopOpacity="0.35" />
            <stop offset="100%" stopColor={strokeColor} stopOpacity="0.0" />
          </linearGradient>
        </defs>
        <path d={areaD} fill={`url(#${gradId})`} />
        <path d={pathD} fill="none" stroke={strokeColor} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        {points.length > 0 && (
          <circle
            cx={points[points.length - 1].x}
            cy={points[points.length - 1].y}
            r="2.5"
            fill={strokeColor}
            className="sparkline-last-dot"
          />
        )}
      </svg>
    );
  };

  const toneClass = `tone-${tone}`;

  return (
    <div
      className={`fc-metric-card ${toneClass} ${isLive ? 'is-live-card' : ''} ${className}`}
      onClick={onClick}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
    >
      <div className="fc-metric-header">
        <div className="fc-metric-icon-wrap">
          {icon && <span className="fc-metric-icon" aria-hidden="true">{icon}</span>}
          <span className="fc-metric-label">{label}</span>
        </div>

        {isLive ? (
          <span className="fc-metric-live-badge">
            <span className="fc-live-pulse-dot" />
            <Radio size={12} className="fc-live-radio-icon" />
            <span>LIVE</span>
          </span>
        ) : trend ? (
          <span
            className={`fc-metric-trend-badge ${
              trend.isPositive !== false ? 'trend-up' : 'trend-down'
            }`}
            title={trend.label || undefined}
          >
            {trend.isPositive !== false ? (
              <ArrowUpRight size={13} className="trend-arrow" />
            ) : (
              <ArrowDownRight size={13} className="trend-arrow" />
            )}
            <span>{trend.value}</span>
          </span>
        ) : null}
      </div>

      <div className="fc-metric-middle">
        <div className="fc-metric-value-wrap">
          <span className="fc-metric-value">{value}</span>
        </div>
        <div className="fc-metric-spark-wrap">
          {renderSparkline()}
        </div>
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
