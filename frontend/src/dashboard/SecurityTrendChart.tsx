import { useState, useMemo } from 'react';
import type { JobResponse } from '../api/types';
import { repoLabel, timeAgo } from '../dash';
import { ShieldCheck, Calendar, GitCommit } from 'lucide-react';

export interface SecurityTrendChartProps {
  jobs: JobResponse[];
  onSelectAudit?: (jobId: string) => void;
  className?: string;
}

interface ScoredAuditPoint {
  id: string;
  repoName: string;
  branch: string;
  commitSha: string | null;
  score: number;
  dateStr: string;
  displayDate: string;
  timestamp: number;
}

export function SecurityTrendChart({
  jobs,
  onSelectAudit,
  className = '',
}: SecurityTrendChartProps) {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

  // Extract only genuine completed audits that have a valid security score
  const scoredAudits = useMemo(() => {
    return jobs
      .filter((j) => j.status === 'completed' && j.security_score != null)
      .map((j): ScoredAuditPoint => {
        const rawDate = j.created_at.includes('T') ? j.created_at : j.created_at.replace(' ', 'T') + 'Z';
        const d = new Date(rawDate);
        return {
          id: j.id,
          repoName: repoLabel(j.repo_url),
          branch: j.repo_branch,
          commitSha: j.commit_sha || j.requested_commit_sha || null,
          score: Math.max(0, Math.min(10, j.security_score!)),
          dateStr: isNaN(d.getTime()) ? j.created_at : d.toISOString().split('T')[0],
          displayDate: isNaN(d.getTime())
            ? j.created_at
            : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }),
          timestamp: isNaN(d.getTime()) ? 0 : d.getTime(),
        };
      })
      .sort((a, b) => a.timestamp - b.timestamp);
  }, [jobs]);

  // Real metrics derived strictly from genuine completed audits
  const stats = useMemo(() => {
    if (scoredAudits.length === 0) return null;
    const scores = scoredAudits.map((a) => a.score);
    const latestScore = scores[scores.length - 1];
    const avgScore = Math.round((scores.reduce((sum, s) => sum + s, 0) / scores.length) * 10) / 10;
    const highestScore = Math.max(...scores);
    const lowestScore = Math.min(...scores);
    return {
      latestScore,
      avgScore,
      highestScore,
      lowestScore,
      count: scoredAudits.length,
    };
  }, [scoredAudits]);

  // Chart layout calculations
  const width = 640;
  const height = 180;
  const paddingLeft = 32;
  const paddingRight = 24;
  const paddingTop = 20;
  const paddingBottom = 26;

  const chartW = width - paddingLeft - paddingRight;
  const chartH = height - paddingTop - paddingBottom;

  const yMin = 0;
  const yMax = 10;

  const coordinates = scoredAudits.map((audit, index) => {
    const x = scoredAudits.length === 1
      ? paddingLeft + chartW / 2
      : paddingLeft + (index / (scoredAudits.length - 1)) * chartW;
    const y = paddingTop + chartH - ((audit.score - yMin) / (yMax - yMin)) * chartH;
    return { x, y, audit, index };
  });

  // Construct SVG path if 2+ data points
  const pathD = coordinates.length >= 2
    ? coordinates.reduce((acc, curr, idx, arr) => {
        if (idx === 0) return `M ${curr.x} ${curr.y}`;
        const prev = arr[idx - 1];
        const cpX = (prev.x + curr.x) / 2;
        return `${acc} C ${cpX} ${prev.y}, ${cpX} ${curr.y}, ${curr.x} ${curr.y}`;
      }, '')
    : '';

  const areaD = pathD && coordinates.length >= 2
    ? `${pathD} L ${coordinates[coordinates.length - 1].x} ${paddingTop + chartH} L ${coordinates[0].x} ${paddingTop + chartH} Z`
    : '';

  const activePoint = hoveredIndex !== null && coordinates[hoveredIndex]
    ? coordinates[hoveredIndex]
    : null;

  return (
    <div className={`fc-panel fc-trend-panel ${className}`}>
      <div className="fc-panel-header">
        <div>
          <h2 className="fc-panel-title">Audit Score History</h2>
          <p className="fc-panel-subtitle">
            Deterministic security scores (0–10) across completed repository audits
          </p>
        </div>

        {stats && (
          <div className="fc-chart-header-stats">
            <span className="fc-stat-pill">
              <span className="fc-stat-pill-label">Latest:</span>
              <span className="fc-stat-pill-val">{stats.latestScore.toFixed(1)}/10</span>
            </span>
            <span className="fc-stat-pill">
              <span className="fc-stat-pill-label">Average:</span>
              <span className="fc-stat-pill-val">{stats.avgScore.toFixed(1)}/10</span>
            </span>
          </div>
        )}
      </div>

      <div className="fc-panel-body">
        {scoredAudits.length >= 2 ? (
          <div className="fc-svg-chart-container">
            <svg
              viewBox={`0 0 ${width} ${height}`}
              className="fc-svg-chart"
              onMouseLeave={() => setHoveredIndex(null)}
              role="img"
              aria-label="Security score history graph"
            >
              <defs>
                <linearGradient id="restrainedAreaGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#f97316" stopOpacity="0.16" />
                  <stop offset="100%" stopColor="#f97316" stopOpacity="0.0" />
                </linearGradient>
              </defs>

              {/* Horizontal score grid lines */}
              {[10, 8, 6, 4, 2].map((gridVal) => {
                const gridY = paddingTop + chartH - ((gridVal - yMin) / (yMax - yMin)) * chartH;
                return (
                  <g key={gridVal}>
                    <line
                      x1={paddingLeft}
                      y1={gridY}
                      x2={width - paddingRight}
                      y2={gridY}
                      className="fc-chart-gridline"
                    />
                    <text
                      x={paddingLeft - 8}
                      y={gridY + 3.5}
                      textAnchor="end"
                      className="fc-chart-gridtext"
                    >
                      {gridVal}
                    </text>
                  </g>
                );
              })}

              {/* Area fill */}
              {areaD && <path d={areaD} fill="url(#restrainedAreaGrad)" />}

              {/* Subtle line stroke */}
              {pathD && (
                <path
                  d={pathD}
                  fill="none"
                  stroke="#f97316"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              )}

              {/* Data points */}
              {coordinates.map((item, idx) => {
                const isHovered = hoveredIndex === idx;
                return (
                  <circle
                    key={item.audit.id}
                    cx={item.x}
                    cy={item.y}
                    r={isHovered ? 5 : 3.5}
                    fill={isHovered ? '#ffffff' : '#f97316'}
                    stroke={isHovered ? '#f97316' : '#141418'}
                    strokeWidth="2"
                    style={{ transition: 'r 0.15s ease', cursor: 'pointer' }}
                  />
                );
              })}

              {/* Active cursor line */}
              {activePoint && (
                <line
                  x1={activePoint.x}
                  y1={paddingTop}
                  x2={activePoint.x}
                  y2={paddingTop + chartH}
                  className="fc-chart-crosshair"
                />
              )}

              {/* Invisible mouse hover trigger hitboxes */}
              {coordinates.map((item, idx) => {
                const colW = chartW / coordinates.length;
                return (
                  <rect
                    key={idx}
                    x={item.x - colW / 2}
                    y={paddingTop}
                    width={colW}
                    height={chartH}
                    fill="transparent"
                    style={{ cursor: 'pointer' }}
                    onMouseEnter={() => setHoveredIndex(idx)}
                    onClick={() => onSelectAudit?.(item.audit.id)}
                  />
                );
              })}
            </svg>

            {/* Tooltip */}
            {activePoint && (
              <div
                className="fc-chart-tooltip"
                style={{
                  left: `${(activePoint.x / width) * 100}%`,
                  top: `${Math.max(10, (activePoint.y / height) * 100 - 30)}%`,
                }}
              >
                <div className="fc-tooltip-title">{activePoint.audit.repoName}</div>
                <div className="fc-tooltip-score-line">
                  <span className="fc-tooltip-score-val">{activePoint.audit.score.toFixed(1)}</span>
                  <span className="fc-tooltip-score-scale">/ 10</span>
                </div>
                <div className="fc-tooltip-meta">
                  <Calendar size={11} className="inline mr-1 text-zinc-400" />
                  <span>{activePoint.audit.displayDate}</span>
                </div>
                {activePoint.audit.commitSha && (
                  <div className="fc-tooltip-sha">
                    <GitCommit size={10} className="inline mr-1 text-zinc-500" />
                    <span>{activePoint.audit.commitSha.slice(0, 7)}</span>
                  </div>
                )}
              </div>
            )}
          </div>
        ) : scoredAudits.length === 1 ? (
          <div className="fc-chart-single-audit">
            <div className="fc-single-audit-badge">
              <ShieldCheck size={20} className="text-orange-400" />
            </div>
            <div>
              <h4 className="fc-single-audit-title">
                {scoredAudits[0].repoName} — Score: {scoredAudits[0].score.toFixed(1)} / 10
              </h4>
              <p className="fc-single-audit-desc">
                First scored audit completed {timeAgo(scoredAudits[0].dateStr) || 'recently'}.
                A comparative score trajectory will appear once additional audits are completed.
              </p>
            </div>
          </div>
        ) : (
          <div className="fc-chart-empty">
            <p className="fc-chart-empty-text">
              No scored audits recorded. As repository audits complete, deterministic security scores (0–10)
              are plotted here to track scores over time.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

export default SecurityTrendChart;
