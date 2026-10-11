import { useState, useMemo } from 'react';
import type { JobResponse } from '../api/types';
import {
  Table as TableIcon,
  List as ListIcon,
  Search,
  Plus,
  GitBranch,
  GitCommit,
  ExternalLink,
  Download,
  AlertTriangle,
  Clock,
  Shield,
} from 'lucide-react';
import {
  ScoreRing,
  StatusPill,
  timeAgo,
  repoLabel,
} from '../dash';

export interface AuditTableProps {
  jobs: JobResponse[];
  activeJobId?: string | null;
  onSelectJob: (jobId: string) => void;
  onStartAudit: (preset?: string) => void;
  onDownloadReport?: (jobId: string) => void;
  className?: string;
}

export function AuditTable({
  jobs,
  activeJobId,
  onSelectJob,
  onStartAudit,
  onDownloadReport,
  className = '',
}: AuditTableProps) {
  const [viewMode, setViewMode] = useState<'table' | 'list'>('table');
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'completed' | 'running' | 'failed'>('all');

  // Filtered jobs list based on real data
  const filteredJobs = useMemo(() => {
    return jobs.filter((job) => {
      // Query filter
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const repo = repoLabel(job.repo_url).toLowerCase();
        const branch = (job.repo_branch || '').toLowerCase();
        const sha = (job.commit_sha || job.requested_commit_sha || '').toLowerCase();
        if (!repo.includes(q) && !branch.includes(q) && !sha.includes(q)) {
          return false;
        }
      }

      // Status filter
      if (statusFilter === 'completed') return job.status === 'completed';
      if (statusFilter === 'running') return job.status === 'running' || job.status === 'queued';
      if (statusFilter === 'failed') return job.status === 'failed' || job.status === 'cancelled';

      return true;
    });
  }, [jobs, searchQuery, statusFilter]);

  return (
    <div className={`fc-panel fc-audits-panel ${className}`}>
      {/* Header bar with controls */}
      <div className="fc-panel-header">
        <div>
          <h2 className="fc-panel-title">Recent Audits</h2>
          <p className="fc-panel-subtitle">
            Repository audits and their reports
          </p>
        </div>

        <div className="fc-audits-header-actions">
          {/* Search input */}
          {jobs.length > 0 && (
            <div className="fc-search-wrap">
              <Search size={14} className="fc-search-icon" aria-hidden="true" />
              <input
                type="text"
                placeholder="Filter audits…"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="fc-search-input"
                aria-label="Filter audits by repository, branch, or commit"
              />
            </div>
          )}

          {/* View switcher: Table vs List */}
          {jobs.length > 0 && (
            <div className="fc-view-switcher" role="group" aria-label="Audit list layout">
              <button
                type="button"
                className={`fc-view-btn ${viewMode === 'table' ? 'is-active' : ''}`}
                onClick={() => setViewMode('table')}
                title="Table view"
                aria-label="Table view"
              >
                <TableIcon size={14} />
              </button>
              <button
                type="button"
                className={`fc-view-btn ${viewMode === 'list' ? 'is-active' : ''}`}
                onClick={() => setViewMode('list')}
                title="List view"
                aria-label="List view"
              >
                <ListIcon size={14} />
              </button>
            </div>
          )}

          {/* Start Audit CTA */}
          <button
            type="button"
            onClick={() => onStartAudit()}
            className="fc-btn-primary fc-btn-sm"
          >
            <Plus size={14} />
            <span>New audit</span>
          </button>
        </div>
      </div>

      {/* Filter tab bar */}
      {jobs.length > 0 && (
        <div className="fc-filter-tabs-bar" role="tablist" aria-label="Filter by audit status">
          {(
            [
              { id: 'all', label: 'All', count: jobs.length },
              { id: 'completed', label: 'Completed', count: jobs.filter((j) => j.status === 'completed').length },
              { id: 'running', label: 'Running', count: jobs.filter((j) => j.status === 'running' || j.status === 'queued').length },
              { id: 'failed', label: 'Needs attention', count: jobs.filter((j) => j.status === 'failed' || j.status === 'cancelled').length },
            ] as const
          ).map((tab) => (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={statusFilter === tab.id}
              className={`fc-filter-tab ${statusFilter === tab.id ? 'is-active' : ''}`}
              onClick={() => setStatusFilter(tab.id)}
            >
              <span>{tab.label}</span>
              <span className="fc-filter-tab-count">{tab.count}</span>
            </button>
          ))}
        </div>
      )}

      {/* Body: Empty State OR Table View OR List View */}
      {filteredJobs.length === 0 ? (
        <div className="fc-empty-state">
          <div className="fc-empty-icon-wrap" aria-hidden="true">
            <Shield size={24} className="text-zinc-500" />
          </div>
          <h3 className="fc-empty-title">
            {jobs.length === 0 ? 'No repository audits recorded' : 'No matching audits found'}
          </h3>
          <p className="fc-empty-desc">
            {jobs.length === 0
              ? 'Submit a repository to run a security audit, then review its findings and report.'
              : 'Try clearing your search query or choosing another status filter.'}
          </p>

          {jobs.length === 0 ? (
            <button
              type="button"
              onClick={() => onStartAudit()}
              className="fc-btn-primary"
            >
              <Plus size={14} />
              <span>Start an audit</span>
            </button>
          ) : (
            <button
              type="button"
              onClick={() => {
                setSearchQuery('');
                setStatusFilter('all');
              }}
              className="fc-btn-secondary fc-btn-sm"
            >
              Clear filters
            </button>
          )}
        </div>
      ) : viewMode === 'table' ? (
        /* TABLE VIEW */
        <div className="fc-table-responsive-wrap">
          <table className="fc-table">
            <thead>
              <tr>
                <th scope="col" className="fc-th-repo">Repository</th>
                <th scope="col" className="fc-th-branch">Branch & Commit</th>
                <th scope="col" className="fc-th-score">Security Score</th>
                <th scope="col" className="fc-th-status">Status</th>
                <th scope="col" className="fc-th-date">Time</th>
                <th scope="col" className="fc-th-actions text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredJobs.map((job) => {
                const sha = job.commit_sha || job.requested_commit_sha;
                const isActive = activeJobId === job.id;
                const failed = job.status === 'failed' || job.status === 'cancelled';

                return (
                  <tr
                    key={job.id}
                    className={`fc-table-row ${isActive ? 'is-selected' : ''}`}
                    onClick={() => onSelectJob(job.id)}
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        onSelectJob(job.id);
                      }
                    }}
                    aria-label={`Inspect audit of ${repoLabel(job.repo_url)}`}
                  >
                    {/* Repository */}
                    <td className="fc-td-repo">
                      <div className="fc-repo-cell">
                        <span className="fc-repo-name">{repoLabel(job.repo_url)}</span>
                        {failed && job.error_message && (
                          <span className="fc-repo-error-hint" title={job.error_message}>
                            <AlertTriangle size={11} className="inline mr-1 text-red-400" />
                            {job.error_message.slice(0, 48)}…
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Branch & Commit */}
                    <td className="fc-td-branch">
                      <div className="fc-branch-cell">
                        <span className="fc-branch-tag">
                          <GitBranch size={11} className="mr-1 text-zinc-400" />
                          {job.repo_branch || 'main'}
                        </span>
                        {sha && (
                          <span className="fc-sha-tag font-mono" title={`Commit ${sha}`}>
                            <GitCommit size={10} className="mr-0.5 text-zinc-500" />
                            {sha.slice(0, 7)}
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Security Score */}
                    <td className="fc-td-score">
                      <div className="fc-score-cell">
                        {job.security_score != null ? (
                          <ScoreRing score={job.security_score} size={30} />
                        ) : (
                          <span className="fc-score-null">—</span>
                        )}
                      </div>
                    </td>

                    {/* Status */}
                    <td className="fc-td-status">
                      <StatusPill status={job.status} />
                    </td>

                    {/* Run Time */}
                    <td className="fc-td-date">
                      <div className="fc-date-cell">
                        <Clock size={11} className="text-zinc-500 mr-1" />
                        <span>{timeAgo(job.created_at) || 'just now'}</span>
                      </div>
                    </td>

                    {/* Actions */}
                    <td className="fc-td-actions text-right">
                      <div className="fc-actions-group" onClick={(e) => e.stopPropagation()}>
                        <button
                          type="button"
                          onClick={() => onSelectJob(job.id)}
                          className="fc-btn-action"
                          title="Inspect findings and execution history"
                        >
                          <span>Inspect</span>
                          <ExternalLink size={11} />
                        </button>
                        {job.status === 'completed' && job.report_pdf_url && onDownloadReport && (
                          <button
                            type="button"
                            onClick={() => onDownloadReport(job.id)}
                            className="fc-btn-action-icon"
                            title="Download report"
                            aria-label={`Download report for ${repoLabel(job.repo_url)}`}
                          >
                            <Download size={13} />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        /* LIST VIEW */
        <div className="fc-card-list">
          {filteredJobs.map((job) => {
            const sha = job.commit_sha || job.requested_commit_sha;
            const isActive = activeJobId === job.id;
            const failed = job.status === 'failed' || job.status === 'cancelled';

            return (
              <div
                key={job.id}
                className={`fc-audit-list-item ${isActive ? 'is-active' : ''}`}
                onClick={() => onSelectJob(job.id)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    onSelectJob(job.id);
                  }
                }}
                role="button"
                tabIndex={0}
              >
                <div className="fc-list-item-left">
                  {job.security_score != null ? (
                    <ScoreRing score={job.security_score} size={36} />
                  ) : (
                    <div className="fc-score-ring-placeholder">—</div>
                  )}
                  <div className="fc-list-item-info">
                    <div className="flex items-center gap-2">
                      <h4 className="fc-list-item-repo">{repoLabel(job.repo_url)}</h4>
                      <StatusPill status={job.status} />
                    </div>
                    <div className="fc-list-item-meta">
                      <span className="fc-meta-branch">
                        <GitBranch size={11} className="inline mr-1 text-zinc-400" />
                        {job.repo_branch}
                      </span>
                      {sha && (
                        <>
                          <span className="fc-meta-sep">·</span>
                          <span className="fc-meta-sha font-mono">
                            <GitCommit size={10} className="inline mr-0.5 text-zinc-500" />
                            {sha.slice(0, 8)}
                          </span>
                        </>
                      )}
                      <span className="fc-meta-sep">·</span>
                      <span className="fc-meta-time">{timeAgo(job.created_at) || 'just now'}</span>
                    </div>
                    {failed && job.error_message && (
                      <p className="fc-list-item-error">
                        <AlertTriangle size={12} className="inline mr-1" />
                        {job.error_message}
                      </p>
                    )}
                  </div>
                </div>

                <div className="fc-list-item-actions" onClick={(e) => e.stopPropagation()}>
                  <button
                    type="button"
                    onClick={() => onSelectJob(job.id)}
                    className="fc-btn-secondary fc-btn-sm"
                  >
                    <span>Inspect</span>
                    <ExternalLink size={11} />
                  </button>
                  {job.status === 'completed' && job.report_pdf_url && onDownloadReport && (
                    <button
                      type="button"
                      onClick={() => onDownloadReport(job.id)}
                      className="fc-btn-action-icon"
                      title="Download report"
                      aria-label={`Download report for ${repoLabel(job.repo_url)}`}
                    >
                      <Download size={13} />
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default AuditTable;
