import type { JobResponse, GithubRepo } from '../api/types';
import type { DeepHealth } from '../dash';
import {
  ArrowRight,
  Shield,
  CheckCircle2,
  Database,
  HardDrive,
  ChevronRight,
  Server,
} from 'lucide-react';

export interface ActionSidebarProps {
  jobs: JobResponse[];
  userRepos: GithubRepo[];
  reposStatus: 'idle' | 'loading' | 'ready' | 'not_connected' | 'github_error' | 'network_error';
  deepHealth: DeepHealth | null;
  onStartAudit: () => void;
  onNavigate: (route: string) => void;
  onViewJobDetail?: (jobId: string) => void;
  className?: string;
}

export function ActionSidebar({
  jobs,
  userRepos,
  reposStatus,
  deepHealth,
  onStartAudit,
  onNavigate,
  onViewJobDetail,
  className = '',
}: ActionSidebarProps) {
  const completedJobs = jobs.filter((j) => j.status === 'completed');
  const reportsReady = completedJobs.filter((j) => j.report_pdf_url).length;

  // Real backend health evaluation strictly matching deepHealth contract
  const dbOk = deepHealth?.database === 'ok' || deepHealth?.database === 'connected';
  const lsOk = deepHealth?.local_storage == null || deepHealth?.local_storage === 'ok';
  const breakersTripped = Object.values(deepHealth?.circuit_breakers || {}).some(
    (cb) => cb.state !== 'closed'
  );
  const isHealthy = Boolean(deepHealth && dbOk && lsOk && !breakersTripped);

  const repoStatusText = (() => {
    switch (reposStatus) {
      case 'loading': return 'Syncing GitHub repositories…';
      case 'ready': return `${userRepos.length} ${userRepos.length === 1 ? 'repository' : 'repositories'} available`;
      case 'not_connected': return 'GitHub not connected — public repository URLs supported';
      case 'github_error': return 'Repository sync error — public URLs supported';
      case 'network_error': return 'Service unreachable — public URLs supported';
      default: return 'Paste repository URL or select connected repo';
    }
  })();

  // Newest completed audit by creation time — the list order is not a
  // contract, so pick explicitly instead of assuming index 0 is latest.
  const latestCompletedJob = completedJobs.length > 0
    ? [...completedJobs].sort((a, b) => (a.created_at < b.created_at ? 1 : -1))[0]
    : null;

  return (
    <aside className={`fc-action-sidebar ${className}`}>
      {/* 1. Audit Workflow Guide */}
      <section className="fc-panel fc-sidebar-panel">
        <div className="fc-panel-header">
          <div className="flex items-center gap-2">
            <Shield size={14} className="text-orange-500" />
            <h3 className="fc-panel-title">Audit Workflow</h3>
          </div>
          <span className="fc-workflow-step-tag">
            {completedJobs.length > 0 ? 'Step 3 of 3' : userRepos.length > 0 ? 'Step 2 of 3' : 'Step 1 of 3'}
          </span>
        </div>

        <div className="fc-panel-body">
          <ol className="fc-workflow-steps">
            {/* Step 1 */}
            <li className={`fc-workflow-step ${userRepos.length > 0 ? 'is-completed' : 'is-active'}`}>
              <div className="fc-step-indicator">
                <span className="fc-step-dot">
                  {userRepos.length > 0 ? <CheckCircle2 size={12} className="text-emerald-400" /> : '1'}
                </span>
                <span className="fc-step-track" />
              </div>
              <div className="fc-step-body">
                <h4 className="fc-step-heading">Select Repository</h4>
                <p className="fc-step-copy">{repoStatusText}</p>
                <button
                  type="button"
                  onClick={onStartAudit}
                  className="fc-step-trigger"
                >
                  <span>New audit</span>
                  <ArrowRight size={11} />
                </button>
              </div>
            </li>

            {/* Step 2 */}
            <li className={`fc-workflow-step ${completedJobs.length > 0 ? 'is-completed' : ''}`}>
              <div className="fc-step-indicator">
                <span className="fc-step-dot">
                  {completedJobs.length > 0 ? <CheckCircle2 size={12} className="text-emerald-400" /> : '2'}
                </span>
                <span className="fc-step-track" />
              </div>
              <div className="fc-step-body">
                <h4 className="fc-step-heading">Review Findings</h4>
                <p className="fc-step-copy">
                  {completedJobs.length > 0
                    ? `${completedJobs.length} completed ${completedJobs.length === 1 ? 'audit' : 'audits'} with deterministic findings`
                    : 'Confirmed findings include severity, evidence, and remediation guidance'}
                </p>
                {latestCompletedJob && onViewJobDetail && (
                  <button
                    type="button"
                    onClick={() => onViewJobDetail(latestCompletedJob.id)}
                    className="fc-step-trigger"
                  >
                    <span>Inspect latest results</span>
                    <ArrowRight size={11} />
                  </button>
                )}
              </div>
            </li>

            {/* Step 3 */}
            <li className={`fc-workflow-step ${reportsReady > 0 ? 'is-completed' : ''}`}>
              <div className="fc-step-indicator">
                <span className="fc-step-dot">
                  {reportsReady > 0 ? <CheckCircle2 size={12} className="text-emerald-400" /> : '3'}
                </span>
              </div>
              <div className="fc-step-body">
                <h4 className="fc-step-heading">Access Reports</h4>
                <p className="fc-step-copy">
                  {reportsReady} of {completedJobs.length} completed audits have downloadable reports
                </p>
                <button
                  type="button"
                  onClick={() => onNavigate('/console/jobs')}
                  className="fc-step-trigger"
                >
                  <span>View all reports</span>
                  <ArrowRight size={11} />
                </button>
              </div>
            </li>
          </ol>
        </div>
      </section>

      {/* 2. Genuine Service Telemetry (Strictly from deepHealth) */}
      <section className="fc-panel fc-sidebar-panel">
        <div className="fc-panel-header">
          <div className="flex items-center gap-2">
            <Server size={14} className="text-zinc-400" />
            <h3 className="fc-panel-title">Service Telemetry</h3>
          </div>
          {deepHealth ? (
            <span className={`fc-status-pill ${isHealthy ? 'is-ok' : 'is-degraded'}`}>
              <span className="fc-status-dot" />
              {isHealthy ? 'Operational' : 'Degraded'}
            </span>
          ) : (
            <span className="fc-status-pill is-probe">
              <span className="fc-status-dot" />
              Probing
            </span>
          )}
        </div>

        <div className="fc-panel-body">
          <div className="fc-telemetry-list">
            <div className="fc-telemetry-row">
              <div className="flex items-center gap-2">
                <Database size={12} className="text-zinc-500" />
                <span className="fc-telemetry-label">Audit Database</span>
              </div>
              <span className="fc-telemetry-val">
                {deepHealth?.database ? (deepHealth.database === 'ok' || deepHealth.database === 'connected' ? 'Connected' : deepHealth.database) : '—'}
              </span>
            </div>

            <div className="fc-telemetry-row">
              <div className="flex items-center gap-2">
                <HardDrive size={12} className="text-zinc-500" />
                <span className="fc-telemetry-label">Session Store</span>
              </div>
              <span className="fc-telemetry-val">
                {deepHealth?.local_storage ? (deepHealth.local_storage === 'ok' ? 'Connected' : deepHealth.local_storage) : '—'}
              </span>
            </div>
          </div>

          <div className="fc-telemetry-footer">
            <button
              type="button"
              onClick={() => onNavigate('/console/diagnostics')}
              className="fc-telemetry-link"
            >
              <span>Service diagnostics</span>
              <ChevronRight size={12} />
            </button>
          </div>
        </div>
      </section>
    </aside>
  );
}

export default ActionSidebar;
