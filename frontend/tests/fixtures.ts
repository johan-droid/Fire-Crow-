// Backend-shaped fixtures. Mirror backend/src/schemas/* Serialize output;
// if the backend adds a required field, the typed fixture fails compilation,
// which is the point: the contract lock must break loudly, not silently.
import type {
  CanonicalAuditReport,
  ExecutionHistoryEntry,
  JobResponse,
  NarrativeResponse,
} from '../src/api/types.js';

export const jobFixture: JobResponse = {
  id: 'job-1',
  user_id: 'user-1',
  repo_url: 'https://github.com/org/repo',
  repo_branch: 'main',
  status: 'completed',
  created_at: '2026-10-01T00:00:00Z',
  finished_at: '2026-10-01T00:05:00Z',
  cancel_requested: false,
  cancel_requested_at: null,
  report_pdf_url: null,
  error_message: null,
  security_score: 8.5,
  email_delivered: false,
  github_issues_raised: false,
  github_pr_created: false,
  requested_commit_sha: null,
  commit_sha: 'a'.repeat(40),
};

export const executionsFixture: ExecutionHistoryEntry[] = [
  {
    execution_id: 'exec-1',
    attempt_number: 1,
    status: 'failed',
    commit_sha: 'a'.repeat(40),
    started_at: '2026-10-01T00:00:00Z',
    finished_at: '2026-10-01T00:01:00Z',
    finding_count: 0,
    has_report: false,
    has_narrative: false,
    deliveries: [],
  },
  {
    execution_id: 'exec-2',
    attempt_number: 2,
    status: 'completed',
    commit_sha: 'a'.repeat(40),
    started_at: '2026-10-01T00:02:00Z',
    finished_at: '2026-10-01T00:05:00Z',
    finding_count: 2,
    has_report: true,
    has_narrative: true,
    deliveries: [{ channel: 'email', status: 'sent', failure_class: null }],
  },
];

export const reportFixture: CanonicalAuditReport = {
  report_schema_version: 1,
  identity: {
    audit_id: 'audit-1',
    execution_id: 'exec-2',
    attempt_number: 2,
    repository_url: 'https://github.com/org/repo',
    repo_branch: 'main',
    repo_owner: 'org',
    repo_name: 'repo',
    snapshot_commit: 'a'.repeat(40),
    snapshot_file_count: 10,
    snapshot_total_size: 1024,
    canonical_schema_version: 1,
    report_schema_version: 1,
  },
  coverage: {
    state: 'SUCCESS_FINDINGS',
    complete: true,
    limitations: [],
    successful_scanners: ['gitleaks'],
    unsuccessful_scanners: {},
    scanner_runs: [],
  },
  summary: {
    headline: '2 finding(s) reported across 1 scanner(s).',
    finding_count: 2,
    findings_by_severity: { high: 1, unknown: 1 },
    findings_by_scanner: { gitleaks: 2 },
    invalid_finding_count: 0,
    duplicate_group_count: 0,
    security_score: null,
  },
  findings: [],
  correlations: [],
  invalid_findings: [],
  limitations: [],
  disclaimers: [],
};

export const narrativeEnvelopeFixture: NarrativeResponse = {
  execution_id: 'exec-2',
  attempt_number: 2,
  narrative_schema_version: 1,
  narrative: {
    narrative_schema_version: 1,
    executive_summary: 'Two findings were reported.',
    finding_explanations: [],
    remediation_guidance: [
      { finding_id: 'f-1', guidance: 'Rotate the exposed secret.', verified: false },
    ],
    limitations: [],
  },
};
