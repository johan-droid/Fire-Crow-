// Canonical frontend types mirroring backend Serialize shapes.
// Sources: backend/src/schemas/audit_api.rs, backend/src/models/user.rs
// (JobStatus/Severity), backend/src/models/audit_job.rs (PhaseLedgerModel),
// backend/src/api/routes_audit.rs (list_job_executions JSON), error.rs ({detail}).

export type JobStatus =
  | 'queued'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'partial'
  | 'engine_unavailable'
  | (string & {});

export type Severity =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'info'
  | 'unknown'
  | (string & {});

export type CoverageState =
  | 'SUCCESS_CLEAN'
  | 'SUCCESS_FINDINGS'
  | 'FAILED'
  | 'TIMEOUT'
  | 'CANCELLED'
  | 'NO_FILES_ANALYZED';

export interface SubmitJobRequest {
  repo_url: string;
  repo_branch?: string | null;
  commit_sha?: string | null;
  attestation_accepted?: boolean;
  authorization_scope?: string | null;
  custom_email?: string | null;
}

export interface JobResponse {
  id: string;
  user_id: string;
  repo_url: string;
  repo_branch: string;
  status: JobStatus;
  created_at: string;
  finished_at: string | null;
  cancel_requested: boolean;
  cancel_requested_at: string | null;
  report_pdf_url: string | null;
  error_message: string | null;
  security_score: number | null;
  email_delivered: boolean;
  github_issues_raised: boolean;
  github_pr_created: boolean;
  requested_commit_sha?: string | null;
  commit_sha?: string | null;
}

export interface CanonicalReference {
  reference_type: string;
  url: string;
}

export interface FindingResponse {
  id: string;
  canonical_id: string;
  agent_source: string;
  title: string;
  description: string;
  severity: Severity;
  cvss_score: number | null;
  cvss_vector: string | null;
  evidence: string | null;
  remediation: string | null;
  scanner_name: string | null;
  scanner_mode: string | null;
  scanner_version: string | null;
  parser: string | null;
  rule_id: string | null;
  native_fingerprint: string | null;
  snapshot_commit: string | null;
  file_path: string | null;
  line_number: number | null;
  cwe_id: string | null;
  owasp_category: string | null;
  confidence: string | null;
  references: CanonicalReference[];
}

export interface JobDetailResponse {
  job: JobResponse;
  findings: FindingResponse[];
  execution_id?: string | null;
  attempt_number?: number | null;
  canonical_json?: unknown;
}

export interface PhaseLedgerEntry {  id: string;
  job_id: string;
  execution_id: string | null;
  phase_name: string;
  status: string;
  mode: string;
  duration_sec: number | null;
  error_message: string | null;
  started_at: string;
  ended_at: string | null;
}

export interface ExecutionDelivery {
  channel: string;
  status: string;
  failure_class: string | null;
}
export interface ExecutionHistoryEntry {
  execution_id: string;
  attempt_number: number;
  status: string;
  commit_sha: string | null;
  started_at: string;
  finished_at: string | null;
  finding_count: number;
  has_report: boolean;
  has_narrative: boolean;
  deliveries: ExecutionDelivery[];
}

// Cancel returns {status:"cancellation_requested"}; retry returns {status:"queued"}.
export interface StatusResponse {
  status: string;
}

// Narrative endpoints wrap the narrative in an execution envelope.
export interface NarrativeResponse {
  execution_id: string;
  attempt_number: number;
  narrative_schema_version: number;
  narrative: ReportNarrative;
}

// Delivery reports the persisted outcome: sent | already_sent.
export interface DeliveryResponse {
  status: string;
  execution_id: string;
  recipient?: string | null;
  delivery_status?: unknown;
}

// Canonical finding as presented in a deterministic report (report.rs).
export interface ReportFinding {
  id: string;
  agent_source: string;
  title: string;
  description: string;
  severity: Severity;
  confidence?: string | null;
  cwe_id?: string | null;
  owasp_category?: string | null;
  remediation?: string | null;
  evidence?: string | null;
  evidence_truncated?: boolean;
  location?: { file: string; line: number } | null;
  references?: CanonicalReference[];
}

// Live SSE job payload: {job, phases} on update/done; {error} on error.
export interface SseJobPayload {
  job?: JobResponse;
  phases?: PhaseLedgerEntry[];
  error?: string;
}

// Minimal structural view of CanonicalAuditReport (report.rs). The viewer must
// treat it as data, never recompute scores/coverage from it.
export interface ReportIdentity {
  audit_id: string;
  execution_id: string;
  attempt_number: number;
  repository_url: string;
  repo_branch: string;
  repo_owner: string;
  repo_name: string;
  snapshot_commit: string | null;
  snapshot_file_count: number;
  snapshot_total_size: number;
  canonical_schema_version: number;
  report_schema_version: number;
}

export interface ReportSummary {
  headline: string;
  finding_count: number;
  findings_by_severity: Record<string, number>;
  findings_by_scanner: Record<string, number>;
  invalid_finding_count: number;
  duplicate_group_count: number;
  security_score: number | null;
}

export interface CanonicalAuditReport {
  report_schema_version: number;
  identity: ReportIdentity;
  coverage: {
    state: CoverageState;
    complete: boolean;
    limitations: string[];
    successful_scanners: string[];
    unsuccessful_scanners: Record<string, string>;
    scanner_runs: unknown[];
  };
  summary: ReportSummary;
  findings: ReportFinding[];
  correlations: unknown[];
  invalid_findings: unknown[];
  limitations: string[];
  disclaimers: string[];
}

export interface ReportNarrative {
  narrative_schema_version: number;
  executive_summary: string;
  finding_explanations: Array<{
    finding_id: string;
    severity?: string | null;
    explanation: string;
  }>;
  remediation_guidance: Array<{
    finding_id: string;
    guidance: string;
    verified: boolean;
  }>;
  limitations: string[];
}

export interface JobsLiteResponse {
  jobs: JobResponse[];
  generated_at: string;
}

export interface GithubRepo {
  id?: number | string;
  name?: string | null;
  full_name: string;
  clone_url?: string | null;
  html_url?: string | null;
  private?: boolean | null;
  description?: string | null;
  default_branch?: string | null;
  updated_at?: string | null;
}

// Backend returns HTTP 200 with a status field (routes_user.rs): "ok" carries
// repositories; the other states carry an empty list plus a message.
export interface GithubReposResponse {
  status: 'ok' | 'not_connected' | 'github_error' | 'network_error';
  message?: string | null;
  count?: number | null;
  repositories: GithubRepo[];
}

export interface AuthMeResponse {
  user_id: string;
  username: string;
  email: string | null;
  is_active?: boolean;
  credit_balance?: number;
}

export interface ExchangeResponse {
  access_token?: string | null;
  token_type?: string | null;
  user_id: string;
  username: string;
  email?: string | null;
}
