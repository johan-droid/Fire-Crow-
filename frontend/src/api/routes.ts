// Pure endpoint-path builders: the single source of truth for the backend
// route table (backend/src/app.rs nests + routes_*.rs). All paths are relative
// to the versioned base (/api/v1); the base itself lives in client.ts.
// Unit-tested in tests/routes.test.ts — no fetch, no staging needed.
const enc = encodeURIComponent;

export type ReportFormatParam = 'markdown' | 'json' | 'html';

export const auditPaths = {
  submit: () => '/audit/submit',
  jobs: () => '/audit/jobs',
  job: (jobId: string) => `/audit/job/${enc(jobId)}`,
  retry: (jobId: string) => `/audit/job/${enc(jobId)}/retry`,
  phases: (jobId: string) => `/audit/job/${enc(jobId)}/phases`,
  executions: (jobId: string) => `/audit/job/${enc(jobId)}/executions`,
  latestReport: (jobId: string, format: ReportFormatParam) =>
    `/audit/job/${enc(jobId)}/report?format=${format}`,
  executionReport: (jobId: string, executionId: string, format: ReportFormatParam) =>
    `/audit/job/${enc(jobId)}/execution/${enc(executionId)}/report?format=${format}`,
  narrative: (jobId: string, executionId: string) =>
    `/audit/job/${enc(jobId)}/execution/${enc(executionId)}/narrative`,
  email: (jobId: string, executionId: string) =>
    `/audit/job/${enc(jobId)}/execution/${enc(executionId)}/email`,
  telegram: (jobId: string, executionId: string) =>
    `/audit/job/${enc(jobId)}/execution/${enc(executionId)}/telegram`,
};

export const authPaths = {
  login: () => '/auth/login',
  register: () => '/auth/register',
  logout: () => '/auth/logout',
  me: () => '/auth/me',
  session: () => '/auth/session',
  refresh: () => '/auth/refresh',
  exchange: () => '/auth/exchange',
};

export const userPaths = {
  repos: () => '/user/repos',
};

export const dashboardPaths = {
  summary: () => '/dashboard/summary',
  jobsLite: () => '/dashboard/jobs-lite',
};

export const ssePaths = {
  job: (jobId: string) => `/sse/job/${enc(jobId)}`,
};
