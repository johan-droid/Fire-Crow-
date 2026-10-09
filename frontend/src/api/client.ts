// Thin typed client for the existing Axum API. No business logic, no score or
// coverage recomputation: the backend's deterministic report is the source of
// truth. Every historical action takes an explicit execution_id.
import { ApiError, DELIVERY_TIMEOUT_MS, deliveryTimeoutNote, toApiError, withTimeout } from './errors.js';
import {
  auditPaths,
  authPaths,
  dashboardPaths,
  ssePaths,
  userPaths,
} from './routes.js';
import type {
  AuthMeResponse,
  CanonicalAuditReport,
  DeliveryResponse,
  ExchangeResponse,
  ExecutionHistoryEntry,
  FindingResponse,
  GithubReposResponse,
  JobDetailResponse,
  JobResponse,
  JobsLiteResponse,
  NarrativeResponse,
  PhaseLedgerEntry,
  StatusResponse,
  SubmitJobRequest,
} from './types.js';

export type ReportFormat = 'markdown' | 'json' | 'html';

export function getApiBase(): string {
  const viteUrl = (import.meta.env.VITE_API_URL as string | undefined)?.trim();
  if (viteUrl) return viteUrl.replace(/\/$/, '');
  if (
    typeof window !== 'undefined' &&
    (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
  ) {
    return 'http://localhost:8000/api/v1';
  }
  return '/api/v1';
}

async function requestJson<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`${getApiBase()}${path}`, {
    credentials: 'include',
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init.headers ?? {}) },
  });
  if (!res.ok) throw await toApiError(res);
  const text = await res.text();
  if (!text.trim()) {
    // Backend always returns JSON on success; empty is a contract violation.
    throw new ApiError(res.status, 'malformed', 'Empty response from server.', false);
  }
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new ApiError(res.status, 'malformed', 'Server returned malformed JSON.', false);
  }
}

/** Non-JSON downloads (markdown/html reports): resolved only on 2xx + body. */
async function requestText(path: string, accept: string): Promise<string> {
  const res = await fetch(`${getApiBase()}${path}`, {
    credentials: 'include',
    headers: { Accept: accept },
  });
  if (!res.ok) throw await toApiError(res);
  return res.text();
}

export const api = {
  // --- auth / user ---
  login: (username: string, password: string) =>
    requestJson<unknown>(authPaths.login(), {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),
  register: (username: string, email: string, password: string) =>
    requestJson<unknown>(authPaths.register(), {
      method: 'POST',
      body: JSON.stringify({ username, email, password }),
    }),
  logout: () => requestJson<unknown>(authPaths.logout(), { method: 'POST' }),
  me: () => requestJson<AuthMeResponse>(authPaths.me()),
  exchangeCode: (code: string) =>
    requestJson<ExchangeResponse>(authPaths.exchange(), {
      method: 'POST',
      body: JSON.stringify({ code }),
    }),
  session: () => requestJson<unknown>(authPaths.session()),
  refresh: () => requestJson<unknown>(authPaths.refresh(), { method: 'POST' }),
  repos: () => requestJson<GithubReposResponse>(userPaths.repos()),

  // --- jobs ---
  submitJob: (req: SubmitJobRequest) =>
    requestJson<JobResponse>(auditPaths.submit(), {
      method: 'POST',
      body: JSON.stringify(req),
    }),
  listJobs: () => requestJson<JobResponse[]>(auditPaths.jobs()),
  jobsLite: () => requestJson<JobsLiteResponse>(dashboardPaths.jobsLite()),
  jobDetail: (jobId: string, signal?: AbortSignal) =>
    requestJson<JobDetailResponse>(auditPaths.job(jobId), { signal }),
  cancelJob: (jobId: string) =>
    requestJson<StatusResponse>(auditPaths.job(jobId), { method: 'DELETE' }),
  retryJob: (jobId: string) =>
    requestJson<StatusResponse>(auditPaths.retry(jobId), { method: 'POST' }),
  jobPhases: (jobId: string, signal?: AbortSignal) =>
    requestJson<PhaseLedgerEntry[]>(auditPaths.phases(jobId), { signal }),
  jobExecutions: (jobId: string, signal?: AbortSignal) =>
    requestJson<ExecutionHistoryEntry[]>(auditPaths.executions(jobId), { signal }),
  jobFindings: async (jobId: string, signal?: AbortSignal): Promise<FindingResponse[]> => {
    const detail = await api.jobDetail(jobId, signal);
    return detail.findings;
  },

  // --- execution-scoped report / narrative / delivery ---
  executionReportJson: (jobId: string, executionId: string) =>
    requestJson<CanonicalAuditReport>(
      auditPaths.executionReport(jobId, executionId, 'json'),
    ),
  executionReportText: (jobId: string, executionId: string, format: ReportFormat) =>
    requestText(
      auditPaths.executionReport(jobId, executionId, format),
      format === 'html' ? 'text/html' : 'text/markdown',
    ),
  latestReportText: (jobId: string, format: ReportFormat) =>
    requestText(
      auditPaths.latestReport(jobId, format),
      format === 'json' ? 'application/json' : format === 'html' ? 'text/html' : 'text/markdown',
    ),
  getNarrative: (jobId: string, executionId: string) =>
    requestJson<NarrativeResponse>(
      auditPaths.narrative(jobId, executionId),
    ),
  generateNarrative: (jobId: string, executionId: string, timeoutMs = 120_000) =>
    withTimeout(
      (signal) =>
        requestJson<NarrativeResponse>(
          auditPaths.narrative(jobId, executionId),
          { method: 'POST', signal },
        ),
      timeoutMs,
      'Narrative generation',
    ),
  emailReport: (jobId: string, executionId: string, timeoutMs = DELIVERY_TIMEOUT_MS) =>
    withTimeout(
      (signal) =>
        requestJson<DeliveryResponse>(
          auditPaths.email(jobId, executionId),
          { method: 'POST', body: JSON.stringify({}), signal },
        ),
      timeoutMs,
      'Email delivery',
      deliveryTimeoutNote('email'),
    ),
  telegramReport: (jobId: string, executionId: string, timeoutMs = DELIVERY_TIMEOUT_MS) =>
    withTimeout(
      (signal) =>
        requestJson<DeliveryResponse>(
          auditPaths.telegram(jobId, executionId),
          { method: 'POST', signal },
        ),
      timeoutMs,
      'Telegram delivery',
      deliveryTimeoutNote('telegram'),
    ),

  sseJobUrl: (jobId: string) => `${getApiBase()}${ssePaths.job(jobId)}`,
};
