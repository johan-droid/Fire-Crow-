// Thin typed client for the existing Axum API. No business logic, no score or
// coverage recomputation: the backend's deterministic report is the source of
// truth. Every historical action takes an explicit execution_id.
import { ApiError, DELIVERY_TIMEOUT_MS, deliveryTimeoutNote, fetchWithRetry, looksLikeHtmlDocument, SPA_FALLBACK_MESSAGE, toApiError, withTimeout } from './errors.js';
import { resolveApiBase } from './api-base.js';
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
  LoginResponse,
  NarrativeResponse,
  PhaseLedgerEntry,
  StatusResponse,
  SubmitJobRequest,
} from './types.js';

export type ReportFormat = 'markdown' | 'json' | 'html';

export function getApiBase(): string {
  return resolveApiBase(import.meta.env.VITE_API_URL as string | undefined);
}

const IDEMPOTENT_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

async function requestJson<T>(path: string, init: RequestInit = {}, opts: { timeoutMs?: number } = {}): Promise<T> {
  const method = (init.method ?? 'GET').toUpperCase();
  // Retries only for idempotent methods: a timed-out POST may already have
  // executed server-side, and retrying it could double-submit (see
  // fetchWithRetry). Every attempt is bounded; a cold backend surfaces fast.
  const res = await fetchWithRetry(
    `${getApiBase()}${path}`,
    {
      credentials: 'include',
      ...init,
      headers: { 'Content-Type': 'application/json', ...(init.headers ?? {}) },
    },
    fetch,
    { retry: IDEMPOTENT_METHODS.has(method), timeoutMs: opts.timeoutMs },
  );
  if (!res.ok) throw await toApiError(res);
  const text = await res.text();
  if (!text.trim()) {
    // Backend always returns JSON on success; empty is a contract violation.
    throw new ApiError(res.status, 'malformed', 'Empty response from server.', false);
  }
  if (looksLikeHtmlDocument(text)) {
    // 2xx HTML is never API output — it is the SPA fallback answering for an
    // unconfigured API base. Say so instead of "malformed JSON".
    throw new ApiError(res.status, 'misconfigured', SPA_FALLBACK_MESSAGE, false);
  }
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new ApiError(res.status, 'malformed', 'Server returned malformed JSON.', false);
  }
}

/** Non-JSON downloads (markdown/html reports): resolved only on 2xx + body. */
async function requestText(path: string, accept: string): Promise<string> {
  const res = await fetchWithRetry(
    `${getApiBase()}${path}`,
    {
      credentials: 'include',
      headers: { Accept: accept },
    },
    fetch,
    { retry: true },
  );
  if (!res.ok) throw await toApiError(res);
  const text = await res.text();
  // An HTML report is expected here; any *other* requested format receiving
  // HTML means the SPA fallback answered, not the report endpoint.
  if (!accept.includes('html') && looksLikeHtmlDocument(text)) {
    throw new ApiError(res.status, 'misconfigured', SPA_FALLBACK_MESSAGE, false);
  }
  return text;
}

export const api = {
  // --- auth / user ---
  login: (username: string, password: string) =>
    requestJson<LoginResponse>(authPaths.login(), {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),
  loginMfa: (mfaToken: string, code: string) =>
    requestJson<LoginResponse>(authPaths.loginMfa(), {
      method: 'POST',
      body: JSON.stringify({ mfa_token: mfaToken, code }),
    }),
  register: (username: string, email: string, password: string) =>
    requestJson<unknown>(authPaths.register(), {
      method: 'POST',
      body: JSON.stringify({ username, email, password }),
    }),
  logout: () => requestJson<unknown>(authPaths.logout(), { method: 'POST' }),
  me: () =>
    withTimeout(
      (signal) => requestJson<AuthMeResponse>(authPaths.me(), { signal }),
      4000,
      'Session verification',
      'proceeding as signed out.',
    ),
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

  // --- account lifecycle ---
  deletionRequest: () =>
    requestJson<{
      status: string;
      deadline: string;
      cancel_url: string;
    }>(authPaths.deletionRequest(), { method: 'POST' }),
  deletionCancel: (token: string) =>
    requestJson<{ status: string }>(
      `${authPaths.deletionCancel()}?token=${encodeURIComponent(token)}`,
      { method: 'POST' },
    ),

  sseJobUrl: (jobId: string) => `${getApiBase()}${ssePaths.job(jobId)}`,
};
