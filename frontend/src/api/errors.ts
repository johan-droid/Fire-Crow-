// Error envelope parsing. Backend serializes every failure as
// `{ "detail": <string> }` (backend/src/error.rs IntoResponse).
// Unknown coverage/score must stay "unknown", never default to clean/zero.

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  /** True for 429/502/503/504: caller may retry with backoff, never tight-loop. */
  readonly retryable: boolean;

  constructor(status: number, code: string, message: string, retryable: boolean) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.retryable = retryable;
  }
}

function codeFor(status: number): { code: string; retryable: boolean } {
  if (status === 400) return { code: 'bad_request', retryable: false };
  if (status === 401) return { code: 'unauthorized', retryable: false };
  if (status === 403) return { code: 'forbidden', retryable: false };
  if (status === 404) return { code: 'not_found', retryable: false };
  if (status === 409) return { code: 'conflict', retryable: false };
  if (status === 422) return { code: 'validation', retryable: false };
  if (status === 429) return { code: 'rate_limited', retryable: true };
  if (status === 501) return { code: 'not_implemented', retryable: false };
  if (status === 502 || status === 503 || status === 504)
    return { code: 'upstream', retryable: true };
  if (status >= 500) return { code: 'server_error', retryable: false };
  return { code: 'request_failed', retryable: false };
}

function defaultMessage(status: number): string {
  if (status === 400) return 'Invalid request. Check the form values and try again.';
  if (status === 401) return 'Session expired — please sign in again.';
  if (status === 403) return 'You do not have permission to perform this action.';
  if (status === 404) return 'Not found. It may have been removed or belong to another account.';
  if (status === 409) return 'This action conflicts with the current state. Refresh and try the offered next step.';
  if (status === 422) return 'Validation failed. Check the highlighted fields.';
  if (status === 429) return 'Too many requests. Wait a moment, then retry.';
  if (status >= 500) return 'Server error. Your data is unchanged — retry shortly.';
  return `Request failed (HTTP ${status}).`;
}

/** Extract `detail` from a body that may be JSON, text, or empty/malformed. */
export function extractDetail(bodyText: string): string | null {
  const trimmed = bodyText.trim();
  if (!trimmed) return null;
  try {
    const parsed: unknown = JSON.parse(trimmed);
    if (
      typeof parsed === 'object' &&
      parsed !== null &&
      'detail' in parsed &&
      typeof (parsed as Record<string, unknown>).detail === 'string'
    ) {
      return (parsed as Record<string, string>).detail;
    }
    return null;
  } catch {
    return null; // not JSON: caller falls back to status default
  }
}

export async function toApiError(res: Response): Promise<ApiError> {
  const { code, retryable } = codeFor(res.status);
  let message = defaultMessage(res.status);
  try {
    const text = await res.text();
    const detail = extractDetail(text);
    if (detail) message = detail;
    else if (text.trim() && res.status < 500 && !codeFor(res.status).retryable) {
      // Keep short plain-text bodies; never surface raw HTML pages.
      if (text.length < 300 && !/<html/i.test(text)) message = text.trim();
    }
  } catch {
    // Keep the status default.
  }
  return new ApiError(res.status, code, message, retryable);
}

export function isApiError(err: unknown): err is ApiError {
  return err instanceof ApiError;
}

/** Delivery POST budget: the outcome stays unknown after this, never failed. */
export const DELIVERY_TIMEOUT_MS = 60_000;

/** True for statuses the caller may retry with backoff, never tight-loop. */
export function isRetryableStatus(status: number): boolean {
  return status === 429 || status === 502 || status === 503 || status === 504;
}

/** Per-attempt budget: under the server's 30s cutoff so the client speaks first. */
export const REQUEST_TIMEOUT_MS = 25_000;
/** Bounded retries: 3 attempts max, then the error surfaces honestly. */
export const REQUEST_MAX_ATTEMPTS = 3;

function retryDelayMs(attempt: number, res: Response | null, baseDelayMs = 500): number {
  const retryAfter = res?.headers.get('Retry-After');
  if (retryAfter) {
    const secs = Number(retryAfter);
    if (Number.isFinite(secs) && secs >= 0) return Math.min(secs * 1000, 10_000);
  }
  return Math.min(baseDelayMs * 2 ** (attempt - 1), 4000);
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * Single-shot fetch with a per-attempt timeout and bounded retries.
 *
 * Retries only when `retry` is true (idempotent methods — never blindly
 * re-POST: a client timeout cannot cancel server-side work, so retrying a
 * mutation could double-submit). Respects `Retry-After`, links the caller's
 * signal (unmount/sign-out cancels immediately), and throws the last
 * ApiError / network error when attempts run out — never a fabricated result.
 */
export async function fetchWithRetry(
  url: string,
  init: RequestInit,
  fetchImpl: typeof fetch,
  opts: { timeoutMs?: number; maxAttempts?: number; retry?: boolean; baseDelayMs?: number } = {},
): Promise<Response> {
  const timeoutMs = opts.timeoutMs ?? REQUEST_TIMEOUT_MS;
  const maxAttempts = opts.maxAttempts ?? REQUEST_MAX_ATTEMPTS;
  const baseDelayMs = opts.baseDelayMs ?? 500;
  const retry = opts.retry ?? true;
  let lastError: unknown = null;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const ctrl = new AbortController();
    let ownTimeout = false;
    const timer = setTimeout(() => {
      ownTimeout = true;
      ctrl.abort();
    }, timeoutMs);
    const onCallerAbort = () => ctrl.abort();
    init.signal?.addEventListener('abort', onCallerAbort, { once: true });
    try {
      const res = await fetchImpl(url, { ...init, signal: ctrl.signal });
      if (retry && attempt < maxAttempts && isRetryableStatus(res.status)) {
        await sleep(retryDelayMs(attempt, res, baseDelayMs));
        continue;
      }
      return res;
    } catch (err) {
      if (ownTimeout && !init.signal?.aborted) {
        // Our deadline fired (not the caller's cancel): a 408 with the
        // honest blast radius — the server may still have processed it.
        throw new ApiError(
          408,
          'timeout',
          'Request timed out — the outcome is unknown. Retry idempotent reads; do not blindly resubmit.',
          true,
        );
      }
      lastError = err;
      if (!retry || init.signal?.aborted || attempt >= maxAttempts) throw err;
      await sleep(retryDelayMs(attempt, null, baseDelayMs));
    } finally {
      clearTimeout(timer);
      init.signal?.removeEventListener('abort', onCallerAbort);
    }
  }
  throw lastError;
}

/**
 * Timeout copy per channel. States the outcome is unknown and points at the
 * persisted delivery status — never success, never conclusive failure, never
 * a claim the server did not process the request.
 */
export function deliveryTimeoutNote(channel: 'email' | 'telegram'): string {
  const dest = channel === 'email' ? 'account email' : 'configured Telegram chat';
  return `delivery outcome to the ${dest} is unknown — check the attempt history before trying again.`;
}

/**
 * Race `run` against `ms`. On timeout the signal aborts and callers get a
 * 408 ApiError — never a hang, never a fabricated result. The `note` explains
 * the blast radius; callers must never imply the server did not process the
 * request, because a client timeout cannot cancel server-side work.
 */
export async function withTimeout<T>(
  run: (signal: AbortSignal) => Promise<T>,
  ms: number,
  what: string,
  note = 'the deterministic report is unchanged.',
): Promise<T> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await run(ctrl.signal);
  } catch (err) {
    if (ctrl.signal.aborted) {
      throw new ApiError(408, 'timeout', `${what} timed out — ${note}`, true);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * True when a body is an HTML document rather than the JSON the API contract
 * promises. A 2xx HTML body is never legitimate API output: it is the frontend
 * SPA being served in place of the API, i.e. the deployment's API base URL is
 * not configured and requests fall through to the SPA fallback rewrite.
 */
export function looksLikeHtmlDocument(text: string): boolean {
  const head = text.slice(0, 512).trimStart().toLowerCase();
  return head.startsWith('<!doctype html') || head.startsWith('<html') || head.startsWith('<!--');
}

/**
 * The one genuinely confusing deployment failure this codebase can hit: with
 * `VITE_API_URL` unset, a Vercel-hosted SPA asks its own origin for /api/v1/*,
 * the catch-all rewrite answers with index.html, and every call used to fail as
 * "Server returned malformed JSON." Name the real cause instead.
 */
export const SPA_FALLBACK_MESSAGE =
  'The API returned an HTML page instead of JSON: requests are falling through to the frontend SPA. ' +
  'This deployment was most likely built without VITE_API_URL. Set it to the backend origin ' +
  '(for example https://<service>.onrender.com) and redeploy.';
