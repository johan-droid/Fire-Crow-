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
