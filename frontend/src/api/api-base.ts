// Pure API-base-URL resolution and validation. No Vite globals, no browser
// globals — compilable under both the app config and the tests config, exactly
// like the neighbouring `errors.ts` / `validation.ts` / `routes.ts` modules.
//
// FC-DEP-05: a malformed `VITE_API_URL` previously produced a silently wrong
// request target (e.g. `not-a-url/api/v1/...`), which surfaces as a confusing
// 404 or an opaque CORS failure. A decoupled deployment must fail loudly with
// an actionable message instead of quietly pointing somewhere unintended.

/**
 * Validate a configured API base URL before it is used.
 *
 * Returns `null` when the value is acceptable, or a human-readable reason.
 * An absolute `http(s)://` origin is required; protocol-relative (`//host`),
 * relative paths, and non-HTTP schemes are rejected. Unset/blank is the
 * documented same-origin default and is accepted.
 */
export function validateApiBaseUrl(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed) return null; // unset is the documented same-origin default
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return `VITE_API_URL is not a valid absolute URL: ${JSON.stringify(trimmed)}`;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return `VITE_API_URL must use http or https, got ${parsed.protocol}`;
  }
  if (!parsed.hostname) {
    return `VITE_API_URL must include a hostname: ${JSON.stringify(trimmed)}`;
  }
  return null;
}

/**
 * Resolve the request base from a configured value.
 *
 * Throws on a malformed value (fail loudly, never guess a target). Returns
 * `/api/v1` when unset. A configured origin gets exactly one `/api/v1` suffix.
 */
export function resolveApiBase(configured: string | undefined): string {
  const viteUrl = configured?.trim();
  if (!viteUrl) return '/api/v1';
  const problem = validateApiBaseUrl(viteUrl);
  if (problem) {
    throw new Error(
      `${problem}. Set VITE_API_URL to the backend origin, e.g. https://api.example.com`,
    );
  }
  const cleaned = viteUrl.replace(/\/$/, '');
  return cleaned.endsWith('/api/v1') ? cleaned : `${cleaned}/api/v1`;
}
