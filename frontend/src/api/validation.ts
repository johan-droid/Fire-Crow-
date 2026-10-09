// Submit-request construction. Mirrors backend rules
// (backend/src/agents/fetch.rs, backend/src/schemas/audit_api.rs).
// Client-side checks are early feedback only; the backend gate is authoritative.
import type { SubmitJobRequest } from './types.js';

/** Backend `is_valid_commit_sha`: 40 chars, hex, no uppercase. */
export function isValidCommitSha(value: string): boolean {
  return /^[0-9a-f]{40}$/.test(value);
}

/**
 * Build a SubmitJobRequest from form input.
 *
 * `custom_email` is ALWAYS present (null): the backend field is
 * `Option<String>` (absent deserializes to None, verified live 2026-10-09 —
 * an absent key is accepted, not rejected). The key is still always sent so
 * the wire shape stays stable. The value plays no role in delivery —
 * reports go to the account email.
 */
export function buildSubmitRequest(input: {
  repoUrl: string;
  repoBranch?: string;
  commitSha?: string;
}): SubmitJobRequest {
  const sha = (input.commitSha ?? '').trim();
  return {
    repo_url: input.repoUrl.trim(),
    repo_branch: (input.repoBranch ?? '').trim() || 'main',
    commit_sha: sha || null,
    custom_email: null,
  };
}
