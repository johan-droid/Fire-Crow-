import type { JobResponse } from '../api/types.js';

/**
 * The console's audit view-state, as pure functions.
 *
 * These used to live inline in App.tsx (attention filter, sort) and in
 * AuditTable.tsx (search + status filter), so the same rules were written
 * twice and could drift. Keeping them here means one definition of "needs
 * attention", one sort order, and one filter — testable without a DOM and
 * reusable by every window.
 */

/** A run that did not produce a complete, trustworthy verdict. */
export const INCOMPLETE_STATUSES = [
  'failed',
  'cancelled',
  'partial',
  'engine_unavailable',
] as const;

/** Everything that belongs in the "needs attention" queue: not-clean runs plus in-flight ones. */
export const ATTENTION_STATUSES = [
  'failed',
  'cancelled',
  'partial',
  'engine_unavailable',
  'running',
  'queued',
] as const;

export function isIncomplete(status: string): boolean {
  return (INCOMPLETE_STATUSES as readonly string[]).includes(status);
}

/** Newest first, without mutating the input. */
export function sortByCreatedDesc(jobs: readonly JobResponse[]): JobResponse[] {
  return [...jobs].sort((a, b) => (a.created_at < b.created_at ? 1 : a.created_at > b.created_at ? -1 : 0));
}

/** Not-clean runs plus in-flight ones, newest first, optionally capped. */
export function needsAttention(jobs: readonly JobResponse[], limit?: number): JobResponse[] {
  const rows = sortByCreatedDesc(
    jobs.filter((j) => (ATTENTION_STATUSES as readonly string[]).includes(j.status)),
  );
  return typeof limit === 'number' ? rows.slice(0, limit) : rows;
}

export type AuditSort = 'newest' | 'oldest' | 'score';

export const AUDIT_SORTS: ReadonlyArray<{ id: AuditSort; label: string }> = [
  { id: 'newest', label: 'Newest first' },
  { id: 'oldest', label: 'Oldest first' },
  { id: 'score', label: 'Lowest score first' },
];

export function sortLabel(sort: AuditSort): string {
  return AUDIT_SORTS.find((s) => s.id === sort)?.label ?? 'Newest first';
}

/**
 * Order audits for display. Stable on ties so the list never reshuffles
 * between renders. `score` puts runs with no score last — a run we could not
 * score is never implied to be the cleanest.
 */
export function sortAudits(jobs: readonly JobResponse[], sort: AuditSort): JobResponse[] {
  const asc = (a: JobResponse, b: JobResponse) =>
    a.created_at < b.created_at ? -1 : a.created_at > b.created_at ? 1 : 0;
  const copy = [...jobs];
  if (sort === 'oldest') return copy.sort(asc);
  if (sort === 'score') {
    return copy.sort((a, b) => {
      const sa = a.security_score;
      const sb = b.security_score;
      if (sa == null && sb == null) return asc(b, a);
      if (sa == null) return 1;
      if (sb == null) return -1;
      return sa - sb || asc(b, a);
    });
  }
  return copy.sort((a, b) => asc(b, a));
}

export type AuditStatusFilter = 'all' | 'completed' | 'running' | 'needs_attention';

export const AUDIT_STATUS_FILTERS: ReadonlyArray<{ id: AuditStatusFilter; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'completed', label: 'Completed' },
  { id: 'running', label: 'Running' },
  { id: 'needs_attention', label: 'Needs attention' },
];

const matchesStatus = (job: JobResponse, status: AuditStatusFilter): boolean => {
  switch (status) {
    case 'completed':
      return job.status === 'completed';
    case 'running':
      return job.status === 'running' || job.status === 'queued';
    case 'needs_attention':
      return job.status === 'failed' || job.status === 'cancelled';
    default:
      return true;
  }
};

/** Count per status filter, for the filter tabs. */
export function auditFilterCounts(jobs: readonly JobResponse[]): Record<AuditStatusFilter, number> {
  return {
    all: jobs.length,
    completed: jobs.filter((j) => matchesStatus(j, 'completed')).length,
    running: jobs.filter((j) => matchesStatus(j, 'running')).length,
    needs_attention: jobs.filter((j) => matchesStatus(j, 'needs_attention')).length,
  };
}

export interface AuditQuery {
  query?: string;
  status?: AuditStatusFilter;
}

/** Repository/branch/commit search plus the status filter. */
export function filterAudits(jobs: readonly JobResponse[], { query = '', status = 'all' }: AuditQuery): JobResponse[] {
  const q = query.trim().toLowerCase();
  return jobs.filter((job) => {
    if (!matchesStatus(job, status)) return false;
    if (!q) return true;
    const repo = (job.repo_url || '').toLowerCase();
    const branch = (job.repo_branch || '').toLowerCase();
    const sha = (job.commit_sha || job.requested_commit_sha || '').toLowerCase();
    return repo.includes(q) || branch.includes(q) || sha.includes(q);
  });
}
