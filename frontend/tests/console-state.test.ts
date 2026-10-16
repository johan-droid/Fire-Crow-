import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { JobResponse } from '../src/api/types.js';
import {
  auditFilterCounts,
  filterAudits,
  isIncomplete,
  needsAttention,
  sortAudits,
} from '../src/dashboard/console.js';

// The console's audit view-state is pure, so it is tested directly rather than
// through the DOM: one definition of filter + sort, in dashboard/console.ts.

const job = (over: Partial<JobResponse> & { id: string; status: string }): JobResponse => ({
  user_id: 'u-1',
  repo_url: 'https://github.com/org/repo',
  repo_branch: 'main',
  created_at: '2026-10-01T10:00:00Z',
  finished_at: null,
  cancel_requested: false,
  cancel_requested_at: null,
  report_pdf_url: null,
  error_message: null,
  security_score: null,
  email_delivered: false,
  github_issues_raised: false,
  github_pr_created: false,
  ...over,
} as JobResponse);

describe('isIncomplete', () => {
  it('flags runs that did not produce a clean, complete verdict', () => {
    for (const s of ['failed', 'cancelled', 'partial', 'engine_unavailable']) {
      assert.equal(isIncomplete(s), true, `${s} must count as incomplete`);
    }
    for (const s of ['completed', 'running', 'queued']) {
      assert.equal(isIncomplete(s), false, `${s} must not count as incomplete`);
    }
  });
});

describe('needsAttention', () => {
  const rows = [
    job({ id: 'a', status: 'completed', created_at: '2026-10-05T00:00:00Z' }),
    job({ id: 'b', status: 'running', created_at: '2026-10-03T00:00:00Z' }),
    job({ id: 'c', status: 'queued', created_at: '2026-10-02T00:00:00Z' }),
    job({ id: 'd', status: 'failed', created_at: '2026-10-04T00:00:00Z' }),
    job({ id: 'e', status: 'partial', created_at: '2026-10-01T00:00:00Z' }),
    job({ id: 'f', status: 'engine_unavailable', created_at: '2026-10-06T00:00:00Z' }),
    job({ id: 'g', status: 'cancelled', created_at: '2026-10-07T00:00:00Z' }),
  ];

  it('takes not-clean and in-flight runs, newest first, and drops completed', () => {
    const ids = needsAttention(rows).map((j) => j.id);
    assert.deepEqual(ids, ['g', 'f', 'd', 'b', 'c', 'e']);
  });

  it('caps the list without dropping the newest', () => {
    assert.deepEqual(needsAttention(rows, 2).map((j) => j.id), ['g', 'f']);
  });

  it('never counts a completed run as needing attention', () => {
    assert.ok(!needsAttention(rows).some((j) => j.id === 'a'));
  });
});

describe('sortAudits', () => {
  const rows = [
    job({ id: 'mid', status: 'completed', created_at: '2026-10-02T00:00:00Z', security_score: 8 }),
    job({ id: 'no-score', status: 'running', created_at: '2026-10-04T00:00:00Z', security_score: null }),
    job({ id: 'low', status: 'partial', created_at: '2026-10-01T00:00:00Z', security_score: 3 }),
    job({ id: 'new', status: 'completed', created_at: '2026-10-03T00:00:00Z', security_score: 10 }),
  ];

  it('orders newest and oldest by created_at', () => {
    assert.deepEqual(sortAudits(rows, 'newest').map((j) => j.id), ['no-score', 'new', 'mid', 'low']);
    assert.deepEqual(sortAudits(rows, 'oldest').map((j) => j.id), ['low', 'mid', 'new', 'no-score']);
  });

  it('orders lowest score first and puts unscored runs last — never implied clean', () => {
    assert.deepEqual(sortAudits(rows, 'score').map((j) => j.id), ['low', 'mid', 'new', 'no-score']);
  });

  it('does not mutate its input', () => {
    const before = rows.map((j) => j.id);
    sortAudits(rows, 'oldest');
    assert.deepEqual(rows.map((j) => j.id), before);
  });
});

describe('filterAudits', () => {
  const rows = [
    job({ id: 'a', status: 'completed', repo_url: 'https://github.com/acme/core-api', repo_branch: 'main' }),
    job({ id: 'b', status: 'failed', repo_url: 'https://github.com/acme/web', repo_branch: 'release', commit_sha: 'abcdef1234' }),
    job({ id: 'c', status: 'running', repo_url: 'https://github.com/other/thing', repo_branch: 'dev' }),
  ];

  it('matches repository, branch, and commit substring', () => {
    assert.deepEqual(filterAudits(rows, { query: 'core-api' }).map((j) => j.id), ['a']);
    assert.deepEqual(filterAudits(rows, { query: 'release' }).map((j) => j.id), ['b']);
    assert.deepEqual(filterAudits(rows, { query: 'abcdef' }).map((j) => j.id), ['b']);
  });

  it('applies the status filter', () => {
    assert.deepEqual(filterAudits(rows, { status: 'completed' }).map((j) => j.id), ['a']);
    assert.deepEqual(filterAudits(rows, { status: 'running' }).map((j) => j.id), ['c']);
    assert.deepEqual(filterAudits(rows, { status: 'needs_attention' }).map((j) => j.id), ['b']);
  });

  it('combines query and status', () => {
    assert.deepEqual(filterAudits(rows, { query: 'acme', status: 'needs_attention' }).map((j) => j.id), ['b']);
    assert.deepEqual(filterAudits(rows, { query: 'other', status: 'needs_attention' }).map((j) => j.id), []);
  });

  it('returns everything for the default query', () => {
    assert.equal(filterAudits(rows, {}).length, 3);
    assert.equal(filterAudits(rows, { query: '   ' }).length, 3);
  });
});

describe('auditFilterCounts', () => {
  it('counts each filter bucket from real data only', () => {
    const rows = [
      job({ id: 'a', status: 'completed' }),
      job({ id: 'b', status: 'completed' }),
      job({ id: 'c', status: 'running' }),
      job({ id: 'd', status: 'queued' }),
      job({ id: 'e', status: 'failed' }),
      job({ id: 'f', status: 'cancelled' }),
      job({ id: 'g', status: 'partial' }),
    ];
    assert.deepEqual(auditFilterCounts(rows), {
      all: 7,
      completed: 2,
      running: 2,
      needs_attention: 2,
    });
  });
});
