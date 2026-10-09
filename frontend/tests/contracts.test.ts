import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildSubmitRequest } from '../src/api/validation.js';
import {
  executionsFixture,
  jobFixture,
  narrativeEnvelopeFixture,
  reportFixture,
} from './fixtures.js';

const COVERAGE_STATES = [
  'SUCCESS_CLEAN',
  'SUCCESS_FINDINGS',
  'FAILED',
  'TIMEOUT',
  'CANCELLED',
  'NO_FILES_ANALYZED',
];

const JOB_RESPONSE_KEYS = [
  'id', 'user_id', 'repo_url', 'repo_branch', 'status',
  'created_at', 'finished_at', 'cancel_requested', 'cancel_requested_at',
  'report_pdf_url', 'error_message', 'security_score', 'email_delivered',
  'github_issues_raised', 'github_pr_created',
  'requested_commit_sha', 'commit_sha',
];

describe('contract lock: backend Serialize shapes', () => {
    it('submit payload always carries custom_email (stable wire shape)', () => {
    for (const args of [
      { repoUrl: 'https://github.com/o/r' },
      { repoUrl: 'https://github.com/o/r', repoBranch: 'dev', commitSha: 'c'.repeat(40) },
    ]) {
      const wire = JSON.parse(JSON.stringify(buildSubmitRequest(args))) as Record<string, unknown>;
      assert.ok('custom_email' in wire, `missing custom_email for ${JSON.stringify(args)}`);
    }
  });
  it('JobResponse fixture carries every backend field', () => {
    for (const key of JOB_RESPONSE_KEYS) {
      assert.ok(key in jobFixture, `JobResponse missing ${key}`);
    }
  });
  it('executions keep distinct identities per attempt', () => {
    const ids = executionsFixture.map((e) => e.execution_id);
    assert.equal(new Set(ids).size, ids.length);
    const attempts = executionsFixture.map((e) => e.attempt_number);
    assert.equal(new Set(attempts).size, attempts.length);
    for (const e of executionsFixture) {
      assert.equal(typeof e.has_report, 'boolean');
      assert.equal(typeof e.has_narrative, 'boolean');
    }
  });
  it('report coverage state is a known literal; unknown score stays null', () => {
    assert.ok(COVERAGE_STATES.includes(reportFixture.coverage.state));
    assert.equal(reportFixture.summary.security_score, null);
    assert.equal(typeof reportFixture.summary.finding_count, 'number');
  });
  it('narrative envelope wraps .narrative; guidance is never verified', () => {
    assert.equal(typeof narrativeEnvelopeFixture.narrative.executive_summary, 'string');
    for (const g of narrativeEnvelopeFixture.narrative.remediation_guidance) {
      assert.equal(g.verified, false);
    }
  });
});
