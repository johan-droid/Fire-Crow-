import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  auditPaths,
  authPaths,
  dashboardPaths,
  ssePaths,
  userPaths,
} from '../src/api/routes.js';

// Locks the frontend paths to the backend route table
// (backend/src/app.rs nests + routes_audit/auth/user/dashboard/sse.rs).
// A backend route rename breaks this suite instead of failing silently at runtime.
describe('audit paths', () => {
  it('covers submit, jobs, detail, retry, phases, executions', () => {
    assert.equal(auditPaths.submit(), '/audit/submit');
    assert.equal(auditPaths.jobs(), '/audit/jobs');
    assert.equal(auditPaths.job('j1'), '/audit/job/j1');
    assert.equal(auditPaths.retry('j1'), '/audit/job/j1/retry');
    assert.equal(auditPaths.phases('j1'), '/audit/job/j1/phases');
    assert.equal(auditPaths.executions('j1'), '/audit/job/j1/executions');
  });
  it('builds execution-scoped report/narrative/delivery paths', () => {
    assert.equal(
      auditPaths.executionReport('j1', 'e2', 'json'),
      '/audit/job/j1/execution/e2/report?format=json',
    );
    assert.equal(
      auditPaths.narrative('j1', 'e2'),
      '/audit/job/j1/execution/e2/narrative',
    );
    assert.equal(auditPaths.email('j1', 'e2'), '/audit/job/j1/execution/e2/email');
    assert.equal(auditPaths.telegram('j1', 'e2'), '/audit/job/j1/execution/e2/telegram');
    assert.equal(auditPaths.latestReport('j1', 'markdown'), '/audit/job/j1/report?format=markdown');
  });
  it('percent-encodes ids (no path injection via crafted ids)', () => {
    assert.equal(auditPaths.job('a/b'), '/audit/job/a%2Fb');
    assert.equal(
      auditPaths.executionReport('a/b', 'c?d', 'json'),
      '/audit/job/a%2Fb/execution/c%3Fd/report?format=json',
    );
    assert.equal(ssePaths.job('a/b'), '/sse/job/a%2Fb');
  });
});

describe('auth/user/dashboard paths', () => {
  it('matches the mounted routes', () => {
    assert.equal(authPaths.login(), '/auth/login');
    assert.equal(authPaths.register(), '/auth/register');
    assert.equal(authPaths.logout(), '/auth/logout');
    assert.equal(authPaths.me(), '/auth/me');
    assert.equal(authPaths.session(), '/auth/session');
    assert.equal(authPaths.refresh(), '/auth/refresh');
    assert.equal(authPaths.exchange(), '/auth/exchange');
    assert.equal(userPaths.repos(), '/user/repos');
    assert.equal(dashboardPaths.summary(), '/dashboard/summary');
    assert.equal(dashboardPaths.jobsLite(), '/dashboard/jobs-lite');
  });
});
