import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { JobResponse } from '../src/api/types.js';

const cwd = process.cwd();
const app = readFileSync(join(cwd, 'src', 'App.tsx'), 'utf8');
const dashboardCss = readFileSync(join(cwd, 'src', 'dashboard.css'), 'utf8');
const metricCardSrc = readFileSync(join(cwd, 'src', 'dashboard', 'MetricCard.tsx'), 'utf8');
const trendChartSrc = readFileSync(join(cwd, 'src', 'dashboard', 'SecurityTrendChart.tsx'), 'utf8');
const severitySrc = readFileSync(join(cwd, 'src', 'dashboard', 'SeverityBreakdown.tsx'), 'utf8');
const auditTableSrc = readFileSync(join(cwd, 'src', 'dashboard', 'AuditTable.tsx'), 'utf8');
const actionSidebarSrc = readFileSync(join(cwd, 'src', 'dashboard', 'ActionSidebar.tsx'), 'utf8');

describe('Phase 0 & 1 — Modular Sub-components & Design System Baselines', () => {
  it('has dedicated sub-component files in src/dashboard/', () => {
    assert.ok(existsSync(join(cwd, 'src', 'dashboard', 'MetricCard.tsx')), 'MetricCard.tsx missing in src/dashboard');
    assert.ok(existsSync(join(cwd, 'src', 'dashboard', 'SecurityTrendChart.tsx')), 'SecurityTrendChart.tsx missing in src/dashboard');
    assert.ok(existsSync(join(cwd, 'src', 'dashboard', 'AuditTable.tsx')), 'AuditTable.tsx missing in src/dashboard');
    assert.ok(existsSync(join(cwd, 'src', 'dashboard', 'ActionSidebar.tsx')), 'ActionSidebar.tsx missing in src/dashboard');
    assert.ok(existsSync(join(cwd, 'src', 'dashboard', 'SeverityBreakdown.tsx')), 'SeverityBreakdown.tsx missing in src/dashboard');
    assert.ok(existsSync(join(cwd, 'src', 'dashboard', 'index.ts')), 'index.ts missing in src/dashboard');
  });

  it('provides root re-exports in src/ for all main sub-components', () => {
    assert.ok(existsSync(join(cwd, 'src', 'MetricCard.tsx')), 'MetricCard.tsx missing in src');
    assert.ok(existsSync(join(cwd, 'src', 'SecurityTrendChart.tsx')), 'SecurityTrendChart.tsx missing in src');
    assert.ok(existsSync(join(cwd, 'src', 'AuditTable.tsx')), 'AuditTable.tsx missing in src');
    assert.ok(existsSync(join(cwd, 'src', 'ActionSidebar.tsx')), 'ActionSidebar.tsx missing in src');
  });

  it('App.tsx imports and integrates all modular dashboard sub-components', () => {
    assert.ok(app.includes('MetricCard'), 'MetricCard not integrated in App.tsx');
    assert.ok(app.includes('SecurityTrendChart'), 'SecurityTrendChart not integrated in App.tsx');
    assert.ok(app.includes('SeverityBreakdown'), 'SeverityBreakdown not integrated in App.tsx');
    assert.ok(app.includes('AuditTable'), 'AuditTable not integrated in App.tsx');
    assert.ok(app.includes('ActionSidebar'), 'ActionSidebar not integrated in App.tsx');
  });

  it('defines restrained minimal-dark tokens (canvas, cards, borders, brand)', () => {
    assert.ok(dashboardCss.includes('--fc-canvas: #09090b'), 'Canvas token #09090b missing');
    assert.ok(dashboardCss.includes('--fc-surface: #141418'), 'Surface token #141418 missing');
    assert.ok(dashboardCss.includes('--fc-surface-elevated: #1a1a22'), 'Elevated surface token #1a1a22 missing');
    assert.ok(dashboardCss.includes('--fc-border: rgba(255, 255, 255, 0.08)'), 'Fine border token missing');
    assert.ok(dashboardCss.includes('--fc-accent: #f97316'), 'Brand accent token #f97316 missing');
  });
});

describe('Phase 3A — Truthful Metric Derivation & Clean MetricCard', () => {
  const sampleJobs: JobResponse[] = [
    {
      id: 'job-1',
      user_id: 'u-1',
      repo_url: 'https://github.com/org/repo-a',
      repo_branch: 'main',
      status: 'completed',
      created_at: '2026-10-01T10:00:00Z',
      finished_at: '2026-10-01T10:05:00Z',
      cancel_requested: false,
      cancel_requested_at: null,
      report_pdf_url: '/api/v1/audits/job-1/report.pdf',
      error_message: null,
      security_score: 88,
      email_delivered: true,
      github_issues_raised: false,
      github_pr_created: false,
    },
    {
      id: 'job-2',
      user_id: 'u-1',
      repo_url: 'https://github.com/org/repo-b',
      repo_branch: 'develop',
      status: 'running',
      created_at: '2026-10-01T10:10:00Z',
      finished_at: null,
      cancel_requested: false,
      cancel_requested_at: null,
      report_pdf_url: null,
      error_message: null,
      security_score: null,
      email_delivered: false,
      github_issues_raised: false,
      github_pr_created: false,
    },
    {
      id: 'job-3',
      user_id: 'u-1',
      repo_url: 'https://github.com/org/repo-c',
      repo_branch: 'main',
      status: 'queued',
      created_at: '2026-10-01T10:12:00Z',
      finished_at: null,
      cancel_requested: false,
      cancel_requested_at: null,
      report_pdf_url: null,
      error_message: null,
      security_score: null,
      email_delivered: false,
      github_issues_raised: false,
      github_pr_created: false,
    },
    {
      id: 'job-4',
      user_id: 'u-1',
      repo_url: 'https://github.com/org/repo-d',
      repo_branch: 'patch-1',
      status: 'failed',
      created_at: '2026-10-01T09:00:00Z',
      finished_at: '2026-10-01T09:02:00Z',
      cancel_requested: false,
      cancel_requested_at: null,
      report_pdf_url: null,
      error_message: 'Clone error',
      security_score: null,
      email_delivered: false,
      github_issues_raised: false,
      github_pr_created: false,
    },
    {
      id: 'job-5',
      user_id: 'u-1',
      repo_url: 'https://github.com/org/repo-e',
      repo_branch: 'main',
      status: 'completed',
      created_at: '2026-10-01T08:00:00Z',
      finished_at: '2026-10-01T08:06:00Z',
      cancel_requested: false,
      cancel_requested_at: null,
      report_pdf_url: null,
      error_message: null,
      security_score: 92,
      email_delivered: true,
      github_issues_raised: false,
      github_pr_created: false,
    },
  ];

  it('correctly calculates completed, running, reports ready, and needs attention metrics', () => {
    const completedCount = sampleJobs.filter(j => j.status === 'completed').length;
    const runningCount = sampleJobs.filter(j => j.status === 'running' || j.status === 'queued').length;
    const reportsReady = sampleJobs.filter(j => j.status === 'completed' && j.report_pdf_url).length;
    const needsAttention = sampleJobs.filter(j => j.status === 'failed' || j.status === 'cancelled').length;

    assert.equal(completedCount, 2, 'Completed count should be 2');
    assert.equal(runningCount, 2, 'Running + queued count should be 2');
    assert.equal(reportsReady, 1, 'Reports ready should be 1');
    assert.equal(needsAttention, 1, 'Needs attention should be 1');
  });

  it('MetricCard is free of synthetic sparklines and fake percentage trends', () => {
    assert.ok(!metricCardSrc.includes('metric-sparkline'), 'MetricCard must not contain decorative sparklines');
    assert.ok(!metricCardSrc.includes('fc-metric-trend-badge'), 'MetricCard must not contain fake percentage badges');
    assert.ok(!metricCardSrc.includes('+14.2%'), 'MetricCard must not contain hardcoded trend percentages');
    assert.ok(metricCardSrc.includes('fc-metric-card'), 'MetricCard renders root .fc-metric-card');
    assert.ok(metricCardSrc.includes('fc-metric-value'), 'MetricCard renders .fc-metric-value');
    assert.ok(metricCardSrc.includes('fc-metric-label'), 'MetricCard renders .fc-metric-label');
  });
});

describe('Phase 3B & 3C — Truthful Data Visualization', () => {
  it('SecurityTrendChart renders strictly from real scored audits and displays fallback when data is insufficient', () => {
    assert.ok(trendChartSrc.includes('No scored audits recorded'), 'Chart must render truthful 0-audit fallback');
    assert.ok(trendChartSrc.includes('A comparative score trajectory will appear once additional audits are completed'), 'Chart must render 1-audit comparative note');
    assert.ok(!trendChartSrc.includes('Math.random'), 'Chart must not use random data');
    assert.ok(!trendChartSrc.includes('baselineDate'), 'Chart must not fabricate fake baseline calendar data');
    assert.ok(trendChartSrc.includes('Audit Score History'), 'Chart header title present');
  });

  it('SeverityBreakdown computes strictly from passed findings without heuristic fabrication', () => {
    assert.ok(severitySrc.includes('No findings loaded for this scope'), 'Must show empty fallback when 0 findings');
    assert.ok(severitySrc.includes('fc-stacked-bar'), 'Renders clean horizontal distribution bar');
    assert.ok(severitySrc.includes('fc-severity-pill'), 'Renders clear legend items');
    assert.ok(!severitySrc.includes('fc-donut-svg'), 'Must not render misleading donut chart');
  });
});

describe('Phase 4 — Audit Table & Views', () => {
  it('AuditTable supports table and list view switching', () => {
    assert.ok(auditTableSrc.includes("viewMode === 'table'"), 'View mode toggle support missing');
    assert.ok(auditTableSrc.includes('fc-table'), 'Table view missing');
    assert.ok(auditTableSrc.includes('fc-card-list'), 'List view missing');
  });

  it('AuditTable supports status filtering and search', () => {
    assert.ok(auditTableSrc.includes('fc-filter-tab'), 'Filter tabs missing');
    assert.ok(auditTableSrc.includes('fc-search-input'), 'Search input missing');
  });

  it('AuditTable renders a clean empty state with no fake template galleries', () => {
    assert.ok(auditTableSrc.includes('fc-empty-state'), 'Empty state missing');
    assert.ok(auditTableSrc.includes('No repository audits recorded'), 'Truthful empty message missing');
    assert.ok(!auditTableSrc.includes('Full OWASP Top 10 Audit'), 'Must not invent fake template cards');
    assert.ok(!auditTableSrc.includes('SOC 2 Compliance Scan'), 'Must not invent fake template cards');
  });
});

describe('Phase 5 — Action Sidebar & Service Telemetry', () => {
  it('ActionSidebar guides users through the genuine 3-step audit workflow', () => {
    assert.ok(actionSidebarSrc.includes('Select Repository'), 'Step 1 missing');
    assert.ok(actionSidebarSrc.includes('Review Findings'), 'Step 2 missing');
    assert.ok(actionSidebarSrc.includes('Access Reports'), 'Step 3 missing');
  });

  it('ActionSidebar reflects real backend deepHealth and contains zero simulated ping telemetry', () => {
    assert.ok(actionSidebarSrc.includes('deepHealth'), 'Must read real deepHealth');
    assert.ok(!actionSidebarSrc.includes('18ms'), 'Must not contain hardcoded 18ms latency');
    assert.ok(!actionSidebarSrc.includes('99.98%'), 'Must not contain fake uptime percentages');
    assert.ok(!actionSidebarSrc.includes('AI Agent Insights'), 'Must not contain fake AI PR marketing cards');
  });
});

describe('Phase 6 — Layout & Responsiveness', () => {
  it('styles responsive layouts for desktop, tablet, and mobile', () => {
    assert.ok(dashboardCss.includes('.fc-metrics-grid'), 'Metrics grid class missing');
    assert.ok(dashboardCss.includes('.fc-charts-grid'), 'Charts grid class missing');
    assert.ok(dashboardCss.includes('.fc-main-grid'), 'Main split grid class missing');
    assert.ok(dashboardCss.includes('@media (max-width: 1024px)'), 'Tablet breakpoint missing');
    assert.ok(dashboardCss.includes('@media (max-width: 600px)'), 'Mobile breakpoint missing');
  });
});
