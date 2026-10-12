import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { JobResponse } from '../src/api/types.js';

const cwd = process.cwd();
const app = readFileSync(join(cwd, 'src', 'App.tsx'), 'utf8');
const dashboardCss = readFileSync(join(cwd, 'src', 'dashboard.css'), 'utf8');
const landingCss = readFileSync(join(cwd, 'src', 'landing', 'styles', 'landing.css'), 'utf8');
const metricCardSrc = readFileSync(join(cwd, 'src', 'dashboard', 'MetricCard.tsx'), 'utf8');
const auditTableSrc = readFileSync(join(cwd, 'src', 'dashboard', 'AuditTable.tsx'), 'utf8');

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

describe('Workspace information architecture', () => {
  it('navigates the five product windows: Overview, Repositories, Audits, Findings, Settings', () => {
    for (const id of ['overview', 'repositories', 'audits', 'findings', 'settings']) {
      assert.ok(app.includes(`id: '${id}'`), `nav item '${id}' missing`);
      assert.ok(app.includes(`activeWindow === '${id}'`), `window '${id}' never rendered`);
    }
  });

  it('exposes no admin or infrastructure windows in console navigation', () => {
    for (const id of ['jobs', 'diagnostics', 'sso', 'pam', 'iam', 'domains', 'mfa', 'activity']) {
      assert.ok(!app.includes(`id: '${id}'`), `admin nav item '${id}' must not exist`);
    }
  });

  it('maps legacy admin routes to the closest workspace window', () => {
    assert.ok(app.includes('LEGACY_WINDOWS'), 'legacy route map missing');
    assert.ok(app.includes("jobs: 'audits'"), 'legacy /console/jobs must resolve to audits');
    for (const seg of ['diagnostics', 'sso', 'pam', 'iam', 'domains', 'mfa', 'activity']) {
      assert.ok(app.includes(`${seg}: 'settings'`), `legacy /console/${seg} must resolve to settings`);
    }
  });
});

describe('No infrastructure clutter in console content', () => {
  it('shows no deployment or backend-internals content', () => {
    for (const s of ['Docker Sandbox', 'circuit_breaker', 'object_storage', 'onrender.com']) {
      assert.ok(!app.includes(s), `infrastructure string '${s}' must not appear in console content`);
    }
  });

  it('shows no admin surfaces (SSO/PAM/IAM/domains/billing) in the console', () => {
    for (const s of [
      'SSO Providers',
      'PAM Elevation',
      'IAM Policies',
      'Domain Verification',
      'Service Status',
      'Service Telemetry',
      'Dodo Payments Checkout',
    ]) {
      assert.ok(!app.includes(s), `admin surface '${s}' must not appear in the console`);
    }
  });

  it('imports no admin, telemetry, or decorative widgets into the workspace', () => {
    for (const s of [
      'SecurityTrendChart',
      'SeverityBreakdown',
      'ActionSidebar',
      'BackendStatusIndicator',
      'HealthWidget',
      'AuroraBackdrop',
    ]) {
      assert.ok(!app.includes(s), `console must not import '${s}'`);
    }
  });
});

describe('Ember graphite Next Lab / Fire Crow identity', () => {
  it('defines the restrained ember-graphite tokens', () => {
    assert.ok(dashboardCss.includes('--fc-canvas: #000000'), 'true black canvas token missing');
    assert.ok(dashboardCss.includes('--fc-surface: #000000'), 'surface token missing');
    assert.ok(dashboardCss.includes('--fc-text-primary: #FFFFFF'), 'white text token missing');
    assert.ok(dashboardCss.includes('--fc-text-secondary: #A1A1AA'), 'secondary text token missing');
    assert.ok(dashboardCss.includes('--fc-accent: #E5484D'), 'ember accent missing');
  });

  it('scopes landing tokens to .fc-landing so they never re-theme the console or login', () => {
    assert.ok(!/^:root\s*\{/m.test(landingCss), 'landing.css must not define a global :root token block');
    assert.ok(landingCss.includes('--fc-bg-canvas: #0A0B0E'), 'landing graphite canvas token missing');
  });

  it('styles the workspace surfaces: attention, repos, settings, guidance', () => {
    for (const cls of [
      '.fc-attention-list',
      '.fc-how-list',
      '.fc-calm-note',
      '.fc-repo-list',
      '.fc-settings-grid',
      '.fc-side-stack',
    ]) {
      assert.ok(dashboardCss.includes(cls), `workspace style '${cls}' missing`);
    }
  });

  it('brands the workspace as Next Lab · Fire Crow', () => {
    assert.ok(app.includes('Next Lab · Fire Crow'), 'parent-brand/product eyebrow missing');
  });

  it('supports reduced motion and small screens', () => {
    assert.ok(dashboardCss.includes('@media (prefers-reduced-motion: reduce)'), 'reduced-motion support missing');
    assert.ok(dashboardCss.includes('@media (max-width: 720px)'), 'small-screen support missing');
  });
});

describe('Decision-first overview: what was audited, what needs attention, how to fix', () => {
  it('leads with a needs-attention panel and the audit workflow, not charts', () => {
    assert.ok(app.includes('Needs attention'), 'needs-attention panel missing');
    assert.ok(app.includes('How an audit works'), 'workflow guidance missing');
    assert.ok(app.includes('AuditTable'), 'recent-audits table missing from overview');
  });

  it('counts failed, cancelled, partial, and engine-missing runs as needing attention', () => {
    assert.ok(
      app.includes("['failed', 'cancelled', 'partial', 'engine_unavailable']"),
      'attention filter must include partial and engine-missing states',
    );
    const sample = [
      job({ id: 'a', status: 'completed' }),
      job({ id: 'b', status: 'running' }),
      job({ id: 'c', status: 'queued' }),
      job({ id: 'd', status: 'failed' }),
      job({ id: 'e', status: 'partial' }),
      job({ id: 'f', status: 'engine_unavailable' }),
      job({ id: 'g', status: 'cancelled' }),
    ];
    const attention = sample.filter((j) =>
      ['failed', 'cancelled', 'partial', 'engine_unavailable'].includes(j.status),
    );
    assert.equal(attention.length, 4, 'running/queued must not count as needing attention');
  });

  it('MetricCard stays free of synthetic sparklines and fake percentage trends', () => {
    assert.ok(!metricCardSrc.includes('metric-sparkline'), 'MetricCard must not contain decorative sparklines');
    assert.ok(!metricCardSrc.includes('fc-metric-trend-badge'), 'MetricCard must not contain fake percentage badges');
    assert.ok(!metricCardSrc.includes('+14.2%'), 'MetricCard must not contain hardcoded trend percentages');
    assert.ok(metricCardSrc.includes('fc-metric-card'), 'MetricCard renders root .fc-metric-card');
    assert.ok(metricCardSrc.includes('fc-metric-value'), 'MetricCard renders .fc-metric-value');
    assert.ok(metricCardSrc.includes('fc-metric-label'), 'MetricCard renders .fc-metric-label');
  });
});

describe('Honest partial and incomplete states', () => {
  it('labels incomplete runs as incomplete — never as clean', () => {
    assert.ok(app.includes('Not a complete audit'), 'partial-coverage honesty copy missing');
    assert.ok(app.includes('Not a clean result'), 'engine-missing honesty copy missing');
    assert.ok(app.includes('No scan engine ran'), 'engine-missing explanation missing');
    assert.ok(app.includes('Partial coverage'), 'partial-coverage explanation missing');
  });

  it('keeps every retry as a separate attempt instead of merging history', () => {
    assert.ok(app.includes('Retry as new attempt'), 'retry-as-new-attempt action missing');
    assert.ok(app.includes('attempt_number'), 'execution attempt tracking missing');
  });

  it('presents AI narrative as optional annotation, never as evidence', () => {
    assert.ok(app.includes('AI explanation (optional)'), 'AI-optional framing missing');
    assert.ok(
      app.includes('severity always comes from scanner evidence'),
      'scanner-evidence supremacy note missing',
    );
  });
});

describe('Repositories, findings, and settings views', () => {
  it('groups audit history by repository with branch/commit identity and actions', () => {
    assert.ok(app.includes('Audit history'), 'per-repository audit history missing');
    assert.ok(app.includes('Inspect latest'), 'inspect-latest action missing');
    assert.ok(app.includes('Audit again'), 'audit-again action missing');
    assert.ok(app.includes('Connected repositories'), 'connected-repositories section missing');
    assert.ok(app.includes('GitHub is not connected'), 'not-connected honesty note missing');
  });

  it('investigates findings per audit run with incomplete-state honesty', () => {
    assert.ok(app.includes('Investigate an audit'), 'findings investigator missing');
    assert.ok(app.includes('Investigate'), 'investigate action missing');
    assert.ok(
      app.includes('never estimated here'),
      'no-fabricated-counts note missing',
    );
  });

  it('limits settings to account, MFA, and product truth', () => {
    assert.ok(app.includes('Two-factor authentication'), 'MFA setting missing');
    assert.ok(app.includes('About this workspace'), 'product-truth note missing');
    assert.ok(app.includes('Sign out'), 'sign-out action missing');
  });
});

describe('Empty, loading, and error states', () => {
  it('explains the next action for every empty workspace surface', () => {
    assert.ok(app.includes('No audited repositories'), 'repositories empty state missing');
    assert.ok(app.includes('No audits to investigate'), 'findings empty state missing');
    assert.ok(app.includes('No audits yet'), 'audits empty state missing');
    assert.ok(app.includes('Start an audit'), 'empty-state next action missing');
  });

  it('keeps skeleton loading and retryable error paths', () => {
    assert.ok(app.includes('state-skeleton'), 'loading skeletons missing');
    assert.ok(app.includes('onRetry={() => fetchDashboardData(true, { force: true })}'), 'error retry path missing');
  });
});

describe('Audit table capabilities (unchanged contract)', () => {
  it('supports table and list view switching', () => {
    assert.ok(auditTableSrc.includes("viewMode === 'table'"), 'View mode toggle support missing');
    assert.ok(auditTableSrc.includes('fc-table'), 'Table view missing');
    assert.ok(auditTableSrc.includes('fc-card-list'), 'List view missing');
  });

  it('supports status filtering and search', () => {
    assert.ok(auditTableSrc.includes('fc-filter-tab'), 'Filter tabs missing');
    assert.ok(auditTableSrc.includes('fc-search-input'), 'Search input missing');
  });

  it('renders a clean empty state with no fake template galleries', () => {
    assert.ok(auditTableSrc.includes('fc-empty-state'), 'Empty state missing');
    assert.ok(auditTableSrc.includes('No repository audits recorded'), 'Truthful empty message missing');
    assert.ok(!auditTableSrc.includes('Full OWASP Top 10 Audit'), 'Must not invent fake template cards');
    assert.ok(!auditTableSrc.includes('SOC 2 Compliance Scan'), 'Must not invent fake template cards');
  });
});
