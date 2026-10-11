import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { AuroraBackdrop } from './scene';
import LandingPage from './LandingPage';
import LoginPage from './LoginPage';
import { useNavigate, useLocation } from 'react-router-dom';
import { api } from './api/client';
import { ApiError } from './api/errors';
import { parseSsePayload } from './api/sse';
import { BackendStatusIndicator } from './api/BackendStatusIndicator';
import { useToasts } from './api/toast';
import { ToastHost } from './api/toast-host';
import { transitionToast, TOAST_COPY } from './api/health';
import { filterFindings, fromDetailFindings, fromReportFindings, isSafeExternalUrl } from './api/explorer';
import { buildSubmitRequest, isValidCommitSha } from './api/validation';
import type {
  CanonicalAuditReport,
  ExecutionHistoryEntry,
  GithubRepo,
  JobResponse,
  PhaseLedgerEntry,
  ReportNarrative,
} from './api/types';
import {
  PanelState, ScoreRing, HealthWidget, jobStatusInfo, jobStatusMix, severityClass,
  fmtUtc, timeAgo, MetricCard, StatusPill, AuditRow, EmptyState, repoLabel,
  type LoadState, type DeepHealth,
} from './dash';

const getApiBase = (): string => {
  const viteApiUrl = import.meta.env.VITE_API_URL;
  if (viteApiUrl && typeof viteApiUrl === 'string' && viteApiUrl.trim().length > 0) {
    return viteApiUrl.trim();
  }
  if (typeof window !== 'undefined' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')) {
    return 'http://localhost:8000/api/v1';
  }
  return '/api/v1';
};

const API_BASE = getApiBase();

interface UserProfile {
  user_id: string;
  username: string;
  email: string | null;
  credit_balance?: number;
  is_active?: boolean;
}

interface Finding {
  id: string;
  title: string;
  severity: string;
  cwe_id?: string | null;
  owasp_category?: string | null;
  file_path?: string | null;
  line_number?: number | null;
  description: string;
  remediation?: string | null;
  cvss_score?: number | null;
  cvss_vector?: string | null;
  agent_source?: string | null;
  route?: string | null;
}

/* Single job contract: canonical JobResponse from ./api/types (backend audit_api.rs). */

interface SsoProvider {
  id: string;
  name: string;
  provider_type: string;
  issuer_url?: string | null;
  client_id?: string | null;
  enforce_mfa?: boolean;
  auto_provision?: boolean;
}

interface PamRequest {
  id: string;
  user_id: string;
  role_name: string;
  permission: string;
  reason: string;
  requested_duration_minutes: number;
  status: string;
  created_at: string;
}

interface PamGrant {
  id: string;
  request_id: string;
  granted_by: string;
  expires_at: string;
  revoked: boolean;
  created_at: string;
}

interface IamPolicy {
  id: string;
  name: string;
  effect: string;
  actions: string;
  resources: string;
  priority: number;
}

interface DomainVerification {
  id: string;
  domain: string;
  verified: boolean;
  dns_txt_name?: string;
  dns_txt_value?: string;
  created_at: string;
}

interface ActivityEvent {
  id: string;
  action: string;
  details_json?: string | null;
  created_at: string;
}

interface MfaStatus {
  enabled: boolean;
  backup_codes_remaining: number;
}

const apiFetch = async (endpoint: string, options: RequestInit = {}) => {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> || {}),
  };
  const res = await fetch(`${API_BASE}${endpoint}`, {
    credentials: 'include',
    ...options,
    headers,
  });

  // Session cookies are HttpOnly: only the server's logout response can clear
  // them, never JavaScript. 401s surface to callers as responses.
  return res;
};

// Lightweight in-memory cache for dashboard summary (5 s TTL, avoids duplicate calls on re-render)
let _dashboardCache: { data: any; ts: number } | null = null;
const DASH_CACHE_TTL = 5000;

function App() {
  const [view, setView] = useState<'landing' | 'login' | 'dashboard'>('landing');
  void view; void setView;
  // Toasts: connection-state changes and user-facing errors. Never throws.
  const { toasts, push: pushToast, dismiss: dismissToast } = useToasts();
  const [user, setUser] = useState<UserProfile | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  // Explicit session lifecycle: initializing (blocking splash) → signed_out |
  // authenticated | error. Distinct from data-loading flags elsewhere.
  type AuthState = 'initializing' | 'signed_out' | 'authenticated' | 'error';
  const [authState, setAuthState] = useState<AuthState>('initializing');

  // Dashboard Tab state
  type ConsoleWindow = 'overview' | 'jobs' | 'diagnostics' | 'sso' | 'pam' | 'iam' | 'domains' | 'mfa' | 'activity';
  const navigate = useNavigate();
  const location = useLocation();
  const getWindowFromPath = (): ConsoleWindow => {
    const seg = location.pathname.replace(/^\/console\/?/, '').split('/')[0] as ConsoleWindow;
    if (['overview','jobs','diagnostics','sso','pam','iam','domains','mfa','activity'].includes(seg)) return seg as ConsoleWindow;
    return 'overview';
  };
  const activeWindow = getWindowFromPath();
  // keep dashTab for internal handlers; sync from router
  const [dashTab, setDashTabRaw] = useState<ConsoleWindow>('overview');
  const setDashTab = (w: ConsoleWindow) => navigate(`/console/${w}`);
  void setDashTab;
  useEffect(() => {
    const w = getWindowFromPath();
    if (w !== dashTab) setDashTabRaw(w);
    if (location.pathname === '/console' || location.pathname === '/console/') navigate('/console/overview', { replace: true });
  }, [location.pathname]);
  const [themeAccent, setThemeAccent] = useState<'ember' | 'azure' | 'violet' | 'mint'>(() => {
    const stored = localStorage.getItem('fc-accent');
    return stored === 'azure' || stored === 'violet' || stored === 'mint' || stored === 'ember' ? stored : 'ember';
  });
  const [themeMenuOpen, setThemeMenuOpen] = useState(false);
  useEffect(() => {
    document.documentElement.dataset.accent = themeAccent;
    localStorage.setItem('fc-accent', themeAccent);
  }, [themeAccent]);

  // Live Backend Data States
  const [jobs, setJobs] = useState<JobResponse[]>([]);
  const [selectedJobDetail, setSelectedJobDetail] = useState<{ job: JobResponse; findings: Finding[] } | null>(null);
  // Execution-aware inspector: one selected attempt drives report, narrative
  // and delivery. Defaults to the latest attempt on open, never mid-view.
  const [executions, setExecutions] = useState<ExecutionHistoryEntry[]>([]);
  const [execLoading, setExecLoading] = useState(false);
  const [selectedExecutionId, setSelectedExecutionId] = useState<string | null>(null);
  const [execReport, setExecReport] = useState<CanonicalAuditReport | null>(null);
  const [reportState, setReportState] = useState<'idle' | 'loading' | 'ready' | 'error'>('idle');
  const [reportError, setReportError] = useState('');
  const [narrative, setNarrative] = useState<ReportNarrative | null>(null);
  const [narrativeState, setNarrativeState] = useState<'idle' | 'loading' | 'ready' | 'error'>('idle');
  const [narrativeError, setNarrativeError] = useState('');
  const [findingQuery, setFindingQuery] = useState('');
  const [findingSev, setFindingSev] = useState('all');
  const [deliveryMsg, setDeliveryMsg] = useState('');
  const [deliveryBusy, setDeliveryBusy] = useState<string | null>(null);
  const [cancelNote, setCancelNote] = useState('');
  const [retryBusy, setRetryBusy] = useState(false);
  const inspectReqRef = useRef(0);
  // Closing invalidates in-flight execution loads so they can't populate a reopened view.
  const closeInspector = () => { inspectReqRef.current++; setSelectedJobDetail(null); };

  // Findings explorer source: the selected attempt's report when loaded,
  // otherwise the job's latest-execution findings (labeled as such below).
  const explorerFindings = useMemo(() => {
    const rows =
      reportState === 'ready' && execReport
        ? fromReportFindings(execReport.findings)
        : fromDetailFindings(selectedJobDetail?.findings ?? []);
    return filterFindings(rows, findingQuery, findingSev);
  }, [reportState, execReport, selectedJobDetail, findingQuery, findingSev]);
  const [detailLoading, setDetailLoading] = useState(false);
  const [_selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [ssoProviders, setSsoProviders] = useState<SsoProvider[]>([]);
  const [pamRequests, setPamRequests] = useState<PamRequest[]>([]);
  const [_pamGrants, setPamGrants] = useState<PamGrant[]>([]);
  const [iamPolicies, setIamPolicies] = useState<IamPolicy[]>([]);
  const [domains, setDomains] = useState<DomainVerification[]>([]);
  const [activities, setActivities] = useState<ActivityEvent[]>([]);
  const [mfaStatus, setMfaStatus] = useState<MfaStatus>({ enabled: false, backup_codes_remaining: 0 });
  const [activeMonitorJobId, setActiveMonitorJobId] = useState<string | null>(null);
  const [monitorPhases, setMonitorPhases] = useState<PhaseLedgerEntry[]>([]);

  // Dashboard state machine: loading → ready | error, with sync + health telemetry
  const [dashLoad, setDashLoad] = useState<LoadState>('loading');
  const [dashError, setDashError] = useState<string | null>(null);
  const [lastSync, setLastSync] = useState<Date | null>(null);
  const [deepHealth, setDeepHealth] = useState<DeepHealth | null>(null);
  const [cancellingIds, setCancellingIds] = useState<string[]>([]);
  const [mfaEnrollment, setMfaEnrollment] = useState<{ secret: string; uri: string; recovery_codes: string[] } | null>(null);

  // Modals error & submission state
  const [modalError, setModalError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Modals visibility
  const [isScanModalOpen, setIsScanModalOpen] = useState(false);
  const [newRepoUrl, setNewRepoUrl] = useState('');
  const [newRepoBranch, setNewRepoBranch] = useState('main');
  const [newCommitSha, setNewCommitSha] = useState('');
  const [userRepos, setUserRepos] = useState<GithubRepo[]>([]);
  const [isLoadingRepos, setIsLoadingRepos] = useState(false);
  // GitHub connection is distinct from an empty list: HTTP 200 can still mean
  // not_connected / github_error / network_error (backend routes_user.rs).
  const [reposStatus, setReposStatus] = useState<'idle' | 'loading' | 'ready' | 'not_connected' | 'github_error' | 'network_error'>('idle');
  const [reposMessage, setReposMessage] = useState('');

  const lastRepoFetchRef = useRef<number>(0);
  const reposInflightRef = useRef(false);
  const fetchUserRepos = useCallback(async (force = false) => {
    if (reposInflightRef.current) return;
    const now = Date.now();
    if (!force && now - lastRepoFetchRef.current < 30_000) return; // 30 s throttle
    if (isLoadingRepos) return;
    lastRepoFetchRef.current = now;
    reposInflightRef.current = true;
    setIsLoadingRepos(true);
    setReposStatus('loading');
    try {
      const data = await api.repos();
      if (data.status === 'ok') {
        setUserRepos(data.repositories ?? []);
        setReposStatus('ready');
        setReposMessage('');
      } else {
        // Connected HTTP, failed GitHub link: never present as an empty account.
        setUserRepos([]);
        setReposStatus(data.status);
        setReposMessage(data.message || '');
      }
    } catch (err) {
      console.error('Failed to fetch user repos', err);
      setUserRepos([]);
      setReposStatus('network_error');
      setReposMessage(err instanceof ApiError ? err.message : 'Network error reaching the API.');
    } finally {
      setIsLoadingRepos(false);
      reposInflightRef.current = false;
    }
  }, [isLoadingRepos]);

  const [isPamModalOpen, setIsPamModalOpen] = useState(false);
  const [pamRole, setPamRole] = useState('production_admin');
  const [pamPermission, setPamPermission] = useState('deploy:execute');
  const [pamReason, setPamReason] = useState('');
  const [pamDuration, setPamDuration] = useState('60');

  const [isSsoModalOpen, setIsSsoModalOpen] = useState(false);
  const [ssoName, setSsoName] = useState('');
  const [ssoProviderType, setSsoProviderType] = useState('oidc');
  const [ssoIssuer, setSsoIssuer] = useState('');

  const [isDomainModalOpen, setIsDomainModalOpen] = useState(false);
  const [newDomainName, setNewDomainName] = useState('');

  // Dodo Payments Modal State
  const [isDodoModalOpen, setIsDodoModalOpen] = useState(false);
  const [dodoPackage, setDodoPackage] = useState<'starter' | 'pro' | 'enterprise'>('pro');
  const [dodoCheckoutUrl, setDodoCheckoutUrl] = useState('');



  const handleInitiateDodoCheckout = async (amount: number, packageName: string) => {
    setIsSubmitting(true);
    setModalError('');
    try {
      const res = await apiFetch('/payments/dodo/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          amount,
          package_name: packageName,
          currency: 'USD',
        }),
      });

      if (!res.ok) throw new Error('Failed to create Dodo Payments checkout session.');
      const data = await res.json();
      if (data.checkout_url) {
        setDodoCheckoutUrl(data.checkout_url);
        window.open(data.checkout_url, '_blank');
      }
    } catch (err: any) {
      setModalError(err.message || 'Checkout failed');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Auth & Navigation State
  const [authFormError, setAuthFormError] = useState('');

  // Dedupe guard for concurrent dashboard fetches
  const dashboardInflightRef = useRef(false);

  // Fetch all dashboard data via SINGLE batched endpoint (remedy: 8 → 1 request).
  // Falls back to legacy 8-call flow if batch endpoint is unavailable.
  const fetchDashboardData = useCallback(async (showSpinner = false, opts: { force?: boolean } = {}) => {
    if (dashboardInflightRef.current) return;
    const now = Date.now();
    if (!opts.force && _dashboardCache && (now - _dashboardCache.ts) < DASH_CACHE_TTL) {
      const d = _dashboardCache.data;
      setJobs(d.jobs || []); setSsoProviders(d.sso_providers || []); setPamRequests(d.pam_requests || []);
      setPamGrants(d.pam_grants || []); setIamPolicies(d.iam_policies || []); setDomains(d.domains || []);
      setActivities(d.activities || []); if (d.mfa_status) setMfaStatus(d.mfa_status);
      setLastSync(new Date(_dashboardCache.ts)); setDashError(null); setDashLoad('ready');
      return;
    }
    if (showSpinner) setDashLoad('loading');
    dashboardInflightRef.current = true;
    try {
      // Prefer batched summary: single auth validation + single round-trip
      const batchRes = await apiFetch('/dashboard/summary');
      if (batchRes.ok) {
        const d = await batchRes.json();
        _dashboardCache = { data: d, ts: Date.now() };
        setJobs(d.jobs || []); setSsoProviders(d.sso_providers || []); setPamRequests(d.pam_requests || []);
        setPamGrants(d.pam_grants || []); setIamPolicies(d.iam_policies || []); setDomains(d.domains || []);
        setActivities(d.activities || []); if (d.mfa_status) setMfaStatus(d.mfa_status);
        setDashError(null); setDashLoad('ready'); setLastSync(new Date());
        return;
      }
      // Fallback: legacy fan-out (if backend not yet deployed) — keep working
      const results = await Promise.allSettled([
        apiFetch('/audit/jobs'), apiFetch('/sso/providers'), apiFetch('/pam/requests'),
        apiFetch('/pam/grants'), apiFetch('/iam/policies'), apiFetch('/verify/domains'),
        apiFetch('/auth/activities'), apiFetch('/mfa/status'),
      ]) as PromiseSettledResult<Response>[];
      const [jobsRes, ssoRes, pamReqRes, pamGrantRes, iamRes, domainRes, actRes, mfaRes] = results;
      let jobsOk = false;
      const jobsHttp = jobsRes.status === 'fulfilled' ? jobsRes.value.status : null;
      if (jobsRes.status === 'fulfilled' && jobsRes.value.ok) { setJobs(await jobsRes.value.json()); jobsOk = true; }
      else if (jobsRes.status === 'rejected') { throw jobsRes.reason; }
      else if (jobsHttp === 401) { throw new Error('Session expired — please sign in again.'); }
      else { throw new Error(`Audit API returned HTTP ${jobsHttp}`); }
      if (ssoRes.status === 'fulfilled' && ssoRes.value.ok) setSsoProviders(await ssoRes.value.json());
      if (pamReqRes.status === 'fulfilled' && pamReqRes.value.ok) setPamRequests(await pamReqRes.value.json());
      if (pamGrantRes.status === 'fulfilled' && pamGrantRes.value.ok) setPamGrants(await pamGrantRes.value.json());
      if (iamRes.status === 'fulfilled' && iamRes.value.ok) setIamPolicies(await iamRes.value.json());
      if (domainRes.status === 'fulfilled' && domainRes.value.ok) setDomains(await domainRes.value.json());
      if (actRes.status === 'fulfilled' && actRes.value.ok) setActivities(await actRes.value.json());
      if (mfaRes.status === 'fulfilled' && mfaRes.value.ok) setMfaStatus(await mfaRes.value.json());
      setDashError(null); setDashLoad('ready'); if (jobsOk) setLastSync(new Date());
    } catch (err: any) {
      console.warn('Dashboard live data fetch error:', err);
      setDashError(err?.message || 'Network error — backend unreachable.');
      setDashLoad('error');
    } finally { dashboardInflightRef.current = false; }
  }, []);

  // Lightweight poll: only jobs (+ phases via separate call) when a job is running.
  // Saves ~7/8 requests per tick vs full fetchDashboardData.
  const fetchJobsLite = useCallback(async () => {
    try {
      const d = await api.jobsLite();
      setJobs(d.jobs ?? []);
      setLastSync(new Date());
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) { setAuthState('signed_out'); return; }
      try {
        // Fallback for backends predating /dashboard/jobs-lite.
        setJobs(await api.listJobs());
        setLastSync(new Date());
      } catch (fallbackErr) {
        if (fallbackErr instanceof ApiError && fallbackErr.status === 401) setAuthState('signed_out');
        /* else silent — next tick will retry */
      }
    }
  }, []);

  // Deep health telemetry (public endpoint). Operational status only: a healthy
  // database never implies any particular scan succeeded.
  useEffect(() => {
    if (!location.pathname.startsWith('/console')) return;
    let alive = true;
    const probe = async () => {
      try {
        // R-24: this used to strip the `/api/v1` prefix and request
        // `${base}/health/deep`, which the backend never serves. Through the
        // `_redirects` SPA fallback it received index.html with status 200, so
        // the widget reported "database unreachable" permanently. Use API_BASE.
        const res = await fetch(`${API_BASE}/health/deep`);
        if (!alive) return;
        setDeepHealth(res.ok ? await res.json() : { status: 'unhealthy', database: 'unavailable' });
      } catch {
        if (alive) setDeepHealth({ status: 'network_failure', database: 'unreachable' });
      }
    };
    probe();
    const t = setInterval(probe, 30000);
    return () => { alive = false; clearInterval(t); };
  }, [location.pathname]);

  // Cancel requests finalization; the worker owns the terminal write.
  const handleCancelJob = async (jobId: string) => {
    setCancellingIds((ids) => [...ids, jobId]);
    setCancelNote('');
    try {
      await api.cancelJob(jobId);
      setCancelNote('Cancellation requested — the worker is finalizing. Watch the live monitor for the terminal state.');
    } catch (err) {
      setModalError(err instanceof ApiError ? err.message : 'Network error while cancelling job.');
    } finally {
      setCancellingIds((ids) => ids.filter((id) => id !== jobId));
      fetchDashboardData(false, { force: true });
    }
  };

  // Retry queues a new attempt; history stays immutable. 409 when ineligible.
  const handleRetryJob = async (jobId: string) => {
    if (retryBusy) return;
    setRetryBusy(true);
    setModalError('');
    try {
      await api.retryJob(jobId);
      const req = inspectReqRef.current;
      try {
        const execs = await api.jobExecutions(jobId);
        if (inspectReqRef.current === req) {
          setExecutions(execs);
          const latest = [...execs].sort((a, b) => b.attempt_number - a.attempt_number)[0];
          if (latest) void selectExecution(jobId, latest.execution_id);
        }
      } catch { /* executions refresh is best-effort */ }
      fetchDashboardData(false, { force: true });
    } catch (err) {
      setModalError(err instanceof ApiError ? err.message : 'Network error requesting retry.');
    } finally {
      setRetryBusy(false);
    }
  };

  // Download the compiled markdown report for a completed job
  const handleDownloadReport = async (jobId: string) => {
    try {
      const res = await apiFetch(`/audit/job/${jobId}/report`);
      if (!res.ok) { setModalError(`Report unavailable (HTTP ${res.status})`); return; }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `firecrow-report-${jobId.substring(0, 8)}.md`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      setModalError('Network error while downloading report.');
    }
  };

  // MFA lifecycle (POST /mfa/enroll · POST /mfa/disable)
  const handleMfaEnroll = async () => {
    try {
      const res = await apiFetch('/mfa/enroll', { method: 'POST' });
      if (!res.ok) { setModalError(`MFA enrollment failed (HTTP ${res.status})`); return; }
      setMfaEnrollment(await res.json());
      fetchDashboardData(false, { force: true });
    } catch {
      setModalError('Network error during MFA enrollment.');
    }
  };

  const handleMfaDisable = async () => {
    try {
      const res = await apiFetch('/mfa/disable', { method: 'POST' });
      if (!res.ok) { setModalError(`MFA disable failed (HTTP ${res.status})`); return; }
      setMfaEnrollment(null);
      fetchDashboardData(false, { force: true });
    } catch {
      setModalError('Network error while disabling MFA.');
    }
  };

  // Live progress — SSE-first with strict rate-limit fallback (fixes “backend works but frontend blank”)
  const jobsRef = useRef(jobs);
  useEffect(() => { jobsRef.current = jobs; }, [jobs]);

  useEffect(() => {
    if (!location.pathname.startsWith('/console')) return;
    const targetJobId = activeMonitorJobId || (jobsRef.current.length > 0 ? jobsRef.current[0].id : null);
    if (!targetJobId) return;

    let sse: EventSource | null = null;
    let pollTimer: ReturnType<typeof setInterval> | null = null;
    let sseFailed = false;
    let cancelled = false;

    const fetchPhases = async () => {
      try {
        const phases = await api.jobPhases(targetJobId);
        if (!cancelled) setMonitorPhases(phases);
      } catch (err) {
        // Expired session must surface as signed-out, not poll forever.
        if (err instanceof ApiError && err.status === 401) setAuthState('signed_out');
        else console.warn('Error fetching job phases:', err);
      }
    };
    const isJobActive = () => {
      const j = jobsRef.current.find(x => x.id === targetJobId);
      return !j || j.status === 'running' || j.status === 'queued';
    };

    const startPolling = () => {
      if (cancelled || pollTimer) return;
      // Rate limit: 1x phases + 1x jobs-lite every 5s (was 9 req / 2s → now 0.4 req/s)
      fetchPhases();
      if (isJobActive()) void fetchJobsLite();
      if (!isJobActive()) return;
      pollTimer = setInterval(() => {
        if (document.hidden) return; // pause when tab hidden — zero stress when backgrounded
        if (!isJobActive()) { if (pollTimer) clearInterval(pollTimer); pollTimer = null; return; }
        void fetchPhases();
        void fetchJobsLite();
      }, 5000);
    };

    // SSE: Authenticate via HttpOnly credentials (withCredentials: true)
    const sseUrl = `${API_BASE}/sse/job/${targetJobId}`;

    try {
      sse = new EventSource(sseUrl, { withCredentials: true });
      const onUpdate = (ev: MessageEvent) => {
        const p = parseSsePayload(ev.data);
        if (!p) return;
        if (Array.isArray(p.phases)) setMonitorPhases(p.phases);
        if (p.job) setJobs(prev => {
          const exists = prev.some(x => x.id === p.job!.id);
          return exists ? prev.map(x => x.id === p.job!.id ? { ...x, ...p.job! } : x) : prev;
        });
      };
      const onDone = (ev: MessageEvent) => {
        const p = parseSsePayload(ev.data);
        if (p) {
          if (Array.isArray(p.phases)) setMonitorPhases(p.phases);
          if (p.job) setJobs(prev => prev.map(x => x.id === p.job!.id ? { ...x, ...p.job! } : x));
        }
        try { sse?.close(); } catch {}
        sse = null;
        void fetchJobsLite(); // final sync
      };
      const onErrorEvent = (ev: MessageEvent) => {
        const p = parseSsePayload(ev.data);
        // error payload is still useful — try to apply it before fallback.
        // A stream error never means completion: only a done event does.
        if (p?.error) console.warn('SSE job error event', p.error);
        if (p && Array.isArray(p.phases)) setMonitorPhases(p.phases);
      };
      sse.addEventListener('update', onUpdate as EventListener);
      sse.addEventListener('done', onDone as EventListener);
      sse.addEventListener('error', onErrorEvent as EventListener);
      sse.onerror = () => {
        if (sseFailed) return;
        sseFailed = true;
        try { sse?.close(); } catch {}
        sse = null;
        startPolling();
      };
      // If not OPEN in 2.5s → fallback (backend emits instantly, so this catches auth/firewall blocks)
      setTimeout(() => {
        if (!cancelled && sse && sse.readyState !== 1 && !sseFailed) {
          sseFailed = true; try { sse.close(); } catch {} sse = null; startPolling();
        }
      }, 2500);
      // If SSE never fires update within 4s, also trigger phases fetch to avoid blank
      setTimeout(() => { if (!cancelled && !sseFailed && sse) void fetchPhases(); }, 4000);
    } catch {
      startPolling();
    }

    // Safety net: if SSE object never created
    setTimeout(() => { if (!cancelled && !sse && !pollTimer) startPolling(); }, 3200);

    return () => {
      cancelled = true;
      try { sse?.close(); } catch {}
      if (pollTimer) clearInterval(pollTimer);
    };
  }, [location.pathname, activeMonitorJobId, fetchJobsLite]);




  // Auto-sync repositories — throttled to 30 s, manual refresh via button forces it
  useEffect(() => {
    if (user && view === 'dashboard') {
      fetchUserRepos(false);
    }
  }, [user, view, fetchUserRepos]);
  useEffect(() => {
    if (user && (isScanModalOpen || activeWindow === 'overview')) {
      fetchUserRepos(false);
    }
  }, [user, isScanModalOpen, activeWindow, fetchUserRepos]);

  const oauthHandledRef = useRef(false);
  const sessionCheckedRef = useRef(false);

  // Check active session or OAuth exchange on mount
  useEffect(() => {
    const checkSession = async () => {
      try {
        const data = await api.me();
        setUser({
          user_id: data.user_id,
          username: data.username,
          email: data.email,
          credit_balance: data.credit_balance,
        });
        setAuthState('authenticated');
        navigate('/console/overview');
        fetchDashboardData(true, { force: true });
      } catch (err) {
        // No session (401) or unreachable backend: stay signed out, never
        // fabricate a user from a failed response.
        console.warn('No active session found:', err);
        setUser(null);
        setAuthState('signed_out');
      } finally {
        setIsLoading(false);
      }
    };

    const handleOAuthCallback = async (code: string) => {
      setIsLoading(true);
      setAuthState('initializing');
      setError('');
      try {
        const exchangeData = await api.exchangeCode(code);

        if (exchangeData.user_id && exchangeData.username) {
          setUser({
            user_id: exchangeData.user_id,
            username: exchangeData.username,
            email: exchangeData.email || null,
          });
          setAuthState('authenticated');
          navigate('/console/overview');
          fetchDashboardData(false, { force: true });
        }

        try {
          const data = await api.me();
          setUser({
            user_id: data.user_id,
            username: data.username,
            email: data.email,
            credit_balance: data.credit_balance,
          });
          setAuthState('authenticated');
          navigate('/console/overview');
        } catch {
          // If background meRes fails, remain logged in via exchangeData
        }
      } catch (err) {
        setAuthState('error');
        setError(err instanceof ApiError ? err.message : 'Authentication failed. Please try again.');
        navigate('/login');
      } finally {
        setIsLoading(false);
      }
    };

    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const oauthError = params.get('oauth_error');

    if (oauthError) {
      setAuthState('error');
      setError(`OAuth login failed: ${decodeURIComponent(oauthError)}`);
      navigate('/login');
      window.history.replaceState({}, document.title, window.location.pathname);
      setIsLoading(false);
    } else if (code) {
      if (oauthHandledRef.current) return;
      oauthHandledRef.current = true;
      // Single-use code: strip it from the URL immediately so it never lingers
      // in history, logs, or shared links.
      window.history.replaceState({}, document.title, window.location.pathname);
      handleOAuthCallback(code);
    } else {
      if (sessionCheckedRef.current) return;
      sessionCheckedRef.current = true;
      checkSession();
    }
  }, [fetchDashboardData]);

  const handleGitHubLogin = () => {
    const privacyVersion = '2026-06-06';
    window.location.href = `${API_BASE}/auth/github?privacy_policy_accepted=true&privacy_policy_version=${privacyVersion}`;
  };

  const handleLogout = async () => {
    setIsLoading(true);
    try {
      // Server response clears the HttpOnly session cookies.
      await api.logout();
    } catch (err) {
      console.error('Logout error:', err);
    } finally {
      setUser(null);
      setAuthState('signed_out');
      setJobs([]);
      setSelectedJobDetail(null);
      setSelectedFinding(null);
      setSsoProviders([]);
      setPamRequests([]);
      setPamGrants([]);
      setIamPolicies([]);
      setDomains([]);
      setActivities([]);
      setMfaStatus({ enabled: false, backup_codes_remaining: 0 });
      navigate('/');
      setIsLoading(false);
    }
  };

  // Submit real audit job — only SubmitJobRequest fields. Backend validates the
  // URL/branch/SHA and enforces the per-user active-job cap (409) itself.
  const openScanModal = () => { setModalError(''); setIsScanModalOpen(true); };
  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    const repoUrl = newRepoUrl.trim();
    const branch = newRepoBranch.trim() || 'main';
    const sha = newCommitSha.trim();
    if (!repoUrl) return;
    if (sha && !isValidCommitSha(sha)) {
      setModalError('Commit SHA must be a 40-character lowercase hex digest, or left empty to scan the branch head.');
      return;
    }
    if (isSubmitting) return; // duplicate-click guard

    setModalError('');
    setIsSubmitting(true);

    try {
      const job = await api.submitJob(buildSubmitRequest({ repoUrl, repoBranch: branch, commitSha: sha }));
      setIsScanModalOpen(false);
      setNewRepoUrl('');
      setNewCommitSha('');
      setActiveMonitorJobId(job.id);
      navigate('/console/jobs');
      fetchDashboardData(false, { force: true });
    } catch (err) {
      // Values retained; no success screen on failure. 409 names the cap.
      setModalError(err instanceof ApiError ? err.message : 'Network error submitting scan job.');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Submit real PAM Request
  const handleCreatePamRequest = async (e: React.FormEvent) => {
    e.preventDefault();
    setModalError('');
    setIsSubmitting(true);
    try {
      const res = await apiFetch('/pam/requests', {
        method: 'POST',
        body: JSON.stringify({
          role_name: pamRole,
          permission: pamPermission,
          reason: pamReason,
          requested_duration_minutes: parseInt(pamDuration) || 60,
          ticket_ref: `REF-${Math.floor(Math.random() * 9000 + 1000)}`,
          id: '',
          user_id: '',
          status: 'pending',
          created_at: new Date().toISOString(),
        }),
      });
      if (res.ok) {
        setIsPamModalOpen(false);
        setPamReason('');
        fetchDashboardData(false, { force: true });
      } else {
        const errData = await res.json().catch(() => ({}));
        setModalError(errData.message || errData.error || 'Failed to create PAM request.');
      }
    } catch (err: any) {
      setModalError(err.message || 'Network error creating PAM request.');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Submit real SSO Provider
  const handleCreateSsoProvider = async (e: React.FormEvent) => {
    e.preventDefault();
    setModalError('');
    setIsSubmitting(true);
    try {
      const res = await apiFetch('/sso/providers', {
        method: 'POST',
        body: JSON.stringify({
          id: '',
          name: ssoName,
          provider_type: ssoProviderType,
          issuer_url: ssoIssuer,
          client_id: `client_${Math.random().toString(36).substring(2, 10)}`,
          created_at: new Date().toISOString(),
        }),
      });
      if (res.ok) {
        setIsSsoModalOpen(false);
        setSsoName('');
        setSsoIssuer('');
        fetchDashboardData(false, { force: true });
      } else {
        const errData = await res.json().catch(() => ({}));
        setModalError(errData.message || errData.error || 'Failed to save SSO provider.');
      }
    } catch (err: any) {
      setModalError(err.message || 'Network error adding SSO provider.');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Initiate real Domain Verification
  const handleInitiateDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDomainName) return;
    setModalError('');
    setIsSubmitting(true);
    try {
      const res = await apiFetch('/verify/domains/initiate', {
        method: 'POST',
        body: JSON.stringify({ domain: newDomainName }),
      });
      if (res.ok) {
        setIsDomainModalOpen(false);
        setNewDomainName('');
        fetchDashboardData(false, { force: true });
      } else {
        const errData = await res.json().catch(() => ({}));
        setModalError(errData.message || errData.error || 'Failed to initiate domain verification.');
      }
    } catch (err: any) {
      setModalError(err.message || 'Network error initiating domain verification.');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Execution-scoped report + narrative for one attempt. Stale responses (a
  // newer attempt selected mid-flight) are dropped, never applied.
  const loadExecutionData = async (jobId: string, executionId: string, req: number) => {
    setReportState('loading');
    setReportError('');
    setNarrative(null);
    setNarrativeState('loading');
    setNarrativeError('');
    try {
      const rep = await api.executionReportJson(jobId, executionId);
      if (inspectReqRef.current !== req) return;
      setExecReport(rep);
      setReportState('ready');
    } catch (err) {
      if (inspectReqRef.current !== req) return;
      setExecReport(null);
      setReportState('error');
      setReportError(err instanceof ApiError ? err.message : 'Network error loading report.');
    }
    try {
      const n = await api.getNarrative(jobId, executionId);
      if (inspectReqRef.current !== req) return;
      setNarrative(n.narrative);
      setNarrativeState('ready');
    } catch (err) {
      if (inspectReqRef.current !== req) return;
      // 404 = no narrative yet: offer generation. Anything else surfaces.
      if (err instanceof ApiError && err.status === 404) {
        setNarrativeState('idle');
      } else {
        setNarrativeState('error');
        setNarrativeError(err instanceof ApiError ? err.message : 'Network error loading narrative.');
      }
    }
  };

  const selectExecution = async (jobId: string, executionId: string) => {
    const req = ++inspectReqRef.current;
    setSelectedExecutionId(executionId);
    setDeliveryMsg('');
    await loadExecutionData(jobId, executionId, req);
  };

  // Fetch specific job details + attempt history
  const handleViewJobDetail = async (jobId: string) => {
    const req = ++inspectReqRef.current;
    setSelectedJobDetail({ job: { id: jobId } as JobResponse, findings: [] });
    setDetailLoading(true);
    setModalError('');
    setExecutions([]);
    setSelectedExecutionId(null);
    setExecReport(null);
    setReportState('idle');
    setReportError('');
    setNarrative(null);
    setNarrativeState('idle');
    setNarrativeError('');
    setFindingQuery('');
    setFindingSev('all');
    setDeliveryMsg('');
    setCancelNote('');
    try {
      const detail = await api.jobDetail(jobId);
      if (inspectReqRef.current !== req) return;
      setSelectedJobDetail(detail);
      if (detail.findings && detail.findings.length > 0) {
        setSelectedFinding(detail.findings[0]);
      }
    } catch (err) {
      if (inspectReqRef.current !== req) return;
      console.error('Fetch job detail error:', err);
      setModalError(err instanceof ApiError ? err.message : 'Network error while loading job details.');
      closeInspector();
      setDetailLoading(false);
      return;
    } finally {
      if (inspectReqRef.current === req) setDetailLoading(false);
    }
    try {
      setExecLoading(true);
      const execs = await api.jobExecutions(jobId);
      if (inspectReqRef.current !== req) return;
      setExecutions(execs);
      // Default to the latest attempt only on open — never switch mid-view.
      const latest = [...execs].sort((a, b) => b.attempt_number - a.attempt_number)[0];
      if (latest) {
        setSelectedExecutionId(latest.execution_id);
        await loadExecutionData(jobId, latest.execution_id, req);
      }
    } catch {
      if (inspectReqRef.current === req) setExecutions([]);
    } finally {
      if (inspectReqRef.current === req) setExecLoading(false);
    }
  };

  // AI narrative is optional annotation: failure never touches the report.
  const handleGenerateNarrative = async () => {
    const d = selectedJobDetail;
    if (!d || !selectedExecutionId || narrativeState === 'loading') return;
    setNarrativeState('loading');
    setNarrativeError('');
    const req = inspectReqRef.current;
    try {
      const n = await api.generateNarrative(d.job.id, selectedExecutionId);
      if (inspectReqRef.current !== req) return;
      setNarrative(n.narrative);
      setNarrativeState('ready');
      try {
        const execs = await api.jobExecutions(d.job.id);
        if (inspectReqRef.current === req) setExecutions(execs);
      } catch { /* flag refresh is best-effort */ }
    } catch (err) {
      if (inspectReqRef.current !== req) return;
      setNarrativeState('error');
      setNarrativeError(err instanceof ApiError ? err.message : 'Network error generating narrative.');
    }
  };

  // Delivery reports the backend's persisted outcome — never claims sent on request.
  const handleDeliver = async (channel: 'email' | 'telegram') => {
    const d = selectedJobDetail;
    if (!d || !selectedExecutionId || deliveryBusy) return;
    const label = channel === 'email' ? 'account email' : 'configured Telegram chat';
    if (!window.confirm(`Send this attempt's report to the ${label}?`)) return;
    setDeliveryBusy(channel);
    setDeliveryMsg('');
    // A closed dialog invalidates the request: late responses must not write
    // into a reopened view, same lifecycle as report/narrative loads.
    const req = inspectReqRef.current;
    try {
      const res = channel === 'email'
        ? await api.emailReport(d.job.id, selectedExecutionId)
        : await api.telegramReport(d.job.id, selectedExecutionId);
      if (inspectReqRef.current !== req) return;
      setDeliveryMsg(res.status === 'already_sent' ? 'Already delivered.' : `Delivered (${res.status}).`);
    } catch (err) {
      if (inspectReqRef.current !== req) return;
      setDeliveryMsg(err instanceof ApiError ? err.message : 'Network error requesting delivery.');
    } finally {
      if (inspectReqRef.current === req) setDeliveryBusy(null);
    }
  };

  const downloadTextFile = (name: string, text: string, mime: string) => {
    const blob = new Blob([text], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Execution-scoped downloads. HTML is a file download, never injected.
  const handleDownloadExecutionReport = async (format: 'markdown' | 'json' | 'html') => {
    const d = selectedJobDetail;
    if (!d || !selectedExecutionId) return;
    const ext = format === 'json' ? 'json' : format === 'html' ? 'html' : 'md';
    try {
      const text = format === 'json'
        ? JSON.stringify(await api.executionReportJson(d.job.id, selectedExecutionId), null, 2)
        : await api.executionReportText(d.job.id, selectedExecutionId, format);
      downloadTextFile(
        `firecrow-report-${d.job.id.substring(0, 8)}-attempt-${ext}.${ext}`,
        text,
        format === 'html' ? 'text/html' : 'text/plain;charset=utf-8',
      );
    } catch (err) {
      setModalError(err instanceof ApiError ? err.message : 'Network error downloading report.');
    }
  };

  // Overview derivations — counts only from jobs[]; findings live per audit.
  const completedCount = jobs.filter(j => j.status === 'completed').length;
  const reportsReady = jobs.filter(j => j.status === 'completed' && j.report_pdf_url).length;
  // Latest audits that actually produced a result — the only place a
  // dashboard-wide "outcome" list can be honest.
  const latestResults = jobs.filter(j => j.status === 'completed').slice(0, 3);
  // GitHub connection state as the backend reports it (never invented).
  const repoConnectionText = () => {
    switch (reposStatus) {
      case 'loading': return 'Syncing your GitHub repositories…';
      case 'ready': return `${userRepos.length} ${userRepos.length === 1 ? 'repository' : 'repositories'} available to audit.`;
      case 'not_connected': return 'GitHub is not connected — connect GitHub, or paste a public repository URL.';
      case 'github_error': return 'Repository sync failed — you can still paste a public repository URL.';
      case 'network_error': return 'Repository sync is unreachable — you can still paste a public repository URL.';
      default: return 'Paste a repository URL, or pick a synced GitHub repository.';
    }
  };

  const isLanding = location.pathname === '/' ;
  const isLogin = location.pathname === '/login';
  const isConsole = location.pathname.startsWith('/console');

  // Guard: unauthenticated console access returns to login (401 contract).
  useEffect(() => {
    if (isConsole && !user && (authState === 'signed_out' || authState === 'error')) {
      navigate('/login');
    }
  }, [isConsole, user, authState, navigate]);

  if (authState === 'initializing' || isLoading) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', backgroundColor: 'var(--bg-primary)', color: 'var(--text-primary)', fontFamily: 'var(--font-sans)' }}>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1.25rem' }}>
          <div style={{ width: '32px', height: '32px', borderRadius: '50%', border: '3px solid rgba(255,255,255,0.1)', borderTopColor: '#fff', animation: 'spin 0.8s linear infinite' }}></div>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', letterSpacing: '0.1em', fontWeight: 600 }}>VERIFYING AUTHENTICATION SESSION...</span>
        </div>
      </div>
    );
  }

  // Render Landing View
  if (isLanding) {
    return (
      <LandingPage
        user={user}
        onNavigateLogin={() => navigate('/login')}
        onInitiateCheckout={handleInitiateDodoCheckout}
      />
    );
  }

  // Render Login View
  if (isLogin) {
    return (
      <LoginPage
        onNavigateLanding={() => navigate('/')}
        onGitHubLogin={handleGitHubLogin}
        error={error}
        authFormError={authFormError}
        clearErrors={() => { setError(''); setAuthFormError(''); }}
      />
    );
  }

  // Render Dashboard View — per-function windows with proper navigation
  if (!isConsole) {
    // fallback: unknown route -> landing
    return (
      <LandingPage user={user} onNavigateLogin={() => navigate('/login')} onInitiateCheckout={handleInitiateDodoCheckout} />
    );
  }
  return (
    <div className="shell">
      {/* Ambient 3D Aurora Backdrop */}
      <AuroraBackdrop variant="dashboard" />

      {/* Hover Navigation Island — collapses to icon rail, expands on hover */}
      <nav className="nav-island" aria-label="Dashboard navigation">
        <div className="island-brand">
          <img src="/fire-crow-logo.png" alt="Fire Crow" className="island-logo" />
          <span className="island-label island-brand-text">Fire Crow</span>
        </div>

        <div className="island-divider" />

        {([
          {
            group: 'Security work',
            items: [
              { id: 'overview', label: 'Overview', desc: 'Audit activity and next steps', icon: (
                <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
              ) },
              { id: 'jobs', label: 'Audit Jobs', desc: 'Every repository audit', badge: jobs.length, icon: (
                <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M9 15h6M9 11h3"/></svg>
              ) },
            ],
          },
          {
            group: 'Operations',
            items: [
              { id: 'diagnostics', label: 'Service Status', desc: 'Health of the audit service', icon: (
                <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
              ) },
            ],
          },
          {
            group: 'Access & administration',
            items: [
              { id: 'sso', label: 'SSO', desc: 'Sign-on providers', badge: ssoProviders.length, icon: (
                <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>
              ) },
              { id: 'pam', label: 'PAM', desc: 'Privileged access requests', badge: pamRequests.length, icon: (
                <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
              ) },
              { id: 'iam', label: 'IAM', desc: 'Access policies', badge: iamPolicies.length, icon: (
                <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M19 8v6M22 11h-6"/></svg>
              ) },
              { id: 'domains', label: 'Domains', desc: 'Domain verification', badge: domains.length, icon: (
                <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 4 9 15 15 0 0 1-4 9 15 15 0 0 1-4-9 15 15 0 0 1 4-9z"/></svg>
              ) },
              { id: 'mfa', label: 'MFA', desc: 'Two-factor authentication', badge: mfaStatus.enabled ? 1 : 0, icon: (
                <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><circle cx="12" cy="16" r="1"/></svg>
              ) },
              { id: 'activity', label: 'Activity', desc: 'Security event log', badge: activities.length, icon: (
                <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
              ) },
            ],
          },
        ] as const).map((section) => (
          <div key={section.group} className="island-group">
            <div className="island-group-label">{section.group}</div>
            {section.items.map((item) => (
              <button
                key={item.id}
                className={`island-item ${activeWindow === item.id ? 'active' : ''}`}
                onClick={() => navigate(`/console/${item.id}`)}
                title={item.label}
                aria-label={item.label}
                aria-current={activeWindow === item.id ? 'page' : undefined}
              >
                <span className="island-item-icon">{item.icon}</span>
                <span className="island-item-text">
                  <span className="island-label">{item.label}</span>
                  <span className="island-item-desc">{item.desc}</span>
                </span>
                {'badge' in item && item.badge > 0 && <span className="island-badge">{item.badge}</span>}
              </button>
            ))}
          </div>
        ))}

        <div className="island-flex-spacer" />

        <div className="island-user">
          <div className="island-avatar">{user?.username ? user.username[0].toUpperCase() : 'U'}</div>
          <span className="island-label island-username">{user?.username}</span>
          <button onClick={handleLogout} className="island-logout" title="Sign Out" aria-label="Sign out">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
              <polyline points="16 17 21 12 16 7"/>
              <line x1="21" y1="12" x2="9" y2="12"/>
            </svg>
          </button>
        </div>
      </nav>

      {/* Main Container */}
      <main className="main-content">
        {/* Topbar — persistent controls. Section titles live in the page body:
            the overview owns its own H1, so no duplicate heading here. */}
        <div className="topbar">
          {activeWindow !== 'overview' && (
            <div>
              <div className="topbar-title">
                {activeWindow === 'jobs' && 'Audit Jobs'}
                {activeWindow === 'diagnostics' && 'Service Status'}
                {activeWindow === 'sso' && 'SSO Providers'}
                {activeWindow === 'pam' && 'Privileged Access'}
                {activeWindow === 'iam' && 'IAM Policies'}
                {activeWindow === 'domains' && 'Domain Verification'}
                {activeWindow === 'mfa' && 'MFA & Keys'}
                {activeWindow === 'activity' && 'Activity & Logs'}
              </div>
              <div className="topbar-subtitle">
                Signed in as {user?.username ?? 'unknown'}
              </div>
            </div>
          )}

          <div className="topbar-right">
            <ToastHost toasts={toasts} onDismiss={dismissToast} />

            {/* Dynamic Theme Picker */}
            <div className={`theme-picker ${themeMenuOpen ? 'open' : ''}`} onMouseLeave={() => setThemeMenuOpen(false)}>
              <button
                className={`theme-btn ${themeMenuOpen ? 'active' : ''}`}
                onClick={() => setThemeMenuOpen((open) => !open)}
                onMouseEnter={() => setThemeMenuOpen(true)}
                title="Theme"
                aria-label="Change accent theme"
              >
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="9"/>
                  <path d="M12 3a9 9 0 0 0 0 18c1.5 0 2-.8 2-1.6 0-1.3-1.2-1.6-1.2-2.7 0-.9.7-1.7 1.9-1.7H16a5 5 0 0 0 5-5c0-3.9-4-7-9-7z"/>
                </svg>
              </button>
              <div className="theme-menu">
                {([
                  { id: 'ember', color: '#ff6b00', name: 'Ember' },
                  { id: 'azure', color: '#2997ff', name: 'Azure' },
                  { id: 'violet', color: '#bf5af2', name: 'Violet' },
                  { id: 'mint', color: '#4ade80', name: 'Mint' },
                ] as const).map((t) => (
                  <button
                    key={t.id}
                    className={`theme-swatch ${themeAccent === t.id ? 'selected' : ''}`}
                    onClick={() => { setThemeAccent(t.id); setThemeMenuOpen(false); }}
                    title={t.name}
                  >
                    <span className="swatch-dot" style={{ background: t.color }} />
                    <span className="island-label">{t.name}</span>
                    {themeAccent === t.id && (
                      <svg className="swatch-check" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg>
                    )}
                  </button>
                ))}
              </div>
            </div>

            <button onClick={handleLogout} className="topbar-avatar" title="Sign Out" aria-label="Sign out">
              {user?.username ? user.username[0].toUpperCase() : 'U'}
            </button>
          </div>
        </div>

        {/* Page Content Body */}
        <div className="page-body">
          {/* Tab 1: Overview */}
          {activeWindow === 'overview' && (
            <>
              {dashLoad === 'error' && (
                <div className="dash-error-banner">
                  <span>{dashError}</span>
                  <button className="btn btn-secondary btn-sm" onClick={() => fetchDashboardData(true, { force: true })}>Retry</button>
                </div>
              )}

              {/* Page introduction: customer-facing heading, one obvious action.
                  Infrastructure identifiers never appear here — service health
                  lives in the Service Status window. */}
              <header className="page-head">
                <div className="page-head-main">
                  <p className="page-eyebrow">Security workspace</p>
                  <h1 className="page-head-title">Security Overview</h1>
                  <p className="page-head-sub">
                    Track repository audits, review findings and reports, and start the next audit.
                  </p>
                </div>
                <div className="page-head-side">
                  {dashLoad === 'ready' && lastSync && (
                    <span className="page-head-meta">
                      <span className="status-dot status-dot-live" aria-hidden="true" />
                      Synced {timeAgo(lastSync.toISOString())}
                    </span>
                  )}
                  {/* Audit-service availability: reporting-only, never a scan claim. */}
                  <BackendStatusIndicator
                    onTransition={(prev, next) => {
                      const decision = transitionToast(prev, next);
                      if (decision === 'none') return;
                      pushToast(TOAST_COPY[decision].tone, TOAST_COPY[decision].message);
                    }}
                  />
                  <button onClick={() => { openScanModal(); }} className="btn btn-primary">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" aria-hidden="true"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                    New audit
                  </button>
                </div>
              </header>

              {/* Metrics — real security-workflow counts only. No trends,
                  no invented scores or findings totals: every value is derived
                  from jobs[] fields the backend actually returns. Findings are
                  reported per audit, so no dashboard-wide finding count exists. */}
              <div className="metrics-grid">
                <MetricCard
                  icon={<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>}
                  label="Audits completed"
                  value={jobs.filter(j => j.status === 'completed').length}
                  hint="finished audit runs"
                />
                <MetricCard
                  icon={<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>}
                  label="Running now"
                  value={jobs.filter(j => j.status === 'running' || j.status === 'queued').length}
                  hint="queued or scanning"
                  tone={jobs.some(j => j.status === 'running' || j.status === 'queued') ? 'accent' : 'neutral'}
                />
                <MetricCard
                  icon={<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg>}
                  label="Reports ready"
                  value={jobs.filter(j => j.status === 'completed' && j.report_pdf_url).length}
                  hint="available to download"
                />
                <MetricCard
                  icon={<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/></svg>}
                  label="Needs attention"
                  value={jobs.filter(j => j.status === 'failed' || j.status === 'cancelled').length}
                  hint="failed or cancelled audits"
                  tone={jobs.some(j => j.status === 'failed' || j.status === 'cancelled') ? 'crit' : 'neutral'}
                />
              </div>

              {/* Live audit — only while a job is genuinely running or queued */}
              {(() => {
                const activeMonitorJob = jobs.find(j => j.id === (activeMonitorJobId || ''));
                const job = (activeMonitorJob && (activeMonitorJob.status === 'running' || activeMonitorJob.status === 'queued'))
                  ? activeMonitorJob
                  : jobs.find(j => j.status === 'running' || j.status === 'queued') || null;
                if (!job) return null;

                const phaseOrder = ['intake', 'recon', 'scanning', 'ai_analysis', 'remediation', 'attack_graph', 'reporting'];
                const phaseLabels: Record<string, string> = {
                  intake: 'Intake', recon: 'Recon', scanning: 'Scanning', ai_analysis: 'AI analysis',
                  remediation: 'Remediation', attack_graph: 'Attack graph', reporting: 'Reporting',
                };
                const isRunning = job.status === 'running' || job.status === 'queued';

                let pct = 0;
                if (job.status === 'completed') pct = 100;
                else if (job.status === 'queued') pct = 8;
                else if (!isRunning) pct = 100;
                else {
                  const done = monitorPhases.filter(p => p.status === 'completed').length;
                  const hasStarted = monitorPhases.some(p => p.status === 'started' || p.status === 'running');
                  pct = Math.min(95, Math.max(12, Math.round((done / phaseOrder.length) * 100) + (hasStarted ? 8 : 0)));
                }

                const createdUtc = job.created_at.includes('T') ? job.created_at : job.created_at.replace(' ', 'T') + 'Z';
                const elapsed = Math.max(0, Math.floor((Date.now() - new Date(createdUtc).getTime()) / 1000));
                const elapsedStr = elapsed < 60 ? `${elapsed}s` : `${Math.floor(elapsed / 60)}m ${elapsed % 60}s`;

                return (
                  <section className="panel live-audit" aria-label="Audit in progress">
                    <div className="live-audit-head">
                      <div className="live-audit-id">
                        <p className="live-audit-eyebrow">Audit in progress</p>
                        <h2 className="live-audit-repo">{repoLabel(job.repo_url)}</h2>
                        <p className="live-audit-meta">
                          <span className="audit-row-branch">{job.repo_branch}</span>
                          <span aria-hidden="true">·</span>
                          <span>started {timeAgo(job.created_at) || 'just now'}</span>
                          <span aria-hidden="true">·</span>
                          <span>{elapsedStr} elapsed</span>
                        </p>
                      </div>
                      <div className="live-audit-side">
                        <StatusPill status={job.status} />
                        <button
                          onClick={() => { handleViewJobDetail(job.id); setActiveMonitorJobId(job.id); }}
                          className="btn btn-secondary btn-sm"
                        >
                          View progress
                        </button>
                      </div>
                    </div>

                    <div className="live-audit-bar">
                      <div className="live-audit-track">
                        <div className={`live-audit-fill${isRunning ? ' is-running' : ''}`} style={{ width: `${pct}%` }} />
                      </div>
                      <span className="live-audit-pct">{pct}%</span>
                    </div>

                    <ol className="live-audit-phases">
                      {phaseOrder.map(phase => {
                        const logged = monitorPhases.find(p => p.phase_name.toLowerCase() === phase);
                        const done = job.status === 'completed' || (logged && logged.status === 'completed');
                        const active = isRunning && logged && logged.status === 'started';
                        const failedPhase = logged && logged.status === 'failed';
                        return (
                          <li
                            key={phase}
                            className={`live-phase${done ? ' is-done' : ''}${active ? ' is-active' : ''}${failedPhase ? ' is-failed' : ''}`}
                            aria-current={active ? 'step' : undefined}
                          >
                            <span className="live-phase-dot" aria-hidden="true" />
                            {phaseLabels[phase]}
                          </li>
                        );
                      })}
                    </ol>
                  </section>
                );
              })()}

              {/* Primary operational surface: audits + the guided path to a result */}
              <div className="overview-grid">
                <div className="overview-main">
                  <section className="panel">
                    <div className="panel-header">
                      <div>
                        <h2 className="panel-title">Recent audits</h2>
                        <p className="panel-sub">
                          {jobs.length > 0
                            ? `Latest ${Math.min(jobs.length, 8)} of ${jobs.length}`
                            : 'Your repository audits appear here'}
                        </p>
                      </div>
                      {jobs.length > 0 && (
                        <button onClick={() => navigate('/console/jobs')} className="btn btn-ghost btn-sm panel-link">
                          View all
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" aria-hidden="true"><polyline points="9 18 15 12 9 6"/></svg>
                        </button>
                      )}
                    </div>
                    <div className="panel-body">
                      {jobs.length > 0 && (
                        <div className="status-mix">
                          {jobStatusMix(jobs).map(({ status, n }) => {
                            const info = jobStatusInfo(status);
                            return (
                              <span key={status} className={`status-pill status-${status}`}>
                                <span className="status-dot" aria-hidden="true" />
                                {n} {info.label.toLowerCase()}
                              </span>
                            );
                          })}
                        </div>
                      )}
                      <PanelState state={dashLoad} error={dashError} empty={jobs.length === 0} rows={4} onRetry={() => fetchDashboardData(true, { force: true })}>
                        {jobs.length === 0 ? (
                          <EmptyState
                            title="No audits yet"
                            body="Submit a repository to run your first audit. Findings, scores and reports appear here as each audit completes."
                            action={
                              <button onClick={() => { openScanModal(); }} className="btn btn-primary btn-sm">Start an audit</button>
                            }
                          />
                        ) : (
                          <div className="audit-list">
                            {jobs.slice(0, 8).map(j => (
                              <AuditRow
                                key={j.id}
                                job={j}
                                active={activeMonitorJobId === j.id}
                                onOpen={() => { handleViewJobDetail(j.id); setActiveMonitorJobId(j.id); }}
                              />
                            ))}
                          </div>
                        )}
                      </PanelState>
                    </div>
                  </section>

                  {/* Findings & outcomes — findings exist per audit attempt, so
                      this section routes to the existing results experience
                      instead of inventing a dashboard-wide findings feed. */}
                  <section className="panel">
                    <div className="panel-header">
                      <div>
                        <h2 className="panel-title">Findings &amp; results</h2>
                        <p className="panel-sub">Severity, evidence and remediation are reported per audit.</p>
                      </div>
                    </div>
                    <div className="panel-body results-body">
                      {latestResults.length > 0 ? (
                        <>
                          <div className="result-list">
                            {latestResults.map(j => (
                              <div key={j.id} className="result-row">
                                <div className="result-row-main">
                                  <span className="result-row-repo">{repoLabel(j.repo_url)}</span>
                                  <span className="result-row-meta">
                                    <span className="audit-row-branch">{j.repo_branch}</span>
                                    <span aria-hidden="true">·</span>
                                    <span>{timeAgo(j.created_at) || 'just now'}</span>
                                  </span>
                                </div>
                                {j.security_score != null && (
                                  <span className="result-score" title={`Security score ${j.security_score}/10`}>
                                    {j.security_score.toFixed(1)}
                                  </span>
                                )}
                                <button
                                  onClick={() => { handleViewJobDetail(j.id); setActiveMonitorJobId(j.id); }}
                                  className="btn btn-secondary btn-sm"
                                >
                                  Open findings
                                </button>
                              </div>
                            ))}
                          </div>
                          <p className="panel-note">
                            Open an audit to review its findings in full: severity, file and line, evidence,
                            and the deterministic report for each attempt.
                          </p>
                        </>
                      ) : (
                        <p className="panel-note">
                          Open an audit to review its findings: severity, file and line, evidence,
                          and the deterministic report for each attempt.
                        </p>
                      )}
                      <div className="results-actions">
                        <button onClick={() => navigate('/console/jobs')} className="btn btn-ghost btn-sm">
                          Browse all audits
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" aria-hidden="true"><polyline points="9 18 15 12 9 6"/></svg>
                        </button>
                      </div>
                    </div>
                  </section>
                </div>

                {/* Aside: the path from repository → audit → result, with real
                    GitHub connection state. No invented repositories or statuses. */}
                <aside className="overview-side">
                  <section className="panel flow-panel">
                    <div className="panel-header">
                      <h2 className="panel-title">Your next step</h2>
                    </div>
                    <div className="panel-body">
                      <ol className="flow-steps">
                        <li className="flow-step">
                          <div className="flow-step-head">
                            <span className="flow-num" aria-hidden="true">1</span>
                            <h3 className="flow-step-title">Pick a repository</h3>
                          </div>
                          <p className="flow-step-text">{repoConnectionText()}</p>
                          <button onClick={() => { openScanModal(); }} className="btn btn-primary btn-sm">New audit</button>
                        </li>
                        <li className="flow-step">
                          <div className="flow-step-head">
                            <span className="flow-num" aria-hidden="true">2</span>
                            <h3 className="flow-step-title">Review the findings</h3>
                          </div>
                          <p className="flow-step-text">
                            Every audit reports severity, evidence and remediation for each confirmed finding.
                          </p>
                        </li>
                        <li className="flow-step">
                          <div className="flow-step-head">
                            <span className="flow-num" aria-hidden="true">3</span>
                            <h3 className="flow-step-title">Keep the record</h3>
                          </div>
                          <p className="flow-step-text">
                            {reportsReady} of {completedCount} completed audits have a downloadable report.
                          </p>
                        </li>
                      </ol>
                      <div className="flow-foot">
                        <span>Service internals and health detail</span>
                        <button onClick={() => navigate('/console/diagnostics')} className="btn btn-ghost btn-sm">
                          Service status
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" aria-hidden="true"><polyline points="9 18 15 12 9 6"/></svg>
                        </button>
                      </div>
                    </div>
                  </section>
                </aside>
              </div>
            </>
          )}

          {/* Window: Service Status — operational infrastructure detail,
              intentionally secondary: service availability, never scan claims.
              Audit-level outcomes live on each audit job, not here. */}
          {activeWindow === 'diagnostics' && (
            <div className="panel">
              <div className="panel-header">
                <div>
                  <h2 className="panel-title">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
                    Service status
                  </h2>
                  <p className="panel-sub">Availability of the audit service and its internal dependencies.</p>
                </div>
                {(() => {
                  const cbOpen = Object.values(deepHealth?.circuit_breakers || {}).some(cb => cb.state !== 'closed');
                  const ok = !!(deepHealth
                    && (deepHealth.database === 'ok' || deepHealth.database === 'connected')
                    && (deepHealth.local_storage == null || deepHealth.local_storage === 'ok')
                    && (deepHealth.object_storage == null || deepHealth.object_storage === 'ok' || deepHealth.object_storage === 'disabled')
                    && !cbOpen);
                  if (!deepHealth) return <span className="health-chip probe">Probing</span>;
                  return ok
                    ? <span className="health-chip ok">Operational</span>
                    : <span className="health-chip degraded">Degraded</span>;
                })()}
              </div>
              <div className="panel-body">
                <div className="diag-note">
                  Operational status of the audit service — API reachability, storage and internal
                  dependencies. A healthy service never implies any audit succeeded: per-audit results,
                  scores and findings are reported on each audit job.
                </div>
                <HealthWidget deep={deepHealth} />
              </div>
            </div>
          )}

          {/* Tab 2: Audit Jobs */}
          {activeWindow === 'jobs' && (
            <div className="panel">
              <div className="panel-header">
                <div>
                  <h2 className="panel-title">Audit Jobs ({jobs.length})</h2>
                  {dashLoad === 'ready' && lastSync && (
                    <p className="panel-sub">Synced {timeAgo(lastSync.toISOString())}</p>
                  )}
                </div>
                <div className="panel-actions">
                  <button onClick={() => fetchDashboardData(true, { force: true })} className="btn btn-secondary btn-sm" disabled={dashLoad === 'loading'}>
                    {dashLoad === 'loading' ? 'Syncing…' : 'Refresh'}
                  </button>
                  <button onClick={() => { openScanModal(); }} className="btn btn-primary btn-sm">New audit</button>
                </div>
              </div>

              {modalError && (
                <div style={{ padding: '0.75rem 1.25rem 0' }}>
                  <div className="error-box">{modalError}</div>
                </div>
              )}

              <div className="panel-body">
                <PanelState
                  state={dashLoad}
                  error={dashError}
                  empty={jobs.length === 0}
                  rows={5}
                  onRetry={() => fetchDashboardData(true, { force: true })}
                >
                  {jobs.length === 0 ? (
                    <EmptyState
                      title="No audits yet"
                      body="Submit a repository to run your first audit. Every audit attempt, score and report is listed here."
                      action={
                        <button onClick={() => { openScanModal(); }} className="btn btn-primary btn-sm">
                          Start an audit
                        </button>
                      }
                    />
                  ) : (
                    <div className="table-wrap">
                      <table>
                        <thead>
                          <tr>
                            <th>Job</th>
                            <th>Repository</th>
                            <th>Status</th>
                            <th>Score</th>
                            <th>Created</th>
                            <th style={{ textAlign: 'right' }}>Actions</th>
                          </tr>
                        </thead>
                        <tbody>
                          {jobs.map(j => {
                            const isActive = j.status === 'queued' || j.status === 'running';
                            const busy = cancellingIds.includes(j.id);
                            return (
                              <tr key={j.id} style={{ opacity: busy ? 0.55 : 1 }}>
                                <td className="mono" style={{ fontSize: '0.78rem' }}>{j.id.substring(0, 8)}</td>
                                <td>
                                  <div style={{ fontWeight: 600 }}>{repoLabel(j.repo_url)}</div>
                                  <code style={{ fontSize: '0.72rem', color: 'var(--dash-text-3)' }}>⎇ {j.repo_branch}</code>
                                  {(j.commit_sha || j.requested_commit_sha) ? (
                                    <code style={{ fontSize: '0.72rem', color: 'var(--dash-text-3)', marginLeft: '0.5rem' }} title={`Pinned snapshot ${j.commit_sha || j.requested_commit_sha}`}>⏺ {((j.commit_sha || j.requested_commit_sha) ?? '').substring(0, 8)}</code>
                                  ) : null}
                                </td>
                                <td>
                                  <StatusPill status={j.status} />
                                  {(j.status === 'failed') && j.error_message && (
                                    <div className="cell-error" title={j.error_message}>
                                      {j.error_message}
                                    </div>
                                  )}
                                </td>
                                <td><ScoreRing score={j.security_score ?? null} size={38} /></td>
                                <td style={{ color: 'var(--dash-text-3)', fontSize: '0.78rem' }} title={fmtUtc(j.created_at)}>{timeAgo(j.created_at)}</td>
                                <td>
                                  <div className="row-actions">
                                    <button onClick={() => handleViewJobDetail(j.id)} className="btn btn-secondary btn-sm">Inspect</button>
                                    {j.status === 'completed' && (
                                      <button onClick={() => handleDownloadReport(j.id)} className="btn btn-secondary btn-sm" title="Download report">Report</button>
                                    )}
                                    {isActive && (
                                      <button onClick={() => handleCancelJob(j.id)} className="btn btn-danger btn-sm" disabled={busy}>
                                        {busy ? '…' : 'Cancel'}
                                      </button>
                                    )}
                                  </div>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  )}
                </PanelState>
              </div>
            </div>
          )}

          {/* Window: SSO Providers — per-function */}
          {activeWindow === 'sso' && (
            <div className="panel" style={{ maxWidth: '900px', margin: '0 auto', width: '100%' }}>
              <div className="panel-header">
                <div className="panel-title">SSO Providers ({ssoProviders.length})</div>
                <button onClick={() => setIsSsoModalOpen(true)} className="btn btn-secondary btn-sm">+ Provider</button>
              </div>
              <div className="panel-body" style={{ padding: '0.75rem' }}>
                <PanelState state={dashLoad} error={dashError} empty={ssoProviders.length === 0} emptyIcon="🔑" rows={2} onRetry={() => fetchDashboardData(true, { force: true })}>
                  {ssoProviders.length === 0 ? <p>No SSO providers configured yet.</p> : ssoProviders.map(p => (
                    <div key={p.id} className="list-item" style={{ cursor: 'default' }}>
                      <div className="list-item-info"><div className="list-item-title">{p.name}</div><div className="list-item-sub">Type: {p.provider_type} • Issuer: {p.issuer_url || 'N/A'}</div></div>
                      <span className="badge badge-success">ACTIVE</span>
                    </div>
                  ))}
                </PanelState>
              </div>
            </div>
          )}

          {/* Window: PAM Requests — per-function */}
          {activeWindow === 'pam' && (
            <div className="panel" style={{ maxWidth: '900px', margin: '0 auto', width: '100%' }}>
              <div className="panel-header">
                <div className="panel-title">PAM Elevation Requests ({pamRequests.length})</div>
                <button onClick={() => setIsPamModalOpen(true)} className="btn btn-secondary btn-sm">+ Request</button>
              </div>
              <div className="panel-body" style={{ padding: '0.75rem' }}>
                <PanelState state={dashLoad} error={dashError} empty={pamRequests.length === 0} emptyIcon="🔐" rows={2} onRetry={() => fetchDashboardData(true, { force: true })}>
                  {pamRequests.length === 0 ? <p>No PAM elevation requests submitted.</p> : pamRequests.map(r => (
                    <div key={r.id} className="list-item" style={{ cursor: 'default' }}>
                      <div className="list-item-info"><div className="list-item-title">{r.role_name} ({r.permission})</div><div className="list-item-sub">{r.reason} • {r.requested_duration_minutes}m</div></div>
                      <span className="badge badge-medium">{r.status}</span>
                    </div>
                  ))}
                </PanelState>
              </div>
            </div>
          )}

          {/* Window: IAM Policies — per-function */}
          {activeWindow === 'iam' && (
            <div className="panel" style={{ maxWidth: '900px', margin: '0 auto', width: '100%' }}>
              <div className="panel-header">
                <div className="panel-title">IAM Policies ({iamPolicies.length})</div>
                <span className="badge badge-neutral">{iamPolicies.length} policies</span>
              </div>
              <div className="panel-body" style={{ padding: '0.75rem' }}>
                <PanelState state={dashLoad} error={dashError} empty={iamPolicies.length === 0} emptyIcon="🛡️" rows={2} onRetry={() => fetchDashboardData(true, { force: true })}>
                  {iamPolicies.length === 0 ? <p>No IAM policies defined.</p> : iamPolicies.map((pol: any) => (
                    <div key={pol.id} className="list-item" style={{ cursor: 'default' }}>
                      <div className="list-item-info"><div className="list-item-title">{pol.name}</div><div className="list-item-sub">{pol.effect} • {pol.actions} → {pol.resources}</div></div>
                      <span className="badge badge-info">P{pol.priority}</span>
                    </div>
                  ))}
                </PanelState>
              </div>
            </div>
          )}

          {/* Window: Domains — per-function */}
          {activeWindow === 'domains' && (
            <div className="panel" style={{ maxWidth: '900px', margin: '0 auto', width: '100%' }}>
              <div className="panel-header">
                <div className="panel-title">Domain Verifications ({domains.length})</div>
                <button onClick={() => setIsDomainModalOpen(true)} className="btn btn-secondary btn-sm">+ Add Domain</button>
              </div>
              <div className="panel-body" style={{ padding: '0.75rem' }}>
                <PanelState state={dashLoad} error={dashError} empty={domains.length === 0} emptyIcon="🌐" rows={2} onRetry={() => fetchDashboardData(true, { force: true })}>
                  {domains.length === 0 ? <p>No domain verifications registered.</p> : domains.map(d => (
                    <div key={d.id} className="list-item" style={{ cursor: 'default' }}>
                      <div className="list-item-info"><div className="list-item-title">{d.domain}</div><div className="list-item-sub">{d.verified ? 'Domain verified' : 'Pending DNS verification'}</div></div>
                      <span className={`badge ${d.verified ? 'badge-success' : 'badge-medium'}`}>{d.verified ? 'VERIFIED' : 'PENDING DNS'}</span>
                    </div>
                  ))}
                </PanelState>
              </div>
            </div>
          )}

                    {/* Window: MFA — per-function */}
          {activeWindow === 'mfa' && (
            <div className="panel" style={{ maxWidth: '700px', margin: '0 auto', width: '100%' }}>
              <div className="panel-header">
                <div className="panel-title">MFA Authentication Status</div>
                <span className={`badge ${mfaStatus.enabled ? 'badge-success' : 'badge-neutral'}`}>{mfaStatus.enabled ? 'ACTIVE' : 'DISABLED'}</span>
              </div>
              <div className="panel-body">
                <PanelState state={dashLoad} error={dashError} onRetry={() => fetchDashboardData(true, { force: true })}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <div><div style={{ fontWeight: 600, fontSize: '0.9rem' }}>TOTP Authenticator App</div><div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{mfaStatus.enabled ? `Protected • ${mfaStatus.backup_codes_remaining} recovery codes remaining` : 'Two-factor protection is not enrolled'}</div></div>
                    </div>
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      {mfaStatus.enabled ? <button onClick={handleMfaDisable} className="btn btn-danger btn-sm">Disable MFA</button> : <button onClick={handleMfaEnroll} className="btn btn-primary btn-sm">Enroll TOTP App</button>}
                    </div>
                  </div>
                </PanelState>
              </div>
            </div>
          )}

          {/* Window: Activity — per-function */}
          {activeWindow === 'activity' && (
            <div className="panel" style={{ maxWidth: '900px', margin: '0 auto', width: '100%' }}>
              <div className="panel-header"><div className="panel-title">User Security Activities ({activities.length})</div></div>
              <div className="panel-body" style={{ padding: '0.75rem', maxHeight: '520px', overflowY: 'auto' }}>
                <PanelState state={dashLoad} error={dashError} empty={activities.length === 0} emptyIcon="🧾" rows={4} onRetry={() => fetchDashboardData(true, { force: true })}>
                  {activities.length === 0 ? <p>No security events recorded yet.</p> : activities.map(act => (
                    <div key={act.id} className="list-item" style={{ cursor: 'default' }}>
                      <div className="list-item-info"><div className="list-item-title">{act.action}</div>{act.details_json && <div className="list-item-sub">{act.details_json}</div>}</div>
                      <span className="badge badge-neutral" title={fmtUtc(act.created_at)}>{timeAgo(act.created_at)}</span>
                    </div>
                  ))}
                </PanelState>
              </div>
            </div>
          )}

          {/* Modal: MFA Enrollment (POST /mfa/enroll response) */}
          {mfaEnrollment && (
            <div className="modal-backdrop" onClick={() => setMfaEnrollment(null)}>
              <div className="modal" onClick={e => e.stopPropagation()}>
                <div className="modal-head">
                  <div>
                    <div className="modal-title">MFA Enrollment</div>
                    <div className="modal-sub">Add the secret to your authenticator app, then activate with a 6-digit code from /mfa endpoints or CLI.</div>
                  </div>
                  <button onClick={() => setMfaEnrollment(null)} className="btn btn-ghost btn-icon">✕</button>
                </div>
                <div className="modal-body">
                  <div className="form-group">
                    <label className="form-label">TOTP Secret</label>
                    <code className="code-block" style={{ display: 'block', padding: '0.6rem' }}>{mfaEnrollment.secret}</code>
                  </div>
                  <div className="form-group">
                    <label className="form-label">otpauth URI</label>
                    <code className="code-block" style={{ display: 'block', padding: '0.6rem', wordBreak: 'break-all' }}>{mfaEnrollment.uri}</code>
                  </div>
                  <div className="form-group">
                    <label className="form-label">Emergency Recovery Codes — store securely, shown once</label>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.4rem' }}>
                      {(mfaEnrollment.recovery_codes || []).map((c) => (
                        <code key={c} style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border)', borderRadius: '6px', padding: '0.35rem 0.55rem' }}>{c}</code>
                      ))}
                    </div>
                  </div>
                </div>
                <div className="modal-footer">
                  <button onClick={() => setMfaEnrollment(null)} className="btn btn-primary">I've stored my codes</button>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>

      {/* Modal: New Scan */}
      {isScanModalOpen && (
        <div className="modal-backdrop" onClick={() => setIsScanModalOpen(false)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div className="modal-head">
              <div>
                <div className="modal-title">Start an audit</div>
                <div className="modal-sub">Submit a repository for a security audit</div>
              </div>
              <button onClick={() => setIsScanModalOpen(false)} className="btn btn-ghost btn-icon">✕</button>
            </div>

            <form onSubmit={handleStartScan}>
              <div className="modal-body">
                <div className="form-group" style={{ marginBottom: '1.25rem', background: 'rgba(255, 255, 255, 0.02)', padding: '0.85rem', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                    <label className="form-label" style={{ margin: 0 }}>Your GitHub repositories</label>
                    <button 
                      type="button" 
                      onClick={() => fetchUserRepos(true)} 
                      className="btn btn-ghost btn-sm"
                      style={{ padding: '0.15rem 0.5rem', fontSize: '0.72rem', color: 'var(--apple-blue-light)' }}
                    >
                      {isLoadingRepos ? 'Syncing...' : '🔄 Sync Account Repos'}
                    </button>
                  </div>
                  <select 
                    className="form-input"
                    onChange={(e) => {
                      if (e.target.value) {
                        const repo = userRepos.find(r => (r.clone_url || r.html_url) === e.target.value);
                        if (repo) {
                          setNewRepoUrl(repo.clone_url || repo.html_url || '');
                          setNewRepoBranch(repo.default_branch || 'main');
                        }
                      }
                    }}
                    defaultValue=""
                  >
                    <option value="" disabled>-- Select a GitHub Repository to Audit --</option>
                    {userRepos.map((r) => (
                      <option key={r.id} value={r.clone_url || r.html_url || ''}>
                        {r.private ? '🔒 Private' : '🌐 Public'}: {r.full_name} ({r.default_branch || 'main'})
                      </option>
                    ))}
                  </select>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.35rem' }}>
                    {reposStatus === 'not_connected'
                      ? 'GitHub not connected — sign in with GitHub to sync repositories, or paste a public URL below.'
                      : reposStatus === 'github_error' || reposStatus === 'network_error'
                        ? `Repository sync failed${reposMessage ? `: ${reposMessage}` : '.'} You can still paste a URL below.`
                        : userRepos.length > 0
                          ? `${userRepos.length} repositories synchronized from your GitHub account.`
                          : 'Click "Sync Account Repos" to load your public & private GitHub repositories.'}
                  </div>
                </div>

                <div className="form-group">
                  <label className="form-label">Repository Git URL</label>
                  <input 
                    type="text" 
                    className="form-input" 
                    placeholder="https://github.com/org/repo"
                    value={newRepoUrl}
                    onChange={e => setNewRepoUrl(e.target.value)}
                    required
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Branch</label>
                  <input 
                    type="text" 
                    className="form-input" 
                    value={newRepoBranch}
                    onChange={e => setNewRepoBranch(e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Pinned commit (optional)</label>
                  <input
                    type="text"
                    className="form-input"
                    placeholder="40-char lowercase hex, or empty for branch head"
                    value={newCommitSha}
                    onChange={e => setNewCommitSha(e.target.value)}
                    maxLength={40}
                  />
                </div>

                {modalError && <div className="error-box" style={{ marginBottom: '1rem' }}>{modalError}</div>}
              </div>

              <div className="modal-footer">
                <button type="button" onClick={() => setIsScanModalOpen(false)} className="btn btn-secondary">Cancel</button>
                <button type="submit" className="btn btn-primary" disabled={isSubmitting || !newRepoUrl.trim()}>
                  {isSubmitting ? 'Submitting...' : 'Submit Job'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Job Inspector (execution-aware) */}
      {selectedJobDetail && (
        <div className="modal-backdrop" onClick={() => closeInspector()} onKeyDown={e => { if (e.key === 'Escape') closeInspector(); }}>
          <div className="modal" style={{ maxWidth: '760px' }} role="dialog" aria-modal="true" aria-label={`Audit ${selectedJobDetail.job.id.substring(0, 8)}`} onClick={e => e.stopPropagation()}>
            <div className="modal-head">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.9rem' }}>
                <ScoreRing score={detailLoading ? null : (selectedJobDetail.job.security_score ?? null)} size={54} />
                <div>
                  <div className="modal-title">
                    Audit {selectedJobDetail.job.id.substring(0, 8)}
                    {!detailLoading && (() => { const st = jobStatusInfo(selectedJobDetail.job.status); return (
                      <span className={`badge ${st.cls}`} style={{ marginLeft: '0.6rem', verticalAlign: 'middle' }}>
                        {st.pulse && <span className="badge-pulse" />} {st.label}
                      </span>
                    ); })()}
                  </div>
                  <div className="modal-sub" style={{ fontFamily: 'var(--font-mono)' }}>
                    {selectedJobDetail.job.repo_url || '…'} ⎇ {selectedJobDetail.job.repo_branch || '?'} • {fmtUtc(selectedJobDetail.job.created_at)}
                  </div>
                </div>
              </div>
              <button onClick={() => closeInspector()} className="btn btn-ghost btn-icon">✕</button>
            </div>

            <div className="modal-body" style={{ maxHeight: '440px', overflowY: 'auto' }}>
              {detailLoading ? (
                <div className="state-skeleton">
                  {[0, 1, 2].map(i => <div key={i} className="skeleton-row" style={{ animationDelay: `${i * 0.12}s`, width: `${90 - i * 10}%` }} />)}
                </div>
              ) : (
                <>
                  {modalError && <div className="error-box" role="alert" style={{ marginBottom: '0.75rem' }}>{modalError}</div>}
                  {cancelNote && <div style={{ marginBottom: '0.75rem', fontSize: '0.78rem', color: '#ffd60a' }}>{cancelNote}</div>}

                  {/* Attempt history: each retry is a separate immutable execution */}
                  <div style={{ fontSize: '0.78rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
                    Attempts{execLoading ? ' (loading…)' : ''}
                  </div>
                  {execLoading ? (
                    <div className="state-skeleton"><div className="skeleton-row" style={{ width: '60%' }} /></div>
                  ) : executions.length === 0 ? (
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
                      No attempt history — showing the latest result below.
                    </div>
                  ) : (
                    <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', marginBottom: '0.75rem' }}>
                      {[...executions].sort((a, b) => a.attempt_number - b.attempt_number).map(ex => (
                        <button
                          key={ex.execution_id}
                          onClick={() => void selectExecution(selectedJobDetail.job.id, ex.execution_id)}
                          className={`btn btn-sm ${ex.execution_id === selectedExecutionId ? 'btn-primary' : 'btn-secondary'}`}
                          title={`${ex.status} • ${ex.finding_count} findings${ex.has_report ? ' • report' : ''}${ex.has_narrative ? ' • narrative' : ''}`}
                        >
                          #{ex.attempt_number} {ex.status}{ex.has_report ? ' • R' : ''}{ex.has_narrative ? ' • AI' : ''}
                        </button>
                      ))}
                    </div>
                  )}

                  {/* Deterministic report for the selected attempt */}
                  {selectedExecutionId && (
                    <>
                      {reportState === 'loading' && (
                        <div className="state-skeleton"><div className="skeleton-row" style={{ width: '80%' }} /></div>
                      )}
                      {reportState === 'error' && (
                        <div className="error-box" role="alert" style={{ marginBottom: '0.75rem' }}>
                          {reportError || 'Report unavailable.'}{' '}
                          <button className="btn btn-secondary btn-sm" onClick={() => void selectExecution(selectedJobDetail.job.id, selectedExecutionId)}>Retry</button>
                        </div>
                      )}
                      {reportState === 'ready' && execReport && (
                        <div style={{ marginBottom: '0.75rem', padding: '0.6rem 0.75rem', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(255,255,255,0.02)' }}>
                          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginBottom: '0.3rem' }}>
                            Attempt #{execReport.identity.attempt_number} • exec {execReport.identity.execution_id.substring(0, 8)} • snapshot {(execReport.identity.snapshot_commit ?? '').substring(0, 8) || 'branch head'}
                          </div>
                          {execReport.coverage.state === 'NO_FILES_ANALYZED' ? (
                            <div><strong>No files were analyzed — coverage is unknown, not clean.</strong></div>
                          ) : execReport.coverage.state === 'SUCCESS_CLEAN' ? (
                            <div>All scanners completed — no findings.</div>
                          ) : execReport.coverage.state === 'SUCCESS_FINDINGS' ? (
                            <div>{execReport.summary.headline}</div>
                          ) : (
                            <div><strong>Coverage {execReport.coverage.state}:</strong> this attempt did not fully cover the snapshot.</div>
                          )}
                          <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.3rem' }}>
                            Findings: {execReport.summary.finding_count} • Invalid quarantined: {execReport.summary.invalid_finding_count} • Score: {execReport.summary.security_score ?? 'Unknown'}
                          </div>
                          {Object.entries(execReport.summary.findings_by_severity).length > 0 && (
                            <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap', marginTop: '0.35rem' }}>
                              {Object.entries(execReport.summary.findings_by_severity).map(([sev, n]) => (
                                <span key={sev} className={`badge ${severityClass(sev)}`}>{sev.toUpperCase()} {n}</span>
                              ))}
                            </div>
                          )}
                          {Object.entries(execReport.coverage.unsuccessful_scanners).length > 0 && (
                            <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', marginTop: '0.3rem' }}>
                              Unsuccessful scanners:{' '}
                              {Object.entries(execReport.coverage.unsuccessful_scanners).map(([name, why]) => (
                                <span key={name} className="badge badge-medium" title={why} style={{ marginRight: '0.3rem' }}>{name}</span>
                              ))}
                            </div>
                          )}
                          {execReport.limitations.length > 0 && (
                            <details style={{ marginTop: '0.35rem', fontSize: '0.76rem' }}>
                              <summary>Limitations ({execReport.limitations.length})</summary>
                              <ul style={{ margin: '0.3rem 0 0', paddingLeft: '1.1rem' }}>
                                {execReport.limitations.map((l, i) => <li key={i}>{l}</li>)}
                              </ul>
                            </details>
                          )}
                        </div>
                      )}
                    </>
                  )}

                  {/* Findings explorer */}
                  <div className="detail-summary-row">
                    <div style={{ fontSize: '0.78rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)' }}>
                      Findings ({explorerFindings.length}{reportState === 'ready' ? '' : ' • latest result'})
                    </div>
                    <div style={{ display: 'flex', gap: '0.4rem', marginTop: '0.4rem' }}>
                      <input
                        type="text"
                        className="form-input"
                        placeholder="Search title, description, path…"
                        value={findingQuery}
                        onChange={e => setFindingQuery(e.target.value)}
                        style={{ flex: 1 }}
                        aria-label="Search findings"
                      />
                      <select className="form-input" value={findingSev} onChange={e => setFindingSev(e.target.value)} aria-label="Filter by severity" style={{ maxWidth: '130px' }}>
                        {['all', 'critical', 'high', 'medium', 'low', 'info', 'unknown'].map(s => (
                          <option key={s} value={s}>{s === 'all' ? 'All severities' : s}</option>
                        ))}
                      </select>
                    </div>
                    {reportState !== 'ready' && selectedJobDetail.job.status === 'engine_unavailable' && (
                      <div style={{ marginTop: '0.4rem', fontSize: '0.78rem' }}>
                        <strong>No analysis was performed.</strong> No engine is installed in this build — this is <strong>not</strong> a clean result.
                      </div>
                    )}
                  </div>

                  {explorerFindings.length === 0 ? (
                    <div className="panel-empty">
                      {reportState === 'ready' && execReport && execReport.coverage.state !== 'SUCCESS_CLEAN' && execReport.coverage.state !== 'SUCCESS_FINDINGS'
                        ? `No findings shown — coverage ${execReport.coverage.state}: this attempt is not a complete audit, not a clean result.`
                        : selectedJobDetail.job.status === 'completed' && reportState !== 'loading'
                          ? 'Clean audit — no vulnerabilities reported.'
                          : `No findings match — job is ${selectedJobDetail.job.status}.`}
                    </div>
                  ) : (
                    explorerFindings.map(f => (
                      <div key={f.key} className="finding-card">
                        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '0.35rem', flexWrap: 'wrap' }}>
                          <span className={`badge ${severityClass(f.severity)}`}>{(f.severity || 'info').toUpperCase()}</span>
                          {f.cvss != null && <span className="badge badge-neutral">CVSS {f.cvss.toFixed(1)}</span>}
                          {f.cwe && <span style={{ fontSize: '0.73rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{f.cwe}</span>}
                          {f.file && (
                            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginLeft: 'auto' }}>
                              {f.file}{f.line != null ? `:${f.line}` : ''}
                            </span>
                          )}
                        </div>
                        <div style={{ fontWeight: 600, fontSize: '0.85rem' }}>{f.title}</div>
                        <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', margin: '0.4rem 0' }}>{f.description}</div>
                        {f.evidence && (
                          <details className="remediation-details">
                            <summary>View evidence{f.evidenceTruncated ? ' (truncated by scanner)' : ''}</summary>
                            <pre className="code-block"><code>{f.evidence}</code></pre>
                          </details>
                        )}
                        {f.references.length > 0 && (
                          <div style={{ fontSize: '0.74rem', marginTop: '0.3rem' }}>
                            {f.references.map(r => (
                              <div key={r.url}>
                                <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>[{r.reference_type}] </span>
                                {isSafeExternalUrl(r.url) ? (
                                  <a href={r.url} target="_blank" rel="noreferrer">{r.url}</a>
                                ) : (
                                  <span>{r.url}</span>
                                )}
                              </div>
                            ))}
                          </div>
                        )}
                        {f.remediation && (
                          <details className="remediation-details">
                            <summary>View remediation</summary>
                            <pre className="code-block"><code>{f.remediation}</code></pre>
                          </details>
                        )}
                      </div>
                    ))
                  )}

                  {/* Optional AI narrative for the selected attempt */}
                  {selectedExecutionId && (
                    <div style={{ marginTop: '0.75rem' }}>
                      <div style={{ fontSize: '0.78rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
                        AI explanation (optional)
                      </div>
                      {narrativeState === 'loading' && (
                        <div className="state-skeleton"><div className="skeleton-row" style={{ width: '70%' }} /></div>
                      )}
                      {narrativeState === 'error' && (
                        <div className="error-box" role="alert" style={{ marginBottom: '0.5rem' }}>
                          {narrativeError || 'Narrative unavailable.'} The deterministic report above is unchanged.{' '}
                          <button className="btn btn-secondary btn-sm" onClick={() => void handleGenerateNarrative()}>Retry</button>
                        </div>
                      )}
                      {narrativeState === 'ready' && narrative && (
                        <div style={{ fontSize: '0.8rem', padding: '0.6rem 0.75rem', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.08)' }}>
                          <p style={{ margin: '0 0 0.5rem' }}>{narrative.executive_summary}</p>
                          {narrative.finding_explanations.map(e => (
                            <div key={e.finding_id} style={{ marginBottom: '0.4rem' }}>
                              <strong style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>{e.finding_id}</strong>
                              <div>{e.explanation}</div>
                            </div>
                          ))}
                          {narrative.remediation_guidance.map(g => (
                            <div key={g.finding_id} style={{ marginBottom: '0.4rem' }}>
                              <strong> Suggested fix for {g.finding_id} (unverified advice):</strong>
                              <div>{g.guidance}</div>
                            </div>
                          ))}
                          {narrative.limitations.length > 0 && (
                            <div style={{ color: 'var(--text-muted)' }}>Limitations: {narrative.limitations.join('; ')}</div>
                          )}
                        </div>
                      )}
                      {narrativeState === 'idle' && reportState === 'ready' && (
                        <button className="btn btn-secondary btn-sm" onClick={() => void handleGenerateNarrative()}>
                          Generate AI explanation
                        </button>
                      )}
                    </div>
                  )}

                  {/* Delivery of the selected attempt's report */}
                  {selectedExecutionId && reportState === 'ready' && (
                    <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center', flexWrap: 'wrap', marginTop: '0.75rem' }}>
                      <button className="btn btn-secondary btn-sm" disabled={deliveryBusy !== null} onClick={() => void handleDeliver('email')}>
                        {deliveryBusy === 'email' ? 'Sending…' : '@ Email report'}
                      </button>
                      <button className="btn btn-secondary btn-sm" disabled={deliveryBusy !== null} onClick={() => void handleDeliver('telegram')}>
                        {deliveryBusy === 'telegram' ? 'Sending…' : '✈ Telegram report'}
                      </button>
                      {deliveryMsg && <span style={{ fontSize: '0.76rem', color: 'var(--text-secondary)' }}>{deliveryMsg}</span>}
                    </div>
                  )}
                </>
              )}
            </div>

            <div className="modal-footer">
              {(() => {
                const st = selectedJobDetail.job.status;
                const isActive = st === 'queued' || st === 'running';
                const retryable = st === 'failed' || st === 'cancelled' || st === 'partial' || st === 'engine_unavailable';
                const busy = cancellingIds.includes(selectedJobDetail.job.id);
                return (
                  <>
                    {isActive && (
                      <button onClick={() => void handleCancelJob(selectedJobDetail.job.id)} className="btn btn-danger btn-sm" disabled={busy}>
                        {busy ? 'Cancelling…' : selectedJobDetail.job.cancel_requested ? 'Cancel requested…' : 'Cancel audit'}
                      </button>
                    )}
                    {retryable && (
                      <button onClick={() => void handleRetryJob(selectedJobDetail.job.id)} className="btn btn-secondary btn-sm" disabled={retryBusy}>
                        {retryBusy ? 'Queuing…' : '↻ Retry as new attempt'}
                      </button>
                    )}
                  </>
                );
              })()}
              {selectedExecutionId && (
                <>
                  <button onClick={() => void handleDownloadExecutionReport('markdown')} className="btn btn-secondary btn-sm" title="Download this attempt's report">↓ MD</button>
                  <button onClick={() => void handleDownloadExecutionReport('json')} className="btn btn-secondary btn-sm" title="Download this attempt's report">↓ JSON</button>
                  <button onClick={() => void handleDownloadExecutionReport('html')} className="btn btn-secondary btn-sm" title="Download this attempt's report">↓ HTML</button>
                </>
              )}
              {selectedJobDetail.job.status === 'completed' && !selectedExecutionId && (
                <button onClick={() => handleDownloadReport(selectedJobDetail.job.id)} className="btn btn-secondary">↓ Download Report</button>
              )}
              <button onClick={() => closeInspector()} className="btn btn-primary" autoFocus>Close</button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: PAM Elevation */}
      {isPamModalOpen && (
        <div className="modal-backdrop" onClick={() => setIsPamModalOpen(false)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div className="modal-head">
              <div>
                <div className="modal-title">Request Privileged Access (PAM)</div>
                <div className="modal-sub">Submit temporary access request to backend</div>
              </div>
              <button onClick={() => setIsPamModalOpen(false)} className="btn btn-ghost btn-icon">✕</button>
            </div>

            <form onSubmit={handleCreatePamRequest}>
              <div className="modal-body">
                {modalError && <div className="error-box" style={{ marginBottom: '1rem' }}>{modalError}</div>}
                <div className="form-group">
                  <label className="form-label">Role</label>
                  <input type="text" className="form-input" value={pamRole} onChange={e => setPamRole(e.target.value)} required />
                </div>

                <div className="form-group">
                  <label className="form-label">Permission</label>
                  <input type="text" className="form-input" value={pamPermission} onChange={e => setPamPermission(e.target.value)} required />
                </div>

                <div className="form-group">
                  <label className="form-label">Reason / Justification</label>
                  <textarea 
                    className="form-input" 
                    rows={3} 
                    placeholder="Audit, code deployment..." 
                    value={pamReason}
                    onChange={e => setPamReason(e.target.value)}
                    required
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Duration (minutes)</label>
                  <input type="number" className="form-input" value={pamDuration} onChange={e => setPamDuration(e.target.value)} required />
                </div>
              </div>

              <div className="modal-footer">
                <button type="button" onClick={() => setIsPamModalOpen(false)} className="btn btn-secondary">Cancel</button>
                <button type="submit" className="btn btn-primary" disabled={isSubmitting}>
                  {isSubmitting ? 'Submitting...' : 'Submit Request'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Add SSO Provider */}
      {isSsoModalOpen && (
        <div className="modal-backdrop" onClick={() => setIsSsoModalOpen(false)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div className="modal-head">
              <div>
                <div className="modal-title">Configure SSO Provider</div>
                <div className="modal-sub">Register new OIDC / SAML single sign-on provider</div>
              </div>
              <button onClick={() => setIsSsoModalOpen(false)} className="btn btn-ghost btn-icon">✕</button>
            </div>

            <form onSubmit={handleCreateSsoProvider}>
              <div className="modal-body">
                {modalError && <div className="error-box" style={{ marginBottom: '1rem' }}>{modalError}</div>}
                <div className="form-group">
                  <label className="form-label">Provider Name</label>
                  <input type="text" className="form-input" placeholder="Okta / Azure AD" value={ssoName} onChange={e => setSsoName(e.target.value)} required />
                </div>

                <div className="form-group">
                  <label className="form-label">Provider Type</label>
                  <select className="form-input" value={ssoProviderType} onChange={e => setSsoProviderType(e.target.value)}>
                    <option value="oidc">OIDC (OpenID Connect)</option>
                    <option value="saml">SAML 2.0</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Issuer URL</label>
                  <input type="url" className="form-input" placeholder="https://dev-1234.okta.com" value={ssoIssuer} onChange={e => setSsoIssuer(e.target.value)} />
                </div>
              </div>

              <div className="modal-footer">
                <button type="button" onClick={() => setIsSsoModalOpen(false)} className="btn btn-secondary">Cancel</button>
                <button type="submit" className="btn btn-primary" disabled={isSubmitting}>
                  {isSubmitting ? 'Saving...' : 'Save Provider'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Initiate Domain Verification */}
      {isDomainModalOpen && (
        <div className="modal-backdrop" onClick={() => setIsDomainModalOpen(false)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div className="modal-head">
              <div>
                <div className="modal-title">Initiate Domain Verification</div>
                <div className="modal-sub">Generate DNS TXT token for domain ownership</div>
              </div>
              <button onClick={() => setIsDomainModalOpen(false)} className="btn btn-ghost btn-icon">✕</button>
            </div>

            <form onSubmit={handleInitiateDomain}>
              <div className="modal-body">
                {modalError && <div className="error-box" style={{ marginBottom: '1rem' }}>{modalError}</div>}
                <div className="form-group">
                  <label className="form-label">Domain Name</label>
                  <input type="text" className="form-input" placeholder="org.example.com" value={newDomainName} onChange={e => setNewDomainName(e.target.value)} required />
                </div>
              </div>

              <div className="modal-footer">
                <button type="button" onClick={() => setIsDomainModalOpen(false)} className="btn btn-secondary">Cancel</button>
                <button type="submit" className="btn btn-primary" disabled={isSubmitting}>
                  {isSubmitting ? 'Initiating...' : 'Initiate'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Dodo Payments Checkout */}
      {isDodoModalOpen && (
        <div className="modal-backdrop" onClick={() => setIsDodoModalOpen(false)}>
          <div className="modal" style={{ maxWidth: '520px' }} onClick={e => e.stopPropagation()}>
            <div className="modal-head">
              <div>
                <div className="modal-title">💳 Dodo Payments Checkout</div>
                <div className="modal-sub">Select credit package to top-up account balance</div>
              </div>
              <button onClick={() => setIsDodoModalOpen(false)} className="btn btn-ghost btn-icon">✕</button>
            </div>

            <div className="modal-body">
              {modalError && <div className="error-box" style={{ marginBottom: '1rem' }}>{modalError}</div>}
              
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', marginBottom: '1.25rem' }}>
                <div 
                  className={`panel ${dodoPackage === 'starter' ? 'active' : ''}`}
                  style={{ cursor: 'pointer', padding: '1rem', border: dodoPackage === 'starter' ? '2px solid var(--accent)' : '1px solid var(--border)' }}
                  onClick={() => setDodoPackage('starter')}
                >
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>STARTER</div>
                  <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#ffffff' }}>$10</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--green)' }}>+10 Scan Credits</div>
                </div>

                <div 
                  className={`panel ${dodoPackage === 'pro' ? 'active' : ''}`}
                  style={{ cursor: 'pointer', padding: '1rem', border: dodoPackage === 'pro' ? '2px solid var(--accent)' : '1px solid var(--border)' }}
                  onClick={() => setDodoPackage('pro')}
                >
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>PRO (POPULAR)</div>
                  <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#ffffff' }}>$25</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--green)' }}>+30 Scan Credits (+20% Bonus)</div>
                </div>

                <div 
                  className={`panel ${dodoPackage === 'enterprise' ? 'active' : ''}`}
                  style={{ cursor: 'pointer', padding: '1rem', border: dodoPackage === 'enterprise' ? '2px solid var(--accent)' : '1px solid var(--border)', gridColumn: 'span 2' }}
                  onClick={() => setDodoPackage('enterprise')}
                >
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>ENTERPRISE UNLIMITED</div>
                  <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#ffffff' }}>$100</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--purple)' }}>+150 Credits + Priority Docker Sandbox</div>
                </div>
              </div>

              {dodoCheckoutUrl && (
                <div style={{ marginBottom: '1rem', padding: '0.75rem', background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.3)', borderRadius: '8px', fontSize: '0.8rem', color: '#86efac' }}>
                  ✓ Checkout URL generated: <a href={dodoCheckoutUrl} target="_blank" rel="noreferrer" style={{ color: '#60a5fa' }}>{dodoCheckoutUrl}</a>
                </div>
              )}
            </div>

            <div className="modal-footer">
              <button type="button" onClick={() => setIsDodoModalOpen(false)} className="btn btn-secondary">Cancel</button>
              <button 
                type="button" 
                onClick={() => {
                  const amount = dodoPackage === 'starter' ? 10 : dodoPackage === 'pro' ? 25 : 100;
                  handleInitiateDodoCheckout(amount, dodoPackage);
                }} 
                className="btn btn-primary" 
                disabled={isSubmitting}
              >
                {isSubmitting ? 'Generating Link...' : 'Pay with Dodo Payments 💳'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
