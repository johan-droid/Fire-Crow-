import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { BrandMark } from './BrandMark';
import LandingPage from './LandingPage';
import LoginPage from './LoginPage';
import { useNavigate, useLocation } from 'react-router-dom';
// Single API-origin contract (FC-DEP-01): base URL resolution, credentials,
// and error handling live in ./api/client — never re-implemented here.
import { api, getApiBase } from './api/client';
import { ApiError, withTimeout } from './api/errors';
import { parseSsePayload, sseReconnectDelay, SSE_MAX_RECONNECTS } from './api/sse';
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
  PanelState, ScoreRing, jobStatusInfo, severityClass,
  fmtUtc, timeAgo, StatusPill, EmptyState, repoLabel,
  type LoadState,
} from './dash';
import {
  MetricCard,
  AuditTable,
  Dropdown,
  DropdownItem,
  DropdownOption,
  needsAttention,
} from './dashboard';
import {
  ShieldCheck,
  Flame,
  FileText,
  AlertTriangle,
  Plus,
  RefreshCw,
  GitBranch,
  ChevronDown,
  Settings,
  LogOut,
} from 'lucide-react';

const API_BASE = getApiBase();

/**
 * FC-SEC: Sanitizes a redirect / return destination.
 * Must start with exactly one '/', must NOT start with '//' or '/\',
 * and must not contain any backslashes or protocol specifiers to prevent open redirects.
 */
export function sanitizeReturnTarget(target: unknown, fallback = '/console/overview'): string {
  if (typeof target !== 'string') return fallback;
  const trimmed = target.trim();
  if (!trimmed.startsWith('/') || trimmed.startsWith('//') || trimmed.startsWith('/\\')) {
    return fallback;
  }
  if (/[\r\n\t\\]/.test(trimmed)) {
    return fallback;
  }
  return trimmed;
}

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

interface MfaStatus {
  enabled: boolean;
  backup_codes_remaining: number;
}

const apiFetch = async (endpoint: string, options: RequestInit = {}) => {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> || {}),
  };
  // Bounded: a cold free-tier backend must surface a 408, never a hang.
  // Callers already treat non-2xx as responses; timeout arrives as ApiError.
  return withTimeout(
    (signal) =>
      fetch(`${API_BASE}${endpoint}`, {
        credentials: 'include',
        ...options,
        headers,
        signal,
      }),
    25_000,
    `Request to ${endpoint}`,
  );

  // Session cookies are HttpOnly: only the server's logout response can clear
  // them, never JavaScript. 401s surface to callers as responses.
};

// Lightweight in-memory cache for dashboard summary (5 s TTL, avoids duplicate calls on re-render)
let _dashboardCache: { data: any; ts: number } | null = null;
const DASH_CACHE_TTL = 5000;

/** Severity filter values for the findings explorer, in display order. */
const SEVERITY_FILTERS = ['all', 'critical', 'high', 'medium', 'low', 'info', 'unknown'] as const;
const severityFilterLabel = (s: string): string => (s === 'all' ? 'All severities' : s);

function App() {
  const [view, setView] = useState<'landing' | 'login' | 'dashboard'>('landing');
  void view; void setView;
  const [user, setUser] = useState<UserProfile | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  // Explicit session lifecycle: initializing (blocking splash) → signed_out |
  // authenticated | error. Distinct from data-loading flags elsewhere.
  type AuthState = 'initializing' | 'signed_out' | 'authenticated' | 'error';
  const [authState, setAuthState] = useState<AuthState>('initializing');

// Console navigation: the developer security workspace. Legacy admin routes
// (jobs, diagnostics, sso, pam, iam, domains, mfa, activity) resolve to the
// closest workspace window so old links and history entries keep working.
type ConsoleWindow = 'overview' | 'repositories' | 'audits' | 'findings' | 'settings';
const LEGACY_WINDOWS: Record<string, ConsoleWindow> = {
  jobs: 'audits',
  reports: 'audits',
  diagnostics: 'settings',
  sso: 'settings',
  pam: 'settings',
  iam: 'settings',
  domains: 'settings',
  mfa: 'settings',
  activity: 'settings',
};
  const navigate = useNavigate();
  const location = useLocation();
  const getWindowFromPath = useCallback((path: string): ConsoleWindow => {
    const seg = path.replace(/^\/console\/?/, '').split('/')[0];
    if (['overview', 'repositories', 'audits', 'findings', 'settings'].includes(seg)) return seg as ConsoleWindow;
    if (seg in LEGACY_WINDOWS) return LEGACY_WINDOWS[seg];
    return 'overview';
  }, [LEGACY_WINDOWS]);
  const activeWindow = getWindowFromPath(location.pathname);
  // keep dashTab for internal handlers; sync from router
  const [dashTab, setDashTabRaw] = useState<ConsoleWindow>('overview');
  const setDashTab = (w: ConsoleWindow) => navigate(`/console/${w}`);
  void setDashTab;
  useEffect(() => {
    const w = getWindowFromPath(location.pathname);
    if (w !== dashTab) setDashTabRaw(w);
    if (location.pathname === '/console' || location.pathname === '/console/') navigate('/console/overview', { replace: true });
    const seg = location.pathname.replace(/^\/console\/?/, '').split('/')[0];
    if (seg in LEGACY_WINDOWS) navigate(`/console/${LEGACY_WINDOWS[seg]}`, { replace: true });
  }, [location.pathname, dashTab, navigate, getWindowFromPath, LEGACY_WINDOWS]);

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
  const [mfaStatus, setMfaStatus] = useState<MfaStatus>({ enabled: false, backup_codes_remaining: 0 });
  // P0-A: when a password login meets an MFA-enabled account, the backend
  // returns a short-lived challenge instead of a session; this holds it while
  // the second-factor step is on screen.
  const [mfaChallenge, setMfaChallenge] = useState<string | null>(null);
  const [activeMonitorJobId, setActiveMonitorJobId] = useState<string | null>(null);
  const [monitorPhases, setMonitorPhases] = useState<PhaseLedgerEntry[]>([]);

  // Dashboard state machine: loading → ready | error, with sync telemetry
  const [dashLoad, setDashLoad] = useState<LoadState>('loading');
  const [dashError, setDashError] = useState<string | null>(null);
  const [lastSync, setLastSync] = useState<Date | null>(null);
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

  // Fetch workspace data via the SINGLE batched endpoint (remedy: 8 → 1 request).
  // Only job and MFA state is consumed: the console is a security workspace,
  // not an admin surface, so SSO/PAM/IAM/domain/activity payloads are ignored.
  // Falls back to a jobs + MFA flow if the batch endpoint is unavailable.
  const fetchDashboardData = useCallback(async (showSpinner = false, opts: { force?: boolean } = {}) => {
    if (dashboardInflightRef.current) return;
    const now = Date.now();
    if (!opts.force && _dashboardCache && (now - _dashboardCache.ts) < DASH_CACHE_TTL) {
      const d = _dashboardCache.data;
      setJobs(d.jobs || []); if (d.mfa_status) setMfaStatus(d.mfa_status);
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
        setJobs(d.jobs || []); if (d.mfa_status) setMfaStatus(d.mfa_status);
        setDashError(null); setDashLoad('ready'); setLastSync(new Date());
        return;
      }
      // Fallback: legacy fan-out (if backend not yet deployed) — keep working
      const results = await Promise.allSettled([
        apiFetch('/audit/jobs'), apiFetch('/mfa/status'),
      ]) as PromiseSettledResult<Response>[];
      const [jobsRes, mfaRes] = results;
      let jobsOk = false;
      const jobsHttp = jobsRes.status === 'fulfilled' ? jobsRes.value.status : null;
      if (jobsRes.status === 'fulfilled' && jobsRes.value.ok) { setJobs(await jobsRes.value.json()); jobsOk = true; }
      else if (jobsRes.status === 'rejected') { throw jobsRes.reason; }
      else if (jobsHttp === 401) { throw new Error('Session expired — please sign in again.'); }
      else { throw new Error(`Audit API returned HTTP ${jobsHttp}`); }
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
    let streamDone = false;
    let sseAttempts = 0;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
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

    // A dead stream falls back to polling — but not on the first failure:
    // a cold free-tier backend needs seconds, so re-establish the stream
    // with bounded backoff first, and poll only after reconnects run out.
    const giveUpToPolling = () => {
      if (sseFailed) return;
      sseFailed = true;
      try { sse?.close(); } catch {}
      sse = null;
      startPolling();
    };
    const scheduleReconnect = () => {
      if (streamDone) return;
      sseAttempts += 1;
      try { sse?.close(); } catch {}
      sse = null;
      if (sseAttempts > SSE_MAX_RECONNECTS || cancelled) { giveUpToPolling(); return; }
      reconnectTimer = setTimeout(() => { if (!cancelled) connectSse(); }, sseReconnectDelay(sseAttempts));
    };
    const connectSse = () => {
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
        streamDone = true;
        if (reconnectTimer) clearTimeout(reconnectTimer);
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
        scheduleReconnect();
      };
      // If not OPEN in 2.5s → reconnect path (backend emits instantly when
      // warm, so this catches auth/firewall blocks; cold starts retry above)
      setTimeout(() => {
        if (!cancelled && sse && sse.readyState !== 1 && !sseFailed) {
          scheduleReconnect();
        }
      }, 2500);
      // If SSE never fires update within 4s, also trigger phases fetch to avoid blank
      setTimeout(() => { if (!cancelled && !sseFailed && sse) void fetchPhases(); }, 4000);
    } catch {
      giveUpToPolling();
    }
    }; // connectSse

    connectSse();

    // Safety net: if SSE object never created
    setTimeout(() => { if (!cancelled && !sse && !pollTimer) startPolling(); }, 3200);

    return () => {
      cancelled = true;
      try { sse?.close(); } catch {}
      if (pollTimer) clearInterval(pollTimer);
      if (reconnectTimer) clearTimeout(reconnectTimer);
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
        // Deep links survive session re-validation: an already-open console
        // path (legacy admin routes remap below) is kept instead of being
        // reset to Overview on every mount.
        if (location.pathname.startsWith('/console')) {
          navigate(location.pathname);
        }
        fetchDashboardData(true, { force: true });
      } catch (err) {
        // 401 means no session: stay signed out. Anything else (429/5xx/
        // network/timeout) is indeterminate — a throttled or failed read is
        // not proof of sign-out, so keep any in-memory user and surface error
        // instead of fabricating a signed-out state a retry could reverse.
        if (err instanceof ApiError && err.status === 401) {
          console.warn('No active session found:', err);
          setUser(null);
          setAuthState('signed_out');
        } else {
          console.warn('Session verification indeterminate:', err);
          setAuthState('error');
        }
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

        // P0-A: the exchange endpoint is MFA-gated for MFA-enabled accounts
        // (including those signing in via GitHub). Hold the challenge and show
        // the second-factor step instead of completing the session.
        if (exchangeData?.status === 'mfa_required' && exchangeData.mfa_token) {
          setMfaChallenge(exchangeData.mfa_token);
          setAuthState('signed_out');
          navigate('/login');
          return;
        }

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
  }, [fetchDashboardData, navigate, location.pathname]);

  const handleGitHubLogin = () => {
    const privacyVersion = '2026-06-06';
    window.location.href = `${API_BASE}/auth/github?privacy_policy_accepted=true&privacy_policy_version=${privacyVersion}`;
  };

  // Shared tail of every successful credential login (password or redeemed
  // MFA): read the session identity, flip to authenticated, and route.
  const completeSession = async () => {
    const me = await api.me();
    setUser({
      user_id: me.user_id,
      username: me.username,
      email: me.email,
      credit_balance: me.credit_balance,
    });
    setAuthState('authenticated');
    const rawTarget =
      (location.state as { returnTo?: string } | null)?.returnTo ||
      new URLSearchParams(location.search).get('returnTo');
    const returnTarget = sanitizeReturnTarget(rawTarget);
    navigate(returnTarget);
    fetchDashboardData(true, { force: true });
  };

  const handlePasswordLogin = async (identifier: string, password: string) => {
    setIsLoading(true);
    setError('');
    setAuthFormError('');
    try {
      const res = await api.login(identifier, password);
      // P0-A: an MFA-enabled account gets a challenge, not a session. Hold it
      // and surface the second-factor step; no session cookie exists yet.
      if (res?.status === 'mfa_required' && res.mfa_token) {
        setMfaChallenge(res.mfa_token);
        return;
      }
      await completeSession();
    } catch (err) {
      console.warn('Password login failed:', err);
      setAuthFormError(err instanceof ApiError ? err.message : 'Invalid credentials or network failure.');
    } finally {
      setIsLoading(false);
    }
  };

  // P0-A: redeem the MFA challenge with a TOTP code or a recovery code.
  const handleMfaVerify = async (code: string) => {
    if (!mfaChallenge) return;
    setIsLoading(true);
    setError('');
    setAuthFormError('');
    try {
      await api.loginMfa(mfaChallenge, code);
    } catch (err) {
      // Redemption itself failed — the challenge is still unconsumed (or
      // rejected); retrying with a fresh code is meaningful.
      console.warn('MFA verification failed:', err);
      setAuthFormError(err instanceof ApiError ? err.message : 'Invalid authentication code.');
      setIsLoading(false);
      return;
    }
    // Redemption succeeded: the challenge is consumed server-side and the
    // session cookie is set. Never report this state as a bad code.
    setMfaChallenge(null);
    try {
      await completeSession();
    } catch (err) {
      console.warn('Session load failed after MFA redemption:', err);
      setAuthFormError('Signed in, but loading your account failed. Refresh the page to continue.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleMfaCancel = () => {
    setMfaChallenge(null);
    setAuthFormError('');
  };

  const handleRegister = async (username: string, email: string, password: string) => {
    setIsLoading(true);
    setError('');
    setAuthFormError('');
    try {
      await api.register(username, email, password);
      // Automatically log the newly registered user in
      await handlePasswordLogin(username, password);
    } catch (err) {
      console.warn('Registration failed:', err);
      setAuthFormError(err instanceof ApiError ? err.message : 'Registration failed. Please try again.');
      setIsLoading(false);
    }
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

  const isLanding = location.pathname === '/' ;
  const isLogin = location.pathname === '/login';
  const isConsole = location.pathname.startsWith('/console');

  // Escape closes whichever dialog is open. A window listener is used rather
  // than a handler on the backdrop because focus may still sit on the control
  // that opened the dialog, where backdrop key events never fire.
  useEffect(() => {
    if (!selectedJobDetail && !isScanModalOpen && !mfaEnrollment) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      if (selectedJobDetail) {
        // Same lifecycle as closeInspector: invalidate in-flight loads.
        inspectReqRef.current++;
        setSelectedJobDetail(null);
      } else if (isScanModalOpen) {
        setIsScanModalOpen(false);
      } else if (mfaEnrollment) {
        setMfaEnrollment(null);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [selectedJobDetail, isScanModalOpen, mfaEnrollment]);

  // Remember what had focus outside any dialog, so closing a dialog can hand
  // focus back to the control that opened it. Focus that lands on <body> (as
  // it does when the backdrop is clicked) must not overwrite the opener.
  const lastOutsideFocusRef = useRef<HTMLElement | null>(null);
  useEffect(() => {
    const onFocusIn = (e: FocusEvent) => {
      const t = e.target;
      if (!(t instanceof HTMLElement)) return;
      if (t === document.body || t === document.documentElement) return;
      if (t.closest('[role="dialog"][aria-modal="true"]')) return;
      lastOutsideFocusRef.current = t;
    };
    window.addEventListener('focusin', onFocusIn);
    return () => window.removeEventListener('focusin', onFocusIn);
  }, []);

  // Focus containment for dialogs: move focus in on open when the dialog has
  // no autofocus of its own, keep Tab / Shift+Tab cycling within it, and return
  // focus to the opener on close. One window listener keyed on the same three
  // dialogs as the Escape handler above, resolved from the DOM rather than
  // per-dialog refs, so any future role="dialog" is covered by construction.
  useEffect(() => {
    if (!selectedJobDetail && !isScanModalOpen && !mfaEnrollment) return;

    const FOCUSABLE =
      'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
    const openDialog = () =>
      document.querySelector<HTMLElement>('[role="dialog"][aria-modal="true"]');

    // Focus may still sit on the opener behind the backdrop (the MFA dialog
    // has no autofocus of its own), so pull the first Tab inside.
    const root = openDialog();
    const active = document.activeElement;
    if (root && !(active instanceof HTMLElement && root.contains(active))) {
      root.querySelector<HTMLElement>(FOCUSABLE)?.focus();
    }

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== 'Tab') return;
      const dialog = openDialog();
      if (!dialog) return;
      const items = Array.from(dialog.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
        (el) => el.getClientRects().length > 0,
      );
      // Nothing to cycle through (e.g. a bare loading state): never hard-trap.
      if (items.length === 0) return;
      const idx = items.findIndex((el) => el === document.activeElement);
      if (idx === -1) {
        // Focus is on or behind the dialog: the next Tab must land inside.
        e.preventDefault();
        (e.shiftKey ? items[items.length - 1] : items[0]).focus();
      } else if (e.shiftKey && idx === 0) {
        e.preventDefault();
        items[items.length - 1].focus();
      } else if (!e.shiftKey && idx === items.length - 1) {
        e.preventDefault();
        items[0].focus();
      }
    };
    window.addEventListener('keydown', onKeyDown);

    return () => {
      window.removeEventListener('keydown', onKeyDown);
      // Hand focus back to whatever opened the dialog, if still mounted.
      const opener = lastOutsideFocusRef.current;
      if (opener?.isConnected) opener.focus();
    };
  }, [selectedJobDetail, isScanModalOpen, mfaEnrollment]);

  // Guard: unauthenticated console access returns to login (401 contract).
  useEffect(() => {
    if (isConsole && !user && (authState === 'signed_out' || authState === 'error')) {
      navigate('/login', { state: { returnTo: location.pathname } });
    }
  }, [isConsole, user, authState, navigate, location.pathname]);

  // Guard: already-authenticated user on /login returns to destination or overview
  useEffect(() => {
    if (isLogin && user && authState === 'authenticated') {
      const rawTarget =
        (location.state as { returnTo?: string } | null)?.returnTo ||
        new URLSearchParams(location.search).get('returnTo');
      const returnTarget = sanitizeReturnTarget(rawTarget);
      navigate(returnTarget, { replace: true });
    }
  }, [isLogin, user, authState, navigate, location.state, location.search]);

  // Render Landing View immediately — visitors to the public marketing page
  // must never be blocked by backend session verification.
  if (isLanding) {
    return (
      <LandingPage
        user={user}
        onNavigateLogin={() => navigate('/login')}
        onNavigateConsole={() => navigate('/console/overview')}
        onInitiateCheckout={handleInitiateDodoCheckout}
      />
    );
  }

  // Render Login View immediately
  if (isLogin) {
    return (
      <LoginPage
        onNavigateLanding={() => navigate('/')}
        onGitHubLogin={handleGitHubLogin}
        onPasswordLogin={handlePasswordLogin}
        onRegister={handleRegister}
        mfaToken={mfaChallenge}
        onMfaVerify={handleMfaVerify}
        onMfaCancel={handleMfaCancel}
        error={error}
        authFormError={authFormError}
        clearErrors={() => { setError(''); setAuthFormError(''); }}
      />
    );
  }

  // Only block with the splash screen for console/dashboard routes that require authentication
  if (isConsole && (authState === 'initializing' || isLoading)) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', backgroundColor: 'var(--bg-primary)', color: 'var(--text-primary)', fontFamily: 'var(--font-sans)' }}>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1.25rem' }}>
          <div style={{ width: '32px', height: '32px', borderRadius: '50%', border: '3px solid rgba(255,255,255,0.1)', borderTopColor: '#fff', animation: 'spin 0.8s linear infinite' }}></div>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', letterSpacing: '0.1em', fontWeight: 600 }}>VERIFYING AUTHENTICATION SESSION...</span>
        </div>
      </div>
    );
  }

  // Render Dashboard View — the developer security workspace
  if (!isConsole) {
    // fallback: unknown route -> landing
    return (
      <LandingPage onNavigateLogin={() => navigate('/login')} />
    );
  }
  // Live-audit pill for the dynamic island: the monitored run when it is
  // genuinely in flight, otherwise the newest running/queued job.
  // Same progress formula as the overview live-audit panel (7 phases).
  const islandLiveJob = (() => {
    const monitored = jobs.find(j => j.id === (activeMonitorJobId || ''));
    const job = (monitored && (monitored.status === 'running' || monitored.status === 'queued'))
      ? monitored
      : jobs.find(j => j.status === 'running' || j.status === 'queued') || null;
    if (!job) return null;
    const TOTAL_PHASES = 7; // keep in sync with the overview live-audit phase order
    const done = monitorPhases.filter(p => p.status === 'completed').length;
    const hasStarted = monitorPhases.some(p => p.status === 'started' || p.status === 'running');
    const pct = job.status === 'queued'
      ? 8
      : Math.min(95, Math.max(12, Math.round((done / TOTAL_PHASES) * 100) + (hasStarted ? 8 : 0)));
    return { job, pct };
  })();

  return (
    <div className="shell">
      {/* Dynamic island — the workspace command bar. Compact by default:
          brand, five sections, live-audit activity, new audit, identity.
          It expands with a live pill while a run is queued or running. */}
      <nav className="dyn-island" aria-label="Security workspace navigation">
        <button
          className="dyn-brand"
          onClick={() => navigate('/console/overview')}
          title="Fire Crow — Overview"
          aria-label="Fire Crow — go to Overview"
        >
          <BrandMark size={28} />
          <span className="dyn-brand-name">Fire Crow</span>
        </button>

        <div className="dyn-sep" aria-hidden="true" />

        <div className="dyn-options" role="group" aria-label="Workspace sections">
          {([
            { id: 'overview', label: 'Overview', desc: 'What needs attention', icon: (
              <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
            ) },
            { id: 'repositories', label: 'Repositories', desc: 'Audited code, history, actions', icon: (
              <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9"><circle cx="6" cy="6" r="2.5"/><circle cx="6" cy="18" r="2.5"/><circle cx="18" cy="12" r="2.5"/><path d="M6 8.5v7M8 7l7.5 3.8M8 17l7.5-3.8"/></svg>
            ) },
            { id: 'audits', label: 'Audits', desc: 'Every repository audit run', badge: jobs.length, icon: (
              <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M9 15h6M9 11h3"/></svg>
            ) },
            { id: 'findings', label: 'Findings', desc: 'Evidence and how to fix it', icon: (
              <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9"><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            ) },
            { id: 'settings', label: 'Settings', desc: 'Account and security', icon: (
              <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.9 2.9l-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1a2 2 0 1 1-2.9-2.9l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9l-.1-.1a2 2 0 1 1 2.9-2.9l.1.1a1.7 1.7 0 0 0 1.9.3h0a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5h0a1.7 1.7 0 0 0 1.9-.3l.1-.1a2 2 0 1 1 2.9 2.9l-.1.1a1.7 1.7 0 0 0-.3 1.9v0a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></svg>
            ) },
          ] as const).map((item) => (
            <button
              key={item.id}
              className={`dyn-item ${activeWindow === item.id ? 'active' : ''}`}
              onClick={() => navigate(`/console/${item.id}`)}
              title={`${item.label} — ${item.desc}`}
              aria-label={item.label}
              aria-current={activeWindow === item.id ? 'page' : undefined}
            >
              <span className="dyn-item-icon">{item.icon}</span>
              <span className="dyn-item-label">{item.label}</span>
              {'badge' in item && item.badge > 0 && <span className="dyn-badge">{item.badge}</span>}
            </button>
          ))}
        </div>

        {islandLiveJob && (
          <>
            <div className="dyn-sep" aria-hidden="true" />
            <button
              className="dyn-live"
              onClick={() => { setActiveMonitorJobId(islandLiveJob.job.id); navigate('/console/audits'); void handleViewJobDetail(islandLiveJob.job.id); }}
              title={`${repoLabel(islandLiveJob.job.repo_url)} — ${islandLiveJob.job.status}, ${islandLiveJob.pct}% — open audit`}
              aria-label={`Audit in progress: ${repoLabel(islandLiveJob.job.repo_url)}, ${islandLiveJob.pct} percent. Open audit.`}
            >
              <span className="dyn-live-dot" aria-hidden="true" />
              <span className="dyn-live-repo">{repoLabel(islandLiveJob.job.repo_url)}</span>
              <span className="dyn-live-track" aria-hidden="true">
                <span className="dyn-live-fill" style={{ width: `${islandLiveJob.pct}%` }} />
              </span>
              <span className="dyn-live-pct">{islandLiveJob.pct}%</span>
            </button>
          </>
        )}

        <div className="dyn-sep" aria-hidden="true" />

        <button onClick={() => { openScanModal(); }} className="fc-btn-secondary fc-btn-sm dyn-audit" title="Start a new audit" aria-label="Start a new audit">
          <Plus size={15} />
          <span className="dyn-audit-label">New audit</span>
        </button>

        <div className="dyn-user">
          <Dropdown
            label="Account"
            align="end"
            triggerClassName="fc-user-btn"
            triggerLabel={`Account menu for ${user?.username ?? 'signed-in user'}`}
            trigger={
              <>
                <span className="dyn-avatar" aria-hidden="true">
                  {user?.username ? user.username[0].toUpperCase() : 'U'}
                </span>
                <span className="fc-user-name">{user?.username ?? 'Signed in'}</span>
                <ChevronDown size={14} aria-hidden="true" />
              </>
            }
          >
            <DropdownItem asHeader>
              <span className="fc-dropdown-head-name">{user?.username ?? 'Signed in'}</span>
              <span className="fc-dropdown-head-mail">{user?.email ?? 'No email on file'}</span>
            </DropdownItem>
            <DropdownItem icon={<Settings size={15} />} onSelect={() => navigate('/console/settings')}>
              Settings
            </DropdownItem>
            <DropdownItem icon={<LogOut size={15} />} onSelect={handleLogout}>
              Sign out
            </DropdownItem>
          </Dropdown>
        </div>
      </nav>

      {/* Main Container */}
      <main className="main-content">
        {/* Page Content Body */}
        <div className="page-body">
          {/* Tab 1: Overview */}
          {activeWindow === 'overview' && (
            <>
              {dashLoad === 'error' && (
                <div className="dash-error-banner">
                  <span>{dashError}</span>
                  <button className="fc-btn-secondary fc-btn-sm" onClick={() => fetchDashboardData(true, { force: true })}>Retry</button>
                </div>
              )}

              {/* Page introduction: the product promise in one glance —
                  which repositories were audited, what needs attention,
                  and how to fix it. */}
              <header className="page-head">
                <div className="page-head-main">
                  <p className="page-eyebrow">Next Lab · Fire Crow</p>
                  <h1 className="page-head-title">Overview</h1>
                  <p className="page-head-sub">
                    Verified findings, evidence, and fixes across your audited GitHub repositories — at a glance.
                  </p>
                </div>
                <div className="page-head-side">
                  {dashLoad === 'ready' && lastSync && (
                    <span className="page-head-meta">
                      <span className="status-dot status-dot-live" aria-hidden="true" />
                      Synced {timeAgo(lastSync.toISOString())}
                    </span>
                  )}
                  <button onClick={() => { openScanModal(); }} className="fc-btn-primary">
                    <Plus size={15} />
                    New audit
                  </button>
                </div>
              </header>

              {/* Summary Metrics: Truthful, enterprise-grade indicators */}
              <div className="fc-metrics-grid">
                <MetricCard
                  icon={<ShieldCheck size={18} />}
                  label="Audits completed"
                  value={completedCount}
                  hint="finished end to end"
                  tone={completedCount > 0 ? 'health' : 'neutral'}
                />
                <MetricCard
                  icon={<Flame size={18} />}
                  label="Running now"
                  value={jobs.filter(j => j.status === 'running' || j.status === 'queued').length}
                  hint="queued or scanning"
                  tone={jobs.some(j => j.status === 'running' || j.status === 'queued') ? 'accent' : 'neutral'}
                />
                <MetricCard
                  icon={<FileText size={18} />}
                  label="Reports ready"
                  value={reportsReady}
                  hint="ready to download"
                  tone="neutral"
                />
                <MetricCard
                  icon={<AlertTriangle size={18} />}
                  label="Needs attention"
                  value={jobs.filter(j => ['failed', 'cancelled', 'partial', 'engine_unavailable'].includes(j.status)).length}
                  hint="failed, partial, or incomplete"
                  tone={jobs.some(j => ['failed', 'cancelled', 'partial', 'engine_unavailable'].includes(j.status)) ? 'crit' : 'neutral'}
                />
              </div>

              {/* Live audit — only while a job is genuinely running or queued. */}
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
                          className="fc-btn-secondary fc-btn-sm"
                        >
                          View progress
                        </button>
                      </div>
                    </div>

                    <div className="live-audit-bar">
                      <div
                        className="live-audit-track"
                        role="progressbar"
                        aria-valuemin={0}
                        aria-valuemax={100}
                        aria-valuenow={pct}
                        aria-label={`Audit progress for ${repoLabel(job.repo_url)}`}
                      >
                        <div className={`live-audit-fill${isRunning ? ' is-running' : ''}`} style={{ width: `${pct}%` }} />
                      </div>
                      <span className="live-audit-pct" role="status" aria-live="polite">{pct}%</span>
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

              {/* Decision surface: the audits that need a developer first.
                  Failed, partial, and engine-missing runs are never presented
                  as clean — each row says what happened and what to do next. */}
              <div className="fc-main-grid">
                <AuditTable
                  jobs={jobs}
                  activeJobId={activeMonitorJobId}
                  onSelectJob={(jobId) => { handleViewJobDetail(jobId); setActiveMonitorJobId(jobId); }}
                  onStartAudit={(preset) => {
                    if (preset && preset.startsWith('http')) {
                      setNewRepoUrl(preset);
                    }
                    openScanModal();
                  }}
                  onDownloadReport={handleDownloadReport}
                />

                <div className="fc-side-stack">
                  <section className="fc-panel" aria-label="What needs your attention">
                    <div className="fc-panel-header">
                      <div>
                        <h2 className="fc-panel-title">Needs attention</h2>
                        <p className="fc-panel-subtitle">Incomplete or failed audits first — never mistaken for clean</p>
                      </div>
                    </div>
                    {(() => {
                      const attention = needsAttention(jobs, 5);
                      if (attention.length === 0) {
                        return (
                          <p className="fc-calm-note">
                            {jobs.length === 0
                              ? 'No audits yet. Submit a repository to get your first verified findings.'
                              : 'Nothing waiting — every finished audit completed. New failures or partial runs will appear here.'}
                          </p>
                        );
                      }
                      const reason = (j: JobResponse): string => {
                        switch (j.status) {
                          case 'failed': return j.error_message || 'The audit failed before producing a report.';
                          case 'cancelled': return 'Cancelled before completion — no verdict was reached.';
                          case 'partial': return 'Partial coverage: some scanners did not finish. Not a complete audit.';
                          case 'engine_unavailable': return 'No scan engine ran for this audit. Not a clean result.';
                          case 'running': return 'Scan in progress — findings appear when it finishes.';
                          default: return 'Queued — waiting for a scan slot.';
                        }
                      };
                      const retryable = (s: string) => ['failed', 'cancelled', 'partial', 'engine_unavailable'].includes(s);
                      return (
                        <ul className="fc-attention-list">
                          {attention.map(j => (
                            <li key={j.id} className="fc-attention-item">
                              <div className="fc-attention-main">
                                <div className="fc-attention-top">
                                  <span className="fc-attention-repo">{repoLabel(j.repo_url)}</span>
                                  <StatusPill status={j.status} />
                                </div>
                                <p className="fc-attention-reason" title={reason(j)}>{reason(j)}</p>
                                <p className="fc-attention-meta">{j.repo_branch} · {timeAgo(j.created_at) || 'just now'}</p>
                              </div>
                              <div className="fc-attention-actions">
                                <button
                                  type="button"
                                  className="fc-btn-secondary fc-btn-sm"
                                  onClick={() => { handleViewJobDetail(j.id); setActiveMonitorJobId(j.id); }}
                                >
                                  Inspect
                                </button>
                                {retryable(j.status) && (
                                  <button
                                    type="button"
                                    className="fc-btn-secondary fc-btn-sm"
                                    disabled={retryBusy}
                                    onClick={() => void handleRetryJob(j.id)}
                                  >
                                    Retry
                                  </button>
                                )}
                              </div>
                            </li>
                          ))}
                        </ul>
                      );
                    })()}
                  </section>

                  <section className="fc-panel" aria-label="How Fire Crow works">
                    <div className="fc-panel-header">
                      <div>
                        <h2 className="fc-panel-title">How an audit works</h2>
                        <p className="fc-panel-subtitle">Scanner evidence first, AI explanation optional</p>
                      </div>
                    </div>
                    <ol className="fc-how-list">
                      <li><strong>Submit a repository.</strong> Audit a branch head or a pinned commit.</li>
                      <li><strong>Scanners inspect it.</strong> Secrets, vulnerable dependencies, risky code patterns.</li>
                      <li><strong>Evidence is consolidated.</strong> One canonical report per attempt — file, line, evidence, scanner provenance.</li>
                      <li><strong>You prioritize and fix.</strong> Severity first, with remediation guidance and references.</li>
                    </ol>
                    <p className="fc-calm-note">AI can explain a finding, but never invents one: severity always comes from scanner evidence.</p>
                  </section>
                </div>
              </div>

            </>
          )}

          {/* Window: Audits — execution history. Each row is one audit run with
              its own status, score, and report; attempts are never merged. */}
          {activeWindow === 'audits' && (
            <div className="fc-panel">
              <div className="fc-panel-header">
                <div>
                  <h2 className="fc-panel-title">Audits ({jobs.length})</h2>
                  <p className="fc-panel-subtitle">
                    {dashLoad === 'ready' && lastSync ? `Synced ${timeAgo(lastSync.toISOString())}` : 'Repository audit execution history'}
                  </p>
                </div>
                <div className="panel-actions">
                  <button onClick={() => fetchDashboardData(true, { force: true })} className="fc-btn-secondary fc-btn-sm" disabled={dashLoad === 'loading'}>
                    {dashLoad === 'loading' ? 'Syncing…' : 'Refresh'}
                  </button>
                  <button onClick={() => { openScanModal(); }} className="fc-btn-primary fc-btn-sm">New audit</button>
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
                        <button onClick={() => { openScanModal(); }} className="fc-btn-primary fc-btn-sm">
                          Start an audit
                        </button>
                      }
                    />
                  ) : (
                    <div className="fc-table-responsive-wrap">
                      <table className="fc-table">
                        <thead>
                          <tr>
                            <th scope="col" style={{ width: '100px' }}>Job</th>
                            <th scope="col">Repository</th>
                            <th scope="col">Status</th>
                            <th scope="col">Score</th>
                            <th scope="col">Created</th>
                            <th scope="col" style={{ textAlign: 'right' }}>Actions</th>
                          </tr>
                        </thead>
                        <tbody>
                          {jobs.map(j => {
                            const isActive = j.status === 'queued' || j.status === 'running';
                            const busy = cancellingIds.includes(j.id);
                            return (
                              <tr key={j.id} className="fc-table-row" style={{ opacity: busy ? 0.55 : 1 }}>
                                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.74rem', color: '#888888' }}>{j.id.substring(0, 8)}</td>
                                <td>
                                  <div style={{ fontWeight: 600, color: '#FFFFFF', fontSize: '0.86rem', fontFamily: 'var(--font-mono)' }}>{repoLabel(j.repo_url)}</div>
                                  <div style={{ display: 'flex', gap: '0.35rem', alignItems: 'center', marginTop: '0.2rem' }}>
                                    <span className="fc-branch-tag">
                                      <GitBranch size={11} className="inline mr-1 text-zinc-400" />
                                      {j.repo_branch}
                                    </span>
                                    {(j.commit_sha || j.requested_commit_sha) ? (
                                      <span className="fc-sha-tag font-mono" title={`Pinned snapshot ${j.commit_sha || j.requested_commit_sha}`}>⏺ {((j.commit_sha || j.requested_commit_sha) ?? '').substring(0, 8)}</span>
                                    ) : null}
                                  </div>
                                </td>
                                <td>
                                  <StatusPill status={j.status} />
                                  {(j.status === 'failed') && j.error_message && (
                                    <div className="fc-repo-error-hint" title={j.error_message}>
                                      {j.error_message}
                                    </div>
                                  )}
                                </td>
                                <td>
                                  {j.security_score != null ? (
                                    <ScoreRing score={j.security_score} size={30} />
                                  ) : (
                                    <span className="fc-score-na" title="Score not available for this run">N/A</span>
                                  )}
                                </td>
                                <td style={{ color: '#888888', fontSize: '0.74rem' }} title={fmtUtc(j.created_at)}>{timeAgo(j.created_at)}</td>
                                <td>
                                  <div className="fc-actions-group">
                                    <button onClick={() => handleViewJobDetail(j.id)} className="fc-btn-action">Inspect</button>
                                    {j.status === 'completed' && (
                                      <button onClick={() => handleDownloadReport(j.id)} className="fc-btn-action" title="Download report">Report</button>
                                    )}
                                    {isActive && (
                                      <button onClick={() => handleCancelJob(j.id)} className="fc-btn-secondary fc-btn-sm" style={{ color: 'var(--fc-critical)' }} disabled={busy}>
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

          {/* Window: Repositories — identity, branches/commits, audit history,
              and the supported audit action. Groups real audit runs by repo. */}
          {activeWindow === 'repositories' && (
            <>
              <header className="page-head">
                <div className="page-head-main">
                  <p className="page-eyebrow">Next Lab · Fire Crow</p>
                  <h1 className="page-head-title">Repositories</h1>
                  <p className="page-head-sub">
                    Connected GitHub repositories and everything audited so far.
                  </p>
                </div>
                <div className="page-head-side">
                  <button
                    type="button"
                    onClick={() => void fetchUserRepos(true)}
                    className="fc-btn-secondary"
                    disabled={isLoadingRepos}
                    title="Sync connected repositories from GitHub"
                  >
                    <RefreshCw size={14} className={isLoadingRepos ? 'spin' : ''} />
                    <span>{isLoadingRepos ? 'Syncing…' : 'Sync repositories'}</span>
                  </button>
                  <button onClick={() => { openScanModal(); }} className="fc-btn-primary">
                    <Plus size={15} />
                    New audit
                  </button>
                </div>
              </header>

              <section className="fc-panel fc-panel-flush" aria-label="Connected GitHub repositories">
                <div className="fc-panel-header">
                  <div>
                    <h2 className="fc-panel-title">Connected repositories</h2>
                    <p className="fc-panel-subtitle">Synced from your GitHub account</p>
                  </div>
                  {userRepos.length > 0 && (
                    <span className="fc-repo-count-badge">
                      {userRepos.length} {userRepos.length === 1 ? 'repository' : 'repositories'}
                    </span>
                  )}
                </div>
                {reposStatus === 'loading' || reposStatus === 'idle' ? (
                  <div className="state-skeleton" aria-busy="true">
                    {[0, 1, 2].map(i => <div key={i} className="skeleton-row" style={{ animationDelay: `${i * 0.12}s`, width: `${88 - i * 8}%` }} />)}
                  </div>
                ) : reposStatus === 'not_connected' ? (
                  <p className="fc-calm-note">GitHub is not connected — sign in with GitHub to list repositories here, or audit any public repository URL directly.</p>
                ) : (reposStatus === 'github_error' || reposStatus === 'network_error') ? (
                  <div className="state-error">
                    <span>Repository sync failed{reposMessage ? `: ${reposMessage}` : '.'} You can still audit a public URL.</span>
                    <button className="fc-btn-secondary fc-btn-sm" onClick={() => void fetchUserRepos(true)}>Retry</button>
                  </div>
                ) : userRepos.length === 0 ? (
                  <p className="fc-calm-note">No repositories found on the connected account. Audit a public URL instead.</p>
                ) : (
                  <ul className="fc-repo-list">
                    {userRepos.map(r => {
                      const url = r.clone_url || r.html_url || (r.full_name ? `https://github.com/${r.full_name}` : '');
                      const norm = (u?: string | null) => (u || '').toLowerCase().replace(/\.git$/, '').replace(/\/$/, '');
                      const cNorm = norm(r.clone_url);
                      const hNorm = norm(r.html_url);
                      const nameNorm = (r.full_name || '').toLowerCase();
                      const matchingJobs = jobs.filter(j => {
                        const jNorm = norm(j.repo_url);
                        return (cNorm && jNorm === cNorm) || (hNorm && jNorm === hNorm) || norm(repoLabel(j.repo_url)) === nameNorm;
                      });
                      const latestRun = matchingJobs.length > 0
                        ? [...matchingJobs].sort((a, b) => (a.created_at < b.created_at ? 1 : -1))[0]
                        : null;

                      return (
                        <li key={String(r.id ?? r.full_name)} className="fc-repo-item">
                          <div className="fc-repo-main">
                            <span className="fc-repo-name mono">{r.full_name}</span>
                            <div className="fc-repo-meta">
                              <span className={`badge fc-repo-visibility-pill ${r.private ? 'badge-neutral is-private' : 'badge-success is-public'}`}>
                                {r.private ? 'Private' : 'Public'}
                              </span>
                              <span className="mono fc-repo-branch">
                                <GitBranch size={12} className="fc-repo-branch-icon" />
                                {r.default_branch || 'main'}
                              </span>
                            </div>
                            {r.description && (
                              <p className="fc-repo-desc" title={r.description}>
                                {r.description}
                              </p>
                            )}
                          </div>
                          <div className="fc-repo-side">
                            <div className="fc-repo-audit-meta">
                              {latestRun ? (
                                <>
                                  <span className="fc-repo-last-run">
                                    Last audited {timeAgo(latestRun.created_at) || 'just now'}
                                  </span>
                                  <StatusPill status={latestRun.status} />
                                  {latestRun.security_score != null && (
                                    <ScoreRing score={latestRun.security_score} size={28} />
                                  )}
                                </>
                              ) : (
                                <span className="fc-repo-unscanned">Not audited yet</span>
                              )}
                            </div>
                            {url && (
                              <button
                                type="button"
                                className="fc-repo-audit-btn"
                                onClick={() => {
                                  setNewRepoUrl(url);
                                  setNewRepoBranch(r.default_branch || 'main');
                                  openScanModal();
                                }}
                                title={`Audit ${r.full_name}`}
                              >
                                Audit
                              </button>
                            )}
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </section>

              <section className="fc-panel fc-panel-flush" aria-label="Audit history by repository">
                <div className="fc-panel-header">
                  <div>
                    <h2 className="fc-panel-title">Audit history</h2>
                    <p className="fc-panel-subtitle">Runs grouped by repository — newest activity first</p>
                  </div>
                </div>
                {(() => {
                  const groups = new Map<string, JobResponse[]>();
                  for (const j of jobs) {
                    const key = j.repo_url || 'unknown';
                    const list = groups.get(key) ?? [];
                    list.push(j);
                    groups.set(key, list);
                  }
                  const ordered = [...groups.entries()].sort(([, a], [, b]) => ((a[0]?.created_at ?? '') < (b[0]?.created_at ?? '') ? 1 : -1));
                  if (ordered.length === 0) {
                    return (
                      <div style={{ padding: '24px' }}>
                        <EmptyState
                          title="No audited repositories"
                          body="Submit a repository to run your first audit."
                          action={
                            <button onClick={() => { openScanModal(); }} className="fc-btn-primary fc-btn-sm">
                              Start an audit
                            </button>
                          }
                        />
                      </div>
                    );
                  }
                  return (
                    <ul className="fc-repo-list">
                      {ordered.map(([repoUrl, runs]) => {
                        const latest = [...runs].sort((a, b) => (a.created_at < b.created_at ? 1 : -1))[0];
                        const sha = latest.commit_sha || latest.requested_commit_sha;
                        return (
                          <li key={repoUrl} className="fc-repo-item">
                            <div className="fc-repo-main">
                              <span className="fc-repo-name mono">{repoLabel(repoUrl)}</span>
                              <div className="fc-repo-meta">
                                <span className="fc-repo-count-badge">
                                  {runs.length} {runs.length === 1 ? 'audit' : 'audits'}
                                </span>
                                <span className="mono fc-repo-branch">
                                  <GitBranch size={12} className="fc-repo-branch-icon" />
                                  {latest.repo_branch}{sha ? ` · ${sha.substring(0, 8)}` : ''}
                                </span>
                                <span aria-hidden="true" className="fc-meta-sep">·</span>
                                <span>Last run {timeAgo(latest.created_at) || 'just now'}</span>
                              </div>
                            </div>
                            <div className="fc-repo-side">
                              <div className="fc-repo-audit-meta">
                                {latest.security_score != null && (
                                  <ScoreRing score={latest.security_score} size={28} />
                                )}
                                <StatusPill status={latest.status} />
                              </div>
                              <button
                                type="button"
                                className="fc-btn-secondary fc-btn-sm"
                                onClick={() => { handleViewJobDetail(latest.id); setActiveMonitorJobId(latest.id); }}
                              >
                                Inspect latest
                              </button>
                              <button
                                type="button"
                                className="fc-repo-audit-btn"
                                onClick={() => { setNewRepoUrl(repoUrl); setNewRepoBranch(latest.repo_branch || 'main'); openScanModal(); }}
                              >
                                Audit again
                              </button>
                            </div>
                          </li>
                        );
                      })}
                    </ul>
                  );
                })()}
              </section>
            </>
          )}

          {/* Window: Findings — what was detected, why it matters, where, and
              how to fix it. Findings live per audit run: pick a run to
              investigate its verified, evidence-backed findings. */}
          {activeWindow === 'findings' && (
            <>
              <header className="page-head">
                <div className="page-head-main">
                  <p className="page-eyebrow">Next Lab · Fire Crow</p>
                  <h1 className="page-head-title">Findings</h1>
                  <p className="page-head-sub">
                    Verified scanner evidence per audit run — severity, file and line, evidence, remediation, references.
                  </p>
                </div>
              </header>

              <section className="fc-panel" aria-label="Investigate audit findings">
                <div className="fc-panel-header">
                  <div>
                    <h2 className="fc-panel-title">Investigate an audit</h2>
                    <p className="fc-panel-subtitle">Finding counts and severity come from the audit report — never estimated here</p>
                  </div>
                </div>
                <PanelState
                  state={dashLoad}
                  error={dashError}
                  empty={jobs.length === 0}
                  rows={4}
                  onRetry={() => fetchDashboardData(true, { force: true })}
                >
                  {jobs.length === 0 ? (
                    <EmptyState
                      title="No audits to investigate"
                      body="Findings appear after your first audit finishes."
                      action={
                        <button onClick={() => { openScanModal(); }} className="fc-btn-primary fc-btn-sm">
                          Start an audit
                        </button>
                      }
                    />
                  ) : (
                    <ul className="fc-repo-list">
                      {[...jobs].sort((a, b) => (a.created_at < b.created_at ? 1 : -1)).map(j => {
                        const sha = j.commit_sha || j.requested_commit_sha;
                        const incomplete = ['partial', 'engine_unavailable', 'failed', 'cancelled'].includes(j.status);
                        return (
                          <li key={j.id} className="fc-repo-item">
                            <div className="fc-repo-main">
                              <span className="fc-repo-name">{repoLabel(j.repo_url)}</span>
                              <span className="fc-repo-meta">
                                <span className="mono">⎇ {j.repo_branch}{sha ? ` · ${sha.substring(0, 8)}` : ''}</span>
                                <span aria-hidden="true">·</span>
                                <span>{timeAgo(j.created_at) || 'just now'}</span>
                              </span>
                              {incomplete && (
                                <span className="fc-attention-reason">
                                  {j.status === 'partial' && 'Partial coverage — findings below are incomplete, not a full audit.'}
                                  {j.status === 'engine_unavailable' && 'No scan engine ran — there are no verified findings to show.'}
                                  {j.status === 'failed' && (j.error_message || 'This run failed before producing findings.')}
                                  {j.status === 'cancelled' && 'Cancelled before completion — no verdict was reached.'}
                                </span>
                              )}
                            </div>
                            <div className="fc-repo-side">
                              {j.security_score != null && <ScoreRing score={j.security_score} size={34} />}
                              <StatusPill status={j.status} />
                              <button
                                type="button"
                                className="fc-btn-secondary fc-btn-sm"
                                onClick={() => { handleViewJobDetail(j.id); setActiveMonitorJobId(j.id); }}
                              >
                                Investigate
                              </button>
                            </div>
                          </li>
                        );
                      })}
                    </ul>
                  )}
                </PanelState>
              </section>
            </>
          )}

          {/* Window: Settings — only supported account and application settings. */}
          {activeWindow === 'settings' && (
            <>
              <header className="page-head">
                <div className="page-head-main">
                  <p className="page-eyebrow">Next Lab · Fire Crow</p>
                  <h1 className="page-head-title">Settings</h1>
                  <p className="page-head-sub">
                    Your account and sign-in security.
                  </p>
                </div>
              </header>

              <div className="fc-settings-grid">
                <section className="fc-panel" aria-label="Account">
                  <div className="fc-panel-header">
                    <div>
                      <h2 className="fc-panel-title">Account</h2>
                      <p className="fc-panel-subtitle">Signed-in identity for this workspace</p>
                    </div>
                  </div>
                  <dl className="fc-settings-list">
                    <div className="fc-settings-row">
                      <dt>Username</dt>
                      <dd>{user?.username ?? '—'}</dd>
                    </div>
                    <div className="fc-settings-row">
                      <dt>Email</dt>
                      <dd>{user?.email ?? '—'}</dd>
                    </div>
                  </dl>
                  <div style={{ marginTop: '1rem' }}>
                    <button onClick={handleLogout} className="fc-btn-secondary fc-btn-sm">
                      Sign out
                    </button>
                  </div>
                </section>

                <section className="fc-panel" aria-label="Two-factor authentication">
                  <div className="fc-panel-header">
                    <div>
                      <h2 className="fc-panel-title">Two-factor authentication</h2>
                      <p className="fc-panel-subtitle">TOTP authenticator protection for your account</p>
                    </div>
                    <span className={`badge ${mfaStatus.enabled ? 'badge-success' : 'badge-neutral'}`}>{mfaStatus.enabled ? 'Active' : 'Disabled'}</span>
                  </div>
                  <PanelState state={dashLoad} error={dashError} onRetry={() => fetchDashboardData(true, { force: true })}>
                    <p className="fc-calm-note">
                      {mfaStatus.enabled
                        ? `Protected · ${mfaStatus.backup_codes_remaining} recovery codes remaining.`
                        : 'Two-factor protection is not enrolled.'}
                    </p>
                    <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.75rem' }}>
                      {mfaStatus.enabled
                        ? <button onClick={handleMfaDisable} className="fc-btn-danger fc-btn-sm">Disable MFA</button>
                        : <button onClick={handleMfaEnroll} className="fc-btn-primary fc-btn-sm">Enroll TOTP app</button>}
                    </div>
                  </PanelState>
                </section>

                <section className="fc-panel" aria-label="About Fire Crow">
                  <div className="fc-panel-header">
                    <div>
                      <h2 className="fc-panel-title">About this workspace</h2>
                      <p className="fc-panel-subtitle">What Fire Crow does and does not claim</p>
                    </div>
                  </div>
                  <p className="fc-calm-note">
                    Fire Crow audits GitHub repositories with established scanners and consolidates their
                    output into one evidence-backed report per attempt: severity, file and line, evidence,
                    remediation, and references.
                  </p>
                  <p className="fc-calm-note">
                    AI explanations are optional annotations. Incomplete, failed, or engine-missing runs are
                    always labeled as such — never as a clean bill of health.
                  </p>
                </section>
              </div>
            </>
          )}

          {/* Modal: MFA Enrollment (POST /mfa/enroll response) */}
          {mfaEnrollment && (
            <div className="modal-backdrop" onClick={() => setMfaEnrollment(null)}>
              <div
                className="modal"
                role="dialog"
                aria-modal="true"
                aria-labelledby="fc-mfa-modal-title"
                onClick={e => e.stopPropagation()}
              >
                <div className="modal-head">
                  <div>
                    <div className="modal-title" id="fc-mfa-modal-title">MFA Enrollment</div>
                    <div className="modal-sub">Add the secret to your authenticator app, then activate with a 6-digit code from /mfa endpoints or CLI.</div>
                  </div>
                  <button onClick={() => setMfaEnrollment(null)} className="btn btn-ghost btn-icon" aria-label="Close MFA enrollment">✕</button>
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
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '0.4rem' }}>
                      {(mfaEnrollment.recovery_codes || []).map((c) => (
                        <code key={c} style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', background: 'var(--fc-surface-elevated, #1A1A1A)', border: '1px solid var(--fc-border, #2A2A2A)', color: 'var(--fc-text-primary, #FFFFFF)', borderRadius: '6px', padding: '0.35rem 0.55rem' }}>{c}</code>
                      ))}
                    </div>
                  </div>
                </div>
                <div className="modal-footer">
                  <button onClick={() => setMfaEnrollment(null)} className="fc-btn-primary">I've stored my codes</button>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>

      {/* Modal: New Scan */}
      {isScanModalOpen && (
        <div className="modal-backdrop" onClick={() => setIsScanModalOpen(false)}>
          <div
            className="modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="fc-scan-modal-title"
            onClick={e => e.stopPropagation()}
          >
            <div className="modal-head">
              <div>
                <div className="modal-title" id="fc-scan-modal-title">Start an audit</div>
                <div className="modal-sub">Submit a repository for a security audit</div>
              </div>
              <button
                type="button"
                onClick={() => setIsScanModalOpen(false)}
                className="fc-modal-close-btn"
                title="Close modal"
                aria-label="Close modal"
                autoFocus
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleStartScan}>
              <div className="modal-body">
                <div className="fc-modal-repo-picker">
                  <div className="fc-modal-repo-header">
                    <div className="fc-modal-repo-labels">
                      <label className="form-label" htmlFor="github-repo-select">Your GitHub repositories</label>
                      <span className="fc-modal-repo-caption">
                        {reposStatus === 'not_connected'
                          ? 'GitHub not connected — audit any public URL directly'
                          : reposStatus === 'github_error' || reposStatus === 'network_error'
                            ? `Sync failed${reposMessage ? `: ${reposMessage}` : ''} — paste URL below`
                            : userRepos.length > 0
                              ? `${userRepos.length} repositories synchronized from GitHub`
                              : 'Sync to select from your GitHub repositories'}
                      </span>
                    </div>
                    <button 
                      type="button" 
                      onClick={() => void fetchUserRepos(true)} 
                      className="fc-modal-sync-btn"
                      disabled={isLoadingRepos}
                      title="Sync repositories from your GitHub account"
                    >
                      <RefreshCw size={12} className={isLoadingRepos ? 'spin' : ''} />
                      <span>{isLoadingRepos ? 'Syncing…' : 'Sync repos'}</span>
                    </button>
                  </div>
                  <div className="fc-select-wrap">
                    <select 
                      id="github-repo-select"
                      className="fc-modal-select"
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
                    <svg className="fc-select-chevron" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <polyline points="6 9 12 15 18 9"></polyline>
                    </svg>
                  </div>
                </div>

                <div className="form-group">
                  <label className="form-label" htmlFor="repo-git-url">Repository Git URL</label>
                  <input 
                    id="repo-git-url"
                    type="text" 
                    className="form-input" 
                    placeholder="https://github.com/org/repo"
                    value={newRepoUrl}
                    onChange={e => setNewRepoUrl(e.target.value)}
                    required
                  />
                </div>

                <div className="form-row-2col">
                  <div className="form-group">
                    <label className="form-label" htmlFor="repo-branch">Branch</label>
                    <input 
                      id="repo-branch"
                      type="text" 
                      className="form-input" 
                      value={newRepoBranch}
                      onChange={e => setNewRepoBranch(e.target.value)}
                    />
                  </div>

                  <div className="form-group">
                    <label className="form-label" htmlFor="repo-commit">Pinned commit (optional)</label>
                    <input
                      id="repo-commit"
                      type="text" 
                      className="form-input font-mono"
                      placeholder="40-char lowercase hex"
                      value={newCommitSha}
                      onChange={e => setNewCommitSha(e.target.value)}
                      maxLength={40}
                    />
                  </div>
                </div>

                {modalError && <div className="error-box" style={{ marginBottom: '1rem' }}>{modalError}</div>}
              </div>

              <div className="modal-footer">
                <button type="button" onClick={() => setIsScanModalOpen(false)} className="fc-btn-cancel">
                  Cancel
                </button>
                <button type="submit" className="fc-btn-submit-job" disabled={isSubmitting || !newRepoUrl.trim()}>
                  {isSubmitting ? 'Submitting…' : 'Submit Job'}
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
              <button onClick={() => closeInspector()} className="btn btn-ghost btn-icon" aria-label="Close audit inspector">✕</button>
            </div>

            <div className="modal-body modal-body-scroll">
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
                          <button className="fc-btn-secondary fc-btn-sm" onClick={() => void selectExecution(selectedJobDetail.job.id, selectedExecutionId)}>Retry</button>
                        </div>
                      )}
                      {reportState === 'ready' && execReport && (
                        <div style={{ marginBottom: '0.75rem', padding: '0.75rem 0.9rem', borderRadius: '8px', border: '1px solid var(--fc-border, #2A2A2A)', background: 'var(--fc-surface-elevated, #1A1A1A)' }}>
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
                    <div className="finding-filters">
                      <input
                        type="text"
                        className="form-input"
                        placeholder="Search title, description, path…"
                        value={findingQuery}
                        onChange={e => setFindingQuery(e.target.value)}
                        style={{ flex: 1 }}
                        aria-label="Search findings"
                      />
                      <Dropdown
                        label="Filter by severity"
                        align="end"
                        triggerClassName="fc-select"
                        triggerLabel="Filter by severity"
                        trigger={
                          <>
                            <span>{severityFilterLabel(findingSev)}</span>
                            <ChevronDown size={14} aria-hidden="true" />
                          </>
                        }
                      >
                        {SEVERITY_FILTERS.map(s => (
                          <DropdownOption key={s} selected={findingSev === s} onSelect={() => setFindingSev(s)}>
                            {severityFilterLabel(s)}
                          </DropdownOption>
                        ))}
                      </Dropdown>
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
                        <div className="finding-meta-row">
                          <span className={`badge ${severityClass(f.severity)}`}>{(f.severity || 'info').toUpperCase()}</span>
                          {f.cvss != null && <span className="badge badge-neutral">CVSS {f.cvss.toFixed(1)}</span>}
                          {f.cwe && <span style={{ fontSize: '0.73rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{f.cwe}</span>}
                          {f.file && (
                            <span className="finding-path" title={`${f.file}${f.line != null ? `:${f.line}` : ''}`}>
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
                        <div style={{ fontSize: '0.8rem', padding: '0.75rem 0.9rem', borderRadius: '8px', border: '1px solid var(--fc-border, #2A2A2A)', background: 'var(--fc-surface-elevated, #1A1A1A)' }}>
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
    </div>
  );
}

export default App;
