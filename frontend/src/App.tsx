import { useState, useEffect, useCallback, useRef } from 'react';
import { HeroScene, AuroraBackdrop, useScrollReveal } from './scene';
import {
  PanelState, ScoreRing, SeverityBars, HealthWidget, jobStatusInfo, severityClass,
  fmtUtc, timeAgo, type LoadState, type DeepHealth,
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

/* Matches backend JobResponse (API_DOCUMENTATION.md §8) */
interface AuditJob {
  id: string;
  repo_url: string;
  repo_branch: string;
  status: string;
  created_at: string;
  security_score?: number | null;
  error_message?: string | null;
  report_pdf_url?: string | null;
  cancel_requested?: boolean;
}

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
  const token = localStorage.getItem('access_token');
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> || {}),
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  const res = await fetch(`${API_BASE}${endpoint}`, {
    credentials: 'include',
    ...options,
    headers,
  });

  // Auto purge tokens on 401 Unauthorized
  if (res.status === 401 && endpoint !== '/auth/login' && endpoint !== '/auth/register' && endpoint !== '/auth/demo') {
    localStorage.removeItem('access_token');
    document.cookie = 'access_token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
    document.cookie = 'refresh_token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
  }

  return res;
};

function App() {
  const [view, setView] = useState<'landing' | 'login' | 'dashboard'>('landing');
  const [user, setUser] = useState<UserProfile | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');

  // Dashboard Tab state
  const [dashTab, setDashTab] = useState<'overview' | 'scans' | 'identity' | 'security'>('overview');
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
  const [jobs, setJobs] = useState<AuditJob[]>([]);
  const [selectedJobDetail, setSelectedJobDetail] = useState<{ job: AuditJob; findings: Finding[] } | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [_selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [ssoProviders, setSsoProviders] = useState<SsoProvider[]>([]);
  const [pamRequests, setPamRequests] = useState<PamRequest[]>([]);
  const [_pamGrants, setPamGrants] = useState<PamGrant[]>([]);
  const [_iamPolicies, setIamPolicies] = useState<IamPolicy[]>([]);
  const [domains, setDomains] = useState<DomainVerification[]>([]);
  const [activities, setActivities] = useState<ActivityEvent[]>([]);
  const [mfaStatus, setMfaStatus] = useState<MfaStatus>({ enabled: false, backup_codes_remaining: 0 });
  const [activeMonitorJobId, setActiveMonitorJobId] = useState<string | null>(null);
  const [monitorPhases, setMonitorPhases] = useState<any[]>([]);

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
  const [userRepos, setUserRepos] = useState<any[]>([]);
  const [isLoadingRepos, setIsLoadingRepos] = useState(false);

  const fetchUserRepos = async () => {
    setIsLoadingRepos(true);
    try {
      const res = await apiFetch('/user/repos');
      if (res.ok) {
        const data = await res.json();
        if (data && data.repositories) {
          setUserRepos(data.repositories);
        }
      }
    } catch (err) {
      console.error('Failed to fetch user repos', err);
    } finally {
      setIsLoadingRepos(false);
    }
  };

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

  // Interactive Dynamic Landing Page States
  const [billingCycle, setBillingCycle] = useState<'monthly' | 'annual'>('monthly');
  const [openFaqIndex, setOpenFaqIndex] = useState<number | null>(0);

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

  // Auth Form State
  const [authFormError, setAuthFormError] = useState('');

  // Landing Page Interactive State
  const [landingTab, setLandingTab] = useState<'terminal' | 'graph' | 'diff'>('terminal');

  // Fetch all real backend data in parallel with explicit load-state tracking
  const fetchDashboardData = useCallback(async (showSpinner = false) => {
    if (showSpinner) setDashLoad('loading');
    try {
      const results = await Promise.allSettled([
        apiFetch('/audit/jobs'),
        apiFetch('/sso/providers'),
        apiFetch('/pam/requests'),
        apiFetch('/pam/grants'),
        apiFetch('/iam/policies'),
        apiFetch('/verify/domains'),
        apiFetch('/auth/activities'),
        apiFetch('/mfa/status'),
      ]);

      const [jobsRes, ssoRes, pamReqRes, pamGrantRes, iamRes, domainRes, actRes, mfaRes] = results;

      // Jobs are the primary dataset — a failure here surfaces as a dashboard error.
      let jobsOk = false;
      if (jobsRes.status === 'fulfilled' && jobsRes.value.ok) {
        setJobs(await jobsRes.value.json());
        jobsOk = true;
      } else if (jobsRes.status === 'rejected') {
        throw jobsRes.reason;
      } else if (jobsRes.value.status === 401) {
        throw new Error('Session expired — please sign in again.');
      } else {
        throw new Error(`Audit API returned HTTP ${jobsRes.value.status}`);
      }

      if (ssoRes.status === 'fulfilled' && ssoRes.value.ok) setSsoProviders(await ssoRes.value.json());
      if (pamReqRes.status === 'fulfilled' && pamReqRes.value.ok) setPamRequests(await pamReqRes.value.json());
      if (pamGrantRes.status === 'fulfilled' && pamGrantRes.value.ok) setPamGrants(await pamGrantRes.value.json());
      if (iamRes.status === 'fulfilled' && iamRes.value.ok) setIamPolicies(await iamRes.value.json());
      if (domainRes.status === 'fulfilled' && domainRes.value.ok) setDomains(await domainRes.value.json());
      if (actRes.status === 'fulfilled' && actRes.value.ok) setActivities(await actRes.value.json());
      if (mfaRes.status === 'fulfilled' && mfaRes.value.ok) setMfaStatus(await mfaRes.value.json());

      setDashError(null);
      setDashLoad('ready');
      if (jobsOk) setLastSync(new Date());
    } catch (err: any) {
      console.warn('Dashboard live data fetch error:', err);
      setDashError(err?.message || 'Network error — backend unreachable.');
      setDashLoad('error');
    }
  }, []);

  // Deep health telemetry (public endpoint, per API docs §14)
  useEffect(() => {
    if (view !== 'dashboard') return;
    let alive = true;
    const probe = async () => {
      try {
        const base = API_BASE.replace(/\/api\/v1$/, '');
        const res = await fetch(`${base}/health/deep`);
        if (!alive) return;
        setDeepHealth(res.ok ? await res.json() : { status: 'unhealthy', database: 'unavailable' });
      } catch {
        if (alive) setDeepHealth({ status: 'network_failure', database: 'unreachable' });
      }
    };
    probe();
    const t = setInterval(probe, 30000);
    return () => { alive = false; clearInterval(t); };
  }, [view]);

  // Cancel an active job via DELETE /audit/job/{id}
  const handleCancelJob = async (jobId: string) => {
    setCancellingIds((ids) => [...ids, jobId]);
    try {
      const res = await apiFetch(`/audit/job/${jobId}`, { method: 'DELETE' });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        setModalError(body.detail || `Cancel failed (HTTP ${res.status})`);
      }
    } catch {
      setModalError('Network error while cancelling job.');
    } finally {
      setCancellingIds((ids) => ids.filter((id) => id !== jobId));
      fetchDashboardData();
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
      fetchDashboardData();
    } catch {
      setModalError('Network error during MFA enrollment.');
    }
  };

  const handleMfaDisable = async () => {
    try {
      const res = await apiFetch('/mfa/disable', { method: 'POST' });
      if (!res.ok) { setModalError(`MFA disable failed (HTTP ${res.status})`); return; }
      setMfaEnrollment(null);
      fetchDashboardData();
    } catch {
      setModalError('Network error while disabling MFA.');
    }
  };

  useEffect(() => {
    if (view !== 'dashboard') return;
    const targetJobId = activeMonitorJobId || (jobs.length > 0 ? jobs[0].id : null);
    if (!targetJobId) return;

    const fetchPhases = async () => {
      try {
        const res = await apiFetch(`/audit/job/${targetJobId}/phases`);
        if (res.ok) {
          const data = await res.json();
          setMonitorPhases(data);
        }
      } catch (err) {
        console.warn('Error fetching job phases:', err);
      }
    };

    // Determine if job is still active using current jobs state
    const activeJob = jobs.find(j => j.id === targetJobId);
    const isJobActive = !activeJob || activeJob.status === 'running' || activeJob.status === 'queued';

    // Initial fetch
    fetchPhases();
    if (isJobActive) {
      fetchDashboardData();
    }

    // If job is finished, do a single fetch but don't start polling
    if (!isJobActive) return;

    // Poll at 2s intervals while job is active
    const interval = setInterval(() => {
      fetchPhases();
      fetchDashboardData();
    }, 2000);
    return () => clearInterval(interval);
  }, [view, activeMonitorJobId, jobs]);

  // Scroll-reveal choreography for landing page sections
  useScrollReveal(view === 'landing', '.apple-landing-page section');

  // Auto-sync repositories from GitHub whenever dashboard opens or scan modal opens
  useEffect(() => {
    if (user && (view === 'dashboard' || isScanModalOpen)) {
      fetchUserRepos();
    }
  }, [user, view, isScanModalOpen]);

  const oauthHandledRef = useRef(false);
  const sessionCheckedRef = useRef(false);

  // Check active session or OAuth exchange on mount
  useEffect(() => {
    const checkSession = async () => {
      try {
        const res = await apiFetch('/auth/me');
        if (res.ok) {
          const data = await res.json();
          setUser({
            user_id: data.user_id,
            username: data.username,
            email: data.email,
            credit_balance: data.credit_balance,
          });
          setView('dashboard');
          fetchDashboardData(true);
        } else {
          localStorage.removeItem('access_token');
          document.cookie = 'access_token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
          document.cookie = 'refresh_token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
          setUser(null);
        }
      } catch (err) {
        console.warn('No active session found:', err);
        setUser(null);
      } finally {
        setIsLoading(false);
      }
    };

    const handleOAuthCallback = async (code: string) => {
      setIsLoading(true);
      setError('');
      try {
        const exchangeRes = await fetch(`${API_BASE}/auth/exchange`, {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code }),
        });

        if (!exchangeRes.ok) {
          throw new Error('Failed to exchange authorization code.');
        }

        const exchangeData = await exchangeRes.json();
        if (exchangeData.access_token) {
          localStorage.setItem('access_token', exchangeData.access_token);
        }

        if (exchangeData.user_id && exchangeData.username) {
          setUser({
            user_id: exchangeData.user_id,
            username: exchangeData.username,
            email: exchangeData.email || null,
          });
          setView('dashboard');
          fetchDashboardData();
        }

        try {
          const meRes = await apiFetch('/auth/me');
          if (meRes.ok) {
            const data = await meRes.json();
            setUser({
              user_id: data.user_id,
              username: data.username,
              email: data.email,
              credit_balance: data.credit_balance,
            });
            setView('dashboard');
          }
        } catch {
          // If background meRes fails, remain logged in via exchangeData
        }
      } catch (err: any) {
        setError(err.message || 'Authentication failed. Please try again.');
        setView('login');
      } finally {
        window.history.replaceState({}, document.title, window.location.pathname);
        setIsLoading(false);
      }
    };

    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const oauthError = params.get('oauth_error');

    if (oauthError) {
      setError(`OAuth login failed: ${decodeURIComponent(oauthError)}`);
      setView('login');
      window.history.replaceState({}, document.title, window.location.pathname);
      setIsLoading(false);
    } else if (code) {
      if (oauthHandledRef.current) return;
      oauthHandledRef.current = true;
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
      await apiFetch('/auth/logout', { method: 'POST' });
    } catch (err) {
      console.error('Logout error:', err);
    } finally {
      localStorage.removeItem('access_token');
      document.cookie = 'access_token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
      document.cookie = 'refresh_token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
      setUser(null);
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
      setView('landing');
      setIsLoading(false);
    }
  };

  // Submit real audit job
  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRepoUrl || !newRepoUrl.trim()) return;

    setModalError('');
    setIsSubmitting(true);

    try {
      const res = await apiFetch('/audit/submit', {
        method: 'POST',
        body: JSON.stringify({
          repo_url: newRepoUrl.trim(),
          repo_branch: newRepoBranch.trim() || 'main',
        }),
      });

      if (res.ok) {
        const data = await res.json().catch(() => ({}));
        setIsScanModalOpen(false);
        setNewRepoUrl('');
        if (data && data.job_id) {
          setActiveMonitorJobId(data.job_id);
        }
        setDashTab('overview');
        setView('dashboard');
        fetchDashboardData();
      } else {
        const errData = await res.json().catch(() => ({}));
        setModalError(errData.message || errData.error || errData.detail || 'Failed to submit audit job.');
      }
    } catch (err: any) {
      setModalError(err.message || 'Network error submitting scan job.');
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
        fetchDashboardData();
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
        fetchDashboardData();
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
        fetchDashboardData();
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

  // Fetch specific job details
  const handleViewJobDetail = async (jobId: string) => {
    setSelectedJobDetail({ job: { id: jobId } as AuditJob, findings: [] });
    setDetailLoading(true);
    try {
      const res = await apiFetch(`/audit/job/${jobId}`);
      if (res.ok) {
        const detail = await res.json();
        setSelectedJobDetail(detail);
        if (detail.findings && detail.findings.length > 0) {
          setSelectedFinding(detail.findings[0]);
        }
      } else {
        setModalError(`Failed to load job details (HTTP ${res.status}).`);
        setSelectedJobDetail(null);
      }
    } catch (err) {
      console.error('Fetch job detail error:', err);
      setModalError('Network error while loading job details.');
      setSelectedJobDetail(null);
    } finally {
      setDetailLoading(false);
    }
  };

  if (isLoading) {
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
  if (view === 'landing') {
    return (
      <div className="apple-landing-page">
        {/* Ambient Apple Atmospheric Glows */}
        <div className="apple-ambient-glow-top"></div>
        <div className="apple-ambient-glow-mid"></div>

        {/* Apple Frosted Glass Navigation Bar */}
        <header className="apple-nav">
          <div className="apple-nav-container">
            <div className="apple-logo-wrap" onClick={() => setView('landing')}>
              <img src="/fire-crow-logo.png" alt="Fire Crow Logo" className="logo-img" />
              <span className="apple-logo-text">Fire Crow</span>
            </div>

            <nav className="apple-nav-links">
              <a href="#capabilities" className="apple-nav-link">Product</a>
              <a href="#architecture" className="apple-nav-link">How it works</a>
              <a href="#metrics" className="apple-nav-link">Performance</a>
              <a href="#pricing" className="apple-nav-link">Pricing</a>
              <a href="https://github.com/johan-droid/Fire-Crow-" target="_blank" rel="noreferrer" className="apple-nav-link">GitHub</a>
            </nav>

            <div className="apple-nav-actions">
              <button onClick={() => setView('login')} className="btn-apple-secondary" style={{ padding: '0.45rem 1.1rem', fontSize: '0.82rem' }}>
                Sign In
              </button>
              <button onClick={() => setView('login')} className="btn-apple-primary" style={{ padding: '0.45rem 1.25rem', fontSize: '0.82rem' }}>
                Launch Console →
              </button>
            </div>
          </div>
        </header>

        {/* Apple Hero Section */}
        <section className="apple-hero-section">
          <HeroScene />
          <div className="apple-pill-badge">
            <div className="apple-status-beacon"></div>
            <span>Agentic Application Security Platform</span>
          </div>

          <h1 className="apple-hero-headline">
            <span className="apple-headline-gradient">Ship code,</span><br />
            <span className="apple-headline-accent">not vulnerabilities.</span>
          </h1>

          <p className="apple-hero-subtext">
            Fire Crow audits your repositories with autonomous LLM security agents, verifies every finding in an isolated sandbox, and delivers compiler-tested patches. Zero false positives, SOC2-ready reports.
          </p>

          <div className="apple-hero-cta-group">
            <button onClick={() => setView('login')} className="btn-apple-primary" style={{ padding: '0.8rem 2rem', fontSize: '0.95rem' }}>
              Start scanning free →
            </button>
            <a href="#capabilities" className="btn-apple-secondary" style={{ padding: '0.8rem 1.8rem', fontSize: '0.95rem' }}>
              See how it works
            </a>
          </div>

          <div className="hero-trust-row">
            {['Zero false positives', 'Compiler-verified patches', 'SOC2 / ISO-27001 reporting', 'JIT PAM & SSO'].map(claim => (
              <span key={claim} className="hero-check-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="#30d158" strokeWidth="3"><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                {claim}
              </span>
            ))}
          </div>

          {/* Apple macOS / iPadOS Window Preview Widget */}
          <div className="apple-preview-window">
            <div className="apple-window-header">
              <div className="apple-traffic-lights">
                <div className="apple-light apple-light-red"></div>
                <div className="apple-light apple-light-yellow"></div>
                <div className="apple-light apple-light-green"></div>
              </div>

              <div className="apple-segmented-tabs">
                <button
                  className={`apple-tab-button ${landingTab === 'terminal' ? 'active' : ''}`}
                  onClick={() => setLandingTab('terminal')}
                >
                  Live Agent Stream
                </button>
                <button
                  className={`apple-tab-button ${landingTab === 'graph' ? 'active' : ''}`}
                  onClick={() => setLandingTab('graph')}
                >
                  Attack Topology
                </button>
                <button
                  className={`apple-tab-button ${landingTab === 'diff' ? 'active' : ''}`}
                  onClick={() => setLandingTab('diff')}
                >
                  Verified Patch
                </button>
              </div>

              <div className="apple-window-badge">
                <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#30d158', display: 'inline-block' }}></span>
                <span>SANDBOX: DOCKER_NODE_RUST</span>
              </div>
            </div>

            {/* Tab 1: Agent Stream */}
            {landingTab === 'terminal' && (
              <div className="apple-tab-content" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', lineHeight: '1.75', color: '#e5e5ea', background: '#020203' }}>
                <div><span style={{ color: '#86868b' }}>$</span> firecrow scan --repo https://github.com/org/app</div>
                <div><span style={{ color: '#2997ff' }}>[intake]</span> Cloning repository and resolving dependency graph...</div>
                <div><span style={{ color: '#2997ff' }}>[recon]</span> Ingesting AST structure across 84 source files.</div>
                <div><span style={{ color: '#ffd60a' }}>[scanning]</span> Running SAST rules and secret detection heuristics.</div>
                <div><span style={{ color: '#bf5af2' }}>[ai_analysis]</span> Gemini reasoning loop analyzing 12 candidate findings...</div>
                <div><span style={{ color: '#bf5af2' }}>[ai_analysis]</span> Filtering false positives via Docker sandbox verification.</div>
                <div><span style={{ color: '#ffd60a' }}>[remediation]</span> Synthesizing non-breaking AST patches.</div>
                <div><span style={{ color: '#ffd60a' }}>[attack_graph]</span> Mapping multi-node lateral movement paths.</div>
                <div><span style={{ color: '#2997ff' }}>[report]</span> Compiling SOC2 compliance PDF artifact.</div>
                <div style={{ marginTop: '0.5rem', color: '#30d158', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <span>✓</span> Scan complete — 4 findings confirmed, 2 patches ready.
                </div>
                <div style={{ marginTop: '0.25rem', color: '#86868b' }}>
                  Sign in to run a real scan against your own repository.
                </div>
              </div>
            )}

            {/* Tab 2: Architecture Overview */}
            {landingTab === 'graph' && (
              <div className="apple-tab-content" style={{ background: '#020203', minHeight: '340px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                <div className="topology-svg-container">
                  <svg width="100%" height="220" viewBox="0 0 800 220" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <defs>
                      <linearGradient id="grad-blue" x1="0%" y1="0%" x2="100%"><stop offset="0%" stopColor="#2997ff"/><stop offset="100%" stopColor="#2997ff"/></linearGradient>
                      <linearGradient id="grad-purple" x1="0%" y1="0%" x2="100%"><stop offset="0%" stopColor="#bf5af2"/><stop offset="100%" stopColor="#bf5af2"/></linearGradient>
                      <linearGradient id="grad-green" x1="0%" y1="0%" x2="100%"><stop offset="0%" stopColor="#30d158"/><stop offset="100%" stopColor="#30d158"/></linearGradient>
                    </defs>
                    <path d="M140 110 L320 110" stroke="#2997ff" strokeWidth="2" strokeDasharray="6" opacity="0.5"/>
                    <path d="M480 110 L640 110" stroke="#bf5af2" strokeWidth="2" strokeDasharray="6" opacity="0.5"/>
                    <g>
                      <circle cx="120" cy="110" r="32" fill="rgba(41,151,255,0.06)" stroke="#2997ff" strokeWidth="1.5"/>
                      <text x="120" y="106" fill="#ffffff" fontSize="10" fontWeight="600" textAnchor="middle">Git Repo</text>
                      <text x="120" y="120" fill="#86868b" fontSize="8" fontFamily="var(--font-mono)" textAnchor="middle">AST + deps</text>
                    </g>
                    <g>
                      <rect x="340" y="82" width="100" height="56" rx="8" fill="rgba(191,90,242,0.06)" stroke="#bf5af2" strokeWidth="1.5"/>
                      <text x="390" y="106" fill="#ffffff" fontSize="10" fontWeight="600" textAnchor="middle">Security Agent</text>
                      <text x="390" y="120" fill="#86868b" fontSize="8" fontFamily="var(--font-mono)" textAnchor="middle">Gemini + LLM</text>
                    </g>
                    <g>
                      <rect x="480" y="82" width="90" height="56" rx="8" fill="rgba(255,214,10,0.06)" stroke="#ffd60a" strokeWidth="1.5"/>
                      <text x="525" y="106" fill="#ffffff" fontSize="10" fontWeight="600" textAnchor="middle">Docker</text>
                      <text x="525" y="120" fill="#86868b" fontSize="8" fontFamily="var(--font-mono)" textAnchor="middle">Sandbox</text>
                    </g>
                    <g>
                      <circle cx="660" cy="110" r="32" fill="rgba(48,209,88,0.06)" stroke="#30d158" strokeWidth="1.5"/>
                      <text x="660" y="106" fill="#ffffff" fontSize="10" fontWeight="600" textAnchor="middle">PostgreSQL</text>
                      <text x="660" y="120" fill="#86868b" fontSize="8" fontFamily="var(--font-mono)" textAnchor="middle">Findings DB</text>
                    </g>
                    <path d="M152 110 L308 110" stroke="#2997ff" strokeWidth="1.5" opacity="0.2" markerEnd="url(#arrow-blue)"/>
                    <path d="M440 110 L470 110" stroke="#bf5af2" strokeWidth="1.5" opacity="0.2"/>
                    <path d="M570 110 L628 110" stroke="#30d158" strokeWidth="1.5" opacity="0.2"/>
                  </svg>
                </div>
                <div style={{ marginTop: '1rem', padding: '0.6rem 1rem', background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '8px', fontSize: '0.74rem', color: '#86868b', textAlign: 'center', maxWidth: '500px', lineHeight: '1.5' }}>
                  Four isolated stages — ingestion, reasoning, sandbox verification, and persistence — with zero trust boundaries between them.
                </div>
              </div>
            )}

            {/* Tab 3: Findings Preview */}
            {landingTab === 'diff' && (
              <div className="apple-tab-content" style={{ background: '#020203', minHeight: '300px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '2rem 1.5rem', textAlign: 'center' }}>
                <div style={{ marginBottom: '1rem' }}>
                  <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="#bf5af2" strokeWidth="1.5" style={{ opacity: 0.6 }}>
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M9 13h6M9 17h6"/>
                  </svg>
                </div>
                <div style={{ color: '#ffffff', fontWeight: 700, fontSize: '0.95rem', marginBottom: '0.4rem' }}>
                  Findings appear here after a real scan.
                </div>
                <div style={{ color: '#86868b', fontSize: '0.82rem', lineHeight: '1.5', maxWidth: '400px' }}>
                  Each finding includes severity, file location, CWE mapping, CVSS score, and an auto-generated remediation patch.
                </div>
                <div style={{ marginTop: '1.5rem', display: 'flex', gap: '0.6rem', flexWrap: 'wrap', justifyContent: 'center' }}>
                  <span className="badge badge-critical" style={{ opacity: 0.5 }}>CRITICAL</span>
                  <span className="badge badge-high" style={{ opacity: 0.5 }}>HIGH</span>
                  <span className="badge badge-medium" style={{ opacity: 0.5 }}>MEDIUM</span>
                  <span className="badge badge-low" style={{ opacity: 0.5 }}>LOW</span>
                </div>
                <div style={{ marginTop: '1.5rem' }}>
                  <button onClick={() => setView('login')} className="btn-apple-primary" style={{ padding: '0.6rem 1.5rem', fontSize: '0.84rem' }}>
                    Run your first scan →
                  </button>
                </div>
              </div>
            )}
          </div>
        </section>

        {/* Apple Bento Grid Section (Platform Capabilities) */}
        <section id="capabilities" className="apple-bento-section">
          <div className="apple-section-header">
            <div className="apple-section-eyebrow">✦ Platform Capabilities</div>
            <h2 className="apple-section-title">Engineered for Zero False Positives.</h2>
            <p className="apple-section-sub">
              Every security finding is synthesized, verified in an isolated Docker sandbox, and mapped to an interactive multi-node attack graph.
            </p>
          </div>

          <div className="apple-bento-grid">
            {/* Bento Card 1: Col-8 (Gemini Agentic Reasoning) */}
            <div className="apple-bento-card apple-bento-col-8">
              <div>
                <div className="apple-bento-icon">
                  <svg className="bento-svg" viewBox="0 0 24 24" fill="none" stroke="#bf5af2" strokeWidth="1.8"><rect x="5" y="5" width="14" height="14" rx="2"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/><circle cx="12" cy="12" r="3"/></svg>
                </div>
                <h3 className="apple-bento-title">Agentic Vulnerability Reasoning</h3>
                <p className="apple-bento-desc">
                  LLM agents formulate hypotheses, construct proof-of-concept exploits, and synthesize non-breaking patches — no hallucinated vulnerabilities.
                </p>
              </div>

              <div className="bento-code-strip">
                <div className="bento-code-head"><span className="dot" style={{ background: '#bf5af2' }}></span>Reasoning loop</div>
                <div>Hypothesize exploit path → verify against AST → generate compiler-tested patch</div>
              </div>
            </div>

            {/* Bento Card 2: Col-4 (Docker Sandbox Isolation) */}
            <div className="apple-bento-card apple-bento-col-4">
              <div>
                <div className="apple-bento-icon">
                  <svg className="bento-svg" viewBox="0 0 24 24" fill="none" stroke="#30d158" strokeWidth="1.8"><path d="M21 8l-9-5-9 5v8l9 5 9-5V8z"/><path d="M3.3 8.3L12 13l8.7-4.7M12 13v9"/></svg>
                </div>
                <h3 className="apple-bento-title">Sandboxed Verification</h3>
                <p className="apple-bento-desc">
                  Every finding is proven in an ephemeral, non-root container before it ever reaches your report.
                </p>
              </div>

              <div className="bento-status-pill green"><span className="dot"></span>100% isolated runtime</div>
            </div>

            {/* Bento Card 3: Col-4 (High-Throughput Rust Engine) */}
            <div className="apple-bento-card apple-bento-col-4">
              <div>
                <div className="apple-bento-icon">
                  <svg className="bento-svg" viewBox="0 0 24 24" fill="none" stroke="#ffd60a" strokeWidth="1.8"><path d="M13 2L4.09 12.97a1 1 0 0 0 .77 1.64H11l-1 7.39L18.91 11.03a1 1 0 0 0-.77-1.64H12l1-7.39z"/></svg>
                </div>
                <h3 className="apple-bento-title">High-Throughput Rust Engine</h3>
                <p className="apple-bento-desc">
                  Axum, Tokio async workers, and SQLx drive fast concurrent repository scans.
                </p>
              </div>

              <div className="bento-status-metric">&lt; 2.4s AST parse latency</div>
            </div>

            {/* Bento Card 4: Col-4 (Just-In-Time PAM & IAM) */}
            <div className="apple-bento-card apple-bento-col-4">
              <div>
                <div className="apple-bento-icon">
                  <svg className="bento-svg" viewBox="0 0 24 24" fill="none" stroke="#2997ff" strokeWidth="1.8"><circle cx="8" cy="15" r="4"/><path d="M10.85 12.15L19 4m-3 3l2.5 2.5M13.5 9.5L16 12"/></svg>
                </div>
                <h3 className="apple-bento-title">Just-In-Time PAM &amp; IAM</h3>
                <p className="apple-bento-desc">
                  Zero-standing access with temporary elevation, immutable audit trails, and OIDC / SAML SSO.
                </p>
              </div>

              <div style={{ marginTop: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span className="badge badge-success">Active Elevation</span>
                <span className="badge badge-low">Audit Logged</span>
              </div>
            </div>

            {/* Bento Card 5: Col-4 (Compliance PDF Generation) */}
            <div className="apple-bento-card apple-bento-col-4">
              <div>
                <div className="apple-bento-icon">
                  <svg className="bento-svg" viewBox="0 0 24 24" fill="none" stroke="#2997ff" strokeWidth="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M9 13h6M9 17h6"/></svg>
                </div>
                <h3 className="apple-bento-title">Compliance Reports, Automated</h3>
                <p className="apple-bento-desc">
                  CVEs, fixes, and CWE risk matrices compiled into SOC2 / ISO-27001-ready PDF artifacts.
                </p>
              </div>

              <div className="bento-status-metric blue">PDF &amp; JSON export</div>
            </div>

            {/* Bento Card 6: Col-12 (PostgreSQL Attack Topology Graph) */}
            <div className="apple-bento-card apple-bento-col-12">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1.5rem' }}>
                <div style={{ maxWidth: '600px' }}>
                  <div className="apple-bento-icon">
                    <svg className="bento-svg" viewBox="0 0 24 24" fill="none" stroke="#ff453a" strokeWidth="1.8"><circle cx="5" cy="12" r="2.5"/><circle cx="19" cy="5" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="M7.3 10.8l9.4-4.6M7.3 13.2l9.4 4.6"/></svg>
                  </div>
                  <h3 className="apple-bento-title">Multi-Node Attack Topology Graph</h3>
                  <p className="apple-bento-desc">
                    Lateral movement paths, entrypoints, database exposures, and privilege escalation chains — persisted to relational schemas, explorable node by node.
                  </p>
                </div>

                <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                  <span className="badge badge-critical">CWE-798 Hardcoded Secrets</span>
                  <span className="badge badge-high">OWASP A01 Access Control</span>
                  <span className="badge badge-low">SQLx ORM Validated</span>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* 4-Stage Architecture Pipeline Section */}
        <section id="architecture" className="apple-pipeline-section">
          <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
            <div className="apple-section-header">
              <div className="apple-section-eyebrow">✦ Autonomous Lifecycle</div>
              <h2 className="apple-section-title">End-to-End Autonomous Pipeline</h2>
              <p className="apple-section-sub">
                From source code ingestion to compiler-verified patch generation and compliance delivery.
              </p>
            </div>

            <div className="apple-pipeline-grid">
              <div className="apple-pipeline-card">
                <div className="apple-step-tag" style={{ color: '#2997ff' }}>STEP 01</div>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#ffffff', marginBottom: '0.5rem' }}>Repository Ingestion</h3>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: '1.6' }}>
                  Parses Abstract Syntax Trees (AST), dependencies, and configuration matrices via secure Git cloning.
                </p>
              </div>

              <div className="apple-pipeline-card">
                <div className="apple-step-tag" style={{ color: '#bf5af2' }}>STEP 02</div>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#ffffff', marginBottom: '0.5rem' }}>Agentic Reasoning</h3>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: '1.6' }}>
                  Security LLM reasoning loops discover architectural vulnerabilities and construct attack graphs.
                </p>
              </div>

              <div className="apple-pipeline-card">
                <div className="apple-step-tag" style={{ color: '#ffd60a' }}>STEP 03</div>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#ffffff', marginBottom: '0.5rem' }}>Sandboxed Testing</h3>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: '1.6' }}>
                  Simulates exploit paths inside isolated Docker containers to confirm zero false positives.
                </p>
              </div>

              <div className="apple-pipeline-card">
                <div className="apple-step-tag" style={{ color: '#30d158' }}>STEP 04</div>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#ffffff', marginBottom: '0.5rem' }}>Patch & Delivery</h3>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: '1.6' }}>
                  Generates ready-to-merge remediation pull requests and compliance-ready PDF artifacts.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Key Performance Metrics Showcase */}
        <section id="metrics" className="apple-metrics-section">
          <div className="apple-metric-box">
            <div className="apple-metric-num">0%</div>
            <div className="apple-metric-title">False Positive Guarantee</div>
            <div className="apple-metric-sub">Sandboxed container exploit verification</div>
          </div>

          <div className="apple-metric-box">
            <div className="apple-metric-num">&lt; 2.4s</div>
            <div className="apple-metric-title">AST Ingestion Latency</div>
            <div className="apple-metric-sub">High-throughput Rust Tokio async worker</div>
          </div>

          <div className="apple-metric-box">
            <div className="apple-metric-num">100%</div>
            <div className="apple-metric-title">Docker Sandbox Isolation</div>
            <div className="apple-metric-sub">Zero host escape runtime protection</div>
          </div>

          <div className="apple-metric-box">
            <div className="apple-metric-num">SOC2</div>
            <div className="apple-metric-title">Compliance Artifacts</div>
            <div className="apple-metric-sub">Automated audit reports & ISO 27001</div>
          </div>
        </section>

        {/* SaaS Pricing Grid */}
        <section id="pricing" className="apple-pricing-section">
          <div className="apple-section-header">
            <div className="apple-section-eyebrow">✦ Transparent Pricing</div>
            <h2 className="apple-section-title">A plan for every security posture.</h2>
            <p className="apple-section-sub">
              Initiate automated container verification scans, elevation auditing, and SOC2 compliance mapping.
            </p>

            {/* Billing Cycle Switch */}
            <div className="billing-toggle-wrapper">
              <span style={{ fontSize: '0.86rem', color: billingCycle === 'monthly' ? '#ffffff' : 'var(--text-muted)', fontWeight: billingCycle === 'monthly' ? 600 : 400 }}>Monthly</span>
              <div className="billing-toggle">
                <button 
                  className={`billing-toggle-btn ${billingCycle === 'monthly' ? 'active' : ''}`}
                  onClick={() => setBillingCycle('monthly')}
                >
                  Monthly
                </button>
                <button 
                  className={`billing-toggle-btn ${billingCycle === 'annual' ? 'active' : ''}`}
                  onClick={() => setBillingCycle('annual')}
                >
                  Annual <span className="billing-discount-badge">Save 20%</span>
                </button>
              </div>
              <span style={{ fontSize: '0.86rem', color: billingCycle === 'annual' ? '#ffffff' : 'var(--text-muted)', fontWeight: billingCycle === 'annual' ? 600 : 400 }}>Annual</span>
            </div>
          </div>

          <div className="pricing-grid">
            {/* Tier 1: Starter */}
            <div className="pricing-card">
              <div>
                <div className="pricing-tier-name">Starter</div>
                <div className="pricing-price-wrap">
                  <span className="pricing-price">{billingCycle === 'annual' ? '$15' : '$19'}</span>
                  <span className="pricing-period">/ month</span>
                </div>
                <p className="pricing-desc">Essential automated code security reasoning for solo developers and side projects.</p>
                <ul className="pricing-features">
                  <li className="pricing-feature-item">
                    <svg className="pricing-feature-check" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="3"><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                    <span>5 Repository scans per month</span>
                  </li>
                  <li className="pricing-feature-item">
                    <svg className="pricing-feature-check" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="3"><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                    <span>Ephemeral Docker sandbox validation</span>
                  </li>
                  <li className="pricing-feature-item">
                    <svg className="pricing-feature-check" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="3"><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                    <span>Standard email alerts</span>
                  </li>
                  <li className="pricing-feature-item">
                    <svg className="pricing-feature-check" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="3"><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                    <span>Basic PDF report exports</span>
                  </li>
                </ul>
              </div>
              <button 
                onClick={() => user ? handleInitiateDodoCheckout(billingCycle === 'annual' ? 15 : 19, 'starter') : setView('login')} 
                className="btn-apple-secondary" 
                style={{ width: '100%', padding: '0.75rem 0' }}
              >
                {user ? 'Upgrade to Starter' : 'Get Started'}
              </button>
            </div>

            {/* Tier 2: Pro (Premium) */}
            <div className="pricing-card premium">
              <span className="pricing-badge">Most Popular</span>
              <div>
                <div className="pricing-tier-name" style={{ color: 'var(--accent-bright)' }}>Pro Console</div>
                <div className="pricing-price-wrap">
                  <span className="pricing-price">{billingCycle === 'annual' ? '$79' : '$99'}</span>
                  <span className="pricing-period">/ month</span>
                </div>
                <p className="pricing-desc">Advanced agentic reasoning, code patches, and multi-node attack topology mapping.</p>
                <ul className="pricing-features">
                  <li className="pricing-feature-item">
                    <svg className="pricing-feature-check" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="3"><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                    <span style={{ color: '#ffffff', fontWeight: 600 }}>Unlimited repository scans</span>
                  </li>
                  <li className="pricing-feature-item">
                    <svg className="pricing-feature-check" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="3"><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                    <span>Advanced Gemini reasoning engine</span>
                  </li>
                  <li className="pricing-feature-item">
                    <svg className="pricing-feature-check" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="3"><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                    <span>PoC exploit path verification</span>
                  </li>
                  <li className="pricing-feature-item">
                    <svg className="pricing-feature-check" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="3"><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                    <span>Auto-generated pull request patches</span>
                  </li>
                  <li className="pricing-feature-item">
                    <svg className="pricing-feature-check" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="3"><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                    <span>Full interactive attack topology graphs</span>
                  </li>
                  <li className="pricing-feature-item">
                    <svg className="pricing-feature-check" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="3"><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                    <span>SOC2 & ISO-27001 compliance PDFs</span>
                  </li>
                </ul>
              </div>
              <button 
                onClick={() => user ? handleInitiateDodoCheckout(billingCycle === 'annual' ? 79 : 99, 'pro') : setView('login')} 
                className="btn-apple-primary" 
                style={{ width: '100%', padding: '0.75rem 0' }}
              >
                {user ? 'Upgrade to Pro' : 'Start Pro Free Trial'}
              </button>
            </div>

            {/* Tier 3: Enterprise */}
            <div className="pricing-card">
              <div>
                <div className="pricing-tier-name">Enterprise</div>
                <div className="pricing-price-wrap">
                  <span className="pricing-price">{billingCycle === 'annual' ? '$399' : '$499'}</span>
                  <span className="pricing-period">/ month</span>
                </div>
                <p className="pricing-desc">SLA-backed execution, private sandboxes, and zero-standing elevation permissions.</p>
                <ul className="pricing-features">
                  <li className="pricing-feature-item">
                    <svg className="pricing-feature-check" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="3"><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                    <span>All Pro features included</span>
                  </li>
                  <li className="pricing-feature-item">
                    <svg className="pricing-feature-check" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="3"><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                    <span>Private cloud sandbox deployments</span>
                  </li>
                  <li className="pricing-feature-item">
                    <svg className="pricing-feature-check" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="3"><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                    <span>Multi-tenant OIDC SSO & SAML support</span>
                  </li>
                  <li className="pricing-feature-item">
                    <svg className="pricing-feature-check" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="3"><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                    <span>Custom JIT permission boundary rules</span>
                  </li>
                  <li className="pricing-feature-item">
                    <svg className="pricing-feature-check" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="3"><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                    <span>24/7 dedicated support & SLA metrics</span>
                  </li>
                </ul>
              </div>
              <button 
                onClick={() => user ? handleInitiateDodoCheckout(billingCycle === 'annual' ? 399 : 499, 'enterprise') : setView('login')} 
                className="btn-apple-secondary" 
                style={{ width: '100%', padding: '0.75rem 0' }}
              >
                Contact Sales / Upgrade
              </button>
            </div>
          </div>
        </section>

        {/* Interactive FAQ Section */}
        <section className="apple-faq-section">
          <div className="apple-section-header">
            <div className="apple-section-eyebrow">✦ Frequently Asked Questions</div>
            <h2 className="apple-section-title">Everything you need to know.</h2>
            <p className="apple-section-sub">
              Got questions about autonomous code execution, container safety, or custom deployments?
            </p>
          </div>

          <div className="faq-list">
            {[
              {
                q: "How does Fire Crow eliminate zero-day false positives?",
                a: "Fire Crow doesn't rely solely on static pattern matching. It spawns an isolated, non-root Docker container sandbox for each candidate vulnerability to dynamically compile, execute, and verify exploit vectors before reporting them."
              },
              {
                q: "Is my proprietary repository source code shared with third-party LLMs?",
                a: "No. Source code ASTs and repository contents are parsed locally by the high-throughput Rust engine. Only anonymized code snippets required for vulnerability reasoning are transmitted via encrypted TLS endpoints."
              },
              {
                q: "Can Fire Crow be deployed on-premise or in private clouds?",
                a: "Yes. Enterprise plans support private Kubernetes cluster deployments, custom Docker registry integration, and air-gapped security orchestrators."
              },
              {
                q: "How does Just-In-Time (JIT) PAM elevation work with our IAM?",
                a: "Fire Crow integrates natively with OIDC and SAML 2.0 identity providers. Security architects can request temporary privilege elevation that automatically expires after a predefined TTL, complete with immutable PostgreSQL audit trails."
              }
            ].map((faq, idx) => (
              <div 
                key={idx}
                className={`faq-item ${openFaqIndex === idx ? 'open' : ''}`}
                onClick={() => setOpenFaqIndex(openFaqIndex === idx ? null : idx)}
              >
                <div className="faq-question">
                  <span>{faq.q}</span>
                  <div className="faq-toggle-icon">+</div>
                </div>
                {openFaqIndex === idx && (
                  <div className="faq-answer">
                    {faq.a}
                  </div>
                )}
              </div>
            ))}
          </div>
        </section>

        {/* Cupertino Call to Action Spotlight Banner */}
        <section className="apple-cta-section">
          <div className="apple-cta-card">
            <h2 style={{ fontSize: 'clamp(2rem, 4vw, 3.2rem)', fontWeight: 800, letterSpacing: '-0.04em', color: '#ffffff', marginBottom: '1rem' }}>
              Ready to harden your enterprise stack?
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '1.1rem', maxWidth: '620px', margin: '0 auto 2.5rem', lineHeight: '1.6' }}>
              Deploy Fire Crow in your CI/CD pipeline or launch the interactive cloud console in seconds.
            </p>
            <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center', flexWrap: 'wrap' }}>
              <button onClick={() => setView('login')} className="btn-apple-primary" style={{ padding: '0.85rem 2.25rem', fontSize: '0.95rem' }}>
                Start scanning free →
              </button>
              <a href="https://github.com/johan-droid/Fire-Crow-" target="_blank" rel="noreferrer" className="btn-apple-secondary" style={{ padding: '0.85rem 2rem', fontSize: '0.95rem' }}>
                Explore on GitHub ↗
              </a>
            </div>
          </div>
        </section>

        {/* Multi-Column Apple-Style Footer */}
        <footer className="apple-footer">
          <div className="apple-footer-grid">
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '1.1rem' }}>
                <img src="/fire-crow-logo.png" alt="Fire Crow Logo" style={{ width: '28px', height: '28px', borderRadius: '6px' }} />
                <span style={{ fontWeight: 700, fontSize: '1.05rem', color: '#ffffff' }}>Fire Crow</span>
              </div>
              <p style={{ fontSize: '0.84rem', color: 'var(--text-muted)', lineHeight: '1.65', maxWidth: '340px' }}>
                Autonomous agentic security intelligence and vulnerability hardening platform built natively in Rust with Tokio async workers and Gemini LLM reasoning.
              </p>
            </div>

            <div>
              <div className="apple-footer-col-title">Platform</div>
              <ul className="apple-footer-links">
                <li><a href="#capabilities">Agent Capabilities</a></li>
                <li><a href="#architecture">Autonomous Pipeline</a></li>
                <li><a href="#pricing">Pricing</a></li>
              </ul>
            </div>

            <div>
              <div className="apple-footer-col-title">Developers</div>
              <ul className="apple-footer-links">
                <li><a href="https://github.com/johan-droid/Fire-Crow-" target="_blank" rel="noreferrer">GitHub Repository</a></li>
                <li><a href="https://github.com/johan-droid/Fire-Crow-/blob/main/documentation/API_DOCUMENTATION.md" target="_blank" rel="noreferrer">API Documentation</a></li>
                <li><a href="https://github.com/johan-droid/Fire-Crow-/blob/main/documentation/CLOUDFLARE_DEPLOYMENT.md" target="_blank" rel="noreferrer">Deployment Guide</a></li>
              </ul>
            </div>

            <div>
              <div className="apple-footer-col-title">Security & Trust</div>
              <ul className="apple-footer-links">
                <li><span style={{ color: 'var(--text-muted)' }}>SOC2 Type II Ready</span></li>
                <li><span style={{ color: 'var(--text-muted)' }}>ISO 27001 Mapping</span></li>
                <li><span style={{ color: 'var(--text-muted)' }}>Docker Sandbox Isolation</span></li>
                <li><span style={{ color: 'var(--text-muted)' }}>Zero-Standing PAM</span></li>
              </ul>
            </div>
          </div>

          <div className="apple-footer-bottom">
            <div>© {new Date().getFullYear()} Fire Crow Security Intelligence Inc. All rights reserved.</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1.75rem' }}>
              <span style={{ color: 'var(--text-muted)' }}>Privacy Policy</span>
              <span style={{ color: 'var(--text-muted)' }}>Terms of Service</span>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: '#30d158', fontWeight: 600 }}>
                <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#30d158', display: 'inline-block' }}></span>
                System Operational
              </span>
            </div>
          </div>
        </footer>
      </div>
    );
  }

  // Render Login View
  if (view === 'login') {
    return (
      <div className="page-center" style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#050506', backgroundImage: 'radial-gradient(circle at 50% 50%, rgba(255,255,255,0.02) 0%, transparent 80%)', padding: '1.5rem' }}>
        <AuroraBackdrop variant="login" />
        <div className="login-card" style={{ width: '100%', maxWidth: '400px', background: 'rgba(255,255,255,0.01)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '16px', padding: '2.5rem 2rem', boxShadow: '0 30px 60px rgba(0,0,0,0.8)', backdropFilter: 'blur(20px)', textAlign: 'center' }}>
          
          {/* Custom Login Tile Header */}
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginBottom: '2rem' }}>
            <div style={{ width: '56px', height: '56px', borderRadius: '12px', background: 'rgba(255, 255, 255, 0.03)', border: '1px solid rgba(255,255,255,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '1rem', boxShadow: '0 8px 16px rgba(0,0,0,0.4)' }}>
              <img src="/fire-crow-logo.png" alt="Fire Crow" style={{ width: '38px', height: '38px' }} />
            </div>
            <h2 className="saas-h1-accent" style={{ fontSize: '1.5rem', fontWeight: 800, margin: 0, letterSpacing: '-0.03em', color: '#ffffff' }}>Fire Crow</h2>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.35rem', letterSpacing: '-0.01em' }}>Secure Autonomous Security Orchestration Console</p>
          </div>

          {/* Pure GitHub Signin Tile Button */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', margin: '2rem 0' }}>
            <button 
              onClick={handleGitHubLogin} 
              className="btn-saas-solid" 
              style={{ 
                width: '100%', 
                display: 'flex', 
                alignItems: 'center', 
                justifyContent: 'center', 
                gap: '0.75rem', 
                background: '#ffffff', 
                color: '#000000', 
                padding: '0.85rem', 
                fontSize: '0.88rem', 
                fontWeight: 700, 
                borderRadius: '8px', 
                border: 'none', 
                cursor: 'pointer',
                transition: 'all 0.2s cubic-bezier(0.16, 1, 0.3, 1)'
              }}
            >
              <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.166 6.839 9.489.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.603-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.579.688.481C19.137 20.162 22 16.418 22 12c0-5.523-4.477-10-10-10z" />
              </svg>
              Continue with GitHub
            </button>
          </div>

          {(error || authFormError) && (
            <div className="error-box" style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.2)', color: '#f87171', padding: '0.75rem', borderRadius: '8px', fontSize: '0.8rem', marginBottom: '1.25rem' }}>
              {authFormError || error}
            </div>
          )}

          {/* Secure monospaced audit info */}
          <div style={{ padding: '0.75rem', background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)', borderRadius: '8px', fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textAlign: 'left', marginBottom: '1.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
              <span>Connection:</span>
              <span style={{ color: '#4ade80' }}>SECURE (TLS 1.3)</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>Identity Provider:</span>
              <span>github.com</span>
            </div>
          </div>

          <button onClick={() => { setError(''); setAuthFormError(''); setView('landing'); }} className="btn btn-ghost" style={{ width: '100%', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            ← Back to landing page
          </button>
        </div>
      </div>
    );
  }

  // Render Dashboard View (Single-board with Sidebar & Mobile Topbar)
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
          { id: 'overview', label: 'Overview', badge: null, icon: (
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z"/></svg>
          ) },
          { id: 'scans', label: 'Audit Jobs', badge: jobs.length, icon: (
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          ) },
          { id: 'identity', label: 'Identity', badge: ssoProviders.length + pamRequests.length, icon: (
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/></svg>
          ) },
          { id: 'security', label: 'Security', badge: activities.length, icon: (
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
          ) },
        ] as const).map((item) => (
          <button
            key={item.id}
            className={`island-item ${dashTab === item.id ? 'active' : ''}`}
            onClick={() => setDashTab(item.id)}
            title={item.label}
          >
            <span className="island-item-icon">{item.icon}</span>
            <span className="island-label">{item.label}</span>
            {item.badge !== null && item.badge > 0 && <span className="island-badge">{item.badge}</span>}
          </button>
        ))}

        <div className="island-flex-spacer" />

        <div className="island-user">
          <div className="island-avatar">{user?.username ? user.username[0].toUpperCase() : 'U'}</div>
          <span className="island-label island-username">{user?.username}</span>
          <button onClick={handleLogout} className="island-logout" title="Sign Out">
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
        {/* Topbar — precise single row */}
        <div className="topbar">
          <div>
            <div className="topbar-title">
              {dashTab === 'overview' && 'Security Console'}
              {dashTab === 'scans' && 'Audit Jobs'}
              {dashTab === 'identity' && 'Identity & Access'}
              {dashTab === 'security' && 'Logs & Telemetry'}
            </div>
            <div className="topbar-subtitle">
              Node: {user?.username} • {user?.user_id.substring(0, 8)}
            </div>
          </div>

          <div className="topbar-right">
            <div className="status-indicator">
              <div className="status-dot status-dot-live" />
              <span>LIVE</span>
            </div>

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

            <button onClick={() => setIsScanModalOpen(true)} className="btn btn-primary btn-sm">
              + New Audit Job
            </button>

            <button onClick={handleLogout} className="topbar-avatar" title="Sign Out">
              {user?.username ? user.username[0].toUpperCase() : 'U'}
            </button>
          </div>
        </div>

        {/* Page Content Body */}
        <div className="page-body">
          {/* Tab 1: Overview */}
          {dashTab === 'overview' && (
            <>
              {dashLoad === 'error' && (
                <div className="dash-error-banner">
                  <span>{dashError}</span>
                  <button className="btn btn-secondary btn-sm" onClick={() => fetchDashboardData(true)}>Retry</button>
                </div>
              )}

              {/* Metrics — 3 compact cards */}
              <div className="metrics-grid">
                <div className="metric-card">
                  <div className="metric-label">Completed</div>
                  <div className="metric-value">{jobs.filter(j => j.status === 'completed').length}</div>
                  <div className="metric-sub">audits passed</div>
                </div>
                <div className="metric-card">
                  <div className="metric-label">Active</div>
                  <div className="metric-value" style={{ color: jobs.some(j => j.status === 'running' || j.status === 'queued') ? 'var(--accent-bright)' : undefined }}>
                    {jobs.filter(j => j.status === 'running' || j.status === 'queued').length}
                  </div>
                  <div className="metric-sub">in progress</div>
                </div>
                <div className="metric-card">
                  <div className="metric-label">System</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.35rem' }}>
                    <span className={`status-dot ${deepHealth && (deepHealth.database === 'ok' || deepHealth.database === 'connected') ? 'status-dot-live' : 'status-dot-down'}`} />
                    <span className="metric-value" style={{ fontSize: '1.5rem' }}>
                      {deepHealth ? deepHealth.database.replace('_', ' ') : 'probing'}
                    </span>
                  </div>
                  <div className="metric-sub">PostgreSQL cluster</div>
                </div>
              </div>

              {/* Terminal Progress Bar — full width */}
              {(() => {
                const job = jobs.find(j => j.id === (activeMonitorJobId || (jobs.length > 0 ? jobs[0].id : ''))) || (jobs.length > 0 ? jobs[0] : null);
                if (!job) return null;

                const phaseOrder = ['intake', 'recon', 'scanning', 'ai_analysis', 'remediation', 'attack_graph', 'reporting'];
                const isRunning = job.status === 'running' || job.status === 'queued';
                const failed = job.status === 'failed' || job.status === 'cancelled';

                let pct = 0;
                if (job.status === 'completed') pct = 100;
                else if (job.status === 'queued') pct = 8;
                else if (failed) pct = 100;
                else {
                  const done = monitorPhases.filter(p => p.status === 'completed').length;
                  const hasStarted = monitorPhases.some(p => p.status === 'started' || p.status === 'running');
                  pct = Math.min(95, Math.max(12, Math.round((done / phaseOrder.length) * 100) + (hasStarted ? 8 : 0)));
                }

                const createdUtc = job.created_at.includes('T') ? job.created_at : job.created_at.replace(' ', 'T') + 'Z';
                const elapsed = Math.max(0, Math.floor((Date.now() - new Date(createdUtc).getTime()) / 1000));
                const elapsedStr = elapsed < 60 ? `${elapsed}s` : `${Math.floor(elapsed / 60)}m ${elapsed % 60}s`;

                return (
                  <div className="progress-card">
                    <div className="term-progress">
                      <div className="term-header">
                        <div className="term-dots">
                          <span style={{ background: '#ff5f57' }} />
                          <span style={{ background: '#febc2e' }} />
                          <span style={{ background: '#28c840' }} />
                        </div>
                        <span style={{ color: '#ffffff', fontSize: '0.72rem', fontWeight: 600 }}>
                          {job.repo_url.split('/').slice(-2).join('/')}:{job.repo_branch}
                        </span>
                        <div className="term-header-meta">
                          <span>{job.id.substring(0, 8)}</span>
                          <span>{elapsedStr}</span>
                          <span style={{ color: isRunning ? '#ffd60a' : failed ? '#ff3b30' : '#30d158', fontWeight: 600 }}>{job.status}</span>
                        </div>
                      </div>

                      <div className="term-bar-row">
                        <div className="term-bar-track">
                          <div className={`term-bar-fill ${isRunning ? 'running' : failed ? 'fail' : 'done'}`} style={{ width: `${pct}%` }} />
                        </div>
                        <div className="term-bar-pct">{pct}%</div>
                      </div>

                      <div className="term-phases">
                        {phaseOrder.map(phase => {
                          const logged = monitorPhases.find(p => p.phase_name.toLowerCase() === phase);
                          const done = job.status === 'completed' || (logged && logged.status === 'completed');
                          const active = isRunning && logged && logged.status === 'started';
                          const failedPhase = logged && logged.status === 'failed';
                          return (
                            <span key={phase} className={`term-phase ${done ? 'done' : active ? 'active' : failedPhase ? 'fail' : ''}`}>
                              <span className="term-phase-dot" />
                              {phase.replace('_', ' ')}
                            </span>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                );
              })()}

              {/* Two Column: Job List + Health */}
              <div className="two-col">
                <div className="panel">
                  <div className="panel-header">
                    <div className="panel-title">
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                      Audit Jobs
                    </div>
                    <button onClick={() => setIsScanModalOpen(true)} className="btn btn-secondary btn-sm">+ New</button>
                  </div>
                  <div className="panel-body" style={{ padding: '0.75rem' }}>
                    <PanelState state={dashLoad} error={dashError} empty={jobs.length === 0} emptyIcon="🛡" rows={3} onRetry={() => fetchDashboardData(true)}>
                      {jobs.length === 0 ? (
                        <p>No audit jobs yet. Trigger your first scan.</p>
                      ) : (
                        jobs.slice(0, 8).map(j => {
                          const st = jobStatusInfo(j.status);
                          return (
                            <div
                              key={j.id}
                              onClick={() => { handleViewJobDetail(j.id); setActiveMonitorJobId(j.id); }}
                              className="list-item"
                              style={{ borderLeft: activeMonitorJobId === j.id ? '2px solid var(--accent)' : undefined, cursor: 'pointer' }}
                            >
                              <ScoreRing score={j.security_score ?? null} size={34} />
                              <div className="list-item-info">
                                <div className="list-item-title">{j.repo_url.split('/').slice(-2).join('/') || j.repo_url}</div>
                                <div className="list-item-sub">{j.repo_branch} · {j.id.substring(0, 8)} · {timeAgo(j.created_at)}</div>
                                {(j.status === 'failed' || j.status === 'cancelled') && j.error_message && (
                                  <div className="list-item-sub" style={{ color: 'var(--apple-red)' }} title={j.error_message}>
                                    {j.error_message.length > 55 ? `${j.error_message.slice(0, 55)}…` : j.error_message}
                                  </div>
                                )}
                              </div>
                              <span className={`badge ${st.cls}`}>
                                {st.pulse && <span className="badge-pulse" />} {st.label}
                              </span>
                            </div>
                          );
                        })
                      )}
                    </PanelState>
                  </div>
                </div>

                <div className="panel">
                  <div className="panel-header">
                    <div className="panel-title">
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
                      System Health
                    </div>
                  </div>
                  <div className="panel-body" style={{ padding: '0.85rem' }}>
                    <HealthWidget deep={deepHealth} />
                  </div>
                </div>
              </div>
            </>
          )}

          {/* Tab 2: Audit Jobs */}
          {dashTab === 'scans' && (
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">
                  Database Audit Jobs ({jobs.length})
                  {dashLoad === 'ready' && lastSync && (
                    <span style={{ fontSize: '0.7rem', fontWeight: 500, color: 'var(--text-muted)', marginLeft: '0.5rem' }}>
                      synced {timeAgo(lastSync.toISOString())}
                    </span>
                  )}
                </div>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <button onClick={() => fetchDashboardData(true)} className="btn btn-secondary btn-sm" disabled={dashLoad === 'loading'}>
                    {dashLoad === 'loading' ? 'Syncing…' : '↻ Refresh'}
                  </button>
                  <button onClick={() => setIsScanModalOpen(true)} className="btn btn-primary btn-sm">
                    + Trigger Scan
                  </button>
                </div>
              </div>

              {modalError && (
                <div style={{ padding: '0.75rem 1.25rem 0' }}>
                  <div className="error-box">{modalError}</div>
                </div>
              )}

              <div className="panel-body" style={{ padding: dashLoad === 'ready' && jobs.length > 0 ? '0.75rem' : undefined }}>
                <PanelState
                  state={dashLoad}
                  error={dashError}
                  empty={jobs.length === 0}
                  emptyIcon="📡"
                  rows={5}
                  onRetry={() => fetchDashboardData(true)}
                >
                  {jobs.length === 0 ? (
                    <>
                      <p style={{ marginBottom: '0.75rem' }}>No audit jobs registered in PostgreSQL yet.</p>
                      <button onClick={() => setIsScanModalOpen(true)} className="btn btn-primary btn-sm">
                        Submit Repo for Scan
                      </button>
                    </>
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
                            const st = jobStatusInfo(j.status);
                            const isActive = j.status === 'queued' || j.status === 'running';
                            const busy = cancellingIds.includes(j.id);
                            return (
                              <tr key={j.id} style={{ opacity: busy ? 0.55 : 1 }}>
                                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>{j.id.substring(0, 8)}</td>
                                <td>
                                  <div style={{ fontWeight: 600 }}>{j.repo_url.split('/').slice(-2).join('/') || j.repo_url}</div>
                                  <code style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>⎇ {j.repo_branch}</code>
                                </td>
                                <td>
                                  <span className={`badge ${st.cls}`}>{st.pulse && <span className="badge-pulse" />} {st.label}</span>
                                  {(j.status === 'failed') && j.error_message && (
                                    <div style={{ fontSize: '0.68rem', color: 'var(--apple-red)', marginTop: '0.25rem', maxWidth: '220px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={j.error_message}>
                                      {j.error_message}
                                    </div>
                                  )}
                                </td>
                                <td><ScoreRing score={j.security_score ?? null} size={38} /></td>
                                <td style={{ color: 'var(--text-muted)', fontSize: '0.78rem' }} title={fmtUtc(j.created_at)}>{timeAgo(j.created_at)}</td>
                                <td>
                                  <div style={{ display: 'flex', gap: '0.4rem', justifyContent: 'flex-end' }}>
                                    <button onClick={() => handleViewJobDetail(j.id)} className="btn btn-secondary btn-sm">Inspect</button>
                                    {j.status === 'completed' && (
                                      <button onClick={() => handleDownloadReport(j.id)} className="btn btn-secondary btn-sm" title="Download report">↓ Report</button>
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

          {/* Tab 3: Identity & Access */}
          {dashTab === 'identity' && (
            <div className="two-col">
              {/* SSO Providers */}
              <div className="panel">
                <div className="panel-header">
                  <div className="panel-title">SSO Providers ({ssoProviders.length})</div>
                  <button onClick={() => setIsSsoModalOpen(true)} className="btn btn-secondary btn-sm">
                    + Provider
                  </button>
                </div>
                <div className="panel-body" style={{ padding: '0.75rem' }}>
                  <PanelState state={dashLoad} error={dashError} empty={ssoProviders.length === 0} emptyIcon="🔑" rows={2} onRetry={() => fetchDashboardData(true)}>
                    {ssoProviders.length === 0 ? (
                      <p>No SSO providers configured yet.</p>
                    ) : (
                      ssoProviders.map(p => (
                        <div key={p.id} className="list-item" style={{ cursor: 'default' }}>
                          <div className="list-item-info">
                            <div className="list-item-title">{p.name}</div>
                            <div className="list-item-sub">Type: {p.provider_type} • Issuer: {p.issuer_url || 'N/A'}</div>
                          </div>
                          <span className="badge badge-success">ACTIVE</span>
                        </div>
                      ))
                    )}
                  </PanelState>
                </div>
              </div>

              {/* PAM Requests */}
              <div className="panel">
                <div className="panel-header">
                  <div className="panel-title">PAM Elevation Requests ({pamRequests.length})</div>
                  <button onClick={() => setIsPamModalOpen(true)} className="btn btn-secondary btn-sm">
                    + Request
                  </button>
                </div>
                <div className="panel-body" style={{ padding: '0.75rem' }}>
                  <PanelState state={dashLoad} error={dashError} empty={pamRequests.length === 0} emptyIcon="🔐" rows={2} onRetry={() => fetchDashboardData(true)}>
                    {pamRequests.length === 0 ? (
                      <p>No PAM elevation requests submitted.</p>
                    ) : (
                      pamRequests.map(r => (
                        <div key={r.id} className="list-item" style={{ cursor: 'default' }}>
                          <div className="list-item-info">
                            <div className="list-item-title">{r.role_name} ({r.permission})</div>
                            <div className="list-item-sub">{r.reason} • {r.requested_duration_minutes}m</div>
                          </div>
                          <span className="badge badge-medium">{r.status}</span>
                        </div>
                      ))
                    )}
                  </PanelState>
                </div>
              </div>

              {/* Domain Verifications */}
              <div className="panel" style={{ gridColumn: '1 / -1' }}>
                <div className="panel-header">
                  <div className="panel-title">Domain Verifications ({domains.length})</div>
                  <button onClick={() => setIsDomainModalOpen(true)} className="btn btn-secondary btn-sm">
                    + Add Domain
                  </button>
                </div>
                <div className="panel-body" style={{ padding: '0.75rem' }}>
                  <PanelState state={dashLoad} error={dashError} empty={domains.length === 0} emptyIcon="🌐" rows={2} onRetry={() => fetchDashboardData(true)}>
                    {domains.length === 0 ? (
                      <p>No domain verifications registered.</p>
                    ) : (
                      domains.map(d => (
                        <div key={d.id} className="list-item" style={{ cursor: 'default' }}>
                          <div className="list-item-info">
                            <div className="list-item-title">{d.domain}</div>
                            <div className="list-item-sub">{d.verified ? 'Domain verified' : 'Pending DNS verification'}</div>
                          </div>
                          <span className={`badge ${d.verified ? 'badge-success' : 'badge-medium'}`}>
                            {d.verified ? 'VERIFIED' : 'PENDING DNS'}
                          </span>
                        </div>
                      ))
                    )}
                  </PanelState>
                </div>
              </div>
            </div>
          )}

          {/* Tab 4: Logs & MFA */}
          {dashTab === 'security' && (
            <div className="two-col">
              <div className="panel">
                <div className="panel-header">
                  <div className="panel-title">MFA Authentication Status</div>
                  <span className={`badge ${mfaStatus.enabled ? 'badge-success' : 'badge-neutral'}`}>
                    {mfaStatus.enabled ? 'ACTIVE' : 'DISABLED'}
                  </span>
                </div>
                <div className="panel-body">
                  <PanelState state={dashLoad} error={dashError} onRetry={() => fetchDashboardData(true)}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <div>
                          <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>TOTP Authenticator App</div>
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                            {mfaStatus.enabled
                              ? `Protected • ${mfaStatus.backup_codes_remaining} recovery codes remaining`
                              : 'Two-factor protection is not enrolled'}
                          </div>
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: '0.5rem' }}>
                        {mfaStatus.enabled ? (
                          <button onClick={handleMfaDisable} className="btn btn-danger btn-sm">Disable MFA</button>
                        ) : (
                          <button onClick={handleMfaEnroll} className="btn btn-primary btn-sm">Enroll TOTP App</button>
                        )}
                      </div>
                    </div>
                  </PanelState>
                </div>
              </div>

              <div className="panel">
                <div className="panel-header">
                  <div className="panel-title">User Security Activities ({activities.length})</div>
                </div>
                <div className="panel-body" style={{ padding: '0.75rem', maxHeight: '420px', overflowY: 'auto' }}>
                  <PanelState state={dashLoad} error={dashError} empty={activities.length === 0} emptyIcon="🧾" rows={4} onRetry={() => fetchDashboardData(true)}>
                    {activities.length === 0 ? (
                      <p>No security events recorded yet.</p>
                    ) : (
                      activities.map(act => (
                        <div key={act.id} className="list-item" style={{ cursor: 'default' }}>
                          <div className="list-item-info">
                            <div className="list-item-title">{act.action}</div>
                            {act.details_json && <div className="list-item-sub">{act.details_json}</div>}
                          </div>
                          <span className="badge badge-neutral" title={fmtUtc(act.created_at)}>{timeAgo(act.created_at)}</span>
                        </div>
                      ))
                    )}
                  </PanelState>
                </div>
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
                <div className="modal-title">Trigger Security Audit Job</div>
                <div className="modal-sub">Submit Git repository to PostgreSQL audit queue</div>
              </div>
              <button onClick={() => setIsScanModalOpen(false)} className="btn btn-ghost btn-icon">✕</button>
            </div>

            <form onSubmit={handleStartScan}>
              <div className="modal-body">
                <div className="form-group" style={{ marginBottom: '1.25rem', background: 'rgba(255, 255, 255, 0.02)', padding: '0.85rem', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                    <label className="form-label" style={{ margin: 0 }}>Sync'd GitHub Repositories</label>
                    <button 
                      type="button" 
                      onClick={fetchUserRepos} 
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
                          setNewRepoUrl(repo.clone_url || repo.html_url);
                          setNewRepoBranch(repo.default_branch || 'main');
                        }
                      }
                    }}
                    defaultValue=""
                  >
                    <option value="" disabled>-- Select a GitHub Repository to Audit --</option>
                    {userRepos.map((r: any) => (
                      <option key={r.id} value={r.clone_url || r.html_url}>
                        {r.private ? '🔒 Private' : '🌐 Public'}: {r.full_name} ({r.default_branch || 'main'})
                      </option>
                    ))}
                  </select>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.35rem' }}>
                    {userRepos.length > 0 ? `${userRepos.length} repositories synchronized from your GitHub account.` : 'Click "Sync Account Repos" to load your public & private GitHub repositories.'}
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

      {/* Modal: Job Findings Detail */}
      {selectedJobDetail && (
        <div className="modal-backdrop" onClick={() => setSelectedJobDetail(null)}>
          <div className="modal" style={{ maxWidth: '680px' }} onClick={e => e.stopPropagation()}>
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
              <button onClick={() => setSelectedJobDetail(null)} className="btn btn-ghost btn-icon">✕</button>
            </div>

            <div className="modal-body" style={{ maxHeight: '440px', overflowY: 'auto' }}>
              {detailLoading ? (
                <div className="state-skeleton">
                  {[0, 1, 2].map(i => <div key={i} className="skeleton-row" style={{ animationDelay: `${i * 0.12}s`, width: `${90 - i * 10}%` }} />)}
                </div>
              ) : (
                <>
                  {/* Severity distribution */}
                  <div className="detail-summary-row">
                    <div style={{ fontSize: '0.78rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)' }}>
                      Findings ({selectedJobDetail.findings.length})
                    </div>
                    {selectedJobDetail.findings.length > 0 && <SeverityBars findings={selectedJobDetail.findings} />}
                  </div>

                  {selectedJobDetail.findings.length === 0 ? (
                    <div className="panel-empty">
                      {selectedJobDetail.job.status === 'completed'
                        ? 'Clean audit — no vulnerabilities reported.'
                        : `No findings yet — job is ${selectedJobDetail.job.status}.`}
                    </div>
                  ) : (
                    selectedJobDetail.findings.map(f => (
                      <div key={f.id} className="finding-card">
                        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '0.35rem', flexWrap: 'wrap' }}>
                          <span className={`badge ${severityClass(f.severity)}`}>{(f.severity || 'info').toUpperCase()}</span>
                          {f.cvss_score != null && (
                            <span className="badge badge-neutral" title={f.cvss_vector || ''}>CVSS {f.cvss_score.toFixed(1)}</span>
                          )}
                          <span style={{ fontSize: '0.73rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{f.cwe_id || ''}</span>
                          {f.file_path && (
                            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginLeft: 'auto' }}>
                              {f.file_path}{f.line_number != null ? `:${f.line_number}` : ''}
                            </span>
                          )}
                        </div>
                        <div style={{ fontWeight: 600, fontSize: '0.85rem' }}>{f.title}</div>
                        <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', margin: '0.4rem 0' }}>{f.description}</div>
                        {f.remediation && (
                          <details className="remediation-details">
                            <summary>View remediation</summary>
                            <pre className="code-block"><code>{f.remediation}</code></pre>
                          </details>
                        )}
                      </div>
                    ))
                  )}
                </>
              )}
            </div>

            <div className="modal-footer">
              {selectedJobDetail.job.status === 'completed' && (
                <button onClick={() => handleDownloadReport(selectedJobDetail.job.id)} className="btn btn-secondary">↓ Download Report</button>
              )}
              <button onClick={() => setSelectedJobDetail(null)} className="btn btn-primary">Close</button>
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
