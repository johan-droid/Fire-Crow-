import { useState, useEffect, useCallback, useRef } from 'react';

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
}

interface AuditJob {
  id: string;
  repo_url: string;
  repo_branch: string;
  status: string;
  score?: number | null;
  created_at: string;
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
  const [mobileDrawerOpen, setMobileDrawerOpen] = useState(false);

  // Live Backend Data States
  const [jobs, setJobs] = useState<AuditJob[]>([]);
  const [selectedJobDetail, setSelectedJobDetail] = useState<{ job: AuditJob; findings: Finding[] } | null>(null);
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
  const [selectedGraphNode, setSelectedGraphNode] = useState<'ingress' | 'exploit' | 'sandbox' | 'target'>('exploit');
  const [selectedDiffPatch, setSelectedDiffPatch] = useState<'jwt' | 'sqli' | 'csrf'>('jwt');
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
  const [simRepo, setSimRepo] = useState('https://github.com/johan-droid/express-api-demo.git');
  const [isSimulating, setIsSimulating] = useState(false);
  const [simProgress, setSimProgress] = useState(0);
  const [simStage, setSimStage] = useState('');
  const [simComplete, setSimComplete] = useState(false);

  const handleRunSimulatedScan = (repoUrl?: string) => {
    const targetUrl = repoUrl || simRepo;
    if (repoUrl) setSimRepo(repoUrl);
    setIsSimulating(true);
    setSimProgress(20);
    setSimStage(`Cloning ${targetUrl.split('/').pop() || 'repo'} AST structure...`);
    setSimComplete(false);

    setTimeout(() => {
      setSimProgress(50);
      setSimStage('Running Gemini 1.5 Pro Agentic Vulnerability Reasoning...');
    }, 1000);

    setTimeout(() => {
      setSimProgress(80);
      setSimStage('Simulating Docker sandbox execution & attack path verification...');
    }, 2200);

    setTimeout(() => {
      setSimProgress(100);
      setSimStage('Scan Complete! Discovered 2 high-severity exploits with automated patches.');
      setIsSimulating(false);
      setSimComplete(true);
    }, 3400);
  };

  // Fetch all real backend data in parallel using Promise.allSettled
  const fetchDashboardData = useCallback(async () => {
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

      if (jobsRes.status === 'fulfilled' && jobsRes.value.ok) {
        setJobs(await jobsRes.value.json());
      }
      if (ssoRes.status === 'fulfilled' && ssoRes.value.ok) {
        setSsoProviders(await ssoRes.value.json());
      }
      if (pamReqRes.status === 'fulfilled' && pamReqRes.value.ok) {
        setPamRequests(await pamReqRes.value.json());
      }
      if (pamGrantRes.status === 'fulfilled' && pamGrantRes.value.ok) {
        setPamGrants(await pamGrantRes.value.json());
      }
      if (iamRes.status === 'fulfilled' && iamRes.value.ok) {
        setIamPolicies(await iamRes.value.json());
      }
      if (domainRes.status === 'fulfilled' && domainRes.value.ok) {
        setDomains(await domainRes.value.json());
      }
      if (actRes.status === 'fulfilled' && actRes.value.ok) {
        setActivities(await actRes.value.json());
      }
      if (mfaRes.status === 'fulfilled' && mfaRes.value.ok) {
        setMfaStatus(await mfaRes.value.json());
      }
    } catch (err) {
      console.warn('Dashboard live data fetch error:', err);
    }
  }, []);

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

    fetchPhases();
    const activeJob = jobs.find(j => j.id === targetJobId);
    const isJobActive = !activeJob || activeJob.status === 'running' || activeJob.status === 'queued';
    const interval = setInterval(() => {
      fetchPhases();
      if (isJobActive) {
        fetchDashboardData();
      }
    }, isJobActive ? 1500 : 4000);
    return () => clearInterval(interval);
  }, [view, activeMonitorJobId, jobs]);

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
          fetchDashboardData();
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
    if (!newRepoUrl) return;

    setModalError('');
    setIsSubmitting(true);

    try {
      const res = await apiFetch('/audit/submit', {
        method: 'POST',
        body: JSON.stringify({
          repo_url: newRepoUrl,
          repo_branch: newRepoBranch || 'main',
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
        setModalError(errData.message || errData.error || 'Failed to submit audit job.');
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
    try {
      const res = await apiFetch(`/audit/job/${jobId}`);
      if (res.ok) {
        const detail = await res.json();
        setSelectedJobDetail(detail);
        if (detail.findings && detail.findings.length > 0) {
          setSelectedFinding(detail.findings[0]);
        }
      }
    } catch (err) {
      console.error('Fetch job detail error:', err);
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
              <span className="apple-version-badge">v2.4 Pro</span>
            </div>

            <nav className="apple-nav-links">
              <a href="#playground" className="apple-nav-link">Playground</a>
              <a href="#capabilities" className="apple-nav-link">Capabilities</a>
              <a href="#architecture" className="apple-nav-link">Architecture</a>
              <a href="#metrics" className="apple-nav-link">Performance</a>
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
          <div className="apple-pill-badge">
            <div className="apple-status-beacon"></div>
            <span>Autonomous Agentic Security Intelligence</span>
          </div>

          <h1 className="apple-hero-headline">
            <span className="apple-headline-gradient">Security reasoning at the</span><br />
            <span className="apple-headline-accent">speed of thought.</span>
          </h1>

          <p className="apple-hero-subtext">
            Fire Crow orchestrates sandboxed LLM security agents to ingest repository ASTs, synthesize multi-node attack topologies, simulate exploit vectors, and compile verified code patches.
          </p>

          <div className="apple-hero-cta-group">
            <button onClick={() => setView('login')} className="btn-apple-primary" style={{ padding: '0.8rem 2rem', fontSize: '0.95rem' }}>
              Launch Control Console →
            </button>
            <a href="#playground" className="btn-apple-secondary" style={{ padding: '0.8rem 1.8rem', fontSize: '0.95rem' }}>
              ⚡ Interactive Scan Playground
            </a>
          </div>

          {/* Social Proof Logo Cloud */}
          <div className="apple-logo-cloud">
            <div className="logo-cloud-title">Securing Infrastructure for High-Growth Teams</div>
            <div className="logo-item">
              <svg className="logo-icon-svg" viewBox="0 0 24 24"><path d="M12 2L2 22h20L12 2zm0 3.8L18.4 18H5.6L12 5.8z"/></svg>
              <span>Vertex Security</span>
            </div>
            <div className="logo-item">
              <svg className="logo-icon-svg" viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>
              <span>Aether Sec</span>
            </div>
            <div className="logo-item">
              <svg className="logo-icon-svg" viewBox="0 0 24 24"><path d="M12 22c5.52 0 10-4.48 10-10S17.52 2 12 2 2 6.48 2 12s4.48 10 10 10zm-1-15h2v6h-2V7zm0 8h2v2h-2v-2z"/></svg>
              <span>Krypton Shield</span>
            </div>
            <div className="logo-item">
              <svg className="logo-icon-svg" viewBox="0 0 24 24"><path d="M12 2L1 21h22L12 2zm0 3.5l7.5 13H4.5L12 5.5z"/></svg>
              <span>OmniCorp</span>
            </div>
            <div className="logo-item">
              <svg className="logo-icon-svg" viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5-10-5-10 5z"/></svg>
              <span>Acme Cloud</span>
            </div>
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
                  <span>📺</span> Tokio Stream
                </button>
                <button 
                  className={`apple-tab-button ${landingTab === 'graph' ? 'active' : ''}`}
                  onClick={() => setLandingTab('graph')}
                >
                  <span>🕸️</span> Attack Topology
                </button>
                <button 
                  className={`apple-tab-button ${landingTab === 'diff' ? 'active' : ''}`}
                  onClick={() => setLandingTab('diff')}
                >
                  <span>📝</span> Verified Patch
                </button>
              </div>

              <div className="apple-window-badge">
                <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#30d158', display: 'inline-block' }}></span>
                <span>SANDBOX: DOCKER_NODE_RUST</span>
              </div>
            </div>

            {/* Tab 1: Terminal Log */}
            {landingTab === 'terminal' && (
              <div className="apple-tab-content" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem', lineHeight: '1.75', color: '#e5e5ea', background: '#020203' }}>
                <div><span style={{ color: '#2997ff' }}>[10:45:02]</span> Initializing Rust Axum Agentic Engine v2.4 (Tokio Async Worker pool)...</div>
                <div><span style={{ color: '#2997ff' }}>[10:45:03]</span> Spawning isolated Docker Container Sandbox (Node 20 / Python 3.12 / Rust)...</div>
                <div><span style={{ color: '#ffd60a' }}>[10:45:04]</span> Ingesting Git repository AST structure & constructing full dependency graph...</div>
                <div><span style={{ color: '#ff453a' }}>[10:45:06]</span> <strong style={{ color: '#ff453a' }}>CVE-2026-798 Identified:</strong> Hardcoded JWT secret fallback in <code style={{ color: '#bf5af2', background: 'rgba(191,90,242,0.12)', padding: '0.1rem 0.35rem', borderRadius: '4px' }}>backend/src/config.rs:42</code></div>
                <div><span style={{ color: '#30d158' }}>[10:45:08]</span> Gemini Security Agent synthesized non-breaking AST patch with verified signature.</div>
                <div><span style={{ color: '#86868b' }}>[10:45:09]</span> Persisted multi-node attack topology to PostgreSQL schema <code style={{ color: '#bf5af2' }}>attack_graph_nodes</code></div>
                <div style={{ marginTop: '0.5rem', color: '#30d158', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <span>✓</span> Sandbox compilation verified (0 warnings, 0 errors, 100% test pass)
                </div>
              </div>
            )}

            {/* Tab 2: Attack Topology Visualizer */}
            {landingTab === 'graph' && (
              <div className="apple-tab-content" style={{ background: '#020203', minHeight: '340px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                <div className="topology-svg-container">
                  <svg width="100%" height="240" viewBox="0 0 800 240" fill="none" xmlns="http://www.w3.org/2000/svg">
                    {/* Animated connection lines */}
                    <path d="M140 120 L275 60" stroke="url(#blue-to-red)" strokeWidth="2" strokeDasharray="6" className="svg-link-dash" />
                    <path d="M140 120 L275 180" stroke="#2997ff" strokeWidth="1.5" opacity="0.3" />
                    <path d="M295 60 L455 120" stroke="url(#red-to-purple)" strokeWidth="2" strokeDasharray="6" className="svg-link-dash" />
                    <path d="M295 180 L455 120" stroke="#86868b" strokeWidth="1.5" opacity="0.3" />
                    <path d="M475 120 L635 120" stroke="url(#purple-to-green)" strokeWidth="2" strokeDasharray="6" className="svg-link-dash" />

                    {/* Gradients */}
                    <defs>
                      <linearGradient id="blue-to-red" x1="0%" y1="0%" x2="100%" y2="0%">
                        <stop offset="0%" stopColor="#2997ff" />
                        <stop offset="100%" stopColor="#ff453a" />
                      </linearGradient>
                      <linearGradient id="red-to-purple" x1="0%" y1="0%" x2="100%" y2="0%">
                        <stop offset="0%" stopColor="#ff453a" />
                        <stop offset="100%" stopColor="#bf5af2" />
                      </linearGradient>
                      <linearGradient id="purple-to-green" x1="0%" y1="0%" x2="100%" y2="0%">
                        <stop offset="0%" stopColor="#bf5af2" />
                        <stop offset="100%" stopColor="#30d158" />
                      </linearGradient>
                    </defs>

                    {/* Node 1: Entry API Route */}
                    <g className="svg-node" style={{ color: '#2997ff' }} onClick={() => setSelectedGraphNode('ingress')}>
                      <circle cx="120" cy="120" r="28" fill="rgba(41, 151, 255, 0.08)" stroke={selectedGraphNode === 'ingress' ? '#ffffff' : '#2997ff'} strokeWidth={selectedGraphNode === 'ingress' ? '3' : '1.5'} />
                      <circle cx="120" cy="120" r="6" fill="#2997ff" className="svg-node-pulse" />
                      <text x="120" y="165" fill="#ffffff" fontSize="11" fontWeight="600" textAnchor="middle">Web Ingress</text>
                      <text x="120" y="180" fill="#86868b" fontSize="9" fontFamily="var(--font-mono)" textAnchor="middle">POST /api/v1/auth</text>
                    </g>

                    {/* Node 2: Exploit Node (JWT) */}
                    <g className="svg-node" style={{ color: '#ff453a' }} onClick={() => setSelectedGraphNode('exploit')}>
                      <circle cx="285" cy="60" r="28" fill="rgba(255, 69, 58, 0.1)" stroke={selectedGraphNode === 'exploit' ? '#ffffff' : '#ff453a'} strokeWidth={selectedGraphNode === 'exploit' ? '3' : '1.8'} />
                      <circle cx="285" cy="60" r="6" fill="#ff453a" />
                      <text x="285" y="105" fill="#ff8a80" fontSize="11" fontWeight="700" textAnchor="middle">CVE-2026-798</text>
                      <text x="285" y="120" fill="#a1a1a6" fontSize="9" fontFamily="var(--font-mono)" textAnchor="middle">JWT Secret Bypass</text>
                    </g>

                    {/* Node 3: Safe Route Node */}
                    <g className="svg-node" style={{ color: '#86868b' }} opacity="0.6" onClick={() => setSelectedGraphNode('ingress')}>
                      <circle cx="285" cy="180" r="24" fill="rgba(255, 255, 255, 0.02)" stroke="#86868b" strokeWidth="1" />
                      <circle cx="285" cy="180" r="4" fill="#86868b" />
                      <text x="285" y="218" fill="#86868b" fontSize="10" textAnchor="middle">Public Assets</text>
                    </g>

                    {/* Node 4: Sandbox Exploit Orchestrator */}
                    <g className="svg-node" style={{ color: '#bf5af2' }} onClick={() => setSelectedGraphNode('sandbox')}>
                      <rect x="440" y="92" width="56" height="56" rx="10" fill="rgba(191, 90, 242, 0.08)" stroke={selectedGraphNode === 'sandbox' ? '#ffffff' : '#bf5af2'} strokeWidth={selectedGraphNode === 'sandbox' ? '3' : '1.5'} />
                      <circle cx="468" cy="120" r="6" fill="#bf5af2" className="svg-node-pulse" />
                      <text x="468" y="165" fill="#ffffff" fontSize="11" fontWeight="600" textAnchor="middle">Docker Sandbox</text>
                      <text x="468" y="180" fill="#86868b" fontSize="9" fontFamily="var(--font-mono)" textAnchor="middle">Exploit Simulator</text>
                    </g>

                    {/* Node 5: Target Postgres Asset */}
                    <g className="svg-node" style={{ color: '#30d158' }} onClick={() => setSelectedGraphNode('target')}>
                      <circle cx="650" cy="120" r="28" fill="rgba(48, 209, 88, 0.08)" stroke={selectedGraphNode === 'target' ? '#ffffff' : '#30d158'} strokeWidth={selectedGraphNode === 'target' ? '3' : '1.5'} />
                      <polygon points="650,112 658,124 642,124" fill="#30d158" />
                      <text x="650" y="165" fill="#ffffff" fontSize="11" fontWeight="600" textAnchor="middle">PostgreSQL DB</text>
                      <text x="650" y="180" fill="#86868b" fontSize="9" fontFamily="var(--font-mono)" textAnchor="middle">Neon Target</text>
                    </g>
                  </svg>
                </div>

                {/* Live Node Inspector Panel */}
                <div className="inspector-card">
                  <div className="inspector-header">
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                      <span style={{ fontSize: '0.82rem', fontWeight: 700, color: '#ffffff' }}>NODE INSPECTOR:</span>
                      <span className="badge badge-high" style={{ textTransform: 'uppercase' }}>
                        {selectedGraphNode === 'ingress' && 'Ingress Gateway'}
                        {selectedGraphNode === 'exploit' && 'Vulnerability Target'}
                        {selectedGraphNode === 'sandbox' && 'Docker Container Engine'}
                        {selectedGraphNode === 'target' && 'PostgreSQL Cluster'}
                      </span>
                    </div>
                    <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>Click graph nodes to inspect metadata</span>
                  </div>

                  <div className="inspector-grid">
                    {selectedGraphNode === 'ingress' && (
                      <>
                        <div className="inspector-item"><div style={{ color: '#86868b' }}>Route:</div><div style={{ color: '#2997ff', fontWeight: 600 }}>POST /api/v1/auth</div></div>
                        <div className="inspector-item"><div style={{ color: '#86868b' }}>Traffic:</div><div style={{ color: '#ffffff' }}>Encrypted TLS 1.3</div></div>
                        <div className="inspector-item"><div style={{ color: '#86868b' }}>Rate Limit:</div><div style={{ color: '#30d158' }}>Active (100 req/s)</div></div>
                        <div className="inspector-item"><div style={{ color: '#86868b' }}>Risk Score:</div><div style={{ color: '#ffd60a' }}>2.1 Low</div></div>
                      </>
                    )}
                    {selectedGraphNode === 'exploit' && (
                      <>
                        <div className="inspector-item"><div style={{ color: '#86868b' }}>CVE ID:</div><div style={{ color: '#ff453a', fontWeight: 700 }}>CVE-2026-798</div></div>
                        <div className="inspector-item"><div style={{ color: '#86868b' }}>Type:</div><div style={{ color: '#ffffff' }}>Hardcoded Secret Fallback</div></div>
                        <div className="inspector-item"><div style={{ color: '#86868b' }}>File Location:</div><div style={{ color: '#bf5af2' }}>backend/src/config.rs:42</div></div>
                        <div className="inspector-item"><div style={{ color: '#86868b' }}>CVSS Severity:</div><div style={{ color: '#ff453a', fontWeight: 700 }}>9.8 CRITICAL</div></div>
                      </>
                    )}
                    {selectedGraphNode === 'sandbox' && (
                      <>
                        <div className="inspector-item"><div style={{ color: '#86868b' }}>Runtime:</div><div style={{ color: '#bf5af2', fontWeight: 600 }}>Docker Linux Container</div></div>
                        <div className="inspector-item"><div style={{ color: '#86868b' }}>Privileges:</div><div style={{ color: '#30d158' }}>Non-Root (ephemeral)</div></div>
                        <div className="inspector-item"><div style={{ color: '#86868b' }}>Network Mode:</div><div style={{ color: '#30d158' }}>Isolated Subnet</div></div>
                        <div className="inspector-item"><div style={{ color: '#86868b' }}>Verification:</div><div style={{ color: '#30d158' }}>100% Confirmed</div></div>
                      </>
                    )}
                    {selectedGraphNode === 'target' && (
                      <>
                        <div className="inspector-item"><div style={{ color: '#86868b' }}>Asset:</div><div style={{ color: '#30d158', fontWeight: 600 }}>Neon PostgreSQL DB</div></div>
                        <div className="inspector-item"><div style={{ color: '#86868b' }}>Tables:</div><div style={{ color: '#ffffff' }}>attack_graph_edges</div></div>
                        <div className="inspector-item"><div style={{ color: '#86868b' }}>SSL Binding:</div><div style={{ color: '#30d158' }}>Enforced</div></div>
                        <div className="inspector-item"><div style={{ color: '#86868b' }}>Data Loss:</div><div style={{ color: '#30d158' }}>Prevented</div></div>
                      </>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Tab 3: Code Remediation Diff */}
            {landingTab === 'diff' && (
              <div className="apple-tab-content" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem', lineHeight: '1.7', background: '#020203', minHeight: '300px' }}>
                <div className="patch-selector-bar">
                  <button 
                    className={`patch-tab-btn ${selectedDiffPatch === 'jwt' ? 'active' : ''}`}
                    onClick={() => setSelectedDiffPatch('jwt')}
                  >
                    backend/src/config.rs (JWT Secret)
                  </button>
                  <button 
                    className={`patch-tab-btn ${selectedDiffPatch === 'sqli' ? 'active' : ''}`}
                    onClick={() => setSelectedDiffPatch('sqli')}
                  >
                    backend/src/api/routes_auth.rs (SQL Sanitizer)
                  </button>
                  <button 
                    className={`patch-tab-btn ${selectedDiffPatch === 'csrf' ? 'active' : ''}`}
                    onClick={() => setSelectedDiffPatch('csrf')}
                  >
                    backend/src/main.rs (CSRF Cookie)
                  </button>
                </div>

                {selectedDiffPatch === 'jwt' && (
                  <>
                    <div style={{ color: '#86868b', marginBottom: '0.85rem' }}>// Patch 1: Enforce Environment Guard for JWT Key</div>
                    <div style={{ background: 'rgba(255, 69, 58, 0.12)', color: '#ff8a80', padding: '0.35rem 0.75rem', borderRadius: '6px', marginBottom: '0.35rem', borderLeft: '3px solid #ff453a' }}>
                      - let jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| "default_insecure_secret".to_string());
                    </div>
                    <div style={{ background: 'rgba(48, 209, 88, 0.12)', color: '#86efac', padding: '0.35rem 0.75rem', borderRadius: '6px', borderLeft: '3px solid #30d158' }}>
                      + let jwt_secret = env::var("JWT_SECRET").map_err(|_| ConfigError::MissingSecret("JWT_SECRET environment variable is mandatory in production"))?;
                    </div>
                  </>
                )}

                {selectedDiffPatch === 'sqli' && (
                  <>
                    <div style={{ color: '#86868b', marginBottom: '0.85rem' }}>// Patch 2: Parameterize Dynamic Query in Auth Model</div>
                    <div style={{ background: 'rgba(255, 69, 58, 0.12)', color: '#ff8a80', padding: '0.35rem 0.75rem', borderRadius: '6px', marginBottom: '0.35rem', borderLeft: '3px solid #ff453a' }}>
                      - let query = format!("SELECT * FROM users WHERE email = '{}'", user_email);
                    </div>
                    <div style={{ background: 'rgba(48, 209, 88, 0.12)', color: '#86efac', padding: '0.35rem 0.75rem', borderRadius: '6px', borderLeft: '3px solid #30d158' }}>
                      + let user = sqlx::query_as::&lt;_, User&gt;("SELECT * FROM users WHERE email = $1").bind(&user_email).fetch_one(&pool).await?;
                    </div>
                  </>
                )}

                {selectedDiffPatch === 'csrf' && (
                  <>
                    <div style={{ color: '#86868b', marginBottom: '0.85rem' }}>// Patch 3: SameSite Lax Cookie Flag for OAuth Callbacks</div>
                    <div style={{ background: 'rgba(255, 69, 58, 0.12)', color: '#ff8a80', padding: '0.35rem 0.75rem', borderRadius: '6px', marginBottom: '0.35rem', borderLeft: '3px solid #ff453a' }}>
                      - Cookie::build("oauth_redirect_origin", origin).path("/").finish()
                    </div>
                    <div style={{ background: 'rgba(48, 209, 88, 0.12)', color: '#86efac', padding: '0.35rem 0.75rem', borderRadius: '6px', borderLeft: '3px solid #30d158' }}>
                      + Cookie::build("oauth_redirect_origin", origin).path("/").same_site(SameSite::Lax).secure(true).finish()
                    </div>
                  </>
                )}

                <div style={{ marginTop: '1.25rem', padding: '0.75rem 1rem', background: 'rgba(255, 255, 255, 0.03)', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ color: '#30d158', fontSize: '0.8rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span>✓</span> Compiler & Unit Test Verification: 100% Passed
                  </div>
                  <span style={{ color: '#86868b', fontSize: '0.74rem' }}>Target: Rust 1.84 / Axum 0.7</span>
                </div>
              </div>
            )}
          </div>
        </section>

        {/* Apple Interactive Scan Playground Section */}
        <section id="playground" className="apple-playground-section">
          <div className="apple-playground-card">
            <div className="apple-section-eyebrow">✦ Interactive Security Playground</div>
            <h2 style={{ fontSize: '2rem', fontWeight: 800, color: '#ffffff', letterSpacing: '-0.03em', marginBottom: '0.6rem' }}>
              Test Fire Crow Agent Instantly
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.95rem', marginBottom: '1.75rem', lineHeight: '1.6' }}>
              Select a repository preset or enter your repository Git URL to trigger an instant agentic vulnerability scan simulation.
            </p>

            <div className="apple-quick-chips">
              <span 
                className={`apple-chip ${simRepo === 'https://github.com/expressjs/express.git' ? 'active' : ''}`}
                onClick={() => handleRunSimulatedScan('https://github.com/expressjs/express.git')}
              >
                expressjs/express
              </span>
              <span 
                className={`apple-chip ${simRepo === 'https://github.com/tokio-rs/axum.git' ? 'active' : ''}`}
                onClick={() => handleRunSimulatedScan('https://github.com/tokio-rs/axum.git')}
              >
                tokio-rs/axum
              </span>
              <span 
                className={`apple-chip ${simRepo === 'https://github.com/tiangolo/fastapi.git' ? 'active' : ''}`}
                onClick={() => handleRunSimulatedScan('https://github.com/tiangolo/fastapi.git')}
              >
                tiangolo/fastapi
              </span>
              <span 
                className={`apple-chip ${simRepo === 'https://github.com/kubernetes/kubernetes.git' ? 'active' : ''}`}
                onClick={() => handleRunSimulatedScan('https://github.com/kubernetes/kubernetes.git')}
              >
                kubernetes/kubernetes
              </span>
            </div>

            <div className="apple-input-group">
              <input
                type="text"
                value={simRepo}
                onChange={(e) => setSimRepo(e.target.value)}
                placeholder="https://github.com/your-org/your-repo.git"
                className="apple-input"
              />
              <button 
                onClick={() => handleRunSimulatedScan()} 
                disabled={isSimulating}
                className="btn-apple-primary"
                style={{ padding: '0.85rem 1.75rem', whiteSpace: 'nowrap' }}
              >
                {isSimulating ? 'Simulating Scan...' : 'Run Agentic Scan 🚀'}
              </button>
            </div>

            {isSimulating && (
              <div style={{ marginTop: '1.75rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem', color: '#e5e5ea', fontFamily: 'var(--font-mono)' }}>
                  <span>{simStage}</span>
                  <span style={{ fontWeight: 700 }}>{simProgress}%</span>
                </div>
                <div className="apple-progress-track">
                  <div className="apple-progress-fill" style={{ width: `${simProgress}%` }}></div>
                </div>
              </div>
            )}

            {simComplete && (
              <div className="posture-card">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: '1rem', marginBottom: '1.25rem' }}>
                  <div>
                    <div style={{ fontSize: '1.1rem', fontWeight: 800, color: '#ffffff', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span>🛡️</span> Security Posture Audit: Discovered Exploit Metrics
                    </div>
                    <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>Target: {simRepo}</p>
                  </div>
                  <span className="badge badge-critical" style={{ padding: '0.3rem 0.75rem', fontSize: '0.74rem' }}>SCORE: 9.2 CRITICAL</span>
                </div>
                <div className="posture-grid">
                  <div className="posture-item">
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '0.25rem' }}>Vulnerabilities</div>
                    <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#ff453a' }}>2 Discovered</div>
                  </div>
                  <div className="posture-item">
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '0.25rem' }}>Exploit Testing</div>
                    <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#30d158' }}>100% Sandbox Verified</div>
                  </div>
                  <div className="posture-item">
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '0.25rem' }}>AST Code Patch</div>
                    <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#bf5af2' }}>Auto-Generated</div>
                  </div>
                </div>
                <div style={{ marginTop: '1.5rem', display: 'flex', justifyContent: 'flex-end' }}>
                  <button onClick={() => setView('login')} className="btn-apple-primary" style={{ padding: '0.55rem 1.35rem', fontSize: '0.84rem' }}>
                    View Full Console Report →
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
                <div className="apple-bento-icon">🤖</div>
                <h3 className="apple-bento-title">Gemini Agentic Vulnerability Reasoning</h3>
                <p className="apple-bento-desc">
                  Autonomous LLM agents formulate hypotheses, construct proof-of-concept exploits, and synthesize non-breaking code patches with zero hallucinated vulnerabilities.
                </p>
              </div>

              <div style={{ marginTop: '1.75rem', background: 'rgba(0, 0, 0, 0.4)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '12px', padding: '1rem 1.25rem', fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
                <div style={{ color: '#bf5af2', display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                  <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#bf5af2', display: 'inline-block' }}></span>
                  Gemini 1.5 Pro Reasoning Loop
                </div>
                <div style={{ color: '#86868b' }}>Formulating exploit path → Verifying against Rust AST → Generating compiler-tested patch</div>
              </div>
            </div>

            {/* Bento Card 2: Col-4 (Docker Sandbox Isolation) */}
            <div className="apple-bento-card apple-bento-col-4">
              <div>
                <div className="apple-bento-icon">🐳</div>
                <h3 className="apple-bento-title">Docker Sandbox Isolation</h3>
                <p className="apple-bento-desc">
                  Ephemeral, non-root container isolation guarantees absolute host boundary protection during exploit verification.
                </p>
              </div>

              <div style={{ marginTop: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'rgba(48, 209, 88, 0.08)', border: '1px solid rgba(48, 209, 88, 0.25)', borderRadius: '10px', padding: '0.65rem 0.9rem' }}>
                <div style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#30d158' }}></div>
                <span style={{ fontSize: '0.76rem', color: '#30d158', fontWeight: 600 }}>100% Isolated Runtime</span>
              </div>
            </div>

            {/* Bento Card 3: Col-4 (High-Throughput Rust Engine) */}
            <div className="apple-bento-card apple-bento-col-4">
              <div>
                <div className="apple-bento-icon">⚡</div>
                <h3 className="apple-bento-title">High-Throughput Rust Engine</h3>
                <p className="apple-bento-desc">
                  Built on Axum 0.7, Tokio async workers, and SQLx for lightning-fast concurrent repository scans.
                </p>
              </div>

              <div style={{ marginTop: '1.5rem', fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: '#ff8533' }}>
                ⚡ &lt; 2.4s AST Parse Latency
              </div>
            </div>

            {/* Bento Card 4: Col-4 (Just-In-Time PAM & IAM) */}
            <div className="apple-bento-card apple-bento-col-4">
              <div>
                <div className="apple-bento-icon">🔑</div>
                <h3 className="apple-bento-title">Just-In-Time PAM & IAM</h3>
                <p className="apple-bento-desc">
                  Zero-standing access controls with temporary elevation, audit trails, and OIDC / SAML SSO integration.
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
                <div className="apple-bento-icon">📄</div>
                <h3 className="apple-bento-title">Automated Compliance PDFs</h3>
                <p className="apple-bento-desc">
                  Instantly compiles discovered CVEs, code fixes, and CWE risk matrices into SOC2 / ISO-27001 audit reports.
                </p>
              </div>

              <div style={{ marginTop: '1.5rem', fontSize: '0.78rem', color: '#2997ff', fontWeight: 600 }}>
                ✓ Export Ready (PDF / JSON)
              </div>
            </div>

            {/* Bento Card 6: Col-12 (PostgreSQL Attack Topology Graph) */}
            <div className="apple-bento-card apple-bento-col-12">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1.5rem' }}>
                <div style={{ maxWidth: '600px' }}>
                  <div className="apple-bento-icon">🕸️</div>
                  <h3 className="apple-bento-title">Multi-Node PostgreSQL Attack Topology Graph</h3>
                  <p className="apple-bento-desc">
                    Models complex lateral movement paths, entrypoints, database exposures, and privilege escalation vulnerabilities stored directly in relational schemas.
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
        <section className="apple-pricing-section">
          <div className="apple-section-header">
            <div className="apple-section-eyebrow">✦ Transparent SaaS Pricing</div>
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
                <div className="pricing-tier-name" style={{ color: '#ff8533' }}>Pro Console</div>
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
                Launch Control Console →
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
                <li><a href="#playground">Interactive Playground</a></li>
                <li><a href="#capabilities">Agent Capabilities</a></li>
                <li><a href="#architecture">Autonomous Pipeline</a></li>
                <li><a href="#metrics">Engine Performance</a></li>
              </ul>
            </div>

            <div>
              <div className="apple-footer-col-title">Developers</div>
              <ul className="apple-footer-links">
                <li><a href="https://github.com/johan-droid/Fire-Crow-" target="_blank" rel="noreferrer">GitHub Repository</a></li>
                <li><a href="#architecture">Axum Engine Specs</a></li>
                <li><a href="/documentation/API_DOCUMENTATION.md">API Documentation</a></li>
                <li><a href="/apple_design.md">Apple Design System</a></li>
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
      {/* Mobile Drawer Overlay */}
      <div 
        className={`drawer-overlay ${mobileDrawerOpen ? 'open' : ''}`}
        onClick={() => setMobileDrawerOpen(false)}
      />

      {/* Sidebar Navigation */}
      <aside className={`sidebar ${mobileDrawerOpen ? 'open' : ''}`}>
        <div className="sidebar-logo">
          <img src="/fire-crow-logo.png" alt="Fire Crow Flying Logo" className="logo-img" />
          <div style={{ flex: 1 }}>
            <div className="sidebar-logo-text">Fire Crow</div>
          </div>
          <span className="sidebar-logo-badge">SEC</span>
        </div>

        <div className="sidebar-section-title">Navigation</div>

        <div className="sidebar-nav">
          <button 
            className={`sidebar-item ${dashTab === 'overview' ? 'active' : ''}`}
            onClick={() => { setDashTab('overview'); setMobileDrawerOpen(false); }}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z"/>
            </svg>
            <span>Overview</span>
          </button>

          <button 
            className={`sidebar-item ${dashTab === 'scans' ? 'active' : ''}`}
            onClick={() => { setDashTab('scans'); setMobileDrawerOpen(false); }}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            <span>Audit Jobs</span>
            <span className="sidebar-item-badge">{jobs.length}</span>
          </button>

          <button 
            className={`sidebar-item ${dashTab === 'identity' ? 'active' : ''}`}
            onClick={() => { setDashTab('identity'); setMobileDrawerOpen(false); }}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
              <circle cx="9" cy="7" r="4"/>
            </svg>
            <span>IAM, SSO & PAM</span>
            <span className="sidebar-item-badge">{ssoProviders.length + pamRequests.length}</span>
          </button>

          <button 
            className={`sidebar-item ${dashTab === 'security' ? 'active' : ''}`}
            onClick={() => { setDashTab('security'); setMobileDrawerOpen(false); }}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
            </svg>
            <span>Logs & MFA</span>
            <span className="sidebar-item-badge">{activities.length}</span>
          </button>
        </div>

        <div className="sidebar-user">
          <div className="sidebar-avatar">
            {user?.username ? user.username[0].toUpperCase() : 'U'}
          </div>
          <div className="sidebar-user-info">
            <div className="sidebar-username">{user?.username}</div>
            <div className="sidebar-email">{user?.email || user?.user_id.substring(0, 10)}</div>
          </div>
          <button onClick={handleLogout} className="btn btn-ghost btn-icon" title="Sign Out">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
              <polyline points="16 17 21 12 16 7"/>
              <line x1="21" y1="12" x2="9" y2="12"/>
            </svg>
          </button>
        </div>
      </aside>

      {/* Main Container */}
      <main className="main-content">
        {/* Mobile Header */}
        <div className="mobile-topbar">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <button className="hamburger" onClick={() => setMobileDrawerOpen(!mobileDrawerOpen)}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <line x1="3" y1="6" x2="21" y2="6"/>
                <line x1="3" y1="12" x2="21" y2="12"/>
                <line x1="3" y1="18" x2="21" y2="18"/>
              </svg>
            </button>
            <span style={{ fontWeight: 700, fontSize: '0.95rem' }}>Fire Crow</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <button onClick={() => setIsScanModalOpen(true)} className="btn btn-primary btn-sm">
              + Scan
            </button>
          </div>
        </div>

        {/* Desktop Topbar */}
        <div className="topbar">
          <div>
            <div className="topbar-title">
              {dashTab === 'overview' && 'System Security Console'}
              {dashTab === 'scans' && 'Autonomous Audit Jobs'}
              {dashTab === 'identity' && 'Identity & Access Management'}
              {dashTab === 'security' && 'Logs & Telemetry'}
            </div>
            <div className="topbar-subtitle">
              Connected Node: {user?.username} • ID: {user?.user_id.substring(0, 8)}
            </div>
          </div>

          <div className="topbar-right">
            <div className="status-indicator">
              <div className="status-dot status-dot-live" />
              <span>LIVE HYBRID NODE</span>
            </div>
            <button onClick={() => setIsScanModalOpen(true)} className="btn btn-primary btn-sm">
              + New Audit Job
            </button>
          </div>
        </div>

        {/* Page Content Body */}
        <div className="page-body">
          {/* Tab 1: Overview */}
          {dashTab === 'overview' && (
            <>
              {/* Metrics Row */}
              <div className="metrics-grid">
                <div className="metric-card">
                  <div className="metric-label">Audit Jobs</div>
                  <div className="metric-value">{jobs.length}</div>
                  <div className="metric-sub">PostgreSQL records</div>
                </div>

                <div className="metric-card">
                  <div className="metric-label">SSO Providers</div>
                  <div className="metric-value">{ssoProviders.length}</div>
                  <div className="metric-sub">OIDC / SAML</div>
                </div>

                <div className="metric-card">
                  <div className="metric-label">PAM Requests</div>
                  <div className="metric-value">{pamRequests.length}</div>
                  <div className="metric-sub">Elevation requests</div>
                </div>

                <div className="metric-card" style={{ position: 'relative' }}>
                  <div className="metric-label">User Balance</div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div className="metric-value">{user?.credit_balance ?? 10.0}</div>
                    <button 
                      onClick={() => setIsDodoModalOpen(true)} 
                      className="btn btn-primary btn-sm" 
                      style={{ fontSize: '0.72rem', padding: '0.25rem 0.65rem' }}
                    >
                      💳 Top-Up (Dodo)
                    </button>
                  </div>
                  <div className="metric-sub">API execution credits</div>
                </div>
              </div>

              {/* Two Column Layout: Recent Scans + Activity Feed */}
              <div className="two-col">
                {/* Active Audit Jobs Panel */}
                <div className="panel">
                  <div className="panel-header">
                    <div className="panel-title">
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                      </svg>
                      Recent Audit Jobs
                    </div>
                    <button onClick={() => setIsScanModalOpen(true)} className="btn btn-secondary btn-sm">
                      + Scan
                    </button>
                  </div>

                  <div className="panel-body" style={{ padding: '0.75rem' }}>
                    {jobs.length === 0 ? (
                      <div className="panel-empty">
                        <p style={{ marginBottom: '0.75rem' }}>No audit jobs in database yet.</p>
                        <button onClick={() => setIsScanModalOpen(true)} className="btn btn-primary btn-sm">
                          Trigger First Scan
                        </button>
                      </div>
                    ) : (
                      jobs.slice(0, 5).map(j => (
                        <div key={j.id} onClick={() => { handleViewJobDetail(j.id); setActiveMonitorJobId(j.id); }} className="list-item" style={{ borderLeft: activeMonitorJobId === j.id ? '2px solid var(--accent-green)' : undefined }}>
                          <div className="list-item-info">
                            <div className="list-item-title">{j.repo_url}</div>
                            <div className="list-item-sub">branch: {j.repo_branch} • {j.id.substring(0, 8)}</div>
                          </div>
                          <span className={`badge ${j.status === 'completed' ? 'badge-success' : 'badge-low'}`}>
                            {j.status}
                          </span>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                {/* Audit Console Tracker */}
                <div className="panel">
                  <div className="panel-header">
                    <div className="panel-title">
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <polyline points="4 17 10 11 12 13 18 7 14 7 18 7 18 11"/>
                      </svg>
                      Audit Console Tracker
                    </div>
                  </div>

                  <div className="panel-body" style={{ padding: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    {/* Live Progress Bar & Stage Pipeline Checklist */}
                    {(() => {
                      const selectedJob = jobs.find(j => j.id === (activeMonitorJobId || (jobs.length > 0 ? jobs[0].id : ''))) || (jobs.length > 0 ? jobs[0] : null);
                      if (!selectedJob) return null;

                      const phaseOrder = [
                        { key: 'intake', label: '1. Intake' },
                        { key: 'recon', label: '2. Recon' },
                        { key: 'scanning', label: '3. AST Scan' },
                        { key: 'ai_analysis', label: '4. AI Analysis' },
                        { key: 'remediation', label: '5. Remediation' },
                        { key: 'attack_graph', label: '6. Attack Graph' },
                        { key: 'reporting', label: '7. Report' },
                      ];

                      let percentage = 0;
                      if (selectedJob.status === 'completed') percentage = 100;
                      else if (selectedJob.status === 'queued') percentage = 8;
                      else if (selectedJob.status === 'failed' || selectedJob.status === 'cancelled') percentage = 100;
                      else {
                        const completedCount = monitorPhases.filter(p => p.status === 'completed').length;
                        const hasStarted = monitorPhases.some(p => p.status === 'started' || p.status === 'running');
                        percentage = Math.min(95, Math.max(12, Math.round((completedCount / phaseOrder.length) * 100) + (hasStarted ? 8 : 0)));
                      }

                      const isRunning = selectedJob.status === 'running' || selectedJob.status === 'queued';

                      return (
                        <div className="progress-card">
                          <div className="progress-header">
                            <div className="progress-title">
                              {isRunning && <span className="pulse-spinner"></span>}
                              <span>{selectedJob.repo_url}</span>
                              <span style={{ fontSize: '0.75rem', fontWeight: 500, color: 'var(--text-muted)' }}>
                                ({selectedJob.repo_branch})
                              </span>
                            </div>
                            <div className="progress-percent">{percentage}%</div>
                          </div>

                          <div className="progress-track">
                            <div 
                              className={`progress-fill ${isRunning ? 'animated' : ''}`}
                              style={{ 
                                width: `${percentage}%`,
                                background: selectedJob.status === 'failed' ? '#ff3b30' : selectedJob.status === 'completed' ? '#30d158' : undefined 
                              }}
                            ></div>
                          </div>

                          <div className="progress-steps-list">
                            {phaseOrder.map(phase => {
                              const loggedPhase = monitorPhases.find(p => p.phase_name.toLowerCase() === phase.key.toLowerCase());
                              const isDone = selectedJob.status === 'completed' || (loggedPhase && loggedPhase.status === 'completed');
                              const isActive = isRunning && loggedPhase && loggedPhase.status === 'started';
                              return (
                                <div 
                                  key={phase.key} 
                                  className={`progress-step-item ${isDone ? 'completed' : isActive ? 'active' : ''}`}
                                >
                                  <span>{isDone ? '✓' : isActive ? '⏳' : '◦'}</span>
                                  <span>{phase.label}</span>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      );
                    })()}

                    {/* Console Output Log */}
                    <div style={{
                      backgroundColor: '#000000',
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                      borderRadius: '4px',
                      padding: '0.75rem',
                      height: '180px',
                      overflowY: 'auto',
                      fontFamily: 'var(--font-mono)',
                      fontSize: '0.73rem',
                      color: '#00ff00',
                      lineHeight: '1.4',
                      boxShadow: 'inset 0 0 10px rgba(0,0,0,0.8)'
                    }}>
                      <pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>
                        {(() => {
                          const selectedJob = jobs.find(j => j.id === (activeMonitorJobId || (jobs.length > 0 ? jobs[0].id : ''))) || (jobs.length > 0 ? jobs[0] : null);
                          let terminalContent = '';
                          if (!selectedJob) {
                            terminalContent = '[SYSTEM] No active audit job found.\n[SYSTEM] Run a scan or select a job from the list to begin tracking.';
                          } else {
                            terminalContent += `[SYSTEM] Monitoring Job: ${selectedJob.id.substring(0, 8)}...\n`;
                            terminalContent += `[SYSTEM] Repo: ${selectedJob.repo_url}\n`;
                            terminalContent += '------------------------------------------------------------\n';
                            if (monitorPhases.length === 0) {
                              if (selectedJob.status === 'queued') {
                                terminalContent += '[QUEUE] Job is currently queued. Waiting for worker...\n';
                              } else {
                                terminalContent += '[SYSTEM] Spawning scan sandbox environment...\n';
                              }
                            } else {
                              monitorPhases.forEach(p => {
                                const time = p.started_at ? p.started_at.substring(11, 19) : '00:00:00';
                                terminalContent += `[${time}] [AGENT:${p.phase_name.toUpperCase()}] Spawning agent...\n`;
                                if (p.status === 'completed') {
                                  terminalContent += `[${time}] [AGENT:${p.phase_name.toUpperCase()}] Phase completed successfully in ${p.duration_sec || 0}s.\n`;
                                } else if (p.status === 'failed') {
                                  terminalContent += `[${time}] [AGENT:${p.phase_name.toUpperCase()}] ERROR: ${p.error_message || 'Phase execution failed'}\n`;
                                } else {
                                  terminalContent += `[${time}] [AGENT:${p.phase_name.toUpperCase()}] Agent is working...\n`;
                                }
                              });
                            }
                            if (selectedJob.status === 'completed') {
                              terminalContent += '------------------------------------------------------------\n';
                              terminalContent += '[SYSTEM] Scan sequence successfully completed.\n';
                              terminalContent += '[SYSTEM] Discovered findings saved to PostgreSQL.\n';
                            }
                          }
                          return terminalContent;
                        })()}
                      </pre>
                    </div>
                  </div>
                </div>
              </div>
            </>
          )}

          {/* Tab 2: Audit Jobs */}
          {dashTab === 'scans' && (
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">Database Audit Jobs ({jobs.length})</div>
                <button onClick={() => setIsScanModalOpen(true)} className="btn btn-primary btn-sm">
                  + Trigger Scan
                </button>
              </div>

              {jobs.length === 0 ? (
                <div className="panel-empty">
                  <p style={{ marginBottom: '0.75rem' }}>No audit jobs registered in PostgreSQL database.</p>
                  <button onClick={() => setIsScanModalOpen(true)} className="btn btn-primary btn-sm">
                    Submit Repo for Scan
                  </button>
                </div>
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Job ID</th>
                        <th>Repository</th>
                        <th>Branch</th>
                        <th>Status</th>
                        <th>Date</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {jobs.map(j => (
                        <tr key={j.id}>
                          <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>{j.id.substring(0, 8)}</td>
                          <td style={{ fontWeight: 600 }}>{j.repo_url}</td>
                          <td><code style={{ fontSize: '0.75rem', background: 'rgba(255,255,255,0.06)', padding: '0.15rem 0.4rem', borderRadius: '4px' }}>{j.repo_branch}</code></td>
                          <td>
                            <span className={`badge ${j.status === 'completed' ? 'badge-success' : 'badge-low'}`}>
                              {j.status}
                            </span>
                          </td>
                          <td style={{ color: 'var(--text-muted)', fontSize: '0.78rem' }}>{j.created_at.substring(0, 16)}</td>
                          <td>
                            <button onClick={() => handleViewJobDetail(j.id)} className="btn btn-secondary btn-sm">
                              Inspect
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
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
                  {ssoProviders.length === 0 ? (
                    <div className="panel-empty">No SSO providers configured.</div>
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
                  {pamRequests.length === 0 ? (
                    <div className="panel-empty">No PAM requests submitted.</div>
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
                  {domains.length === 0 ? (
                    <div className="panel-empty">No domain verifications registered.</div>
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
                </div>
                <div className="panel-body">
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>TOTP Authenticator App</div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Status: {mfaStatus.enabled ? 'Active & Enforced' : 'Not Enrolled'}</div>
                    </div>
                    <span className={`badge ${mfaStatus.enabled ? 'badge-success' : 'badge-neutral'}`}>
                      {mfaStatus.enabled ? 'ACTIVE' : 'DISABLED'}
                    </span>
                  </div>
                </div>
              </div>

              <div className="panel">
                <div className="panel-header">
                  <div className="panel-title">User Security Activities ({activities.length})</div>
                </div>
                <div className="panel-body" style={{ padding: '0.75rem' }}>
                  {activities.length === 0 ? (
                    <div className="panel-empty">No security logs recorded.</div>
                  ) : (
                    activities.map(act => (
                      <div key={act.id} className="list-item" style={{ cursor: 'default' }}>
                        <div className="list-item-info">
                          <div className="list-item-title">{act.action}</div>
                          {act.details_json && <div className="list-item-sub">{act.details_json}</div>}
                        </div>
                        <span className="badge badge-neutral">{act.created_at.substring(11, 19)}</span>
                      </div>
                    ))
                  )}
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
                    type="url" 
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
                <button type="submit" className="btn btn-primary" disabled={isSubmitting}>
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
          <div className="modal" style={{ maxWidth: '650px' }} onClick={e => e.stopPropagation()}>
            <div className="modal-head">
              <div>
                <div className="modal-title">Job Details: {selectedJobDetail.job.id.substring(0, 8)}</div>
                <div className="modal-sub">{selectedJobDetail.job.repo_url}</div>
              </div>
              <button onClick={() => setSelectedJobDetail(null)} className="btn btn-ghost btn-icon">✕</button>
            </div>

            <div className="modal-body" style={{ maxHeight: '420px', overflowY: 'auto' }}>
              <div style={{ fontSize: '0.82rem', fontWeight: 700, marginBottom: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)' }}>
                Reported Findings ({selectedJobDetail.findings.length})
              </div>

              {selectedJobDetail.findings.length === 0 ? (
                <div className="panel-empty">No findings reported for this audit job.</div>
              ) : (
                selectedJobDetail.findings.map(f => (
                  <div key={f.id} className="panel" style={{ marginBottom: '0.75rem', padding: '0.85rem' }}>
                    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '0.35rem' }}>
                      <span className="badge badge-critical">{f.severity}</span>
                      <span style={{ fontSize: '0.73rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{f.cwe_id || 'CWE-UNKNOWN'}</span>
                    </div>
                    <div style={{ fontWeight: 600, fontSize: '0.85rem' }}>{f.title}</div>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', margin: '0.4rem 0' }}>{f.description}</div>
                    {f.remediation && (
                      <pre className="code-block" style={{ marginTop: '0.4rem' }}>
                        <code>{f.remediation}</code>
                      </pre>
                    )}
                  </div>
                ))
              )}
            </div>

            <div className="modal-footer">
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
