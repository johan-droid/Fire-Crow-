import { useState, useEffect, useCallback, useRef } from 'react';

const API_BASE = '/api/v1';

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
  verification_token: string;
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
    const interval = setInterval(fetchPhases, 3000);
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
        setIsScanModalOpen(false);
        setNewRepoUrl('');
        setDashTab('scans');
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
      <div className="saas-page-bg" style={{ color: 'var(--text-primary)', minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
        {/* Minimal Floating Navigation Bar */}
        <header className="saas-nav">
          <div className="landing-nav-container" style={{ maxWidth: '1200px', margin: '0 auto', padding: '0.85rem 1.5rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <img src="/fire-crow-logo.png" alt="Fire Crow Logo" className="logo-img" style={{ width: '28px', height: '28px' }} />
              <span style={{ fontSize: '1.05rem', fontWeight: 700, letterSpacing: '-0.02em', color: '#ffffff' }}>Fire Crow</span>
              <span style={{ fontSize: '0.7rem', color: '#71717a', fontFamily: 'var(--font-mono)', border: '1px solid rgba(255,255,255,0.1)', padding: '0.1rem 0.45rem', borderRadius: '4px' }}>v2.4</span>
            </div>

            <nav className="landing-nav-links" style={{ display: 'flex', gap: '2rem', fontSize: '0.875rem' }}>
              <a href="#playground" style={{ color: '#a1a1aa', textDecoration: 'none', transition: 'color 0.2s' }}>Playground</a>
              <a href="#features" style={{ color: '#a1a1aa', textDecoration: 'none', transition: 'color 0.2s' }}>Platform</a>
              <a href="#architecture" style={{ color: '#a1a1aa', textDecoration: 'none', transition: 'color 0.2s' }}>Architecture</a>
              <a href="https://github.com/johan-droid/Fire-Crow-" target="_blank" rel="noreferrer" style={{ color: '#a1a1aa', textDecoration: 'none' }}>GitHub</a>
            </nav>

            <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
              <button onClick={() => setView('login')} className="btn-saas-outline" style={{ padding: '0.45rem 1rem', fontSize: '0.82rem' }}>
                Sign In
              </button>
              <button onClick={() => setView('login')} className="btn-saas-solid" style={{ padding: '0.45rem 1.1rem', fontSize: '0.82rem' }}>
                Launch Console →
              </button>
            </div>
          </div>
        </header>

        {/* Ultra-Minimal Hero Section */}
        <section style={{ padding: '7rem 1.5rem 4rem', textAlign: 'center', maxWidth: '1100px', margin: '0 auto', width: '100%' }}>
          <div className="saas-badge">
            <div className="saas-status-dot"></div>
            <span>AUTONOMOUS RED TEAM ENGINE</span>
          </div>

          <h1 className="saas-h1">
            Autonomous Security Reasoning<br />
            <span className="saas-h1-accent">for Enterprise Stacks</span>
          </h1>

          <p className="saas-sub">
            Fire Crow coordinates sandboxed security LLM agents to map application repositories, execute safe exploit simulations, enforce access controls, and generate compliance fixes.
          </p>

          <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center', flexWrap: 'wrap' }}>
            <button onClick={() => setView('login')} className="btn-saas-solid">
              Launch Control Console →
            </button>
            <a href="#playground" className="btn-saas-outline">
              ⚡ Try Interactive Scan
            </a>
          </div>

          {/* Minimalist SaaS Terminal & Topology Visualizer Widget */}
          <div className="saas-terminal-box" style={{ maxWidth: '980px', margin: '4rem auto 0' }}>
            <div className="saas-tab-header">
              <div style={{ display: 'flex', gap: '0.25rem' }}>
                <button 
                  className={`saas-tab-item ${landingTab === 'terminal' ? 'active' : ''}`}
                  onClick={() => setLandingTab('terminal')}
                >
                  <span>📺</span> Tokio Agent Log
                </button>
                <button 
                  className={`saas-tab-item ${landingTab === 'graph' ? 'active' : ''}`}
                  onClick={() => setLandingTab('graph')}
                >
                  <span>🕸️</span> Attack Topology
                </button>
                <button 
                  className={`saas-tab-item ${landingTab === 'diff' ? 'active' : ''}`}
                  onClick={() => setLandingTab('diff')}
                >
                  <span>📝</span> Remediation Patch
                </button>
              </div>

              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: '#a1a1aa' }}>
                SANDBOX: DOCKER_NODE_RUST
              </span>
            </div>

            {/* Tab 1: Terminal Log */}
            {landingTab === 'terminal' && (
              <div style={{ padding: '1.5rem', fontFamily: 'var(--font-mono)', fontSize: '0.82rem', lineHeight: '1.7', color: '#e4e4e7', minHeight: '250px' }}>
                <div><span style={{ color: '#38bdf8' }}>[10:45:02]</span> Initializing Rust Axum Agentic Engine v2.4 (Tokio Async Worker)...</div>
                <div><span style={{ color: '#38bdf8' }}>[10:45:03]</span> Mounting Sandboxed Docker Scanner Container (Node 20 / Python 3.12)...</div>
                <div><span style={{ color: '#fbbf24' }}>[10:45:04]</span> Ingesting Git repository AST & constructing dependency graph...</div>
                <div><span style={{ color: '#f43f5e' }}>[10:45:06]</span> CVE-2026-798 Detected: Hardcoded JWT signing secret fallback in <code style={{ color: '#a5b4fc' }}>backend/src/config.rs:42</code></div>
                <div><span style={{ color: '#4ade80' }}>[10:45:08]</span> Gemini Security LLM generated automated remediation patch snippet.</div>
                <div><span style={{ color: '#71717a' }}>[10:45:09]</span> Persisted multi-node attack graph to Neon PostgreSQL schema <code style={{ color: '#c084fc' }}>attack_graph_nodes</code></div>
              </div>
            )}

            {/* Tab 2: Attack Topology Map */}
            {landingTab === 'graph' && (
              <div style={{ padding: '2.5rem 1.5rem', display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '250px', background: '#040405' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem', width: '100%', maxWidth: '640px', justifyContent: 'space-between' }}>
                  <div style={{ background: '#09090b', border: '1px solid rgba(255,255,255,0.1)', padding: '1rem 1.25rem', borderRadius: '10px', textAlign: 'center', flex: 1 }}>
                    <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#38bdf8' }}>ENTRYPOINT</div>
                    <div style={{ fontSize: '0.85rem', color: '#ffffff', fontWeight: 600, marginTop: '0.2rem' }}>Web API Route</div>
                  </div>
                  <div style={{ width: '40px', height: '1px', background: 'rgba(255,255,255,0.2)' }}></div>
                  <div style={{ background: 'rgba(244, 63, 94, 0.1)', border: '1px solid rgba(244, 63, 94, 0.3)', padding: '1rem 1.25rem', borderRadius: '10px', textAlign: 'center', flex: 1 }}>
                    <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#f43f5e' }}>VULNERABILITY</div>
                    <div style={{ fontSize: '0.85rem', color: '#fca5a5', fontWeight: 600, marginTop: '0.2rem' }}>CVE-2026-798</div>
                  </div>
                  <div style={{ width: '40px', height: '1px', background: 'rgba(255,255,255,0.2)' }}></div>
                  <div style={{ background: '#09090b', border: '1px solid rgba(255,255,255,0.1)', padding: '1rem 1.25rem', borderRadius: '10px', textAlign: 'center', flex: 1 }}>
                    <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#c084fc' }}>DATABASE</div>
                    <div style={{ fontSize: '0.85rem', color: '#ffffff', fontWeight: 600, marginTop: '0.2rem' }}>PostgreSQL Cluster</div>
                  </div>
                </div>
              </div>
            )}

            {/* Tab 3: Code Remediation Diff */}
            {landingTab === 'diff' && (
              <div style={{ padding: '1.5rem', fontFamily: 'var(--font-mono)', fontSize: '0.82rem', lineHeight: '1.6', background: '#040405', minHeight: '250px' }}>
                <div style={{ color: '#71717a', marginBottom: '0.75rem' }}>// Automated Patch Generated by Gemini Agent for backend/src/config.rs</div>
                <div style={{ background: 'rgba(244, 63, 94, 0.12)', color: '#fca5a5', padding: '0.2rem 0.6rem', borderRadius: '4px', marginBottom: '0.25rem' }}>
                  - let jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| "default_insecure_secret".to_string());
                </div>
                <div style={{ background: 'rgba(74, 222, 128, 0.12)', color: '#86efac', padding: '0.2rem 0.6rem', borderRadius: '4px' }}>
                  + let jwt_secret = env::var("JWT_SECRET").map_err(|_| ConfigError::MissingSecret("JWT_SECRET must be set"))?;
                </div>
                <div style={{ color: '#4ade80', marginTop: '1rem', fontSize: '0.78rem', fontWeight: 500 }}>
                  ✓ Verified against Rust compiler and sandboxed unit test suite.
                </div>
              </div>
            )}
          </div>
        </section>

        {/* Minimal Interactive Scan Playground Widget */}
        <section id="playground" style={{ padding: '3rem 1.5rem 5rem' }}>
          <div className="saas-playground-box">
            <div style={{ fontSize: '0.75rem', fontWeight: 600, fontFamily: 'var(--font-mono)', color: '#f97316', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '0.5rem' }}>
              ✦ Interactive Security Playground
            </div>
            <h2 style={{ fontSize: '1.75rem', fontWeight: 700, color: '#ffffff', letterSpacing: '-0.02em', marginBottom: '0.5rem' }}>
              Test Fire Crow Agent Instantly
            </h2>
            <p style={{ color: '#a1a1aa', fontSize: '0.92rem', marginBottom: '1.75rem' }}>
              Select a repository preset or enter your Git URL to trigger an instant agentic vulnerability scan simulation.
            </p>

            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '1.25rem' }}>
              <span className="quick-chip" onClick={() => handleRunSimulatedScan('https://github.com/expressjs/express.git')}>
                expressjs/express
              </span>
              <span className="quick-chip" onClick={() => handleRunSimulatedScan('https://github.com/tokio-rs/axum.git')}>
                tokio-rs/axum
              </span>
              <span className="quick-chip" onClick={() => handleRunSimulatedScan('https://github.com/tiangolo/fastapi.git')}>
                tiangolo/fastapi
              </span>
            </div>

            <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
              <input
                type="text"
                value={simRepo}
                onChange={(e) => setSimRepo(e.target.value)}
                placeholder="https://github.com/your-org/your-repo.git"
                className="input"
                style={{ flex: 1, minWidth: '280px', background: '#000000', borderColor: 'rgba(255, 255, 255, 0.15)', color: '#ffffff' }}
              />
              <button 
                onClick={() => handleRunSimulatedScan()} 
                disabled={isSimulating}
                className="btn-saas-solid"
                style={{ padding: '0.75rem 1.5rem', whiteSpace: 'nowrap' }}
              >
                {isSimulating ? 'Scanning...' : 'Run Scan 🚀'}
              </button>
            </div>

            {isSimulating && (
              <div style={{ marginTop: '1.5rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', color: '#a1a1aa', fontFamily: 'var(--font-mono)' }}>
                  <span>{simStage}</span>
                  <span>{simProgress}%</span>
                </div>
                <div className="progress-bar-wrap">
                  <div className="progress-bar-fill" style={{ width: `${simProgress}%`, background: '#ffffff', boxShadow: 'none' }}></div>
                </div>
              </div>
            )}

            {simComplete && (
              <div style={{ marginTop: '1.5rem', background: 'rgba(255, 255, 255, 0.03)', border: '1px solid rgba(255, 255, 255, 0.12)', borderRadius: '10px', padding: '1.25rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
                <div>
                  <div style={{ fontSize: '0.9rem', fontWeight: 600, color: '#ffffff' }}>
                    🎉 Agent Scan Simulation Complete
                  </div>
                  <div style={{ fontSize: '0.8rem', color: '#a1a1aa', marginTop: '0.25rem' }}>
                    {simStage}
                  </div>
                </div>
                <button onClick={() => setView('login')} className="btn-saas-solid" style={{ padding: '0.45rem 1rem', fontSize: '0.8rem' }}>
                  View Full Console Report →
                </button>
              </div>
            )}
          </div>
        </section>

        {/* Minimal Platform Capabilities Grid */}
        <section id="features" style={{ maxWidth: '1150px', margin: '0 auto 6rem', padding: '0 1.5rem', width: '100%' }}>
          <div style={{ textAlign: 'center', marginBottom: '4rem' }}>
            <h2 style={{ fontSize: '2.25rem', fontWeight: 700, letterSpacing: '-0.03em', color: '#ffffff', marginBottom: '0.5rem' }}>
              Enterprise Platform Capabilities
            </h2>
            <p style={{ color: '#a1a1aa', fontSize: '1rem', maxWidth: '580px', margin: '0 auto' }}>
              Engineered for modern software teams requiring zero false positives and high-throughput security.
            </p>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.25rem' }}>
            <div className="saas-card-minimal">
              <div className="saas-icon-badge">🤖</div>
              <h3>Gemini Agentic Reasoning</h3>
              <p>Autonomous LLM loops plan, discover, and synthesize code patches for complex security vulnerabilities.</p>
            </div>

            <div className="saas-card-minimal">
              <div className="saas-icon-badge">🕸️</div>
              <h3>Attack Topology Mapping</h3>
              <p>PostgreSQL attack vector graph engine modeling entrypoints, exploit nodes, and lateral movement paths.</p>
            </div>

            <div className="saas-card-minimal">
              <div className="saas-icon-badge">🐳</div>
              <h3>Docker Sandbox Isolation</h3>
              <p>Executes code analyzers inside isolated Docker containers to guarantee zero host environment escape.</p>
            </div>

            <div className="saas-card-minimal">
              <div className="saas-icon-badge">🔑</div>
              <h3>Just-In-Time PAM & IAM</h3>
              <p>Just-in-time privilege elevation, ticket tracking, service accounts, and GitHub/Google OAuth2 security.</p>
            </div>

            <div className="saas-card-minimal">
              <div className="saas-icon-badge">⚡</div>
              <h3>High-Throughput Rust Engine</h3>
              <p>Built natively in Rust using Axum 0.7, Tokio async workers, and SQLx for high-throughput scanning.</p>
            </div>

            <div className="saas-card-minimal">
              <div className="saas-icon-badge">📄</div>
              <h3>Compliance PDF Generation</h3>
              <p>Automatically compiles audit findings, CVE mappings, and code fix instructions into structured PDF artifacts.</p>
            </div>
          </div>
        </section>

        {/* 4-Step Architecture Workflow & Minimal Footer */}
        <section id="architecture" style={{ background: 'rgba(255, 255, 255, 0.01)', borderTop: '1px solid rgba(255, 255, 255, 0.07)', borderBottom: '1px solid rgba(255, 255, 255, 0.07)', padding: '5.5rem 1.5rem' }}>
          <div style={{ maxWidth: '1150px', margin: '0 auto' }}>
            <div style={{ textAlign: 'center', marginBottom: '4rem' }}>
              <h2 style={{ fontSize: '2.25rem', fontWeight: 700, letterSpacing: '-0.03em', color: '#ffffff', marginBottom: '0.5rem' }}>
                End-to-End Autonomous Pipeline
              </h2>
              <p style={{ color: '#a1a1aa', fontSize: '1rem' }}>
                From source code ingestion to automated patch verification.
              </p>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1.25rem' }}>
              <div className="saas-card-minimal">
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', fontWeight: 600, color: '#38bdf8', marginBottom: '0.5rem' }}>STEP 01</div>
                <h3>Repository Ingestion</h3>
                <p>Parses AST structure, dependencies, and configuration files via secure Git clones.</p>
              </div>

              <div className="saas-card-minimal">
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', fontWeight: 600, color: '#c084fc', marginBottom: '0.5rem' }}>STEP 02</div>
                <h3>Agentic Reasoning</h3>
                <p>Security LLM reasoning loops discover architectural vulnerabilities and map attack graphs.</p>
              </div>

              <div className="saas-card-minimal">
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', fontWeight: 600, color: '#fbbf24', marginBottom: '0.5rem' }}>STEP 03</div>
                <h3>Sandboxed Testing</h3>
                <p>Simulates exploit paths inside isolated Docker containers to confirm zero false positives.</p>
              </div>

              <div className="saas-card-minimal">
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', fontWeight: 600, color: '#4ade80', marginBottom: '0.5rem' }}>STEP 04</div>
                <h3>Patch & Delivery</h3>
                <p>Generates ready-to-merge remediation pull requests and compliance-ready PDF artifacts.</p>
              </div>
            </div>
          </div>
        </section>

        {/* Minimal Site Footer */}
        <footer style={{ background: '#040405', borderTop: '1px solid rgba(255, 255, 255, 0.07)', padding: '4rem 1.5rem 2rem' }}>
          <div style={{ maxWidth: '1150px', margin: '0 auto', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '2.5rem' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                <img src="/fire-crow-logo.png" alt="Fire Crow Logo" style={{ width: '24px', height: '24px' }} />
                <span style={{ fontWeight: 700, color: '#ffffff' }}>Fire Crow</span>
              </div>
              <p style={{ fontSize: '0.82rem', color: '#71717a', lineHeight: 1.6 }}>
                Autonomous agentic security intelligence and vulnerability hardening platform built natively in Rust.
              </p>
            </div>

            <div>
              <div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#ffffff', marginBottom: '1rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Platform</div>
              <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.6rem', fontSize: '0.82rem' }}>
                <li><a href="#playground" style={{ color: '#71717a', textDecoration: 'none' }}>Live Playground</a></li>
                <li><a href="#features" style={{ color: '#71717a', textDecoration: 'none' }}>Capabilities</a></li>
                <li><a href="#architecture" style={{ color: '#71717a', textDecoration: 'none' }}>Architecture</a></li>
              </ul>
            </div>

            <div>
              <div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#ffffff', marginBottom: '1rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Developers</div>
              <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.6rem', fontSize: '0.82rem' }}>
                <li><a href="https://github.com/johan-droid/Fire-Crow-" target="_blank" rel="noreferrer" style={{ color: '#71717a', textDecoration: 'none' }}>GitHub Repository</a></li>
                <li><a href="#architecture" style={{ color: '#71717a', textDecoration: 'none' }}>Rust Engine Specs</a></li>
              </ul>
            </div>

            <div>
              <div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#ffffff', marginBottom: '1rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Security</div>
              <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.6rem', fontSize: '0.82rem', color: '#71717a' }}>
                <li>SOC2 Type II Ready</li>
                <li>ISO 27001 Mapping</li>
                <li>Docker Isolated</li>
              </ul>
            </div>
          </div>

          <div style={{ maxWidth: '1150px', margin: '3rem auto 0', paddingTop: '1.5rem', borderTop: '1px solid rgba(255, 255, 255, 0.05)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.78rem', color: '#71717a', flexWrap: 'wrap', gap: '1rem' }}>
            <div>© {new Date().getFullYear()} Fire Crow Intelligence Inc. All rights reserved.</div>
            <div style={{ display: 'flex', gap: '1.5rem' }}>
              <span>Privacy</span>
              <span>Terms</span>
              <span>Status: <strong style={{ color: '#4ade80' }}>Operational</strong></span>
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
                    {/* Progress Bar String */}
                    <div style={{
                      backgroundColor: 'rgba(255, 255, 255, 0.03)',
                      border: '1px solid rgba(255, 255, 255, 0.05)',
                      borderRadius: '4px',
                      padding: '0.65rem 0.75rem',
                      fontFamily: 'var(--font-mono)',
                      fontSize: '0.78rem',
                      color: '#00ff00',
                      whiteSpace: 'pre-wrap',
                      letterSpacing: '0.05em'
                    }}>
                      {(() => {
                        const selectedJob = jobs.find(j => j.id === (activeMonitorJobId || (jobs.length > 0 ? jobs[0].id : ''))) || (jobs.length > 0 ? jobs[0] : null);
                        let progressString = 'Status: Idle | [                    ] 0%';
                        if (selectedJob) {
                          if (selectedJob.status === 'completed') {
                            progressString = `Status: Completed | [====================] 100%`;
                          } else if (selectedJob.status === 'cancelled') {
                            progressString = `Status: Cancelled | [xxxxxxxxxxxxxxxxxxxx] 0%`;
                          } else if (selectedJob.status === 'failed') {
                            progressString = `Status: Failed | [xxxxxxxxxxxxxxxxxxxx] 0%`;
                          } else if (selectedJob.status === 'queued') {
                            progressString = `Status: Queued | [                    ] 0%`;
                          } else {
                            const phaseOrder = ['intake', 'recon', 'scanning', 'ai_analysis', 'remediation', 'attack_graph', 'scoring', 'reporting'];
                            const completedPhasesCount = monitorPhases.filter(p => p.status === 'completed').length;
                            const percentage = Math.round((completedPhasesCount / phaseOrder.length) * 100);
                            const barLength = 20;
                            const filledLength = Math.round((completedPhasesCount / phaseOrder.length) * barLength);
                            const bar = '='.repeat(filledLength) + ' '.repeat(barLength - filledLength);
                            progressString = `Status: Running (${selectedJob.status}) | [${bar}] ${percentage}%`;
                          }
                        }
                        return progressString;
                      })()}
                    </div>

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
                          <div className="list-item-sub">Token: {d.verification_token}</div>
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
                {modalError && <div className="error-box" style={{ marginBottom: '1rem' }}>{modalError}</div>}
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
