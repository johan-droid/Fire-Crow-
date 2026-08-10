import { useState, useEffect, useCallback } from 'react';

const API_BASE = window.location.origin.includes('localhost') || window.location.origin.includes('127.0.0.1')
  ? 'http://localhost:8000/api/v1'
  : '/api/v1';

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

  // Auto purge token on 401 Unauthorized
  if (res.status === 401 && endpoint !== '/auth/me' && endpoint !== '/auth/login') {
    localStorage.removeItem('access_token');
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
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [ssoProviders, setSsoProviders] = useState<SsoProvider[]>([]);
  const [pamRequests, setPamRequests] = useState<PamRequest[]>([]);
  const [pamGrants, setPamGrants] = useState<PamGrant[]>([]);
  const [iamPolicies, setIamPolicies] = useState<IamPolicy[]>([]);
  const [domains, setDomains] = useState<DomainVerification[]>([]);
  const [activities, setActivities] = useState<ActivityEvent[]>([]);
  const [mfaStatus, setMfaStatus] = useState<MfaStatus>({ enabled: false, backup_codes_remaining: 0 });

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
        }
      } catch (err) {
        console.warn('No active session found:', err);
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
            fetchDashboardData();
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
      setError(`GitHub login failed: ${decodeURIComponent(oauthError)}`);
      setView('login');
      window.history.replaceState({}, document.title, window.location.pathname);
      setIsLoading(false);
    } else if (code) {
      handleOAuthCallback(code);
    } else {
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
      <div style={{ background: 'var(--bg-primary)', color: 'var(--text-primary)', minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
        {/* Landing Top Navigation Bar */}
        <header className="landing-nav">
          <div className="landing-nav-container">
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <img src="/fire-crow-logo.png" alt="Fire Crow Logo" className="logo-img" />
              <span style={{ fontSize: '1.05rem', fontWeight: 800, letterSpacing: '-0.03em', color: '#fff' }}>Fire Crow</span>
              <span className="badge badge-info" style={{ fontSize: '0.65rem' }}>v2.4 LIVE</span>
            </div>

            <nav className="landing-nav-links">
              <a href="#features">Capabilities</a>
              <a href="#architecture">Architecture</a>
              <a href="#metrics">Telemetry</a>
              <a href="https://github.com/johan-droid/Fire-Crow-" target="_blank" rel="noreferrer">GitHub</a>
            </nav>

            <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
              <button onClick={() => setView('login')} className="btn btn-primary btn-sm">
                Sign In / Console
              </button>
            </div>
          </div>
        </header>

        {/* Hero Section */}
        <section style={{ padding: '5rem 1.5rem 4rem', textAlign: 'center', maxWidth: '1000px', margin: '0 auto' }}>
          <div style={{ marginBottom: '1.5rem', display: 'flex', justifyContent: 'center' }}>
            <img src="/fire-crow-logo.png" alt="Fire Crow Flying Logo" className="logo-img-lg" />
          </div>

          <div className="landing-pill">
            <span>🔥</span> AUTONOMOUS AGENTIC RED TEAM ENGINE
          </div>

          <h1 className="landing-h1">
            Autonomously Hardening<br />Your Application Stack
          </h1>

          <p className="landing-sub">
            Fire Crow coordinates sandboxed security LLM agents to map repositories, execute safe exploit simulations, enforce enterprise access controls, and build compliance-ready reports.
          </p>

          <div className="landing-cta">
            <button onClick={() => setView('login')} className="btn btn-primary" style={{ padding: '0.75rem 2rem', fontSize: '0.9rem' }}>
              Launch Control Console →
            </button>
            <a href="#features" className="btn btn-secondary" style={{ padding: '0.75rem 1.75rem', fontSize: '0.9rem' }}>
              Explore Architecture
            </a>
          </div>

          {/* Interactive Terminal Simulation Widget */}
          <div className="terminal-window">
            <div className="terminal-header">
              <div className="terminal-dots">
                <span className="terminal-dot" style={{ background: '#ef4444' }}></span>
                <span className="terminal-dot" style={{ background: '#f59e0b' }}></span>
                <span className="terminal-dot" style={{ background: '#22c55e' }}></span>
              </div>
              <span className="terminal-title">firecrow-orchestrator — tokio-async-worker</span>
              <span className="badge badge-success" style={{ fontSize: '0.65rem' }}>SANDBOX ACTIVE</span>
            </div>

            <div className="terminal-body">
              <div><span className="terminal-cyan">[10:45:02 INFO]</span> Initializing Rust Axum Agentic Engine v2.4...</div>
              <div><span className="terminal-cyan">[10:45:03 INFO]</span> Mounting Sandboxed Docker Scanner Container (Node 20 / Python 3.12)...</div>
              <div><span className="terminal-yellow">[10:45:04 WARN]</span> Ingesting Git repository AST & constructing dependency graph...</div>
              <div><span className="terminal-red">[10:45:06 ALERT]</span> CVE-2026-798 Detected: Hardcoded JWT signing secret fallback in <code style={{ color: '#60a5fa' }}>backend/src/config.rs:42</code></div>
              <div><span className="terminal-green">[10:45:08 SUCCESS]</span> Gemini Security LLM generated automated remediation patch snippet.</div>
              <div><span className="terminal-muted">[10:45:09 LOG]</span> Persisted multi-node attack graph to Neon PostgreSQL schema <code style={{ color: '#a855f7' }}>attack_graph_nodes</code></div>
            </div>
          </div>
        </section>

        {/* Platform Metrics Banner */}
        <section id="metrics" style={{ background: 'rgba(11, 13, 18, 0.6)', borderTop: '1px solid var(--border)', borderBottom: '1px solid var(--border)', padding: '3rem 1.5rem', margin: '2rem 0 4rem' }}>
          <div style={{ maxWidth: '1100px', margin: '0 auto' }} className="metrics-grid">
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '2.25rem', fontWeight: 800, color: '#fff', letterSpacing: '-0.03em' }}>100%</div>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginTop: '0.25rem' }}>Docker Isolation</div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '2.25rem', fontWeight: 800, color: '#60a5fa', letterSpacing: '-0.03em' }}>&lt; 30s</div>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginTop: '0.25rem' }}>Agent Reasoning</div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '2.25rem', fontWeight: 800, color: '#22c55e', letterSpacing: '-0.03em' }}>99.9%</div>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginTop: '0.25rem' }}>Audit Accuracy</div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '2.25rem', fontWeight: 800, color: '#a855f7', letterSpacing: '-0.03em' }}>Zero</div>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginTop: '0.25rem' }}>False Positive Overhead</div>
            </div>
          </div>
        </section>

        {/* Feature Capabilities Grid */}
        <section id="features" style={{ maxWidth: '1100px', margin: '0 auto 6rem', padding: '0 1.5rem' }}>
          <div style={{ textAlign: 'center', marginBottom: '3rem' }}>
            <h2 style={{ fontSize: '2.25rem', fontWeight: 800, letterSpacing: '-0.03em', marginBottom: '0.5rem' }}>
              Platform Capabilities
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.95rem' }}>
              Minimalist, high-performance security automation built for modern software teams.
            </p>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.25rem' }}>
            <div className="feature-card">
              <div className="feature-icon-wrap">🤖</div>
              <h3>Agentic Auditing</h3>
              <p>Autonomous Google Gemini LLM reasoning loops to plan, identify, and repair zero-day code vulnerabilities.</p>
            </div>

            <div className="feature-card">
              <div className="feature-icon-wrap">🛡️</div>
              <h3>Attack Graph Generation</h3>
              <p>Native PostgreSQL attack vector mapping that models entry points, exploits, and lateral movement paths.</p>
            </div>

            <div className="feature-card">
              <div className="feature-icon-wrap">🔒</div>
              <h3>Container Isolation</h3>
              <p>Executes code analyzers and scanners inside sandboxed Docker containers to prevent environment escape.</p>
            </div>

            <div className="feature-card">
              <div className="feature-icon-wrap">🔑</div>
              <h3>Enterprise IAM & PAM</h3>
              <p>Just-in-time privilege elevation, ticket tracking, service accounts, and GitHub/Google OAuth2 session security.</p>
            </div>

            <div className="feature-card">
              <div className="feature-icon-wrap">⚡</div>
              <h3>High-Throughput Engine</h3>
              <p>Built natively in Rust using Axum 0.7, Tokio async workers, and SQLx for lightning-fast security execution.</p>
            </div>

            <div className="feature-card">
              <div className="feature-icon-wrap">📄</div>
              <h3>Compliance PDF Reports</h3>
              <p>Automatically compiles audit findings, CVE mappings, and code fix instructions into structured PDF artifacts.</p>
            </div>
          </div>
        </section>

        {/* Architecture & Workflow Deep Dive */}
        <section id="architecture" style={{ background: 'rgba(11, 13, 18, 0.4)', borderTop: '1px solid var(--border)', borderBottom: '1px solid var(--border)', padding: '5rem 1.5rem' }}>
          <div style={{ maxWidth: '1100px', margin: '0 auto' }}>
            <div style={{ textAlign: 'center', marginBottom: '3.5rem' }}>
              <h2 style={{ fontSize: '2.25rem', fontWeight: 800, letterSpacing: '-0.03em', marginBottom: '0.5rem' }}>
                How Fire Crow Works
              </h2>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.95rem' }}>
                An end-to-end autonomous security pipeline from source repository ingestion to patch delivery.
              </p>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1.5rem' }}>
              <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '1.5rem' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--blue)', marginBottom: '0.5rem' }}>STEP 01</div>
                <h4 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.5rem' }}>Repository Ingestion</h4>
                <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  Parses source code AST, configuration files, and dependency manifests via secure Git clones.
                </p>
              </div>

              <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '1.5rem' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--purple)', marginBottom: '0.5rem' }}>STEP 02</div>
                <h4 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.5rem' }}>Agentic Reasoning</h4>
                <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  Security LLM reasoning loops discover architectural vulnerabilities and construct attack graphs.
                </p>
              </div>

              <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '1.5rem' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--yellow)', marginBottom: '0.5rem' }}>STEP 03</div>
                <h4 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.5rem' }}>Sandboxed Testing</h4>
                <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  Executes exploit simulations inside isolated Docker sandboxes to confirm vulnerability validity.
                </p>
              </div>

              <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '1.5rem' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--green)', marginBottom: '0.5rem' }}>STEP 04</div>
                <h4 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.5rem' }}>Patch & Report</h4>
                <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  Generates ready-to-merge remediation patches and exports compliance-ready PDF reports.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Multi-Column Site Footer */}
        <footer className="site-footer">
          <div className="footer-container">
            {/* Column 1: Brand */}
            <div className="footer-brand">
              <div className="footer-logo">
                <img src="/fire-crow-logo.png" alt="Fire Crow Flying Logo" className="logo-img" />
                <span>Fire Crow</span>
              </div>
              <p className="footer-desc">
                Autonomous agentic security intelligence and vulnerability hardening platform built natively in Rust.
              </p>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.5rem' }}>
                <div className="status-dot status-dot-live"></div>
                <span>HYBRID NODE STATUS: <strong>100% OPERATIONAL</strong></span>
              </div>
            </div>

            {/* Column 2: Product */}
            <div>
              <div className="footer-col-title">Product</div>
              <ul className="footer-links">
                <li><a href="#features">Autonomous Scans</a></li>
                <li><a href="#architecture">Attack Graph Mapping</a></li>
                <li><a href="#features">Container Isolation</a></li>
                <li><a href="#features">IAM & PAM Security</a></li>
                <li><a href="#metrics">Live Telemetry</a></li>
              </ul>
            </div>

            {/* Column 3: Developers */}
            <div>
              <div className="footer-col-title">Developers</div>
              <ul className="footer-links">
                <li><a href="https://github.com/johan-droid/Fire-Crow-" target="_blank" rel="noreferrer">GitHub Repository</a></li>
                <li><a href="file:///home/ashutoshsahoo/Downloads/Fire%20Crow/Fire-Crow-/API_DOCUMENTATION.md">API Documentation</a></li>
                <li><a href="file:///home/ashutoshsahoo/Downloads/Fire%20Crow/Fire-Crow-/GITHUB_AUTH.md">OAuth Setup Guide</a></li>
                <li><a href="#architecture">Rust Engine Specs</a></li>
              </ul>
            </div>

            {/* Column 4: Compliance & Legal */}
            <div>
              <div className="footer-col-title">Compliance & Legal</div>
              <ul className="footer-links">
                <li><a href="#">Privacy Policy</a></li>
                <li><a href="#">Terms of Service</a></li>
                <li><a href="#">Security Disclosures</a></li>
                <li><a href="#">GDPR Data Rights</a></li>
              </ul>
            </div>
          </div>

          <div className="footer-bottom">
            <div>&copy; {new Date().getFullYear()} Fire Crow Intelligence Inc. All rights reserved.</div>
            <div style={{ display: 'flex', gap: '1.5rem' }}>
              <a href="https://github.com/johan-droid/Fire-Crow-" target="_blank" rel="noreferrer" style={{ color: 'var(--text-muted)', textDecoration: 'none' }}>
                GitHub Source
              </a>
              <span style={{ color: 'var(--text-muted)' }}>•</span>
              <a href="#" style={{ color: 'var(--text-muted)', textDecoration: 'none' }}>System Health</a>
            </div>
          </div>
        </footer>
      </div>
    );
  }

  // Render Login View
  if (view === 'login') {
    return (
      <div className="page-center">
        <div className="login-card">
          <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '1.25rem' }}>
            <img src="/fire-crow-logo.png" alt="Fire Crow Flying Logo" className="logo-img" style={{ width: '48px', height: '48px', borderRadius: '12px' }} />
          </div>
          <h2>Sign in to Fire Crow</h2>
          <p>Access your security orchestration dashboard</p>

          {error && <div className="error-box">{error}</div>}

          <button onClick={handleGitHubLogin} className="gh-btn">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
              <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.166 6.839 9.489.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.603-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.579.688.481C19.137 20.162 22 16.418 22 12c0-5.523-4.477-10-10-10z" />
            </svg>
            Sign in with GitHub
          </button>

          <button onClick={() => setView('landing')} className="btn btn-ghost" style={{ marginTop: '1rem', width: '100%', fontSize: '0.8rem' }}>
            ← Back to home
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

                <div className="metric-card">
                  <div className="metric-label">User Balance</div>
                  <div className="metric-value">{user?.credit_balance ?? 10.0}</div>
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
                        <div key={j.id} onClick={() => handleViewJobDetail(j.id)} className="list-item">
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

                {/* Live Activity Feed */}
                <div className="panel">
                  <div className="panel-header">
                    <div className="panel-title">
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                      </svg>
                      Security Telemetry
                    </div>
                  </div>

                  <div className="panel-body" style={{ padding: '0.75rem' }}>
                    {activities.length === 0 ? (
                      <div className="panel-empty">
                        <p>No activity events logged in database.</p>
                      </div>
                    ) : (
                      activities.slice(0, 5).map(act => (
                        <div key={act.id} className="list-item" style={{ cursor: 'default' }}>
                          <div className="list-item-info">
                            <div className="list-item-title">{act.action}</div>
                            {act.details_json && <div className="list-item-sub">{act.details_json}</div>}
                          </div>
                          <span className="badge badge-neutral">{act.created_at.substring(11, 16)}</span>
                        </div>
                      ))
                    )}
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
    </div>
  );
}

export default App;
