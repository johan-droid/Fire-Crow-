import { useState, useEffect } from 'react';

const API_BASE = window.location.origin.includes('localhost') || window.location.origin.includes('127.0.0.1')
  ? 'http://localhost:8000/api/v1'
  : '/api/v1';

interface UserProfile {
  user_id: string;
  username: string;
  email: string | null;
}

function App() {
  const [view, setView] = useState<'landing' | 'login' | 'dashboard'>('landing');
  const [user, setUser] = useState<UserProfile | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');

  // 1. Check if user is already signed in or completing an OAuth exchange on mount
  useEffect(() => {
    const checkSession = async () => {
      try {
        const res = await fetch(`${API_BASE}/auth/me`, { credentials: 'include' });
        if (res.ok) {
          const data = await res.json();
          setUser({
            user_id: data.user_id,
            username: data.username,
            email: data.email,
          });
          setView('dashboard');
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
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ code }),
        });

        if (!exchangeRes.ok) {
          throw new Error('Failed to exchange authorization code.');
        }

        // Successfully exchanged, check session to get user details
        const meRes = await fetch(`${API_BASE}/auth/me`, { credentials: 'include' });
        if (meRes.ok) {
          const data = await meRes.json();
          setUser({
            user_id: data.user_id,
            username: data.username,
            email: data.email,
          });
          setView('dashboard');
        }
      } catch (err: any) {
        setError(err.message || 'Authentication failed. Please try again.');
        setView('login');
      } finally {
        // Clear code query parameter from URL
        window.history.replaceState({}, document.title, window.location.pathname);
        setIsLoading(false);
      }
    };

    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');

    if (code) {
      handleOAuthCallback(code);
    } else {
      checkSession();
    }
  }, []);

  const handleGitHubLogin = () => {
    // Redirect user to the backend GitHub OAuth endpoint
    const privacyVersion = '2026-06-06';
    window.location.href = `${API_BASE}/auth/github?privacy_policy_accepted=true&privacy_policy_version=${privacyVersion}`;
  };

  const handleLogout = async () => {
    setIsLoading(true);
    try {
      await fetch(`${API_BASE}/auth/logout`, {
        method: 'POST',
        credentials: 'include',
      });
    } catch (err) {
      console.error('Logout error:', err);
    } finally {
      setUser(null);
      setView('landing');
      setIsLoading(false);
    }
  };

  if (isLoading) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', backgroundColor: '#000000', color: '#ffffff', fontFamily: 'var(--font-sans)' }}>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1rem' }}>
          <div style={{ width: '24px', height: '24px', borderRadius: '50%', border: '2px solid #222', borderTopColor: '#fff', animation: 'spin 0.8s linear infinite' }}></div>
          <span style={{ fontSize: '0.85rem', color: '#888888', letterSpacing: '0.05em' }}>VERIFYING SESSION...</span>
        </div>
      </div>
    );
  }

  return (
    <>
      {/* Header / Navigation */}
      <header>
        <div className="nav-container">
          <a href="#" onClick={(e) => { e.preventDefault(); if (view !== 'dashboard') setView('landing'); }} className="logo">
            <span>Fire Crow</span>
          </a>
          
          <nav className="nav-links">
            {view === 'landing' && <a href="#features">Features</a>}
            {view === 'dashboard' && <span style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Active Node: <strong>{user?.username}</strong></span>}
          </nav>

          <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
            {view === 'landing' && (
              <button onClick={() => setView('login')} className="btn btn-primary" style={{ padding: '0.45rem 1.25rem', fontSize: '0.85rem', borderRadius: '4px' }}>
                Sign In
              </button>
            )}
            {view === 'login' && (
              <button onClick={() => setView('landing')} className="btn btn-secondary" style={{ padding: '0.45rem 1.25rem', fontSize: '0.85rem', borderRadius: '4px' }}>
                Back to Home
              </button>
            )}
            {view === 'dashboard' && (
              <button onClick={handleLogout} className="btn btn-secondary" style={{ padding: '0.45rem 1.25rem', fontSize: '0.85rem', borderRadius: '4px' }}>
                Sign Out
              </button>
            )}
          </div>
        </div>
      </header>

      {view === 'landing' && (
        <>
          {/* Hero Section */}
          <section className="container hero">
            <div className="badge">
              <span className="badge-dot"></span>
              Secure Agentic Orchestration
            </div>
            <h1>
              Autonomously Hardening<br />
              Your Application Stack
            </h1>
            <p>
              Fire Crow coordinates sandboxed security LLM agents to map repositories, execute safe exploit simulations, and build compliance-ready PDF reports.
            </p>
            <div className="cta-group">
              <button onClick={() => setView('login')} className="btn btn-primary">
                Get Started
              </button>
              <a href="#features" className="btn btn-secondary">
                Explore Features
              </a>
            </div>
          </section>

          {/* Feature Section */}
          <section id="features" className="container" style={{ marginBottom: '8rem' }}>
            <div className="features-title">
              <h2>Platform Capabilities</h2>
              <p>Minimal, secure, and developer-focused security automation.</p>
            </div>
            
            <div className="features-grid">
              <div className="feature-card">
                <div className="feature-icon">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <rect x="2" y="2" width="20" height="8" rx="2" ry="2"/>
                    <rect x="2" y="14" width="20" height="8" rx="2" ry="2"/>
                    <line x1="6" y1="6" x2="6.01" y2="6"/>
                    <line x1="6" y1="18" x2="6.01" y2="18"/>
                  </svg>
                </div>
                <h3>Agentic Auditing</h3>
                <p>
                  Runs autonomous LLM security loops to plan and identify security vulnerabilities in source code.
                </p>
              </div>

              <div className="feature-card">
                <div className="feature-icon">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                  </svg>
                </div>
                <h3>Container Isolation</h3>
                <p>
                  Executes code analyzers and scanners inside sandboxed Docker containers to isolate execution.
                </p>
              </div>

              <div className="feature-card">
                <div className="feature-icon">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                    <polyline points="14 2 14 8 20 8"/>
                    <line x1="16" y1="13" x2="8" y2="13"/>
                    <line x1="16" y1="17" x2="8" y2="17"/>
                  </svg>
                </div>
                <h3>PDF Vulnerability Reports</h3>
                <p>
                  Compiles raw audit findings, CVE mappings, and remediation instruction codes into structured PDF reports.
                </p>
              </div>
            </div>
          </section>
        </>
      )}

      {view === 'login' && (
        /* Sleek GitHub Only Login Screen */
        <section className="container" style={{ minHeight: 'calc(100vh - 200px)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '4rem 0' }}>
          <div style={{ width: '100%', maxWidth: '380px', padding: '2.5rem 2rem', borderRadius: '8px', border: '1px solid var(--border-color)', backgroundColor: 'var(--bg-secondary)', textAlign: 'center' }}>
            <h2 style={{ fontSize: '1.75rem', fontWeight: '700', letterSpacing: '-0.03em', marginBottom: '0.5rem' }}>
              Sign in to Fire Crow
            </h2>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '2rem' }}>
              Access your security orchestration dashboard.
            </p>

            {error && (
              <div style={{ color: '#ef4444', backgroundColor: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.2)', padding: '0.75rem', borderRadius: '4px', fontSize: '0.85rem', marginBottom: '1.5rem', textAlign: 'left' }}>
                {error}
              </div>
            )}

            <button 
              onClick={handleGitHubLogin} 
              className="btn btn-primary" 
              style={{ 
                width: '100%', 
                display: 'flex', 
                alignItems: 'center', 
                justifyContent: 'center', 
                gap: '0.75rem',
                padding: '0.75rem',
                fontSize: '0.9rem',
                fontWeight: '600',
                borderRadius: '4px'
              }}
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
                <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.166 6.839 9.489.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.603-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.579.688.481C19.137 20.162 22 16.418 22 12c0-5.523-4.477-10-10-10z" />
              </svg>
              Sign in with GitHub
            </button>

            <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '2rem' }}>
              By signing in, you agree to our Terms of Service and Privacy Policy.
            </p>
          </div>
        </section>
      )}

      {view === 'dashboard' && (
        /* Sleek Dashboard Panel for Logged in Users */
        <section className="container" style={{ minHeight: 'calc(100vh - 200px)', padding: '5rem 0' }}>
          <div style={{ border: '1px solid var(--border-color)', borderRadius: '8px', padding: '3rem', backgroundColor: 'var(--bg-secondary)' }}>
            <h2 style={{ fontSize: '2rem', fontWeight: '700', letterSpacing: '-0.04em', marginBottom: '1rem' }}>
              Welcome back, {user?.username}
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.95rem', marginBottom: '2.5rem', maxWidth: '600px' }}>
              Your session is active. You have been automatically signed in using your GitHub account.
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '2rem', marginTop: '3rem' }}>
              <div style={{ border: '1px solid var(--border-color)', borderRadius: '6px', padding: '1.5rem', backgroundColor: 'var(--bg-primary)' }}>
                <h4 style={{ margin: '0 0 0.5rem 0', fontWeight: '600' }}>Active Node</h4>
                <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Connected as {user?.email || 'Public Profile'}</p>
              </div>
              <div style={{ border: '1px solid var(--border-color)', borderRadius: '6px', padding: '1.5rem', backgroundColor: 'var(--bg-primary)' }}>
                <h4 style={{ margin: '0 0 0.5rem 0', fontWeight: '600' }}>Auth Persistence</h4>
                <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Active session keys successfully saved in the database.</p>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* Footer */}
      <footer>
        <div className="container footer-content">
          <a href="#" onClick={(e) => { e.preventDefault(); if (view !== 'dashboard') setView('landing'); }} className="logo" style={{ fontSize: '1rem' }}>
            <span>Fire Crow</span>
          </a>
          <div className="footer-links">
            <a href="#">Privacy Policy</a>
            <a href="#">Terms of Service</a>
            <a href="https://github.com/johan-droid/Fire-Crow-" target="_blank" rel="noreferrer">GitHub Project</a>
          </div>
          <div className="footer-text">
            &copy; {new Date().getFullYear()} Fire Crow. All rights reserved.
          </div>
        </div>
      </footer>
    </>
  );
}

export default App;
