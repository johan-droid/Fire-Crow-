import { AuroraBackdrop } from './scene';

/* ─── GitHub SVG icon ──────────────────────────────────────── */
const GitHubIcon = ({ size = 22 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor">
    <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.166 6.839 9.489.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.603-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.579.688.481C19.137 20.162 22 16.418 22 12c0-5.523-4.477-10-10-10z" />
  </svg>
);

/* ─── Types ─────────────────────────────────────────────────── */
interface LoginPageProps {
  onNavigateLanding: () => void;
  onGitHubLogin: () => void;
  onDemoLogin: () => void;
  loginMode: 'github' | 'demo';
  setLoginMode: (mode: 'github' | 'demo') => void;
  isSubmitting: boolean;
  error: string;
  authFormError: string;
  clearErrors: () => void;
}

/* ─── Login Page Component ─────────────────────────────────── */
export default function LoginPage({
  onNavigateLanding,
  onGitHubLogin,
  onDemoLogin,
  loginMode,
  setLoginMode,
  isSubmitting,
  error,
  authFormError,
  clearErrors,
}: LoginPageProps) {
  const hasError = error || authFormError;

  return (
    <div className="login-page">
      <AuroraBackdrop variant="login" />

      <div className="login-card">
        {/* Logo Pair: Fire Crow + GitHub */}
        <div className="login-header">
          <div className="login-logo-pair">
            <div className="login-logo-box">
              <img src="/fire-crow-logo.png" alt="Fire Crow" className="login-logo-img" />
            </div>
            <span className="login-logo-plus">+</span>
            <div className="login-logo-box login-logo-github">
              <GitHubIcon size={28} />
            </div>
          </div>
          <h2 className="login-title">Sign in &amp; Sync with GitHub</h2>
          <p className="login-subtitle">
            Connect your GitHub account to enable automated security auditing, repository scanning, and pull-request patch creation.
          </p>
        </div>

        {/* Mode Switcher Tabs */}
        <div className="login-mode-tabs">
          <button className={`login-mode-tab ${loginMode === 'github' ? 'active' : ''}`} onClick={() => setLoginMode('github')}>
            GitHub OAuth
          </button>
          <button className={`login-mode-tab ${loginMode === 'demo' ? 'active' : ''}`} onClick={() => setLoginMode('demo')}>
            Demo Access
          </button>
        </div>

        {loginMode === 'github' ? (
          <>
            {/* GitHub Sign In Button */}
            <button onClick={onGitHubLogin} className="login-github-btn">
              <GitHubIcon />
              Sync &amp; Sign in with GitHub
            </button>

            {/* Features List */}
            <div className="login-features-box">
              <div className="login-features-title">What syncing enables:</div>
              <ul className="login-features-list">
                <li>
                  <span className="login-feature-icon blue">⚡</span>
                  <span><strong>Auto-Discover Repos:</strong> Load public &amp; private repositories instantly into your security dashboard.</span>
                </li>
                <li>
                  <span className="login-feature-icon green">🛡️</span>
                  <span><strong>Sandboxed Audits:</strong> Run 0% false positive vulnerability scans against source code ASTs.</span>
                </li>
                <li>
                  <span className="login-feature-icon purple">🔄</span>
                  <span><strong>Automated PR Patches:</strong> Generate compiler-tested code remediations pushed to GitHub branches.</span>
                </li>
              </ul>
            </div>
          </>
        ) : (
          <div className="login-demo-section">
            <p className="login-demo-desc">
              Launch the security console instantly in demo mode to explore live repository audits, attack topology graphs, and SOC2 report exports without connecting GitHub OAuth.
            </p>
            <button onClick={onDemoLogin} disabled={isSubmitting} className="btn-apple-primary login-demo-btn" style={{ opacity: isSubmitting ? 0.6 : 1 }}>
              {isSubmitting ? 'Authenticating Session...' : 'Sign in as Demo Developer →'}
            </button>
          </div>
        )}

        {/* Error Display */}
        {hasError && (
          <div className="login-error">
            {authFormError || error}
          </div>
        )}

        {/* Connection Info */}
        <div className="login-connection-info">
          <div className="login-info-row">
            <span>Connection:</span>
            <span className="login-info-secure">SECURE (TLS 1.3)</span>
          </div>
          <div className="login-info-row">
            <span>Identity Scope:</span>
            <span>read:user, repo</span>
          </div>
          <div className="login-info-row">
            <span>Provider:</span>
            <span>github.com</span>
          </div>
        </div>

        <button onClick={() => { clearErrors(); onNavigateLanding(); }} className="login-back-btn">
          ← Back to landing page
        </button>
      </div>
    </div>
  );
}
