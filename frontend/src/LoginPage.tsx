import { useState, type FormEvent, useEffect, useRef } from 'react';
import {
  NextLabSymbol,
  FireCrowSymbol,
  BrandLockup,
} from './landing/components/BrandLogos';
import { Eye, EyeOff, AlertCircle, ArrowRight } from 'lucide-react';
import './landing/styles/landing.css';
import './auth.css';

/* ─── GitHub SVG Icon ────────────────────────────────────────── */
const GitHubIcon = ({ size = 20 }: { size?: number }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="currentColor"
    aria-hidden="true"
  >
    <path
      fillRule="evenodd"
      clipRule="evenodd"
      d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.166 6.839 9.489.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.603-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.579.688.481C19.137 20.162 22 16.418 22 12c0-5.523-4.477-10-10-10z"
    />
  </svg>
);

/* ─── Types ─────────────────────────────────────────────────── */
export interface LoginPageProps {
  onNavigateLanding: () => void;
  onGitHubLogin: () => void;
  onPasswordLogin?: (identifier: string, password: string) => Promise<void>;
  onRegister?: (username: string, email: string, password: string) => Promise<void>;
  error: string;
  authFormError: string;
  clearErrors: () => void;
  isSubmitting?: boolean;
}

/* ─── Login Page Component ─────────────────────────────────── */
export default function LoginPage({
  onNavigateLanding,
  onGitHubLogin,
  onPasswordLogin,
  onRegister,
  error,
  authFormError,
  clearErrors,
  isSubmitting: parentSubmitting = false,
}: LoginPageProps) {
  const [mode, setMode] = useState<'signin' | 'register'>('signin');
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [registerUsername, setRegisterUsername] = useState('');
  const [registerEmail, setRegisterEmail] = useState('');
  const [registerPassword, setRegisterPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [localSubmitting, setLocalSubmitting] = useState(false);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  const identifierInputRef = useRef<HTMLInputElement | null>(null);

  const isSubmitting = parentSubmitting || localSubmitting;
  const activeError = authFormError || error;

  // Clear errors when switching tabs
  const handleTabChange = (nextMode: 'signin' | 'register') => {
    if (nextMode === mode) return;
    clearErrors();
    setFieldErrors({});
    setMode(nextMode);
  };

  const handleCredentialSubmit = async (e: FormEvent) => {
    e.preventDefault();
    clearErrors();
    const errors: Record<string, string> = {};

    if (mode === 'signin') {
      const trimmedId = identifier.trim();
      const trimmedPw = password;

      if (!trimmedId) {
        errors.identifier = 'Please enter your email or username.';
      }
      if (!trimmedPw) {
        errors.password = 'Please enter your password.';
      }

      if (Object.keys(errors).length > 0) {
        setFieldErrors(errors);
        return;
      }

      setFieldErrors({});
      if (onPasswordLogin) {
        setLocalSubmitting(true);
        try {
          await onPasswordLogin(trimmedId, trimmedPw);
        } finally {
          setLocalSubmitting(false);
        }
      }
    } else {
      // Register Mode
      const trimmedUser = registerUsername.trim();
      const trimmedEmail = registerEmail.trim();
      const trimmedPw = registerPassword;

      if (!trimmedUser) {
        errors.registerUsername = 'Username is required.';
      } else if (
        trimmedUser.length < 1 ||
        trimmedUser.length > 64 ||
        !/^[a-zA-Z0-9_-]+$/.test(trimmedUser)
      ) {
        errors.registerUsername = 'Username must be 1-64 characters (letters, numbers, _, -).';
      }

      if (trimmedEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)) {
        errors.registerEmail = 'Please provide a valid email address.';
      }

      if (!trimmedPw) {
        errors.registerPassword = 'Password is required.';
      } else if (trimmedPw.length < 10) {
        errors.registerPassword = 'Password must be at least 10 characters.';
      }

      if (Object.keys(errors).length > 0) {
        setFieldErrors(errors);
        return;
      }

      setFieldErrors({});
      if (onRegister) {
        setLocalSubmitting(true);
        try {
          await onRegister(trimmedUser, trimmedEmail, trimmedPw);
        } finally {
          setLocalSubmitting(false);
        }
      }
    }
  };

  // Switch tabs cleanly without lingering errors
  useEffect(() => {
    // Clear errors when mode changes
    clearErrors();
    setFieldErrors({});
  }, [mode]);

  return (
    <div className="fc-auth-shell">
      <main className="fc-auth-container" aria-label="Fire Crow Authentication">
        {/* ─── LEFT PANEL: Studio Endorsement & Engineering Principles ─── */}
        <aside className="fc-auth-brand-panel" aria-label="Brand Overview">
          <div className="fc-auth-brand-content">
            {/* NEXT LAB Endorsement Pill */}
            <div className="fc-auth-studio-endorsement">
              <NextLabSymbol size={16} />
              <span>NEXT LAB</span>
              <span className="fc-auth-studio-inc-badge">.inc</span>
              <span style={{ opacity: 0.6 }}>// STUDIO</span>
            </div>

            {/* Fire Crow Product Hero */}
            <div className="fc-auth-brand-hero">
              <FireCrowSymbol size={48} animated={true} state="idle" />
              <div className="fc-auth-brand-hero-text">
                <h1 className="fc-auth-brand-title">
                  <span>Fire </span>
                  <span style={{ color: 'var(--fc-accent, #C92F38)' }}>Crow</span>
                </h1>
                <span className="fc-auth-brand-sub" style={{ letterSpacing: '0.12em' }}>
                  SECURE · SCAN · REMEDIATE
                </span>
              </div>
            </div>

            <p className="fc-auth-brand-desc">
              Deterministic security auditing, ephemeral container SAST verification, and
              compiler-checked remediations for mission-critical codebases.
            </p>

            {/* Engineering Guarantees */}
            <div className="fc-auth-guarantees">
              <div className="fc-auth-guarantee-item">
                <span className="fc-auth-guarantee-num">01</span>
                <div className="fc-auth-guarantee-text">
                  <strong>Zero Code Retention</strong>
                  <p>Ephemeral scratch containers are mounted strictly read-only and destroyed immediately upon run completion.</p>
                </div>
              </div>

              <div className="fc-auth-guarantee-item">
                <span className="fc-auth-guarantee-num">02</span>
                <div className="fc-auth-guarantee-text">
                  <strong>Deterministic Ledgers</strong>
                  <p>Immutable scoring formulas anchored to verified CWE identifiers and CVSS vectors with zero LLM hallucinations.</p>
                </div>
              </div>

              <div className="fc-auth-guarantee-item">
                <span className="fc-auth-guarantee-num">03</span>
                <div className="fc-auth-guarantee-text">
                  <strong>Airgapped Execution</strong>
                  <p>Scanners run with Linux privileges dropped (--cap-drop=ALL) under strict network isolation ceilings.</p>
                </div>
              </div>
            </div>
          </div>

          {/* Telemetry Footer */}
          <div className="fc-auth-telemetry" aria-hidden="true">
            <span className="fc-auth-telemetry-dot" />
            <span>CORE ENGINE v2.4 · TLS 1.3 · SESSION ISOLATION</span>
          </div>
        </aside>

        {/* ─── RIGHT PANEL: Authentication Interaction Form ─── */}
        <section className="fc-auth-form-panel" aria-labelledby="fc-auth-heading">
          {/* Mobile-only compact brand lockup */}
          <div className="fc-auth-mobile-brand">
            <BrandLockup compact={true} />
          </div>

          <div className="fc-auth-header">
            <h2 id="fc-auth-heading" className="fc-auth-title">
              {mode === 'signin' ? 'Sign in to Fire Crow' : 'Create an Account'}
            </h2>
            <p className="fc-auth-sub">
              {mode === 'signin'
                ? 'Authenticate to access your security workspace and repository audits.'
                : 'Register a new engineering profile to start containerized security scans.'}
            </p>
          </div>

          {/* Segmented Mode Selector */}
          <div className="fc-auth-tabs" role="tablist" aria-label="Authentication mode">
            <button
              type="button"
              role="tab"
              aria-selected={mode === 'signin'}
              className={`fc-auth-tab ${mode === 'signin' ? 'active' : ''}`}
              onClick={() => handleTabChange('signin')}
            >
              Sign In
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={mode === 'register'}
              className={`fc-auth-tab ${mode === 'register' ? 'active' : ''}`}
              onClick={() => handleTabChange('register')}
            >
              Register
            </button>
          </div>

          {/* OAuth: GitHub Authentication Button */}
          <button
            type="button"
            onClick={onGitHubLogin}
            className="fc-auth-github-btn"
            disabled={isSubmitting}
            aria-label="Continue with GitHub"
          >
            <GitHubIcon />
            <span>Continue with GitHub</span>
          </button>

          {/* Geometric Divider */}
          <div className="fc-auth-divider" aria-hidden="true">
            <span>OR CONTINUE WITH CREDENTIALS</span>
          </div>

          {/* Active Error Banner */}
          {activeError && (
            <div className="fc-auth-error-banner" role="alert" aria-live="assertive">
              <AlertCircle size={16} />
              <span>{activeError}</span>
            </div>
          )}

          {/* Credentials Form */}
          <form className="fc-auth-form" onSubmit={handleCredentialSubmit} noValidate>
            {mode === 'signin' ? (
              <>
                {/* Identifier: Email or Username */}
                <div className="fc-auth-field">
                  <label htmlFor="fc-auth-identifier" className="fc-auth-label">
                    <span>Email or Username</span>
                  </label>
                  <div className="fc-auth-input-wrapper">
                    <input
                      ref={identifierInputRef}
                      id="fc-auth-identifier"
                      name="username"
                      type="text"
                      autoComplete="username"
                      value={identifier}
                      onChange={(e) => setIdentifier(e.target.value)}
                      placeholder="developer@company.com or username"
                      className="fc-auth-input"
                      disabled={isSubmitting}
                      aria-invalid={Boolean(fieldErrors.identifier)}
                      aria-describedby={fieldErrors.identifier ? 'fc-auth-id-err' : undefined}
                      required
                    />
                  </div>
                  {fieldErrors.identifier && (
                    <span id="fc-auth-id-err" className="fc-auth-field-error" role="alert">
                      <AlertCircle size={13} aria-hidden="true" />
                      <span>{fieldErrors.identifier}</span>
                    </span>
                  )}
                </div>

                {/* Password Field */}
                <div className="fc-auth-field">
                  <label htmlFor="fc-auth-password" className="fc-auth-label">
                    <span>Password</span>
                  </label>
                  <div className="fc-auth-input-wrapper">
                    <input
                      id="fc-auth-password"
                      name="password"
                      type={showPassword ? 'text' : 'password'}
                      autoComplete="current-password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="••••••••••••"
                      className="fc-auth-input"
                      disabled={isSubmitting}
                      aria-invalid={Boolean(fieldErrors.password)}
                      aria-describedby={fieldErrors.password ? 'fc-auth-pw-err' : undefined}
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword((prev) => !prev)}
                      className="fc-auth-pw-toggle"
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                      aria-pressed={showPassword}
                    >
                      {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                    </button>
                  </div>
                  {fieldErrors.password && (
                    <span id="fc-auth-pw-err" className="fc-auth-field-error" role="alert">
                      <AlertCircle size={13} aria-hidden="true" />
                      <span>{fieldErrors.password}</span>
                    </span>
                  )}
                  <p className="fc-auth-recovery-note">
                    Self-service reset is disabled for zero-retention accounts. Contact your organization admin for password updates.
                  </p>
                </div>
              </>
            ) : (
              <>
                {/* Registration: Username */}
                <div className="fc-auth-field">
                  <label htmlFor="fc-reg-username" className="fc-auth-label">
                    <span>Username</span>
                  </label>
                  <div className="fc-auth-input-wrapper">
                    <input
                      ref={identifierInputRef}
                      id="fc-reg-username"
                      name="username"
                      type="text"
                      autoComplete="username"
                      value={registerUsername}
                      onChange={(e) => setRegisterUsername(e.target.value)}
                      placeholder="e.g. dev_analyst"
                      className="fc-auth-input"
                      disabled={isSubmitting}
                      aria-invalid={Boolean(fieldErrors.registerUsername)}
                      aria-describedby={fieldErrors.registerUsername ? 'fc-reg-user-err' : undefined}
                      required
                    />
                  </div>
                  {fieldErrors.registerUsername && (
                    <span id="fc-reg-user-err" className="fc-auth-field-error" role="alert">
                      <AlertCircle size={13} aria-hidden="true" />
                      <span>{fieldErrors.registerUsername}</span>
                    </span>
                  )}
                </div>

                {/* Registration: Email */}
                <div className="fc-auth-field">
                  <label htmlFor="fc-reg-email" className="fc-auth-label">
                    <span>Email Address (Optional)</span>
                  </label>
                  <div className="fc-auth-input-wrapper">
                    <input
                      id="fc-reg-email"
                      name="email"
                      type="email"
                      autoComplete="email"
                      value={registerEmail}
                      onChange={(e) => setRegisterEmail(e.target.value)}
                      placeholder="developer@company.com"
                      className="fc-auth-input"
                      disabled={isSubmitting}
                      aria-invalid={Boolean(fieldErrors.registerEmail)}
                      aria-describedby={fieldErrors.registerEmail ? 'fc-reg-email-err' : undefined}
                    />
                  </div>
                  {fieldErrors.registerEmail && (
                    <span id="fc-reg-email-err" className="fc-auth-field-error" role="alert">
                      <AlertCircle size={13} aria-hidden="true" />
                      <span>{fieldErrors.registerEmail}</span>
                    </span>
                  )}
                </div>

                {/* Registration: Password */}
                <div className="fc-auth-field">
                  <label htmlFor="fc-reg-password" className="fc-auth-label">
                    <span>Password (Minimum 10 characters)</span>
                  </label>
                  <div className="fc-auth-input-wrapper">
                    <input
                      id="fc-reg-password"
                      name="password"
                      type={showPassword ? 'text' : 'password'}
                      autoComplete="new-password"
                      value={registerPassword}
                      onChange={(e) => setRegisterPassword(e.target.value)}
                      placeholder="••••••••••••"
                      className="fc-auth-input"
                      disabled={isSubmitting}
                      aria-invalid={Boolean(fieldErrors.registerPassword)}
                      aria-describedby={fieldErrors.registerPassword ? 'fc-reg-pw-err' : undefined}
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword((prev) => !prev)}
                      className="fc-auth-pw-toggle"
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                      aria-pressed={showPassword}
                    >
                      {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                    </button>
                  </div>
                  {fieldErrors.registerPassword && (
                    <span id="fc-reg-pw-err" className="fc-auth-field-error" role="alert">
                      <AlertCircle size={13} aria-hidden="true" />
                      <span>{fieldErrors.registerPassword}</span>
                    </span>
                  )}
                </div>
              </>
            )}

            {/* Submit Action */}
            <button
              type="submit"
              className="fc-auth-submit-btn"
              disabled={isSubmitting}
            >
              {isSubmitting ? (
                <>
                  <span className="fc-auth-spinner" aria-hidden="true" />
                  <span>Authenticating...</span>
                </>
              ) : (
                <>
                  <span>
                    {mode === 'signin' ? 'Sign In to Workspace' : 'Create Account & Sign In'}
                  </span>
                  <ArrowRight size={16} />
                </>
              )}
            </button>
          </form>

          {/* Mode Switch Helper */}
          <div className="fc-auth-switch-mode">
            {mode === 'signin' ? (
              <span>
                New to Fire Crow?{' '}
                <button
                  type="button"
                  onClick={() => handleTabChange('register')}
                  className="fc-auth-text-link"
                >
                  Create an account
                </button>
              </span>
            ) : (
              <span>
                Already registered?{' '}
                <button
                  type="button"
                  onClick={() => handleTabChange('signin')}
                  className="fc-auth-text-link"
                >
                  Sign in
                </button>
              </span>
            )}
          </div>

          {/* Back to landing */}
          <button
            type="button"
            onClick={() => {
              clearErrors();
              onNavigateLanding();
            }}
            className="fc-auth-back-btn"
          >
            ← Back to landing page
          </button>
        </section>
      </main>
    </div>
  );
}
