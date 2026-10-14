import { useState, type FormEvent, useEffect, useRef, type ReactNode } from 'react';
import { Eye, EyeOff, AlertCircle } from 'lucide-react';
import { BrandMark } from './BrandMark';
import './login-site.css';

/**
 * FC-SEC: Open redirect protection helper re-exported for convenience.
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

const GitHubIcon = ({ size = 20 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
    <path
      fillRule="evenodd"
      clipRule="evenodd"
      d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.166 6.839 9.489.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.603-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.579.688.481C19.137 20.162 22 16.418 22 12c0-5.523-4.477-10-10-10z"
    />
  </svg>
);

interface FieldProps {
  id: string;
  label: string;
  error?: string;
  children: ReactNode;
}

function Field({ id, label, error, children }: FieldProps) {
  return (
    <div className="lg-field">
      <label htmlFor={id}>{label}</label>
      {children}
      {error && (
        <span id={`${id}-err`} className="lg-field-error" role="alert">
          <AlertCircle size={14} aria-hidden="true" />
          <span>{error}</span>
        </span>
      )}
    </div>
  );
}

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
  const clearErrorsRef = useRef(clearErrors);
  clearErrorsRef.current = clearErrors;
  useEffect(() => {
    // Clear errors when mode changes
    clearErrorsRef.current();
    setFieldErrors({});
  }, [mode]);

  const errId = (id: string, key: string) => (fieldErrors[key] ? `${id}-err` : undefined);

  return (
    <div className="lg">
      <main className="lg-grid" aria-labelledby="lg-heading">
        <section className="lg-form-side">
          <button
            type="button"
            className="lg-brand"
            onClick={() => {
              clearErrors();
              onNavigateLanding();
            }}
            aria-label="Fire Crow home"
          >
            <BrandMark />
            <span>Fire Crow</span>
          </button>

          <div className="lg-card">
            <h1 id="lg-heading">{mode === 'signin' ? 'Sign in' : 'Create your account'}</h1>
            <p className="lg-sub">
              {mode === 'signin'
                ? 'Open your workspace to run audits and read reports.'
                : 'Pick a username and a password of at least 10 characters.'}
            </p>

            <button type="button" onClick={onGitHubLogin} className="lg-github" disabled={isSubmitting}>
              <GitHubIcon />
              <span>Continue with GitHub</span>
            </button>

            <p className="lg-or" aria-hidden="true"><span>or use a password</span></p>

            {activeError && (
              <div className="lg-error" role="alert">
                <AlertCircle size={16} aria-hidden="true" />
                <span>{activeError}</span>
              </div>
            )}

            <form className="lg-form" onSubmit={handleCredentialSubmit} noValidate>
              {mode === 'signin' ? (
                <>
                  <Field id="lg-identifier" label="Email or username" error={fieldErrors.identifier}>
                    <input
                      ref={identifierInputRef}
                      id="lg-identifier"
                      name="username"
                      type="text"
                      autoComplete="username"
                      value={identifier}
                      onChange={(e) => setIdentifier(e.target.value)}
                      disabled={isSubmitting}
                      aria-invalid={Boolean(fieldErrors.identifier)}
                      aria-describedby={errId('lg-identifier', 'identifier')}
                      required
                    />
                  </Field>
                  <Field id="lg-password" label="Password" error={fieldErrors.password}>
                    <div className="lg-pw">
                      <input
                        id="lg-password"
                        name="password"
                        type={showPassword ? 'text' : 'password'}
                        autoComplete="current-password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        disabled={isSubmitting}
                        aria-invalid={Boolean(fieldErrors.password)}
                        aria-describedby={errId('lg-password', 'password')}
                        required
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword((p) => !p)}
                        aria-label={showPassword ? 'Hide password' : 'Show password'}
                        aria-pressed={showPassword}
                      >
                        {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                      </button>
                    </div>
                  </Field>
                  <p className="lg-hint">
                    Self-service password reset isn&rsquo;t available. Ask your organization admin to reset it.
                  </p>
                </>
              ) : (
                <>
                  <Field id="lg-reg-username" label="Username" error={fieldErrors.registerUsername}>
                    <input
                      ref={identifierInputRef}
                      id="lg-reg-username"
                      name="username"
                      type="text"
                      autoComplete="username"
                      value={registerUsername}
                      onChange={(e) => setRegisterUsername(e.target.value)}
                      disabled={isSubmitting}
                      aria-invalid={Boolean(fieldErrors.registerUsername)}
                      aria-describedby={errId('lg-reg-username', 'registerUsername')}
                      required
                    />
                  </Field>
                  <Field id="lg-reg-email" label="Email (optional)" error={fieldErrors.registerEmail}>
                    <input
                      id="lg-reg-email"
                      name="email"
                      type="email"
                      autoComplete="email"
                      value={registerEmail}
                      onChange={(e) => setRegisterEmail(e.target.value)}
                      disabled={isSubmitting}
                      aria-invalid={Boolean(fieldErrors.registerEmail)}
                      aria-describedby={errId('lg-reg-email', 'registerEmail')}
                    />
                  </Field>
                  <Field id="lg-reg-password" label="Password (10 characters or more)" error={fieldErrors.registerPassword}>
                    <div className="lg-pw">
                      <input
                        id="lg-reg-password"
                        name="password"
                        type={showPassword ? 'text' : 'password'}
                        autoComplete="new-password"
                        value={registerPassword}
                        onChange={(e) => setRegisterPassword(e.target.value)}
                        disabled={isSubmitting}
                        aria-invalid={Boolean(fieldErrors.registerPassword)}
                        aria-describedby={errId('lg-reg-password', 'registerPassword')}
                        required
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword((p) => !p)}
                        aria-label={showPassword ? 'Hide password' : 'Show password'}
                        aria-pressed={showPassword}
                      >
                        {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                      </button>
                    </div>
                  </Field>
                </>
              )}

              <button type="submit" className="lg-submit" disabled={isSubmitting}>
                {isSubmitting
                  ? mode === 'signin' ? 'Signing in…' : 'Creating account…'
                  : mode === 'signin' ? 'Sign in' : 'Create account'}
              </button>
            </form>

            <p className="lg-switch">
              {mode === 'signin' ? 'New to Fire Crow? ' : 'Already have an account? '}
              <button type="button" onClick={() => handleTabChange(mode === 'signin' ? 'register' : 'signin')}>
                {mode === 'signin' ? 'Create an account' : 'Sign in'}
              </button>
            </p>
          </div>
        </section>

        <aside className="lg-panel" aria-label="What happens after you sign in">
          <div className="lg-panel-inner">
            <h2>Every audit ends in a record, not a guess.</h2>
            <ul className="lg-points">
              <li>
                <strong>Your code is deleted after the run.</strong>
                <span>Scanners get a read-only copy in a throwaway container with no network access.</span>
              </li>
              <li>
                <strong>The score comes from findings only.</strong>
                <span>The same findings always give the same score. AI summaries can&rsquo;t change it.</span>
              </li>
              <li>
                <strong>A failed scan says so.</strong>
                <span>If a scanner times out, the report is marked partial instead of clean.</span>
              </li>
            </ul>
            <div className="lg-sample" aria-hidden="true">
              <span className="lg-sample-sev">high</span>
              <span className="lg-sample-text">Known prototype pollution in dependency</span>
              <span className="lg-sample-file">package.json:28</span>
            </div>
          </div>
        </aside>
      </main>
    </div>
  );
}
