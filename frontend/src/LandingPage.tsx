import { useEffect, useState, type FormEvent } from 'react';
import { BrandMark } from './BrandMark';
import { Ledger } from './landing/site/Ledger';
import { CAPABILITIES, FAQ_ITEMS, PIPELINE_STAGES } from './landing/data/landingData';
import './landing/site/landing-site.css';

export interface LandingPageUser {
  user_id?: string;
  username: string;
  email: string | null;
  credit_balance?: number;
}

export type UserProfile = LandingPageUser;

export interface LandingPageProps {
  user?: LandingPageUser | null;
  onNavigateLogin: () => void;
  onNavigateConsole?: () => void;
  onInitiateCheckout?: (amount: number, packageName: string) => Promise<void> | void;
}

const REPO_URL = 'https://github.com/johan-droid/Fire-Crow-';

const NAV = [
  { href: '#how', label: 'How a scan runs' },
  { href: '#guarantees', label: 'Guarantees' },
  { href: '#failures', label: 'When scans fail' },
  { href: '#faq', label: 'FAQ' },
];

const FAILURE_ROWS = [
  { when: 'Every scanner finishes', status: 'completed', note: 'Findings are normalised and the score is calculated.' },
  { when: 'A scanner times out or crashes', status: 'partial', note: 'The report says which scanner is missing. It is not shown as clean.' },
  { when: 'A scanner is not available', status: 'engine_unavailable', note: 'The job records the gap instead of skipping it silently.' },
  { when: 'The archive is over 50 MB', status: 'stopped at intake', note: 'No scanner starts. Nothing is unpacked past the limit.' },
];

export default function LandingPage({ user, onNavigateLogin, onNavigateConsole }: LandingPageProps) {
  const [menu, setMenu] = useState(false);
  const [email, setEmail] = useState('');
  const [sent, setSent] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMenu(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const primary = user && onNavigateConsole ? onNavigateConsole : onNavigateLogin;
  const primaryLabel = user ? 'Open console' : 'Sign in to run an audit';

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (email.trim()) setSent(true);
  };

  return (
    <div className="lp" id="top">
      <a href="#main" className="lp-skip">Skip to main content</a>

      <header className="lp-nav">
        <div className="lp-wrap lp-nav-inner">
          <a href="#top" className="lp-brand" aria-label="Fire Crow home">
            <BrandMark />
            <span>Fire Crow</span>
            <small>by Next Lab</small>
          </a>
          <nav className="lp-nav-links" aria-label="Main">
            {NAV.map((n) => (
              <a key={n.href} href={n.href}>{n.label}</a>
            ))}
            <a href={REPO_URL} target="_blank" rel="noreferrer">GitHub</a>
          </nav>
          <div className="lp-nav-actions">
            {!user && (
              <button type="button" className="lp-link-btn" onClick={onNavigateLogin}>Sign in</button>
            )}
            <button type="button" className="lp-btn lp-btn-ink" onClick={primary}>
              {user ? `Open console (${user.username})` : 'Open console'}
            </button>
            <button
              type="button"
              className="lp-menu-btn"
              aria-expanded={menu}
              aria-controls="lp-menu"
              onClick={() => setMenu((m) => !m)}
            >
              {menu ? 'Close' : 'Menu'}
            </button>
          </div>
        </div>
        {menu && (
          <nav id="lp-menu" className="lp-menu" aria-label="Mobile">
            {NAV.map((n) => (
              <a key={n.href} href={n.href} onClick={() => setMenu(false)}>{n.label}</a>
            ))}
            <a href={REPO_URL} target="_blank" rel="noreferrer">GitHub</a>
          </nav>
        )}
      </header>

      <main id="main" tabIndex={-1}>
        <section className="lp-hero">
          <div className="lp-wrap lp-hero-grid">
            <div className="lp-hero-copy">
              <h1>Audit results you can prove, not just read.</h1>
              <p className="lp-lede">
                Fire Crow scans your GitHub repository with Gitleaks, Semgrep and OSV-Scanner inside throwaway
                containers, then records every finding in a ledger that can&rsquo;t be edited afterwards.
              </p>
              <div className="lp-cta-row">
                <button type="button" className="lp-btn lp-btn-ember" onClick={primary}>{primaryLabel}</button>
                <a href="#how" className="lp-btn lp-btn-quiet">See how a scan runs</a>
              </div>
              <p className="lp-fineprint">The audit shown is a sample. Select a finding to open it.</p>
            </div>
            <Ledger />
          </div>
        </section>

        <section id="how" className="lp-section">
          <div className="lp-wrap lp-split">
            <div className="lp-split-head">
              <h2>From repository URL to frozen report</h2>
              <p>Five steps, always in this order. Each one either finishes or says why it didn&rsquo;t.</p>
            </div>
            <ol className="lp-steps">
              {PIPELINE_STAGES.map((s, i) => (
                <li key={s.name} className="lp-step">
                  <span className="lp-step-n" aria-hidden="true">{i + 1}</span>
                  <div>
                    <h3>{s.name}</h3>
                    <p>{s.summary}</p>
                  </div>
                  <span className="lp-step-tool">{s.scanner}</span>
                </li>
              ))}
            </ol>
          </div>
        </section>

        <section id="guarantees" className="lp-section lp-section-tint">
          <div className="lp-wrap lp-split">
            <div className="lp-split-head">
              <h2>What the audit guarantees</h2>
              <p>These come from how the system is built, not from settings you have to remember to turn on.</p>
            </div>
            <dl className="lp-defs">
              {CAPABILITIES.map((c) => (
                <div key={c.id} className="lp-def">
                  <dt>{c.title}</dt>
                  <dd>
                    {c.description} <span>{c.technicalDetail}</span>
                  </dd>
                </div>
              ))}
            </dl>
          </div>
        </section>

        <section id="failures" className="lp-section">
          <div className="lp-wrap lp-split">
            <div className="lp-split-head">
              <h2>A failed scan never looks like a clean one</h2>
              <p>If a scanner can&rsquo;t do its job, the report tells you. A missing result is not a pass.</p>
            </div>
            <div className="lp-table-wrap">
              <table className="lp-table">
                <caption className="lp-sr">What Fire Crow records in each situation</caption>
                <thead>
                  <tr><th scope="col">What happens</th><th scope="col">Job status</th><th scope="col">What you see</th></tr>
                </thead>
                <tbody>
                  {FAILURE_ROWS.map((r) => (
                    <tr key={r.when}>
                      <th scope="row">{r.when}</th>
                      <td><code>{r.status}</code></td>
                      <td>{r.note}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>

        <section id="access" className="lp-section lp-section-ink">
          <div className="lp-wrap lp-access">
            <div>
              <h2>Run your first audit</h2>
              <p>
                Sign in with GitHub or a password and paste a repository URL. Self-serve billing is paused right now,
                so teams that need dedicated capacity or a self-hosted runner can ask for it here.
              </p>
              <button type="button" className="lp-btn lp-btn-ember" onClick={primary}>{primaryLabel}</button>
            </div>
            {sent ? (
              <p className="lp-sent" role="status">Request received. We&rsquo;ll email you about capacity and onboarding.</p>
            ) : (
              <form className="lp-form" onSubmit={submit}>
                <label htmlFor="lp-email">Work email for dedicated capacity</label>
                <div className="lp-form-row">
                  <input
                    id="lp-email"
                    type="email"
                    required
                    autoComplete="email"
                    placeholder="name@company.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                  />
                  <button type="submit" className="lp-btn lp-btn-light">Request access</button>
                </div>
              </form>
            )}
          </div>
        </section>

        <section id="faq" className="lp-section">
          <div className="lp-wrap lp-split">
            <div className="lp-split-head">
              <h2>Questions teams ask first</h2>
            </div>
            <div className="lp-faq">
              {FAQ_ITEMS.map((f) => (
                <details key={f.id} className="lp-faq-item">
                  <summary>{f.question}</summary>
                  <div>
                    {f.answer.split('\n\n').map((p, i) => (
                      <p key={i}>{p}</p>
                    ))}
                  </div>
                </details>
              ))}
            </div>
          </div>
        </section>
      </main>

      <footer className="lp-footer">
        <div className="lp-wrap lp-footer-inner">
          <span>Fire Crow by Next Lab</span>
          <nav aria-label="Footer">
            {NAV.map((n) => (
              <a key={n.href} href={n.href}>{n.label}</a>
            ))}
            <a href={REPO_URL} target="_blank" rel="noreferrer">GitHub</a>
          </nav>
        </div>
      </footer>
    </div>
  );
}
