import { useEffect, useRef, useState } from 'react';
import { BrandMark } from './BrandMark';
import { Ledger } from './landing/site/Ledger';
import { HeroCanvas3D } from './scene';
import { NextLabSymbol } from './landing/components/BrandLogos';
import { CAPABILITIES, FAQ_ITEMS, PIPELINE_STAGES } from './landing/data/landingData';
import './landing/site/landing-site.css';

/** One-shot scroll reveal. Honors prefers-reduced-motion by showing at once. */
function useReveal<T extends HTMLElement>() {
  const ref = useRef<T | null>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches || typeof IntersectionObserver === 'undefined') {
      el.classList.add('is-visible');
      return;
    }
    const io = new IntersectionObserver((entries) => {
      for (const e of entries) {
        if (e.isIntersecting) { e.target.classList.add('is-visible'); io.disconnect(); }
      }
    }, { threshold: 0.12, rootMargin: '0px 0px -8% 0px' });
    io.observe(el);
    return () => io.disconnect();
  }, []);
  return ref;
}

/** Section wrapper that reveals on scroll. */
function Reveal({ children, className = '', delay = 0 }: { children: React.ReactNode; className?: string; delay?: number }) {
  const ref = useReveal<HTMLDivElement>();
  return (
    <div ref={ref} className={`lp-reveal${className ? ` ${className}` : ''}`} style={{ '--lp-reveal-delay': `${delay}ms` } as React.CSSProperties}>
      {children}
    </div>
  );
}

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
  { href: '#studio', label: 'Studio' },
  { href: '#access', label: 'Request access' },
];

/**
 * Shown only to signed-out visitors. On the free-tier preview a cold backend
 * takes tens of seconds to answer, and real scanner execution is unavailable
 * until the supported Docker topology is in place. Saying so up front is the
 * honest alternative to a spinner that looks like a hang or a fake result.
 */
const DEMO_NOTE = {
  tag: 'Preview environment',
  body: 'This deployment runs on the free tier as a demo: the API may take up to a minute to wake on the first request. Scanners run either in an isolated container or as hardened native subprocesses depending on the deployment — the console shows the live execution mode and any reduced-isolation warning before you audit.',
};

const STUDIO_PILLARS = [
  {
    tag: 'Deterministic systems',
    title: 'Zero black boxes',
    body: 'We reject opaque, hand-waving claims. Every risk score is calculated via an open formula, every finding is linked to line-level evidence and authoritative CWE identifiers, and audits are strictly reproducible.',
    meta: 'formula: 100 − Σ(severity_weights)',
  },
  {
    tag: 'Zero-trust runtime',
    title: 'Ephemeral sandbox isolation',
    body: 'Developer tools must never compromise the systems they audit. Fire Crow runs every scanner in a disposable container with all Linux capabilities dropped, mounting your code read-only and discarding the container the moment it finishes.',
    meta: 'privileges: dropped · network: none (OSV via filtered proxy)',
  },
  {
    tag: 'Studio ecosystem',
    title: 'Built for a family of tools',
    body: 'Fire Crow adopts Next Lab’s unified visual grammar — precise grids, fine borders, layered surfaces, and purposeful motion. Every tool the studio releases shares this foundation.',
    meta: 'ecosystem: NEXT LAB // Fire Crow',
  },
];

const FAILURE_ROWS = [
  { when: 'Every scanner finishes', status: 'completed', note: 'Findings are normalised and the score is calculated.' },
  { when: 'A scanner times out or crashes', status: 'partial', note: 'The report says which scanner is missing. It is not shown as clean.' },
  { when: 'A scanner is not available', status: 'engine_unavailable', note: 'The job records the gap instead of skipping it silently.' },
  { when: 'The archive is over 50 MB', status: 'stopped at intake', note: 'No scanner starts. Nothing is unpacked past the limit.' },
];

export default function LandingPage({ user, onNavigateLogin, onNavigateConsole }: LandingPageProps) {
  const [menu, setMenu] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMenu(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  // Scroll progress → --lp-scroll (read by the fixed hairline). Passive.
  useEffect(() => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const root = document.documentElement;
    let raf = 0;
    const onScroll = () => {
      if (raf) return;
      raf = requestAnimationFrame(() => {
        raf = 0;
        const max = document.body.scrollHeight - window.innerHeight;
        root.style.setProperty('--lp-scroll', max > 0 ? (window.scrollY / max).toFixed(4) : '0');
      });
    };
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
    return () => { window.removeEventListener('scroll', onScroll); if (raf) cancelAnimationFrame(raf); };
  }, []);

  const primary = user && onNavigateConsole ? onNavigateConsole : onNavigateLogin;
  const primaryLabel = user ? 'Open console' : 'Sign in to run an audit';

  return (
    <div className="lp" id="top">
      <span className="lp-scrollbar" aria-hidden="true" />
      <a href="#main" className="lp-skip">Skip to main content</a>

      <header className="lp-nav">
        <div className="lp-wrap lp-nav-inner">
          <a href="#top" className="lp-brand" aria-label="Fire Crow home">
            <BrandMark />
            <span>Fire Crow</span>
            <small className="lp-brand-parent"><NextLabSymbol size={13} />by Next Lab</small>
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
          <HeroCanvas3D />
          <div className="lp-wrap lp-hero-grid">
            <Reveal className="lp-hero-copy">
              <p className="lp-eyebrow"><span className="lp-eyebrow-dot" aria-hidden="true" />Zero-trust deterministic security auditing</p>
              <h1 className="lp-serif">Find the gaps.<span className="lp-cursive-accent"> Before they become risks.</span></h1>
              <p className="lp-lede">
                Fire Crow scans your GitHub repository with Gitleaks, Semgrep, and OSV-Scanner inside
                throwaway containers, then freezes every finding into a ledger no one can edit after the run.
              </p>
              <div className="lp-cta-row">
                <button type="button" className="lp-btn lp-btn-ember" onClick={primary}>{primaryLabel}</button>
                <a href="#how" className="lp-btn lp-btn-quiet">See how a scan runs</a>
              </div>
              {!user && (
                <p className="lp-demo-note" role="note">
                  <strong>{DEMO_NOTE.tag}</strong> — {DEMO_NOTE.body}
                </p>
              )}
              <p className="lp-fineprint">The audit shown is a sample. Select a finding to open it.</p>
            </Reveal>
            <Reveal delay={120}><Ledger /></Reveal>
          </div>
        </section>

        <section id="how" className="lp-section">
          <div className="lp-wrap lp-split">
            <Reveal className="lp-split-head">
              <p className="lp-eyebrow lp-eyebrow-sec" aria-hidden="true">01 // How a scan runs</p>
              <h2>From repository URL to frozen report</h2>
              <p>Five steps, always in this order. Each one either finishes or says why it didn&rsquo;t.</p>
            </Reveal>
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

        <section id="guarantees" className="lp-section lp-section-ivory">
          <div className="lp-wrap lp-split">
            <Reveal className="lp-split-head">
              <p className="lp-eyebrow lp-eyebrow-sec" aria-hidden="true">02 // Guarantees</p>
              <h2>What the audit guarantees</h2>
              <p>These come from how the system is built, not from settings you have to remember to turn on.</p>
            </Reveal>
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
            <Reveal className="lp-split-head">
              <p className="lp-eyebrow lp-eyebrow-sec" aria-hidden="true">03 // When scans fail</p>
              <h2>A failed scan never looks like a clean one</h2>
              <p>If a scanner can&rsquo;t do its job, the report tells you. A missing result is not a pass.</p>
            </Reveal>
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
            <div className="lp-access-ask">
              <p>
                Dedicated capacity and self-hosted runners are arranged case by case.
                Open a request on GitHub and we&rsquo;ll pick it up.
              </p>
              <a
                className="lp-btn lp-btn-light"
                href={`${REPO_URL}/issues/new`}
                target="_blank"
                rel="noreferrer"
              >
                Request capacity on GitHub
              </a>
            </div>
          </div>
        </section>

        <section id="faq" className="lp-section">
          <div className="lp-wrap lp-split">
            <Reveal className="lp-split-head">
              <p className="lp-eyebrow lp-eyebrow-sec" aria-hidden="true">04 // FAQ</p>
              <h2>Questions teams ask first</h2>
            </Reveal>
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

        <section id="studio" className="lp-section lp-section-ivory">
          <div className="lp-wrap">
            <Reveal className="lp-studio-head">
              <p className="lp-eyebrow lp-eyebrow-sec" aria-hidden="true">05 // The studio</p>
              <h2>Engineering tools for what comes next.</h2>
              <p className="lp-studio-lede">
                <strong>Next Lab</strong> is an independent, engineering-first software studio. We build
                precise, developer-centric tools that make complex systems more secure, transparent, and
                mathematically verifiable. Fire Crow is our flagship security auditing product.
              </p>
            </Reveal>

            <div className="lp-studio-grid">
              {STUDIO_PILLARS.map((p, i) => (
                <Reveal key={p.tag} delay={i * 100}>
                  <article className="lp-pillar">
                    <div className="lp-pillar-head">
                      <span className="lp-pillar-idx" aria-hidden="true">0{i + 1}</span>
                      <span className="lp-pillar-tag">{p.tag}</span>
                    </div>
                    <h3>{p.title}</h3>
                    <p>{p.body}</p>
                    <code className="lp-pillar-meta">{p.meta}</code>
                  </article>
                </Reveal>
              ))}
            </div>

            <Reveal className="lp-blueprint" delay={120}>
              <div className="lp-blueprint-brand">
                <NextLabSymbol size={22} />
                <div>
                  <span className="lp-blueprint-parent">Next Lab</span>
                  <span className="lp-blueprint-sub">Independent developer tools</span>
                </div>
              </div>
              <span className="lp-blueprint-arrow" aria-hidden="true">→</span>
              <div className="lp-blueprint-product">
                <BrandMark size={26} />
                <div>
                  <span className="lp-blueprint-prod">Fire Crow</span>
                  <span className="lp-blueprint-prod-tag">Flagship security auditing</span>
                </div>
              </div>
              <dl className="lp-blueprint-stats">
                <div><dt>Paradigm</dt><dd>Containerized SAST &amp; CVE</dd></div>
                <div><dt>Data policy</dt><dd>Zero code retention</dd></div>
                <div><dt>Intelligence</dt><dd>Read-only AI summaries</dd></div>
              </dl>
            </Reveal>
          </div>
        </section>
      </main>

      <footer className="lp-footer">
        <div className="lp-wrap lp-footer-inner">
          <span className="lp-footer-brand"><NextLabSymbol size={18} />Fire Crow <span aria-hidden="true">·</span> by <strong>Next Lab</strong></span>
          <nav aria-label="Footer">
            {NAV.map((n) => (
              <a key={n.href} href={n.href}>{n.label}</a>
            ))}
            <a href={REPO_URL} target="_blank" rel="noreferrer">GitHub</a>
          </nav>
        </div>
        <div className="lp-wrap lp-footer-note">
          <p>
            An independent project — designed, engineered, and maintained solo by{' '}
            <a href="https://github.com/johan-droid" target="_blank" rel="noreferrer">Ashutosh Sahoo</a>.
            No team, no funding — just one developer building the security tooling he wished existed.
          </p>
        </div>
        <div className="lp-wrap lp-footer-legal">
          <span>MIT licensed · Open source</span>
          <span>© {new Date().getFullYear()} Next Lab · Built with precision and zero trust</span>
        </div>
      </footer>
    </div>
  );
}
