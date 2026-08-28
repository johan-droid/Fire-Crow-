import { useState } from 'react';
import { HeroScene, TiltCard, useScrollReveal } from './scene';

/* ─── GitHub SVG icon (reused across nav, hero, footer) ────── */
const GitHubIcon = ({ size = 14 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor">
    <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.166 6.839 9.489.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.603-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.579.688.481C19.137 20.162 22 16.418 22 12c0-5.523-4.477-10-10-10z" />
  </svg>
);

/* ─── Check SVG icon (reused in trust row & pricing) ─────── */
const CheckIcon = () => (
  <svg className="pricing-feature-check" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="3">
    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
  </svg>
);

/* ─── Types ─────────────────────────────────────────────────── */
interface UserProfile {
  user_id: string;
  username: string;
  email: string | null;
  credit_balance?: number;
}

interface LandingPageProps {
  user: UserProfile | null;
  onNavigateLogin: () => void;
  onInitiateCheckout: (amount: number, packageName: string) => void;
}

/* ─── Landing Page Component ───────────────────────────────── */
export default function LandingPage({ user, onNavigateLogin, onInitiateCheckout }: LandingPageProps) {
  const [landingTab, setLandingTab] = useState<'terminal' | 'graph' | 'diff'>('terminal');
  const [billingCycle, setBillingCycle] = useState<'monthly' | 'annual'>('monthly');
  const [openFaqIndex, setOpenFaqIndex] = useState<number | null>(0);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  // Scroll-reveal choreography for landing page sections
  useScrollReveal(true, '.apple-landing-page section');

  return (
    <div className="apple-landing-page" id="top">
      {/* Ambient Atmospheric Glows */}
      <div className="apple-ambient-glow-top"></div>
      <div className="apple-ambient-glow-mid"></div>

      {/* ═══ Frosted Glass Navigation Header ═══ */}
      <header className="apple-nav">
        <div className="apple-nav-container">
          <div className="apple-logo-wrap">
            <img src="/fire-crow-logo.png" alt="Fire Crow Logo" className="logo-img" />
            <span className="apple-logo-text">Fire Crow</span>
            <div className="nav-engine-pill">
              <span className="nav-engine-dot"></span>
              <span>Engine Active</span>
            </div>
          </div>

          <nav className="apple-nav-links">
            <a href="#capabilities" className="apple-nav-link">Capabilities</a>
            <a href="#architecture" className="apple-nav-link">Pipeline</a>
            <a href="#metrics" className="apple-nav-link">Metrics</a>
            <a href="#pricing" className="apple-nav-link">Pricing</a>
            <a href="https://github.com/johan-droid/Fire-Crow-" target="_blank" rel="noreferrer" className="apple-nav-link apple-nav-link-icon">
              <GitHubIcon />
              GitHub
            </a>
          </nav>

          <div className="apple-nav-actions">
            <button onClick={onNavigateLogin} className="btn-apple-secondary nav-btn-sm">
              <GitHubIcon />
              Sync with GitHub
            </button>
            <button onClick={onNavigateLogin} className="btn-apple-primary nav-btn-sm">
              Launch Console →
            </button>

            {/* Mobile Hamburger */}
            <button
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
              className="mobile-menu-toggle"
              aria-label="Toggle Menu"
            >
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                {isMobileMenuOpen ? <path d="M18 6L6 18M6 6l12 12" /> : <path d="M4 6h16M4 12h16M4 18h16" />}
              </svg>
            </button>
          </div>
        </div>

        {/* Mobile Drawer Menu */}
        {isMobileMenuOpen && (
          <div className="mobile-drawer">
            <a href="#capabilities" onClick={() => setIsMobileMenuOpen(false)}>Capabilities</a>
            <a href="#architecture" onClick={() => setIsMobileMenuOpen(false)}>Pipeline</a>
            <a href="#metrics" onClick={() => setIsMobileMenuOpen(false)}>Metrics</a>
            <a href="#pricing" onClick={() => setIsMobileMenuOpen(false)}>Pricing</a>
            <a href="https://github.com/johan-droid/Fire-Crow-" target="_blank" rel="noreferrer" className="mobile-drawer-ext">GitHub ↗</a>
            <button onClick={() => { setIsMobileMenuOpen(false); onNavigateLogin(); }} className="btn-apple-primary mobile-drawer-cta">
              Sign In &amp; Sync with GitHub
            </button>
          </div>
        )}
      </header>

      {/* ═══ 3D Hero Section ═══ */}
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
          Fire Crow audits your repositories with autonomous LLM security agents, verifies every finding in an isolated container sandbox, and delivers compiler-tested patches. Zero false positives, SOC2-ready reports.
        </p>

        <div className="apple-hero-cta-group">
          <button onClick={onNavigateLogin} className="btn-apple-primary hero-cta-btn">
            <GitHubIcon size={18} />
            Start scanning free →
          </button>
          <a href="#capabilities" className="btn-apple-secondary hero-cta-btn">
            Explore features
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

        {/* macOS Window Preview Widget */}
        <div className="apple-preview-window">
          <div className="apple-window-header">
            <div className="apple-traffic-lights">
              <div className="apple-light apple-light-red"></div>
              <div className="apple-light apple-light-yellow"></div>
              <div className="apple-light apple-light-green"></div>
            </div>

            <div className="apple-segmented-tabs">
              <button className={`apple-tab-button ${landingTab === 'terminal' ? 'active' : ''}`} onClick={() => setLandingTab('terminal')}>Live Agent Stream</button>
              <button className={`apple-tab-button ${landingTab === 'graph' ? 'active' : ''}`} onClick={() => setLandingTab('graph')}>Attack Topology</button>
              <button className={`apple-tab-button ${landingTab === 'diff' ? 'active' : ''}`} onClick={() => setLandingTab('diff')}>Verified Patch</button>
            </div>

            <div className="apple-window-badge">
              <span className="apple-window-badge-dot"></span>
              <span>SANDBOX: EPHEMERAL_ISOLATED</span>
            </div>
          </div>

          {/* Tab 1: Agent Stream */}
          {landingTab === 'terminal' && (
            <div className="apple-tab-content terminal-tab">
              <div><span className="term-prompt">$</span> firecrow scan --repo https://github.com/org/app</div>
              <div><span className="term-blue">[intake]</span> Cloning repository and resolving dependency graph...</div>
              <div><span className="term-blue">[recon]</span> Ingesting AST structure across 84 source files.</div>
              <div><span className="term-yellow">[scanning]</span> Running SAST rules and secret detection heuristics.</div>
              <div><span className="term-purple">[ai_analysis]</span> Reasoning loop analyzing 12 candidate findings...</div>
              <div><span className="term-purple">[ai_analysis]</span> Filtering false positives via container sandbox verification.</div>
              <div><span className="term-yellow">[remediation]</span> Synthesizing non-breaking AST patches.</div>
              <div><span className="term-yellow">[attack_graph]</span> Mapping multi-node lateral movement paths.</div>
              <div><span className="term-blue">[report]</span> Compiling SOC2 compliance PDF artifact.</div>
              <div className="term-success">
                <span>✓</span> Scan complete — 4 findings confirmed, 2 patches ready.
              </div>
              <div className="term-hint">
                Sign in with GitHub to run a real scan against your repository.
              </div>
            </div>
          )}

          {/* Tab 2: Attack Topology */}
          {landingTab === 'graph' && (
            <div className="apple-tab-content topology-tab">
              <div className="topology-svg-container">
                <svg width="100%" height="220" viewBox="0 0 800 220" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path d="M140 110 L320 110" stroke="#2997ff" strokeWidth="2" strokeDasharray="6" opacity="0.5"/>
                  <path d="M480 110 L640 110" stroke="#bf5af2" strokeWidth="2" strokeDasharray="6" opacity="0.5"/>
                  <g>
                    <circle cx="120" cy="110" r="32" fill="rgba(41,151,255,0.06)" stroke="#2997ff" strokeWidth="1.5"/>
                    <text x="120" y="106" fill="#ffffff" fontSize="10" fontWeight="600" textAnchor="middle">GitHub Repo</text>
                    <text x="120" y="120" fill="#86868b" fontSize="8" fontFamily="var(--font-mono)" textAnchor="middle">AST + deps</text>
                  </g>
                  <g>
                    <rect x="340" y="82" width="100" height="56" rx="8" fill="rgba(191,90,242,0.06)" stroke="#bf5af2" strokeWidth="1.5"/>
                    <text x="390" y="106" fill="#ffffff" fontSize="10" fontWeight="600" textAnchor="middle">Security Reasoning</text>
                    <text x="390" y="120" fill="#86868b" fontSize="8" fontFamily="var(--font-mono)" textAnchor="middle">LLM Engine</text>
                  </g>
                  <g>
                    <rect x="480" y="82" width="90" height="56" rx="8" fill="rgba(255,214,10,0.06)" stroke="#ffd60a" strokeWidth="1.5"/>
                    <text x="525" y="106" fill="#ffffff" fontSize="10" fontWeight="600" textAnchor="middle">Sandbox</text>
                    <text x="525" y="120" fill="#86868b" fontSize="8" fontFamily="var(--font-mono)" textAnchor="middle">Isolated Micro-VM</text>
                  </g>
                  <g>
                    <circle cx="660" cy="110" r="32" fill="rgba(48,209,88,0.06)" stroke="#30d158" strokeWidth="1.5"/>
                    <text x="660" y="106" fill="#ffffff" fontSize="10" fontWeight="600" textAnchor="middle">Audit Vault</text>
                    <text x="660" y="120" fill="#86868b" fontSize="8" fontFamily="var(--font-mono)" textAnchor="middle">Encrypted DB</text>
                  </g>
                  <path d="M152 110 L308 110" stroke="#2997ff" strokeWidth="1.5" opacity="0.2"/>
                  <path d="M440 110 L470 110" stroke="#bf5af2" strokeWidth="1.5" opacity="0.2"/>
                  <path d="M570 110 L628 110" stroke="#30d158" strokeWidth="1.5" opacity="0.2"/>
                </svg>
              </div>
              <div className="topology-caption">
                Four isolated stages — ingestion, reasoning, sandbox verification, and persistence — with zero trust boundaries between them.
              </div>
            </div>
          )}

          {/* Tab 3: Verified Patch */}
          {landingTab === 'diff' && (
            <div className="apple-tab-content patch-tab">
              <div className="patch-tab-icon">
                <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="#bf5af2" strokeWidth="1.5" style={{ opacity: 0.6 }}>
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M9 13h6M9 17h6"/>
                </svg>
              </div>
              <div className="patch-tab-title">Findings &amp; Patches appear here after a real scan.</div>
              <div className="patch-tab-desc">
                Each finding includes severity, file location, CWE mapping, CVSS score, and an auto-generated remediation patch ready to push to your GitHub branch.
              </div>
              <div className="patch-tab-badges">
                <span className="badge badge-critical" style={{ opacity: 0.5 }}>CRITICAL</span>
                <span className="badge badge-high" style={{ opacity: 0.5 }}>HIGH</span>
                <span className="badge badge-medium" style={{ opacity: 0.5 }}>MEDIUM</span>
                <span className="badge badge-low" style={{ opacity: 0.5 }}>LOW</span>
              </div>
              <div className="patch-tab-action">
                <button onClick={onNavigateLogin} className="btn-apple-primary">Run your first scan →</button>
              </div>
            </div>
          )}
        </div>
      </section>

      {/* ═══ Bento Grid — Platform Capabilities ═══ */}
      <section id="capabilities" className="apple-bento-section">
        <div className="apple-section-header">
          <div className="apple-section-eyebrow">✦ Platform Capabilities</div>
          <h2 className="apple-section-title">Engineered for Zero False Positives.</h2>
          <p className="apple-section-sub">
            Every security finding is synthesized, verified in an isolated container sandbox, and mapped to an interactive multi-node attack graph.
          </p>
        </div>

        <div className="apple-bento-grid">
          <TiltCard className="apple-bento-card apple-bento-col-8">
            <div>
              <div className="apple-bento-icon">
                <svg className="bento-svg" viewBox="0 0 24 24" fill="none" stroke="#bf5af2" strokeWidth="1.8"><rect x="5" y="5" width="14" height="14" rx="2"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/><circle cx="12" cy="12" r="3"/></svg>
              </div>
              <h3 className="apple-bento-title">Agentic Vulnerability Reasoning</h3>
              <p className="apple-bento-desc">
                LLM reasoning agents formulate hypotheses, construct proof-of-concept exploits, and synthesize non-breaking patches — eliminating false positive alerts.
              </p>
            </div>
            <div className="bento-code-strip">
              <div className="bento-code-head"><span className="dot" style={{ background: '#bf5af2' }}></span>Reasoning Loop</div>
              <div>Hypothesize exploit path → verify against AST → generate compiler-tested patch</div>
            </div>
          </TiltCard>

          <TiltCard className="apple-bento-card apple-bento-col-4">
            <div>
              <div className="apple-bento-icon">
                <svg className="bento-svg" viewBox="0 0 24 24" fill="none" stroke="#30d158" strokeWidth="1.8"><path d="M21 8l-9-5-9 5v8l9 5 9-5V8z"/><path d="M3.3 8.3L12 13l8.7-4.7M12 13v9"/></svg>
              </div>
              <h3 className="apple-bento-title">Sandboxed Verification</h3>
              <p className="apple-bento-desc">
                Every candidate finding is proven inside an ephemeral, non-root container before it ever reaches your security report.
              </p>
            </div>
            <div className="bento-status-pill green"><span className="dot"></span>100% Isolated Runtime</div>
          </TiltCard>

          <TiltCard className="apple-bento-card apple-bento-col-4">
            <div>
              <div className="apple-bento-icon">
                <svg className="bento-svg" viewBox="0 0 24 24" fill="none" stroke="#ffd60a" strokeWidth="1.8"><path d="M13 2L4.09 12.97a1 1 0 0 0 .77 1.64H11l-1 7.39L18.91 11.03a1 1 0 0 0-.77-1.64H12l1-7.39z"/></svg>
              </div>
              <h3 className="apple-bento-title">High-Speed Async Audit Engine</h3>
              <p className="apple-bento-desc">
                Multi-threaded parallel processing engine driving sub-second AST analysis and concurrent repository scans.
              </p>
            </div>
            <div className="bento-status-metric">&lt; 2.4s AST parse latency</div>
          </TiltCard>

          <TiltCard className="apple-bento-card apple-bento-col-4">
            <div>
              <div className="apple-bento-icon">
                <svg className="bento-svg" viewBox="0 0 24 24" fill="none" stroke="#2997ff" strokeWidth="1.8"><circle cx="8" cy="15" r="4"/><path d="M10.85 12.15L19 4m-3 3l2.5 2.5M13.5 9.5L16 12"/></svg>
              </div>
              <h3 className="apple-bento-title">Just-In-Time PAM &amp; IAM</h3>
              <p className="apple-bento-desc">
                Zero-standing privilege access with temporary role elevation, immutable audit logs, and OIDC / SAML SSO integration.
              </p>
            </div>
            <div className="bento-badge-row">
              <span className="badge badge-success">Active Elevation</span>
              <span className="badge badge-low">Audit Logged</span>
            </div>
          </TiltCard>

          <TiltCard className="apple-bento-card apple-bento-col-4">
            <div>
              <div className="apple-bento-icon">
                <svg className="bento-svg" viewBox="0 0 24 24" fill="none" stroke="#2997ff" strokeWidth="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M9 13h6M9 17h6"/></svg>
              </div>
              <h3 className="apple-bento-title">Automated Compliance Reports</h3>
              <p className="apple-bento-desc">
                CVEs, remediation fixes, and CWE risk matrices compiled into SOC2 Type II &amp; ISO-27001-ready PDF artifacts.
              </p>
            </div>
            <div className="bento-status-metric blue">PDF &amp; JSON export</div>
          </TiltCard>

          <TiltCard className="apple-bento-card apple-bento-col-12">
            <div className="bento-wide-layout">
              <div className="bento-wide-text">
                <div className="apple-bento-icon">
                  <svg className="bento-svg" viewBox="0 0 24 24" fill="none" stroke="#ff453a" strokeWidth="1.8"><circle cx="5" cy="12" r="2.5"/><circle cx="19" cy="5" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="M7.3 10.8l9.4-4.6M7.3 13.2l9.4 4.6"/></svg>
                </div>
                <h3 className="apple-bento-title">Multi-Node Attack Topology Graph</h3>
                <p className="apple-bento-desc">
                  Lateral movement paths, entrypoints, database exposures, and privilege escalation chains — mapped visually node by node.
                </p>
              </div>
              <div className="bento-wide-badges">
                <span className="badge badge-critical">CWE-798 Hardcoded Secrets</span>
                <span className="badge badge-high">OWASP A01 Access Control</span>
                <span className="badge badge-low">Automated Remediation</span>
              </div>
            </div>
          </TiltCard>
        </div>
      </section>

      {/* ═══ 4-Stage Architecture Pipeline ═══ */}
      <section id="architecture" className="apple-pipeline-section">
        <div className="apple-section-wrapper">
          <div className="apple-section-header">
            <div className="apple-section-eyebrow">✦ Autonomous Lifecycle</div>
            <h2 className="apple-section-title">End-to-End Autonomous Pipeline</h2>
            <p className="apple-section-sub">
              From source code ingestion to compiler-verified patch generation and compliance delivery.
            </p>
          </div>

          <div className="apple-pipeline-grid">
            {[
              { step: '01', color: '#2997ff', title: 'Repository Ingestion', desc: 'Parses Abstract Syntax Trees (AST), dependencies, and configuration matrices via secure GitHub repository integration.' },
              { step: '02', color: '#bf5af2', title: 'Agentic Reasoning', desc: 'Security LLM reasoning loops discover architectural vulnerabilities and construct multi-node attack topology graphs.' },
              { step: '03', color: '#ffd60a', title: 'Sandboxed Testing', desc: 'Simulates exploit paths inside isolated micro-containers to confirm findings with 0% false positives.' },
              { step: '04', color: '#30d158', title: 'Patch & Delivery', desc: 'Generates ready-to-merge pull requests with verified code patches and compliance PDF reports.' },
            ].map(s => (
              <TiltCard key={s.step} className="apple-pipeline-card">
                <div className="apple-step-tag" style={{ color: s.color }}>STEP {s.step}</div>
                <h3 className="pipeline-card-title">{s.title}</h3>
                <p className="pipeline-card-desc">{s.desc}</p>
              </TiltCard>
            ))}
          </div>
        </div>
      </section>

      {/* ═══ Performance Metrics ═══ */}
      <section id="metrics" className="apple-metrics-section">
        {[
          { num: '0%', title: 'False Positive Guarantee', sub: 'Sandboxed container exploit verification' },
          { num: '< 2.4s', title: 'AST Ingestion Latency', sub: 'High-performance async parsing engine' },
          { num: '100%', title: 'Sandbox Isolation', sub: 'Zero host escape container runtime protection' },
          { num: 'SOC2', title: 'Compliance Artifacts', sub: 'Automated audit reports & ISO 27001 mapping' },
        ].map(m => (
          <div key={m.title} className="apple-metric-box">
            <div className="apple-metric-num">{m.num}</div>
            <div className="apple-metric-title">{m.title}</div>
            <div className="apple-metric-sub">{m.sub}</div>
          </div>
        ))}
      </section>

      {/* ═══ Pricing Grid ═══ */}
      <section id="pricing" className="apple-pricing-section">
        <div className="apple-section-header">
          <div className="apple-section-eyebrow">✦ Transparent Pricing</div>
          <h2 className="apple-section-title">A plan for every security posture.</h2>
          <p className="apple-section-sub">
            Initiate automated container verification scans, elevation auditing, and SOC2 compliance mapping.
          </p>

          <div className="billing-toggle-wrapper">
            <span className={`billing-label ${billingCycle === 'monthly' ? 'active' : ''}`}>Monthly</span>
            <div className="billing-toggle">
              <button className={`billing-toggle-btn ${billingCycle === 'monthly' ? 'active' : ''}`} onClick={() => setBillingCycle('monthly')}>Monthly</button>
              <button className={`billing-toggle-btn ${billingCycle === 'annual' ? 'active' : ''}`} onClick={() => setBillingCycle('annual')}>Annual <span className="billing-discount-badge">Save 20%</span></button>
            </div>
            <span className={`billing-label ${billingCycle === 'annual' ? 'active' : ''}`}>Annual</span>
          </div>
        </div>

        <div className="pricing-grid">
          {/* Starter */}
          <TiltCard className="pricing-card">
            <div>
              <div className="pricing-tier-name">Starter</div>
              <div className="pricing-price-wrap">
                <span className="pricing-price">{billingCycle === 'annual' ? '$15' : '$19'}</span>
                <span className="pricing-period">/ month</span>
              </div>
              <p className="pricing-desc">Essential automated code security reasoning for solo developers and side projects.</p>
              <ul className="pricing-features">
                {['5 Repository scans per month', 'Ephemeral sandbox validation', 'Standard email alerts', 'Basic PDF report exports'].map(f => (
                  <li key={f} className="pricing-feature-item"><CheckIcon /><span>{f}</span></li>
                ))}
              </ul>
            </div>
            <button onClick={() => user ? onInitiateCheckout(billingCycle === 'annual' ? 15 : 19, 'starter') : onNavigateLogin()} className="btn-apple-secondary pricing-cta">
              {user ? 'Upgrade to Starter' : 'Get Started'}
            </button>
          </TiltCard>

          {/* Pro */}
          <TiltCard className="pricing-card premium">
            <span className="pricing-badge">Most Popular</span>
            <div>
              <div className="pricing-tier-name accent">Pro Console</div>
              <div className="pricing-price-wrap">
                <span className="pricing-price">{billingCycle === 'annual' ? '$79' : '$99'}</span>
                <span className="pricing-period">/ month</span>
              </div>
              <p className="pricing-desc">Advanced agentic reasoning, code patches, and multi-node attack topology mapping.</p>
              <ul className="pricing-features">
                {[
                  { text: 'Unlimited repository scans', highlight: true },
                  { text: 'Advanced LLM reasoning engine' },
                  { text: 'PoC exploit path verification' },
                  { text: 'Auto-generated pull request patches' },
                  { text: 'Full interactive attack topology graphs' },
                  { text: 'SOC2 & ISO-27001 compliance PDFs' },
                ].map(f => (
                  <li key={typeof f === 'string' ? f : f.text} className="pricing-feature-item">
                    <CheckIcon />
                    <span className={f.highlight ? 'pricing-highlight' : ''}>{typeof f === 'string' ? f : f.text}</span>
                  </li>
                ))}
              </ul>
            </div>
            <button onClick={() => user ? onInitiateCheckout(billingCycle === 'annual' ? 79 : 99, 'pro') : onNavigateLogin()} className="btn-apple-primary pricing-cta">
              {user ? 'Upgrade to Pro' : 'Start Pro Free Trial'}
            </button>
          </TiltCard>

          {/* Enterprise */}
          <TiltCard className="pricing-card">
            <div>
              <div className="pricing-tier-name">Enterprise</div>
              <div className="pricing-price-wrap">
                <span className="pricing-price">{billingCycle === 'annual' ? '$399' : '$499'}</span>
                <span className="pricing-period">/ month</span>
              </div>
              <p className="pricing-desc">SLA-backed execution, private sandboxes, and zero-standing elevation permissions.</p>
              <ul className="pricing-features">
                {['All Pro features included', 'Private cloud sandbox deployments', 'Multi-tenant OIDC SSO & SAML support', 'Custom JIT permission boundary rules', '24/7 dedicated support & SLA metrics'].map(f => (
                  <li key={f} className="pricing-feature-item"><CheckIcon /><span>{f}</span></li>
                ))}
              </ul>
            </div>
            <button onClick={() => user ? onInitiateCheckout(billingCycle === 'annual' ? 399 : 499, 'enterprise') : onNavigateLogin()} className="btn-apple-secondary pricing-cta">
              Contact Sales / Upgrade
            </button>
          </TiltCard>
        </div>
      </section>

      {/* ═══ FAQ ═══ */}
      <section className="apple-faq-section" id="faq">
        <div className="apple-section-header">
          <div className="apple-section-eyebrow">✦ Frequently Asked Questions</div>
          <h2 className="apple-section-title">Everything you need to know.</h2>
          <p className="apple-section-sub">Got questions about autonomous code execution, container safety, or custom deployments?</p>
        </div>

        <div className="faq-list">
          {[
            { q: "How does Fire Crow eliminate zero-day false positives?", a: "Fire Crow doesn't rely solely on static pattern matching. It spawns an isolated, non-root container sandbox for each candidate vulnerability to dynamically compile, execute, and verify exploit vectors before reporting them." },
            { q: "Is my proprietary repository source code shared with third-party LLMs?", a: "No. Source code ASTs and repository contents are parsed locally in encrypted memory. Only anonymized code snippets required for vulnerability reasoning are transmitted via encrypted TLS endpoints." },
            { q: "Can Fire Crow be deployed on-premise or in private clouds?", a: "Yes. Enterprise plans support private Kubernetes cluster deployments, custom container registry integration, and air-gapped security orchestrators." },
            { q: "How does Just-In-Time (JIT) PAM elevation work with our IAM?", a: "Fire Crow integrates natively with OIDC and SAML 2.0 identity providers. Security architects can request temporary privilege elevation that automatically expires after a predefined TTL with immutable audit trails." },
          ].map((faq, idx) => (
            <div key={idx} className={`faq-item ${openFaqIndex === idx ? 'open' : ''}`} onClick={() => setOpenFaqIndex(openFaqIndex === idx ? null : idx)}>
              <div className="faq-question">
                <span>{faq.q}</span>
                <div className="faq-toggle-icon">+</div>
              </div>
              {openFaqIndex === idx && <div className="faq-answer">{faq.a}</div>}
            </div>
          ))}
        </div>
      </section>

      {/* ═══ CTA Banner ═══ */}
      <section className="apple-cta-section">
        <div className="apple-cta-card">
          <h2 className="cta-headline">Ready to harden your enterprise stack?</h2>
          <p className="cta-subtext">Deploy Fire Crow in your CI/CD pipeline or launch the interactive cloud console in seconds.</p>
          <div className="cta-btn-group">
            <button onClick={onNavigateLogin} className="btn-apple-primary hero-cta-btn">Start scanning free →</button>
            <a href="https://github.com/johan-droid/Fire-Crow-" target="_blank" rel="noreferrer" className="btn-apple-secondary hero-cta-btn">Explore on GitHub ↗</a>
          </div>
        </div>
      </section>

      {/* ═══ Footer ═══ */}
      <footer className="apple-footer">
        <div className="apple-footer-grid">
          <div>
            <div className="footer-brand">
              <img src="/fire-crow-logo.png" alt="Fire Crow Logo" className="footer-logo" />
              <span className="footer-brand-name">Fire Crow</span>
            </div>
            <p className="footer-desc">
              Autonomous agentic security intelligence and vulnerability hardening platform engineered for zero false positives, isolated sandboxed execution, and compliance reporting.
            </p>
          </div>
          <div>
            <div className="apple-footer-col-title">Platform</div>
            <ul className="apple-footer-links">
              <li><a href="#capabilities">Agent Capabilities</a></li>
              <li><a href="#architecture">Autonomous Pipeline</a></li>
              <li><a href="#metrics">Performance Metrics</a></li>
              <li><a href="#pricing">Pricing Plans</a></li>
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
            <div className="apple-footer-col-title">Security &amp; Trust</div>
            <ul className="apple-footer-links">
              <li><span className="footer-trust-item">SOC2 Type II Ready</span></li>
              <li><span className="footer-trust-item">ISO 27001 Mapping</span></li>
              <li><span className="footer-trust-item">Docker Sandbox Isolation</span></li>
              <li><span className="footer-trust-item">Zero-Standing Access</span></li>
            </ul>
          </div>
        </div>

        <div className="apple-footer-bottom">
          <div>© {new Date().getFullYear()} Fire Crow Security Intelligence Inc. All rights reserved.</div>
          <div className="footer-bottom-right">
            <span className="footer-legal-link">Privacy Policy</span>
            <span className="footer-legal-link">Terms of Service</span>
            <span className="footer-status-pill">
              <span className="footer-status-dot"></span>
              System Operational
            </span>
            <button onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })} className="footer-back-top">
              ↑ Back to top
            </button>
          </div>
        </div>
      </footer>
    </div>
  );
}
