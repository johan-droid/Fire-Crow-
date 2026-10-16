/**
 * Fire Crow Landing Page Data & Content Model.
 * Grounded in actual scanner architectures, canonical finding shapes,
 * and verified platform capabilities.
 */

export interface FindingMock {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  scanner: string;
  filePath: string;
  lineNumber: number;
  cwe: string;
  cvss: number;
  evidence: string;
  remediation: string;
  description: string;
}

export interface PipelineStage {
  step: string;
  name: string;
  scanner: string;
  duration: string;
  status: 'passed' | 'completed' | 'verified';
  summary: string;
}

export interface CapabilityItem {
  id: string;
  title: string;
  eyebrow: string;
  description: string;
  technicalDetail: string;
  badge: string;
}

export interface WorkflowStep {
  number: string;
  title: string;
  description: string;
  specs: string[];
}

export interface PricingTier {
  id: 'starter' | 'pro' | 'enterprise';
  name: string;
  tagline: string;
  priceMonthly: number;
  priceAnnual: number;
  popular?: boolean;
  features: Array<{ text: string; highlight?: boolean }>;
  ctaLabel: string;
}

export interface FAQItem {
  id: string;
  question: string;
  answer: string;
}

/* ─── Real findings reflecting actual Semgrep, OSV, and Gitleaks output ─── */
export const SAMPLE_FINDINGS: FindingMock[] = [
  {
    id: 'FC-SEC-01',
    title: 'Hardcoded JSON Web Token Secret in Configuration',
    severity: 'critical',
    scanner: 'gitleaks v8.18.2',
    filePath: 'backend/src/config.rs',
    lineNumber: 44,
    cwe: 'CWE-798: Use of Hard-coded Credentials',
    cvss: 8.9,
    evidence: 'let secret_key = b"super-secret-production-signing-key-001";',
    remediation: 'Load secret keys from environment variables or a secure key management service (KMS). Never commit secrets into source control.',
    description: 'High-entropy credential scan detected a static symmetric signing key committed directly into repository configuration.',
  },
  {
    id: 'FC-DEP-02',
    title: 'Known Prototype Pollution Vulnerability in Dependency',
    severity: 'high',
    scanner: 'osv-scanner v1.7.0',
    filePath: 'package.json',
    lineNumber: 28,
    cwe: 'CWE-1321: Improperly Controlled Modification of Object Prototype',
    cvss: 7.5,
    evidence: '"minimist": "0.0.8" // Affected range <0.2.4 (GHSA-vh95-rm6w-qq85)',
    remediation: 'Upgrade minimist to version 0.2.4 or higher to patch known prototype pollution exploit vectors.',
    description: 'Upstream OSV database query matched an installed package against CVE-2020-7598 with confirmed remote exploitability.',
  },
  {
    id: 'FC-SAST-03',
    title: 'Unsanitized Archive Path Extraction (Path Traversal)',
    severity: 'medium',
    scanner: 'semgrep v1.62.0',
    filePath: 'backend/src/agents/fetch.rs',
    lineNumber: 89,
    cwe: 'CWE-22: Improper Limitation of a Pathname to a Restricted Directory',
    cvss: 6.5,
    evidence: 'let dest_path = target_dir.join(entry.path()?); // Missing prefix check',
    remediation: 'Enforce canonical path validation: ensure normalized destination begins strictly with target_dir before unpacking archive entries.',
    description: 'Static taint analysis identified archive entry extraction without validating that the target path does not escape the unpack directory.',
  },
];

/* ─── Verified Scanner Pipeline Stages ─── */
export const PIPELINE_STAGES: PipelineStage[] = [
  {
    step: '01',
    name: 'Bounded Intake',
    scanner: 'fetch.rs',
    duration: '0.38s',
    status: 'completed',
    summary: 'Clones your branch with a 50MB cap and verifies the exact commit SHA.',
  },
  {
    step: '02',
    name: 'Secret Detection',
    scanner: 'Gitleaks',
    duration: '0.64s',
    status: 'completed',
    summary: 'Entropy & regex audit for leaked API keys, tokens, and certificates.',
  },
  {
    step: '03',
    name: 'SAST Rule Engine',
    scanner: 'Semgrep',
    duration: '1.28s',
    status: 'completed',
    summary: 'Static analysis checking OWASP Top 10, injection paths, and insecure calls.',
  },
  {
    step: '04',
    name: 'Dependency CVE Audit',
    scanner: 'OSV-Scanner',
    duration: '0.72s',
    status: 'completed',
    summary: 'Cross-reference dependencies against Open Source Vulnerability feeds.',
  },
  {
    step: '05',
    name: 'Canonical Ledger',
    scanner: 'Audit Aggregator',
    duration: '0.18s',
    status: 'verified',
    summary: 'Deduplicates findings, computes CVSS, and locks in the risk score.',
  },
];

/* ─── Platform Capabilities (Truthful, implemented features) ─── */
export const CAPABILITIES: CapabilityItem[] = [
  {
    id: 'isolation',
    eyebrow: 'CONTAINER SECURITY',
    title: 'Ephemeral Sandbox Isolation',
    description: 'Scanners execute inside disposable, non-root micro-containers with --cap-drop=ALL, read-only repository mounts, and no route off the host.',
    technicalDetail: 'Semgrep and Gitleaks run with --network=none. OSV-Scanner attaches only to an internal network whose single reachable destination is a filtering egress proxy. Container workspaces are destroyed on completion; code is never stored or used for model training.',
    badge: 'Zero Host Access',
  },
  {
    id: 'tri-engine',
    eyebrow: 'COMPREHENSIVE COVERAGE',
    title: 'Tri-Engine Scanner Orchestration',
    description: 'Orchestrates Semgrep for static code analysis, Gitleaks for high-entropy secret detection, and OSV-Scanner for known open-source CVEs.',
    technicalDetail: 'Unified schema parses heterogeneous tool outputs into structured, normalized finding models.',
    badge: '3 Scanner Engines',
  },
  {
    id: 'deterministic',
    eyebrow: 'OBJECTIVE VERIFICATION',
    title: 'Deterministic Risk Scoring',
    description: 'Security risk scores (0–100) are computed mathematically from verified findings and severity weights—never estimated or hallucinated.',
    technicalDetail: 'Score model: weighted deductions per critical, high, medium, and low finding with transparent formula auditability.',
    badge: 'Mathematical Ledger',
  },
  {
    id: 'bounds',
    eyebrow: 'INGESTION HYGIENE',
    title: 'Stream-Bounded Repository Intake',
    description: 'Enforces strict decompression bounds (50MB ceiling), commit SHA verification, and branch validation to prevent archive bomb exploits.',
    technicalDetail: 'Stream parser halts immediately upon exceeding size or entry thresholds before scanner launch.',
    badge: 'Anti-Bomb Defense',
  },
  {
    id: 'ai-boundary',
    eyebrow: 'ARCHITECTURAL INTEGRITY',
    title: 'Strict AI Narrative Boundary',
    description: 'Optional LLM executive summaries operate exclusively as a read-only reporting layer. AI can never alter scores or invent findings.',
    technicalDetail: 'Separation of concerns: audit findings are frozen before passing to the narrative provider.',
    badge: 'Read-Only AI Layer',
  },
  {
    id: 'artifacts',
    eyebrow: 'AUDIT REPORTING',
    title: 'Exportable Audit Artifacts',
    description: 'Generate structured JSON ledgers, printable HTML views, and Markdown reports on demand.',
    technicalDetail: 'Cryptographically hashed audit records with full execution timestamps and scanner version metadata. These are audit artifacts, not a compliance certification.',
    badge: 'JSON / HTML / Markdown',
  },
];

/* ─── 4-Step Verified Workflow ─── */
export const WORKFLOW_STEPS: WorkflowStep[] = [
  {
    number: '01',
    title: 'Stream-Bounded Intake',
    description: 'Fire Crow ingests your target branch or commit SHA with streaming bounds validation, ensuring repositories meet size and format constraints.',
    specs: ['Commit SHA attestation', '50MB unpack ceiling', 'Header validation'],
  },
  {
    number: '02',
    title: 'Sandboxed Scanner Execution',
    description: 'Dedicated scanner containers spin up with zero host privileges, mounting source files in read-only mode to prevent script execution.',
    specs: ['--cap-drop=ALL', 'Read-only source mount', 'Internal-only network'],
  },
  {
    number: '03',
    title: 'Canonical Normalization',
    description: 'Scanner outputs are deduplicated, anchored to exact file paths and line numbers, and enriched with CWE classifications and CVSS metrics.',
    specs: ['Fingerprint deduplication', 'CWE & OWASP mapping', 'CVSS 3.1 scoring'],
  },
  {
    number: '04',
    title: 'Deterministic Report & Export',
    description: 'The audit results are finalized into an immutable security ledger with mathematical scoring, actionable remediation, and optional AI summaries.',
    specs: ['Deterministic score (0-100)', 'Actionable remediation', 'JSON / HTML / Markdown export'],
  },
];

/* ─── Truthful Pricing Tiers (Matching onInitiateCheckout contract) ─── */
export const PRICING_TIERS: PricingTier[] = [
  {
    id: 'starter',
    name: 'Starter',
    tagline: 'Essential repository security scanning for individual developers.',
    priceMonthly: 19,
    priceAnnual: 15,
    features: [
      { text: '5 Repository audits per month' },
      { text: 'Tri-engine scanning (SAST, Secrets, CVEs)' },
      { text: 'Ephemeral container isolation' },
      { text: 'Standard JSON, HTML & Markdown report exports' },
      { text: 'Community support via GitHub' },
    ],
    ctaLabel: 'Get Started',
  },
  {
    id: 'pro',
    name: 'Pro Console',
    tagline: 'Comprehensive security intelligence for engineering teams.',
    priceMonthly: 99,
    priceAnnual: 79,
    popular: true,
    features: [
      { text: 'Unlimited repository audits', highlight: true },
      { text: 'Priority scanner container execution' },
      { text: 'Tri-engine analysis (Semgrep, OSV, Gitleaks)' },
      { text: 'Optional AI executive narrative briefing' },
      { text: 'Cryptographically hashed audit records' },
      { text: 'Interactive audit findings explorer' },
    ],
    ctaLabel: 'Start Pro Trial',
  },
  {
    id: 'enterprise',
    name: 'Enterprise',
    tagline: 'Dedicated capacity and custom configurations for security teams.',
    priceMonthly: 499,
    priceAnnual: 399,
    features: [
      { text: 'Everything in Pro Console' },
      { text: 'Custom scanner concurrency limits' },
      { text: 'Self-hosted Docker runner integration' },
      { text: 'Custom rule configuration & exclusions' },
      { text: 'Dedicated 99.9% scanning SLA' },
      { text: 'Direct security engineering support' },
    ],
    ctaLabel: 'Contact Sales',
  },
];

/* ─── Truthful Technical FAQ ─── */
export const FAQ_ITEMS: FAQItem[] = [
  {
    id: 'faq-1',
    question: 'How does Fire Crow prevent repository code leaks?',
    answer: 'Scanners execute inside isolated, non-root micro-containers with read-only repository mounts and stripped Linux capabilities (--cap-drop=ALL).\n\nRepository archives are deleted immediately upon completion of the scan, and code is never stored or used to train machine learning models.',
  },
  {
    id: 'faq-2',
    question: 'Can the AI narrative summary modify my security score or findings?',
    answer: 'No. By architectural design, audit findings, severities, and risk scores are mathematically frozen in the canonical ledger before the narrative agent is invoked.\n\nThe AI functions strictly as a read-only briefing writer with zero write access to the findings database.',
  },
  {
    id: 'faq-3',
    question: 'What happens if a scanner tool encounters an error or timeout?',
    answer: 'Fire Crow reports engine status truthfully. If a scanner fails, times out, or is unavailable, the job status reflects partial or engine_unavailable rather than falsely presenting a clean bill of health.\n\nWe do not generate false green indicators under degraded scanner conditions.',
  },
  {
    id: 'faq-4',
    question: 'What scanners are included in the standard audit pipeline?',
    answer: 'Fire Crow orchestrates three industry-standard tools: Gitleaks for high-entropy secret detection, Semgrep for rule-based static application security testing (SAST), and Google OSV-Scanner for identifying known vulnerabilities in dependencies.\n\nEach engine runs in parallel within dedicated isolation boundaries.',
  },
  {
    id: 'faq-5',
    question: 'How do I download or share audit reports?',
    answer: 'Every completed audit can be viewed in the interactive console or downloaded as a standalone JSON data ledger, printable HTML view, or a Markdown report.\n\nReports include cryptographic verification hashes and line-level remediation evidence.',
  },
];
