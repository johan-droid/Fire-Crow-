# Fire Crow — Use Cases

Who Fire Crow serves and what each user can do. Every claim below maps to
an implemented API surface under `/api/v1` (see `backend/src/app.rs`).

## 1. Audit a repository for security issues (core)

Submit a GitHub repository (or connected account repository) as an audit
job. Three isolated scanners run with separated privileges:

- **Gitleaks** — leaked secrets and credentials (`--network=none`).
- **Semgrep** — static-analysis findings with the pinned rulepack
  (`--network=none`).
- **OSV** — known vulnerabilities in dependencies, via the controlled
  egress proxy (the only scanner allowed external network access).

Each scanner's success or failure is recorded separately. A failed scanner
is reported as failed — never as zero findings.

## 2. Read a deterministic, coverage-honest report

Every finished execution produces a canonical audit report (Markdown, JSON,
or HTML) with a coverage verdict: **Complete**, **Partial**, or **Absent**,
plus which scanners succeeded. Partial coverage is shown as partial
everywhere — report views, exports, email artifacts, and the AI narrative
is instructed never to claim full coverage from a partial audit.

## 3. Track jobs over time

List jobs, inspect per-job detail (findings, phase ledger, execution
history), cancel or retry jobs, and watch live progress over SSE with
polling fallback. Retries never erase previously established findings.

## 4. Get an AI executive narrative (optional, supplementary)

Generate a plain-language summary of an execution's findings via the
configured model provider. The narrative is advisory only: it never
determines the verdict and never replaces scanner evidence.

## 5. Receive and share results

Email or Telegram delivery of execution reports with truthful delivery
status (accepted vs. confirmed), downloadable report artifacts, and a
team dashboard with job history.

## 6. Sign in securely, work in isolation

Password + TOTP MFA (with single-use recovery codes), GitHub OAuth,
session/refresh-token lifecycle with revocation, CSRF-protected mutations,
and per-tenant isolation: users can only read, cancel, or download their
own jobs, reports, and artifacts.

## 7. Connect GitHub organizations (App / OAuth)

List account repositories for audit intake and receive webhook deliveries.
The app requests only the permissions needed for intake; repository
credentials are redacted from logs, reports, and error output.

## 8. Operate and monitor (self-hosted / demo)

Health (`/health`), readiness (`/api/v1/health/ready`), and deep checks;
graceful shutdown; rate-limited public endpoints; audit logging of
authentication and security events.

## Non-goals and honest limitations

- Fire Crow reports what its scanners found — it does not guarantee
  detection of all vulnerabilities and claims no certification.
- Real scanner execution requires the supported Docker topology (mTLS
  daemon channel + authorization plugin + isolated networks). Deployments
  that cannot enforce this boundary (e.g. Render free tier) run as
  **preview/demo without real scans**, and the UI must label them so.
- The free-tier demo may cold-start (backend sleeps after inactivity);
  the UI shows indeterminate status during wake-up, never fake success.
