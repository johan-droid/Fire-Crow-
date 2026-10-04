# Fire Crow — Frontend Contract v1 (backend FROZEN)

The backend is frozen. Build against these execution-scoped contracts;
do not invent parallel business logic.

Base: `{API}/api/v1`. Auth: JWT bearer + cookie session
(`/auth/*`); GitHub OAuth at `/auth/github` → `/auth/github/callback`.
Health (no auth): `/health`, `/api/v1/health[/deep|/ready|/live]`.

## Audit (execution-scoped — never flatten retries into one mutable audit)

- `POST /audit/submit {repo_url, repo_branch?, commit_sha?}` → job.
  Gate: per-user active-job cap; excess → refusal (not queue growth).
  Webhook path shares the gate.
- `GET /audit/jobs` → job list (owner-scoped; foreign → 404, never 403).
- `GET /audit/job/:job_id` → job + latest execution pointer.
- `DELETE /audit/job/:job_id` → cancel (running only).
- `POST /audit/job/:job_id/retry` → attempt N+1 (terminal rows immutable).
- `GET /audit/job/:job_id/executions` → attempt history (status, snapshot
  SHA, coverage, delivery outcome per execution).
- `GET /audit/job/:job_id/phases` → phase_ledger rows.
- `GET /audit/job/:job_id/insight`, `/graph` → derived views (optional).

## Findings (per execution)

Fields: canonical `id`, `agent_source` (gitleaks|osv|semgrep),
`scanner_mode`, `title` (= rule id), `severity` (Critical…Unknown),
`file_path`, `line_number` (+cols), redacted `evidence` ([REDACTED]),
`cwe_id`/`owasp_category`/`confidence` (present ONLY when the scanner
supplied them — never infer), `metadata_json` (native fingerprint,
advisory, fixed_versions, direct, manifest), provenance
(scanner/version/parser/image). Coverage: `complete|partial|failed`;
score NULL unless complete. Failure ≠ clean, always.

## Report (deterministic, immutable, keyed by execution)

- `GET /audit/job/:job_id/report` → latest execution's report.
- `GET /audit/job/:job_id/execution/:execution_id/report` → historical.
  JSON + Markdown + HTML renderings; byte-identical regeneration;
  unfinished execution → refusal (never a partial presented as final).

## Narrative (optional explanation layer)

- `GET /audit/job/:job_id/execution/:execution_id/narrative` →
  absent (never requested / provider down) vs present AiNarrative v1.
  `POST .../narrative` → generate (validated against the exact report;
  refusal is a legitimate outcome). AI can never create/alter/remove a
  finding or change the report.

## Delivery (on-demand, execution-scoped, idempotent)

- `POST /audit/job/:job_id/execution/:execution_id/email` → SMTP to the
  account address (no destination parameter accepted).
- `POST /audit/job/:job_id/execution/:execution_id/telegram` → operator
  chat (no destination parameter accepted; hijack → 501).
  Statuses: queued→sending→sent|failed; `(execution,channel,dest,version)`
  PK; resend = new version, history additive. Delivery failure never mutates
  the report.

## GitHub

- Webhook `POST /github/webhook` (HMAC, server-side only).
- Check Run `firecrow-security-audit` on the pinned SHA: conclusion +
  counts + coverage, no inline annotations.
- Installation state: `/auth/*` GitHub connection; frontend only needs
  repo picker (owner/name + branch + optional SHA) + installation
  authorization link; tokens never reach the browser.

## Non-contract (do NOT build on these)

`POST /chat/ask` = stub ("not yet implemented"); `GET /leaderboard/` =
`{"entries": []}` stub. Both return 200 shapes; treat as absent.
