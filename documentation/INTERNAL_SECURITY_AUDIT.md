# FireCrow — Internal Security Audit (BASELINE / PRE-REMEDIATION)

```text
Audit status: BASELINE / PRE-REMEDIATION
Audited revision: 36f342b3f849b9fdea786322cfd730f166f1379f
Audit date (UTC): 2026-10-07
Application code modified during audit: NO
Production systems touched: NO
Full integration suite executed: NO
Production readiness: NOT APPROVED
```

> Location note: the freeze request suggested `docs/INTERNAL_SECURITY_AUDIT.md`.
> FireCrow's established convention is `documentation/*.md` (no `docs/` dir exists),
> so the baseline is frozen here as `documentation/INTERNAL_SECURITY_AUDIT.md`.

> Passing this internal audit does not prove that FireCrow contains no vulnerabilities.
> It establishes only that no in-scope issue was identified with the evidence and
> testing available during this audit.

---

## 1. Audited revision / scope / limitations

- **Revision:** `36f342b3f849b9fdea786322cfd730f166f1379f` (`git rev-parse HEAD` verified 2026-10-07, clean tree).
- **Inspected:** `backend/src` (api, agents, orchestrator, services, schemas, models, middleware, workers, config),
  `backend/migrations` (28 migrations), `backend/tests` (surveyed ~40 suites), `backend/Cargo.toml`,
  `Dockerfile`, `backend/Dockerfile`, `docker-compose.yml`, `frontend/src` (`App.tsx`, `dash.tsx`, `main.tsx`),
  `frontend/package.json`, `documentation/` (cross-checked against implementation).
- **Testing limitations (explicit):**
  ```text
  cargo fmt --check: PASS
  Full cargo test: NOT RUN (requires Postgres + Docker; scripts/test.sh provisions isolated Postgres — unavailable here)
  Container builds: NOT RUN
  Live PostgreSQL tests: NOT RUN
  Live Docker sandbox tests: NOT RUN
  Live OSV egress test: NOT RUN (H2 metadata reachability therefore LIKELY, not VERIFIED)
  Live gzip-bomb test: NOT RUN (H1 reasoned from code flow, not detonated)
  Live Gemini smoke: PENDING (credential-gated, as documented upstream)
  ```
- **Out of scope / not assessed:** physical/DC security, cloud/K8s/Vercel/Cloudflare internals,
  GitHub/Google/SMTP/Postgres/Docker-engine internals, kernel/HW/speculative execution,
  upstream scanner CVEs, third-party source, zero-days, personnel/legal/compliance certification,
  production pentest, GitHub Actions depth, frontend lockfile CVE scan, social engineering.
- **Method:** static code/config review + targeted grep/read verification of every finding
  (file:line cited). No destructive tests, no prod systems, no secret exfiltration.

### Confidence scale (preserved, not collapsed)

- **VERIFIED** — directly established from repository code/configuration/tests.
- **LIKELY** — strongly supported but requiring live/environmental verification.
- **POSSIBLE** — plausible but insufficiently demonstrated.
- **UNKNOWN** — could not be established.
- **NOT ASSESSED** — explicitly outside scope.

---

## 2. Executive summary

FireCrow's **deterministic security-truth pipeline holds**: SHA-pinned acquisition, hardened
per-scanner containers, schema-validated Canonical Audit v1, atomic finalization, DB-frozen
immutable history, score-NULL-on-partial enforced at three gates, and a structural (not
prompt-based) AI isolation boundary. Authorization is consistently `user_id`-scoped, webhooks
are HMAC-first with delivery idempotency, and archive traversal/link attacks are explicitly
rejected. Verified in source, not assumed from docs.

Weaknesses sit **around** the pipeline:

- **P0 (F1):** deployed backend mounts host Docker socket (`docker-compose.yml:43`) and runs as
  root (no `USER` in Dockerfiles). This is a VERIFIED dangerous **configuration**; actual host
  takeover additionally requires a backend RCE precondition (distinction preserved).
- **P1:** streaming resource enforcement ordered wrong (H1), unrestricted OSV bridge egress —
  bridge mode VERIFIED, metadata reachability LIKELY/PENDING live test (H2), illegal job
  transition storable (H3), token placement amplifying theft (H4).
- Deterministic truth model is sound; downgraded to PARTIAL only for the explicit
  scanner-honesty architectural assumption plus the concrete H3 defect (different categories,
  preserved separately — not treated as equal breaks).

---

## 3. Architecture reviewed (as implemented)

```text
Browser (JWT localStorage + HttpOnly cookie, SSE ?token=)
 ↓
Axum API (CORS allowlist, 20/s global + per-route limits, 10MB body layer)
 ↓
JWT auth (HS256, anti-replay jti/family, Redis-or-DB revocation) → user_id ownership gate
(tenant_id decorative; middleware/tenant.rs dead code — zero references)
 ↓
Job submit (advisory xact lock, max 2 active/user) → audit_jobs (queued)
 ↓
Worker claims (queued→running) → fetch (pinned 40-hex SHA → tarball, caps, link/traversal reject → private tempdir)
 ↓
Sequential hardened docker runs (gitleaks:v8.18.4 none / osv:v2.2.4 bridge / semgrep:1.96.0 none;
ro-root, nobody, cap-drop, no-new-privs, cgroup caps, 16MB/1MB stream caps)
 ↓
Parsers → Canonical Audit v1 (validated, redacted, exact-identity dedup)
 ↓
score (Some only if coverage complete; else NULL) → atomic finalize tx → DB freeze triggers
 ↓
Deterministic reporter (pure fn, zero I/O) → optional AI narrative (validated, never written back)
→ execution-scoped email/Telegram + Check Run
```

Corrections vs implied docs: tenant layer is claim-only decoration; `can_transition` is dead code
(tests only); branch is display-only when SHA pinned; `debug=true` opens extra CORS origins.

---

## 4. Threat model (condensed)

| Attacker | Assessment |
|---|---|
| A — malicious repo owner | Traversal/links rejected (VERIFIED); bomb OOM gap (H1). No false-clean path found. Realistic path: availability via gzip bomb. |
| B — malicious GitHub actor | OAuth single-use Lax state; webhook HMAC-first + idempotent; installation live-token-auth; SHA pinned; Check Runs server-SHA-bound. No cross-repo confusion found. Residual: broad `repo` scope (by design); unvalidated `repo_branch` (low). |
| C — malicious network endpoint | Intake charset-constrained; redirects follow reqwest default (required for codeload) with no private-IP check — trust delegated to GitHub. LLM host-allowlisted. OSV bridge unfiltered (H2). |
| D — compromised scanner | Filesystem/privilege escape: none found. Network exfil via OSV bridge: YES by design, unfiltered. Secrets/env: none passed. Cross-execution: none (sequential, unique names, --rm + rm -f). Kernel-level: UNKNOWN (no seccomp/apparmor/userns). |
| E — malicious scanner output | Bounded by stream caps + schema validation; failure → FAILED, never clean. Dedup fails safe (split, not merge). |
| F — compromised AI provider | Hallucinations structurally rejected at 3 layers (VERIFIED). Residual: misleading prose phrasing only; no state impact. |

### Trust boundaries

| # | Boundary | Attacker-controlled? | Validation | Risk |
|---|---|---|---|---|
| 1–3 | Browser→API→auth→authz | yes | JWT + anti-replay; `WHERE id=$1 AND user_id=$2` every route | Low (residual H4) |
| 4–5 | GitHub→FireCrow; repo→FireCrow | yes | HMAC sha256= ct_eq; owner/repo charset; SHA pin | Low |
| 6–7 | Archive→extractor→scanner | yes | `..`/abs/prefix reject; links hard-fail; caps (bomb gap H1) | H1 HIGH, else Low |
| 8–10 | Scanner→parser→canonical→DB | yes (schema) | stream caps; schema+redaction+dedup; freeze triggers | Low (+ scanner-honesty assumption) |
| 11–13 | DB→report→AI→FireCrow | AI untrusted | pure reporter; subset prompt; re-validated response, no truth write path | Low (prose residual) |
| 14–15 | FireCrow→GitHub/email | no (server-bound) | live installation-token auth; DB/config recipients | Low |
| 16–18 | →frontend; URLs→FireCrow; env→runtime | yes (URLs/env) | React text rendering + server escaping; intake charset; key gates fail-closed | Medium (no CSP; `GITHUB_API_BASE_URL` is operator-trust) |

---

## 5. Critical findings

### F1 — CRITICAL — Host takeover configuration: Docker-socket mount + root backend (P0)
- **Affected file:** `docker-compose.yml:43` (`- /var/run/docker.sock:/var/run/docker.sock` on `backend`); `Dockerfile:22-52`, `backend/Dockerfile:22-52` (install `docker.io`, no `USER` → root).
- **Observed behavior:** backend (which shells `docker run/rm`, `sandbox.rs:715-716,860-866`) runs as root with host-root-equivalent socket.
- **Security impact:** any backend RCE → `docker run --privileged -v /:/host …` → host FS, all secrets (`SECRET_KEY`, `GITHUB_APP_PRIVATE_KEY`, `GEMINI_API_KEY`), other tenants' snapshots, DB/Redis.
- **Attack precondition:** a backend RCE (deserialization, dependency CVE, future endpoint bug). The configuration alone does not grant a remote attacker host access — **configuration vulnerability vs exploitability distinguished and preserved**.
- **Exploitability confidence:** LIKELY (chained; requires RCE). **Evidence confidence:** VERIFIED (config read).
- **Recommended remediation:** remove `docker.sock`; non-root `USER`; scanner execution behind least-privilege socket proxy or isolated runner host.
- **Regression-test recommendation:** CI asserts no `docker.sock` mount in compose + non-root user in built image + `docker_argv` image in pinned set.
- **Scope:** In Scope.

---

## 6. High findings

### H1 — HIGH — Decompression bomb / response buffering OOM before cap checks
- **Affected file/range:** `backend/src/agents/fetch.rs:779-794` (`read_bounded`: `resp.bytes().await` buffers whole body; length checked after; `content-length` early-out attacker-optional); `:809-818` (`GzDecoder::read_to_end` inflates fully; `MAX_TOTAL_BYTES` checked after).
- **Observed behavior:** 100MB high-ratio gzip (within `MAX_DOWNLOAD_BYTES=100MB`, `:19`) inflates to GBs in worker RAM before rejection; chunked bodies with no `content-length` skip early-out.
- **Security impact:** worker OOM/kill, cross-user job starvation. No false-clean (fetch failure ≠ audit success; finalize paths null score).
- **Attack precondition:** submit (or webhook-trigger) an audit of an attacker-owned repo containing a bomb archive.
- **Exploitability:** LIKELY. **Evidence:** VERIFIED (code flow; not live-detonated).
- **Remediation:** streaming gunzip with incremental counter + early abort; chunk-streamed body with cumulative counter.
- **Regression test:** unit test feeding high-ratio gzip; assert rejection under bounded RSS / before full inflation.
- **Scope:** In Scope.

### H2 — HIGH — Unrestricted OSV bridge egress
- **Affected file/range:** `backend/src/agents/scanner.rs:298`; `backend/src/services/sandbox.rs:195-246` (comment `:208-213` claims "no metadata service" with no enforcing mechanism — claim/implementation contradiction preserved).
- **Observed behavior:**
  - **VERIFIED:** OSV receives unrestricted Docker bridge networking (sole declared exception; all other scanners `--network=none`).
  - **LIKELY:** metadata (`169.254.169.254`) / private-network reachability from a compromised OSV container (default bridge semantics; not live-probed).
  - **PENDING:** live egress test (assert `169.254.169.254` unreachable + only `osv.dev` reachable).
- **Security impact:** exploit-in-OSV-container → arbitrary egress + mounted-snapshot exfil. Requires scanner-compromise precondition. This is an unfiltered **network position**, not a container escape (distinction preserved).
- **Remediation:** filtering egress proxy (allowlist `osv.dev`/`api.osv.dev`); explicit metadata/private-IP block.
- **Regression test:** assert `docker_argv(OSV)` network is proxied/restricted; live test for metadata unreachability.
- **Scope:** In Scope (repo config) / Boundary Dependency (Docker networking).

### H3 — HIGH — Illegal `queued→completed` job transition storable; `can_transition` dead; no `audit_jobs` trigger
- **Affected file/range:** `backend/src/models/user.rs:58-75`, `backend/src/schemas/scan_contract.rs:288` (contract: Queued→Completed illegal); zero non-test call sites (grep VERIFIED — tests in `audit_lifecycle.rs`, `job_lifecycle.rs` only); `orchestrator/execution.rs:829-840` accepts `IN ('queued','running',…)`; no `audit_jobs` transition trigger (only `audit_executions_*` freeze triggers).
- **Observed behavior:** storage would accept a direct `queued→completed` write without evidence (requires worker bug / direct finalize — not reachable via normal race).
- **Security impact:** lifecycle-history corruption. Score gates still NULL it (false-clean mitigated), but history integrity breaks. **Concrete integrity defect** (category preserved; not equated with the scanner-honesty assumption).
- **Remediation:** `audit_jobs` status-transition trigger mirroring the contract.
- **Regression test:** DB test asserting `queued→completed` direct update fails.
- **Scope:** In Scope. **Evidence:** VERIFIED.

### H4 — HIGH — Session-theft amplifier: JWT in `localStorage` + token-in-URL (SSE) + 30-day refresh
- **Affected file/range:** `frontend/src/App.tsx:122,621` (localStorage token), `:492-495` (`?token=` SSE); `backend/src/middleware/auth.rs:47-66` (accepts `?token=`/`?access_token=`); `backend/src/services/auth.rs:188` (30d refresh); `config.rs:424-426` (24h access).
- **Observed behavior:** XSS-readable session with month-long window; token into history/Referer/upstream logs (app log redacts; upstream may not). HttpOnly cookies already set but frontend ignores them.
- **Security impact:** credential/session compromise amplifier. No XSS sink exists today (mitigating).
- **Remediation:** cookie-only auth; remove `?token=` (cookie SSE or one-time ticket).
- **Regression test:** frontend test asserting no `localStorage` token; backend test rejecting `?token=` on non-SSE routes.
- **Scope:** In Scope. **Evidence:** VERIFIED.

---

## 7. Medium findings

### M1 — MEDIUM — Missing CSP; HTML report served as `text/html`
- **Files:** `backend/src/middleware/security_headers.rs:8-32` (nosniff/DENY/HSTS, **no CSP**); `routes_audit.rs:429,440` (`?format=html`, no `Content-Disposition: attachment`).
- **Observed:** content escaped today (`reporter.rs:19-26,467-503`; fence neutralization `:34-36`); frontend only downloads markdown. Exposure needs direct navigation + future escaping regression.
- **Remediation:** add CSP + `attachment` disposition. **Test:** header assertions on HTML report route. **Evidence:** VERIFIED. **Scope:** In Scope.

### M2 — MEDIUM — JSON/chunked request-limit gap; `/audit/submit` has no per-route limit
- **Files:** `app.rs:36-52` (pre-check reads only `Content-Length`; chunked skips 2MB JSON gate → 10MB layer); `max_json_body_bytes` (`config.rs:223-224`) never wired to extractor; `/audit/submit` relies on global 20/s + 2-active-jobs + advisory lock.
- **Remediation:** wire extractor limit; submit rate limit; SSE per-user caps. **Evidence:** VERIFIED (code) / LIKELY (exploitability; still bounded at 10MB). **Scope:** In Scope.

### M3 — MEDIUM — Missing retention/eviction
- **Files:** `services/housekeeping.rs:7-32` (only sessions-flag, login-failures-30d, exchange-codes); never `token_revocations` (per refresh/logout row), `user_sessions` rows (flag-only), `user_activity`/`activities` (frontend renders unbounded), jobs/executions/findings/reports/deliveries, workspace dirs (`config.rs:693-704`, no TTL). `retention_days` (`compliance.rs`) unenforced.
- **Impact:** privacy + disk exhaustion. **Remediation:** retention/eviction job + policy. **Evidence:** VERIFIED. **Scope:** In Scope.

### M4 — MEDIUM — Stale delivery `sending` state blocks channel (`delivery_version` hardcoded `1`)
- **Files:** `routes_audit.rs:739,827`; `delivery.rs:180-184` (crash between accept and write leaves `sending` forever; no API to advance version). Delivery never mutates audit (availability only).
- **Remediation:** version-advance endpoint or TTL-reclaim of stale `sending`. **Evidence:** LIKELY (code-read; not live-crashed). **Scope:** In Scope.

---

## 8. Low / Informational findings

- **L1 (Low):** `error.rs:334-344` `IntoResponse` renders `to_string()` for all statuses; `error_sanitizer` only rewrites 5xx → 4xx `safe_message` gate bypassed. Fix: render `safe_message` in `IntoResponse`. VERIFIED.
- **L2 (Low):** `extra_tmpfs` (`/tmp`) missing `noexec` (`sandbox.rs:621-624`) while `/work` has it. Inconsistent; low value given nobody+cap-drop+no-new-privs. VERIFIED.
- **L3 (Low):** `commit_sha` columns lack shape CHECK (`audit_jobs.commit_sha VARCHAR(64)`, executions); `repo_branch` unvalidated free text. Relies on fetch-time validation. Add CHECK + branch charset. VERIFIED.
- **L4 (Low):** No `--security-opt seccomp/apparmor`, no userns-remap, no ulimits in `docker_argv`. Kernel-exploit containment = caps/user/netns only. Add default seccomp profile. VERIFIED.
- **L5 (Low):** `validate_pinned_image` accepts any well-formed registry+tag; `run_in_sandbox(image: &str)` takes arbitrary image (no production callers today). Future-caller footgun. Add pinned allowlist. VERIFIED.
- **L6 (Low):** `audit_jobs.user_id` has no FK to `users`; `findings.execution_id` nullable + `ON DELETE SET NULL` permits orphaning on running-execution delete. Narrow window. Add FK + NOT NULL (migration). VERIFIED.
- **L7 (Low/Info):** Dead code expanding audit surface: `middleware/tenant.rs` (zero references), `services/csrf.rs` token store (Origin-check only + SameSite carry CSRF), `bcrypt` dep (argon2 used), `crypto_manager` SECRET fallback (unreachable), `password_needs_rehash` (no callers found). Remove. VERIFIED (grep).
- **L8 (Low/Info):** Floating supply chain: `rust:1.82-bookworm` + `debian:bookworm-slim` without digest; frontend `^` ranges (`react ^19`, `vite ^8`). Pin digests/lock. Previously-committed docker-compose secret now blocklisted (`config.rs:584`) — rotate if ever used in prod. VERIFIED.
- **L9 (Low):** Open registration (5/min only, 8-char password, `500` on duplicate UNIQUE → enumeration oracle). Add CAPTCHA/409 handling. LIKELY.
- **L10 (Info):** AI prose validators list-based (`ALL_CLEAR_PHRASES`, `COMPLETE_COVERAGE_PHRASES`, `CWE-/CVE-/A0n` shapes) — paraphrased all-clear passes prose checks. Blast radius prose-only (structural guarantees hold). VERIFIED.
- **L11 (Info):** `GITHUB_API_BASE_URL` env override redirects all API+tarball traffic (operator trust). Document as privileged; protect env. VERIFIED.

### Unverified risks (separate from main lists)

- Kernel/Docker-engine escape from scanner containers (no seccomp test; outside repo scope to prove). UNKNOWN.
- Upstream scanner CVEs / advisory-DB poisoning. NOT ASSESSED (external dependency).
- Production topology (ports/domains/firewall/secret store). UNKNOWN — not established from repo.

---

## 9. Security-truth assessment

> Can FireCrow incorrectly claim a repository is secure?

No false-clean path found for the standard pipeline — scanner crash/timeout/cancel/unparseable
→ `FAILED`/partial coverage → score `NULL` (gates: `canonical_audit.rs:85-90,225-254,807-834`;
`orchestrator/mod.rs:239-244,293-312,628-633,702-711`; `execution.rs:654-665`; `report.rs:184-254`).
Zero findings yields `9.0`, never `10.0`. AI cannot create/alter findings/severity/score/coverage
(three layers VERIFIED). Reports are pure functions of committed state, DB-frozen.

```text
SECURITY TRUTH VERDICT: PARTIAL
```

Two qualifications, deliberately different categories:

1. **Scanner-honesty assumption (architectural trust assumption):** a compromised scanner emitting
   valid-schema empty results is trusted for its domain (e.g., OSV "no vulns" with no lockfile is
   `clean` by design). Cross-scanner correlation absent by design (`edges: []`). The codebase is
   honest (9.0 cap, NULL-on-partial); "9.0, zero findings" means "no scanner reported anything",
   not "proven secure". This does NOT classify the deterministic pipeline as broken.
2. **H3 lifecycle-history defect (concrete integrity defect):** `queued→completed` without evidence
   is storable via worker bug/direct finalize (score gates still NULL it).

---

## 10. Sandbox assessment

```text
SANDBOX VERDICT: NO — with stated exceptions
```

- No demonstrated filesystem/privilege escape: `--network=none` default, `--read-only`,
  `--cap-drop=ALL`, `no-new-privileges`, `nobody:nogroup`, cgroup caps, tmpfs-only writes, unique
  names, `--init`, `--rm` + `rm -f`, `env_clear`, validated `:ro` mounts, structured argv.
- OSV has an unrestricted bridge network position (H2) — a network position, NOT a container escape.
- Kernel-exploit resistance UNKNOWN (no seccomp/apparmor/userns; not tested).
- Backend docker.sock/root (F1) is a separate host-boundary failure; scanners cannot reach the socket.

---

## 11. Authentication / authorization assessment

Sound. JWT + anti-replay + rotation + revocation; every job/execution/report/narrative/delivery/
artifact route gates `WHERE … user_id=$2` → `404` (no oracle, no IDOR found); execution resolution
(`execution.rs:436-458`) scopes to job after ownership; email/Telegram destinations server-bound
(DB email, config chat) — no open relay; refresh/logout revoke family. Gaps: H4 (token placement),
L7 (dead tenant/CSRF stores), L9 (registration oracle). `tenant_id` decorative — isolation is
`user_id`-only, correct until tenant middleware is actually wired.

## 12. GitHub assessment

Strong. OAuth single-use Lax `state`, referer allowlist, identity on immutable `github_id`
(no email matching), encrypted token storage. Webhook fail-closed secret, 1MB cap pre-HMAC,
raw-bytes verify, `ct_eq`, `sha256=` enforced; replay-safe via `delivery_id` PK + body-hash;
one delivery → ≤1 job (`UNIQUE webhook_delivery_id` + `ON CONFLICT DO NOTHING` + pre-gate).
Installation→repo: DB-known + unsuspended + installer-match → live token exchange → live repo check.
**Immutable-commit invariant holds on pinned path** (`fetch.rs:172-185` verbatim SHA; else
branch-head resolved then tarball at that SHA — TOCTOU collapses to the resolved SHA). Check Runs
bind server-pinned SHA, skipped when absent. Residuals: L3, broad `repo` scope (by design).

## 13. Repository acquisition assessment

Strong except H1. `normalize_repository_url` (literal `https://github.com/` + strict segments);
hand-rolled tar honors GNU-longname/PAX effective names; symlinks/hardlinks hard-fail; devices
skipped; `safe_join` rejects `..`/absolute/prefix; caps 100MB/150MB/20MB-file/20k-files; snapshot
walk never follows links; tempdir guard cleans all paths. Hole: H1 (caps checked after full
buffering). No zip path (codeload tar.gz only); no shell-outs.

## 14. Scanner assessment

Pinned images (`:latest` rejected); structured `Command::new("docker")` argv, never `sh -c` with
untrusted input; per-scanner CPU/mem/pids + pinned swap; streaming 16MB/1MB caps (breach→FAILED);
layered timeouts (120s fetch / 300/300/600 / 3600 max / 1800 worker); `kill_on_drop` + SIGTERM grace
+ `rm -f`; sequential over one snapshot. Gaps: H2, L4/L5.

## 15. Canonical Audit integrity assessment

Strong. Schema+version validated; identity `sha256(v|scanner|rule|native_fp|file|line|cols|
dep-coords|evidence_sha256)`; severity/confidence excluded by design; dedup deterministic (sort,
smallest id wins); invalid rows get `invalid-v1:` identity (never collapse — safe direction);
`correlate_findings` never merges; evidence non-empty + char-capped + credential-gated; metadata
capped + secret-scanned; redaction finite and documented as such. No malformed-output corruption
path (invalid → error, not merge).

## 16. Execution lifecycle assessment

Model + execution guards strong, job-guard missing (H3). Atomic `queued→running` claim;
`may_execute_job` refuses terminal; single-tx `finalize_execution` with `FOR UPDATE` + lease +
`status='running'` guard + cancel-wins-in-tx; heartbeat reaper (never wall-clock alone) with
re-check + `SKIP LOCKED`; terminal freeze triggers. Cancel is request-flag consumed by finalizer.
Retry creates new attempt, never mutates prior. Gap: H3 only.

## 17. Deterministic reporting assessment

Pure layer VERIFIED: report = pure fn of committed state, zero I/O; score `None` stays `None`;
failed-scanner headlines list them; `NoFilesAnalyzed` never maps to clean; HTML escapes
prose+evidence in `<pre>`; Markdown neutralizes fence-breakout. Immutability DB-enforced (reports
frozen when execution terminal; deliveries/narratives frozen/sent-locked). Report size unbounded
except evidence/metadata caps.

## 18. AI / Gemini assessment

Untrusted-service discipline VERIFIED: key as `x-goog-api-key` header only, never in prompt/URL/
logs; base-URL allowlist; streaming caps reject-not-truncate; transient-only retries ≤3; fail-closed
on missing key; prompt = report subset (zero evidence/raw code/secrets); `deny_unknown_fields` +
semantic re-validation (unknown refs, severity mismatch, `verified:true` refusal, coverage-overclaim,
invented locations, credential shapes); failure leaves truth untouched. Prompt injection
structurally inert — no write path from model text into truth tables. Residual: L10 prose.

## 19. SSRF / network assessment

Intake charset + host-pinned API good; redirects follow reqwest default (required `api→codeload`
302) with no private-IP/metadata check — acceptable only because targets derive from validated
owner/repo, not user URLs. `GITHUB_API_BASE_URL` is operator-trust (L11). Scanner default `none`;
OSV `bridge` unfiltered (H2). LLM/Telegram host-allowlisted. No other user-influenced URL clients
found. IPv6/DNS-rebinding: no specific handling — covered by H2 proxy-allowlist remediation.

## 20. Database assessment

28 migrations reviewed: init + reconciliation + hardening + atomic-commit + lifecycle +
execution-wiring + report/narrative/email/installation/webhook. Present: execution/findings/report/
narrative/delivery freeze triggers, `uq(job,attempt)`, one-running guard, advisory xact lock on
submit, `FOR UPDATE` + lease finalization. Missing: job transition trigger (H3), `commit_sha` CHECKs
(L3), `jobs.user_id` FK (L6), `findings.execution_id` NOT NULL (L6). No other concurrency-critical
app invariant found unenforced; count-then-insert is lock+tx atomic. Trigger behavior read from
migration SQL (not live-executed — stated limitation).

## 21. Frontend assessment

No XSS sink shipped (zero `dangerouslySetInnerHTML`/`innerHTML`/markdown-renderer hits; untrusted
fields as JSX text; `dash.tsx` text/SVG only) + server-side escaping — currently sound. Gaps: H4,
M1, console echo of backend errors, zero frontend tests (no `test` script; no XSS-render regression
test), floating `^` deps.

## 22. Supply-chain assessment

Backend mostly pinned; scanner images pinned; `prometheus-client 0.22` sole metrics dep
(documented cleanup — good). Issues: L8 (floating base digests, floating frontend ranges, dead
`bcrypt`), `openssl vendored` (acceptable). No lockfile CVE scan performed (recorded risk).
CI workflows not deeply audited — follow-up recommended (not claimed).

## 23. Resource-exhaustion assessment

Bounded: per-scanner CPU/mem/pids/swap, tmpfs, stream caps, archive caps (except H1 order),
10MB request layer, global+per-route limits, 2-active-jobs/user + advisory lock, LLM retries ≤3,
worker 1800s ceiling. Gaps: H1, M2 (chunked JSON), M3 (growth), SSE per-connection DB polling
without per-user cap, unbounded report size (evidence-capped only).

## 24. Concurrency assessment

DB-authoritative and well-engineered: advisory-lock submit, `FOR UPDATE` finalize + lease,
cancel-flag-in-tx, heartbeat reaper + re-check, `ON CONFLICT DO NOTHING` delivery claims, unique
narrative index (winner returned). No double-finalize/double-delivery/cross-execution-write found
except M4 (stale-`sending` liveness) and H3 (bug-gated, not race-gated).

## 25. Test-coverage gaps

Strong: ~40 suites incl. `security_regressions`, `sandbox_hardening`, `rate_limit_audit`,
`canonical_audit`, `secret_key_config`, `scan_contract`, `scan_integrity`, `atomic_audit_commit`,
`kill_recovery`. Missing: H1 bomb streaming test, H2 egress test, H3 illegal-transition DB test,
H4 token-placement tests, M1 header tests, M2 chunked-cap test, M3 eviction test, M4
stale-`sending` test, frontend XSS-render test, live Gemini smoke (PENDING — honestly marked).

## 26. Documentation contradictions

Docs unusually honest (9.0 cap, NULL-on-partial, `edges: []`, controlled-beta, redaction limits,
manual golden review, PENDING Gemini smoke). Two contradictions preserved:
(1) sandbox comment claims OSV has "no metadata service" access (`sandbox.rs:208-213`) with no
enforcing mechanism — CLAIM vs IMPLEMENTATION; (2) 2MB JSON gate implied vs 10MB effective for
chunked (M2). Plus stale tenant concepts vs dead `tenant_middleware`.

## 27. Attack chains (ranked)

1. **Host takeover (CRITICAL chain):** any backend RCE → docker.sock+root (F1) → host/secrets/all tenants. Highest blast radius; needs RCE precondition.
2. **Worker DoS:** repo gzip bomb (H1) → OOM → cross-user starvation. Most realistic external path; no exec, no false-clean.
3. **Scanner-position exfil:** scanner compromise → OSV bridge (H2) → internal/metadata + snapshot exfil. Needs scanner compromise.
4. **Session theft:** future XSS + localStorage/URL token + 30d refresh (H4) (+no CSP M1) → account + private-repo audits. Amplifier; no sink today.
5. **History corruption:** worker bug → `queued→completed` w/o evidence (H3) → misleading terminal row (score still NULL).
6. **No chain found:** repo→false-clean; AI→truth corruption; A→B report read; webhook→cross-repo status.

---

## 28. Security invariant matrix

| Invariant | Implementation | Enforcement | Test | Status |
|---|---|---|---|---|
| Immutable commit | SHA validated + verbatim; branch→SHA | Code (`fetch.rs:172-185`) | `repo_fetch`, `repo_intake` | **PASS** (L3 open) |
| Scanner isolation | ro-root, nobody, cap-drop, no-new-privs, net-none default, cgroup/tmpfs/stream caps | Code (`sandbox.rs:585-641`) | `sandbox_hardening` | **PASS with exceptions** (H2, L4) |
| Failure ≠ clean | 3 gates null score; FAILED/partial; headlines | Code + contracts | `scan_pipeline`, `report`, `scan_integrity` | **PASS** |
| Canonical integrity | schema+identity+dedup+redaction | Code | `canonical_audit` | **PASS** |
| Report immutability | pure fn + freeze triggers | DB + code | `report_persistence`, `atomic_audit_commit` | **PASS** |
| AI cannot alter truth | subset prompt + deny-unknown + semantic validation, no write path | Code + contracts | `ai_narrative*`, `llm_provider` | **PASS** (L10 prose) |
| Execution binding | exec-scoped keys; ownership-first resolve | Code | `audit_lifecycle`, `job_lifecycle` | **PASS** (H3 gap) |
| Authorization | `user_id` gate every route | Code | `iam_authorization`, `system_authorization` | **PASS** (H4 placement) |
| SSRF protection | intake charset; LLM allowlist | Code (partial) | `repo_intake` | **PARTIAL** (H2, redirect) |
| Secret isolation | header-only keys; redacted Debug/logs; encrypted tokens | Code | `secret_key_config`, `config_security` | **PASS** (H4 URL token) |
| Lifecycle legality | `can_transition` defined; finalize guards | Code only, dead contract | contract-only tests | **FAIL** (H3) |
| Availability bounds | caps/timeouts/limits | Code (mostly) | `rate_limit_audit` | **PARTIAL** (H1, M2, M3) |

---

## 29. Remediation priority (frozen — not started)

- **P0:** F1.
- **P1:** H1, H2, H3, H4.
- **P2:** M1, M2, M3, M4, L1, L3.
- **P3:** L2, L4, L5, L6, L7, L8, L9, L10.
- **Suggested phase order:** A (P0 host boundary) → B (P1 resource+network: H1, H2, H3, H4) → C (P2 app hardening) → D (P3 defense in depth) → E (re-audit vs this baseline; independent fix-vs-certify separation).

## 30. Recommended next audit phase

After P0+P1: (1) re-audit deployment + live sandbox egress test; (2) live DB trigger tests;
(3) bounded gzip-bomb RSS test; (4) cookie-only auth review; (5) Actions workflow-permission +
frontend lockfile audit; (6) credential-gated Gemini smoke. Then soak/multi-user concurrency before
any production claim.

---

## 31. Audit scope statement

1. Revision `36f342b…1379f`; dirs/components as §1. 2. Tests: `cargo fmt --check` PASS; full suite/containers/live-DB/live-Docker/live-egress/live-bomb NOT RUN; Gemini PENDING. 3. No live environments. 4. External systems not assessed (§1). 5. Verified: authz scoping, webhook HMAC/idempotency, SHA pinning, archive link/traversal rejection, sandbox argv, failure≠clean gates, canonical/AI/report immutability. 6. Unknown: kernel escape, live trigger/race behavior, prod topology. 7. Assumptions: scanners honest-but-buggy; operator env intact. 8. Limits: non-destructive, no secret exfiltration, bomb/egress from code flow.

---

## FINAL VERDICT (frozen)

### SECURITY VERDICT
```text
CONDITIONALLY READY
CONTROLLED/BETA ONLY
NOT PRODUCTION READY
```

### SECURITY TRUTH VERDICT
```text
PARTIAL
```
Pipeline preserves deterministic truth (VERIFIED) with two preserved qualifications: (1) explicit scanner-honesty architectural assumption; (2) concrete H3 history defect.

### SANDBOX VERDICT
```text
NO — with stated exceptions
```
No plausible code/filesystem escape found; OSV bridge is an unfiltered network position (not an escape); kernel resistance UNKNOWN; docker.sock/root is a separate backend host-boundary failure.

### TOP 10 ACTIONS (frozen order)
1. Remove `docker.sock`; non-root backend; least-privilege scanner runner (F1).
2. Streaming gunzip/body caps (H1). 3. OSV egress allowlist/metadata block (H2).
4. Job transition trigger (H3). 5. Cookie-only auth, kill `?token=` (H4).
6. CSP + report attachment (M1). 7. JSON/submit/SSE limits (M2). 8. Retention job (M3).
9. SHA CHECKs + branch charset (L3). 10. `safe_message` in `IntoResponse` + digest pinning + dead-code removal (L1+L8+L7).

---

## Remediation state tracking

| Finding | Severity | Baseline Status | Remediation | Re-audit |
|---|---|---|---|---|
| F1 | CRITICAL | OPEN | PENDING | REQUIRED |
| H1 | HIGH | OPEN | PENDING | REQUIRED |
| H2 | HIGH | OPEN | PENDING | REQUIRED |
| H3 | HIGH | OPEN | PENDING | REQUIRED |
| H4 | HIGH | OPEN | PENDING | REQUIRED |
| M1 | MEDIUM | OPEN | PENDING | REQUIRED |
| M2 | MEDIUM | OPEN | PENDING | REQUIRED |
| M3 | MEDIUM | OPEN | PENDING | REQUIRED |
| M4 | MEDIUM | OPEN | PENDING | REQUIRED |
| L1–L11 | LOW/INFO | OPEN | PENDING | AS APPROPRIATE |

Nothing is marked fixed. No severity changed without new evidence. Uncomfortable findings retained.
