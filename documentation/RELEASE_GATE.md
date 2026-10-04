# Phase 20 — Production Audit & Release Gate (FROZEN: controlled beta, not public beta)

> **Phase status: FROZEN as a release-gate phase.** No new features, no new
> scanners, no new rules from this point. The only work permitted under this
> phase header is closing the residual evidence gates listed below.
> Fire Crow is in **controlled beta** until every P0 gate below is green.

Treating the repository as a release candidate. **No functionality was added in
this phase**: findings were fixed only where a control was genuinely broken.

## Findings fixed

| # | Finding | Enforcement point | Proof |
|---|---|---|---|
| 1 | **Backpressure gate was a non-atomic read-then-write.** `SELECT COUNT(*)` then a bare `INSERT` let concurrent submissions all observe the same live count and all insert — 6 of 6 passed a limit of 2. Under a webhook flood this is exactly the unbounded job producer the gate exists to prevent. | Gate + insert now run in one transaction behind a per-user `pg_advisory_xact_lock`, so different users never block each other and a crash releases the lock | `submission.rs`: `concurrent_submissions_from_one_user_respect_the_gate` asserts exactly 2 admitted / 4 refused; `github_app.rs`: `concurrent_distinct_events_respect_the_per_user_gate` |
| 2 | **Credential-bearing models derived `Debug`.** `User`, `GithubCredential` (two definitions), `AuthExchangeCode`, `PushSubscription`, `UserSession`, `MfaConfiguration`, `SsoProvider`, and `TurnstileVerifyRequest` printed password hashes, OAuth tokens, TOTP secrets, push keys, and SSO client secrets into any log line, panic message, or snapshot. | Manual secret-safe `Debug` impls (`redact_debug!` in `models/user.rs`; explicit impls elsewhere) | `security_regressions.rs`: `security_p20_credential_models_have_secret_safe_debug`, `security_p20_turnstile_request_debug_hides_secrets` |
| 3 | **Sandbox stderr logged verbatim.** Scanner stderr is attacker-influenced (it echoes repository content, including secrets) and was logged unbounded. | Routed through `redact_text(.., 500)` before the log | `security_p20_sandbox_stderr_is_redacted_before_logging` |
| 4 | **GitHub signup collision logged the claimant's email.** The `sqlx` unique-violation error embeds `Key (email)=(…)`. | Log now names the GitHub subject, never the address | `security_p20_signup_collision_error_hides_email` |
| 5 | **HTTP audit logger did not redact `email`/`evidence`/`snippet` keys.** | Added to the JSON redaction key set | `security_p20_logger_redacts_email_and_evidence_keys` |
| 6 | **Documentation contradicted the build.** README claimed only gitleaks ran, that osv-scanner and semgrep were "not implemented", and that Telegram delivery did not exist. All three are false. | README corrected | `documentation/RELEASE_GATE.md` (this file) |

## Executed evidence

| Gate item | Result |
|---|---|
| Full production call graph | Reviewed; one broken control found (finding 1) and fixed |
| Migrations, empty DB → current | **28/28 applied** to a fresh database; no duplicate versions |
| Migration re-run (upgrade path) | Idempotent — still 28 rows, nothing re-applied |
| Schema shape | `requested_commit_sha` CHECK, `webhook_delivery_id` UNIQUE, delivery `outcome` CHECK all present |
| GitHub App install/revocation | Covered by `tests/github_app.rs` (24 tests) |
| Concurrent webhook delivery | 8 simultaneous deliveries of one event → **one** job, one shared id |
| Concurrent user submission | 5 users → all admitted; 1 user × 6 → exactly 2 admitted |
| Retry / reaper | Dead worker → reaper → attempt 2, attempt 1 history preserved; live worker never reaped |
| Scanner resource exhaustion | Bounded in `sandbox_hardening.rs` (15 tests) |
| Secret leakage | Repository-wide sweep; findings 2–5 fixed, regression-tested |
| Report/narrative immutability | `report_persistence.rs`, `ai_narrative_persistence.rs` |
| Cross-user / cross-execution authz | `github_app.rs`, `telegram_delivery.rs` (foreign execution → 404) |
| Delivery idempotency | `email_delivery.rs` (20), `telegram_delivery.rs` (33) |
| Production configuration | Fail-closed secrets, all-or-nothing App identity, known-value rejection (`config_security.rs`, 17 tests) |
| **Live end-to-end audit** | **Real Gitleaks container against a planted vulnerable tree: 3 findings, all redacted, canonical audit + deterministic report produced, persisted, and byte-identical on regeneration. Host tree provably unmodified.** |
| Recovery after killing components | Dead worker, dead GitHub API, Redis-independence (`kill_recovery.rs`) |
| Docs vs behaviour | Finding 6 fixed |

Full suite: **690 tests, 0 failures** (prior gate; re-verified 2026-10-04:
`canonical_audit` 23 + `report` 33 + `scan_contract` 19 + `report_persistence`
10, all green against live Postgres).

```text
Public-beta gate (2026-10-04):
[✓] cargo audit (5 vulns classified, 0 need a change; no blind update)
[✓] live Gitleaks (prior gate: 3 findings, redacted, persisted, identical regen)
[✓] live OSV (5 E2Es: vuln + fixed + transitive + cargo + clean)
[✓] live Semgrep (3 E2Es: vuln + clean discrimination + empty-never-clean)
[✓] complete canonical persistence (Gitleaks live E2E; OSV-flavoured test open)
[✓] deterministic report reconstruction (byte-identical regen, live-proven)
[✓] GitHub App workflow (24 tests)
[✓] concurrency/backpressure (per-user advisory-lock gate; 8×webhook→1 job)
[✓] secret-leak sweep (findings 2–5 fixed + regression tests)
[✓] migration/recovery (28/28 fresh, idempotent re-run, kill-recovery)
[✓] scanner isolation (sandbox hardening, 15 tests; OSV=sole bridge exception)
[✓] cross-user authorization (foreign execution → 404)
[✓] retry/cancellation/reaper (attempt history, live-worker safety)
[✓] delivery isolation (email 20, telegram 33, idempotent)
[ ] production load evidence (P1: multi-user/multi-worker soak under gate)
[ ] live Gemini smoke test (P1/optional: needs GEMINI_API_KEY; outage → audit+no-narrative)
```

## Not executed (explicitly unproven)

- **Live Gemini smoke test.** Credential-gated, unchanged since Phase 16.
  Opt-in only (`FIRECROW_LLM_LIVE=1`, `GEMINI_API_KEY`, `GEMINI_MODEL`;
  see `documentation/LLM_PROVIDER.md`). No credential is present in this
  environment, so this gate is still open. It does not block the security
  core: a Gemini outage must always yield `successful deterministic audit +
  no narrative`, never a failed audit.
- **Load/throughput testing.** No soak or concurrent-worker benchmark was run.
  The COUNT→INSERT race found in this phase is fixed and regression-tested
  (finding 1), but a multi-user / multi-worker soak under backpressure is
  still open (P1).
- **Live OSV→Postgres→report→API persistence path as one test.** The live
  OSV and Semgrep E2Es below prove tool→finding; the Gitleaks live E2E proves
  finding→Postgres→report→reconstruction. A single live test chaining
  OSV/Semgrep findings through Postgres persistence and API reconstruction
  does not exist yet.

## Executed 2026-10-04 (residual-gate closure, part 1: cargo audit)

`cargo-audit 0.22.2` vs advisory DB `ef6173cb` (1290 advisories, 2026-10-03)
over production `Cargo.lock` (570 deps). Raw JSON: `/tmp/cargo_audit.json`.

**5 vulnerabilities, 0 requiring a dependency change. No `cargo update` run.**

Duplicate transitive versions (`--duplicates`: 115 groups / 283 packages)
are **not** findings — normal unification; audit reports no advisory on them.

- `h2 0.3.27` RUSTSEC-2026-0258 (low DoS): reachable only via
  `aws-smithy-http-client → hyper 0.14.32` (S3/R2 path, operator-controlled
  endpoints). Fix `>=0.4.16` is incompatible with the AWS SDK's pinned
  hyper-0.14 line — upgrade vehicle is the AWS SDK's hyper-1 migration, not
  this gate. **Accepted risk.**
- `rsa 0.9.10` RUSTSEC-2023-0071 (Marvin, no fix available): **unreachable** —
  enters only via optional `sqlx-mysql`, which Fire Crow never enables
  (forward tree shows only `sqlx-postgres`+`sqlx-sqlite`; `cargo tree
  --edges normal -i rsa` is empty). **No action possible.**
- `rustls-webpki 0.101.7` ×3 (CRL panic + 2 name-constraint): legacy
  `rustls 0.21` line inside the AWS SDK. Fire Crow never parses CRLs
  (`grep crl` hits only JWT revocation tables). Fixed `0.103.15` already
  in-tree on the modern line. Same AWS-SDK upgrade vehicle. **Accepted.**
- `adler 1.0.2` + `tokio-io 0.1.13` (unmaintained, no CVE): load-bearing via
  `flate2 1.0.22` (tarball gzip decode). `flate2 1.1.x` drops both but
  renames the `tokio` feature — a code change, tracked for next touch of
  `agents/fetch.rs`, not snuck into a frozen gate. **Accepted with path.**
- `chacha20 0.10.1` (yanked): **not in the production graph** (optional
  reqwest `http3` → `quinn` chain, never enabled). **No action.**

## Executed 2026-10-04 (part 2: live OSV + live Semgrep)

Pinned images: `ghcr.io/google/osv-scanner:v2.2.4`,
`semgrep/semgrep:1.96.0`. Frozen ruleset
`scanners/semgrep/firecrow-sast.yml` — no new rules added.
Serial runs (`--test-threads=1`; parallel Docker-bridge runs flake).

Live OSV (`tests/osv_integration.rs`, ignored E2Es):

```text
e2e_npm_vulnerable_dependency ............ ok (1.5s)
e2e_fixed_dependency_drops_the_fixed_advisory .. ok (2.9s)
e2e_npm_transitive_dependency_is_not_direct ... ok (1.8s)
e2e_cargo_vulnerable_dependency .......... ok (1.6s)
e2e_npm_clean_repo_is_success_zero ....... ok (prior gate)
```

Proven, not just "OSV returned JSON": lodash 4.17.20 → exactly 3 findings
(5 records / 3 alias-groups, `direct=true`, `osv:` fingerprints, fixed
versions); 4.17.21 drops `GHSA-29mw-wpgm-hmr9` (range handling, no false
zero-findings claim); transitive lodash `direct=false`; regex 1.5.1 grouped
aliases on `Cargo.lock`; clean tree `Success{0}`; empty output fails closed.

Live Semgrep (`tests/semgrep_integration.rs`, ignored E2Es):

```text
e2e_vulnerable_fixture_produces_canonical_findings .. ok (~2s)
e2e_clean_fixture_proves_the_ruleset_discriminates . ok (1.7s)
e2e_empty_repository_is_never_reported_clean ...... ok (1.5s)
```

Proven: real Docker execution, exact locations, bounded evidence, CWE/OWASP/
confidence only where supplied (`CWE-89`/`A03:2021`/`HIGH`), `semgrep:`
fingerprints, clean discrimination (8 families silent on `safe.py`; the one
known SSRF review-signal is documented in `test-fixtures/semgrep/README.md`),
empty tree → `no_files_analyzed`, never clean. Raw run: 11 findings/10 rules.

Persistence note: OSV/Semgrep→canonical is proven live above; the shared
canonical→Postgres→report→API chain is proven live by the Gitleaks E2E
(`live_findings_persist_and_carry_no_live_secret`). A single OSV-flavoured
persistence test is still open (listed above).

## Verdict (2026-10-04 update — controlled beta re-affirmed)

The security-auditing core remains **production-ready for controlled beta**.

The security-auditing core is **production-ready for controlled beta**.
Before public beta, the remaining gates are: production load evidence and
the live Gemini smoke test (which never blocks the security core).
`cargo audit` and the OSV/Semgrep live paths are now closed (2026-10-04).