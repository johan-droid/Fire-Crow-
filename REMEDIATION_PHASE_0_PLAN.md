# FireCrow — Phase 0 Remediation Plan

**Baseline:** `main` @ `52e6cc2`, working tree clean.
**Date:** 2026-09-30
**Scope of this document:** reconcile the two supplied audits against the *current* code, then fix the five P0-class findings plus the product-integrity (P0-C) finding.

---

## 1. Current repository state

Verified directly, not taken from the audit reports.

| Fact | Value | How verified |
|---|---|---|
| HEAD | `52e6cc2` | `git log --oneline -3` |
| Working tree | clean | `git status --short` → empty |
| Branch | `main` | `git rev-parse --abbrev-ref HEAD` |
| Rust source files | 103 | `find backend/src -name '*.rs' \| wc -l` |
| Rust LOC | 7,397 | `wc -l` |
| Migrations | 15 | `find backend/migrations -name '*.sql' \| wc -l` |
| Tests | **0** | no `#[test]`, `#[tokio::test]`, `#[cfg(test)]`, no `backend/tests/` |
| CI | **none** | no `.github/`; `.dockerignore:2` ignores a dir that does not exist |
| Dockerfile | **absent** | `find -iname 'Dockerfile*'` → empty; referenced by compose |
| `cargo check` | passes | executed, exit 0 |
| Committed secrets | 1 live-shaped | compose key defaults (§4 P0-2) |
| `LICENSE` | absent | `ls LICENSE*` → no match, despite README badge + `license = "MIT"` |

The repository has not drifted since the audits were written. Every finding below was re-confirmed by reading the current file at the cited line.

---

## 2. Audit finding reconciliation

Classification per the required scheme.

| ID | Finding | Class | Evidence re-checked |
|---|---|---|---|
| P0-1 | UTF-8 boundary panic in HTTP logger, outside `CatchPanicLayer`, under `panic = "abort"` | **CONFIRMED** | `middleware/http_logger.rs:62,79`; `main.rs:199,201`; `Cargo.toml:76` |
| P0-1b | Full request URI (incl. query string) logged, so `?token=<JWT>` is written to logs in plaintext | **CONFIRMED** (new, found while re-reading) | `http_logger.rs:95` → `:112,131,144` |
| P0-2 | Publicly-known default `SECRET_KEY`/`ENCRYPTION_KEY` committed in compose | **CONFIRMED** | `deploy/cloudflare/docker-compose.cloudflare.yml:48-49` |
| P0-2b | Those two defaults are *identical*, which `config.rs:292-301` hard-rejects → compose cannot boot | **CONFIRMED** | read both files |
| P0-3 | `SECRET_KEY` silently replaced with a source-visible constant when unset; `debug` defaults true | **CONFIRMED** | `config.rs:239-244,261-267` |
| P0-4 | `client_secret` decrypted and returned by every SSO read path | **CONFIRMED** | `services/sso_service.rs:15-19,45-51` |
| P0-5 | GitHub OAuth links/mints a session on unverified email match | **CONFIRMED** | `api/routes_auth.rs:397-410,412-424,448` |
| P0-C | SAST / recon / AI analyzer / LLM / sandbox are stubs; findings are fabricated | **CONFIRMED** | `agents/sast.rs`, `agents/ai_analyzer.rs:4-9`, `agents/mod.rs:11-22`, `services/llm.rs:18-22`, `services/sandbox.rs` |
| S-1 | Rate limiter + audit log keyed on spoofable `CF-Connecting-IP`; CF middleware applied *inside* the governor | **CONFIRMED** | `main.rs:212-220`; `rate_limit.rs:16-24`; `cloudflare.rs:78-85` |
| S-11 | `is_allowed_origin` hardcodes localhost in all environments | **CONFIRMED** | `routes_auth.rs:507-525` |
| S-13 | Token in `localStorage` defeats the `httpOnly` cookie | **CONFIRMED** | `App.tsx:121-134` |
| R-7 | `findings.metadata_json` is `JSONB`, bound as `Option<String>` | **REQUIRES RUNTIME VERIFICATION** | `orchestrator/mod.rs:112,122` vs `migrations/...init_schema.sql:48` |
| R-16 | 13 `FromRow` structs require columns that no migration creates | **CONFIRMED** | `models/*.rs` vs `migrations/*` |
| R-17 | `main.rs` and `lib.rs` each declare all 13 modules; lib is unreferenced | **CONFIRMED** | `main.rs:11-23`, `lib.rs:5-17` |
| "Push unsubscribe returns fake success" | suspect finding | **FALSE POSITIVE** | reclassified: `routes_push.rs` returns `501 Not Implemented` in current code, not a fake 200 |
| "PAM revoke unaudited" | reported as a bug | **PARTLY FALSE POSITIVE** | the `pam_audit` insert is correct SQL; the *table* is missing from migrations (a schema gap, not a silent-failure bug) |

**Corrections to the audit reports:**
1. The reports described the release-build panic as "one-request connection reset." That understates it. With `panic = "abort"` (`Cargo.toml:76`) and `Procfile` running `cargo run --release`, the **entire process terminates**, taking the API, both workers, and all in-flight jobs. Treated as P0 on that basis.
2. The reports treated the push/PAM stubs as returning fake success. Re-checked: they return `501`. The product-integrity problem is concentrated in the scanner, not in these endpoints. The feature-deletion decision (Phase 5) still applies but for different reasons.
3. P0-1b (JWT logged from the query string) was reported under the SSE finding, not under the logger. It belongs to P0-1 and is fixed in the same commit, because it is the same function and the same `tracing` call.

---

## 3. Confirmed P0/P1 findings and evidence

### P0-1 — Unauthenticated remote process termination

```rust
// backend/src/middleware/http_logger.rs:57-62
if let Ok(utf8_str) = std::str::from_utf8(bytes) {
    if let Ok(mut json_val) = serde_json::from_str::<serde_json::Value>(utf8_str) {
        redact_json_value(&mut json_val);
        let s = json_val.to_string();
        if s.len() > max_len {
            format!("{}... [truncated]", &s[..max_len])   // <-- byte index
```
`:78-79` repeats it for the non-JSON branch. `max_len` is `800` (`:110,142`). `s.len()` is **bytes**. If byte 800 falls inside a multi-byte sequence, `&s[..800]` panics with *"byte index 800 is not a char boundary"*.

**Compounding conditions, all confirmed:**
- `http_audit_logger` is applied at `main.rs:201`; `CatchPanicLayer` at `main.rs:199`. In axum, the **last** `.layer()` is the **outermost**, so `CatchPanicLayer` is *inside* `http_audit_logger` and cannot catch this panic.
- `Cargo.toml:76` sets `panic = "abort"` under `[profile.release]`. A panic is then not a panic — it is process termination.
- The middleware runs on **every** request (`http_logger.rs:90`).
- The cheapest reachable trigger is `POST /api/v1/auth/policy-events` (`routes_auth.rs:502`), which has **no auth extractor** and an untyped JSON body, so the body is fully attacker-controlled and reaches `safe_payload_snippet` at `:110` *before* any handler runs.

**Why P0:** a single unauthenticated HTTP request terminates the process, losing the API, both workers, every in-flight scan, and every SSE stream.

### P0-1b — Bearer token written to the application log

```rust
// backend/src/middleware/http_logger.rs:95
let uri = req.uri().to_string();          // includes ?token=<jwt>
...
// :112, :131, :144
info!(target: "http_audit", "[HTTP REQ] {} {} | ...", method, uri, ...);
```
`middleware/auth.rs:45-64` accepts `?token=` / `?access_token=` on **every** `AuthenticatedUser`-guarded route, and `frontend/src/App.tsx:514-517` puts the access token there. The redaction helper `redact_json_value` only walks body JSON; the URI is never redacted. Result: a 24-hour bearer token (`config.rs:195`) lands in plaintext in logs on every SSE connect.

### P0-2 — Committed, publicly-known signing key

```yaml
# deploy/cloudflare/docker-compose.cloudflare.yml:48-49
SECRET_KEY:    ${SECRET_KEY:-a7f3b8c2...d2e3f4a}
ENCRYPTION_KEY:${ENCRYPTION_KEY:-a7f3b8c2...d2e3f4a}
```
The default is 64 hex chars, so it **passes** `config.rs:275` (`len() < 32`) and is **absent** from the `insecure_dev_values` denylist (`config.rs:254-259`). It is therefore accepted as a production key. Anyone with the repo can forge a JWT for any `sub`.

P0-2b: because the two defaults are byte-identical, `config.rs:292-301` returns `Err`, `Settings::new()` fails, and `main.rs:49-52` returns `Err` — **the committed compose file cannot start the backend.** The two defaults are simultaneously a hardcoded secret and non-functional.

**Treated as compromised.** The value is in git history and must be considered burned on any environment that ever used the default.

### P0-3 — Fail-open default silently installs a source-visible signing key

```rust
// backend/src/config.rs:239-244
let run_mode = std::env::var("RUN_MODE").unwrap_or_else(|_| "development".into());
.set_default("debug", run_mode == "development")?      // unset RUN_MODE => debug = true
// :261-267
if settings.debug {
    if settings.secret_key.is_empty() {
        settings.secret_key = "local_dev_secret_key_change_me_1234567890_DO_NOT_USE_IN_PRODUCTION".into();
    }
```
Deploy with `DATABASE_URL` set but `SECRET_KEY` and `RUN_MODE` unset, and the server boots green, logs `"Environment: development | Debug: true"`, and signs every token with a constant published at `config.rs:263`. **Complete authentication bypass, no error, no warning.**

The same `debug` flag also disables the global rate limiter and the Cloudflare middleware (`main.rs:209-211`), disables `error_sanitizer` so raw Postgres errors reach clients (`error_sanitizer.rs:18-20`), adds six localhost CORS origins (`config.rs:319-326`), and `is_allowed_origin` hardcodes localhost with **no debug gate at all** (`routes_auth.rs:507-525`).

Root cause: **one boolean controls five unrelated security controls.** Fixing the boolean alone leaves the architecture in place.

### P0-4 — Every OIDC client secret readable by any authenticated user

```rust
// backend/src/services/sso_service.rs:14-20
for mut p in providers {
    if let Some(secret) = &p.client_secret {
        if let Ok(decrypted) = crypto.decrypt_secret(secret) {
            p.client_secret = Some(decrypted);     // plaintext
        }
    }
    result.push(p);   // SsoProvider: Serialize -> secret is serialized
}
```
`list_providers` is reachable at `routes_sso.rs:15` behind `AuthenticatedUser`, and again via `routes_dashboard.rs:57`. Writes are correctly `AdminUser` (`routes_sso.rs:22,44,73`) — only the reads are wrong.

Chain: `POST /auth/register` (unauthenticated, no CAPTCHA, no email verification) → `POST /auth/login` → `GET /api/v1/sso/providers` returns every configured enterprise IdP secret in cleartext. The 5-second Redis cache at `routes_dashboard.rs:39,85` then persists the plaintext into Redis.

### P0-5 — GitHub OAuth account takeover

```rust
// backend/src/api/routes_auth.rs:397-401
if db_user.is_none() {
    if let Some(email) = &gh_user.email {
        db_user = /* SELECT * FROM users WHERE email = $1 */;
    }
}
// :412-424 — bind attacker token to the matched row
let _ = sqlx::query("UPDATE users SET github_id=$1, github_access_token=$2 WHERE id=$3")...
// :448 — mint a session for it
```
`gh_user.email` is never checked against `email_verified`; the requested scope is `repo,read:org,user:email` (`:301`). An attacker who registers that address on GitHub (permitted on non-protected domains) is bound to the victim's account and receives a session.

Aggravating: the `UPDATE` result is discarded with `let _ =` (`:421`), so a failed write still yields a session while the victim's stored GitHub token is never rotated.

### P0-C — Fabricated security findings (product safety)

| Component | Reality | Call sites |
|---|---|---|
| `agents/sast.rs` | 3 hardcoded `Finding` literals with fixed CVSS, fixed `file_path`, fixed `line_number` | 1 |
| `agents/ai_analyzer.rs:4-9` | `state.validated_findings = state.scored_findings.clone()` + `sleep(400ms)` | 1 |
| `agents/mod.rs:11-22` `run_recon` | returns a fixed 5-element `tech_stack` vec without reading anything | 1 |
| `services/llm.rs:18-22` | `Ok(String::new())` | **0** |
| `services/sandbox.rs` | Docker flags, correct argv, `--network=none` | **0** |

`AuditState::clone_path` is never set — **nothing is ever cloned from the submitted URL.** No file is read, no AST is parsed, no scanner is executed. Every user, on every repository, receives the same three findings naming `src/config.rs:42`, `src/db/queries.rs:118`, `src/middleware/cors.rs:15`.

A security product that reports invented vulnerabilities with invented file/line references is worse than one that reports nothing: it destroys user trust and pollutes downstream triage.

**Decision: Option B (explicit engine-unavailable), not Option A.**

Rationale — implementing a real SAST engine is a separate multi-week project with its own security review (clone/SSRF/sandbox escape surface). Option B is the correct Phase 0 action because it converts a *false claim* into an *honest refusal*, which is a strict improvement and is implementable and testable now. It also shrinks the attack surface by removing the unused sandbox and LLM scaffolding rather than growing it. Option A can be adopted later against a much smaller, honest codebase.

---

## 4. Dependencies (fix ordering)

```
P0-1  (logger panic + token leak)   ── standalone, no dependencies
  │
P0-3  (fail closed on missing secret; decouple debug)
  │      └── must land BEFORE P0-2 verification, because P0-2's
  │          "identical keys rejected" check only runs outside `debug`
  │
P0-2  (remove compose secret defaults; add to denylist)
  │
P0-4  (strip client_secret)  ── standalone
  │
P0-5  (remove email-match linking)  ── standalone
  │
P0-C  (engine_unavailable + doc truth)  ── needs P0-1..P0-5 committed first
                                           so the "Fixed/Verified" report
                                           in the commit history is accurate
```

S-1 (rate-limiter layer order), the schema reconciliation, and the worker reliability work are **Phase 1+** and are listed at the end of this document as the follow-on queue. They are not in Phase 0 because none of them is exploitable without a configured production environment, whereas all five P0s are exploitable in the default configuration.

---

## 5. Tests required

Every fix in Phase 0 ships with a test in the same commit. Naming: `security_<finding>_<description>`.

| Test | Location | Asserts |
|---|---|---|
| `security_p0_1_logger_utf8_dos` | `backend/tests/security_regressions.rs` | `safe_payload_snippet` returns normally (no panic) for a JSON body >800 B whose 800th byte is inside a 3- and a 4-byte char |
| `security_p0_1_logger_utf8_dos_text` | same | same, for the non-JSON text branch |
| `security_p0_1b_logger_redacts_query_token` | same | `redact_uri_for_log` strips `token`/`access_token`/`code` query values |
| `security_p0_3_missing_secret_key_fails_closed` | `backend/tests/config_security.rs` | `Settings::new()` with no `SECRET_KEY` and no `RUN_MODE` returns `Err`, and no signing key is substituted |
| `security_p0_3_debug_does_not_control_rate_limiting` | same | the flag that gates the governor is no longer derived from `debug` |
| `security_p0_4_sso_response_omits_secret` | `backend/tests/security_regressions.rs` | `SsoProvider` serializes without `client_secret`; the redacted DTO never contains the plaintext |
| `security_p0_5_no_email_account_linking` | same (static assertion) | the email-fallback lookup is absent from `github_callback` |
| `security_p0_c_engine_unavailable` | same | a submitted job cannot reach a terminal `completed` status with findings sourced from a scanner |

Plus the pre-existing baseline: `cargo check` must stay at exit 0 throughout, and `cargo test` must be green before any commit.

**Not yet possible:** end-to-end integration tests requiring a live Postgres. FireCrow has no test database harness, no `DATABASE_URL` fixture, and no `sqlx` offline query data. Building that harness is Phase 1 work and is a prerequisite for the auth/authorization test matrix. Phase 0 therefore uses pure-function and configuration tests, which is honest about what has actually been verified.

---

## 6. Risks of this remediation

| Risk | Assessment | Mitigation |
|---|---|---|
| Removing the dev secret fallback breaks local dev | Real | The failure becomes a loud, explicit startup error naming the variable. That is the correct behaviour; a developer sets `SECRET_KEY` in `.env.local`. Documented in the commit message and README. |
| Removing compose key defaults breaks `docker compose up` | Real, and already broken (P0-2b) | Use `${SECRET_KEY:?set SECRET_KEY}` so compose fails with an actionable message instead of silently using a public key. |
| Dropping `panic = "abort"` slightly increases binary size | Negligible | Required for `CatchPanicLayer` and `catch_unwind` to function at all. They are already registered in `main.rs:199` and are currently dead code. |
| Stripping `client_secret` breaks the admin edit flow | Real | Admins already have no way to *read* a secret back today without this fix. Add a write-only field convention: empty string on update means "leave unchanged", which `update_provider` already implements via `COALESCE` (`sso_service.rs:70`). Verified compatible. |
| Removing email-match linking locks out existing users | Possible | GitHub users created via the old path keep their stored `github_id` and continue to log in by `github_id` — only the *unsafe fallback* is removed. No data migration needed. |
| `engine_unavailable` is a visible product regression | Intentional | The current behaviour is a false security claim. Shipping honest "unavailable" over invented findings is the point. Phase 5 may implement a real engine and flip this off behind an explicit flag. |
| Fixing the logger removes a debugging convenience | Real | Truncation becomes char-boundary-safe instead of byte-indexed, which is a strict improvement. Body logging is capped and redaction is widened. |

---

## 7. Exact remediation order

Each step is independently mergeable and independently revertable.

1. **P0-1** — char-boundary-safe truncation; redact query-string tokens from the logged URI; move `CatchPanicLayer` outside `http_audit_logger`; remove `panic = "abort"`. + tests.
2. **P0-3** — `RUN_MODE` defaults to `production`; delete the dev signing-key substitution entirely; stop deriving the rate-limit / Cloudflare-middleware gate from `debug`; gate `is_allowed_origin`'s localhost list on `debug`. + tests.
3. **P0-2** — remove both compose defaults to `${VAR:?...}`; add the burned values to `insecure_dev_values`. Document rotation.
4. **P0-4** — `#[serde(skip_serializing)]` on `SsoProvider.client_secret`; introduce an explicit redacted DTO for reads. + test.
5. **P0-5** — delete the email fallback; require `github_id` linkage; stop discarding the token-persist result with `let _ =`.
6. **P0-C** — return an explicit `engine_unavailable` terminal state; stop writing fabricated findings; stop computing a security score from them; correct README, API docs, and the landing page.

---

## 8. Proposed commit boundaries

```
security: make audit logger UTF-8 safe and stop logging bearer tokens
security: fail closed on missing secrets and decouple hardening from debug
security: remove default secrets from deployment config
security: never return SSO client secrets from read endpoints
security: bind GitHub OAuth identity only to a verified provider id
fix: stop the audit engine from reporting fabricated findings
docs: describe the product that actually exists
```

Each is independently understandable and independently revertable, as required. No commit bundles unrelated fixes. Tests land in the same commit as the fix they protect, which is why commit 1 and 2 are each self-verifying.

---

## 9. Follow-on queue (not Phase 0)

Recorded so nothing is lost; each needs its own plan.

**Phase 1 — correctness and security**
S-1 rate-limiter/Cloudflare layer order · S-2/S-3 admin-gate `/system/*` · S-5 restrict `?token=` to SSE · S-6/S-7 enforce MFA at the auth boundary and actually read `mfa_enforced` · S-8 check `is_active` in both extractors · S-9 revocation TTL must match the token it revokes · S-10 logout must revoke the family · S-11 covered by P0-3 step 2 · S-13 cookie-only auth · S-15 admin-gate or delete `POST /auth/policy-events` · S-16 shared `reqwest` client with timeouts · S-19 validate `repo_url` · S-20 CSP · R-5/R-6/R-7 transactions and findings persistence.

**Phase 2 — reliability**
R-1 await migrations and abort on failure · R-2 `catch_unwind` in the worker loop · R-3 reaper threshold 10 min → 30 min · R-4 SIGTERM + drain · R-9 status-guard the reaper and worker error writes · R-10 fix `/health/ready` · R-11 atomic lockout · R-12 atomic exchange-code consumption · R-13 recovery-code atomic guard.

**Phase 3 — database**
R-16 reconcile 13 `FromRow` structs and 6 missing tables · R-15 `role_permissions.role_id` FK (after deciding what a role *is*) · R-14 make migrations idempotent, remove the production `DROP TABLE` · add the missing indexes · adopt `sqlx::query!` so drift becomes a build error.

**Phase 4 — architecture**
R-17 collapse the duplicate module tree · remove the crate-root `#![allow(...)]` blankets once the warnings are survivable · enforce `max_active_jobs_per_user` · bound the eight unbounded list queries.

**Phase 5 — deployment and product**
Dockerfile + working compose + tunnel · CI pipeline · feature matrix decisions (implement or delete) · documentation regeneration from the router.
