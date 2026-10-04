# Fire Crow Threat Model (Phase 18)

The adversary is the **scanned repository itself** — plus anyone who can make
the backend talk to a hostile endpoint or replay a hostile identifier. Every
row below names the actual enforcement point, not the intended one. Paths are
relative to `backend/`.

Convention: **DB** = PostgreSQL constraint/trigger (authoritative even if
application code is buggy); **APP** = application check (defense in depth);
**DROP** = the hostile input is refused and counted, never repaired into a
finding.

## 1. Malicious repository → snapshot escape

| Attacker input | Boundary | Enforcement |
|---|---|---|
| `..`, absolute paths, over-long paths in tar members | extraction | `safe_join` rejects traversal/root/over-long (`src/agents/fetch.rs:948`); pre-existing symlinks refused at write (`fetch.rs:867`) |
| Symlinks / hardlinks in archive | extraction | link entries refused outright (`fetch.rs:896`); snapshot walk never follows symlinks (`fetch.rs:671`) |
| Devices, FIFOs, sockets | extraction | non-file/dir/link entries skipped (`fetch.rs:902`) |
| Decompression bomb | download + extract | `MAX_DOWNLOAD_BYTES` 100MB (`fetch.rs:19`), post-gzip `MAX_TOTAL_BYTES` 150MB check before disk (`fetch.rs:798`), per-file 20MB + 20k-file caps (`fetch.rs:22-25`) |
| Unicode/normalization escape | extraction | component-wise `Path::components` match; only `Normal`/`CurDir` accepted (`fetch.rs:957`); `starts_with(dest)` re-check (`fetch.rs:973`) |
| Non-github / ssh / file URLs | intake | single authority `normalize_repository_url`, enforced at route and fetch (`src/api/routes_audit.rs:701`, `fetch.rs:919`) |
| Oversized tree that grew post-extract | snapshot | walk re-checks file-count and byte caps (`fetch.rs:689-695`) |
| Secret files read for inventory | snapshot | sensitive paths recorded but never opened (`fetch.rs:710-712`) |

Exceeding a budget is `PayloadTooLarge` → FAILED. Never clean.

## 2. Malicious repository → scanner escape

Single definition point: `docker_argv` (`src/services/sandbox.rs:585`).
Unit-verifiable without Docker.

| Attack | Enforcement |
|---|---|
| Network exfiltration / DNS / localhost | `--network=none` default; only declared exception is OSV on `bridge` (never `host`) (`sandbox.rs:195-246`) |
| Container-root or host writes | `--read-only` + tmpfs scratch only (`/work` 64m, extras 32m); mounts restricted to `/scan` + `/config`, read-only enforced (`sandbox.rs:374-417`) |
| Privilege escalation | `--cap-drop=ALL`, `no-new-privileges`, `--user=65534:65534` |
| Fork bomb / memory / CPU exhaustion | `--cpus`, `-m` + `--memory-swap` pinned equal, `--pids-limit`; values validated (`sandbox.rs:156-177`) |
| Zombie accumulation / surviving containers | `--init` + `--rm` + explicit `docker rm -f` on timeout/cancel (`sandbox.rs:840`) |
| stdout/stderr flooding worker memory | streaming caps while reading, never buffered whole (`sandbox.rs:643`); breach is `OutputLimitExceeded` → FAILED, never a result |
| Host env leaking into the run | client env cleared (`sandbox.rs:727`); container env only via validated `-e` |
| Unpinned / flag-shaped images, entries, mounts | `validate_spec` before Docker is touched (`sandbox.rs:422`): pinned image, timeout range, absolute validated tmpfs/env/mounts |

## 3. Malicious scanner output → forged findings

Scanner JSON is hostile input. Pipeline: schema parse → adapter
bounds/redaction → canonical validation → persistence.

| Attack | Enforcement |
|---|---|
| Malformed JSON / missing report | parse failure → `FAILED`, never zero findings (gitleaks `scanner.rs:1985`, osv `:1288`, semgrep `:840`; semgrep additionally requires `results`+`paths` keys so `[]` is not clean) |
| Scanner errors / scanned-nothing | semgrep `errors[]` non-empty → FAILED; `scanned==[]` → FAILED/`no_files_analyzed` (`scanner.rs:925-960`); any failed scanner → score `None`, coverage partial |
| Empty evidence / missing file / bad line | canonical `finding_location` + `check_evidence`: file required and path-validated, `line > 0`, evidence non-empty, secret evidence must carry a redaction marker, credential shapes rejected elsewhere (`src/orchestrator/canonical_audit.rs:477-546`) |
| Oversized title/description/remediation/evidence/metadata | `check_text` / `check_evidence` / `check_metadata_size` bounds (`canonical_audit.rs:528-569`); adapter-level truncation first (e.g. `SEMGREP_SNIPPET_MAX_CHARS`) |
| Absurd line numbers (`i64::MAX`, negative) | adapters yield no anchor on `i32` overflow (`scanner.rs:1149,2061`); negatives refused by canonical `line > 0`; both quarantined + counted, never mis-located |
| Unredacted secrets in evidence | adapter exact-secret replacement + shared redactor (`scanner.rs:2032-2039`); canonical requires marker (`canonical_audit.rs:534`) |
| Duplicate detections erasing real vulns | identity = scanner + rule + native fingerprint + normalized location + evidence digest; severity/version/provenance excluded by design (`canonical_audit.rs:626-640`); dedupe keeps first in canonical order, duplicates counted (`canonical_audit.rs:888`) |

## 4. Malicious AI output / provider → corrupted truth

| Attack | Enforcement |
|---|---|
| Invented finding IDs / severities / scores / locations | validator cross-checks every ID against the report; unknown fields/severity/scores rejected (`src/schemas/ai_narrative.rs`, `src/orchestrator/ai_narrative.rs`) |
| Secret in narrative prose | every model-authored string checked → `SecretMaterial`, never persisted |
| Enormous / malformed / timed-out response | wire cap before parse (`src/services/llm_provider.rs:214`); fixed failure classes, provider bodies never enter errors (`llm_provider.rs:189-206`); any AI failure leaves the deterministic report untouched |
| Prompt injection via report content | prompt built from canonical fields only, evidence excluded (`src/services/llm.rs:18-21`), prompt capped (`narrative.rs:124`) |
| Provider key in URL/errors | Gemini key is a header, never a URL (`llm_provider.rs:150`); transport errors drop `reqwest::Error` detail; Telegram never formats `reqwest::Error` because the token is a path segment (`src/services/telegram.rs:142`) |

## 5. Forged / replayed identifiers → cross-attempt or cross-user access

| Attack | Enforcement |
|---|---|
| Foreign execution ID / wrong job | every route checks job ownership first, then execution-belongs-to-job; foreign is 404 (`src/api/routes_audit.rs:510-548,600-626`) |
| Execution ID as capability token | ownership is always re-checked per request; no route trusts the ID alone |
| Delivery to attacker-chosen destination | recipient from account record (email) or operator config (Telegram); request bodies cannot name a destination (telegram hijack test pins 501) |
| Retry mixing attempts | findings/reports/deliveries keyed by `execution_id`; retry creates attempt N+1, never reopens (`routes_audit.rs:187-249` refuses while running; `execution.rs:711` deletes scoped to execution) |
| Duplicate delivery after crash | idempotency key `(execution, channel, destination, version)` is the PK; retry into `sending` refuses instead of re-sending; resend is a new version, history additive |

## 6. Concurrent / stale workers → state corruption

| Race | Enforcement (DB authoritative) |
|---|---|
| Double finalize | `FOR UPDATE` + `status='running'` guard in app (`execution.rs:607-630`); backstop trigger `audit_executions_freeze` refuses non-running transitions; findings frozen under terminal executions |
| Stale worker finalize | `owner_token` lease checked under the row lock (`execution.rs:619-624`); one running execution per job via partial unique index |
| Cancel vs finalize | cancellation is a request flag, never a direct write; the finalization transaction consumes it and cancellation wins (`execution.rs:635-665`) |
| Reaper vs live worker | heartbeat-gated reap with `FOR UPDATE` re-check; claim via `SKIP LOCKED` (`src/workers/mod.rs:186-238`) |
| Terminal mutation | freeze triggers on executions + findings + reports + deliveries (`20260901000400`, `20260901000500`, `20260901000800` migrations) |

## 7. Secrets → logs / errors / responses / DB

| Sink | Enforcement |
|---|---|
| HTTP 5xx bodies | `error_sanitizer` middleware replaces detail in production (`src/app.rs:185`, `src/middleware/error_sanitizer.rs:10`) |
| Application logs | URI query denylist incl. `client_secret` (`http_logger.rs:52`); JSON/text body redaction + 800-char UTF-8-safe truncation; response bodies redacted the same way |
| Debug formatting | `Settings` and `ModelConfig` have secret-safe manual `Debug` impls (`config.rs`, `services/narrative.rs`); regression-tested |
| Delivery error rows | fixed failure classes only; provider bodies, prompts, findings never persisted (`src/orchestrator/delivery.rs:294-326`) |

Known residual (accepted, documented): derived `Debug` on DB models
(`User.github_access_token`, `GithubCredential.access_token`) — these are
never formatted in code (no `{:?}` on models found); the write path for
`SsoProvider.client_secret` nulls on read and skips serializing.

## 8. Resource budgets (exceeding → explicit state, never clean)

fetch 100MB download / 150MB extracted / 20MB single file / 20k files →
`PayloadTooLarge`/FAILED · sandbox stdout 16MB / stderr 1MB → FAILED ·
scanner CPU/mem/pids → container-enforced, timeout → TIMEOUT · AI prompt
chars / response bytes → `PayloadTooLarge` / `ResponseTooLarge`, report
survives · Telegram 4096 UTF-16 units → explicit summary stating omitted
count, never truncation · email bounded by SMTP retry deadline, failures
classified · DB payloads bounded by canonical text/evidence/metadata caps.

## Exit evidence

Each row above is covered by an integration or unit test named for the
property it pins; the suites are `sandbox_hardening`, `repo_fetch`,
`repo_intake`, `scanner_runtime`, `scan_contract`, `scan_integrity`,
`canonical_audit`, `atomic_audit_commit`, `audit_lifecycle`,
`ai_narrative*`, `llm_provider`, `email_delivery`, `telegram_delivery`,
and `security_regressions`.
