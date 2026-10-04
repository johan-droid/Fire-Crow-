# Fire Crow — Release Candidate (controlled beta)

Status correction (user verdict, 2026-10-04):

> **Backend architecture frozen + controlled-beta candidate, with release
> hygiene/operational gates still pending.**

"Fully production-ready" is NOT claimed. The RC gate below is the final
tightening pass before the backend is permanently frozen for frontend work.
No architecture was modified in this pass.

## RC gate results (2026-10-04)

| # | Gate | Result |
|---|---|---|
| 1 | `cargo fmt --check` | **CLEAN (0 diffs).** `cargo fmt` applied to the uncommitted Phase 8–20 tree; `--check` now passes. Formatting only — no logic touched. |
| 2 | `cargo clippy --all-targets -- -D warnings` | **CLEAN (exit 0).** 3 mechanical fixes (needless borrow, `or_else`→`or`, test borrow) + 3 documented `#[allow(too_many_arguments)]` on the frozen 8-arg gate signatures (`create_audit_job_attributed`, `post_check_run`, `run_audit_job`) with rationale comments. Splitting those signatures is a refactor, deferred out of the freeze. |
| 3 | `startup_and_migrations` | **12/12 PASS** (`/tmp/startup_mig.log`, 60.6s — slow tests need a real window; the earlier "timeout" was the harness window, not a code failure). Fresh-apply, idempotent re-run, schema shape, secret hygiene, unreachable-DB refusal all green. |
| 4 | Backpressure soak | **PASS at available scale, P1 remainder recorded.** `concurrent_submissions_from_one_user_respect_the_gate`: 6-way `join_all` burst vs cap 2 → exactly 2 admitted / 4 refused (409), `audit_jobs` = 2 rows, zero 500s; `concurrent_submissions_from_distinct_users_all_succeed` proves no cross-user blocking. Larger N-user/N-worker sustained flood (webhooks × retries × cancellations) remains **P1 PENDING** — recorded in the test comment, not claimed. |
| 5 | Gemini live smoke | **PENDING (credential-gated).** No `GEMINI_API_KEY` in env; test not faked. AI is optional; outage → audit + no narrative by design. |
| 6 | Dead config | **Documented, not removed** (`PRODUCTION_DEPLOYMENT.md`): RESEND/BREVO, GOOGLE_OAUTH, mock-sandbox, fallback-model, and 14 legacy `cf_secrets.json.example` keys. Removal is a behavior change — deferred. |
| 7 | Obsidian | Fire Crow memory kept separate (`Claude memory/FireCrow/Fire Crow/`); Zenkai vault untouched. Correct per user verdict. |

## Scoreboard (user verdict, unchanged)

🟢 Architecture frozen · Security core · Scanners (live) · Persistence ·
AI boundary · GitHub App · Hygiene · Frontend contract v1 —
🟡 Production ops (this RC closes hygiene; soak-smoke remain) —
⏭️ Frontend next.

## Freeze statement

Backend is now permanently frozen for frontend work. `FRONTEND_CONTRACT.md`
v1 is the source of truth. Future backend changes require a demonstrated
production defect, security issue, or explicit product requirement.
