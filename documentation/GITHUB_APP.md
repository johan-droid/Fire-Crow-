# GitHub App Trust Boundary (Phase 19B)

## Architectural rule

> **GitHub App integration is an input/authentication boundary, not a new
> scanning or audit pipeline.**

Every event the App produces — push, pull request, installation change —
funnels into the one 19A submission path (`create_audit_job`) and from there
into the one execution pipeline. A webhook-created job is indistinguishable
from a user-submitted one. No second pipeline was created, and none may be:
a parallel path would need its own validation, backpressure, and state
machine, and they would drift.

## Stages

| Stage | Boundary | Proof |
|---|---|---|
| 19B.1 App identity | all-or-nothing config, RSA PEM gate, RS256 JWT ≤10 min, key never logged/persisted | `tests/github_app.rs`, `tests/config_security.rs` |
| 19B.2 Installation identity | minimum metadata only; tokens/repos/keys never stored; revocation is deletion | `tests/github_app.rs` |
| 19B.3 Token acquisition | short-lived, memory-only, bounded HTTP, transient-only retry, fixed error classes | `tests/github_app.rs` (mock GitHub) |
| 19B.4 Repo authorization | user → owned usable installation → token → GitHub decides; browser values validated then proven | `tests/github_app.rs` |
| 19B.5 Webhook HMAC | raw-bytes-first verification, delivery-ID dedup, modified-replay conflict, unconfigured fails closed | `tests/github_app.rs` |
| 19B.6 Webhook → execution | push pins head SHA through `create_audit_job_attributed`; one delivery → at most one job | `tests/github_app.rs` |
| 19B.7 PR checks | PR head through the same door; Check Run reports audit outcome only, best-effort from the worker | `tests/github_app.rs` |
| 19B.8 Kill/recovery | dead worker → reaper → new attempt; dead GitHub → honest failure; audit path has no Redis dependency | `tests/kill_recovery.rs` |

## Invariants

- Tokens (OAuth, installation, App JWT) live in memory and die with the
  request or the job run. None is ever a database value, a log line, or an
  error body.
- `installation_id`, `owner`, and `repo` from any client (browser or webhook
  payload) are questions GitHub answers, never facts the backend trusts.
- A redelivered webhook is a duplicate acknowledgement, never a duplicate
  job (`webhook_delivery_id` UNIQUE + delivery outcome machine).
- Removing the App, Gemini, email, Telegram, Redis, or the UI leaves the
  security audit itself intact.
