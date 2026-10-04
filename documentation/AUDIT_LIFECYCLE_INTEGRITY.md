# Audit Lifecycle & Persistence Integrity (Phase 11)

Scope: the audit **lifecycle** — state machine, transaction boundary, idempotency,
retry identity, snapshot immutability, and round-trip fidelity. This phase does
**not** change scoring (`score_scan` is frozen) and does **not** add cross-scanner
semantic correlation (exact-canonical-identity correlation is frozen).

## 11.1 Inventory (inspect-first, no code changed)

### Job state machine as actually implemented

`JobStatus` (`src/models/user.rs`): `Queued, Running, Completed, Failed, Cancelled,
Partial, EngineUnavailable`. Terminal = all but `Queued`/`Running`.

Legal transitions (`JobStatus::can_transition`):
- `Queued -> {Running, Failed, Cancelled}`
- `Running -> {Completed, Partial, Failed, Cancelled, EngineUnavailable}`

`Queued -> Completed/Partial/EngineUnavailable` is **illegal** in the Rust contract.

### Where status is written (every site, and its guard)

| Site | Guard | Notes |
|---|---|---|
| `orchestrator::execute_audit_job` (claim) | `status IN ('queued','running')` | sets `running` |
| `orchestrator` terminal writes (5x) | `status IN ('queued','running')` | Completed/Partial/Failed/Cancelled/EngineUnavailable |
| `workers::mark_job_failed` | `status IN ('queued','running')` | failure + timeout |
| `workers` reaper (cancel) | `status IN ('queued','running') AND cancel_requested=true` | bulk |
| `workers` reaper (orphan) | `status IN ('queued','running')` | >10min running, not active |
| `workers::worker_loop` claim | `WHERE status='queued' ... FOR UPDATE SKIP LOCKED` | atomic claim |
| `api::cancel_job` | `status IN ('queued','running')` | sets `cancelled` **immediately** |

### Storage layout

- `audit_jobs`: `status VARCHAR(64)` with **no CHECK constraint**, no unique
  constraint on (repo, snapshot), no `commit_sha` column.
- `findings`: per-job rows, `metadata_json JSONB` carries scanner provenance and
  `snapshot_commit`.
- `audit_reports`: unique per `job_id`.
- `phase_ledger`: per-phase rows with `status`/`started_at`/`ended_at`.

### Defects found (demonstrable, not hypothetical)

**D1 — Findings are committed before the audit is finalized, in a separate
transaction.** `persist_findings` commits its own transaction; the job status is
written later by a different statement. A crash between them leaves findings
persisted while the job is still `running` (later reaped to `failed`). The
inverse — "audit says completed but findings are missing" — is currently
prevented only by an in-process read-back assertion, which cannot survive a
crash. There is no single commit point.

**D2 — Re-running a terminal job mutates it.** `execute_audit_job`'s claim
UPDATE matches `status IN ('queued','running')`, but its result is discarded
(`let _ =`). For a job already in a terminal state the UPDATE affects 0 rows and
the pipeline proceeds anyway: it re-fetches, re-scans, and `persist_findings`
**deletes and rewrites** the historical finding rows. The status guard prevents
the status from changing but not the findings from being replaced. This breaks
snapshot immutability and historical integrity.

**D3 — `api::cancel_job` writes `status='cancelled'` directly.** The API moves a
job to a terminal state outside the orchestrator, while the worker may still be
mid-pipeline and will later persist findings and a report for a job the user was
told is cancelled.

**D4 — No snapshot binding at the job level.** `audit_jobs` has no `commit_sha`.
Snapshot identity exists only inside `findings.metadata_json`. A finding cannot be
proven to belong to the snapshot the audit claims, and the job cannot be
re-identified as "this snapshot was already audited".

**D5 — No database-level state-machine enforcement.** The transition contract is
enforced only by string guards duplicated across ~10 call sites, and
`audit_jobs.status` accepts any varchar. Nothing prevents an illegal transition
or an unknown status at the storage layer.

## Frozen decisions carried forward

- `score_scan` (flat 1.5/finding) is **unchanged**. Scoring redesign is a
  separate phase.
- Cross-scanner correlation stays deferred. Only exact canonical identity
  correlates; everything else remains distinct.

## 11.2–11.6 What Phase 11 enforces

### Execution identity (11.3/11.5)

`may_execute_job` is the single authority on whether an execution may proceed:
a **terminal** audit is refused, a **missing** audit is refused. `queued` and
`running` are both accepted, because the queue claims `queued -> running` before
handing the job to the pipeline — refusing `running` would silently skip every
real production job. `claim_job_for_execution` is the queue's atomic
`queued -> running` claim and resolves races between workers.

A duplicate or retried execution of a finished audit now does nothing at all:
it does not re-fetch, does not re-scan, and does not touch the findings.

### Persistence boundary (11.4)

`assert_audit_is_writable` runs inside the same transaction as the write and
refuses, before any row is touched, when:

1. the audit is in a terminal state (its findings are immutable history), or
2. a finding's `snapshot_commit` differs from the snapshot the job is pinned to.

### Snapshot immutability (11.6)

`audit_jobs.commit_sha` is stamped the moment the fetch phase resolves the head,
and every finding is checked against it. A repository moving on cannot relabel a
historical audit, and evidence about a different tree cannot be attached to this
one.

### State machine at the storage layer (11.2)

`audit_jobs.status` now carries a CHECK constraint, so the state machine is
enforced by the database rather than only by whichever code path happens to
write the row. Unknown statuses are normalized to `failed` before the constraint
is added.

## Defects found and fixed in this phase

**F1 — A finished audit could be silently rewritten (critical).**
`execute_audit_job` ran its claim `UPDATE` and discarded the result
(`let _ = ...`), then executed the pipeline unconditionally. For an audit
already in a terminal state the UPDATE matched nothing, so nothing stopped the
run: it re-fetched, re-scanned, and `persist_findings` — which replaces a job's
entire finding set — deleted and rewrote the finished audit's findings. The
status guard protected the *status* while the *findings* were replaced
underneath it. Fixed by `may_execute_job` plus the terminal-state guard in
`persist_findings`. Regression test:
`a_duplicate_worker_execution_changes_nothing`.

**F2 — Findings could be attached to the wrong snapshot (high).**
Nothing bound a finding's `snapshot_commit` to the audit's snapshot. Fixed by
`audit_jobs.commit_sha` and the drift check. Regression test:
`every_persisted_finding_carries_its_job_snapshot`.

**F3 — The state machine was unenforced at the storage layer (medium).**
`status` accepted any varchar. Fixed by the CHECK constraint.

**F4 — The migration-integrity test asserted literal constants (low, test-only).**
`migration_chain_is_fully_recorded` hardcoded both the migration count (`18`)
and the newest version (`20260901000200`). The count was the number itself
rather than the property being asserted, and adding any migration broke it. Both
are now derived from the migrations directory, so the test asserts the real
invariant and stops needing an edit per migration.

### A regression caught during implementation

The first version of the execution guard refused any job that was not `queued`.
That broke `cancelled_running_job_ends_cancelled`, and the reason is worth
recording: the worker claims `queued -> running` *before* calling
`execute_audit_job`, so an in-flight job is already `running` when its pipeline
starts. A "queued-only" guard would have skipped every production job while
passing the new tests. The guard was widened to "not terminal" and
`an_in_flight_job_may_still_execute` now pins that distinction.