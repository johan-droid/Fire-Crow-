# Atomic Audit Commit & Execution Identity (Phase 12)

Phase 11 is frozen. This phase closes the remaining lifecycle gap: the audit
result must be **atomic**, **reconstructable**, and **immutable per execution**.

## 12.1 Persistence inventory (traced, not assumed)

Actual write order in `orchestrator::run_pipeline` / `execute_audit_job`, with the
real commit boundaries. `pool.execute(...)` outside a transaction is its own
implicit transaction; only `persist_findings` opens an explicit one.

| # | Step | Table(s) mutated | Transaction boundary |
|---|---|---|---|
| 1 | claim (`may_execute_job` + `claim_job_for_execution`) | `audit_jobs` | implicit (own commit) |
| 2 | `phase()` ledger open | `phase_ledger` | implicit |
| 3 | fetch → snapshot pin | `audit_jobs.commit_sha` | implicit |
| 4 | scan | **nothing** — `AuditState::scanner_execution` is in-memory only | none |
| 5 | normalize | **nothing** — counts kept in memory | none |
| 6 | score | **nothing** — score is in-memory until step 10 | none |
| 7 | report → `persist_findings` | `findings` (UPDATE/INSERT + **DELETE** of non-listed) | **explicit tx, commits** |
| 8 | report → `load_findings` read-back | — | read only |
| 9 | report → `audit_reports` upsert | `audit_reports` | implicit (own commit) |
| 10 | `deliver` → existence check | — | read only |
| 11 | terminal status write | `audit_jobs` | implicit (own commit) |

### Consequences (observed, not hypothetical)

**D1 confirmed — four separate commits between "findings written" and "audit is
terminal".** A crash after step 7 and before step 11 leaves findings persisted
under a job still marked `running`; the reaper later marks it `failed`. The
audit then reports a failure while carrying real findings — the inverse of a
false clean, but equally inconsistent.

**D2 (new, severe) — scanner statuses and coverage are never persisted at all.**
Step 4 and 5 write only into `AuditState`, which is a local variable discarded
when the function returns. There is no table holding scanner run outcomes,
coverage status, or limitations. Consequences:

- A finished audit cannot be reconstructed: the canonical audit is unrecoverable
  after the process exits.
- The API has no way to answer "which scanners ran, and did any fail?" for a
  historical job.
- 12.11's required equality (canonical coverage == persisted scanner statuses)
  is currently unverifiable, because there is nothing to compare against.

**D3 (new) — `deliver` checks `audit_reports` in a separate transaction from the
write in step 9**, so the existence assertion proves nothing about atomicity.

**D4 (new) — attempt count is unreconstructable.** `phase_ledger` records phases
per *job*, not per *attempt*. A retried job overwrites/duplicates phase rows with
no attempt number, so "how many times did this run, and why did each end?" has no
answer.

### Execution identity

Confirmed absent: no `execution_id`, `attempt`, `lease`, or `heartbeat` column or
table exists anywhere in the schema. `audit_jobs.started_at` is a single mutable
field, so a second attempt overwrites the first attempt's start time.

### Cancellation

`POST /audit/job/:id/cancel` writes `status='cancelled'` directly. The worker
observes `cancel_requested` only *between* phases. A cancellation arriving during
step 7–11 (persistence/finalization) is not observed at all, so a cancelled audit
can still reach `Outcome::Ok` in memory while the guarded terminal write
silently no-ops. Winner determination is timing-dependent, not durable.

## Design decisions for Phase 12

1. **One `audit_executions` table** — durable attempt identity (attempt_number,
   status, started_at, finished_at, failure_reason, commit_sha, lease fields).
   A new table is warranted: the existing schema cannot represent "how many
   attempts, and what happened to each" at all.
2. **Findings are re-parented to an execution** (`findings.execution_id`), so an
   attempt's evidence can never be silently replaced by a later attempt.
3. **A `scanner_runs` table** — per-execution scanner outcomes, coverage, and
   limitations. This closes D2 and makes 12.11 checkable.
4. **A single finalization transaction** commits findings + scanner runs +
   coverage + summary + canonical row + terminal status together, guarded by an
   execution lease so a stale worker cannot commit.
5. **Cancellation is a request, not a terminal write.** The API records
   `cancel_requested`; only the owning execution may write `cancelled`, and it
   does so inside the finalization transaction. A race is therefore decided by
   PostgreSQL row locking, not by timing.

## What Phase 12 implements

### Execution identity (12.2)

`audit_executions` is one row per attempt with a deterministic, dense
`attempt_number` derived under a `UNIQUE (job_id, attempt_number)` constraint, so
two racing workers cannot both believe they are attempt 2. A retry opens attempt
N+1 and leaves every earlier attempt queryable, including its `failure_reason`.

### Atomic finalization (12.4)

`finalize_execution` is the single commit point. In **one** transaction, under a
`FOR UPDATE` lock on the execution row, it commits: findings, scanner runs, the
canonical document, the report row, the execution's terminal status, and the
job's status. The states the criterion forbids — terminal status with findings
missing, or findings present under an audit that never finalized — are no longer
reachable by a crash, because there is no commit between them.

### Scanner statuses are persisted (closes D2)

`audit_scanner_runs` stores each scanner's status, coverage flag, detail, and
limitations per execution. A finished audit is now reconstructable from storage,
and 12.11's required equality (canonical coverage == persisted statuses) is
checkable for the first time.

### Ownership (12.8/12.9)

Each execution carries an `owner_token`. Only the holder may bind a snapshot or
finalize; a worker that lost the token is refused by the database. `heartbeat`
refreshes `heartbeat_at`, so the reaper can distinguish "this worker is alive"
from "this worker died" rather than guessing from elapsed time. No distributed
infrastructure was introduced.

### Immutability (12.12)

Two database triggers: a terminal execution rejects any further update or
snapshot rebinding, and a finding whose execution is terminal rejects edits and
deletes. Re-parenting a finding to a *new* execution is the one permitted move,
which is what makes a retry additive rather than destructive.

## Defects found and fixed while implementing Phase 12

**G1 — A `BEFORE UPDATE` trigger returned `OLD`, silently discarding every
write.** The terminal-immutability guard ended with `RETURN OLD`, which in
PostgreSQL means "discard this update". Finalization became a no-op that still
reported success: executions stayed `running` forever, findings never landed,
and `begin_execution` then refused every retry because an execution appeared to
still be running. Caught by 23 of 25 tests failing at once. Fixed by returning
`NEW`, with a comment recording why.

**G2 — The finding-freeze trigger silently cancelled DELETEs.** In a `BEFORE
DELETE` trigger `NEW` is NULL, so the re-parenting branch evaluated to "changed"
and `RETURN NEW` quietly skipped the deletion — the row survived, but by
accident and without any error. A test asserting "delete must be refused" saw a
successful statement. Fixed by branching on `TG_OP` so a delete raises instead.

**G3 — One cancellation poisoned every future attempt.** `cancel_requested` was
read but never cleared, so a job cancelled once could never be retried into a
successful audit: each retry's finalization saw the stale flag and reverted to
`cancelled`. The request now describes *this* execution and is cleared in the
same transaction that acts on it.

**G4 — A retry could not reopen its job.** The job-status write was guarded on
`status IN ('queued','running')`, so once an attempt left the job `failed` or
`cancelled`, a successful retry could not move it forward — the audit stayed
`cancelled` while its newest execution was `completed`. The guard now admits
prior *attempt* outcomes, while stale-worker protection remains with the
ownership check.

**G5 — Two migration tests asserted magic constants.** `migration_chain_produces_the_expected_schema`
counted tables (`34`) rather than asserting the tables the product needs. Both
that and the migration-count/latest-version assertions were replaced with
properties derived from the repository, so they assert what they mean.

### A regression caught during implementation

G1 is the same failure shape as the Phase 11 queued-only guard: an
implementation that *looked* correct and whose early tests passed, while making
the feature not work at all. It was only visible because the lifecycle tests
assert persisted database state after each step rather than return values.

## Closing the gap that made the first Phase 12 report FAIL

The first report was **FAIL**, correctly: all the invariants above were proven
by calling the new module directly, while `execute_audit_job` still ran the old
path — four commits, and scanner statuses never stored. Green tests on an
unwired module prove nothing about the product.

The pipeline is now wired to the atomic path:

| Site | Before | After |
|---|---|---|
| attempt open | none | `begin_execution` at job start |
| snapshot | job only | job **and** execution, via `bind_snapshot` |
| findings | `persist_findings`, own commit | committed inside `finalize_execution` |
| scanner runs | in-memory only | `audit_scanner_runs`, same commit |
| report row | own commit | same commit |
| terminal status | 5 separate arms | same commit |
| cancellation | API wrote `cancelled` directly | request only; owning execution decides |
| reaper | 10-min wall-clock on `audit_jobs` | heartbeat-based, closes the **execution** |

`cancel_job` records `cancel_requested` and stops. The reaper no longer writes a
terminal status at all; it closes abandoned *executions* whose owner stopped
heartbeating and releases a job with no live execution back to `queued`, so
recovery does not require a human.

Wiring tests added: `the_pipeline_creates_an_execution_for_its_attempt`,
`a_cancellation_request_alone_does_not_finalize_the_audit`,
`a_second_pipeline_run_opens_a_second_attempt`.