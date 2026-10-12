# ADR 003: Database-Authoritative Lifecycle State Machine via PostgreSQL Triggers

## Status
**Accepted**

## Context
In asynchronous auditing platforms with background worker tasks, several concurrency bugs commonly arise:
1. **Premature Status Mark**: An API handler or async worker marks an audit as `completed` before scanner output files have been fully ingested or verified.
2. **Race Conditions & Inconsistent States**: Distributed workers or retry loops might update an audit from `failed` back to `running`, or skip the `running` phase altogether.
3. **False Clean Audits**: In error conditions (e.g., container OOM, network timeout downloading tarball), an application-level bug might swallow the exception and record an empty finding set with status `completed`.

Application-level guards (Rust code checks) are necessary, but alone they can be bypassed by parallel workers, manual administrative SQL updates, or unhandled panic recovery routines.

## Decision
We enforce the audit lifecycle state machine at the database layer using a PostgreSQL 16 `BEFORE UPDATE` trigger function: `audit_jobs_lifecycle_guard_fn`.

### State Machine Rules
The valid status transitions are strictly defined:
- `queued` ➔ `running`
- `running` ➔ `completed`
- `running` ➔ `failed`
- `queued` ➔ `failed` (e.g. queue timeout or cancellation)

Any other transition attempt (for example, `queued` ➔ `completed`, `completed` ➔ `running`, `failed` ➔ `completed`) raises a fatal PostgreSQL exception (`RAISE EXCEPTION 'Illegal audit job status transition: % to %', OLD.status, NEW.status`), aborting the transaction.

### Invariant: `failure != clean`
When an audit fails, the engine updates `status = 'failed'` and logs the exact failure phase and stderr output. A failed audit cannot write an empty `CanonicalAuditV1` record that masquerades as a clean scan.

## Consequences
### Positive
- **Impossible Illegal States**: Neither buggy application code, racing background threads, nor manual DB updates can put an audit into an invalid state.
- **Audit Integrity Guarantee**: Compliance auditors can verify that every completed audit followed the sequential intake -> scan -> normalize pipeline.

### Negative / Trade-offs
- Integration tests simulating edge cases must strictly follow the state sequence when updating records in the database.
- Database schema changes to add new phases require updating the PL/pgSQL trigger function.
