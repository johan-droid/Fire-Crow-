-- Audit lifecycle integrity (Phase 11).
--
-- The audit lifecycle was enforced only by string guards duplicated across ~10
-- call sites in the orchestrator and worker. Three consequences followed:
--
--   1. `status` accepted any varchar, so an unknown or misspelled status could
--      be persisted and would fail to deserialize on read.
--   2. Nothing tied an audit to the snapshot it judged. Snapshot identity lived
--      only inside `findings.metadata_json`, so a finding could not be proven to
--      belong to the audit's snapshot.
--   3. A finalized audit was not protected at the storage layer: re-running a
--      completed job rewrote its findings, because the delete/rewrite in
--      `persist_findings` was not guarded by job status.
--
-- This migration adds:
--   * `commit_sha` — the snapshot an audit is bound to. Historical audits can
--     now be identified by the exact tree they judged, and a later repository
--     change cannot silently relabel them.
--   * a CHECK constraint on `status` — the state machine is now enforced by the
--     database, not only by whichever code path happens to write the row.
--
-- Findings are *not* retrofitted: existing rows keep whatever provenance they
-- already carry, and the Phase 11 guard only enforces the binding for findings
-- written from now on.

ALTER TABLE audit_jobs ADD COLUMN IF NOT EXISTS commit_sha VARCHAR(64);

-- Enforce the state machine at the storage boundary. The constraint is added
-- only when absent so re-running migrations stays safe, and it is deliberately
-- NOT VALID-friendly: existing rows are normalized first.
--
-- Historical rows that predate the constraint can hold a status this build does
-- not know; map the ones with an obvious intent rather than failing startup.
UPDATE audit_jobs SET status = 'failed'
 WHERE status IS NOT NULL
   AND status NOT IN (
       'queued', 'running', 'completed', 'partial',
       'failed', 'cancelled', 'engine_unavailable'
   );

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'audit_jobs_status_known'
    ) THEN
        ALTER TABLE audit_jobs
            ADD CONSTRAINT audit_jobs_status_known
            CHECK (status IN (
                'queued', 'running', 'completed', 'partial',
                'failed', 'cancelled', 'engine_unavailable'
            ));
    END IF;
END
$$;

-- An audit's snapshot is fixed once the fetch phase pins it.
CREATE INDEX IF NOT EXISTS idx_audit_jobs_commit_sha
    ON audit_jobs (commit_sha)
    WHERE commit_sha IS NOT NULL;