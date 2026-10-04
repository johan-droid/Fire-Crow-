-- Atomic audit commit & execution identity (Phase 12).
--
-- Phase 11 froze the audit from silent rewrite, but left three observed gaps:
--
--   D1. Findings, the report row, and the terminal status each committed
--       separately, so a crash between them left persisted findings under a
--       job still marked `running`.
--   D2. Scanner run outcomes, coverage, and limitations were never persisted at
--       all — they lived only in the in-memory `AuditState` and died with the
--       process. A finished audit could not be reconstructed, and the API could
--       not answer "which scanners ran, and did any fail?".
--   D3. `phase_ledger` is keyed by job, not by attempt, so "how many times did
--       this audit run and why did each end?" was unanswerable, and a second
--       attempt overwrote the first attempt's `started_at`.
--
-- This migration adds the durable execution identity and the persistence the
-- finalization transaction needs:
--
--   * `audit_executions` — one row per attempt: deterministic attempt number,
--     status, start/end, failure reason, the immutable snapshot it judged, and
--     the lease fields that let a stale worker be refused.
--   * `audit_scanner_runs` — per-execution scanner outcomes plus coverage and
--     limitations, so the canonical audit is reconstructable from storage.
--   * `audit_executions.canonical_json` — the canonical document itself, written
--     in the same commit as the terminal status.
--
-- `findings` gains a nullable `execution_id`. It is nullable so existing rows
-- and the Phase 11 paths keep working; every row written from Phase 12 onward
-- carries one.

CREATE TABLE IF NOT EXISTS audit_executions (
    id                VARCHAR(128) PRIMARY KEY,
    job_id            VARCHAR(128) NOT NULL REFERENCES audit_jobs(id) ON DELETE CASCADE,
    -- Deterministic and dense per job: attempt 1, 2, 3, ... A retry never
    -- reuses a number, so ordering is meaningful and gaps are detectable.
    attempt_number    INTEGER      NOT NULL,
    status            VARCHAR(64)  NOT NULL DEFAULT 'running',
    -- The snapshot this execution judged. Immutable once set (see the guard
    -- below): an execution is a judgement about exactly one tree.
    commit_sha        VARCHAR(64),
    started_at        TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at       TIMESTAMP,
    failure_reason    TEXT,
    -- Lease/ownership. `owner_token` identifies the worker that owns this
    -- execution; a worker that no longer holds the token is stale and is
    -- refused at finalization. `heartbeat_at` is the liveness signal the reaper
    -- uses instead of a bare wall-clock threshold.
    owner_token       VARCHAR(128),
    heartbeat_at      TIMESTAMP,
    created_at        TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- One execution per (job, attempt): the uniqueness that makes an attempt
    -- number trustworthy rather than merely conventional.
    CONSTRAINT uq_audit_execution_attempt UNIQUE (job_id, attempt_number)
);

-- Attempt lookup is the hot path: "what happened on this job, in order?".
CREATE INDEX IF NOT EXISTS idx_audit_executions_job
    ON audit_executions (job_id, attempt_number DESC);

CREATE INDEX IF NOT EXISTS idx_audit_executions_recoverable
    ON audit_executions (status, heartbeat_at)
    WHERE status = 'running';

-- Only one running execution per job. Two workers therefore cannot both own an
-- execution of the same audit, whatever their in-process bookkeeping believes.
CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_executions_one_running
    ON audit_executions (job_id)
    WHERE status = 'running';
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'audit_executions_status_known'
    ) THEN
        ALTER TABLE audit_executions
            ADD CONSTRAINT audit_executions_status_known
            CHECK (status IN (
                'running', 'completed', 'partial', 'failed',
                'cancelled', 'engine_unavailable'
            ));
    END IF;

    -- Attempt numbers are positive: a retry never reuses or rewinds one.
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'audit_executions_attempt_positive'
    ) THEN
        ALTER TABLE audit_executions
            ADD CONSTRAINT audit_executions_attempt_positive
            CHECK (attempt_number >= 1);
    END IF;
END
$$;

-- The canonical audit document, stored with its execution. Nullable: an
-- execution that failed before finalization has no canonical audit, and that
-- absence is meaningful rather than a defect.
ALTER TABLE audit_executions
    ADD COLUMN IF NOT EXISTS canonical_json JSONB;

-- Scanner outcomes per execution. This is the persisted form of what Phase 10
-- calls a canonical scanner run: status, the detail behind it, and the
-- limitations the run contributes to aggregate coverage.
CREATE TABLE IF NOT EXISTS audit_scanner_runs (
    id             VARCHAR(128) PRIMARY KEY,
    execution_id   VARCHAR(128) NOT NULL REFERENCES audit_executions(id) ON DELETE CASCADE,
    scanner        VARCHAR(64)  NOT NULL,
    version        VARCHAR(64)  NOT NULL DEFAULT '',
    parser         VARCHAR(64)  NOT NULL DEFAULT '',
    mode           VARCHAR(64)  NOT NULL DEFAULT '',
    image          VARCHAR(64)  NOT NULL DEFAULT '',
    status         VARCHAR(64)  NOT NULL,
    finding_count  INTEGER,
    coverage_known BOOLEAN      NOT NULL DEFAULT FALSE,
    detail         TEXT,
    limitations    JSONB        NOT NULL DEFAULT '[]'::jsonb,
    created_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- One row per scanner per execution: re-running an execution must not
    -- accumulate duplicate status rows.
    CONSTRAINT uq_audit_scanner_run UNIQUE (execution_id, scanner)
);

CREATE INDEX IF NOT EXISTS idx_audit_scanner_runs_execution
    ON audit_scanner_runs (execution_id);

-- Findings belong to the execution that produced them, so a retry cannot
-- silently replace a previous attempt's evidence.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS execution_id VARCHAR(128);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'findings_execution_fk'
    ) THEN
        ALTER TABLE findings
            ADD CONSTRAINT findings_execution_fk
            FOREIGN KEY (execution_id) REFERENCES audit_executions(id) ON DELETE SET NULL;
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_findings_execution
    ON findings (execution_id)
    WHERE execution_id IS NOT NULL;

-- Terminal executions are immutable. Enforced in the database rather than by
-- convention, so no code path — including a future one — can rewrite the
-- history of an attempt that has already finished.
CREATE OR REPLACE FUNCTION audit_executions_freeze_snapshot() RETURNS TRIGGER AS $$
BEGIN
    IF OLD.commit_sha IS NOT NULL
       AND NEW.commit_sha IS DISTINCT FROM OLD.commit_sha THEN
        RAISE EXCEPTION
            'audit execution % is bound to snapshot % and cannot be rebound',
            OLD.id, OLD.commit_sha
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_executions_snapshot_immutable ON audit_executions;
CREATE TRIGGER audit_executions_snapshot_immutable
    BEFORE UPDATE ON audit_executions
    FOR EACH ROW EXECUTE FUNCTION audit_executions_freeze_snapshot();

-- Once an execution has finished, its row is frozen: status, findings,
-- snapshot, scanner statuses, canonical document, and provenance can no longer
-- be rewritten. The transition out of `running` is still permitted (that is how
-- an execution becomes terminal); every later write is refused.
CREATE OR REPLACE FUNCTION audit_executions_freeze() RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status <> 'running' THEN
        RAISE EXCEPTION
            'audit execution % is already % and its result is immutable',
            OLD.id, OLD.status
            USING ERRCODE = 'restrict_violation';
    END IF;
    -- NEW, not OLD: a BEFORE UPDATE trigger that returns OLD silently discards
    -- the write, which would make finalization a no-op that still reported
    -- success.
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_executions_immutable ON audit_executions;
CREATE TRIGGER audit_executions_immutable
    BEFORE UPDATE ON audit_executions
    FOR EACH ROW EXECUTE FUNCTION audit_executions_freeze();

-- Findings are likewise frozen once their execution is terminal. This is the
-- database-level form of the Phase 11 guarantee: an attempt's evidence cannot
-- be replaced after the attempt has finished, whatever asks.
--
-- DELETE is handled explicitly. In a BEFORE DELETE trigger `NEW` is NULL, so
-- testing the re-parenting branch would evaluate to "changed" and `RETURN NEW`
-- would quietly cancel the delete — the row would survive, but by accident and
-- with no error. An unhandled delete must be a loud refusal instead.
CREATE OR REPLACE FUNCTION findings_freeze_when_execution_terminal() RETURNS TRIGGER AS $$
DECLARE
    exec_status VARCHAR(64);
BEGIN
    IF OLD.execution_id IS NULL THEN
        RETURN COALESCE(NEW, OLD);
    END IF;

    IF TG_OP = 'DELETE' THEN
        SELECT status INTO exec_status FROM audit_executions WHERE id = OLD.execution_id;
        IF exec_status IS NOT NULL AND exec_status <> 'running' THEN
            RAISE EXCEPTION
                'finding % belongs to execution % which is already % and is immutable',
                OLD.id, OLD.execution_id, exec_status
                USING ERRCODE = 'restrict_violation';
        END IF;
        RETURN OLD;
    END IF;

    -- Re-parenting is the one permitted move: a retry attaches its findings to a
    -- new execution, and the previous execution keeps its own record. Anything
    -- else that would edit a finding already owned by a finished execution is
    -- refused.
    IF NEW.execution_id IS DISTINCT FROM OLD.execution_id THEN
        RETURN NEW;
    END IF;
    SELECT status INTO exec_status FROM audit_executions WHERE id = OLD.execution_id;
    IF exec_status IS NOT NULL AND exec_status <> 'running' THEN
        RAISE EXCEPTION
            'finding % belongs to execution % which is already % and is immutable',
            OLD.id, OLD.execution_id, exec_status
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS findings_frozen_with_execution ON findings;
CREATE TRIGGER findings_frozen_with_execution
    BEFORE UPDATE OR DELETE ON findings
    FOR EACH ROW EXECUTE FUNCTION findings_freeze_when_execution_terminal();
