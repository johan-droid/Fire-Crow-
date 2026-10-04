-- Phase 15A: validated AI narrative persistence.
--
-- A narrative is an optional annotation on a finalized deterministic report,
-- never a replacement for it. It is keyed by the *execution* that produced the
-- report it explains, for the same reason the report itself is: a job can have
-- several attempts, and attempt N+1's explanation must never be served as
-- attempt N's.
--
-- Only the already-validated Phase 14 representation is stored (`narrative_json`
-- holds a `ReportNarrative v1`). The Rust validator remains authoritative for
-- semantic correctness; PostgreSQL enforces identity, lineage, uniqueness, and
-- immutability, and refuses to store a narrative for a still-running execution.
--
-- Lineage is structural: the row stores only `execution_id`, whose FK chains to
-- `audit_executions.job_id`. A narrative therefore cannot name a job other than
-- its execution's own -- there is no second column to disagree with, and no
-- composite/paired key that could be supplied inconsistently.

CREATE TABLE IF NOT EXISTS ai_narratives (
    id VARCHAR(128) PRIMARY KEY,
    execution_id VARCHAR(128) NOT NULL REFERENCES audit_executions(id) ON DELETE CASCADE,
    narrative_json JSONB NOT NULL,
    narrative_schema_version INTEGER NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- One final narrative per execution. A retry opens a new execution and writes
-- its own row; it can never overwrite an earlier attempt's narrative.
DROP INDEX IF EXISTS uq_ai_narratives_execution;
CREATE UNIQUE INDEX IF NOT EXISTS uq_ai_narratives_execution
    ON ai_narratives (execution_id);

-- Every lookup is execution-scoped, and `audit_executions (job_id)` is already
-- indexed for the job-scoped step, so this needs no second index.

-- A narrative is an *explanation of a finalized deterministic report*, so the
-- report it explains is a precondition, not a coincidence. Enforced relationally:
--
--     ai_narratives.execution_id
--         -> audit_executions.id          (exists, and is not `running`)
--         -> audit_reports.execution_id   (that execution's report is finalized)
--
-- The second hop is what makes this impossible without enumerating the lifecycle
-- state machine here. Reports are inserted in the same transaction that makes the
-- execution terminal, so "this execution has a report row" *is* "this execution's
-- deterministic report is finalized" — no separate finalized flag, no second
-- source of truth for status, and no list of success statuses that can go stale.
-- Any execution that ended without a deterministic report (failed, cancelled,
-- engine_unavailable) fails here whatever its status says.
--
-- SECURITY DEFINER because a cross-table invariant is not expressible as CHECK
-- or FK, and must not be bypassable by a caller lacking read access on
-- audit_executions / audit_reports.
CREATE OR REPLACE FUNCTION ai_narratives_require_finalized_report() RETURNS TRIGGER AS $$
DECLARE
    exec_status VARCHAR(64);
BEGIN
    SELECT status INTO exec_status FROM audit_executions WHERE id = NEW.execution_id;
    IF exec_status IS NULL THEN
        RAISE EXCEPTION
            'execution % does not exist and cannot gain a narrative', NEW.execution_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    IF exec_status = 'running' THEN
        RAISE EXCEPTION
            'execution % is still running and cannot gain a final narrative', NEW.execution_id
            USING ERRCODE = 'restrict_violation';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM audit_reports WHERE execution_id = NEW.execution_id
    ) THEN
        RAISE EXCEPTION
            'execution % is % and has no finalized deterministic report, so it cannot gain an AI narrative',
            NEW.execution_id, exec_status
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS ai_narratives_require_finalized_report ON ai_narratives;
CREATE TRIGGER ai_narratives_require_finalized_report
    BEFORE INSERT ON ai_narratives
    FOR EACH ROW EXECUTE FUNCTION ai_narratives_require_finalized_report();

-- Once persisted for a finalized execution, the narrative is immutable.
-- Mutation attempts raise rather than silently doing nothing (never RETURN OLD
-- to discard a write): a rejected UPDATE/DELETE is evidence, a silent one is a
-- lie about what the audit said.
CREATE OR REPLACE FUNCTION ai_narratives_freeze_when_terminal() RETURNS TRIGGER AS $$
-- SECURITY DEFINER so the immutability guard cannot be bypassed either; it
-- always raises, so it grants no data access beyond the status read.
DECLARE
    exec_status VARCHAR(64);
BEGIN
    IF TG_OP = 'DELETE' THEN
        SELECT status INTO exec_status FROM audit_executions WHERE id = OLD.execution_id;
        RAISE EXCEPTION
            'narrative for execution % is immutable and cannot be deleted (execution status: %)',
            OLD.execution_id, COALESCE(exec_status, 'unknown')
            USING ERRCODE = 'restrict_violation';
    END IF;

    SELECT status INTO exec_status FROM audit_executions WHERE id = NEW.execution_id;
    RAISE EXCEPTION
        'narrative for execution % is immutable and cannot be updated (execution status: %)',
        NEW.execution_id, COALESCE(exec_status, 'unknown')
        USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS ai_narratives_frozen_once_written ON ai_narratives;
CREATE TRIGGER ai_narratives_frozen_once_written
    BEFORE UPDATE OR DELETE ON ai_narratives
    FOR EACH ROW EXECUTE FUNCTION ai_narratives_freeze_when_terminal();
