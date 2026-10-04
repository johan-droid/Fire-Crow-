-- Phase 13: deterministic report persistence.
--
-- A report is keyed by the *execution* that produced it, not the job. Phase 12
-- made an execution the unit of audit identity, so the report that presents an
-- execution's canonical audit must be reconstructable per attempt: a retry that
-- opens attempt N+1 writes its own report row and can never overwrite the report
-- of attempt N.
--
-- The old schema had a single UNIQUE(job_id), which forced retries to clobber
-- the previous attempt's report. That constraint is dropped; the unique key
-- moves to `execution_id`.
ALTER TABLE audit_reports
    ADD COLUMN IF NOT EXISTS execution_id VARCHAR(128);

-- One report per execution. Partial index: legacy report rows predating this
-- migration have a NULL execution_id and are left untouched.
DROP INDEX IF EXISTS uq_audit_reports_execution;
CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_reports_execution
    ON audit_reports (execution_id)
    WHERE execution_id IS NOT NULL;

-- The old per-job uniqueness is incompatible with per-execution reports.
ALTER TABLE audit_reports
    DROP CONSTRAINT IF EXISTS audit_reports_job_id_key;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'audit_reports_execution_fk'
    ) THEN
        ALTER TABLE audit_reports
            ADD CONSTRAINT audit_reports_execution_fk
            FOREIGN KEY (execution_id) REFERENCES audit_executions(id) ON DELETE CASCADE;
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_audit_reports_job ON audit_reports (job_id);

-- The report document itself. `report_json` is the canonical presentation model;
-- `report_schema_version` and `canonical_schema_version` pin the two contracts
-- the stored bytes were produced under, so a reader can refuse a document whose
-- version it does not understand. `html_content` is derived from the same model
-- as `markdown_content` — never from an independent read.
ALTER TABLE audit_reports
    ADD COLUMN IF NOT EXISTS report_json JSONB,
    ADD COLUMN IF NOT EXISTS report_schema_version INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS canonical_schema_version INTEGER;

-- A report may only be attached to an execution that exists. It is written in
-- the same commit that makes the execution terminal, so at write time the
-- execution is still `running`; the foreign key covers existence, and the
-- terminality is enforced by the report generator's read guard.

-- Phase 13: freeze a finalized execution's report, exactly as its findings and
-- its canonical document are frozen.
--
-- Without this, `audit_reports` was the one mutable surface left in a finalized
-- audit: the execution row, the findings, and the scanner runs were all
-- refused a post-terminal write, yet the *report* — the artifact a reader is
-- actually shown — could be edited freely. A tampered report would then be
-- served by the API as if it were the audit's own output, which is precisely
-- the property the whole phase exists to guarantee.
--
-- The transition is still permitted, because that is how a report becomes
-- durable: `finalize_execution` inserts the row while the execution is still
-- `running` and only then writes the terminal status in the same transaction.
-- Rows with a NULL `execution_id` predate this migration and have no owning
-- execution to be frozen by, so they are left alone.
CREATE OR REPLACE FUNCTION audit_reports_freeze_when_execution_terminal() RETURNS TRIGGER AS $$
DECLARE
    exec_status VARCHAR(64);
BEGIN
    IF COALESCE(OLD.execution_id, NEW.execution_id) IS NULL THEN
        RETURN COALESCE(NEW, OLD);
    END IF;

    IF TG_OP = 'DELETE' THEN
        SELECT status INTO exec_status FROM audit_executions WHERE id = OLD.execution_id;
        IF exec_status IS NOT NULL AND exec_status <> 'running' THEN
            RAISE EXCEPTION
                'report % belongs to execution % which is already % and its report is immutable',
                OLD.id, OLD.execution_id, exec_status
                USING ERRCODE = 'restrict_violation';
        END IF;
        RETURN OLD;
    END IF;

    SELECT status INTO exec_status FROM audit_executions WHERE id = NEW.execution_id;
    IF exec_status IS NOT NULL AND exec_status <> 'running' THEN
        RAISE EXCEPTION
            'report % belongs to execution % which is already % and its report is immutable',
            NEW.id, NEW.execution_id, exec_status
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_reports_frozen_with_execution ON audit_reports;
CREATE TRIGGER audit_reports_frozen_with_execution
    BEFORE UPDATE OR DELETE ON audit_reports
    FOR EACH ROW EXECUTE FUNCTION audit_reports_freeze_when_execution_terminal();

-- A report may not be attached to an execution that has already finished: the
-- canonical document and the findings are frozen at that point, so a report
-- written afterwards would present a result that execution never reached.
CREATE OR REPLACE FUNCTION audit_reports_require_live_execution() RETURNS TRIGGER AS $$
DECLARE
    exec_status VARCHAR(64);
BEGIN
    IF NEW.execution_id IS NOT NULL THEN
        SELECT status INTO exec_status FROM audit_executions WHERE id = NEW.execution_id;
        IF exec_status IS NOT NULL AND exec_status <> 'running' THEN
            RAISE EXCEPTION
                'execution % is already % and cannot gain a report', NEW.execution_id, exec_status
                USING ERRCODE = 'restrict_violation';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_reports_require_live_execution ON audit_reports;
CREATE TRIGGER audit_reports_require_live_execution
    BEFORE INSERT ON audit_reports
    FOR EACH ROW EXECUTE FUNCTION audit_reports_require_live_execution();
