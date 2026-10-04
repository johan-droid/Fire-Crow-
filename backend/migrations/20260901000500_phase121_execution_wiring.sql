-- Phase 12.1: wire the production pipeline to execution identity.
ALTER TABLE phase_ledger ADD COLUMN IF NOT EXISTS execution_id VARCHAR(128);
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'phase_ledger_execution_fk') THEN
        ALTER TABLE phase_ledger ADD CONSTRAINT phase_ledger_execution_fk FOREIGN KEY (execution_id) REFERENCES audit_executions(id) ON DELETE SET NULL;
    END IF;
END
$$;
CREATE INDEX IF NOT EXISTS idx_phase_ledger_execution ON phase_ledger (execution_id) WHERE execution_id IS NOT NULL;
CREATE OR REPLACE FUNCTION audit_executions_freeze_delete() RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status <> 'running' THEN
        RAISE EXCEPTION 'audit execution % is already % and cannot be deleted', OLD.id, OLD.status USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS audit_executions_immutable_delete ON audit_executions;
CREATE TRIGGER audit_executions_immutable_delete BEFORE DELETE ON audit_executions FOR EACH ROW EXECUTE FUNCTION audit_executions_freeze_delete();
CREATE OR REPLACE FUNCTION findings_freeze_when_execution_terminal() RETURNS TRIGGER AS $$
DECLARE
    exec_status VARCHAR(64);
    job_status VARCHAR(64);
BEGIN
    IF TG_OP <> 'DELETE' AND OLD.execution_id IS NULL AND NEW.execution_id IS NULL THEN
        SELECT status INTO job_status FROM audit_jobs WHERE id = OLD.job_id;
        IF job_status IN ('completed','partial','failed','cancelled','engine_unavailable') THEN
            RAISE EXCEPTION 'finding % belongs to job % which is already % and is immutable', OLD.id, OLD.job_id, job_status USING ERRCODE = 'restrict_violation';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.execution_id IS NULL THEN
        IF TG_OP = 'DELETE' THEN
            SELECT status INTO job_status FROM audit_jobs WHERE id = OLD.job_id;
            IF job_status IN ('completed','partial','failed','cancelled','engine_unavailable') THEN
                RAISE EXCEPTION 'finding % belongs to job % which is already % and is immutable', OLD.id, OLD.job_id, job_status USING ERRCODE = 'restrict_violation';
            END IF;
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        SELECT status INTO exec_status FROM audit_executions WHERE id = OLD.execution_id;
        IF exec_status IS NOT NULL AND exec_status <> 'running' THEN
            RAISE EXCEPTION 'finding % belongs to execution % which is already % and is immutable', OLD.id, OLD.execution_id, exec_status USING ERRCODE = 'restrict_violation';
        END IF;
        RETURN OLD;
    END IF;
    IF NEW.execution_id IS DISTINCT FROM OLD.execution_id THEN
        -- Re-parenting is the one permitted move. Finding identity is
        -- content-stable (canonical fingerprint), so the same detection found
        -- by a retry is the same row adopted by the new execution; the
        -- previous attempt's own history (status, scanner runs, canonical
        -- document) is untouched and stays immutable.
        RETURN NEW;
    END IF;
    SELECT status INTO exec_status FROM audit_executions WHERE id = OLD.execution_id;
    IF exec_status IS NOT NULL AND exec_status <> 'running' THEN
        RAISE EXCEPTION 'finding % belongs to execution % which is already % and is immutable', OLD.id, OLD.execution_id, exec_status USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS findings_frozen_with_execution ON findings;
CREATE TRIGGER findings_frozen_with_execution BEFORE UPDATE OR DELETE ON findings FOR EACH ROW EXECUTE FUNCTION findings_freeze_when_execution_terminal();
CREATE OR REPLACE FUNCTION findings_require_live_parent() RETURNS TRIGGER AS $$
DECLARE
    exec_status VARCHAR(64);
    job_status VARCHAR(64);
BEGIN
    IF NEW.execution_id IS NOT NULL THEN
        SELECT status INTO exec_status FROM audit_executions WHERE id = NEW.execution_id;
        IF exec_status IS NOT NULL AND exec_status <> 'running' THEN
            RAISE EXCEPTION 'execution % is already % and cannot gain findings', NEW.execution_id, exec_status USING ERRCODE = 'restrict_violation';
        END IF;
        RETURN NEW;
    END IF;
    SELECT status INTO job_status FROM audit_jobs WHERE id = NEW.job_id;
    IF job_status IN ('completed','partial','failed','cancelled','engine_unavailable') THEN
        RAISE EXCEPTION 'job % is already % and cannot gain findings outside an execution', NEW.job_id, job_status USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS findings_live_parent_only ON findings;
CREATE TRIGGER findings_live_parent_only BEFORE INSERT ON findings FOR EACH ROW EXECUTE FUNCTION findings_require_live_parent();
