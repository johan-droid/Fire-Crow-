-- Audit jobs state transition lifecycle guard (Phase D / H3).
--
-- Enforces that transitions on `audit_jobs.status` adhere strictly to the
-- legal state machine.
--
-- Legal transitions:
--   - 'queued' -> 'running', 'failed', 'cancelled'
--   - 'running' -> 'completed', 'partial', 'failed', 'cancelled', 'engine_unavailable', 'queued' (reaper recovery)
--   - 'failed' / 'cancelled' / 'partial' / 'engine_unavailable' -> 'queued' (retry only)
--
-- Illegal transitions (strictly rejected):
--   - 'queued' -> 'completed', 'partial', 'engine_unavailable'
--   - 'completed' -> ANY (completed is permanently immutable)
--   - 'failed' / 'cancelled' / 'partial' / 'engine_unavailable' -> 'running' (must retry via queued first)

CREATE OR REPLACE FUNCTION audit_jobs_lifecycle_guard() RETURNS TRIGGER AS $$
BEGIN
    -- Permit no-op updates where status is unchanged (e.g. updating commit_sha, cancel_requested, finished_at)
    IF NEW.status = OLD.status THEN
        RETURN NEW;
    END IF;

    -- 'completed' is permanently immutable: cannot transition to any other status
    IF OLD.status = 'completed' THEN
        RAISE EXCEPTION
            'audit job % is already completed and its status is permanently immutable',
            OLD.id
            USING ERRCODE = 'restrict_violation';
    END IF;

    -- Transitions from 'queued'
    IF OLD.status = 'queued' THEN
        IF NEW.status NOT IN ('running', 'failed', 'cancelled') THEN
            RAISE EXCEPTION
                'illegal audit job status transition % -> % for job % (cannot bypass running)',
                OLD.status, NEW.status, OLD.id
                USING ERRCODE = 'restrict_violation';
        END IF;
        RETURN NEW;
    END IF;

    -- Transitions from 'running'
    IF OLD.status = 'running' THEN
        IF NEW.status NOT IN ('completed', 'partial', 'failed', 'cancelled', 'engine_unavailable', 'queued') THEN
            RAISE EXCEPTION
                'illegal audit job status transition % -> % for job %',
                OLD.status, NEW.status, OLD.id
                USING ERRCODE = 'restrict_violation';
        END IF;
        RETURN NEW;
    END IF;

    -- Transitions from non-completed terminal states: only retry to 'queued' is legal
    IF OLD.status IN ('failed', 'cancelled', 'partial', 'engine_unavailable') THEN
        IF NEW.status <> 'queued' THEN
            RAISE EXCEPTION
                'illegal audit job status transition % -> % for job % (terminal jobs may only retry to queued)',
                OLD.status, NEW.status, OLD.id
                USING ERRCODE = 'restrict_violation';
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION
        'unhandled audit job status transition % -> % for job %',
        OLD.status, NEW.status, OLD.id
        USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_jobs_lifecycle_trigger ON audit_jobs;
CREATE TRIGGER audit_jobs_lifecycle_trigger
    BEFORE UPDATE ON audit_jobs
    FOR EACH ROW EXECUTE FUNCTION audit_jobs_lifecycle_guard();
