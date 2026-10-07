-- Migration: L6 Database foreign keys and execution ownership integrity
-- Ensures findings cascade with executions, and audit_jobs reference valid users.

-- 1. Ensure findings execution cascade
ALTER TABLE findings DROP CONSTRAINT IF EXISTS fk_findings_execution;
ALTER TABLE findings ADD CONSTRAINT fk_findings_execution
    FOREIGN KEY (execution_id) REFERENCES audit_executions(id) ON DELETE CASCADE;

-- 2. Foreign key from audit_jobs.user_id to users(id) ON DELETE CASCADE
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_audit_jobs_user'
    ) THEN
        ALTER TABLE audit_jobs
            ADD CONSTRAINT fk_audit_jobs_user
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
    END IF;
END $$;
