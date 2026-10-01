-- Scan-pipeline honesty pass.
--
-- `audit_jobs.started_at` records when a worker actually claimed the job, so the
-- orphan reaper can measure how long a job has *been running* rather than how
-- long ago it was created. Reaping on `created_at` killed jobs that waited a long
-- time in the queue before ever starting.
--
-- `audit_jobs.email_delivery_status` records report-delivery state separately
-- from the job's terminal status: a delivery failure must never turn a
-- `completed` job into a `failed` one.
ALTER TABLE audit_jobs ADD COLUMN IF NOT EXISTS started_at TIMESTAMP;
ALTER TABLE audit_jobs ADD COLUMN IF NOT EXISTS email_delivery_status VARCHAR(32);

CREATE INDEX IF NOT EXISTS idx_audit_jobs_running_started_at
    ON audit_jobs (started_at)
    WHERE status = 'running';
