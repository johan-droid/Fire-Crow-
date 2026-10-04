-- Phase 19B.6: webhook-created jobs reuse the one submission path, crash-safely.
--
-- `audit_jobs.webhook_delivery_id` makes one GitHub delivery produce at most
-- one job: the insert is `ON CONFLICT DO NOTHING` and a redelivery finds the
-- existing row instead of queueing a second audit. NULL for user-submitted
-- jobs; the UNIQUE constraint ignores NULLs, so those are unaffected.
--
-- `audit_jobs.github_installation_id` links a webhook-created job to the
-- installation that authorized it (19B.7 Check Runs need it to report back).
-- It is attribution, not a foreign key into live authorization: every use
-- re-resolves through GitHub, and a revoked installation simply fails closed.
--
-- `github_webhook_deliveries.outcome` lets a redelivery distinguish "already
-- handled, acknowledge" (processed/ignored) from "the first attempt died
-- before finishing, try again" (pending/failed_transient). Without it,
-- recording the ID before processing would turn a crash into a silently
-- dropped audit.

ALTER TABLE audit_jobs
    ADD COLUMN IF NOT EXISTS webhook_delivery_id TEXT UNIQUE,
    ADD COLUMN IF NOT EXISTS github_installation_id BIGINT;

ALTER TABLE github_webhook_deliveries
    ADD COLUMN IF NOT EXISTS outcome TEXT NOT NULL DEFAULT 'pending'
    CHECK (outcome IN ('pending', 'processed', 'ignored', 'failed_transient'));
