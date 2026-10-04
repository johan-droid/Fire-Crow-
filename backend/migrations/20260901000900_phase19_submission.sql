-- Phase 19.4: the submission contract can pin an immutable commit SHA.
--
-- Every execution already pins the snapshot it judged (`commit_sha`, set by
-- the fetch phase). This column records what the *caller asked for*: either
-- NULL (scan the branch head, resolved at fetch time) or an exact SHA the
-- fetch phase must use verbatim instead of resolving a branch head.
--
-- Nullable and additive, so existing databases upgrade without a backfill:
-- every pre-existing job asked for a branch head, which NULL already means.
-- The format is enforced by a CHECK (40 lowercase hex), so no code path can
-- store a branch name, URL, or empty string here and have the fetch phase
-- mistake it for a pinned snapshot.

ALTER TABLE audit_jobs
    ADD COLUMN IF NOT EXISTS requested_commit_sha VARCHAR(40);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'audit_jobs_requested_sha_shape'
    ) THEN
        ALTER TABLE audit_jobs
            ADD CONSTRAINT audit_jobs_requested_sha_shape
            CHECK (
                requested_commit_sha IS NULL
                OR requested_commit_sha ~ '^[0-9a-f]{40}$'
            );
    END IF;
END
$$;
