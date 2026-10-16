-- Phase: account-deletion lifecycle (grace period, cancellation, reminders).
--
-- A deletion is a request, not an immediate erasure. The account stays usable
-- until a persisted deadline passes without a cancellation, at which point a
-- verified deletion-completion event removes it. Reminders fire during the
-- grace period; cancelled requests are never processed.

-- One row per deletion request. `user_id` cascades so the request cannot
-- outlive the account it belongs to, and `status` is constrained so a typo
-- cannot invent a state the worker doesn't understand.
CREATE TABLE IF NOT EXISTS account_deletion_requests (
    id VARCHAR(128) PRIMARY KEY,
    user_id VARCHAR(128) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    requested_at TIMESTAMP NOT NULL DEFAULT NOW(),
    deadline TIMESTAMP NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'requested',
    cancellation_token VARCHAR(128) NOT NULL UNIQUE,
    cancelled_at TIMESTAMP,
    last_reminder_sent TIMESTAMP,
    reminder_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_account_deletion_requests_user_status
    ON account_deletion_requests(user_id, status);
CREATE INDEX IF NOT EXISTS idx_account_deletion_requests_deadline
    ON account_deletion_requests(deadline);

-- Terminal marker on the account itself, set only when deletion has actually
-- completed (deadline passed, no cancellation). Until then the account remains
-- usable and cancellable.
ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'account_deletion_requests_status_known'
    ) THEN
        ALTER TABLE account_deletion_requests
            ADD CONSTRAINT account_deletion_requests_status_known
            CHECK (status IN ('requested', 'cancelled', 'deleted'));
    END IF;
END $$;
