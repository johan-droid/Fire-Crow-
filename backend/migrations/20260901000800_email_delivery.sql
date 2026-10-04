-- Phase 17: delivery state, scoped per execution and per channel.
--
-- Delivery is downstream of a finished audit and is recorded separately from it.
-- Four properties matter here:
--
--   1. Delivery state never rewrites audit state. `audit_jobs.status` and
--      `audit_executions.status` are untouched by this table: a provider
--      rejecting a message is a delivery failure, not a security-audit failure.
--   2. A record belongs to an execution, never merely to a job. The foreign key
--      is to `audit_executions`, so retrying a job produces a completely
--      independent delivery history: attempt 1's report cannot be recorded as
--      attempt 2's, and attempt 2's delivery is not blocked by attempt 1's.
--   3. One (execution, channel, destination, version) produces at most one
--      delivery, structurally. The primary key *is* the idempotency key, so two
--      concurrent requests cannot both proceed: the loser's insert fails rather
--      than being silently ignored.
--   4. A delivered report is a historical fact, exactly like a finalized audit.
--      The trigger below makes that a database invariant rather than a
--      convention.
--
-- `audit_jobs.email_delivery_status` (Phase 12) is job-scoped and predates
-- execution-scoped delivery; it cannot distinguish attempts. This table is the
-- authoritative per-execution record for every channel.

CREATE TABLE IF NOT EXISTS audit_deliveries (
    execution_id VARCHAR(128) NOT NULL REFERENCES audit_executions(id) ON DELETE CASCADE,
    -- 'email' | 'telegram'. A new channel is a migration, so an unknown channel
    -- is rejected by the database instead of being written by a typo.
    channel VARCHAR(32) NOT NULL,
    -- Where this specific attempt went: a recipient address or a chat id. Part of
    -- the idempotency key, so one execution may be delivered to more than one
    -- destination, each with its own independent record and state.
    destination_ref VARCHAR(320) NOT NULL,
    -- The delivery attempt number. `1` is the first send. A deliberate resend
    -- increments it, which creates a *new* row rather than reopening the
    -- previous one -- a frozen 'sent' record is never moved back to 'sending'.
    delivery_version INTEGER NOT NULL DEFAULT 1,
    -- queued -> sending -> sent | failed. 'queued' exists so a request that has
    -- been accepted but not yet attempted is distinguishable from one that was
    -- attempted and failed.
    status VARCHAR(32) NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    -- The provider's own identifier for the delivered message, when the channel
    -- has one. Telegram names the message it accepted, which is what makes a
    -- duplicate-suppression claim auditable. SMTP issues no id, so an email
    -- delivery leaves this null rather than recording a fabricated one -- hence
    -- nullable, and hence not part of the 'sent' constraint below.
    -- Provider-safe: an opaque id, never a payload.
    provider_message_id VARCHAR(128),
    -- Log-safe class name (e.g. 'smtp_authentication', 'telegram_rate_limited').
    -- Never a provider body, never a prompt, never a finding, never a secret.
    failure_class VARCHAR(64),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    -- Set when the delivery reached a terminal state, sent or failed. A delivery
    -- cannot claim a terminal outcome without a timestamp to audit it against.
    completed_at TIMESTAMP,
    -- The idempotency key, and the *only* uniqueness in this table. `ON CONFLICT`
    -- names these four columns, so this constraint is what makes a duplicate
    -- request impossible rather than merely unlikely.
    PRIMARY KEY (execution_id, channel, destination_ref, delivery_version)
);

CREATE INDEX IF NOT EXISTS idx_audit_deliveries_status
    ON audit_deliveries (status);

CREATE INDEX IF NOT EXISTS idx_audit_deliveries_execution
    ON audit_deliveries (execution_id);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'audit_deliveries_channel_known'
    ) THEN
        ALTER TABLE audit_deliveries
            ADD CONSTRAINT audit_deliveries_channel_known
            CHECK (channel IN ('email', 'telegram'));
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'audit_deliveries_status_known'
    ) THEN
        ALTER TABLE audit_deliveries
            ADD CONSTRAINT audit_deliveries_status_known
            CHECK (status IN ('queued', 'sending', 'sent', 'failed'));
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'audit_deliveries_version_positive'
    ) THEN
        ALTER TABLE audit_deliveries
            ADD CONSTRAINT audit_deliveries_version_positive
            CHECK (delivery_version >= 1);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'audit_deliveries_destination_present'
    ) THEN
        -- An empty destination would make the idempotency key meaningless: every
        -- request would collide on the same key regardless of where it was
        -- actually sent.
        ALTER TABLE audit_deliveries
            ADD CONSTRAINT audit_deliveries_destination_present
            CHECK (length(btrim(destination_ref)) > 0);
    END IF;

    -- A terminal delivery must say when it happened, and must say why when it
    -- failed. Both are checked here so no code path can record a bare 'failed'.
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'audit_deliveries_terminal_has_timestamp'
    ) THEN
        ALTER TABLE audit_deliveries
            ADD CONSTRAINT audit_deliveries_terminal_has_timestamp
            CHECK (status NOT IN ('sent', 'failed') OR completed_at IS NOT NULL);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'audit_deliveries_failure_has_class'
    ) THEN
        ALTER TABLE audit_deliveries
            ADD CONSTRAINT audit_deliveries_failure_has_class
            CHECK (status <> 'failed' OR failure_class IS NOT NULL);
    END IF;

    END
$$;

-- The state machine (17.6), as a trigger rather than a CHECK: a CHECK cannot see the
-- previous row, and the edges that matter are all about the transition.
--
-- Legal:    queued -> sending | failed
--           sending -> sent | failed
-- Illegal:  anything -> sent once already sent (handled by the freeze trigger)
--           sent -> anything
CREATE OR REPLACE FUNCTION audit_deliveries_enforce_transition() RETURNS TRIGGER AS $$
DECLARE
    allowed BOOLEAN := FALSE;
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.status = 'sent' THEN
            RAISE EXCEPTION
                'delivery % for execution % is already sent and cannot be deleted',
                OLD.channel, OLD.execution_id
                USING ERRCODE = 'restrict_violation';
        END IF;
        RETURN OLD;
    END IF;

    IF OLD.status = NEW.status THEN
        RETURN NEW;
    END IF;

    allowed := (OLD.status = 'queued'  AND NEW.status IN ('sending', 'failed'))
            OR (OLD.status = 'sending' AND NEW.status IN ('sent', 'failed'));

    IF NOT allowed THEN
        RAISE EXCEPTION
            'illegal delivery transition % -> % for execution % on channel %',
            OLD.status, NEW.status, OLD.execution_id, OLD.channel
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_deliveries_legal_transition ON audit_deliveries;
CREATE TRIGGER audit_deliveries_legal_transition
    BEFORE UPDATE ON audit_deliveries
    FOR EACH ROW EXECUTE FUNCTION audit_deliveries_enforce_transition();

-- A delivered report is a historical fact, exactly like a finalized audit.
-- Moving a record back out of 'sent', or deleting it, would erase the only
-- evidence that the auditor was ever told -- and, for an external channel, the
-- only record that the message was not silently re-sent. A record that never
-- reached 'sent' stays retryable.
CREATE OR REPLACE FUNCTION audit_deliveries_freeze_once_sent() RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status = 'sent' THEN
        RAISE EXCEPTION
            'delivery % for execution % is already sent and cannot be changed or removed',
            OLD.channel, OLD.execution_id
            USING ERRCODE = 'restrict_violation';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_deliveries_frozen_once_sent ON audit_deliveries;
CREATE TRIGGER audit_deliveries_frozen_once_sent
    BEFORE UPDATE OR DELETE ON audit_deliveries
    FOR EACH ROW EXECUTE FUNCTION audit_deliveries_freeze_once_sent();