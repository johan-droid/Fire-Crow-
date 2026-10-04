-- Phase 19B.5: webhook delivery identity (replay protection + dedup).
--
-- One row per GitHub delivery ID. The primary key is the deduplication
-- mechanism: a redelivered event inserts nothing and is acknowledged without
-- reprocessing. `body_sha256` binds the ID to the exact bytes GitHub sent —
-- the same ID with different bytes is a replay with a modified body and is
-- refused, not processed.
--
-- This table records delivery identity only: event names and timestamps for
-- operations, never request bodies, secrets, or tokens.

CREATE TABLE IF NOT EXISTS github_webhook_deliveries (
    delivery_id TEXT PRIMARY KEY CHECK (char_length(delivery_id) BETWEEN 1 AND 128),
    event TEXT NOT NULL CHECK (char_length(event) BETWEEN 1 AND 64),
    body_sha256 TEXT NOT NULL,
    installation_id BIGINT,
    received_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_github_webhook_deliveries_received
    ON github_webhook_deliveries (received_at);
