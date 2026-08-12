-- Migration: Security hardening — MFA configuration/persistence + DB token revocation
-- Adds the tables required by the (previously broken) MFA flow and a database-backed
-- token revocation store used when Redis is unavailable (HIGH-02).

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS mfa_enforced BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS mfa_configurations (
    id VARCHAR(128) PRIMARY KEY,
    user_id VARCHAR(128) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    secret TEXT,
    backup_codes_consumed INTEGER NOT NULL DEFAULT 0,
    last_verified_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_mfa_config_user UNIQUE (user_id)
);

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    id VARCHAR(128) PRIMARY KEY,
    mfa_config_id VARCHAR(128) NOT NULL REFERENCES mfa_configurations(id) ON DELETE CASCADE,
    code_hash VARCHAR(128) NOT NULL,
    used_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_mfa_recovery_codes_config ON mfa_recovery_codes(mfa_config_id);

CREATE TABLE IF NOT EXISTS token_revocations (
    id VARCHAR(128) PRIMARY KEY,
    jti VARCHAR(128) NOT NULL UNIQUE,
    token_family VARCHAR(128) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_token_revocations_family ON token_revocations(token_family);
CREATE INDEX IF NOT EXISTS idx_login_failures_key ON login_failures(key_hash);