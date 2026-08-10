-- Migration: Fix auth schema to match Rust models
-- This migration fixes mismatches between the initial schema and the Rust User/AuthExchangeCode models

-- 1. Fix the users table
--    - Make email and password_hash optional (OAuth users have neither)
--    - Add all missing columns: github_id, google_id, github_access_token, credit_balance, etc.

ALTER TABLE users
    ALTER COLUMN email DROP NOT NULL,
    ALTER COLUMN password_hash DROP NOT NULL;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS credit_balance DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(128),
    ADD COLUMN IF NOT EXISTS github_id VARCHAR(128),
    ADD COLUMN IF NOT EXISTS google_id VARCHAR(128),
    ADD COLUMN IF NOT EXISTS github_access_token TEXT,
    ADD COLUMN IF NOT EXISTS github_token_scopes TEXT,
    ADD COLUMN IF NOT EXISTS github_token_updated_at TIMESTAMP,
    ADD COLUMN IF NOT EXISTS privacy_policy_version VARCHAR(64),
    ADD COLUMN IF NOT EXISTS privacy_policy_accepted_at TIMESTAMP,
    ADD COLUMN IF NOT EXISTS terms_version VARCHAR(64),
    ADD COLUMN IF NOT EXISTS terms_accepted_at TIMESTAMP,
    ADD COLUMN IF NOT EXISTS first_login_at TIMESTAMP,
    ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP,
    ADD COLUMN IF NOT EXISTS last_logout_at TIMESTAMP,
    ADD COLUMN IF NOT EXISTS region VARCHAR(64),
    ADD COLUMN IF NOT EXISTS timezone VARCHAR(64),
    ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS mfa_secret TEXT;

-- Create unique index on github_id (only for non-null values)
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_github_id ON users(github_id) WHERE github_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id) WHERE google_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE email IS NOT NULL;

-- 2. Fix the auth_exchange_codes table
--    - Add username and access_token columns that the code expects
--    - Remove the mandatory id column (the code uses code as primary identifier)

ALTER TABLE auth_exchange_codes
    ADD COLUMN IF NOT EXISTS username VARCHAR(128),
    ADD COLUMN IF NOT EXISTS access_token TEXT;

-- 3. Fix the audit_jobs table
--    - Add columns that the Rust AuditJob model may reference

ALTER TABLE audit_jobs
    ADD COLUMN IF NOT EXISTS user_id VARCHAR(128),
    ADD COLUMN IF NOT EXISTS budget_usd DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS cost_usd DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS error_message TEXT,
    ADD COLUMN IF NOT EXISTS scanner_output TEXT,
    ADD COLUMN IF NOT EXISTS metadata_json JSONB;

-- 4. Add security_events table used by security_log service

CREATE TABLE IF NOT EXISTS security_events (
    id VARCHAR(128) PRIMARY KEY,
    user_id VARCHAR(128),
    ip_address VARCHAR(64),
    event_type VARCHAR(128) NOT NULL,
    details TEXT,
    metadata_json JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- security_logs table used by security_log service
CREATE TABLE IF NOT EXISTS security_logs (
    id VARCHAR(128) PRIMARY KEY,
    user_id VARCHAR(128),
    tenant_id VARCHAR(128),
    action VARCHAR(128) NOT NULL,
    details_json TEXT,
    ip_hash VARCHAR(128),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
