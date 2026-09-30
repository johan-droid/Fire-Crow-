-- Phase 4: reconcile the application models with the database schema.
--
-- Root cause: `FromRow` is derived rather than compiled, so structs could name
-- columns that no migration created and the crate still built. The mismatch only
-- surfaced at request time, and only once a row existed (an empty table never
-- attempts decoding, so these endpoints returned `200 []`).
--
-- This migration adds the missing columns and the three tables that application
-- code writes but no migration ever created. Every statement is idempotent.
--
-- Data-safety notes:
--   * Added NOT NULL columns carry a DEFAULT, so existing rows survive.
--   * Nothing is reinterpreted. `role_permissions.role_id` still references
--     `iam_policies(id)` here; Phase 5 introduces `roles` and re-points it, after
--     inspecting the existing rows.
--   * `users.tenant_id` is deliberately left unconstrained. There is no
--     users->tenants relationship in this schema, and inventing one would
--     manufacture tenancy semantics that no code implements.

-- ---------------------------------------------------------------------------
-- sso_providers: the migrations only ever created 7 of the OIDC provider shape.
-- ---------------------------------------------------------------------------
ALTER TABLE sso_providers ADD COLUMN IF NOT EXISTS authorization_url   TEXT;
ALTER TABLE sso_providers ADD COLUMN IF NOT EXISTS token_url           TEXT;
ALTER TABLE sso_providers ADD COLUMN IF NOT EXISTS userinfo_url        TEXT;
ALTER TABLE sso_providers ADD COLUMN IF NOT EXISTS jwks_url            TEXT;
ALTER TABLE sso_providers ADD COLUMN IF NOT EXISTS certificate         TEXT;
ALTER TABLE sso_providers ADD COLUMN IF NOT EXISTS attribute_mapping   TEXT;
ALTER TABLE sso_providers ADD COLUMN IF NOT EXISTS domains             VARCHAR(255);
ALTER TABLE sso_providers ADD COLUMN IF NOT EXISTS enforce_mfa         BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE sso_providers ADD COLUMN IF NOT EXISTS auto_provision      BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE sso_providers ADD COLUMN IF NOT EXISTS default_role_id     VARCHAR(128);

-- ---------------------------------------------------------------------------
-- audit_artifacts: had no owner column at all, so object-level authorization
-- was impossible.
--
-- Per the Phase 4 decision:
--   * user_id          is the immediate ownership / authorization boundary and is
--                      what /storage/* filters on.
--   * organization_id  is retained as the future tenancy boundary. It is NOT
--                      wired to users or tenants here; there is no such
--                      relationship in this schema yet.
-- ---------------------------------------------------------------------------
ALTER TABLE audit_artifacts ADD COLUMN IF NOT EXISTS user_id            VARCHAR(128);
ALTER TABLE audit_artifacts ADD COLUMN IF NOT EXISTS organization_id     VARCHAR(128) NOT NULL DEFAULT '';
ALTER TABLE audit_artifacts ADD COLUMN IF NOT EXISTS artifact_type      VARCHAR(64)  NOT NULL DEFAULT 'report';
ALTER TABLE audit_artifacts ADD COLUMN IF NOT EXISTS file_name           TEXT         NOT NULL DEFAULT '';
ALTER TABLE audit_artifacts ADD COLUMN IF NOT EXISTS size_bytes          BIGINT       NOT NULL DEFAULT 0;
ALTER TABLE audit_artifacts ADD COLUMN IF NOT EXISTS sha256              VARCHAR(64)  NOT NULL DEFAULT '';
ALTER TABLE audit_artifacts ADD COLUMN IF NOT EXISTS mime_type           TEXT;
ALTER TABLE audit_artifacts ADD COLUMN IF NOT EXISTS storage_key         TEXT         NOT NULL DEFAULT '';
ALTER TABLE audit_artifacts ADD COLUMN IF NOT EXISTS sensitivity_level   VARCHAR(32)  NOT NULL DEFAULT 'internal';
ALTER TABLE audit_artifacts ADD COLUMN IF NOT EXISTS legal_hold          BOOLEAN      NOT NULL DEFAULT FALSE;

-- Backfill ownership from the job that produced the artifact, so pre-existing
-- rows are attributable rather than ownerless.
UPDATE audit_artifacts a
   SET user_id = j.user_id
  FROM audit_jobs j
 WHERE a.job_id = j.id
   AND a.user_id IS NULL;

-- Ownerless artifacts can never be served by an owner-scoped query, so deny
-- them explicitly rather than leaving them matchable.
ALTER TABLE audit_artifacts ALTER COLUMN user_id SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_audit_artifacts_user_id'
    ) THEN
        ALTER TABLE audit_artifacts
            ADD CONSTRAINT fk_audit_artifacts_user_id
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_audit_artifacts_user_id ON audit_artifacts (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_artifacts_job_id  ON audit_artifacts (job_id);

-- ---------------------------------------------------------------------------
-- iam_policies: the policy document body had no columns, so no policy could
-- express a rule.
-- ---------------------------------------------------------------------------
ALTER TABLE iam_policies ADD COLUMN IF NOT EXISTS effect       VARCHAR(16) NOT NULL DEFAULT 'Deny';
ALTER TABLE iam_policies ADD COLUMN IF NOT EXISTS actions      VARCHAR(64) NOT NULL DEFAULT '';
ALTER TABLE iam_policies ADD COLUMN IF NOT EXISTS resources    VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE iam_policies ADD COLUMN IF NOT EXISTS description  TEXT;
ALTER TABLE iam_policies ADD COLUMN IF NOT EXISTS conditions   TEXT;

-- ---------------------------------------------------------------------------
-- role_permissions: iam_service.rs has always inserted resource_pattern.
-- ---------------------------------------------------------------------------
ALTER TABLE role_permissions ADD COLUMN IF NOT EXISTS resource_pattern VARCHAR(255) NOT NULL DEFAULT '*';

-- ---------------------------------------------------------------------------
-- tenants: lifecycle and quota fields were absent, so /tenant/* could not work.
-- ---------------------------------------------------------------------------
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS domain         VARCHAR(255);
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS plan           VARCHAR(64)  NOT NULL DEFAULT 'free';
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS max_users      INTEGER;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS max_storage_gb INTEGER;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS is_active      BOOLEAN NOT NULL DEFAULT TRUE;

-- ---------------------------------------------------------------------------
-- domain_verifications: only token verification was modelled, while
-- services/domain_verify.rs implements DNS TXT, /.well-known/ and HTML-meta.
-- ---------------------------------------------------------------------------
ALTER TABLE domain_verifications ADD COLUMN IF NOT EXISTS verified_at      TIMESTAMP;
ALTER TABLE domain_verifications ADD COLUMN IF NOT EXISTS dns_txt_name     VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE domain_verifications ADD COLUMN IF NOT EXISTS dns_txt_value    VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE domain_verifications ADD COLUMN IF NOT EXISTS html_meta_name   VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE domain_verifications ADD COLUMN IF NOT EXISTS html_meta_content VARCHAR(512) NOT NULL DEFAULT '';
ALTER TABLE domain_verifications ADD COLUMN IF NOT EXISTS well_known_path  VARCHAR(512) NOT NULL DEFAULT '';
ALTER TABLE domain_verifications ADD COLUMN IF NOT EXISTS well_known_content TEXT NOT NULL DEFAULT '';

-- ---------------------------------------------------------------------------
-- pam_requests / pam_grants: the approval workflow was not representable.
-- ---------------------------------------------------------------------------
ALTER TABLE pam_requests ADD COLUMN IF NOT EXISTS role_name                 VARCHAR(128) NOT NULL DEFAULT '';
ALTER TABLE pam_requests ADD COLUMN IF NOT EXISTS permission                VARCHAR(128) NOT NULL DEFAULT '';
ALTER TABLE pam_requests ADD COLUMN IF NOT EXISTS requested_duration_minutes INTEGER      NOT NULL DEFAULT 60;
ALTER TABLE pam_requests ADD COLUMN IF NOT EXISTS ticket_ref                VARCHAR(128);
ALTER TABLE pam_requests ADD COLUMN IF NOT EXISTS approver_id               VARCHAR(128);
ALTER TABLE pam_requests ADD COLUMN IF NOT EXISTS deny_reason               TEXT;
ALTER TABLE pam_requests ADD COLUMN IF NOT EXISTS started_at                TIMESTAMP;
ALTER TABLE pam_requests ADD COLUMN IF NOT EXISTS ends_at                   TIMESTAMP;

ALTER TABLE pam_grants ADD COLUMN IF NOT EXISTS granted_by VARCHAR(128) NOT NULL DEFAULT '';
ALTER TABLE pam_grants ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP;
ALTER TABLE pam_grants ADD COLUMN IF NOT EXISTS revoked_by VARCHAR(128);

CREATE INDEX IF NOT EXISTS idx_pam_requests_user_id ON pam_requests (user_id);
CREATE INDEX IF NOT EXISTS idx_pam_grants_user_id   ON pam_grants   (user_id);

-- ---------------------------------------------------------------------------
-- Tables that application code writes but no migration ever created. Every
-- write to these failed at runtime.
-- ---------------------------------------------------------------------------

-- Every PAM grant revocation inserts here, so revocations were never recorded.
CREATE TABLE IF NOT EXISTS pam_audit (
    id         VARCHAR(128) PRIMARY KEY,
    request_id VARCHAR(128),
    action     VARCHAR(64)  NOT NULL,
    actor_id   VARCHAR(128),
    details    TEXT,
    created_at TIMESTAMP    NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_pam_audit_request_id ON pam_audit (request_id);

CREATE TABLE IF NOT EXISTS mfa_audit_logs (
    id         VARCHAR(128) PRIMARY KEY,
    user_id    VARCHAR(128) NOT NULL,
    action     VARCHAR(64)  NOT NULL,
    success    BOOLEAN      NOT NULL DEFAULT TRUE,
    ip_hash    VARCHAR(128),
    created_at TIMESTAMP    NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_mfa_audit_logs_user_id ON mfa_audit_logs (user_id);

CREATE TABLE IF NOT EXISTS service_accounts (
    id          VARCHAR(128) PRIMARY KEY,
    name        VARCHAR(128) NOT NULL,
    -- Only a hash is stored; the plaintext token is shown once at creation.
    token_hash  VARCHAR(255) NOT NULL,
    permissions VARCHAR(255) NOT NULL DEFAULT '',
    description TEXT,
    expires_at  TIMESTAMP,
    created_by  VARCHAR(128) NOT NULL,
    is_active   BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMP    NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_service_accounts_created_by ON service_accounts (created_by);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_service_accounts_created_by'
    ) THEN
        ALTER TABLE service_accounts
            ADD CONSTRAINT fk_service_accounts_created_by
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE;
    END IF;
END $$;