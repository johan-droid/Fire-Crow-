-- Migration: Tenant Usecase, Payment Audit & Privacy Records
-- Created for Fire Crow Backend

ALTER TABLE tenants 
ADD COLUMN IF NOT EXISTS usecase VARCHAR(128) DEFAULT 'security_audit',
ADD COLUMN IF NOT EXISTS industry_type VARCHAR(128) DEFAULT 'technology',
ADD COLUMN IF NOT EXISTS credit_balance DOUBLE PRECISION DEFAULT 0.0,
ADD COLUMN IF NOT EXISTS billing_email VARCHAR(255);

CREATE TABLE IF NOT EXISTS tenant_memberships (
    id VARCHAR(128) PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id VARCHAR(128) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(64) NOT NULL DEFAULT 'member',
    joined_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_tenant_user UNIQUE (tenant_id, user_id)
);

CREATE TABLE IF NOT EXISTS payment_records (
    id VARCHAR(128) PRIMARY KEY,
    user_id VARCHAR(128) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id VARCHAR(128) REFERENCES tenants(id) ON DELETE SET NULL,
    amount DOUBLE PRECISION NOT NULL,
    currency VARCHAR(16) NOT NULL DEFAULT 'USD',
    status VARCHAR(64) NOT NULL DEFAULT 'completed',
    payment_provider VARCHAR(64) NOT NULL DEFAULT 'stripe',
    transaction_reference VARCHAR(255) NOT NULL,
    description TEXT,
    receipt_pdf_url TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS privacy_audit_logs (
    id VARCHAR(128) PRIMARY KEY,
    user_id VARCHAR(128) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id VARCHAR(128) REFERENCES tenants(id) ON DELETE SET NULL,
    event_type VARCHAR(128) NOT NULL,
    anonymized_ip VARCHAR(128) NOT NULL,
    user_agent_hash VARCHAR(128),
    details_json JSONB,
    is_brand_visible BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_tenant_memberships_tenant_id ON tenant_memberships(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_memberships_user_id ON tenant_memberships(user_id);
CREATE INDEX IF NOT EXISTS idx_payment_records_user_id ON payment_records(user_id);
CREATE INDEX IF NOT EXISTS idx_payment_records_tenant_id ON payment_records(tenant_id);
CREATE INDEX IF NOT EXISTS idx_privacy_audit_logs_user_id ON privacy_audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_privacy_audit_logs_tenant_id ON privacy_audit_logs(tenant_id);
