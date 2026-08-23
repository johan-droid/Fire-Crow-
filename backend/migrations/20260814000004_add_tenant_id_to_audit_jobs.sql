-- Migration: Add missing tenant_id column to audit_jobs table for multi-tenancy isolation
ALTER TABLE audit_jobs
    ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(128);

CREATE INDEX IF NOT EXISTS idx_audit_jobs_tenant_id ON audit_jobs(tenant_id);
