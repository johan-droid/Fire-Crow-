-- Migration: Add missing columns to audit_jobs and audit_reports tables
ALTER TABLE audit_jobs
    ADD COLUMN IF NOT EXISTS cancel_requested BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS cancel_requested_at TIMESTAMP,
    ADD COLUMN IF NOT EXISTS report_pdf_url TEXT,
    ADD COLUMN IF NOT EXISTS security_score DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS finished_at TIMESTAMP,
    ADD COLUMN IF NOT EXISTS legal_hold BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE audit_reports
    ADD COLUMN IF NOT EXISTS html_content TEXT;
