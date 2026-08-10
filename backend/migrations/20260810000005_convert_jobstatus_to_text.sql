-- Migration: Convert audit_jobs status column to VARCHAR to accept all status strings
ALTER TABLE audit_jobs ALTER COLUMN status TYPE VARCHAR(64) USING status::text;
