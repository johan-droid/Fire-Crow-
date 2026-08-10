-- Migration: Create phase_ledger table for audit phase tracking
CREATE TABLE IF NOT EXISTS phase_ledger (
    id VARCHAR(128) PRIMARY KEY,
    job_id VARCHAR(128) NOT NULL,
    phase_name VARCHAR(128) NOT NULL,
    status VARCHAR(64) NOT NULL,
    mode VARCHAR(64) NOT NULL DEFAULT 'real',
    started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMP,
    duration_sec DOUBLE PRECISION,
    error_message TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_phase_ledger_job_id ON phase_ledger(job_id);
