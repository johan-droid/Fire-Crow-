-- Migration: Ensure default values and nullability on auth_exchange_codes table
ALTER TABLE auth_exchange_codes
    ADD COLUMN IF NOT EXISTS id VARCHAR(128),
    ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP,
    ALTER COLUMN created_at DROP NOT NULL;

ALTER TABLE auth_exchange_codes
    ALTER COLUMN id DROP NOT NULL;
