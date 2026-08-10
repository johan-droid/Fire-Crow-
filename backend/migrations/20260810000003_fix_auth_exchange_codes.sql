-- Ensure auth_exchange_codes table has all required columns and constraints

ALTER TABLE auth_exchange_codes
    ADD COLUMN IF NOT EXISTS id VARCHAR(128),
    ADD COLUMN IF NOT EXISTS username VARCHAR(128),
    ADD COLUMN IF NOT EXISTS access_token TEXT;
