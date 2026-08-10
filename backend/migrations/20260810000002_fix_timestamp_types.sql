-- Dynamically convert ALL TIMESTAMPTZ columns in the entire schema to TIMESTAMP WITHOUT TIME ZONE
-- This solves SQLx type mismatches (NaiveDateTime <-> TIMESTAMPTZ) once and for all across all tables.

DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN 
        SELECT table_name, column_name 
        FROM information_schema.columns 
        WHERE table_schema = 'public' 
          AND data_type = 'timestamp with time zone'
    LOOP
        RAISE NOTICE 'Converting %.% from TIMESTAMPTZ to TIMESTAMP', r.table_name, r.column_name;
        EXECUTE format('ALTER TABLE %I ALTER COLUMN %I TYPE TIMESTAMP WITHOUT TIME ZONE USING %I AT TIME ZONE ''UTC''', 
                       r.table_name, r.column_name, r.column_name);
    END LOOP;
END $$;
