-- Add unique constraint to payment_records.transaction_reference to prevent double-crediting
ALTER TABLE payment_records ADD CONSTRAINT payment_records_transaction_reference_key UNIQUE (transaction_reference);
