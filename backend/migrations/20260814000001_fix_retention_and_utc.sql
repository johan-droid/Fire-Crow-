-- Fix unbound growth in tables by adding an explicit TTL column if possible, but actually we will just add a migration to ensure tables have ON DELETE CASCADE for foreign keys.

ALTER TABLE role_permissions
    ADD CONSTRAINT fk_role_permissions_role_id FOREIGN KEY (role_id) REFERENCES iam_policies(id) ON DELETE CASCADE;

ALTER TABLE auth_exchange_codes
    ADD CONSTRAINT fk_auth_exchange_codes_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
