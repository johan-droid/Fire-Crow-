-- Add missing ON DELETE CASCADE / SET NULL to various user_id columns

ALTER TABLE audit_jobs
    ADD CONSTRAINT fk_audit_jobs_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE pam_requests
    ADD CONSTRAINT fk_pam_requests_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE user_activity_events
    ADD CONSTRAINT fk_user_activity_events_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE domain_verifications
    ADD CONSTRAINT fk_domain_verifications_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE push_subscriptions
    ADD CONSTRAINT fk_push_subscriptions_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE mfa_configurations
    ADD CONSTRAINT fk_mfa_configurations_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

-- For logs and events, we want to retain the record but set the user_id to NULL if the user is deleted
CREATE TABLE IF NOT EXISTS account_audit_logs (
    id VARCHAR(128) PRIMARY KEY,
    user_id VARCHAR(128) REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(128) NOT NULL,
    details TEXT,
    actor_id VARCHAR(128),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE security_events
    ADD CONSTRAINT fk_security_events_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE security_logs
    ADD CONSTRAINT fk_security_logs_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;
