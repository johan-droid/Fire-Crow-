-- Migration: Initial Schema for Neon PostgreSQL
-- Created for Fire Crow Backend

CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(128) PRIMARY KEY,
    username VARCHAR(128) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role_id VARCHAR(128),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_jobs (
    id VARCHAR(128) PRIMARY KEY,
    user_id VARCHAR(128) NOT NULL,
    repo_url TEXT NOT NULL,
    repo_branch VARCHAR(255) NOT NULL DEFAULT 'main',
    status VARCHAR(64) NOT NULL,
    report_id VARCHAR(128),
    score INTEGER,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
    id VARCHAR(128) PRIMARY KEY,
    job_id VARCHAR(128) NOT NULL REFERENCES audit_jobs(id) ON DELETE CASCADE,
    agent_source VARCHAR(128) NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(64) NOT NULL,
    cvss_vector VARCHAR(128),
    cvss_score DOUBLE PRECISION,
    evidence TEXT,
    remediation TEXT,
    cwe_id VARCHAR(64),
    owasp_category VARCHAR(128),
    confidence VARCHAR(64),
    scanner_name VARCHAR(128),
    scanner_mode VARCHAR(128),
    file_path TEXT,
    line_number INTEGER,
    route TEXT,
    metadata_json JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_reports (
    id VARCHAR(128) PRIMARY KEY,
    job_id VARCHAR(128) NOT NULL UNIQUE REFERENCES audit_jobs(id) ON DELETE CASCADE,
    markdown_content TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_artifacts (
    id VARCHAR(128) PRIMARY KEY,
    job_id VARCHAR(128) NOT NULL REFERENCES audit_jobs(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    file_path TEXT NOT NULL,
    storage_backend VARCHAR(64) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Attack Graph Nodes (Migrated from Neo4j AttackNode)
CREATE TABLE IF NOT EXISTS attack_graph_nodes (
    id VARCHAR(128) PRIMARY KEY,
    job_id VARCHAR(128) NOT NULL REFERENCES audit_jobs(id) ON DELETE CASCADE,
    node_id VARCHAR(128) NOT NULL,
    label TEXT NOT NULL,
    severity VARCHAR(64) NOT NULL,
    node_type VARCHAR(64) NOT NULL DEFAULT 'vulnerability',
    metadata_json JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_attack_node_job_id_node_id UNIQUE (job_id, node_id)
);

-- Attack Graph Edges (Migrated from Neo4j CHAINED relationships)
CREATE TABLE IF NOT EXISTS attack_graph_edges (
    id VARCHAR(128) PRIMARY KEY,
    job_id VARCHAR(128) NOT NULL REFERENCES audit_jobs(id) ON DELETE CASCADE,
    source_node_id VARCHAR(128) NOT NULL,
    target_node_id VARCHAR(128) NOT NULL,
    label TEXT NOT NULL DEFAULT 'chained',
    metadata_json JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_attack_edge_job_source_target_label UNIQUE (job_id, source_node_id, target_node_id, label)
);

CREATE TABLE IF NOT EXISTS pam_requests (
    id VARCHAR(128) PRIMARY KEY,
    user_id VARCHAR(128) NOT NULL,
    target_resource VARCHAR(255) NOT NULL,
    reason TEXT NOT NULL,
    status VARCHAR(64) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS pam_grants (
    id VARCHAR(128) PRIMARY KEY,
    request_id VARCHAR(128) NOT NULL REFERENCES pam_requests(id) ON DELETE CASCADE,
    user_id VARCHAR(128) NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_activity_events (
    id VARCHAR(128) PRIMARY KEY,
    user_id VARCHAR(128) NOT NULL,
    action VARCHAR(128) NOT NULL,
    details_json JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS domain_verifications (
    id VARCHAR(128) PRIMARY KEY,
    user_id VARCHAR(128) NOT NULL,
    domain VARCHAR(255) NOT NULL,
    verification_token VARCHAR(255) NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sso_providers (
    id VARCHAR(128) PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    provider_type VARCHAR(64) NOT NULL,
    issuer_url TEXT,
    client_id VARCHAR(255),
    client_secret TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tenants (
    id VARCHAR(128) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(128) NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS push_subscriptions (
    id VARCHAR(128) PRIMARY KEY,
    user_id VARCHAR(128) NOT NULL,
    endpoint TEXT NOT NULL,
    p256dh TEXT NOT NULL,
    auth TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS login_failures (
    id VARCHAR(128) PRIMARY KEY,
    key_hash VARCHAR(128) NOT NULL,
    attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS auth_exchange_codes (
    id VARCHAR(128) PRIMARY KEY,
    code VARCHAR(128) NOT NULL UNIQUE,
    user_id VARCHAR(128) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS iam_policies (
    id VARCHAR(128) PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    policy_json JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS role_permissions (
    id VARCHAR(128) PRIMARY KEY,
    role_id VARCHAR(128) NOT NULL,
    permission VARCHAR(128) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_attack_nodes_job_id ON attack_graph_nodes(job_id);
CREATE INDEX IF NOT EXISTS idx_attack_edges_job_id ON attack_graph_edges(job_id);
CREATE INDEX IF NOT EXISTS idx_findings_job_id ON findings(job_id);
