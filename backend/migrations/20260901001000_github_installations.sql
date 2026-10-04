-- Phase 19B.2: GitHub App installation identity.
--
-- Minimum viable identity for "which GitHub account/org installed the App,
-- and which Fire Crow user performed the install". This table answers
-- *identity* only: whether an installation is known, whose account it
-- belongs to, and whether it is suspended.
--
-- Deliberately NOT stored here: installation access tokens (short-lived,
-- memory-only, exchanged in 19B.3), repository lists (resolved live through
-- GitHub in 19B.4 so a removed repository cannot linger as a stale row), and
-- the App private key (operator configuration, never database content).
--
-- Revocation is row deletion (driven by the uninstall webhook in 19B.5, or
-- operator action). A deleted installation is unknown, and every downstream
-- use treats unknown as unauthorized.

CREATE TABLE IF NOT EXISTS github_installations (
    installation_id BIGINT PRIMARY KEY,
    account_id BIGINT NOT NULL,
    account_login TEXT NOT NULL CHECK (char_length(account_login) BETWEEN 1 AND 255),
    account_type TEXT NOT NULL CHECK (account_type IN ('User', 'Organization')),
    -- Fire Crow user who performed the install. Attribution, not an authz
    -- dependency: authorization is re-resolved live through GitHub (19B.4).
    installed_by_user_id TEXT NOT NULL,
    suspended BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_github_installations_account
    ON github_installations (account_id);
