//! GitHub App installation identity (Phase 19B.2).
//!
//! Identity only: which account/org holds the installation and whether it is
//! suspended. No tokens, no repository lists, no key material — those are
//! resolved live (19B.3/19B.4) or live in operator configuration (19B.1).

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

/// One row of `github_installations`.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GithubInstallation {
    pub installation_id: i64,
    pub account_id: i64,
    pub account_login: String,
    pub account_type: String,
    pub installed_by_user_id: String,
    pub suspended: bool,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}
