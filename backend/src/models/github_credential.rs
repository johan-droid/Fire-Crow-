use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GithubCredential {
    pub id: String,
    pub user_id: String,
    pub github_id: String,
    pub access_token: String,
    pub scopes: Option<String>,
    pub created_at: NaiveDateTime,
}

// Secret-safe Debug (Phase 20): the derived impl printed the OAuth token.
// See the `redact_debug!` contract on the sibling model in `user.rs`.
impl std::fmt::Debug for GithubCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GithubCredential")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("github_id", &self.github_id)
            .field("access_token", &"[REDACTED]")
            .field("scopes", &self.scopes)
            .field("created_at", &self.created_at)
            .finish()
    }
}
