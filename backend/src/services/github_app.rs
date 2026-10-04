//! GitHub App identity — Phase 19B.1.
//!
//! ```text
//!   App ID + RSA private key (operator configuration)
//!       ↓
//!   App JWT (RS256, ≤10 min lifetime, in memory only)
//!       ↓
//!   installation token exchange (19B.3) / Check Runs (19B.7)
//! ```
//!
//! This module is identity only: it mints the short-lived JWT that
//! authenticates *as the App*. It performs no repository access and persists
//! nothing. The private key lives in this struct, which has no `Debug` impl,
//! and never enters an error message, a log line, or a database row.

use crate::error::{AppError, Result};

/// How far back `iat` is set, absorbing clock skew between Fire Crow and
/// GitHub. GitHub rejects an `iat` more than 60s in the future; backdating
/// keeps a slightly fast clock inside the window.
const IAT_SKEW_SECONDS: i64 = 60;

/// JWT lifetime. GitHub requires `exp - iat <= 600s`; 540s stays inside with
/// margin, so a token minted now is still valid when it reaches GitHub.
const JWT_LIFETIME_SECONDS: i64 = 540;

/// The App's identity: an ID plus the RSA private key that proves it.
///
/// Deliberately `Clone` (the worker and the webhook handler each hold one)
/// but never `Debug`/`Display`/`Serialize`: there is no legitimate rendering
/// of this value anywhere.
#[derive(Clone)]
pub struct AppIdentity {
    app_id: u64,
    private_key_pem: String,
}

impl AppIdentity {
    /// Build from operator configuration. `None` means the App integration is
    /// disabled (both values absent) — not an error. A half identity or an
    /// unparsable key is an explicit error with a fixed message; the key
    /// material itself never appears in it.
    pub fn from_parts(app_id: u64, private_key_pem: &str) -> Result<Option<Self>> {
        let key_set = !private_key_pem.trim().is_empty();
        match (app_id != 0, key_set) {
            (false, false) => Ok(None),
            (true, true) => {
                // Parse now so a bad key fails at startup, not at first mint.
                // `from_rsa_pem` accepts PKCS#1 and PKCS#8.
                jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).map_err(
                    |_| {
                        AppError::BadRequest("GitHub App private key is not a valid RSA key".into())
                    },
                )?;
                Ok(Some(Self {
                    app_id,
                    private_key_pem: private_key_pem.to_string(),
                }))
            }
            _ => Err(AppError::BadRequest(
                "GitHub App identity is incomplete: configure both the App ID and its private key"
                    .into(),
            )),
        }
    }

    /// Build from application settings.
    pub fn from_settings(settings: &crate::config::Settings) -> Result<Option<Self>> {
        Self::from_parts(settings.github_app_id, &settings.github_app_private_key)
    }

    /// The public App ID (appears in JWT claims and API URLs; not secret).
    pub fn app_id(&self) -> u64 {
        self.app_id
    }

    /// Mint a short-lived App JWT for `now`.
    ///
    /// Pure apart from the clock argument, so tests pin exact timestamps:
    /// `iat = now - skew`, `exp = iat + lifetime`. The signed token is the
    /// only output; the key never leaves this function except inside it.
    pub fn mint_jwt(&self, now: chrono::DateTime<chrono::Utc>) -> Result<String> {
        #[derive(serde::Serialize)]
        struct Claims {
            iat: i64,
            exp: i64,
            iss: String,
        }

        let iat = now.timestamp() - IAT_SKEW_SECONDS;
        let claims = Claims {
            iat,
            exp: iat + JWT_LIFETIME_SECONDS,
            iss: self.app_id.to_string(),
        };
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(self.private_key_pem.as_bytes())
            .map_err(|_| AppError::Internal("GitHub App signing key is unusable".into()))?;
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
            &claims,
            &key,
        )
        .map_err(|_| AppError::Internal("GitHub App token minting failed".into()))
    }
}

// ---------------------------------------------------------------------------
// Installation identity — Phase 19B.2.
// ---------------------------------------------------------------------------

use crate::models::github_installation::GithubInstallation;

/// Register (or re-register) an installation.
///
/// Validation is explicit because these values arrive from webhook payloads
/// and API calls: non-positive IDs, blank logins, and unknown account types
/// are refused before touching the database. Re-registration upserts — a
/// reinstall updates the stored identity instead of creating a second row,
/// so one installation ID always means one row.
pub async fn register_installation(
    pool: &sqlx::PgPool,
    installation_id: i64,
    account_id: i64,
    account_login: &str,
    account_type: &str,
    installed_by_user_id: &str,
) -> Result<GithubInstallation> {
    if installation_id <= 0 || account_id <= 0 {
        return Err(AppError::BadRequest(
            "GitHub installation identity has an invalid identifier".into(),
        ));
    }
    let login = account_login.trim();
    if login.is_empty() || login.len() > 255 {
        return Err(AppError::BadRequest(
            "GitHub installation identity has an invalid account login".into(),
        ));
    }
    if !matches!(account_type, "User" | "Organization") {
        return Err(AppError::BadRequest(
            "GitHub installation identity has an unknown account type".into(),
        ));
    }
    if installed_by_user_id.trim().is_empty() {
        return Err(AppError::BadRequest(
            "GitHub installation identity has no installer".into(),
        ));
    }

    sqlx::query_as::<_, GithubInstallation>(
        "INSERT INTO github_installations
             (installation_id, account_id, account_login, account_type, installed_by_user_id)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (installation_id) DO UPDATE SET
             account_id = EXCLUDED.account_id,
             account_login = EXCLUDED.account_login,
             account_type = EXCLUDED.account_type,
             installed_by_user_id = EXCLUDED.installed_by_user_id,
             updated_at = NOW()
         RETURNING *",
    )
    .bind(installation_id)
    .bind(account_id)
    .bind(login)
    .bind(account_type)
    .bind(installed_by_user_id.trim())
    .fetch_one(pool)
    .await
    .map_err(AppError::Database)
}

/// Look up an installation. A non-positive ID is malformed and resolves to
/// `None` — the same answer as "unknown", so callers cannot distinguish them
/// and neither answer leaks which installations exist to the wrong caller.
pub async fn get_installation(
    pool: &sqlx::PgPool,
    installation_id: i64,
) -> Result<Option<GithubInstallation>> {
    if installation_id <= 0 {
        return Ok(None);
    }
    sqlx::query_as::<_, GithubInstallation>(
        "SELECT * FROM github_installations WHERE installation_id = $1",
    )
    .bind(installation_id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::Database)
}

/// Whether an installation may be used: known and not suspended.
///
/// This is the gate 19B.3 checks before exchanging a token. Unknown covers
/// never-registered, revoked (deleted), and malformed alike.
pub async fn installation_usable(pool: &sqlx::PgPool, installation_id: i64) -> Result<bool> {
    Ok(get_installation(pool, installation_id)
        .await?
        .is_some_and(|row| !row.suspended))
}

/// Mark an installation suspended or clear the flag (suspend/unsuspend
/// webhook events, 19B.5). Returns `false` for an unknown installation.
pub async fn set_installation_suspended(
    pool: &sqlx::PgPool,
    installation_id: i64,
    suspended: bool,
) -> Result<bool> {
    if installation_id <= 0 {
        return Ok(false);
    }
    let updated = sqlx::query(
        "UPDATE github_installations SET suspended = $1, updated_at = NOW()
         WHERE installation_id = $2",
    )
    .bind(suspended)
    .bind(installation_id)
    .execute(pool)
    .await
    .map_err(AppError::Database)?;
    Ok(updated.rows_affected() > 0)
}

/// Forget an installation: revocation is deletion.
///
/// After this, the ID is unknown and every downstream gate refuses it. The
/// uninstall webhook (19B.5) and operator tooling both funnel through here.
pub async fn remove_installation(pool: &sqlx::PgPool, installation_id: i64) -> Result<bool> {
    if installation_id <= 0 {
        return Ok(false);
    }
    let deleted = sqlx::query("DELETE FROM github_installations WHERE installation_id = $1")
        .bind(installation_id)
        .execute(pool)
        .await
        .map_err(AppError::Database)?;
    Ok(deleted.rows_affected() > 0)
}

// ---------------------------------------------------------------------------
// Installation token acquisition — Phase 19B.3.
// ---------------------------------------------------------------------------

/// Wall-clock ceiling for the token exchange.
const TOKEN_EXCHANGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Ceiling on the token response body. The response is one small JSON
/// object; anything larger is refused rather than buffered.
const TOKEN_RESPONSE_MAX_BYTES: usize = 64 * 1024;

/// Exchange attempts. Only transient failures (rate limits, 5xx) are
/// retried; a rejected credential or an unknown installation fails at once.
const TOKEN_EXCHANGE_ATTEMPTS: u32 = 2;

/// A short-lived installation access token.
///
/// Memory only: it is never persisted, never logged, and never enters
/// `AuditState`, `CanonicalAudit`, a report, a narrative, or an error. No
/// `Debug`/`Display`/`Serialize` exists for this type, so none of those
/// sinks can render it.
pub struct InstallationToken {
    token: String,
    expires_at: chrono::DateTime<chrono::Utc>,
}

impl InstallationToken {
    /// Borrow the token for one repository operation.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// When GitHub says the token stops working.
    pub fn expires_at(&self) -> chrono::DateTime<chrono::Utc> {
        self.expires_at
    }

    /// True when the token is expired or within the skew margin of it.
    /// Callers check this before use rather than discovering it mid-fetch.
    pub fn is_expired(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        now.timestamp() + IAT_SKEW_SECONDS >= self.expires_at.timestamp()
    }
}

/// Exchange the App JWT for an installation access token.
///
/// ```text
///   App JWT → POST /app/installations/{id}/access_tokens → token (memory)
/// ```
///
/// `base_url` is the GitHub API root (production or Enterprise Server). The
/// response body is capped before parsing and the provider's own error bodies
/// are never read into errors — only the status class is reported. The
/// returned token must be used and dropped, never stored.
pub async fn exchange_installation_token(
    base_url: &str,
    identity: &AppIdentity,
    installation_id: i64,
) -> Result<InstallationToken> {
    if installation_id <= 0 {
        return Err(AppError::NotFound(
            "GitHub installation is unknown, revoked, or suspended".into(),
        ));
    }
    let client = reqwest::Client::builder()
        .timeout(TOKEN_EXCHANGE_TIMEOUT)
        .user_agent("FireCrow-Scanner/1.0")
        .build()
        .map_err(|_| AppError::Internal("GitHub token exchange is unavailable".into()))?;

    let url = format!(
        "{}/app/installations/{installation_id}/access_tokens",
        base_url.trim_end_matches('/')
    );
    let mut attempt = 0;
    loop {
        attempt += 1;
        let jwt = identity.mint_jwt(chrono::Utc::now())?;
        let response = client
            .post(&url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("Authorization", format!("Bearer {jwt}"))
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    AppError::Timeout("GitHub installation token exchange timed out".into())
                } else {
                    AppError::HttpClientError("GitHub installation token exchange failed".into())
                }
            })?;

        let status = response.status().as_u16();
        if status == 429 {
            if attempt < TOKEN_EXCHANGE_ATTEMPTS {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
            return Err(AppError::RateLimited);
        }
        if status >= 500 {
            if attempt < TOKEN_EXCHANGE_ATTEMPTS {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
            return Err(AppError::Unavailable(
                "GitHub installation token service is unavailable".into(),
            ));
        }
        // Permanent failures fail at once: retrying a rejected credential or
        // an unknown installation only burns rate budget.
        return match status {
            200 | 201 => read_token_response(response).await,
            401 => Err(AppError::Unauthorized(
                "GitHub rejected the App credential".into(),
            )),
            403 | 404 => Err(AppError::NotFound(
                "GitHub installation is unknown, revoked, or suspended".into(),
            )),
            _ => Err(AppError::HttpClientError(
                "GitHub installation token exchange failed".into(),
            )),
        };
    }
}

/// Read and validate a 2xx token response. The body is capped before parsing;
async fn read_token_response(response: reqwest::Response) -> Result<InstallationToken> {
    if let Some(len) = response.content_length() {
        if len > TOKEN_RESPONSE_MAX_BYTES as u64 {
            return Err(AppError::PayloadTooLarge);
        }
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|_| AppError::HttpClientError("GitHub token response unreadable".into()))?;
    if bytes.len() > TOKEN_RESPONSE_MAX_BYTES {
        return Err(AppError::PayloadTooLarge);
    }
    let body: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::Internal("GitHub token response was not valid JSON".into()))?;
    let token = body
        .get("token")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| AppError::Internal("GitHub token response carried no token".into()))?;
    let expires_at = body
        .get("expires_at")
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .ok_or_else(|| AppError::Internal("GitHub token response carried no expiry".into()))?;
    Ok(InstallationToken {
        token: token.to_string(),
        expires_at,
    })
}

// ---------------------------------------------------------------------------
// Check Runs — Phase 19B.7.
// ---------------------------------------------------------------------------

/// Name of the check Fire Crow reports. One name, always: a second check
/// would split the audit's verdict across two widgets.
pub const FIRECROW_CHECK_NAME: &str = "firecrow-security-audit";

/// Post a completed Check Run for `head_sha`.
///
/// Initially a status only — conclusion, finding count, coverage, and the
/// audited identifiers — never inline annotations (those come later, if
/// ever). The token is used for this call and dropped.
///
/// Eight parameters is the settled Check Run signature (endpoint + token +
/// repo triple + verdict triple); same frozen-gate rationale as the audit gate.
#[allow(clippy::too_many_arguments)]
pub async fn post_check_run(
    base_url: &str,
    token: &str,
    owner: &str,
    repo: &str,
    head_sha: &str,
    conclusion: &str,
    title: &str,
    summary: &str,
) -> Result<i64> {
    if !crate::agents::fetch::is_valid_commit_sha(head_sha) {
        return Err(AppError::BadRequest(
            "check run head is not a commit SHA".into(),
        ));
    }
    if !matches!(
        conclusion,
        "success" | "failure" | "neutral" | "cancelled" | "timed_out" | "action_required"
    ) {
        return Err(AppError::BadRequest(
            "check run conclusion is unknown".into(),
        ));
    }
    let client = reqwest::Client::builder()
        .timeout(TOKEN_EXCHANGE_TIMEOUT)
        .user_agent("FireCrow-Scanner/1.0")
        .build()
        .map_err(|_| AppError::Internal("GitHub check run is unavailable".into()))?;
    let response = client
        .post(format!(
            "{}/repos/{owner}/{repo}/check-runs",
            base_url.trim_end_matches('/')
        ))
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("Authorization", format!("Bearer {token}"))
        .json(&serde_json::json!({
            "name": FIRECROW_CHECK_NAME,
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": conclusion,
            "output": {"title": title, "summary": summary},
        }))
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() {
                AppError::Timeout("GitHub check run timed out".into())
            } else {
                AppError::HttpClientError("GitHub check run failed".into())
            }
        })?;
    if response.status().as_u16() == 201 {
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|_| AppError::Internal("GitHub check response was not valid JSON".into()))?;
        return body
            .get("id")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| AppError::Internal("GitHub check response carried no ID".into()));
    }
    Err(crate::agents::fetch::map_repo_access_error(
        response.status().as_u16(),
        true,
        None,
        owner,
        repo,
    ))
}

// ---------------------------------------------------------------------------
// Webhook cryptographic boundary — Phase 19B.5.
// ---------------------------------------------------------------------------

/// Ceiling on a webhook body. GitHub event payloads are small JSON objects;
/// anything larger is refused before HMAC verification, so a flooding sender
/// cannot make the backend hash megabytes per request.
pub const GITHUB_WEBHOOK_MAX_BYTES: usize = 1024 * 1024;

/// Verify `header_value` (`sha256=<hex>`) against the exact raw `body`.
///
/// Pure, so the whole authentication contract is unit-testable without a
/// server. The comparison is constant-time; failure carries no reason, only
/// a boolean, so callers cannot leak why a forgery failed.
pub fn verify_webhook_signature(secret: &str, body: &[u8], header_value: &str) -> bool {
    use hmac::{Hmac, Mac};
    use subtle::ConstantTimeEq;

    if secret.is_empty() || body.len() > GITHUB_WEBHOOK_MAX_BYTES {
        return false;
    }
    let hex_digest = match header_value.strip_prefix("sha256=") {
        Some(hex_digest) if !hex_digest.trim().is_empty() => hex_digest.trim(),
        _ => return false,
    };
    let mut mac = match Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    mac.update(body);
    let expected = hex::encode(mac.finalize().into_bytes());
    expected.as_bytes().ct_eq(hex_digest.as_bytes()).unwrap_u8() == 1
}

/// SHA-256 of a delivery body, hex-encoded. Binds a delivery ID to the exact
/// bytes GitHub sent, so a replay with a modified body is detectable.
pub fn webhook_body_sha256(body: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(body))
}

/// What a redelivery means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryReplay {
    /// First sighting, or a retry after an unfinished attempt: process it.
    Process,
    /// Already handled: acknowledge without reprocessing.
    Duplicate,
}

/// Record a delivery ID, or detect a replay.
///
/// `Process` the first time an ID is seen — and also when the stored outcome
/// is `pending` or `failed_transient`, meaning the first attempt died before
/// finishing: GitHub redelivers, and the redelivery must be allowed to
/// complete the work. A repeated ID with a *different* body hash is a replay
/// carrying different bytes → `Conflict`, never processed. A repeated ID
/// already `processed` or `ignored` → `Duplicate`.
pub async fn record_webhook_delivery(
    pool: &sqlx::PgPool,
    delivery_id: &str,
    event: &str,
    body_sha256: &str,
    installation_id: Option<i64>,
) -> Result<DeliveryReplay> {
    if delivery_id.len() > 128 || event.len() > 64 {
        return Err(AppError::BadRequest(
            "GitHub webhook identity is invalid".into(),
        ));
    }
    let inserted = sqlx::query(
        "INSERT INTO github_webhook_deliveries
             (delivery_id, event, body_sha256, installation_id)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (delivery_id) DO NOTHING",
    )
    .bind(delivery_id)
    .bind(event)
    .bind(body_sha256)
    .bind(installation_id)
    .execute(pool)
    .await
    .map_err(AppError::Database)?;
    if inserted.rows_affected() > 0 {
        return Ok(DeliveryReplay::Process);
    }
    let stored: (String, String) = sqlx::query_as(
        "SELECT body_sha256, outcome FROM github_webhook_deliveries WHERE delivery_id = $1",
    )
    .bind(delivery_id)
    .fetch_one(pool)
    .await
    .map_err(AppError::Database)?;
    if stored.0 != body_sha256 {
        return Err(AppError::Conflict(
            "GitHub webhook delivery was replayed with a different body".into(),
        ));
    }
    match stored.1.as_str() {
        "pending" | "failed_transient" => Ok(DeliveryReplay::Process),
        _ => Ok(DeliveryReplay::Duplicate),
    }
}

/// Mark how a delivery ended. `processed`/`ignored` close it; anything else
/// leaves it retryable. Only moves forward: a closed delivery is never
/// reopened by a late writer.
pub async fn mark_webhook_outcome(
    pool: &sqlx::PgPool,
    delivery_id: &str,
    outcome: &str,
) -> Result<()> {
    if !matches!(outcome, "processed" | "ignored" | "failed_transient") {
        return Err(AppError::BadRequest("unknown webhook outcome".into()));
    }
    sqlx::query(
        "UPDATE github_webhook_deliveries SET outcome = $1
         WHERE delivery_id = $2 AND outcome IN ('pending', 'failed_transient')",
    )
    .bind(outcome)
    .bind(delivery_id)
    .execute(pool)
    .await
    .map_err(AppError::Database)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Installation → repository authorization — Phase 19B.4.
// ---------------------------------------------------------------------------

/// A repository proven reachable through an installation the caller owns.
///
/// Constructed only by [`authorize_installation_repo`]: holding one means
/// every link in the chain was resolved through GitHub, not trusted from a
/// browser-supplied `installation_id`/`owner`/`repo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedRepo {
    pub installation_id: i64,
    pub owner: String,
    pub repo: String,
}

/// Authorize one audit source through the full chain.
///
/// ```text
///   authenticated user → owned, usable installation (database)
///       ↓
///   installation token (memory only)
///       ↓
///   repository reachable under that token (GitHub is the authority)
///       ↓
///   AuthorizedRepo
/// ```
///
/// The claimed `owner`/`repo` are validated as path segments and then proven
/// against GitHub with the installation's own token: a 200 means the
/// installation genuinely has access, anything else is a classified refusal.
/// The token is used for this check and dropped — it never enters the
/// returned value, the job, or the execution.
pub async fn authorize_installation_repo(
    pool: &sqlx::PgPool,
    base_url: &str,
    identity: &AppIdentity,
    user_id: &str,
    installation_id: i64,
    owner: &str,
    repo: &str,
) -> Result<AuthorizedRepo> {
    let owner = validate_account_segment(owner)?;
    let repo = validate_account_segment(repo)?;

    // Link 1: the installation is known, unsuspended, and belongs to the
    // caller. All three are database facts checked before any network call.
    let installation = get_installation(pool, installation_id)
        .await?
        .ok_or_else(|| {
            AppError::NotFound("GitHub installation is unknown, revoked, or suspended".into())
        })?;
    if installation.suspended {
        return Err(AppError::NotFound(
            "GitHub installation is unknown, revoked, or suspended".into(),
        ));
    }
    if installation.installed_by_user_id != user_id {
        return Err(AppError::Forbidden(
            "GitHub installation does not belong to this account".into(),
        ));
    }

    // Link 2: a live token for that installation. Unknown/revoked between
    // the row read and now fails here, still memory-only.
    let token = exchange_installation_token(base_url, identity, installation_id).await?;

    // Link 3: GitHub itself decides whether the installation sees the
    // repository. The browser's claim is a question, not an answer.
    verify_installation_repo(base_url, token.token(), &owner, &repo).await?;

    Ok(AuthorizedRepo {
        installation_id,
        owner,
        repo,
    })
}

/// One account or repository path segment: GitHub's own charset, no slashes,
/// no traversal, no emptiness. Anything else never reaches a URL.
fn validate_account_segment(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > 255
        || !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'))
    {
        return Err(AppError::BadRequest(
            "repository owner and name must be plain GitHub path segments".into(),
        ));
    }
    Ok(trimmed.to_string())
}

/// Prove `owner/repo` is reachable under an installation token.
///
/// Reuses the fetch phase's access-error mapping, so installation access
/// failures speak the same language as repository access failures: 404 never
/// distinguishes "missing" from "private" from "no access".
async fn verify_installation_repo(
    base_url: &str,
    token: &str,
    owner: &str,
    repo: &str,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(TOKEN_EXCHANGE_TIMEOUT)
        .user_agent("FireCrow-Scanner/1.0")
        .build()
        .map_err(|_| AppError::Internal("GitHub repository check is unavailable".into()))?;
    let response = client
        .get(format!(
            "{}/repos/{owner}/{repo}",
            base_url.trim_end_matches('/')
        ))
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() {
                AppError::Timeout("GitHub repository check timed out".into())
            } else {
                AppError::HttpClientError("GitHub repository check failed".into())
            }
        })?;
    if response.status().is_success() {
        return Ok(());
    }
    Err(crate::agents::fetch::map_repo_access_error(
        response.status().as_u16(),
        true,
        None,
        owner,
        repo,
    ))
}
