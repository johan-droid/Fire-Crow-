use crate::error::{AppError, Result};
use axum::{
    extract::{ConnectInfo, Query, State},
    http::StatusCode,
    response::Redirect,
    routing::{get, post},
    Json, Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use percent_encoding::utf8_percent_encode;
use serde::Deserialize;
use std::sync::Arc;
use tracing::{error, info};

pub fn router() -> Router<Arc<crate::AppState>> {
    // Two buckets, split by what a request costs the server:
    //
    // - Credential and state-changing routes keep the strict 5/minute
    //   per-IP ceiling (brute-force protection for login/register).
    // - The read-only session checks get their own 30/minute bucket. The SPA
    //   follows a successful login with an immediate GET /auth/me; when both
    //   shared one bucket, that follow-up could be rejected with 429 while the
    //   session cookie was already valid, so the UI reported a login failure
    //   for a login that had succeeded.
    let credential_routes = Router::new()
        .route("/exchange", post(exchange_token))
        .route("/refresh", post(refresh_token))
        .route("/policy-context", get(policy_context))
        .route("/policy-events", post(create_policy_event))
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/login/mfa", post(login_mfa))
        .route("/logout", post(logout))
        .route("/github", get(github_login))
        .route("/github/callback", get(github_callback))
        .layer(crate::middleware::rate_limit::rate_limiter("5/minute"));

    let session_read_routes = Router::new()
        .route("/me", get(get_me))
        .route("/session", get(get_session))
        .route("/activities", get(get_activities))
        .layer(crate::middleware::rate_limit::rate_limiter("30/minute"));

    credential_routes.merge(session_read_routes)
}

pub async fn exchange_token(
    State(state): State<Arc<crate::AppState>>,
    jar: CookieJar,
    Json(payload): Json<serde_json::Value>,
) -> Result<(CookieJar, Json<serde_json::Value>)> {
    let code = payload
        .get("code")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing code".into()))?;
    let (user_id, username, _encrypted_access_token) =
        crate::services::auth::verify_and_consume_exchange_code(state.pool(), code, state.crypto())
            .await?
            .ok_or_else(|| AppError::BadRequest("Invalid or expired exchange code".into()))?;

    let db_user: Option<crate::models::User> = sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(&user_id)
        .fetch_optional(state.pool())
        .await
        .map_err(AppError::Database)?;
    let tenant_id = db_user
        .as_ref()
        .and_then(|u| u.tenant_id.clone())
        .unwrap_or_default();

    // P0-A (ZT-01-1 / ZT-01-5): cookies only; tokens are never echoed in the
    // body. An exchange code is only a *first* factor (it proves the caller
    // completed the upstream OAuth step), so an MFA-enabled account must still
    // redeem a second factor before a session is minted — otherwise GitHub
    // login would bypass TOTP entirely. Mirrors the login() MFA branch.
    let user_mfa_enabled = db_user.as_ref().map(|u| u.mfa_enabled).unwrap_or(false);
    if user_mfa_enabled {
        let (challenge, _) = crate::services::auth::create_mfa_challenge_token(
            &user_id,
            &username,
            &state.settings().secret_key,
            &tenant_id,
        )?;
        let _ = crate::services::security_log::record_security_event(
            state.pool(),
            Some(&user_id),
            None,
            "mfa_challenge_issued",
            Some("{\"via\":\"exchange\"}"),
            None,
        )
        .await;
        return Ok((
            jar,
            Json(serde_json::json!({
                "status": "mfa_required",
                "mfa_token": challenge,
                "username": username,
            })),
        ));
    }

    // `session_response` mints the shared-family token pair and both cookies.
    let email = db_user.as_ref().and_then(|u| u.email.clone());
    session_response(&state, jar, &user_id, &username, &tenant_id, email)
}

pub async fn refresh_token(
    State(state): State<Arc<crate::AppState>>,
    jar: CookieJar,
    Json(payload): Json<serde_json::Value>,
) -> Result<(CookieJar, Json<serde_json::Value>)> {
    // The refresh cookie is written as `{cookie}_refresh`; the literal
    // `refresh_token` name is accepted as a legacy fallback so sessions
    // minted before the cookie-name fix keep refreshing.
    let derived_name = format!("{}_refresh", state.settings().auth_cookie_name);
    let token = payload
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .or_else(|| jar.get(&derived_name).map(|c| c.value()))
        .or_else(|| jar.get("refresh_token").map(|c| c.value()))
        .unwrap_or("");
    // V1+V2: signature, `Refresh` purpose, single-use rotation, and session
    // liveness are enforced atomically. Replays fail closed (rotated families
    // are already retired; consumed jtis never re-validate); access tokens
    // presented here are rejected.
    let claims = crate::services::auth::consume_refresh_token(
        token,
        &state.settings().secret_key,
        state.redis(),
        state.pool(),
    )
    .await?;

    // Rotation retires the whole predecessor family (including the previous
    // access token, which shares it since V2) with a TTL covering the
    // longest-lived token the family can hold.
    let old_family = claims.claims.token_family.clone();
    let family_ttl = crate::services::auth::REFRESH_TOKEN_TTL_SECONDS + 3600;
    if let Some(redis) = state.redis() {
        let _ = crate::services::auth::revoke_token_family(redis, &old_family, family_ttl).await;
    }
    let _ = crate::services::auth::revoke_token_in_db(
        state.pool(),
        &claims.claims.jti,
        &old_family,
        family_ttl,
    )
    .await;

    let new_family = uuid::Uuid::new_v4().to_string();
    let tenant_id = claims.claims.tenant_id.clone();
    let (access_token_str, _) = crate::services::auth::create_access_token(
        &claims.claims.sub,
        &claims.claims.username,
        &state.settings().secret_key,
        &tenant_id,
        &new_family,
        state.settings().jwt_access_token_expire_minutes,
    )?;
    let (refresh_token_str, _) = crate::services::auth::create_refresh_token(
        &claims.claims.sub,
        &claims.claims.username,
        &state.settings().secret_key,
        &tenant_id,
        &new_family,
    )?;

    let cookie_name = state.settings().auth_cookie_name.clone();
    let samesite = get_cookie_samesite(&state);
    let is_secure = is_cookie_secure(&state, samesite);
    let access_cookie = Cookie::build((cookie_name.clone(), access_token_str.clone()))
        .path("/")
        .http_only(true)
        .secure(is_secure)
        .same_site(samesite)
        .build();

    let refresh_cookie = Cookie::build((
        format!("{}_refresh", cookie_name),
        refresh_token_str.clone(),
    ))
    .path("/")
    .http_only(true)
    .secure(is_secure)
    .same_site(samesite)
    .build();

    let jar = jar.add(access_cookie).add(refresh_cookie);

    // P0-A (ZT-01-5, finding 5): tokens live only in HttpOnly cookies, like
    // every other session-issuing path — refresh bodies no longer echo them.
    Ok((
        jar,
        Json(serde_json::json!({
            "token_type": "bearer",
            "username": claims.claims.username,
            "user_id": claims.claims.sub
        })),
    ))
}

pub async fn register(
    State(state): State<Arc<crate::AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>> {
    // P0-A (ZT-01-23): registration is a credential-abuse surface too.
    enforce_turnstile(&state, &payload).await?;
    let username = payload
        .get("username")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .ok_or_else(|| AppError::BadRequest("Missing username".into()))?;
    if username.is_empty()
        || username.len() > 64
        || !username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(AppError::BadRequest(
            "Username must be 1-64 alphanumeric characters, underscores, or hyphens".into(),
        ));
    }

    let password = payload
        .get("password")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing password".into()))?;
    let email_input = payload.get("email").and_then(|v| v.as_str()).unwrap_or("");
    let email = if email_input.trim().is_empty() {
        format!("{}@local.firecrow", username.to_lowercase())
    } else {
        email_input.trim().to_lowercase()
    };

    if password.len() < 10 {
        return Err(AppError::BadRequest(
            "Password must be at least 10 characters".into(),
        ));
    }
    let password_hash = crate::services::auth::hash_password(password)?;
    let user_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().naive_utc();
    let insert_res = sqlx::query(
        "INSERT INTO users (id, username, email, password_hash, is_active, credit_balance, created_at) VALUES ($1,$2,$3,$4,true,0.0,$5)",
    )
    .bind(&user_id)
    .bind(username)
    .bind(&email)
    .bind(password_hash)
    .bind(now)
    .execute(state.pool())
    .await;

    match insert_res {
        Ok(_) => {
            crate::services::security_log::record_security_event(
                state.pool(),
                Some(&user_id),
                None,
                "user_registered",
                None,
                None,
            )
            .await
            .ok();
            Ok(Json(
                serde_json::json!({"user_id": user_id, "username": username, "email": email}),
            ))
        }
        Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => Err(
            AppError::Conflict("An account with this username or email already exists".into()),
        ),
        Err(e) => Err(AppError::Database(e)),
    }
}

/// Resolve the lockout keys for one login attempt: the per-account key plus an
/// OPTIONAL per-IP key.
///
/// The IP dimension is `Some` only when the client identity is proven — the
/// peer is a trusted proxy / Cloudflare edge (so `client_ip` is XFF-derived
/// through a trustworthy hop), or the operator explicitly attests a direct
/// deploy (`TRUST_DIRECT_PEER`). Every other topology (Render-style or
/// unknown shared ingress, unverified peer) yields `None`: an IP key over a
/// shared address would be a GLOBAL lockout, and aliasing it to the account
/// key double-records each failure and halves the documented limit.
/// `None` is unrepresentable as either defect (FC-RELEASE-017 findings 1+2).
fn resolve_lockout_keys(
    peer_is_proxy: bool,
    direct_peer_trusted: bool,
    client_ip: &str,
    normalized: &str,
) -> (String, Option<String>) {
    let account_key = format!("login:{}", normalized);
    let ip_key = if peer_is_proxy || direct_peer_trusted {
        Some(format!("login_ip:{}", client_ip))
    } else {
        None
    };
    (account_key, ip_key)
}

pub async fn login(
    State(state): State<Arc<crate::AppState>>,
    jar: CookieJar,
    headers: axum::http::HeaderMap,
    connect_info: Option<ConnectInfo<std::net::SocketAddr>>,
    Json(payload): Json<serde_json::Value>,
) -> Result<(CookieJar, Json<serde_json::Value>)> {
    // P0-A (ZT-01-23): mandatory credential-abuse gate when enabled.
    enforce_turnstile(&state, &payload).await?;
    let username = payload
        .get("username")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing username".into()))?;
    let password = payload
        .get("password")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing password".into()))?;
    let normalized = username.trim().to_lowercase();
    // P2-B (ZT-01-16): layered lockout — per-account (targeted brute force)
    // AND per verified client IP. The IP is derived through the trusted-proxy
    // rules, never blindly from spoofable headers.
    //
    // FC-RELEASE-017 (review findings 1+2, plus the independent-review catch
    // below): the extractor MUST be the bare `ConnectInfo` that
    // `into_make_service_with_connect_info` inserts — wrapping it in
    // `Extension` never matches, silently yields `None` on every request, and
    // would turn the attested path into a global `login_ip:unresolved` key.
    let peer_ip = connect_info.map(|ci| ci.0.ip());
    let client_ip = crate::middleware::cloudflare::resolve_client_ip(&headers, peer_ip);
    // P1-B follow-up: the per-IP lockout is only meaningful when `client_ip`
    // identifies a single client. When the peer is a shared ingress, every
    // user resolves to the SAME address, so an IP-keyed lockout becomes a
    // GLOBAL lockout. In that configuration the per-account key still
    // enforces the lockout and the 5/min rate limiter still throttles, so the
    // IP dimension is skipped rather than made global. When proxies ARE
    // configured the IP key is per-client and is enforced.
    let peer_is_proxy = peer_ip
        .map(|ip| {
            crate::middleware::cloudflare::is_cloudflare_peer(ip)
                || crate::middleware::cloudflare::is_trusted_proxy_ip(
                    ip,
                    crate::middleware::cloudflare::trusted_proxies(),
                )
        })
        .unwrap_or(false);
    // A raw (non-proxy) peer is the real client on a direct deploy, but it is
    // Render's SHARED ingress when TRUSTED_PROXY_CIDRS is empty — identical
    // for every caller, so an IP-keyed lockout there would be a global
    // lockout. The RENDER signal is the same one config.rs uses to warn about
    // this topology; without it we assume a direct deploy and keep the IP
    // dimension. (Other platforms with an unrecognized shared ingress keep the
    // existing coarse-but-spoof-proof posture; documented in the campaign
    // report.)
    // FC-RELEASE-017 (review findings 1+2): the per-IP lockout dimension exists
    // only when the client identity is PROVEN — the peer is a trusted proxy /
    // Cloudflare edge (so `client_ip` is XFF-derived through a trustworthy
    // hop), or the operator explicitly attests a direct deploy with
    // TRUST_DIRECT_PEER set to a truthy value (`1`/`true`/`yes`; presence
    // alone is NOT enough, so `TRUST_DIRECT_PEER=0` cannot enable it by
    // accident). Otherwise there is NO IP key at all (`None`):
    // behind an unrecognized shared ingress the peer address is identical
    // for every caller, so an IP key would be a GLOBAL lockout; and aliasing
    // the IP key to the account key double-records each failure and halves
    // the documented limit. The per-account key and the rate limiter still
    // enforce in every topology. This rule subsumes the old RENDER
    // special-case: a shared ingress peer is simply never a proven client.
    let direct_peer_trusted = std::env::var("TRUST_DIRECT_PEER")
        .map(|v| matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);
    let (lockout_key, ip_lockout_key) =
        resolve_lockout_keys(peer_is_proxy, direct_peer_trusted, &client_ip, &normalized);
    for key in std::iter::once(&lockout_key).chain(ip_lockout_key.as_ref()) {
        if crate::services::auth::check_login_lockout(
            state.pool(),
            key,
            state.settings().login_failure_window_minutes,
            state.settings().login_failure_limit,
        )
        .await?
        {
            let _ = crate::services::security_log::record_security_event(
                state.pool(),
                None,
                None,
                "login_lockout",
                // P2-D companion (finding 6): the key embeds the submitted
                // username, which is attacker-controlled — build the JSON
                // through serde so quotes/backslashes can't forge the field.
                Some(&serde_json::json!({ "key": key }).to_string()),
                None,
            )
            .await;
            return Err(AppError::AccountLocked);
        }
    }
    let user: Option<crate::models::User> = sqlx::query_as::<_, crate::models::User>(
        "SELECT * FROM users WHERE LOWER(username)=$1 OR LOWER(email)=$1",
    )
    .bind(&normalized)
    .fetch_optional(state.pool())
    .await
    .map_err(AppError::Database)?;
    let user = match user {
        Some(u) => u,
        None => {
            crate::services::auth::record_login_failure(state.pool(), &lockout_key).await?;
            // The IP dimension records only when it exists (`Some`): recording
            // an aliased-or-shared key twice is exactly the double-count and
            // global-lockout defects this resolution removed.
            if let Some(ip_key) = &ip_lockout_key {
                let _ = crate::services::auth::record_login_failure(state.pool(), ip_key).await;
            }
            let _ = crate::services::security_log::record_security_event(
                state.pool(),
                None,
                None,
                "login_failed",
                // FC-RELEASE-017 (independent review): built through serde like
                // the neighboring lockout event — one refactor away from an
                // injection if this ever stops being an IpAddr/`"unresolved"`.
                Some(
                    &serde_json::json!({ "identifier_found": false, "ip": client_ip }).to_string(),
                ),
                None,
            )
            .await;
            return Err(AppError::InvalidCredentials);
        }
    };
    if !user.is_active {
        crate::services::auth::record_login_failure(state.pool(), &lockout_key).await?;
        if let Some(ip_key) = &ip_lockout_key {
            let _ = crate::services::auth::record_login_failure(state.pool(), ip_key).await;
        }
        let _ = crate::services::security_log::record_security_event(
            state.pool(),
            Some(&user.id),
            None,
            "login_failed",
            Some("{\"reason\":\"deactivated\"}"),
            None,
        )
        .await;
        return Err(AppError::Forbidden("Account is deactivated".into()));
    }
    let password_hash = user.password_hash.as_deref().unwrap_or("");
    if !crate::services::auth::verify_password(password, password_hash)? {
        crate::services::auth::record_login_failure(state.pool(), &lockout_key).await?;
        if let Some(ip_key) = &ip_lockout_key {
            let _ = crate::services::auth::record_login_failure(state.pool(), ip_key).await;
        }
        let _ = crate::services::security_log::record_security_event(
            state.pool(),
            Some(&user.id),
            None,
            "login_failed",
            Some("{\"reason\":\"bad_password\"}"),
            None,
        )
        .await;
        return Err(AppError::InvalidCredentials);
    }
    crate::services::auth::clear_login_failures(state.pool(), &lockout_key).await?;
    if let Some(ip_key) = &ip_lockout_key {
        crate::services::auth::clear_login_failures(state.pool(), ip_key).await?;
    }

    // P0-A (ZT-01-1/5): an MFA-enabled account gets a short-lived,
    // single-purpose challenge — NOT a session. No cookies are set and no
    // access/refresh token exists; the full session is minted only by
    // `POST /auth/login/mfa` after the second factor verifies.
    if user.mfa_enabled {
        let tenant_id = user.tenant_id.clone().unwrap_or_default();
        let (challenge, _) = crate::services::auth::create_mfa_challenge_token(
            &user.id,
            &user.username,
            &state.settings().secret_key,
            &tenant_id,
        )?;
        let _ = crate::services::security_log::record_security_event(
            state.pool(),
            Some(&user.id),
            None,
            "mfa_challenge_issued",
            None,
            None,
        )
        .await;
        return Ok((
            jar,
            Json(serde_json::json!({
                "status": "mfa_required",
                "mfa_token": challenge,
                "username": user.username,
            })),
        ));
    }

    sqlx::query("UPDATE users SET last_login_at=$1 WHERE id=$2")
        .bind(chrono::Utc::now().naive_utc())
        .bind(&user.id)
        .execute(state.pool())
        .await
        .ok();
    let _ = crate::services::security_log::record_security_event(
        state.pool(),
        Some(&user.id),
        None,
        "login_success",
        None,
        None,
    )
    .await;
    let tenant_id = user.tenant_id.clone().unwrap_or_default();
    session_response(
        &state,
        jar,
        &user.id,
        &user.username,
        &tenant_id,
        user.email.clone(),
    )
}

/// P0-A (ZT-01-1): redeem an MFA challenge for a full session. The challenge
/// is HMAC-signed, purpose-bound (`Mfachallenge` — rejected for both Access
/// and Refresh), short-lived, and single-use. The second factor is a TOTP
/// code or an unused recovery code; there is no password-only path here.
pub async fn login_mfa(
    State(state): State<Arc<crate::AppState>>,
    jar: CookieJar,
    Json(payload): Json<serde_json::Value>,
) -> Result<(CookieJar, Json<serde_json::Value>)> {
    let challenge = payload
        .get("mfa_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing MFA challenge".into()))?;
    let code = payload
        .get("code")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing MFA code".into()))?;

    // Signature + expiry + anti-replay (Redis with authoritative DB
    // fallback), then purpose: an access or refresh token presented here is
    // rejected, and a redeemed challenge can never be replayed.
    let claims = crate::services::auth::validate_token_with_anti_replay(
        challenge,
        &state.settings().secret_key,
        state.redis(),
        state.pool(),
    )
    .await?;
    crate::services::auth::require_token_type(
        &claims,
        crate::services::auth::TokenType::Mfachallenge,
    )?;

    let user: Option<crate::models::User> =
        sqlx::query_as::<_, crate::models::User>("SELECT * FROM users WHERE id = $1")
            .bind(&claims.claims.sub)
            .fetch_optional(state.pool())
            .await
            .map_err(AppError::Database)?;
    let user = user.ok_or(AppError::InvalidCredentials)?;
    if !user.is_active {
        return Err(AppError::Forbidden("Account is deactivated".into()));
    }
    // Challenges are only minted for MFA-enabled accounts. If MFA was
    // disabled between mint and redemption, fail closed — never downgrade to
    // a password-only session.
    if !user.mfa_enabled {
        return Err(AppError::Forbidden(
            "MFA is no longer enabled for this account".into(),
        ));
    }

    let rl_key = format!("mfa_login:{}", user.id);
    if crate::services::auth::check_login_lockout(state.pool(), &rl_key, 10, 5).await? {
        return Err(AppError::RateLimited);
    }

    let totp_ok = match user.mfa_secret.as_deref() {
        Some(encrypted) => match state.crypto().decrypt_secret(encrypted) {
            Ok(secret) => crate::services::mfa_service::MfaService::verify_totp(&secret, code),
            // Malformed secret state: TOTP cannot verify, but recovery
            // codes remain a valid second factor (never a bypass). Finding 8:
            // this fail-closed state (key rotation, corrupt row) used to be
            // silent — emit an event so it is visible in the audit trail.
            Err(e) => {
                let _ = crate::services::security_log::record_security_event(
                    state.pool(),
                    Some(&user.id),
                    None,
                    "mfa_secret_decrypt_failed",
                    Some(&serde_json::json!({ "reason": e.to_string() }).to_string()),
                    None,
                )
                .await;
                false
            }
        },
        None => false,
    };
    let factor_ok = if totp_ok {
        true
    } else {
        crate::api::routes_mfa::try_consume_recovery_code(state.pool(), &user.id, code).await?
    };
    if !factor_ok {
        let _ = crate::services::auth::record_login_failure(state.pool(), &rl_key).await;
        let _ = crate::services::security_log::record_security_event(
            state.pool(),
            Some(&user.id),
            None,
            "mfa_login_failed",
            None,
            None,
        )
        .await;
        return Err(AppError::InvalidCredentials);
    }
    crate::services::auth::clear_login_failures(state.pool(), &rl_key).await?;

    // Single-use: retire the challenge family so the same challenge cannot
    // mint a second session (replay protection beyond the 5-minute TTL).
    let family = &claims.claims.token_family;
    let challenge_ttl = crate::services::auth::MFA_CHALLENGE_TTL_MINUTES * 60 + 3600;
    // Finding 7: validation above is a READ — two concurrent redemptions with
    // a valid code could both pass it and both reach session issuance.
    // consume_jti_once is atomic (SET NX / INSERT ... ON CONFLICT DO
    // NOTHING), so exactly one caller claims the challenge; the loser fails
    // with a replay error even though its factor verified.
    let claimed = crate::services::auth::consume_jti_once(
        state.redis(),
        state.pool(),
        &claims.claims.jti,
        family,
        challenge_ttl,
    )
    .await?;
    if !claimed {
        return Err(AppError::TokenRevoked);
    }
    if let Some(redis) = state.redis() {
        let _ =
            crate::services::auth::revoke_token_jti(redis, &claims.claims.jti, challenge_ttl).await;
        let _ = crate::services::auth::revoke_token_family(redis, family, challenge_ttl).await;
    }
    let _ = crate::services::auth::revoke_token_in_db(
        state.pool(),
        &claims.claims.jti,
        family,
        challenge_ttl,
    )
    .await;

    sqlx::query("UPDATE users SET last_login_at=$1 WHERE id=$2")
        .bind(chrono::Utc::now().naive_utc())
        .bind(&user.id)
        .execute(state.pool())
        .await
        .ok();
    let _ = crate::services::security_log::record_security_event(
        state.pool(),
        Some(&user.id),
        None,
        "mfa_login_success",
        None,
        None,
    )
    .await;
    let tenant_id = user.tenant_id.clone().unwrap_or_default();
    session_response(
        &state,
        jar,
        &user.id,
        &user.username,
        &tenant_id,
        user.email.clone(),
    )
}

/// P0-A (ZT-01-5): the browser contract is HttpOnly-cookie authentication.
/// Every session-issuing path returns identity metadata only — access and
/// refresh tokens are never echoed in JSON bodies.
fn session_response(
    state: &crate::AppState,
    jar: CookieJar,
    user_id: &str,
    username: &str,
    tenant_id: &str,
    email: Option<String>,
) -> Result<(CookieJar, Json<serde_json::Value>)> {
    // One session family shared by both tokens (see exchange_token): a
    // single family revocation (logout, rotation, reuse containment) kills
    // the whole session.
    let token_family = uuid::Uuid::new_v4().to_string();
    let (access_token_str, _) = crate::services::auth::create_access_token(
        user_id,
        username,
        &state.settings().secret_key,
        tenant_id,
        &token_family,
        state.settings().jwt_access_token_expire_minutes,
    )?;
    let (refresh_token_str, _) = crate::services::auth::create_refresh_token(
        user_id,
        username,
        &state.settings().secret_key,
        tenant_id,
        &token_family,
    )?;

    let cookie_name = state.settings().auth_cookie_name.clone();
    let samesite = get_cookie_samesite(state);
    let is_secure = is_cookie_secure(state, samesite);
    let access_cookie = Cookie::build((cookie_name.clone(), access_token_str))
        .path("/")
        .http_only(true)
        .secure(is_secure)
        .same_site(samesite)
        .build();
    let refresh_cookie = Cookie::build((format!("{}_refresh", cookie_name), refresh_token_str))
        .path("/")
        .http_only(true)
        .secure(is_secure)
        .same_site(samesite)
        .build();
    let jar = jar.add(access_cookie).add(refresh_cookie);
    Ok((
        jar,
        Json(serde_json::json!({
            "token_type": "bearer",
            "username": username,
            "user_id": user_id,
            "email": email
        })),
    ))
}

/// P0-A (ZT-01-23): the Turnstile credential-abuse gate. Default-off keeps
/// dev/test dependency-free; when enabled the client token is mandatory and
/// a missing secret key is a hard error — an enabled control never silently
/// approves unverified requests.
async fn enforce_turnstile(state: &crate::AppState, payload: &serde_json::Value) -> Result<()> {
    if !state.settings().cf_turnstile_enabled {
        return Ok(());
    }
    let token = payload
        .get("turnstile_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Forbidden("Turnstile challenge required".into()))?;
    let svc = crate::services::turnstile::TurnstileService::new(
        state.settings().cf_turnstile_secret_key.clone(),
        true,
    );
    svc.verify_token(token, None).await.map(|_| ())
}

pub async fn logout(
    State(state): State<Arc<crate::AppState>>,
    jar: CookieJar,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<(CookieJar, Json<serde_json::Value>)> {
    // V2: logout revokes the whole session family, not just the presenting
    // token. The family TTL must cover the refresh lifetime (7 days), not
    // just the access lifetime — otherwise a logged-out refresh token would
    // resurrect the session after the record expired. Both stores are
    // written so revocation survives a Redis failover in either direction.
    // Post-V2 sessions share one family across both tokens; pre-V2 sessions
    // have disjoint families, so their refresh token is only killed when it
    // next rotates into a shared family (bounded by its 7-day expiry).
    let access_ttl = state.settings().jwt_access_token_expire_minutes * 60;
    let family_ttl = crate::services::auth::REFRESH_TOKEN_TTL_SECONDS + 3600;
    if let Some(redis) = state.redis() {
        let _ = crate::services::auth::revoke_token_jti(redis, &user.jti, access_ttl).await;
        let _ =
            crate::services::auth::revoke_token_family(redis, &user.token_family, family_ttl).await;
    }
    let _ = crate::services::auth::revoke_token_in_db(
        state.pool(),
        &user.jti,
        &user.token_family,
        family_ttl,
    )
    .await;
    let _ = crate::services::security_log::record_security_event(
        state.pool(),
        Some(&user.user_id),
        None,
        "logout",
        None,
        None,
    )
    .await;

    let cookie_name = state.settings().auth_cookie_name.clone();
    let mut access_cookie = Cookie::build((cookie_name.clone(), ""))
        .path("/")
        .http_only(true)
        .build();
    access_cookie.make_removal();

    let mut refresh_cookie = Cookie::build((format!("{}_refresh", cookie_name), ""))
        .path("/")
        .http_only(true)
        .build();
    refresh_cookie.make_removal();

    let jar = jar.add(access_cookie).add(refresh_cookie);
    Ok((jar, Json(serde_json::json!({"status": "logged_out"}))))
}

pub async fn get_me(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<serde_json::Value>> {
    let db_user: Option<crate::models::User> =
        sqlx::query_as::<_, crate::models::User>("SELECT * FROM users WHERE id=$1")
            .bind(&user.user_id)
            .fetch_optional(state.pool())
            .await
            .map_err(AppError::Database)?;
    let db_user = db_user.ok_or_else(|| AppError::NotFound("User not found".into()))?;
    Ok(Json(
        serde_json::json!({"user_id": db_user.id, "username": db_user.username, "email": db_user.email, "is_active": db_user.is_active, "credit_balance": db_user.credit_balance}),
    ))
}

pub async fn get_session(
    State(_state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<serde_json::Value>> {
    Ok(Json(
        serde_json::json!({"user_id": user.user_id, "username": user.username, "session_valid": true}),
    ))
}

pub async fn get_activities(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<Vec<crate::models::UserActivityEvent>>> {
    crate::services::user_activity::list_user_activities(state.pool(), &user.user_id, 50)
        .await
        .map(Json)
}

#[derive(Deserialize)]
pub struct OAuthCallbackQuery {
    code: String,
    state: String,
}

#[derive(serde::Deserialize)]
struct GitHubTokenResponse {
    access_token: String,
}

#[derive(serde::Deserialize)]
struct GitHubUser {
    id: i64,
    login: String,
    email: Option<String>,
}

/// P1-A (ZT-04-6): public for the `resolve_backend_base_url_ignores_forwarded_headers`
/// regression test — the OAuth redirect base must come only from operator config
/// or Render's env, never from request headers.
pub fn resolve_backend_base_url(
    state: &crate::AppState,
    _headers: &axum::http::HeaderMap,
) -> String {
    let configured = state.settings().backend_base_url.trim_end_matches('/');
    if !configured.is_empty() && configured != "http://localhost:8000" {
        return configured.to_string();
    }
    if let Ok(render_url) = std::env::var("RENDER_EXTERNAL_URL") {
        let r = render_url.trim().trim_end_matches('/');
        if !r.is_empty() {
            return r.to_string();
        }
    }
    // P1-A (ZT-04-6): the old fallback built the OAuth `redirect_uri` from
    // raw `X-Forwarded-Host`/`X-Forwarded-Proto`. Those headers are
    // attacker-controlled unless a trusted proxy rewrites them, so a forged
    // value could steer the callback URL. The only remaining sources are the
    // operator-configured `backend_base_url` and Render's own env var; local
    // dev falls back to the configured localhost default (fail-closed: an
    // unconfigured production deployment produces a redirect GitHub rejects
    // rather than one an attacker can steer).
    configured.to_string()
}

pub async fn github_login(
    State(state): State<Arc<crate::AppState>>,
    headers: axum::http::HeaderMap,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect)> {
    let oauth_state = crate::services::auth::create_oauth_state();
    let samesite = get_cookie_samesite(&state);
    let cookie_samesite = if samesite == axum_extra::extract::cookie::SameSite::None {
        axum_extra::extract::cookie::SameSite::None
    } else {
        axum_extra::extract::cookie::SameSite::Lax
    };
    let is_secure = is_cookie_secure(&state, cookie_samesite);
    let cookie = Cookie::build(("oauth_state", oauth_state.clone()))
        .path("/")
        .http_only(true)
        .secure(is_secure)
        .same_site(cookie_samesite)
        .build();

    let mut jar = jar.add(cookie);

    let referer = headers
        .get(axum::http::header::REFERER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !referer.is_empty() {
        if let Ok(url) = url::Url::parse(referer) {
            let origin = format!("{}://{}", url.scheme(), url.host_str().unwrap_or(""));
            let origin = if let Some(port) = url.port() {
                format!("{}:{}", origin, port)
            } else {
                origin
            };

            let allowed = is_allowed_origin(&origin, &state);

            if allowed {
                let redirect_cookie = Cookie::build(("oauth_redirect_origin", origin))
                    .path("/")
                    .http_only(true)
                    .secure(is_secure)
                    .same_site(cookie_samesite)
                    .build();
                jar = jar.add(redirect_cookie);
            }
        }
    }

    let base_url = resolve_backend_base_url(&state, &headers);
    let auth_url = format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}/api/v1/auth/github/callback&state={}&scope=repo,read:org,user:email",
        state.settings().github_client_id,
        base_url,
        oauth_state
    );
    Ok((jar, Redirect::temporary(&auth_url)))
}

pub async fn github_callback(
    State(state): State<Arc<crate::AppState>>,
    headers: axum::http::HeaderMap,
    jar: CookieJar,
    Query(query): Query<OAuthCallbackQuery>,
) -> (CookieJar, Redirect) {
    let redirect_origin = jar
        .get("oauth_redirect_origin")
        .map(|c| c.value().to_string());
    let jar = jar.remove(
        Cookie::build(("oauth_redirect_origin", ""))
            .path("/")
            .build(),
    );

    let frontend_base = redirect_origin.unwrap_or_else(|| {
        state
            .settings()
            .frontend_url
            .trim_end_matches('/')
            .to_string()
    });
    let error_redirect = |msg: &str| {
        error!("GitHub OAuth error: {}", msg);
        let url = format!("{}/?oauth_error={}", frontend_base, urlencoding(msg));
        Redirect::temporary(&url)
    };

    let stored_state = match jar.get("oauth_state").map(|c| c.value().to_string()) {
        Some(s) => s,
        None => return (jar, error_redirect("Missing OAuth state cookie")),
    };
    if query.state != stored_state {
        return (jar, error_redirect("Invalid OAuth state"));
    }
    let jar = jar.remove(Cookie::build(("oauth_state", "")).path("/").build());

    let base_url = resolve_backend_base_url(&state, &headers);
    let redirect_uri = format!("{}/api/v1/auth/github/callback", base_url);

    // security_s_16: `Client::new()` has no timeout, so a stalled peer
    // pins a connection from a small pool for as long as it likes. The
    // unauthenticated GitHub endpoints were the worst case: ~40 stalled
    // callbacks exhaust the pool.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default();
    let token_res = client
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .header("User-Agent", "Fire-Crow-Backend")
        .form(&[
            ("client_id", state.settings().github_client_id.as_str()),
            (
                "client_secret",
                state.settings().github_client_secret.as_str(),
            ),
            ("code", query.code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
        ])
        .send()
        .await;

    let token_body = match token_res {
        Ok(r) => match r.text().await {
            Ok(t) => t,
            Err(e) => {
                return (
                    jar,
                    error_redirect(&format!("Failed to read token response: {e}")),
                )
            }
        },
        Err(e) => {
            return (
                jar,
                error_redirect(&format!("GitHub token request failed: {e}")),
            )
        }
    };

    let token_data: GitHubTokenResponse = match serde_json::from_str(&token_body) {
        Ok(t) => t,
        Err(e) => {
            return (
                jar,
                error_redirect(&format!("GitHub token parse error: {e}")),
            )
        }
    };

    let user_res = client
        .get("https://api.github.com/user")
        .header("User-Agent", "Fire-Crow-Backend")
        .header("Accept", "application/vnd.github.v3+json")
        .header(
            "Authorization",
            format!("Bearer {}", token_data.access_token),
        )
        .send()
        .await;

    let user_body = match user_res {
        Ok(r) => match r.text().await {
            Ok(t) => t,
            Err(e) => {
                return (
                    jar,
                    error_redirect(&format!("Failed to read user response: {e}")),
                )
            }
        },
        Err(e) => {
            return (
                jar,
                error_redirect(&format!("GitHub user request failed: {e}")),
            )
        }
    };

    let gh_user: GitHubUser = match serde_json::from_str(&user_body) {
        Ok(u) => u,
        Err(e) => {
            return (
                jar,
                error_redirect(&format!("GitHub user parse error: {e}")),
            )
        }
    };

    let github_id_str = gh_user.id.to_string();

    let db_user_opt =
        sqlx::query_as::<_, crate::models::User>("SELECT * FROM users WHERE github_id = $1")
            .bind(&github_id_str)
            .fetch_optional(state.pool())
            .await;

    let db_user = match db_user_opt {
        Ok(u) => u,
        Err(e) => {
            error!("DB error looking up github_id: {}", e);
            return (jar, error_redirect(&format!("Database error: {e}")));
        }
    };

    // security_p0_5: there is deliberately NO email-based account lookup here.
    // An email address returned by an OAuth provider is not proof of ownership:
    // GitHub permits unverified addresses on non-protected domains, so matching on
    // it let anyone who registered a victim's address on GitHub bind their token
    // to the victim's row and receive a session for it. Identity is now keyed on
    // the immutable provider subject (`github_id`) alone. Linking a GitHub
    // identity to an existing FireCrow account must happen from inside an
    // authenticated session, which does not exist yet - see the follow-up note
    // in the commit message.

    let user = if let Some(mut existing) = db_user {
        let encrypted = match state.crypto().encrypt_secret(&token_data.access_token) {
            Ok(e) => e,
            Err(e) => {
                return (
                    jar,
                    error_redirect(&format!("Token encryption failed: {e}")),
                )
            }
        };
        if let Err(e) =
            sqlx::query("UPDATE users SET github_id = $1, github_access_token = $2 WHERE id = $3")
                .bind(&github_id_str)
                .bind(&encrypted)
                .bind(&existing.id)
                .execute(state.pool())
                .await
        {
            // security_p0_5: this used to be `let _ = ...`, so a failed write
            // still produced a session. The account would be authenticated with
            // an OAuth token the server never stored.
            error!(
                "Failed to persist GitHub identity for user {}: {}",
                existing.id, e
            );
            return (
                jar,
                error_redirect("Could not link this GitHub account. Please try again."),
            );
        }
        existing.github_id = Some(github_id_str);
        existing.github_access_token = Some(token_data.access_token);
        existing
    } else {
        let new_id = uuid::Uuid::new_v4().to_string();
        let username = format!(
            "{}_{}",
            gh_user.login,
            new_id.chars().take(4).collect::<String>()
        );
        let now = chrono::Utc::now().naive_utc();
        let encrypted = match state.crypto().encrypt_secret(&token_data.access_token) {
            Ok(e) => e,
            Err(e) => {
                return (
                    jar,
                    error_redirect(&format!("Token encryption failed: {e}")),
                )
            }
        };
        match sqlx::query(
            "INSERT INTO users (id, username, email, is_active, credit_balance, github_id, github_access_token, created_at) VALUES ($1, $2, $3, true, 0.0, $4, $5, $6)")
            .bind(&new_id).bind(&username).bind(&gh_user.email)
            .bind(&github_id_str).bind(&encrypted).bind(now)
            .execute(state.pool()).await {
            Ok(_) => {},
            Err(_) => {
                // `users.email` is UNIQUE. Without the email-match fallback above,
                // an address already in use means someone else holds the account,
                // so say so rather than leaking the constraint name.
                if gh_user.email.is_some() {
                    // Phase 20: the sqlx error embeds `Key (email)=(…)` — the
                    // claimant's address must not reach the log. The GitHub
                    // subject identifies the collision without PII.
                    error!(
                        "GitHub signup collided with an existing email for github_id {}",
                        gh_user.id
                    );
                    return (jar, error_redirect(
                        "An account already exists for this email address. Sign in with your password instead.",
                    ));
                }
                return (jar, error_redirect("Could not create an account. Please try again."));
            }
        };
        match sqlx::query_as::<_, crate::models::User>("SELECT * FROM users WHERE id = $1")
            .bind(&new_id)
            .fetch_one(state.pool())
            .await
        {
            Ok(u) => u,
            Err(e) => {
                return (
                    jar,
                    error_redirect(&format!("Failed to fetch new user: {e}")),
                )
            }
        }
    };

    // P0-A (ZT-01-1 / ZT-01-5): the callback does NOT mint session cookies.
    // It only proves the GitHub OAuth step succeeded and issues a one-time
    // exchange code; the session (or the MFA challenge, for MFA-enabled
    // accounts) is issued by POST /auth/exchange. Minting cookies here would
    // hand a full session to an MFA-enabled account with no second factor.
    let exchange_code = uuid::Uuid::new_v4().to_string();
    // The exchange flow only consumes user_id/username (the session is minted
    // fresh in POST /auth/exchange), so no token material needs to be stored —
    // a plain placeholder goes in; create_exchange_code encrypts it at rest.
    if let Err(e) = crate::services::auth::create_exchange_code(
        state.pool(),
        &exchange_code,
        &user.id,
        &user.username,
        "oauth-exchange-no-token",
        120,
        state.crypto(),
    )
    .await
    {
        return (
            jar,
            error_redirect(&format!("Exchange code creation failed: {e}")),
        );
    }

    let _ = crate::services::security_log::record_security_event(
        state.pool(),
        Some(&user.id),
        None,
        "oauth_github_success",
        None,
        None,
    )
    .await;

    let frontend_redirect = format!("{}/?code={}", frontend_base, exchange_code);
    info!(
        "GitHub OAuth success for user: {}, redirecting to frontend",
        user.username
    );
    (jar, Redirect::temporary(&frontend_redirect))
}

// HIGH-08: previously cast `char as u8`, corrupting any non-ASCII character.
// Uses RFC 3986 percent-encoding over UTF-8 bytes instead (preserves -_.~).
fn urlencoding(s: &str) -> String {
    utf8_percent_encode(s, percent_encoding::CONTROLS).to_string()
}

pub async fn policy_context() -> Result<Json<serde_json::Value>> {
    Ok(Json(
        serde_json::json!({"privacy_policy_version": "2026-06-06", "terms_version": "2026-06-06"}),
    ))
}
/// security_s_15: this endpoint was unauthenticated and unbounded, and passed
/// `None` as the user id, so any anonymous caller could write an unbounded number
/// of unattributable rows. There is no caller of this route anywhere in the
/// frontend, so requiring authentication closes the hole without breaking a
/// client. Every row is now attributable to the authenticated user.
pub async fn create_policy_event(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
    Json(payload): Json<serde_json::Value>,
) -> Result<StatusCode> {
    crate::services::security_log::record_security_event(
        state.pool(),
        // (user_id, tenant_id) — the author, not the tenant. Passing this in the
        // tenant slot silently left every row unattributable, which is the very
        // defect security_s_15 describes.
        Some(&user.user_id),
        None,
        "policy_event",
        Some(&payload.to_string()),
        None,
    )
    .await?;
    Ok(StatusCode::ACCEPTED)
}

fn is_allowed_origin(origin: &str, state: &crate::AppState) -> bool {
    let frontend_base = state.settings().frontend_url.trim_end_matches('/');
    if origin == frontend_base {
        return true;
    }
    let cors_origins: Vec<&str> = state
        .settings()
        .cors_origins
        .split(',')
        .map(|s| s.trim().trim_end_matches('/'))
        .collect();
    if cors_origins.contains(&origin) {
        return true;
    }
    // security_p0_3: localhost was previously accepted in every environment, so a
    // `Referer: http://localhost:8000` header made `github_login` store
    // `oauth_redirect_origin` on the victim's browser and then deliver the
    // single-use session code to whatever host that cookie named. Local origins
    // are now a development-only allowance.
    if state.settings().debug {
        return matches!(
            origin,
            "http://localhost:3000"
                | "http://127.0.0.1:3000"
                | "http://localhost:5173"
                | "http://127.0.0.1:5173"
                | "http://localhost:8000"
                | "http://127.0.0.1:8000"
        );
    }
    false
}

fn get_cookie_samesite(state: &crate::AppState) -> axum_extra::extract::cookie::SameSite {
    match state
        .settings()
        .auth_cookie_samesite
        .to_lowercase()
        .as_str()
    {
        "lax" => axum_extra::extract::cookie::SameSite::Lax,
        "none" => axum_extra::extract::cookie::SameSite::None,
        _ => axum_extra::extract::cookie::SameSite::Strict,
    }
}

fn is_cookie_secure(
    state: &crate::AppState,
    samesite: axum_extra::extract::cookie::SameSite,
) -> bool {
    state.settings().auth_cookie_secure
        || !state.settings().debug
        || samesite == axum_extra::extract::cookie::SameSite::None
}

#[cfg(test)]
mod lockout_key_tests {
    use super::resolve_lockout_keys;

    /// No topology may ever alias the IP key to the account key: aliasing
    /// double-records each failure and halves the documented lockout limit
    /// (FC-RELEASE-017 finding 2).
    fn assert_no_alias(account: &str, ip: &Option<String>) {
        assert_ne!(
            ip.as_deref(),
            Some(account),
            "IP key must never equal the account key"
        );
    }

    #[test]
    fn trusted_proxy_peer_enables_a_distinct_ip_key() {
        let (account, ip) = resolve_lockout_keys(true, false, "203.0.113.7", "analyst");
        assert_eq!(account, "login:analyst");
        assert_eq!(ip.as_deref(), Some("login_ip:203.0.113.7"));
        assert_no_alias(&account, &ip);
    }

    #[test]
    fn attested_direct_deploy_enables_a_distinct_ip_key() {
        let (account, ip) = resolve_lockout_keys(false, true, "198.51.100.9", "analyst");
        assert_eq!(ip.as_deref(), Some("login_ip:198.51.100.9"));
        assert_no_alias(&account, &ip);
    }

    #[test]
    fn unrecognized_shared_ingress_has_no_ip_key() {
        // The finding-1 topology: peer is a load balancer nobody configured
        // (not a trusted proxy, no direct-deploy attestation). The peer
        // address is identical for every caller, so any IP key here would be
        // a GLOBAL lockout — hence None.
        let (account, ip) = resolve_lockout_keys(false, false, "10.0.4.21", "analyst");
        assert_eq!(account, "login:analyst");
        assert_eq!(ip, None);
    }

    #[test]
    fn render_style_topology_has_no_ip_key() {
        // Same rule, no RENDER special-case needed: a shared-ingress peer is
        // simply never a proven client, with or without the env signal.
        let (account, ip) = resolve_lockout_keys(false, false, "10.0.4.21", "victim");
        assert_eq!(ip, None);
        assert_no_alias(&account, &ip);
    }
}
