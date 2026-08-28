use axum::{Json, Router, extract::{State, Query}, http::StatusCode, routing::{get, post}, response::Redirect};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use percent_encoding::utf8_percent_encode;
use serde::Deserialize;
use std::sync::Arc;
use tracing::{error, info};
use crate::error::{AppError, Result};

pub fn router() -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/exchange", post(exchange_token))
        .route("/refresh", post(refresh_token))
        .route("/policy-context", get(policy_context))
        .route("/policy-events", post(create_policy_event))
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/me", get(get_me))
        .route("/session", get(get_session))
        .route("/activities", get(get_activities))
        .route("/github", get(github_login))
        .route("/github/callback", get(github_callback))
}

pub async fn exchange_token(
    State(state): State<Arc<crate::AppState>>,
    jar: CookieJar,
    Json(payload): Json<serde_json::Value>,
) -> Result<(CookieJar, Json<serde_json::Value>)> {
    let code = payload.get("code").and_then(|v| v.as_str()).ok_or_else(|| AppError::BadRequest("Missing code".into()))?;
    let (user_id, username, _encrypted_access_token) = crate::services::auth::verify_and_consume_exchange_code(state.pool(), code, state.crypto()).await?
        .ok_or_else(|| AppError::BadRequest("Invalid or expired exchange code".into()))?;

    let db_user: Option<crate::models::User> = sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(&user_id).fetch_optional(state.pool()).await.map_err(AppError::Database)?;
    let tenant_id = db_user.as_ref().and_then(|u| u.tenant_id.clone()).unwrap_or_default();

    let token_family = uuid::Uuid::new_v4().to_string();
    let (access_token_str, _) = crate::services::auth::create_access_token(&user_id, &username, &state.settings().secret_key, &tenant_id, state.settings().jwt_access_token_expire_minutes)?;
    let (refresh_token_str, _) = crate::services::auth::create_refresh_token(&user_id, &username, &state.settings().secret_key, &tenant_id, &token_family)?;

    let cookie_name = state.settings().auth_cookie_name.clone();
    let samesite = get_cookie_samesite(&state);
    let access_cookie = Cookie::build((cookie_name.clone(), access_token_str.clone()))
        .path("/")
        .http_only(true)
        .secure(!state.settings().debug)
        .same_site(samesite)
        .build();

    let refresh_cookie = Cookie::build((format!("{}_refresh", cookie_name), refresh_token_str.clone()))
        .path("/")
        .http_only(true)
        .secure(!state.settings().debug)
        .same_site(samesite)
        .build();

    let jar = jar.add(access_cookie).add(refresh_cookie);

    let email = db_user.as_ref().and_then(|u| u.email.clone());

    Ok((jar, Json(serde_json::json!({
        "access_token": access_token_str,
        "token_type": "bearer",
        "username": username,
        "user_id": user_id,
        "email": email
    }))))
}

pub async fn refresh_token(
    State(state): State<Arc<crate::AppState>>,
    jar: CookieJar,
    Json(payload): Json<serde_json::Value>,
) -> Result<(CookieJar, Json<serde_json::Value>)> {
    let token = payload.get("refresh_token").and_then(|v| v.as_str())
        .or_else(|| jar.get("refresh_token").map(|c| c.value()))
        .unwrap_or("");
    // Use the anti-replay validator so an already-rotated/revoked refresh token
    // is rejected (HIGH-02/HIGH-03).
    let claims = crate::services::auth::validate_token_with_anti_replay(token, &state.settings().secret_key, state.redis(), state.pool()).await?;
    if claims.claims.token_type != crate::services::auth::TokenType::Refresh { return Err(AppError::InvalidToken); }

    let ttl = state.settings().jwt_access_token_expire_minutes * 60;
    let old_jti = claims.claims.jti.clone();
    let old_family = claims.claims.token_family.clone();
    if let Some(redis) = state.redis() {
        let _ = crate::services::auth::revoke_token_jti(redis, &old_jti, ttl).await;
        let _ = crate::services::auth::revoke_token_family(redis, &old_family, ttl).await;
    } else {
        let _ = crate::services::auth::revoke_token_in_db(state.pool(), &old_jti, &old_family, ttl).await;
    }

    let new_family = uuid::Uuid::new_v4().to_string();
    let tenant_id = claims.claims.tenant_id.clone();
    let (access_token_str, _) = crate::services::auth::create_access_token(&claims.claims.sub, &claims.claims.username, &state.settings().secret_key, &tenant_id, state.settings().jwt_access_token_expire_minutes)?;
    let (refresh_token_str, _) = crate::services::auth::create_refresh_token(&claims.claims.sub, &claims.claims.username, &state.settings().secret_key, &tenant_id, &new_family)?;

    let cookie_name = state.settings().auth_cookie_name.clone();
    let samesite = get_cookie_samesite(&state);
    let access_cookie = Cookie::build((cookie_name.clone(), access_token_str.clone()))
        .path("/")
        .http_only(true)
        .secure(!state.settings().debug)
        .same_site(samesite)
        .build();

    let refresh_cookie = Cookie::build((format!("{}_refresh", cookie_name), refresh_token_str.clone()))
        .path("/")
        .http_only(true)
        .secure(!state.settings().debug)
        .same_site(samesite)
        .build();

    let jar = jar.add(access_cookie).add(refresh_cookie);

    Ok((jar, Json(serde_json::json!({"access_token": access_token_str, "token_type": "bearer", "username": claims.claims.username, "user_id": claims.claims.sub}))))
}

pub async fn register(State(state): State<Arc<crate::AppState>>, Json(payload): Json<serde_json::Value>) -> Result<Json<serde_json::Value>> {
    let username = payload.get("username").and_then(|v| v.as_str()).ok_or_else(|| AppError::BadRequest("Missing username".into()))?;
    let password = payload.get("password").and_then(|v| v.as_str()).ok_or_else(|| AppError::BadRequest("Missing password".into()))?;
    let email_input = payload.get("email").and_then(|v| v.as_str()).unwrap_or("");
    let email = if email_input.trim().is_empty() {
        format!("{}@local.firecrow", username.trim().to_lowercase())
    } else {
        email_input.trim().to_lowercase()
    };

    if password.len() < 8 { return Err(AppError::BadRequest("Password must be at least 8 characters".into())); }
    let password_hash = crate::services::auth::hash_password(password)?;
    let user_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().naive_utc();
    sqlx::query("INSERT INTO users (id, username, email, password_hash, is_active, credit_balance, created_at) VALUES ($1,$2,$3,$4,true,0.0,$5)")
        .bind(&user_id).bind(username).bind(&email).bind(password_hash).bind(now)
        .execute(state.pool()).await.map_err(AppError::Database)?;
    crate::services::security_log::record_security_event(state.pool(), Some(&user_id), None, "user_registered", None, None).await.ok();
    Ok(Json(serde_json::json!({"user_id": user_id, "username": username, "email": email})))
}

pub async fn login(
    State(state): State<Arc<crate::AppState>>,
    jar: CookieJar,
    Json(payload): Json<serde_json::Value>,
) -> Result<(CookieJar, Json<serde_json::Value>)> {
    let username = payload.get("username").and_then(|v| v.as_str()).ok_or_else(|| AppError::BadRequest("Missing username".into()))?;
    let password = payload.get("password").and_then(|v| v.as_str()).ok_or_else(|| AppError::BadRequest("Missing password".into()))?;
    let normalized = username.trim().to_lowercase();
    let lockout_key = format!("login:{}", normalized);
    if crate::services::auth::check_login_lockout(state.pool(), &lockout_key, state.settings().login_failure_window_minutes, state.settings().login_failure_limit).await? {
        return Err(AppError::AccountLocked);
    }
    let user: Option<crate::models::User> = sqlx::query_as::<_, crate::models::User>("SELECT * FROM users WHERE LOWER(username)=$1 OR LOWER(email)=$1")
        .bind(&normalized).fetch_optional(state.pool()).await.map_err(AppError::Database)?;
    let user = match user { Some(u) => u, None => { crate::services::auth::record_login_failure(state.pool(), &lockout_key).await?; return Err(AppError::InvalidCredentials); } };
    if !user.is_active {
        crate::services::auth::record_login_failure(state.pool(), &lockout_key).await?;
        return Err(AppError::Forbidden("Account is deactivated".into()));
    }
    let password_hash = user.password_hash.as_deref().unwrap_or("");
    if !crate::services::auth::verify_password(password, password_hash)? {
        crate::services::auth::record_login_failure(state.pool(), &lockout_key).await?;
        return Err(AppError::InvalidCredentials);
    }
    crate::services::auth::clear_login_failures(state.pool(), &lockout_key).await?;
    let token_family = uuid::Uuid::new_v4().to_string();
    let tenant_id = user.tenant_id.clone().unwrap_or_default();
    let (access_token_str, _) = crate::services::auth::create_access_token(&user.id, &user.username, &state.settings().secret_key, &tenant_id, state.settings().jwt_access_token_expire_minutes)?;
    let (refresh_token_str, _) = crate::services::auth::create_refresh_token(&user.id, &user.username, &state.settings().secret_key, &tenant_id, &token_family)?;
    sqlx::query("UPDATE users SET last_login_at=$1 WHERE id=$2").bind(chrono::Utc::now().naive_utc()).bind(&user.id).execute(state.pool()).await.ok();

    let cookie_name = state.settings().auth_cookie_name.clone();
    let samesite = get_cookie_samesite(&state);
    let access_cookie = Cookie::build((cookie_name.clone(), access_token_str.clone()))
        .path("/")
        .http_only(true)
        .secure(!state.settings().debug)
        .same_site(samesite)
        .build();

    let refresh_cookie = Cookie::build((format!("{}_refresh", cookie_name), refresh_token_str.clone()))
        .path("/")
        .http_only(true)
        .secure(!state.settings().debug)
        .same_site(samesite)
        .build();

    let jar = jar.add(access_cookie).add(refresh_cookie);

    Ok((jar, Json(serde_json::json!({"access_token": access_token_str, "token_type": "bearer", "username": user.username, "user_id": user.id, "email": user.email}))))
}

pub async fn demo_login(
    State(_state): State<Arc<crate::AppState>>,
    jar: CookieJar,
) -> Result<(CookieJar, Json<serde_json::Value>)> {
    Err(AppError::Unauthorized("Demo endpoint disabled".into()))
}

pub async fn logout(
    State(state): State<Arc<crate::AppState>>,
    jar: CookieJar,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<(CookieJar, Json<serde_json::Value>)> {
    let ttl = state.settings().jwt_access_token_expire_minutes * 60;
    if let Some(redis) = state.redis() {
        let _ = crate::services::auth::revoke_token_jti(redis, &user.jti, ttl).await;
        let _ = crate::services::auth::revoke_token_family(redis, &user.token_family, ttl).await;
    } else {
        let _ = crate::services::auth::revoke_token_in_db(state.pool(), &user.jti, &user.token_family, ttl).await;
    }

    let cookie_name = state.settings().auth_cookie_name.clone();
    let mut access_cookie = Cookie::build((cookie_name.clone(), "")).path("/").http_only(true).build();
    access_cookie.make_removal();

    let mut refresh_cookie = Cookie::build((format!("{}_refresh", cookie_name), "")).path("/").http_only(true).build();
    refresh_cookie.make_removal();

    let jar = jar.add(access_cookie).add(refresh_cookie);
    Ok((jar, Json(serde_json::json!({"status": "logged_out"}))))
}

pub async fn get_me(State(state): State<Arc<crate::AppState>>, user: crate::middleware::auth::AuthenticatedUser) -> Result<Json<serde_json::Value>> {
    let db_user: Option<crate::models::User> = sqlx::query_as::<_, crate::models::User>("SELECT * FROM users WHERE id=$1").bind(&user.user_id).fetch_optional(state.pool()).await.map_err(AppError::Database)?;
    let db_user = db_user.ok_or_else(|| AppError::NotFound("User not found".into()))?;
    Ok(Json(serde_json::json!({"user_id": db_user.id, "username": db_user.username, "email": db_user.email, "is_active": db_user.is_active, "credit_balance": db_user.credit_balance})))
}

pub async fn get_session(State(_state): State<Arc<crate::AppState>>, user: crate::middleware::auth::AuthenticatedUser) -> Result<Json<serde_json::Value>> {
    Ok(Json(serde_json::json!({"user_id": user.user_id, "username": user.username, "session_valid": true})))
}

pub async fn get_activities(State(state): State<Arc<crate::AppState>>, user: crate::middleware::auth::AuthenticatedUser) -> Result<Json<Vec<crate::models::UserActivityEvent>>> {
    crate::services::user_activity::list_user_activities(state.pool(), &user.user_id, 50).await.map(Json)
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

pub async fn github_login(
    State(state): State<Arc<crate::AppState>>,
    headers: axum::http::HeaderMap,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect)> {
    let oauth_state = crate::services::auth::create_oauth_state();
    let cookie = Cookie::build(("oauth_state", oauth_state.clone()))
        .path("/")
        .http_only(true)
        .secure(!state.settings().debug)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
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
                    .secure(!state.settings().debug)
                    .same_site(axum_extra::extract::cookie::SameSite::Lax)
                    .build();
                jar = jar.add(redirect_cookie);
            }
        }
    }
        
    let base_url = state.settings().backend_base_url.trim_end_matches('/');
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
    jar: CookieJar,
    Query(query): Query<OAuthCallbackQuery>
) -> (CookieJar, Redirect) {
    let redirect_origin = jar.get("oauth_redirect_origin").map(|c| c.value().to_string());
    let jar = jar.remove(Cookie::from("oauth_redirect_origin"));

    let frontend_base = redirect_origin.unwrap_or_else(|| {
        state.settings().frontend_url.trim_end_matches('/').to_string()
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
    let jar = jar.remove(Cookie::from("oauth_state"));

    let base_url = state.settings().backend_base_url.trim_end_matches('/');
    let redirect_uri = format!("{}/api/v1/auth/github/callback", base_url);

    let client = reqwest::Client::new();
    let token_res = client.post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .header("User-Agent", "Fire-Crow-Backend")
        .form(&[
            ("client_id", state.settings().github_client_id.as_str()),
            ("client_secret", state.settings().github_client_secret.as_str()),
            ("code", query.code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
        ])
        .send().await;

    let token_body = match token_res {
        Ok(r) => match r.text().await {
            Ok(t) => t,
            Err(e) => return (jar, error_redirect(&format!("Failed to read token response: {e}"))),
        },
        Err(e) => return (jar, error_redirect(&format!("GitHub token request failed: {e}"))),
    };

    let token_data: GitHubTokenResponse = match serde_json::from_str(&token_body) {
        Ok(t) => t,
        Err(e) => return (jar, error_redirect(&format!("GitHub token parse error: {e}"))),
    };

    let user_res = client.get("https://api.github.com/user")
        .header("User-Agent", "Fire-Crow-Backend")
        .header("Accept", "application/vnd.github.v3+json")
        .header("Authorization", format!("Bearer {}", token_data.access_token))
        .send().await;

    let user_body = match user_res {
        Ok(r) => match r.text().await {
            Ok(t) => t,
            Err(e) => return (jar, error_redirect(&format!("Failed to read user response: {e}"))),
        },
        Err(e) => return (jar, error_redirect(&format!("GitHub user request failed: {e}"))),
    };

    let gh_user: GitHubUser = match serde_json::from_str(&user_body) {
        Ok(u) => u,
        Err(e) => return (jar, error_redirect(&format!("GitHub user parse error: {e}"))),
    };

    let github_id_str = gh_user.id.to_string();

    let db_user_opt = sqlx::query_as::<_, crate::models::User>(
        "SELECT * FROM users WHERE github_id = $1")
        .bind(&github_id_str)
        .fetch_optional(state.pool()).await;

    let mut db_user = match db_user_opt {
        Ok(u) => u,
        Err(e) => {
            error!("DB error looking up github_id: {}", e);
            return (jar, error_redirect(&format!("Database error: {e}")));
        }
    };

    if db_user.is_none() {
        if let Some(email) = &gh_user.email {
            db_user = match sqlx::query_as::<_, crate::models::User>(
                "SELECT * FROM users WHERE email = $1")
                .bind(email)
                .fetch_optional(state.pool()).await {
                Ok(u) => u,
                Err(e) => {
                    error!("DB error looking up email: {}", e);
                    None
                }
            };
        }
    }

    let user = if let Some(mut existing) = db_user {
        let encrypted = match state.crypto().encrypt_secret(&token_data.access_token) {
            Ok(e) => e,
            Err(e) => return (jar, error_redirect(&format!("Token encryption failed: {e}"))),
        };
        let _ = sqlx::query("UPDATE users SET github_id = $1, github_access_token = $2 WHERE id = $3")
            .bind(&github_id_str)
            .bind(&encrypted)
            .bind(&existing.id)
            .execute(state.pool()).await;
        existing.github_id = Some(github_id_str);
        existing.github_access_token = Some(token_data.access_token);
        existing
    } else {
        let new_id = uuid::Uuid::new_v4().to_string();
        let username = format!("{}_{}", gh_user.login, new_id.chars().take(4).collect::<String>());
        let now = chrono::Utc::now().naive_utc();
        let encrypted = match state.crypto().encrypt_secret(&token_data.access_token) {
            Ok(e) => e,
            Err(e) => return (jar, error_redirect(&format!("Token encryption failed: {e}"))),
        };
        match sqlx::query(
            "INSERT INTO users (id, username, email, is_active, credit_balance, github_id, github_access_token, created_at) VALUES ($1, $2, $3, true, 0.0, $4, $5, $6)")
            .bind(&new_id).bind(&username).bind(&gh_user.email)
            .bind(&github_id_str).bind(&encrypted).bind(now)
            .execute(state.pool()).await {
            Ok(_) => {},
            Err(e) => return (jar, error_redirect(&format!("Failed to create user: {e}"))),
        };
        match sqlx::query_as::<_, crate::models::User>("SELECT * FROM users WHERE id = $1")
            .bind(&new_id).fetch_one(state.pool()).await {
            Ok(u) => u,
            Err(e) => return (jar, error_redirect(&format!("Failed to fetch new user: {e}"))),
        }
    };

    let access_token_str = match crate::services::auth::create_access_token(
        &user.id, &user.username, &state.settings().secret_key,
        user.tenant_id.as_deref().unwrap_or(""),
        state.settings().jwt_access_token_expire_minutes) {
        Ok((tok, _)) => tok,
        Err(e) => return (jar, error_redirect(&format!("Token creation failed: {e}"))),
    };

    let exchange_code = uuid::Uuid::new_v4().to_string();
    if let Err(e) = crate::services::auth::create_exchange_code(
        state.pool(), &exchange_code, &user.id, &user.username, &access_token_str, 120, state.crypto()).await {
        return (jar, error_redirect(&format!("Exchange code creation failed: {e}")));
    }

    let token_family = uuid::Uuid::new_v4().to_string();
    let refresh_token_str = match crate::services::auth::create_refresh_token(
        &user.id, &user.username, &state.settings().secret_key,
        user.tenant_id.as_deref().unwrap_or(""), &token_family) {
        Ok((tok, _)) => tok,
        Err(e) => return (jar, error_redirect(&format!("Refresh token creation failed: {e}"))),
    };

    let cookie_name = state.settings().auth_cookie_name.clone();
    let samesite = get_cookie_samesite(&state);
    let access_cookie = Cookie::build((cookie_name.clone(), access_token_str.clone()))
        .path("/")
        .http_only(true)
        .secure(!state.settings().debug)
        .same_site(samesite)
        .build();

    let refresh_cookie = Cookie::build((format!("{}_refresh", cookie_name), refresh_token_str))
        .path("/")
        .http_only(true)
        .secure(!state.settings().debug)
        .same_site(samesite)
        .build();

    let jar = jar.add(access_cookie).add(refresh_cookie);

    let frontend_redirect = format!("{}/?code={}", frontend_base, exchange_code);
    info!("GitHub OAuth success for user: {}, redirecting to frontend", user.username);
    (jar, Redirect::temporary(&frontend_redirect))
}

// HIGH-08: previously cast `char as u8`, corrupting any non-ASCII character.
// Uses RFC 3986 percent-encoding over UTF-8 bytes instead (preserves -_.~).
fn urlencoding(s: &str) -> String {
    utf8_percent_encode(s, percent_encoding::CONTROLS).to_string()
}

pub async fn policy_context() -> Result<Json<serde_json::Value>> {
    Ok(Json(serde_json::json!({"privacy_policy_version": "2026-06-06", "terms_version": "2026-06-06"})))
}
pub async fn create_policy_event(State(state): State<Arc<crate::AppState>>, Json(payload): Json<serde_json::Value>) -> Result<StatusCode> {
    crate::services::security_log::record_security_event(state.pool(), None, None, "policy_event", Some(&payload.to_string()), None).await?;
    Ok(StatusCode::ACCEPTED)
}

fn is_allowed_origin(origin: &str, state: &crate::AppState) -> bool {
    let frontend_base = state.settings().frontend_url.trim_end_matches('/');
    if origin == frontend_base {
        return true;
    }
    let cors_origins: Vec<&str> = state.settings().cors_origins.split(',').map(|s| s.trim().trim_end_matches('/')).collect();
    if cors_origins.contains(&origin) {
        return true;
    }
    matches!(
        origin,
        "http://localhost:3000"
            | "http://127.0.0.1:3000"
            | "http://localhost:5173"
            | "http://127.0.0.1:5173"
            | "http://localhost:8000"
            | "http://127.0.0.1:8000"
    )
}

fn get_cookie_samesite(state: &crate::AppState) -> axum_extra::extract::cookie::SameSite {
    match state.settings().auth_cookie_samesite.to_lowercase().as_str() {
        "lax" => axum_extra::extract::cookie::SameSite::Lax,
        "none" => axum_extra::extract::cookie::SameSite::None,
        _ => axum_extra::extract::cookie::SameSite::Strict,
    }
}

