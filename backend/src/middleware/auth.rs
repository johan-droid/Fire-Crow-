use crate::error::AppError;
use crate::services::auth::validate_token_with_anti_replay;
use axum::http::request::Parts;
use std::sync::Arc;
use tracing::warn;

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub username: String,
    pub jti: String,
    pub token_family: String,
}

#[axum::async_trait]
impl axum::extract::FromRequestParts<Arc<crate::AppState>> for AuthenticatedUser {
    type Rejection = AppError;
    async fn from_request_parts(parts: &mut Parts, state: &Arc<crate::AppState>) -> Result<Self, Self::Rejection> {
        let token_opt = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|auth_header| auth_header.strip_prefix("Bearer ").map(|t| t.to_string()))
            .or_else(|| {
                parts
                    .headers
                    .get(axum::http::header::COOKIE)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|cookie_str| {
                        cookie_str.split(';').find_map(|pair| {
                            let mut parts = pair.trim().splitn(2, '=');
                            let key = parts.next()?;
                            let val = parts.next()?;
                            if key == "access_token" {
                                Some(val.to_string())
                            } else {
                                None
                            }
                        })
                    })
            });

        let token = token_opt.ok_or_else(|| AppError::Unauthorized("Missing authentication token".into()))?;
        
        let claims = validate_token_with_anti_replay(
            &token,
            &state.settings().secret_key,
            state.redis(),
        )
        .await
        .map_err(|e| {
            warn!("Token validation failed: {}", e);
            e
        })?;

        Ok(Self {
            user_id: claims.claims.sub,
            username: claims.claims.username,
            jti: claims.claims.jti,
            token_family: claims.claims.token_family,
        })
    }
}

