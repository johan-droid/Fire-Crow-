use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

pub async fn error_sanitizer(
    State(state): State<Arc<crate::AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let response = next.run(req).await;

    if response.status().is_server_error() {
        let debug = state.settings().debug;

        if !debug {
            let (parts, body) = response.into_parts();

            let safe_detail = match StatusCode::from_u16(parts.status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR) {
                StatusCode::INTERNAL_SERVER_ERROR => "Internal server error".to_string(),
                StatusCode::BAD_GATEWAY => "Bad gateway".to_string(),
                StatusCode::SERVICE_UNAVAILABLE => "Service unavailable".to_string(),
                _ => "Internal server error".to_string(),
            };

            let json_body = serde_json::json!({ "detail": safe_detail });
            let mut new_response = Response::builder()
                .status(parts.status)
                .header("Content-Type", "application/json")
                .body(Body::from(json_body.to_string()))
                .unwrap();

            for (key, value) in parts.headers.iter() {
                new_response.headers_mut().insert(key, value.clone());
            }

            new_response
        } else {
            response
        }
    } else {
        response
    }
}