use axum::{extract::Request, middleware::Next, response::Response};
use std::time::Instant;
use tracing::{info, warn};

pub async fn telemetry_middleware(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let start = Instant::now();
    let response = next.run(req).await;
    let duration = start.elapsed();
    let status = response.status().as_u16();
    if status >= 500 {
        warn!(method=%method, path=%path, status=status, duration_ms=duration.as_millis(), "Request completed with server error");
    } else {
        info!(method=%method, path=%path, status=status, duration_ms=duration.as_millis(), "Request completed");
    }
    response
}
