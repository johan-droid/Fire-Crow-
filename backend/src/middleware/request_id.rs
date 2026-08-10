use axum::{extract::Request, middleware::Next, response::Response};

pub async fn request_id_middleware(req: Request, next: Next) -> Response {
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let mut response = next.run(req).await;
    if let Ok(header_val) = request_id.parse() {
        response.headers_mut().insert("X-Request-ID", header_val);
    }
    response
}
