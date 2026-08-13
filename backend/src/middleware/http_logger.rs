//! Safe HTTP Request & Response Audit Logger Middleware
//! Redacts all security keys, secrets, passwords, tokens, and authorization headers,
//! while printing clean, unbuffered, color-coded HTTP traffic logs for AI flaw analysis.

use axum::{
    body::{to_bytes, Body},
    extract::Request,
    middleware::Next,
    response::Response,
};
use std::time::Instant;
use tracing::info;
use crate::middleware::cloudflare::extract_client_ip;

/// Recursively redacts sensitive keys in JSON payloads
pub fn redact_json_value(val: &mut serde_json::Value) {
    match val {
        serde_json::Value::Object(map) => {
            for (key, v) in map.iter_mut() {
                let k_lower = key.to_lowercase();
                if k_lower.contains("password")
                    || k_lower.contains("secret")
                    || k_lower.contains("token")
                    || k_lower.contains("auth")
                    || k_lower.contains("cookie")
                    || k_lower.contains("key")
                    || k_lower.contains("credential")
                    || k_lower.contains("p256dh")
                    || k_lower.contains("private")
                {
                    *v = serde_json::Value::String("[REDACTED]".into());
                } else {
                    redact_json_value(v);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                redact_json_value(item);
            }
        }
        serde_json::Value::String(s) => {
            if s.starts_with("Bearer ") || s.starts_with("eyJ") {
                *s = "[REDACTED_JWT_TOKEN]".to_string();
            }
        }
        _ => {}
    }
}

/// Helper to parse and safely redact JSON or text payloads
pub fn safe_payload_snippet(bytes: &[u8], max_len: usize) -> String {
    if bytes.is_empty() {
        return "<empty>".to_string();
    }

    if let Ok(utf8_str) = std::str::from_utf8(bytes) {
        if let Ok(mut json_val) = serde_json::from_str::<serde_json::Value>(utf8_str) {
            redact_json_value(&mut json_val);
            let s = json_val.to_string();
            if s.len() > max_len {
                format!("{}... [truncated]", &s[..max_len])
            } else {
                s
            }
        } else {
            let mut text = utf8_str.to_string();
            let keys = [
                "password", "secret", "token", "authorization", "bearer", "cookie",
                "api_key", "gemini_api_key", "encryption_key", "secret_key"
            ];
            for key in keys {
                let pattern = format!(r"(?i)({}\s*[:=]\s*)[^\s&,}}]+", key);
                if let Ok(re) = regex::Regex::new(&pattern) {
                    text = re.replace_all(&text, "${1}[REDACTED]").to_string();
                }
            }
            if text.len() > max_len {
                format!("{}... [truncated]", &text[..max_len])
            } else {
                text
            }
        }
    } else {
        format!("<binary data {} bytes>", bytes.len())
    }
}

/// Middleware that logs every incoming HTTP request and outgoing response cleanly with secret redaction.
pub async fn http_audit_logger(
    req: Request,
    next: Next,
) -> Result<Response, axum::http::StatusCode> {
    let method = req.method().clone();
    let uri = req.uri().to_string();
    let client_ip = extract_client_ip(req.headers(), None);
    let start_time = Instant::now();

    // 1. Inspect Request Body
    let (parts, body) = req.into_parts();
    let (req_bytes, req_body) = if method == axum::http::Method::GET || method == axum::http::Method::HEAD || method == axum::http::Method::OPTIONS {
        (Vec::new(), body)
    } else {
        match to_bytes(body, 2 * 1024 * 1024).await {
            Ok(b) => (b.to_vec(), Body::from(b)),
            Err(_) => (Vec::new(), Body::empty()),
        }
    };

    let req_payload_summary = safe_payload_snippet(&req_bytes, 800);
    
    info!(target: "http_audit", "[HTTP REQ] {} {} | Client: {} | Payload: {}", method, uri, client_ip, req_payload_summary);

    // Reconstruct Request
    let req = Request::from_parts(parts, req_body);

    // 2. Execute Handler
    let res = next.run(req).await;
    let duration_ms = start_time.elapsed().as_millis();
    let status = res.status();

    // Check if response is a streaming response (e.g. SSE stream)
    let is_stream = res
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("text/event-stream"))
        .unwrap_or(false);

    if is_stream {
        info!(target: "http_audit", "[HTTP RES] {} {} -> {} ({}ms) | Payload: <event-stream>", method, uri, status, duration_ms);
        return Ok(res);
    }

    // 3. Inspect Response Body for normal JSON/text responses
    let (res_parts, res_body) = res.into_parts();
    let (res_bytes, new_res_body) = match to_bytes(res_body, 2 * 1024 * 1024).await {
        Ok(b) => (b.to_vec(), Body::from(b)),
        Err(_) => (Vec::new(), Body::empty()),
    };

    let res_payload_summary = safe_payload_snippet(&res_bytes, 800);

    info!(target: "http_audit", "[HTTP RES] {} {} -> {} ({}ms) | Payload: {}", method, uri, status, duration_ms, res_payload_summary);

    // Reconstruct Response
    let res = Response::from_parts(res_parts, new_res_body);
    Ok(res)
}
