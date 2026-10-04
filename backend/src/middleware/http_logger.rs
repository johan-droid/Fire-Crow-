//! Safe HTTP Request & Response Audit Logger Middleware
//! Redacts all security keys, secrets, passwords, tokens, and authorization headers,
//! while printing clean, unbuffered, color-coded HTTP traffic logs for AI flaw analysis.

use crate::middleware::cloudflare::{peer_ip_of, resolve_client_ip};
use axum::{
    body::{to_bytes, Body},
    extract::Request,
    middleware::Next,
    response::Response,
};
use std::time::Instant;
use tracing::info;

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
                    // Phase 20: request bodies carry user PII and finding
                    // evidence. Both are attacker-influenceable (an email
                    // field, a report response) and neither belongs in logs.
                    || k_lower.contains("email")
                    || k_lower.contains("evidence")
                    || k_lower.contains("snippet")
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
        serde_json::Value::String(s) if (s.starts_with("Bearer ") || s.starts_with("eyJ")) => {
            *s = "[REDACTED_JWT_TOKEN]".to_string();
        }
        _ => {}
    }
}

/// Query-string keys whose values must never reach the log.
/// `token`/`access_token` are accepted by `AuthenticatedUser` (middleware/auth.rs),
/// so a bearer JWT arrives in the URI on every SSE connect.
const SENSITIVE_QUERY_KEYS: &[&str] = &[
    "token",
    "access_token",
    "refresh_token",
    "code",
    "password",
    "secret",
    // Exact match, so "secret" does not cover this: an OAuth client secret in
    // the query string would otherwise be logged verbatim.
    "client_secret",
    "api_key",
];

/// Strips sensitive query-string values from a URI before it is logged.
///
/// Returns the URI unchanged when it has no query string. The path is never
/// modified — only the *values* of sensitive keys are replaced, so the log stays
/// useful for debugging while never containing a usable credential.
///
/// security_p0_1b: the audit logger must not write bearer tokens to disk.
pub fn redact_uri_for_log(uri: &str) -> String {
    let Some((path, query)) = uri.split_once('?') else {
        return uri.to_string();
    };
    if query.is_empty() {
        return uri.to_string();
    }

    let mut out = String::with_capacity(uri.len());
    out.push_str(path);
    out.push('?');

    for (i, pair) in query.split('&').enumerate() {
        if i > 0 {
            out.push('&');
        }
        match pair.split_once('=') {
            Some((k, _))
                if SENSITIVE_QUERY_KEYS
                    .iter()
                    .any(|sensitive| sensitive.eq_ignore_ascii_case(k)) =>
            {
                out.push_str(k);
                out.push_str("=[REDACTED]");
            }
            _ => out.push_str(pair),
        }
    }
    out
}

/// Truncates on a UTF-8 character boundary.
///
/// `&s[..max_len]` panics when `max_len` lands inside a multi-byte character.
/// An attacker fully controls request bodies, so that panic is remotely
/// reachable and, under `panic = "abort"`, terminates the process.
///
/// security_p0_1: all audit-log truncation goes through here.
pub fn truncate_utf8_safe(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }
    let end = s.floor_char_boundary(max_len);
    format!("{}... [truncated]", &s[..end])
}

/// Patterns for redacting `key: value` / `key=value` pairs in non-JSON bodies.
///
/// Compiled once. Compiling these per request let an attacker force 10 regex
/// compilations for every 2 MB non-JSON POST.
static TEXT_REDACT_PATTERNS: std::sync::OnceLock<Vec<regex::Regex>> = std::sync::OnceLock::new();

fn text_redact_patterns() -> &'static [regex::Regex] {
    TEXT_REDACT_PATTERNS.get_or_init(|| {
        [
            "password",
            "secret",
            "token",
            "authorization",
            "bearer",
            "cookie",
            "api_key",
            "gemini_api_key",
            "encryption_key",
            "secret_key",
        ]
        .iter()
        .filter_map(|key| regex::Regex::new(&format!(r"(?i)({}\s*[:=]\s*)[^\s&,}}]+", key)).ok())
        .collect()
    })
}

/// Helper to parse and safely redact JSON or text payloads
pub fn safe_payload_snippet(bytes: &[u8], max_len: usize) -> String {
    if bytes.is_empty() {
        return "<empty>".to_string();
    }

    if let Ok(utf8_str) = std::str::from_utf8(bytes) {
        if let Ok(mut json_val) = serde_json::from_str::<serde_json::Value>(utf8_str) {
            redact_json_value(&mut json_val);
            truncate_utf8_safe(&json_val.to_string(), max_len)
        } else {
            let mut text = utf8_str.to_string();
            for re in text_redact_patterns() {
                text = re.replace_all(&text, "${1}[REDACTED]").to_string();
            }
            truncate_utf8_safe(&text, max_len)
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
    let uri = redact_uri_for_log(&req.uri().to_string());
    let client_ip = resolve_client_ip(req.headers(), peer_ip_of(&req));
    let start_time = Instant::now();

    // 1. Inspect Request Body
    let (parts, body) = req.into_parts();
    let (req_bytes, req_body) = if method == axum::http::Method::GET
        || method == axum::http::Method::HEAD
        || method == axum::http::Method::OPTIONS
    {
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
