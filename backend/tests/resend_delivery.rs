//! FC-OPS-EMAIL-001: Resend HTTP transport for report email delivery.
//!
//! Every test drives the *real* request path — headers, JSON body, status
//! classification, retry loop — against an in-process mock of
//! `POST https://api.resend.com/emails`. No test touches the network and no
//! test can send a real email: the mock constructor refuses any non-loopback
//! base URL.
//!
//! What is proven here: a configured Resend key sends exactly the documented
//! request shape; provider acceptance is treated as acceptance (never as inbox
//! delivery, which only a webhook could prove); auth rejections are permanent
//! and unretried; rate limits and 5xx retry within the attempt ceiling with a
//! stable idempotency key; timeouts are never retried; a malformed recipient
//! never reaches the provider; and the API key never appears in errors.

mod support;

use firecrow_backend::error::DeliveryError;
use firecrow_backend::services::email::EmailService;
use firecrow_backend::services::email_artifact::EmailArtifact;
use firecrow_backend::AppError;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const API_KEY: &str = "re_test_secret_key_do_not_log";
const FROM: &str = "Fire Crow <reports@firecrow.test>";
const RECIPIENT: &str = "analyst@firecrow.test";

#[derive(Clone, Copy)]
struct MockReply {
    status: u16,
    delay_ms: Option<u64>,
}

#[derive(Debug, Clone)]
struct Captured {
    path: String,
    authorization: Option<String>,
    idempotency_key: Option<String>,
    content_type: Option<String>,
    body: String,
}

/// Spawn a minimal HTTP server that mimics the Resend send endpoint.
///
/// Replies are consumed in order; once exhausted, the last reply repeats. Each
/// response carries `connection: close`, so every attempt is a fresh request
/// and can be counted independently.
async fn spawn_resend_mock(replies: Vec<MockReply>) -> (String, Arc<Mutex<Vec<Captured>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
    let addr = listener.local_addr().expect("mock address");
    let captured: Arc<Mutex<Vec<Captured>>> = Arc::new(Mutex::new(Vec::new()));
    let queue: Arc<Mutex<VecDeque<MockReply>>> = Arc::new(Mutex::new(replies.into()));
    let cap = Arc::clone(&captured);

    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let cap = Arc::clone(&cap);
            let queue = Arc::clone(&queue);
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 4096];
                let head_end = loop {
                    let Ok(n) = sock.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos + 4;
                    }
                    if buf.len() > 65_536 {
                        return;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let mut lines = head.split("\r\n");
                let path = lines
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or_default()
                    .to_string();
                let mut content_length = 0usize;
                let mut authorization = None;
                let mut idempotency_key = None;
                let mut content_type = None;
                for line in lines {
                    let Some((key, value)) = line.split_once(':') else {
                        continue;
                    };
                    match key.trim().to_ascii_lowercase().as_str() {
                        "content-length" => content_length = value.trim().parse().unwrap_or(0),
                        "authorization" => authorization = Some(value.trim().to_string()),
                        "idempotency-key" => idempotency_key = Some(value.trim().to_string()),
                        "content-type" => content_type = Some(value.trim().to_string()),
                        _ => {}
                    }
                }
                let mut body = buf[head_end..].to_vec();
                while body.len() < content_length {
                    let Ok(n) = sock.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&chunk[..n]);
                }
                cap.lock().unwrap().push(Captured {
                    path,
                    authorization,
                    idempotency_key,
                    content_type,
                    body: String::from_utf8_lossy(&body).to_string(),
                });
                let reply = {
                    let mut q = queue.lock().unwrap();
                    let popped = q.pop_front();
                    // Repeat the last reply once the queue is exhausted: a
                    // test that queues [500] means *every* attempt sees 500.
                    if let Some(ref r) = popped {
                        if q.is_empty() {
                            q.push_back(*r);
                        }
                    }
                    popped
                };
                let (status, delay_ms) = match reply {
                    Some(r) => (r.status, r.delay_ms),
                    None => (200, None),
                };
                if let Some(ms) = delay_ms {
                    tokio::time::sleep(Duration::from_millis(ms)).await;
                }
                let payload = if status >= 400 {
                    r#"{"message":"mock provider error"}"#
                } else {
                    r#"{"id":"mock-email-id"}"#
                };
                let response = format!(
                    "HTTP/1.1 {status} Mock\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{payload}",
                    payload.len()
                );
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (format!("http://{addr}"), captured)
}

fn mock_service(base_url: &str, timeout_ms: u64) -> EmailService {
    EmailService::resend_loopback(FROM, API_KEY, base_url, Duration::from_millis(timeout_ms))
        .expect("loopback mock URL is accepted")
}

fn artifact(execution_id: &str, attempt_number: i32) -> EmailArtifact {
    EmailArtifact {
        schema_version: 1,
        execution_id: execution_id.to_string(),
        attempt_number,
        subject: "Fire Crow audit report".to_string(),
        text_body: "plain body".to_string(),
        html_body: "<p>plain body</p>".to_string(),
    }
}

fn sent(captured: &Arc<Mutex<Vec<Captured>>>) -> Vec<Captured> {
    captured.lock().unwrap().clone()
}

#[tokio::test]
async fn accepted_message_sends_the_documented_request_shape() {
    let (base, captured) = spawn_resend_mock(vec![MockReply {
        status: 200,
        delay_ms: None,
    }])
    .await;
    let service = mock_service(&base, 2_000);

    service
        .send_artifact(RECIPIENT, &artifact("exec-42", 2))
        .await
        .expect("2xx is provider acceptance");

    let all = sent(&captured);
    assert_eq!(all.len(), 1);
    let req = &all[0];
    assert_eq!(req.path, "/emails");
    assert_eq!(
        req.authorization.as_deref(),
        Some(format!("Bearer {API_KEY}").as_str())
    );
    assert_eq!(
        req.idempotency_key.as_deref(),
        Some("firecrow-email-exec-42-2"),
        "the key is derived from the artifact's execution identity, not request input"
    );
    assert!(
        req.content_type
            .as_deref()
            .is_some_and(|v| v.contains("application/json")),
        "JSON request, got {:?}",
        req.content_type
    );
    let json: serde_json::Value = serde_json::from_str(&req.body).expect("JSON body");
    assert_eq!(json["from"], FROM);
    assert_eq!(json["to"], serde_json::json!([RECIPIENT]));
    assert_eq!(json["subject"], "Fire Crow audit report");
    assert_eq!(json["text"], "plain body");
    assert_eq!(json["html"], "<p>plain body</p>");
}

#[tokio::test]
async fn auth_rejection_is_permanent_and_unretried() {
    let (base, captured) = spawn_resend_mock(vec![MockReply {
        status: 401,
        delay_ms: None,
    }])
    .await;
    let service = mock_service(&base, 2_000).with_max_attempts(3);

    let err = service
        .send_artifact(RECIPIENT, &artifact("exec-42", 1))
        .await
        .expect_err("401 must not be reported as a send");
    assert!(
        matches!(err, AppError::Delivery(DeliveryError::Authentication)),
        "{err:?}"
    );
    assert_eq!(
        sent(&captured).len(),
        1,
        "a rejected credential is never retried"
    );
}

#[tokio::test]
async fn rate_limit_retries_with_a_stable_idempotency_key() {
    let (base, captured) = spawn_resend_mock(vec![
        MockReply {
            status: 429,
            delay_ms: None,
        },
        MockReply {
            status: 200,
            delay_ms: None,
        },
    ])
    .await;
    let service = mock_service(&base, 2_000).with_max_attempts(2);

    service
        .send_artifact(RECIPIENT, &artifact("exec-7", 1))
        .await
        .expect("transient rate limit recovers within the ceiling");

    let all = sent(&captured);
    assert_eq!(all.len(), 2, "one retry, no storm");
    assert_eq!(
        all[0].idempotency_key, all[1].idempotency_key,
        "every attempt carries the same key so the provider can dedupe"
    );
}

#[tokio::test]
async fn server_errors_are_unavailable_and_never_leak_details() {
    let (base, captured) = spawn_resend_mock(vec![MockReply {
        status: 500,
        delay_ms: None,
    }])
    .await;
    let service = mock_service(&base, 2_000).with_max_attempts(2);

    let err = service
        .send_artifact(RECIPIENT, &artifact("exec-9", 1))
        .await
        .expect_err("persistent 5xx must surface as a delivery failure");
    assert!(
        matches!(err, AppError::Delivery(DeliveryError::Unavailable)),
        "{err:?}"
    );
    assert_eq!(
        sent(&captured).len(),
        2,
        "transient class retries to the ceiling"
    );
    let rendered = format!("{err}");
    assert!(
        !rendered.contains(API_KEY) && !rendered.contains("mock provider error"),
        "fixed Fire Crow text only; provider wording and the key stay out of errors: {rendered}"
    );
}

#[tokio::test]
async fn timeout_is_never_retried() {
    let (base, captured) = spawn_resend_mock(vec![
        MockReply {
            status: 200,
            delay_ms: Some(1_500),
        },
        MockReply {
            status: 200,
            delay_ms: None,
        },
    ])
    .await;
    let service = mock_service(&base, 200).with_max_attempts(3);

    let err = service
        .send_artifact(RECIPIENT, &artifact("exec-3", 1))
        .await
        .expect_err("a stalled provider must time out");
    assert!(
        matches!(err, AppError::Delivery(DeliveryError::Timeout)),
        "{err:?}"
    );
    assert_eq!(
        sent(&captured).len(),
        1,
        "a timeout may mean acceptance; retrying could duplicate the email"
    );
}

#[tokio::test]
async fn malformed_recipient_never_reaches_the_provider() {
    let (base, captured) = spawn_resend_mock(vec![MockReply {
        status: 200,
        delay_ms: None,
    }])
    .await;
    let service = mock_service(&base, 2_000);

    let err = service
        .send_artifact(
            "victim@example.test\r\nBcc: attacker@evil.test",
            &artifact("exec-1", 1),
        )
        .await
        .expect_err("header-injection shaped recipient must be rejected");
    assert!(
        matches!(err, AppError::Delivery(DeliveryError::InvalidRecipient)),
        "{err:?}"
    );
    assert!(
        sent(&captured).is_empty(),
        "no request may be issued for a rejected recipient"
    );
}

#[tokio::test]
async fn mock_constructor_refuses_non_loopback_base_urls() {
    for url in [
        "https://api.resend.com",
        "http://evil.example",
        "ftp://127.0.0.1",
    ] {
        assert!(
            EmailService::resend_loopback(FROM, API_KEY, url, Duration::from_secs(1)).is_err(),
            "{url} must be refused: the test constructor cannot re-point production traffic"
        );
    }
}

#[tokio::test]
async fn transport_selection_follows_configuration() {
    use firecrow_backend::Settings;

    // Nothing configured: honestly absent, so the route answers 501.
    let mut settings: Settings = support::test_settings();
    settings.smtp_host = String::new();
    settings.sender_email = String::new();
    settings.resend_api_key = String::new();
    settings.resend_from_email = String::new();
    assert!(EmailService::from_settings(&settings).is_none());

    // Resend key + explicit sender: the Resend transport is selected.
    settings.resend_api_key = "re_key".into();
    settings.resend_from_email = FROM.into();
    assert!(EmailService::from_settings(&settings).is_some());

    // Resend key with no sender anywhere: still honestly absent (startup
    // validation rejects this combination; this is defense in depth).
    settings.resend_from_email = String::new();
    assert!(EmailService::from_settings(&settings).is_none());

    // SMTP-only configuration still selects a transport.
    settings.resend_api_key = String::new();
    settings.smtp_host = "smtp.example.test".into();
    settings.sender_email = "reports@example.test".into();
    assert!(EmailService::from_settings(&settings).is_some());
}
