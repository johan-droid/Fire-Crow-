//! F1 HTTP-level: rate-limit buckets must key on the *verified* client, not
//! on the proxy's own address and not on attacker-supplied headers.
//!
//! Uses a real axum server with `ConnectInfo` (exactly as `main.rs` builds
//! it) so the TCP peer is genuinely 127.0.0.1 — the trusted test proxy — with
//! reqwest as the client. The per-route credential limiter (5/minute,
//! negligible refill during a test) makes the bucket assertions deterministic.
//!
//! IMPORTANT: every app in this binary must use `bucket_state`'s fixture. The
//! trusted-proxy list is installed once per process (first `build_state`
//! wins), so mixing fixtures with different lists would make these tests
//! order-dependent.

mod support;

use firecrow_backend::app::{build_app, build_state};
use firecrow_backend::config::Settings;
use firecrow_backend::state::AppState;
use sqlx::PgPool;
use std::net::SocketAddr;
use std::sync::Arc;

async fn bucket_state(pool: PgPool) -> Arc<AppState> {
    let settings = Settings {
        rate_limit_enabled: true,
        trusted_proxy_cidrs: "127.0.0.1/32, ::1/128".into(),
        ..support::test_settings()
    };
    build_state(settings, pool, None)
        .await
        .expect("state must build")
}

async fn spawn(state: Arc<AppState>) -> SocketAddr {
    let app = build_app(state, false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("serve");
    });
    addr
}

async fn login(client: &reqwest::Client, addr: SocketAddr, xff: &str) -> u16 {
    client
        .post(format!("http://{addr}/api/v1/auth/login"))
        .header("x-forwarded-for", xff)
        .json(&serde_json::json!({"username": "nobody", "password": "wrong-password"}))
        .send()
        .await
        .expect("request must reach the server")
        .status()
        .as_u16()
}

#[sqlx::test(migrations = "./migrations")]
async fn security_f1_verified_clients_get_independent_rate_limit_buckets(pool: PgPool) {
    let state = bucket_state(pool).await;
    let addr = spawn(state).await;
    let client = reqwest::Client::new();

    // Client A drains its credential bucket (5/minute; refill is 5/12s, so no
    // meaningful recovery during the test).
    let mut a_limited = 0;
    for _ in 0..7 {
        if login(&client, addr, "198.51.100.1").await == 429 {
            a_limited += 1;
        }
    }
    assert!(
        a_limited >= 2,
        "client A must hit its own 5/minute limit, got {a_limited} rejections"
    );

    // Client B is a distinct verified identity behind the same proxy: it gets
    // its own bucket (not 429; the handler's own 4xx is fine).
    let b = login(&client, addr, "198.51.100.2").await;
    assert_ne!(
        b, 429,
        "client B must not share client A's rate-limit bucket"
    );

    // Client A is still limited: its bucket is persistent and per-client.
    let a_again = login(&client, addr, "198.51.100.1").await;
    assert_eq!(a_again, 429, "client A must remain limited");

    // A client-supplied spoofed prefix collapses into client A's verified
    // identity and cannot mint a fresh bucket.
    let spoofed = login(&client, addr, "6.6.6.6, 198.51.100.1").await;
    assert_eq!(
        spoofed, 429,
        "a spoofed XFF prefix must not mint a fresh bucket for client A"
    );
}

/// A broken proxy configuration must fail state construction rather than
/// silently running with "trust nobody" (which would collapse every proxied
/// client into one bucket in production).
#[sqlx::test(migrations = "./migrations")]
async fn security_f1_build_state_rejects_invalid_proxy_configuration(pool: PgPool) {
    let settings = Settings {
        trusted_proxy_cidrs: "garbage".into(),
        ..support::test_settings()
    };
    assert!(
        build_state(settings, pool, None).await.is_err(),
        "a malformed TRUSTED_PROXY_CIDRS must fail state construction"
    );
}
