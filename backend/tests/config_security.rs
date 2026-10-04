//! Configuration and proxy-trust security regressions.
//!
//! Covers security_p0_3 (fail closed on secrets, decouple hardening from
//! `debug`) and security_s1 (stop trusting spoofable forwarding headers).
//!
//! NOTE: `std::env::set_var` mutates process-global state and `cargo test` runs
//! tests on parallel threads in one process, so every environment-touching test
//! holds `ENV_LOCK`. Without it the cases clobber each other's secrets and the
//! suite is order-dependent.

use firecrow_backend::config::Settings;
use firecrow_backend::middleware::cloudflare::{is_cloudflare_peer, resolve_client_ip};
use std::net::IpAddr;
use std::str::FromStr;

static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Every variable `Settings` reads that these tests care about.
const ENV_KEYS: &[&str] = &[
    "RUN_MODE",
    "DEBUG",
    "RATE_LIMIT_ENABLED",
    "SECRET_KEY",
    "ENCRYPTION_KEY",
    "DATABASE_URL",
    "FRONTEND_URL",
    "CORS_ORIGINS",
    "BACKEND_BASE_URL",
    "PORT",
    "HOST",
    "CSRF_ENABLED",
    "GITHUB_APP_ID",
    "GITHUB_APP_PRIVATE_KEY",
];

struct Env {
    _lock: std::sync::MutexGuard<'static, ()>,
    saved: Vec<(&'static str, Option<String>)>,
}

impl Env {
    /// Locks the environment and clears every relevant variable, so a test
    /// cannot inherit the developer's real configuration.
    fn clean() -> Self {
        let lock = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let saved = ENV_KEYS
            .iter()
            .map(|k| (*k, std::env::var(k).ok()))
            .collect();
        for k in ENV_KEYS {
            std::env::remove_var(k);
        }
        // Minimum viable non-secret config.
        std::env::set_var("DATABASE_URL", "postgresql://u:p@localhost/db");
        std::env::set_var("FRONTEND_URL", "https://example.com");
        std::env::set_var("CORS_ORIGINS", "https://example.com");
        Self { _lock: lock, saved }
    }

    fn set(&self, k: &str, v: &str) {
        std::env::set_var(k, v);
    }

    /// A key that passes every strength check, so a test can isolate the
    /// behaviour it is actually about.
    fn with_valid_keys(&self) {
        self.set("SECRET_KEY", &"K".repeat(48));
        self.set("ENCRYPTION_KEY", &"E".repeat(48));
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        for (k, v) in &self.saved {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }
}

fn ip(s: &str) -> IpAddr {
    IpAddr::from_str(s).expect("valid ip")
}

fn headers(pairs: &[(&str, &str)]) -> axum::http::HeaderMap {
    let mut m = axum::http::HeaderMap::new();
    for (k, v) in pairs {
        m.insert(
            axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
            v.parse().unwrap(),
        );
    }
    m
}

/// A 104.16.0.0/13 address, i.e. a genuine Cloudflare edge.
const CF_EDGE: &str = "104.16.0.1";
const ATTACKER: &str = "203.0.113.7";

// ---------------------------------------------------------------------------
// P0-3: secrets
// ---------------------------------------------------------------------------

#[test]
fn security_p0_3_missing_secret_key_fails_closed() {
    // Held for its Drop: clears the environment for the duration of the test.
    let _env = Env::clean();
    // No SECRET_KEY, no ENCRYPTION_KEY, no RUN_MODE, no DEBUG.
    let res = Settings::new();
    assert!(
        res.is_err(),
        "SECRET_KEY must be required even with no RUN_MODE/DEBUG set (security_p0_3)"
    );
    assert!(res
        .err()
        .unwrap()
        .to_string()
        .to_lowercase()
        .contains("secret_key"));
}

#[test]
fn security_p0_3_missing_encryption_key_fails_closed() {
    let env = Env::clean();
    env.set("SECRET_KEY", &"K".repeat(48));
    // ENCRYPTION_KEY deliberately unset.
    let res = Settings::new();
    assert!(res.is_err(), "ENCRYPTION_KEY must also be required");
    assert!(res
        .err()
        .unwrap()
        .to_string()
        .to_lowercase()
        .contains("encryption_key"));
}

#[test]
fn security_p0_3_dev_mode_never_substitutes_a_signing_key() {
    let env = Env::clean();
    // Explicitly development. A key must still be demanded.
    env.set("RUN_MODE", "development");
    assert!(
        Settings::new().is_err(),
        "RUN_MODE=development must not unlock a substituted signing key"
    );

    env.set("SECRET_KEY", &"K".repeat(48));
    assert!(
        Settings::new().is_err(),
        "development mode must not substitute ENCRYPTION_KEY either"
    );
}

#[test]
fn security_p0_3_committed_compose_key_is_rejected() {
    // Previously committed as the docker-compose default, so it is public.
    let burned = "a7f3b8c29e4d5f6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a";
    let env = Env::clean();
    env.set("SECRET_KEY", burned);
    env.set("ENCRYPTION_KEY", &"E".repeat(48));

    let err = Settings::new().expect_err("previously-committed key must be rejected");
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("compromised"),
        "error should say the key is compromised, got: {msg}"
    );
}

#[test]
fn security_p0_3_old_dev_fallback_key_is_rejected() {
    let env = Env::clean();
    env.set(
        "SECRET_KEY",
        "local_dev_secret_key_change_me_1234567890_DO_NOT_USE_IN_PRODUCTION",
    );
    env.set("ENCRYPTION_KEY", &"E".repeat(48));

    assert!(
        Settings::new().is_err(),
        "the former development fallback key must be rejected"
    );
}

#[test]
fn security_p0_3_keys_must_differ_and_be_long_enough() {
    let env = Env::clean();

    // Identical keys collapse the crypto boundary.
    env.set("SECRET_KEY", &"K".repeat(48));
    env.set("ENCRYPTION_KEY", &"K".repeat(48));
    assert!(Settings::new().is_err(), "identical keys must be rejected");

    // Too short.
    env.set("SECRET_KEY", &"K".repeat(16));
    env.set("ENCRYPTION_KEY", &"E".repeat(48));
    assert!(
        Settings::new().is_err(),
        "short SECRET_KEY must be rejected"
    );

    // A valid pair is accepted, and `debug` defaults to false in production.
    env.with_valid_keys();
    let s = Settings::new().expect("a valid key pair must be accepted");
    assert!(
        !s.debug,
        "debug must default to false when RUN_MODE is unset (security_p0_3)"
    );
}

#[test]
fn security_p0_3_rate_limiting_is_independent_of_debug() {
    let env = Env::clean();
    env.with_valid_keys();

    // On, with debug logging enabled.
    env.set("DEBUG", "true");
    let s = Settings::new().unwrap();
    assert!(s.debug);
    assert!(
        s.rate_limit_enabled,
        "debug=true must not disable rate limiting (security_p0_3)"
    );

    // On, with debug off.
    env.set("DEBUG", "false");
    assert!(Settings::new().unwrap().rate_limit_enabled);

    // Off only when explicitly disabled.
    env.set("RATE_LIMIT_ENABLED", "false");
    assert!(!Settings::new().unwrap().rate_limit_enabled);
}

// ---------------------------------------------------------------------------
// S-1: proxy header trust
// ---------------------------------------------------------------------------

#[test]
fn security_s1_forged_cf_header_from_untrusted_peer_is_ignored() {
    let h = headers(&[
        ("cf-connecting-ip", "9.9.9.9"),
        ("x-real-ip", "8.8.8.8"),
        ("x-forwarded-for", "7.7.7.7, 6.6.6.6"),
    ]);

    // A direct client that forges every forwarding header.
    let out = resolve_client_ip(&h, Some(ip(ATTACKER)));
    assert_eq!(
        out, ATTACKER,
        "forged forwarding headers from an untrusted peer must be ignored"
    );
}

#[test]
fn security_s1_forged_cf_header_with_no_peer_is_not_a_key() {
    let h = headers(&[("cf-connecting-ip", "9.9.9.9")]);

    // No peer => trust cannot be established. Must not return the header value.
    let out = resolve_client_ip(&h, None);
    assert_ne!(out, "9.9.9.9", "unverifiable peer must not key on a header");
    assert_eq!(out, "unresolved");
}

#[test]
fn security_s1_forged_headers_cannot_mint_distinct_rate_limit_buckets() {
    // The original exploit: vary CF-Connecting-IP per request to get a fresh
    // bucket. From an untrusted peer, all of these must collapse to one key.
    let mut keys = std::collections::HashSet::new();
    for spoofed in ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"] {
        let h = headers(&[("cf-connecting-ip", spoofed)]);
        keys.insert(resolve_client_ip(&h, Some(ip(ATTACKER))));
    }
    assert_eq!(
        keys.len(),
        1,
        "spoofed headers produced {keys:?} — rate limiting is bypassable"
    );
}

#[test]
fn security_s1_real_cloudflare_edge_headers_are_trusted() {
    assert!(is_cloudflare_peer(ip(CF_EDGE)));
    let h = headers(&[("cf-connecting-ip", "198.51.100.42")]);
    assert_eq!(
        resolve_client_ip(&h, Some(ip(CF_EDGE))),
        "198.51.100.42",
        "a real Cloudflare edge must still yield the true client IP"
    );
}

#[test]
fn security_s1_non_cloudflare_peer_never_gets_header_trust() {
    assert!(!is_cloudflare_peer(ip("8.8.8.8")));
    assert!(!is_cloudflare_peer(ip("127.0.0.1")));
    assert!(!is_cloudflare_peer(ip("10.0.0.1")));
    let h = headers(&[("cf-connecting-ip", "198.51.100.42")]);
    assert_eq!(resolve_client_ip(&h, Some(ip("8.8.8.8"))), "8.8.8.8");
}

#[test]
fn security_s1_real_peer_with_no_forwarding_headers_is_used_directly() {
    let out = resolve_client_ip(&headers(&[]), Some(ip(ATTACKER)));
    assert_eq!(out, ATTACKER);
}

// ---------------------------------------------------------------------------
// Phase 19B.1: GitHub App identity is all-or-nothing at startup
// ---------------------------------------------------------------------------

/// TEST-ONLY RSA key (generated with `openssl genrsa`); signs nothing real.
const TEST_APP_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDM5+/U2YwFZdjE
jBfKwA4PSdSp9oRe60vhNesRGE+nGMlO9dZHc7AITvvXIYu5qUHTQkbLJlH2BIe/
CfKSBoIFHBfn/TOcmNz3U2NFwALaPtA56NXxFxbbof8z3cda4udToY76I5B/k5bS
QSTsM0QPPNoSWz6L3hG/wVFGGLARI1fU91ZAOcBOvwerZ5Ygbk72i/WQHO2H15X0
9bVAmqSt/ATOfCg6S6A7pPieJ/lHzSlT0K8+rdVddB2ss4BT93Lt62JNk5eSYA46
nL8Mz/Qk6pwQCQB7CEVteHKCRx/mnqlj7n2ksZRODloPDYkyu+KUPqYf/fwan9OG
rRoY+ewjAgMBAAECggEATg07ahTEJXo6LARBO9YUhPZWr7dbjNyMNulW9VgRX1Et
vYofaXBD6aZMgBIjK0Gx9UsVtGSQa+ol2ztqzvzzogalhJUKh+gio4N8GSGe9Itg
ve5XMFLfPiJjF9qvCYvNGio8UEQj0rThio2OBvswPa2sU7m2BYk9sZFt6AmXZ68k
LJGYX24Ktquo8Wz33Q/Fx7WAt0NlOrwaNa6jUjue9MLl6peIFZXNSd0gPU62IqmL
o+IMtTbVHYe3b+I1GEKUrzXs1/j9OGB+veUlqLokQvJSQugYGmqlxNOJMAO2GAHb
Z2CfwuNBim55XcLwR+kvOuVQAV40RqrS4WttsyzRIQKBgQDvBxI+o+vROBw19rnn
JFYwgY2TJOCOA+OQ9L8ZytQDgXW159siGlnYdrtmEV20yo6+x9FYROz4M8bVEENC
P5wHHgtcf4MBhgzOy2OoDqXjBggwbG2BmgG20QQJ9M/74sBQ7eMW1mvfrfFfVnG4
Yvfgjebl7TNcnGIjApW4/LzqXQKBgQDbdJ6Hn4UqJgjraeGPNxVXcBQpRX9FKMuQ
pwd3UDaZdVsBcQ2ybzcINqytuHx1x7Jafmccp27NSOJFNeo5IcYPn7EjJ7azfF8n
AOyDBJC6Oyk/fW9+CGquxobjKcejtdnMaMuLMdXsmWLLwHsvP9CRjLc2oky3+Pqw
g3PN6D3IfwKBgQCH3bkdKgftELvYYLojDKCBSeKzdQ6/Kq67wqKtgoEozPmfwH7q
z5eqVzMGPXDKRykEgIgaaHNaUfP/QBM7IPULhqRmm4RX5V56XVn0OP9KIC+fdsJ4
HJZE2GI3VpSyVJ2EYvPmE1OV/UVqL7TMXlUPqxlIMKA1UB7oT5vTXrXzcQKBgQCf
n4qz0Ub16mZwfTpQhltilyZDAsbY0hyHIcbfdRvRsTe5q7avxA8+TS56yYbV0KQd
CHYNtId2j/3tI5MzbSp4MMqSbI+Kq/s2Doj5n3d5zhBpmt5eyNZ4O/TfBIOuw1Yh
RVRP8bbNeqAO3fl726nkRHr7JUAyTMpjW6n+6l8OFwKBgDPbwQtfMS23yQxtCTt5
UbasFdoYNeaI9tIYe7VEDvZXqpXiIqb7gqEfl2Fgy+a+MSSkLKhwNSSDNLg7COhb
F2bluSxO3pitCf0N0F4p6iiB6kTurzID41KVAwVGWZtsz/+9t7ze1ufiUREo4BpD
vTr3yQc1kmXLT8QMholpAl29
-----END PRIVATE KEY-----
";

#[test]
fn security_p19b1_app_identity_absent_means_disabled() {
    let env = Env::clean();
    env.with_valid_keys();
    let settings = Settings::new().expect("no App config must start fine");
    assert_eq!(settings.github_app_id, 0);
    assert!(settings.github_app_private_key.trim().is_empty());
    // And the Debug impl must not print what is not there to print —
    // nor anything else secret.
    let rendered = format!("{settings:?}");
    assert!(rendered.contains("github_app_id"));
    assert!(!rendered.contains("MIIEvg"));
}

#[test]
fn security_p19b1_app_identity_half_configured_fails_startup() {
    // ID without a key.
    {
        let env = Env::clean();
        env.with_valid_keys();
        env.set("GITHUB_APP_ID", "123456");
        let err = Settings::new().expect_err("an ID with no key must fail closed");
        assert!(err.to_string().contains("GITHUB_APP_ID"));
    }

    // Key without an ID.
    {
        let env = Env::clean();
        env.with_valid_keys();
        env.set("GITHUB_APP_PRIVATE_KEY", TEST_APP_KEY_PEM);
        let err = Settings::new().expect_err("a key with no ID must fail closed");
        assert!(err.to_string().contains("GITHUB_APP_ID"));
        assert!(
            !err.to_string().contains("MIIEvg"),
            "the key must not appear in the startup error"
        );
    }
}

#[test]
fn security_p19b1_app_identity_non_rsa_key_fails_startup() {
    let env = Env::clean();
    env.with_valid_keys();
    env.set("GITHUB_APP_ID", "123456");
    env.set("GITHUB_APP_PRIVATE_KEY", "definitely-not-a-pem-key");
    let err = Settings::new().expect_err("a non-PEM key must fail closed");
    assert!(err.to_string().contains("GITHUB_APP_PRIVATE_KEY"));
}

#[test]
fn security_p19b1_app_identity_complete_starts() {
    let env = Env::clean();
    env.with_valid_keys();
    env.set("GITHUB_APP_ID", "123456");
    env.set("GITHUB_APP_PRIVATE_KEY", TEST_APP_KEY_PEM);
    let settings = Settings::new().expect("a complete identity must start");
    assert_eq!(settings.github_app_id, 123456);
    let rendered = format!("{settings:?}");
    assert!(rendered.contains("123456"), "the public ID stays visible");
    assert!(!rendered.contains("MIIEvg"), "the key stays hidden");
}
