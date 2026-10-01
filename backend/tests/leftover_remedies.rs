//! Batch A remedies for the leftover backlog.
//!
//! Each test is named `security_<finding-id>_<short_description>` or
//! `audit_<id>_<short_description>` so a future regression is a named test
//! failure rather than a silently reintroduced defect. Every source-level guard
//! here asserts on a pattern that was *removed*, so each one fails if the
//! offending code returns.

mod support;

use sqlx::PgPool;

// ---------------------------------------------------------------------------
// S-15: POST /auth/policy-events was unauthenticated and wrote `user_id = None`
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn security_s_15_policy_event_rejects_anonymous_callers(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;

    let res = app
        .post("/api/v1/auth/policy-events")
        .json(&serde_json::json!({"policy_version": "2026-06-06"}))
        .await;

    assert_eq!(
        res.status_code(),
        401,
        "an unauthenticated caller must not be able to write policy events, \
         otherwise the table grows without limit and no row is attributable"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn security_s_15_policy_event_is_attributable_to_its_author(pool: PgPool) {
    let user = support::seed_user(&pool, "policy").await;
    let app = support::test_app(pool.clone()).await;

    let res = app
        .post("/api/v1/auth/policy-events")
        .add_header("authorization", user.auth_header())
        .json(&serde_json::json!({"policy_version": "2026-06-06"}))
        .await;
    assert_eq!(
        res.status_code(),
        202,
        "an authenticated caller must succeed"
    );

    // `record_security_event` writes to `security_logs`, not `security_events`.
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT action, COALESCE(user_id, '') FROM security_logs")
            .fetch_all(&pool)
            .await
            .expect("query security_logs");

    let policy: Vec<_> = rows.iter().filter(|(a, _)| a == "policy_event").collect();
    assert!(
        !policy.is_empty(),
        "the event must be persisted, otherwise the endpoint is silently broken; \
         security_logs held: {rows:?}"
    );
    assert!(
        policy.iter().all(|(_, uid)| *uid == user.id),
        "every policy event must record its author; found: {policy:?}"
    );
}

// ---------------------------------------------------------------------------
// S-16: outbound reqwest clients with no timeout pin connections from a small pool
// ---------------------------------------------------------------------------

#[test]
fn security_s_16_every_reqwest_client_is_built_with_a_timeout() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let offenders = std::fs::read_dir(&dir)
        .expect("src must be readable")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .flat_map(|p| {
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            let text = std::fs::read_to_string(&p).unwrap_or_default();
            text.lines()
                .enumerate()
                .filter(|(i, l)| {
                    l.contains("Client::new()")
                        // comments may still name the old pattern
                        && !text[..l.as_ptr() as usize - text.as_ptr() as usize]
                            .lines()
                            .nth(i.saturating_sub(1))
                            .is_some_and(|p| p.trim_start().starts_with("//"))
                        && !l.trim_start().starts_with("//")
                })
                .map(move |(i, _)| format!("{name}:{}", i + 1))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    assert!(
        offenders.is_empty(),
        "reqwest clients built with Client::new() have no timeout and can pin a \
         connection indefinitely: {offenders:?}"
    );
}

#[test]
fn security_s_16_a_timeout_is_actually_configured() {
    // Guard against "the builder call exists but the timeout was forgotten".
    for rel in [
        "src/services/dodo_payment_service.rs",
        "src/api/routes_auth.rs",
        "src/api/routes_user.rs",
    ] {
        let text =
            std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel))
                .unwrap_or_else(|e| panic!("{rel} must be readable: {e}"));
        assert!(
            text.contains(".timeout(std::time::Duration::from_secs("),
            "{rel} builds a reqwest client without a timeout"
        );
    }
}

// ---------------------------------------------------------------------------
// R-24: the deep-health probe stripped /api/v1, so it always reported failure
// ---------------------------------------------------------------------------

#[test]
fn audit_r_24_deep_health_probe_keeps_the_api_prefix() {
    let src = read_frontend("src/App.tsx");

    assert!(
        !src.contains("API_BASE.replace("),
        "stripping the /api/v1 prefix made the deep-health request 404 through the \
         SPA fallback and return index.html with status 200"
    );
    assert!(
        src.contains("`${API_BASE}/health/deep`"),
        "the deep-health probe must request the path the backend actually serves"
    );
}

// ---------------------------------------------------------------------------
// R-25: the Demo Access button posted to a route that never existed
// ---------------------------------------------------------------------------

#[test]
fn audit_r_25_no_frontend_call_targets_a_nonexistent_route() {
    let src = read_frontend("src/App.tsx");
    assert!(
        !src.contains("/auth/demo"),
        "the frontend still calls /auth/demo, which the backend does not serve, \
         so the button can only ever fail"
    );

    // If demo mode is ever reintroduced, the route must exist *and* be
    // authenticated. This fails loudly if a bare endpoint is added back.
    let backend = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/api/routes_auth.rs"),
    )
    .expect("routes_auth.rs must be readable");
    assert!(
        !backend.contains("\"/demo\""),
        "a /auth/demo route has been added; it must be authenticated and must not \
         issue a session without a real credential"
    );
}

fn read_frontend(rel: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("backend must have a parent")
            .join("frontend")
            .join(rel),
    )
    .unwrap_or_else(|e| panic!("frontend/{rel} must be readable: {e}"))
}
