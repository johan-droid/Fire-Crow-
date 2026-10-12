//! V1/V2 regression tests (database): token purpose at the HTTP boundary,
//! refresh rotation single-use, logout kills the session, sessions are
//! isolated, concurrent refresh has one winner.
//!
//! Requires a test database (`./backend/scripts/test.sh`, or
//! `TEST_DATABASE_URL`); each test gets a migrated throwaway database via
//! `#[sqlx::test]`. Every test stays under the unconditional per-route
//! `/auth` governor (5/minute burst) by using fresh app instances per phase
//! where needed.

mod support;

use axum_test::TestServer;
use sqlx::PgPool;

/// Tokens minted by the login response, both read from the `Set-Cookie` jar:
/// the access token is deliberately NOT in the JSON body (HttpOnly-cookie-only
/// hardening), so the helper parses the `fc_access_token` cookie exactly as a
/// browser jar would. Refresh comes from `{cookie}_refresh`, with the legacy
/// `refresh_token` name as fallback — mirroring the server's read order.
struct Session {
    access: String,
    refresh: String,
}

fn access_from_set_cookies(res: &axum_test::TestResponse) -> String {
    for value in res.headers().get_all("set-cookie").iter() {
        let pair = value.to_str().unwrap_or("").split(';').next().unwrap_or("");
        let (name, val) = pair.split_once('=').unwrap_or(("", ""));
        if name == "fc_access_token" && !val.is_empty() {
            return val.to_string();
        }
    }
    panic!("login must set an fc_access_token cookie")
}

fn refresh_from_set_cookies(res: &axum_test::TestResponse) -> String {
    let mut legacy: Option<String> = None;
    for value in res.headers().get_all("set-cookie").iter() {
        let pair = value.to_str().unwrap_or("").split(';').next().unwrap_or("");
        let (name, val) = pair.split_once('=').unwrap_or(("", ""));
        if name == "fc_access_token_refresh" && !val.is_empty() {
            return val.to_string();
        }
        if name == "refresh_token" && !val.is_empty() {
            legacy = Some(val.to_string());
        }
    }
    legacy.expect("login must set a refresh cookie")
}

async fn login(app: &TestServer, pool: &PgPool) -> (support::SeededUser, Session) {
    let user = support::seed_user(pool, "sess").await;
    let res = app
        .post("/api/v1/auth/login")
        .json(&serde_json::json!({"username": user.username, "password": user.password}))
        .await;
    assert_eq!(res.status_code(), 200, "login must succeed: {}", res.text());
    let access = access_from_set_cookies(&res);
    let refresh = refresh_from_set_cookies(&res);
    (user, Session { access, refresh })
}

async fn me(app: &TestServer, bearer: &str) -> u16 {
    app.get("/api/v1/auth/me")
        .add_header("authorization", format!("Bearer {bearer}"))
        .await
        .status_code()
        .as_u16()
}

async fn refresh_with(app: &TestServer, refresh_token: &str) -> axum_test::TestResponse {
    app.post("/api/v1/auth/refresh")
        .json(&serde_json::json!({"refresh_token": refresh_token}))
        .await
}

/// V1: a refresh token presented as a bearer credential is rejected, while
/// the session's access token keeps working.
#[sqlx::test(migrations = "./migrations")]
async fn v1_refresh_token_as_bearer_is_rejected(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let (_user, session) = login(&app, &pool).await;

    assert_eq!(
        me(&app, &session.access).await,
        200,
        "control: access works"
    );
    assert_eq!(
        me(&app, &session.refresh).await,
        401,
        "V1: refresh-as-bearer must be 401"
    );
}

/// V1: an access token presented to the refresh endpoint is rejected.
#[sqlx::test(migrations = "./migrations")]
async fn v1_access_token_as_refresh_is_rejected(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let (_user, session) = login(&app, &pool).await;

    let res = refresh_with(&app, &session.access).await;
    assert_eq!(
        res.status_code(),
        401,
        "V1: access-as-refresh must be 401, body: {}",
        res.text()
    );
}

/// V1: the SSE extractor enforces the same purpose rule. Rejection happens
/// in the auth extractor before any stream starts, so this returns
/// immediately; the timeout only guards against a regression that would
/// otherwise hang on an infinite stream.
#[sqlx::test(migrations = "./migrations")]
async fn v1_sse_rejects_refresh_token(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let (_user, session) = login(&app, &pool).await;

    let res = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        app.get("/api/v1/sse/dashboard")
            .add_header("authorization", format!("Bearer {}", session.refresh))
            .await
    })
    .await
    .expect("SSE must reject before streaming; timed out");
    assert_eq!(
        res.status_code(),
        401,
        "V1: SSE with a refresh token must be 401, body: {}",
        res.text()
    );
}

/// V2: rotation mints a working successor and the consumed refresh token is
/// dead on replay.
#[sqlx::test(migrations = "./migrations")]
async fn v2_refresh_rotation_is_single_use(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let (_user, session) = login(&app, &pool).await;

    let res = refresh_with(&app, &session.refresh).await;
    assert_eq!(
        res.status_code(),
        200,
        "first refresh works: {}",
        res.text()
    );
    let new_access = access_from_set_cookies(&res);
    assert_eq!(me(&app, &new_access).await, 200, "rotated access works");

    let replay = refresh_with(&app, &session.refresh).await;
    assert_eq!(
        replay.status_code(),
        401,
        "V2: replaying a rotated refresh token must be 401, body: {}",
        replay.text()
    );
    // The successor session survives the replay: a lost consume race costs
    // only the loser, never the live session.
    assert_eq!(
        me(&app, &new_access).await,
        200,
        "successor session survives"
    );
}

/// V2: logout revokes the whole session — the refresh token cannot mint
/// successors, and the access token is dead immediately under the
/// family-revocation policy (not merely left to expire).
#[sqlx::test(migrations = "./migrations")]
async fn v2_logout_kills_the_session(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let (_user, session) = login(&app, &pool).await;

    let res = app
        .post("/api/v1/auth/logout")
        .add_header("authorization", format!("Bearer {}", session.access))
        .await;
    assert_eq!(res.status_code(), 200, "logout works: {}", res.text());

    let app2 = support::test_app(pool.clone()).await;
    let res = refresh_with(&app2, &session.refresh).await;
    assert_eq!(
        res.status_code(),
        401,
        "V2: refresh after logout must be 401, body: {}",
        res.text()
    );
    assert_eq!(
        me(&app2, &session.access).await,
        401,
        "V2: access after logout must be 401 under family revocation"
    );
}

/// V2: logging out one session leaves a sibling session untouched.
#[sqlx::test(migrations = "./migrations")]
async fn v2_sessions_are_isolated(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "iso").await;
    let payload = serde_json::json!({"username": user.username, "password": user.password});

    let res_a = app.post("/api/v1/auth/login").json(&payload).await;
    assert_eq!(res_a.status_code(), 200);
    let access_a = access_from_set_cookies(&res_a);

    let app2 = support::test_app(pool.clone()).await;
    let res_b = app2.post("/api/v1/auth/login").json(&payload).await;
    assert_eq!(res_b.status_code(), 200);
    let access_b = access_from_set_cookies(&res_b);
    let refresh_b = refresh_from_set_cookies(&res_b);

    let out = app
        .post("/api/v1/auth/logout")
        .add_header("authorization", format!("Bearer {access_a}"))
        .await;
    assert_eq!(out.status_code(), 200);

    let app3 = support::test_app(pool.clone()).await;
    assert_eq!(me(&app3, &access_b).await, 200, "sibling session survives");
    let res = refresh_with(&app3, &refresh_b).await;
    assert_eq!(
        res.status_code(),
        200,
        "sibling session still refreshes: {}",
        res.text()
    );
}

/// V2: two concurrent presentations of one refresh token produce exactly one
/// successor. Separate app instances share the database, so the atomic
/// consume (unique `jti`) is what decides the winner, not request ordering.
#[sqlx::test(migrations = "./migrations")]
async fn v2_concurrent_refresh_has_one_winner(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let (_user, session) = login(&app, &pool).await;

    let app_a = support::test_app(pool.clone()).await;
    let app_b = support::test_app(pool.clone()).await;
    let token = session.refresh.clone();
    let (res_a, res_b) = tokio::join!(refresh_with(&app_a, &token), refresh_with(&app_b, &token),);
    let codes = [res_a.status_code().as_u16(), res_b.status_code().as_u16()];
    assert_eq!(
        codes.iter().filter(|c| **c == 200).count(),
        1,
        "exactly one concurrent refresh must succeed, got {codes:?}"
    );
    assert!(
        codes.contains(&401),
        "the loser must be rejected, got {codes:?}"
    );

    let winner = if codes[0] == 200 { res_a } else { res_b };
    let winner_access = access_from_set_cookies(&winner);
    let app_c = support::test_app(pool.clone()).await;
    assert_eq!(
        me(&app_c, &winner_access).await,
        200,
        "the single winner holds a working session"
    );
}

/// The refresh cookie is read under its derived `{cookie}_refresh` name, with
/// the legacy literal name as fallback.
#[sqlx::test(migrations = "./migrations")]
async fn v2_refresh_cookie_names_are_accepted(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let (_user, session) = login(&app, &pool).await;

    let app2 = support::test_app(pool.clone()).await;
    let res = app2
        .post("/api/v1/auth/refresh")
        .add_header(
            "cookie",
            format!("fc_access_token_refresh={}", session.refresh),
        )
        .json(&serde_json::json!({}))
        .await;
    assert_eq!(
        res.status_code(),
        200,
        "derived refresh-cookie name must work: {}",
        res.text()
    );

    let app3 = support::test_app(pool.clone()).await;
    let new_refresh = refresh_from_set_cookies(&res);
    let res = app3
        .post("/api/v1/auth/refresh")
        .add_header("cookie", format!("refresh_token={new_refresh}"))
        .json(&serde_json::json!({}))
        .await;
    assert_eq!(
        res.status_code(),
        200,
        "legacy refresh-cookie name must keep working: {}",
        res.text()
    );
}
