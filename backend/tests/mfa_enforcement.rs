//! P0-A (ZT-01-1 / ZT-01-5 / ZT-01-8 / ZT-01-23) regression suite.
//!
//! Password-only login must never produce a fully authenticated session for
//! an MFA-enabled account; the MFA challenge must be purpose-bound,
//! short-lived, single-use; authentication JSON bodies must never carry
//! access/refresh tokens; and revocation must be authoritative through the
//! database when Redis is absent.
//!
//! Requires a test database (`#[sqlx::test]` throwaway DBs).

mod support;

use axum_test::TestServer;
use chrono::Utc;
use sqlx::PgPool;

fn access_cookie_set(res: &axum_test::TestResponse) -> bool {
    res.headers().get_all("set-cookie").iter().any(|value| {
        let pair = value.to_str().unwrap_or("").split(';').next().unwrap_or("");
        let (name, val) = pair.split_once('=').unwrap_or(("", ""));
        name == "fc_access_token" && !val.is_empty()
    })
}

/// The session cookie from a response, replayed exactly as a browser jar
/// would (axum_test's `save_cookies` defaults to off).
fn access_cookie_of(res: &axum_test::TestResponse) -> String {
    for value in res.headers().get_all("set-cookie").iter() {
        let pair = value.to_str().unwrap_or("").split(';').next().unwrap_or("");
        if let Some((name, val)) = pair.split_once('=') {
            if name == "fc_access_token" && !val.is_empty() {
                return val.to_string();
            }
        }
    }
    panic!("response must set an fc_access_token cookie");
}

fn challenge_for(res: &axum_test::TestResponse) -> String {
    let body: serde_json::Value = res.json();
    assert_eq!(
        body["status"].as_str(),
        Some("mfa_required"),
        "MFA-enabled login must return an mfa_required challenge: {}",
        res.text()
    );
    // P0-A (ZT-01-5): the challenge response must never carry session tokens.
    assert!(
        body.get("access_token").is_none() && body.get("refresh_token").is_none(),
        "challenge response must not contain tokens: {}",
        res.text()
    );
    body["mfa_token"]
        .as_str()
        .expect("challenge must carry an mfa_token")
        .to_string()
}

async fn login_challenge(app: &TestServer, user: &support::SeededUser) -> String {
    let res = app
        .post("/api/v1/auth/login")
        .json(&serde_json::json!({"username": user.username, "password": user.password}))
        .await;
    assert_eq!(
        res.status_code(),
        200,
        "password step must pass: {}",
        res.text()
    );
    assert!(
        !access_cookie_set(&res),
        "no session cookie may be set before the second factor"
    );
    challenge_for(&res)
}

fn current_totp(secret: &str) -> String {
    let totp = otpauth::TOTP::new(secret.to_string());
    totp.generate(1, Utc::now().timestamp() as u64).to_string()
}

/// Enable MFA for a seeded user with a known TOTP secret, mirroring the
/// activation flow's storage (encrypted secret + configuration row).
async fn enable_mfa(pool: &PgPool, user: &support::SeededUser, secret: &str) {
    let crypto =
        firecrow_backend::services::crypto::CryptoManager::new(support::TEST_ENCRYPTION_KEY)
            .expect("crypto");
    let encrypted = crypto.encrypt_secret(secret).expect("encrypt secret");
    sqlx::query("UPDATE users SET mfa_enabled = true, mfa_secret = $1 WHERE id = $2")
        .bind(&encrypted)
        .bind(&user.id)
        .execute(pool)
        .await
        .expect("enable mfa");
    sqlx::query(
        "INSERT INTO mfa_configurations (id, user_id, enabled, secret, backup_codes_consumed, created_at)
         VALUES ($1, $2, true, $3, 0, NOW())
         ON CONFLICT (user_id) DO UPDATE SET enabled = true, secret = EXCLUDED.secret",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&user.id)
    .bind(&encrypted)
    .execute(pool)
    .await
    .expect("insert mfa configuration");
}

// ---------------------------------------------------------------------------
// ZT-01-1: MFA enforcement at login
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn password_only_login_cannot_open_a_session_for_mfa_user(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "mfa-lock").await;
    enable_mfa(&pool, &user, "JBSWY3DPEHPK3PXP").await;

    let challenge = login_challenge(&app, &user).await;
    assert!(!challenge.is_empty());

    // The challenge is not a credential: /auth/me without any cookie fails.
    let me = app.get("/api/v1/auth/me").await;
    assert_eq!(
        me.status_code(),
        401,
        "challenge alone must not authenticate"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn valid_totp_redeems_challenge_into_full_session(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "mfa-ok").await;
    let secret = "JBSWY3DPEHPK3PXP";
    enable_mfa(&pool, &user, secret).await;

    let challenge = login_challenge(&app, &user).await;
    let code = current_totp(secret);

    let res = app
        .post("/api/v1/auth/login/mfa")
        .json(&serde_json::json!({"mfa_token": challenge, "code": code}))
        .await;
    assert_eq!(
        res.status_code(),
        200,
        "valid TOTP must redeem: {}",
        res.text()
    );
    assert!(
        access_cookie_set(&res),
        "redemption must set the session cookie"
    );
    let body: serde_json::Value = res.json();
    assert!(
        body.get("access_token").is_none() && body.get("refresh_token").is_none(),
        "session response must not contain tokens: {}",
        res.text()
    );

    let access = access_cookie_of(&res);
    let me = app
        .get("/api/v1/auth/me")
        .add_header("cookie", format!("fc_access_token={access}"))
        .await;
    assert_eq!(me.status_code(), 200, "redeemed session must authenticate");
}

#[sqlx::test(migrations = "./migrations")]
async fn challenge_is_single_use(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "mfa-replay").await;
    let secret = "JBSWY3DPEHPK3PXP";
    enable_mfa(&pool, &user, secret).await;

    let challenge = login_challenge(&app, &user).await;
    let code = current_totp(secret);

    let first = app
        .post("/api/v1/auth/login/mfa")
        .json(&serde_json::json!({"mfa_token": challenge, "code": code}))
        .await;
    assert_eq!(first.status_code(), 200, "{}", first.text());

    // Replay of the redeemed challenge must fail even with a valid code.
    let replay = app
        .post("/api/v1/auth/login/mfa")
        .json(&serde_json::json!({"mfa_token": challenge, "code": current_totp(secret)}))
        .await;
    assert_eq!(
        replay.status_code(),
        401,
        "redeemed challenge must be single-use: {}",
        replay.text()
    );
    assert!(!access_cookie_set(&replay));
}

#[sqlx::test(migrations = "./migrations")]
async fn access_and_refresh_tokens_are_not_mfa_challenges(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "mfa-purpose").await;
    enable_mfa(&pool, &user, "JBSWY3DPEHPK3PXP").await;

    // A real access token must be rejected at the MFA endpoint (purpose gate).
    let access = user.token();
    let res = app
        .post("/api/v1/auth/login/mfa")
        .json(&serde_json::json!({"mfa_token": access, "code": "123456"}))
        .await;
    assert_eq!(
        res.status_code(),
        401,
        "access token must not redeem: {}",
        res.text()
    );

    // A real refresh token must be rejected too.
    let (refresh, _) = firecrow_backend::services::auth::create_refresh_token(
        &user.id,
        &user.username,
        support::TEST_SECRET_KEY,
        &user.tenant_id,
        &uuid::Uuid::new_v4().to_string(),
    )
    .expect("mint refresh");
    let res = app
        .post("/api/v1/auth/login/mfa")
        .json(&serde_json::json!({"mfa_token": refresh, "code": "123456"}))
        .await;
    assert_eq!(
        res.status_code(),
        401,
        "refresh token must not redeem: {}",
        res.text()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn wrong_code_is_rejected_without_a_session(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "mfa-wrong").await;
    let secret = "JBSWY3DPEHPK3PXP";
    enable_mfa(&pool, &user, secret).await;

    let challenge = login_challenge(&app, &user).await;
    let res = app
        .post("/api/v1/auth/login/mfa")
        .json(&serde_json::json!({"mfa_token": challenge, "code": "000000"}))
        .await;
    assert_eq!(res.status_code(), 401, "{}", res.text());
    assert!(!access_cookie_set(&res));
}

/// The MFA guess lockout (limit 5, key `mfa_login:{user_id}` in `login_mfa`)
/// is checked at the handler entry BEFORE any factor is verified — so even a
/// *correct* TOTP is rejected while the account is locked.
///
/// Failures are seeded through the same `record_login_failure` service the
/// handler calls: the credential-route governor allows 5 requests/minute on
/// one shared in-process key, so a six-attempt end-to-end loop cannot fit in
/// a single test. What this proves is the threshold (five, not four) and the
/// check-before-verify ordering over real HTTP.
#[sqlx::test(migrations = "./migrations")]
async fn mfa_lockout_short_circuits_redemption_before_factor_check(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "mfa-brute").await;
    let secret = "JBSWY3DPEHPK3PXP";
    enable_mfa(&pool, &user, secret).await;

    let key = format!("mfa_login:{}", user.id);
    for _ in 0..4 {
        firecrow_backend::services::auth::record_login_failure(&pool, &key)
            .await
            .expect("record failure");
    }
    assert!(
        !firecrow_backend::services::auth::check_login_lockout(&pool, &key, 10, 5)
            .await
            .unwrap(),
        "four failures must not lock"
    );
    firecrow_backend::services::auth::record_login_failure(&pool, &key)
        .await
        .expect("record fifth failure");
    assert!(
        firecrow_backend::services::auth::check_login_lockout(&pool, &key, 10, 5)
            .await
            .unwrap(),
        "five failures must lock"
    );

    // A fresh challenge with a VALID code is still rejected — the lockout
    // short-circuits before TOTP verification.
    let challenge = login_challenge(&app, &user).await;
    let res = app
        .post("/api/v1/auth/login/mfa")
        .json(&serde_json::json!({"mfa_token": challenge, "code": current_totp(secret)}))
        .await;
    assert_eq!(
        res.status_code(),
        429,
        "locked account must be rate-limited: {}",
        res.text()
    );
    assert!(!access_cookie_set(&res));
}

#[sqlx::test(migrations = "./migrations")]
async fn recovery_code_redeems_challenge_and_is_consumed(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "mfa-rec").await;
    enable_mfa(&pool, &user, "JBSWY3DPEHPK3PXP").await;

    let config: (String,) = sqlx::query_as("SELECT id FROM mfa_configurations WHERE user_id = $1")
        .bind(&user.id)
        .fetch_one(&pool)
        .await
        .expect("config row");
    let code = "ABCDEFGH";
    sqlx::query(
        "INSERT INTO mfa_recovery_codes (id, mfa_config_id, code_hash) VALUES ($1, $2, $3)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&config.0)
    .bind(firecrow_backend::services::mfa_service::MfaService::hash_recovery_code(code))
    .execute(&pool)
    .await
    .expect("seed recovery code");

    let challenge = login_challenge(&app, &user).await;
    let res = app
        .post("/api/v1/auth/login/mfa")
        .json(&serde_json::json!({"mfa_token": challenge, "code": code}))
        .await;
    assert_eq!(
        res.status_code(),
        200,
        "recovery code must redeem: {}",
        res.text()
    );
    assert!(access_cookie_set(&res));

    // Consumed: the same code must not work again on a fresh challenge.
    let challenge2 = login_challenge(&app, &user).await;
    let res2 = app
        .post("/api/v1/auth/login/mfa")
        .json(&serde_json::json!({"mfa_token": challenge2, "code": code}))
        .await;
    assert_eq!(
        res2.status_code(),
        401,
        "recovery code must be single-use: {}",
        res2.text()
    );
}

// ---------------------------------------------------------------------------
// MFA-disabled accounts keep the explicit existing policy
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn mfa_disabled_account_logs_in_with_password_only(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "mfa-off").await;

    let res = app
        .post("/api/v1/auth/login")
        .json(&serde_json::json!({"username": user.username, "password": user.password}))
        .await;
    assert_eq!(res.status_code(), 200, "{}", res.text());
    assert!(
        access_cookie_set(&res),
        "MFA-less account gets a session directly"
    );
    let body: serde_json::Value = res.json();
    assert!(
        body.get("access_token").is_none() && body.get("refresh_token").is_none(),
        "login response must not contain tokens: {}",
        res.text()
    );
    assert_eq!(
        body["status"].as_str(),
        None,
        "no challenge for MFA-less account"
    );

    let access = access_cookie_of(&res);
    let me = app
        .get("/api/v1/auth/me")
        .add_header("cookie", format!("fc_access_token={access}"))
        .await;
    assert_eq!(me.status_code(), 200);
}

// ---------------------------------------------------------------------------
// ZT-01-8 (P1-H): revocation is authoritative without Redis
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn db_revocation_is_authoritative_for_access_tokens(pool: PgPool) {
    let user = support::seed_user(&pool, "rev").await;
    let (token, jti) = firecrow_backend::services::auth::create_access_token(
        &user.id,
        &user.username,
        support::TEST_SECRET_KEY,
        &user.tenant_id,
        "family-rev-1",
        60,
    )
    .expect("mint");
    // Sanity: unrevoked validates.
    assert!(
        firecrow_backend::services::auth::validate_token_with_anti_replay(
            &token,
            support::TEST_SECRET_KEY,
            None,
            &pool,
        )
        .await
        .is_ok()
    );

    // Revoke in the database only (no Redis in this test), then re-validate.
    firecrow_backend::services::auth::revoke_token_in_db(&pool, &jti, "family-rev-1", 3600)
        .await
        .expect("revoke");
    let err = firecrow_backend::services::auth::validate_token_with_anti_replay(
        &token,
        support::TEST_SECRET_KEY,
        None,
        &pool,
    )
    .await
    .expect_err("revoked token must fail");
    assert_eq!(err.status_code(), 401);
}

// ---------------------------------------------------------------------------
// ZT-01-23: Turnstile fail-closed semantics (no network involved)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn turnstile_enabled_without_secret_fails_closed() {
    let svc = firecrow_backend::services::turnstile::TurnstileService::new(String::new(), true);
    let err = svc
        .verify_token("dummy-token", None)
        .await
        .expect_err("enabled + unconfigured must fail closed");
    assert_eq!(err.status_code(), 500);
}

#[tokio::test]
async fn turnstile_disabled_is_an_explicit_noop() {
    let svc = firecrow_backend::services::turnstile::TurnstileService::new(String::new(), false);
    let res = svc.verify_token("dummy-token", None).await.expect("noop");
    assert!(res.success);
}

// ---------------------------------------------------------------------------
// P1-C: durable security events on auth flows
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn auth_flows_write_security_events(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "secev").await;

    // Failed login → login_failed attributed to the user.
    let bad = app
        .post("/api/v1/auth/login")
        .json(&serde_json::json!({"username": user.username, "password": "wrong-password-x"}))
        .await;
    assert_eq!(bad.status_code(), 401);

    // Successful login → login_success.
    let ok = app
        .post("/api/v1/auth/login")
        .json(&serde_json::json!({"username": user.username, "password": user.password}))
        .await;
    assert_eq!(ok.status_code(), 200, "{}", ok.text());

    // Logout → logout (authenticated by the session cookie from the login).
    let access = access_cookie_of(&ok);
    let out = app
        .post("/api/v1/auth/logout")
        .add_header("cookie", format!("fc_access_token={access}"))
        .await;
    assert_eq!(out.status_code(), 200, "{}", out.text());

    let actions: Vec<(String,)> =
        sqlx::query_as("SELECT action FROM security_logs WHERE user_id = $1 ORDER BY created_at")
            .bind(&user.id)
            .fetch_all(&pool)
            .await
            .expect("read security_logs");
    let actions: Vec<String> = actions.into_iter().map(|(a,)| a).collect();
    assert!(actions.contains(&"login_failed".to_string()), "{actions:?}");
    assert!(
        actions.contains(&"login_success".to_string()),
        "{actions:?}"
    );
    assert!(actions.contains(&"logout".to_string()), "{actions:?}");
}

// ---------------------------------------------------------------------------
// Stage-5 reviewer follow-ups (FC-ZT-SEC-001)
// ---------------------------------------------------------------------------

/// Finding 9a (P1-A): the OAuth redirect base comes from operator config or
/// Render's env only — `X-Forwarded-Host`/`X-Forwarded-Proto` are
/// attacker-controlled and must not influence it.
#[sqlx::test(migrations = "./migrations")]
async fn resolve_backend_base_url_ignores_forwarded_headers(pool: PgPool) {
    let mut settings = support::test_settings();
    settings.backend_base_url = "https://api.configured.test".into();
    let state = firecrow_backend::app::build_state(settings, pool, None)
        .await
        .expect("state builds");

    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-forwarded-host", "evil.example".parse().unwrap());
    headers.insert("x-forwarded-proto", "http".parse().unwrap());
    let url = firecrow_backend::api::routes_auth::resolve_backend_base_url(&state, &headers);
    assert_eq!(
        url, "https://api.configured.test",
        "forwarded headers must be ignored: {url}"
    );
}

/// Finding 9d (P0-A): with Turnstile enabled, login AND register fail closed
/// with 403 when no token is presented — rejected before any credential check
/// (and without any network round-trip).
#[sqlx::test(migrations = "./migrations")]
async fn turnstile_enabled_rejects_login_and_register_without_token(pool: PgPool) {
    let mut settings = support::test_settings();
    settings.cf_turnstile_enabled = true;
    settings.cf_turnstile_secret_key = String::new(); // fail-closed config
    let state = firecrow_backend::app::build_state(settings, pool, None)
        .await
        .expect("state builds");
    let app = TestServer::new(firecrow_backend::app::build_app(state, false)).expect("server");

    let login = app
        .post("/api/v1/auth/login")
        .json(&serde_json::json!({"username": "anyone", "password": "pw"}))
        .await;
    assert_eq!(
        login.status_code(),
        403,
        "missing Turnstile token must fail closed: {}",
        login.text()
    );
    assert!(!access_cookie_set(&login));

    let register = app
        .post("/api/v1/auth/register")
        .json(&serde_json::json!({"username": "anyone", "email": "a@b.c", "password": "pw"}))
        .await;
    assert_eq!(
        register.status_code(),
        403,
        "register must fail closed too: {}",
        register.text()
    );
    assert!(!access_cookie_set(&register));
}

/// Finding 9e (P0-A): `login_mfa` re-fetches the user and fails closed when
/// the account changed between challenge mint and redemption — deactivated
/// accounts and MFA-disabled accounts never reach session issuance, even with
/// a valid TOTP.
#[sqlx::test(migrations = "./migrations")]
async fn redemption_fails_closed_when_account_state_changes(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let secret = "JBSWY3DPEHPK3PXP";

    // (a) deactivated after the challenge was minted
    let user = support::seed_user(&pool, "mfa-deact").await;
    enable_mfa(&pool, &user, secret).await;
    let challenge = login_challenge(&app, &user).await;
    sqlx::query("UPDATE users SET is_active = false WHERE id = $1")
        .bind(&user.id)
        .execute(&pool)
        .await
        .expect("deactivate");
    let res = app
        .post("/api/v1/auth/login/mfa")
        .json(&serde_json::json!({"mfa_token": challenge, "code": current_totp(secret)}))
        .await;
    assert_eq!(
        res.status_code(),
        403,
        "deactivated account must fail closed: {}",
        res.text()
    );
    assert!(!access_cookie_set(&res));

    // (b) MFA disabled between mint and redemption — never downgrade to a
    // password-only session.
    let user2 = support::seed_user(&pool, "mfa-off-after").await;
    enable_mfa(&pool, &user2, secret).await;
    let challenge2 = login_challenge(&app, &user2).await;
    sqlx::query("UPDATE users SET mfa_enabled = false WHERE id = $1")
        .bind(&user2.id)
        .execute(&pool)
        .await
        .expect("disable mfa");
    let res2 = app
        .post("/api/v1/auth/login/mfa")
        .json(&serde_json::json!({"mfa_token": challenge2, "code": current_totp(secret)}))
        .await;
    assert_eq!(
        res2.status_code(),
        403,
        "MFA-disabled account must fail closed: {}",
        res2.text()
    );
    assert!(!access_cookie_set(&res2));
}

/// Stage-5 finding 2 (OAuth MFA bypass): the exchange endpoint issues an MFA
/// challenge — never a session — for an MFA-enabled account, so GitHub login
/// cannot become a second-factor bypass. Non-MFA accounts still get their
/// session here (the gate must not break normal OAuth completion).
#[sqlx::test(migrations = "./migrations")]
async fn exchange_issues_challenge_for_mfa_enabled_user(pool: PgPool) {
    let state = firecrow_backend::app::build_state(support::test_settings(), pool.clone(), None)
        .await
        .expect("state builds");
    let app =
        TestServer::new(firecrow_backend::app::build_app(state.clone(), false)).expect("server");

    let secret = "JBSWY3DPEHPK3PXP";
    let user = support::seed_user(&pool, "mfa-exchange").await;
    enable_mfa(&pool, &user, secret).await;
    let code = uuid::Uuid::new_v4().to_string();
    firecrow_backend::services::auth::create_exchange_code(
        &pool,
        &code,
        &user.id,
        &user.username,
        "test-exchange-no-token",
        120,
        state.crypto(),
    )
    .await
    .expect("exchange code minted");

    let res = app
        .post("/api/v1/auth/exchange")
        .json(&serde_json::json!({"code": code}))
        .await;
    assert_eq!(res.status_code(), 200, "{}", res.text());
    let body: serde_json::Value = res.json();
    assert_eq!(
        body["status"].as_str(),
        Some("mfa_required"),
        "exchange must challenge MFA-enabled users: {body}"
    );
    assert!(
        body["mfa_token"].as_str().is_some(),
        "challenge present: {body}"
    );
    assert!(
        !access_cookie_set(&res),
        "no session cookie before the second factor"
    );

    // Control: a non-MFA account still completes the exchange into a session.
    let user2 = support::seed_user(&pool, "oauth-plain").await;
    let code2 = uuid::Uuid::new_v4().to_string();
    firecrow_backend::services::auth::create_exchange_code(
        &pool,
        &code2,
        &user2.id,
        &user2.username,
        "test-exchange-no-token",
        120,
        state.crypto(),
    )
    .await
    .expect("exchange code minted");
    let res2 = app
        .post("/api/v1/auth/exchange")
        .json(&serde_json::json!({"code": code2}))
        .await;
    assert_eq!(res2.status_code(), 200, "{}", res2.text());
    assert!(
        access_cookie_set(&res2),
        "non-MFA exchange keeps its session"
    );
    let body2: serde_json::Value = res2.json();
    assert_eq!(body2["user_id"].as_str(), Some(user2.id.as_str()));
}

/// FC-RELEASE-017 (review finding 6): concurrent redemptions of DIFFERENT
/// recovery codes must each increment the consumed counter. The old
/// read-modify-write bound the increment to a value fetched before the
/// UPDATE, so both racers wrote `0 + 1` and the remaining-codes report
/// drifted. Redemption safety itself is unchanged (the `used_at IS NULL`
/// UPDATE stays the single-flight gate; asserted for both codes).
#[sqlx::test(migrations = "./migrations")]
async fn concurrent_recovery_redemptions_each_increment_the_counter(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "mfa-race").await;
    enable_mfa(&pool, &user, "JBSWY3DPEHPK3PXP").await;

    let config: (String,) = sqlx::query_as("SELECT id FROM mfa_configurations WHERE user_id = $1")
        .bind(&user.id)
        .fetch_one(&pool)
        .await
        .expect("config row");
    for code in ["RACECODE1", "RACECODE2"] {
        sqlx::query(
            "INSERT INTO mfa_recovery_codes (id, mfa_config_id, code_hash) VALUES ($1, $2, $3)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&config.0)
        .bind(firecrow_backend::services::mfa_service::MfaService::hash_recovery_code(code))
        .execute(&pool)
        .await
        .expect("seed recovery code");
    }

    // One challenge per redemption (challenge JTIs are single-use).
    let challenge_a = login_challenge(&app, &user).await;
    let challenge_b = login_challenge(&app, &user).await;
    let (res_a, res_b) = tokio::join!(
        app.post("/api/v1/auth/login/mfa")
            .json(&serde_json::json!({"mfa_token": challenge_a, "code": "RACECODE1"})),
        app.post("/api/v1/auth/login/mfa")
            .json(&serde_json::json!({"mfa_token": challenge_b, "code": "RACECODE2"})),
    );
    assert_eq!(
        res_a.status_code(),
        200,
        "first redemption must succeed: {}",
        res_a.text()
    );
    assert_eq!(
        res_b.status_code(),
        200,
        "concurrent redemption must succeed: {}",
        res_b.text()
    );

    let (consumed,): (i32,) =
        sqlx::query_as("SELECT backup_codes_consumed FROM mfa_configurations WHERE id = $1")
            .bind(&config.0)
            .fetch_one(&pool)
            .await
            .expect("counter row");
    assert_eq!(
        consumed, 2,
        "both concurrent redemptions must be counted, none lost"
    );
}
