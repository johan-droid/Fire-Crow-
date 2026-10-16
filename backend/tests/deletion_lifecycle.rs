//! Account-deletion lifecycle integration tests.
//!
//! Each test runs against its own freshly migrated database
//! (`#[sqlx::test(migrations = "./migrations")]`), so state cannot leak and the
//! new `account_deletion_requests` table is proven to apply through the same
//! chain as every other migration.

use chrono::{Duration, Utc};
use firecrow_backend::config::Settings;
use firecrow_backend::services::deletion_lifecycle;
use firecrow_backend::services::email::EmailService;
use serde_json::Value;
use sqlx::PgPool;

mod support;
use support::{bearer_for, seed_user, test_app, test_settings};

fn settings() -> Settings {
    test_settings()
}

async fn count_requests(pool: &PgPool, user_id: &str) -> i64 {
    let (n,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM account_deletion_requests WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .expect("count requests");
    n
}

async fn request_status(pool: &PgPool, user_id: &str) -> Option<String> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT status FROM account_deletion_requests WHERE user_id = $1 ORDER BY requested_at DESC LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .expect("read status");
    row.map(|(s,)| s)
}

async fn deleted_at(pool: &PgPool, user_id: &str) -> Option<String> {
    let (d,): (Option<String>,) =
        sqlx::query_as("SELECT deleted_at::text FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .expect("read deleted_at");
    d
}

#[sqlx::test(migrations = "./migrations")]
async fn request_then_cancel_happy_path(pool: PgPool) {
    let user = seed_user(&pool, "delreq").await;
    let settings = settings();

    // No mailer configured in tests -> EmailService is None; the request still
    // completes and no email is sent.
    assert!(EmailService::from_settings(&settings).is_none());

    let (deadline, token) = deletion_lifecycle::request_deletion(&pool, &user.id, &settings)
        .await
        .expect("request deletion");

    assert!(deadline > Utc::now().naive_utc(), "deadline in future");
    assert!(!token.is_empty());
    assert_eq!(count_requests(&pool, &user.id).await, 1);
    assert_eq!(
        request_status(&pool, &user.id).await,
        Some("requested".to_string())
    );

    // First cancel succeeds; second cancel with the same token is a no-op.
    assert!(deletion_lifecycle::cancel_deletion(&pool, &user.id, &token)
        .await
        .expect("cancel deletion"));
    assert_eq!(
        request_status(&pool, &user.id).await,
        Some("cancelled".to_string())
    );
    assert!(
        !deletion_lifecycle::cancel_deletion(&pool, &user.id, &token)
            .await
            .expect("repeat cancel returns bool")
    );
    assert_eq!(
        request_status(&pool, &user.id).await,
        Some("cancelled".to_string())
    );

    // The account is still usable: not deleted.
    assert!(deleted_at(&pool, &user.id).await.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn cancel_token_is_bound_to_its_owner(pool: PgPool) {
    let owner = seed_user(&pool, "owner").await;
    let impostor = seed_user(&pool, "impostor").await;
    let settings = settings();

    let (_deadline, token) = deletion_lifecycle::request_deletion(&pool, &owner.id, &settings)
        .await
        .expect("request");

    // The impostor cannot cancel the owner's request.
    assert!(
        !deletion_lifecycle::cancel_deletion(&pool, &impostor.id, &token)
            .await
            .expect("impostor cancel returns bool")
    );
    assert_eq!(
        request_status(&pool, &owner.id).await,
        Some("requested".to_string())
    );

    // The owner can.
    assert!(
        deletion_lifecycle::cancel_deletion(&pool, &owner.id, &token)
            .await
            .expect("owner cancel")
    );
    assert_eq!(
        request_status(&pool, &owner.id).await,
        Some("cancelled".to_string())
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn process_marks_overdue_request_deleted(pool: PgPool) {
    let user = seed_user(&pool, "overdue").await;
    let settings = settings();

    // A session to revoke.
    sqlx::query(
        "INSERT INTO user_sessions (id, user_id, token_family, ip_hash, user_agent_hash, expires_at, is_revoked)
         VALUES ($1,$2,$3,$4,$5,$6,false)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&user.id)
    .bind("family")
    .bind("ip")
    .bind("ua")
    .bind(Utc::now().naive_utc() + Duration::hours(1))
    .execute(&pool)
    .await
    .expect("seed session");

    // Request with a deadline already in the past.
    let past = Utc::now().naive_utc() - Duration::hours(1);
    sqlx::query(
        "INSERT INTO account_deletion_requests (id, user_id, deadline, status, cancellation_token, created_at)
         VALUES ($1,$2,$3,'requested',$4,NOW())",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&user.id)
    .bind(past)
    .bind("token-past")
    .execute(&pool)
    .await
    .expect("insert overdue request");

    let stats = deletion_lifecycle::process(&pool, &settings)
        .await
        .expect("process");

    assert_eq!(stats.accounts_deleted, 1);
    assert_eq!(stats.sessions_revoked, 1);
    assert_eq!(
        request_status(&pool, &user.id).await,
        Some("deleted".to_string())
    );
    assert!(
        deleted_at(&pool, &user.id).await.is_some(),
        "deleted_at must be set"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn process_reminds_pending_request_once_per_interval(pool: PgPool) {
    let user = seed_user(&pool, "remind").await;
    let settings = settings();

    // Deadline far in the future, no reminder sent yet.
    let future = Utc::now().naive_utc() + Duration::days(10);
    sqlx::query(
        "INSERT INTO account_deletion_requests (id, user_id, deadline, status, cancellation_token, created_at)
         VALUES ($1,$2,$3,'requested',$4,NOW())",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&user.id)
    .bind(future)
    .bind("token-remind")
    .execute(&pool)
    .await
    .expect("insert pending request");

    let s1 = deletion_lifecycle::process(&pool, &settings)
        .await
        .expect("process 1");
    assert_eq!(s1.reminders_sent, 1);

    // Immediate second run: within the interval, no duplicate reminder.
    let s2 = deletion_lifecycle::process(&pool, &settings)
        .await
        .expect("process 2");
    assert_eq!(s2.reminders_sent, 0);

    let (count,): (i32,) =
        sqlx::query_as("SELECT reminder_count FROM account_deletion_requests WHERE user_id = $1")
            .bind(&user.id)
            .fetch_one(&pool)
            .await
            .expect("read reminder_count");
    assert_eq!(count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn process_skips_cancelled_and_deleted(pool: PgPool) {
    let user = seed_user(&pool, "skip").await;
    let settings = settings();

    // Cancelled request: never reminded, never deleted.
    let past = Utc::now().naive_utc() - Duration::hours(1);
    sqlx::query(
        "INSERT INTO account_deletion_requests (id, user_id, deadline, status, cancellation_token, cancelled_at, created_at)
         VALUES ($1,$2,$3,'cancelled',$4,NOW(),NOW())",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&user.id)
    .bind(past)
    .bind("token-skip")
    .execute(&pool)
    .await
    .expect("insert cancelled request");

    let stats = deletion_lifecycle::process(&pool, &settings)
        .await
        .expect("process");
    assert_eq!(stats.accounts_deleted, 0);
    assert_eq!(stats.reminders_sent, 0);
    assert_eq!(
        request_status(&pool, &user.id).await,
        Some("cancelled".to_string())
    );
    assert!(deleted_at(&pool, &user.id).await.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn deletion_request_route_requires_auth_and_returns_deadline(pool: PgPool) {
    let user = seed_user(&pool, "route").await;
    let app = test_app(pool.clone()).await;

    // Unauthenticated: rejected by the auth extractor, not a missing route.
    let res = app.post("/api/v1/auth/account/deletion-request").await;
    assert_eq!(res.status_code(), 401, "expected 401: {}", res.text());

    let res = app
        .post("/api/v1/auth/account/deletion-request")
        .add_header("authorization", bearer_for(&pool, &user.id).await)
        .await;
    assert_eq!(res.status_code(), 200, "expected 200: {}", res.text());
    let body: Value = res.json();
    assert_eq!(body["status"], "requested");
    assert!(body["deadline"].as_str().is_some());
    assert!(body["cancel_url"].as_str().is_some());
    assert_eq!(count_requests(&pool, &user.id).await, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn deletion_cancel_route_requires_token(pool: PgPool) {
    let user = seed_user(&pool, "cancelroute").await;
    let app = test_app(pool.clone()).await;

    // No token -> 400 (the cancellation token is a required query parameter).
    let res = app
        .get("/api/v1/auth/account/deletion-cancel")
        .add_header("authorization", bearer_for(&pool, &user.id).await)
        .await;
    assert_eq!(
        res.status_code(),
        400,
        "expected 400 without token: {}",
        res.text()
    );

    // Create a request, then cancel it through the route.
    let settings = settings();
    let (_deadline, token) = deletion_lifecycle::request_deletion(&pool, &user.id, &settings)
        .await
        .expect("request");

    let res = app
        .get("/api/v1/auth/account/deletion-cancel")
        .add_query_param("token", &token)
        .add_header("authorization", bearer_for(&pool, &user.id).await)
        .await;
    let body = res.text();
    assert_eq!(
        res.status_code(),
        200,
        "expected 200, got {}: {}",
        res.status_code(),
        body
    );
    let body: Value = res.json();
    assert_eq!(body["status"], "cancelled");
    assert_eq!(
        request_status(&pool, &user.id).await,
        Some("cancelled".to_string())
    );
}
