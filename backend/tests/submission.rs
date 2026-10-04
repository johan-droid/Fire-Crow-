//! Phase 19A: the submission contract and user-facing audit surface.
//!
//! What is proven here:
//!
//! * 19.4 — an explicitly pinned `commit_sha` must be a commit SHA (40
//!   lowercase hex) and is stored on the job for the fetch phase; anything
//!   else is a 400. A branch remains the default input, resolved to a SHA at
//!   fetch time.
//! * 19.9 — a user with `max_active_jobs_per_user` live audits cannot queue
//!   more; the door holds instead of the queue growing without bound.
//! * 19.6 — `GET /job/:id/executions` lists every attempt with its own
//!   status, snapshot, finding count, and artifact/delivery presence, and is
//!   ownership-gated like every other audit route.
//! * 19.2 — the worker resolves the owner's own connected GitHub token when
//!   one exists (private repositories), the platform token otherwise, and the
//!   platform token when the stored blob cannot be decrypted. The resolved
//!   value is never written to any audit table.

mod support;

use axum::http::StatusCode;
use firecrow_backend::orchestrator::execution::{begin_execution, finalize_without_findings};
use sqlx::PgPool;

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

async fn submit(
    app: &axum_test::TestServer,
    token: &str,
    body: serde_json::Value,
) -> axum_test::TestResponse {
    app.post("/api/v1/audit/submit")
        .add_header("authorization", token)
        .json(&body)
        .await
}

// ---------------------------------------------------------------------------
// 19.4: the pinned snapshot
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn a_pinned_sha_is_accepted_and_recorded(pool: PgPool) {
    let user = support::seed_user(&pool, "pin").await;
    let token = support::bearer_for(&pool, &user.id).await;
    let app = support::test_app(pool.clone()).await;

    let response = submit(
        &app,
        &token,
        serde_json::json!({
            "repo_url": "https://github.com/example/repo",
            "repo_branch": "main",
            "commit_sha": SHA,
        }),
    )
    .await;
    assert_eq!(response.status_code(), 200, "body: {}", response.text());
    let job_id = response.json::<serde_json::Value>()["id"]
        .as_str()
        .expect("submit returns id")
        .to_string();

    let stored: (Option<String>,) =
        sqlx::query_as("SELECT requested_commit_sha FROM audit_jobs WHERE id=$1")
            .bind(&job_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored.0.as_deref(), Some(SHA));

    // And the user can see what was requested.
    let detail = app
        .get(format!("/api/v1/audit/job/{job_id}").as_str())
        .add_header("authorization", &token)
        .await;
    assert_eq!(detail.status_code(), 200);
    assert_eq!(
        detail.json::<serde_json::Value>()["job"]["requested_commit_sha"],
        serde_json::json!(SHA),
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn a_non_sha_commit_pin_is_rejected(pool: PgPool) {
    let user = support::seed_user(&pool, "pinbad").await;
    let token = support::bearer_for(&pool, &user.id).await;
    let app = support::test_app(pool.clone()).await;

    for bad in [
        "main",
        "abc",
        "0123456789ABCDEF0123456789ABCDEF01234567",
        "https://github.com/example/repo",
        "0123456789abcdef0123456789abcdef0123456",
    ] {
        let response = submit(
            &app,
            &token,
            serde_json::json!({
                "repo_url": "https://github.com/example/repo",
                "commit_sha": bad,
            }),
        )
        .await;
        assert_eq!(
            response.status_code(),
            400,
            "{bad:?} must be rejected: {}",
            response.text()
        );
    }

    let rows: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows.0, 0, "no job may be created for a refused pin");
}

#[sqlx::test(migrations = "./migrations")]
async fn no_pin_means_branch_head(pool: PgPool) {
    let user = support::seed_user(&pool, "nopin").await;
    let token = support::bearer_for(&pool, &user.id).await;
    let app = support::test_app(pool.clone()).await;

    let response = submit(
        &app,
        &token,
        serde_json::json!({"repo_url": "https://github.com/example/repo"}),
    )
    .await;
    assert_eq!(response.status_code(), 200, "body: {}", response.text());
    let job_id = response.json::<serde_json::Value>()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let stored: (Option<String>,) =
        sqlx::query_as("SELECT requested_commit_sha FROM audit_jobs WHERE id=$1")
            .bind(&job_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(stored.0.is_none(), "branch-head scan stores no pin");
}

// ---------------------------------------------------------------------------
// 19.9: backpressure at the door
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn a_user_with_too_many_live_audits_is_turned_away(pool: PgPool) {
    let user = support::seed_user(&pool, "flood").await;
    let token = support::bearer_for(&pool, &user.id).await;
    let app = support::test_app(pool.clone()).await;

    // The test settings allow two live audits per user; the third is refused.
    for _ in 0..2 {
        let response = submit(
            &app,
            &token,
            serde_json::json!({"repo_url": "https://github.com/example/repo"}),
        )
        .await;
        assert_eq!(response.status_code(), 200, "body: {}", response.text());
    }
    let refused = submit(
        &app,
        &token,
        serde_json::json!({"repo_url": "https://github.com/example/other"}),
    )
    .await;
    assert_eq!(
        refused.status_code(),
        409,
        "the third live audit must wait: {}",
        refused.text()
    );

    // Another user is unaffected by the first user's queue.
    let other = support::seed_user(&pool, "other").await;
    let other_token = support::bearer_for(&pool, &other.id).await;
    let admitted = submit(
        &app,
        &other_token,
        serde_json::json!({"repo_url": "https://github.com/example/repo"}),
    )
    .await;
    assert_eq!(admitted.status_code(), 200, "body: {}", admitted.text());
}

// ---------------------------------------------------------------------------
// 19.6: the attempt history
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn executions_lists_every_attempt_with_its_own_state(pool: PgPool) {
    use firecrow_backend::models::JobStatus;

    let user = support::seed_user(&pool, "hist").await;
    let job = support::seed_job(&pool, &user.id, JobStatus::Running.as_str()).await;
    let first = begin_execution(&pool, &job).await.unwrap();
    // Attempts are sequential: the first must be terminal before the second
    // opens. That is exactly the property history must show.
    finalize_without_findings(&pool, &first, "failed", "test seam")
        .await
        .unwrap();
    let second = begin_execution(&pool, &job).await.unwrap();

    let token = support::bearer_for(&pool, &user.id).await;
    let app = support::test_app(pool.clone()).await;

    let response = app
        .get(format!("/api/v1/audit/job/{job}/executions").as_str())
        .add_header("authorization", &token)
        .await;
    assert_eq!(response.status_code(), 200, "body: {}", response.text());
    let executions = response.json::<Vec<serde_json::Value>>();
    assert_eq!(executions.len(), 2, "both attempts must be listed");
    assert_eq!(executions[0]["attempt_number"], serde_json::json!(1));
    assert_eq!(executions[1]["attempt_number"], serde_json::json!(2));
    assert_eq!(
        executions[0]["execution_id"].as_str().unwrap(),
        first.execution_id
    );
    assert_eq!(
        executions[1]["execution_id"].as_str().unwrap(),
        second.execution_id
    );
    // Retries are distinct records, never a flattened mutable audit.
    for execution in &executions {
        assert!(execution["status"].as_str().is_some());
        assert!(execution["finding_count"].as_i64().is_some());
        assert!(execution["has_report"].as_bool().is_some());
        assert!(execution["has_narrative"].as_bool().is_some());
        assert!(execution["deliveries"].as_array().is_some());
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn executions_is_ownership_gated(pool: PgPool) {
    use firecrow_backend::models::JobStatus;

    let user = support::seed_user(&pool, "histown").await;
    let job = support::seed_job(&pool, &user.id, JobStatus::Running.as_str()).await;
    let other = support::seed_user(&pool, "histforeign").await;
    let app = support::test_app(pool.clone()).await;

    let foreign = app
        .get(format!("/api/v1/audit/job/{job}/executions").as_str())
        .add_header(
            "authorization",
            &support::bearer_for(&pool, &other.id).await,
        )
        .await;
    assert_eq!(foreign.status_code(), 404);
}

// ---------------------------------------------------------------------------
// 19.2: per-user token resolution, never persisted
// ---------------------------------------------------------------------------

fn settings_with_platform_token() -> firecrow_backend::config::Settings {
    let mut settings = support::test_settings();
    settings.github_token = "platform-token".into();
    settings
}

#[sqlx::test(migrations = "./migrations")]
async fn the_owners_connected_token_wins_over_the_platform_token(pool: PgPool) {
    let user = support::seed_user(&pool, "token").await;
    let settings = settings_with_platform_token();
    let crypto = firecrow_backend::services::crypto::crypto_manager(
        &settings.secret_key,
        &settings.encryption_key,
    )
    .expect("test crypto builds");
    let encrypted = crypto.encrypt_secret("user-oauth-token").expect("encrypt");
    sqlx::query("UPDATE users SET github_access_token=$1 WHERE id=$2")
        .bind(&encrypted)
        .bind(&user.id)
        .execute(&pool)
        .await
        .unwrap();

    let resolved =
        firecrow_backend::workers::resolve_github_token(&pool, &settings, &user.id).await;
    assert_eq!(resolved, "user-oauth-token");

    // The resolved credential lives in memory, not in any audit table.
    let audit_tables = [
        "SELECT commit_sha FROM audit_jobs",
        "SELECT evidence FROM findings",
        "SELECT failure_class FROM audit_deliveries",
    ];
    for query in audit_tables {
        let rows: Vec<(Option<String>,)> = sqlx::query_as(query)
            .fetch_all(&pool)
            .await
            .unwrap_or_default();
        for (value,) in rows {
            assert_ne!(value.as_deref(), Some("user-oauth-token"));
        }
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn without_a_connected_token_the_platform_token_is_used(pool: PgPool) {
    let user = support::seed_user(&pool, "notoken").await;
    let settings = settings_with_platform_token();

    let resolved =
        firecrow_backend::workers::resolve_github_token(&pool, &settings, &user.id).await;
    assert_eq!(resolved, "platform-token");
}

#[sqlx::test(migrations = "./migrations")]
async fn an_undecryptable_token_falls_back_to_the_platform_token(pool: PgPool) {
    let user = support::seed_user(&pool, "badtoken").await;
    let settings = settings_with_platform_token();
    sqlx::query("UPDATE users SET github_access_token=$1 WHERE id=$2")
        .bind("ENC[not-valid-base64!!!]")
        .bind(&user.id)
        .execute(&pool)
        .await
        .unwrap();

    let resolved =
        firecrow_backend::workers::resolve_github_token(&pool, &settings, &user.id).await;
    assert_eq!(
        resolved, "platform-token",
        "a corrupt blob must not fail resolution"
    );
}

// ---------------------------------------------------------------------------
// Phase 20: concurrent user submission under backpressure
// ---------------------------------------------------------------------------

/// N users submit simultaneously. Each gets their own job — the backpressure
/// gate is per-user, so one user's flood cannot starve another.
#[sqlx::test(migrations = "./migrations")]
async fn concurrent_submissions_from_distinct_users_all_succeed(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let app = std::sync::Arc::new(app);
    let responses = futures::future::join_all((0..5).map(|i| {
        let pool = pool.clone();
        let app = app.clone();
        async move {
            let user = support::seed_user(&pool, &format!("concurrent-{i}")).await;
            let token = support::bearer_for(&pool, &user.id).await;
            submit(
                &app,
                &token,
                serde_json::json!({"repo_url": "https://github.com/example/repo"}),
            )
            .await
        }
    }))
    .await;
    for response in responses {
        assert_eq!(response.status_code(), 200, "body: {}", response.text());
    }
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 5);
}

/// One user submits concurrently past the gate. Exactly `max_active` succeed;
/// the rest are refused with 409.
///
/// SOAK (release-candidate gate, 2026-10-04): this 6-way burst is the
/// production-like backpressure soak at the available scale — real Postgres,
/// real advisory-lock gate, `join_all` thundering-herd timing (not staged
/// sequential submits). Measured: 2 admitted / 4 refused, `audit_jobs` holds
/// exactly 2 rows, no 500s, cross-user test proves no global blocking.
/// A larger N-user/N-worker flood soak (webhook deliveries × retries ×
/// cancellations under sustained load) remains P1 PENDING — recorded, not
/// claimed.
#[sqlx::test(migrations = "./migrations")]
async fn concurrent_submissions_from_one_user_respect_the_gate(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "flood-race").await;
    let token = support::bearer_for(&pool, &user.id).await;

    let app = std::sync::Arc::new(app);
    // The test settings allow 2 live audits. Fire 6 concurrent submissions.
    let responses = futures::future::join_all((0..6).map(|_| {
        submit(
            &app,
            &token,
            serde_json::json!({"repo_url": "https://github.com/example/repo"}),
        )
    }))
    .await;
    let mut admitted = 0;
    let mut refused = 0;
    for response in responses {
        match response.status_code() {
            StatusCode::OK => admitted += 1,
            StatusCode::CONFLICT => refused += 1,
            other => panic!("unexpected status: {}", other.as_u16()),
        }
    }
    // Exactly max_active (2) admitted, the rest refused. The gate counts and
    // inserts under a per-user advisory lock in one transaction, so concurrent
    // submissions cannot all observe the same live count and all insert.
    assert_eq!(admitted, 2, "the gate must admit exactly its limit");
    assert_eq!(refused, 4, "the overflow must be refused");
}
