mod support;

use axum_test::TestServer;
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn user_cannot_access_another_users_audit_job(pool: PgPool) {
    let app: TestServer = support::test_app(pool.clone()).await;

    let user_a = support::seed_user(&pool, "user_a").await;
    let user_b = support::seed_user(&pool, "user_b").await;

    let job_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO audit_jobs (id, user_id, repo_url, repo_branch, status, cancel_requested, legal_hold, created_at)
         VALUES ($1, $2, 'https://github.com/example/repo', 'main', 'queued', false, false, NOW())",
    )
    .bind(&job_id)
    .bind(&user_a.id)
    .execute(&pool)
    .await
    .expect("seed user A job");

    // 1. User B cannot get status of User A's job
    let res = app
        .get(&format!("/api/v1/audit/job/{job_id}"))
        .add_header("Authorization", user_b.auth_header())
        .await;
    assert_eq!(
        res.status_code(),
        404,
        "User B must not see User A's job: {}",
        res.text()
    );

    // 2. User B cannot cancel User A's job
    let res = app
        .delete(&format!("/api/v1/audit/job/{job_id}"))
        .add_header("Authorization", user_b.auth_header())
        .await;
    assert_eq!(
        res.status_code(),
        404,
        "User B must not cancel User A's job"
    );

    // 3. User B cannot retry User A's job
    let res = app
        .post(&format!("/api/v1/audit/job/{job_id}/retry"))
        .add_header("Authorization", user_b.auth_header())
        .await;
    assert_eq!(res.status_code(), 404, "User B must not retry User A's job");

    // 4. User B cannot view executions of User A's job
    let res = app
        .get(&format!("/api/v1/audit/job/{job_id}/executions"))
        .add_header("Authorization", user_b.auth_header())
        .await;
    assert_eq!(
        res.status_code(),
        404,
        "User B must not view executions of User A's job"
    );

    // 5. User B cannot view report of User A's job
    let res = app
        .get(&format!("/api/v1/audit/job/{job_id}/report"))
        .add_header("Authorization", user_b.auth_header())
        .await;
    assert_eq!(
        res.status_code(),
        404,
        "User B must not view report of User A's job"
    );

    // 6. User B's audit listing must not show User A's job
    let res = app
        .get("/api/v1/audit/jobs")
        .add_header("Authorization", user_b.auth_header())
        .await;
    assert_eq!(res.status_code(), 200);
    assert!(
        !res.text().contains(&job_id),
        "User B's listing must not contain User A's job"
    );

    // 7. User A can see their own job
    let res = app
        .get(&format!("/api/v1/audit/job/{job_id}"))
        .add_header("Authorization", user_a.auth_header())
        .await;
    assert_eq!(res.status_code(), 200, "User A must see their own job");
}
