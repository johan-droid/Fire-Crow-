use sqlx::PgPool;
use uuid::Uuid;

async fn create_test_user(pool: &PgPool) -> String {
    let user_id = Uuid::new_v4().to_string();
    let username = format!("user_{}", &user_id[..8]);
    let email = format!("user_{}@example.com", &user_id[..8]);
    sqlx::query(
        "INSERT INTO users (id, username, email, password_hash, role_id, is_active, created_at, updated_at)
         VALUES ($1, $2, $3, 'hash', 'developer', true, NOW(), NOW())"
    )
    .bind(&user_id)
    .bind(&username)
    .bind(&email)
    .execute(pool)
    .await
    .expect("test user insertion");
    user_id
}

#[sqlx::test(migrations = "./migrations")]
async fn db_rejects_illegal_queued_to_completed_transition(pool: PgPool) {
    let user_id = create_test_user(&pool).await;
    let job_id = Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO audit_jobs (id, user_id, repo_url, status)
         VALUES ($1, $2, 'https://github.com/org/repo', 'queued')",
    )
    .bind(&job_id)
    .bind(&user_id)
    .execute(&pool)
    .await
    .expect("job insertion must succeed");

    // Attempt illegal transition: queued -> completed
    let res = sqlx::query("UPDATE audit_jobs SET status = 'completed' WHERE id = $1")
        .bind(&job_id)
        .execute(&pool)
        .await;

    assert!(
        res.is_err(),
        "Database trigger must reject direct queued -> completed transition"
    );
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("illegal audit job status transition")
            || err_msg.contains("restrict_violation"),
        "Expected illegal status transition error, got: {err_msg}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn db_rejects_mutation_out_of_completed(pool: PgPool) {
    let user_id = create_test_user(&pool).await;
    let job_id = Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO audit_jobs (id, user_id, repo_url, status)
         VALUES ($1, $2, 'https://github.com/org/repo', 'queued')",
    )
    .bind(&job_id)
    .bind(&user_id)
    .execute(&pool)
    .await
    .expect("job insertion must succeed");

    // Advance to running, then completed
    sqlx::query("UPDATE audit_jobs SET status = 'running' WHERE id = $1")
        .bind(&job_id)
        .execute(&pool)
        .await
        .expect("queued -> running must succeed");

    sqlx::query("UPDATE audit_jobs SET status = 'completed' WHERE id = $1")
        .bind(&job_id)
        .execute(&pool)
        .await
        .expect("running -> completed must succeed");

    // Attempt mutation out of completed: completed -> running
    let res = sqlx::query("UPDATE audit_jobs SET status = 'running' WHERE id = $1")
        .bind(&job_id)
        .execute(&pool)
        .await;

    assert!(
        res.is_err(),
        "Database trigger must reject completed -> running transition"
    );

    // Attempt completed -> queued
    let res2 = sqlx::query("UPDATE audit_jobs SET status = 'queued' WHERE id = $1")
        .bind(&job_id)
        .execute(&pool)
        .await;

    assert!(
        res2.is_err(),
        "Database trigger must reject completed -> queued transition"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn db_rejects_failed_to_running_direct(pool: PgPool) {
    let user_id = create_test_user(&pool).await;
    let job_id = Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO audit_jobs (id, user_id, repo_url, status)
         VALUES ($1, $2, 'https://github.com/org/repo', 'queued')",
    )
    .bind(&job_id)
    .bind(&user_id)
    .execute(&pool)
    .await
    .expect("job insertion must succeed");

    sqlx::query("UPDATE audit_jobs SET status = 'failed' WHERE id = $1")
        .bind(&job_id)
        .execute(&pool)
        .await
        .expect("queued -> failed must succeed");

    // Direct failed -> running must fail
    let res = sqlx::query("UPDATE audit_jobs SET status = 'running' WHERE id = $1")
        .bind(&job_id)
        .execute(&pool)
        .await;

    assert!(
        res.is_err(),
        "Direct failed -> running must be rejected by trigger"
    );

    // Legal retry: failed -> queued must succeed
    sqlx::query("UPDATE audit_jobs SET status = 'queued' WHERE id = $1")
        .bind(&job_id)
        .execute(&pool)
        .await
        .expect("failed -> queued (retry) must succeed");

    // Now queued -> running must succeed
    sqlx::query("UPDATE audit_jobs SET status = 'running' WHERE id = $1")
        .bind(&job_id)
        .execute(&pool)
        .await
        .expect("queued -> running must succeed");
}

#[sqlx::test(migrations = "./migrations")]
async fn db_enforces_user_foreign_key(pool: PgPool) {
    let nonexistent_user = Uuid::new_v4().to_string();
    let job_id = Uuid::new_v4().to_string();

    let res = sqlx::query(
        "INSERT INTO audit_jobs (id, user_id, repo_url, status)
         VALUES ($1, $2, 'https://github.com/org/repo', 'queued')",
    )
    .bind(&job_id)
    .bind(&nonexistent_user)
    .execute(&pool)
    .await;

    assert!(
        res.is_err(),
        "Database must reject audit_job referencing non-existent user"
    );
}
