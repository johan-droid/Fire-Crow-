//! Phase P0-C: the product-integrity boundary.
//!
//! FireCrow must never present invented vulnerabilities as a real scan. This suite
//! pins that boundary at four levels: the engine declaration, the persistence
//! layer, the API contract, and the absence of the historical fabricated literals
//! anywhere in the tree.

mod support;

use firecrow_backend::agents::{ENGINE_AVAILABLE, ENGINE_NAME, ENGINE_UNAVAILABLE_REASON};
use firecrow_backend::models::JobStatus;
use sqlx::PgPool;

// ---------------------------------------------------------------------------
// The historical fabrications, quoted verbatim from the deleted sast agent.
// None may appear in a scan result, the source tree, or the built frontend.
// ---------------------------------------------------------------------------
const FABRICATED_PATHS: &[&str] = &[
    "src/config.rs",
    "src/db/queries.rs",
    "src/middleware/cors.rs",
];
const FABRICATED_EVIDENCE: &[&str] = &[
    "pub const SECRET_KEY: &str = \"dev_secret_key_123\";",
    "format!(\"SELECT * FROM users WHERE username = '{}'\", user_input)",
    "CorsLayer::new().allow_origin(Any)",
];
const FABRICATED_MARKERS: &[&str] = &[
    "sast_jwt_checker",
    "sast_sqli_checker",
    "sast_cors_checker",
    "ast_deep_scan",
    "FireCrow AST Engine",
    "Weak or Hardcoded JWT Secret Key Signature",
    "Unparameterized Dynamic SQL Query String Concatenation",
    "Overly Permissive CORS Access-Control-Allow-Origin Wildcard",
];

// ---------------------------------------------------------------------------
// Test 1 — engine unavailable, declared
// ---------------------------------------------------------------------------

#[test]
fn engine_reports_unavailable() {
    // black_box keeps this a real runtime assertion rather than a const one, so
    // flipping the constant to `true` fails here instead of being folded away.
    assert!(
        !std::hint::black_box(ENGINE_AVAILABLE),
        "no analysis engine is compiled into this build; if a real engine was added, \
         ENGINE_AVAILABLE must only be set once it produces evidence from the repository"
    );
    assert_eq!(ENGINE_NAME, "none");
    assert!(
        ENGINE_UNAVAILABLE_REASON.contains("not"),
        "the reason must state that no analysis happened: {ENGINE_UNAVAILABLE_REASON}"
    );
}

#[test]
fn job_status_distinguishes_unavailable_from_completed() {
    // These must be three separable states.
    assert_ne!(JobStatus::EngineUnavailable, JobStatus::Completed);
    assert_ne!(JobStatus::EngineUnavailable, JobStatus::Failed);
    assert_ne!(JobStatus::EngineUnavailable, JobStatus::Queued);

    assert_eq!(JobStatus::EngineUnavailable.as_str(), "engine_unavailable");
    assert_eq!(
        "engine_unavailable".parse::<JobStatus>().unwrap(),
        JobStatus::EngineUnavailable,
        "the status must round-trip through the database text representation"
    );
}

/// Test 5 — the state survives serialization in both directions.
#[test]
fn engine_unavailable_survives_serialization() {
    let json = serde_json::to_string(&JobStatus::EngineUnavailable).unwrap();
    assert_eq!(json, "\"engine_unavailable\"");
    let back: JobStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(back, JobStatus::EngineUnavailable);

    // And it must be distinguishable from the states it could be mistaken for.
    for other in [
        JobStatus::Completed,
        JobStatus::Failed,
        JobStatus::Cancelled,
    ] {
        let j = serde_json::to_string(&other).unwrap();
        assert_ne!(
            j, json,
            "{other:?} must not serialize like EngineUnavailable"
        );
    }
}

// ---------------------------------------------------------------------------
// Test 2/7 — no hard-coded finding data can escape
// ---------------------------------------------------------------------------

/// `grep` exits 0 on a match, so a *successful* run is the failure case here.
fn grep_found(needle: &str, dir: &str) -> Option<String> {
    let out = std::process::Command::new("grep")
        .args(["-rl", "--include=*.rs", needle, dir])
        .output()
        .expect("grep must run");
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[test]
fn fabricated_scan_literals_are_absent_from_the_backend_source() {
    for marker in FABRICATED_MARKERS {
        assert_eq!(
            grep_found(marker, "src/"),
            None,
            "fabricated scan data still present in production source: {marker}"
        );
    }
}

#[test]
fn fabricated_findings_are_absent_from_the_frontend_source() {
    for marker in FABRICATED_PATHS.iter().chain(FABRICATED_EVIDENCE) {
        assert_eq!(
            grep_found(marker, "../frontend/src"),
            None,
            "frontend source contains fabricated scan data: {marker}"
        );
    }
}

// ---------------------------------------------------------------------------
// Test 1/3/4 — the job lifecycle
// ---------------------------------------------------------------------------

async fn submit_and_run(pool: &PgPool) -> (String, String) {
    let user = support::seed_user(pool, "p0c").await;
    let job_id = uuid::Uuid::new_v4().to_string();
    let repo = "https://github.com/example/some-repository";

    sqlx::query(
        "INSERT INTO audit_jobs (id, user_id, repo_url, status, cancel_requested, legal_hold, created_at)
         VALUES ($1,$2,$3,$4,false,false,NOW())",
    )
    .bind(&job_id)
    .bind(&user.id)
    .bind(repo)
    .bind(JobStatus::Queued.as_str())
    .execute(pool)
    .await
    .expect("submit");

    // Run the real orchestrator, exactly as the worker does.
    firecrow_backend::orchestrator::execute_audit_job(
        pool, &job_id, &user.id, repo, "main", None, None,
    )
    .await
    .expect("orchestrator must not error");

    (job_id, user.id)
}

/// Test 1 — a scan with no engine reports the explicit state, not a result.
#[sqlx::test(migrations = "./migrations")]
async fn scan_without_engine_reports_engine_unavailable(pool: PgPool) {
    let (job_id, _) = submit_and_run(&pool).await;

    let (status,): (String,) = sqlx::query_as("SELECT status FROM audit_jobs WHERE id=$1")
        .bind(&job_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        status, "engine_unavailable",
        "a job with no analysis engine must not report Completed"
    );

    let decoded: JobStatus = status.parse().expect("status must decode");
    assert_eq!(decoded, JobStatus::EngineUnavailable);
}

/// Test 1 — zero findings are returned, and that is paired with the explicit state.
#[sqlx::test(migrations = "./migrations")]
async fn scan_without_engine_returns_no_findings_and_no_score(pool: PgPool) {
    let (job_id, _) = submit_and_run(&pool).await;

    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM findings WHERE job_id=$1")
        .bind(&job_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0, "no finding rows may be persisted without an engine");

    // A perfect score derived from zero findings would be the most misleading
    // output this product could produce, so the score must be absent.
    let (score,): (Option<f64>,) =
        sqlx::query_as("SELECT security_score FROM audit_jobs WHERE id=$1")
            .bind(&job_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        score.is_none(),
        "security_score must be NULL when no analysis ran, got {score:?} (10.0 would read as a perfect score)"
    );
}

/// Test 4 — no fabricated metadata reaches persistence.
#[sqlx::test(migrations = "./migrations")]
async fn scan_without_engine_persists_no_fabricated_metadata(pool: PgPool) {
    let (job_id, _) = submit_and_run(&pool).await;

    type FindingRow = (String, Option<String>, Option<i32>, Option<f64>);
    let rows: Vec<FindingRow> = sqlx::query_as(
        "SELECT title, file_path, line_number, cvss_score FROM findings WHERE job_id=$1",
    )
    .bind(&job_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(rows.is_empty(), "no finding rows expected: {rows:?}");

    // A report must not exist either: an empty report would read as "all clear".
    let (reports,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_reports WHERE job_id=$1")
        .bind(&job_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(reports, 0, "no report may be generated without an engine");

    // The phase ledger must record why nothing happened.
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM phase_ledger WHERE job_id=$1 AND phase_name='engine_unavailable'",
    )
    .bind(&job_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        n, 1,
        "the unavailability must be recorded in the phase ledger"
    );

    let (msg,): (Option<String>,) = sqlx::query_as(
        "SELECT error_message FROM phase_ledger WHERE job_id=$1 AND phase_name='engine_unavailable'",
    )
    .bind(&job_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let msg = msg.unwrap_or_default();
    assert!(
        msg.contains("not") && msg.len() > 20,
        "a truthful diagnostic must be persisted, got {msg:?}"
    );
}

/// Test 3 — two materially different repositories must not receive identical
/// findings. Neither receives any.
#[sqlx::test(migrations = "./migrations")]
async fn different_repositories_receive_no_findings(pool: PgPool) {
    let user = support::seed_user(&pool, "p0c_multi").await;

    let mut ids = Vec::new();
    for repo in [
        "https://github.com/torvalds/linux",
        "https://github.com/rust-lang/cargo",
        "https://gitlab.com/gitlab-org/gitlab",
    ] {
        let job_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO audit_jobs (id, user_id, repo_url, status, cancel_requested, legal_hold, created_at)
             VALUES ($1,$2,$3,'queued',false,false,NOW())",
        )
        .bind(&job_id)
        .bind(&user.id)
        .bind(repo)
        .execute(&pool)
        .await
        .unwrap();

        firecrow_backend::orchestrator::execute_audit_job(
            &pool, &job_id, &user.id, repo, "main", None, None,
        )
        .await
        .unwrap();
        ids.push(job_id);
    }

    for id in &ids {
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM findings WHERE job_id=$1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0, "job {id} received fabricated findings");
    }

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM findings")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        total, 0,
        "no findings anywhere for three distinct repositories"
    );
}

// ---------------------------------------------------------------------------
// Test 5 — the API contract carries the distinction
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn api_contract_separates_unavailable_from_a_clean_scan(pool: PgPool) {
    let user = support::seed_user(&pool, "p0c_api").await;
    let repo = "https://github.com/example/some-repository";
    let job_id = uuid::Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO audit_jobs (id, user_id, repo_url, status, cancel_requested, legal_hold, created_at)
         VALUES ($1,$2,$3,$4,false,false,NOW())",
    )
    .bind(&job_id)
    .bind(&user.id)
    .bind(repo)
    .bind(JobStatus::Queued.as_str())
    .execute(&pool)
    .await
    .expect("submit");

    firecrow_backend::orchestrator::execute_audit_job(
        &pool, &job_id, &user.id, repo, "main", None, None,
    )
    .await
    .expect("orchestrator must not error");

    let app = support::test_app(pool.clone()).await;
    let res = app
        .get(&format!("/api/v1/audit/job/{job_id}"))
        .add_header("authorization", user.auth_header())
        .await;

    assert_eq!(res.status_code(), 200, "owner must read their own job");

    let body: serde_json::Value = res.json();

    // The three properties a client needs to avoid showing a false "all clear".
    assert_eq!(
        body["job"]["status"], "engine_unavailable",
        "the API must carry the explicit unavailable status"
    );
    assert!(
        body["job"]["security_score"].is_null(),
        "the API must not invent a score, got {}",
        body["job"]["security_score"]
    );
    assert_eq!(
        body["findings"].as_array().map(Vec::len),
        Some(0),
        "findings must be empty"
    );

    // The distinction that matters: an empty findings list paired with
    // `engine_unavailable` must not be confusable with a clean scan.
    let clean_scan = serde_json::json!({
        "job": { "status": "completed", "security_score": 10.0 },
        "findings": [],
    });
    assert_ne!(
        body["job"]["status"], clean_scan["job"]["status"],
        "an unavailable scan must be distinguishable from a clean scan"
    );
    assert_ne!(
        body["job"]["security_score"], clean_scan["job"]["security_score"],
        "an unavailable scan must not borrow a clean scan's score"
    );
}

// ---------------------------------------------------------------------------
// Test 6 — the client must not read unavailable as "no vulnerabilities"
// ---------------------------------------------------------------------------

#[test]
fn frontend_does_not_render_engine_unavailable_as_a_pending_or_clean_scan() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("frontend/src/App.tsx"),
    )
    .expect("App.tsx must be readable");

    let at = src
        .find("selectedJobDetail.findings.length === 0")
        .expect("the empty-findings branch must exist");
    let branch = &src[at..];
    let end = branch.find(") : (").unwrap_or(branch.len());
    let branch = &branch[..end];

    assert!(
        branch.contains("engine_unavailable"),
        "the empty-findings branch must handle engine_unavailable explicitly"
    );
    assert!(
        branch.contains("No analysis was performed"),
        "it must say that no analysis was performed"
    );
    assert!(
        branch.find("engine_unavailable").unwrap()
            < branch.find("'completed'").unwrap_or(usize::MAX),
        "engine_unavailable must be checked BEFORE completed, or a clean-scan label \
         could win"
    );
}
