//! The product-integrity boundary.
//!
//! FireCrow must never present invented vulnerabilities as a real scan. This
//! suite pins that boundary now that a real engine exists: the engine declares
//! itself honestly, every failure path yields no findings and a NULL score, and
//! the historical fabricated literals are absent from the tree.

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
// The engine declares the scanner it actually runs.
// ---------------------------------------------------------------------------

#[test]
fn engine_declares_the_scanner_it_actually_runs() {
    // black_box keeps this a real runtime assertion rather than a folded const.
    assert!(
        std::hint::black_box(ENGINE_AVAILABLE),
        "this build ships a real scan pipeline; ENGINE_AVAILABLE must reflect it"
    );
    assert_eq!(
        ENGINE_NAME, "gitleaks",
        "ENGINE_NAME must name the scanner the orchestrator actually invokes"
    );
    // The unavailability text still has to be truthful for the branch that
    // reports it, and must state that nothing was read or analyzed.
    assert!(
        ENGINE_UNAVAILABLE_REASON.contains("not")
            && ENGINE_UNAVAILABLE_REASON.contains("no findings"),
        "the unavailable reason must state that no analysis happened"
    );
}

#[test]
fn job_status_distinguishes_unavailable_from_completed() {
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

#[test]
fn engine_unavailable_survives_serialization() {
    let json = serde_json::to_string(&JobStatus::EngineUnavailable).unwrap();
    assert_eq!(json, "\"engine_unavailable\"");
    let back: JobStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(back, JobStatus::EngineUnavailable);

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
// No hard-coded finding data can escape.
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
// Every failure path yields no findings and a NULL score.
// ---------------------------------------------------------------------------

/// Seed a job whose repository cannot be acquired, then run the real
/// orchestrator exactly as the worker does. The URL does not match
/// `https://github.com/{owner}/{repo}`, so the fetch phase fails immediately —
/// no network is required and the outcome is deterministic.
async fn run_unfetchable_job(pool: &PgPool) -> (String, support::SeededUser) {
    let user = support::seed_user(pool, "p0c").await;
    let job_id = uuid::Uuid::new_v4().to_string();
    let repo = "https://gitlab.com/example/project";

    sqlx::query(
        "INSERT INTO audit_jobs (id, user_id, repo_url, status, cancel_requested, legal_hold, created_at)
         VALUES ($1,$2,$3,'queued',false,false,NOW())",
    )
    .bind(&job_id)
    .bind(&user.id)
    .bind(repo)
    .execute(pool)
    .await
    .expect("submit");

    firecrow_backend::orchestrator::execute_audit_job(
        pool, &job_id, &user.id, repo, "main", None, None,
    )
    .await
    .expect("orchestrator must not error");

    (job_id, user)
}

#[sqlx::test(migrations = "./migrations")]
async fn failed_fetch_ends_failed_not_completed(pool: PgPool) {
    let (job_id, _) = run_unfetchable_job(&pool).await;
    let (status,): (String,) = sqlx::query_as("SELECT status FROM audit_jobs WHERE id=$1")
        .bind(&job_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        status, "failed",
        "a job whose repository could not be acquired must not report Completed"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn failed_fetch_persists_no_score(pool: PgPool) {
    let (job_id, _) = run_unfetchable_job(&pool).await;
    let (score,): (Option<f64>,) =
        sqlx::query_as("SELECT security_score FROM audit_jobs WHERE id=$1")
            .bind(&job_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        score.is_none(),
        "security_score must be NULL when no analysis ran, got {score:?}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn failed_fetch_persists_no_findings_or_report(pool: PgPool) {
    let (job_id, _) = run_unfetchable_job(&pool).await;

    let (findings,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM findings WHERE job_id=$1")
        .bind(&job_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(findings, 0, "no finding rows may be persisted on failure");

    let (reports,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_reports WHERE job_id=$1")
        .bind(&job_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(reports, 0, "no report may be written when the scan fails");
}

#[sqlx::test(migrations = "./migrations")]
async fn failed_phase_is_recorded_in_the_ledger(pool: PgPool) {
    let (job_id, _) = run_unfetchable_job(&pool).await;

    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM phase_ledger WHERE job_id=$1 AND phase_name='fetch' AND status='failed'",
    )
    .bind(&job_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(n, 1, "the failing phase and its name must be recorded");

    // A phase that never ran must not appear as completed.
    let (later,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM phase_ledger WHERE job_id=$1 AND phase_name IN ('scan','score','report') AND status='completed'",
    )
    .bind(&job_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(later, 0, "no later phase may be reported as completed");
}

// ---------------------------------------------------------------------------
// The API contract carries the distinction.
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn api_contract_reports_failure_without_a_score_or_findings(pool: PgPool) {
    let (job_id, user) = run_unfetchable_job(&pool).await;
    let app = support::test_app(pool.clone()).await;

    let res = app
        .get(&format!("/api/v1/audit/job/{job_id}"))
        .add_header("authorization", user.auth_header())
        .await;
    assert_eq!(res.status_code(), 200, "owner must read their own job");

    let body: serde_json::Value = res.json();
    assert_eq!(body["job"]["status"], "failed");
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
}

// ---------------------------------------------------------------------------
// The client must not read unavailable as "no vulnerabilities".
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
        "engine_unavailable must be checked BEFORE completed, or a clean-scan label could win"
    );
}
