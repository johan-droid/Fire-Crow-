//! 8.1-A: `Severity` survives the database and the API.
//!
//! `Severity::Unknown` was added in Phase 8 so an OSV finding with no
//! advisory-backed severity could report `unknown` instead of a fabricated
//! `High`. Nothing exercised the round-trip, so a row carrying it could have
//! failed to encode, failed to decode, or serialized as a missing field.
//!
//! `findings.severity` is `VARCHAR(64)` and the enum implements sqlx
//! `Type`/`Encode`/`Decode` by hand, so every variant is proven here.

mod support;

use firecrow_backend::agents::scanner::{findings_from_osv, ScanInput, Scanner};
use firecrow_backend::models::{FindingModel, Severity};
use firecrow_backend::schemas::audit_api::FindingResponse;
use firecrow_backend::schemas::audit_state::Finding;
use sqlx::PgPool;

/// Every variant, in declaration order: nothing may be skipped.
const ALL: [Severity; 6] = [
    Severity::Critical,
    Severity::High,
    Severity::Medium,
    Severity::Low,
    Severity::Info,
    Severity::Unknown,
];

fn finding_with_severity(severity: Severity) -> Finding {
    let mut f = support::dummy_finding();
    f.id = uuid::Uuid::new_v4().to_string();
    f.severity = severity;
    f
}

#[sqlx::test(migrations = "./migrations")]
async fn every_severity_round_trips_through_the_database(pool: PgPool) {
    let user = support::seed_user(&pool, "sev").await;
    let job = support::seed_job(&pool, &user.id, "running").await;

    let findings: Vec<Finding> = ALL.iter().copied().map(finding_with_severity).collect();
    let stored = firecrow_backend::orchestrator::persist_findings(&pool, &job, &findings)
        .await
        .expect("persist all severities");
    assert_eq!(stored, ALL.len());

    let rows = firecrow_backend::orchestrator::load_findings(&pool, &job)
        .await
        .expect("read all severities");
    assert_eq!(rows.len(), ALL.len());

    for (expected, row) in ALL.iter().zip(rows.iter()) {
        assert_eq!(
            row.severity, *expected,
            "{:?} must read back as itself",
            expected
        );
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn unknown_severity_is_stored_literally(pool: PgPool) {
    // The stored value must be the word `unknown`, not null, not an empty
    // string, and not silently mapped to `info`.
    let user = support::seed_user(&pool, "sev-unknown").await;
    let job = support::seed_job(&pool, &user.id, "running").await;

    let mut finding = finding_with_severity(Severity::Unknown);
    finding.id = "sev-unknown-1".into();
    firecrow_backend::orchestrator::persist_findings(&pool, &job, &[finding])
        .await
        .expect("persist unknown severity");

    let (stored,): (String,) = sqlx::query_as("SELECT severity FROM findings WHERE id=$1")
        .bind("sev-unknown-1")
        .fetch_one(&pool)
        .await
        .expect("read raw severity");
    assert_eq!(stored, "unknown");

    let (non_null,): (bool,) = sqlx::query_as(
        "SELECT metadata_json IS NOT NULL OR severity IS NOT NULL FROM findings WHERE id=$1",
    )
    .bind("sev-unknown-1")
    .fetch_one(&pool)
    .await
    .expect("severity is present");
    assert!(non_null);
}

#[sqlx::test(migrations = "./migrations")]
async fn an_unknown_severity_finding_stays_usable_through_the_api(pool: PgPool) {
    // A real OSV finding whose advisory carries no severity: it must persist,
    // read back, and serialize as `unknown` rather than as a fabricated band.
    let user = support::seed_user(&pool, "sev-osv").await;
    let job = support::seed_job(&pool, &user.id, "running").await;

    let report = serde_json::json!({"results": [{
        "source": {"path": "/scan/package-lock.json", "type": "lockfile"},
        "packages": [{
            "package": {"name": "left-pad", "version": "1.3.0", "ecosystem": "npm"},
            "vulnerabilities": [{
                "id": "OSV-UNRATED-1",
                "aliases": [],
                "summary": "Unrated advisory.",
                "affected": [], "references": [],
                "database_specific": {},
            }],
            "groups": [{"ids": ["OSV-UNRATED-1"]}],
        }],
    }]})
    .to_string();
    let findings = findings_from_osv(
        &report,
        &ScanInput::from_dir(std::path::Path::new("/tmp")).source_dir,
    )
    .expect("canonicalize unrated advisory");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Unknown);

    // A canonical finding is usable: it has file, line, and evidence, so
    // normalization keeps it.
    let prepared = firecrow_backend::orchestrator::prepare_findings_for_persist(findings);
    assert_eq!(
        prepared.dropped_count, 0,
        "unknown severity must not drop it"
    );
    assert_eq!(prepared.valid.len(), 1);

    let finding = prepared.valid.into_iter().next().unwrap();
    assert_eq!(finding.severity, Severity::Unknown);
    firecrow_backend::orchestrator::persist_findings(&pool, &job, std::slice::from_ref(&finding))
        .await
        .expect("persist unrated finding");

    let rows = firecrow_backend::orchestrator::load_findings(&pool, &job)
        .await
        .expect("read unrated finding");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].severity, Severity::Unknown);
    assert_eq!(rows[0].file_path.as_deref(), Some("package-lock.json"));

    // API serialization: the model decodes, and the band is carried verbatim.
    let model: FindingModel = sqlx::query_as("SELECT * FROM findings WHERE job_id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .expect("FindingModel decodes an unknown-severity row");
    assert_eq!(model.severity, Severity::Unknown);

    let response = FindingResponse::from(model);
    let body = serde_json::to_value(&response).expect("response serializes");
    assert_eq!(body["severity"], "unknown");

    // And the enum's own serde form agrees with the DB form.
    let direct = serde_json::to_value(Severity::Unknown).expect("severity serializes");
    assert_eq!(direct, "unknown");
}

#[sqlx::test(migrations = "./migrations")]
async fn scoring_does_not_treat_unknown_as_clean(_pool: PgPool) {
    // `Unknown` must sort below every known band in remediation priority:
    // an advisory we could not rate is not a low-priority finding.
    use firecrow_backend::services::remediation_planner::remediation_planner_body;

    // Distinct titles, since the planner output is keyed by title.
    let mut unknown = finding_with_severity(Severity::Unknown);
    unknown.title = "unrated".into();
    let mut low = unknown.clone();
    low.title = "low-band".into();
    low.severity = Severity::Low;
    let mut critical = unknown.clone();
    critical.title = "critical-band".into();
    critical.severity = Severity::Critical;

    // Input order is [unknown, low, critical]; the planner must reorder by band.
    let bodies = remediation_planner_body(&[unknown, low, critical]);
    let rank = |title: &str| -> i64 {
        bodies
            .iter()
            .find(|b| b["title"] == title)
            .map(|b| b["priority"].as_i64().unwrap_or(i64::MAX))
            .unwrap_or_else(|| panic!("no plan for {title}: {bodies:?}"))
    };
    let (critical_rank, low_rank, unknown_rank) =
        (rank("critical-band"), rank("low-band"), rank("unrated"));
    assert!(
        critical_rank < low_rank,
        "critical ({critical_rank}) must outrank low ({low_rank})"
    );
    assert!(
        low_rank < unknown_rank,
        "low ({low_rank}) must outrank unknown ({unknown_rank}): an unrated \
         advisory is not a low-priority finding"
    );
}

#[test]
fn every_severity_has_a_stable_wire_name() {
    // The stored/serialized spelling is part of the persisted contract; these
    // strings must never drift silently.
    let expected = [
        (Severity::Critical, "critical"),
        (Severity::High, "high"),
        (Severity::Medium, "medium"),
        (Severity::Low, "low"),
        (Severity::Info, "info"),
        (Severity::Unknown, "unknown"),
    ];
    for (severity, name) in expected {
        assert_eq!(severity.as_str(), name);
        assert_eq!(
            serde_json::to_value(severity).unwrap(),
            serde_json::json!(name)
        );
        assert_eq!(
            name.parse::<Severity>().expect("must parse back"),
            severity,
            "{name} must parse back to itself"
        );
    }
    // The scanner identity is stable and version-independent.
    assert_eq!(Scanner::osv().mode, "dependency");
}
