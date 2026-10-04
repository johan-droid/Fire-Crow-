//! Phase 7: Gitleaks is the first real vulnerability detector.
//!
//! Path under test (no AI, no scoring, no reporting):
//! snapshot -> scanner runtime -> gitleaks -> JSON artifact -> parser ->
//! canonical finding with redacted evidence and no raw secrets.
//!
//! All tests are pure except the final end-to-end, which needs Docker and the
//! pinned gitleaks image (`cargo test -- --ignored`).

use firecrow_backend::agents::scanner::{
    classify, finding_from_gitleaks, gitleaks_fingerprint, parse_gitleaks_report, run_secret_scan,
    ScanInput, Scanner, ScannerOutcome, GITLEAKS_PARSER, GITLEAKS_REPORT_PATH,
};
use firecrow_backend::error::AppError;
use firecrow_backend::services::sandbox::{SandboxManager, SandboxOutput};

const AWS_SECRET: &str = "AKIAIOSFODNN7EXAMPLE";
const GITHUB_TOKEN: &str = "ghp_faketoken0000000000000000000000000001";
const GENERIC_KEY: &str = "sk-live-fake0123456789abcdefABCDEF01";
const DB_PASSWORD: &str = "db-pass-fake-9917-secret";

fn scanner() -> Scanner {
    Scanner::gitleaks()
}

fn input() -> ScanInput {
    ScanInput {
        source_dir: std::env::temp_dir().join("firecrow-gitleaks-fixture"),
        commit_sha: None,
        file_count: 3,
        total_size: 512,
    }
}

/// A finished container run: `success` is the exit code, `stdout` the bytes
/// the `cat` streamed back from the report artifact.
fn run(exit_ok: bool, stdout: &str, stderr: &str) -> Result<SandboxOutput, AppError> {
    Ok(SandboxOutput {
        stdout: stdout.to_string(),
        stderr: stderr.to_string(),
        success: exit_ok,
    })
}

/// One raw report entry, shaped exactly like gitleaks emits (field names and
/// all; see `report/finding.go` at the pinned version).
fn raw_entry(rule: &str, file: &str, line: i64, secret: &str, match_text: &str) -> String {
    serde_json::json!([{
        "Description": format!("{rule} desc"),
        "StartLine": line,
        "EndLine": line,
        "StartColumn": 18,
        "EndColumn": 18 + secret.len() as i64,
        "Match": match_text,
        "Secret": secret,
        "File": file,
        "SymlinkFile": "",
        "Commit": "",
        "Entropy": 4.1,
        "Author": "dev",
        "Email": "dev@example.com",
        "Date": "2024-01-01T00:00:00Z",
        "Message": "add config",
        "Tags": [],
        "RuleID": rule,
        "Fingerprint": format!("{file}:{rule}:{line}"),
    }])
    .to_string()
}

// ---------------------------------------------------------------------------
// 7.9 scanner status: clean / secret / broken / missing / timeout / cancelled
// ---------------------------------------------------------------------------

#[test]
fn clean_repository_is_success_with_zero_findings_and_known_coverage() {
    for body in ["[]", "null", ""] {
        let result = classify(&scanner(), &input(), run(true, body, ""));
        assert_eq!(
            result.outcome,
            ScannerOutcome::Success { finding_count: 0 },
            "clean body {body:?} must be success"
        );
        assert!(result.usable() && result.analyzed());
        assert_eq!(result.execution_record["finding_count"], 0);
    }
}

#[test]
fn exit_1_with_a_valid_report_is_success_not_failure() {
    // The critical Phase 7 semantic: exit 1 means "I found a secret" when a
    // valid report accompanies it. Turning this into FAILED would report a
    // detection as unknown coverage.
    let body = raw_entry(
        "aws-access-token",
        "config/aws.js",
        27,
        AWS_SECRET,
        &format!("AWS_ACCESS_KEY_ID={AWS_SECRET}"),
    );
    let result = classify(&scanner(), &input(), run(false, &body, ""));
    assert_eq!(result.outcome, ScannerOutcome::Success { finding_count: 1 });
    assert!(result.usable() && result.analyzed());
    assert_eq!(result.execution_record["finding_count"], 1);
}

#[test]
fn broken_report_is_failed_with_unknown_coverage() {
    for (exit_ok, body) in [(true, "not json"), (false, "not json"), (true, "[{")] {
        let result = classify(&scanner(), &input(), run(exit_ok, body, ""));
        assert!(
            matches!(result.outcome, ScannerOutcome::Failed { .. }),
            "broken body {body:?} (exit_ok={exit_ok}) must be failed"
        );
        assert!(!result.usable() && !result.analyzed());
        assert_eq!(result.execution_record["coverage"], "unknown");
        assert!(result.execution_record.get("finding_count").is_none());
    }
}

#[test]
fn missing_report_is_failed_never_clean() {
    // The scanner died before the `cat` could stream the artifact: empty
    // bytes on a non-zero exit. This must never read as "no findings".
    let result = classify(&scanner(), &input(), run(false, "", "OOM?"));
    assert!(matches!(result.outcome, ScannerOutcome::Failed { .. }));
    assert!(!result.usable());
    assert_eq!(result.execution_record["detail"], "missing_report");
    assert_eq!(result.execution_record["coverage"], "unknown");
}

#[test]
fn timeout_and_cancel_stay_timeout_and_cancelled() {
    let timeout = classify(&scanner(), &input(), Err(AppError::Timeout("t".into())));
    assert!(matches!(timeout.outcome, ScannerOutcome::Timeout { .. }));
    assert!(!timeout.usable());
    let cancelled = classify(&scanner(), &input(), Err(AppError::Cancelled("c".into())));
    assert_eq!(cancelled.outcome, ScannerOutcome::Cancelled);
    assert!(!cancelled.usable());
}

// ---------------------------------------------------------------------------
// 7.4 raw model: full gitleaks shape parses, unknown fields do not break it
// ---------------------------------------------------------------------------

#[test]
fn full_raw_shape_parses_with_every_gitleaks_field() {
    let body = raw_entry(
        "github-pat",
        "src/token.py",
        7,
        GITHUB_TOKEN,
        &format!("token = \"{GITHUB_TOKEN}\""),
    );
    let parsed = parse_gitleaks_report(&body).expect("full shape must parse");
    assert_eq!(parsed.len(), 1);
    let g = &parsed[0];
    assert_eq!(g.rule_id, "github-pat");
    assert_eq!(g.file, "src/token.py");
    assert_eq!(g.start_line, 7);
    assert_eq!(g.start_column, 18);
    assert_eq!(g.secret, GITHUB_TOKEN);
    assert_eq!(g.author, "dev");
    assert_eq!(g.fingerprint, "src/token.py:github-pat:7");
}

// ---------------------------------------------------------------------------
// 7.10 fixtures: every secret shape redacts; docs/example text still flows
// ---------------------------------------------------------------------------

fn finding_for(secret: &str, match_text: &str) -> firecrow_backend::schemas::audit_state::Finding {
    let body = raw_entry("test-rule", "svc/app.py", 3, secret, match_text);
    let parsed = parse_gitleaks_report(&body).expect("fixture must parse");
    finding_from_gitleaks(&parsed[0])
}

#[test]
fn every_secret_shape_redacts_to_no_raw_credential() {
    for (secret, m) in [
        (AWS_SECRET, format!("AWS_ACCESS_KEY_ID={AWS_SECRET}")),
        (GITHUB_TOKEN, format!("token = \"{GITHUB_TOKEN}\"")),
        (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIFakeKeyBody\n-----END RSA PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIFakeKeyBody\n-----END RSA PRIVATE KEY-----"
                .to_string(),
        ),
        (GENERIC_KEY, format!("api_key={GENERIC_KEY}")),
        (
            DB_PASSWORD,
            format!("postgres://admin:{DB_PASSWORD}@db:5432/app"),
        ),
    ] {
        let f = finding_for(secret, &m);
        let evidence = f.evidence.expect("evidence required");
        assert!(
            !evidence.contains(secret),
            "raw secret leaked for {secret:?}"
        );
        assert!(evidence.contains("[REDACTED]"), "evidence: {evidence}");
    }
}

#[test]
fn documentation_style_reports_are_not_filtered_by_firecrow() {
    // Fire Crow invents no false-positive intelligence: whatever gitleaks
    // reports becomes a finding. Rule quality belongs to gitleaks' config.
    let f = finding_for("docs-fake-value", "example_password=docs-fake-value");
    assert_eq!(f.file_path.as_deref(), Some("svc/app.py"));
    assert!(f.evidence.is_some());
}

// ---------------------------------------------------------------------------
// 7.6 canonical finding, 7.7 evidence, 7.8 fingerprint
// ---------------------------------------------------------------------------

#[test]
fn canonical_finding_carries_traceable_redacted_evidence() {
    let body = raw_entry(
        "aws-access-token",
        "config/aws.js",
        27,
        AWS_SECRET,
        &format!("AWS_ACCESS_KEY_ID={AWS_SECRET}"),
    );
    let result = classify(&scanner(), &input(), run(false, &body, ""));
    assert_eq!(result.findings.len(), 1);
    let f = &result.findings[0];
    assert!(!f.id.trim().is_empty());
    assert_eq!(f.agent_source, "gitleaks");
    assert_eq!(f.scanner_name.as_deref(), Some("gitleaks"));
    assert_eq!(f.scanner_mode.as_deref(), Some("secret"));
    // Gitleaks reports no severity: the Fire Crow default is High, documented
    // on `finding_from_gitleaks` (CWE-798 / A07:2021), never recomputed.
    assert_eq!(f.severity, firecrow_backend::models::Severity::High);
    assert_eq!(f.cwe_id.as_deref(), Some("CWE-798"));
    assert_eq!(f.file_path.as_deref(), Some("config/aws.js"));
    assert_eq!(f.line_number, Some(27));
    let evidence = f.evidence.clone().unwrap_or_default();
    assert!(!evidence.contains(AWS_SECRET));
    assert!(f.description.contains("aws-access-token"));
    let meta: serde_json::Value =
        serde_json::from_str(f.metadata_json.as_deref().unwrap_or("{}")).unwrap();
    assert_eq!(meta["rule_id"], "aws-access-token");
    assert!(!meta["fingerprint"].as_str().unwrap_or_default().is_empty());
}

#[test]
fn fingerprint_is_deterministic_and_holds_no_secret() {
    let a = {
        let parsed =
            parse_gitleaks_report(&raw_entry("r", "f.py", 1, AWS_SECRET, AWS_SECRET)).unwrap();
        gitleaks_fingerprint(&parsed[0], "f.py")
    };
    let b = {
        let parsed =
            parse_gitleaks_report(&raw_entry("r", "f.py", 1, AWS_SECRET, AWS_SECRET)).unwrap();
        gitleaks_fingerprint(&parsed[0], "f.py")
    };
    assert_eq!(a, b, "same leak must fingerprint identically");
    assert!(!a.contains(AWS_SECRET), "fingerprint must hold no secret");
    // Gitleaks' own fingerprint wins when present; the derived form otherwise.
    let parsed = parse_gitleaks_report(&raw_entry("r", "f.py", 1, AWS_SECRET, AWS_SECRET)).unwrap();
    assert!(a.starts_with("gitleaks:"));
    assert_eq!(a, format!("gitleaks:{}", parsed[0].fingerprint));
    let mut no_fp = parsed[0].clone();
    no_fp.fingerprint.clear();
    assert_eq!(gitleaks_fingerprint(&no_fp, "f.py"), "gitleaks:r:f.py:1:18");
}

// ---------------------------------------------------------------------------
// 7.5 + 7.11 logging security: raw secrets never persist, not even in errors
// ---------------------------------------------------------------------------

#[test]
fn raw_secrets_never_persist_in_records_or_errors() {
    // Failure path: stderr echoes the matched line (as gitleaks does at low
    // log levels). The persisted record must be redacted.
    let stderr = format!("leak: AWS_ACCESS_KEY_ID={AWS_SECRET}\nerror: x");
    let failed = classify(&scanner(), &input(), run(false, "garbage{{{", &stderr));
    let record = serde_json::to_string(&failed.execution_record).unwrap();
    assert!(
        !record.contains(AWS_SECRET),
        "stderr secret persisted: {record}"
    );
    assert!(!record.contains("Match") || !record.contains(AWS_SECRET));

    // Success path: neither findings JSON nor the execution record holds raw
    // `Secret`/`Match` material.
    let body = raw_entry(
        "aws-access-token",
        "config/aws.js",
        27,
        AWS_SECRET,
        &format!("AWS_ACCESS_KEY_ID={AWS_SECRET}"),
    );
    let ok_result = classify(&scanner(), &input(), run(false, &body, ""));
    let findings_json = serde_json::to_string(&ok_result.findings).unwrap();
    let record_json = serde_json::to_string(&ok_result.execution_record).unwrap();
    for leaked in [&findings_json, &record_json] {
        assert!(!leaked.contains(AWS_SECRET), "raw secret persisted");
    }
    assert!(!record_json.contains("\"Secret\""));
    assert!(!record_json.contains("\"Match\""));
}

#[test]
fn report_artifact_path_and_parser_are_pinned() {
    assert_eq!(GITLEAKS_REPORT_PATH, "/work/gitleaks.json");
    assert_eq!(GITLEAKS_PARSER, "gitleaks-json-v1");
    assert_eq!(scanner().parser, GITLEAKS_PARSER);
}

// ---------------------------------------------------------------------------
// 7.12 milestone: vulnerable repo -> container -> JSON -> canonical finding
// ---------------------------------------------------------------------------

/// Fixture repository (`backend/test-fixtures/gitleaks`): one planted fake
/// AWS key on a known line. Scanned read-only through the hardened sandbox.
/// Needs Docker + the pinned image: `cargo test --test gitleaks_integration
/// -- --ignored`.
#[tokio::test]
#[ignore]
async fn e2e_real_gitleaks_finds_exactly_one_redacted_secret() {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test-fixtures")
        .join("gitleaks");
    assert!(
        dir.join("leaked-secret.txt").is_file(),
        "fixture missing: {dir:?}"
    );

    let sandbox = SandboxManager::new();
    let input = ScanInput::from_dir(&dir);
    let result = run_secret_scan(&input, &sandbox, &|| false).await;

    assert!(
        result.usable(),
        "scan must succeed: {:?}",
        result.execution_record
    );
    assert_eq!(result.outcome, ScannerOutcome::Success { finding_count: 1 });
    assert_eq!(result.execution_record["finding_count"], 1);

    let f = &result.findings[0];
    assert_eq!(f.scanner_name.as_deref(), Some("gitleaks"));
    assert_eq!(f.scanner_mode.as_deref(), Some("secret"));
    assert_eq!(f.file_path.as_deref(), Some("leaked-secret.txt"));
    assert_eq!(f.line_number, Some(3));
    let evidence = f.evidence.clone().unwrap_or_default();
    assert!(!evidence.contains(AWS_SECRET), "secret leaked: {evidence}");
    assert!(evidence.contains("[REDACTED]"), "evidence: {evidence}");

    // Belt and braces: the whole result surface holds no raw credential.
    let surface = serde_json::to_string(&(&result.findings, &result.execution_record)).unwrap();
    assert!(!surface.contains(AWS_SECRET));
}
