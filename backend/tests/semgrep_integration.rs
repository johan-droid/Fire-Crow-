//! Phase 9: Semgrep source-code analysis.
//!
//! Snapshot -> scanner runtime -> semgrep -> JSON artifact -> private raw
//! model -> canonical source-code findings with exact locations, bounded
//! evidence, and only scanner-backed metadata.
//!
//! Pure tests need no Docker. The end-to-end group needs Docker and the pinned
//! image: `cargo test --test semgrep_integration -- --ignored`.

use firecrow_backend::agents::scanner::{
    classify, execute, findings_from_semgrep, run_sast_scan, semgrep_fingerprint_for_test,
    semgrep_severity, ScanInput, Scanner, ScannerOutcome, SEMGREP_PARSER, SEMGREP_REPORT_PATH,
    SEMGREP_RULESET_PATH, SEMGREP_SCANNER_MODE, SEMGREP_SCANNER_NAME,
};
use firecrow_backend::error::AppError;
use firecrow_backend::models::Severity;
use firecrow_backend::services::sandbox::{
    docker_argv, NetworkMode, SandboxManager, SandboxOutput,
};
use serde_json::json;

fn semgrep() -> Scanner {
    Scanner::semgrep()
}

fn input() -> ScanInput {
    ScanInput {
        source_dir: std::env::temp_dir().join("firecrow-semgrep-fixture"),
        commit_sha: None,
        file_count: 3,
        total_size: 2048,
    }
}

fn run(exit_ok: bool, stdout: &str, stderr: &str) -> Result<SandboxOutput, AppError> {
    Ok(SandboxOutput {
        stdout: stdout.to_string(),
        stderr: stderr.to_string(),
        success: exit_ok,
    })
}

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test-fixtures")
        .join("semgrep")
        .join(name)
}

/// One detection exactly as `semgrep scan --json` emits it, captured from the
/// pinned image rather than written from memory.
fn detection(
    check_id: &str,
    path: &str,
    start_line: i64,
    end_line: i64,
    start_col: i64,
    end_col: i64,
    severity: &str,
) -> serde_json::Value {
    json!({
        "check_id": check_id,
        "path": path,
        "start": {"line": start_line, "col": start_col, "offset": 100},
        "end": {"line": end_line, "col": end_col, "offset": 200},
        "extra": {
            "severity": severity,
            "message": "A SQL query is built by string concatenation.",
            "lines": "    return conn.cursor().execute(\"SELECT ... '\" + user_id + \"'\")",
            "fingerprint": "abc123def456_0",
            "metadata": {
                "category": "security",
                "confidence": "HIGH",
                "likelihood": "HIGH",
                "impact": "HIGH",
                "cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"],
                "owasp": ["A03:2021 - Injection"],
                "references": ["https://cwe.mitre.org/data/definitions/89.html"],
                "technology": ["django"],
            },
        },
    })
}

/// Build a report body. A single detection may be passed as an object and is
/// wrapped here, so a test that expects exactly one finding cannot accidentally
/// pass a malformed `results`.
fn report(results: serde_json::Value, scanned: Vec<&str>) -> String {
    let results = match results {
        serde_json::Value::Array(a) => serde_json::Value::Array(a),
        other => serde_json::Value::Array(vec![other]),
    };
    json!({
        "results": results,
        "paths": {"scanned": scanned},
        "errors": [],
        "version": "1.96.0",
    })
    .to_string()
}

fn meta(f: &firecrow_backend::schemas::audit_state::Finding) -> serde_json::Value {
    serde_json::from_str(f.metadata_json.as_deref().unwrap_or("{}")).unwrap()
}

// ---------------------------------------------------------------------------
// 9.1 descriptor
// ---------------------------------------------------------------------------

#[test]
fn descriptor_is_pinned_and_offline() {
    let s = semgrep();
    assert_eq!(s.name, "semgrep");
    assert_eq!(s.version, "1.96.0");
    assert_eq!(s.mode, "sast");
    assert_eq!(s.mode, SEMGREP_SCANNER_MODE);
    assert_eq!(s.image, "semgrep/semgrep:1.96.0");
    assert!(!s.image.contains("latest"));
    assert_eq!(s.parser, "semgrep-json-v1");
    assert_eq!(s.parser, SEMGREP_PARSER);
    assert_eq!(SEMGREP_REPORT_PATH, "/work/semgrep.json");
    // SAST reads the whole source tree, so it must not be able to send any of
    // it anywhere: no exception, unlike the dependency scanner.
    assert_eq!(s.network, NetworkMode::None);
    assert!(!s.network.is_excepted());
    assert_eq!(s.execution_key(), "semgrep");
}

#[test]
fn descriptor_uses_a_local_pinned_ruleset_and_bounds_everything() {
    let s = semgrep();
    let shell = &s.command[1];
    assert!(
        shell.contains("--config=/config/firecrow-sast.yml"),
        "{shell}"
    );
    assert!(
        shell.contains("--json-output=/work/semgrep.json"),
        "{shell}"
    );
    // A registry ruleset would need the network, and the read-only root needs
    // both a scratch /tmp and a writable HOME.
    assert!(!shell.contains("p/python"), "{shell}");
    assert!(!shell.contains("--config=http"), "{shell}");
    assert_eq!(s.extra_tmpfs, vec!["/tmp".to_string()]);
    assert_eq!(s.env, vec![("HOME".to_string(), "/work".to_string())]);
    // Explicit, bounded resources: larger than the other scanners because it
    // parses whole files, still capped.
    assert_eq!(s.timeout_secs, 600);
    assert_eq!(s.resource_limits.cpus, 2.0);
    assert_eq!(s.resource_limits.memory, "2g");
    assert_eq!(s.resource_limits.pids_limit, 512);
}

#[test]
fn semgrep_inherits_every_hardening_flag_except_egress() {
    let argv = docker_argv(&input().sandbox_spec(&semgrep()), "s");
    for flag in [
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user=65534:65534",
        "--init",
        "--rm",
    ] {
        assert!(argv.contains(&flag.to_string()), "missing {flag}: {argv:?}");
    }
    // Writable scratch stays in memory: the report area plus a `/tmp` for the
    // tool's runtime. The ruleset arrives read-only.
    assert!(argv.iter().any(|a| a.starts_with("/work:rw")));
    assert!(argv.iter().any(|a| a.starts_with("/tmp:rw")));
    // Neither is a host bind: only the snapshot and the ruleset are.
    for writable in ["/work:rw", "/tmp:rw"] {
        assert!(
            !argv.iter().any(|a| a == writable),
            "{writable} must be a tmpfs, not a mount argument"
        );
    }
    assert!(
        argv.iter().any(|a| a.ends_with("/config:ro")),
        "ruleset must be read-only: {argv:?}"
    );
    assert!(
        argv.iter()
            .any(|a| a.ends_with(":ro") && a.contains("semgrep")),
        "snapshot must be read-only: {argv:?}"
    );
}

#[test]
fn the_ruleset_file_is_reproducible_and_present() {
    let path =
        firecrow_backend::agents::scanner::semgrep_ruleset_host_dir().join("firecrow-sast.yml");
    assert!(
        path.is_file(),
        "the pinned ruleset must exist: {}",
        path.display()
    );
    let body = std::fs::read_to_string(&path).expect("read ruleset");
    // Namespaced so a registry id can never collide, and asserted so a rule
    // cannot be added or renamed without this suite noticing.
    for rule in [
        "firecrow.python.sql-injection-concatenation",
        "firecrow.python.command-injection-shell-true",
        "firecrow.python.code-injection-eval",
        "firecrow.python.path-traversal-open",
        "firecrow.python.xss-string-concat-response",
        "firecrow.python.ssrf-request-to-variable-url",
        "firecrow.python.unsafe-deserialization",
        "firecrow.python.weak-cryptographic-hash",
        "firecrow.python.insecure-random-for-secret",
        "firecrow.python.hardcoded-credential-assignment",
    ] {
        assert!(body.contains(rule), "ruleset must define {rule}");
    }
    assert_eq!(
        SEMGREP_RULESET_PATH, "/config/firecrow-sast.yml",
        "descriptor and ruleset must agree on the path"
    );
}

// ---------------------------------------------------------------------------
// 9.16 / 9.17 outcome semantics — the part that cannot be guessed
// ---------------------------------------------------------------------------

#[test]
fn clean_scan_is_success_with_zero_findings() {
    let body = report(json!([]), vec!["/scan/safe.py"]);
    let result = classify(&semgrep(), &input(), run(true, &body, ""));
    assert_eq!(result.outcome, ScannerOutcome::Success { finding_count: 0 });
    assert!(result.usable() && result.analyzed());
    assert_eq!(result.execution_record["finding_count"], 0);
    assert_eq!(result.execution_record["scanned_file_count"], 1);
}

#[test]
fn findings_are_success_regardless_of_exit_code() {
    // Semgrep exits 0 for both clean and findings, so the exit code carries no
    // signal either way; only the report decides.
    let body = report(
        detection("firecrow.python.x", "/scan/a.py", 5, 5, 1, 9, "ERROR"),
        vec!["/scan/a.py"],
    );
    for exit_ok in [true, false] {
        let result = classify(&semgrep(), &input(), run(exit_ok, &body, ""));
        assert_eq!(
            result.outcome,
            ScannerOutcome::Success { finding_count: 1 },
            "exit_ok={exit_ok}"
        );
        assert!(result.usable());
    }
}

#[test]
fn a_run_that_scanned_nothing_is_never_clean() {
    // The silent false negative this phase exists to prevent:
    //   semgrep scanned zero usable files -> results=[] -> "Clean"
    for (body, label) in [
        (report(json!([]), vec![]), "empty repo"),
        (report(json!([]), vec![]), "unsupported file types only"),
    ] {
        let result = classify(&semgrep(), &input(), run(true, &body, ""));
        assert!(
            matches!(result.outcome, ScannerOutcome::Failed { .. }),
            "{label} must not be clean: {:?}",
            result.outcome
        );
        assert!(!result.usable(), "{label}");
        assert_eq!(result.execution_record["detail"], "no_files_analyzed");
        assert!(result.execution_record.get("finding_count").is_none());
    }
}

#[test]
fn a_partial_scan_with_errors_is_failure_even_with_findings() {
    // Verified against the pinned image: errors[] can be non-empty while the
    // report still carries findings. Coverage is unknown, so it must not be
    // reported as a result.
    let body = json!({
        "results": [detection("firecrow.python.x", "/scan/a.py", 5, 5, 1, 9, "ERROR")],
        "paths": {"scanned": ["/scan/a.py"]},
        "errors": [{
            "type": "SemgrepError",
            "code": 7,
            "level": "error",
            "message": "invalid configuration file found (1 configs were invalid)",
        }],
        "version": "1.96.0",
    })
    .to_string();
    let result = classify(&semgrep(), &input(), run(true, &body, ""));
    assert!(matches!(result.outcome, ScannerOutcome::Failed { .. }));
    assert!(!result.usable(), "a partial scan must not produce a report");
    assert_eq!(result.execution_record["detail"], "scanner_errors");
    assert_eq!(result.execution_record["coverage"], "unknown");
    assert!(result.execution_record.get("finding_count").is_none());
    // The error is recorded so an operator can see why.
    assert_eq!(result.execution_record["errors"][0]["code"], 7);
}

#[test]
fn malformed_output_is_failure_never_clean() {
    let cases = [
        ("not json", "garbage"),
        ("{\"results\": [{", "truncated"),
        ("", "missing"),
        ("[]", "top-level array"),
        ("{}", "no results key"),
        (r#"{"results": []}"#, "no paths key"),
        (r#"{"results": "x", "paths": {}}"#, "wrong results type"),
    ];
    for (body, label) in cases {
        let result = classify(&semgrep(), &input(), run(true, body, ""));
        assert!(
            matches!(result.outcome, ScannerOutcome::Failed { .. }),
            "{label} must fail: {:?}",
            result.outcome
        );
        assert!(!result.usable() && !result.analyzed(), "{label}");
        assert!(
            result.execution_record.get("finding_count").is_none(),
            "{label}"
        );
    }
}

#[test]
fn timeout_is_timeout_and_cancel_is_cancelled() {
    let timeout = classify(&semgrep(), &input(), Err(AppError::Timeout("t".into())));
    assert!(matches!(timeout.outcome, ScannerOutcome::Timeout { .. }));
    assert_eq!(timeout.execution_record["coverage"], "unknown");

    let cancelled = classify(&semgrep(), &input(), Err(AppError::Cancelled("c".into())));
    assert_eq!(cancelled.outcome, ScannerOutcome::Cancelled);
    assert!(!cancelled.usable());
}

#[tokio::test]
async fn cancel_before_start_never_launches_semgrep() {
    let sandbox = SandboxManager::new();
    let result = execute(&semgrep(), &input(), &sandbox, &|| true).await;
    assert_eq!(result.outcome, ScannerOutcome::Cancelled);
    let live = run_sast_scan(&input(), &sandbox, &|| true).await;
    assert_eq!(live.outcome, ScannerOutcome::Cancelled);
}

// ---------------------------------------------------------------------------
// 9.4 / 9.5 / 9.6 identity, location, bounded evidence
// ---------------------------------------------------------------------------

#[test]
fn check_id_is_preserved_verbatim() {
    let body = report(
        detection(
            "rules.firecrow.python.sql-injection-concatenation",
            "/scan/src/app.py",
            21,
            21,
            12,
            85,
            "ERROR",
        ),
        vec!["/scan/src/app.py"],
    );
    let result = classify(&semgrep(), &input(), run(true, &body, ""));
    let f = &result.findings[0];
    assert_eq!(f.agent_source, SEMGREP_SCANNER_NAME);
    assert_eq!(f.scanner_name.as_deref(), Some("semgrep"));
    assert_eq!(f.scanner_mode.as_deref(), Some("sast"));
    assert_eq!(f.title, "rules.firecrow.python.sql-injection-concatenation");
    let m = meta(f);
    assert_eq!(
        m["rule_id"],
        "rules.firecrow.python.sql-injection-concatenation"
    );
    assert_eq!(
        m["check_id"],
        "rules.firecrow.python.sql-injection-concatenation"
    );
}

#[test]
fn multiline_findings_keep_their_whole_range() {
    let body = report(
        detection(
            "firecrow.python.cmd",
            "/scan/multi.py",
            5,
            8,
            9,
            10,
            "ERROR",
        ),
        vec!["/scan/multi.py"],
    );
    let result = classify(&semgrep(), &input(), run(true, &body, ""));
    let f = &result.findings[0];
    // Anchored at the start line, with the range preserved alongside it.
    assert_eq!(f.line_number, Some(5));
    let m = meta(f);
    assert_eq!(m["start_line"], 5);
    assert_eq!(m["end_line"], 8);
    assert_eq!(m["start_column"], 9);
    assert_eq!(m["end_column"], 10);
}

#[test]
fn evidence_is_bounded_and_the_source_is_not_a_payload_bomb() {
    // A huge match must not become a huge database row or API response.
    let mut result = detection("firecrow.python.big", "/scan/min.js", 1, 1, 1, 2, "WARNING");
    result["extra"]["lines"] = json!("x".repeat(200_000));
    let body = report(result, vec!["/scan/min.js"]);
    let outcome = classify(&semgrep(), &input(), run(true, &body, ""));
    let evidence = outcome.findings[0].evidence.clone().unwrap_or_default();
    assert!(
        evidence.len() < 1_000,
        "evidence was {} bytes",
        evidence.len()
    );
    assert!(evidence.contains("truncated"), "{evidence}");

    // And the whole canonical finding stays small.
    let json = serde_json::to_string(&outcome.findings).unwrap();
    assert!(
        json.len() < 4_000,
        "finding serialized to {} bytes",
        json.len()
    );
}

#[test]
fn a_multiline_snippet_stays_readable() {
    let mut result = detection("firecrow.python.x", "/scan/m.py", 1, 4, 1, 2, "ERROR");
    result["extra"]["lines"] = json!("subprocess.call(\n    \"ls \" + u,\n    shell=True,\n)");
    let body = report(result, vec!["/scan/m.py"]);
    let outcome = classify(&semgrep(), &input(), run(true, &body, ""));
    let evidence = outcome.findings[0].evidence.clone().unwrap_or_default();
    assert!(evidence.contains("shell=True"), "{evidence}");
}

// ---------------------------------------------------------------------------
// 9.7 / 9.8 / 9.9 / 9.10 / 9.11 scanner-backed metadata only
// ---------------------------------------------------------------------------

#[test]
fn cwe_and_owasp_are_preserved_when_supplied() {
    let body = report(
        detection("firecrow.python.x", "/scan/a.py", 1, 1, 1, 2, "ERROR"),
        vec!["/scan/a.py"],
    );
    let result = classify(&semgrep(), &input(), run(true, &body, ""));
    let f = &result.findings[0];
    assert_eq!(f.cwe_id.as_deref(), Some("CWE-89"));
    assert_eq!(f.owasp_category.as_deref(), Some("A03:2021"));
    let m = meta(f);
    // The rule's full strings survive for a renderer that wants the prose.
    assert_eq!(
        m["cwe"][0],
        "CWE-89: Improper Neutralization of Special Elements used in an SQL Command"
    );
    assert_eq!(m["owasp"][0], "A03:2021 - Injection");
}

#[test]
fn absent_metadata_stays_absent_never_inferred() {
    let mut result = detection("firecrow.python.bare", "/scan/a.py", 1, 1, 1, 2, "ERROR");
    result["extra"]["metadata"] = json!({});
    let body = report(result, vec!["/scan/a.py"]);
    let outcome = classify(&semgrep(), &input(), run(true, &body, ""));
    let f = &outcome.findings[0];
    assert!(
        f.cwe_id.is_none(),
        "cwe must not be invented from the rule name"
    );
    assert!(f.owasp_category.is_none(), "owasp must not be invented");
    assert!(f.confidence.is_none(), "confidence must not be invented");
    let m = meta(f);
    for key in ["cwe", "owasp", "confidence", "likelihood", "impact"] {
        assert!(m.get(key).is_none(), "{key} must be absent, got {m}");
    }
}

#[test]
fn severity_mapping_is_explicit_and_total() {
    for (scanner_band, expected) in [
        ("ERROR", Severity::Critical),
        ("error", Severity::Critical),
        ("WARNING", Severity::Medium),
        ("warning", Severity::Medium),
        ("INFO", Severity::Low),
        ("info", Severity::Low),
    ] {
        assert_eq!(semgrep_severity(scanner_band), expected, "{scanner_band}");
    }
    // Unrecognized is Unknown, never promoted to a guessed band.
    for value in ["", "SEVERE", "unknown", "3", "CRITICAL"] {
        assert_eq!(
            semgrep_severity(value),
            Severity::Unknown,
            "{value:?} must not be guessed"
        );
    }
}

#[test]
fn scanner_severity_is_preserved_beside_the_mapped_band() {
    for band in ["ERROR", "WARNING", "SEVERE"] {
        let body = report(
            detection("firecrow.python.x", "/scan/a.py", 1, 1, 1, 2, band),
            vec!["/scan/a.py"],
        );
        let result = classify(&semgrep(), &input(), run(true, &body, ""));
        assert_eq!(meta(&result.findings[0])["scanner_severity"], band);
    }
}

#[test]
fn confidence_comes_from_the_rule_not_from_field_completeness() {
    let mut with = detection("firecrow.python.x", "/scan/a.py", 1, 1, 1, 2, "ERROR");
    with["extra"]["metadata"]["confidence"] = json!("MEDIUM");
    let body = report(with, vec!["/scan/a.py"]);
    let result = classify(&semgrep(), &input(), run(true, &body, ""));
    assert_eq!(result.findings[0].confidence.as_deref(), Some("MEDIUM"));

    // A rule that declares no confidence yields none, even though the finding
    // is otherwise complete. A completeness heuristic would say "high" here.
    let mut without = detection("firecrow.python.x", "/scan/a.py", 1, 1, 1, 2, "ERROR");
    without["extra"]["metadata"] = json!({"category": "security"});
    let body = report(without, vec!["/scan/a.py"]);
    let result = classify(&semgrep(), &input(), run(true, &body, ""));
    assert!(result.findings[0].confidence.is_none());
}

#[test]
fn an_autofix_is_recorded_as_a_scanner_suggestion_never_as_remediation() {
    let mut result = detection("firecrow.python.x", "/scan/a.py", 1, 1, 1, 2, "WARNING");
    result["extra"]["metadata"]["fix"] = json!("- bad()\n+ good()");
    let body = report(result, vec!["/scan/a.py"]);
    let outcome = classify(&semgrep(), &input(), run(true, &body, ""));
    let f = &outcome.findings[0];
    assert!(
        f.remediation.is_none(),
        "an unverified autofix must not become a remediation claim"
    );
    let suggestion = &meta(f)["scanner_suggestion"];
    assert_eq!(suggestion["kind"], "autofix");
    assert_eq!(suggestion["unverified"], true);
    assert!(suggestion["diff"].as_str().unwrap().contains("good()"));
}

// ---------------------------------------------------------------------------
// 9.12 references, 9.13 fingerprint, 9.14 dedup, 9.18 validation
// ---------------------------------------------------------------------------

#[test]
fn references_are_normalized_to_type_and_url() {
    let mut result = detection("firecrow.python.x", "/scan/a.py", 1, 1, 1, 2, "ERROR");
    result["extra"]["metadata"]["references"] = json!([
        "https://b.example/2",
        "https://a.example/1",
        "https://b.example/2",
        "  "
    ]);
    let body = report(result, vec!["/scan/a.py"]);
    let outcome = classify(&semgrep(), &input(), run(true, &body, ""));
    assert_eq!(
        meta(&outcome.findings[0])["references"],
        json!([
            {"type": "WEB", "url": "https://a.example/1"},
            {"type": "WEB", "url": "https://b.example/2"},
        ])
    );
}

#[test]
fn fingerprint_prefers_semgreps_own_and_falls_back_deterministically() {
    let dir = &fixture("clean");
    let body = report(
        json!([
            detection("firecrow.python.x", "/scan/a.py", 5, 5, 1, 9, "ERROR"),
            json!({
                "check_id": "firecrow.python.x",
                "path": "/scan/a.py",
                "start": {"line": 5, "col": 1},
                "end": {"line": 5, "col": 9},
                "extra": {"severity": "ERROR", "message": "m", "lines": "l", "metadata": {}},
            }),
        ]),
        vec!["/scan/a.py"],
    );
    let parsed = findings_from_semgrep(&body, dir).unwrap();
    assert_eq!(parsed.valid.len(), 2);

    // The tool's own value when present, a derived value when not — asserted
    // through the same public door the adapter uses.
    assert_eq!(meta(&parsed.valid[0])["fingerprint_source"], "semgrep");
    assert_eq!(meta(&parsed.valid[1])["fingerprint_source"], "derived");
    assert_eq!(
        meta(&parsed.valid[0])["fingerprint"],
        serde_json::json!(semgrep_fingerprint_for_test(
            "firecrow.python.x",
            "abc123def456_0",
            "a.py",
            5,
            1,
            5,
            9,
        )),
        "the tool fingerprint is preferred"
    );
    assert_eq!(
        meta(&parsed.valid[1])["fingerprint"],
        serde_json::json!(semgrep_fingerprint_for_test(
            "firecrow.python.x",
            "",
            "a.py",
            5,
            1,
            5,
            9
        )),
        "derived fingerprints run through the same public door"
    );
    // And the derived value is stable across identical reports.
    let again = findings_from_semgrep(&body, dir).unwrap();
    assert_eq!(
        meta(&parsed.valid[1])["fingerprint"],
        meta(&again.valid[1])["fingerprint"],
        "derived fingerprints must be stable"
    );
}

#[test]
fn two_rules_at_one_location_stay_distinct() {
    // Two different rules on the same file and line must not collapse, which
    // is why the derived fingerprint includes the rule and the columns.
    let body = report(
        json!([
            detection(
                "firecrow.python.rule-a",
                "/scan/a.py",
                20,
                20,
                1,
                10,
                "ERROR"
            ),
            detection(
                "firecrow.python.rule-b",
                "/scan/a.py",
                20,
                20,
                1,
                10,
                "WARNING"
            ),
        ]),
        vec!["/scan/a.py"],
    );
    let parsed = findings_from_semgrep(&body, &fixture("clean")).unwrap();
    assert_eq!(parsed.valid.len(), 2);
    let fps: std::collections::HashSet<String> = parsed
        .valid
        .iter()
        .map(|f| {
            meta(f)["fingerprint"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    assert_eq!(fps.len(), 2, "fingerprints must differ");

    use firecrow_backend::orchestrator::{dedupe_findings, finding_fingerprint};
    let keys: std::collections::HashSet<String> =
        parsed.valid.iter().map(finding_fingerprint).collect();
    assert_eq!(keys.len(), 2, "pipeline dedupe must keep both");
    assert_eq!(dedupe_findings(parsed.valid).len(), 2);
}

#[test]
fn an_exact_duplicate_deduplicates() {
    let one = detection("firecrow.python.x", "/scan/a.py", 20, 20, 1, 10, "ERROR");
    let body = report(json!([one.clone(), one]), vec!["/scan/a.py"]);
    let parsed = findings_from_semgrep(&body, &fixture("clean")).unwrap();
    assert_eq!(parsed.valid.len(), 2, "parser keeps both");
    use firecrow_backend::orchestrator::dedupe_findings;
    assert_eq!(
        dedupe_findings(parsed.valid).len(),
        1,
        "the pipeline collapses the duplicate"
    );
}

#[test]
fn invalid_locations_are_quarantined_not_repaired() {
    let cases = [
        (json!({}), "missing check_id"),
        (
            json!({"check_id": "r", "path": "", "start": {"line": 1}, "end": {"line": 1}}),
            "missing path",
        ),
        (
            json!({"check_id": "r", "path": "/scan/a.py", "start": {"line": 0}, "end": {"line": 1}}),
            "start line is not positive",
        ),
        (
            json!({"check_id": "r", "path": "/scan/a.py", "start": {"line": -3}, "end": {"line": 1}}),
            "start line is not positive",
        ),
        (
            json!({"check_id": "r", "path": "/scan/a.py", "start": {"line": 9}, "end": {"line": 4}}),
            "end line precedes start line",
        ),
    ];
    for (result, reason) in cases {
        let body = report(result, vec!["/scan/a.py"]);
        let parsed = findings_from_semgrep(&body, &fixture("clean")).unwrap();
        assert!(parsed.valid.is_empty(), "{reason} must not be stored");
        assert_eq!(parsed.rejected.len(), 1, "{reason}");
        assert_eq!(parsed.rejected[0].2, reason);
    }

    // A mixed report keeps the good detections and records the refusals.
    let body = report(
        json!([
            detection("firecrow.python.good", "/scan/a.py", 4, 4, 1, 2, "ERROR"),
            json!({"check_id": "firecrow.python.bad", "path": "/scan/a.py",
                   "start": {"line": 0}, "end": {"line": 1}}),
        ]),
        vec!["/scan/a.py"],
    );
    let outcome = classify(&semgrep(), &input(), run(true, &body, ""));
    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(outcome.execution_record["rejected_count"], 1);
    assert_eq!(
        outcome.execution_record["rejected"][0]["reason"],
        "start line is not positive"
    );
}

// ---------------------------------------------------------------------------
// 9.3 raw model isolation, 9.17 logging safety
// ---------------------------------------------------------------------------

#[test]
fn raw_model_does_not_escape_the_adapter() {
    // The canonical metadata is a curated subset: semgrep's internals
    // (byte offsets, metavariables, engine kind, validation state) stay inside
    // the adapter.
    let body = report(
        detection("firecrow.python.x", "/scan/a.py", 5, 5, 1, 9, "ERROR"),
        vec!["/scan/a.py"],
    );
    let result = classify(&semgrep(), &input(), run(true, &body, ""));
    let serialized = serde_json::to_string(&result.findings).unwrap();
    let m = meta(&result.findings[0]);
    for internal in [
        "metavars",
        "abstract_content",
        "engine_kind",
        "validation_state",
        "is_ignored",
        "offset",
    ] {
        assert!(
            !serialized.contains(internal),
            "raw field {internal} escaped: {serialized}"
        );
    }
    let mut keys: Vec<&str> = m.as_object().unwrap().keys().map(|s| s.as_str()).collect();
    keys.sort();
    // Phase 10 adds four run-provenance keys (`scanner_version`, `parser`,
    // `scanner_image`, `snapshot_commit`). They are curated run facts, not
    // semgrep internals, and Phase 10 requires a finding to stay traceable to
    // the exact scanner/parser run that produced it. The isolation property
    // this test protects — no raw model fields above — is unchanged.
    assert_eq!(
        keys,
        vec![
            "category",
            "check_id",
            "confidence",
            "cwe",
            "end_column",
            "end_line",
            "fingerprint",
            "fingerprint_source",
            "impact",
            "likelihood",
            "owasp",
            "parser",
            "references",
            "rule_id",
            "scanner_image",
            "scanner_severity",
            "scanner_version",
            "snapshot_commit",
            "start_column",
            "start_line",
            "technology",
        ],
        "metadata keys drifted"
    );
    // The provenance a canonical finding must be able to report back.
    for key in [
        "scanner_version",
        "parser",
        "scanner_image",
        "snapshot_commit",
    ] {
        assert!(
            m.get(key).is_some(),
            "run provenance {key} must survive normalization"
        );
    }
}

#[test]
fn stderr_is_bounded_and_sanitized() {
    let long = format!("x{}", "y".repeat(10_000));
    let failed = classify(&semgrep(), &input(), run(false, "garbage", &long));
    let record = serde_json::to_string(&failed.execution_record).unwrap();
    assert!(record.len() < 8_000, "stderr must stay bounded");

    // A source fragment echoed by a scanner error is redacted like any other
    // diagnostic that could carry a credential.
    let leaked = classify(
        &semgrep(),
        &input(),
        run(
            false,
            "garbage",
            "context line: token = ghp_faketoken0000000000000000000000000001",
        ),
    );
    let record = serde_json::to_string(&leaked.execution_record).unwrap();
    assert!(!record.contains("ghp_faketoken"), "{record}");
}

// ---------------------------------------------------------------------------
// 9.19 live end-to-end (ignored)
// ---------------------------------------------------------------------------

fn live_input(name: &str) -> ScanInput {
    let dir = fixture(name);
    assert!(dir.is_dir(), "fixture missing: {dir:?}");
    ScanInput::from_dir(&dir)
}

fn meta_of(f: &firecrow_backend::schemas::audit_state::Finding) -> serde_json::Value {
    meta(f)
}

#[tokio::test]
#[ignore]
async fn e2e_vulnerable_fixture_produces_canonical_findings() {
    let sandbox = SandboxManager::new();
    let result = run_sast_scan(&live_input("vulnerable"), &sandbox, &|| false).await;
    assert!(
        result.usable(),
        "scan must succeed: {:?}",
        result.execution_record
    );
    assert_eq!(result.execution_record["scanner"], "semgrep");
    assert_eq!(result.execution_record["parser"], "semgrep-json-v1");
    assert!(
        result.execution_record["scanned_file_count"]
            .as_u64()
            .unwrap_or(0)
            >= 1
    );
    assert!(
        result.findings.len() >= 7,
        "got {} findings",
        result.findings.len()
    );

    // Every finding family the fixture plants is detected with its own rule id.
    let mut rules: std::collections::HashSet<String> = std::collections::HashSet::new();
    for f in &result.findings {
        rules.insert(f.title.clone());
        assert_eq!(f.file_path.as_deref(), Some("vuln.py"));
        assert!(f.line_number.unwrap_or(0) > 0);
        assert!(f.evidence.as_deref().unwrap_or_default().len() < 1_000);
        assert!(meta_of(f)["fingerprint"]
            .as_str()
            .unwrap()
            .starts_with("semgrep:"));
        assert_eq!(f.scanner_name.as_deref(), Some("semgrep"));
    }
    for expected in [
        "firecrow.python.sql-injection-concatenation",
        "firecrow.python.command-injection-shell-true",
        "firecrow.python.code-injection-eval",
        "firecrow.python.path-traversal-open",
        "firecrow.python.unsafe-deserialization",
        "firecrow.python.weak-cryptographic-hash",
        "firecrow.python.hardcoded-credential-assignment",
    ] {
        assert!(
            rules.iter().any(|r| r.ends_with(expected)),
            "missing rule {expected}: {rules:?}"
        );
    }

    // Scanner-backed metadata is preserved, not invented.
    let sqli = result
        .findings
        .iter()
        .find(|f| f.title.ends_with("sql-injection-concatenation"))
        .expect("sql injection finding");
    assert_eq!(sqli.severity, Severity::Critical);
    assert_eq!(sqli.cwe_id.as_deref(), Some("CWE-89"));
    assert_eq!(sqli.owasp_category.as_deref(), Some("A03:2021"));
    assert_eq!(sqli.confidence.as_deref(), Some("HIGH"));
    assert_eq!(meta_of(sqli)["scanner_severity"], "ERROR");

    // Multiline evidence stays bounded but complete.
    let md5 = result
        .findings
        .iter()
        .find(|f| f.title.ends_with("weak-cryptographic-hash"))
        .expect("md5 finding");
    assert!(md5.evidence.as_deref().unwrap().contains("hashlib.md5"));
}

#[tokio::test]
#[ignore]
async fn e2e_clean_fixture_proves_the_ruleset_discriminates() {
    // Not a zero-finding assertion: the SSRF rule is deliberately syntactic
    // and reports a guarded call (see test-fixtures/semgrep/README.md). What
    // matters is that the seven families exercised by the fixture do not fire.
    let sandbox = SandboxManager::new();
    let result = run_sast_scan(&live_input("clean"), &sandbox, &|| false).await;
    assert!(
        result.usable(),
        "clean fixture must scan: {:?}",
        result.execution_record
    );
    assert_eq!(
        result.outcome,
        ScannerOutcome::Success {
            finding_count: result.findings.len()
        }
    );

    let fired: Vec<String> = result.findings.iter().map(|f| f.title.clone()).collect();
    for must_not_fire in [
        "sql-injection-concatenation",
        "command-injection-shell-true",
        "code-injection-eval",
        "path-traversal-open",
        "xss-string-concat-response",
        "unsafe-deserialization",
        "weak-cryptographic-hash",
        "hardcoded-credential-assignment",
    ] {
        assert!(
            !fired.iter().any(|r| r.contains(must_not_fire)),
            "{must_not_fire} fired on the safe fixture: {fired:?}"
        );
    }
}

#[tokio::test]
#[ignore]
async fn e2e_empty_repository_is_never_reported_clean() {
    // The silent false negative, end to end: semgrep analyzes nothing and
    // exits 0. Fire Crow must refuse to call that clean.
    let sandbox = SandboxManager::new();
    let result = run_sast_scan(&live_input("empty"), &sandbox, &|| false).await;
    assert!(
        matches!(result.outcome, ScannerOutcome::Failed { .. }),
        "an empty repository must not be clean: {:?}",
        result.execution_record
    );
    assert!(!result.usable());
    assert_eq!(result.execution_record["detail"], "no_files_analyzed");
    assert!(result.execution_record.get("finding_count").is_none());
}
