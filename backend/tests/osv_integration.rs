//! Phase 8: OSV-Scanner dependency detection alongside Gitleaks.
//!
//! Snapshot -> scanner runtime -> osv-scanner -> JSON artifact -> parser ->
//! canonical dependency findings with evidence, provenance, and fingerprints.
//!
//! All tests are pure except the end-to-end group, which needs Docker, the
//! pinned image, and egress to the OSV database:
//! `cargo test --test osv_integration -- --ignored`.

use firecrow_backend::agents::scanner::{
    classify, execute, findings_from_osv, osv_fingerprint, run_dependency_scan, ScanInput, Scanner,
    ScannerOutcome, OSV_PARSER, OSV_REPORT_PATH, OSV_SCANNER_MODE, OSV_SCANNER_NAME,
};
use firecrow_backend::error::AppError;
use firecrow_backend::models::Severity;
use firecrow_backend::services::sandbox::{docker_argv, SandboxManager, SandboxOutput};
use serde_json::json;

fn osv() -> Scanner {
    Scanner::osv()
}

fn input() -> ScanInput {
    ScanInput {
        source_dir: std::env::temp_dir().join("firecrow-osv-fixture"),
        commit_sha: None,
        file_count: 4,
        total_size: 1024,
    }
}

fn run(exit_ok: bool, stdout: &str, stderr: &str) -> Result<SandboxOutput, AppError> {
    Ok(SandboxOutput {
        stdout: stdout.to_string(),
        stderr: stderr.to_string(),
        success: exit_ok,
    })
}

fn fixture_dir(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test-fixtures")
        .join("osv")
        .join(name)
}

/// One lockfile source with one vulnerable package and one alias-group,
/// shaped like `osv-scanner scan source --format=json` emits.
fn vuln_doc() -> String {
    serde_json::json!({
        "results": [{
            "source": {"path": "/scan/package-lock.json", "type": "lockfile"},
            "packages": [{
                "package": {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
                "vulnerabilities": [
                    {
                        "id": "GHSA-4xc9-xhrj-v574",
                        "aliases": ["CVE-2020-8203"],
                        "summary": "Prototype pollution in lodash.",
                        "severity": [],
                        "affected": [{
                            "package": {"ecosystem": "npm", "name": "lodash"},
                            "ranges": [{
                                "type": "SEMVER",
                                "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]
                            }]
                        }],
                        "references": [{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-4xc9-xhrj-v574"}],
                        "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-1321"]}
                    },
                    {
                        "id": "CVE-2020-8203",
                        "aliases": ["GHSA-4xc9-xhrj-v574"],
                        "summary": "Prototype pollution in lodash.",
                        "severity": [],
                        "affected": [{
                            "package": {"ecosystem": "npm", "name": "lodash"},
                            "ranges": [{
                                "type": "SEMVER",
                                "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]
                            }]
                        }],
                        "references": [{"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-8203"}],
                        "database_specific": {}
                    }
                ],
                "groups": [{"ids": ["GHSA-4xc9-xhrj-v574", "CVE-2020-8203"]}]
            }]
        }]
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// 8.1 descriptor: pinned, explicit, egress-declared
// ---------------------------------------------------------------------------

#[test]
fn osv_descriptor_is_pinned_and_explicit() {
    let s = osv();
    assert_eq!(s.name, "osv");
    assert_eq!(s.version, "2.2.4");
    assert_eq!(s.mode, "dependency");
    assert_eq!(s.image, "ghcr.io/google/osv-scanner:v2.2.4");
    assert!(!s.image.contains("latest"));
    assert_eq!(s.parser, "osv-json-v1");
    assert_eq!(s.parser, OSV_PARSER);
    assert_eq!(s.timeout_secs, 300);
    // The report is a file artifact on scratch, streamed back with `cat`.
    assert_eq!(s.entrypoint, Some("sh"));
    let shell = &s.command[1];
    assert!(shell.contains("/osv-scanner scan source"), "shell: {shell}");
    assert!(shell.contains("--recursive"), "shell: {shell}");
    assert!(shell.contains("--format=json"), "shell: {shell}");
    assert!(shell.contains("--output=/work/osv.json"), "shell: {shell}");
    assert!(shell.contains("/scan"), "shell: {shell}");
    assert_eq!(s.execution_key(), "osv");
    assert_eq!(OSV_REPORT_PATH, "/work/osv.json");
}

#[test]
fn egress_belongs_to_osv_only() {
    // Deny-by-default with one declared exception (see `NetworkMode`).
    // Gitleaks stays fully offline; only OSV reaches the live database.
    use firecrow_backend::services::sandbox::NetworkMode;

    assert_eq!(Scanner::gitleaks().network, NetworkMode::None);
    assert!(!Scanner::gitleaks().network.is_excepted());
    assert_eq!(osv().network, NetworkMode::Bridge);
    assert!(osv().network.is_excepted());

    let gitleaks_argv = docker_argv(&input().sandbox_spec(&Scanner::gitleaks()), "g");
    assert!(gitleaks_argv.iter().any(|a| a == "--network=none"));
    assert!(!gitleaks_argv.iter().any(|a| a.contains("network=bridge")));

    let osv_argv = docker_argv(&input().sandbox_spec(&osv()), "o");
    assert!(osv_argv.iter().any(|a| a == "--network=bridge"));
    assert!(!osv_argv.iter().any(|a| a == "--network=none"));
}

// ---------------------------------------------------------------------------
// 8.9 exit semantics, 8.10 clean, 8.15 malformed, 8.16 timeout/cancel
// ---------------------------------------------------------------------------

#[test]
fn clean_scan_is_success() {
    for body in [
        r#"{"results": null}"#,
        r#"{"results": []}"#,
        r#"{"results": [{"source": {"path": "/scan/package-lock.json", "type": "lockfile"}, "packages": []}]}"#,
    ] {
        let result = classify(&osv(), &input(), run(true, body, ""));
        assert_eq!(
            result.outcome,
            ScannerOutcome::Success { finding_count: 0 },
            "clean body {body:?}"
        );
        assert!(result.usable() && result.analyzed());
    }
}

#[test]
fn valid_report_with_vulns_is_success_on_any_vuln_exit() {
    // Exit 1 means "vulnerabilities found", not failure — same doctrine as
    // gitleaks. Only the report decides.
    for exit_ok in [true, false] {
        let result = classify(&osv(), &input(), run(exit_ok, &vuln_doc(), ""));
        assert_eq!(
            result.outcome,
            ScannerOutcome::Success { finding_count: 1 },
            "exit_ok={exit_ok}"
        );
        assert!(result.usable());
    }
}

#[test]
fn invalid_json_is_failure() {
    for body in [
        "not json",
        "[{\"results\":",
        &vuln_doc()[..vuln_doc().len() / 2],
    ] {
        let result = classify(&osv(), &input(), run(false, body, ""));
        assert!(
            matches!(result.outcome, ScannerOutcome::Failed { .. }),
            "body {body:?}"
        );
        assert!(!result.usable() && !result.analyzed());
        assert_eq!(result.execution_record["coverage"], "unknown");
        assert!(result.execution_record.get("finding_count").is_none());
    }
}

#[test]
fn unexpected_schema_is_failure_never_clean() {
    for body in ["[]", "null", "42", r#"{"result": []}"#] {
        let result = classify(&osv(), &input(), run(true, body, ""));
        assert!(
            matches!(result.outcome, ScannerOutcome::Failed { .. }),
            "schema {body:?} must fail, got {:?}",
            result.outcome
        );
        assert!(!result.usable());
    }
}

#[test]
fn missing_report_is_failure_never_clean() {
    let result = classify(&osv(), &input(), run(false, "", "boom"));
    assert!(matches!(result.outcome, ScannerOutcome::Failed { .. }));
    assert_eq!(result.execution_record["detail"], "missing_report");
    assert!(!result.usable());
}

#[test]
fn timeout_is_timeout() {
    let result = classify(&osv(), &input(), Err(AppError::Timeout("t".into())));
    assert!(matches!(result.outcome, ScannerOutcome::Timeout { .. }));
    assert!(!result.usable());
    assert_eq!(result.execution_record["coverage"], "unknown");
}

#[test]
fn cancel_is_cancelled() {
    let result = classify(&osv(), &input(), Err(AppError::Cancelled("c".into())));
    assert_eq!(result.outcome, ScannerOutcome::Cancelled);
    assert!(!result.usable());
}

#[tokio::test]
async fn cancel_before_start_never_launches_the_scanner() {
    let sandbox = SandboxManager::new();
    let result = execute(&osv(), &input(), &sandbox, &|| true).await;
    assert_eq!(result.outcome, ScannerOutcome::Cancelled);
    let live = run_dependency_scan(&input(), &sandbox, &|| true).await;
    assert_eq!(live.outcome, ScannerOutcome::Cancelled);
}

// ---------------------------------------------------------------------------
// 8.4/8.5/8.6 canonical dependency finding: evidence, location, identity
// ---------------------------------------------------------------------------

#[test]
fn vulnerable_dependency_is_success() {
    let result = classify(&osv(), &input(), run(false, &vuln_doc(), ""));
    assert_eq!(result.outcome, ScannerOutcome::Success { finding_count: 1 });
    let f = &result.findings[0];
    assert_eq!(f.agent_source, OSV_SCANNER_NAME);
    assert_eq!(f.scanner_name.as_deref(), Some("osv"));
    assert_eq!(f.scanner_mode.as_deref(), Some("dependency"));
    assert_eq!(f.scanner_mode.as_deref(), Some(OSV_SCANNER_MODE));
    assert_eq!(
        f.title,
        "Vulnerable dependency: lodash 4.17.20 (GHSA-4xc9-xhrj-v574)"
    );
    // Location is the manifest, not a code line.
    assert_eq!(f.file_path.as_deref(), Some("package-lock.json"));
    assert!(f.line_number.is_some());
    let evidence = f.evidence.clone().unwrap_or_default();
    assert!(evidence.contains("lodash"));
    assert!(evidence.contains("4.17.20"));
    assert!(evidence.contains("GHSA-4xc9-xhrj-v574"));
    assert!(evidence.contains("4.17.21"));
    assert!(evidence.contains("package-lock.json"));
    // Advisory identity: primary + aliases, no manufactured CVEs.
    let meta: serde_json::Value =
        serde_json::from_str(f.metadata_json.as_deref().unwrap_or("{}")).unwrap();
    assert_eq!(meta["advisory"], "GHSA-4xc9-xhrj-v574");
    assert_eq!(meta["rule_id"], "GHSA-4xc9-xhrj-v574");
    assert_eq!(meta["ecosystem"], "npm");
    assert_eq!(meta["package"], "lodash");
    assert_eq!(meta["installed_version"], "4.17.20");
    assert_eq!(meta["manifest"], "package-lock.json");
    let aliases: Vec<&str> = meta["aliases"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(aliases, vec!["CVE-2020-8203"]);
    // Structured ranges preserved, not prose.
    assert_eq!(meta["fixed_versions"], serde_json::json!(["4.17.21"]));
    assert_eq!(meta["affected"][0]["ranges"][0]["type"], "SEMVER");
    assert_eq!(
        meta["affected"][0]["ranges"][0]["events"][1]["fixed"],
        "4.17.21"
    );
}

#[test]
fn multiple_vulnerabilities_yield_multiple_findings() {
    let mut doc: serde_json::Value = serde_json::from_str(&vuln_doc()).unwrap();
    let second = serde_json::json!({
        "package": {"name": "minimist", "version": "1.2.5", "ecosystem": "npm"},
        "vulnerabilities": [{
            "id": "GHSA-xvch-5gv4-984h",
            "aliases": ["CVE-2021-44906"],
            "summary": "Prototype pollution in minimist.",
            "affected": [],
            "references": [],
            "database_specific": {"severity": "CRITICAL"}
        }],
        "groups": [{"ids": ["GHSA-xvch-5gv4-984h"]}]
    });
    doc["results"][0]["packages"]
        .as_array_mut()
        .unwrap()
        .push(second);
    let result = classify(&osv(), &input(), run(false, &doc.to_string(), ""));
    assert_eq!(result.outcome, ScannerOutcome::Success { finding_count: 2 });
    assert_eq!(result.findings[1].severity, Severity::Critical);
}

#[test]
fn multiple_aliases_union_without_duplicates() {
    let mut doc: serde_json::Value = serde_json::from_str(&vuln_doc()).unwrap();
    // A third record sharing the same CVE joins the same group.
    doc["results"][0]["packages"][0]["vulnerabilities"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "id": "GHSA-extra-0000-0000",
            "aliases": ["CVE-2020-8203", "GHSA-4xc9-xhrj-v574"],
            "affected": [], "references": [], "database_specific": {}
        }));
    doc["results"][0]["packages"][0]["groups"] = serde_json::json!([{"ids": ["GHSA-4xc9-xhrj-v574", "CVE-2020-8203", "GHSA-extra-0000-0000"]}]);
    let result = classify(&osv(), &input(), run(false, &doc.to_string(), ""));
    assert_eq!(result.outcome, ScannerOutcome::Success { finding_count: 1 });
    let meta: serde_json::Value =
        serde_json::from_str(result.findings[0].metadata_json.as_deref().unwrap()).unwrap();
    let aliases: Vec<&str> = meta["aliases"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(aliases, vec!["CVE-2020-8203", "GHSA-extra-0000-0000"]);
}

// ---------------------------------------------------------------------------
// 8.7 severity discipline, 8.19 references
// ---------------------------------------------------------------------------

#[test]
fn severity_normalization() {
    let cases = [
        ("CRITICAL", Severity::Critical),
        ("critical", Severity::Critical),
        ("HIGH", Severity::High),
        ("high", Severity::High),
        ("MEDIUM", Severity::Medium),
        ("moderate", Severity::Medium),
        ("LOW", Severity::Low),
        ("low", Severity::Low),
    ];
    for (raw, expected) in cases {
        let mut doc: serde_json::Value = serde_json::from_str(&vuln_doc()).unwrap();
        doc["results"][0]["packages"][0]["vulnerabilities"][0]["database_specific"] =
            serde_json::json!({"severity": raw});
        let result = classify(&osv(), &input(), run(false, &doc.to_string(), ""));
        assert_eq!(result.findings[0].severity, expected, "raw {raw}");
    }
    // No signal, or a signal we do not recognize: Unknown, never invented.
    for db in [
        serde_json::json!({}),
        serde_json::json!({"severity": "SEVERE"}),
        serde_json::json!({"severity": ""}),
    ] {
        let mut doc: serde_json::Value = serde_json::from_str(&vuln_doc()).unwrap();
        doc["results"][0]["packages"][0]["vulnerabilities"][0]["database_specific"] = db.clone();
        doc["results"][0]["packages"][0]["vulnerabilities"][1]["database_specific"] = db;
        let result = classify(&osv(), &input(), run(false, &doc.to_string(), ""));
        assert_eq!(result.findings[0].severity, Severity::Unknown);
    }
}

#[test]
fn reference_normalization() {
    let mut doc: serde_json::Value = serde_json::from_str(&vuln_doc()).unwrap();
    doc["results"][0]["packages"][0]["vulnerabilities"][0]["references"] = serde_json::json!([
        {"type": "ADVISORY", "url": "https://example.com/a"},
        {"type": "WEB", "url": "https://example.com/a"},
        {"type": "WEB", "url": "https://example.com/b"},
        {"type": "WEB", "url": ""},
    ]);
    let result = classify(&osv(), &input(), run(false, &doc.to_string(), ""));
    let meta: serde_json::Value =
        serde_json::from_str(result.findings[0].metadata_json.as_deref().unwrap()).unwrap();
    // The group merge also pulls the second record's NVD reference in.
    assert_eq!(
        meta["references"],
        serde_json::json!([
            {"type": "ADVISORY", "url": "https://example.com/a"},
            {"type": "WEB", "url": "https://example.com/b"},
            {"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-8203"},
        ])
    );
}

// ---------------------------------------------------------------------------
// 8.8 fixed versions, 8.13 direct vs transitive, dependency location
// ---------------------------------------------------------------------------

#[test]
fn unfixed_vulnerability_says_so() {
    let mut doc: serde_json::Value = serde_json::from_str(&vuln_doc()).unwrap();
    doc["results"][0]["packages"][0]["vulnerabilities"][0]["affected"][0]["ranges"][0]["events"] =
        serde_json::json!([{"introduced": "0"}]);
    doc["results"][0]["packages"][0]["vulnerabilities"][1]["affected"] = serde_json::json!([]);
    let result = classify(&osv(), &input(), run(false, &doc.to_string(), ""));
    let f = &result.findings[0];
    let meta: serde_json::Value =
        serde_json::from_str(f.metadata_json.as_deref().unwrap()).unwrap();
    assert_eq!(meta["fixed_versions"], serde_json::json!([]));
    let evidence = f.evidence.clone().unwrap_or_default();
    assert!(
        evidence.contains("no fixed version is published"),
        "{evidence}"
    );
    assert!(f
        .remediation
        .as_deref()
        .unwrap()
        .contains("No fixed version is published"));
}

#[test]
fn transitive_dependency_is_detected() {
    let dir = std::env::temp_dir().join(format!("fc-osv-trans-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"t","version":"1.0.0","dependencies":{"parent-pkg":"1.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(dir.join("package-lock.json"), "{}").unwrap();

    let direct_of = |report: &str, dir: &std::path::Path| {
        let findings = findings_from_osv(report, dir).expect("report must canonicalize");
        assert_eq!(findings.len(), 1);
        serde_json::from_str::<serde_json::Value>(findings[0].metadata_json.as_deref().unwrap())
            .unwrap()["direct"]
            .clone()
    };

    // lodash is in the lock but in no manifest dependency section: transitive.
    assert_eq!(direct_of(&vuln_doc(), &dir), json!(false));

    // Promote it to a direct dependency: the same report now reads direct.
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"t","version":"1.0.0","dependencies":{"parent-pkg":"1.0.0","lodash":"4.17.20"}}"#,
    )
    .unwrap();
    assert_eq!(direct_of(&vuln_doc(), &dir), json!(true));

    // No manifest at all: unknown, never a guess.
    let _ = std::fs::remove_file(dir.join("package.json"));
    assert_eq!(direct_of(&vuln_doc(), &dir), serde_json::Value::Null);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn dependency_location() {
    // npm: the `node_modules/<pkg>` entry line in the committed-shaped lock.
    let dir = fixture_dir("npm-vuln");
    let lodash_line = std::fs::read_to_string(dir.join("package-lock.json"))
        .unwrap()
        .lines()
        .position(|l| l.contains("\"node_modules/lodash\""))
        .unwrap()
        + 1;
    let findings = findings_from_osv(
        &serde_json::json!({"results": [{
            "source": {"path": "/scan/package-lock.json", "type": "lockfile"},
            "packages": [{
                "package": {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
                "vulnerabilities": [{"id": "GHSA-x", "affected": [], "references": []}],
                "groups": [{"ids": ["GHSA-x"]}],
            }],
        }]})
        .to_string(),
        &dir,
    )
    .expect("npm report must canonicalize");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].file_path.as_deref(), Some("package-lock.json"));
    assert_eq!(findings[0].line_number, Some(lodash_line as i32));

    // Cargo: the `version = "…"` line following `name = "…"`.
    let dir = fixture_dir("cargo-vuln");
    let text = std::fs::read_to_string(dir.join("Cargo.lock")).unwrap();
    let version_line = text
        .lines()
        .position(|l| l.trim() == r#"version = "1.5.1""#)
        .unwrap()
        + 1;
    let findings = findings_from_osv(
        &serde_json::json!({"results": [{
            "source": {"path": "/scan/Cargo.lock", "type": "lockfile"},
            "packages": [{
                "package": {"name": "regex", "version": "1.5.1", "ecosystem": "crates.io"},
                "vulnerabilities": [{
                    "id": "GHSA-m5pq-gvj9-9vr8", "aliases": ["CVE-2022-24713"],
                    "affected": [], "references": [], "database_specific": {},
                }],
                "groups": [{"ids": ["GHSA-m5pq-gvj9-9vr8"]}],
            }],
        }]})
        .to_string(),
        &dir,
    )
    .expect("cargo report must canonicalize");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].file_path.as_deref(), Some("Cargo.lock"));
    assert_eq!(findings[0].line_number, Some(version_line as i32));

    // The canonical model carries no ecosystem-specific assumption: the same
    // keys, normalized, for both ecosystems above.
    for (report, dir, package) in [
        (
            serde_json::json!({"results": [{
                "source": {"path": "/scan/package-lock.json", "type": "lockfile"},
                "packages": [{
                    "package": {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
                    "vulnerabilities": [{"id": "G", "affected": [], "references": []}],
                    "groups": [{"ids": ["G"]}],
                }],
            }]})
            .to_string(),
            fixture_dir("npm-vuln"),
            "lodash",
        ),
        (
            serde_json::json!({"results": [{
                "source": {"path": "/scan/Cargo.lock", "type": "lockfile"},
                "packages": [{
                    "package": {"name": "regex", "version": "1.5.1", "ecosystem": "crates.io"},
                    "vulnerabilities": [{"id": "G", "affected": [], "references": []}],
                    "groups": [{"ids": ["G"]}],
                }],
            }]})
            .to_string(),
            fixture_dir("cargo-vuln"),
            "regex",
        ),
    ] {
        let findings = findings_from_osv(&report, &dir).expect("canonicalize");
        let meta: serde_json::Value =
            serde_json::from_str(findings[0].metadata_json.as_deref().unwrap()).unwrap();
        assert_eq!(meta["package"], package);
        for key in [
            "advisory",
            "aliases",
            "ecosystem",
            "package",
            "installed_version",
            "manifest",
            "direct",
            "affected",
            "fixed_versions",
            "references",
            "fingerprint",
        ] {
            assert!(
                meta.get(key).is_some(),
                "{package} missing canonical key {key}"
            );
        }
    }
}

#[test]
fn two_scanners_findings_survive_the_pipeline_dedupe() {
    use firecrow_backend::orchestrator::{dedupe_findings, finding_fingerprint};

    // The dedupe key is a scanner-computed fingerprint when available. Two
    // distinct packages hit by the *same* advisory share a rule and a
    // lockfile, so a rule|file|line key would drop one of them.
    let report = serde_json::json!({"results": [{
    "source": {"path": "/scan/package-lock.json", "type": "lockfile"},
    "packages": [
        {"package": {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
         "vulnerabilities": [{"id": "GHSA-shared", "affected": [], "references": []}],
         "groups": [{"ids": ["GHSA-shared"]}]},
        {"package": {"name": "minimist", "version": "1.2.5", "ecosystem": "npm"},
         "vulnerabilities": [{"id": "GHSA-shared", "affected": [], "references": []}],
         "groups": [{"ids": ["GHSA-shared"]}]},
    ]}]})
    .to_string();
    // An unreadable source dir forces both findings to the same manifest line,
    // which is exactly the condition that used to collapse them.
    let findings =
        findings_from_osv(&report, std::path::Path::new("/nonexistent-dir")).expect("canonicalize");
    assert_eq!(findings.len(), 2);
    assert_ne!(
        finding_fingerprint(&findings[0]),
        finding_fingerprint(&findings[1])
    );
    assert_eq!(dedupe_findings(findings).len(), 2);

    // And a genuine duplicate still collapses: the same package reported twice.
    let repeated = serde_json::json!({"results": [{
        "source": {"path": "/scan/package-lock.json", "type": "lockfile"},
        "packages": [{
            "package": {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
            "vulnerabilities": [{"id": "GHSA-x", "affected": [], "references": []}],
            "groups": [{"ids": ["GHSA-x"]}],
        }],
    }]})
    .to_string();
    let findings = findings_from_osv(&repeated, std::path::Path::new("/nonexistent-dir"))
        .expect("canonicalize");
    let mut twice = findings.clone();
    twice.extend(findings);
    assert_eq!(
        dedupe_findings(twice).len(),
        1,
        "an exact repeat must collapse"
    );
}

// ---------------------------------------------------------------------------
// 8.18 fingerprint, raw-model containment, stderr bounds
// ---------------------------------------------------------------------------

#[test]
fn fingerprint_determinism() {
    let fp = |advisory: &str, ecosystem: &str, package: &str, version: &str, manifest: &str| {
        osv_fingerprint(advisory, ecosystem, package, version, manifest)
    };
    let base = fp(
        "GHSA-4xc9-xhrj-v574",
        "npm",
        "lodash",
        "4.17.20",
        "package-lock.json",
    );
    assert_eq!(
        base,
        fp(
            "GHSA-4xc9-xhrj-v574",
            "npm",
            "lodash",
            "4.17.20",
            "package-lock.json"
        )
    );
    assert!(base.starts_with("osv:"));
    assert_eq!(base.len(), 4 + 64);
    // Every identity component moves the fingerprint; nothing else does.
    for (advisory, ecosystem, package, version, manifest) in [
        (
            "GHSA-other",
            "npm",
            "lodash",
            "4.17.20",
            "package-lock.json",
        ),
        (
            "GHSA-4xc9-xhrj-v574",
            "crates.io",
            "lodash",
            "4.17.20",
            "package-lock.json",
        ),
        (
            "GHSA-4xc9-xhrj-v574",
            "npm",
            "other",
            "4.17.20",
            "package-lock.json",
        ),
        (
            "GHSA-4xc9-xhrj-v574",
            "npm",
            "lodash",
            "4.17.21",
            "package-lock.json",
        ),
        (
            "GHSA-4xc9-xhrj-v574",
            "npm",
            "lodash",
            "4.17.20",
            "yarn.lock",
        ),
    ] {
        assert_ne!(
            fp(advisory, ecosystem, package, version, manifest),
            base,
            "{advisory} {ecosystem} {package} {version} {manifest}"
        );
    }
    // Stored on the finding and stable across identical reports.
    let printed = |r: &firecrow_backend::agents::scanner::ScannerResult| {
        serde_json::from_str::<serde_json::Value>(r.findings[0].metadata_json.as_deref().unwrap())
            .unwrap()["fingerprint"]
            .clone()
    };
    let r1 = classify(&osv(), &input(), run(false, &vuln_doc(), ""));
    let r2 = classify(&osv(), &input(), run(false, &vuln_doc(), ""));
    assert_eq!(printed(&r1), printed(&r2));
    assert_eq!(printed(&r1), json!(base));
}

#[test]
fn raw_model_does_not_escape_adapter() {
    let result = classify(&osv(), &input(), run(false, &vuln_doc(), ""));
    let record = serde_json::to_string(&result.execution_record).unwrap();
    let findings = serde_json::to_string(&result.findings).unwrap();
    // Full advisory bodies, ranges, and DB-specific blobs stay out; only the
    // curated metadata keys persist.
    for banned in ["database_specific", "\"details\"", "\"events\""] {
        assert!(!record.contains(banned), "record holds {banned}");
        assert!(!findings.contains(banned), "findings hold {banned}");
    }
    let meta: serde_json::Value =
        serde_json::from_str(result.findings[0].metadata_json.as_deref().unwrap()).unwrap();
    let mut keys: Vec<&str> = meta
        .as_object()
        .unwrap()
        .keys()
        .map(|s| s.as_str())
        .collect();
    keys.sort();
    // `cwe_id` appears only when the advisory carries one. The four
    // run-provenance keys are Phase 10 additions: a canonical finding must be
    // able to name the scanner build and parser that produced it. They are
    // curated run facts, not the advisory body the assertions above exclude.
    let mut expected = vec![
        "advisory",
        "affected",
        "aliases",
        "direct",
        "ecosystem",
        "fingerprint",
        "fixed_versions",
        "installed_version",
        "manifest",
        "package",
        "parser",
        "references",
        "rule_id",
        "scanner_image",
        "scanner_version",
        "snapshot_commit",
    ];
    if meta.get("cwe_id").is_some() {
        expected.push("cwe_id");
        expected.sort();
    }
    assert_eq!(keys, expected);
}

#[test]
fn stderr_is_bounded_and_sanitized() {
    let long = format!("x{}", "y".repeat(10_000));
    let failed = classify(&osv(), &input(), run(false, "garbage", &long));
    let record = serde_json::to_string(&failed.execution_record).unwrap();
    assert!(record.len() < 8_000, "stderr must stay bounded");
    // Gitleaks-shaped secrets in OSV stderr still redact via the shared pass.
    let leaked = classify(
        &osv(),
        &input(),
        run(
            false,
            "garbage",
            "token = ghp_faketoken0000000000000000000000000001",
        ),
    );
    let record = serde_json::to_string(&leaked.execution_record).unwrap();
    assert!(!record.contains("ghp_faketoken"), "{record}");
}

#[test]
fn osv_parse_accepts_minimal_and_ignores_unknown_fields() {
    // Extra keys anywhere in the report must not break canonicalization.
    let findings = findings_from_osv(
        &serde_json::json!({"results": [{
            "source": {"path": "/scan/x", "type": "other", "zzz": 1},
            "packages": [{
                "package": {"name": "p", "version": "1", "ecosystem": "npm", "purl": "x"},
                "vulnerabilities": [{
                    "id": "G", "affected": [], "references": [],
                    "database_specific": {"whatever": [1, 2]},
                    "extra": {"deep": true},
                }],
                "groups": [{"ids": ["G"]}],
                "extra": true,
            }],
            "extra": "ignored",
        }], "wat": [], "experimental_config": {"licenses": {}}})
        .to_string(),
        &fixture_dir("npm-clean"),
    )
    .expect("minimal shapes must canonicalize");
    assert_eq!(findings.len(), 1);
    let meta: serde_json::Value =
        serde_json::from_str(findings[0].metadata_json.as_deref().unwrap()).unwrap();
    assert_eq!(meta["package"], "p");
    assert_eq!(meta["installed_version"], "1");
}

#[test]
fn null_results_is_the_pinned_versions_clean_report() {
    // Verified live against v2.2.4: a run with no package sources writes
    // `{"results": null, ...}` and exits 0. That is a real empty report.
    let findings = findings_from_osv(
        r#"{"results": null, "experimental_config": {"licenses": {"summary": false, "allowlist": null}}}"#,
        &fixture_dir("npm-clean"),
    )
    .expect("null results must canonicalize");
    assert!(findings.is_empty());
    let result = classify(
        &osv(),
        &input(),
        run(true, r#"{"results": null, "experimental_config": {}}"#, ""),
    );
    assert_eq!(result.outcome, ScannerOutcome::Success { finding_count: 0 });
    assert!(result.usable());
}

#[test]
fn empty_output_is_a_missing_report_not_a_clean_scan() {
    // The wrapper cats the artifact; no bytes means no artifact was written.
    for body in ["", "   \n "] {
        assert!(
            findings_from_osv(body, &fixture_dir("npm-clean")).is_err(),
            "empty report {body:?} must not canonicalize"
        );
    }
    let result = classify(&osv(), &input(), run(true, "", ""));
    assert!(
        matches!(result.outcome, ScannerOutcome::Failed { .. }),
        "empty output must fail, got {:?}",
        result.outcome
    );
    assert!(!result.usable());
    assert_eq!(result.execution_record["coverage"], "unknown");
    assert!(result.execution_record.get("finding_count").is_none());
}

// ---------------------------------------------------------------------------
// Live end-to-end (ignored): real image, real database
// ---------------------------------------------------------------------------

fn live_input(name: &str) -> ScanInput {
    let dir = fixture_dir(name);
    assert!(dir.is_dir(), "fixture missing: {dir:?}");
    ScanInput::from_dir(&dir)
}

fn live_meta(f: &firecrow_backend::schemas::audit_state::Finding) -> serde_json::Value {
    serde_json::from_str(f.metadata_json.as_deref().unwrap_or("{}")).unwrap()
}

#[tokio::test]
#[ignore]
async fn e2e_npm_vulnerable_dependency() {
    let sandbox = SandboxManager::new();
    let result = run_dependency_scan(&live_input("npm-vuln"), &sandbox, &|| false).await;
    assert!(
        result.usable(),
        "scan must succeed: {:?}",
        result.execution_record
    );
    assert!(!result.findings.is_empty(), "expected ≥1 finding");
    let lodash = result
        .findings
        .iter()
        .find(|f| {
            live_meta(f)["package"] == "lodash" && live_meta(f)["installed_version"] == "4.17.20"
        })
        .expect("lodash 4.17.20 finding");
    let meta = live_meta(lodash);
    assert_eq!(meta["ecosystem"], "npm");
    assert_eq!(meta["manifest"], "package-lock.json");
    assert!(!meta["advisory"].as_str().unwrap_or_default().is_empty());
    assert_eq!(lodash.scanner_name.as_deref(), Some("osv"));
    assert_eq!(lodash.scanner_mode.as_deref(), Some("dependency"));
    assert_eq!(lodash.file_path.as_deref(), Some("package-lock.json"));
    assert!(lodash.line_number.unwrap_or(0) > 0);
    assert!(meta["fingerprint"]
        .as_str()
        .unwrap_or_default()
        .starts_with("osv:"));
    assert_eq!(meta["direct"], true);
    assert!(!meta["fixed_versions"]
        .as_array()
        .map(|a| a.is_empty())
        .unwrap_or(true));
    // One finding per alias-group, not one per OSV record: live output lists
    // five vulnerability records for lodash 4.17.20 but groups them into
    // three distinct issues.
    let lodash_findings = result
        .findings
        .iter()
        .filter(|f| live_meta(f)["package"] == "lodash")
        .count();
    assert_eq!(
        lodash_findings, 3,
        "five records in three groups must canonicalize to three findings"
    );
}

/// The fixed fixture must not carry the advisory that 4.17.21 fixes.
///
/// It is *not* a zero-findings assertion: lodash 4.17.21 has its own later
/// advisories (verified against the live database), so "no findings at all"
/// would be a false expectation and would eventually fail for reasons
/// unrelated to version/range handling. What this proves is the thing 8.12
/// actually asks: the same advisory does not follow the package into the
/// fixed version, which is exactly the version/range interpretation that can
/// silently break.
#[tokio::test]
#[ignore]
async fn e2e_fixed_dependency_drops_the_fixed_advisory() {
    // GHSA-29mw-wpgm-hmr9 / CVE-2020-28500 (ReDoS) affects lodash <4.17.21.
    const FIXED_ADVISORY: &str = "GHSA-29mw-wpgm-hmr9";

    let sandbox = SandboxManager::new();
    let vulnerable = run_dependency_scan(&live_input("npm-vuln"), &sandbox, &|| false).await;
    assert!(
        vulnerable.usable(),
        "vulnerable scan must succeed: {:?}",
        vulnerable.execution_record
    );
    assert!(
        vulnerable.findings.iter().any(|f| {
            let m = live_meta(f);
            m["package"] == "lodash"
                && m["installed_version"] == "4.17.20"
                && (m["advisory"] == FIXED_ADVISORY
                    || m["aliases"]
                        .as_array()
                        .is_some_and(|a| a.contains(&json!(FIXED_ADVISORY))))
        }),
        "4.17.20 must carry {FIXED_ADVISORY}: {:?}",
        vulnerable
            .findings
            .iter()
            .map(|f| live_meta(f)["advisory"].clone())
            .collect::<Vec<_>>()
    );

    let fixed = run_dependency_scan(&live_input("npm-fixed"), &sandbox, &|| false).await;
    assert!(
        fixed.usable(),
        "fixed scan must succeed: {:?}",
        fixed.execution_record
    );
    assert!(
        !fixed.findings.iter().any(|f| {
            let m = live_meta(f);
            m["package"] == "lodash"
                && (m["advisory"] == FIXED_ADVISORY
                    || m["aliases"]
                        .as_array()
                        .is_some_and(|a| a.contains(&json!(FIXED_ADVISORY))))
        }),
        "4.17.21 must not carry {FIXED_ADVISORY}"
    );
}

#[tokio::test]
#[ignore]
async fn e2e_npm_transitive_dependency_is_not_direct() {
    let sandbox = SandboxManager::new();
    let result = run_dependency_scan(&live_input("npm-transitive"), &sandbox, &|| false).await;
    assert!(
        result.usable(),
        "scan must succeed: {:?}",
        result.execution_record
    );
    let lodash = result
        .findings
        .iter()
        .find(|f| live_meta(f)["package"] == "lodash")
        .unwrap_or_else(|| panic!("nested lodash finding: {:?}", result.execution_record));
    assert_eq!(live_meta(lodash)["direct"], false);
    assert_eq!(lodash.file_path.as_deref(), Some("package-lock.json"));
}

#[tokio::test]
#[ignore]
async fn e2e_npm_clean_repo_is_success_zero() {
    let sandbox = SandboxManager::new();
    let result = run_dependency_scan(&live_input("npm-clean"), &sandbox, &|| false).await;
    assert!(
        result.usable(),
        "scan must succeed: {:?}",
        result.execution_record
    );
    assert_eq!(result.outcome, ScannerOutcome::Success { finding_count: 0 });
}

#[tokio::test]
#[ignore]
async fn e2e_cargo_vulnerable_dependency() {
    let sandbox = SandboxManager::new();
    let result = run_dependency_scan(&live_input("cargo-vuln"), &sandbox, &|| false).await;
    assert!(
        result.usable(),
        "scan must succeed: {:?}",
        result.execution_record
    );
    assert!(!result.findings.is_empty(), "expected ≥1 finding");
    let regex = result
        .findings
        .iter()
        .find(|f| live_meta(f)["package"] == "regex")
        .unwrap_or_else(|| panic!("regex finding: {:?}", result.execution_record));
    let meta = live_meta(regex);
    assert_eq!(meta["installed_version"], "1.5.1");
    assert_eq!(meta["ecosystem"], "crates.io");
    assert_eq!(meta["manifest"], "Cargo.lock");
    assert_eq!(meta["direct"], true);
    assert!(regex.line_number.unwrap_or(0) > 0);
    // Same underlying issue under two ids collapses to one finding carrying both.
    let aliases: Vec<String> = meta["aliases"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    assert!(!aliases.is_empty(), "grouped aliases: {meta}");
}
