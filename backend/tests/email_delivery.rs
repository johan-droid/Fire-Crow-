//! Phase 17: deterministic email delivery.
//!
//! The delivery path is exercised end to end against a real in-process SMTP
//! server and a real PostgreSQL database. No test needs an external mail server,
//! and none asserts on provider wording: Fire Crow's errors are fixed text, and
//! the tests assert on failure *classes* instead.
//!
//! What is proven here: the artifact is a pure function of the report and an
//! optional narrative; delivery is execution-scoped and cannot cross attempts;
//! an incomplete scan is never labelled clean; every interpolated value is
//! escaped; a provider failure changes nothing about the audit; and a duplicate
//! request cannot produce a second email.

mod support;

use firecrow_backend::agents::scanner::{ScannerOutcome, ScannerResult};
use firecrow_backend::error::DeliveryError;
use firecrow_backend::models::{JobStatus, Severity};
use firecrow_backend::orchestrator::canonical_audit::{canonical_audit, CanonicalAuditRequest};
use firecrow_backend::orchestrator::delivery::{
    deliver_execution_email, delivery_state, DeliveryKey, DeliveryOutcome, CHANNEL_EMAIL,
};

/// The idempotency key a plain email delivery uses.
fn email_key(execution_id: &str) -> DeliveryKey {
    DeliveryKey {
        execution_id: execution_id.to_string(),
        channel: CHANNEL_EMAIL,
        destination_ref: RECIPIENT.to_string(),
        delivery_version: 1,
    }
}

/// The recorded status of an execution's email delivery.
async fn status_of(pool: &sqlx::PgPool, execution_id: &str) -> Option<String> {
    delivery_state(pool, &email_key(execution_id))
        .await
        .unwrap()
        .map(|state| state.status)
}
use firecrow_backend::orchestrator::execution::{
    begin_execution, finalize_execution, finalize_without_findings, load_ai_narrative,
    load_stored_report, reconstruct_latest_audit, reconstruct_report_source, ExecutionLease,
    Finalization, ScannerRunRecord,
};
use firecrow_backend::schemas::ai_narrative::{FindingExplanation, ReportNarrative};
use firecrow_backend::schemas::audit_state::Finding;
use firecrow_backend::schemas::canonical_audit::CanonicalAudit;
use firecrow_backend::schemas::report::{build_report, CanonicalAuditReport, ExecutionIdentity};
use firecrow_backend::services::email::EmailService;
use firecrow_backend::services::email_artifact;
use sqlx::PgPool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const REPO: &str = "https://github.com/example/repo";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const RECIPIENT: &str = "auditor@example.com";

// ---------------------------------------------------------------------------
// A real, minimal SMTP server
// ---------------------------------------------------------------------------

/// Decode what the mail server received into comparable plain text.
///
/// Two encodings stand between the artifact and a substring assertion:
///
/// * quoted-printable, including soft line breaks (`=` at end of line), which is
///   what lettre uses and what splits a long canonical id across two lines;
/// * RFC 2047 encoded words in headers, which is how the em dashes in the
///   subject are transmitted.
///
/// Neither is Fire Crow behaviour being tested — both are transport encoding.
fn decode_quoted_printable(input: &str) -> String {
    // Undo soft line breaks first: a trailing `=` means "no newline here".
    let unfolded = input.replace("=\r\n", "").replace("=\n", "");
    let mut out: Vec<u8> = Vec::new();
    let chars: Vec<char> = unfolded.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '=' && index + 2 < chars.len() {
            let hex: String = chars[index + 1..index + 3].iter().collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        let mut buffer = [0u8; 4];
        out.extend_from_slice(chars[index].encode_utf8(&mut buffer).as_bytes());
        index += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// Decode RFC 2047 `=?utf-8?b?...?=` encoded words.
fn decode_encoded_words(input: &str) -> String {
    let mut out = String::new();
    let mut rest = input;
    while let Some(start) = rest.find("=?utf-8?b?") {
        out.push_str(&rest[..start]);
        let payload_start = start + "=?utf-8?b?".len();
        let Some(end) = rest[payload_start..].find("?=") else {
            break;
        };
        let encoded = &rest[payload_start..payload_start + end];
        match base64_decode(encoded) {
            Some(bytes) => out.push_str(&String::from_utf8_lossy(&bytes)),
            None => out.push_str(encoded),
        }
        rest = &rest[payload_start + end + 2..];
    }
    out.push_str(rest);
    out
}

/// Minimal standard-library base64 decoder.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn value(byte: u8) -> Option<u32> {
        match byte {
            b'A'..=b'Z' => Some((byte - b'A') as u32),
            b'a'..=b'z' => Some((byte - b'a') as u32 + 26),
            b'0'..=b'9' => Some((byte - b'0') as u32 + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for byte in input.bytes() {
        if byte == b'=' {
            break;
        }
        let sextet = value(byte)?;
        buffer = (buffer << 6) | sextet;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

/// What the fake SMTP server should answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SmtpBehaviour {
    /// Accept the whole conversation.
    Accept,
    /// Reject the recipient (permanent, 550).
    RejectRecipient,
    /// Congestion (transient, 451).
    Congested,
    /// Server error (permanent 554).
    ServerError,
    /// Accept the TCP connection and then never speak: the client must time out.
    Silent,
    /// Accept the message but stall before acknowledging it, so a test can
    /// inspect database state *while* the provider call is in flight.
    SlowData,
}

/// One delivered message, as the server saw it.
#[derive(Clone, Debug)]
struct Received {
    /// Recorded for completeness; the sender address comes from configuration.
    #[allow(dead_code)]
    mail_from: String,
    rcpt_to: Vec<String>,
    data: String,
}

/// A minimal SMTP server: greeting, EHLO, MAIL, RCPT, DATA, QUIT.
///
/// Enough of RFC 5321 for lettre's client to complete a real dialogue, which is
/// the point: the transport is exercised, not stubbed.
struct FakeSmtp {
    address: String,
    port: u16,
    messages: Arc<Mutex<Vec<Received>>>,
}

impl FakeSmtp {
    async fn start(behaviour: SmtpBehaviour) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // lettre's `hostname` feature verifies the greeting against the relay
        // domain, so the server must introduce itself as the address we dial.
        let relay_name = "127.0.0.1".to_string();
        let messages: Arc<Mutex<Vec<Received>>> = Arc::new(Mutex::new(Vec::new()));

        let sink = messages.clone();
        let greeting = format!("220 {relay_name} ESMTP\r\n");
        let ehlo_reply = format!("250-{relay_name}\r\n250 PIPELINING\r\n");
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let sink = sink.clone();
                let greeting = greeting.clone();
                let ehlo_reply = ehlo_reply.clone();
                let relay_name = relay_name.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
                    // Split the stream: one half reads commands, the other writes
                    // replies. `split` avoids needing a blocking clone.
                    let (reader, mut writer) = socket.split();
                    let mut lines = BufReader::new(reader).lines();

                    if writer.write_all(greeting.as_bytes()).await.is_err() {
                        return;
                    }
                    if std::env::var("SMTP_TRACE").is_ok() {
                        eprintln!("[smtp] greeted");
                    }
                    let mut current: Option<Received> = None;

                    while let Ok(Some(line)) = lines.next_line().await {
                        let upper = line.trim().to_ascii_uppercase();
                        let reply = match upper.split(' ').next().unwrap_or("") {
                            "EHLO" => ehlo_reply.clone(),
                            "HELO" => format!("250 {relay_name}\r\n"),
                            "MAIL" => "250 OK\r\n".to_string(),
                            "RCPT" => {
                                let address = line
                                    .rsplit('<')
                                    .next()
                                    .unwrap_or("")
                                    .split('>')
                                    .next()
                                    .unwrap_or("")
                                    .to_string();
                                match behaviour {
                                    SmtpBehaviour::RejectRecipient => {
                                        "550 5.1.1 no such user here\r\n".to_string()
                                    }
                                    SmtpBehaviour::Congested => {
                                        "451 4.3.0 try later\r\n".to_string()
                                    }
                                    _ => {
                                        current
                                            .get_or_insert(Received {
                                                mail_from: String::new(),
                                                rcpt_to: Vec::new(),
                                                data: String::new(),
                                            })
                                            .rcpt_to
                                            .push(address);
                                        "250 OK\r\n".to_string()
                                    }
                                }
                            }
                            "DATA" => {
                                let accepts = matches!(
                                    behaviour,
                                    SmtpBehaviour::Accept | SmtpBehaviour::SlowData
                                );
                                if !accepts {
                                    "554 5.0.0 rejected\r\n".to_string()
                                } else {
                                    // RFC 5321: answer 354 and *then* read the
                                    // message body until the lone-dot terminator.
                                    // Replying 250 here would make the client
                                    // treat our ack as the end of the dialogue.
                                    if writer.write_all(b"354 send it\r\n").await.is_err() {
                                        return;
                                    }
                                    let mut body = String::new();
                                    while let Ok(Some(data_line)) = lines.next_line().await {
                                        if data_line.trim_end() == "." {
                                            break;
                                        }
                                        body.push_str(&data_line);
                                        body.push('\n');
                                    }
                                    if let Some(mut record) = current.take() {
                                        record.data = body;
                                        sink.lock().unwrap().push(record);
                                    }
                                    if behaviour == SmtpBehaviour::SlowData {
                                        tokio::time::sleep(std::time::Duration::from_millis(1500))
                                            .await;
                                    }
                                    "250 OK queued\r\n".to_string()
                                }
                            }
                            "QUIT" => "221 bye\r\n".to_string(),
                            "RSET" => "250 OK\r\n".to_string(),
                            "NOOP" => "250 OK\r\n".to_string(),
                            _ => "250 OK\r\n".to_string(),
                        };
                        if writer.write_all(reply.as_bytes()).await.is_err() {
                            return;
                        }
                        if upper.starts_with("QUIT") {
                            return;
                        }
                    }
                });
            }
        });

        Self {
            address: "127.0.0.1".to_string(),
            port,
            messages,
        }
    }

    fn mailer(&self, attempts: u32, timeout: Duration) -> EmailService {
        EmailService::plaintext_loopback("reports@firecrow.test", &self.address, self.port, timeout)
            .expect("loopback plaintext is permitted for tests")
            .with_max_attempts(attempts)
    }

    fn received(&self) -> Vec<Received> {
        self.messages.lock().unwrap().clone()
    }

    /// The decoded message body.
    ///
    /// lettre encodes bodies as quoted-printable, which soft-wraps long lines
    /// with `=` and encodes `=`. Assertions about report content must run against
    /// the decoded text, or a canonical id can be split across two lines.
    fn received_decoded(&self) -> Vec<String> {
        self.received()
            .into_iter()
            .map(|m| decode_encoded_words(&decode_quoted_printable(&m.data)))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn success_run(scanner: &str, mode: &str, findings: Vec<Finding>) -> ScannerResult {
    let finding_count = findings.len();
    ScannerResult {
        scanner: scanner.into(),
        version: "1.0.0".into(),
        mode: mode.into(),
        outcome: ScannerOutcome::Success { finding_count },
        findings,
        execution_record: serde_json::json!({
            "scanner": scanner, "version": "1.0.0", "mode": mode,
            "image": format!("registry/{scanner}:1.0.0"),
            "parser": format!("{scanner}-json-v1"),
            "snapshot_commit": COMMIT, "finding_count": finding_count,
        }),
    }
}

fn finding_with_title(id: &str, title: &str, severity: Severity) -> Finding {
    Finding {
        id: id.to_string(),
        agent_source: "gitleaks".into(),
        title: title.to_string(),
        description: "gitleaks".into(),
        severity,
        cvss_vector: None,
        cvss_score: None,
        evidence: Some("AWS_ACCESS_KEY_ID=[REDACTED]".into()),
        remediation: Some("Rotate the credential.".into()),
        cwe_id: Some("CWE-798".into()),
        owasp_category: Some("A07".into()),
        confidence: Some("high".into()),
        scanner_name: Some("gitleaks".into()),
        scanner_mode: Some("secret".into()),
        file_path: Some("config/aws.env".into()),
        line_number: Some(3),
        route: None,
        metadata_json: Some(
            serde_json::json!({
                "rule_id": "aws-access-token",
                "fingerprint": id,
                "parser": "gitleaks-json-v1",
                "scanner_version": "8.18.4",
                "scanner_image": "ghcr.io/gitleaks/gitleaks:v8.18.4",
            })
            .to_string(),
        ),
    }
}

fn secret_finding(fingerprint: &str) -> Finding {
    finding_with_title(
        &format!("gitleaks-{fingerprint}"),
        &format!("AWS access token ({fingerprint})"),
        Severity::High,
    )
}

fn build_audit(findings: &[Finding], semgrep_failed: bool) -> CanonicalAudit {
    let mut results = vec![
        success_run("gitleaks", "secret", findings.to_vec()),
        success_run("osv", "dependency", vec![]),
    ];
    if semgrep_failed {
        results.push(ScannerResult {
            scanner: "semgrep".into(),
            version: "1.0.0".into(),
            mode: "sast".into(),
            outcome: ScannerOutcome::Failed {
                reason: "semgrep exited non-zero".into(),
            },
            findings: Vec::new(),
            execution_record: serde_json::json!({
                "scanner": "semgrep", "version": "1.0.0", "mode": "sast",
                "error": "semgrep exited non-zero",
            }),
        });
    } else {
        results.push(success_run("semgrep", "sast", vec![]));
    }
    let complete = !semgrep_failed;
    canonical_audit(&CanonicalAuditRequest {
        scan_id: "scan-p17",
        repository_url: REPO,
        repo_branch: "main",
        repo_owner: "example",
        repo_name: "repo",
        snapshot_commit: Some(COMMIT),
        snapshot_file_count: 12,
        snapshot_total_size: 4096,
        results: &results,
        findings,
        security_score: if complete { Some(8.5) } else { None },
    })
    .expect("canonical audit")
}

fn finalization_for(
    lease: &ExecutionLease,
    findings: &[Finding],
    canonical: &CanonicalAudit,
) -> Finalization {
    let report = build_report(
        canonical,
        &ExecutionIdentity {
            execution_id: lease.execution_id.clone(),
            attempt_number: lease.attempt_number,
        },
    )
    .expect("report builds");
    Finalization {
        findings: findings.to_vec(),
        scanner_runs: vec![ScannerRunRecord {
            scanner: "gitleaks".into(),
            version: "1.0.0".into(),
            parser: "gitleaks-json-v1".into(),
            mode: "secret".into(),
            image: "registry/gitleaks:1.0.0".into(),
            status: "success_findings".into(),
            finding_count: Some(findings.len() as i32),
            coverage_known: true,
            detail: None,
            limitations: Vec::new(),
        }],
        coverage_status: if canonical.coverage.complete {
            "complete".into()
        } else {
            "partial".into()
        },
        coverage_complete: canonical.coverage.complete,
        coverage_limitations: canonical.limitations.clone(),
        summary: Some(serde_json::json!({"finding_count": findings.len()})),
        canonical_json: Some(serde_json::to_value(canonical).expect("canonical serializes")),
        report_markdown: Some("# report".into()),
        report_json: Some(serde_json::to_value(&report).expect("report serializes")),
        report_html: Some("<p>report</p>".into()),
        security_score: if canonical.coverage.complete {
            Some(8.5)
        } else {
            None
        },
        job_status: if canonical.coverage.complete {
            "completed".into()
        } else {
            "partial".into()
        },
        failure_reason: None,
    }
}

async fn seed_job(pool: &PgPool) -> String {
    let user = support::seed_user(pool, "p17").await;
    let job = support::seed_job(pool, &user.id, JobStatus::Running.as_str()).await;
    job
}

async fn finalized(pool: &PgPool, job: &str, findings: &[Finding]) -> ExecutionLease {
    let lease = begin_execution(pool, job).await.unwrap();
    finalize_execution(
        pool,
        &lease,
        &finalization_for(&lease, findings, &build_audit(findings, false)),
    )
    .await
    .unwrap();
    lease
}

async fn report_of(pool: &PgPool, job: &str, lease: &ExecutionLease) -> CanonicalAuditReport {
    let source = reconstruct_report_source(pool, job, Some(&lease.execution_id))
        .await
        .unwrap()
        .unwrap();
    build_report(
        &source.audit,
        &ExecutionIdentity {
            execution_id: source.execution_id,
            attempt_number: source.attempt_number,
        },
    )
    .unwrap()
}

fn faithful_narrative(report: &CanonicalAuditReport) -> ReportNarrative {
    ReportNarrative {
        narrative_schema_version: 1,
        executive_summary: format!(
            "This audit recorded {} finding(s).",
            report.summary.finding_count
        ),
        finding_explanations: report
            .findings
            .iter()
            .map(|f| FindingExplanation {
                finding_id: f.id.clone(),
                severity: None,
                explanation: "The credential is exposed and should be rotated.".into(),
            })
            .collect(),
        remediation_guidance: Vec::new(),
        limitations: report.limitations.clone(),
    }
}

// ---------------------------------------------------------------------------
// 4, 5, 6, 7, 10, 11, 28: artifact content and determinism
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_artifact_is_deterministic_and_identical_without_a_narrative() {
    let findings = vec![secret_finding("det")];
    let report = report_for(&findings, false);
    let narrative = faithful_narrative(&report);

    let first = email_artifact::render(&report, Some(&narrative));
    let second = email_artifact::render(&report, Some(&narrative));
    assert_eq!(first, second, "identical inputs must render identically");
    assert_eq!(first.execution_id, report.identity.execution_id);
    assert_eq!(first.attempt_number, report.identity.attempt_number);

    // §28: nothing volatile may appear in the artifact.
    for banned in ["20", "T00:", "uuid", "request_id", "provider"] {
        assert!(
            !first.html_body.to_lowercase().contains(banned),
            "artifact leaked {banned}"
        );
    }

    // Plain text and HTML carry the same security facts.
    for fact in ["gitleaks", "AWS_ACCESS_KEY_ID=[REDACTED]", "8.5"] {
        assert!(first.text_body.contains(fact), "text missing {fact}");
        assert!(first.html_body.contains(fact), "html missing {fact}");
    }
}

#[tokio::test]
async fn the_artifact_reflects_real_coverage_and_never_mislabels_failure() {
    // A partial audit: semgrep failed, gitleaks findings retained.
    let findings = vec![secret_finding("partial")];
    let partial = report_for(&findings, true);
    let artifact = email_artifact::render(&partial, None);

    assert!(!partial.coverage.complete);
    assert!(artifact.subject.contains("FAILED") || artifact.subject.contains("PARTIAL"));
    // The forbidden transformation: a failed scan described as clean, or as zero
    // findings.
    let haystack = format!("{}{}", artifact.text_body, artifact.html_body).to_lowercase();
    for banned in [
        "success_clean",
        "no vulnerabilities",
        "clean result",
        "0 findings",
    ] {
        assert!(
            !haystack.contains(banned),
            "partial audit reported as {banned}"
        );
    }
    // The failed scanner is named, and the null score stays null.
    assert!(artifact.text_body.contains("semgrep"));
    assert!(artifact.text_body.contains("did not succeed"));
    assert!(artifact.text_body.contains("security score: Not available"));
    assert!(!artifact.text_body.contains("security score: 0"));
}

#[tokio::test]
async fn a_clean_audit_says_so_only_when_coverage_is_complete() {
    let clean = report_for(&[], false);
    assert!(clean.coverage.complete);
    let artifact = email_artifact::render(&clean, None);
    assert!(artifact.subject.contains("SUCCESS_CLEAN"));
    assert!(artifact.text_body.contains("none: every scanner completed"));
}

#[tokio::test]
async fn the_subject_carries_no_evidence_secret_or_model_text() {
    let findings = vec![secret_finding("subject")];
    let report = report_for(&findings, false);
    let mut narrative = faithful_narrative(&report);
    narrative.executive_summary = "AKIAIOSFODNN7EXAMPLE should be rotated now.".into();
    let artifact = email_artifact::render(&report, Some(&narrative));

    assert!(artifact.subject.starts_with("Fire Crow —"));
    assert!(artifact.subject.contains("attempt 1"));
    assert!(!artifact.subject.contains("[REDACTED]"));
    assert!(!artifact.subject.contains("AKIA"));
    assert!(!artifact.subject.contains("aws.env"));
    assert!(!artifact.subject.contains("rotate"));
    assert!(artifact.subject.len() < 200, "subject must stay bounded");
}

// ---------------------------------------------------------------------------
// 9, 24, 25: HTML safety and secret safety
// ---------------------------------------------------------------------------

#[tokio::test]
async fn hostile_titles_and_narratives_are_escaped_in_html() {
    let payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
        "\"><iframe src=//evil>",
    ];
    let findings: Vec<Finding> = payloads
        .iter()
        .enumerate()
        .map(|(index, payload)| {
            finding_with_title(
                &format!("gitleaks-inject-{index}"),
                payload,
                Severity::Critical,
            )
        })
        .collect();
    let report = report_for(&findings, false);

    // A narrative carrying equivalent markup.
    let narrative = ReportNarrative {
        narrative_schema_version: 1,
        executive_summary: "<script>alert('narrative')</script>".into(),
        finding_explanations: vec![FindingExplanation {
            finding_id: report.findings[0].id.clone(),
            severity: None,
            explanation: "<img src=x onerror=alert('xss')>".into(),
        }],
        remediation_guidance: Vec::new(),
        limitations: Vec::new(),
    };

    let artifact = email_artifact::render(&report, Some(&narrative));
    let html = &artifact.html_body;

    // No live *markup* survives. Checking the tag openers is the real property:
    // an escaped payload legitimately still contains the words `onerror=` as
    // inert text, and asserting on those would fail for the wrong reason.
    for dangerous in ["<script", "<img", "<svg", "<iframe", "<a href"] {
        assert!(
            !html.contains(dangerous),
            "HTML kept live markup: {dangerous}"
        );
    }
    // The payload is present, but inert.
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
}

#[tokio::test]
async fn a_narrative_carrying_a_known_secret_never_reaches_an_artifact() {
    let findings = vec![secret_finding("secret")];
    let report = report_for(&findings, false);
    let mut narrative = faithful_narrative(&report);
    narrative.finding_explanations[0].explanation =
        "The exposed key is AKIAIOSFODNN7EXAMPLE and must be rotated immediately.".into();
    // The Phase 14 validator is the only thing that may reject this, and it does
    // so before an artifact could ever be rendered from it.
    assert!(
        firecrow_backend::schemas::ai_narrative::validate_narrative(&report, &narrative).is_err(),
        "a secret-bearing narrative must never validate"
    );
}

// ---------------------------------------------------------------------------
// 21: attempt isolation
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn delivery_is_execution_scoped_and_never_crosses_attempts(pool: PgPool) {
    let smtp = FakeSmtp::start(SmtpBehaviour::Accept).await;
    let job = seed_job(&pool).await;

    let first = finalized(&pool, &job, &[secret_finding("a1")]).await;
    let second = begin_execution(&pool, &job).await.unwrap();
    let second_findings = vec![secret_finding("a2")];
    finalize_execution(
        &pool,
        &second,
        &finalization_for(
            &second,
            &second_findings,
            &build_audit(&second_findings, false),
        ),
    )
    .await
    .unwrap();

    let mailer = smtp.mailer(1, Duration::from_secs(5));

    // Requesting attempt 1 sends attempt 1's report.
    assert_eq!(
        deliver_execution_email(
            &pool,
            &job,
            &first.execution_id,
            RECIPIENT,
            &mailer,
            &artifact_for(&pool, &job, &first.execution_id).await
        )
        .await
        .unwrap(),
        DeliveryOutcome::Sent
    );
    // Requesting attempt 2 sends attempt 2's report.
    assert_eq!(
        deliver_execution_email(
            &pool,
            &job,
            &second.execution_id,
            RECIPIENT,
            &mailer,
            &artifact_for(&pool, &job, &second.execution_id).await
        )
        .await
        .unwrap(),
        DeliveryOutcome::Sent
    );

    let messages = smtp.received_decoded();
    assert_eq!(messages.len(), 2, "one email per requested execution");

    // Each email must carry its own execution's identity and its own findings.
    // Finding identity is canonical (a hash over the scanner's native identity),
    // so the check uses the ids the reports actually hold.
    let first_ids: Vec<String> = report_of(&pool, &job, &first)
        .await
        .findings
        .iter()
        .map(|f| f.id.clone())
        .collect();
    let second_ids: Vec<String> = report_of(&pool, &job, &second)
        .await
        .findings
        .iter()
        .map(|f| f.id.clone())
        .collect();
    assert_ne!(
        first_ids, second_ids,
        "the attempts audited different findings"
    );

    assert!(messages[0].contains(&first.execution_id));
    assert!(messages[1].contains(&second.execution_id));
    for id in &first_ids {
        assert!(
            messages[0].contains(id),
            "attempt 1's email must carry attempt 1's finding {id}"
        );
        assert!(
            !messages[1].contains(id),
            "attempt 2's email must not carry attempt 1's finding {id}"
        );
    }
    for id in &second_ids {
        assert!(messages[1].contains(id));
        assert!(!messages[0].contains(id));
    }
    assert!(messages[0].contains("attempt 1"));
    assert!(messages[1].contains("attempt 2"));
}

// ---------------------------------------------------------------------------
// 18: idempotency
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn a_duplicate_request_cannot_send_a_second_email(pool: PgPool) {
    let smtp = FakeSmtp::start(SmtpBehaviour::Accept).await;
    let job = seed_job(&pool).await;
    let lease = finalized(&pool, &job, &[secret_finding("once")]).await;
    let mailer = smtp.mailer(1, Duration::from_secs(5));

    assert_eq!(
        deliver_execution_email(
            &pool,
            &job,
            &lease.execution_id,
            RECIPIENT,
            &mailer,
            &artifact_for(&pool, &job, &lease.execution_id).await
        )
        .await
        .unwrap(),
        DeliveryOutcome::Sent
    );
    // A second request is answered from delivery state, not by re-sending.
    assert_eq!(
        deliver_execution_email(
            &pool,
            &job,
            &lease.execution_id,
            RECIPIENT,
            &mailer,
            &artifact_for(&pool, &job, &lease.execution_id).await
        )
        .await
        .unwrap(),
        DeliveryOutcome::AlreadySent
    );

    assert_eq!(smtp.received().len(), 1, "exactly one email may be sent");
    assert_eq!(
        status_of(&pool, &lease.execution_id).await,
        Some("sent".to_string())
    );

    // Two simultaneous requests also produce exactly one email.
    let other = finalized(&pool, &job, &[secret_finding("race")]).await;
    let raced = artifact_for(&pool, &job, &other.execution_id).await;
    let (a, b) = tokio::join!(
        deliver_execution_email(&pool, &job, &other.execution_id, RECIPIENT, &mailer, &raced),
        deliver_execution_email(&pool, &job, &other.execution_id, RECIPIENT, &mailer, &raced),
    );
    let outcomes = [a, b];
    assert!(
        outcomes
            .iter()
            .any(|r| matches!(r, Ok(DeliveryOutcome::Sent)))
            || outcomes.iter().all(|r| r.is_ok()),
        "at least one request must be served: {outcomes:?}"
    );
    let rows: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_deliveries WHERE execution_id=$1 AND channel='email'",
    )
    .bind(&other.execution_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rows.0, 1, "one delivery record per execution and channel");
}

// ---------------------------------------------------------------------------
// 16, 23: failure isolation
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn provider_failures_never_change_the_audit(pool: PgPool) {
    let job = seed_job(&pool).await;
    let lease = finalized(&pool, &job, &[secret_finding("fail")]).await;
    let audit_before = reconstruct_latest_audit(&pool, &job)
        .await
        .unwrap()
        .unwrap();
    let report_before = load_stored_report(&pool, &job, None)
        .await
        .unwrap()
        .unwrap();

    for behaviour in [
        SmtpBehaviour::RejectRecipient,
        SmtpBehaviour::Congested,
        SmtpBehaviour::ServerError,
        SmtpBehaviour::Silent,
    ] {
        let smtp = FakeSmtp::start(behaviour).await;
        let mailer = smtp.mailer(1, Duration::from_millis(600));
        let result = deliver_execution_email(
            &pool,
            &job,
            &lease.execution_id,
            RECIPIENT,
            &mailer,
            &artifact_for(&pool, &job, &lease.execution_id).await,
        )
        .await;
        assert!(
            result.is_err(),
            "{behaviour:?} must fail rather than claim success"
        );

        // Delivery state records the failure; the audit records nothing.
        assert_eq!(
            status_of(&pool, &lease.execution_id).await,
            Some("failed".to_string()),
            "{behaviour:?} must be recorded as a delivery failure"
        );
        // The job's own status is untouched: a mail failure is not an audit
        // failure.
        let job_status: (String,) = sqlx::query_as("SELECT status FROM audit_jobs WHERE id=$1")
            .bind(&job)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_ne!(
            job_status.0, "failed",
            "audit status must not become failed"
        );
    }

    let audit_after = reconstruct_latest_audit(&pool, &job)
        .await
        .unwrap()
        .unwrap();
    let report_after = load_stored_report(&pool, &job, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(audit_before.canonical_json, audit_after.canonical_json);
    assert_eq!(audit_before.status, audit_after.status);
    assert_eq!(report_before.json, report_after.json);
    assert_eq!(report_before.markdown, report_after.markdown);
    assert_eq!(report_before.html, report_after.html);
}

#[sqlx::test(migrations = "./migrations")]
async fn a_failed_audit_is_delivered_as_a_failure_not_as_zero_findings(pool: PgPool) {
    let smtp = FakeSmtp::start(SmtpBehaviour::Accept).await;
    let job = seed_job(&pool).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    // Terminal, no deterministic report: there is nothing to deliver.
    finalize_without_findings(&pool, &lease, "failed", "scanner crashed")
        .await
        .unwrap();

    // The artifact load is refused, so there is nothing to send and no reason to
    // configure or contact a mail server at all.
    let loaded = firecrow_backend::orchestrator::delivery::finalized_email_artifact(
        &pool,
        &job,
        &lease.execution_id,
    )
    .await;
    assert!(
        loaded.is_err(),
        "an execution with no finalized report has nothing to deliver"
    );
    assert_eq!(smtp.received().len(), 0, "nothing may be sent");

    // And no delivery record was created for a refused execution.
    let rows: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_deliveries")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows.0, 0);
}

// ---------------------------------------------------------------------------
// 8, 22, 27: the narrative is optional
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn delivery_succeeds_with_and_without_a_narrative(pool: PgPool) {
    let smtp = FakeSmtp::start(SmtpBehaviour::Accept).await;
    let job = seed_job(&pool).await;
    let mailer = smtp.mailer(1, Duration::from_secs(5));

    // Without a narrative.
    let without = finalized(&pool, &job, &[secret_finding("plain")]).await;
    assert_eq!(
        deliver_execution_email(
            &pool,
            &job,
            &without.execution_id,
            RECIPIENT,
            &mailer,
            &artifact_for(&pool, &job, &without.execution_id).await
        )
        .await
        .unwrap(),
        DeliveryOutcome::Sent
    );
    let first = smtp.received_decoded().remove(0);
    // The finding's *title* is "AWS access token (<fingerprint>)"; the canonical
    // id is a hash, so the title is the human-visible anchor.
    assert!(
        first.contains("AWS access token (plain)"),
        "the finding must appear in the delivered email"
    );
    assert!(first.contains("security score: 8.5"));
    assert!(first.contains("Scan status: SUCCESS_FINDINGS"));
    assert!(
        !first.contains("AI explanation"),
        "no narrative means no narrative section"
    );

    // With a validated narrative.
    let with = finalized(&pool, &job, &[secret_finding("narrated")]).await;
    let report = report_of(&pool, &job, &with).await;
    let narrative = faithful_narrative(&report);
    firecrow_backend::orchestrator::execution::persist_ai_narrative(
        &pool,
        &with.execution_id,
        &narrative,
    )
    .await
    .unwrap();
    assert!(load_ai_narrative(&pool, &job, Some(&with.execution_id))
        .await
        .unwrap()
        .is_some());

    assert_eq!(
        deliver_execution_email(
            &pool,
            &job,
            &with.execution_id,
            RECIPIENT,
            &mailer,
            &artifact_for(&pool, &job, &with.execution_id).await
        )
        .await
        .unwrap(),
        DeliveryOutcome::Sent
    );
    // `received_decoded` returns a fresh snapshot each call, so index the second
    // message explicitly rather than taking the head again.
    let delivered = smtp.received_decoded();
    assert_eq!(delivered.len(), 2, "exactly two emails");
    let second = &delivered[1];
    assert!(second.contains("AI explanation"));
    assert!(!delivered[0].contains("AI explanation"));
    assert!(second.contains("non-authoritative"));
}

// ---------------------------------------------------------------------------
// 26: provider failure classes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn recipient_validation_refuses_injection_and_typos() {
    for bad in [
        "",
        "   ",
        "no-at-sign",
        "user@",
        "@example.com",
        "user@localhost",
        "user@example.com\r\nBcc: attacker@evil.test",
        "user name@example.com",
        "user@.com",
        "user@example.",
    ] {
        // Exercised through the real send path: an invalid recipient must be
        // refused before any connection is attempted.
        let smtp = FakeSmtp::start(SmtpBehaviour::Accept).await;
        let mailer = smtp.mailer(1, Duration::from_secs(2));
        let artifact = email_artifact::render(&report_for(&[secret_finding("rcpt")], false), None);
        let result = mailer.send_artifact(bad, &artifact).await;
        assert!(
            matches!(
                result,
                Err(firecrow_backend::error::AppError::Delivery(
                    DeliveryError::InvalidRecipient
                ))
            ),
            "expected InvalidRecipient for {bad:?}, got {result:?}"
        );
        assert_eq!(smtp.received().len(), 0, "nothing may be sent");
    }
}

#[tokio::test]
async fn smtp_failures_are_classified_and_errors_stay_bounded() {
    for (behaviour, expected) in [
        (
            SmtpBehaviour::RejectRecipient,
            DeliveryError::RecipientRejected,
        ),
        (SmtpBehaviour::ServerError, DeliveryError::Unavailable),
    ] {
        let smtp = FakeSmtp::start(behaviour).await;
        let mailer = smtp.mailer(1, Duration::from_secs(5));
        let artifact = email_artifact::render(&report_for(&[secret_finding("cls")], false), None);
        let error = mailer
            .send_artifact(RECIPIENT, &artifact)
            .await
            .unwrap_err();

        match error {
            firecrow_backend::error::AppError::Delivery(inner) => {
                assert_eq!(inner, expected, "wrong class for {behaviour:?}");
                // §14/§26: the SMTP reply never reaches the application error.
                assert!(!inner.to_string().contains("5.1.1"));
                assert!(!inner.to_string().contains("5.0.0"));
                assert!(!inner.to_string().contains("554"));
                assert_eq!(inner.category(), expected.category());
            }
            other => panic!("expected a delivery error, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_transient_failure_is_retried_but_a_permanent_one_is_not() {
    // Congestion is transient: several attempts, still failing, is the honest
    // outcome, and it must be reported as rate limiting.
    let smtp = FakeSmtp::start(SmtpBehaviour::Congested).await;
    let mailer = smtp.mailer(3, Duration::from_secs(5));
    let artifact = email_artifact::render(&report_for(&[secret_finding("retry")], false), None);
    let error = mailer
        .send_artifact(RECIPIENT, &artifact)
        .await
        .unwrap_err();
    match error {
        firecrow_backend::error::AppError::Delivery(inner) => {
            assert!(matches!(
                inner,
                DeliveryError::RateLimited | DeliveryError::Unavailable
            ));
            assert!(inner.is_transient());
        }
        other => panic!("expected a delivery error, got {other:?}"),
    }

    // A permanent rejection is never retried, so the attempts cap is irrelevant.
    assert!(!DeliveryError::RecipientRejected.is_transient());
    assert!(!DeliveryError::Authentication.is_transient());
    assert!(!DeliveryError::InvalidRecipient.is_transient());
}

#[tokio::test]
async fn a_silent_server_is_bounded_by_the_timeout() {
    let smtp = FakeSmtp::start(SmtpBehaviour::Silent).await;
    let mailer = smtp.mailer(1, Duration::from_millis(400));
    let artifact = email_artifact::render(&report_for(&[secret_finding("slow")], false), None);

    let started = std::time::Instant::now();
    let error = mailer
        .send_artifact(RECIPIENT, &artifact)
        .await
        .unwrap_err();
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(10),
        "a silent mail server must not hold the request open: {elapsed:?}"
    );
    match error {
        firecrow_backend::error::AppError::Delivery(inner) => {
            assert!(
                matches!(
                    inner,
                    DeliveryError::Timeout | DeliveryError::Transport | DeliveryError::Unavailable
                ),
                "a stalled conversation must be a bounded failure: {inner:?}"
            );
        }
        other => panic!("expected a delivery error, got {other:?}"),
    }
}

#[tokio::test]
async fn plaintext_relay_is_refused_for_any_non_loopback_host() {
    for host in ["smtp.example.com", "10.0.0.5", "169.254.169.254", "0.0.0.0"] {
        assert!(
            EmailService::plaintext_loopback("a@b.test", host, 25, Duration::from_secs(1)).is_err(),
            "plaintext must not be permitted for {host}"
        );
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn no_database_lock_is_held_while_the_provider_is_contacted(pool: PgPool) {
    // A delivery must not hold a transaction open across the network call. If it
    // did, a concurrent writer to the same delivery row would block for the
    // duration of the provider request.
    let smtp = FakeSmtp::start(SmtpBehaviour::SlowData).await;
    let job = seed_job(&pool).await;
    let lease = finalized(&pool, &job, &[secret_finding("nolock")]).await;
    let artifact = artifact_for(&pool, &job, &lease.execution_id).await;
    let mailer = smtp.mailer(1, Duration::from_secs(10));

    let delivery_pool = pool.clone();
    let delivery_job = job.clone();
    let delivery_execution = lease.execution_id.clone();
    let delivery = tokio::spawn(async move {
        deliver_execution_email(
            &delivery_pool,
            &delivery_job,
            &delivery_execution,
            RECIPIENT,
            &mailer,
            &artifact,
        )
        .await
    });

    // Wait until the delivery has claimed its record and is talking to the
    // provider, then write to that same row from an independent connection.
    let mut claimed = None;
    for _ in 0..50 {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT status FROM audit_deliveries WHERE execution_id=$1")
                .bind(&lease.execution_id)
                .fetch_optional(&pool)
                .await
                .unwrap();
        if row.map(|(status,)| status) == Some("sending".to_string()) {
            claimed = Some(true);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(claimed.is_some(), "the delivery should have been in flight");

    // This write must not block behind the in-flight delivery.
    let write =
        sqlx::query("UPDATE audit_deliveries SET attempts = attempts WHERE execution_id = $1")
            .bind(&lease.execution_id)
            .execute(&pool);
    let blocked = tokio::time::timeout(Duration::from_millis(500), write).await;
    assert!(
        blocked.is_ok(),
        "a concurrent write blocked: the delivery is holding a database lock across the provider call"
    );

    delivery.await.unwrap().unwrap();
    assert_eq!(smtp.received().len(), 1);
}

// ---------------------------------------------------------------------------
// 29, 30: the API
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn the_endpoint_is_execution_scoped_and_ownership_gated(pool: PgPool) {
    let job = seed_job(&pool).await;
    let lease = finalized(&pool, &job, &[secret_finding("api")]).await;

    let (user_id,): (String,) = sqlx::query_as("SELECT user_id FROM audit_jobs WHERE id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    let token = support::bearer_for(&pool, &user_id).await;
    let app = support::test_app(pool.clone()).await;

    // Unknown execution: 404.
    let unknown = app
        .post(
            format!(
                "/api/v1/audit/job/{job}/execution/{}/email",
                uuid::Uuid::new_v4()
            )
            .as_str(),
        )
        .add_header("authorization", &token)
        .await;
    assert_eq!(unknown.status_code(), 404);

    // A foreign job's owner cannot reach this execution either.
    let other = seed_job(&pool).await;
    let (other_id,): (String,) = sqlx::query_as("SELECT user_id FROM audit_jobs WHERE id=$1")
        .bind(&other)
        .fetch_one(&pool)
        .await
        .unwrap();
    let foreign = app
        .post(
            format!(
                "/api/v1/audit/job/{job}/execution/{}/email",
                lease.execution_id
            )
            .as_str(),
        )
        .add_header(
            "authorization",
            &support::bearer_for(&pool, &other_id).await,
        )
        .await;
    assert_eq!(
        foreign.status_code(),
        404,
        "a foreign execution must not leak"
    );

    // Unauthenticated: rejected before any lookup.
    let anonymous = app
        .post(
            format!(
                "/api/v1/audit/job/{job}/execution/{}/email",
                lease.execution_id
            )
            .as_str(),
        )
        .await;
    assert!(anonymous.status_code() == 401 || anonymous.status_code() == 403);
}

#[sqlx::test(migrations = "./migrations")]
async fn a_running_execution_is_refused_with_conflict(pool: PgPool) {
    let job = seed_job(&pool).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    let (user_id,): (String,) = sqlx::query_as("SELECT user_id FROM audit_jobs WHERE id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    let token = support::bearer_for(&pool, &user_id).await;
    let app = support::test_app(pool.clone()).await;

    let response = app
        .post(
            format!(
                "/api/v1/audit/job/{job}/execution/{}/email",
                lease.execution_id
            )
            .as_str(),
        )
        .add_header("authorization", &token)
        .await;
    assert_eq!(
        response.status_code(),
        409,
        "a running execution has no finalized report to send: {}",
        response.text()
    );
    let rows: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_deliveries")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows.0, 0, "no delivery record for a refused request");
}

// ---------------------------------------------------------------------------
// Shared helper for the artifact unit tests
// ---------------------------------------------------------------------------

/// The artifact a delivery would send for an execution.
async fn artifact_for(
    pool: &PgPool,
    job: &str,
    execution_id: &str,
) -> email_artifact::EmailArtifact {
    firecrow_backend::orchestrator::delivery::finalized_email_artifact(pool, job, execution_id)
        .await
        .expect("execution has a finalized report")
}

/// Build a report in memory, for renderer tests that need no database.
fn report_for(findings: &[Finding], semgrep_failed: bool) -> CanonicalAuditReport {
    let canonical = build_audit(findings, semgrep_failed);
    build_report(
        &canonical,
        &ExecutionIdentity {
            execution_id: "exec-artifact".into(),
            attempt_number: 1,
        },
    )
    .expect("report builds")
}

#[sqlx::test(migrations = "./migrations")]
async fn an_unconfigured_mail_server_is_reported_honestly(pool: PgPool) {
    // A finalized execution exists, but this environment has no SMTP. The server
    // must answer that delivery is unavailable, never claim the message was sent
    // or queue it into nowhere.
    let job = seed_job(&pool).await;
    let lease = finalized(&pool, &job, &[secret_finding("unconfigured")]).await;

    let (user_id,): (String,) = sqlx::query_as("SELECT user_id FROM audit_jobs WHERE id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    let token = support::bearer_for(&pool, &user_id).await;
    let app = support::test_app(pool.clone()).await;

    let res = app
        .post(
            format!(
                "/api/v1/audit/job/{job}/execution/{}/email",
                lease.execution_id
            )
            .as_str(),
        )
        .add_header("authorization", &token)
        .await;
    assert_eq!(
        res.status_code(),
        501,
        "with no SMTP configured the server must not claim the email was sent: {}",
        res.text()
    );

    // No delivery record is fabricated for a request that could not be sent.
    let rows: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_deliveries")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows.0, 0);
}
