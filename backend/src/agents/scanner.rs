//! Scanner runtime — the `scan` phase.
//!
//! One execution interface for every real security tool:
//!
//! ```text
//! Scanner
//! ├── name          (name, version, mode)
//! ├── command       (argv, never a shell string)
//! ├── timeout       (wall-clock ceiling)
//! ├── resource limits (cpus, memory, pids)
//! ├── input snapshot  (ScanInput: the tree to scan + what it contains)
//! └── parser        (raw stdout -> findings)
//! ```
//!
//! # The rule this module exists to enforce
//!
//! Scanner failure is **not** zero findings. A scanner that crashes, times
//! out, is cancelled, or emits an unparseable report is *unknown coverage* —
//! never "clean". Only [`ScannerOutcome::Success`] may report a finding count,
//! and only an empty *successful* report means zero findings.
//!
//! [`ScannerResult::usable`] and [`ScannerResult::analyzed`] encode that
//! invariant for callers: `analyzed` is true only when a scanner actually
//! reported, so scoring can never silently rest on a failed scan.

use crate::error::{AppError, Result};
use crate::models::Severity;
use crate::schemas::audit_state::Finding;
use crate::services::redaction::redact_text;
use crate::services::sandbox::{
    NetworkMode, ResourceLimits, SandboxManager, SandboxMount, SandboxOutput, SandboxSpec,
    MAX_STDERR_BYTES, MAX_STDOUT_BYTES, SCAN_MOUNT,
};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// The pinned gitleaks image.
///
/// Pinned to a specific tag, never `latest`: a scanner that changes underneath
/// Fire Crow makes an audit result impossible to reproduce.
pub const GITLEAKS_IMAGE: &str = "ghcr.io/gitleaks/gitleaks:v8.18.4";
/// Container path the repository is mounted at (read-only). Re-exported from
/// the sandbox so the mount contract has one definition.
pub use crate::services::sandbox::SCAN_MOUNT as SOURCE_MOUNT;
/// Container path of the structured JSON artifact gitleaks writes. The report
/// is a file on the tmpfs scratch area — not log-mixed stdout — and is
/// streamed back with `cat`; stdout is only the pipe, never the report itself.
pub const GITLEAKS_REPORT_PATH: &str = "/work/gitleaks.json";
/// Parser that reads the artifact above. Recorded on the descriptor and the
/// execution record so a finding stays traceable to its reader.
pub const GITLEAKS_PARSER: &str = "gitleaks-json-v1";
/// The pinned OSV-Scanner image: dependency vulnerabilities, never `latest`.
pub const OSV_IMAGE: &str = "ghcr.io/google/osv-scanner:v2.2.4";
/// Container path of the OSV JSON artifact, same file-handshake as gitleaks.
pub const OSV_REPORT_PATH: &str = "/work/osv.json";
/// Parser for the OSV artifact.
pub const OSV_PARSER: &str = "osv-json-v1";
/// Scanner name recorded on every dependency finding.
pub const OSV_SCANNER_NAME: &str = "osv";
/// Scanner mode recorded on every dependency finding.
pub const OSV_SCANNER_MODE: &str = "dependency";
/// Wall-clock ceiling for a dependency scan.
pub const OSV_TIMEOUT_SECS: u64 = 300;
/// The pinned Semgrep image. Static analysis needs no network and no database.
pub const SEMGREP_IMAGE: &str = "semgrep/semgrep:1.96.0";
/// Container path of the Semgrep JSON artifact.
pub const SEMGREP_REPORT_PATH: &str = "/work/semgrep.json";
/// Parser for the Semgrep artifact.
pub const SEMGREP_PARSER: &str = "semgrep-json-v1";
/// Scanner name recorded on every source-code finding.
pub const SEMGREP_SCANNER_NAME: &str = "semgrep";
/// Scanner mode recorded on every source-code finding.
pub const SEMGREP_SCANNER_MODE: &str = "sast";
/// Wall-clock ceiling for a SAST pass. Semgrep parses whole files, so this is
/// the longest of the three scanners by design.
pub const SEMGREP_TIMEOUT_SECS: u64 = 600;
/// Container path of the pinned ruleset directory.
pub const SEMGREP_RULES_DIR: &str = "/config";
/// The pinned ruleset file inside [`SEMGREP_RULES_DIR`].
pub const SEMGREP_RULESET_PATH: &str = "/config/firecrow-sast.yml";
/// Host directory holding [`SEMGREP_RULESET_PATH`].
///
/// Resolved at run time so the ruleset lives in the repository (auditable,
/// version-controlled) rather than baked into an image. It is exposed to the
/// container read-only and is the only non-repository path a scanner sees.
pub fn semgrep_ruleset_host_dir() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR is `<backend>/`, and the ruleset sits beside `src/`.
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scanners/semgrep")
}
/// Wall-clock ceiling for a scan.
pub const SCAN_TIMEOUT_SECS: u64 = 300;
/// Scanner name recorded on every finding.
pub const SCANNER_NAME: &str = "gitleaks";
/// Scanner mode recorded on every finding.
pub const SCANNER_MODE: &str = "secret";
/// Maximum characters retained from an evidence snippet.
pub const SNIPPET_MAX_CHARS: usize = 400;
/// Maximum characters retained from a scanner's stderr in an execution record.
pub const STDERR_MAX_CHARS: usize = 1000;

/// How a scanner execution ended.
///
/// These four cases are exhaustive and deliberately distinct. In particular
/// there is no "failed but returning an empty list" case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScannerOutcome {
    /// The scanner ran to completion and its report parsed. `finding_count` is
    /// the scanner's own count, which may legitimately be 0.
    Success { finding_count: usize },
    /// The scanner did not produce a trustworthy result: non-zero exit, spawn
    /// failure, or an unparseable report. Coverage is **unknown**.
    Failed { reason: String },
    /// The scanner exceeded its wall-clock ceiling. Coverage is **unknown**.
    Timeout { limit_secs: u64 },
    /// The scan was cancelled by the operator before or during execution.
    /// Coverage is **unknown**, and not a failure.
    Cancelled,
}

impl ScannerOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success { .. } => "success",
            Self::Failed { .. } => "failed",
            Self::Timeout { .. } => "timeout",
            Self::Cancelled => "cancelled",
        }
    }

    /// True only when a scanner actually reported. Every other outcome means
    /// the scan's coverage is unknown.
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success { .. })
    }
}

/// The tree a scanner is asked to analyze.
///
/// Carrying the snapshot alongside the directory means an execution record can
/// always state exactly what was scanned, so a later finding is traceable to a
/// concrete tree rather than a bare path.
#[derive(Debug, Clone)]
pub struct ScanInput {
    /// Local directory holding the extracted repository.
    pub source_dir: PathBuf,
    /// Branch head the tree came from, when known.
    pub commit_sha: Option<String>,
    /// Files in the tree.
    pub file_count: usize,
    /// Total bytes in the tree.
    pub total_size: u64,
}

impl ScanInput {
    /// Build an input from a directory alone, for callers with no snapshot.
    pub fn from_dir(source_dir: &Path) -> Self {
        Self {
            source_dir: source_dir.to_path_buf(),
            commit_sha: None,
            file_count: 0,
            total_size: 0,
        }
    }

    /// The read-only mount for this input, at the container path scanners
    /// expect. The repository is the only host path exposed.
    pub fn mounts(&self) -> Vec<SandboxMount> {
        vec![SandboxMount {
            host_path: self.source_dir.to_string_lossy().to_string(),
            container_path: SCAN_MOUNT.to_string(),
            // Scanners observe the tree; they never modify it.
            read_only: true,
        }]
    }

    /// The sandbox invocation this input implies: the scanner's own image,
    /// command, timeout, and limits, with the repository mounted read-only.
    pub fn sandbox_spec(&self, scanner: &Scanner) -> SandboxSpec {
        let mut mounts = self.mounts();
        mounts.extend(scanner.extra_mounts.iter().cloned());
        SandboxSpec::new(
            scanner.image,
            scanner.command.clone(),
            mounts,
            scanner.timeout_secs,
            scanner.resource_limits.clone(),
        )
        .with_entrypoint(scanner.entrypoint)
        .with_network(scanner.network)
        .with_output_caps(MAX_STDOUT_BYTES, MAX_STDERR_BYTES)
        .with_extra_tmpfs(&scanner.extra_tmpfs)
        .with_env(&scanner.env)
    }
}

/// Identity, execution parameters, and output parser for one scanner.
#[derive(Debug, Clone)]
pub struct Scanner {
    /// Recorded on every finding, e.g. `gitleaks`.
    pub name: &'static str,
    /// Pinned tool version, so a finding's provenance stays reproducible.
    pub version: &'static str,
    /// Detection category, e.g. `secret`.
    pub mode: &'static str,
    /// Container image the tool runs from.
    pub image: &'static str,
    /// Optional entrypoint override (`sh` for gitleaks, to emit the report
    /// file). `None` keeps the image default.
    pub entrypoint: Option<&'static str>,
    /// Argument vector. Never a shell string, so tool output cannot become
    /// shell syntax — except the scanner-owned `sh -c` wrapper built from
    /// constants (see [`Scanner::gitleaks`]), which carries no untrusted bytes.
    pub command: Vec<String>,
    /// Which parser reads the report artifact, e.g. [`GITLEAKS_PARSER`].
    pub parser: &'static str,
    /// Network access this scanner requires. Deny-by-default: the secret and
    /// source scanners ask for [`NetworkMode::None`], and only the dependency
    /// scanner declares the live-database exception (`Scanner::osv`).
    pub network: NetworkMode,
    pub timeout_secs: u64,
    pub resource_limits: ResourceLimits,
    /// Extra in-memory scratch paths this tool needs to start (e.g. `/tmp`).
    /// Empty for tools that run against a read-only root with no runtime
    /// state.
    pub extra_tmpfs: Vec<String>,
    /// Environment this tool needs (e.g. `HOME`). The sandbox clears the
    /// ambient environment, so anything not listed here is absent by design.
    pub env: Vec<(String, String)>,
    /// Additional read-only host directories to expose, beyond the snapshot.
    /// Used for pinned scanner configuration such as a local ruleset: the
    /// snapshot is the only *repository* path, but a scanner's own rules are
    /// part of its contract and must be reproducible.
    pub extra_mounts: Vec<SandboxMount>,
}

impl Scanner {
    /// A secret scanner built on gitleaks, the one this build runs.
    ///
    /// The report is written to [`GITLEAKS_REPORT_PATH`] and streamed back
    /// with `cat`; that shell text is fixed and built from constants only, so
    /// repository content can never become shell syntax. `--exit-code=1` keeps
    /// gitleaks' own signal (0 clean, 1 leaks-or-error); the parser, not the
    /// exit code, decides success (see [`classify`]).
    pub fn gitleaks() -> Self {
        Self {
            name: SCANNER_NAME,
            version: "8.18.4",
            mode: SCANNER_MODE,
            image: GITLEAKS_IMAGE,
            entrypoint: Some("sh"),
            command: vec![
                "-c".into(),
                format!(
                    "gitleaks detect --no-git --source={SOURCE_MOUNT} \
                     --report-format=json --report-path={GITLEAKS_REPORT_PATH} \
                     --exit-code=1 --log-level=error; \
                     code=$?; cat {GITLEAKS_REPORT_PATH} 2>/dev/null; exit $code"
                ),
            ],
            parser: GITLEAKS_PARSER,
            network: NetworkMode::None,
            timeout_secs: SCAN_TIMEOUT_SECS,
            resource_limits: ResourceLimits::default(),
            extra_tmpfs: Vec::new(),
            env: Vec::new(),
            extra_mounts: Vec::new(),
        }
    }

    /// A dependency scanner built on OSV-Scanner.
    ///
    /// Same file-artifact handshake as gitleaks (`--output` to
    /// [`OSV_REPORT_PATH`], streamed back with `cat`). Unlike gitleaks it
    /// needs the network: matching runs against the live OSV database over
    /// HTTPS. That egress is declared here, confined to this scanner, and
    /// asserted in tests — the secret scanner stays fully offline.
    pub fn osv() -> Self {
        Self {
            name: OSV_SCANNER_NAME,
            version: "2.2.4",
            mode: OSV_SCANNER_MODE,
            image: OSV_IMAGE,
            entrypoint: Some("sh"),
            command: vec![
                "-c".into(),
                // Absolute binary path: the image entrypoint is /osv-scanner
                // but it is not on PATH for `sh -c`. `--allow-no-lockfiles`
                // turns "no package sources" (e.g. a secrets-only repo) into
                // a valid empty report instead of exit 128 with no report;
                // an unsupported manifest still fails closed as missing.
                format!(
                    "/osv-scanner scan source --recursive --allow-no-lockfiles --format=json --output={OSV_REPORT_PATH} \
                     --verbosity=error {SOURCE_MOUNT}; \
                     code=$?; cat {OSV_REPORT_PATH} 2>/dev/null; exit $code"
                ),
            ],
            parser: OSV_PARSER,
            network: NetworkMode::Bridge,
            timeout_secs: OSV_TIMEOUT_SECS,
            resource_limits: ResourceLimits::default(),
            extra_tmpfs: Vec::new(),
            env: Vec::new(),
            extra_mounts: Vec::new(),
        }
    }

    /// A static-analysis scanner built on Semgrep.
    ///
    /// Fully offline, like the secret scanner: a registry ruleset would be
    /// fetched over the network, so the ruleset is a local pinned file
    /// ([`SEMGREP_RULESET_PATH`]) and the same rules produce the same findings
    /// on every run.
    ///
    /// The wrapper works around three properties of the pinned image, all
    /// established by running it:
    ///
    /// * the binary is not on `PATH` for `sh -c`, so it is called absolutely;
    /// * the root filesystem is read-only, so it gets a `/tmp` scratch tmpfs
    ///   and a writable `HOME` — both in-memory, never a writable root;
    /// * stdout carries a human-readable summary, not the report, so it is
    ///   discarded and the JSON artifact is what gets streamed back.
    ///
    /// `--no-git-ignore` is deliberate: a repository must not be able to ship a
    /// `.gitignore` that hides its own source from the scanner.
    pub fn semgrep() -> Self {
        Self {
            name: SEMGREP_SCANNER_NAME,
            version: "1.96.0",
            mode: SEMGREP_SCANNER_MODE,
            image: SEMGREP_IMAGE,
            entrypoint: Some("sh"),
            command: vec![
                "-c".into(),
                format!(
                    "semgrep scan --config={SEMGREP_RULESET_PATH} \
                     --json-output={SEMGREP_REPORT_PATH} --quiet --no-git-ignore \
                     --disable-version-check --metrics=off {SOURCE_MOUNT} >/dev/null; \
                     code=$?; cat {SEMGREP_REPORT_PATH} 2>/dev/null; exit $code"
                ),
            ],
            parser: SEMGREP_PARSER,
            // No database, no registry: static analysis needs no network, and
            // SAST reads the whole source tree, so it must not be able to send
            // any of it anywhere.
            network: NetworkMode::None,
            timeout_secs: SEMGREP_TIMEOUT_SECS,
            // Semgrep parses whole files and is the heaviest of the three
            // scanners, so it gets more room than the others — still bounded.
            resource_limits: ResourceLimits {
                cpus: 2.0,
                memory: "2g".into(),
                pids_limit: 512,
            },
            // Reads source rather than shipping a report through stdout.
            extra_tmpfs: vec!["/tmp".into()],
            env: vec![("HOME".into(), "/work".into())],
            // The ruleset directory, mounted read-only next to the snapshot.
            extra_mounts: vec![SandboxMount {
                host_path: semgrep_ruleset_host_dir().to_string_lossy().to_string(),
                container_path: SEMGREP_RULES_DIR.to_string(),
                read_only: true,
            }],
        }
    }

    /// The stable identifier used as the `scanner_execution` map key.
    pub fn execution_key(&self) -> String {
        self.name.to_string()
    }
}

/// The result of one scanner execution.
#[derive(Debug, Clone)]
pub struct ScannerResult {
    /// Name/version/mode that produced this result.
    pub scanner: String,
    pub version: String,
    pub mode: String,
    pub outcome: ScannerOutcome,
    /// Findings from the parser. Populated **only** on
    /// [`ScannerOutcome::Success`] — a failed run carries no findings, so an
    /// empty list can never be read as "clean".
    pub findings: Vec<Finding>,
    /// Persisted verbatim into `AuditState::scanner_execution`.
    pub execution_record: serde_json::Value,
}

impl ScannerResult {
    /// True when a scanner actually reported, so the findings list is
    /// authoritative. False means unknown coverage.
    pub fn analyzed(&self) -> bool {
        self.outcome.is_success()
    }

    /// Whether the pipeline may report a result from this execution.
    ///
    /// Only a successful run qualifies. A `Cancelled` run is not a failure but
    /// is not a result either, so it is excluded.
    pub fn usable(&self) -> bool {
        self.analyzed()
    }
}

/// Execute `scanner` over `input`, returning an explicit outcome.
///
/// Never returns an error for a scanner-side problem: a crash, output flood,
/// timeout, or cancelled run is a [`ScannerOutcome`], not an `Err`, so no caller
/// can accidentally discard the distinction or read a failure as zero findings.
pub async fn execute(
    scanner: &Scanner,
    input: &ScanInput,
    sandbox: &SandboxManager,
    cancel: &(dyn Fn() -> bool + Sync),
) -> ScannerResult {
    // Checked before any work: a cancelled scan must not start.
    if cancel() {
        return cancelled_result(scanner, input);
    }
    let run = sandbox.run(&input.sandbox_spec(scanner), cancel).await;
    // A cancellation that arrived mid-execution wins over whatever the tool
    // managed to emit; partial output is not a result.
    if cancel() {
        return cancelled_result(scanner, input);
    }
    classify(scanner, input, run)
}

/// Map a finished sandbox run onto an outcome and a result.
///
/// Pure, so every outcome is verifiable without Docker. The report artifact is
/// authoritative, not the exit code: gitleaks exits 1 both when it finds a
/// leak and when it errors, so exit 1 with a valid report is `Success` ("I
/// found a secret"), while an unreadable or missing report is `Failed`
/// (unknown coverage) however the process exited. Only timeouts, cancellations
/// (checked by the caller), and output floods map elsewhere.
pub fn classify(scanner: &Scanner, input: &ScanInput, run: Result<SandboxOutput>) -> ScannerResult {
    match run {
        Ok(out) => match scanner.parser {
            GITLEAKS_PARSER => classify_gitleaks(scanner, input, &out),
            OSV_PARSER => classify_osv(scanner, input, &out),
            SEMGREP_PARSER => classify_semgrep(scanner, input, &out),
            unknown => failed_result(
                scanner,
                input,
                format!("unknown scanner parser {unknown:?}"),
                serde_json::json!({ "detail": "unknown_parser" }),
            ),
        },
        // A dedicated timeout variant keeps TIMEOUT from collapsing into
        // FAILED; the two mean different things to the operator.
        Err(AppError::Timeout(_)) => timeout_result(scanner, input),
        // Cancellation is its own outcome, never a failure and never a result.
        Err(AppError::Cancelled(_)) => cancelled_result(scanner, input),
        // A scanner that floods stdout/stderr is FAILED with an explicit
        // reason: its report cannot be trusted, and it must not be allowed to
        // dictate worker memory either way.
        Err(AppError::OutputLimitExceeded { stream, cap_bytes }) => failed_result(
            scanner,
            input,
            format!("output_limit_exceeded: {stream} exceeded {cap_bytes} bytes"),
            serde_json::json!({
                "detail": "output_limit_exceeded",
                "stream": stream,
                "cap_bytes": cap_bytes,
            }),
        ),
        Err(e) => failed_result(
            scanner,
            input,
            e.to_string(),
            serde_json::json!({ "detail": "scanner could not be executed" }),
        ),
    }
}

/// Gitleaks half of [`classify`]: the report artifact is authoritative (see the
/// truth table on [`classify`]).
fn classify_gitleaks(scanner: &Scanner, input: &ScanInput, out: &SandboxOutput) -> ScannerResult {
    // No bytes on a non-zero exit means the scanner died before the
    // `cat` could stream the artifact: a missing report, never clean.
    if out.stdout.trim().is_empty() && !out.success {
        return failed_result(
            scanner,
            input,
            "scanner produced no report".to_string(),
            serde_json::json!({
                "detail": "missing_report",
                "stderr": redact_text(&out.stderr, STDERR_MAX_CHARS),
            }),
        );
    }
    match parse_gitleaks_report(&out.stdout) {
        Ok(raw) => {
            let findings: Vec<Finding> = raw.iter().map(finding_from_gitleaks).collect();
            let count = findings.len();
            success_result(
                scanner,
                input,
                findings,
                serde_json::json!({ "finding_count": count }),
            )
        }
        // A report we cannot read means unknown coverage, not zero
        // findings: the scanner may well have found something.
        Err(e) => failed_result(
            scanner,
            input,
            format!("scanner report was not parseable: {e}"),
            serde_json::json!({
                "detail": "parse_error",
                "stderr": redact_text(&out.stderr, STDERR_MAX_CHARS),
            }),
        ),
    }
}

/// OSV half of [`classify`].
///
/// Truth table (pinned `osv-scanner v2.2.4` documents exits 0/1/127/128/129+;
/// only the report decides between success and failure):
///
/// ```text
/// exit  report                        meaning              outcome
/// 0     valid, no vulns               clean                SUCCESS 0
/// 1     valid, N vulns                findings             SUCCESS N
/// 128   valid, empty                  no packages declared SUCCESS 0
/// any   invalid JSON / wrong shape    broken report        FAILED
/// !=0   empty                         died before report   FAILED
/// ```
///
/// Timeout, cancellation, and output floods are handled by [`classify`]
/// itself, before this runs. stderr is bounded and passed through the generic
/// credential redactor before it is persisted; advisory fields are never fed
/// to that redactor, only truncated — package metadata is not secret
/// material, and blind redaction would mangle legitimate names.
fn classify_osv(scanner: &Scanner, input: &ScanInput, out: &SandboxOutput) -> ScannerResult {
    if out.stdout.trim().is_empty() && !out.success {
        return failed_result(
            scanner,
            input,
            "scanner produced no report".to_string(),
            serde_json::json!({
                "detail": "missing_report",
                "stderr": redact_text(&out.stderr, STDERR_MAX_CHARS),
            }),
        );
    }
    match parse_osv_report(&out.stdout) {
        Ok(doc) => {
            let findings = findings_from_doc(&doc, &input.source_dir);
            let count = findings.len();
            success_result(
                scanner,
                input,
                findings,
                serde_json::json!({ "finding_count": count }),
            )
        }
        Err(e) => failed_result(
            scanner,
            input,
            format!("scanner report was not parseable: {e}"),
            serde_json::json!({
                "detail": "parse_error",
                "stderr": redact_text(&out.stderr, STDERR_MAX_CHARS),
            }),
        ),
    }
}

/// One `results[]` entry of `osv-scanner scan source --format=json`
/// (v2.2.4). Vulnerabilities are full OSV records; only the fields Fire Crow
/// canonicalizes are modeled, the rest is ignored. Never leaves the adapter.
#[derive(Debug, Clone, Deserialize)]
struct OsvDoc {
    /// Required: its absence (or a non-object top level) is an unexpected
    /// schema and fails the run. Note this must NOT carry `#[serde(default)]`:
    /// serde builds all-default structs from an empty sequence, so a default
    /// here would read a bare `[]` or `{}` as a clean report.
    ///
    /// `Option` only because the pinned version emits `"results": null` for a
    /// run that found no package sources — a real, successful empty report,
    /// verified against `v2.2.4`. `null` and `[]` both mean "no results";
    /// a missing key still fails.
    pub results: Option<Vec<OsvSourceResult>>,
}

#[derive(Debug, Clone, Deserialize)]
struct OsvSourceResult {
    #[serde(default)]
    pub source: OsvSource,
    #[serde(default)]
    pub packages: Vec<OsvPackageResult>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct OsvSource {
    #[serde(default)]
    pub path: String,
    #[serde(rename = "type", default)]
    pub source_type: String,
}

#[derive(Debug, Clone, Deserialize)]
struct OsvPackageResult {
    #[serde(default)]
    pub package: OsvPackageId,
    #[serde(default)]
    pub vulnerabilities: Vec<OsvVuln>,
    #[serde(default)]
    pub groups: Vec<OsvGroup>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct OsvPackageId {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub ecosystem: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct OsvVuln {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,
    #[serde(default)]
    pub affected: Vec<OsvAffected>,
    #[serde(default)]
    pub references: Vec<OsvRef>,
    #[serde(default)]
    pub database_specific: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    pub severity_type: String,
    #[serde(default)]
    pub score: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct OsvAffected {
    #[serde(default)]
    pub package: OsvAffectedPackage,
    #[serde(default)]
    pub ranges: Vec<OsvRange>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct OsvAffectedPackage {
    #[serde(default)]
    pub ecosystem: String,
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct OsvRange {
    #[serde(rename = "type")]
    pub range_type: String,
    #[serde(default)]
    pub events: Vec<OsvEvent>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct OsvEvent {
    #[serde(default)]
    pub introduced: String,
    #[serde(default)]
    pub fixed: Option<String>,
    #[serde(default)]
    pub last_affected: Option<String>,
    #[serde(default)]
    pub limit: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct OsvRef {
    #[serde(rename = "type", default)]
    pub ref_type: String,
    #[serde(default)]
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
struct OsvGroup {
    #[serde(default)]
    pub ids: Vec<String>,
}

// ---------------------------------------------------------------------------
// Semgrep adapter (Phase 9)
//
// The raw model below is private to this module. The only way out is
// [`findings_from_semgrep`], which takes a report body and returns canonical
// `Finding`s, so nothing in Fire Crow can hold an unparsed Semgrep record.
// ---------------------------------------------------------------------------

/// Maximum characters of source retained as evidence.
///
/// A finding's snippet is bounded twice over: semgrep's `lines` is truncated
/// here, and the resulting evidence string is capped again by
/// [`crate::services::redaction::redact_text`]. Without a bound, one
/// pathological match (a minified file, a huge generated literal) would put
/// megabytes into a database row and an API response.
pub const SEMGREP_SNIPPET_MAX_CHARS: usize = 400;

/// Maximum characters of a rule message retained in the description.
pub const SEMGREP_MESSAGE_MAX_CHARS: usize = 400;

/// `semgrep scan --json` output (v1.96.0), captured from the pinned image.
///
/// `errors`, `results` and `paths` are the three fields that decide the
/// outcome; the rest of the tool's output is ignored rather than modeled.
#[derive(Debug, Clone, Deserialize)]
struct SemgrepDoc {
    /// Per-file errors. Non-empty means the run is not trustworthy even when
    /// the exit code is 0 — verified against the pinned image, where a bad
    /// ruleset exits 7 and a partial scan exits 0.
    #[serde(default)]
    errors: Vec<SemgrepError>,
    /// Findings.
    #[serde(default)]
    results: Vec<SemgrepResult>,
    /// What the tool actually looked at.
    #[serde(default)]
    paths: SemgrepPaths,
    /// Tool version, recorded when it reports one.
    #[serde(default)]
    version: String,
}

#[derive(Debug, Clone, Deserialize)]
struct SemgrepError {
    #[serde(default)]
    r#type: String,
    #[serde(default)]
    code: i64,
    #[serde(default)]
    level: String,
    #[serde(default)]
    message: String,
}

/// One detection.
#[derive(Debug, Clone, Deserialize)]
struct SemgrepResult {
    /// Preserved verbatim: this is the detection's identity.
    #[serde(default)]
    check_id: String,
    /// Path as the tool saw it, i.e. under [`SCAN_MOUNT`].
    #[serde(default)]
    path: String,
    #[serde(default)]
    start: SemgrepPos,
    #[serde(default)]
    end: SemgrepPos,
    #[serde(default)]
    extra: SemgrepExtra,
}

/// A position in a file. `offset` is a byte offset and is not modeled: line
/// and column are what a canonical finding needs.
#[derive(Debug, Clone, Default, Deserialize)]
struct SemgrepPos {
    #[serde(default)]
    line: i64,
    #[serde(default)]
    col: i64,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct SemgrepExtra {
    /// The tool's own band: `ERROR`, `WARNING`, or `INFO`.
    #[serde(default)]
    severity: String,
    #[serde(default)]
    message: String,
    /// Matched source text. Bounded before it is stored.
    #[serde(default)]
    lines: String,
    /// Semgrep's own stable fingerprint.
    #[serde(default)]
    fingerprint: String,
    /// Rule-supplied metadata. Only fields the rule author set are present.
    #[serde(default)]
    metadata: SemgrepMetadata,
}

/// Rule metadata, modeled field by field because each is independently
/// optional and Fire Crow treats "absent" as "unknown" rather than guessing.
#[derive(Debug, Clone, Default, Deserialize)]
struct SemgrepMetadata {
    #[serde(default)]
    category: String,
    #[serde(default)]
    confidence: String,
    #[serde(default)]
    likelihood: String,
    #[serde(default)]
    impact: String,
    /// Free-form `"CWE-89: description"` strings.
    #[serde(default)]
    cwe: Vec<String>,
    /// Free-form `"A03:2021 - Injection"` strings.
    #[serde(default)]
    owasp: Vec<String>,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    technology: Vec<String>,
    /// Autofix/fix hints, kept as scanner suggestions only.
    #[serde(default)]
    fix: Option<String>,
    #[serde(default)]
    fix_regex: Option<serde_json::Value>,
}

/// What semgrep actually scanned. `scanned` being empty is the signal that
/// would otherwise turn "I looked at nothing" into "clean".
#[derive(Debug, Clone, Default, Deserialize)]
struct SemgrepPaths {
    #[serde(default)]
    scanned: Vec<String>,
}

/// Parse the Semgrep JSON artifact.
///
/// An empty body is a missing report, not a clean scan: the wrapper `cat`s the
/// artifact, so no bytes means semgrep never wrote one.
fn parse_semgrep_report(stdout: &str) -> Result<SemgrepDoc> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Err(AppError::Internal("semgrep produced no report".into()));
    }
    let value: serde_json::Value = serde_json::from_str(trimmed)
        .map_err(|_| AppError::Internal("semgrep report was not valid JSON".into()))?;
    // Both keys must be present. serde would otherwise build an all-defaults
    // document from a `[]` or a truncated body and read schema drift as clean.
    for key in ["results", "paths"] {
        if value.get(key).is_none() {
            return Err(AppError::BadRequest(format!(
                "semgrep report had no {key:?} key"
            )));
        }
    }
    serde_json::from_value(value)
        .map_err(|_| AppError::Internal("semgrep report did not match the expected shape".into()))
}

/// Canonicalize a Semgrep report body.
///
/// `source_dir` is accepted for symmetry with the other adapters and is
/// deliberately unused: semgrep already reports the matched source in
/// `extra.lines`, so no part of the canonical finding depends on re-reading the
/// snapshot. Keeping the parameter means the orchestrator cannot accidentally
/// depend on which adapter it is calling.
pub fn findings_from_semgrep(
    report: &str,
    source_dir: &std::path::Path,
) -> Result<SemgrepFindings> {
    let _ = source_dir;
    Ok(findings_from_semgrep_doc(&parse_semgrep_report(report)?))
}

/// Semgrep half of [`classify`].
///
/// Truth table, established by running the pinned image:
///
/// ```text
/// exit  report                       meaning              outcome
/// 0     results>0, errors=[]          findings             SUCCESS N
/// 0     results=[], paths.scanned>0   clean                SUCCESS 0
/// 0     results=[], scanned=[]        nothing analyzed     FAILED
/// any   errors[] non-empty            partial/failed run   FAILED
/// any   missing / malformed report    no usable report     FAILED
/// ```
///
/// Two of those rows are the whole reason this table exists. Semgrep exits 0
/// both when it finds something and when it finds nothing, so the exit code
/// carries no signal; and it reports `paths.scanned: []` with zero findings for
/// a tree it could not analyze — an empty repo, a repository whose files are
/// all unsupported, or one whose own `.semgrepignore` excludes everything.
/// Reporting that as "clean" would be a silent false negative, so a run that
/// scanned nothing is treated as unknown coverage.
fn classify_semgrep(scanner: &Scanner, input: &ScanInput, out: &SandboxOutput) -> ScannerResult {
    if out.stdout.trim().is_empty() && !out.success {
        return failed_result(
            scanner,
            input,
            "scanner produced no report".to_string(),
            serde_json::json!({
                "detail": "missing_report",
                "stderr": redact_text(&out.stderr, STDERR_MAX_CHARS),
            }),
        );
    }
    let doc = match parse_semgrep_report(&out.stdout) {
        Ok(doc) => doc,
        Err(e) => {
            return failed_result(
                scanner,
                input,
                format!("scanner report was not parseable: {e}"),
                serde_json::json!({
                    "detail": "parse_error",
                    "stderr": redact_text(&out.stderr, STDERR_MAX_CHARS),
                }),
            )
        }
    };

    // A run that reported errors has unknown coverage even if it also produced
    // findings: the findings it did produce are not evidence that the rest of
    // the tree was analyzed.
    if !doc.errors.is_empty() {
        return failed_result(
            scanner,
            input,
            format!("scanner reported {} error(s)", doc.errors.len()),
            serde_json::json!({
                "detail": "scanner_errors",
                "errors": doc
                    .errors
                    .iter()
                    .take(MAX_REPORTED_ERRORS)
                    .map(|e| serde_json::json!({
                        "type": e.r#type,
                        "code": e.code,
                        "level": e.level,
                        // Messages can echo a path or a fragment of source.
                        "message": truncate_chars(&e.message, STDERR_MAX_CHARS),
                    }))
                    .collect::<Vec<_>>(),
            }),
        );
    }

    let scanned = doc.paths.scanned.len();
    if scanned == 0 {
        // "Semgrep scanned zero usable files" must never become "clean".
        return failed_result(
            scanner,
            input,
            "scanner analyzed no files".to_string(),
            serde_json::json!({
                "detail": "no_files_analyzed",
                "scanned_file_count": 0,
            }),
        );
    }

    let parsed = findings_from_semgrep_doc(&doc);
    // Refusals are recorded, never discarded silently: a run that could not
    // locate some of its own detections has partial coverage.
    let rejected_count = parsed.rejected.len();
    let mut record = serde_json::json!({
        "finding_count": parsed.valid.len(),
        "scanned_file_count": scanned,
        "tool_version": doc.version,
    });
    if rejected_count > 0 {
        record["rejected_count"] = serde_json::json!(rejected_count);
        record["rejected"] = serde_json::json!(parsed
            .rejected
            .iter()
            .take(MAX_REPORTED_ERRORS)
            .map(|(check_id, path, reason)| serde_json::json!({
                "check_id": check_id,
                "path": path,
                "reason": reason,
            }))
            .collect::<Vec<_>>());
    }
    success_result(scanner, input, parsed.valid, record)
}

/// How many scanner errors are echoed into an execution record. Bounded so a
/// pathological run cannot inflate the record.
const MAX_REPORTED_ERRORS: usize = 5;

/// Canonical findings plus the detections that were refused.
///
/// A refusal is never silent: a detection with no path, a non-positive line, or
/// an end before its start cannot be located by a developer, so it is excluded
/// and counted rather than stored with a repaired coordinate.
#[derive(Debug, Clone, Default)]
pub struct SemgrepFindings {
    pub valid: Vec<Finding>,
    /// `(check_id, path, reason)` for each refused detection.
    pub rejected: Vec<(String, String, String)>,
}

fn findings_from_semgrep_doc(doc: &SemgrepDoc) -> SemgrepFindings {
    let mut valid = Vec::new();
    let mut rejected = Vec::new();
    for result in &doc.results {
        match validate_semgrep_location(result) {
            Ok(()) => valid.push(finding_from_semgrep(result)),
            Err(reason) => rejected.push((
                result.check_id.clone(),
                result.path.clone(),
                reason.to_string(),
            )),
        }
    }
    SemgrepFindings { valid, rejected }
}

/// Whether a detection's location is usable as-is.
///
/// Coordinates are never repaired. A scanner reporting line 0, a negative line,
/// or an end that precedes its start is describing something that cannot be
/// opened; guessing a location would send a developer to the wrong file.
fn validate_semgrep_location(r: &SemgrepResult) -> std::result::Result<(), &'static str> {
    if r.check_id.trim().is_empty() {
        return Err("missing check_id");
    }
    if r.path.trim().is_empty() {
        return Err("missing path");
    }
    if r.start.line < 1 {
        return Err("start line is not positive");
    }
    if r.end.line < 1 {
        return Err("end line is not positive");
    }
    if r.end.line < r.start.line {
        return Err("end line precedes start line");
    }
    Ok(())
}

/// Convert one Semgrep detection into a canonical `Finding`.
///
/// Discipline, and the reason this function is longer than the OSV one:
///
/// * `check_id` is preserved verbatim. It is the detection's identity; rewriting
///   it into a Fire Crow name would break traceability back to the rule.
/// * CWE, OWASP, and confidence appear **only** when the rule supplies them.
///   A missing `metadata.cwe` yields `None`, never a guess derived from the rule
///   id.
/// * Severity is mapped explicitly; an unrecognized band becomes
///   [`Severity::Unknown`], and the tool's original string is always kept.
/// * The snippet is bounded before it is stored.
fn finding_from_semgrep(r: &SemgrepResult) -> Finding {
    let meta = &r.extra.metadata;
    let file_path = normalize_repo_path(&r.path);
    let start_line = r.start.line;
    let end_line = if r.end.line >= r.start.line {
        r.end.line
    } else {
        r.start.line
    };
    let severity = semgrep_severity(&r.extra.severity);
    let cwe = first_cwe_id(&meta.cwe);
    let owasp = first_owasp_id(&meta.owasp);
    let references = semgrep_references(&meta.references);
    let fingerprint = semgrep_fingerprint(r, &file_path);

    let snippet = truncate_chars(r.extra.lines.trim_end(), SEMGREP_SNIPPET_MAX_CHARS);
    let evidence = redact_text(&snippet, SNIPPET_MAX_CHARS);

    let description = truncate_chars(r.extra.message.trim(), SEMGREP_MESSAGE_MAX_CHARS);

    let mut metadata = serde_json::json!({
        "rule_id": r.check_id,
        "check_id": r.check_id,
        "fingerprint": fingerprint,
        "fingerprint_source": if r.extra.fingerprint.trim().is_empty() {
            "derived"
        } else {
            "semgrep"
        },
        "start_line": r.start.line,
        "start_column": r.start.col,
        "end_line": r.end.line,
        "end_column": r.end.col,
        // The tool's own band, kept verbatim beside the mapped value.
        "scanner_severity": r.extra.severity,
    });
    if !meta.confidence.trim().is_empty() {
        metadata["confidence"] = serde_json::Value::String(meta.confidence.trim().into());
    }
    if !meta.likelihood.trim().is_empty() {
        metadata["likelihood"] = serde_json::Value::String(meta.likelihood.trim().into());
    }
    if !meta.impact.trim().is_empty() {
        metadata["impact"] = serde_json::Value::String(meta.impact.trim().into());
    }
    if !meta.category.trim().is_empty() {
        metadata["category"] = serde_json::Value::String(meta.category.trim().into());
    }
    if !meta.technology.is_empty() {
        metadata["technology"] = serde_json::json!(meta.technology);
    }
    if !meta.cwe.is_empty() {
        metadata["cwe"] = serde_json::json!(meta.cwe);
    }
    if !meta.owasp.is_empty() {
        metadata["owasp"] = serde_json::json!(meta.owasp);
    }
    if !references.is_empty() {
        metadata["references"] = serde_json::json!(references);
    }
    // An autofix is the rule author's suggestion. It is recorded as such and is
    // never promoted into `remediation`, which the report presents as guidance.
    // Scanner suggestions can echo matched source, so they pass through the
    // same credential redactor as evidence before they are persisted.
    if let Some(fix) = meta.fix.as_deref().filter(|f| !f.trim().is_empty()) {
        metadata["scanner_suggestion"] = serde_json::json!({
            "kind": "autofix",
            "unverified": true,
            "diff": redact_text(fix, SEMGREP_MESSAGE_MAX_CHARS),
        });
    }

    Finding {
        id: uuid::Uuid::new_v4().to_string(),
        agent_source: SEMGREP_SCANNER_NAME.to_string(),
        title: r.check_id.clone(),
        description,
        severity,
        cvss_vector: None,
        cvss_score: None,
        evidence: Some(evidence),
        // No verified remediation: nothing here has been confirmed as a fix,
        // and the rule's message is already the description.
        remediation: None,
        cwe_id: cwe,
        owasp_category: owasp,
        // The rule's own confidence, or `None` when it declared none. Never
        // derived from field completeness.
        confidence: non_empty(meta.confidence.trim()),
        scanner_name: Some(SEMGREP_SCANNER_NAME.to_string()),
        scanner_mode: Some(SEMGREP_SCANNER_MODE.to_string()),
        file_path: Some(file_path),
        // Canonical findings carry a single anchor line; the full range lives in
        // metadata so a multiline match is never reduced to one line.
        //
        // `try_from`, not `as`: a hostile or corrupt report could carry a line
        // number outside `i32` range, and `as` would silently wrap it into a
        // wrong-but-positive line. `None` fails canonical validation openly, so
        // the finding is quarantined and counted rather than mis-located.
        line_number: i32::try_from(start_line).ok(),
        route: None,
        metadata_json: Some(metadata.to_string()),
    }
}

/// Map a Semgrep band onto Fire Crow's.
///
/// ```text
/// ERROR    -> Critical
/// WARNING  -> Medium
/// INFO     -> Low
/// anything else, or absent -> Unknown
/// ```
///
/// `INFO` maps to `Low` rather than `Info`: an advisory-grade detection is
/// still a finding. Nothing is promoted above what the tool reported, and an
/// unrecognized value is `Unknown` rather than a guess.
pub fn semgrep_severity(scanner_severity: &str) -> Severity {
    match scanner_severity.trim().to_ascii_uppercase().as_str() {
        "ERROR" => Severity::Critical,
        "WARNING" => Severity::Medium,
        "INFO" => Severity::Low,
        _ => Severity::Unknown,
    }
}

/// Extract the identifier from `"CWE-89: description"`, keeping the full
/// string too. `None` when the rule supplied nothing.
fn first_cwe_id(entries: &[String]) -> Option<String> {
    entries
        .iter()
        .map(|s| s.trim())
        .find(|s| !s.is_empty())
        .map(|s| s.split(':').next().unwrap_or(s).trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Extract the identifier from `"A03:2021 - Injection"`. `None` when absent.
fn first_owasp_id(entries: &[String]) -> Option<String> {
    entries
        .iter()
        .map(|s| s.trim())
        .find(|s| !s.is_empty())
        .map(|s| s.split(" - ").next().unwrap_or(s).trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Normalize Semgrep's string references into the same `{type, url}` shape the
/// OSV adapter uses, so both land in one canonical representation.
fn semgrep_references(entries: &[String]) -> Vec<serde_json::Value> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for entry in entries {
        let url = entry.trim();
        if url.is_empty() || !seen.insert(url.to_string()) {
            continue;
        }
        out.push(serde_json::json!({ "type": "WEB", "url": url }));
    }
    out.sort_by(|a, b| a["url"].as_str().cmp(&b["url"].as_str()));
    out
}

/// Deterministic identity for one detection.
///
/// Prefers Semgrep's own fingerprint, which is content-derived and stable for
/// the same rule at the same location. When absent, derives identity from
/// rule, file, and the full position range — including both columns, so two
/// rules matching the same line at different columns stay distinct. Source text
/// is deliberately excluded: editing a line must not re-identify the finding.
pub fn semgrep_fingerprint_for_test(
    check_id: &str,
    tool_fingerprint: &str,
    file_path: &str,
    start_line: i64,
    start_col: i64,
    end_line: i64,
    end_col: i64,
) -> String {
    if !tool_fingerprint.trim().is_empty() {
        // Scoped by `check_id`. The tool's fingerprint is content-derived and
        // not rule-scoped, so two different rules matching at one location can
        // carry the same value; keying on it alone would let the pipeline
        // dedupe drop one of two genuine findings.
        return format!("semgrep:{check_id}:{}", tool_fingerprint.trim());
    }
    semgrep_derived_fingerprint(
        check_id, file_path, start_line, start_col, end_line, end_col,
    )
}

fn semgrep_derived_fingerprint(
    check_id: &str,
    file_path: &str,
    start_line: i64,
    start_col: i64,
    end_line: i64,
    end_col: i64,
) -> String {
    let payload =
        format!("semgrep|{check_id}|{file_path}|{start_line}:{start_col}|{end_line}:{end_col}",);
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    format!("semgrep:{:x}", hasher.finalize())
}

fn semgrep_fingerprint(r: &SemgrepResult, file_path: &str) -> String {
    semgrep_fingerprint_for_test(
        &r.check_id,
        &r.extra.fingerprint,
        file_path,
        r.start.line,
        r.start.col,
        r.end.line,
        r.end.col,
    )
}

fn non_empty(value: &str) -> Option<String> {
    (!value.trim().is_empty()).then(|| value.trim().to_string())
}

/// Run the static-analysis scanner over `input` and return its result.
pub async fn run_sast_scan(
    input: &ScanInput,
    sandbox: &SandboxManager,
    cancel: &(dyn Fn() -> bool + Sync),
) -> ScannerResult {
    execute(&Scanner::semgrep(), input, sandbox, cancel).await
}

/// Parse the OSV JSON artifact.
///
/// An empty body is **not** a report: the wrapper `cat`s the artifact, so
/// nothing on stdout means the scanner never produced one. That is a missing
/// report, and the caller fails the run. Only a real report — including the
/// pinned version's `"results": null` for a clean run — is a result.
fn parse_osv_report(stdout: &str) -> Result<OsvDoc> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Err(AppError::Internal("osv produced no report".into()));
    }
    let value: serde_json::Value = serde_json::from_str(trimmed)
        .map_err(|_| AppError::Internal("osv report was not valid JSON".into()))?;
    // The key must be present. serde would otherwise accept a `{"result": …}`
    // typo as an all-defaults document and read schema drift as "clean", so
    // presence is asserted before the struct is built.
    if value.get("results").is_none() {
        return Err(AppError::Internal(
            "osv report had no \"results\" key".into(),
        ));
    }
    serde_json::from_value(value)
        .map_err(|_| AppError::Internal("osv report did not match the expected shape".into()))
}

/// Canonicalize an OSV report body against a snapshot directory.
///
/// The adapter's only public entry point: raw report in, canonical findings
/// out. [`OsvDoc`] and its children stay private, so nothing outside this
/// module can hold an unparsed OSV record.
pub fn findings_from_osv(report: &str, source_dir: &std::path::Path) -> Result<Vec<Finding>> {
    Ok(findings_from_doc(&parse_osv_report(report)?, source_dir))
}

/// Canonicalize a whole OSV document: one [`Finding`] per alias-group (see
/// [`osv_group_finding`]), across every lockfile source.
fn findings_from_doc(doc: &OsvDoc, source_dir: &std::path::Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    for source_result in doc.results.iter().flatten() {
        let manifest = normalize_repo_path(&source_result.source.path);
        for package_result in &source_result.packages {
            findings.extend(osv_package_findings(package_result, &manifest, source_dir));
        }
    }
    findings
}

/// One finding per alias-group of a vulnerable package.
///
/// OSV groups records that alias each other ("considered the same
/// vulnerability"), so a group yields one finding: `primary` is the first
/// group id, `aliases` the union of group ids and record aliases. Without
/// groups, each record stands alone.
fn osv_package_findings(
    package_result: &OsvPackageResult,
    manifest: &str,
    source_dir: &std::path::Path,
) -> Vec<Finding> {
    let by_id: std::collections::HashMap<&str, &OsvVuln> = package_result
        .vulnerabilities
        .iter()
        .map(|v| (v.id.as_str(), v))
        .collect();
    let groups: Vec<Vec<&str>> = if package_result.groups.is_empty() {
        package_result
            .vulnerabilities
            .iter()
            .map(|v| vec![v.id.as_str()])
            .collect()
    } else {
        package_result
            .groups
            .iter()
            .map(|g| g.ids.iter().map(|s| s.as_str()).collect())
            .collect()
    };
    let mut findings = Vec::new();
    for ids in groups {
        let records: Vec<&OsvVuln> = ids.iter().filter_map(|id| by_id.get(id).copied()).collect();
        // Groups name listed vulnerabilities by construction. If a group ever
        // names nothing known (schema drift), the finding is still produced
        // from the group ids with unknown everything rather than vanishing.
        findings.push(osv_group_finding(
            &records,
            ids,
            package_result,
            manifest,
            source_dir,
        ));
    }
    findings
}

/// Maximum characters kept from an advisory summary in a description.
pub const OSV_SUMMARY_MAX_CHARS: usize = 240;
/// Maximum characters of a canonical dependency evidence string.
pub const OSV_EVIDENCE_MAX_CHARS: usize = 400;

fn osv_group_finding(
    records: &[&OsvVuln],
    ids: Vec<&str>,
    package_result: &OsvPackageResult,
    manifest: &str,
    source_dir: &std::path::Path,
) -> Finding {
    let pkg = &package_result.package;
    let primary = ids.first().copied().unwrap_or("").to_string();
    let mut aliases: Vec<String> = ids
        .iter()
        .skip(1)
        .map(|s| s.to_string())
        .chain(records.iter().flat_map(|r| r.aliases.iter().cloned()))
        .filter(|a| *a != primary && !a.trim().is_empty())
        .collect();
    aliases.sort();
    aliases.dedup();

    let severity = records
        .iter()
        .filter_map(|r| osv_advisory_severity(r))
        .max_by_key(severity_rank)
        .unwrap_or(Severity::Unknown);

    let (affected, fixed) = osv_affected_fixed(records, pkg);
    let references = osv_references(records);
    let fingerprint = osv_fingerprint(&primary, &pkg.ecosystem, &pkg.name, &pkg.version, manifest);
    let direct = osv_directness(source_dir, manifest, &pkg.name);
    let line = osv_manifest_line(source_dir, manifest, &pkg.name, &pkg.version);

    let fixed_text = if fixed.is_empty() {
        "no fixed version is published".to_string()
    } else {
        format!("fixed in {}", fixed.join(", "))
    };
    let mut evidence = format!(
        "{} package {}@{} declared in {} is affected by {}{}; {}.",
        pkg.ecosystem,
        pkg.name,
        pkg.version,
        manifest,
        primary,
        if aliases.is_empty() {
            String::new()
        } else {
            format!(" ({})", aliases.join(", "))
        },
        fixed_text,
    );
    if evidence.len() > OSV_EVIDENCE_MAX_CHARS {
        evidence.truncate(OSV_EVIDENCE_MAX_CHARS);
        evidence.push_str("... [truncated]");
    }

    let summary = records.iter().find_map(|r| {
        if r.summary.trim().is_empty() {
            None
        } else {
            Some(r.summary.trim())
        }
    });
    let description = match summary {
        Some(s) => truncate_chars(s, OSV_SUMMARY_MAX_CHARS),
        None => format!(
            "Advisory {} affects {} {} ({}).",
            primary, pkg.name, pkg.version, pkg.ecosystem
        ),
    };

    let remediation = if fixed.is_empty() {
        format!(
            "No fixed version is published for {}; review the advisory references in the finding metadata.",
            primary
        )
    } else {
        format!(
            "Upgrade {} to version {} or later (declared in {}), then re-lock and rescan.",
            pkg.name, fixed[0], manifest
        )
    };

    let cwe = records.iter().find_map(|r| osv_advisory_cwe(r));

    let mut meta = serde_json::json!({
        "rule_id": primary,
        "advisory": primary,
        "aliases": aliases,
        "ecosystem": pkg.ecosystem,
        "package": pkg.name,
        "installed_version": pkg.version,
        "fingerprint": fingerprint,
        "manifest": manifest,
        "direct": direct,
        "affected": affected,
        "fixed_versions": fixed,
        "references": references,
    });
    if let Some(cwe) = cwe.as_deref() {
        meta["cwe_id"] = serde_json::Value::String(cwe.to_string());
    }

    Finding {
        id: uuid::Uuid::new_v4().to_string(),
        agent_source: OSV_SCANNER_NAME.to_string(),
        title: format!(
            "Vulnerable dependency: {} {} ({})",
            pkg.name, pkg.version, primary
        ),
        description,
        // Discipline (see `osv_advisory_severity`): Some only when backed by
        // advisory data, else Unknown — never a blanket High.
        severity,
        cvss_vector: None,
        cvss_score: None,
        evidence: Some(evidence),
        remediation: Some(remediation),
        cwe_id: cwe,
        owasp_category: None,
        // No scanner confidence signal exists for version matching; None is
        // honest, where gitleaks reports its own "high".
        confidence: None,
        scanner_name: Some(OSV_SCANNER_NAME.to_string()),
        scanner_mode: Some(OSV_SCANNER_MODE.to_string()),
        file_path: Some(manifest.to_string()),
        // Manifest-level anchor when the declaration line cannot be located.
        line_number: Some(line),
        route: None,
        metadata_json: Some(meta.to_string()),
    }
}

/// Severity backed by advisory data, else `None`.
///
/// Only `database_specific.severity` (present on e.g. GHSA records) counts:
/// OSV `severity[]` entries carry CVSS vectors without scores, and Fire Crow
/// has no vector calculator — deriving a band from a vector would invent
/// urgency. Absent or unrecognized values mean Unknown downstream.
fn osv_advisory_severity(vuln: &OsvVuln) -> Option<Severity> {
    let raw = vuln
        .database_specific
        .get("severity")
        .and_then(|v| v.as_str())?;
    match raw.to_lowercase().as_str() {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" | "moderate" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        _ => None,
    }
}

fn severity_rank(severity: &Severity) -> u8 {
    match severity {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Info | Severity::Unknown => 0,
    }
}

/// First `database_specific.cwe_ids` entry when the advisory carries one
/// (preserved, never invented).
fn osv_advisory_cwe(vuln: &OsvVuln) -> Option<String> {
    vuln.database_specific
        .get("cwe_ids")
        .and_then(|v| v.as_array())
        .and_then(|ids| ids.iter().filter_map(|v| v.as_str()).next())
        .map(|s| s.to_string())
}

/// Affected ranges and fixed versions for our package, merged across the
/// group's records and preserved structurally (not flattened into prose).
///
/// Only `affected[]` entries naming our package count; entries for sibling
/// packages the same advisory touches are ignored. Ranges keep their
/// `{type, events}` shape so a later reporter can reason over them.
fn osv_affected_fixed(
    records: &[&OsvVuln],
    pkg: &OsvPackageId,
) -> (Vec<serde_json::Value>, Vec<String>) {
    let mut affected = Vec::new();
    let mut fixed: Vec<String> = Vec::new();
    for record in records {
        for entry in &record.affected {
            if !entry.package.name.is_empty() && entry.package.name != pkg.name {
                continue;
            }
            let ranges: Vec<serde_json::Value> = entry
                .ranges
                .iter()
                .map(|r| {
                    for event in &r.events {
                        if let Some(f) = event.fixed.as_deref() {
                            if !f.is_empty() && !fixed.contains(&f.to_string()) {
                                fixed.push(f.to_string());
                            }
                        }
                    }
                    serde_json::json!({
                        "type": r.range_type,
                        "events": r.events.iter().map(|e| {
                            let mut o = serde_json::Map::new();
                            if !e.introduced.is_empty() {
                                o.insert("introduced".into(), e.introduced.clone().into());
                            }
                            if let Some(f) = e.fixed.as_deref() {
                                o.insert("fixed".into(), f.to_string().into());
                            }
                            if let Some(l) = e.last_affected.as_deref() {
                                o.insert("last_affected".into(), l.to_string().into());
                            }
                            if let Some(l) = e.limit.as_deref() {
                                o.insert("limit".into(), l.to_string().into());
                            }
                            serde_json::Value::Object(o)
                        }).collect::<Vec<_>>(),
                    })
                })
                .collect();
            affected.push(serde_json::json!({ "ranges": ranges }));
        }
    }
    fixed.sort();
    (affected, fixed)
}

/// Advisory references merged across the group, deduplicated by URL, kept as
/// `{type, url}` pairs for a later renderer. Never prose.
fn osv_references(records: &[&OsvVuln]) -> Vec<serde_json::Value> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for record in records {
        for reference in &record.references {
            if reference.url.trim().is_empty() || !seen.insert(reference.url.clone()) {
                continue;
            }
            out.push(serde_json::json!({
                "type": reference.ref_type,
                "url": reference.url,
            }));
        }
    }
    out.sort_by(|a, b| a["url"].as_str().cmp(&b["url"].as_str()));
    out
}

/// Deterministic fingerprint: `osv:<sha256 of advisory|ecosystem|package|
/// version|manifest>`. Advisory identity plus what is installed where — never
/// a secret, never unstable scanner output.
pub fn osv_fingerprint(
    advisory: &str,
    ecosystem: &str,
    package: &str,
    version: &str,
    manifest: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(format!("osv|{advisory}|{ecosystem}|{package}|{version}|{manifest}").as_bytes());
    format!("osv:{:x}", hasher.finalize())
}

/// Whether `package` is a direct dependency, from the manifest beside the
/// lockfile. `Some(true/false)` only when determinable; `None` is unknown,
/// never a guess:
///
/// * `package-lock.json` → sibling `package.json` dependency keys.
/// * `Cargo.lock` → sibling `Cargo.toml` `[*-dependencies]` keys.
/// * `package.json` / `Cargo.toml` scanned directly → their own dependency keys.
fn osv_directness(source_dir: &std::path::Path, manifest: &str, package: &str) -> Option<bool> {
    let manifest_path = source_dir.join(manifest);
    let file_name = manifest_path.file_name()?.to_str()?;
    match file_name {
        "package.json" => npm_direct_deps(&manifest_path).map(|deps| deps.contains(package)),
        "package-lock.json" | "npm-shrinkwrap.json" => {
            npm_direct_deps(&manifest_path.with_file_name("package.json"))
                .map(|deps| deps.contains(package))
        }
        "Cargo.toml" => cargo_direct_deps(&manifest_path).map(|deps| deps.contains(package)),
        "Cargo.lock" => cargo_direct_deps(&manifest_path.with_file_name("Cargo.toml"))
            .map(|deps| deps.contains(package)),
        _ => None,
    }
}

fn npm_direct_deps(manifest_path: &std::path::Path) -> Option<std::collections::HashSet<String>> {
    let text = std::fs::read_to_string(manifest_path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    let mut deps = std::collections::HashSet::new();
    for section in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        if let Some(map) = value.get(section).and_then(|v| v.as_object()) {
            deps.extend(map.keys().cloned());
        }
    }
    Some(deps)
}

/// Minimal `Cargo.toml` dependency scan: collects keys under any
/// `[*-dependencies]` section (including `[target.*.dependencies]`).
/// Best-effort line scan, not a TOML parser: quoted values spanning lines or
/// exotic layouts fall back to `None` via the caller, never a wrong answer…
/// except aliased `foo = { package = "bar" }`, where the manifest key `foo`
/// is what counts as the direct edge.
fn cargo_direct_deps(manifest_path: &std::path::Path) -> Option<std::collections::HashSet<String>> {
    let text = std::fs::read_to_string(manifest_path).ok()?;
    let mut deps = std::collections::HashSet::new();
    let mut in_deps = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            let section = line
                .trim_matches(|c| c == '[' || c == ']')
                .trim()
                .to_lowercase();
            let leaf = section.rsplit('.').next().unwrap_or("");
            in_deps = matches!(
                leaf,
                "dependencies" | "dev-dependencies" | "build-dependencies"
            );
            continue;
        }
        if in_deps {
            let code = line.split('#').next().unwrap_or("").trim();
            if let Some((key, _)) = code.split_once('=') {
                let key = key.trim().trim_matches('"');
                if !key.is_empty() {
                    deps.insert(key.to_string());
                }
            }
        }
    }
    Some(deps)
}

/// Best-effort manifest line for `package@version`: the lockfile entry
/// declaring it, else the version string, else the manifest anchor (1).
fn osv_manifest_line(
    source_dir: &std::path::Path,
    manifest: &str,
    package: &str,
    version: &str,
) -> i32 {
    let Ok(text) = std::fs::read_to_string(source_dir.join(manifest)) else {
        return 1;
    };
    let lines: Vec<&str> = text.lines().collect();
    let file_name = std::path::Path::new(manifest)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    // npm: the `node_modules/<pkg>` entry (v3) or the `"<pkg>": {` block (v1).
    if file_name == "package-lock.json" || file_name == "npm-shrinkwrap.json" {
        let entry = format!("\"node_modules/{package}\"");
        for (index, line) in lines.iter().enumerate() {
            if line.contains(&entry) {
                return (index + 1) as i32;
            }
        }
    }
    // Cargo: the `version = "<version>"` following `name = "<package>"`.
    if file_name == "Cargo.lock" {
        let name_line = format!("name = \"{package}\"");
        let version_line = format!("version = \"{version}\"");
        for (index, line) in lines.iter().enumerate() {
            if line.trim() == name_line {
                for (offset, candidate) in lines.iter().skip(index + 1).take(5).enumerate() {
                    if candidate.trim() == version_line {
                        return (index + 1 + offset + 1) as i32;
                    }
                }
                return (index + 1) as i32;
            }
        }
    }
    for (index, line) in lines.iter().enumerate() {
        if line.contains(version) && line.contains(package) {
            return (index + 1) as i32;
        }
    }
    1
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
    let mut out: String = text.chars().take(max_chars).collect();
    if text.chars().count() > max_chars {
        out.push_str("... [truncated]");
    }
    out
}

/// Run the dependency scanner over `input` and return its result.
pub async fn run_dependency_scan(
    input: &ScanInput,
    sandbox: &SandboxManager,
    cancel: &(dyn Fn() -> bool + Sync),
) -> ScannerResult {
    execute(&Scanner::osv(), input, sandbox, cancel).await
}

/// Base fields shared by every execution record: what ran, against what, with
/// what limits. A record without these cannot be reproduced or audited.
fn record_base(scanner: &Scanner, input: &ScanInput) -> serde_json::Value {
    serde_json::json!({
        "scanner": scanner.name,
        "version": scanner.version,
        "mode": scanner.mode,
        "image": scanner.image,
        "parser": scanner.parser,
        "snapshot_commit": input.commit_sha,
        "timeout_secs": scanner.timeout_secs,
        "cpus": scanner.resource_limits.cpus,
        "memory": scanner.resource_limits.memory,
        "pids_limit": scanner.resource_limits.pids_limit,
        "source_file_count": input.file_count,
        "source_total_size": input.total_size,
    })
}

/// Attach the scanner run's provenance to a finding's curated metadata.
///
/// Adapters already record scanner-specific identity and evidence. This adds
/// the run-level facts every downstream consumer needs without changing
/// detection semantics: scanner version/parser/image and the snapshot the
/// scanner actually read. Invalid metadata is left untouched so canonical
/// validation can reject it instead of silently repairing it.
fn with_run_provenance(mut finding: Finding, scanner: &Scanner, input: &ScanInput) -> Finding {
    if let Some(raw) = finding.metadata_json.as_deref() {
        if let Ok(serde_json::Value::Object(mut metadata)) = serde_json::from_str(raw) {
            metadata.insert(
                "scanner_version".to_string(),
                serde_json::Value::String(scanner.version.to_string()),
            );
            metadata.insert(
                "parser".to_string(),
                serde_json::Value::String(scanner.parser.to_string()),
            );
            metadata.insert(
                "scanner_image".to_string(),
                serde_json::Value::String(scanner.image.to_string()),
            );
            metadata.insert(
                "snapshot_commit".to_string(),
                match input.commit_sha.as_deref() {
                    Some(commit) => serde_json::Value::String(commit.to_string()),
                    None => serde_json::Value::Null,
                },
            );
            finding.metadata_json = Some(serde_json::Value::Object(metadata).to_string());
        }
    }
    finding
}

fn success_result(
    scanner: &Scanner,
    input: &ScanInput,
    findings: Vec<Finding>,
    extra: serde_json::Value,
) -> ScannerResult {
    let mut record = record_base(scanner, input);
    merge_into(&mut record, extra);
    let findings = findings
        .into_iter()
        .map(|finding| with_run_provenance(finding, scanner, input))
        .collect::<Vec<_>>();
    let finding_count = findings.len();
    ScannerResult {
        scanner: scanner.name.to_string(),
        version: scanner.version.to_string(),
        mode: scanner.mode.to_string(),
        outcome: ScannerOutcome::Success { finding_count },
        findings,
        execution_record: record,
    }
}

fn failed_result(
    scanner: &Scanner,
    input: &ScanInput,
    reason: String,
    extra: serde_json::Value,
) -> ScannerResult {
    let mut record = record_base(scanner, input);
    merge_into(&mut record, extra);
    record["error"] = serde_json::Value::String(reason.clone());
    // Explicit: this run does not support a finding count.
    record["coverage"] = serde_json::Value::String("unknown".into());
    ScannerResult {
        scanner: scanner.name.to_string(),
        version: scanner.version.to_string(),
        mode: scanner.mode.to_string(),
        outcome: ScannerOutcome::Failed { reason },
        findings: Vec::new(),
        execution_record: record,
    }
}

fn timeout_result(scanner: &Scanner, input: &ScanInput) -> ScannerResult {
    let mut record = record_base(scanner, input);
    record["error"] = serde_json::Value::String(format!(
        "scanner exceeded its {}s timeout",
        scanner.timeout_secs
    ));
    record["coverage"] = serde_json::Value::String("unknown".into());
    ScannerResult {
        scanner: scanner.name.to_string(),
        version: scanner.version.to_string(),
        mode: scanner.mode.to_string(),
        outcome: ScannerOutcome::Timeout {
            limit_secs: scanner.timeout_secs,
        },
        findings: Vec::new(),
        execution_record: record,
    }
}

fn cancelled_result(scanner: &Scanner, input: &ScanInput) -> ScannerResult {
    let mut record = record_base(scanner, input);
    record["error"] = serde_json::Value::String("scan was cancelled".into());
    record["coverage"] = serde_json::Value::String("unknown".into());
    ScannerResult {
        scanner: scanner.name.to_string(),
        version: scanner.version.to_string(),
        mode: scanner.mode.to_string(),
        outcome: ScannerOutcome::Cancelled,
        findings: Vec::new(),
        execution_record: record,
    }
}

fn merge_into(record: &mut serde_json::Value, extra: serde_json::Value) {
    if let (Some(dst), Some(src)) = (record.as_object_mut(), extra.as_object()) {
        for (k, v) in src {
            dst.insert(k.clone(), v.clone());
        }
    }
}

/// Run the secret scanner over `input` and return its result.
///
/// The scanner's declared name, version, mode, and limits come from
/// [`Scanner::gitleaks`]; the parser is gitleaks' report format.
pub async fn run_secret_scan(
    input: &ScanInput,
    sandbox: &SandboxManager,
    cancel: &(dyn Fn() -> bool + Sync),
) -> ScannerResult {
    execute(&Scanner::gitleaks(), input, sandbox, cancel).await
}

/// One entry of gitleaks' JSON report. Field names mirror gitleaks exactly
/// (see `report/finding.go`); every field defaults so adapter-level schema drift
/// fails closed at parse time, not silently. This type never leaves the
/// adapter: only redacted [`Finding`]s are persisted, logged, or returned.
#[derive(Debug, Clone, Deserialize)]
pub struct GitleaksFinding {
    #[serde(rename = "RuleID", default)]
    pub rule_id: String,
    #[serde(rename = "Description", default)]
    pub description: String,
    #[serde(rename = "File", default)]
    pub file: String,
    #[serde(rename = "StartLine", default)]
    pub start_line: i64,
    #[serde(rename = "EndLine", default)]
    pub end_line: i64,
    #[serde(rename = "StartColumn", default)]
    pub start_column: i64,
    #[serde(rename = "EndColumn", default)]
    pub end_column: i64,
    #[serde(rename = "Match", default)]
    pub match_text: String,
    #[serde(rename = "Secret", default)]
    pub secret: String,
    #[serde(rename = "SymlinkFile", default)]
    pub symlink_file: String,
    #[serde(rename = "Commit", default)]
    pub commit: String,
    #[serde(rename = "Entropy", default)]
    pub entropy: f32,
    #[serde(rename = "Author", default)]
    pub author: String,
    #[serde(rename = "Email", default)]
    pub email: String,
    #[serde(rename = "Date", default)]
    pub date: String,
    #[serde(rename = "Message", default)]
    pub message: String,
    #[serde(rename = "Tags", default)]
    pub tags: Vec<String>,
    #[serde(rename = "Fingerprint", default)]
    pub fingerprint: String,
}

/// Parse gitleaks' JSON report.
///
/// Accepts an empty body or `null` as "no findings" (gitleaks does this on some
/// versions), a bare array, or an array preceded by log noise on stdout.
pub fn parse_gitleaks_report(stdout: &str) -> Result<Vec<GitleaksFinding>> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Ok(Vec::new());
    }

    if let Ok(v) = serde_json::from_str::<Vec<GitleaksFinding>>(trimmed) {
        return Ok(v);
    }

    // Recover the array if other lines were interleaved.
    if let (Some(start), Some(end)) = (trimmed.find('['), trimmed.rfind(']')) {
        if start < end {
            if let Ok(v) = serde_json::from_str::<Vec<GitleaksFinding>>(&trimmed[start..=end]) {
                return Ok(v);
            }
        }
    }

    Err(AppError::Internal(
        "gitleaks report was not valid JSON".into(),
    ))
}

/// Convert one gitleaks entry into a `Finding`.
///
/// The `Finding` always carries `file_path`, `line_number`, and an evidence
/// snippet; the snippet is the scanner's own match text with the secret value
/// replaced by `[REDACTED]` and then passed through the shared redactor, so
/// neither `Secret` nor `Match` ever persists in raw form.
///
/// Severity is a Fire Crow default, documented here because gitleaks reports
/// no severity of its own: every exposed secret is `High` (`CWE-798`,
/// `A07:2021`). The reporter must preserve it, never recompute it.
pub fn finding_from_gitleaks(g: &GitleaksFinding) -> Finding {
    let title = if g.description.trim().is_empty() {
        format!("Exposed secret: {}", g.rule_id)
    } else {
        g.description.clone()
    };

    let raw_snippet = if !g.match_text.trim().is_empty() {
        g.match_text.clone()
    } else {
        format!("{} = {}", g.rule_id, g.secret)
    };

    // Replace the exact secret value first, then run the generic redactor for
    // anything else that looks like a credential.
    let without_secret = if g.secret.is_empty() {
        raw_snippet
    } else {
        raw_snippet.replace(&g.secret, "[REDACTED]")
    };
    let evidence = redact_text(&without_secret, SNIPPET_MAX_CHARS);
    let file_path = normalize_repo_path(&g.file);

    Finding {
         id: uuid::Uuid::new_v4().to_string(),
         agent_source: SCANNER_NAME.to_string(),
         title,
         description: format!("gitleaks rule {}: {}", g.rule_id, g.description),
         severity: Severity::High,
         cvss_vector: None,
         cvss_score: None,
         evidence: Some(evidence),
         remediation: Some(
             "Revoke the exposed credential, remove it from the repository history, and load it from a secret manager at runtime.".to_string(),
         ),
         cwe_id: Some("CWE-798".to_string()),
         owasp_category: Some("A07:2021".to_string()),
         // Scanner's own confidence, not a computed heuristic.
         confidence: Some("high".to_string()),
         scanner_name: Some(SCANNER_NAME.to_string()),
         scanner_mode: Some(SCANNER_MODE.to_string()),
         file_path: Some(file_path.clone()),
         // `try_from`, not `as`: a hostile report could carry a line outside
         // `i32` range, and `as` would wrap it into a wrong-but-positive line.
         // `None` fails canonical validation openly — quarantined, never
         // mis-located.
         line_number: i32::try_from(g.start_line).ok(),
         route: None,
         metadata_json: Some(gitleaks_metadata(g, &file_path)),
     }
}

/// Stable metadata for one gitleaks detection: the rule, the deterministic
/// fingerprint, and the precise location. Never the secret.
fn gitleaks_metadata(g: &GitleaksFinding, file_path: &str) -> String {
    let mut meta = serde_json::json!({
        "rule_id": g.rule_id,
        "fingerprint": gitleaks_fingerprint(g, file_path),
        "start_column": g.start_column,
        "end_column": g.end_column,
    });
    if !g.commit.trim().is_empty() {
        meta["commit"] = serde_json::Value::String(g.commit.clone());
    }
    meta.to_string()
}

/// Deterministic fingerprint for one raw detection.
///
/// Prefers gitleaks' own `Fingerprint` when present; otherwise derives
/// `gitleaks:<rule>:<file>:<line>:<col>` from stable identity fields. The raw
/// secret never participates, so the fingerprint is safe to persist and
/// stable across rescans.
pub fn gitleaks_fingerprint(g: &GitleaksFinding, file_path: &str) -> String {
    if !g.fingerprint.trim().is_empty() {
        return format!("gitleaks:{}", g.fingerprint.trim());
    }
    format!(
        "gitleaks:{}:{}:{}:{}",
        g.rule_id, file_path, g.start_line, g.start_column
    )
}

/// Strip the container mount prefix so the stored path is repository-relative.
///
/// gitleaks reports the path it saw (`/src/aws.env`); the product should record
/// `aws.env`, not an internal container path.
fn normalize_repo_path(path: &str) -> String {
    let with_slash = format!("{SOURCE_MOUNT}/");
    path.strip_prefix(with_slash.as_str())
        .unwrap_or(path)
        .trim_start_matches('/')
        .to_string()
}
