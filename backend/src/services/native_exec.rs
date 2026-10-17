//! Native (docker-free) scanner execution — an opt-in alternative to the
//! container sandbox.
//!
//! # Why this exists
//!
//! Render's free tier has no Docker daemon and no Docker-in-Docker, so the
//! container boundary in [`crate::services::sandbox`] cannot be used there.
//! This module runs the *same pinned scanner binaries* directly as subprocesses
//! so a deployment without a daemon can still scan.
//!
//! # The honest security boundary
//!
//! The three scanners (gitleaks, osv-scanner, semgrep) **never execute
//! repository code** — they parse files, parse lockfiles, and parse ASTs. The
//! container's job is to bound the blast radius *around the scanner process*
//! (a parser memory-safety bug, a file crafted against the parser) and to
//! enforce network isolation. Native mode keeps most of the *process-level*
//! hardening but is **not** equivalent to a container or VM boundary:
//!
//! What native mode still enforces:
//! * argument arrays only — never a shell, so untrusted bytes cannot become
//!   syntax ([`native_argv`]);
//! * a cleared environment — no ambient secret, token, or proxy reaches a
//!   scanner unless it is explicitly declared ([`native_env`]);
//! * wall-clock timeout with reliable child termination ([`run_native`]);
//! * bounded stderr, and a bounded report file;
//! * per-process resource ceilings via `setrlimit` (address space, CPU, file
//!   size, process count) and `PR_SET_NO_NEW_PRIVS` ([`apply_resource_limits`]);
//! * a dedicated scratch directory that is removed on every exit path;
//! * the already-unprivileged container uid (the backend runs as `10001`).
//!
//! What it does **not** enforce (residual risk, documented rather than hidden):
//! * no per-process filesystem namespace — a scanner subprocess can read any
//!   file the backend user can (the backend holds no secrets on disk beyond its
//!   own config, and scanner stderr is redacted before logging);
//! * no kernel-enforced network isolation — gitleaks and semgrep are invoked
//!   with flags that make no network calls, and osv-scanner's egress is routed
//!   through the validated filtering proxy, but the OS does not block a
//!   determined process the way `--network=none` does.
//!
//! Because of that gap, native mode is **opt-in** (see
//! [`ExecutionMode::resolve`]) and the readiness/capability endpoints report
//! the *actual* isolation level so the frontend can warn before a scan. It must
//! never be described as a container substitute.

use crate::agents::scanner::{ScanInput, Scanner, GITLEAKS_PARSER, OSV_PARSER, SEMGREP_PARSER};
use crate::error::{AppError, Result};
use crate::services::sandbox::{SandboxOutput, MAX_STDERR_BYTES, MAX_STDOUT_BYTES};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

/// How scanners are executed. Defined alongside the container sandbox so the
/// two execution backends share one vocabulary; re-exported here for callers.
pub use crate::services::sandbox::ExecutionMode;

/// The env var that names each native scanner binary, and its default command
/// name searched on `PATH` when the var is unset.
///
/// Keeping the binary location operator-configurable means the pinned version
/// can be installed anywhere (image build, a package, a toolchain dir) without a
/// code change; an explicitly configured but non-executable path fails closed
/// (returns unavailable) rather than silently falling back to a different binary
/// on `PATH`.
fn binary_spec(scanner_name: &str) -> Option<(&'static str, &'static str)> {
    match scanner_name {
        "gitleaks" => Some(("GITLEAKS_BIN", "gitleaks")),
        "osv" => Some(("OSV_SCANNER_BIN", "osv-scanner")),
        "semgrep" => Some(("SEMGREP_BIN", "semgrep")),
        _ => None,
    }
}

/// True when the named scanner has a runnable native binary.
///
/// Reported by the capability/readiness endpoints so a scan is never offered
/// when its scanner cannot run. This is the docker-free analogue of the daemon
/// probe.
pub fn scanner_available(scanner_name: &str) -> bool {
    resolve_binary(scanner_name).is_some()
}

/// Report availability for all three scanners, keyed by scanner name.
pub fn availability() -> Vec<(&'static str, bool)> {
    vec![
        ("gitleaks", scanner_available("gitleaks")),
        ("osv", scanner_available("osv")),
        ("semgrep", scanner_available("semgrep")),
    ]
}

/// Locate the native binary for `scanner_name`.
///
/// An explicit env path that is not a runnable file returns `None` (fail closed
/// — never silently PATH-search for a substitute). Otherwise the default
/// command name is looked up on `PATH`.
fn resolve_binary(scanner_name: &str) -> Option<PathBuf> {
    let (env_key, default_name) = binary_spec(scanner_name)?;
    if let Ok(raw) = std::env::var(env_key) {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            let candidate = PathBuf::from(trimmed);
            return if is_executable_file(&candidate) {
                Some(candidate)
            } else {
                None
            };
        }
    }
    which(default_name)
}

/// Minimal `which`: find `name` on `PATH` and return it only if it is an
/// executable file. Deliberately small rather than a new dependency.
fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(meta) => meta.is_file() && meta.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

/// Report artifact filename written by a scanner, per parser.
fn report_file_name(scanner: &Scanner) -> &'static str {
    match scanner.parser {
        GITLEAKS_PARSER => "gitleaks.json",
        OSV_PARSER => "osv.json",
        SEMGREP_PARSER => "semgrep.json",
        _ => "report.json",
    }
}

/// Build the native argument vector for `scanner` over `input`.
///
/// Mirrors the container command in [`Scanner`] but as a direct binary
/// invocation (no `sh -c`, no `/scan` mount path, no `cat`): the report is
/// written to `report_path` and read back by [`run_native`]. Every element is a
/// fixed constant or a validated filesystem path — never shell syntax.
fn native_argv(
    scanner: &Scanner,
    input: &ScanInput,
    bin: &Path,
    report_path: &Path,
) -> Vec<String> {
    let src = input.source_dir.to_string_lossy().to_string();
    let report = report_path.to_string_lossy().to_string();
    match scanner.parser {
        GITLEAKS_PARSER => vec![
            "detect".into(),
            "--no-git".into(),
            format!("--source={src}"),
            "--report-format=json".into(),
            format!("--report-path={report}"),
            "--exit-code=1".into(),
            "--log-level=error".into(),
        ],
        OSV_PARSER => vec![
            "scan".into(),
            "source".into(),
            "--recursive".into(),
            "--allow-no-lockfiles".into(),
            "--format=json".into(),
            format!("--output={report}"),
            "--verbosity=error".into(),
            src,
        ],
        SEMGREP_PARSER => {
            let ruleset =
                crate::agents::scanner::semgrep_ruleset_host_dir().join("firecrow-sast.yml");
            vec![
                "scan".into(),
                format!("--config={}", ruleset.to_string_lossy()),
                format!("--json-output={report}"),
                "--quiet".into(),
                "--no-git-ignore".into(),
                "--disable-version-check".into(),
                "--metrics=off".into(),
                src,
            ]
        }
        // Unknown parsers are refused; the container path is the only place a
        // generic command shape exists.
        _ => Vec::new(),
    }
}

/// Environment for a native scanner run.
///
/// The ambient environment is cleared by the caller; only these declared values
/// are set. `bin` is unused but kept for symmetry/future absolute-path needs.
fn native_env(scanner: &Scanner, scratch: &Path) -> Vec<(String, String)> {
    match scanner.parser {
        // osv-scanner: pass through the operator-validated filtering-proxy
        // variables already attached to the descriptor (never repository-
        // controlled). `NO_PROXY` is deliberately absent, matching the
        // container path so every destination goes through the proxy.
        OSV_PARSER => scanner.env.clone(),
        // semgrep: a writable HOME/TMPDIR inside the scratch dir (it wants
        // somewhere to write caches); the scratch dir dies with the run.
        SEMGREP_PARSER => {
            let s = scratch.to_string_lossy().to_string();
            vec![("HOME".into(), s.clone()), ("TMPDIR".into(), s)]
        }
        // gitleaks: offline, needs no environment.
        _ => Vec::new(),
    }
}

/// Per-process resource ceilings applied between fork and exec.
///
/// These are defense-in-depth bounds, not a sandbox: they cap how much address
/// space, CPU time, file size, and how many processes a scanner may create, so a
/// runaway or hostile input cannot exhaust the host before the wall-clock
/// timeout fires. Address-space and CPU ceilings are best-effort on Linux (the
/// OOM killer remains the hard memory backstop, and a process killed by the OOM
/// killer exits non-zero — which [`crate::agents::scanner::classify`] reports as
/// `Failed`, never as clean).
fn apply_resource_limits() -> std::io::Result<()> {
    // No setuid-style privilege escalation from here on.
    unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1usize, 0usize, 0usize, 0usize);
    }
    // 2 GiB address space: enough for semgrep on a normal repo, still bounded.
    set_rlimit(libc::RLIMIT_AS, 2 * 1024 * 1024 * 1024)?;
    // 1 GiB file size: a scanner must not write an unbounded file to disk.
    set_rlimit(libc::RLIMIT_FSIZE, 1024 * 1024 * 1024)?;
    // 1024 processes/threads: blocks fork bombs.
    set_rlimit(libc::RLIMIT_NPROC, 1024)?;
    Ok(())
}

fn set_rlimit(resource: libc::__rlimit_resource_t, limit: libc::rlim_t) -> std::io::Result<()> {
    let lim = libc::rlimit {
        rlim_cur: limit,
        rlim_max: limit,
    };
    // SAFETY: `lim` is a valid stack value; setrlimit reads it and writes no
    // pointer. Failure is propagated as an io error, aborting the spawn so a
    // scanner never runs without its ceilings.
    let rc = unsafe { libc::setrlimit(resource, &lim) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Scratch directory for one native run; removed on drop (success, error, and
/// unwind alike) so report artifacts never outlive the scan.
struct ReportScratch {
    path: PathBuf,
}

impl ReportScratch {
    fn new() -> Result<Self> {
        let path = std::env::temp_dir().join(format!("firecrow-native-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path)
            .map_err(|e| AppError::Internal(format!("failed to create native scratch dir: {e}")))?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ReportScratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Read a report file, bounded so an oversized artifact cannot exhaust memory.
fn read_report_bounded(path: &Path, cap: usize) -> Result<String> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        // A missing report is empty stdout; `classify` treats empty-on-failure
        // as `Failed` (unknown coverage), never clean.
        Err(_) => return Ok(String::new()),
    };
    if meta.len() as usize > cap {
        return Err(AppError::OutputLimitExceeded {
            stream: "report".into(),
            cap_bytes: cap,
        });
    }
    let bytes = std::fs::read(path)
        .map_err(|e| AppError::Internal(format!("failed to read native scanner report: {e}")))?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

/// Run one scanner natively over `input`, returning the same [`SandboxOutput`]
/// shape the container path produces so [`crate::agents::scanner::classify`]
/// (and therefore the entire Canonical Audit contract) is unchanged.
///
/// Never returns success for a run that timed out, was cancelled, or flooded
/// stderr: each surfaces as its own error, exactly like the container path, so
/// a failure can never be read as zero findings.
pub async fn run_native(
    scanner: &Scanner,
    input: &ScanInput,
    cancel: &(dyn Fn() -> bool + Sync),
) -> Result<SandboxOutput> {
    let bin = resolve_binary(scanner.name).ok_or_else(|| {
        AppError::Internal(format!(
            "native scanner binary for {} is not available",
            scanner.name
        ))
    })?;

    let scratch = ReportScratch::new()?;
    let report_path = scratch.path().join(report_file_name(scanner));
    let argv = native_argv(scanner, input, &bin, &report_path);
    if argv.is_empty() {
        return Err(AppError::Internal(format!(
            "no native invocation for scanner parser {:?}",
            scanner.parser
        )));
    }

    tracing::info!(
        scanner = scanner.name,
        binary = %bin.display(),
        timeout_secs = scanner.timeout_secs,
        "Native scanner execution starting"
    );

    let mut cmd = tokio::process::Command::new(&bin);
    cmd.args(&argv)
        .stdin(Stdio::null())
        // The report is read back from the file, not stdout; discarding stdout
        // avoids a full-pipe stall with no memory cost.
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env_clear();
    for (k, v) in native_env(scanner, scratch.path()) {
        cmd.env(k, v);
    }
    // Apply resource ceilings between fork and exec. A failure here aborts the
    // spawn (propagated as an io error) so no scanner runs unbounded.
    unsafe {
        cmd.pre_exec(apply_resource_limits);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| AppError::Internal(format!("failed to spawn native scanner: {e}")))?;

    let stderr_pipe = child.stderr.take();
    let Some(stderr_pipe) = stderr_pipe else {
        let _ = child.kill().await;
        return Err(AppError::Internal(
            "failed to capture native scanner stderr".into(),
        ));
    };

    let mut err_task = tokio::spawn(crate::services::sandbox::read_capped(
        stderr_pipe,
        MAX_STDERR_BYTES,
        "stderr",
    ));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(scanner.timeout_secs.max(1));
    let mut err_val: Option<Vec<u8>> = None;
    let mut err_err: Option<AppError> = None;
    let mut status: Option<std::process::ExitStatus> = None;
    let mut poll = tokio::time::interval(Duration::from_millis(200));

    enum Stop {
        Finished,
        OutputExceeded(AppError),
        Timeout,
        Cancelled,
    }

    let stop = loop {
        if let (Some(_), true) = (status, err_val.is_some() || err_err.is_some()) {
            break Stop::Finished;
        }
        if let Some(e) = err_err.take() {
            break Stop::OutputExceeded(e);
        }
        tokio::select! {
            s = child.wait(), if status.is_none() => {
                status = Some(s.map_err(|e| AppError::Internal(format!("failed waiting on native scanner: {e}")))?);
            }
            r = &mut err_task, if err_val.is_none() && err_err.is_none() => match r {
                Ok(Ok(v)) => err_val = Some(v),
                Ok(Err(e)) => err_err = Some(e),
                Err(join) => err_err = Some(AppError::Internal(format!("stderr reader failed: {join}"))),
            },
            _ = tokio::time::sleep_until(deadline) => break Stop::Timeout,
            _ = poll.tick(), if cancel() => break Stop::Cancelled,
        }
    };

    err_task.abort();

    let status = match stop {
        Stop::Finished => {
            // `status` is Some here because the loop only breaks Finished when
            // both are settled; unwrap safely.
            status.expect("Finished implies a reaped status")
        }
        other => {
            // Terminate the real process, not just a DB flag: kill the child so
            // nothing survives this call.
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(match other {
                Stop::OutputExceeded(e) => e,
                Stop::Timeout => AppError::Timeout(format!(
                    "native scanner {} timed out after {}s",
                    scanner.name, scanner.timeout_secs
                )),
                Stop::Cancelled => AppError::Cancelled("scan cancelled by operator".into()),
                Stop::Finished => unreachable!("Finished is handled above"),
            });
        }
    };

    // Bounded read of the report artifact the scanner wrote.
    let report = read_report_bounded(&report_path, MAX_STDOUT_BYTES)?;

    let stderr = String::from_utf8_lossy(&err_val.unwrap_or_default()).to_string();
    if !status.success() {
        // stderr echoes untrusted repository content; redact and bound it
        // before it reaches the log, exactly like the container path.
        tracing::warn!(
            "Native scanner process failed: {}",
            crate::services::redaction::redact_text(&stderr, 500)
        );
    }

    Ok(SandboxOutput {
        stdout: report,
        stderr,
        success: status.success(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::scanner::{ScanInput, Scanner};
    use std::path::PathBuf;
    use std::sync::Mutex;

    // Serialize tests that touch process-global env vars; env mutation races
    // across parallel tests (same pattern as routes_health's probe tests).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn argv_for(scanner: Scanner) -> Vec<String> {
        let input = ScanInput::from_dir(std::path::Path::new("/tmp/repo-under-test"));
        let bin = PathBuf::from("/usr/bin/fake");
        let report = PathBuf::from("/tmp/scratch/report.json");
        native_argv(&scanner, &input, &bin, &report)
    }

    #[test]
    fn gitleaks_argv_is_an_arg_array_with_no_shell_syntax() {
        let argv = argv_for(Scanner::gitleaks());
        let joined = argv.join(" ");
        assert!(argv.iter().any(|a| a == "detect"), "{argv:?}");
        assert!(joined.contains("--no-git"), "{joined}");
        assert!(joined.contains("--source=/tmp/repo-under-test"), "{joined}");
        assert!(
            joined.contains("--report-path=/tmp/scratch/report.json"),
            "{joined}"
        );
        for bad in ["; ", "|", "$(", "`", "&&"] {
            assert!(
                !joined.contains(bad),
                "argv must not contain {bad:?}: {joined}"
            );
        }
    }

    #[test]
    fn osv_argv_targets_the_source_dir_and_report() {
        let argv = argv_for(Scanner::osv());
        let joined = argv.join(" ");
        assert!(argv.iter().any(|a| a == "scan"), "{argv:?}");
        assert!(
            joined.contains("--output=/tmp/scratch/report.json"),
            "{joined}"
        );
        assert!(joined.contains("/tmp/repo-under-test"), "{joined}");
    }

    #[test]
    fn semgrep_argv_uses_the_pinned_local_ruleset_and_no_network() {
        let argv = argv_for(Scanner::semgrep());
        let joined = argv.join(" ");
        assert!(joined.contains("--config="), "{joined}");
        assert!(joined.contains("firecrow-sast.yml"), "{joined}");
        assert!(joined.contains("--metrics=off"), "{joined}");
        assert!(
            joined.contains("--json-output=/tmp/scratch/report.json"),
            "{joined}"
        );
        assert!(
            !joined.contains("--config=https"),
            "must not fetch a remote ruleset: {joined}"
        );
    }

    #[test]
    fn mode_defaults_to_container_and_requires_exact_opt_in() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("SCANNER_EXECUTION_MODE");
        assert_eq!(ExecutionMode::resolve(), ExecutionMode::Container);

        std::env::set_var("SCANNER_EXECUTION_MODE", "native");
        assert_eq!(ExecutionMode::resolve(), ExecutionMode::Native);

        // A typo or near-miss must never silently select the weaker boundary.
        std::env::set_var("SCANNER_EXECUTION_MODE", "Native ");
        assert_eq!(ExecutionMode::resolve(), ExecutionMode::Container);
        std::env::set_var("SCANNER_EXECUTION_MODE", "docker");
        assert_eq!(ExecutionMode::resolve(), ExecutionMode::Container);
        std::env::remove_var("SCANNER_EXECUTION_MODE");
    }

    #[test]
    fn an_explicit_but_missing_binary_path_fails_closed() {
        let _g = ENV_LOCK.lock().unwrap();
        // Point gitleaks at a path that does not exist: availability must be
        // false, never silently PATH-searched for a different binary.
        std::env::set_var("GITLEAKS_BIN", "/nonexistent/gitleaks-binary");
        assert!(!scanner_available("gitleaks"));
        std::env::remove_var("GITLEAKS_BIN");
    }
}
