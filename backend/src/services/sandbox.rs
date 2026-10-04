//! Hardened sandbox — the execution boundary for every scanner.
//!
//! ```text
//!   host snapshot ──:ro──▶ /scan     (read-only, deterministic path)
//!   tmpfs               ──rw──▶ /work     (scratch, never touches the host)
//! ```
//!
//! # What the boundary guarantees
//!
//! [`docker_argv`] is the single place isolation is defined, so it can be
//! asserted exhaustively without Docker. Every run gets:
//!
//! * `--network=none` — no egress, so a scanner cannot exfiltrate a finding or
//!   a secret it just read.
//! * `--read-only` — the container root filesystem cannot be modified.
//! * `--cap-drop=ALL` + `--security-opt=no-new-privileges` — no capability
//!   acquisition, and no setuid-style escalation.
//! * `--user=65534:65534` — never root.
//! * `--cpus` / `-m` / `--pids-limit` — bounded CPU, memory, and process count,
//!   so a runaway scanner degrades instead of taking the VPS with it.
//! * `--init` — tini is PID 1 and reaps orphans; a scanner that forks cannot
//!   accumulate zombies or escape termination.
//! * `--rm` plus an explicit `docker rm -f` on timeout/cancel — no container
//!   outlives its run.
//!
//! The repository is mounted read-only at a fixed path, and the writable
//! [`WORK_DIR`] is a `tmpfs`: it is not a bind mount, so nothing a scanner
//! writes there ever reaches the host filesystem, and it is discarded with the
//! container.
//!
//! # Output and cleanup boundaries
//!
//! stdout and stderr are read with hard caps ([`MAX_STDOUT_BYTES`],
//! [`MAX_STDERR_BYTES`]) while streaming, never buffered whole, so a scanner
//! cannot exhaust worker memory by printing. Exceeding a cap is
//! [`AppError::OutputLimitExceeded`] — reported as `FAILED`, never as a result.
//!
//! On timeout or cancellation the child is killed, reaped, and the container
//! force-removed.

use crate::error::{AppError, Result};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;

/// The unprivileged uid:gid the sandboxed process runs as.
///
/// `65534` is `nobody`/`nogroup` on essentially every Linux image, so an escaped
/// or compromised scanner still owns nothing. Never `0`/root.
pub const SANDBOX_USER: &str = "65534:65534";

/// Where the repository snapshot is mounted inside the container.
///
/// Read-only and deterministic: a scanner must never have to discover where its
/// input is, and a report path can never be confused with a writable path.
pub const SCAN_MOUNT: &str = "/scan";

/// Writable scratch for a scanner that needs temporary files.
///
/// A `tmpfs`, not a bind mount: writes never reach the host and the contents
/// die with the container. The root filesystem stays read-only.
pub const WORK_DIR: &str = "/work";

/// Size ceiling on the writable scratch area.
pub const WORK_TMPFS_SIZE: &str = "64m";

/// Size ceiling on each extra scratch path (`/tmp`, writable `HOME`, …).
///
/// Smaller than [`WORK_TMPFS_SIZE`]: these exist so a tool's runtime can
/// start, not so it can stage large artifacts. Note that `noexec` is
/// deliberately *not* set here — some tools extract helper binaries into a
/// temp directory during startup, and the container is already
/// `no-new-privileges`, capability-free, and rootless, so an executed helper
/// gains nothing.
pub const EXTRA_TMPFS_SIZE: &str = "32m";

/// Hard cap on captured stdout. A scanner's JSON report is orders of magnitude
/// smaller than this; beyond it the report is treated as unusable.
pub const MAX_STDOUT_BYTES: usize = 16 * 1024 * 1024;

/// Hard cap on captured stderr. stderr is diagnostic only and is redacted
/// before it is persisted, so it gets a much smaller budget than stdout.
pub const MAX_STDERR_BYTES: usize = 1024 * 1024;

/// Read granularity for the bounded stream readers.
const READ_CHUNK_BYTES: usize = 64 * 1024;

/// How often the cancellation callback is consulted while a process runs.
const CANCEL_POLL_MS: u64 = 200;

/// How long a terminating process gets to exit before it is killed outright.
const KILL_GRACE: Duration = Duration::from_secs(5);

/// A read-only (or read-write) bind mount into the sandbox.
#[derive(Debug, Clone)]
pub struct SandboxMount {
    pub host_path: String,
    pub container_path: String,
    pub read_only: bool,
}

impl SandboxMount {
    /// The `host:container[:ro]` argument Docker expects.
    pub fn as_docker_spec(&self) -> String {
        let mut spec = format!("{}:{}", self.host_path, self.container_path);
        if self.read_only {
            spec.push_str(":ro");
        }
        spec
    }
}

/// Result of a sandboxed process.
#[derive(Debug, Clone)]
pub struct SandboxOutput {
    pub stdout: String,
    pub stderr: String,
    pub success: bool,
}

/// CPU/memory/pid ceilings applied to a sandboxed process.
///
/// Per-scanner, not global: a memory-hungry scanner gets its own ceiling
/// instead of being allowed to exhaust the host or forcing every scanner down
/// to the worst case. `clone` is required to hand a copy to the executor.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceLimits {
    pub cpus: f64,
    pub memory: String,
    pub pids_limit: u32,
}

/// The limits every scanner uses unless it declares its own.
impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            cpus: 1.0,
            memory: "512m".to_string(),
            pids_limit: 256,
        }
    }
}

impl ResourceLimits {
    /// Docker flags for these limits, in the order [`docker_argv`] applies them.
    pub fn as_docker_args(&self) -> Vec<String> {
        vec![
            format!("--cpus={}", self.cpus),
            format!("-m={}", self.memory),
            // Pin swap to the same ceiling so `-m` cannot be evaded via swap.
            format!("--memory-swap={}", self.memory),
            format!("--pids-limit={}", self.pids_limit),
        ]
    }

    fn validate(&self) -> Result<()> {
        if !(self.cpus.is_finite() && self.cpus > 0.0 && self.cpus <= 8.0) {
            return Err(AppError::BadRequest(format!(
                "sandbox cpus must be in (0, 8], got {}",
                self.cpus
            )));
        }
        if !valid_memory(&self.memory) {
            return Err(AppError::BadRequest(format!(
                "sandbox memory {:?} must look like \"512m\" or \"2g\"",
                self.memory
            )));
        }
        if self.pids_limit == 0 || self.pids_limit > 2048 {
            return Err(AppError::BadRequest(format!(
                "sandbox pids_limit must be in 1..=2048, got {}",
                self.pids_limit
            )));
        }
        Ok(())
    }
}

/// `512m`, `2g`, `1024k` — a positive integer plus a unit. Anything else is
/// rejected rather than passed to Docker.
fn valid_memory(memory: &str) -> bool {
    let (num, unit) = match memory.strip_suffix(['m', 'M', 'g', 'G', 'k', 'K']) {
        Some(n) => (n, true),
        None => (memory, false),
    };
    if !unit {
        return false;
    }
    matches!(num.parse::<u64>(), Ok(n) if n > 0)
}

/// Timeout ceiling for one sandboxed run, in seconds.
pub const MAX_TIMEOUT_SECS: u64 = 3600;

/// Network access granted to a sandboxed run.
///
/// # Deny-by-default
///
/// The contract is: **no scanner gets network access unless it explicitly
/// declares an exception here.** [`NetworkMode::None`] is the default on
/// [`SandboxSpec`], and every scanner but one asks for nothing.
///
/// | Mode | Docker flag | Who |
/// |------|-------------|-----|
/// | `None` | `--network=none` | every scanner (default) |
/// | `Bridge` | `--network=bridge` | OSV only, for the live vulnerability database |
///
/// `Bridge` is the default bridge network, never `host`: the container can
/// reach the internet but has no view of the host's interfaces, no metadata
/// service, and no route to any other container. It is deliberately the weakest
/// exception that still lets the tool work, so a future scanner cannot widen
/// the boundary by asking for something stronger — there is nothing stronger
/// to ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkMode {
    /// `--network=none`. The default, and the only mode most scanners use.
    #[default]
    None,
    /// `--network=bridge`. Reserved for scanners that query a live
    /// third-party database as part of doing their job.
    Bridge,
}

impl NetworkMode {
    /// The Docker network argument for this mode.
    pub fn as_docker_arg(self) -> String {
        match self {
            Self::None => "--network=none".into(),
            Self::Bridge => "--network=bridge".into(),
        }
    }

    /// Stable name for execution records and tests.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Bridge => "bridge",
        }
    }

    /// True only for a declared exception, so a caller can assert that a
    /// scanner did not quietly gain egress.
    pub fn is_excepted(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Everything needed to run one command under the sandbox.
#[derive(Debug, Clone)]
pub struct SandboxSpec {
    /// Pinned image reference. Must pass [`validate_pinned_image`].
    pub image: String,
    /// Optional `--entrypoint` override. `None` keeps the image default.
    ///
    /// When set it must be a bare binary name or absolute path (`sh`,
    /// `/bin/sh`): never a flag, never a shell string. The gitleaks scanner
    /// sets `sh` so its JSON report can be written to the tmpfs scratch area
    /// and then streamed to stdout with `cat`; that shell text is fixed
    /// scanner-owned text over constant paths, never scanner output.
    pub entrypoint: Option<String>,
    /// Network access for this run. Deny-by-default: [`NetworkMode::None`]
    /// renders `--network=none`, leaving no exfiltration path for whatever the
    /// scanner reads. Only a scanner that *declares* an exception gets
    /// [`NetworkMode::Bridge`].
    pub network: NetworkMode,
    /// Argument vector. Never a shell string: an argument containing `;`, `|`,
    /// or `$(...)` is passed through as that literal argument. The one
    /// exception is a scanner-owned `sh -c` wrapper built from constants (see
    /// `entrypoint`); untrusted bytes never flow into it.
    pub command: Vec<String>,
    /// Host directories to expose. Repository mounts must be read-only.
    pub mounts: Vec<SandboxMount>,
    /// Extra writable scratch paths, as in-memory filesystems.
    ///
    /// [`WORK_DIR`] always exists. A tool that also needs a conventional
    /// temporary directory (`/tmp`) or a writable `HOME` asks for it here
    /// rather than the sandbox growing a writable root: the root filesystem
    /// stays read-only and every writable path is still a tmpfs that dies with
    /// the container. Paths are validated to be absolute and free of option
    /// metacharacters.
    pub extra_tmpfs: Vec<String>,
    /// Environment variables to set, e.g. `HOME=/work`.
    ///
    /// Names must be shell-safe identifiers and values free of newlines and
    /// NULs, so nothing can smuggle a second argument into the container.
    pub env: Vec<(String, String)>,
    pub timeout_secs: u64,
    pub limits: ResourceLimits,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
}

impl SandboxSpec {
    /// A spec with the standard output caps.
    pub fn new(
        image: impl Into<String>,
        command: Vec<String>,
        mounts: Vec<SandboxMount>,
        timeout_secs: u64,
        limits: ResourceLimits,
    ) -> Self {
        Self {
            image: image.into(),
            command,
            entrypoint: None,
            network: NetworkMode::default(),
            mounts,
            extra_tmpfs: Vec::new(),
            env: Vec::new(),
            timeout_secs,
            limits,
            max_stdout_bytes: MAX_STDOUT_BYTES,
            max_stderr_bytes: MAX_STDERR_BYTES,
        }
    }

    /// Add writable in-memory scratch paths, e.g. `/tmp`.
    ///
    /// Duplicates and the default scratch area are ignored, so a repeated path
    /// cannot produce two conflicting `--tmpfs` flags.
    pub fn with_extra_tmpfs<S: AsRef<str>>(mut self, paths: &[S]) -> Self {
        for path in paths {
            let path = path.as_ref().to_string();
            if path != WORK_DIR && !self.extra_tmpfs.contains(&path) {
                self.extra_tmpfs.push(path);
            }
        }
        self
    }

    /// Set environment variables for the run, e.g. `HOME=/work`.
    pub fn with_env<K: AsRef<str>, V: AsRef<str>>(mut self, vars: &[(K, V)]) -> Self {
        for (name, value) in vars {
            let (name, value) = (name.as_ref().to_string(), value.as_ref().to_string());
            if !self.env.iter().any(|(n, _)| *n == name) {
                self.env.push((name, value));
            }
        }
        self
    }

    /// Override the container entrypoint (validates in [`SandboxManager::run`]).
    pub fn with_entrypoint(mut self, entrypoint: Option<&str>) -> Self {
        self.entrypoint = entrypoint.map(|s| s.to_string());
        self
    }

    /// Declare this run's network access. Defaults to [`NetworkMode::None`];
    /// a scanner must ask for an exception to get one.
    pub fn with_network(mut self, network: NetworkMode) -> Self {
        self.network = network;
        self
    }

    /// Override the output caps, for tests and unusually chatty scanners.
    pub fn with_output_caps(mut self, stdout: usize, stderr: usize) -> Self {
        self.max_stdout_bytes = stdout;
        self.max_stderr_bytes = stderr;
        self
    }
}

/// Where pinned scanner configuration is mounted read-only.
///
/// Scanner *rules* are part of the scanner contract: a registry-fetched ruleset
/// would make a finding unreproducible, so rules travel as a pinned local file.
/// This is the only host path a scanner may observe besides the snapshot, and
/// it is still read-only.
pub const CONFIG_MOUNT: &str = "/config";

/// The host paths a scanner may observe: the repository snapshot, and pinned
/// scanner configuration. Nothing else — not `/`, not the Docker socket, not a
/// writable bind.
const ALLOWED_CONTAINER_PATHS: [&str; 2] = [SCAN_MOUNT, CONFIG_MOUNT];

/// Reject any mount that is not read-only, and not one of the two paths a
/// scanner is allowed to observe.
///
/// A writable bind would let a compromised scanner persist on the host or
/// corrupt the tree for the next scanner. Any other path would expose host
/// files or shadow `/work`. `:`/newline in the host path would escape the
/// `host:container:ro` spec itself.
fn validate_mount(mount: &SandboxMount) -> Result<()> {
    if mount.host_path.trim().is_empty() || mount.container_path.trim().is_empty() {
        return Err(AppError::BadRequest(
            "sandbox mount needs a host and a container path".into(),
        ));
    }
    if !mount.container_path.starts_with('/') {
        return Err(AppError::BadRequest(format!(
            "sandbox container path {} must be absolute",
            mount.container_path
        )));
    }
    if !ALLOWED_CONTAINER_PATHS.contains(&mount.container_path.as_str()) {
        return Err(AppError::BadRequest(format!(
            "sandbox container path must be one of {ALLOWED_CONTAINER_PATHS:?}, got {}",
            mount.container_path
        )));
    }
    if !mount.read_only {
        return Err(AppError::BadRequest(format!(
            "sandbox mount at {} must be read-only",
            mount.container_path
        )));
    }
    if mount
        .host_path
        .chars()
        .any(|c| c == ':' || c == '\n' || c == '\r' || c == '\0')
    {
        return Err(AppError::BadRequest(
            "sandbox host path contains an invalid character".into(),
        ));
    }
    Ok(())
}

/// Check a spec without running it: image pin, limits, timeout, command,
/// entrypoint, and mounts. [`SandboxManager::run`] applies this first, so a
/// bad spec fails before Docker is touched.
pub fn validate_spec(spec: &SandboxSpec) -> Result<()> {
    validate_pinned_image(&spec.image)?;
    spec.limits.validate()?;
    if spec.timeout_secs == 0 || spec.timeout_secs > MAX_TIMEOUT_SECS {
        return Err(AppError::BadRequest(format!(
            "sandbox timeout must be in 1..={MAX_TIMEOUT_SECS}s, got {}",
            spec.timeout_secs
        )));
    }
    if spec.command.is_empty() {
        return Err(AppError::BadRequest(
            "sandbox command must not be empty".into(),
        ));
    }
    if let Some(entrypoint) = spec.entrypoint.as_deref() {
        // Positioned among the `docker run` options: a leading `-` would be
        // parsed as another option, whitespace would smuggle extra argv.
        if entrypoint.trim().is_empty()
            || entrypoint.starts_with('-')
            || entrypoint
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(AppError::BadRequest(format!(
                "sandbox entrypoint {entrypoint:?} is not a valid binary"
            )));
        }
    }
    for mount in &spec.mounts {
        validate_mount(mount)?;
    }
    for path in &spec.extra_tmpfs {
        validate_tmpfs_path(path)?;
    }
    for (name, value) in &spec.env {
        validate_env(name, value)?;
    }
    Ok(())
}

/// An extra scratch path must be absolute and free of anything Docker could
/// read as an option or a second mount spec.
fn validate_tmpfs_path(path: &str) -> Result<()> {
    if !path.starts_with('/') || path.len() < 2 {
        return Err(AppError::BadRequest(format!(
            "sandbox scratch path {path:?} must be an absolute path"
        )));
    }
    if path
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, ':' | ',' | '=' | '\0'))
    {
        return Err(AppError::BadRequest(format!(
            "sandbox scratch path {path:?} contains an invalid character"
        )));
    }
    // The snapshot is mounted read-only; scratch must never shadow it.
    if path == SCAN_MOUNT {
        return Err(AppError::BadRequest(format!(
            "sandbox scratch path must not shadow {SCAN_MOUNT}"
        )));
    }
    Ok(())
}

/// An environment name is a plain identifier and a value has no newlines or
/// NULs, so neither can inject an extra argv entry.
fn validate_env(name: &str, value: &str) -> Result<()> {
    let valid_name = !name.is_empty()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !name.starts_with(|c: char| c.is_ascii_digit());
    if !valid_name {
        return Err(AppError::BadRequest(format!(
            "sandbox env name {name:?} is not a valid identifier"
        )));
    }
    if value.contains(['\n', '\r', '\0']) {
        return Err(AppError::BadRequest(format!(
            "sandbox env value for {name:?} contains a control character"
        )));
    }
    Ok(())
}

/// A unique container name, so a timed-out or cancelled run can be force-removed
/// by name even if the client process was already killed.
pub fn container_name() -> String {
    format!("firecrow-scan-{}", uuid::Uuid::new_v4())
}

/// Split an image reference into its name and its tag or digest.
///
/// Handles registries with ports, so `localhost:5000/foo` is not read as
/// name `localhost` with tag `5000/foo`.
pub fn split_image_ref(image: &str) -> (&str, Option<&str>) {
    if let Some(idx) = image.rfind('@') {
        return (&image[..idx], Some(&image[idx + 1..]));
    }
    let name_start = image.rfind('/').map(|i| i + 1).unwrap_or(0);
    match image[name_start..].rfind(':') {
        Some(i) => (&image[..name_start + i], Some(&image[name_start + i + 1..])),
        None => (image, None),
    }
}

/// Reject an unpinned image reference.
///
/// Scanner behaviour changing underneath Fire Crow makes an audit result
/// impossible to reproduce, so a floating reference is refused outright:
///
/// * `gitleaks` — no tag at all; resolves to whatever is newest.
/// * `:latest` — explicitly floating.
/// * `@sha256:<64 hex>` — accepted, and the strongest form.
/// * `:v8.18.4` — accepted.
pub fn validate_pinned_image(image: &str) -> Result<()> {
    let img = image.trim();
    if img.is_empty() {
        return Err(AppError::BadRequest(
            "scanner image must be explicitly configured".into(),
        ));
    }
    // Positioned after `docker run [flags]`: a leading `-` would be parsed as
    // a Docker flag, not an image. Whitespace/control would split or smuggle
    // extra argv. Both are refused outright.
    if img.starts_with('-') || img.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(AppError::BadRequest(format!(
            "scanner image {img:?} is not a valid pinned reference"
        )));
    }
    let (name, reference) = split_image_ref(img);
    if name.is_empty() {
        return Err(AppError::BadRequest(format!(
            "scanner image {img:?} has no image name"
        )));
    }
    match reference {
        None => Err(AppError::BadRequest(format!(
            "scanner image {img:?} is not pinned: name it with an explicit version tag or digest"
        ))),
        Some(digest) if digest.starts_with("sha256:") => {
            let hex = &digest["sha256:".len()..];
            if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                Ok(())
            } else {
                Err(AppError::BadRequest(format!(
                    "scanner image {img:?} has a malformed digest"
                )))
            }
        }
        Some("") => Err(AppError::BadRequest(format!(
            "scanner image {img:?} has an empty version tag"
        ))),
        Some("latest") => Err(AppError::BadRequest(format!(
            "scanner image {img:?} must not use :latest — pin an explicit version or digest so results stay reproducible"
        ))),
        Some(_) => Ok(()),
    }
}

/// Build the exact `docker` argument vector for a run.
///
/// Pure, so the whole isolation contract is verifiable without Docker. Every
/// flag that defines the boundary lives here and nowhere else.
pub fn docker_argv(spec: &SandboxSpec, name: &str) -> Vec<String> {
    let mut argv: Vec<String> = vec![
        "run".into(),
        // Removed on normal exit; force-removed on timeout/cancel.
        "--rm".into(),
        // Unique name so an abandoned container is addressable.
        "--name".into(),
        name.into(),
        // tini as PID 1: reaps orphaned grandchildren, forwards signals.
        "--init".into(),
    ];
    // Deny-by-default. A scanner cannot reach the network unless its
    // descriptor declared a `NetworkMode` exception (see `NetworkMode`).
    argv.push(spec.network.as_docker_arg());
    argv.extend([
        // Root filesystem immutable; only the tmpfs below is writable.
        "--read-only".into(),
        // No capabilities, and no way to acquire any.
        "--cap-drop=ALL".into(),
        "--security-opt=no-new-privileges".into(),
        // Never root.
        format!("--user={SANDBOX_USER}"),
    ]);
    // Optional entrypoint override, before the image. Validated in `run`, so
    // a flag-shaped value can never reach Docker here.
    if let Some(entrypoint) = spec.entrypoint.as_deref() {
        argv.push(format!("--entrypoint={entrypoint}"));
    }
    argv.extend(spec.limits.as_docker_args());
    // Writable scratch, not on the host and not executable. Extra paths are
    // in-memory too: a tool needing `/tmp` or a writable HOME gets a tmpfs,
    // never a writable root or a host bind.
    argv.push("--tmpfs".into());
    argv.push(format!(
        "{WORK_DIR}:rw,noexec,nosuid,nodev,size={WORK_TMPFS_SIZE}"
    ));
    for path in &spec.extra_tmpfs {
        argv.push("--tmpfs".into());
        argv.push(format!("{path}:rw,nosuid,nodev,size={EXTRA_TMPFS_SIZE}"));
    }
    for mount in &spec.mounts {
        argv.push("-v".into());
        argv.push(mount.as_docker_spec());
    }
    // Declared container environment. The client process itself gets nothing
    // ambient (see `run`), so every one of these `-e` flags is an explicit,
    // validated decision rather than a host variable leaking through.
    for (name, value) in &spec.env {
        argv.push("-e".into());
        argv.push(format!("{name}={value}"));
    }
    argv.push(spec.image.clone());
    // Appended verbatim: the image's entrypoint receives these as argv. No
    // shell is involved, so metacharacters carry no meaning.
    argv.extend(spec.command.iter().cloned());
    argv
}

/// Read at most `cap` bytes from `reader`, failing the moment the cap is passed.
///
/// Streaming with an incremental cap check, so a flood is stopped at the cap
/// rather than being buffered first.
async fn read_capped<R>(mut reader: R, cap: usize, stream: &'static str) -> Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut out: Vec<u8> = Vec::with_capacity(READ_CHUNK_BYTES.min(cap));
    let mut chunk = vec![0u8; READ_CHUNK_BYTES];
    loop {
        let n = reader
            .read(&mut chunk)
            .await
            .map_err(|e| AppError::Internal(format!("failed to read sandbox {stream}: {e}")))?;
        if n == 0 {
            return Ok(out);
        }
        if out.len() + n > cap {
            return Err(AppError::OutputLimitExceeded {
                stream: stream.to_string(),
                cap_bytes: cap,
            });
        }
        out.extend_from_slice(&chunk[..n]);
    }
}

/// Why a run stopped.
enum Stop {
    /// Both pipes hit EOF and the process was reaped.
    Finished(std::process::ExitStatus),
    /// A stream hit its cap.
    OutputExceeded(AppError),
    Timeout,
    Cancelled,
}

/// Runs sandboxed commands. Holds no configuration: the hardened flag set is
/// not caller-selectable, so no caller can weaken it.
#[derive(Debug, Default)]
pub struct SandboxManager;

impl SandboxManager {
    pub fn new() -> Self {
        Self
    }

    /// Run `spec` under the hardened sandbox, aborting if `cancel()` goes true.
    ///
    /// Never returns success for a run that hit an output cap, timed out, or
    /// was cancelled: each surfaces as its own error so the caller can report
    /// it as `FAILED`/`TIMEOUT`/`CANCELLED` rather than as zero findings.
    pub async fn run(
        &self,
        spec: &SandboxSpec,
        cancel: &(dyn Fn() -> bool + Sync),
    ) -> Result<SandboxOutput> {
        validate_spec(spec)?;

        let name = container_name();
        let argv = docker_argv(spec, &name);
        tracing::info!(
            image = %spec.image,
            %name,
            timeout_secs = spec.timeout_secs,
            cpus = spec.limits.cpus,
            memory = %spec.limits.memory,
            pids_limit = spec.limits.pids_limit,
            "Sandbox execution starting"
        );

        let mut cmd = tokio::process::Command::new("docker");
        cmd.args(&argv)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Belt and braces: the child dies even if this task unwinds
            // unexpectedly, so a panic cannot leave a container running.
            .kill_on_drop(true);
        // The ambient environment is cleared on the *client*: a host variable
        // (a proxy, a token, a DOCKER_HOST) cannot influence how the `docker`
        // invocation itself behaves. Values listed in `spec.env` travel into
        // the container as validated `-e` flags, which `docker_argv` renders.
        cmd.env_clear();
        let mut child = cmd
            .spawn()
            .map_err(|e| AppError::Internal(format!("Failed to execute sandbox: {e}")))?;

        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();
        let (Some(stdout_pipe), Some(stderr_pipe)) = (stdout_pipe, stderr_pipe) else {
            terminate(&mut child, &name).await;
            return Err(AppError::Internal(
                "Failed to capture sandbox output pipes".into(),
            ));
        };

        // Each stream is bounded by its own cap and observed concurrently, so
        // the first breach ends the run instead of waiting on the other pipe.
        let mut out_task = tokio::spawn(read_capped(stdout_pipe, spec.max_stdout_bytes, "stdout"));
        let mut err_task = tokio::spawn(read_capped(stderr_pipe, spec.max_stderr_bytes, "stderr"));

        let mut status: Option<std::process::ExitStatus> = None;
        let mut out_val: Option<Vec<u8>> = None;
        let mut out_err: Option<AppError> = None;
        let mut err_val: Option<Vec<u8>> = None;
        let mut err_err: Option<AppError> = None;
        let mut poll = tokio::time::interval(Duration::from_millis(CANCEL_POLL_MS));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(spec.timeout_secs.max(1));

        let stop = loop {
            let out_settled = out_val.is_some() || out_err.is_some();
            let err_settled = err_val.is_some() || err_err.is_some();
            if let (Some(status), true) = (status, out_settled && err_settled) {
                break Stop::Finished(status);
            }
            // An output cap is a verdict: stop immediately rather than waiting
            // for the process to finish emitting.
            if let Some(e) = out_err.take().or_else(|| err_err.take()) {
                break Stop::OutputExceeded(e);
            }
            tokio::select! {
                s = child.wait() => {
                    status = Some(s.map_err(|e| AppError::Internal(format!("Failed waiting on sandbox: {e}")))?);
                }
                r = &mut out_task, if !out_settled => match r {
                    Ok(Ok(v)) => out_val = Some(v),
                    Ok(Err(e)) => out_err = Some(e),
                    Err(join) => out_err = Some(AppError::Internal(format!("stdout reader failed: {join}"))),
                },
                r = &mut err_task, if !err_settled => match r {
                    Ok(Ok(v)) => err_val = Some(v),
                    Ok(Err(e)) => err_err = Some(e),
                    Err(join) => err_err = Some(AppError::Internal(format!("stderr reader failed: {join}"))),
                },
                _ = tokio::time::sleep_until(deadline) => break Stop::Timeout,
                _ = poll.tick(), if cancel() => break Stop::Cancelled,
            }
        };

        out_task.abort();
        err_task.abort();

        let (status, stdout, stderr) = match stop {
            Stop::Finished(status) => {
                let stdout = out_val.unwrap_or_default();
                let stderr = err_val.unwrap_or_default();
                (status, stdout, stderr)
            }
            other => {
                // Terminate before returning: kill the client, reap it, and
                // force-remove the container so nothing survives this call.
                terminate(&mut child, &name).await;
                return Err(match other {
                    Stop::OutputExceeded(e) => e,
                    Stop::Timeout => AppError::Timeout(format!(
                        "Sandbox execution timed out after {}s",
                        spec.timeout_secs
                    )),
                    Stop::Cancelled => AppError::Cancelled("scan cancelled by operator".into()),
                    Stop::Finished(_) => unreachable!("Finished is handled above"),
                });
            }
        };

        let stdout = String::from_utf8_lossy(&stdout).to_string();
        let stderr = String::from_utf8_lossy(&stderr).to_string();
        if !status.success() {
            // Phase 20: stderr comes from the untrusted repository (scanner
            // output echoes repository content, including secrets). It is
            // redacted and bounded before it reaches the log, like every
            // other scanner-controlled string.
            tracing::warn!(
                "Sandbox process failed: {}",
                crate::services::redaction::redact_text(&stderr, 500)
            );
        }
        Ok(SandboxOutput {
            stdout,
            stderr,
            success: status.success(),
        })
    }

    /// Convenience wrapper for a mount-free run.
    pub async fn run_in_sandbox(
        &self,
        image: &str,
        command: &[&str],
        timeout_secs: u64,
    ) -> Result<(String, String)> {
        let spec = SandboxSpec::new(
            image,
            command.iter().map(|s| s.to_string()).collect(),
            vec![],
            timeout_secs,
            ResourceLimits::default(),
        );
        let out = self.run(&spec, &|| false).await?;
        Ok((out.stdout, out.stderr))
    }
}

/// Terminate a run and make sure nothing survives it.
///
/// Order matters: kill the client so it stops blocking, give it a grace period
/// to exit cleanly, reap it so it is not a zombie, then force-remove the
/// container by name — which is what actually kills scanner processes still
/// running inside it.
async fn terminate(child: &mut tokio::process::Child, name: &str) {
    // SIGTERM the docker client.
    let _ = child.start_kill();
    // Reap it, but never wait forever for a wedged client.
    let _ = tokio::time::timeout(KILL_GRACE, child.wait()).await;
    // The container, and every process inside it, goes now. `--rm` covers the
    // normal exit; this covers the abnormal one.
    let _ = tokio::process::Command::new("docker")
        .args(["rm", "-f", name])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
    tracing::debug!(%name, "Sandbox terminated and container removed");
}
