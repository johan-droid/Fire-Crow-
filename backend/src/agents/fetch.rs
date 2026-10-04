//! Repository acquisition — the `fetch` phase.
//!
//! Downloads a repository tarball from the GitHub API into a private temporary
//! directory and returns a handle to it. The directory is removed on drop, so it
//! is cleaned up on success, on error, and on timeout alike.
//!
//! Safety properties enforced here, not by a downstream tool:
//!   * the token is checked for read access **before** any bytes are downloaded;
//!   * the download and the extracted tree are bounded (bytes and file count);
//!   * symlinks, hardlinks, absolute paths and `..` members are rejected;
//!   * the tarball is parsed by hand rather than shelled out to `tar`, so a
//!     malicious archive never reaches a tool with its own extraction quirks.

use crate::error::{AppError, Result};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

/// Ceiling on the compressed download.
pub const MAX_DOWNLOAD_BYTES: u64 = 100 * 1024 * 1024;
/// Ceiling on total uncompressed bytes extracted.
pub const MAX_TOTAL_BYTES: u64 = 150 * 1024 * 1024;
/// Ceiling on a single file's size.
pub const MAX_FILE_BYTES: u64 = 20 * 1024 * 1024;
/// Ceiling on the number of extracted files.
pub const MAX_FILE_COUNT: usize = 20_000;
/// Ceiling on an archive member's full path length, in characters. Longer
/// paths are rejected before touching the disk.
pub const MAX_PATH_CHARS: usize = 1024;
/// Ceiling on a single path component, in bytes (the common filesystem limit).
pub const MAX_COMPONENT_CHARS: usize = 255;
/// How many bytes of a file are sniffed to decide binary vs text.
pub const SNAPSHOT_SNIFF_BYTES: u64 = 8000;
/// Network timeout for the access check and the download.
pub const FETCH_TIMEOUT_SECS: u64 = 120;

/// Removes its directory on drop unless disarmed.
///
/// The fetch phase creates its temp dir before any network call; this guard
/// owns it across every early `return Err`, so a failed intake can never leak
/// the directory. Disarmed once the finished [`FetchedRepo`] takes over.
struct TempDirGuard {
    dir: Option<PathBuf>,
}

impl TempDirGuard {
    fn disarm(&mut self) -> PathBuf {
        self.dir.take().expect("temp scan dir guard used twice")
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        if let Some(dir) = self.dir.take() {
            if let Err(e) = std::fs::remove_dir_all(&dir) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!("Failed to remove temp scan dir {:?}: {}", dir, e);
                }
            }
        }
    }
}

/// Base URL of the GitHub REST API.
/// Overridable via `GITHUB_API_BASE_URL` (used by tests to point at a mock
/// server, and by GitHub Enterprise Server deployments). Defaults to
/// `https://api.github.com`.
pub fn github_api_base() -> String {
    std::env::var("GITHUB_API_BASE_URL")
        .map(|v| v.trim().trim_end_matches('/').to_string())
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "https://api.github.com".to_string())
}

/// A fetched repository on local disk. Removes its temporary directory on drop.
#[derive(Debug)]
pub struct FetchedRepo {
    dir: PathBuf,
    metadata: RepositoryMetadata,
    snapshot: RepoSnapshot,
}

impl FetchedRepo {
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// Metadata captured from the GitHub API during intake, before download.
    pub fn metadata(&self) -> &RepositoryMetadata {
        &self.metadata
    }

    /// Snapshot of the extracted tree: what the scanner will actually see.
    pub fn snapshot(&self) -> &RepoSnapshot {
        &self.snapshot
    }
}

impl Drop for FetchedRepo {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.dir) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!("Failed to remove temp scan dir {:?}: {}", self.dir, e);
            }
        }
    }
}

/// Download `repo_url` at `repo_branch` using `token`, into a fresh temp dir.
///
/// Intake runs before any byte is downloaded:
/// 1. the URL is parsed (only `https://github.com/{owner}/{repo}` passes);
/// 2. `GET /repos/{owner}/{repo}` validates the token's read permission **and**
///    captures the repository metadata (default branch, visibility);
/// 3. the branch head commit is resolved, so the scan pins an exact `commit_sha`;
/// 4. only then is the tarball downloaded — pinned at that sha — and extracted.
///
/// A blank `token` means an unauthenticated request: public repositories work,
/// private ones answer 404, which surfaces as `NotFound`, never as a leak of
/// whether the repository exists.
pub async fn fetch_repo(repo_url: &str, repo_branch: &str, token: &str) -> Result<FetchedRepo> {
    fetch_repo_with_cancel(repo_url, repo_branch, token, None, &|| false).await
}

/// Download `repo_url` at `repo_branch`, aborting promptly when `cancel()`
/// reports true (the job's cancellation flag). The temp dir is still removed:
/// the [`TempDirGuard`] owns it until the finished handle takes over.
///
/// `requested_sha` pins the snapshot: when `Some`, the tarball is downloaded
/// at that exact commit and no branch head is resolved. A branch is only ever
/// an input used to resolve a SHA. The SHA is re-validated here (defense in
/// depth: the submission route validated it first), and anything else fails
/// closed rather than scanning an unintended ref.
pub async fn fetch_repo_with_cancel(
    repo_url: &str,
    repo_branch: &str,
    token: &str,
    requested_sha: Option<&str>,
    cancel: &(dyn Fn() -> bool + Sync),
) -> Result<FetchedRepo> {
    if cancel() {
        return Err(AppError::Cancelled("fetch cancelled before intake".into()));
    }
    let (owner, repo) = parse_github_owner_repo(repo_url).ok_or_else(|| {
        AppError::BadRequest("repo_url must be an https://github.com/{owner}/{repo} URL".into())
    })?;
    let canonical_url = format!("https://github.com/{owner}/{repo}");

    // Create the temp dir first, wrapped in its cleanup guard, so *any* failure
    // below (including a timeout) still removes it.
    let base = std::env::temp_dir().join(format!("firecrow-scan-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&base)
        .map_err(|e| AppError::Internal(format!("failed to create temp scan dir: {e}")))?;
    let mut temp_guard = TempDirGuard {
        dir: Some(base.clone()),
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(FETCH_TIMEOUT_SECS))
        .user_agent("FireCrow-Scanner/1.0")
        .build()
        .map_err(|e| AppError::HttpClientError(e.to_string()))?;

    // 1. Metadata + permission check, before downloading anything.
    let metadata = fetch_repository_metadata(&client, &owner, &repo, &canonical_url, token).await?;
    if cancel() {
        return Err(AppError::Cancelled("fetch cancelled after intake".into()));
    }

    // 2. Resolve which branch to scan (blank means the repo default) and pin
    // its head commit — unless the caller pinned a SHA at submission time.
    let branch = resolve_branch(repo_branch, &metadata.default_branch);
    let commit_sha = match requested_sha.map(str::trim).filter(|s| !s.is_empty()) {
        Some(pinned) => {
            if !is_valid_commit_sha(pinned) {
                return Err(AppError::BadRequest(
                    "requested commit SHA is not a 40-character lowercase hex digest".into(),
                ));
            }
            pinned.to_string()
        }
        None => {
            fetch_branch_head_sha(&client, &metadata.owner, &metadata.repo, &branch, token).await?
        }
    };
    let metadata = RepositoryMetadata {
        commit_sha: Some(commit_sha.clone()),
        ..metadata
    };
    if cancel() {
        return Err(AppError::Cancelled(
            "fetch cancelled before download".into(),
        ));
    }

    // 3. Download the tarball pinned at the resolved sha, bounded.
    let url = tarball_url(&metadata.owner, &metadata.repo, &commit_sha);
    let mut req = client.get(&url);
    if let Some(auth) = auth_header_value(token) {
        req = req.header("Authorization", auth);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| AppError::HttpClientError(format!("GitHub tarball download failed: {e}")))?;
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let rate_limited = rate_limit_remaining(resp.headers());
        return Err(map_repo_access_error(
            status,
            !token.trim().is_empty(),
            rate_limited.as_deref(),
            &metadata.owner,
            &metadata.repo,
        ));
    }

    let bytes = read_bounded(resp, MAX_DOWNLOAD_BYTES).await?;
    if cancel() {
        return Err(AppError::Cancelled("fetch cancelled before extract".into()));
    }

    // 4. Extract, bounded and symlink-free.
    extract_tarball_with_cancel(&bytes, &base, cancel)?;

    // 5. Snapshot the extracted tree: this is what the scanner will see.
    let snapshot = snapshot_repo(&base, &commit_sha)?;

    // Success: the finished handle takes over the directory.
    temp_guard.disarm();
    Ok(FetchedRepo {
        dir: base,
        metadata,
        snapshot,
    })
}

/// Repository metadata captured from the GitHub API during intake, before any
/// download. This is what the scan is pinned to: an exact repository, branch
/// head, and visibility — never an unexamined URL string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryMetadata {
    pub owner: String,
    pub repo: String,
    /// Canonical `https://github.com/{owner}/{repo}` form.
    pub repository_url: String,
    /// The repository's default branch as reported by GitHub.
    pub default_branch: String,
    /// Head commit of the scanned branch. `None` only when the metadata came
    /// from parsing alone and the branch head was never resolved over the API.
    pub commit_sha: Option<String>,
    pub visibility: Visibility,
}

/// Whether the repository is world-readable or needs a privileged token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Public,
    Private,
}

impl Visibility {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
        }
    }
}

/// `Authorization` header value for `token`, or `None` for an unauthenticated
/// (public-repositories-only) request. Blank tokens are never sent: a
/// `Bearer ` header with no credential would be a lie about authentication.
pub fn auth_header_value(token: &str) -> Option<String> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(format!("Bearer {trimmed}"))
    }
}

/// Tarball endpoint for `git_ref`, which may be a branch name or — as the
/// fetch phase always passes — a pinned commit sha.
pub fn tarball_url(owner: &str, repo: &str, git_ref: &str) -> String {
    format!(
        "{}/repos/{owner}/{repo}/tarball/{git_ref}",
        github_api_base()
    )
}

/// Which branch to scan: the requested one, or the repository default when the
/// request is blank.
pub fn resolve_branch(requested_branch: &str, default_branch: &str) -> String {
    let requested = requested_branch.trim();
    if requested.is_empty() {
        default_branch.to_string()
    } else {
        requested.to_string()
    }
}

/// A git commit sha is 40 lowercase hex characters. Anything else is not a
/// sha GitHub could have returned, so it is rejected rather than scanned.
pub fn is_valid_commit_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// Map a failed GitHub repository-access response to an honest error.
///
/// * `401` — the token was rejected. GitHub answers 401 ("Bad credentials")
///   for invalid, expired, and revoked tokens alike, so they are reported
///   together rather than distinguished by guessing.
/// * `404` — the repository does not exist, is private, or the token has no
///   access. These are deliberately reported together so the error never
///   reveals whether a private repository exists.
/// * `403` with an exhausted rate-limit budget — slow down, not access denied.
/// * `403` otherwise — the token is valid but lacks permission.
/// * `429` — secondary rate limit; slow down.
pub fn map_repo_access_error(
    http_status: u16,
    token_present: bool,
    rate_limit_remaining: Option<&str>,
    owner: &str,
    repo: &str,
) -> AppError {
    match http_status {
        401 => AppError::Unauthorized(format!(
            "GitHub rejected the supplied token (invalid, expired, or revoked); \
             cannot read {owner}/{repo}"
        )),
        403 if rate_limit_remaining == Some("0") => AppError::RateLimited,
        403 => AppError::Forbidden(format!(
            "the supplied GitHub token lacks permission to read {owner}/{repo} (HTTP 403)"
        )),
        404 if token_present => AppError::NotFound(format!(
            "repository {owner}/{repo} was not found, is private, or the token has no access to it"
        )),
        404 => AppError::NotFound(format!(
            "repository {owner}/{repo} was not found, is private, or requires a token: \
             no GitHub token was supplied and unauthenticated requests can only read public repositories"
        )),
        429 => AppError::RateLimited,
        _ => AppError::HttpClientError(format!(
            "GitHub repository access for {owner}/{repo} returned HTTP {http_status}"
        )),
    }
}

/// Parse repository metadata out of a `GET /repos/{{owner}}/{{repo}}` body.
///
/// `private: true` — or any `visibility` other than `"public"` (e.g.
/// `"internal"`) — counts as [`Visibility::Private`].
pub fn parse_repository_metadata(
    owner: &str,
    repo: &str,
    repository_url: &str,
    body: &serde_json::Value,
) -> Result<RepositoryMetadata> {
    let default_branch = body
        .get("default_branch")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AppError::Internal(format!(
                "GitHub response for {owner}/{repo} is missing default_branch"
            ))
        })?
        .to_string();

    let private_flag = body.get("private").and_then(serde_json::Value::as_bool);
    let visibility_field = body
        .get("visibility")
        .and_then(|v| v.as_str())
        .map(str::trim);
    let visibility = match (private_flag, visibility_field) {
        (_, Some("public")) => Visibility::Public,
        (_, Some(_)) => Visibility::Private,
        (Some(false), _) => Visibility::Public,
        _ => Visibility::Private,
    };

    Ok(RepositoryMetadata {
        owner: owner.to_string(),
        repo: repo.to_string(),
        repository_url: repository_url.to_string(),
        default_branch,
        commit_sha: None,
        visibility,
    })
}

/// Validate the token against the repository and capture its metadata.
///
/// This is the permission gate: it runs before any download, and its errors
/// (via [`map_repo_access_error`]) distinguish an expired/invalid token from
/// an inaccessible repository and from a missing token on a private repo.
async fn fetch_repository_metadata(
    client: &reqwest::Client,
    owner: &str,
    repo: &str,
    repository_url: &str,
    token: &str,
) -> Result<RepositoryMetadata> {
    let url = format!("{}/repos/{owner}/{repo}", github_api_base());
    let mut req = client
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28");
    if let Some(auth) = auth_header_value(token) {
        req = req.header("Authorization", auth);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| AppError::HttpClientError(format!("GitHub access check failed: {e}")))?;
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let rate_limited = rate_limit_remaining(resp.headers());
        return Err(map_repo_access_error(
            status,
            !token.trim().is_empty(),
            rate_limited.as_deref(),
            owner,
            repo,
        ));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| AppError::HttpClientError(format!("GitHub metadata decode failed: {e}")))?;
    parse_repository_metadata(owner, repo, repository_url, &body)
}

/// Resolve the head commit sha of `branch` via `GET
/// /repos/{{owner}}/{{repo}}/commits/{{branch}}`.
async fn fetch_branch_head_sha(
    client: &reqwest::Client,
    owner: &str,
    repo: &str,
    branch: &str,
    token: &str,
) -> Result<String> {
    let url = format!(
        "{}/repos/{owner}/{repo}/commits/{branch}",
        github_api_base()
    );
    let mut req = client
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28");
    if let Some(auth) = auth_header_value(token) {
        req = req.header("Authorization", auth);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| AppError::HttpClientError(format!("GitHub branch lookup failed: {e}")))?;
    if resp.status().as_u16() == 404 {
        return Err(AppError::NotFound(format!(
            "branch '{branch}' was not found in {owner}/{repo}"
        )));
    }
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let rate_limited = rate_limit_remaining(resp.headers());
        return Err(map_repo_access_error(
            status,
            !token.trim().is_empty(),
            rate_limited.as_deref(),
            owner,
            repo,
        ));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| AppError::HttpClientError(format!("GitHub branch decode failed: {e}")))?;
    let sha = body.get("sha").and_then(|v| v.as_str()).unwrap_or_default();
    if !is_valid_commit_sha(sha) {
        return Err(AppError::Internal(format!(
            "GitHub returned an invalid head sha for {owner}/{repo}@{branch}"
        )));
    }
    Ok(sha.to_string())
}

/// The `x-ratelimit-remaining` response header, when GitHub sent one.
fn rate_limit_remaining(headers: &reqwest::header::HeaderMap) -> Option<String> {
    headers
        .get("x-ratelimit-remaining")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .map(str::to_string)
}

/// Snapshot of the extracted repository tree: what the scanner will see.
///
/// Recorded after extraction, before scanning, so a later finding can always
/// be tied back to the exact tree it came from.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RepoSnapshot {
    /// Branch head the tree was downloaded at.
    pub commit_sha: String,
    pub file_count: usize,
    pub total_size: u64,
    /// Language name → file count, by filename extension.
    pub languages: std::collections::BTreeMap<String, usize>,
    /// Repo-relative paths of recognized dependency manifests, sorted.
    pub manifests: Vec<String>,
    /// Repo-relative paths of directories in the tree, sorted.
    pub directories: Vec<String>,
    /// Files that look binary (NUL byte in the first sniffed bytes). They are
    /// still scanned on disk; this count only records that they exist, so a
    /// tree full of binaries is never mistaken for an empty one.
    pub binary_file_count: usize,
    /// Repo-relative paths of security-sensitive files, sorted. Detected by
    /// name and path only — see [`is_security_sensitive_path`]. These files
    /// are inventoried but never opened during the snapshot.
    pub security_sensitive: Vec<String>,
}

/// Extension (lowercase, without dot) → language name.
fn language_for_extension(ext: &str) -> Option<&'static str> {
    match ext {
        "rs" => Some("Rust"),
        "py" | "pyi" => Some("Python"),
        "js" | "mjs" | "cjs" | "jsx" => Some("JavaScript"),
        "ts" | "mts" | "cts" | "tsx" => Some("TypeScript"),
        "go" => Some("Go"),
        "java" => Some("Java"),
        "rb" => Some("Ruby"),
        "php" => Some("PHP"),
        "c" | "h" => Some("C"),
        "cpp" | "cc" | "cxx" | "hpp" | "hh" | "hxx" => Some("C++"),
        "cs" => Some("C#"),
        "swift" => Some("Swift"),
        "kt" | "kts" => Some("Kotlin"),
        "scala" => Some("Scala"),
        "sh" | "bash" => Some("Shell"),
        "ps1" => Some("PowerShell"),
        "sql" => Some("SQL"),
        "html" | "htm" => Some("HTML"),
        "css" | "scss" | "less" => Some("CSS"),
        "vue" | "svelte" => Some("JavaScript"),
        "sol" => Some("Solidity"),
        "tf" => Some("Terraform"),
        "yaml" | "yml" => Some("YAML"),
        "json" => Some("JSON"),
        "toml" => Some("TOML"),
        "xml" => Some("XML"),
        "md" | "markdown" => Some("Markdown"),
        _ => None,
    }
}

/// Dependency manifest filenames recognized in the tree. Compared against the
/// lowercased file name, so all entries are lowercase here.
fn is_manifest_file_name(file_name: &str) -> bool {
    matches!(
        file_name,
        "package.json"
            | "package-lock.json"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "cargo.toml"
            | "cargo.lock"
            | "go.mod"
            | "go.sum"
            | "requirements.txt"
            | "pipfile"
            | "pipfile.lock"
            | "poetry.lock"
            | "pyproject.toml"
            | "gemfile"
            | "gemfile.lock"
            | "pom.xml"
            | "build.gradle"
            | "build.gradle.kts"
            | "composer.json"
            | "composer.lock"
    )
}

/// True for paths worth flagging before the scan: secret stores, container
/// definitions, CI workflows, and infrastructure manifests.
///
/// Name and path only — the file is never opened to decide this. `config`
/// matches the file itself and its dotted variants (`config.json`), not build
/// files like `webpack.config.js`. `terraform`/`kubernetes` match path
/// components and their native extensions, not every YAML file that might be
/// one.
pub fn is_security_sensitive_path(repo_relative_path: &str) -> bool {
    let lower = repo_relative_path.to_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    // Secret material.
    if name == ".env" || name.starts_with(".env.") {
        return true;
    }
    if name.contains("credentials") {
        return true;
    }
    if name == "config" || name.starts_with("config.") {
        return true;
    }
    if name.ends_with(".tfstate") || name.ends_with(".tfvars") {
        return true;
    }
    // Containers and CI: what builds and ships the code. `Dockerfile.md` and
    // friends are documentation about container definitions, not the
    // definitions themselves, so doc extensions stay out.
    if name == "dockerfile"
        || name.starts_with("dockerfile-")
        || name.starts_with("dockerfile_")
        || (name.starts_with("dockerfile.")
            && !matches!(
                name.rsplit('.').next().unwrap_or(""),
                "md" | "markdown" | "txt" | "rst" | "adoc"
            ))
    {
        return true;
    }
    if name.starts_with("docker-compose.") {
        return true;
    }
    if lower.contains(".github/workflows/") {
        return true;
    }
    // Infrastructure as code.
    if name.ends_with(".tf") || name.ends_with(".tofu") {
        return true;
    }
    if name == "kustomization.yaml" || name == "kustomization.yml" {
        return true;
    }
    // A path component exactly named `config`, `terraform`, `kubernetes`,
    // or `k8s` flags the subtree: these directories conventionally hold
    // credentials and environment files alongside plain settings, so the
    // whole subtree is worth review. Deliberately exact-component match —
    // `webpack.config.js` and `terraforming/` stay out.
    if lower
        .split('/')
        .any(|c| c == "config" || c == "terraform" || c == "kubernetes" || c == "k8s")
    {
        return true;
    }
    false
}

/// True when the first bytes contain a NUL: binary, not text.
fn looks_binary(sample: &[u8]) -> bool {
    sample.contains(&0)
}

/// Walk `dir` (never following symlinks) and record the snapshot.
///
/// Entry counts re-checked here as defence in depth: the walk must agree with
/// what extraction allowed, and a tree that somehow grew past the caps is
/// rejected rather than scanned.
///
/// Inventory never reads secrets: a file flagged by
/// [`is_security_sensitive_path`] is recorded by path and skipped by the
/// content sniff — its bytes are never opened for the snapshot.
pub fn snapshot_repo(dir: &Path, commit_sha: &str) -> Result<RepoSnapshot> {
    let mut file_count = 0usize;
    let mut total_size = 0u64;
    let mut languages: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut manifests = Vec::new();
    let mut directories = Vec::new();
    let mut binary_file_count = 0usize;
    let mut security_sensitive = Vec::new();

    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = std::fs::read_dir(&current)
            .map_err(|e| AppError::Internal(format!("snapshot walk failed: {e}")))?;
        for entry in entries {
            let entry =
                entry.map_err(|e| AppError::Internal(format!("snapshot walk failed: {e}")))?;
            // Never follow symlinks: an archive symlink that survived to disk
            // (or one raced in afterwards) must not pull the walk outside.
            let meta = std::fs::symlink_metadata(entry.path())
                .map_err(|e| AppError::Internal(format!("snapshot stat failed: {e}")))?;
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                let rel = entry
                    .path()
                    .strip_prefix(dir)
                    .map_err(|e| AppError::Internal(format!("snapshot path error: {e}")))?
                    .to_string_lossy()
                    .to_string();
                directories.push(rel);
                stack.push(entry.path());
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            file_count += 1;
            if file_count > MAX_FILE_COUNT {
                return Err(AppError::PayloadTooLarge);
            }
            total_size = total_size.saturating_add(meta.len());
            if total_size > MAX_TOTAL_BYTES {
                return Err(AppError::PayloadTooLarge);
            }

            let path = entry.path();
            let rel = path
                .strip_prefix(dir)
                .map_err(|e| AppError::Internal(format!("snapshot path error: {e}")))?
                .to_string_lossy()
                .to_string();
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if is_manifest_file_name(&file_name.to_lowercase()) {
                    manifests.push(rel.clone());
                }
            }
            // Sensitive files are recorded by path above and never opened:
            // no secret is read merely for inventory.
            let sensitive = is_security_sensitive_path(&rel);
            if sensitive {
                security_sensitive.push(rel.clone());
            }
            // Binary sniff: raw bytes only, never decoded as text, so a binary
            // file cannot break the walk.
            if !sensitive {
                let sample = read_prefix(&path, SNAPSHOT_SNIFF_BYTES).unwrap_or_default();
                if looks_binary(&sample) {
                    binary_file_count += 1;
                }
            }
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if let Some(lang) = language_for_extension(&ext.to_lowercase()) {
                    *languages.entry(lang.to_string()).or_insert(0) += 1;
                }
            }
        }
    }

    manifests.sort();
    directories.sort();
    security_sensitive.sort();
    Ok(RepoSnapshot {
        commit_sha: commit_sha.to_string(),
        file_count,
        total_size,
        languages,
        manifests,
        directories,
        binary_file_count,
        security_sensitive,
    })
}

/// Read up to `limit` bytes from the start of `path`. A short read (or an
/// unreadable file) yields what was read, never an error: the snapshot must
/// not fail the fetch because one file is odd.
fn read_prefix(path: &Path, limit: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)
        .map_err(|e| AppError::Internal(format!("snapshot read failed: {e}")))?;
    let mut buf = Vec::new();
    file.by_ref()
        .take(limit)
        .read_to_end(&mut buf)
        .map_err(|e| AppError::Internal(format!("snapshot read failed: {e}")))?;
    Ok(buf)
}

/// Read an HTTP body up to `cap` bytes, erroring past the cap.
async fn read_bounded(resp: reqwest::Response, cap: u64) -> Result<Vec<u8>> {
    // Reject on the declared length before allocating, and verify again after.
    if let Some(len) = resp.content_length() {
        if len > cap {
            return Err(AppError::PayloadTooLarge);
        }
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| AppError::HttpClientError(e.to_string()))?;
    if bytes.len() as u64 > cap {
        return Err(AppError::PayloadTooLarge);
    }
    Ok(bytes.to_vec())
}

/// Extract a gzip-compressed tar into `dest`, enforcing every cap and rejecting
/// every link/escape entry.
pub fn extract_tarball(gz: &[u8], dest: &Path) -> Result<()> {
    extract_tarball_with_cancel(gz, dest, &|| false)
}

/// Extract with cancellation: `cancel()` is consulted every few entries so a
/// cancelled job stops extracting instead of grinding through a huge archive.
pub fn extract_tarball_with_cancel(
    gz: &[u8],
    dest: &Path,
    cancel: &(dyn Fn() -> bool + Sync),
) -> Result<()> {
    let mut decoder = flate2::read::GzDecoder::new(gz);
    let mut data = Vec::new();
    decoder
        .read_to_end(&mut data)
        .map_err(|e| AppError::Internal(format!("gzip decode failed: {e}")))?;

    // Decompression bomb guard: refuse before touching the disk.
    if data.len() as u64 > MAX_TOTAL_BYTES {
        return Err(AppError::PayloadTooLarge);
    }

    let mut pos = 0usize;
    let mut pending_name: Option<String> = None;
    let mut file_count = 0usize;
    let mut total: u64 = 0;

    while pos + 512 <= data.len() {
        // Consulted every entry: a single boolean load against disk IO, so a
        // cancelled job stops extracting at once instead of grinding on.
        if cancel() {
            return Err(AppError::Cancelled("extract cancelled".into()));
        }
        let header = &data[pos..pos + 512];
        // Two zero blocks mark the end of the archive.
        if header.iter().all(|&b| b == 0) {
            break;
        }

        let raw_name = cstr(&header[0..100]);
        let size = parse_octal(&header[124..136])?;
        let typeflag = header[156];
        let prefix = cstr(&header[345..500]);

        pos += 512;
        let data_end = pos
            .checked_add(size as usize)
            .ok_or_else(|| AppError::Internal("tar entry size overflow".into()))?;
        if data_end > data.len() {
            return Err(AppError::Internal("truncated tar archive".into()));
        }
        let body = &data[pos..data_end];

        match typeflag {
            // GNU long name: the following entry's name is this payload.
            b'L' => {
                pending_name = Some(
                    String::from_utf8_lossy(body)
                        .trim_end_matches('\0')
                        .to_string(),
                );
            }
            // PAX extended header: honour only `path=`.
            b'x' => {
                if let Some(p) = pax_path(body) {
                    pending_name = Some(p);
                }
            }
            // Global PAX header: ignore.
            b'g' => {}
            b'0' | b'\0' | b'7' => {
                let name = resolve_name(&pending_name, &raw_name, &prefix);
                pending_name = None;

                if size > MAX_FILE_BYTES {
                    return Err(AppError::PayloadTooLarge);
                }
                total = total.saturating_add(size);
                if total > MAX_TOTAL_BYTES {
                    return Err(AppError::PayloadTooLarge);
                }
                file_count += 1;
                if file_count > MAX_FILE_COUNT {
                    return Err(AppError::PayloadTooLarge);
                }

                let path = safe_join(dest, &name)?;
                // Defence in depth: never write through a pre-existing symlink.
                if let Ok(meta) = std::fs::symlink_metadata(&path) {
                    if meta.file_type().is_symlink() {
                        return Err(AppError::Internal(
                            "refusing to write through a symlink in the archive".into(),
                        ));
                    }
                }
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        AppError::Internal(format!("failed to create directory: {e}"))
                    })?;
                }
                std::fs::write(&path, body)
                    .map_err(|e| AppError::Internal(format!("failed to write file: {e}")))?;
            }
            b'5' => {
                let name = resolve_name(&pending_name, &raw_name, &prefix);
                pending_name = None;
                // Directories count toward the entry budget too, so a
                // directory-only bomb cannot evade the file-count cap.
                file_count += 1;
                if file_count > MAX_FILE_COUNT {
                    return Err(AppError::PayloadTooLarge);
                }
                let path = safe_join(dest, &name)?;
                std::fs::create_dir_all(&path)
                    .map_err(|e| AppError::Internal(format!("failed to create directory: {e}")))?;
            }
            // Symlinks and hardlinks are rejected outright.
            b'1' | b'2' => {
                return Err(AppError::Internal(
                    "repository archive contains a link entry; refusing to extract".into(),
                ));
            }
            // Everything else (devices, fifos, …) is skipped.
            _ => {
                pending_name = None;
            }
        }

        pos = data_end + pad(size as usize);
    }

    Ok(())
}

/// `owner`/`repo` from an `https://github.com/{owner}/{repo}` URL.
///
/// Delegates to the scan contract's [`normalize_repository_url`](crate::schemas::scan_contract::normalize_repository_url),
/// the single authority on which URLs are acceptable, so the fetch phase can
/// never disagree with intake validation about what counts as a repository.
pub fn parse_github_owner_repo(url: &str) -> Option<(String, String)> {
    let canonical = crate::schemas::scan_contract::normalize_repository_url(url).ok()?;
    let rest = canonical.strip_prefix("https://github.com/")?;
    let mut it = rest.split('/');
    let owner = it.next()?.to_string();
    let repo = it.next()?.to_string();
    if it.next().is_some() {
        return None;
    }
    Some((owner, repo))
}

fn resolve_name(pending: &Option<String>, raw: &str, prefix: &str) -> String {
    if let Some(p) = pending {
        return p.clone();
    }
    if prefix.is_empty() {
        raw.to_string()
    } else {
        format!("{prefix}/{raw}")
    }
}

/// Join a tarball member name onto `dest`, refusing anything that could escape.
///
/// Besides traversal and absolute paths, over-long paths are rejected: a
/// `MAX_PATH_CHARS`-plus name or a component over the filesystem's
/// `MAX_COMPONENT_CHARS` would otherwise fail later at the OS call with a
/// confusing error — or, on some filesystems, silently truncate.
fn safe_join(dest: &Path, name: &str) -> Result<PathBuf> {
    let name = name.trim_start_matches("./");
    if name.is_empty() {
        return Err(AppError::Internal("tar entry has an empty name".into()));
    }
    if name.chars().count() > MAX_PATH_CHARS {
        return Err(AppError::PayloadTooLarge);
    }
    let mut out = dest.to_path_buf();
    for comp in Path::new(name).components() {
        match comp {
            Component::Normal(c) => {
                if c.len() > MAX_COMPONENT_CHARS {
                    return Err(AppError::PayloadTooLarge);
                }
                out.push(c);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(AppError::Internal(format!(
                    "tar entry escapes the extraction root: {name}"
                )));
            }
        }
    }
    if !out.starts_with(dest) {
        return Err(AppError::Internal(format!(
            "tar entry escapes the extraction root: {name}"
        )));
    }
    Ok(out)
}

fn pad(size: usize) -> usize {
    (512 - (size % 512)) % 512
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

/// Parse a tar numeric field (octal, or base-256 for GNU large values).
fn parse_octal(bytes: &[u8]) -> Result<u64> {
    if bytes.is_empty() {
        return Ok(0);
    }
    if bytes[0] & 0x80 != 0 {
        // GNU base-256 encoding.
        let mut value: u64 = 0;
        for &b in &bytes[1..] {
            value = (value << 8) | b as u64;
        }
        return Ok(value);
    }
    let s = cstr(bytes);
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(&s, 8)
        .map_err(|_| AppError::Internal("invalid octal field in tar header".into()))
}

/// Extract `path=` from a PAX extended-header payload, if present.
fn pax_path(body: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    for line in text.split('\n') {
        if let Some((_, rest)) = line.split_once(' ') {
            if let Some(value) = rest.strip_prefix("path=") {
                return Some(value.to_string());
            }
        }
    }
    None
}
