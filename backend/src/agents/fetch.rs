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
/// Network timeout for the access check and the download.
pub const FETCH_TIMEOUT_SECS: u64 = 120;

/// A fetched repository on local disk. Removes its temporary directory on drop.
pub struct FetchedRepo {
    dir: PathBuf,
}

impl FetchedRepo {
    pub fn path(&self) -> &Path {
        &self.dir
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
pub async fn fetch_repo(repo_url: &str, repo_branch: &str, token: &str) -> Result<FetchedRepo> {
    let (owner, repo) = parse_github_owner_repo(repo_url).ok_or_else(|| {
        AppError::BadRequest("repo_url must be an https://github.com/{owner}/{repo} URL".into())
    })?;

    // Create the temp dir first, wrapped in its cleanup guard, so *any* failure
    // below (including a timeout) still removes it.
    let base = std::env::temp_dir().join(format!("firecrow-scan-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&base)
        .map_err(|e| AppError::Internal(format!("failed to create temp scan dir: {e}")))?;
    let handle = FetchedRepo { dir: base.clone() };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(FETCH_TIMEOUT_SECS))
        .user_agent("FireCrow-Scanner/1.0")
        .build()
        .map_err(|e| AppError::HttpClientError(e.to_string()))?;

    // 1. Confirm the token can read the repository before downloading anything.
    let access_url = format!("https://api.github.com/repos/{owner}/{repo}");
    let mut req = client.get(&access_url);
    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    let access = req
        .send()
        .await
        .map_err(|e| AppError::HttpClientError(format!("GitHub access check failed: {e}")))?;
    if !access.status().is_success() {
        return Err(AppError::Forbidden(format!(
            "the supplied GitHub token cannot read {owner}/{repo} (HTTP {})",
            access.status().as_u16()
        )));
    }

    // 2. Download the tarball, bounded.
    let tarball_url = format!("https://api.github.com/repos/{owner}/{repo}/tarball/{repo_branch}");
    let mut req = client.get(&tarball_url);
    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    let resp = req
        .send()
        .await
        .map_err(|e| AppError::HttpClientError(format!("GitHub tarball download failed: {e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::HttpClientError(format!(
            "GitHub tarball download returned HTTP {}",
            resp.status().as_u16()
        )));
    }

    let bytes = read_bounded(resp, MAX_DOWNLOAD_BYTES).await?;

    // 3. Extract, bounded and symlink-free.
    extract_tarball(&bytes, &base)?;

    Ok(handle)
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
                pending_name =
                    Some(String::from_utf8_lossy(body).trim_end_matches('\0').to_string());
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
pub fn parse_github_owner_repo(url: &str) -> Option<(String, String)> {
    let rest = url
        .trim()
        .strip_prefix("https://github.com/")?
        .trim_end_matches('/');
    let rest = rest.strip_suffix(".git").unwrap_or(rest);
    let mut it = rest.split('/');
    let owner = it.next()?;
    let repo = it.next()?;
    if it.next().is_some() {
        return None;
    }
    let ok = |s: &str| {
        !s.is_empty()
            && s != "."
            && s != ".."
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    };
    if ok(owner) && ok(repo) {
        Some((owner.to_string(), repo.to_string()))
    } else {
        None
    }
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
fn safe_join(dest: &Path, name: &str) -> Result<PathBuf> {
    let name = name.trim_start_matches("./");
    if name.is_empty() {
        return Err(AppError::Internal("tar entry has an empty name".into()));
    }
    let mut out = dest.to_path_buf();
    for comp in Path::new(name).components() {
        match comp {
            Component::Normal(c) => out.push(c),
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
