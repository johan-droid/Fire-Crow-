//! Phase 3 fetcher tests: obtain the source safely.
//!
//! Covers: malicious archives (`../evil`, absolute paths, symlinks,
//! decompression bombs, file-count bombs, oversized files, over-long paths),
//! extraction cancellation, snapshot recording (sha, counts, languages,
//! manifests, directories, binaries), and an end-to-end mocked-GitHub fetch.
//! Nothing here touches the live GitHub API.

use firecrow_backend::agents::fetch::{
    extract_tarball, extract_tarball_with_cancel, fetch_repo_with_cancel, github_api_base,
    snapshot_repo, tarball_url, MAX_COMPONENT_CHARS, MAX_FILE_BYTES, MAX_FILE_COUNT,
    MAX_PATH_CHARS, MAX_TOTAL_BYTES,
};
use firecrow_backend::error::AppError;
use std::path::{Path, PathBuf};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Serializes the tests that mutate the process-global API base URL.
/// An async-aware mutex: the mocked end-to-end test legitimately holds it
/// across awaits while it owns the process environment.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn lock_env_blocking() -> tokio::sync::MutexGuard<'static, ()> {
    ENV_LOCK.blocking_lock()
}

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

// ---------------------------------------------------------------------------
// Tar fixture builders (headers carry only what the parser reads)
// ---------------------------------------------------------------------------

fn tar_header(name: &str, typeflag: u8, size: usize) -> [u8; 512] {
    let mut h = [0u8; 512];
    let name_bytes = name.as_bytes();
    let prefix_len = name_bytes.len().saturating_sub(100);
    let (prefix, short) = if prefix_len > 0 {
        (
            &name_bytes[..prefix_len.min(155)],
            &name_bytes[prefix_len..],
        )
    } else {
        (&[][..], name_bytes)
    };
    let take = short.len().min(100);
    h[0..take].copy_from_slice(&short[..take]);
    let size_field = format!("{size:011o}\0");
    h[124..136].copy_from_slice(size_field.as_bytes());
    h[136..148].copy_from_slice(b"00000000000\0");
    h[148..156].copy_from_slice(b"        ");
    h[156] = typeflag;
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    let plen = prefix.len().min(155);
    h[345..345 + plen].copy_from_slice(&prefix[..plen]);
    h
}

fn tar_entry(name: &str, typeflag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = tar_header(name, typeflag, data.len()).to_vec();
    out.extend_from_slice(data);
    let pad = (512 - (data.len() % 512)) % 512;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

/// Entry with a GNU long-name (`L`) header, for names over 100 bytes.
fn tar_entry_long(name: &str, typeflag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = tar_entry(name, b'L', name.as_bytes());
    out.extend(tar_entry("longname-placeholder", typeflag, data));
    out
}

fn gzify(data: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "firecrow-fetch-test-{tag}-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn dir_is_empty(dir: &Path) -> bool {
    std::fs::read_dir(dir)
        .map(|mut it| it.next().is_none())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Malicious archives
// ---------------------------------------------------------------------------

#[test]
fn parent_traversal_entry_is_rejected_and_writes_nothing() {
    let dir = scratch_dir("traversal");
    let tar = tar_entry("pkg/../../evil.txt", b'0', b"x");
    assert!(extract_tarball(&gzify(&tar), &dir).is_err());
    assert!(dir_is_empty(&dir), "traversal must write nothing");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn absolute_path_entry_is_rejected_and_writes_nothing() {
    let dir = scratch_dir("absolute");
    let tar = tar_entry("/abs/evil.txt", b'0', b"x");
    assert!(extract_tarball(&gzify(&tar), &dir).is_err());
    assert!(dir_is_empty(&dir), "absolute path must write nothing");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn symlink_and_hardlink_entries_are_rejected() {
    for (tag, flag) in [("symlink", b'2'), ("hardlink", b'1')] {
        let dir = scratch_dir(tag);
        let tar = tar_entry("pkg/link", flag, b"");
        let err = extract_tarball(&gzify(&tar), &dir).unwrap_err();
        assert!(
            matches!(err, AppError::Internal(_)),
            "link entries must be refused outright: {err:?}"
        );
        assert!(dir_is_empty(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn over_long_paths_are_rejected_before_touching_disk() {
    // Full path over the limit (needs a long-name entry past 100 bytes).
    let dir = scratch_dir("longpath");
    let long = format!("pkg/{}.txt", "a".repeat(MAX_PATH_CHARS));
    assert!(extract_tarball(&gzify(&tar_entry_long(&long, b'0', b"x")), &dir).is_err());
    assert!(dir_is_empty(&dir));
    let _ = std::fs::remove_dir_all(&dir);

    // One component over the filesystem limit.
    let dir = scratch_dir("longcomp");
    let evil = format!("pkg/{}/f.txt", "b".repeat(MAX_COMPONENT_CHARS + 1));
    assert!(extract_tarball(&gzify(&tar_entry_long(&evil, b'0', b"x")), &dir).is_err());
    assert!(dir_is_empty(&dir));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn oversized_single_file_is_rejected() {
    let dir = scratch_dir("bigfile");
    // Declared size just over the per-file cap; zeros compress to almost nothing.
    let body = vec![0u8; (MAX_FILE_BYTES + 1) as usize];
    let err = extract_tarball(&gzify(&tar_entry("pkg/big.bin", b'0', &body)), &dir).unwrap_err();
    assert!(
        matches!(err, AppError::PayloadTooLarge),
        "oversized file must be PayloadTooLarge: {err:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn huge_total_archive_is_rejected() {
    let dir = scratch_dir("bigtotal");
    // Each file stays under the per-file cap; the sum breaks the total cap.
    let per_file = (MAX_TOTAL_BYTES / 8) as usize;
    assert!(per_file as u64 <= MAX_FILE_BYTES);
    let mut tar = Vec::new();
    for i in 0..9 {
        tar.extend(tar_entry(
            &format!("pkg/f{i}.bin"),
            b'0',
            &vec![0u8; per_file],
        ));
    }
    let err = extract_tarball(&gzify(&tar), &dir).unwrap_err();
    assert!(
        matches!(err, AppError::PayloadTooLarge),
        "decompression bomb must be PayloadTooLarge: {err:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn huge_file_count_is_rejected() {
    let dir = scratch_dir("manyfiles");
    let one = tar_entry("p/f.txt", b'0', b"");
    let mut tar = Vec::with_capacity(one.len() * (MAX_FILE_COUNT + 1));
    for _ in 0..=MAX_FILE_COUNT {
        tar.extend_from_slice(&one);
    }
    let err = extract_tarball(&gzify(&tar), &dir).unwrap_err();
    assert!(
        matches!(err, AppError::PayloadTooLarge),
        "file-count bomb must be PayloadTooLarge: {err:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn directory_only_bomb_counts_against_the_budget() {
    let dir = scratch_dir("manydirs");
    let one = tar_entry("p/d", b'5', b"");
    let mut tar = Vec::with_capacity(one.len() * (MAX_FILE_COUNT + 1));
    for _ in 0..=MAX_FILE_COUNT {
        tar.extend_from_slice(&one);
    }
    assert!(
        extract_tarball(&gzify(&tar), &dir).is_err(),
        "directory-only bomb must not evade the entry cap"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------

#[test]
fn extract_aborts_when_cancelled() {
    let dir = scratch_dir("cancel");
    let mut tar = Vec::new();
    for i in 0..100 {
        tar.extend(tar_entry(&format!("pkg/f{i}.txt"), b'0', b"x"));
    }
    let gz = gzify(&tar);
    let err = extract_tarball_with_cancel(&gz, &dir, &|| true).unwrap_err();
    assert!(
        matches!(err, AppError::Cancelled(_)),
        "cancelled extract must report Cancelled: {err:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn fetch_aborts_before_any_network_when_cancelled() {
    // Cancelled up front: must fail without touching the network and without
    // leaking a temp dir.
    let before: Vec<PathBuf> = std::fs::read_dir(std::env::temp_dir())
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("firecrow-scan-"))
                .unwrap_or(false)
        })
        .collect();
    let err = fetch_repo_with_cancel("https://github.com/acme/widget", "main", "", None, &|| true)
        .await
        .unwrap_err();
    assert!(
        matches!(err, AppError::Cancelled(_)),
        "cancelled fetch must report Cancelled: {err:?}"
    );
    let after: Vec<PathBuf> = std::fs::read_dir(std::env::temp_dir())
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("firecrow-scan-"))
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(before, after, "cancelled fetch must leak no temp dir");
}

// ---------------------------------------------------------------------------
// Snapshot recording
// ---------------------------------------------------------------------------

fn write_tree(root: &Path) {
    for (rel, content) in [
        ("repo/src/main.rs", b"fn main() {}".as_slice()),
        ("repo/src/lib.rs", b"pub fn f() {}".as_slice()),
        ("repo/app/app.py", b"print('hi')".as_slice()),
        ("repo/web/index.js", b"console.log(1)".as_slice()),
        ("repo/README.md", b"# hi".as_slice()),
        ("repo/package.json", b"{}".as_slice()),
        ("repo/rust/Cargo.toml", b"[package]".as_slice()),
        ("repo/blob.bin", &[0u8, 1, 2, 0, 3][..]),
        ("repo/img/logo.png", &[137u8, 80, 78, 71, 0][..]),
        ("repo/data/notes.txt", b"plain".as_slice()),
    ] {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, content).unwrap();
    }
}

#[test]
fn snapshot_records_tree_shape() {
    let dir = scratch_dir("snapshot");
    write_tree(&dir);
    // A symlink must be ignored, never followed.
    #[cfg(unix)]
    std::os::unix::fs::symlink(dir.join("repo/src"), dir.join("repo/link")).unwrap();

    let snap = snapshot_repo(&dir, SHA).expect("snapshot must succeed");
    assert_eq!(snap.commit_sha, SHA);
    assert_eq!(snap.file_count, 10);
    assert_eq!(
        snap.total_size,
        [
            "fn main() {}".len(),
            "pub fn f() {}".len(),
            "print('hi')".len(),
            "console.log(1)".len(),
            "# hi".len(),
            "{}".len(),
            "[package]".len(),
            5,
            5,
            "plain".len(),
        ]
        .iter()
        .sum::<usize>() as u64
    );
    assert_eq!(snap.languages.get("Rust"), Some(&2));
    assert_eq!(snap.languages.get("Python"), Some(&1));
    assert_eq!(snap.languages.get("JavaScript"), Some(&1));
    assert_eq!(snap.languages.get("Markdown"), Some(&1));
    assert_eq!(snap.languages.get("JSON"), Some(&1));
    assert_eq!(snap.languages.get("TOML"), Some(&1));
    assert!(
        !snap.languages.contains_key(""),
        "unknown extensions stay out"
    );
    assert_eq!(
        snap.manifests,
        vec!["repo/package.json", "repo/rust/Cargo.toml"]
    );
    assert!(snap.directories.contains(&"repo".to_string()));
    assert!(snap.directories.contains(&"repo/src".to_string()));
    assert!(
        !snap.directories.iter().any(|d| d.contains("link")),
        "symlink must not appear"
    );
    assert_eq!(
        snap.binary_file_count, 2,
        "blob.bin and logo.png are binary"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn manifest_names_match_case_insensitively() {
    let dir = scratch_dir("manifestcase");
    std::fs::create_dir_all(dir.join("repo")).unwrap();
    std::fs::write(dir.join("repo/Package.JSON"), b"{}").unwrap();
    let snap = snapshot_repo(&dir, SHA).unwrap();
    assert_eq!(snap.manifests, vec!["repo/Package.JSON"]);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// API base URL + tarball pinning
// ---------------------------------------------------------------------------

#[test]
fn api_base_defaults_and_overrides() {
    let _guard = lock_env_blocking();
    std::env::remove_var("GITHUB_API_BASE_URL");
    assert_eq!(github_api_base(), "https://api.github.com");
    std::env::set_var("GITHUB_API_BASE_URL", "https://ghe.example.com/api/v3/");
    assert_eq!(github_api_base(), "https://ghe.example.com/api/v3");
    std::env::set_var("GITHUB_API_BASE_URL", "   ");
    assert_eq!(github_api_base(), "https://api.github.com");
    std::env::remove_var("GITHUB_API_BASE_URL");
}

#[test]
fn tarball_url_uses_the_configured_base() {
    let _guard = lock_env_blocking();
    std::env::remove_var("GITHUB_API_BASE_URL");
    assert_eq!(
        tarball_url("acme", "widget", SHA),
        format!("https://api.github.com/repos/acme/widget/tarball/{SHA}")
    );
    std::env::remove_var("GITHUB_API_BASE_URL");
}

// ---------------------------------------------------------------------------
// End-to-end fetch against a mocked GitHub API
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mocked_fetch_captures_metadata_snapshot_and_tree() {
    let _guard = ENV_LOCK.lock().await;
    let server = MockServer::start().await;
    std::env::set_var("GITHUB_API_BASE_URL", server.uri());

    Mock::given(method("GET"))
        .and(path("/repos/acme/widget"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "full_name": "acme/widget",
            "private": false,
            "default_branch": "main",
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widget/commits/main"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sha": SHA,
        })))
        .mount(&server)
        .await;
    let mut tar = tar_entry("widget-abc123/src/main.rs", b'0', b"fn main() {}");
    tar.extend(tar_entry("widget-abc123/Cargo.toml", b'0', b"[package]"));
    Mock::given(method("GET"))
        .and(path(format!("/repos/acme/widget/tarball/{SHA}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(gzify(&tar)))
        .mount(&server)
        .await;

    let fetched = fetch_repo_with_cancel(
        "https://github.com/acme/widget",
        "main",
        "test-token",
        None,
        &|| false,
    )
    .await
    .expect("mocked fetch must succeed");

    let meta = fetched.metadata();
    assert_eq!(meta.owner, "acme");
    assert_eq!(meta.repo, "widget");
    assert_eq!(meta.repository_url, "https://github.com/acme/widget");
    assert_eq!(meta.default_branch, "main");
    assert_eq!(meta.commit_sha.as_deref(), Some(SHA));
    assert!(matches!(
        meta.visibility,
        firecrow_backend::agents::fetch::Visibility::Public
    ));

    let snap = fetched.snapshot();
    assert_eq!(snap.commit_sha, SHA);
    assert_eq!(snap.file_count, 2);
    assert_eq!(snap.languages.get("Rust"), Some(&1));
    assert_eq!(snap.languages.get("TOML"), Some(&1));
    assert_eq!(snap.manifests, vec!["widget-abc123/Cargo.toml"]);
    assert!(snap.directories.contains(&"widget-abc123".to_string()));

    // The tree is really on disk where the handle says it is.
    assert!(fetched.path().join("widget-abc123/src/main.rs").is_file());

    std::env::remove_var("GITHUB_API_BASE_URL");
}

/// A pinned SHA is used verbatim: no branch-head lookup happens, and the
/// tarball is downloaded at exactly the requested snapshot.
#[tokio::test]
async fn a_pinned_sha_skips_branch_resolution_and_uses_the_snapshot() {
    const PINNED: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    let _guard = ENV_LOCK.lock().await;
    let server = MockServer::start().await;
    std::env::set_var("GITHUB_API_BASE_URL", server.uri());

    Mock::given(method("GET"))
        .and(path("/repos/acme/widget"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "full_name": "acme/widget",
            "private": false,
            "default_branch": "main",
        })))
        .mount(&server)
        .await;
    let tar = tar_entry("widget-abc123/src/main.rs", b'0', b"fn main() {}");
    Mock::given(method("GET"))
        .and(path(format!("/repos/acme/widget/tarball/{PINNED}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(gzify(&tar)))
        .mount(&server)
        .await;

    let fetched = fetch_repo_with_cancel(
        "https://github.com/acme/widget",
        "main",
        "test-token",
        Some(PINNED),
        &|| false,
    )
    .await
    .expect("pinned fetch must succeed");

    assert_eq!(fetched.snapshot().commit_sha, PINNED);

    // The branch head was never resolved: no request for it was made.
    let requests = server.received_requests().await.unwrap_or_default();
    assert!(
        requests
            .iter()
            .all(|r| !r.url.as_str().contains("/commits/main")),
        "a pinned fetch must not resolve the branch head"
    );

    std::env::remove_var("GITHUB_API_BASE_URL");
}

/// A pin that is not a SHA fails closed instead of scanning an unintended ref.
#[tokio::test]
async fn a_malformed_pin_fails_before_any_download() {
    let _guard = ENV_LOCK.lock().await;
    let server = MockServer::start().await;
    std::env::set_var("GITHUB_API_BASE_URL", server.uri());

    Mock::given(method("GET"))
        .and(path("/repos/acme/widget"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "full_name": "acme/widget",
            "private": false,
            "default_branch": "main",
        })))
        .mount(&server)
        .await;

    let err = fetch_repo_with_cancel(
        "https://github.com/acme/widget",
        "main",
        "test-token",
        Some("main"),
        &|| false,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, AppError::BadRequest(_)),
        "a branch name in the SHA slot must be refused, got: {err}"
    );

    std::env::remove_var("GITHUB_API_BASE_URL");
}
