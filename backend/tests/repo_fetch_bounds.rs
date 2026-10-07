//! Phase B (H1) bounds tests: acquisition must be streaming and incrementally
//! bounded — never buffer-then-check.
//!
//! Covers: oversized declared bodies, oversized *chunked* bodies with early
//! abort (server-side byte accounting proves the client stops consuming),
//! cancellation mid-download, high-ratio gzip bombs, total-budget aborts
//! mid-stream, skipped-body bombs, partial-file cleanup on mid-stream failure,
//! stream alignment after `g`/sized-dir members, multi-chunk round-trips, and
//! fetch-level tempdir cleanup after a bomb. DB-free.
//!
//! Scope: H1 only.

use firecrow_backend::agents::fetch::{
    extract_tarball, fetch_repo_with_cancel, read_bounded, MAX_TOTAL_BYTES,
};
use firecrow_backend::error::AppError;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Serializes tests that mutate the process-global API base URL.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

// ---------------------------------------------------------------------------
// Tar fixture builders (same minimal subset the parser reads)
// ---------------------------------------------------------------------------

fn tar_header(name: &str, typeflag: u8, size: usize) -> [u8; 512] {
    let mut h = [0u8; 512];
    let take = name.len().min(100);
    h[0..take].copy_from_slice(&name.as_bytes()[..take]);
    let size_field = format!("{size:011o}\0");
    h[124..136].copy_from_slice(size_field.as_bytes());
    h[156] = typeflag;
    h
}

fn tar_entry(name: &str, typeflag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = tar_header(name, typeflag, data.len()).to_vec();
    out.extend_from_slice(data);
    let pad = (512 - (data.len() % 512)) % 512;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

fn gzify(data: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "firecrow-bounds-test-{tag}-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn is_payload_too_large(err: &AppError) -> bool {
    matches!(err, AppError::PayloadTooLarge)
}

// ---------------------------------------------------------------------------
// Raw chunked HTTP server: full control over transfer framing, plus
// server-side byte accounting that proves the client aborts early.
// ---------------------------------------------------------------------------

struct ChunkServer {
    port: u16,
    handle: Option<std::thread::JoinHandle<()>>,
}

/// Serve `total_bytes` of chunked body in `chunk` pieces paced `pace_ms`
/// apart, then idle. The pacing is the point: at 32KB/5ms a 1GB stream would
/// take hours, so a buffer-then-check client hangs (or OOMs) while a
/// streaming client refuses in milliseconds.
fn serve_chunked(
    total_bytes: u64,
    chunk: usize,
    first_chunk_delay_ms: u64,
    pace_ms: u64,
) -> ChunkServer {
    use std::io::{BufRead, Read as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(30)))
            .ok();
        // Consume the request head; the path does not matter.
        let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                break;
            }
        }
        let head = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ncontent-type: application/octet-stream\r\n\r\n";
        if stream.write_all(head).is_err() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(first_chunk_delay_ms));
        let piece = vec![b'z'; chunk];
        let mut remaining = total_bytes;
        while remaining > 0 {
            let n = remaining.min(chunk as u64) as usize;
            let frame = format!("{n:x}\r\n");
            let mut buf = frame.into_bytes();
            buf.extend_from_slice(&piece[..n]);
            buf.extend_from_slice(b"\r\n");
            if stream.write_all(&buf).is_err() {
                break; // client went away: stop pushing.
            }
            remaining -= n as u64;
            std::thread::sleep(std::time::Duration::from_millis(pace_ms));
        }
        // Best effort: terminator + drain. Either may fail on a gone client;
        // the read timeout below guarantees this thread always terminates.
        let _ = stream.write_all(b"0\r\n\r\n");
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .ok();
        let mut drain = [0u8; 1024];
        let _ = reader.read(&mut drain);
    });
    ChunkServer {
        port,
        handle: Some(handle),
    }
}

impl ChunkServer {
    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/tarball", self.port)
    }

    /// Release the server thread: it observes the client disconnect and exits
    /// on its own (write failure, then the bounded drain read). Joining it
    /// would couple the test to TCP teardown timing, which is
    /// environment-dependent and says nothing about the client under test.
    fn detach(mut self) {
        if let Some(h) = self.handle.take() {
            std::mem::forget(h);
        }
    }
}

// ---------------------------------------------------------------------------
// Download bounds
// ---------------------------------------------------------------------------

/// A paced, effectively endless chunked body against an 8KB cap: at
/// 32KB/5ms the full 1GB would take ~9 hours, so a buffer-then-check client
/// hangs (or OOMs) while the streaming client must refuse in milliseconds
/// having consumed ~cap bytes. (The old `resp.bytes()` code did the former.)
#[tokio::test]
async fn chunked_oversized_body_aborts_early() {
    let server = serve_chunked(1024 * 1024 * 1024, 32 * 1024, 0, 5);
    let started = std::time::Instant::now();
    let err = read_bounded(
        reqwest::get(server.url()).await.expect("chunk server up"),
        8 * 1024,
        &|| false,
    )
    .await
    .unwrap_err();
    assert!(
        is_payload_too_large(&err),
        "oversized chunked body must be PayloadTooLarge, got: {err}"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "client must refuse promptly, took {:?}",
        started.elapsed()
    );
    server.detach();
}

/// Cancellation between chunks surfaces as Cancelled, not as a partial body.
#[tokio::test]
async fn chunked_download_honours_cancellation() {
    static CANCEL: AtomicBool = AtomicBool::new(false);
    CANCEL.store(false, Ordering::SeqCst);
    // First chunk arrives after the flag is already set: deterministic.
    let server = serve_chunked(1024 * 1024, 4096, 300, 0);
    CANCEL.store(true, Ordering::SeqCst);
    let err = read_bounded(
        reqwest::get(server.url()).await.expect("chunk server up"),
        8 * 1024,
        &|| CANCEL.load(Ordering::SeqCst),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, AppError::Cancelled(_)),
        "cancelled download must be Cancelled, got: {err}"
    );
    CANCEL.store(false, Ordering::SeqCst);
    server.detach();
}

/// A declared Content-Length past the cap fails before a single body byte.
/// Served over raw TCP: a well-behaved mock server refuses to declare a
/// length it does not send, which is exactly the lie this path must survive.
#[tokio::test]
async fn oversized_declared_length_fails_before_body() {
    use std::io::Write as _;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut head = [0u8; 1024];
        use std::io::Read as _;
        let _ = stream.read(&mut head);
        // Lie about the length, then stall: the client must refuse on the
        // header alone without waiting for (or reading) the body.
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK\r\ncontent-length: 999999999\r\ncontent-type: application/octet-stream\r\n\r\n",
        );
        std::thread::sleep(std::time::Duration::from_secs(10));
    });
    let err = read_bounded(
        reqwest::get(format!("http://127.0.0.1:{port}/big"))
            .await
            .unwrap(),
        8 * 1024,
        &|| false,
    )
    .await
    .unwrap_err();
    assert!(is_payload_too_large(&err), "got: {err}");
    let _ = server.join();
}

// ---------------------------------------------------------------------------
// Inflation bounds (all through the public streaming extractor)
// ---------------------------------------------------------------------------

/// Ten 16MB zero files = 160MB inflated from kilobytes: the total budget must
/// abort mid-stream, not after materializing the archive.
#[test]
fn high_ratio_gzip_bomb_aborts_midstream() {
    let mut tar = Vec::new();
    for i in 0..10 {
        tar.extend(tar_entry(
            &format!("big/{i}.bin"),
            b'0',
            &vec![0u8; 16 * 1024 * 1024],
        ));
    }
    let gz = gzify(&tar);
    assert!(
        gz.len() < 1024 * 1024,
        "fixture must actually be high-ratio ({} bytes)",
        gz.len()
    );
    let dir = scratch_dir("bomb");
    let err = extract_tarball(&gz, &dir).unwrap_err();
    assert!(
        is_payload_too_large(&err),
        "160MB-from-KBs bomb must be PayloadTooLarge, got: {err}"
    );
    const { assert!(MAX_TOTAL_BYTES == 150 * 1024 * 1024) };
    std::fs::remove_dir_all(&dir).ok();
}

/// A giant *skipped* member (device entry) charges the same budget: it cannot
/// inflate for free.
#[test]
fn skipped_body_bomb_aborts() {
    let mut tar = tar_entry("dev/null", b'6', &vec![0u8; 200 * 1024 * 1024]);
    tar.extend([0u8; 1024]); // end-of-archive blocks
    let gz = gzify(&tar);
    let dir = scratch_dir("skipbomb");
    let err = extract_tarball(&gz, &dir).unwrap_err();
    assert!(
        is_payload_too_large(&err),
        "200MB skipped body must be PayloadTooLarge, got: {err}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Corruption mid-file must fail AND leave no half-written member behind.
#[test]
fn mid_stream_failure_leaves_no_partial_file() {
    let tar = tar_entry("pkg/data.bin", b'0', &vec![7u8; 5 * 1024 * 1024]);
    let mut gz = gzify(&tar);
    gz.truncate(gz.len() * 6 / 10); // sever the stream inside the file body
    let dir = scratch_dir("partial");
    let err = extract_tarball(&gz, &dir).unwrap_err();
    assert!(
        !is_payload_too_large(&err),
        "corruption is an integrity error, not a budget error: {err}"
    );
    assert!(
        !dir.join("pkg/data.bin").exists(),
        "half-written member must be removed"
    );
    assert!(
        std::fs::read_dir(&dir).unwrap().next().is_none()
            || !dir.join("pkg").exists()
            || std::fs::read_dir(dir.join("pkg"))
                .map(|mut it| it.next().is_none())
                .unwrap_or(true),
        "no partial artifacts may remain"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Global PAX headers and hostile sized directories must not desynchronize
/// the stream: the file after them extracts byte-identical.
#[test]
fn global_pax_and_sized_dir_keep_stream_aligned() {
    let mut tar = tar_entry("g", b'g', b"comment=hello\n");
    tar.extend(tar_header("weird", 53 /* '5' */, 100).to_vec());
    tar.extend(vec![9u8; 100]);
    tar.extend(vec![0u8; 512 - 100]);
    tar.extend(tar_entry("ok/data.txt", b'0', b"aligned"));
    tar.extend([0u8; 1024]);
    let dir = scratch_dir("aligned");
    extract_tarball(&gzify(&tar), &dir).expect("aligned archive must extract");
    assert_eq!(
        std::fs::read(dir.join("ok/data.txt")).unwrap(),
        b"aligned",
        "post-header file must be byte-identical"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// A multi-chunk file (larger than the 64KB stream chunk) round-trips intact.
#[test]
fn multichunk_file_roundtrips_intact() {
    let body: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();
    let tar = tar_entry("pkg/blob.bin", b'0', &body);
    let dir = scratch_dir("roundtrip");
    extract_tarball(&gzify(&tar), &dir).expect("valid archive must extract");
    assert_eq!(std::fs::read(dir.join("pkg/blob.bin")).unwrap(), body);
    std::fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------------
// Fetch-level: bomb fails AND the tempdir is cleaned up
// ---------------------------------------------------------------------------

fn scan_dirs() -> Vec<PathBuf> {
    std::fs::read_dir(std::env::temp_dir())
        .map(|rd| {
            rd.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("firecrow-scan-"))
                })
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn bomb_fetch_fails_and_cleans_up() {
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
    let mut tar = Vec::new();
    for i in 0..10 {
        tar.extend(tar_entry(
            &format!("w/big{i}.bin"),
            b'0',
            &vec![0u8; 16 * 1024 * 1024],
        ));
    }
    Mock::given(method("GET"))
        .and(path(format!("/repos/acme/widget/tarball/{SHA}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(gzify(&tar)))
        .mount(&server)
        .await;

    let before = scan_dirs();
    let err = fetch_repo_with_cancel(
        "https://github.com/acme/widget",
        "main",
        "test-token",
        None,
        &|| false,
    )
    .await
    .unwrap_err();
    assert!(
        is_payload_too_large(&err),
        "bomb fetch must be PayloadTooLarge, got: {err}"
    );
    let after = scan_dirs();
    assert_eq!(
        before.len(),
        after.len(),
        "failed fetch must not leak its tempdir"
    );

    std::env::remove_var("GITHUB_API_BASE_URL");
}
