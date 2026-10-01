//! Phase 9: rate-limited requests must leave an audit trail.
//!
//! In axum the last `.layer()` is the outermost. `http_audit_logger` was applied
//! inside the global `GovernorLayer`, so the governor rejected a request with 429
//! *before* the audit logger ran. A rejected request therefore produced no audit
//! record at all: the audit trail showed a gap exactly where an operator most
//! needs evidence, and a burst of blocked traffic was invisible.
//!
//! The audit trail for HTTP is the structured log emitted on the `http_audit`
//! tracing target. These tests capture that target and assert that a 429 is
//! recorded, that a normal request still produces exactly one record, and that a
//! burst does not log once per rejection from any other code path.

mod support;

use std::io;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use tracing_subscriber::layer::SubscriberExt;

/// Serialises the audit-observing tests.
///
/// The subscriber is process-global and the requests are indistinguishable, so a
/// test running in parallel would observe another test's lines. These tests hold
/// this lock for their whole body.
static AUDIT_SERIAL: Mutex<()> = Mutex::new(());

static CAPTURE: OnceLock<Arc<Mutex<Vec<String>>>> = OnceLock::new();

fn buffer() -> Arc<Mutex<Vec<String>>> {
    CAPTURE
        .get_or_init(|| {
            let buf: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let sink = buf.clone();
            let layer = tracing_subscriber::fmt::layer()
                .json()
                .with_writer(move || Writer(sink.clone()));
            let _ =
                tracing::subscriber::set_global_default(tracing_subscriber::registry().with(layer));
            buf
        })
        .clone()
}

#[derive(Clone)]
struct Writer(Arc<Mutex<Vec<String>>>);

impl io::Write for Writer {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("capture lock")
            .push(String::from_utf8_lossy(b).into_owned());
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Writer {
    type Writer = Writer;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Installs the capture subscriber, empties the buffer, and blocks other
/// audit-observing tests for as long as it is held.
struct AuditCapture {
    /// Held purely for its `Drop`: the lock must span the whole test body.
    _guard: MutexGuard<'static, ()>,
}

impl AuditCapture {
    fn new() -> Self {
        // Poisoning is irrelevant here: the lock only serialises tests.
        let guard = AUDIT_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        buffer().lock().expect("capture lock").clear();
        Self { _guard: guard }
    }
}

/// Every captured audit line mentioning `needle`.
fn audit_lines_containing(needle: &str) -> Vec<String> {
    buffer()
        .lock()
        .expect("capture lock")
        .iter()
        .filter(|l| l.contains(needle))
        .cloned()
        .collect()
}

/// The absolute form the audit logger records for a test request.
fn full(uri: &str) -> String {
    format!("http://localhost{uri}")
}

/// Number of audit records showing `uri` was rejected with 429.
///
/// The status must be matched as `-> 429`, not as a bare `429`: the JSON log line
/// contains a timestamp, and a microsecond field can legitimately read `429xxx`.
fn rejected_records_for(uri: &str) -> usize {
    let needle = format!("{} -> 429", full(uri));
    audit_lines_containing(&needle).len()
}

/// Number of audit `[HTTP RES]` records for `uri`.
fn res_records_for(uri: &str) -> usize {
    let u = full(uri);
    audit_lines_containing("[HTTP RES]")
        .iter()
        .filter(|l| l.contains(&u))
        .count()
}

/// Every audit line, so a test can prove nothing else logged the same request.
fn all_audit_lines() -> Vec<String> {
    buffer().lock().expect("capture lock").clone()
}

/// Drive `n` rapid requests and return how many were rate limited.
///
/// The global limiter is 20/s with a burst of 40, keyed on the synthetic peer
/// address, so all requests from one test share a bucket.
async fn burst(app: &axum_test::TestServer, uri: &str, n: usize) -> usize {
    let mut limited = 0;
    for _ in 0..n {
        if app.get(uri).await.status_code() == 429 {
            limited += 1;
        }
    }
    limited
}

// ---------------------------------------------------------------------------
// The gap
// ---------------------------------------------------------------------------

/// A rate-limited request must appear in the audit trail.
#[sqlx::test(migrations = "./migrations")]
async fn rate_limited_request_is_recorded_in_the_audit_trail(pool: sqlx::PgPool) {
    let _audit = AuditCapture::new();
    let app = support::test_app_rate_limited(pool).await;

    let limited = burst(&app, "/health", 90).await;
    assert!(limited > 0, "the burst must actually trigger a 429");

    let recorded = rejected_records_for("/health");
    assert!(
        recorded > 0,
        "phase_9: {limited} request(s) were rejected with 429 but none were \
         recorded on the http_audit target; a burst of blocked traffic is invisible"
    );
}

/// Normal requests must keep exactly one audit record each — the fix must not
/// introduce a second logging path.
#[sqlx::test(migrations = "./migrations")]
async fn normal_request_still_produces_exactly_one_audit_record(pool: sqlx::PgPool) {
    let _audit = AuditCapture::new();
    let app = support::test_app_rate_limited(pool).await;

    assert_eq!(app.get("/health").await.status_code(), 200);

    assert_eq!(
        res_records_for("/health"),
        1,
        "one request must yield one [HTTP RES] record, got: {:?}",
        audit_lines_containing("[HTTP RES]")
    );
}

/// A burst must be logged, but not duplicated by a second logger.
#[sqlx::test(migrations = "./migrations")]
async fn repeated_rejections_are_logged_once_each_without_duplication(pool: sqlx::PgPool) {
    let _audit = AuditCapture::new();
    let app = support::test_app_rate_limited(pool).await;

    let limited = burst(&app, "/health", 90).await;
    assert!(limited > 0, "the burst must actually trigger a 429");

    let rejected = rejected_records_for("/health");
    let records = res_records_for("/health");
    let total_res = all_audit_lines()
        .iter()
        .filter(|l| l.contains("[HTTP RES]"))
        .count();

    assert_eq!(
        rejected, limited,
        "each of the {limited} rejections must be recorded exactly once"
    );
    assert_eq!(
        records, total_res,
        "a request must not be logged by a second code path: {records} for /health vs \
         {total_res} in total"
    );
}

/// An unauthenticated request must be audited the same way, so the audit trail
/// cannot be bypassed by simply omitting credentials.
#[sqlx::test(migrations = "./migrations")]
async fn unauthenticated_rejection_is_also_recorded(pool: sqlx::PgPool) {
    let _audit = AuditCapture::new();
    let app = support::test_app_rate_limited(pool).await;

    // No Authorization header: this is rejected for rate limiting before any
    // authentication or authorization runs.
    let limited = burst(&app, "/api/v1/system/database/stats", 90).await;
    assert!(limited > 0, "the burst must actually trigger a 429");

    let uri = "/api/v1/system/database/stats";
    assert_eq!(
        rejected_records_for(uri),
        limited,
        "an unauthenticated rate-limited request must be recorded"
    );
}

/// Disabling rate limiting must not leave the audit logger broken.
#[sqlx::test(migrations = "./migrations")]
async fn auditing_still_works_when_rate_limiting_is_disabled(pool: sqlx::PgPool) {
    let _audit = AuditCapture::new();
    let app = support::test_app(pool).await;

    assert_eq!(app.get("/health").await.status_code(), 200);
    assert_eq!(res_records_for("/health"), 1);
}
