//! F2 integration: the real `POST /auth/exchange` logging path must never
//! emit the one-time exchange code, at any layer of the middleware stack.
//!
//! The unit tests in `security_regressions.rs` prove the redaction function;
//! this file proves the audit-logger middleware actually routes the exchange
//! body through it, against the assembled application.

mod support;

use std::io;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use tracing_subscriber::layer::SubscriberExt;

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

struct AuditCapture {
    /// Held for its `Drop`: the guard must span the whole test body so the
    /// process-global subscriber stays serialized.
    _guard: MutexGuard<'static, ()>,
}

static CAPTURE_SERIAL: Mutex<()> = Mutex::new(());

impl AuditCapture {
    fn new() -> Self {
        let guard = CAPTURE_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        buffer().lock().expect("capture lock").clear();
        Self { _guard: guard }
    }
}

fn all_audit_lines() -> Vec<String> {
    buffer()
        .lock()
        .expect("capture lock")
        .iter()
        .cloned()
        .collect()
}

/// The synthetic credential is never a real one; it exists only to be
/// searched for in captured logs.
const SYNTHETIC_CODE: &str = "fc-synthetic-exchange-code-never-log-me";

#[sqlx::test(migrations = "./migrations")]
async fn security_f2_exchange_endpoint_never_emits_the_raw_code(pool: sqlx::PgPool) {
    let _audit = AuditCapture::new();
    let app = support::test_app(pool).await;

    // An unknown code produces the normal "invalid or expired" error path;
    // the redaction guarantee must hold regardless of the handler outcome.
    let res = app
        .post("/api/v1/auth/exchange")
        .json(&serde_json::json!({ "code": SYNTHETIC_CODE }))
        .await;
    assert!(
        res.status_code() == 400 || res.status_code() == 401,
        "an unknown exchange code must be rejected, got {}",
        res.status_code()
    );

    let lines = all_audit_lines();
    for line in &lines {
        assert!(
            !line.contains(SYNTHETIC_CODE),
            "the raw exchange code reached the audit log: {line}"
        );
    }

    // The request must actually have been logged *with* redaction — proving
    // redaction happened rather than the line being absent.
    assert!(
        lines
            .iter()
            .any(|l| l.contains("/auth/exchange") && l.contains("[REDACTED]")),
        "the exchange request must appear in the audit trail with its code redacted; got: {lines:?}"
    );
}
