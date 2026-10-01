//! Vulnerability analysis engine.
//!
//! An engine reads a target repository and produces findings **derived from that
//! repository's contents**. This build ships one: a gitleaks-based secret scanner
//! ([`scanner`]), fed by a bounded repository fetch ([`fetch`]).
//!
//! This build previously returned three hardcoded `Finding` values naming
//! `src/config.rs:42`, `src/db/queries.rs:118` and `src/middleware/cors.rs:15`
//! with CVSS 9.8 / 8.5 / 5.3, for every user, on every repository, without
//! opening a single file. Those fabrications were deleted. Every finding the
//! current engine emits carries a file, a line, and an evidence snippet taken
//! from the scanner's own output.
//!
//! The score is `NULL` whenever no analysis ran or a scanner failed. A score of
//! "10/10, low risk" computed from zero findings would be the single most
//! misleading output this product could produce, so an unavailable or failed
//! engine yields a **null** score rather than a perfect one.

pub mod fetch;
pub mod scanner;

/// Whether a real vulnerability analysis engine is compiled into this build.
///
/// True: the fetch + gitleaks scan pipeline exists and produces evidence-backed
/// findings. This remains a compiled-in constant rather than a runtime flag so a
/// deployment cannot advertise a capability it does not contain.
pub const ENGINE_AVAILABLE: bool = true;

/// Machine-readable reason surfaced on the job when [`ENGINE_AVAILABLE`] is false.
pub const ENGINE_UNAVAILABLE_REASON: &str =
    "No vulnerability analysis engine is installed in this build. The repository was not \
     fetched, read, or analyzed, and no findings were produced.";

/// Short label for UI and log lines.
pub const ENGINE_NAME: &str = "gitleaks";

