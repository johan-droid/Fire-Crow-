//! Vulnerability analysis engine.
//!
//! # This build has no engine.
//!
//! An engine is a component that reads a target repository and produces findings
//! **derived from that repository's contents**. Nothing in this crate does that.
//!
//! This build previously returned three hardcoded `Finding` values naming
//! `src/config.rs:42`, `src/db/queries.rs:118` and `src/middleware/cors.rs:15`
//! with CVSS 9.8 / 8.5 / 5.3, for every user, on every repository, without
//! opening a single file. `run_recon` returned a fixed five-entry tech stack and
//! `run_ai_analyzer` copied its input to its own output after a 400 ms sleep.
//! Those fabrications have been deleted rather than disabled.
//!
//! Because no engine exists, a scan cannot claim any result. It terminates as
//! [`crate::models::JobStatus::EngineUnavailable`] with no findings and no
//! security score. A score of "10/10, low risk" computed from zero findings
//! would be the single most misleading output this product could produce, so an
//! unavailable engine yields a **null** score rather than a perfect one.
//!
//! Implementing a real engine is a separate programme. It must supply evidence
//! for every finding, and its repository acquisition needs its own threat model
//! (SSRF, path traversal, command injection, resource exhaustion). When that
//! exists, set [`ENGINE_AVAILABLE`] to `true` and the orchestrator will run it.

/// Whether a real vulnerability analysis engine is compiled into this build.
///
/// This is the single source of truth for whether FireCrow may report scan
/// results. It is deliberately a constant rather than a feature flag or an
/// environment variable, so it cannot be enabled by configuration alone in a
/// deployment that has no engine present.
pub const ENGINE_AVAILABLE: bool = false;

/// Machine-readable reason surfaced on the job when [`ENGINE_AVAILABLE`] is false.
///
/// Carries no stack trace, filesystem path, or credential. It states exactly what
/// did and did not happen.
pub const ENGINE_UNAVAILABLE_REASON: &str =
    "No vulnerability analysis engine is installed in this build. The repository was not \
     fetched, read, or analyzed, and no findings were produced.";

/// Short label for UI and log lines.
pub const ENGINE_NAME: &str = "none";
