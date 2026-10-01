//! Phase 7: SECRET_KEY configuration diagnostics.
//!
//! Environment isolation matters here, so every test spawns the **real binary**
//! with a purpose-built environment. Nothing mutates this process's environment,
//! which would race the `#[sqlx::test]` tests sharing the same binary because
//! sqlx resolves `DATABASE_URL` at run time.

use std::process::Command;

const BINARY: &str = env!("CARGO_BIN_EXE_firecrow-backend");

/// A deliberately recognisable fake secret, so a leak is unmissable.
const CANARY: &str = "CANARY_a1b2c3d4e5f6_DO_NOT_LEAK_9z8y7x";

const VALID_ENC: &str = "test-only-encryption-key-not-valid-in-prod-0000";

type Env = Vec<(String, String)>;

struct Run {
    code: i32,
    output: String,
}

impl Run {
    fn served(&self) -> bool {
        self.output.contains("Server listening")
    }
    /// The configuration message an operator would see, without the tracing
    /// timestamp/level prefix, so two runs compare equal.
    fn error(&self) -> String {
        let line = self
            .output
            .lines()
            .find(|l| l.contains("Configuration error") || l.trim_start().starts_with("Error:"))
            .unwrap_or_default();
        line.rsplit("Configuration error: ")
            .next()
            .unwrap_or(line)
            .trim()
            .to_string()
    }
}

/// Run the backend with an explicit, minimal environment.
fn run(env: &Env) -> Run {
    let mut cmd = Command::new(BINARY);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("backend binary must be runnable");
    let mut output = String::from_utf8_lossy(&out.stdout).to_string();
    output.push_str(&String::from_utf8_lossy(&out.stderr));
    Run {
        code: out.status.code().unwrap_or(-1),
        output,
    }
}

/// A minimal environment with everything except SECRET_KEY, which the caller
/// supplies, so each test perturbs exactly one thing.
///
/// No DATABASE_URL is set on purpose: a valid configuration must be *accepted*,
/// and the run then fails at the database gate, which is unambiguously a
/// different, later failure.
fn env_with_secret(secret: Option<&str>) -> Env {
    let mut v: Env = vec![
        ("FRONTEND_URL".into(), "https://app.firecrow.test".into()),
        ("CORS_ORIGINS".into(), "https://app.firecrow.test".into()),
        // Present purely so deserialisation succeeds and SECRET_KEY validation is
        // actually reached; never connected to. `database_url` is one of three
        // required fields that still fail with serde's opaque error, which would
        // otherwise mask the behaviour under test.
        (
            "DATABASE_URL".into(),
            "postgres://u:p@127.0.0.1:1/db".into(),
        ),
        ("ENCRYPTION_KEY".into(), VALID_ENC.into()),
        ("PORT".into(), "0".into()),
    ];
    if let Some(s) = secret {
        v.push(("SECRET_KEY".into(), s.into()));
    }
    v
}

// ---------------------------------------------------------------------------
// The defect: an absent SECRET_KEY produced serde's internal error
// ---------------------------------------------------------------------------

#[test]
fn secret_key_absent_reports_the_environment_variable() {
    let r = run(&env_with_secret(None));

    assert_ne!(
        r.code, 0,
        "a missing SECRET_KEY must abort startup:\n{}",
        r.output
    );
    assert!(!r.served(), "nothing may be served:\n{}", r.output);

    let err = r.error();
    assert!(
        err.contains("SECRET_KEY"),
        "the error must name SECRET_KEY: {err:?}"
    );
    assert!(
        !err.contains("missing field"),
        "serde's internal error must not be the user-facing message: {err:?}"
    );
    assert!(
        !err.contains("secret_key"),
        "the Rust field name must not be surfaced: {err:?}"
    );
    assert!(
        err.contains("openssl rand -base64 48"),
        "the error must say how to fix it: {err:?}"
    );
}

/// Absent and empty are the same operator mistake, so they must produce the same
/// guidance rather than two different messages.
#[test]
fn secret_key_absent_and_empty_report_identically() {
    let absent = run(&env_with_secret(None));
    let empty = run(&env_with_secret(Some("")));

    assert_ne!(absent.code, 0);
    assert_ne!(empty.code, 0);
    assert_eq!(
        absent.error(),
        empty.error(),
        "an absent and an empty SECRET_KEY must give identical guidance"
    );
}

#[test]
fn secret_key_too_short_reports_the_requirement() {
    let r = run(&env_with_secret(Some("tooshort")));

    assert_ne!(r.code, 0);
    assert!(!r.served());
    let err = r.error();
    assert!(err.contains("SECRET_KEY"), "{err:?}");
    assert!(
        err.contains("32 characters"),
        "the length rule must be stated: {err:?}"
    );
}

/// Publicly known values must be refused as compromised, and the value must not
/// be echoed back.
#[test]
fn secret_key_known_bad_value_is_reported_as_compromised() {
    for bad in [
        "local_dev_secret_key_change_me_1234567890_DO_NOT_USE_IN_PRODUCTION",
        "secret",
        "change_me",
        "a7f3b8c29e4d5f6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a",
    ] {
        let r = run(&env_with_secret(Some(bad)));

        assert_ne!(r.code, 0, "{bad} must be refused");
        assert!(!r.served());
        let err = r.error();
        assert!(err.contains("SECRET_KEY"), "{bad}: {err:?}");
        assert!(
            err.to_lowercase().contains("compromised"),
            "{bad} must be reported as compromised: {err:?}"
        );
        assert!(
            !err.contains(bad),
            "the rejected value must not be echoed: {err:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Non-disclosure
// ---------------------------------------------------------------------------

/// A rejected secret's value must never appear anywhere in the output.
///
/// The canary is long enough to pass the length check, so rejection comes from the
/// identical-keys rule rather than the length rule - a different code path.
#[test]
fn secret_key_value_never_appears_in_diagnostics() {
    // Make the two keys identical so a valid-length value is rejected.
    let mut e = env_with_secret(Some(CANARY));
    e.retain(|(k, _)| k != "ENCRYPTION_KEY");
    e.push(("ENCRYPTION_KEY".into(), CANARY.into()));
    let r = run(&e);

    assert_ne!(r.code, 0);
    assert!(r.error().contains("must be different"), "{}", r.error());
    assert!(
        !r.output.contains(CANARY),
        "the secret value leaked into startup output:\n{}",
        r.output
    );
}

#[test]
fn secret_key_missing_error_contains_no_environment_dump() {
    let r = run(&env_with_secret(None));

    assert_ne!(r.code, 0);
    for leak in [
        "FRONTEND_URL=",
        "CORS_ORIGINS=",
        "PATH=",
        "HOME=",
        "ENCRYPTION_KEY=",
    ] {
        assert!(
            !r.output.contains(leak),
            "startup output leaked environment state via {leak:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Compatibility: a valid secret must behave exactly as before
// ---------------------------------------------------------------------------

/// Values containing characters that would break naive parsing must be accepted.
#[test]
fn secret_key_with_special_characters_is_accepted() {
    for value in [
        "has spaces and #hashes and \"quotes\" and 'apostrophes'",
        "p@ssw0rd/with+special=chars?and=query&more",
        "unicode-\u{20ac}-\u{1F525}-value-that-is-long-enough-1234",
    ] {
        let r = run(&env_with_secret(Some(value)));
        assert!(
            !r.error().contains("SECRET_KEY"),
            "a valid SECRET_KEY with special characters must be accepted, got: {}",
            r.error()
        );
    }
}

/// The length boundary is unchanged: 32 accepted, 31 refused.
#[test]
fn secret_key_length_boundary_is_unchanged() {
    let r_ok = run(&env_with_secret(Some(&"a".repeat(32))));
    assert!(
        !r_ok.error().contains("32 characters"),
        "a 32-character SECRET_KEY must be accepted, got: {}",
        r_ok.error()
    );

    let r_short = run(&env_with_secret(Some(&"a".repeat(31))));
    assert!(
        r_short.error().contains("32 characters"),
        "a 31-character SECRET_KEY must be refused, got: {}",
        r_short.error()
    );
}

// ---------------------------------------------------------------------------
// Structural guards
// ---------------------------------------------------------------------------

/// SECRET_KEY must keep the `#[serde(default)]` that routes an absent value
/// through `validate()`. Removing it silently restores serde's opaque error.
#[test]
fn secret_key_keeps_its_serde_default() {
    let src = include_str!("../src/config.rs");
    let at = src
        .find("pub secret_key: String")
        .expect("field must exist");
    // Window from the previous field declaration up to this one, so an attribute
    // belonging to a neighbouring field is not mis-attributed.
    let from = src[..at].rfind("pub ").unwrap_or(0);
    let window = &src[from..at];
    assert!(
        window.contains("#[serde(default)]"),
        "secret_key must carry #[serde(default)] so an absent value is reported by \
         validate() rather than by serde:\n{window}"
    );
}

/// Records the sibling defect. Phase 7 is scoped to SECRET_KEY, so these three
/// required variables still fail with serde's opaque `missing field` error. The
/// test fails loudly if the set changes, so nothing is fixed or added silently.
#[test]
fn other_required_variables_with_the_same_defect_are_recorded() {
    const KNOWN_OPAQUE_REQUIRED: &[&str] = &["frontend_url", "cors_origins", "database_url"];

    let src = include_str!("../src/config.rs");
    let mut opaque: Vec<&str> = Vec::new();
    for field in ["frontend_url", "cors_origins", "database_url", "secret_key"] {
        let at = src
            .find(&format!("pub {field}:"))
            .expect("field must exist");
        let from = src[..at].rfind("pub ").unwrap_or(0);
        if !src[from..at].contains("serde(default") {
            opaque.push(field);
        }
    }

    assert_eq!(
        opaque, KNOWN_OPAQUE_REQUIRED,
        "the set of required fields that fail with serde's opaque `missing field` \
         error changed. If one was fixed, drop it from KNOWN_OPAQUE_REQUIRED; if one \
         was added, fix it or record why not."
    );
}
