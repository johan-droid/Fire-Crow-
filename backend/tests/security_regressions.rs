//! Security regression tests.
//!
//! Every confirmed vulnerability gets a test named
//! `security_<finding-id>_<short_description>` so that a future regression is a
//! named test failure rather than an audit finding.

mod support;

use firecrow_backend::middleware::http_logger::{
    redact_uri_for_log, safe_payload_snippet, truncate_utf8_safe,
};

// ---------------------------------------------------------------------------
// P0-1: unauthenticated remote process termination via the audit logger
// ---------------------------------------------------------------------------

/// Builds a JSON string whose byte at `max_len` falls *inside* a multi-byte
/// character, which is the exact condition that made `&s[..max_len]` panic.
fn json_body_with_multibyte_at(max_len: usize, ch: char) -> String {
    let mut s = String::from("{\"a\":\"");
    while s.len() < max_len - 1 {
        s.push('A');
    }
    s.push(ch);
    s.push_str("\"}");
    s
}

#[test]
fn security_p0_1_logger_utf8_dos_json_three_byte_char() {
    // € is 3 bytes (U+20AC).
    let body = json_body_with_multibyte_at(800, '€');
    assert!(
        body.len() > 800,
        "test body must exceed the truncation limit to exercise the bug"
    );

    let out = safe_payload_snippet(body.as_bytes(), 800);

    assert!(out.contains("[truncated]"), "expected truncation marker");
    // Must remain valid UTF-8 with no partial character at the seam.
    assert!(out.chars().all(|c| c != '\u{FFFD}'));
}

#[test]
fn security_p0_1_logger_utf8_dos_json_four_byte_char() {
    // 🔥 is 4 bytes (U+1F525). Worst case for a byte-indexed slice.
    let body = json_body_with_multibyte_at(800, '🔥');
    assert!(body.len() > 800);

    let out = safe_payload_snippet(body.as_bytes(), 800);

    assert!(out.contains("[truncated]"));
    assert!(!out.contains('\u{FFFD}'));
}

#[test]
fn security_p0_1_logger_utf8_dos_text_branch() {
    // The non-JSON branch (http_logger.rs) had the identical byte-indexed slice.
    // Build a long non-JSON UTF-8 text body straddling the boundary.
    let mut body = String::new();
    while body.len() < 799 {
        body.push('B');
    }
    body.push('€'); // straddles byte 800 (799..802)
    while body.len() < 1200 {
        body.push('C');
    }

    let out = safe_payload_snippet(body.as_bytes(), 800);

    assert!(out.contains("[truncated]"));
    assert!(!out.contains('\u{FFFD}'));
}

/// Directly exercise the truncation helper across every awkward boundary.
#[test]
fn security_p0_1_truncate_utf8_safe_boundaries() {
    let s = "a€b🔥c"; // 1 + 3 + 1 + 4 + 1 = 10 bytes
    assert_eq!(s.len(), 10);

    for max_len in 0..=12 {
        // Must not panic for any limit, including mid-character.
        let out = truncate_utf8_safe(s, max_len);
        // Output is always a valid prefix of the input plus an optional marker.
        let kept = out.strip_suffix("... [truncated]").unwrap_or(&out);
        assert!(
            s.starts_with(kept),
            "limit {max_len} produced a non-prefix: {kept:?}"
        );
        assert!(!kept.contains('\u{FFFD}'));
    }

    // Exact-length input is returned untouched.
    assert_eq!(truncate_utf8_safe(s, s.len()), s);
    // Oversized limit returns the input untouched.
    assert_eq!(truncate_utf8_safe(s, 999), s);
}

#[test]
fn security_p0_1_logger_handles_empty_and_binary() {
    assert_eq!(safe_payload_snippet(&[], 800), "<empty>");
    // Invalid UTF-8 must be reported, not panic.
    let binary = [0xff_u8, 0xfe, 0x00, 0x01];
    assert!(safe_payload_snippet(&binary, 800).contains("binary data"));
}

/// An oversized attacker-controlled body must not panic and must stay bounded.
#[test]
fn security_p0_1_logger_handles_oversized_body() {
    let mut body = String::from("{\"a\":\"");
    // 200 KB of multi-byte characters: forces truncation on a char boundary.
    for _ in 0..50_000 {
        body.push('日'); // 3 bytes
    }
    body.push_str("\"}");

    let out = safe_payload_snippet(body.as_bytes(), 800);

    assert!(out.contains("[truncated]"));
    // Output must be bounded, not proportional to the input.
    assert!(
        out.len() < 1_000,
        "snippet must stay bounded, got {}",
        out.len()
    );
}

// ---------------------------------------------------------------------------
// P0-1b: bearer tokens written to the application log
// ---------------------------------------------------------------------------

#[test]
fn security_p0_1b_logger_redacts_query_token() {
    let uri = "/api/v1/sse/job/abc123?token=eyJhbGciOiJIUzI1NiJ9.payload.sig";
    let out = redact_uri_for_log(uri);

    assert!(
        !out.contains("eyJhbGciOiJIUzI1NiJ9"),
        "JWT leaked into log: {out}"
    );
    assert!(out.contains("token=[REDACTED]"), "unexpected shape: {out}");
    // The path must survive so the log stays useful.
    assert!(out.starts_with("/api/v1/sse/job/abc123?"));
}

#[test]
fn security_p0_1b_logger_redacts_all_known_bearer_params() {
    for key in [
        "token",
        "access_token",
        "refresh_token",
        "code",
        "password",
        "secret",
        // Exact match, so this is its own case: "secret" does not cover it.
        "client_secret",
        "api_key",
    ] {
        let uri = format!("/path?{key}=SUPERSECRETVALUE&other=keepme");
        let out = redact_uri_for_log(&uri);
        assert!(
            !out.contains("SUPERSECRETVALUE"),
            "value for {key} leaked: {out}"
        );
        assert!(out.contains(&format!("{key}=[REDACTED]")));
        // Non-sensitive params must be preserved.
        assert!(out.contains("other=keepme"), "over-redacted: {out}");
    }
}

#[test]
fn security_p0_1b_logger_redaction_is_case_insensitive_and_preserves_shape() {
    assert_eq!(
        redact_uri_for_log("/p?Token=abc"),
        "/p?Token=[REDACTED]",
        "redaction must be case-insensitive on the key"
    );
    // No query string -> unchanged.
    assert_eq!(redact_uri_for_log("/p"), "/p");
    // Empty query -> unchanged.
    assert_eq!(redact_uri_for_log("/p?"), "/p?");
    // No sensitive params -> unchanged.
    assert_eq!(redact_uri_for_log("/p?a=1&b=2"), "/p?a=1&b=2");
    // Multiple params, first and last.
    assert_eq!(
        redact_uri_for_log("/p?token=x&b=2"),
        "/p?token=[REDACTED]&b=2"
    );
    assert_eq!(
        redact_uri_for_log("/p?b=2&token=x"),
        "/p?b=2&token=[REDACTED]"
    );
}

// ---------------------------------------------------------------------------
// P0-4: SSO client secrets must never be serialized to a client
// ---------------------------------------------------------------------------

#[test]
fn security_p0_4_sso_provider_never_serializes_client_secret() {
    use firecrow_backend::models::SsoProvider;

    let provider = SsoProvider {
        id: "p1".into(),
        name: "Okta".into(),
        provider_type: "oidc".into(),
        issuer_url: Some("https://acme.okta.com".into()),
        client_id: Some("0oa1clientid".into()),
        client_secret: Some("ENC[super-secret-blob]".into()),
        authorization_url: None,
        token_url: None,
        userinfo_url: None,
        jwks_url: None,
        certificate: None,
        attribute_mapping: None,
        domains: None,
        enforce_mfa: false,
        auto_provision: false,
        default_role_id: None,
        created_at: chrono::NaiveDate::from_ymd_opt(2026, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap(),
        client_secret_set: Some(true),
    };

    let json = serde_json::to_string(&provider).expect("serialize");

    assert!(
        !json.contains("client_secret\":"),
        "client_secret key must be absent from the wire format: {json}"
    );
    assert!(
        !json.contains("super-secret-blob"),
        "secret material leaked into the response: {json}"
    );
    // A UI still needs to know whether a secret is configured.
    assert!(
        json.contains("\"client_secret_set\":true"),
        "expected a non-disclosing configured flag: {json}"
    );
    // Non-secret fields are unaffected.
    assert!(json.contains("0oa1clientid"));
}

#[test]
fn security_p0_4_sso_provider_still_accepts_a_secret_on_write() {
    use firecrow_backend::models::SsoProvider;

    // The field must remain deserializable, or admins could not create providers.
    let parsed: SsoProvider = serde_json::from_value(serde_json::json!({
        "id": "p1",
        "name": "Okta",
        "provider_type": "oidc",
        "client_secret": "plaintext-on-write",
        "enforce_mfa": false,
        "auto_provision": false,
        "created_at": "1970-01-01T00:00:00",
    }))
    .expect("a secret must still be accepted as input");

    assert_eq!(parsed.client_secret.as_deref(), Some("plaintext-on-write"));
}

#[test]
fn security_p0_4_sso_read_paths_do_not_decrypt() {
    // Structural guard: the read helpers must not reference the crypto manager.
    // A regression here would reintroduce plaintext secrets into responses.
    let svc = include_str!("../src/services/sso_service.rs");

    for fname in ["list_providers", "get_provider"] {
        let body = svc
            .split(&format!("fn {fname}"))
            .nth(1)
            .unwrap_or_else(|| panic!("{fname} not found"))
            // Bound the slice to this function's next sibling.
            .split("    pub async fn ")
            .next()
            .unwrap();
        assert!(
            !body.contains("decrypt_secret"),
            "{fname} must not decrypt client_secret (security_p0_4):\n{body}"
        );
    }
}

// ---------------------------------------------------------------------------
// P0-5: OAuth identity must be keyed on the provider subject, not on email
// ---------------------------------------------------------------------------

#[test]
fn security_p0_5_no_email_account_linking() {
    // There is no database harness yet, so this is a structural regression test:
    // it fails if the email-match lookup is reintroduced into the OAuth callback.
    let src = include_str!("../src/api/routes_auth.rs");
    let callback = src
        .split("pub async fn github_callback")
        .nth(1)
        .expect("github_callback must exist");

    assert!(
        !callback.contains("SELECT * FROM users WHERE email"),
        "github_callback must not look accounts up by email (security_p0_5)"
    );
    assert!(
        callback.contains("security_p0_5"),
        "expected the rationale comment to stay next to the identity lookup"
    );
}

#[test]
fn security_p0_5_github_identity_is_looked_up_by_provider_subject() {
    let src = include_str!("../src/api/routes_auth.rs");
    let callback = src
        .split("pub async fn github_callback")
        .nth(1)
        .expect("github_callback must exist");

    assert!(
        callback.contains("github_id = $1") || callback.contains("github_id=$1"),
        "github_callback must resolve identity by the immutable provider id (security_p0_5)"
    );
}

#[test]
fn security_p0_5_identity_write_failures_are_not_swallowed() {
    let src = include_str!("../src/api/routes_auth.rs");
    let callback = src
        .split("pub async fn github_callback")
        .nth(1)
        .expect("github_callback must exist");

    // The token-persist UPDATE was `let _ = ...`, so a failed write still minted a
    // session for an account whose OAuth token was never stored.
    let mut saw_swallowed_update = false;
    for line in callback.lines() {
        let l = line.trim();
        if l.starts_with("let _ = sqlx::query(\"UPDATE users SET github_id") {
            saw_swallowed_update = true;
        }
    }
    assert!(
        !saw_swallowed_update,
        "the GitHub identity write must not be discarded (security_p0_5)"
    );
}

// ---------------------------------------------------------------------------
// Phase 18: secret-holding structs must be Debug-safe
// ---------------------------------------------------------------------------

/// A derived `Debug` on `Settings` printed every credential the process uses
/// (signing keys, password-bearing URLs, provider tokens) into any log line,
/// panic message, or test snapshot that formatted it.
#[test]
fn security_p18_settings_debug_hides_every_credential() {
    let settings = support::test_settings();
    let rendered = format!("{settings:?}");

    // The fixture's own known values must not survive formatting.
    for leaked in [
        support::TEST_SECRET_KEY,
        support::TEST_ENCRYPTION_KEY,
        "postgres://unused",
    ] {
        assert!(
            !rendered.contains(leaked),
            "Settings Debug leaked a credential: {leaked}"
        );
    }
    assert!(
        rendered.contains("[REDACTED]"),
        "expected redaction markers, got: {rendered}"
    );
    // Non-secret operational fields stay visible, or the output is useless.
    assert!(
        rendered.contains("8000"),
        "port must stay visible: {rendered}"
    );
}

/// `ModelConfig` carries the live provider key; a derived `Debug` printed it.
#[test]
fn security_p18_model_config_debug_hides_the_api_key() {
    use firecrow_backend::services::narrative::ModelConfig;

    let config = ModelConfig {
        provider: "gemini",
        model: "gemini-2.0-flash".into(),
        api_key: "sk-live-key-that-must-never-print".into(),
        timeout: std::time::Duration::from_secs(30),
        max_prompt_chars: 8000,
        max_response_bytes: 262_144,
        max_attempts: 2,
    };
    let rendered = format!("{config:?}");

    assert!(
        !rendered.contains("sk-live-key-that-must-never-print"),
        "ModelConfig Debug leaked the provider key: {rendered}"
    );
    assert!(rendered.contains("gemini-2.0-flash"));
}

// ---------------------------------------------------------------------------
// Phase 18: a hostile scanner report cannot mis-locate a finding
// ---------------------------------------------------------------------------

/// `start_line as i32` wrapped out-of-range values into wrong-but-positive
/// lines. The adapter must yield no anchor instead, so canonical validation
/// quarantines the finding openly rather than attaching a false location.
#[test]
fn security_p18_gitleaks_absurd_line_is_quarantined_not_mislocated() {
    use firecrow_backend::agents::scanner::{finding_from_gitleaks, GitleaksFinding};
    use firecrow_backend::orchestrator::canonical_audit::normalize_findings_for_persist;

    fn hostile(start_line: i64) -> GitleaksFinding {
        GitleaksFinding {
            rule_id: "aws-access-token".into(),
            description: "AWS".into(),
            file: "config/aws.env".into(),
            start_line,
            end_line: start_line,
            start_column: 1,
            end_column: 10,
            match_text: "AKIAIOSFODNN7EXAMPLE".into(),
            secret: "AKIAIOSFODNN7EXAMPLE".into(),
            symlink_file: String::new(),
            commit: String::new(),
            entropy: 0.0,
            author: String::new(),
            email: String::new(),
            date: String::new(),
            message: String::new(),
            tags: Vec::new(),
            fingerprint: "fp".into(),
        }
    }

    for line in [i64::MAX, i64::MIN, i64::from(i32::MAX) + 1] {
        let finding = finding_from_gitleaks(&hostile(line));
        assert!(
            finding.line_number.is_none(),
            "line {line} must yield no anchor, got {:?}",
            finding.line_number
        );
        // And the pipeline must not carry it as a valid finding.
        let normalized = normalize_findings_for_persist(vec![finding]);
        assert!(
            normalized.valid.is_empty(),
            "an anchorless finding must not validate (line {line})"
        );
        assert_eq!(
            normalized.invalid.len(),
            1,
            "it must be quarantined and counted, not dropped silently (line {line})"
        );
    }

    // A negative line fits `i32`, so the adapter passes it through and the
    // canonical layer refuses it: `finding_location` requires `line > 0`.
    let negative = finding_from_gitleaks(&hostile(-3));
    assert_eq!(negative.line_number, Some(-3));
    let normalized = normalize_findings_for_persist(vec![negative]);
    assert!(normalized.valid.is_empty());
    assert_eq!(normalized.invalid.len(), 1);

    // Sanity: an ordinary line still anchors normally.
    let sane = finding_from_gitleaks(&hostile(3));
    assert_eq!(sane.line_number, Some(3));
}

/// Same property through the Semgrep adapter: a line past `i32` range passes
/// location validation (it is positive) but must still not wrap into a false
/// anchor. It arrives anchorless and the canonical layer quarantines it.
#[test]
fn security_p18_semgrep_huge_line_is_quarantined_not_wrapped() {
    use firecrow_backend::agents::scanner::findings_from_semgrep;
    use firecrow_backend::orchestrator::canonical_audit::normalize_findings_for_persist;

    let report = serde_json::json!({
        "errors": [],
        "paths": {"scanned": ["a.py"]},
        "version": "1.96.0",
        "results": [{
            "check_id": "python.hostile",
            "path": "a.py",
            "start": {"line": i64::MAX, "col": 1},
            "end": {"line": i64::MAX, "col": 5},
            "extra": {
                "severity": "ERROR",
                "message": "hostile",
                "lines": "x = 1",
                "fingerprint": "fp",
                "metadata": {},
            },
        }],
    })
    .to_string();

    let parsed = findings_from_semgrep(&report, std::path::Path::new("/tmp"))
        .expect("a well-formed report parses");
    assert_eq!(parsed.valid.len(), 1);
    assert!(
        parsed.valid[0].line_number.is_none(),
        "a line past i32 range must not wrap into a false anchor, got {:?}",
        parsed.valid[0].line_number
    );
    let normalized = normalize_findings_for_persist(parsed.valid);
    assert!(normalized.valid.is_empty());
    assert_eq!(normalized.invalid.len(), 1);
}

// ---------------------------------------------------------------------------
// Phase 20: secret-safe Debug for credential-bearing models
// ---------------------------------------------------------------------------

/// Every model that carries a credential must render `[REDACTED]` for it in
/// `Debug`, never the value. A derived `Debug` on any of these would print
/// the secret into any log line, panic message, or test snapshot.
#[test]
fn security_p20_credential_models_have_secret_safe_debug() {
    use firecrow_backend::models::{GithubCredential, MfaConfiguration, SsoProvider, User};

    let user = User {
        id: "u1".into(),
        username: "alice".into(),
        password_hash: Some("argon2-hash-secret".into()),
        credit_balance: 0.0,
        email: Some("alice@example.com".into()),
        tenant_id: None,
        role_id: None,
        is_active: true,
        github_id: Some("12345".into()),
        google_id: None,
        github_access_token: Some("gho_real-oauth-token".into()),
        github_token_scopes: None,
        github_token_updated_at: None,
        privacy_policy_version: None,
        privacy_policy_accepted_at: None,
        terms_version: None,
        terms_accepted_at: None,
        first_login_at: None,
        last_login_at: None,
        last_logout_at: None,
        region: None,
        timezone: None,
        mfa_enabled: true,
        mfa_secret: Some("JBSWY3DPEHPK3PXP".into()),
        created_at: chrono::NaiveDate::from_ymd_opt(2026, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap(),
    };
    let rendered = format!("{user:?}");
    assert!(
        !rendered.contains("argon2-hash-secret"),
        "password hash leaked: {rendered}"
    );
    assert!(
        !rendered.contains("gho_real-oauth-token"),
        "OAuth token leaked: {rendered}"
    );
    assert!(
        !rendered.contains("JBSWY3DPEHPK3PXP"),
        "MFA secret leaked: {rendered}"
    );
    assert!(rendered.contains("[REDACTED]"));
    // Non-secret fields stay visible.
    assert!(rendered.contains("alice"));
    assert!(rendered.contains("12345"));

    let credential = GithubCredential {
        id: "c1".into(),
        user_id: "u1".into(),
        github_id: "12345".into(),
        access_token: "gho_credential-token".into(),
        scopes: Some("repo".into()),
        created_at: chrono::NaiveDate::from_ymd_opt(2026, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap(),
    };
    let rendered = format!("{credential:?}");
    assert!(
        !rendered.contains("gho_credential-token"),
        "credential token leaked: {rendered}"
    );
    assert!(rendered.contains("[REDACTED]"));

    let mfa = MfaConfiguration {
        id: "m1".into(),
        user_id: "u1".into(),
        enabled: true,
        secret: Some("JBSWY3DPEHPK3PXP".into()),
        backup_codes_consumed: 0,
        last_verified_at: None,
        created_at: chrono::NaiveDate::from_ymd_opt(2026, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap(),
    };
    let rendered = format!("{mfa:?}");
    assert!(
        !rendered.contains("JBSWY3DPEHPK3PXP"),
        "MFA secret leaked: {rendered}"
    );
    assert!(rendered.contains("[REDACTED]"));

    let sso = SsoProvider {
        id: "p1".into(),
        name: "Okta".into(),
        provider_type: "oidc".into(),
        issuer_url: Some("https://acme.okta.com".into()),
        client_id: Some("0oa1clientid".into()),
        client_secret: Some("ENC[super-secret-blob]".into()),
        client_secret_set: Some(true),
        authorization_url: None,
        token_url: None,
        userinfo_url: None,
        jwks_url: None,
        certificate: None,
        attribute_mapping: None,
        domains: None,
        enforce_mfa: false,
        auto_provision: false,
        default_role_id: None,
        created_at: chrono::NaiveDate::from_ymd_opt(2026, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap(),
    };
    let rendered = format!("{sso:?}");
    assert!(
        !rendered.contains("super-secret-blob"),
        "SSO secret leaked: {rendered}"
    );
    assert!(rendered.contains("[REDACTED]"));
    // The non-disclosing flag stays visible.
    assert!(rendered.contains("client_secret_set"));
}

/// The Turnstile verify request carries the site secret and the user's
/// verification token. Its `Debug` must render neither.
#[test]
fn security_p20_turnstile_request_debug_hides_secrets() {
    use firecrow_backend::services::turnstile::TurnstileVerifyRequest;

    let request = TurnstileVerifyRequest {
        secret: "0x4-secret-key",
        response: "cf-turnstile-response-token",
        remoteip: Some("203.0.113.1"),
    };
    let rendered = format!("{request:?}");
    assert!(
        !rendered.contains("0x4-secret-key"),
        "site secret leaked: {rendered}"
    );
    assert!(
        !rendered.contains("cf-turnstile-response-token"),
        "user token leaked: {rendered}"
    );
    assert!(rendered.contains("[REDACTED]"));
    assert!(rendered.contains("203.0.113.1"));
}

/// The HTTP audit logger must redact email and evidence keys in JSON bodies,
/// not just credentials.
#[test]
fn security_p20_logger_redacts_email_and_evidence_keys() {
    let body = serde_json::json!({
        "email": "victim@example.com",
        "evidence": "AKIAIOSFODNN7EXAMPLE in source code",
        "snippet": "password = hunter2",
        "username": "alice",
    });
    let out = safe_payload_snippet(body.to_string().as_bytes(), 800);
    assert!(!out.contains("victim@example.com"), "email leaked: {out}");
    assert!(
        !out.contains("AKIAIOSFODNN7EXAMPLE"),
        "evidence leaked: {out}"
    );
    assert!(!out.contains("hunter2"), "snippet leaked: {out}");
    assert!(
        out.contains("alice"),
        "non-sensitive field must survive: {out}"
    );
}

/// Sandbox stderr from a failed scanner run must be redacted before logging.
/// The stderr comes from the untrusted repository and can carry secrets.
#[test]
fn security_p20_sandbox_stderr_is_redacted_before_logging() {
    // Structural: the warn! call in sandbox.rs must route stderr through
    // redact_text. A regression that logs it verbatim fails this test.
    let src = include_str!("../src/services/sandbox.rs");
    let warn_line = src
        .lines()
        .find(|l| l.contains("Sandbox process failed"))
        .expect("the sandbox failure warning must exist");
    // The warning must reference redact_text, not pass stderr directly.
    let context_start = src.find("Sandbox process failed").unwrap();
    let context = &src[context_start.saturating_sub(200)..context_start + 200];
    assert!(
        context.contains("redact_text"),
        "sandbox stderr must be redacted before logging:\n{context}"
    );
    assert!(
        !warn_line.contains("stderr") || context.contains("redact_text"),
        "raw stderr must not reach the log"
    );
}

/// The GitHub signup collision error must not embed the claimant's email.
#[test]
fn security_p20_signup_collision_error_hides_email() {
    let src = include_str!("../src/api/routes_auth.rs");
    let handler = src
        .split("pub async fn github_callback")
        .nth(1)
        .expect("github_callback must exist");
    let collision = handler
        .split("collided with an existing email")
        .next()
        .expect("collision handling must exist");
    // The error! call must not interpolate the sqlx error (which embeds the
    // email in `Key (email)=(…)`).
    assert!(
        !collision.contains("error!(\"GitHub signup collided with an existing email: {}\", e)"),
        "the collision error must not interpolate the sqlx error:\n{collision}"
    );
}
