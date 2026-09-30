//! Security regression tests.
//!
//! Every confirmed vulnerability gets a test named
//! `security_<finding-id>_<short_description>` so that a future regression is a
//! named test failure rather than an audit finding.

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
