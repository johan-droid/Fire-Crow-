const CREDENTIAL_ASSIGNMENT_PATTERNS: [&str; 10] = [
    r"(?i)password\s*[=:]\s*\S+",
    r"(?i)token\s*[=:]\s*\S+",
    r"(?i)secret\s*[=:]\s*\S+",
    r"(?i)api[_-]?key\s*[=:]\s*\S+",
    r"(?i)authorization:\s*\S+",
    r"(?i)bearer\s+\S+",
    r"AKIA[0-9A-Z]{16}",
    r"ASIA[0-9A-Z]{16}",
    r"gh[pousr]_[A-Za-z0-9]{36,}",
    r"github_pat_[A-Za-z0-9_]{22,}",
];

/// Whether text contains a high-precision credential assignment.
///
/// This is a validation gate, not a redactor: it deliberately excludes the
/// broad base64 pattern used by [`redact_text`], so legitimate hashes and
/// encoded payloads are not treated as leaked secrets.
pub fn contains_known_credential_assignment(text: &str) -> bool {
    CREDENTIAL_ASSIGNMENT_PATTERNS.iter().any(|pattern| {
        regex::Regex::new(pattern)
            .map(|expression| expression.is_match(text))
            .unwrap_or(false)
    })
}

/// Truncates `s` to at most `max` bytes, backing off to the nearest UTF-8
/// character boundary.
///
/// `String::truncate` panics when `max` splits a multi-byte character, and
/// every caller here feeds it attacker-controlled text (scanner stderr,
/// report snippets) — the panic would be remotely reachable.
pub fn truncate_at_char_boundary(s: &mut String, max: usize) {
    if s.len() > max {
        let end = s.as_str().floor_char_boundary(max);
        s.truncate(end);
    }
}

pub fn redact_text(text: &str, max_length: usize) -> String {
    let mut result = text.to_string();
    let patterns = [
        (CREDENTIAL_ASSIGNMENT_PATTERNS[0], "password=[REDACTED]"),
        (CREDENTIAL_ASSIGNMENT_PATTERNS[1], "token=[REDACTED]"),
        (CREDENTIAL_ASSIGNMENT_PATTERNS[2], "secret=[REDACTED]"),
        (CREDENTIAL_ASSIGNMENT_PATTERNS[3], "api_key=[REDACTED]"),
        (
            CREDENTIAL_ASSIGNMENT_PATTERNS[4],
            "authorization: [REDACTED]",
        ),
        (CREDENTIAL_ASSIGNMENT_PATTERNS[5], "bearer [REDACTED]"),
        // High-precision credential shapes: a scanner's stderr can echo the
        // matched line, and on a failed run there is no parsed report to do
        // exact replacement from, so the generic pass must catch these.
        (CREDENTIAL_ASSIGNMENT_PATTERNS[6], "[REDACTED]"),
        (CREDENTIAL_ASSIGNMENT_PATTERNS[7], "[REDACTED]"),
        (CREDENTIAL_ASSIGNMENT_PATTERNS[8], "[REDACTED]"),
        (CREDENTIAL_ASSIGNMENT_PATTERNS[9], "[REDACTED]"),
        (r"[A-Za-z0-9+/]{40,}={0,2}", "[BASE64_REDACTED]"),
    ];
    for (pattern, replacement) in patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            result = re.replace_all(&result, replacement).to_string();
        }
    }
    if max_length > 0 && result.len() > max_length {
        truncate_at_char_boundary(&mut result, max_length);
        result.push_str("... [truncated]");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{redact_text, truncate_at_char_boundary};

    /// A 300-char multibyte string truncated to a byte length that splits a
    /// character must not panic and must stay within the byte budget.
    #[test]
    fn truncate_multibyte_never_panics_and_respects_limit() {
        let mut s = "é".repeat(300); // 600 bytes
        let max = 451; // splits the 226th char (odd byte index)
        truncate_at_char_boundary(&mut s, max);
        assert!(s.len() <= max);
        assert_eq!(s, "é".repeat(225)); // backed off to byte 450
    }

    /// Same guarantee through the public redaction entry point, including the
    /// truncation marker.
    #[test]
    fn redact_text_multibyte_truncation_no_panic() {
        let text = "日".repeat(300); // 900 bytes, 3 bytes/char
        let out = redact_text(&text, 401); // splits a char if unguarded
        assert!(out.len() <= 401 + "... [truncated]".len());
        let kept = out.trim_end_matches("... [truncated]");
        assert!(text.starts_with(kept), "kept must be a prefix of input");
    }

    #[test]
    fn truncate_empty_string_is_noop() {
        let mut s = String::new();
        truncate_at_char_boundary(&mut s, 0);
        assert!(s.is_empty());
        truncate_at_char_boundary(&mut s, 10);
        assert!(s.is_empty());
    }

    #[test]
    fn truncate_exact_boundary_is_noop() {
        let mut s = "é".repeat(10); // exactly 20 bytes
        truncate_at_char_boundary(&mut s, 20);
        assert_eq!(s, "é".repeat(10));
        // Exact-limit input is not truncated at all by redact_text either.
        let out = redact_text(&s, 20);
        assert!(!out.contains("[truncated]"));
    }
}
