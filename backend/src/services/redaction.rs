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
        result.truncate(max_length);
        result.push_str("... [truncated]");
    }
    result
}
