pub fn redact_text(text: &str, max_length: usize) -> String {
    let mut result = text.to_string();
    let patterns = [
        (r"(?i)password\s*[=:]\s*\S+", "password=[REDACTED]"),
        (r"(?i)token\s*[=:]\s*\S+", "token=[REDACTED]"),
        (r"(?i)secret\s*[=:]\s*\S+", "secret=[REDACTED]"),
        (r"(?i)api[_-]?key\s*[=:]\s*\S+", "api_key=[REDACTED]"),
        (r"(?i)authorization:\s*\S+", "authorization: [REDACTED]"),
        (r"(?i)bearer\s+\S+", "bearer [REDACTED]"),
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
