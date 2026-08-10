//! Common utilities — includes input sanitization & ReDoS protection.

pub fn generate_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// ReDoS Defense: Truncates and validates input strings to prevent regex execution over excessive lengths.
pub fn safe_regex_match(pattern: &str, text: &str, max_len: usize) -> bool {
    if text.len() > max_len {
        return false;
    }
    match regex::Regex::new(pattern) {
        Ok(re) => re.is_match(text),
        Err(_) => false,
    }
}

/// SSTI & HTML Injection Defense: Sanitizes raw strings prior to template/markdown rendering.
pub fn sanitize_html_entities(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
        .replace('/', "&#x2F;")
}

/// Clipboard & Pastejacking Defense: Strips hidden control characters and ANSI escape sequences.
pub fn sanitize_clipboard_text(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}
