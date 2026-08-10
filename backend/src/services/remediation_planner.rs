use crate::schemas::audit_state::Finding;

pub fn remediation_planner_body(findings: &[Finding]) -> Vec<serde_json::Value> {
    findings
        .iter()
        .map(|f| {
            let priority = match f.severity {
                crate::models::Severity::Critical => 1,
                crate::models::Severity::High => 2,
                crate::models::Severity::Medium => 3,
                crate::models::Severity::Low => 4,
                crate::models::Severity::Info => 5,
            };

            let detailed_remediation = match f.cwe_id.as_deref() {
                Some("CWE-1336") => {
                    "SSTI Remediation: Enforce context-aware auto-escaping. Do not render strings containing user input directly; pass data context variables into pre-compiled template files."
                }
                Some("CWE-1333") => {
                    "ReDoS Remediation: Replace backtracking regex engines with linear-time matchers (Rust regex crate). Apply strict parameter length limits and timeout wrappers."
                }
                Some("CWE-400") => {
                    "LPDos Remediation: Enforce request body size limits via middleware, set socket read/write timeouts, and apply rate-limiting policies on all public endpoints."
                }
                Some("CWE-798") => {
                    "Secret Leakage Remediation: Revoke compromised keys immediately, migrate credentials to secure environment vaults, and scrub secrets from logs."
                }
                Some("CWE-89") | Some("CWE-943") => {
                    "SQL/NoSQL Injection Remediation: Enforce parameterized query bindings (sqlx::query! with $1, $2 placeholders) and avoid dynamic string concatenation in database queries."
                }
                Some("CWE-116") => {
                    "Clipboard Attack Remediation: Sanitize user input before writing to clipboard buffers and strip unsafe HTML/script tags from paste handlers."
                }
                Some("CWE-294") => {
                    "Replay Attack Remediation: Attach unique nonces (jti claim in JWT), enforce strict request timestamp windows, and validate single-use anti-CSRF exchange tokens."
                }
                _ => f.remediation.as_deref().unwrap_or("Apply security best practices and input validation."),
            };

            serde_json::json!({
                "title": f.title,
                "severity": f.severity.as_str(),
                "priority": priority,
                "remediation": detailed_remediation,
                "cwe_id": f.cwe_id,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "route": f.route
            })
        })
        .collect()
}
