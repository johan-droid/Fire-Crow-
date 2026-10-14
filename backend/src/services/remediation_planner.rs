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
                // Unknown severity sorts last: it must never outrank a known
                // signal in remediation order.
                crate::models::Severity::Unknown => 6,
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
                    "Improper Encoding or Escaping of Output Remediation: encode data for the context it is written into (HTML, attribute, URL, JS, SQL), and never pass untrusted input to an interpreter without context-correct escaping."
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

use crate::error::AppError;
use std::collections::{HashMap, HashSet, VecDeque};

pub const MAX_PLAN_DEPTH: usize = 50;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RemediationDependency {
    pub task_id: String,
    pub depends_on: String,
}

/// Validates that remediation task dependencies form an acyclic graph within MAX_PLAN_DEPTH,
/// returning tasks in topologically sorted execution order.
pub fn validate_remediation_dependencies(
    tasks: &[String],
    dependencies: &[RemediationDependency],
) -> Result<Vec<String>, AppError> {
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut in_degree: HashMap<&str, usize> = HashMap::new();

    for task in tasks {
        adj.entry(task.as_str()).or_default();
        in_degree.entry(task.as_str()).or_insert(0);
    }

    for dep in dependencies {
        adj.entry(dep.depends_on.as_str())
            .or_default()
            .push(dep.task_id.as_str());
        *in_degree.entry(dep.task_id.as_str()).or_insert(0) += 1;
    }

    let mut queue: VecDeque<(&str, usize)> = in_degree
        .iter()
        .filter(|(_, &deg)| deg == 0)
        .map(|(&node, _)| (node, 1))
        .collect();

    let mut order = Vec::new();
    let mut visited = HashSet::new();

    while let Some((node, depth)) = queue.pop_front() {
        if depth > MAX_PLAN_DEPTH {
            return Err(AppError::Internal("Remediation plan depth limit exceeded".into()));
        }
        if !visited.insert(node) {
            continue;
        }
        order.push(node.to_string());

        if let Some(neighbors) = adj.get(node) {
            for &next in neighbors {
                if let Some(deg) = in_degree.get_mut(next) {
                    *deg = deg.saturating_sub(1);
                    if *deg == 0 {
                        queue.push_back((next, depth + 1));
                    }
                }
            }
        }
    }

    if order.len() < tasks.len() {
        return Err(AppError::Internal("Cyclic dependency detected in remediation plan".into()));
    }

    Ok(order)
}
