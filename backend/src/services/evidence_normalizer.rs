use crate::schemas::audit_state::Finding;

pub fn normalize_findings(findings: &[Finding]) -> Vec<serde_json::Value> {
    findings.iter().map(|f| {
        serde_json::json!({
            "id": f.id, "agent_source": f.agent_source, "title": f.title,
            "severity": f.severity.as_str(), "cvss_score": f.cvss_score,
            "cwe_id": f.cwe_id, "owasp_category": f.owasp_category, "confidence": f.confidence,
        })
    }).collect()
}
