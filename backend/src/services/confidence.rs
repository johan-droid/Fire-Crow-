use crate::schemas::audit_state::Finding;

pub fn calculate_confidence(finding: &Finding) -> f64 {
    let mut score: f64 = 0.5;
    if finding.cvss_score.is_some() { score += 0.15; }
    if finding.evidence.is_some() { score += 0.15; }
    if finding.cwe_id.is_some() { score += 0.1; }
    if finding.remediation.is_some() { score += 0.1; }
    score.min(1.0)
}
