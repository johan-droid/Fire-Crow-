use crate::schemas::audit_state::Finding;

pub fn attack_graph_body(findings: &[Finding]) -> serde_json::Value {
    let nodes: Vec<serde_json::Value> = findings.iter().map(|f| {
        serde_json::json!({ "id": f.id, "label": f.title, "severity": f.severity.as_str(), "type": "vulnerability" })
    }).collect();
    let edges: Vec<serde_json::Value> = findings.windows(2).map(|pair| {
        serde_json::json!({ "source": pair[0].id, "target": pair[1].id, "label": "chained" })
    }).collect();
    serde_json::json!({ "nodes": nodes, "edges": edges })
}
