use crate::schemas::audit_state::Finding;

/// Nodes only. Edges are deliberately empty.
///
/// The previous implementation emitted `findings.windows(2)` pairs labelled
/// "chained". Two adjacent array entries share no relationship — the graph
/// fabricated an attack chain out of list ordering. Nothing in this build
/// discovers real links between findings, so it reports none rather than
/// inventing one.
pub fn attack_graph_body(findings: &[Finding]) -> serde_json::Value {
    let nodes: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "id": f.id,
                "label": f.title,
                "severity": f.severity.as_str(),
                "type": "vulnerability",
                "file_path": f.file_path,
                "line_number": f.line_number,
            })
        })
        .collect();
    let edges: Vec<serde_json::Value> = Vec::new();
    serde_json::json!({ "nodes": nodes, "edges": edges })
}
