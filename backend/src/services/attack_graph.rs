use crate::error::AppError;
use crate::schemas::audit_state::Finding;
use std::collections::{HashSet, VecDeque};

pub const MAX_GRAPH_DEPTH: usize = 50;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Edge {
    pub source: String,
    pub target: String,
    #[serde(default)]
    pub label: Option<String>,
}

/// Computes an attack path starting from a node using BFS while guarding against
/// cyclic recursion and unbounded graph depth (FC-OOM protection).
pub fn calculate_attack_path(start_node_id: &str, edges: &[Edge]) -> Result<Vec<String>, AppError> {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    let mut path = Vec::new();

    queue.push_back((start_node_id.to_string(), 0));

    while let Some((current_id, depth)) = queue.pop_front() {
        if depth > MAX_GRAPH_DEPTH {
            return Err(AppError::Internal("Maximum attack graph depth exceeded".into()));
        }

        // Cycle detection: skip nodes already visited in the path
        if !visited.insert(current_id.clone()) {
            continue;
        }

        path.push(current_id.clone());

        for edge in edges {
            if edge.source == current_id {
                queue.push_back((edge.target.clone(), depth + 1));
            }
        }
    }

    Ok(path)
}

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
