use crate::error::{AppError, Result};
use crate::utils::generate_uuid;
use sqlx::{PgPool, Row};

pub struct GraphStore;

impl GraphStore {
    pub async fn verify_connectivity(pool: &PgPool) -> Result<()> {
        sqlx::query("SELECT 1")
            .execute(pool)
            .await
            .map_err(|e| AppError::GraphDatabase(e.to_string()))?;
        tracing::info!("Neon PostgreSQL graph store connectivity verified");
        Ok(())
    }

    pub async fn store_attack_graph(
        pool: &PgPool,
        job_id: &str,
        nodes: &[serde_json::Value],
        edges: &[serde_json::Value],
    ) -> Result<()> {
        for node in nodes {
            let label = node.get("label").and_then(|v| v.as_str()).unwrap_or("");
            let node_type = node.get("type").and_then(|v| v.as_str()).unwrap_or("vulnerability");
            let severity = node.get("severity").and_then(|v| v.as_str()).unwrap_or("");
            let node_id = node.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let id = generate_uuid();

            sqlx::query(
                r#"
                INSERT INTO attack_graph_nodes (id, job_id, node_id, label, severity, node_type, metadata_json, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
                ON CONFLICT (job_id, node_id) DO UPDATE SET label = EXCLUDED.label, severity = EXCLUDED.severity, node_type = EXCLUDED.node_type
                "#,
            )
            .bind(id)
            .bind(job_id)
            .bind(node_id)
            .bind(label)
            .bind(severity)
            .bind(node_type)
            .bind(node)
            .execute(pool)
            .await
            .map_err(|e| AppError::GraphDatabase(e.to_string()))?;
        }

        for edge in edges {
            let source = edge.get("source").and_then(|v| v.as_str()).unwrap_or("");
            let target = edge.get("target").and_then(|v| v.as_str()).unwrap_or("");
            let label = edge.get("label").and_then(|v| v.as_str()).unwrap_or("chained");
            let id = generate_uuid();

            sqlx::query(
                r#"
                INSERT INTO attack_graph_edges (id, job_id, source_node_id, target_node_id, label, metadata_json, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, NOW())
                ON CONFLICT (job_id, source_node_id, target_node_id, label) DO NOTHING
                "#,
            )
            .bind(id)
            .bind(job_id)
            .bind(source)
            .bind(target)
            .bind(label)
            .bind(edge)
            .execute(pool)
            .await
            .map_err(|e| AppError::GraphDatabase(e.to_string()))?;
        }
        Ok(())
    }

    pub async fn fetch_attack_graph(pool: &PgPool, job_id: &str) -> Result<serde_json::Value> {
        let node_rows = sqlx::query(
            "SELECT node_id, label, severity, node_type FROM attack_graph_nodes WHERE job_id = $1"
        )
        .bind(job_id)
        .fetch_all(pool)
        .await
        .map_err(AppError::Database)?;

        let edge_rows = sqlx::query(
            "SELECT source_node_id, target_node_id, label FROM attack_graph_edges WHERE job_id = $1"
        )
        .bind(job_id)
        .fetch_all(pool)
        .await
        .map_err(AppError::Database)?;

        let nodes: Vec<serde_json::Value> = node_rows
            .into_iter()
            .map(|r| {
                let node_id: String = r.get("node_id");
                let label: String = r.get("label");
                let severity: String = r.get("severity");
                let node_type: String = r.get("node_type");
                serde_json::json!({
                    "id": node_id,
                    "label": label,
                    "severity": severity,
                    "type": node_type
                })
            })
            .collect();

        let edges: Vec<serde_json::Value> = edge_rows
            .into_iter()
            .map(|r| {
                let source_node_id: String = r.get("source_node_id");
                let target_node_id: String = r.get("target_node_id");
                let label: String = r.get("label");
                serde_json::json!({
                    "source": source_node_id,
                    "target": target_node_id,
                    "label": label
                })
            })
            .collect();

        Ok(serde_json::json!({
            "nodes": nodes,
            "edges": edges
        }))
    }
}
