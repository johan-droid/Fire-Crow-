use crate::error::Result;
use crate::schemas::audit_state::AuditState;

pub async fn sbom_graph_body(state: &mut AuditState) -> Result<()> {
    state.sbom_components = vec![];
    state.dependency_graph = serde_json::json!({});
    Ok(())
}
