use crate::error::Result;
use crate::schemas::audit_state::AuditState;

pub async fn api_surface_body(state: &mut AuditState) -> Result<()> {
    state.api_surface = vec![];
    state.route_risk_summary = serde_json::json!({});
    Ok(())
}
