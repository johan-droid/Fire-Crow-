use crate::error::Result;
use crate::schemas::audit_state::AuditState;

pub async fn generate_threat_model(state: &mut AuditState) -> Result<()> {
    state.threat_model = serde_json::json!({"threats": [], "mitigations": []});
    Ok(())
}
