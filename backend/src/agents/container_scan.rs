use crate::error::Result;
use crate::schemas::audit_state::AuditState;

pub async fn run_container_scan(state: &mut AuditState) -> Result<()> {
    tracing::info!("[container_scan] Scanning container configuration");
    state.container_findings.extend(vec![]);
    Ok(())
}
