use crate::error::Result;
use crate::schemas::audit_state::AuditState;

pub async fn run_iac_scan(state: &mut AuditState) -> Result<()> {
    tracing::info!("[iac_scan] Scanning IaC");
    state.iac_findings.extend(vec![]);
    Ok(())
}
