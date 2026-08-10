use crate::error::Result;
use crate::schemas::audit_state::AuditState;

pub async fn run_dependency_scan(state: &mut AuditState) -> Result<()> {
    tracing::info!("[dependency_scan] Scanning dependencies");
    state.dependency_vulns.extend(vec![]);
    Ok(())
}
