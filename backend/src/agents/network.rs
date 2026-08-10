use crate::error::Result;
use crate::schemas::audit_state::AuditState;

pub async fn run_network_scan(state: &mut AuditState) -> Result<()> {
    tracing::info!("[network] Running network scan");
    state.open_ports.extend(vec![]);
    state.tls_issues.extend(vec![]);
    Ok(())
}
