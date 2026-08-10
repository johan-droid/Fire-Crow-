use crate::error::Result;
use crate::schemas::audit_state::AuditState;

pub async fn run_config_scan(state: &mut AuditState) -> Result<()> {
    state.normalized_findings.extend(vec![]);
    Ok(())
}
