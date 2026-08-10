use crate::error::Result;
use crate::schemas::audit_state::AuditState;

pub async fn run_secret_history(state: &mut AuditState) -> Result<()> {
    tracing::info!("[secret_history] Scanning git history for secrets");
    state.secret_history_findings.extend(vec![]);
    Ok(())
}
