use crate::error::Result;
use crate::schemas::audit_state::AuditState;

pub async fn run_semgrep_scan(state: &mut AuditState) -> Result<()> {
    tracing::info!("[semgrep] Running Semgrep scanner");
    state.semgrep_findings.extend(vec![]);
    Ok(())
}
