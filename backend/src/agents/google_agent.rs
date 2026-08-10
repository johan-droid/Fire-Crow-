use crate::error::Result;
use crate::schemas::audit_state::AuditState;

pub async fn run_google_agent(state: &mut AuditState) -> Result<()> {
    state.google_agent_logs = vec!["Google agent stub".into()];
    state.google_agent_delivered = true;
    Ok(())
}
