use crate::error::Result;
use crate::schemas::audit_state::AuditState;

pub async fn run_ai_analyzer(state: &mut AuditState) -> Result<()> {
    state.deduplicated_findings = state.scored_findings.clone();
    state.false_positives = vec![];
    state.attack_chains = vec![];
    Ok(())
}
