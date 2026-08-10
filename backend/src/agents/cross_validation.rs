use crate::error::Result;
use crate::schemas::audit_state::AuditState;

pub async fn cross_validate_findings(state: &mut AuditState) -> Result<()> {
    let mut all = state.deduplicated_findings.clone();
    all.extend(state.static_findings.clone());
    state.validated_findings = all;
    state.correlation_report = vec![];
    Ok(())
}

