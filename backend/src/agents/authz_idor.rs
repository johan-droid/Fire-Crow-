use crate::error::Result;
use crate::schemas::audit_state::AuditState;

pub async fn run_authz_idor_scan(state: &mut AuditState) -> Result<()> {
    state.authz_findings.extend(vec![]);
    Ok(())
}
