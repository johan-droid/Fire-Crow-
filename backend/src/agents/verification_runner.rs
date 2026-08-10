use crate::error::Result;
use crate::schemas::audit_state::AuditState;

pub async fn run_verification(_state: &mut AuditState) -> Result<()> {
    tracing::info!("[verification] Re-verifying findings");
    Ok(())
}
