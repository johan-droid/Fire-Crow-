use crate::error::{AppError, Result};
use crate::schemas::audit_state::AuditState;

pub async fn run_sast(_state: &mut AuditState) -> Result<()> {
    tracing::warn!("[sast] SAST engine not implemented — returning empty findings to avoid fabricated results");
    Err(AppError::Internal("SAST engine not implemented. Configure a real scanner or disable this phase.".into()))
}
