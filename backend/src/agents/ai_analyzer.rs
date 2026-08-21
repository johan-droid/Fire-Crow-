use crate::error::{AppError, Result};
use crate::schemas::audit_state::AuditState;

pub async fn run_ai_analyzer(_state: &mut AuditState) -> Result<()> {
    Err(AppError::NotImplemented("AI analysis phase not implemented. Configure a real LLM analyzer or disable this phase.".into()))
}
