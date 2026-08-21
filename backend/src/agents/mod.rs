pub mod ai_analyzer;
pub mod sast;

pub use ai_analyzer::*;
pub use sast::*;

use crate::error::{AppError, Result};
use crate::schemas::audit_state::AuditState;

/// Recon phase: currently a stub. Restore git-backed agent implementations
/// (src/agents/recon.rs) to re-enable repository reconnaissance.
pub async fn run_recon(_state: &mut AuditState) -> Result<()> {
    Err(AppError::NotImplemented("Recon phase not implemented. Configure a real recon agent or disable this phase.".into()))
}

/// Cross-validation phase: currently a stub. Restore the git-backed
/// `cross_validation` agent to re-enable finding deduplication.
pub async fn cross_validate_findings(state: &mut AuditState) -> Result<()> {
    Err(AppError::NotImplemented("Cross-validation phase not implemented. Configure a real deduplication agent or disable this phase.".into()))
}