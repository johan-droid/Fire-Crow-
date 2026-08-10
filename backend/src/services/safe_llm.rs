use crate::services::llm::LlmService;

pub fn is_llm_enabled(llm: &LlmService) -> bool { llm.is_enabled() }
pub async fn safe_llm_call(llm: &LlmService, prompt: &str, findings: &[serde_json::Value]) -> Result<String, crate::error::AppError> {
    llm.call(prompt, findings).await
}
