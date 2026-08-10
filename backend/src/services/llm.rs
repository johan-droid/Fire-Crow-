use crate::error::{AppError, Result};
use serde_json::Value;

pub struct LlmService {
    api_key: String,
    model: String,
    fallback_model: String,
    max_attempts: i32,
    timeout_seconds: i64,
}

impl LlmService {
    pub fn new(api_key: &str, model: &str, fallback_model: &str, max_attempts: i32, timeout_seconds: i64) -> Self {
        Self { api_key: api_key.into(), model: model.into(), fallback_model: fallback_model.into(), max_attempts, timeout_seconds }
    }
    pub async fn call(&self, prompt: &str, _findings: &[Value]) -> Result<String> {
        if self.api_key.is_empty() { return Err(AppError::LlmError("LLM API key not configured".into())); }
        tracing::debug!("LLM call [STUB]: model={}, prompt_len={}", self.model, prompt.len());
        Ok(String::new())
    }
    pub fn is_enabled(&self) -> bool { !self.api_key.is_empty() }
}
