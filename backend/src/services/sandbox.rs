use crate::error::Result;

pub struct SandboxManager {
    python_image: String,
    node_image: String,
}

impl SandboxManager {
    pub fn new(python_image: &str, node_image: &str) -> Self {
        Self { python_image: python_image.into(), node_image: node_image.into() }
    }
    pub async fn run_in_sandbox(&self, _image: &str, _command: &[&str], _timeout_secs: u64) -> Result<(String, String)> {
        tracing::debug!("Sandbox execution [STUB]");
        Ok((String::new(), String::new()))
    }
    pub async fn cleanup(&self, _container_id: &str) -> Result<()> { Ok(()) }
}
