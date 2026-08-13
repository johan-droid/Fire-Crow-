use crate::error::Result;

pub struct SandboxManager {
    python_image: String,
    node_image: String,
}

impl SandboxManager {
    pub fn new(python_image: &str, node_image: &str) -> Self {
        Self { python_image: python_image.into(), node_image: node_image.into() }
    }
    pub async fn run_in_sandbox(&self, image: &str, command: &[&str], timeout_secs: u64) -> Result<(String, String)> {
        tracing::info!("Sandbox execution starting for image: {}", image);
        let mut cmd = tokio::process::Command::new("docker");
        cmd.arg("run")
           .arg("--rm")
           .arg("--network=none")
           .arg("--read-only")
           .arg("--cpus=1.0")
           .arg("-m=512m")
           .arg(image)
           .args(command);

        match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), cmd.output()).await {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                if !output.status.success() {
                    tracing::warn!("Sandbox process failed: {}", stderr);
                }
                Ok((stdout, stderr))
            }
            Ok(Err(e)) => {
                Err(crate::error::AppError::Internal(format!("Failed to execute sandbox: {}", e)))
            }
            Err(_) => {
                Err(crate::error::AppError::Internal(format!("Sandbox execution timed out after {}s", timeout_secs)))
            }
        }
    }
    pub async fn cleanup(&self, _container_id: &str) -> Result<()> { Ok(()) }
}
