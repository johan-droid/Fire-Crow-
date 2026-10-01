use crate::error::Result;

/// A read-only (or read-write) bind mount into the sandbox.
#[derive(Debug, Clone)]
pub struct SandboxMount {
    pub host_path: String,
    pub container_path: String,
    pub read_only: bool,
}

/// Result of a sandboxed process.
#[derive(Debug, Clone)]
pub struct SandboxOutput {
    pub stdout: String,
    pub stderr: String,
    pub success: bool,
}

/// The unprivileged uid:gid the sandboxed process runs as.
///
/// `65534` is `nobody`/`nogroup` on essentially every Linux image, so an escaped
/// or compromised scanner still owns nothing.
pub const SANDBOX_USER: &str = "65534:65534";

pub struct SandboxManager {
    python_image: String,
    node_image: String,
}

impl SandboxManager {
    pub fn new(python_image: &str, node_image: &str) -> Self {
        Self {
            python_image: python_image.into(),
            node_image: node_image.into(),
        }
    }

    /// Run `command` in `image` with the hardened flag set and the given mounts.
    ///
    /// The command is passed as an **argument vector** — never a shell string —
    /// so scanner output cannot be interpreted as shell syntax.
    ///
    /// Flags: no network, read-only root filesystem, a pid ceiling, all Linux
    /// capabilities dropped, `no-new-privileges`, an unprivileged user, and cpu
    /// and memory limits.
    pub async fn run(
        &self,
        image: &str,
        command: &[&str],
        mounts: &[SandboxMount],
        timeout_secs: u64,
    ) -> Result<SandboxOutput> {
        tracing::info!("Sandbox execution starting for image: {}", image);

        let mut cmd = tokio::process::Command::new("docker");
        cmd.arg("run")
            .arg("--rm")
            .arg("--network=none")
            .arg("--read-only")
            .arg("--pids-limit=256")
            .arg("--cap-drop=ALL")
            .arg("--security-opt=no-new-privileges")
            .arg(format!("--user={SANDBOX_USER}"))
            .arg("--cpus=1.0")
            .arg("-m=512m");

        for mount in mounts {
            let mut spec = format!("{}:{}", mount.host_path, mount.container_path);
            if mount.read_only {
                spec.push_str(":ro");
            }
            cmd.arg("-v").arg(spec);
        }

        cmd.arg(image).args(command);
        // Never inherit an interactive/inherited stdin.
        cmd.stdin(std::process::Stdio::null());

        match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), cmd.output()).await {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                if !output.status.success() {
                    tracing::warn!("Sandbox process failed: {}", stderr);
                }
                Ok(SandboxOutput {
                    stdout,
                    stderr,
                    success: output.status.success(),
                })
            }
            Ok(Err(e)) => Err(crate::error::AppError::Internal(format!(
                "Failed to execute sandbox: {}",
                e
            ))),
            Err(_) => Err(crate::error::AppError::Internal(format!(
                "Sandbox execution timed out after {}s",
                timeout_secs
            ))),
        }
    }

    /// Convenience wrapper for a mount-free run.
    pub async fn run_in_sandbox(
        &self,
        image: &str,
        command: &[&str],
        timeout_secs: u64,
    ) -> Result<(String, String)> {
        let out = self.run(image, command, &[], timeout_secs).await?;
        Ok((out.stdout, out.stderr))
    }

    pub async fn cleanup(&self, _container_id: &str) -> Result<()> {
        Ok(())
    }
}
