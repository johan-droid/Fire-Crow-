//! Phase A live verification: the real `SandboxManager::run` path through the
//! least-privilege socket proxy. Ignored by default (needs Docker + the pinned
//! gitleaks image); run explicitly with:
//!
//! ```sh
//! DOCKER_HOST=tcp://docker-socket-proxy:2375 \
//!   cargo test --test docker_host_live -- --ignored
//! ```
//!
//! Scope: F1 only. Proves an approved scanner executes end-to-end via the
//! proxy (pull/create/start/wait/stream/remove categories) and leaves no
//! container behind. Never runs in normal (Docker-less) CI.

use firecrow_backend::agents::scanner::{classify, ScanInput, Scanner};
use firecrow_backend::services::sandbox::SandboxManager;

async fn docker_container_ids(ancestor: &str) -> Vec<String> {
    let out = tokio::process::Command::new("docker")
        .args([
            "ps",
            "-a",
            "--filter",
            &format!("ancestor={ancestor}"),
            "--format",
            "{{.ID}}",
        ])
        .output()
        .await
        .expect("live test needs a working `docker` client");
    assert!(
        out.status.success(),
        "live test needs a working `docker` client"
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[tokio::test]
#[ignore]
async fn approved_gitleaks_run_executes_through_proxy_and_cleans_up() {
    let image = Scanner::gitleaks().image.to_string();
    let before = docker_container_ids(&image).await;

    let dir = std::env::temp_dir().join(format!("fc-live-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let secret = "AKIAIOSFODNN7EXAMPLE";
    std::fs::write(dir.join("aws.env"), format!("AWS_ACCESS_KEY_ID={secret}\n")).unwrap();

    let sandbox = SandboxManager::new();
    let scanner = Scanner::gitleaks();
    let input = ScanInput::from_dir(&dir);
    let run = sandbox
        .run(&input.sandbox_spec(&scanner), &|| false)
        .await
        .expect("approved run must execute through the proxy");
    let result = classify(&scanner, &input, Ok(run));
    assert!(
        result.outcome.is_success(),
        "gitleaks must report through the proxy, got {:?}",
        result.outcome
    );
    assert_eq!(result.findings.len(), 1, "exactly one secret expected");
    assert!(
        !result.findings[0]
            .evidence
            .as_deref()
            .unwrap_or_default()
            .contains(secret),
        "the secret value must be redacted"
    );

    let after = docker_container_ids(&image).await;
    assert_eq!(
        before, after,
        "the run must leave no container behind (cleanup through the proxy)"
    );

    std::fs::remove_dir_all(&dir).ok();
}
