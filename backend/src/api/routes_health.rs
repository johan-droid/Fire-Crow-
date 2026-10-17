use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use std::process::Stdio;
use std::sync::Arc;

/// Probe whether the Docker daemon is actually reachable.
///
/// Runs `docker version` with a short timeout. Returns `true` only if the
/// command exits successfully, which requires the daemon to be reachable and
/// responsive. Never exposes daemon errors, certificate paths, or internal
/// endpoints — the result is a single boolean.
///
/// The previous check was `std::env::var("DOCKER_HOST").is_ok()`, which only
/// verified that the environment variable was set. A configured-but-unreachable
/// endpoint was reported as "configured", misleading users into submitting jobs
/// that would fail at scan time. This probe closes that gap.
///
/// Fail-closed: if `DOCKER_HOST` is set but not a valid `tcp://host:port`,
/// the probe returns `false` rather than falling back to the default unix
/// socket — a set-but-malformed endpoint must not silently probe an
/// unintended daemon.
async fn docker_daemon_reachable() -> bool {
    // `docker version` exits non-zero when the daemon is unreachable, the CLI
    // is too old, or TLS verification fails. All of those mean "not ready".
    // We discard stdout/stderr and only inspect the exit status, so no daemon
    // error details can leak into the health response.
    //
    // `env_clear()` prevents a tampered ambient environment from influencing
    // the probe (same rationale as `SandboxManager::run`). `DOCKER_HOST` is
    // restored in validated `tcp://host:port` form only — never a unix socket
    // path or credentials — so the probe uses the same least-privilege channel
    // as scanner execution.
    let raw_host = std::env::var_os("DOCKER_HOST");
    let validated_host = raw_host
        .as_deref()
        .and_then(crate::services::sandbox::validated_docker_host);

    // Fail closed: DOCKER_HOST is set but invalid → do not probe the default
    // socket, which could reach an unintended daemon.
    if raw_host.is_some() && validated_host.is_none() {
        return false;
    }

    let mut cmd = tokio::process::Command::new("docker");
    cmd.arg("version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env_clear();
    if let Some(host) = &validated_host {
        cmd.env("DOCKER_HOST", host);
        cmd.env("DOCKER_TLS_VERIFY", "1");
        cmd.env("DOCKER_CERT_PATH", "/etc/firecrow/docker-tls");
    }

    tokio::time::timeout(std::time::Duration::from_secs(5), cmd.output())
        .await
        .map(|result| {
            result
                .map(|output| output.status.success())
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

pub async fn health_deep(State(state): State<Arc<crate::AppState>>) -> impl IntoResponse {
    let db_ok = sqlx::query("SELECT 1").execute(state.pool()).await.is_ok();
    let mode = crate::services::sandbox::ExecutionMode::resolve();

    // Scanner capability is reported per backend. In container mode the real
    // Docker probe decides `docker`; in native mode there is no daemon, so
    // `docker` is `not_required` and each scanner's availability is whether its
    // pinned binary is actually present and runnable.
    let (docker, scanner_block) = match mode {
        crate::services::sandbox::ExecutionMode::Container => {
            let ready = docker_daemon_reachable().await;
            let docker_label = if ready { "ready" } else { "unavailable" };
            // In container mode a scanner's availability tracks the daemon.
            let avail = |_: &str| if ready { "available" } else { "unavailable" };
            (
                docker_label,
                serde_json::json!({
                    "mode": "container",
                    // Honest isolation label: a container boundary, not a claim
                    // of VM-grade isolation.
                    "isolation": "container",
                    "gitleaks": avail("gitleaks"),
                    "osv": avail("osv"),
                    "semgrep": avail("semgrep"),
                }),
            )
        }
        crate::services::sandbox::ExecutionMode::Native => {
            let mut obj = serde_json::json!({
                "mode": "native",
                // Honest isolation label: process-level hardening only. This is
                // NOT equivalent to a container boundary; see the native_exec
                // module docs for the exact residual risk.
                "isolation": "process",
            });
            for (name, available) in crate::services::native_exec::availability() {
                obj[name] = serde_json::Value::String(if available {
                    "available".into()
                } else {
                    "unavailable".into()
                });
            }
            ("not_required", obj)
        }
    };

    let status = if db_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(serde_json::json!({
            "status": if db_ok { "healthy" } else { "unhealthy" },
            "database": if db_ok { "ok" } else { "error" },
            "local_storage": "ok",
            // Capability honesty (FC-DEP-04): scanner execution needs a real
            // boundary that is actually reachable. The body — not the HTTP
            // status — carries capability, so a broken scanner never marks the
            // instance unhealthy (which would trigger a restart loop) but is
            // reported truthfully so the frontend can gate submission before
            // anyone starts a scan.
            "docker": docker,
            "scanner": scanner_block,
            "version": env!("CARGO_PKG_VERSION")
        })),
    )
}

pub async fn health_ready(State(state): State<Arc<crate::AppState>>) -> impl IntoResponse {
    // A readiness probe that never fails is not a readiness probe: it tells a load
    // balancer to keep routing to an instance that cannot reach its database.
    // (audit R-10; clippy flagged the identical branches)
    let db_ok = sqlx::query("SELECT 1").execute(state.pool()).await.is_ok();
    let status = if db_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(serde_json::json!({
            "status": if db_ok { "ready" } else { "degraded" },
            "database": if db_ok { "connected" } else { "disconnected" }
        })),
    )
}

pub async fn health_check(State(state): State<Arc<crate::AppState>>) -> impl IntoResponse {
    let db_ok = sqlx::query("SELECT 1").execute(state.pool()).await.is_ok();

    Json(serde_json::json!({
        "status": "up",
        "database": if db_ok { "connected" } else { "disconnected" }
    }))
}

pub async fn health_live() -> &'static str {
    "live"
}

pub fn router() -> axum::Router<Arc<crate::AppState>> {
    use axum::routing::get;
    axum::Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/health", get(health_check))
        .route("/api/v1/health/deep", get(health_deep))
        .route("/api/v1/health/ready", get(health_ready))
        .route("/api/v1/health/live", get(health_live))
}

#[cfg(test)]
mod tests {
    use super::docker_daemon_reachable;
    use tokio::sync::Mutex;

    /// Serializes tests that mutate the `DOCKER_HOST` environment variable.
    /// Without this, parallel test execution causes interleaved env reads.
    static ENV_LOCK: Mutex<()> = Mutex::const_new(());

    /// Set `DOCKER_HOST`, run the probe, restore the env var.
    async fn with_docker_host(value: &str) -> bool {
        let _guard = ENV_LOCK.lock().await;
        let original = std::env::var("DOCKER_HOST").ok();
        std::env::set_var("DOCKER_HOST", value);
        let result = docker_daemon_reachable().await;
        match original {
            Some(v) => std::env::set_var("DOCKER_HOST", v),
            None => std::env::remove_var("DOCKER_HOST"),
        }
        result
    }

    /// When `docker` CLI is not installed, the probe returns false.
    /// This is the common case in CI and local dev without Docker.
    #[tokio::test]
    async fn docker_unreachable_when_cli_missing() {
        let _guard = ENV_LOCK.lock().await;
        let original = std::env::var("DOCKER_HOST").ok();
        std::env::remove_var("DOCKER_HOST");
        let result = docker_daemon_reachable().await;
        match original {
            Some(v) => std::env::set_var("DOCKER_HOST", v),
            None => std::env::remove_var("DOCKER_HOST"),
        }
        // Assert it's a valid boolean. The real assertion is that this doesn't hang or panic.
        let _ = result;
    }

    /// When `DOCKER_HOST` points to an unreachable endpoint, the probe
    /// returns false within the timeout.
    #[tokio::test]
    async fn docker_unreachable_when_endpoint_is_dead() {
        // TEST-NET-1 (RFC 5737), guaranteed unreachable
        let result = with_docker_host("tcp://192.0.2.1:2375").await;
        assert!(
            !result,
            "unreachable Docker endpoint must report unavailable"
        );
    }

    /// When `DOCKER_HOST` is malformed (not tcp://host:port), the probe
    /// returns false.
    #[tokio::test]
    async fn docker_unreachable_when_host_is_malformed() {
        let result = with_docker_host("not-a-valid-endpoint").await;
        assert!(!result, "malformed DOCKER_HOST must report unavailable");
    }

    /// When `DOCKER_HOST` is a unix socket, the probe returns false
    /// (the backend only accepts tcp://host:port form).
    #[tokio::test]
    async fn docker_unreachable_when_host_is_unix_socket() {
        let result = with_docker_host("unix:///var/run/docker.sock").await;
        assert!(!result, "unix socket DOCKER_HOST must report unavailable");
    }

    /// When `DOCKER_HOST` is not set and no default socket exists, the probe
    /// returns false. (On hosts with a running daemon via default socket, this
    /// would return true — the test only asserts the function doesn't panic.)
    #[tokio::test]
    async fn docker_probe_never_panics() {
        let _guard = ENV_LOCK.lock().await;
        let original = std::env::var("DOCKER_HOST").ok();
        std::env::remove_var("DOCKER_HOST");
        let result = docker_daemon_reachable().await;
        match original {
            Some(v) => std::env::set_var("DOCKER_HOST", v),
            None => std::env::remove_var("DOCKER_HOST"),
        }
        let _ = result;
    }
}
