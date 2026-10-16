//! Phase A (F1) exit criterion: the backend host boundary.
//!
//! The backend must have no unrestricted Docker socket access, must run as a
//! dedicated non-root user, must reject dangerous Docker capabilities, and
//! approved scanner execution must still be admitted unchanged. Pure tests
//! only: no Docker, no network, no database.
//!
//! Scope: F1 only. H1-H4 / M1-M4 / L1-L11 are not covered here.

use firecrow_backend::agents::scanner::{ScanInput, Scanner};
use firecrow_backend::services::sandbox::{
    docker_argv, enforce_execution_policy, validated_docker_host, NetworkMode, ResourceLimits,
    SandboxMount, SandboxSpec, APPROVED_SCANNER_EXECUTIONS,
};
use std::collections::HashSet;

// --- Fixture helpers -------------------------------------------------------

fn approved_specs() -> Vec<(Scanner, NetworkMode, SandboxSpec)> {
    let scanners = [
        (Scanner::gitleaks(), NetworkMode::None),
        (Scanner::osv(), NetworkMode::Filtered),
        (Scanner::semgrep(), NetworkMode::None),
    ];
    scanners
        .into_iter()
        .map(|(scanner, network)| {
            let spec = ScanInput::from_dir(&std::env::temp_dir()).sandbox_spec(&scanner);
            (scanner, network, spec)
        })
        .collect()
}

fn repo_path(segments: &[&str]) -> String {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for s in segments {
        path.push(s);
    }
    path.to_string_lossy().to_string()
}

fn compose_text() -> String {
    std::fs::read_to_string(repo_path(&["..", "docker-compose.yml"]))
        .expect("docker-compose.yml must be readable")
}

/// Extract one `services:` child block by indentation. Minimal on purpose:
/// this file is ours, and the test fails loudly if its shape changes.
fn service_block(text: &str, service: &str) -> String {
    let mut out = Vec::new();
    let mut in_services = false;
    let mut capturing = false;
    for line in text.lines() {
        if line == "services:" {
            in_services = true;
            continue;
        }
        if !in_services {
            continue;
        }
        if !line.starts_with(' ') && !line.trim().is_empty() {
            break; // next top-level key (e.g. `volumes:`)
        }
        let trimmed = line.trim();
        if line.starts_with("  ")
            && !line.starts_with("   ")
            && trimmed.ends_with(':')
            && !trimmed.contains(' ')
        {
            capturing = trimmed.trim_end_matches(':') == service;
            continue;
        }
        if capturing {
            out.push(line);
        }
    }
    assert!(
        !out.is_empty(),
        "compose service {service:?} not found — layout changed?"
    );
    out.join("\n")
}

// --- Deployment: no unrestricted socket ------------------------------------

#[test]
fn backend_service_holds_no_docker_socket() {
    let block = service_block(&compose_text(), "backend");
    assert!(
        !block.contains("docker.sock"),
        "backend must not mount the Docker socket (F1):\n{block}"
    );
    assert!(
        !block.contains("privileged"),
        "backend must not be privileged:\n{block}"
    );
    // T1 (mTLS): the backend reaches the daemon via TLS, not the socket proxy.
    assert!(
        block.contains("DOCKER_HOST") && block.contains("tcp://host.docker.internal:2376"),
        "backend must reach Docker only via the TLS endpoint:\n{block}"
    );
    assert!(
        block.contains("/etc/firecrow/docker-tls"),
        "backend must mount the client certificate for mTLS:\n{block}"
    );
}

#[test]
fn authz_plugin_is_the_daemon_boundary_enforcement_point() {
    let text = compose_text();
    // The authz plugin service must exist and be wired to the daemon socket dir.
    let block = service_block(&text, "authz-plugin");
    assert!(
        block.contains("firecrow-authz-plugin"),
        "authz plugin must build from the authz Dockerfile:\n{block}"
    );
    assert!(
        block.contains("/run/docker/plugins"),
        "authz plugin must mount the daemon plugin socket directory:\n{block}"
    );
    assert!(
        block.contains("FIRECROW_AUTHZ_NAME"),
        "authz plugin must set the plugin name:\n{block}"
    );
    assert!(
        block.contains("FIRECROW_AUTHZ_ALLOWED_CNS"),
        "authz plugin must set the CN allowlist:\n{block}"
    );
}

#[test]
fn socket_proxy_is_retired_in_t1_topology() {
    let text = compose_text();
    // The docker-socket-proxy is retired in the T1 topology. It may exist
    // for backward compatibility but must be profile-gated (not active by
    // default) and must not be the backend's DOCKER_HOST.
    let proxy_block = service_block(&text, "docker-socket-proxy");
    assert!(
        proxy_block.contains("profiles:"),
        "docker-socket-proxy must be profile-gated in the T1 topology:\n{proxy_block}"
    );
    let backend_block = service_block(&text, "backend");
    assert!(
        !backend_block.contains("docker-socket-proxy"),
        "backend must not reference the retired socket proxy:\n{backend_block}"
    );
}

// --- Deployment: non-root backend ------------------------------------------

#[test]
fn backend_images_run_as_dedicated_non_root_user() {
    for rel in ["Dockerfile", "../Dockerfile"] {
        let text = std::fs::read_to_string(repo_path(&[rel])).expect("Dockerfile must be readable");
        let users: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("USER "))
            .collect();
        let last = users.last().expect("Dockerfile must set USER");
        assert!(
            *last != "USER root" && *last != "USER 0" && *last != "USER 0:0",
            "{rel} must never run as root, got {last}"
        );
        assert!(
            last.starts_with("USER 10001"),
            "{rel} must pin the dedicated non-root UID, got {last}"
        );
        assert!(
            !text.contains("chmod 777") && !text.contains("chmod -R 777"),
            "{rel} must not use permission workarounds"
        );
    }
}

// --- Policy: approved runs admitted -----------------------------------------

#[test]
fn scanner_constructors_match_the_execution_allowlist() {
    for (scanner, network) in [
        (Scanner::gitleaks(), NetworkMode::None),
        (Scanner::osv(), NetworkMode::Filtered),
        (Scanner::semgrep(), NetworkMode::None),
    ] {
        assert!(
            APPROVED_SCANNER_EXECUTIONS
                .iter()
                .any(|(image, net)| scanner.image == *image && network == *net),
            "{:?} ({}) drifted from the execution allowlist",
            scanner.image,
            network.as_str(),
        );
        assert!(
            !scanner.image.contains("latest"),
            "allowlisted image must stay pinned"
        );
    }
}

#[test]
fn approved_scanner_specs_pass_the_policy() {
    for (scanner, _, spec) in approved_specs() {
        assert_eq!(spec.network, scanner.network);
        enforce_execution_policy(&spec).expect("approved run must be admitted");
    }
}

#[test]
fn approved_runs_keep_the_hardened_argv() {
    for (_, network, spec) in approved_specs() {
        let argv = docker_argv(&spec, "firecrow-phase-a-fixture");
        let set: HashSet<&str> = argv.iter().map(|s| s.as_str()).collect();
        assert!(set.contains("run"));
        assert!(set.contains("--rm"));
        assert!(set.contains("--read-only"));
        assert!(set.contains("--cap-drop=ALL"));
        assert!(set.contains("--user=65534:65534"));
        assert!(
            argv.iter().any(|a| *a == network.as_docker_arg()),
            "argv must carry the declared network"
        );
        assert_eq!(argv.first().map(|s| s.as_str()), Some("run"));
    }
}

// --- Policy: dangerous capabilities rejected --------------------------------

fn bare_spec(image: &str, network: NetworkMode) -> SandboxSpec {
    SandboxSpec::new(
        image,
        vec!["--version".to_string()],
        Vec::new(),
        60,
        ResourceLimits::default(),
    )
    .with_network(network)
    .with_entrypoint(Some("sh"))
}

#[test]
fn unapproved_images_are_rejected_even_when_pinned() {
    for image in [
        "alpine:3.19",
        "ghcr.io/gitleaks/gitleaks:latest",
        "gitleaks:v8.18.4",
        "",
    ] {
        assert!(
            enforce_execution_policy(&bare_spec(image, NetworkMode::None)).is_err(),
            "image {image:?} must not execute"
        );
    }
}

#[test]
fn network_escalation_outside_the_allowlist_is_rejected() {
    let (_, _, spec) = &approved_specs()[0];
    let mut escalated = spec.clone();
    escalated.network = NetworkMode::Bridge; // gitleaks was granted none
    assert!(enforce_execution_policy(&escalated).is_err());

    let (_, _, osv) = &approved_specs()[1];
    let mut reduced = osv.clone();
    reduced.network = NetworkMode::None; // pair must match exactly, both ways
    assert!(enforce_execution_policy(&reduced).is_err());
}

#[test]
fn nonstandard_entrypoints_are_rejected() {
    let (_, _, spec) = &approved_specs()[0];
    let mut evil = spec.clone();
    evil.entrypoint = Some("/bin/evil".into());
    assert!(enforce_execution_policy(&evil).is_err());
}

#[test]
fn sensitive_host_binds_are_rejected() {
    for host in [
        "/var/run/docker.sock",
        "/etc/passwd",
        "/root/.ssh/id_rsa",
        "/proc/self/environ",
        "/",
        "relative/snapshot",
    ] {
        let (_, _, spec) = &approved_specs()[0];
        let mut bound = spec.clone();
        bound.mounts.push(SandboxMount {
            host_path: host.into(),
            container_path: "/config".into(),
            read_only: true,
        });
        assert!(
            enforce_execution_policy(&bound).is_err(),
            "host path {host:?} must not be observable"
        );
    }
}

// --- DOCKER_HOST pass-through ------------------------------------------------

#[test]
fn docker_host_accepts_only_tcp_host_port_form() {
    use std::ffi::OsStr;
    // T1 (mTLS): the backend connects to the daemon's TLS listener.
    assert_eq!(
        validated_docker_host(OsStr::new("tcp://host.docker.internal:2376")).as_deref(),
        Some("tcp://host.docker.internal:2376")
    );
    // Legacy socket-proxy form (still accepted for backward compatibility).
    assert_eq!(
        validated_docker_host(OsStr::new("tcp://docker-socket-proxy:2375")).as_deref(),
        Some("tcp://docker-socket-proxy:2375")
    );
    for bad in [
        "",
        "unix:///var/run/docker.sock",
        "/var/run/docker.sock",
        "tcp://docker-socket-proxy",
        "tcp://docker-socket-proxy:0",
        "tcp://docker-socket-proxy:99999",
        "http://docker-socket-proxy:2375",
        "tcp://user@docker-socket-proxy:2375",
        "tcp://docker-socket-proxy:2375/path",
        "tcp://docker-socket-proxy:2375?x=1",
        "tcp://:2375",
        "tcp://proxy_host:2375",
    ] {
        assert!(
            validated_docker_host(OsStr::new(bad)).is_none(),
            "DOCKER_HOST {bad:?} must fail closed"
        );
    }
}

// --- FC-RELEASE-017 findings 5+7 -------------------------------------------

/// Both images must pre-create every workspace dir `ensure_workspace_dirs`
/// creates at boot. The Render image (`backend/Dockerfile`) once created
/// only one of the four, so a `read_only: true` run aborted with EROFS
/// before the app could create the rest itself.
#[test]
fn images_precreate_all_boot_workspace_dirs() {
    for rel in ["Dockerfile", "../Dockerfile"] {
        let text = std::fs::read_to_string(repo_path(&[rel])).expect("Dockerfile must be readable");
        for dir in [
            "/app/workspace/storage",
            "/app/workspace/reports",
            "/app/workspace/temp",
            "/app/workspace/scans",
        ] {
            assert!(
                text.contains(dir),
                "{rel} must pre-create {dir} (boot creates it; a read-only rootfs cannot)"
            );
        }
    }
}

/// `WORKSPACE_DIR` is a compile-time constant (`env!("CARGO_MANIFEST_DIR")`
/// in `config.rs`); shipping it as a runtime ENV invites operators to set a
/// value the binary silently ignores. Neither image may set it.
#[test]
fn images_set_no_dead_workspace_dir_env() {
    for rel in ["Dockerfile", "../Dockerfile"] {
        let text = std::fs::read_to_string(repo_path(&[rel])).expect("Dockerfile must be readable");
        assert!(
            !text.lines().map(str::trim).any(|l| l.starts_with("ENV WORKSPACE_DIR")),
            "{rel} must not set ENV WORKSPACE_DIR: config::WORKSPACE_DIR is compile-time, a runtime value would be a silent no-op"
        );
    }
}

/// FC-ZT-SEC-001 §4 (independent review): the retired `Bridge` mode approves
/// nothing, ever — not even the OSV image it once served. A coordinated
/// revert (constructor + allowlist both back to `Bridge`) must fail at the
/// policy gate, not just at the constructor assertions elsewhere.
#[test]
fn retired_bridge_mode_approves_no_scanner_at_all() {
    let (_, _, osv_spec) = &approved_specs()[1];
    for network in [NetworkMode::Bridge, NetworkMode::None] {
        let mut spec = osv_spec.clone();
        spec.network = network;
        assert!(
            enforce_execution_policy(&spec).is_err(),
            "OSV with {network:?} must be rejected: only Filtered is approved"
        );
    }
    let mut osv_filtered = osv_spec.clone();
    osv_filtered.network = NetworkMode::Filtered;
    assert!(
        enforce_execution_policy(&osv_filtered).is_ok(),
        "the approved OSV+Filtered pair must pass"
    );
}
