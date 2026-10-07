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
        (Scanner::osv(), NetworkMode::Bridge),
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

/// A real YAML key line, ignoring comments (which may legitimately name keys).
fn has_yaml_key(block: &str, key: &str) -> bool {
    block.lines().any(|l| {
        let t = l.trim_start();
        !t.starts_with('#') && t.starts_with(key)
    })
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
    assert!(
        block.contains("DOCKER_HOST") && block.contains("docker-socket-proxy:2375"),
        "backend must reach Docker only via the proxy:\n{block}"
    );
}

#[test]
fn socket_proxy_is_the_sole_pinned_filtered_holder() {
    let text = compose_text();
    assert_eq!(
        text.lines().filter(|l| l.contains("docker.sock")).count(),
        1,
        "exactly one socket mount line may exist (the proxy's)"
    );
    let block = service_block(&text, "docker-socket-proxy");
    assert!(
        block.contains("/var/run/docker.sock"),
        "proxy must hold the socket:\n{block}"
    );
    assert!(
        block.contains("tecnativa/docker-socket-proxy:v") && !block.contains(":latest"),
        "proxy image must be pinned, never :latest:\n{block}"
    );
    for denied in [
        "EXEC: 0",
        "NETWORKS: 0",
        "VOLUMES: 0",
        "BUILD: 0",
        "SYSTEM: 0",
        "SWARM: 0",
    ] {
        assert!(block.contains(denied), "proxy must deny {denied}:\n{block}");
    }
    assert!(
        block.contains("CONTAINERS: 1") && block.contains("IMAGES: 1"),
        "proxy must allow only run/pull categories:\n{block}"
    );
    assert!(
        block.contains("POST: 1"),
        "proxy must allow non-GET methods or even container creation is refused:\n{block}"
    );
    assert!(
        !has_yaml_key(&block, "ports:"),
        "proxy port must never be host-published:\n{block}"
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
        (Scanner::osv(), NetworkMode::Bridge),
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
