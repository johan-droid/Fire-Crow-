//! Phase 6 exit criterion: the hardened execution boundary.
//!
//! A scanner can read only the supplied snapshot (read-only `/scan`), has no
//! network/host privileges, is resource-bounded, and cannot turn
//! timeout/cancellation/resource failure into a clean result. Pure tests only:
//! no Docker, no network.

use firecrow_backend::agents::scanner::{classify, ScanInput, Scanner, ScannerOutcome};
use firecrow_backend::error::AppError;
use firecrow_backend::services::sandbox::{
    container_name, docker_argv, validate_pinned_image, validate_spec, NetworkMode, ResourceLimits,
    SandboxManager, SandboxMount, SandboxOutput, SandboxSpec, SCAN_MOUNT,
};
use std::collections::HashSet;

fn scanner() -> Scanner {
    Scanner::gitleaks()
}

fn input() -> ScanInput {
    ScanInput {
        source_dir: std::env::temp_dir().join("firecrow-phase6-fixture"),
        commit_sha: None,
        file_count: 1,
        total_size: 64,
    }
}

fn spec() -> SandboxSpec {
    input().sandbox_spec(&scanner())
}

fn ok(stdout: &str) -> Result<SandboxOutput, AppError> {
    Ok(SandboxOutput {
        stdout: stdout.to_string(),
        stderr: String::new(),
        success: true,
    })
}

// --- Isolation: read-only snapshot, no network/host privileges --------------

#[test]
fn snapshot_is_the_only_mount_and_it_is_read_only() {
    let mounts = input().mounts();
    assert_eq!(mounts.len(), 1);
    assert_eq!(mounts[0].container_path, SCAN_MOUNT);
    assert_eq!(mounts[0].container_path, "/scan");
    assert!(mounts[0].read_only);
    assert!(mounts[0].as_docker_spec().ends_with(":ro"));
}

#[test]
fn docker_argv_denies_network_privilege_and_host_root() {
    let argv = docker_argv(&spec(), "firecrow-scan-test");
    let set: HashSet<&str> = argv.iter().map(|s| s.as_str()).collect();
    for required in [
        "--rm",
        "--init",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user=65534:65534",
    ] {
        assert!(
            set.contains(required),
            "docker_argv missing {required}: {argv:?}"
        );
    }
    // Resource bounds travel with every run, swap pinned so `-m` holds.
    assert!(argv.iter().any(|a| a.starts_with("--cpus=")));
    assert!(argv.iter().any(|a| a.starts_with("-m=")));
    assert!(argv.iter().any(|a| a.starts_with("--memory-swap=")));
    assert!(argv.iter().any(|a| a.starts_with("--pids-limit=")));
    // Writable scratch is tmpfs, never a host bind mount.
    assert!(argv.iter().any(|a| a == "--tmpfs"));
    assert!(argv
        .iter()
        .any(|a| a.starts_with("/work:rw,noexec,nosuid,nodev")));
    // The snapshot mount is present and read-only.
    assert!(argv.iter().any(|a| a == "-v"));
    assert!(argv
        .iter()
        .any(|a| a.ends_with("/scan:ro") || *a == "/scan:ro"));
    // Privilege escalation / host access must never appear.
    for banned in [
        "--privileged",
        "--cap-add",
        "/var/run/docker.sock",
        "--network=host",
    ] {
        assert!(
            !argv.iter().any(|a| a.contains(banned)),
            "docker_argv must never contain {banned}: {argv:?}"
        );
    }
}

#[test]
fn command_is_argv_never_shell() {
    // A caller-supplied argv still passes through verbatim: metacharacters
    // carry no meaning without an entrypoint override.
    let mut s = spec();
    s.entrypoint = None;
    s.command = vec!["detect; rm -rf /".into(), "$(evil)".into(), "a|b".into()];
    let argv = docker_argv(&s, "n");
    let tail = &argv[argv.len() - 3..];
    assert_eq!(tail, &["detect; rm -rf /", "$(evil)", "a|b"]);
    assert!(!argv.iter().any(|a| a.starts_with("--entrypoint")));
}

#[test]
fn entrypoint_override_is_a_validated_binary_not_a_flag() {
    // The gitleaks file-artifact handshake needs `sh -c <fixed text>`; the
    // override travels as one `--entrypoint=` flag and untrusted bytes never
    // flow into the shell string (its paths are constants).
    let argv = docker_argv(&spec(), "n");
    assert!(argv.iter().any(|a| a == "--entrypoint=sh"), "{argv:?}");
    let ep_index = argv.iter().position(|a| a == "--entrypoint=sh").unwrap();
    let img_index = argv.iter().position(|a| a.contains("gitleaks")).unwrap();
    assert!(ep_index < img_index, "entrypoint is a run option: {argv:?}");
}

// --- Validation: bad specs fail before Docker is touched -------------------

// --- Network: deny-by-default with declared exceptions only -----------------

#[test]
fn network_is_denied_unless_a_scanner_declares_an_exception() {
    // The contract, in one place: a spec built without saying anything about
    // the network is fully isolated. Nothing can gain egress by omission.
    let spec = SandboxSpec::new(
        "ghcr.io/example/tool:v1.0.0",
        vec!["scan".into()],
        vec![SandboxMount {
            host_path: "/tmp/x".into(),
            container_path: SCAN_MOUNT.into(),
            read_only: true,
        }],
        60,
        ResourceLimits::default(),
    );
    assert_eq!(spec.network, NetworkMode::None);
    assert!(!spec.network.is_excepted());
    let argv = docker_argv(&spec, "n");
    assert!(
        argv.iter().any(|a| a == "--network=none"),
        "default must isolate: {argv:?}"
    );
    assert!(
        !argv
            .iter()
            .any(|a| a.contains("bridge") || a.contains("host")),
        "default must never reach a network: {argv:?}"
    );
}

#[test]
fn a_declared_exception_renders_bridge_never_host() {
    // `host` would expose the host's interfaces and metadata service. The
    // weakest exception that still works is `bridge`, and it is the only one
    // that exists.
    assert_eq!(NetworkMode::Bridge.as_docker_arg(), "--network=bridge");
    assert_eq!(NetworkMode::None.as_docker_arg(), "--network=none");
    assert_eq!(NetworkMode::Bridge.as_str(), "bridge");
    assert_eq!(NetworkMode::None.as_str(), "none");

    let mut s = spec();
    s.network = NetworkMode::Bridge;
    let argv = docker_argv(&s, "n");
    assert!(argv.iter().any(|a| a == "--network=bridge"));
    assert!(
        !argv.iter().any(|a| a == "--network=host"),
        "host networking must never be emitted: {argv:?}"
    );
    // The exception is the only thing that changes; every other boundary holds.
    let isolated = docker_argv(&spec(), "n");
    for flag in [
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user=65534:65534",
    ] {
        assert!(argv.contains(&flag.to_string()), "{flag} must still apply");
        assert!(isolated.contains(&flag.to_string()));
    }
}

#[test]
fn exactly_one_network_flag_is_emitted() {
    // Two contradictory network flags would make the effective mode depend on
    // Docker's parsing order.
    for network in [NetworkMode::None, NetworkMode::Bridge] {
        let mut s = spec();
        s.network = network;
        let argv = docker_argv(&s, "n");
        let flags: Vec<&str> = argv
            .iter()
            .map(|a| a.as_str())
            .filter(|a| a.starts_with("--network="))
            .collect();
        assert_eq!(flags, vec![network.as_docker_arg().as_str()]);
    }
}

#[test]
fn declared_environment_reaches_the_container_never_the_client() {
    // Environment is a validated `-e` flag inside the container's argv, not an
    // ambient variable on the client: a host variable cannot leak in, and a
    // scanner cannot receive anything the spec did not declare.
    let mut s = spec().with_env(&[("HOME", "/work")]);
    s.command = vec!["-c".into(), "echo hi".into()];
    let argv = docker_argv(&s, "n");
    let positions: Vec<usize> = argv
        .iter()
        .enumerate()
        .filter(|(_, a)| *a == "-e")
        .map(|(i, _)| i)
        .collect();
    assert_eq!(positions.len(), 1, "exactly one env declaration: {argv:?}");
    assert_eq!(argv[positions[0] + 1], "HOME=/work");
    // Before the image, with everything else: it travels with the sandbox,
    // not around it.
    let image = argv
        .iter()
        .position(|a| a.contains("semgrep") || a.contains("gitleaks") || a.contains("osv"))
        .or_else(|| {
            argv.iter()
                .position(|a| a == "scan" || a == "-c" || a == "detect")
        });
    let image = image.expect("command must follow the image");
    assert!(positions[0] < image, "env must precede the image: {argv:?}");
}

#[test]
fn malformed_environment_is_rejected_without_running() {
    for (name, value) in [
        ("", "x"),
        ("BAD NAME", "x"),
        ("-e", "x"),
        (
            "HOME
PATH",
            "x",
        ),
        (
            "HOME", "a
b",
        ),
        ("HOME", "a b"),
    ] {
        let mut s = spec();
        s.env = vec![(name.into(), value.into())];
        let err = validate_spec(&s).unwrap_err();
        assert!(
            matches!(err, AppError::BadRequest(_)),
            "env ({name:?}, {value:?}) must be BadRequest: {err:?}"
        );
    }
    let mut s = spec();
    s.env = vec![("HOME".into(), "/work".into())];
    validate_spec(&s).expect("a plain identifier must validate");
}

#[test]
fn flag_shaped_entrypoint_is_rejected_without_running() {
    for bad in ["--privileged", "", "sh -c evil", "sh\ncat"] {
        let mut s = spec();
        s.entrypoint = Some(bad.into());
        let err = validate_spec(&s).unwrap_err();
        assert!(
            matches!(err, AppError::BadRequest(_)),
            "bad entrypoint {bad:?} must be BadRequest: {err:?}"
        );
    }
    // The scanner's own override validates clean.
    validate_spec(&spec()).expect("the pinned sh override must validate");
}

#[tokio::test]
async fn writable_or_misplaced_mount_is_rejected_before_execution() {
    let sandbox = SandboxManager::new();
    for mounts in [
        vec![SandboxMount {
            host_path: "/tmp/x".into(),
            container_path: SCAN_MOUNT.into(),
            read_only: false,
        }],
        vec![SandboxMount {
            host_path: "/tmp/x".into(),
            container_path: "/work".into(),
            read_only: true,
        }],
        vec![SandboxMount {
            host_path: "/tmp/a:/tmp/b".into(),
            container_path: SCAN_MOUNT.into(),
            read_only: true,
        }],
    ] {
        let mut s = spec();
        s.mounts = mounts;
        let err = sandbox.run(&s, &|| false).await.unwrap_err();
        assert!(
            matches!(err, AppError::BadRequest(_)),
            "bad mount must be BadRequest: {err:?}"
        );
    }
}

#[tokio::test]
async fn unbounded_resources_and_timeouts_are_rejected() {
    let sandbox = SandboxManager::new();
    let mut bad_limits = [
        ResourceLimits {
            cpus: 0.0,
            ..ResourceLimits::default()
        },
        ResourceLimits {
            cpus: 64.0,
            ..ResourceLimits::default()
        },
        ResourceLimits {
            memory: "512".into(),
            ..ResourceLimits::default()
        },
        ResourceLimits {
            memory: "0m".into(),
            ..ResourceLimits::default()
        },
        ResourceLimits {
            pids_limit: 0,
            ..ResourceLimits::default()
        },
    ];
    for limits in bad_limits.iter_mut() {
        let mut s = spec();
        s.limits = limits.clone();
        let err = sandbox.run(&s, &|| false).await.unwrap_err();
        assert!(
            matches!(err, AppError::BadRequest(_)),
            "bad limits must fail: {err:?}"
        );
    }
    for timeout in [0u64, 999_999u64] {
        let mut s = spec();
        s.timeout_secs = timeout;
        let err = sandbox.run(&s, &|| false).await.unwrap_err();
        assert!(
            matches!(err, AppError::BadRequest(_)),
            "bad timeout must fail: {err:?}"
        );
    }
}

#[test]
fn unpinned_or_flag_shaped_images_are_rejected() {
    for bad in [
        "gitleaks",
        "img:latest",
        "",
        "--privileged",
        "alpine:3.19 --evil",
        "img:a\nb",
    ] {
        assert!(validate_pinned_image(bad).is_err(), "must reject {bad:?}");
    }
    assert!(validate_pinned_image("ghcr.io/gitleaks/gitleaks:v8.18.4").is_ok());
}

#[test]
fn container_names_are_unique() {
    assert_ne!(container_name(), container_name());
}

// --- Failure is never a clean result ----------------------------------------

#[test]
fn timeout_cancel_and_output_flood_are_never_success() {
    let s = scanner();
    let i = input();
    let timeout = classify(&s, &i, Err(AppError::Timeout("t".into())));
    assert!(matches!(timeout.outcome, ScannerOutcome::Timeout { .. }));
    assert!(!timeout.usable() && !timeout.analyzed());

    let cancelled = classify(&s, &i, Err(AppError::Cancelled("c".into())));
    assert_eq!(cancelled.outcome, ScannerOutcome::Cancelled);
    assert!(!cancelled.usable() && !cancelled.analyzed());

    let flooded = classify(
        &s,
        &i,
        Err(AppError::OutputLimitExceeded {
            stream: "stdout".into(),
            cap_bytes: 8,
        }),
    );
    assert!(matches!(flooded.outcome, ScannerOutcome::Failed { .. }));
    assert!(!flooded.usable() && !flooded.analyzed());
    assert!(flooded.execution_record.get("finding_count").is_none());

    // Only an empty *successful* report means zero findings.
    let clean = classify(&s, &i, ok("[]"));
    assert_eq!(clean.outcome, ScannerOutcome::Success { finding_count: 0 });
    assert!(clean.usable());
}
