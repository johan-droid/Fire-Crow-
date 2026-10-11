//! V3 regression tests (offline): OSV egress *enforcement*, not just policy.
//!
//! `osv_egress_policy.rs` proves the pure policy functions return the right
//! decisions. This file proves the runtime refuses unfettered egress: no
//! proxy (or a malformed one) means the dependency scan reports failure with
//! zero findings *before Docker is touched*, and a configured proxy is the
//! only network configuration the container can see.
//!
//! No database, no network, no Docker: the fail-closed gate returns before
//! any container exists. Process-environment mutations are serialized with
//! `ENV_LOCK` and restored afterwards.

use firecrow_backend::agents::scanner::{run_dependency_scan, ScanInput, Scanner};
use firecrow_backend::services::egress_policy::resolve_osv_egress_proxy;
use firecrow_backend::services::sandbox::{docker_argv, SandboxManager};

static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct EnvGuard {
    key: &'static str,
    previous: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, value: Option<&str>) -> Self {
        let previous = std::env::var(key).ok();
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        Self { key, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(v) => std::env::set_var(self.key, v),
            None => std::env::remove_var(self.key),
        }
    }
}

/// V3: without `OSV_EGRESS_PROXY` the resolver fails closed.
#[test]
fn missing_proxy_fails_closed() {
    let _lock = ENV_LOCK.lock().unwrap();
    let _env = EnvGuard::set("OSV_EGRESS_PROXY", None);
    assert!(
        resolve_osv_egress_proxy().is_err(),
        "missing proxy must fail closed"
    );
}

/// V3: malformed proxy values fail closed rather than degrading to direct
/// egress or a half-configured container.
#[test]
fn malformed_proxy_fails_closed() {
    let _lock = ENV_LOCK.lock().unwrap();
    for bad in [
        "",
        "   ",
        "gopher://proxy:70",
        "http://",
        "http://user:pass@proxy:3128",
        "http://proxy:3128/extra-path",
        "not a url at all",
    ] {
        let _env = EnvGuard::set("OSV_EGRESS_PROXY", Some(bad));
        assert!(
            resolve_osv_egress_proxy().is_err(),
            "proxy value {bad:?} must fail closed"
        );
    }
}

/// A well-formed proxy resolves to its normalized form.
#[test]
fn valid_proxy_resolves() {
    let _lock = ENV_LOCK.lock().unwrap();
    let _env = EnvGuard::set("OSV_EGRESS_PROXY", Some("http://egress-proxy:3128"));
    assert_eq!(
        resolve_osv_egress_proxy().expect("valid proxy resolves"),
        "http://egress-proxy:3128"
    );
}

/// V3: the dependency scan without a proxy is `Failed` with zero findings —
/// unknown coverage, never "clean" — and Docker is never touched (this test
/// has no Docker and still passes because the gate returns first).
#[tokio::test]
async fn dependency_scan_without_proxy_fails_closed_before_docker() {
    let _lock = ENV_LOCK.lock().unwrap();
    let _env = EnvGuard::set("OSV_EGRESS_PROXY", None);
    let input = ScanInput::from_dir(&std::env::temp_dir());
    let sandbox = SandboxManager::new();
    let result = run_dependency_scan(&input, &sandbox, &|| false).await;
    assert!(
        !result.outcome.is_success(),
        "unproxied OSV run must not succeed"
    );
    assert!(
        result.findings.is_empty(),
        "a refused run must carry zero findings"
    );
    match &result.outcome {
        firecrow_backend::agents::scanner::ScannerOutcome::Failed { reason } => {
            assert!(
                reason.contains("egress proxy"),
                "refusal must name the missing boundary, got: {reason}"
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

/// V3: with a proxy, the scanner's container environment carries exactly the
/// four proxy variables (upper- and lowercase, for Go's lookup order) and no
/// `NO_PROXY` bypass — so redirects and every other destination go through
/// the filter too.
#[test]
fn proxied_scanner_env_is_exact() {
    let _lock = ENV_LOCK.lock().unwrap();
    let _env = EnvGuard::set("OSV_EGRESS_PROXY", Some("http://egress-proxy:3128"));
    let scanner = Scanner::osv_with_proxy("http://egress-proxy:3128");
    for name in ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"] {
        assert!(
            scanner
                .env
                .iter()
                .any(|(k, v)| k == name && v == "http://egress-proxy:3128"),
            "container env must pin {name} to the filtering proxy"
        );
    }
    assert!(
        !scanner
            .env
            .iter()
            .any(|(k, _)| k == "NO_PROXY" || k == "no_proxy"),
        " container env must not contain a NO_PROXY bypass"
    );
    // The boundary survives to the real Docker invocation.
    let input = ScanInput::from_dir(&std::env::temp_dir());
    let argv = docker_argv(&input.sandbox_spec(&scanner), "osv-egress-test");
    assert!(
        argv.contains(&"--network=bridge".to_string()),
        "OSV still uses bridge to reach its proxy: {argv:?}"
    );
    assert!(
        argv.contains(&"HTTPS_PROXY=http://egress-proxy:3128".to_string()),
        "proxy must reach the container argv: {argv:?}"
    );
}

/// Ambient `HTTPS_PROXY`/`HTTP_PROXY` (or a direct `OSV_EGRESS_PROXY`
/// bypass attempt via lowercase smuggling) never leaks into the container:
/// the only source is the validated operator variable.
#[test]
fn ambient_proxy_vars_never_leak_into_the_container() {
    let _lock = ENV_LOCK.lock().unwrap();
    let _ambient_https = EnvGuard::set("HTTPS_PROXY", Some("http://evil:9"));
    let _ambient_http = EnvGuard::set("HTTP_PROXY", Some("http://evil:9"));
    let _ambient_lower = EnvGuard::set("https_proxy", Some("http://evil:9"));
    let _osv = EnvGuard::set("OSV_EGRESS_PROXY", None);

    let scanner = Scanner::osv();
    assert!(
        scanner.env.is_empty(),
        "without a valid operator proxy the container gets no proxy env: {:?}",
        scanner.env
    );
    assert!(
        !scanner.env.iter().any(|(_, v)| v.contains("evil")),
        "ambient attacker-influenced values must not reach the container"
    );
}
