//! Phase C (H2) test suite: OSV scanner network egress hardening.
//!
//! Asserts that:
//! 1. Approved OSV domains (`api.osv.dev`, `osv.dev`) on port 443 are allowed.
//! 2. Cloud instance metadata (`169.254.169.254`, link-local) is blocked.
//! 3. Loopback (`127.0.0.1`, `::1`, `localhost`) is blocked.
//! 4. Private networks (RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) are blocked.
//! 5. Arbitrary external destinations (`attacker.com`, etc.) are blocked.
//! 6. Non-standard ports (anything other than 443 and 53) are blocked.
//! 7. `Scanner::osv()` injects the egress proxy configuration when `OSV_EGRESS_PROXY` is set.

use firecrow_backend::agents::scanner::Scanner;
use firecrow_backend::services::egress_policy::{
    evaluate_egress_target, evaluate_ip, validate_osv_proxy_url, EgressDecision,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn approved_osv_destination_is_allowed() {
    assert_eq!(
        evaluate_egress_target("api.osv.dev", 443),
        EgressDecision::Allow
    );
    assert_eq!(
        evaluate_egress_target("osv.dev", 443),
        EgressDecision::Allow
    );
}

#[test]
fn cloud_metadata_is_blocked() {
    let metadata_ip: IpAddr = "169.254.169.254".parse().unwrap();
    assert!(matches!(evaluate_ip(metadata_ip), EgressDecision::Block(_)));

    assert!(matches!(
        evaluate_egress_target("169.254.169.254", 443),
        EgressDecision::Block(_)
    ));
}

#[test]
fn localhost_and_loopback_are_blocked() {
    let loopback_v4: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
    let loopback_v6: IpAddr = Ipv6Addr::LOCALHOST.into();
    assert!(matches!(evaluate_ip(loopback_v4), EgressDecision::Block(_)));
    assert!(matches!(evaluate_ip(loopback_v6), EgressDecision::Block(_)));

    assert!(matches!(
        evaluate_egress_target("127.0.0.1", 443),
        EgressDecision::Block(_)
    ));
    assert!(matches!(
        evaluate_egress_target("localhost", 443),
        EgressDecision::Block(_)
    ));
}

#[test]
fn private_rfc1918_networks_are_blocked() {
    for ip_str in ["10.0.0.1", "172.16.0.1", "192.168.1.100"] {
        let ip: IpAddr = ip_str.parse().unwrap();
        assert!(
            matches!(evaluate_ip(ip), EgressDecision::Block(_)),
            "IP {ip_str} should be blocked"
        );
        assert!(
            matches!(
                evaluate_egress_target(ip_str, 443),
                EgressDecision::Block(_)
            ),
            "Target {ip_str}:443 should be blocked"
        );
    }
}

#[test]
fn arbitrary_external_destinations_are_blocked() {
    for host in ["evil.attacker.com", "exfil.io", "google.com", "github.com"] {
        assert!(
            matches!(evaluate_egress_target(host, 443), EgressDecision::Block(_)),
            "Host {host} should be blocked"
        );
    }
}

#[test]
fn non_standard_ports_are_blocked() {
    assert!(matches!(
        evaluate_egress_target("api.osv.dev", 80),
        EgressDecision::Block(_)
    ));
    assert!(matches!(
        evaluate_egress_target("api.osv.dev", 8080),
        EgressDecision::Block(_)
    ));
    assert!(matches!(
        evaluate_egress_target("api.osv.dev", 22),
        EgressDecision::Block(_)
    ));
}

/// V3: alternative IP spellings must be judged as the address they denote,
/// not as hostnames. `0x7f.0.0.1`, `2130706433`, and `0177.0.0.1` are all
/// 127.0.0.1 and must carry the loopback reason, not merely fail the
/// allowlist.
#[test]
fn alternative_ip_spellings_are_canonicalized_then_blocked() {
    for host in [
        "0x7f.0.0.1",
        "0X7F.0.0.1",
        "2130706433",
        "0x7f000001",
        "0177.0.0.1",
        "0x0a.0.0.1",
        "167772161",
    ] {
        assert!(
            matches!(evaluate_egress_target(host, 443), EgressDecision::Block(_)),
            "alt-form IP {host} must be blocked"
        );
    }
    // The loopback reason specifically, proving canonicalization ran.
    assert_eq!(
        evaluate_egress_target("0x7f.0.0.1", 443),
        EgressDecision::Block("loopback blocked")
    );
    assert_eq!(
        evaluate_egress_target("2130706433", 443),
        EgressDecision::Block("loopback blocked")
    );
    assert_eq!(
        evaluate_egress_target("0x0a.0.0.1", 443),
        EgressDecision::Block("RFC1918 private network blocked")
    );
}

/// V3: authority-smuggling spellings (`user@host`, `host:port`, paths,
/// brackets, whitespace) never reach the allowlist comparison.
#[test]
fn authority_smuggling_is_blocked() {
    for host in [
        "evil.com@api.osv.dev",
        "api.osv.dev:443",
        "api.osv.dev/path",
        "[::1]",
        // Inner whitespace is smuggling; leading/trailing whitespace is
        // trimmed before comparison (see below), so it is not listed here.
        "api osv.dev",
    ] {
        assert!(
            matches!(evaluate_egress_target(host, 443), EgressDecision::Block(_)),
            "smuggled host {host:?} must be blocked"
        );
    }
    // A trailing dot is the same FQDN, not smuggling: still allowed.
    assert_eq!(
        evaluate_egress_target("api.osv.dev.", 443),
        EgressDecision::Allow
    );
}

/// V3: redirect targets are evaluated with the same rule — a redirect from
/// an allowlisted host to anywhere else is `Block`, which is what the
/// filtering proxy must enforce for every CONNECT, not just the first one.
#[test]
fn redirect_targets_use_the_same_policy() {
    assert_eq!(
        evaluate_egress_target("api.osv.dev", 443),
        EgressDecision::Allow
    );
    for redirected in [
        "evil.attacker.com",
        "169.254.169.254",
        "10.0.0.1",
        "0x7f.0.0.1",
        "storage.googleapis.com",
    ] {
        assert!(
            matches!(
                evaluate_egress_target(redirected, 443),
                EgressDecision::Block(_)
            ),
            "redirect target {redirected} must be blocked"
        );
    }
}

/// V3: IPv6 ranges beyond loopback/unspecified — link-local, unique-local,
/// multicast, and documentation — are blocked.
#[test]
fn ipv6_scopes_are_blocked() {
    for host in [
        "fe80::1",
        "fc00::1",
        "fd00::1",
        "ff02::1",
        "2001:db8::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:169.254.169.254",
    ] {
        assert!(
            matches!(evaluate_egress_target(host, 443), EgressDecision::Block(_)),
            "IPv6 host {host} must be blocked"
        );
    }
}

/// V3: reserved IPv4 ranges — software-scope 0/8 and documentation nets.
#[test]
fn reserved_ipv4_ranges_are_blocked() {
    for host in ["0.1.2.3", "192.0.2.1", "198.51.100.7", "203.0.113.9"] {
        assert!(
            matches!(evaluate_egress_target(host, 443), EgressDecision::Block(_)),
            "reserved IP {host} must be blocked"
        );
    }
}

/// V3: proxy configuration validation — shape only (the proxy host is
/// operator infrastructure and may be internal), but strict about scheme,
/// credentials, and smuggling.
#[test]
fn proxy_url_validation_is_strict_about_shape() {
    assert_eq!(
        validate_osv_proxy_url("http://egress-proxy:3128"),
        Ok("http://egress-proxy:3128".into())
    );
    assert_eq!(
        validate_osv_proxy_url("https://proxy.internal:8080"),
        Ok("https://proxy.internal:8080".into())
    );
    // Internal proxy hosts are legitimate operator infrastructure.
    assert!(validate_osv_proxy_url("http://10.0.0.5:3128").is_ok());
    for bad in [
        "",
        "   ",
        "gopher://proxy:70",
        "ftp://proxy:21",
        "http://",
        "://no-scheme",
        "http://user:pass@proxy:3128",
        "http://user@proxy:3128",
        "http://proxy:3128/path",
        "http://proxy:3128\nX-Injected: 1",
        "http://pro xy:3128",
    ] {
        assert!(
            validate_osv_proxy_url(bad).is_err(),
            "proxy URL {bad:?} must be rejected"
        );
    }
}

#[test]
fn osv_scanner_injects_egress_proxy_env() {
    std::env::set_var("OSV_EGRESS_PROXY", "http://egress-proxy:3128");
    let scanner = Scanner::osv();
    assert!(
        scanner
            .env
            .iter()
            .any(|(k, v)| k == "HTTPS_PROXY" && v == "http://egress-proxy:3128"),
        "Scanner::osv() must forward HTTPS_PROXY from OSV_EGRESS_PROXY"
    );
    assert!(
        scanner
            .env
            .iter()
            .any(|(k, v)| k == "HTTP_PROXY" && v == "http://egress-proxy:3128"),
        "Scanner::osv() must forward HTTP_PROXY from OSV_EGRESS_PROXY"
    );
    std::env::remove_var("OSV_EGRESS_PROXY");
}
