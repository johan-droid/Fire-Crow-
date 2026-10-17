//! Engine tests for the FireCrow authorization plugin.
//!
//! Fixtures under `tests/fixtures/` are real daemon→plugin wire payloads
//! captured from the FC-ZT-SEC-002 evidence bundles (versioned + unversioned,
//! both URI spellings, visible and invisible bodies, distinct identities).
//! Synthetic cases cover the rest of the frozen matrix and the drift/malformed
//! corpus. Every case asserts the exact rule id, not just allow/deny.

use docker_authz_plugin::{parse_request, Plugin, APPROVED_IMAGES};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::PathBuf;

fn plugin() -> Plugin {
    let log = std::env::temp_dir().join(format!(
        "firecrow-authz-engine-{}.jsonl",
        std::process::id()
    ));
    let mut cns = HashSet::new();
    cns.insert("firecrow-backend".to_string());
    Plugin::new(cns, log.to_str().unwrap())
}

fn fixture(name: &str) -> Value {
    let mut p: PathBuf = std::env::current_exe().unwrap();
    p.pop(); // deps
    p.pop(); // target/<profile>
    p.pop(); // target? no: current_exe = target/release/deps/... → pop deps, pop release? handle both
             // Robust approach: walk up until we find tests/fixtures
    let mut dir = std::env::current_exe().unwrap();
    while dir.pop() {
        let cand = dir
            .join("tests")
            .join("fixtures")
            .join(format!("{name}.json"));
        if cand.exists() {
            let text = std::fs::read_to_string(cand).unwrap();
            return serde_json::from_str(&text).unwrap();
        }
    }
    panic!("fixture {name} not found");
}

fn req(json: &str) -> docker_authz_plugin::AuthzRequest {
    let v: Value = serde_json::from_str(json).unwrap();
    parse_request(&v).expect("fixture must parse")
}

fn deny_rule(json: &str) -> &'static str {
    let v: Value = serde_json::from_str(json).unwrap();
    match parse_request(&v) {
        Err(reason) => reason,
        Ok(parsed) => {
            let d = plugin().decide(&parsed);
            assert!(!d.allow, "expected deny, got allow ({})", d.rule);
            d.rule
        }
    }
}

fn allow_rule(json: &str) -> &'static str {
    let v: Value = serde_json::from_str(json).unwrap();
    let parsed = parse_request(&v).expect("must parse");
    let d = plugin().decide(&parsed);
    assert!(d.allow, "expected allow, got deny ({})", d.rule);
    d.rule
}

fn b64(s: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    for chunk in s.as_bytes().chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 63) as usize]);
        out.push(TABLE[((n >> 12) & 63) as usize]);
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 63) as usize]);
        } else {
            out.push(b'=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 63) as usize]);
        } else {
            out.push(b'=');
        }
    }
    String::from_utf8(out).unwrap()
}

const TLS: &str = r#""UserAuthNMethod":"TLS","User":"firecrow-backend""#;

fn create_body(extra: &str) -> String {
    format!(r#"{{"Image":"ghcr.io/gitleaks/gitleaks:v8.18.4","Cmd":["true"]{extra}}}"#)
}

/// The full compliant scanner spec (every field the frozen matrix requires).
/// ReadonlyRootfs lives in HostConfig (the daemon's canonical location,
/// confirmed by the real CLI wire capture).
fn compliant_body() -> String {
    create_body(
        r#","User":"65534:65534","HostConfig":{"CapDrop":["ALL"],"NetworkMode":"none","SecurityOpt":["no-new-privileges:true"],"Tmpfs":{"/work":"rw,noexec,nosuid,nodev,size=64m"},"Binds":["/tmp/staging-xyz:/scan:ro"],"ReadonlyRootfs":true}"#,
    )
}

/// A fixed scanner UUID suffix used across synthetic cases.
const SCAN_ID: &str = "9f8a4b6c-1234-4abc-8def-0123456789ab";

fn create_req(uri_suffix: &str, body: &str) -> String {
    format!(
        r#"{{"RequestMethod":"POST","RequestUri":"/v1.52/containers/create?name=firecrow-scan-{SCAN_ID}{uri_suffix}",{TLS},"RequestBody":"{}"}}"#,
        b64(body)
    )
}

// ---------------------------------------------------------------------------
// Real wire payloads (captured from the evidence bundles)
// ---------------------------------------------------------------------------

#[test]
fn fixture_create_benign_json_is_denied_name_not_scanner_scoped() {
    // Real payload from the t1 harness: name `t1-benign` is not a
    // firecrow-scan-* name, so the name check denies before anything else.
    let v = fixture("create_benign_json");
    let parsed = parse_request(&v).unwrap();
    let d = plugin().decide(&parsed);
    assert!(!d.allow);
    assert_eq!(d.rule, "create-name");
}

#[test]
fn fixture_create_privileged_is_denied() {
    // Real payload from the t1 harness: name `t1-priv` trips the name check
    // before the Privileged field is ever reached. The privileged deny
    // itself is proven synthetically below and live in the dind harness.
    let v = fixture("create_privileged");
    let parsed = parse_request(&v).unwrap();
    let d = plugin().decide(&parsed);
    assert!(!d.allow);
    assert_eq!(d.rule, "create-name");
}

#[test]
fn fixture_create_text_plain_body_invisible_is_denied() {
    // Content-Type was text/plain: the daemon forwarded no body (R-a).
    let v = fixture("create_text_plain");
    let parsed = parse_request(&v).unwrap();
    assert!(parsed.body.is_none());
    let d = plugin().decide(&parsed);
    assert!(!d.allow);
    assert_eq!(d.rule, "create-body-required");
}

#[test]
fn fixture_create_no_content_type_body_invisible_is_denied() {
    let v = fixture("create_no_ct");
    let parsed = parse_request(&v).unwrap();
    assert!(parsed.body.is_none());
    let d = plugin().decide(&parsed);
    assert!(!d.allow);
    assert_eq!(d.rule, "create-body-required");
}

#[test]
fn fixture_update_on_socket_channel_is_denied_identity_required() {
    // Gap 9: captured from the non-TLS harness (no identity fields). The
    // strict channel denies identity-less requests; there is no implicit
    // local-admin allow inside this engine.
    let v = fixture("update");
    let parsed = parse_request(&v).unwrap();
    assert!(parsed.user.is_none() && parsed.user_authn.is_none());
    let d = plugin().decide(&parsed);
    assert!(!d.allow);
    assert_eq!(d.rule, "identity-required");
}

#[test]
fn fixture_archive_put_on_socket_channel_is_denied_identity_required() {
    let v = fixture("archive_put");
    let parsed = parse_request(&v).unwrap();
    let d = plugin().decide(&parsed);
    assert!(!d.allow);
    assert_eq!(d.rule, "identity-required");
}

#[test]
fn fixture_images_load_is_denied() {
    let v = fixture("images_load");
    let parsed = parse_request(&v).unwrap();
    let d = plugin().decide(&parsed);
    assert!(!d.allow);
    assert_eq!(d.rule, "endpoint-denied");
}

#[test]
fn fixture_grpc_is_denied() {
    let v = fixture("grpc_plain");
    let parsed = parse_request(&v).unwrap();
    let d = plugin().decide(&parsed);
    assert!(!d.allow);
    assert_eq!(d.rule, "grpc-door");
}

#[test]
fn fixture_pull_unapproved_image_is_denied() {
    // Real payload from the t1b harness: the harness pulled `alpine`, which is
    // NOT one of the three approved scanner refs => pull allowlist denies.
    let v = fixture("pull");
    let parsed = parse_request(&v).unwrap();
    let d = plugin().decide(&parsed);
    assert!(!d.allow);
    assert_eq!(d.rule, "pull-image");
}

#[test]
fn fixture_other_admin_cn_is_denied() {
    let v = fixture("other_admin");
    let parsed = parse_request(&v).unwrap();
    let d = plugin().decide(&parsed);
    assert!(!d.allow);
    assert_eq!(d.rule, "identity-not-allowed");
}

#[test]
fn fixture_socket_client_is_denied_identity_required() {
    // Gap 9: socket-client capture carries no TLS identity; strict channel
    // denies rather than applying an implicit local-admin allow.
    let v = fixture("socket_client");
    let parsed = parse_request(&v).unwrap();
    let d = plugin().decide(&parsed);
    assert!(!d.allow);
    assert_eq!(d.rule, "identity-required");
}

// ---------------------------------------------------------------------------
// Protocol drift and malformed payloads (R-a/R-b/R-c)
// ---------------------------------------------------------------------------

#[test]
fn requesturi_docs_spelling_is_accepted() {
    // The published docs say RequestURI; the wire says RequestUri (M11).
    let json = format!(r#"{{"RequestMethod":"GET","RequestURI":"/version",{TLS}}}"#);
    assert_eq!(allow_rule(&json), "negotiation");
}

#[test]
fn missing_uri_is_denied() {
    assert_eq!(
        deny_rule(r#"{"RequestMethod":"GET","UserAuthNMethod":"TLS","User":"firecrow-backend"}"#),
        "uri-missing"
    );
}

#[test]
fn empty_uri_is_denied() {
    assert_eq!(
        deny_rule(&format!(
            r#"{{"RequestMethod":"GET","RequestUri":"",{TLS}}}"#
        )),
        "uri-missing"
    );
}

#[test]
fn non_object_payload_is_denied() {
    assert_eq!(deny_rule("[1,2,3]"), "payload-not-object");
    assert_eq!(deny_rule("null"), "payload-not-object");
    assert_eq!(deny_rule("\"x\""), "payload-not-object");
}

#[test]
fn malformed_base64_body_is_denied() {
    let json = format!(
        r#"{{"RequestMethod":"POST","RequestUri":"/containers/create?name=firecrow-scan-a",{TLS},"RequestBody":"!!!not-base64!!!"}}"#
    );
    assert_eq!(deny_rule(&json), "body-undecodable");
}

#[test]
fn oversize_body_is_denied() {
    let big = "x".repeat(9 * 1024 * 1024);
    let json = format!(
        r#"{{"RequestMethod":"POST","RequestUri":"/containers/create?name=firecrow-scan-a",{TLS},"RequestBody":"{}"}}"#,
        b64(&big)
    );
    assert_eq!(deny_rule(&json), "body-too-large");
}

#[test]
fn unknown_extra_fields_are_tolerated() {
    let json = format!(
        r#"{{"RequestMethod":"GET","RequestUri":"/version",{TLS},"SomethingNew":{{"nested":[1]}},"Another":42}}"#
    );
    assert_eq!(allow_rule(&json), "negotiation");
}

#[test]
fn missing_method_is_denied() {
    assert_eq!(
        deny_rule(&format!(r#"{{"RequestUri":"/version",{TLS}}}"#)),
        "method-missing"
    );
}

// ---------------------------------------------------------------------------
// Identity binding
// ---------------------------------------------------------------------------

#[test]
fn no_identity_is_denied() {
    // Gap 9: absent identity never defaults to allow on the strict channel.
    assert_eq!(
        deny_rule(r#"{"RequestMethod":"GET","RequestUri":"/version"}"#),
        "identity-required"
    );
}

#[test]
fn tls_authn_with_empty_user_is_denied() {
    assert_eq!(
        deny_rule(
            r#"{"RequestMethod":"GET","RequestUri":"/version","UserAuthNMethod":"TLS","User":""}"#
        ),
        "identity-required"
    );
}

#[test]
fn non_tls_authn_method_is_denied() {
    assert_eq!(
        deny_rule(
            r#"{"RequestMethod":"GET","RequestUri":"/version","UserAuthNMethod":"basic","User":"firecrow-backend"}"#
        ),
        "identity-required"
    );
}

#[test]
fn forged_identity_headers_are_ignored() {
    // Caller-supplied identity claims must never influence the decision.
    let json = r#"{"RequestMethod":"GET","RequestUri":"/version","UserAuthNMethod":"TLS","User":"other-admin","RequestHeaders":{"X-Forwarded-User":"firecrow-backend","X-Auth-User":"firecrow-backend","Authorization":"Bearer firecrow-backend"}}"#;
    assert_eq!(deny_rule(json), "identity-not-allowed");
}

#[test]
fn unknown_cn_is_denied() {
    let json = r#"{"RequestMethod":"GET","RequestUri":"/version","UserAuthNMethod":"TLS","User":"some-other-service"}"#;
    assert_eq!(deny_rule(json), "identity-not-allowed");
}

// ---------------------------------------------------------------------------
// Versioned / unversioned equivalence (M5)
// ---------------------------------------------------------------------------

#[test]
fn unversioned_benign_create_is_allowed() {
    let body = compliant_body();
    let json = create_req("", &body);
    let json = json.replace("/v1.52/", "/");
    assert_eq!(allow_rule(&json), "create-allowed");
}

#[test]
fn unversioned_privileged_create_is_denied() {
    let json = create_req("", &create_body(r#","HostConfig":{"Privileged":true}"#));
    let json = json.replace("/v1.52/", "/");
    assert_eq!(deny_rule(&json), "create-privileged");
}

#[test]
fn versioned_grpc_is_denied() {
    let json = format!(r#"{{"RequestMethod":"POST","RequestUri":"/v1.52/grpc",{TLS}}}"#);
    assert_eq!(deny_rule(&json), "grpc-door");
}

#[test]
fn unversioned_grpc_is_denied() {
    let json = format!(r#"{{"RequestMethod":"POST","RequestUri":"/grpc",{TLS}}}"#);
    assert_eq!(deny_rule(&json), "grpc-door");
}

#[test]
fn versioned_pull_is_allowed() {
    // Gap 7: an embedded tag and a `tag` parameter must agree; a bare
    // fromImage ref without tag must be exact.
    let json = format!(
        r#"{{"RequestMethod":"POST","RequestUri":"/v1.52/images/create?fromImage=ghcr.io%2Fgitleaks%2Fgitleaks%3Av8.18.4&tag=v8.18.4",{TLS}}}"#
    );
    assert_eq!(allow_rule(&json), "pull-allowed");
    let json = format!(
        r#"{{"RequestMethod":"POST","RequestUri":"/v1.52/images/create?fromImage=ghcr.io%2Fgitleaks%2Fgitleaks%3Av8.18.4",{TLS}}}"#
    );
    assert_eq!(allow_rule(&json), "pull-allowed");
    let json = format!(
        r#"{{"RequestMethod":"POST","RequestUri":"/v1.52/images/create?fromImage=ghcr.io%2Fgitleaks%2Fgitleaks%3Av8.18.4&tag=latest",{TLS}}}"#
    );
    assert_eq!(deny_rule(&json), "pull-image");
}

// ---------------------------------------------------------------------------
// Create spec matrix (each violation => exact rule)
// ---------------------------------------------------------------------------

#[test]
fn create_spec_violations_map_to_exact_rules() {
    // Each case is the fully compliant spec with exactly one violation
    // injected, so the asserted rule is the one that fires.
    fn mutate(raw: &str, patch: impl FnOnce(&mut Value)) -> String {
        let mut v: Value = serde_json::from_str(raw).unwrap();
        patch(&mut v);
        serde_json::to_string(&v).unwrap()
    }
    let compliant = compliant_body();
    let cases: &[(&str, String)] = &[
        (
            "create-image",
            mutate(&compliant, |v| v["Image"] = json!("alpine:latest")),
        ),
        (
            "create-privileged",
            mutate(&compliant, |v| v["HostConfig"]["Privileged"] = json!(true)),
        ),
        (
            "create-capadd",
            mutate(&compliant, |v| {
                v["HostConfig"]["CapAdd"] = json!(["SYS_ADMIN"])
            }),
        ),
        (
            "create-capdrop",
            mutate(&compliant, |v| {
                v["HostConfig"]["CapDrop"] = json!(["NET_RAW"])
            }),
        ),
        (
            "create-binds",
            mutate(&compliant, |v| {
                v["HostConfig"]["Binds"] = json!(["/etc:/etc:ro"])
            }),
        ),
        (
            "create-binds",
            mutate(&compliant, |v| {
                v["HostConfig"]["Binds"] = json!(["/tmp/staging:/scan:rw"])
            }),
        ),
        // Gap 2: sensitive or non-canonical host sources denied even when
        // the container target is a staging path.
        (
            "create-binds",
            mutate(&compliant, |v| {
                v["HostConfig"]["Binds"] = json!(["/var/run/docker.sock:/scan:ro"])
            }),
        ),
        (
            "create-binds",
            mutate(&compliant, |v| {
                v["HostConfig"]["Binds"] = json!(["/tmp/../etc/shadow:/scan:ro"])
            }),
        ),
        (
            "create-binds",
            mutate(&compliant, |v| {
                v["HostConfig"]["Binds"] = json!(["relative:/scan:ro"])
            }),
        ),
        // Gap 4: mistyped security fields denied, not tolerated.
        (
            "create-privileged",
            mutate(&compliant, |v| {
                v["HostConfig"]["Privileged"] = json!("false")
            }),
        ),
        (
            "create-capadd",
            mutate(&compliant, |v| v["HostConfig"]["CapAdd"] = json!("ALL")),
        ),
        (
            "create-binds",
            mutate(&compliant, |v| {
                v["HostConfig"]["Binds"] = json!("/tmp/a:/scan:ro")
            }),
        ),
        (
            "create-devices",
            mutate(&compliant, |v| {
                v["HostConfig"]["Devices"] = json!("/dev/sda")
            }),
        ),
        // Gap 3: alternate mount representations denied.
        (
            "create-mounts",
            mutate(&compliant, |v| {
                v["HostConfig"]["Mounts"] =
                    json!([{"Type":"bind","Source":"/tmp/a","Target":"/scan"}])
            }),
        ),
        (
            "create-volumesfrom",
            mutate(&compliant, |v| {
                v["HostConfig"]["VolumesFrom"] = json!(["other"])
            }),
        ),
        // Gap 10: entrypoint overrides other than `sh` denied.
        (
            "create-entrypoint",
            mutate(&compliant, |v| v["Entrypoint"] = json!("/bin/evil")),
        ),
        (
            "create-network",
            mutate(&compliant, |v| {
                v["HostConfig"]["NetworkMode"] = json!("host")
            }),
        ),
        (
            "create-network",
            mutate(&compliant, |v| {
                v["HostConfig"]["NetworkMode"] = json!("container:other")
            }),
        ),
        (
            "create-network",
            mutate(&compliant, |v| {
                v["HostConfig"]
                    .as_object_mut()
                    .unwrap()
                    .remove("NetworkMode");
            }),
        ),
        (
            "create-namespace",
            mutate(&compliant, |v| v["HostConfig"]["PidMode"] = json!("host")),
        ),
        (
            "create-namespace",
            mutate(&compliant, |v| v["HostConfig"]["IpcMode"] = json!("host")),
        ),
        (
            "create-namespace",
            mutate(&compliant, |v| v["HostConfig"]["UTSMode"] = json!("host")),
        ),
        (
            "create-namespace",
            mutate(&compliant, |v| {
                v["HostConfig"]["UsernsMode"] = json!("host")
            }),
        ),
        (
            "create-devices",
            mutate(&compliant, |v| {
                v["HostConfig"]["Devices"] = json!([{"PathOnHost":"/dev/sda"}])
            }),
        ),
        (
            "create-user",
            mutate(&compliant, |v| v["User"] = json!("0:0")),
        ),
        (
            "create-user",
            mutate(&compliant, |v| {
                v.as_object_mut().unwrap().remove("User");
            }),
        ),
        (
            "create-readonly",
            mutate(&compliant, |v| {
                v["HostConfig"]["ReadonlyRootfs"] = json!(false)
            }),
        ),
        // Bypass shape: top-level ReadonlyRootfs is daemon-ignored; without
        // the canonical HostConfig field the create must deny.
        (
            "create-readonly",
            mutate(&compliant, |v| {
                v["HostConfig"]
                    .as_object_mut()
                    .unwrap()
                    .remove("ReadonlyRootfs");
                v["ReadonlyRootfs"] = json!(true);
            }),
        ),
        (
            "create-securityopt",
            mutate(&compliant, |v| {
                v["HostConfig"]["SecurityOpt"] = json!(["seccomp=unconfined"])
            }),
        ),
        (
            "create-tmpfs",
            mutate(&compliant, |v| {
                v["HostConfig"]["Tmpfs"] = json!({"/etc":"rw"})
            }),
        ),
        (
            "create-restartpolicy",
            mutate(&compliant, |v| {
                v["HostConfig"]["RestartPolicy"] = json!({"Name":"always"})
            }),
        ),
    ];
    for (rule, body) in cases {
        let json = create_req("", body);
        assert_eq!(deny_rule(&json), *rule, "body: {body}");
    }
}

#[test]
fn create_name_must_be_scanner_scoped() {
    let json = create_req("", &create_body("")).replace(SCAN_ID, "other-container");
    assert_eq!(deny_rule(&json), "create-name");
    let json = create_req("", &create_body("")).replace(SCAN_ID, "");
    assert_eq!(deny_rule(&json), "create-name");
    // Scanner names require a lowercase UUID suffix (gap: lifecycle scoping).
    let json = create_req("", &create_body("")).replace(SCAN_ID, "abc");
    assert_eq!(deny_rule(&json), "create-name");
    let json = create_req("", &create_body("")).replace(SCAN_ID, "../../etc");
    assert_eq!(deny_rule(&json), "create-name");
}

#[test]
fn create_fully_compliant_spec_is_allowed() {
    assert_eq!(
        allow_rule(&create_req("", &compliant_body())),
        "create-allowed"
    );
}

#[test]
fn fixture_cli_sandbox_shape_is_allowed() {
    // Verbatim create body captured from the bundled docker CLI 29.1.3 for
    // the real sandbox argv (logging-relay wire capture, W1 evidence). Proves
    // the policy accepts the genuine scanner shape: CapAdd/Binds/VolumesFrom
    // encoded as JSON null (= none), SecurityOpt the bare
    // `no-new-privileges` spelling, RestartPolicy `{"Name":"no"}`.
    let v = fixture("create_cli_sandbox_shape");
    let parsed = parse_request(&v).unwrap();
    let d = plugin().decide(&parsed);
    assert!(d.allow, "rule={} msg={}", d.rule, d.msg);
    assert_eq!(d.rule, "create-allowed");
}

#[test]
fn null_list_fields_mean_none_but_mistyped_non_null_denied() {
    // Docker's canonical encoding of "no additions" for nullable list fields
    // is JSON null (wire-captured). Null and [] are equivalent to absent and
    // must pass on an otherwise compliant spec; any mistyped non-null value
    // or any non-empty forbidden list must deny (gap 4).
    fn mutate(raw: &str, patch: impl FnOnce(&mut Value)) -> String {
        let mut v: Value = serde_json::from_str(raw).unwrap();
        patch(&mut v);
        serde_json::to_string(&v).unwrap()
    }
    let compliant = compliant_body();
    for (field, value) in [
        ("CapAdd", json!(null)),
        ("CapAdd", json!([])),
        ("Binds", json!(null)),
        ("Mounts", json!(null)),
        ("VolumesFrom", json!(null)),
        ("Devices", json!(null)),
        ("Devices", json!([])),
    ] {
        let body = mutate(&compliant, |v| v["HostConfig"][field] = value.clone());
        assert_eq!(
            allow_rule(&create_req("", &body)),
            "create-allowed",
            "null/empty {field}={value} must pass"
        );
    }
    for (field, value, rule) in [
        ("CapAdd", json!(123), "create-capadd"),
        ("Binds", json!({"src":"/tmp"}), "create-binds"),
        ("Mounts", json!("nonsense"), "create-mounts"),
        ("VolumesFrom", json!("nonsense"), "create-volumesfrom"),
        ("Devices", json!(true), "create-devices"),
    ] {
        let body = mutate(&compliant, |v| v["HostConfig"][field] = value.clone());
        assert_eq!(deny_rule(&create_req("", &body)), rule, "{field}={value}");
    }
    // SecurityOpt: bare enabled spelling allowed; disabled form and
    // mistyped entries denied.
    let body = mutate(&compliant, |v| {
        v["HostConfig"]["SecurityOpt"] = json!(["no-new-privileges"])
    });
    assert_eq!(allow_rule(&create_req("", &body)), "create-allowed");
    for value in [
        json!(["no-new-privileges=false"]),
        json!([123]),
        json!(["no-new-privileges=true", "seccomp=unconfined"]),
    ] {
        let body = mutate(&compliant, |v| {
            v["HostConfig"]["SecurityOpt"] = value.clone()
        });
        assert_eq!(
            deny_rule(&create_req("", &body)),
            "create-securityopt",
            "SecurityOpt={value}"
        );
    }
}

#[test]
fn create_body_unparseable_json_is_denied() {
    let json = format!(
        r#"{{"RequestMethod":"POST","RequestUri":"/containers/create?name=firecrow-scan-a",{TLS},"RequestBody":"{}"}}"#,
        b64("{not json")
    );
    assert_eq!(deny_rule(&json), "create-body-unparseable");
}

// ---------------------------------------------------------------------------
// Target scoping + registry (M6, R-d)
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_ops_require_registered_or_scanner_name() {
    let p = plugin();
    let scan = format!("firecrow-scan-{SCAN_ID}");
    let start = |uri: &str| {
        let json = format!(r#"{{"RequestMethod":"POST","RequestUri":"{uri}",{TLS}}}"#);
        p.decide(&req(&json))
    };
    // Unknown id and non-scanner name: denied.
    assert_eq!(
        start("/v1.52/containers/deadbeef/start").rule,
        "target-unknown"
    );
    assert_eq!(
        start("/v1.52/containers/other-container/start").rule,
        "target-unknown"
    );
    // Non-UUID scanner-looking name: denied (gap: strict name scoping).
    assert_eq!(
        start("/v1.52/containers/firecrow-scan-xyz/start").rule,
        "target-unknown"
    );
    // Scanner UUID name without registry: allowed (name scoping).
    assert_eq!(
        start(&format!("/v1.52/containers/{scan}/start")).rule,
        "target-name"
    );
    // Register an id via a base64 allowed create response, then allowed.
    assert!(p.observe(&json!({"ResponseBody": b64(r#"{"Id":"cid-0001","Warnings":[]}"#)})));
    assert_eq!(
        start("/v1.52/containers/cid-0001/start").rule,
        "target-registered"
    );
    assert_eq!(start("/v1.52/containers/cid-0001").rule, "endpoint-denied"); // GET inspect
    let del = format!(
        r#"{{"RequestMethod":"DELETE","RequestUri":"/v1.52/containers/cid-0001?force=1",{TLS}}}"#
    );
    assert_eq!(p.decide(&req(&del)).rule, "target-registered");
    // attach/wait/stop/kill are lifecycle too.
    for op in ["attach", "wait", "stop", "kill"] {
        let json = format!(
            r#"{{"RequestMethod":"POST","RequestUri":"/v1.52/containers/{scan}/{op}",{TLS}}}"#
        );
        assert_eq!(p.decide(&req(&json)).rule, "target-name");
    }
    // Gap 1: DELETE archive is not a removal — denied even for owned target.
    let del_archive = format!(
        r#"{{"RequestMethod":"DELETE","RequestUri":"/v1.52/containers/cid-0001/archive?path=/tmp",{TLS}}}"#
    );
    assert_eq!(p.decide(&req(&del_archive)).rule, "endpoint-denied");
}

#[test]
fn registry_only_narrows_never_widens() {
    // A UUID scanner name that was never created is name-allowed (frozen
    // rule); anything else stays denied even though the registry has entries.
    let p = plugin();
    assert!(p.observe(&json!({"ResponseBody": b64(r#"{"Id":"cid-9"}"#)})));
    // Malformed observe payloads fail closed and register nothing.
    assert!(!p.observe(&json!({"ResponseBody": "!!!not-base64!!!"})));
    assert!(!p.observe(&json!({"ResponseBody": b64(r#"{"Warnings":[]}"#)})));
    let scan = format!("firecrow-scan-{SCAN_ID}");
    let json = format!(
        r#"{{"RequestMethod":"POST","RequestUri":"/v1.52/containers/{scan}/start",{TLS}}}"#
    );
    assert_eq!(p.decide(&req(&json)).rule, "target-name");
    let json =
        format!(r#"{{"RequestMethod":"POST","RequestUri":"/v1.52/containers/cid-9/start",{TLS}}}"#);
    assert_eq!(p.decide(&req(&json)).rule, "target-registered");
}

// ---------------------------------------------------------------------------
// Deny-by-endpoint rows (R-e/R-f) and default deny
// ---------------------------------------------------------------------------

#[test]
fn dangerous_endpoints_are_denied_on_strict_channel() {
    let endpoints: &[&str] = &[
        "/v1.52/containers/cid-1/update",
        "/v1.52/containers/cid-1/rename",
        "/v1.52/containers/cid-1/export",
        "/v1.52/containers/cid-1/archive?path=/etc",
        "/v1.52/containers/cid-1/exec",
        "/v1.52/exec/exec-1/start",
        "/v1.52/containers/prune",
        "/v1.52/images/prune",
        "/v1.52/commit",
        "/v1.52/images/load",
        "/v1.52/images/ghcr.io%2Fgitleaks%2Fgitleaks%3Av8.18.4",
        "/v1.52/images/ghcr.io%2Fgitleaks%2Fgitleaks%3Av8.18.4/tag",
        "/v1.52/images/ghcr.io%2Fgitleaks%2Fgitleaks%3Av8.18.4/push",
        "/v1.52/containers/json",
        "/v1.52/containers/cid-1/json",
        "/v1.52/containers/cid-1/logs",
        "/v1.52/containers/cid-1/top",
        "/v1.52/containers/cid-1/stats",
        "/v1.52/networks",
        "/v1.52/volumes",
        "/v1.52/build?t=x",
        "/v1.52/system/df",
        "/v1.52/swarm",
        "/v1.52/services",
        "/v1.52/tasks",
        "/v1.52/secrets",
        "/v1.52/configs",
        "/v1.52/auth",
        "/v1.52/nodes",
        "/v1.52/plugins",
        "/v1.52/distribution/images/ghcr.io%2Fgitleaks%2Fgitleaks%3Av8.18.4/get",
        "/v1.52/session",
        "/v1.52/info",
        "/v1.52/events",
    ];
    for ep in endpoints {
        let method = if ep.contains("archive") {
            "PUT"
        } else if ep.contains("/load")
            || ep.contains("/push")
            || ep.contains("/tag")
            || ep.contains("prune")
            || ep.contains("commit")
            || ep.contains("exec")
            || ep.contains("rename")
            || ep.contains("update")
        {
            "POST"
        } else if ep.contains("images/") && ep.contains("v8.18.4") && !ep.contains("create") {
            "DELETE"
        } else {
            "GET"
        };
        let json = format!(r#"{{"RequestMethod":"{method}","RequestUri":"{ep}",{TLS}}}"#);
        assert_eq!(deny_rule(&json), "endpoint-denied", "endpoint: {ep}");
    }
}

#[test]
fn unknown_paths_default_to_deny() {
    for ep in [
        "/v1.52/containers",
        "/v1.52/whatever",
        "/v9.99/future/shape",
        "/",
        // Gap 8: ambiguous spellings canonicalize to deny.
        "//v1.52//containers//create",
        "/v1.52/containers/create/",
        "/v1.52/../v1.52/containers/create",
        "/v1.52/./containers/create",
        "/CONTAINERS/CREATE",
        "/v1.52/%2Fcontainers/create",
    ] {
        let json = format!(r#"{{"RequestMethod":"GET","RequestUri":"{ep}",{TLS}}}"#);
        assert_eq!(deny_rule(&json), "endpoint-denied", "path: {ep}");
    }
}

#[test]
fn negotiation_is_allowed() {
    for (m, u) in [
        ("HEAD", "/_ping"),
        ("GET", "/_ping"),
        ("GET", "/version"),
        ("GET", "/v1.52/version"),
    ] {
        let json = format!(r#"{{"RequestMethod":"{m}","RequestUri":"{u}",{TLS}}}"#);
        assert_eq!(allow_rule(&json), "negotiation");
    }
}

#[test]
fn pull_allowlist_enforced() {
    let json = format!(
        r#"{{"RequestMethod":"POST","RequestUri":"/v1.52/images/create?fromImage=alpine%3Alatest",{TLS}}}"#
    );
    assert_eq!(deny_rule(&json), "pull-image");
    let json = format!(r#"{{"RequestMethod":"POST","RequestUri":"/v1.52/images/create",{TLS}}}"#);
    assert_eq!(deny_rule(&json), "pull-image");
    // Gap 7: split/duplicate/conflicting tag parameters.
    let base = "ghcr.io%2Fgitleaks%2Fgitleaks";
    let json = format!(
        r#"{{"RequestMethod":"POST","RequestUri":"/v1.52/images/create?fromImage={base}&tag=v8.18.4",{TLS}}}"#
    );
    assert_eq!(allow_rule(&json), "pull-allowed");
    let json = format!(
        r#"{{"RequestMethod":"POST","RequestUri":"/v1.52/images/create?fromImage={base}%3Av8.18.4&tag=v8.18.4",{TLS}}}"#
    );
    assert_eq!(allow_rule(&json), "pull-allowed");
    let json = format!(
        r#"{{"RequestMethod":"POST","RequestUri":"/v1.52/images/create?fromImage={base}&tag=v9.9.9",{TLS}}}"#
    );
    assert_eq!(deny_rule(&json), "pull-image");
    let json = format!(
        r#"{{"RequestMethod":"POST","RequestUri":"/v1.52/images/create?fromImage={base}%3Av8.18.4&tag=v9.9.9",{TLS}}}"#
    );
    assert_eq!(deny_rule(&json), "pull-image");
    let json = format!(
        r#"{{"RequestMethod":"POST","RequestUri":"/v1.52/images/create?fromImage={base}&tag=v8.18.4&tag=v8.18.4",{TLS}}}"#
    );
    assert_eq!(deny_rule(&json), "pull-image");
}

#[test]
fn approved_images_all_allowed() {
    for img in APPROVED_IMAGES {
        let json = format!(
            r#"{{"RequestMethod":"POST","RequestUri":"/v1.52/images/create?fromImage={}",{TLS}}}"#,
            img.replace(':', "%3A").replace('/', "%2F")
        );
        assert_eq!(allow_rule(&json), "pull-allowed", "image: {img}");
    }
}
