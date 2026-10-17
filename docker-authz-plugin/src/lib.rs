//! FireCrow Docker daemon authorization plugin — decision engine.
//!
//! Enforces the frozen T1 strict-channel policy (FC-ZT-SEC-002-G2-AUTHZ-DESIGN
//! §4, as ratified in FC-ZT-SEC-002-G2-AUTHZ-IMPLEMENTATION-PLAN §3) at the
//! Docker authorization boundary. Deny-by-default: anything not explicitly
//! allowed is denied; unknown identities, request shapes, and policy errors
//! never default to allow (R-a).
//!
//! The engine is pure I/O-free logic so the whole matrix is unit-testable
//! against captured real wire payloads; `main.rs` adds the plugin-protocol
//! HTTP server.

use serde_json::Value;
use std::collections::HashSet;
use std::io::Write as _;
use std::sync::Mutex;

/// Scanner images the backend may pull/create (sandbox.rs:618-622).
/// Exact references only: the tag is part of the reference; a CLI-style
/// split `fromImage=name&tag=tag` must recombine to exactly one of these
/// before it is allowed (gap 7).
pub const APPROVED_IMAGES: &[&str] = &[
    "ghcr.io/gitleaks/gitleaks:v8.18.4",
    "ghcr.io/google/osv-scanner:v2.2.4",
    "semgrep/semgrep:1.96.0",
];

/// Scanner containers are always named `firecrow-scan-<uuid>` (sandbox.rs:526).
/// The suffix must be a lowercase UUID (hex + dashes); anything else is
/// denied so `firecrow-scan-../../x` style spellings cannot widen scope.
pub const SCAN_NAME_PREFIX: &str = "firecrow-scan-";

/// The unprivileged uid:gid every scanner runs as (sandbox.rs:50).
pub const SANDBOX_USER: &str = "65534:65534";

/// Container paths a bind may target, read-only (sandbox.rs:391:
/// `ALLOWED_CONTAINER_PATHS = [SCAN_MOUNT, CONFIG_MOUNT]`).
pub const ALLOWED_BIND_TARGETS: &[&str] = &["/scan", "/config"];

/// Host sources that may back a staging bind. Mirrors the backend
/// `reject_sensitive_host_path` contract (sandbox.rs:652-769): absolute
/// canonical paths only, never the filesystem root, the Docker socket, or
/// sensitive trees. Server tempdir staging and the pinned ruleset are the
/// legitimate sources; everything else is denied (gap 2).
const DENIED_HOST_EXACT: &[&str] = &["/", "/var/run/docker.sock", "/run/docker.sock"];
const DENIED_HOST_PREFIXES: &[&str] = &[
    "/proc/",
    "/sys/",
    "/dev/",
    "/etc/",
    "/root/",
    "/var/run/",
    "/run/",
    "/var/lib/docker/",
    "/boot/",
    "/home/",
];

/// Network modes a scanner container may use (sandbox.rs NetworkMode).
pub const ALLOWED_NETWORKS: &[&str] = &["none", "scanners-internal"];

/// Defensive cap on a single forwarded request body. Real create bodies are
/// kilobytes; the daemon's own limits apply upstream of the plugin.
pub const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub allow: bool,
    /// Stable rule identifier (logged; never contains request content).
    pub rule: &'static str,
    pub msg: String,
    /// Resolved container target (id or name) when the URI addressed one.
    pub target: Option<String>,
}

impl Decision {
    fn allow(rule: &'static str, target: Option<String>) -> Self {
        Decision {
            allow: true,
            rule,
            msg: String::new(),
            target,
        }
    }
    fn deny(rule: &'static str, msg: impl Into<String>, target: Option<String>) -> Self {
        Decision {
            allow: false,
            rule,
            msg: msg.into(),
            target,
        }
    }
}

/// The plugin-facing request shape (M2). Only fields the policy uses are
/// modeled; identity comes exclusively from the mTLS-verified `User` /
/// `UserAuthNMethod` pair — never from request headers.
#[derive(Debug, Clone)]
pub struct AuthzRequest {
    pub method: String,
    pub uri: String,
    pub user: Option<String>,
    pub user_authn: Option<String>,
    /// Decoded `RequestBody` (base64). `None` = absent or undecodable.
    pub body: Option<String>,
}

/// Parse an `AuthZPlugin.AuthZReq` payload per R-a/R-b/R-c.
/// Any missing/mistyped required field is a deny reason, never a default.
pub fn parse_request(v: &Value) -> Result<AuthzRequest, &'static str> {
    let obj = v.as_object().ok_or("payload-not-object")?;
    let get_str = |k: &str| obj.get(k).and_then(|x| x.as_str());
    // R-b: accept both wire spellings; neither (or empty) => deny.
    let uri = get_str("RequestUri")
        .or_else(|| get_str("RequestURI"))
        .filter(|s| !s.is_empty())
        .ok_or("uri-missing")?
        .to_string();
    let method = get_str("RequestMethod")
        .filter(|s| !s.is_empty())
        .ok_or("method-missing")?
        .to_string();
    let user = get_str("User").map(str::to_string);
    let user_authn = get_str("UserAuthNMethod").map(str::to_string);
    // R-c: bodies are base64 and optional; undecodable => deny-worthy None.
    let body = match obj.get("RequestBody") {
        Some(Value::String(s)) => {
            let raw = b64_decode(s).ok_or("body-undecodable")?;
            Some(String::from_utf8(raw).map_err(|_| "body-undecodable")?)
        }
        _ => None,
    };
    Ok(AuthzRequest {
        method,
        uri,
        user,
        user_authn,
        body,
    })
}

/// Standard base64 (padding-enforced). Returns None on any invalid input.
/// Padding `=` may only appear as the final one or two characters; interior
/// padding and any non-alphabet byte (after ASCII-whitespace stripping) is
/// rejected (gap 5: strict decode, fail closed).
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let table = |c: u8| -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return None;
    }
    // `=` is padding: it may only terminate the input (last 1-2 bytes), may
    // not appear in the first two positions of any quantum, and any data
    // after padding is malformed.
    if bytes[0] == b'=' || bytes[1] == b'=' {
        return None;
    }
    if let Some(pos) = bytes.iter().position(|&b| b == b'=') {
        if pos < bytes.len().saturating_sub(2) {
            return None;
        }
        if !bytes[pos..].iter().all(|&b| b == b'=') {
            return None;
        }
        if bytes.len() - pos > 2 {
            return None;
        }
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (qi, chunk) in bytes.chunks(4).enumerate() {
        let last = qi == bytes.len() / 4 - 1;
        let a = table(chunk[0])?;
        let b = table(chunk[1])?;
        let (c, d, n) = match (chunk[2], chunk[3]) {
            (b'=', b'=') if last => (0, 0, 1),
            (c, b'=') if last => (table(c)?, 0, 2),
            (c, d) if c != b'=' && d != b'=' => (table(c)?, table(d)?, 3),
            _ => return None,
        };
        out.push((a << 2) | (b >> 4));
        if n >= 2 {
            out.push((b << 4) | (c >> 2));
        }
        if n >= 3 {
            out.push((c << 6) | d);
        }
    }
    Some(out)
}

/// Strip query/fragment and the `/vX.Y/` version prefix so versioned and
/// unversioned shapes normalize identically (M5). Fail-closed canonical form
/// (gap 8): collapse duplicate slashes, drop a single trailing slash, and
/// reject (return empty → endpoint-denied) any path containing `.` / `..`
/// segments. Percent-decoded separators (`%2F`) are rejected before they can
/// smuggle path structure; matching stays case-sensitive.
pub fn normalize_path(uri: &str) -> String {
    let raw = uri.split(['?', '#']).next().unwrap_or("");
    if raw.is_empty() || !raw.starts_with('/') {
        return String::new();
    }
    if raw.contains("%2f") || raw.contains("%2F") || raw.contains("%00") {
        return String::new();
    }
    let mut segs: Vec<&str> = Vec::new();
    for seg in raw.split('/') {
        match seg {
            "" => continue,
            "." | ".." => return String::new(),
            s => segs.push(s),
        }
    }
    if segs.is_empty() {
        return String::new();
    }
    let joined = format!("/{}", segs.join("/"));
    let rest = joined.strip_prefix('/').unwrap_or(&joined);
    if let Some((ver, tail)) = rest.split_once('/') {
        let digits = &ver[1..];
        if !tail.is_empty()
            && ver.starts_with('v')
            && !digits.is_empty()
            && digits.bytes().all(|c| c.is_ascii_digit() || c == b'.')
        {
            return format!("/{tail}");
        }
    }
    joined
}

/// Percent-decode a query component (docker encodes e.g. `%2F` in fromImage).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn query_param(uri: &str, key: &str) -> Option<String> {
    let q = uri.split_once('?')?.1;
    q.split('&')
        .find_map(|pair| pair.split_once('=').filter(|(k, _)| *k == key))
        .map(|(_, v)| percent_decode(v))
}

/// The id/name segment of `/containers/{id}/...` paths, if any.
fn container_target(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/containers/")?;
    rest.split('/').next().filter(|s| !s.is_empty())
}

fn is_lifecycle_op(path: &str) -> bool {
    path.ends_with("/start")
        || path.ends_with("/attach")
        || path.ends_with("/wait")
        || path.ends_with("/stop")
        || path.ends_with("/kill")
}

/// Scanner names are `firecrow-scan-<lowercase-uuid>`: hex digits and dashes
/// only, 36 chars. Anything else (slashes, dots, empty) is not a scanner
/// name and must not widen lifecycle scope.
fn is_scanner_name(name: &str) -> bool {
    let suffix = match name.strip_prefix(SCAN_NAME_PREFIX) {
        Some(s) => s,
        None => return false,
    };
    if suffix.len() != 36 {
        return false;
    }
    let mut dash = [false; 36];
    for (i, b) in suffix.bytes().enumerate() {
        match b {
            b'0'..=b'9' | b'a'..=b'f' => {}
            b'-' if i == 8 || i == 13 || i == 18 || i == 23 => dash[i] = true,
            _ => return false,
        }
    }
    dash[8] && dash[13] && dash[18] && dash[23]
}

/// Lexically canonicalize an absolute host path (`.`, `..`, duplicate
/// slashes) without touching the filesystem. `..` past the root stays at the
/// root. This does not resolve symlinks: symlinks are contained by
/// read-only mounts + no-new-privileges + dropped capabilities instead.
fn canonical_host_path(host_path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for component in host_path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    format!("/{}", parts.join("/"))
}

/// Backend-compatible sensitive-host check (gap 2): absolute canonical paths
/// only; deny the root, the Docker socket, and every sensitive prefix on a
/// boundary-aware comparison (`/etc` itself is denied, not just `/etc/...`).
fn host_source_denied(host_path: &str) -> bool {
    if !host_path.starts_with('/') {
        return true;
    }
    let cleaned = canonical_host_path(host_path);
    if DENIED_HOST_EXACT.contains(&cleaned.as_str()) {
        return true;
    }
    for prefix in DENIED_HOST_PREFIXES {
        if cleaned == prefix.trim_end_matches('/') || cleaned.starts_with(*prefix) {
            return true;
        }
    }
    false
}

/// The authorization plugin: identity allowlist, create-response ID registry
/// (M6), and the decision log. Local state only — no outbound network, no
/// secrets (design §5/§10 D-4).
pub struct Plugin {
    allowed_cns: HashSet<String>,
    registry: Mutex<HashSet<String>>,
    logger: Mutex<std::fs::File>,
}

impl Plugin {
    pub fn new(allowed_cns: HashSet<String>, log_path: &str) -> Self {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .expect("open decision log");
        Plugin {
            allowed_cns,
            registry: Mutex::new(HashSet::new()),
            logger: Mutex::new(file),
        }
    }

    /// The whole policy. Every path not explicitly allowed is denied.
    /// Gap 9: no implicit allow for identity-less requests — a missing or
    /// mistyped identity is denied on this channel. A separately documented
    /// local-admin socket exception, if ever accepted, must live outside this
    /// strict engine behind its own explicit gate and tests; it is not here.
    pub fn decide(&self, req: &AuthzRequest) -> Decision {
        // Identity gate: bind to the verified mTLS identity only. Header-borne
        // identity claims are ignored by construction (never parsed).
        let identity = match (req.user_authn.as_deref(), req.user.as_deref()) {
            (Some("TLS"), Some(cn)) if !cn.is_empty() => cn,
            _ => {
                return Decision::deny(
                    "identity-required",
                    "TLS client identity required on this channel",
                    None,
                )
            }
        };
        if !self.allowed_cns.contains(identity) {
            return Decision::deny(
                "identity-not-allowed",
                format!("identity '{identity}' is not on the allowlist"),
                None,
            );
        }

        let path = normalize_path(&req.uri);
        let target = container_target(&path).map(str::to_string);
        let target_ref = target.as_deref();

        match (req.method.as_str(), path.as_str()) {
            ("HEAD" | "GET", "/_ping") | ("GET", "/version") => {
                Decision::allow("negotiation", target)
            }
            ("POST", "/containers/create") => self.create_policy(req),
            ("POST", "/images/create") => self.pull_policy(req),
            // O-3 door: gRPC is denied at the plugin; the deny blocks the h2c
            // upgrade before any protocol switch (verified t1b §D/§E).
            ("POST", "/grpc") => {
                Decision::deny("grpc-door", "gRPC denied on this channel (O-3)", target)
            }
            ("POST", p) if target_ref.is_some() && is_lifecycle_op(p) => {
                self.target_policy(target_ref.unwrap())
            }
            // Gap 1: DELETE is scoped to force-removal of channel-owned
            // containers only. DELETE /containers/{id}/archive (export path)
            // is NOT a lifecycle removal and stays denied via endpoint-denied.
            ("DELETE", p) if target_ref.is_some() && Self::is_container_delete(p) => {
                self.target_policy(target_ref.unwrap())
            }
            // Default deny: covers every other endpoint/method, including all
            // deny-by-endpoint rows of the frozen matrix (R-e, R-f).
            _ => Decision::deny(
                "endpoint-denied",
                format!("{} {} is not permitted on this channel", req.method, path),
                target,
            ),
        }
    }

    /// `POST /images/create`: pull only approved scanner refs.
    /// Gap 7: Docker may split the reference as `fromImage=name&tag=tag`.
    /// Semantics: `fromImage` alone must be an exact approved ref; if `tag`
    /// is present it must recombine (`name:tag`) to an exact approved ref and
    /// must equal any tag already embedded in `fromImage`. Missing,
    /// duplicated, conflicting, or unapproved references are denied.
    fn pull_policy(&self, req: &AuthzRequest) -> Decision {
        let query = req.uri.split_once('?').map(|(_, q)| q).unwrap_or("");
        let mut from_images: Vec<String> = Vec::new();
        let mut tags: Vec<String> = Vec::new();
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let Some((k, v)) = pair.split_once('=') else {
                continue;
            };
            if k == "fromImage" {
                from_images.push(percent_decode(v));
            } else if k == "tag" {
                tags.push(percent_decode(v));
            }
        }
        if from_images.len() != 1 {
            return Decision::deny(
                "pull-image",
                "image ref must carry exactly one fromImage",
                None,
            );
        }
        let from = from_images.pop().unwrap();
        if from.is_empty() {
            return Decision::deny("pull-image", "image ref is missing", None);
        }
        let candidate = if tags.is_empty() {
            from.clone()
        } else {
            if tags.len() != 1 || tags[0].is_empty() {
                return Decision::deny(
                    "pull-image",
                    "image tag must be a single non-empty value",
                    None,
                );
            }
            let tag = &tags[0];
            if from.contains('@') {
                // Digest refs cannot take a separate tag.
                return Decision::deny(
                    "pull-image",
                    "digest image ref must not carry a tag parameter",
                    None,
                );
            }
            match from.rsplit_once(':') {
                Some((_, embedded)) if embedded != tag => {
                    return Decision::deny(
                        "pull-image",
                        "image fromImage/tag conflict is denied",
                        None,
                    )
                }
                Some(_) => from.clone(),
                None => format!("{from}:{tag}"),
            }
        };
        if APPROVED_IMAGES.contains(&candidate.as_str()) {
            Decision::allow("pull-allowed", None)
        } else {
            Decision::deny(
                "pull-image",
                format!("image ref '{candidate}' is not approved"),
                None,
            )
        }
    }

    /// Exact container-removal shape only: `/containers/{id}` with no extra
    /// suffix. Anything deeper (e.g. `/archive`, `/checkpoints`) is not a
    /// removal and must not reach `target_policy`.
    fn is_container_delete(path: &str) -> bool {
        let Some(rest) = path.strip_prefix("/containers/") else {
            return false;
        };
        !rest.is_empty() && !rest.contains('/')
    }

    /// Lifecycle ops: allowed only against a container this plugin channel
    /// created (registry) or a `firecrow-scan-*` name (R-d).
    fn target_policy(&self, target: &str) -> Decision {
        if self.registry.lock().unwrap().contains(target) {
            return Decision::allow("target-registered", Some(target.to_string()));
        }
        if is_scanner_name(target) {
            return Decision::allow("target-name", Some(target.to_string()));
        }
        Decision::deny(
            "target-unknown",
            format!("container '{target}' is not owned by this channel"),
            Some(target.to_string()),
        )
    }

    /// `POST /containers/create`: allow iff the full spec passes. The field
    /// list below is the implementation spec (plan §3 matrix).
    fn create_policy(&self, req: &AuthzRequest) -> Decision {
        let body = match req.body.as_deref() {
            // R-a: a body the plugin cannot see is a deny, never a silent
            // allow (this is what the content-type matrix proved necessary).
            Some(b) if b.len() <= MAX_BODY_BYTES => b,
            Some(_) => return Decision::deny("body-too-large", "create body exceeds cap", None),
            None => {
                return Decision::deny(
                    "create-body-required",
                    "create spec body is required and must be visible",
                    None,
                )
            }
        };
        let spec: Value = match serde_json::from_str(body) {
            Ok(v) => v,
            Err(_) => {
                return Decision::deny(
                    "create-body-unparseable",
                    "create body is not valid JSON",
                    None,
                )
            }
        };
        let obj = match spec.as_object() {
            Some(o) => o,
            None => {
                return Decision::deny(
                    "create-body-unparseable",
                    "create body is not an object",
                    None,
                )
            }
        };
        let name = query_param(&req.uri, "name").unwrap_or_default();
        if !is_scanner_name(&name) {
            return Decision::deny(
                "create-name",
                "container name must be firecrow-scan-<uuid>",
                None,
            );
        }
        let image = match obj.get("Image") {
            Some(Value::String(s)) => s.as_str(),
            _ => {
                return Decision::deny(
                    "create-image",
                    "container Image must be an approved string",
                    None,
                )
            }
        };
        if !APPROVED_IMAGES.contains(&image) {
            return Decision::deny(
                "create-image",
                format!("image '{image}' is not approved"),
                None,
            );
        }
        let hc = obj.get("HostConfig").and_then(|v| v.as_object());
        let deny = |rule: &'static str, msg: String| Decision::deny(rule, msg, None);

        // Gap 4: mistyped security fields are denied, never treated as
        // "absent, therefore unrestricted". Presence with the wrong JSON type
        // means the daemon would apply its own default, which this channel
        // must not silently accept.
        if let Some(v) = hc.and_then(|h| h.get("Privileged")) {
            if v.as_bool() != Some(false) {
                return deny(
                    "create-privileged",
                    "Privileged must be explicitly false".into(),
                );
            }
        }
        // Docker's canonical encoding of "no additions" is JSON null (real CLI
        // wire capture: `"CapAdd":null`), identical to an empty array. Null and
        // [] pass; any non-empty array or any mistyped non-null value (string,
        // bool, object, number) is denied — a mistyped field is never read as
        // "absent, therefore unrestricted" (gap 4).
        if let Some(v) = hc.and_then(|h| h.get("CapAdd")) {
            if !v.is_null() {
                match v.as_array() {
                    Some(caps) if caps.is_empty() => {}
                    _ => return deny("create-capadd", "capability additions are denied".into()),
                }
            }
        }
        if hc.and_then(|h| h.get("CapDrop")).and_then(|v| v.as_array())
            != Some(&vec![Value::String("ALL".to_string())])
        {
            return deny("create-capdrop", "CapDrop must be exactly [ALL]".into());
        }
        if let Some(v) = hc.and_then(|h| h.get("Binds")) {
            if !v.is_null() {
                let binds = match v.as_array() {
                    Some(a) => a,
                    None => return deny("create-binds", "Binds must be an array".into()),
                };
                for b in binds {
                    let s = match b.as_str() {
                        Some(s) => s,
                        None => return deny("create-binds", "bind entries must be strings".into()),
                    };
                    let mut parts = s.split(':');
                    let host = parts.next().unwrap_or("");
                    let container = parts.next().unwrap_or("");
                    let opts = parts.next().unwrap_or("");
                    if parts.next().is_some() || host.is_empty() || container.is_empty() {
                        return deny(
                            "create-binds",
                            format!("bind '{s}' has an unsupported shape"),
                        );
                    }
                    if host_source_denied(host) {
                        return deny(
                            "create-binds",
                            format!("bind host source '{host}' is not permitted"),
                        );
                    }
                    if !ALLOWED_BIND_TARGETS.contains(&container)
                        || !opts.split(',').any(|o| o == "ro")
                    {
                        return deny(
                            "create-binds",
                            format!("bind '{s}' is not one of the read-only staging mounts"),
                        );
                    }
                }
            }
        }
        // Gap 3: the structured mount API is an alternate representation of
        // the same host access. Any `Mounts` entry (bind or otherwise) and
        // any `VolumesFrom` entry widens the boundary and is denied: the
        // frozen scanner-launch contract uses string `Binds` only. Null/[]
        // mean "none present" (real CLI wire capture: both null) and pass;
        // mistyped non-null values are denied.
        if let Some(v) = hc.and_then(|h| h.get("Mounts")) {
            if !v.is_null() {
                let deny_mounts = || deny("create-mounts", "structured Mounts are denied".into());
                match v.as_array() {
                    Some(m) if m.is_empty() => {}
                    _ => return deny_mounts(),
                }
            }
        }
        if let Some(v) = hc.and_then(|h| h.get("VolumesFrom")) {
            if !v.is_null() {
                let deny_vf = || deny("create-volumesfrom", "VolumesFrom is denied".into());
                match v.as_array() {
                    Some(a) if a.is_empty() => {}
                    _ => return deny_vf(),
                }
            }
        }
        let net = match hc.and_then(|h| h.get("NetworkMode")) {
            Some(Value::String(s)) => s.as_str(),
            _ => {
                return deny(
                    "create-network",
                    "NetworkMode must be an explicit permitted string".into(),
                )
            }
        };
        if !ALLOWED_NETWORKS.contains(&net) {
            return deny(
                "create-network",
                format!("network mode '{net}' is not permitted"),
            );
        }
        for key in ["PidMode", "IpcMode", "UTSMode", "UsernsMode"] {
            match hc.and_then(|h| h.get(key)) {
                None => {}
                Some(Value::String(s)) if s.is_empty() => {}
                _ => {
                    return deny(
                        "create-namespace",
                        format!("{key} must be absent or empty (host {key} is denied)"),
                    )
                }
            }
        }
        if let Some(v) = hc.and_then(|h| h.get("Devices")) {
            if !v.is_null() {
                match v.as_array() {
                    Some(d) if d.is_empty() => {}
                    _ => return deny("create-devices", "device passthrough is denied".into()),
                }
            }
        }
        // Gap 10 boundary: the frozen scanner-launch contract pins an
        // overridden entrypoint to `sh` only (sandbox.rs:755-761). A create
        // body carrying any other Entrypoint override is denied; absent
        // entrypoint keeps the image default.
        if let Some(v) = obj.get("Entrypoint") {
            let ok = match v {
                Value::Null => true,
                Value::String(s) => s == "sh",
                Value::Array(a) => a.len() == 1 && a[0] == Value::String("sh".to_string()),
                _ => false,
            };
            if !ok {
                return deny(
                    "create-entrypoint",
                    "Entrypoint override must be absent or exactly sh".into(),
                );
            }
        }
        if let Some(v) = obj.get("Cmd") {
            match v {
                Value::Array(a)
                    if !a.is_empty() && a.iter().all(|e| matches!(e, Value::String(_))) => {}
                _ => return deny("create-cmd", "Cmd must be a non-empty string array".into()),
            }
        }
        if obj.get("User").and_then(|v| v.as_str()) != Some(SANDBOX_USER) {
            return deny(
                "create-user",
                format!("container User must be {SANDBOX_USER}"),
            );
        }
        // ReadonlyRootfs is a HostConfig field (real CLI wire capture places
        // it there). A top-level `ReadonlyRootfs` is ignored by the daemon,
        // so accepting it would authorize a container that is NOT read-only;
        // require the canonical HostConfig location to be explicitly true.
        if hc
            .and_then(|h| h.get("ReadonlyRootfs"))
            .and_then(|v| v.as_bool())
            != Some(true)
        {
            return deny(
                "create-readonly",
                "HostConfig.ReadonlyRootfs must be true".into(),
            );
        }
        // Real CLI wire capture for `--security-opt=no-new-privileges`
        // (sandbox.rs:824) sends the bare spelling ["no-new-privileges"];
        // `:true`/`=true` are equivalent enabled spellings. Every entry must
        // be a string and must be one of those enabled spellings — any other
        // security option (including the disabled `=false` form and mistyped
        // non-string entries) is denied (gap 4: mistyped never means absent).
        let secopts: Option<Vec<&str>> = hc.and_then(|h| h.get("SecurityOpt")).and_then(|v| {
            v.as_array()
                .and_then(|a| a.iter().map(|e| e.as_str()).collect::<Option<Vec<_>>>())
        });
        let secopts = match secopts {
            Some(s) if !s.is_empty() => s,
            _ => {
                return deny(
                    "create-securityopt",
                    "SecurityOpt must be a non-empty string list enabling no-new-privileges".into(),
                )
            }
        };
        for opt in &secopts {
            match *opt {
                "no-new-privileges" | "no-new-privileges=true" | "no-new-privileges:true" => {}
                _ => {
                    return deny(
                        "create-securityopt",
                        format!("security option '{opt}' is not permitted on this channel"),
                    )
                }
            }
        }
        if let Some(v) = hc.and_then(|h| h.get("Tmpfs")) {
            let tmpfs = match v.as_object() {
                Some(o) => o,
                None => return deny("create-tmpfs", "Tmpfs must be an object".into()),
            };
            for (dest, opts) in tmpfs.iter() {
                if !(dest == "/work" || dest.starts_with("/work/")) {
                    return deny(
                        "create-tmpfs",
                        format!("tmpfs destination '{dest}' is not under /work"),
                    );
                }
                if let Some(o) = opts.as_str() {
                    let mut seen = std::collections::HashSet::new();
                    for flag in o.split(',') {
                        let key = flag.split('=').next().unwrap_or(flag);
                        if !matches!(key, "rw" | "noexec" | "nosuid" | "nodev" | "size") {
                            return deny(
                                "create-tmpfs",
                                format!("tmpfs option '{flag}' is not permitted"),
                            );
                        }
                        if !seen.insert(key) {
                            return deny(
                                "create-tmpfs",
                                format!("duplicate tmpfs option in '{o}'"),
                            );
                        }
                    }
                    if !(o.contains("noexec") && o.contains("nosuid") && o.contains("nodev")) {
                        return deny(
                            "create-tmpfs",
                            "tmpfs must carry noexec,nosuid,nodev".into(),
                        );
                    }
                }
            }
        }
        // Only the empty/disabled restart contract is permitted: absent, `{}`,
        // or an explicit none shape. Any live restart policy would resurrect
        // scanner containers and is denied.
        if let Some(v) = hc.and_then(|h| h.get("RestartPolicy")) {
            let ok = match v {
                Value::Null => true,
                Value::Object(o) if o.is_empty() => true,
                Value::Object(o) => {
                    let name = o.get("Name").and_then(|n| n.as_str()).unwrap_or("");
                    let count = o
                        .get("MaximumRetryCount")
                        .and_then(|c| c.as_u64())
                        .unwrap_or(0);
                    (name.is_empty() || name == "none" || name == "no") && count == 0
                }
                _ => false,
            };
            if !ok {
                return deny("create-restartpolicy", "RestartPolicy is denied".into());
            }
        }
        Decision::allow("create-allowed", None)
    }

    /// `POST /AuthZPlugin.AuthZRes`: register container IDs seen in allowed
    /// create responses (M6). Gap 5: the daemon sends `ResponseBody` as
    /// base64 (M3/wire evidence); decode it strictly, require a JSON object
    /// with a non-empty string `Id`, and fail closed (register nothing) on
    /// any malformed or unexpected shape.
    pub fn observe(&self, res: &Value) -> bool {
        let body = match res.get("ResponseBody").and_then(|v| v.as_str()) {
            Some(b) => b,
            None => return false,
        };
        let raw = match b64_decode(body) {
            Some(r) => r,
            None => return false,
        };
        let text = match String::from_utf8(raw) {
            Ok(t) => t,
            Err(_) => return false,
        };
        let obj = match serde_json::from_str::<Value>(&text) {
            Ok(Value::Object(o)) => o,
            _ => return false,
        };
        match obj.get("Id").and_then(|v| v.as_str()) {
            Some(id) if !id.is_empty() => {
                self.registry.lock().unwrap().insert(id.to_string());
                true
            }
            _ => false,
        }
    }

    /// Append one JSONL decision record. Never logs request bodies.
    /// Gap 6: callers must pass the actual parsed Docker request
    /// (method/uri/identity), never a synthetic plugin-protocol envelope.
    /// Bodies, peer certificates, and header values are never logged.
    pub fn log_decision(
        &self,
        decision: &Decision,
        req: &AuthzRequest,
        elapsed: std::time::Duration,
    ) {
        let rec = serde_json::json!({
            "ts": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            "decision": if decision.allow { "allow" } else { "deny" },
            "rule": decision.rule,
            "msg": decision.msg,
            "method": req.method,
            "uri": req.uri,
            "user": req.user,
            "user_authn": req.user_authn,
            "target": decision.target,
            "duration_ms": elapsed.as_millis(),
        });
        if let Ok(mut f) = self.logger.lock() {
            let _ = writeln!(f, "{}", rec);
        }
    }

    /// Test/inspection helper: current registry contents.
    pub fn registered(&self) -> Vec<String> {
        self.registry.lock().unwrap().iter().cloned().collect()
    }
}
