//! FireCrow Docker authorization plugin — plugin-protocol server.
//!
//! Speaks the legacy Docker authorization plugin protocol (M1-M3) over the
//! unix socket the daemon resolves from the plugin name:
//! `--authorization-plugin=<name>` -> `/run/docker/plugins/<name>.sock`.
//!
//! Environment:
//!   FIRECROW_AUTHZ_NAME          plugin name (default `firecrow`)
//!   FIRECROW_AUTHZ_LOG           decision-log path (default /var/log/firecrow-authz.jsonl)
//!   FIRECROW_AUTHZ_ALLOWED_CNS   comma-separated TLS CN allowlist
//!                               (default `firecrow-backend`)
//!
//! The process holds no secrets and opens no outbound connections; it only
//! listens on the local socket. If it dies, the daemon fails closed (M7).

use docker_authz_plugin::{parse_request, AuthzRequest, Decision, Plugin};
use serde_json::Value;
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::Instant;

/// Hard cap on a single inbound HTTP request body (defense in depth; the
/// daemon's own limits apply upstream).
const MAX_REQUEST_BODY: usize = 64 * 1024 * 1024;

fn main() {
    let name = std::env::var("FIRECROW_AUTHZ_NAME").unwrap_or_else(|_| "firecrow".to_string());
    let log_path = std::env::var("FIRECROW_AUTHZ_LOG")
        .unwrap_or_else(|_| "/var/log/firecrow-authz.jsonl".to_string());
    let cns = std::env::var("FIRECROW_AUTHZ_ALLOWED_CNS")
        .unwrap_or_else(|_| "firecrow-backend".to_string());
    let allowed_cns: HashSet<String> = cns
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();

    let dir = "/run/docker/plugins";
    std::fs::create_dir_all(dir).expect("create plugin socket dir");
    let sock_path = format!("{dir}/{name}.sock");
    let _ = std::fs::remove_file(&sock_path);
    let listener = UnixListener::bind(&sock_path).expect("bind plugin socket");
    std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600))
        .expect("restrict plugin socket");

    let plugin = Arc::new(Plugin::new(allowed_cns, &log_path));
    eprintln!("docker-authz-plugin: listening on {sock_path}");

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let p = plugin.clone();
                std::thread::spawn(move || handle_conn(stream, p));
            }
            Err(_) => continue,
        }
    }
}

struct RawRequest {
    method: String,
    path: String,
    body: Vec<u8>,
    connection_close: bool,
}

fn handle_conn(stream: UnixStream, plugin: Arc<Plugin>) {
    let mut reader = match stream.try_clone() {
        Ok(r) => BufReader::new(r),
        Err(_) => return,
    };
    let mut writer = stream;
    loop {
        match read_request(&mut reader) {
            Ok(Some(req)) => {
                let (resp, close) = dispatch(&plugin, &req);
                if writer.write_all(&resp).is_err() || writer.flush().is_err() {
                    break;
                }
                if close {
                    break;
                }
            }
            // EOF or malformed input: close the connection. The daemon treats
            // an unusable plugin as a failure and denies (fail closed, M7).
            _ => break,
        }
    }
}

fn read_request(reader: &mut BufReader<UnixStream>) -> std::io::Result<Option<RawRequest>> {
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    if method.is_empty() || path.is_empty() || parts.next().is_none() {
        return Err(std::io::Error::other("malformed request line"));
    }
    let mut content_length = 0usize;
    let mut connection_close = false;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 {
            return Ok(None);
        }
        if header == "\r\n" || header == "\n" {
            break;
        }
        let Some((k, v)) = header.split_once(':') else {
            return Err(std::io::Error::other("malformed header"));
        };
        let v = v.trim();
        if k.eq_ignore_ascii_case("content-length") {
            content_length = v
                .parse()
                .map_err(|_| std::io::Error::other("bad content-length"))?;
        } else if k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("close") {
            connection_close = true;
        }
    }
    if content_length > MAX_REQUEST_BODY {
        return Err(std::io::Error::other("request body too large"));
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;
    Ok(Some(RawRequest {
        method,
        path,
        body,
        connection_close,
    }))
}

fn dispatch(plugin: &Plugin, req: &RawRequest) -> (Vec<u8>, bool) {
    let (status, payload, close) = match (req.method.as_str(), req.path.as_str()) {
        ("POST", "/Plugin.Activate") => (
            "200 OK",
            r#"{"Implements":["authz"]}"#.to_string(),
            req.connection_close,
        ),
        ("POST", "/AuthZPlugin.AuthZReq") => {
            let started = Instant::now();
            let v: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            // Gap 6: log the actual parsed Docker request (method/uri/TLS
            // identity), never the plugin-protocol envelope. Parse failures
            // log the envelope-independent deny reason with empty identity.
            let (decision, logged) = match parse_request(&v) {
                Ok(parsed) => {
                    let d = plugin.decide(&parsed);
                    (d, parsed)
                }
                Err(reason) => (
                    Decision {
                        allow: false,
                        rule: reason,
                        msg: format!("unusable authorization request: {reason}"),
                        target: None,
                    },
                    AuthzRequest {
                        method: String::new(),
                        uri: String::new(),
                        user: None,
                        user_authn: None,
                        body: None,
                    },
                ),
            };
            plugin.log_decision(&decision, &logged, started.elapsed());
            let body = format!(
                "{{\"Allow\":{},\"Msg\":{}}}",
                decision.allow,
                serde_json::to_string(&decision.msg).unwrap_or_else(|_| "\"\"".to_string())
            );
            ("200 OK", body, req.connection_close)
        }
        ("POST", "/AuthZPlugin.AuthZRes") => {
            let v: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            plugin.observe(&v);
            (
                "200 OK",
                r#"{"Allow":true}"#.to_string(),
                req.connection_close,
            )
        }
        _ => (
            "404 Not Found",
            r#"{"Allow":false,"Msg":"unknown plugin method"}"#.to_string(),
            true,
        ),
    };
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        payload.len(),
        payload
    );
    (resp.into_bytes(), close)
}
