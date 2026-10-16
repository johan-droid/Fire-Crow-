//! Filtering forward-proxy sidecar for scanner egress (G1, FC-ZT-SEC-001 §4).
//!
//! An HTTP CONNECT proxy that wraps the existing egress policy as its sole
//! authority. Scanner containers on the `internal: true` network have no
//! external route, so this sidecar — the only straddler — is their sole path
//! out. Proxy env vars on the scanner (`HTTPS_PROXY=…`) are addressing, not
//! the boundary; the boundary is the topology.
//!
//! Request flow per connection (§4.2 resolve-once-then-pin):
//! 1. Parse `CONNECT host:port`; anything else is a 400.
//! 2. `evaluate_egress_target(host, port)` — hostname + port verdict.
//! 3. Resolve **once** in the proxy; `evaluate_ip` **every** candidate.
//!    ANY non-`Allow` (DNS error, empty list, one mixed candidate) denies the
//!    whole request with 403. No fallback to an unvalidated address, ever.
//! 4. Connect to the pinned `IpAddr` (the hostname is never re-resolved).
//!    A connection failure may try the next *already-validated* candidate;
//!    a policy denial never retries, re-resolves, or re-routes.
//! 5. `200 Connection established`, then `copy_bidirectional`. TLS is
//!    end-to-end inside the tunnel.
//!
//! L4 scope honesty (§4.4.3): what is validated is exactly the CONNECT
//! `host:port` pre-check and the pinned-IP post-check. This proxy does NOT
//! inspect TLS SNI, HTTP methods/paths/headers, in-tunnel redirects, or
//! anything else inside the encrypted session. An allowance is host+IP
//! scoped: destinations co-hosted on an allowed IP share the allowance.
//! Pinning guarantees the socket reaches the *validated* address; it does
//! not make that address safe at the application layer.
//!
//! Runtime: `EGRESS_PROXY_PORT` (default `3128`, matching the
//! `http://egress-proxy:3128` contract in `osv_egress_enforcement` tests).
//! An unparseable port is a startup failure, never a silent default.

use firecrow_backend::services::egress_policy::{
    evaluate_egress_target, evaluate_ip, EgressDecision,
};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// Default listen port: the conventional forward-proxy port, and the one the
/// OSV container wiring already assumes (`http://egress-proxy:3128`).
const DEFAULT_PORT: u16 = 3128;
/// Cap on the CONNECT request head: a request line plus a handful of headers
/// fits in far less; anything larger is a malformed client.
const MAX_HEAD_BYTES: usize = 8192;
/// Time allowed for the client to send its CONNECT head.
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
/// Per-candidate TCP connect timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Bound on concurrent proxied connections. A compromised scanner (the only
/// client) must not be able to grow proxy memory without bound by opening
/// thousands of connections; excess connections are refused with 503 and
/// closed. `pids_limit` constrains processes, not tasks — this constrains
/// tasks.
const MAX_CONCURRENT_CONNECTIONS: usize = 128;

/// Tunables, so tests can shrink the waits without touching production
/// defaults. Only timeouts and caps — never policy.
#[derive(Debug, Clone, Copy)]
struct ProxyConfig {
    head_timeout: Duration,
    connect_timeout: Duration,
    max_head_bytes: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            head_timeout: HEAD_TIMEOUT,
            connect_timeout: CONNECT_TIMEOUT,
            max_head_bytes: MAX_HEAD_BYTES,
        }
    }
}

/// Why a CONNECT request was denied. Carries the evaluator's own reason
/// text where one exists — operator-facing policy labels, never secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DenyReason {
    /// `evaluate_egress_target` refused the hostname/port.
    Target(&'static str),
    /// The in-proxy resolution failed.
    Dns,
    /// The resolver returned no candidates.
    Empty,
    /// At least one resolved candidate failed `evaluate_ip`.
    Candidate(&'static str),
}

/// A fallible hostname resolution. `Ok(vec![])` and `Err` both deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolveError {
    Failed,
}

/// Production resolver: blocking system DNS (A and AAAA via the platform
/// resolver), deduplicated, order-preserved. Runs on a blocking thread via
/// the caller — never on the async runtime.
fn system_resolve(host: &str) -> Result<Vec<IpAddr>, ResolveError> {
    let mut out = Vec::new();
    let addrs = std::net::ToSocketAddrs::to_socket_addrs(format!("{host}:443").as_str())
        .map_err(|_| ResolveError::Failed)?;
    for addr in addrs {
        let ip = addr.ip();
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    Ok(out)
}

/// Parse the listen port. Pure, so the startup contract is unit-tested:
/// garbage never becomes a silent default.
fn proxy_port(raw: Option<String>) -> Result<u16, String> {
    match raw {
        None => Ok(DEFAULT_PORT),
        Some(value) => {
            let port = value
                .trim()
                .parse::<u16>()
                .map_err(|_| format!("EGRESS_PROXY_PORT is not a valid port: {value:?}"))?;
            if port == 0 {
                return Err("EGRESS_PROXY_PORT must not be 0".to_string());
            }
            Ok(port)
        }
    }
}

/// Parse a CONNECT request line into `(host, port)`. Purely syntactic — the
/// evaluator stays the sole policy authority; anything shaped wrong here is
/// a 400 before policy ever sees it.
fn parse_connect_line(line: &str) -> Result<(String, u16), &'static str> {
    let mut parts = line.split_whitespace();
    let (method, authority, version) = match (parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(a), Some(v)) if parts.next().is_none() => (m, a, v),
        _ => return Err("malformed CONNECT line"),
    };
    if method != "CONNECT" {
        return Err("only CONNECT is supported");
    }
    // Exact protocol versions only: a prefix match would accept `HTTP/EVIL`
    // and leave version handling to whatever parses next.
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err("unsupported HTTP version");
    }
    parse_authority(authority)
}

/// Split a CONNECT authority into host + port. Bracketed IPv6 (`[::1]:443`)
/// and bare `host:port` only; userinfo, paths, and extra colons are rejected
/// here (and would be rejected again by the evaluator — this is framing, not
/// policy).
fn parse_authority(authority: &str) -> Result<(String, u16), &'static str> {
    if authority.is_empty() || authority.len() > 253 {
        return Err("malformed authority");
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .ok_or("malformed bracketed authority")?;
        if host.is_empty() || host.contains(['[', ']']) {
            return Err("malformed bracketed authority");
        }
        let port = port.parse::<u16>().map_err(|_| "malformed port")?;
        return Ok((host.to_string(), port));
    }
    if authority.contains(['@', '/', '[', ']'])
        || authority
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err("malformed authority");
    }
    let (host, port) = authority.rsplit_once(':').ok_or("authority has no port")?;
    if host.is_empty() || host.contains(':') {
        return Err("malformed authority");
    }
    let port = port.parse::<u16>().map_err(|_| "malformed port")?;
    Ok((host.to_string(), port))
}

/// Step 2 of the request flow: the hostname + port verdict, BEFORE any DNS.
/// Denied targets never reach resolution — no query leaves the proxy for a
/// destination policy already refused.
fn check_target(host: &str, port: u16) -> Result<(), DenyReason> {
    if let EgressDecision::Block(reason) = evaluate_egress_target(host, port) {
        return Err(DenyReason::Target(reason));
    }
    Ok(())
}

/// Step 3 over an ALREADY-COMPLETED single resolution: per-candidate
/// validation. Returns the validated candidates to pin, in resolver order.
///
/// Taking the resolution as a value (rather than a resolver callback) is
/// structural single-resolution: the caller resolved once, and there is no
/// handle left with which to resolve again between validation and connect.
/// A rebinding answer swap therefore has nothing to hook into.
fn check_candidates(
    resolved: Result<Vec<IpAddr>, ResolveError>,
) -> Result<Vec<IpAddr>, DenyReason> {
    let candidates = resolved.map_err(|_| DenyReason::Dns)?;
    if candidates.is_empty() {
        return Err(DenyReason::Empty);
    }
    for ip in &candidates {
        if let EgressDecision::Block(reason) = evaluate_ip(*ip) {
            // One disallowed candidate denies the whole request: no
            // partial-trust interpretation of a mixed answer.
            return Err(DenyReason::Candidate(reason));
        }
    }
    Ok(candidates)
}

/// Step 4 mechanics over an ALREADY-VALIDATED candidate list: connect to the
/// pinned `IpAddr` objects in order (the hostname is never consulted again)
/// and return the connected stream. A connection failure tries the next
/// validated candidate; the list is fixed — no re-resolution and no
/// unvalidated fallback on any path.
async fn connect_pinned(
    port: u16,
    validated: &[IpAddr],
    connect_timeout: Duration,
) -> Result<TcpStream, ()> {
    for ip in validated {
        let target = SocketAddr::new(*ip, port);
        match tokio::time::timeout(connect_timeout, TcpStream::connect(target)).await {
            Ok(Ok(upstream)) => return Ok(upstream),
            // Connection refusal, timeout, or any other failure: the next
            // VALIDATED candidate may still serve. Nothing is re-resolved.
            _ => continue,
        }
    }
    Err(())
}

async fn respond(mut stream: TcpStream, status: &str) {
    let _ = stream
        .write_all(format!("{status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").as_bytes())
        .await;
}

/// One client connection: parse, resolve once, authorize, connect-or-deny,
/// tunnel. The resolver runs on a blocking thread (production DNS is
/// blocking); every other step is async. Exactly one resolution happens per
/// request, by construction: the value flows into `authorize_target`, which
/// accepts no resolver. The `'static` bound is what lets the blocking call
/// move onto the blocking pool.
async fn serve_connection(
    stream: TcpStream,
    resolve: impl Fn(&str) -> Result<Vec<IpAddr>, ResolveError> + Send + Sync + 'static,
    config: ProxyConfig,
) {
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();
    // Read the CONNECT head: first line is the request line, the rest is
    // consumed framing (one request per connection, then close). Bytes
    // already buffered past the blank line are dropped with the reader —
    // safe because clients must wait for the 200 before sending; pipelined
    // pre-200 bytes would be lost, which is breakage-only, never a bypass
    // (no keep-alive is implemented).
    let mut reader = BufReader::new(stream);
    let mut request_line: Option<String> = None;
    let mut total = 0usize;
    let read_head = async {
        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line).await.map_err(|_| ())?;
            if n == 0 {
                return Err(());
            }
            total += n;
            if total > config.max_head_bytes {
                return Err(());
            }
            if request_line.is_none() {
                request_line = Some(line.trim_end().to_string());
            }
            if line == "\r\n" || line == "\n" {
                break;
            }
        }
        Ok(request_line.unwrap_or_default())
    };
    let request_line = match tokio::time::timeout(config.head_timeout, read_head).await {
        Ok(Ok(line)) => line,
        _ => {
            respond(reader.into_inner(), "HTTP/1.1 400 Bad Request").await;
            return;
        }
    };
    let (host, port) = match parse_connect_line(&request_line) {
        Ok(parsed) => parsed,
        Err(_) => {
            respond(reader.into_inner(), "HTTP/1.1 400 Bad Request").await;
            return;
        }
    };
    // Target verdict BEFORE resolution: denied hosts never cause a DNS
    // query to leave the proxy.
    if let Err(reason) = check_target(&host, port) {
        eprintln!("deny {host}:{port} from {peer}: {reason:?}");
        respond(reader.into_inner(), "HTTP/1.1 403 Forbidden").await;
        return;
    }
    let resolved = {
        let host_for_dns = host.clone();
        tokio::task::spawn_blocking(move || resolve(&host_for_dns))
            .await
            .unwrap_or(Err(ResolveError::Failed))
    };
    let validated = match check_candidates(resolved) {
        Ok(addrs) => addrs,
        Err(reason) => {
            eprintln!("deny {host}:{port} from {peer}: {reason:?}");
            respond(reader.into_inner(), "HTTP/1.1 403 Forbidden").await;
            return;
        }
    };
    match connect_pinned(port, &validated, config.connect_timeout).await {
        Ok(upstream) => {
            let connected = upstream
                .peer_addr()
                .map(|a| a.to_string())
                .unwrap_or_default();
            eprintln!("allow {host}:{port} from {peer} via {connected}");
            let mut client = reader.into_inner();
            let mut upstream = upstream;
            let _ = client
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await;
            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        }
        Err(()) => {
            // Allowed but unreachable: 502, not 403 — and no retry beyond
            // the validated list (already exhausted inside connect_pinned).
            eprintln!("unreachable {host}:{port} from {peer}: all validated candidates refused");
            respond(reader.into_inner(), "HTTP/1.1 502 Bad Gateway").await;
        }
    }
}

#[tokio::main]
async fn main() {
    let port = match proxy_port(std::env::var("EGRESS_PROXY_PORT").ok()) {
        Ok(port) => port,
        Err(reason) => {
            eprintln!("egress-proxy: refusing to start: {reason}");
            std::process::exit(1);
        }
    };
    let listener = match TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port)).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("egress-proxy: cannot bind port {port}: {error}");
            std::process::exit(1);
        }
    };
    eprintln!("egress-proxy: listening on port {port}");
    // IPv4-only bind: the compose internal network is an IPv4 /16, so there
    // is no v6 listener to add. Revisit if the topology ever goes dual-stack.
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let semaphore = semaphore.clone();
        tokio::spawn(handle_accept(stream, semaphore));
    }
}

/// One accepted connection under the concurrency bound. Excess connections
/// are refused with 503 and closed — never queued unboundedly.
async fn handle_accept(stream: TcpStream, semaphore: std::sync::Arc<tokio::sync::Semaphore>) {
    match semaphore.try_acquire_owned() {
        Ok(_permit) => serve_connection(stream, system_resolve, ProxyConfig::default()).await,
        Err(_) => {
            eprintln!("overload: refusing excess connection");
            respond(stream, "HTTP/1.1 503 Service Unavailable").await;
        }
    }
}

#[cfg(test)]
mod proxy_tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    const PUBLIC: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    const PRIVATE: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    const METADATA: IpAddr = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));

    fn ok_ips(ips: Vec<IpAddr>) -> Result<Vec<IpAddr>, ResolveError> {
        Ok(ips)
    }

    fn test_config() -> ProxyConfig {
        ProxyConfig {
            head_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_millis(300),
            max_head_bytes: MAX_HEAD_BYTES,
        }
    }

    // --- startup contract -------------------------------------------------

    #[test]
    fn default_port_matches_the_container_wiring() {
        assert_eq!(proxy_port(None).unwrap(), 3128);
        assert_eq!(proxy_port(Some("8080".into())).unwrap(), 8080);
        assert!(
            proxy_port(Some("0".into())).is_err(),
            "port 0 must fail startup"
        );
        assert!(proxy_port(Some("not-a-port".into())).is_err());
        assert!(proxy_port(Some(String::new())).is_err());
    }

    // --- CONNECT framing ----------------------------------------------------

    #[test]
    fn valid_connect_lines_parse() {
        assert_eq!(
            parse_connect_line("CONNECT api.osv.dev:443 HTTP/1.1").unwrap(),
            ("api.osv.dev".to_string(), 443)
        );
        assert_eq!(
            parse_connect_line("CONNECT [::1]:443 HTTP/1.0").unwrap(),
            ("::1".to_string(), 443)
        );
    }

    #[test]
    fn non_connect_methods_and_malformed_lines_are_400s() {
        for line in [
            "GET http://api.osv.dev/ HTTP/1.1",
            "connect api.osv.dev:443 HTTP/1.1",
            "CONNECT api.osv.dev:443",
            "CONNECT api.osv.dev:443 HTTP/1.1 EXTRA",
            "CONNECT evil.com@api.osv.dev:443 HTTP/1.1",
            "CONNECT api.osv.dev:443 FTP/1.0",
            "CONNECT api.osv.dev:443 HTTP/EVIL",
            "CONNECT :443 HTTP/1.1",
            "CONNECT api.osv.dev:99999 HTTP/1.1",
            "CONNECT []:443 HTTP/1.1",
            "",
        ] {
            assert!(parse_connect_line(line).is_err(), "must reject: {line:?}");
        }
    }

    // --- authorize: the real policy over stub resolutions --------------------

    #[test]
    fn allowlisted_host_with_clean_candidates_pins_them_exactly() {
        check_target("api.osv.dev", 443).expect("allowlisted host:port must pass the target check");
        let validated = check_candidates(Ok(vec![PUBLIC])).unwrap();
        assert_eq!(
            validated,
            vec![PUBLIC],
            "pin the exact validated IP, nothing else"
        );
    }

    #[test]
    fn target_denials_never_reach_resolution() {
        // Each case is denied by check_target alone, which takes no resolver
        // at all — denied hosts structurally cannot cause a DNS query. (The
        // serve-level test below proves serve_connection honors the order.)
        for (host, port) in [
            ("203.0.113.7", 443),          // direct IP literal
            ("0x7f.0.0.1", 443),           // alt-spelling loopback
            ("2130706433", 443),           // decimal-spelling loopback
            ("evil.example", 443),         // non-allowlisted domain
            ("api.osv.dev", 80),           // wrong port
            ("evil.com@api.osv.dev", 443), // authority smuggling
        ] {
            assert!(
                matches!(check_target(host, port), Err(DenyReason::Target(_))),
                "must deny target {host}:{port}"
            );
        }
    }

    #[test]
    fn dns_failure_empty_and_mixed_answers_all_deny() {
        assert_eq!(
            check_candidates(Err(ResolveError::Failed)),
            Err(DenyReason::Dns)
        );
        assert_eq!(check_candidates(Ok(vec![])), Err(DenyReason::Empty));
        assert!(
            matches!(
                check_candidates(Ok(vec![PUBLIC, PRIVATE])),
                Err(DenyReason::Candidate(_))
            ),
            "one disallowed candidate denies the whole request"
        );
    }

    #[test]
    fn blocked_candidate_ranges_deny() {
        for ip in [
            LOOPBACK,
            METADATA,
            PRIVATE,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 10, 20)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            IpAddr::V6("fe80::1".parse().unwrap()),
            IpAddr::V6("fc00::1".parse().unwrap()),
            IpAddr::V6("2001:db8::1".parse().unwrap()),
            IpAddr::V6("::ffff:127.0.0.1".parse().unwrap()),
        ] {
            assert!(
                matches!(
                    check_candidates(Ok(vec![ip])),
                    Err(DenyReason::Candidate(_))
                ),
                "must deny candidate {ip}"
            );
        }
    }

    // --- connect mechanics: exact IP, bytes flow, validated-only fallback ----

    #[tokio::test]
    async fn tunnel_reaches_exactly_the_validated_ip() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = sock.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
        // The ONLY connection: through connect_pinned, over the validated
        // address. The echo task accepts exactly this one.
        let validated = vec![addr.ip()];
        let mut upstream = connect_pinned(addr.port(), &validated, Duration::from_secs(5))
            .await
            .expect("loopback echo must connect");
        assert_eq!(
            upstream.peer_addr().unwrap(),
            addr,
            "socket must reach exactly the validated address"
        );
        // Bytes flow through the returned stream.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        upstream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        upstream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn connection_failure_falls_to_the_next_validated_candidate() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = sock.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
        // First candidate refuses (nothing listens on .2), second serves.
        // Both are pre-validated inputs — no resolution happens here.
        let dead = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let upstream = connect_pinned(addr.port(), &[dead, addr.ip()], Duration::from_secs(5))
            .await
            .expect("must fall through to the live candidate");
        assert_eq!(upstream.peer_addr().unwrap(), addr);
    }

    #[tokio::test]
    async fn exhausted_candidates_are_an_error_not_a_fallback() {
        let dead = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        assert!(
            connect_pinned(9, &[dead], Duration::from_millis(200))
                .await
                .is_err(),
            "no validated candidate left means failure, never an unvalidated address"
        );
    }

    // --- serve_connection over real TCP --------------------------------------

    async fn serve_once(
        request: &str,
        resolve: impl Fn(&str) -> Result<Vec<IpAddr>, ResolveError> + Send + Sync + 'static,
    ) -> String {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve_connection(stream, resolve, test_config()).await;
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        client.write_all(request.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
            .await
            .expect("proxy must answer promptly")
            .expect("readable");
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }

    #[tokio::test]
    async fn denied_targets_get_403_without_touching_dns() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let response = serve_once(
            "CONNECT evil.example:443 HTTP/1.1\r\n\r\n",
            move |_: &str| {
                seen.fetch_add(1, Ordering::SeqCst);
                ok_ips(vec![PUBLIC])
            },
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 403"), "got: {response:?}");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "denied target must not resolve"
        );
    }

    #[tokio::test]
    async fn dns_failure_and_mixed_answers_get_403() {
        let r1 = serve_once("CONNECT api.osv.dev:443 HTTP/1.1\r\n\r\n", |_: &str| {
            Err(ResolveError::Failed)
        })
        .await;
        assert!(
            r1.starts_with("HTTP/1.1 403"),
            "DNS failure must fail closed: {r1:?}"
        );
        let r2 = serve_once("CONNECT api.osv.dev:443 HTTP/1.1\r\n\r\n", |_: &str| {
            ok_ips(vec![PUBLIC, PRIVATE])
        })
        .await;
        assert!(
            r2.starts_with("HTTP/1.1 403"),
            "mixed answer must fail closed: {r2:?}"
        );
    }

    #[tokio::test]
    async fn allowed_but_unreachable_is_502_and_resolves_once() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_in = seen.clone();
        let calls_in = calls.clone();
        let response = serve_once(
            "CONNECT api.osv.dev:443 HTTP/1.1\r\n\r\n",
            move |host: &str| {
                calls_in.fetch_add(1, Ordering::SeqCst);
                seen_in.lock().unwrap().push(host.to_string());
                // Allowed public address, unreachable in this sandbox: proves
                // the allow-path reaches the connect stage (502, not 403) while
                // resolving exactly once (no rebinding window).
                ok_ips(vec![PUBLIC])
            },
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 502"),
            "allowed-but-unreachable is 502: {response:?}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "exactly one resolution per request"
        );
        assert_eq!(*seen.lock().unwrap(), vec!["api.osv.dev".to_string()]);
    }

    #[tokio::test]
    async fn malformed_requests_get_400() {
        let r = serve_once("GET http://api.osv.dev/ HTTP/1.1\r\n\r\n", |_: &str| {
            ok_ips(vec![PUBLIC])
        })
        .await;
        assert!(r.starts_with("HTTP/1.1 400"), "got: {r:?}");
    }

    #[tokio::test]
    async fn excess_connections_are_refused_with_503() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let semaphore = Arc::new(tokio::sync::Semaphore::new(2));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let semaphore = semaphore.clone();
                tokio::spawn(handle_accept(stream, semaphore));
            }
        });
        // Hold both permits with idle connections (no CONNECT sent; the
        // server waits on the head timeout while the permit is held).
        let mut held = Vec::new();
        for _ in 0..2 {
            held.push(TcpStream::connect(addr).await.unwrap());
        }
        // The third connection exceeds the bound: prompt 503, then close.
        let mut extra = TcpStream::connect(addr).await.unwrap();
        extra
            .write_all(b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(5), extra.read(&mut buf))
            .await
            .expect("overload refusal must be prompt")
            .expect("readable");
        let response = String::from_utf8_lossy(&buf[..n]).into_owned();
        assert!(response.starts_with("HTTP/1.1 503"), "got: {response:?}");
        let _ = held;
    }
}
