# Threat Model & STRIDE Analysis

This document provides a comprehensive threat model for the FireCrow repository security scanning platform, detailing trust boundaries, attacker profiles, and mitigations mapped against the **STRIDE** methodology.

---

## 1. System Trust Boundaries

```mermaid
flowchart TD
    subgraph TB0["Trust Boundary 0: Public Clients"]
        Client["Web Browser / Attacker Client"]
    end

    subgraph TB1["Trust Boundary 1: Edge & Network"]
        VercelCDN["Vercel CDN Edge"]
        RenderLB["Render Load Balancer / Reverse Proxy"]
    end

    subgraph TB2["Trust Boundary 2: Host Operating System"]
        AxumService["Axum 0.7 Web Engine (Unprivileged User)"]
        DockerSock["Docker Unix Socket (/var/run/docker.sock)"]
        WorkDir["Host Filesystem (/tmp/firecrow)"]
    end

    subgraph TB3["Trust Boundary 3: Container Micro-Sandboxes"]
        ScannerCont["Gitleaks / Semgrep / OSV Container\n(Net: None, Cap-Drop: ALL)"]
    end

    subgraph TB4["Trust Boundary 4: Data & External APIs"]
        PostgresDB[("PostgreSQL 16 (SSL)")]
        GitHubAPI["GitHub REST API"]
        GeminiAPI["Google Gemini API"]
    end

    Client -->|Untrusted HTTP| VercelCDN
    Client -->|Untrusted HTTP + Cookies| RenderLB
    RenderLB --> AxumService
    AxumService --> DockerSock
    DockerSock --> ScannerCont
    AxumService --> WorkDir
    ScannerCont -.->|Read-Only Mount| WorkDir
    AxumService -->|TLS| PostgresDB
    AxumService -->|HTTPS| GitHubAPI
    AxumService -->|HTTPS (Sanitized Data)| GeminiAPI
```

---

## 2. STRIDE Threat Analysis Matrix

| Threat Category | Potential Attack Vector | Impact | Implemented Mitigations |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Attacker spoofs session cookie to impersonate an organization admin. | Unauthorized access to repository audit findings. | Cryptographically signed session cookies (`fc_access_token`; Argon2id + HMAC-SHA256); `HttpOnly`, `Secure` flags prevent XSS access; Origin-allowlist CSRF guard on mutating methods; 15-minute token lifespan; mandatory TOTP MFA. |
| **Tampering** | Malicious repository includes crafted tarball with path traversal (`../../etc/passwd`) or symlinks targeting host files. | Arbitrary file overwrite or unauthorized read on host filesystem. | `FetchAgent` validates pax headers; rejects any tar entries with `..` or leading `/`; drops symlinks resolving outside the ephemeral workspace; strips executable bits. |
| **Tampering** | Downstream Gemini AI synthesis tampers with finding count or modifies severity score. | Misleading compliance report; suppression of critical vulnerabilities. | Structural validation on AI output: schema enforces that AI cannot invent findings or alter score; PostgreSQL triggers enforce immutability of scanner outputs. |
| **Repudiation** | User denies having initiated an audit scan or deleting an organization asset. | Audit trail ambiguity. | Immutable database audit log (`audit_jobs`) recording initiating `user_id`, client IP hash, timestamp, and target commit SHA. |
| **Information Disclosure** | Rogue scanner container exfiltrates analyzed proprietary source code or discovered secrets over the internet. | Source code theft and credential exposure. | Docker containers spawned with `--network none`, completely removing the network stack at the container namespace level. |
| **Information Disclosure** | Insecure Direct Object Reference (IDOR): Authenticated user queries `/api/audit/:id` belonging to another tenant. | Cross-tenant data leakage. | Database queries strictly enforce `WHERE id = $1 AND owner_id = $2`. Non-matching tenant reads return `404 Not Found`. |
| **Denial of Service** | Attacker submits a decompression bomb ("zip bomb") expanding a 1MB archive into 100GB. | Disk exhaustion, host kernel panic, server crash. | `FetchAgent` applies streaming decompression with a strict **150MB ceiling** (`MAX_TOTAL_BYTES = 157,286,400`; 100MB download cap, 20MB per-file cap, 20,000-file cap). If cumulative uncompressed bytes exceed 150MB, extraction aborts immediately. |
| **Denial of Service** | Attacker writes a malicious repository script that spawns endless threads (fork bomb) during Semgrep execution. | Host CPU and process table exhaustion. | Container limits: `--pids-limit 100`, `--cpus 1.0`, `--memory 1024m`, and a hard 300-second container timeout with automatic `SIGKILL`. |
| **Elevation of Privilege** | Container breakout attack attempting to compromise the host Docker daemon. | Host takeover. | Scanners run with `--cap-drop ALL`, `--security-opt no-new-privileges`, `--read-only` root filesystem, and unprivileged user mappings. Host repo mount is strictly read-only (`:ro`). **Backend→daemon boundary:** the backend reaches Docker only through an mTLS channel (`CN=firecrow-backend`) with the **Docker authorization plugin** (`docker-authz-plugin/`) enforcing a deny-by-default policy at the daemon: privileged creates, capability additions, host binds, host namespaces, device passthrough, unapproved images, and non-scanner names are all denied with an exact rule reason. A path/method socket proxy alone is a category filter, not a containment boundary (it cannot see request bodies); the authorization plugin is the content boundary. Verified at runtime against Engine 29.1.3 (76 assertions, 0 failures). |

---

## 3. Threat Profiles & Security Guarantees

### Attacker Profile A: Malicious Code Contributor
- **Objective**: Execute code on FireCrow host or exfiltrate host secrets via a pull request audit.
- **Result**: **Blocked**. Code is never compiled or executed directly. Scanners execute with `--network none` and `--cap-drop ALL`. Symlinks targeting host paths are discarded during extraction.

### Attacker Profile B: Compromised Scanner Dependency
- **Objective**: Backdoored scanner container attempts to phone home with scanned secrets.
- **Result**: **Blocked**. Kernel-level container network namespace has no network interface (`--network none`). DNS resolution and socket connections fail immediately.

### Attacker Profile C: Malicious AI Model Output
- **Objective**: LLM hallucinates non-existent findings or removes critical vulnerabilities.
- **Result**: **Blocked**. The LLM operates purely downstream. Finding records in `audit_results` originate solely from scanner JSON adapters.
