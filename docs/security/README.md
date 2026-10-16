# Security Philosophy & Core Invariants

FireCrow is a security engineering platform designed from first principles with a **Zero-Trust**, **Defense-in-Depth** architecture. Because the system ingests and analyzes untrusted third-party code repositories, security is treated as an inviolable structural constraint rather than an afterthought.

---

## 1. Core Security Principles

### 1. Ingestion is Untrusted Input
Every customer repository, branch, tarball, and configuration file is considered potentially hostile. Repositories may contain decompression bombs, path traversal attacks, symlink exploits, or malicious build scripts. Untrusted code is never executed directly on the host machine.

### 2. Scanner-First Truth & `failure != clean`
Security findings originate strictly from deterministic, sandboxed scanners (`gitleaks`, `semgrep`, `osv-scanner`). If an engine crashes, runs out of memory, or encounters a syntax error, the system records incomplete audit truth—never a false clean pass.

### 3. AI Isolation & Downstream Boundaries
The Google Gemini AI narrative layer operates strictly downstream of the finalized audit ledger. Structural schema validators and database triggers prevent the LLM from hallucinating vulnerabilities, deleting findings, or altering the calculated 0–100 risk score.

### 4. Zero-Privilege Micro-Sandboxing
All scanner engines execute in ephemeral Docker containers stripped of all Linux capabilities (`--cap-drop=ALL`), with root filesystem read-only, loopback/egress disabled (`--network=none`), and strict process and memory limits.

### 5. Ephemeral Workspaces & Code Cleanliness
Source code extracted during an audit exists on the host filesystem only for the duration of the scan. Ephemeral workspaces in `/tmp/firecrow` are destroyed immediately via guaranteed cleanup routines upon job completion or failure. Zero customer intellectual property persists on host disks.

---

## 2. Security Documentation Suite

1. [docs/security/threat-model.md](../../../../../../docs/security/threat-model.md) — STRIDE threat analysis, trust boundaries, attacker profiles, and mitigations.
2. [docs/security/secure-development.md](../../../../../../docs/security/secure-development.md) — Secure coding guidelines for Rust and TypeScript, input sanitization, and dependency scanning.
3. [docs/security/incident-response.md](../../../../../../docs/security/incident-response.md) — Severity tiers, containment playbooks, incident communications, and post-mortem procedures.

---

## 3. Standing Operational Requirement: Scanner Test-Fixture Credentials

`backend/tests/live_e2e.rs` deliberately plants secret-shaped strings — including a GitHub PAT-shaped fixture (real `ghp_` prefix) — so the secret scanner has something genuine to detect. Whether that fixture ever matched a real credential cannot be determined offline from this repository. The repository owner must:

1. **Verify out-of-band** (e.g. via GitHub token review/revocation) that the planted fixture token is **not** a valid credential, and **rotate/revoke it if it is**.
2. **Never replace the fixture with a functional credential.** A live token in a test tree defeats the test's purpose and risks exposure through test output, container images, and CI logs.

This is a one-time verification plus a standing rule for any future secret-shaped fixtures added to tests.
