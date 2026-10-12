# ADR 001: Scanner-First Architecture and AI Isolation

## Status
**Accepted** (Architectural Invariant)

## Context
Automated vulnerability scanning systems increasingly attempt to use Large Language Models (LLMs) to inspect code and generate security findings. However, LLMs are fundamentally probabilistic and subject to severe failure modes in security contexts:
1. **Hallucination of Vulnerabilities**: Fabricating CVEs, nonexistent functions, and phantom attack surfaces.
2. **False Sense of Security**: Failing to report subtle, high-entropy secrets or known dependency vulnerabilities due to context window truncation or attention drift.
3. **Non-Deterministic Outputs**: Producing divergent findings across identical runs on the exact same commit hash, making audits non-reproducible for compliance frameworks (SOC 2, ISO 27001).
4. **Data Exfiltration Risk**: Sending proprietary customer source code across third-party LLM APIs.

## Decision
FireCrow implements an absolute **Scanner-First Architecture**:
1. **Authoritative Engines Only**: All security findings originate exclusively from deterministic, battle-tested, open-source security engines executed inside ephemeral Docker micro-sandboxes:
   - **Gitleaks** (`ghcr.io/gitleaks/gitleaks:v8.18.4`) for secrets and high-entropy credentials.
   - **Semgrep** (`semgrep/semgrep:1.96.0`) for AST-based SAST rules.
   - **OSV-Scanner** (`ghcr.io/google/osv-scanner:v2.2.4`) for open-source vulnerability dependency graphs.
2. **Deterministic Risk Score**: The 0–100 security score is computed purely through mathematical deduction applied to scanner findings.
3. **AI Isolation Guard**: The optional Google Gemini integration operates strictly downstream of the finalized audit record:
   - The LLM receives only structured, sanitized metadata (finding names, severities, rule IDs, affected filenames, line numbers).
   - The LLM **never** receives raw customer source code or repository tarballs.
   - The LLM is structurally barred from generating new findings, altering finding counts, modifying CVSS severities, or editing the calculated risk score.
   - Database schemas and API serialization layers enforce this boundary programmatically.

## Consequences
### Positive
- **100% Reproducible Audits**: Re-running an audit against the same commit hash with identical scanner versions yields the exact same findings and score.
- **Audit-Grade Compliance**: Security teams and compliance auditors can trace every reported item directly to a deterministic rule or known CVE database entry.
- **Zero Source Code Exfiltration**: Intellectual property never leaves the local execution boundary.

### Negative / Trade-offs
- Scanners must be maintained, container images updated, and rules kept current.
- Execution requires a container runtime (Docker daemon) accessible to the backend worker.
