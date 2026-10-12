# ADR 002: Canonical Audit Schema v1 for Multi-Engine Output Normalization

## Status
**Accepted**

## Context
FireCrow orchestrates multiple security engines, each emitting divergent output formats:
- Gitleaks produces a custom JSON array with fields like `Description`, `Secret`, `File`, `StartLine`, `EndLine`, `Commit`.
- Semgrep produces a JSON schema with `results` containing `check_id`, `path`, `start.line`, `extra.severity`, `extra.metadata`.
- OSV-Scanner produces a nested JSON schema with `results[].packages[].vulnerabilities[].id`, aliases (CVE/GHSA), affected versions.

If the frontend, PDF exporter, and risk scoring engine directly ingested raw scanner output files, tight coupling would occur. Any scanner version upgrade or change in engine flags would break the UI, export pipelines, and database queries.

## Decision
We define and mandate a single, versioned data contract: **Canonical Audit Schema v1** (`canonical_audit.rs`).
1. **Normalizer Pipeline**: Immediately following scanner execution, engine-specific adapters parse the raw JSON outputs and normalize each item into a uniform `Finding` structure.
2. **Standardized Severity**: Severities across all engines are mapped to an enum: `Critical`, `High`, `Medium`, `Low`, `Info`.
3. **CWE and Taxonomy Mapping**: Scanner-specific categories are mapped to standard Common Weakness Enumeration (CWE) identifiers.
4. **Immutable Binary Storage**: The normalized structure is stored as an immutable `JSONB` document in the `audit_results` table in PostgreSQL.
5. **Downstream Consumption**: The frontend dashboard, PDF report generator, and JSON export endpoints consume exclusively the Canonical Audit Schema v1.

## Consequences
### Positive
- **Engine Agnostic**: New engines (e.g., Trivy, Checkov) can be introduced by writing a single normalizer parser without changing frontend views or scoring algorithms.
- **Stable API Contracts**: API clients and webhooks receive predictable JSON payloads.
- **Export Consistency**: HTML and PDF reports share identical rendering models.

### Negative / Trade-offs
- Adding a new scanner requires authoring both an execution wrapper and a schema normalizer adapter.
- Engine-specific proprietary fields that cannot be mapped to the canonical schema are discarded or stored in a generic `metadata` map.
