# Secure Development & Engineering Standards

This document establishes the mandatory secure coding practices, static analysis requirements, and memory safety standards for the FireCrow codebase.

---

## 1. Rust Secure Coding Standards (`backend/`)

### Rule 1: Zero `unsafe` Code Policy
Application crates must not use `unsafe` code blocks. Memory safety guarantees are enforced by the Rust compiler.

### Rule 2: Exclusively Parameterized SQL Queries (SQLx)
All queries executed against PostgreSQL must use SQLx compile-time checked queries or parameterized queries.
```rust
// CORRECT: Fully parameterized query
sqlx::query_as::<_, AuditJob>(
    "SELECT * FROM audit_jobs WHERE id = $1 AND owner_id = $2"
)
.bind(job_id)
.bind(user_id)
.fetch_optional(&pool)
.await?;

// STRICTLY FORBIDDEN: String interpolation in SQL
// sqlx::query(&format!("SELECT * FROM audit_jobs WHERE id = '{}'", job_id)) // VULNERABILITY
```

### Rule 3: Error Masking in HTTP Envelopes
Never expose internal database error messages, stack traces, or file paths in client-facing HTTP responses:
- Log internal details at `tracing::error!` level with the associated `request_id`.
- Return generic error messages to clients:
  ```json
  {
    "error": {
      "code": "INTERNAL_SERVER_ERROR",
      "message": "An unexpected error occurred. Reference request ID for support.",
      "request_id": "c1f73b64-8422-4416-8f3b-ec86b36423a2"
    }
  }
  ```

### Rule 4: Canonical Path Resolution
When interacting with the filesystem in `FetchAgent` or `ScannerAgent`:
- Never concatenate unvalidated user strings into file paths.
- Ensure all paths resolve strictly within the designated `WORK_DIR` sandbox directory (`/tmp/firecrow/workspaces/{id}`).

---

## 2. Frontend Security Standards (`frontend/`)

### Rule 1: No `dangerouslySetInnerHTML`
Vulnerability descriptions and scanner rule details must be rendered as raw text inside React elements. React JSX automatically escapes characters like `<`, `>`, `&`, and `"`, preventing Cross-Site Scripting (XSS).

```tsx
// CORRECT: Safe React text rendering
<div className="finding-description">{finding.description}</div>

// STRICTLY FORBIDDEN: Unescaped HTML injection
// <div dangerouslySetInnerHTML={{ __html: finding.description }} /> // VULNERABILITY
```

### Rule 2: Origin-Header CSRF Enforcement
The backend enforces the CSRF control (`backend/src/middleware/csrf.rs`): all state-modifying requests (`POST`, `PUT`, `PATCH`, `DELETE`) must carry an `Origin` header listed in the configured origin allowlist, and mutations that carry the auth cookies but no `Origin` header are rejected with 403. There is no CSRF token header or cookie — frontend requests must simply be sent from an allowlisted origin with `credentials: 'include'`. Non-browser clients using `Authorization: Bearer` headers are unaffected.

### Rule 3: Safe External URL Handling
When rendering links to external repositories or GitHub commits, enforce safe protocols:
- Only allow `https://` URLs.
- Always include `rel="noopener noreferrer"` on `target="_blank"` anchor tags to prevent reverse tabnabbing.

---

## 3. Dependency & Supply Chain Auditing

### Automated Rust Crate Auditing
Run cargo audit to scan dependency tree against the RustSec Advisory Database:
```bash
cargo audit
```

### Frontend Dependency Auditing
Verify npm package integrity and vulnerabilities:
```bash
npm audit --omit=dev
```

### Docker Container Digest Pinning
Production deployment images use exact release tags (`v8.18.4`, `1.96.0`, `v2.2.4`) and immutable image digests to ensure reproducible container environments.
