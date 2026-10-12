# Testing Strategy & Test Execution Matrix

This guide documents the FireCrow test hierarchy, canonical test execution sequence, fixture strategies, and continuous integration pipeline.

---

## 1. Testing Philosophy & Verification Matrix

FireCrow enforces high test coverage to guarantee that security invariants cannot regress:

| Test Tier | Scope | Framework | Execution Command | Target Duration |
| :--- | :--- | :--- | :--- | :--- |
| **Frontend Node Tests** | API contracts, state logic, schemas, security invariants (166 tests) | Node.js Test Runner (`node:test`) | `node --test dist-tests/tests/*.test.js` | ~2.5s |
| **Frontend Typecheck** | Strict TypeScript compilation | `tsc` | `./node_modules/.bin/tsc -p tsconfig.app.json --noEmit` | ~1.5s |
| **Frontend Lint** | React hooks, unused vars, formatting | ESLint | `npm run lint` | ~2.0s |
| **Backend Unit Tests** | Scoring math, normalizers, config validation | Cargo Test | `cd backend && cargo test --lib` | ~10s |
| **Backend Integration** | DB triggers, state machine, auth middleware | Cargo Test + Testcontainers / Postgres | `cd backend && cargo test --test '*'` | ~30s |
| **Dev Environment Suite**| End-to-end dev runner integrity | Bash / cURL | `./scripts/test-dev.sh` | ~15s |

---

## 2. Canonical Pre-Commit Execution Sequence

Before pushing code or submitting a pull request, execute this canonical verification sequence:

```bash
# 1. Frontend Type Safety & Linter
cd frontend
./node_modules/.bin/tsc -p tsconfig.app.json --noEmit
./node_modules/.bin/tsc -p tsconfig.node.json --noEmit
npm run lint

# 2. Frontend Contract & Invariant Suite (166 tests)
node --test dist-tests/tests/*.test.js

# 3. Production Bundle Build Test
npm run build

# 4. Backend Rust Tests & Clippy
cd ../backend
cargo test
cargo clippy -- -D warnings
```

---

## 3. Detailed Test Suite Coverage

### Frontend Contract & Invariant Tests (`166 tests`)
The Node.js test runner verifies critical invariant rules across multiple test files in `frontend/dist-tests/tests/`:
1. **`auth-idor.test.js`**:
   - Asserts tenant isolation on audit fetching (`GET /api/audit/:id`).
   - Asserts non-admin users cannot read cross-tenant audits.
   - Asserts CSRF double-submit token mismatch is rejected with 403.
2. **`audit-lifecycle.test.js`**:
   - Verifies sequential transitions (`queued` ➔ `running` ➔ `completed`).
   - Verifies illegal transitions fail closed with appropriate error codes.
   - Verifies `failure != clean`: failed scanner processes write partial failure logs, never empty clean audits.
3. **`risk-score.test.js`**:
   - Validates mathematical formula: Base 100 with (-25, -15, -5, -1, 0) deductions.
   - Validates clamping to [0, 100].
   - Validates grade letter derivations.
4. **`gemini-boundary.test.js`**:
   - Verifies that AI summary layer cannot modify finding count or risk score.
   - Verifies schema rejects hallucinated findings.
5. **`stream-intake.test.js`**:
   - Verifies 50MB unpacking ceiling triggers immediate abort.
   - Verifies symlink escape attempts and directory traversal (`..`) are dropped.

### Backend Rust Test Suite
Unit and integration tests in `backend/` verify:
- **`config_test`**: Asserts invalid JWT expiry or missing database URLs abort startup.
- **`scanner_normalizer_test`**: Tests ingestion of raw Gitleaks, Semgrep, and OSV JSON outputs into `CanonicalAuditV1`.
- **`trigger_test`**: Asserts PostgreSQL trigger `audit_jobs_lifecycle_guard_fn` raises exception on illegal state transitions.

---

## 4. Test Data Fixtures & Mocking Policy

### Deterministic Test Fixtures
Test inputs are kept in version-controlled fixtures rather than pulled dynamically:
- Mock scanner JSON payloads for Gitleaks secrets, Semgrep SAST alerts, and OSV CVE records.
- Standard archive tarballs for stream-bounded intake testing, including:
  - `clean-repo.tar.gz` (standard small repo)
  - `bomb-repo.tar.gz` (highly compressed archive expanding over 50MB)
  - `traversal-repo.tar.gz` (archive with `../` path entries)

### Mocking Policy:
- **External Network Calls**: In unit and contract test suites, calls to GitHub API and Google Gemini API are strictly mocked. Tests must never make live external network calls that cause test flakiness or leak credentials.
- **Docker Daemon**: Integration tests verify CLI argument generation and exit code handling against mock subprocess runners when Docker daemon is not available.

---

## 5. Continuous Integration Workflow (`.github/workflows/ci.yml`)

The repository includes an automated GitHub Actions pipeline executing on all pull requests and pushes to `main`:

```yaml
name: CI
on: [push, pull_request]

jobs:
  backend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cd backend && cargo check --locked
      - run: cd backend && cargo test
      - run: cd backend && cargo clippy -- -D warnings

  frontend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: cd frontend && npm ci
      - run: cd frontend && npm run lint
      - run: cd frontend && node --test dist-tests/tests/*.test.js
      - run: cd frontend && npm run build
```
