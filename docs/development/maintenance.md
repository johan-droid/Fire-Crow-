# Maintenance, Evolution & Operations Engineering Guide

This guide provides operational procedures for evolving the FireCrow platform: integrating new scanner engines, upgrading dependencies, executing database migrations, rotating secrets, and updating marketing interfaces.

---

## 1. Adding a New Security Scanner Engine

To integrate a fourth scanner engine (e.g. `trivy`, `checkov`, or `grype`):

### Step 1: Pin Container Image & Security Config
In `backend/src/agents/scanner.rs`:
- Define the exact pinned image tag constant (e.g., `pub const TRIVY_IMAGE: &str = "aquasec/trivy:0.56.0";`).
- Add command builder function with mandatory security isolation flags:
  - `--cap-drop=ALL`
  - `--security-opt=no-new-privileges`
  - `--read-only` root filesystem
  - `--network=none`
  - Workspace volume mounted `:ro`
  - Strict timeout (300s).

### Step 2: Implement Output Normalizer Adapter
In `backend/src/schemas/canonical_audit.rs`:
- Parse the engine's JSON report.
- Map findings into `CanonicalFinding` structs with standardized `Severity` enum values (`Critical`, `High`, `Medium`, `Low`, `Info`).
- Map engine-specific taxonomy to Common Weakness Enumeration (CWE) IDs.
- Compute deterministic finding ID hash: `SHA256(engine + rule_id + path + line)`.

### Step 3: Register in Orchestrator
In `backend/src/agents/scanner.rs`:
- Add the engine to the `run_all_scanners` pipeline.
- Record execution metadata in `engines_executed` vector.

### Step 4: Add Test Fixtures
- Add sample JSON output from the new scanner to test fixtures.
- Author unit test asserting correct normalization and scoring penalty calculation.

---

## 2. Modifying the Canonical Audit Schema

The Canonical Audit Schema v1 is an authoritative contract. Follow this versioning policy:

### Backward-Compatible Changes (v1.x.y)
- **Adding an Optional Field**: Add field to `CanonicalFinding` or `CanonicalAuditV1` with `#[serde(default)]` and `Option<T>`.
- **Adding New Engine Type**: The `engine` field is a string, which naturally supports new engine identifiers.
- Update frontend TypeScript interfaces in `frontend/src/api/types.ts`.

### Breaking Changes (v2.0.0)
- Create a new module: `backend/src/schemas/canonical_audit_v2.rs`.
- Bump `schema_version` to `"2.0.0"`.
- Implement a migration function transforming stored v1 JSONB documents to v2 when queried, or support dual-version deserialization.

---

## 3. Database Migration Workflow

FireCrow uses raw SQL migration files executed sequentially:

### Authoring a New Migration:
1. Create a sequentially numbered file in `backend/migrations/`:
   ```bash
   touch backend/migrations/002_add_audit_retries.sql
   ```
2. Write idempotent SQL with rollback notes:
   ```sql
   -- Up
   ALTER TABLE audit_jobs ADD COLUMN retry_count INT NOT NULL DEFAULT 0;

   -- Down
   -- ALTER TABLE audit_jobs DROP COLUMN retry_count;
   ```
3. Test locally against the Docker database:
   ```bash
   psql -U firecrow_user -d firecrow -f backend/migrations/002_add_audit_retries.sql
   ```

> [!CAUTION]
> **Trigger Protection**: If modifying the `audit_jobs` status column or state transitions, you must also update the PL/pgSQL function `audit_jobs_lifecycle_guard_fn` in the migration file.

---

## 4. Dependency Upgrade Policy

### Rust Dependencies (`backend/Cargo.toml`)
- Run `cargo outdated` to check for newer versions.
- Test updates with `cargo update -p <crate_name>`.
- Check compilation with `cargo check --locked`.
- **MSRV Invariant**: Ensure no updated crate requires a Rust version higher than the version pinned in `.github/workflows/ci.yml`.

### Frontend npm Dependencies (`frontend/package.json`)
- Run `npm outdated`.
- Update dependencies using `npm update <package>`.
- Run typechecks and test suite:
  ```bash
  ./node_modules/.bin/tsc -p tsconfig.app.json --noEmit
  npm run lint
  node --test dist-tests/tests/*.test.js
  ```

---

## 5. Secret Rotation Procedures

In production on Render/Vercel:

| Secret | Rotation Impact | Rotation Procedure |
| :--- | :--- | :--- |
| **`SESSION_SECRET`** | Invalidates active user sessions | Generate new 64-char random string (`openssl rand -hex 32`). Update in Render dashboard. Users must re-authenticate. |
| **`JWT_SECRET`** | Invalidates active access tokens | Update in Render dashboard. Access tokens expire within 15 minutes naturally. |
| **`GEMINI_API_KEY`** | AI narrative temporarily unavailable | Rotate in Google Cloud Console. Update `GEMINI_API_KEY` on Render. Scanners and score calculations remain 100% operational. |
| **`DATABASE_URL`** | Backend service restart required | Rotate credentials in Neon/PostgreSQL provider. Update Render env variable. Render restarts Axum container with zero downtime during rolling deploy. |

---

## 6. Updating Landing Page & Marketing Copy

The landing page is `frontend/src/LandingPage.tsx` (mounted at `/`), plus its data and its own stylesheet:

- **Copy, capabilities, FAQ, pipeline stages, sample findings**: `frontend/src/landing/data/landingData.ts`.
- **Layout and styling**: `frontend/src/landing/site/landing-site.css` — its tokens are scoped to the `.lp` class so they never leak into the console or login page.
- **The ledger object**: `frontend/src/landing/site/Ledger.tsx`.
- **Hero canvas**: `frontend/src/scene.tsx` (`HeroCanvas3D`), which must respect `prefers-reduced-motion`.

Honesty rules the page must keep (pinned by `frontend/tests/landing-page.test.ts`): no claim the product cannot back, no form that fakes a submission, no dead nav link, and a visible disclosure while free-tier access is the only open path. Run `npm test` in `frontend/` after any copy change.
