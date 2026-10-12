# Contributing to FireCrow

Thank you for your interest in contributing to **FireCrow**! As an enterprise-grade security auditing and vulnerability scanning platform, we maintain rigorous engineering standards, strict security invariants, and thorough automated test verification.

---

## 1. Code of Conduct & Core Architectural Invariants

Every contribution must preserve the fundamental system invariants:
1. **Scanner-First Truth**: All vulnerability findings originate exclusively from deterministic scanners. No AI layer may generate or alter findings.
2. **`failure != clean`**: Incomplete or crashed scanner runs must never report a clean bill of health.
3. **Stream-Bounded Intake**: Ingestion limits (50MB unpack ceiling, symlink rejection) must never be bypassed.
4. **Database-Authoritative Lifecycle**: State transitions are enforced by database triggers; application code must conform.

---

## 2. Development Workflow

### Branch Naming Conventions
Create feature branches from `main` using descriptive prefixes:
- `feat/feature-name` — New capability or scanner integration
- `fix/bug-description` — Bug fix or security patch
- `docs/topic-name` — Documentation improvements
- `refactor/subsystem-name` — Code refactoring without behavior change
- `test/test-description` — Test suite additions or updates

### Commit Message Standards
We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:
```
<type>(<scope>): <subject>

[optional body]

[optional footer(s)]
```

Examples:
- `feat(scanner): add support for osv-scanner v2.2.4 lockfile parsing`
- `fix(auth): reduce jwt access token expiry to 15 minutes`
- `docs(api): document rate limiting headers and SSE stream contract`
- `test(lifecycle): verify database trigger blocks queued to completed transition`

---

## 3. Pre-PR Verification Checklist

Before submitting a Pull Request, run the local verification commands and confirm zero failures:

```bash
# 1. Frontend Verification
cd frontend
./node_modules/.bin/tsc -p tsconfig.app.json --noEmit
npm run lint
node --test dist-tests/tests/*.test.js
npm run build

# 2. Backend Verification
cd ../backend
cargo check --locked
cargo test
cargo clippy -- -D warnings
```

---

## 4. Pull Request Guidelines

1. **Title**: Follow Conventional Commits format.
2. **Description**: Detail:
   - What changed and why.
   - Security impact and boundary considerations.
   - Relevant issue numbers (`Fixes #123`).
3. **Database Migrations**: If your PR modifies the database schema:
   - Include both migration and rollback SQL files in `backend/migrations/`.
   - Update `audit_jobs_lifecycle_guard_fn` if status transitions changed.
4. **Documentation**: Update the relevant guides in `docs/` and the [Repository Map](file:///home/ashutoshsahoo/Downloads/Fire-Crow-/docs/architecture/repository-map.md).

---

## 5. Review & Merge Policy

- Every Pull Request requires at least one approving review from a code maintainer.
- All GitHub Actions CI checks must pass green.
- PRs are merged using **Squash and Merge** to keep the `main` branch history clean and linear.
