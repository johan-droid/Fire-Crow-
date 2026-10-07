# Schema / model reconciliation matrix

> **Resolution Status (Phase 4): RESOLVED.**
> This document records the Phase 3 discovery inventory of schema-model drift. All missing columns and phantom tables below were reconciled by migration `20260901000000_schema_reconciliation.sql` (Phase 4). The continuous test gate `backend/tests/schema_reconciliation.rs` now asserts `KNOWN_MISSING = []` and `KNOWN_PHANTOM_TABLES = []` (0 missing).

Generated during Phase 3 of the security remediation, by comparing every
`#[derive(FromRow)]` struct against a database created solely by the initial
migrations in `backend/migrations/`. Regenerate with the commands in the
commit message; the live gate is `backend/tests/schema_reconciliation.rs`.

Tables created by migrations: **29**. Columns: **238**.

## Struct/table pairs

| Rust model | Table | Fields | Missing columns | Status |
|---|---|---:|---|---|
| `ArtifactObject` | `audit_artifacts` | 13 | `organization_id`, `artifact_type`, `file_name`, `size_bytes`, `sha256`, `mime_type`, `storage_key`, `sensitivity_level`, `legal_hold` | **9 missing** |
| `AuditJob` | `audit_jobs` | 15 | - | ok |
| `AuditReport` | `audit_reports` | 5 | - | ok |
| `DomainVerification` | `domain_verifications` | 13 | `verified_at`, `dns_txt_name`, `dns_txt_value`, `html_meta_name`, `html_meta_content`, `well_known_path`, `well_known_content` | **7 missing** |
| `FindingModel` | `findings` | 20 | - | ok |
| `IamPolicy` | `iam_policies` | 9 | `effect`, `actions`, `resources`, `description`, `conditions` | **5 missing** |
| `MfaConfiguration` | `mfa_configurations` | 7 | - | ok |
| `PaymentRecord` | `payment_records` | 11 | - | ok |
| `PhaseLedgerModel` | `phase_ledger` | 9 | - | ok |
| `PrivacyAuditLog` | `privacy_audit_logs` | 9 | - | ok |
| `PrivilegedAccessGrant` | `pam_grants` | 8 | `granted_by`, `revoked_at`, `revoked_by` | **3 missing** |
| `PrivilegedAccessRequest` | `pam_requests` | 13 | `role_name`, `permission`, `requested_duration_minutes`, `ticket_ref`, `approver_id`, `deny_reason`, `started_at`, `ends_at` | **8 missing** |
| `SsoProvider` | `sso_providers` | 17 | `authorization_url`, `token_url`, `userinfo_url`, `jwks_url`, `certificate`, `attribute_mapping`, `domains`, `enforce_mfa`, `auto_provision`, `default_role_id` | **10 missing** |
| `Tenant` | `tenants` | 13 | `domain`, `plan`, `max_users`, `max_storage_gb`, `is_active` | **5 missing** |
| `User` | `users` | 25 | - | ok |

## Root cause per broken pair

| Model | Root cause |
|---|---|
| `ArtifactObject` | `audit_artifacts` has no owner column (`user_id`) and no storage key, size, or integrity columns. Object-level authorization is impossible even once decoding works. |
| `DomainVerification` | Only token-based verification is modelled. The DNS TXT, `/.well-known/` and HTML-meta methods implemented in `services/domain_verify.rs` have no columns. |
| `IamPolicy` | The policy document body has no columns, so no policy can express effect, actions, resources, or conditions. |
| `PrivilegedAccessGrant` | Revocation cannot be recorded: no `revoked_at`, `revoked_by`, or `granted_by`. |
| `PrivilegedAccessRequest` | `pam_requests` cannot express an approval workflow: no role, permission, duration, approver, decision, or validity window. |
| `SsoProvider` | Migrations create only 7 columns. The model expects the full OIDC provider shape. Separately, `client_secret_set` (added by the P0-4 fix) is a serialisation-only flag and is not a column at all — it needs `#[sqlx(skip)]` or the struct can never decode. |
| `Tenant` | No plan, quota, lifecycle, or domain columns. `/tenant/*` cannot work. |

## Tables referenced in SQL that no migration creates

| Table | Referenced from | Consequence |
|---|---|---|
| `pam_audit` | `services/pam_service.rs` | Every PAM grant revocation `INSERT` fails, so the grant is never marked revoked. |
| `mfa_audit_logs` | `services/mfa_service.rs` | MFA audit writes fail. |
| `service_accounts` | `services/iam_service.rs` | Service-account create and revoke fail. |

## Latent-failure warning

An empty table never attempts `FromRow` decoding, so all of the pairs above
return `200 []` and look healthy until a row exists. This was confirmed in the
Phase 0 runtime audit: `/sso/providers`, `/iam/policies`, `/pam/requests` and
`/verify/domains` returned `200 []`, and only returned 500 after a row was
inserted. Integration tests must seed a row before asserting on these endpoints.

