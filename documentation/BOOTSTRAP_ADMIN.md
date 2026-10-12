# Platform administrator bootstrap

Fire Crow has **no application-level role-provisioning API** by design: roles
and role permissions are security-sensitive and are provisioned out-of-band by
a database operator. This document is the approved, least-privilege procedure.
It never contains a fixed user id, email, password, or secret — every `…`
placeholder must be replaced with operator-chosen values at execution time.

## Permission model (FC-AUTHZ-01/03)

| Capability | Permission strings | Grants |
|---|---|---|
| Platform administration | `platform:admin`, `platform:*`, `platform:sso`, `platform:iam`, `platform:ops` (legacy: `admin`, `superadmin`) | Global SSO/IAM configuration, all tenants, platform MFA settings, system endpoints |
| Tenant administration | `tenant_admin`, `tenant:manage` | Administration of **one** tenant — the one in `users.tenant_id`. Never implies platform authority |

The `AdminUser` extractor consults `PLATFORM_ADMIN_PERMISSIONS` in
`backend/src/middleware/auth.rs`; tenant administration is resolved per-request
by `authorize_tenant_admin`, which checks membership and tenant activity
against the database.

## Provisioning a platform administrator

Run against the application database (values are operator-chosen):

```sql
-- 1. Create the role (id must be unique, ≤128 chars).
INSERT INTO roles (id, name, description, created_at)
VALUES ('role-platform-admin', 'platform-admin', 'Platform administrator', NOW());

-- 2. Grant exactly one platform capability.
INSERT INTO role_permissions (id, role_id, permission, resource_pattern, created_at)
VALUES (gen_random_uuid()::text, 'role-platform-admin', 'platform:admin', '*', NOW());

-- 3. Attach the role to the operator's existing user account.
UPDATE users SET role_id = 'role-platform-admin' WHERE id = '…operator user id…';
```

Notes:

* `POST /api/v1/iam/permissions` accepts only the explicit
  `GRANTABLE_PERMISSIONS` allowlist and refuses unknown strings and unknown
  role ids, so the API cannot mint ad-hoc privileges.
* Legacy `admin` / `superadmin` strings remain in the platform list only so
  provisioned roles keep working through the migration. Removal condition: once
  a `platform:admin` role is provisioned via this procedure, the legacy strings
  can be dropped from `PLATFORM_ADMIN_PERMISSIONS` in a deprecation release.
* Tenant administration is granted the same way with `tenant_admin`, plus a
  `users.tenant_id` assignment and (when membership enforcement is enabled) a
  `tenant_memberships` row.

## Revoking access

```sql
UPDATE users SET role_id = NULL WHERE id = '…user id…';
-- and, to take effect before the next token expiry as well as by the
-- per-request re-check:
UPDATE users SET is_active = false WHERE id = '…user id…';
```

Deactivated accounts are rejected on every authenticated request
(`AuthenticatedUser` re-reads `users.is_active` per request), so revocation does
not depend on token expiry.
