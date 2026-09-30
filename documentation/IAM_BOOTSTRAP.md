# IAM bootstrap (Option A — documented one-shot SQL)

**Status: operator-run procedure. Nothing here is automatic.**

FireCrow has no code path that creates the first administrator. This is a
deliberate, documented gap, not a bug to be worked around by adding privileged
startup behaviour.

## Why bootstrap is manual

`AdminUser` (`backend/src/middleware/auth.rs:124`) resolves administrative
access with a single query:

```sql
SELECT EXISTS(
    SELECT 1 FROM users u
    JOIN role_permissions rp ON u.role_id = rp.role_id
    WHERE u.id = $1 AND rp.permission = ANY($2::text[])
)
```

For that to ever be true, three things must line up:

1. `users.role_id` must equal a role identifier,
2. a `role_permissions` row must carry that same `role_id` with a permission from
   the 20-value `ADMIN_PERMISSIONS` list,
3. no later step may delete either row.

**No application code writes `users.role_id`.** All ten `INSERT`/`UPDATE`
statements against `users` were audited; none sets that column. And both
`POST /api/v1/iam/policies` and `POST /api/v1/iam/permissions` are themselves
`AdminUser`-gated, so they cannot be used to bootstrap either. The first
administrator must therefore be created directly in the database.

## Prerequisites

* Phase 5B-1 applied, so the `roles` table and
  `role_permissions.role_id → roles(id)` foreign key exist.
* An existing account to promote. Registration is open:
  `POST /api/v1/auth/register`.

## Procedure

Run this **once**, against the FireCrow database, after the first migration.

```sql
BEGIN;

-- 1. Create the role. The id is chosen by you; the name is synthetic.
INSERT INTO roles (id, name, description)
VALUES ('ops-admin',
        'ops-admin',
        'Bootstrap administrator role created by documented bootstrap runbook')
ON CONFLICT (id) DO NOTHING;

-- 2. Grant it an administrative permission. Must be one of the 20 strings in
--    ADMIN_PERMISSIONS (backend/src/middleware/auth.rs). 'admin' is used here.
INSERT INTO role_permissions (id, role_id, permission, resource_pattern, created_at)
VALUES (gen_random_uuid()::text, 'ops-admin', 'admin', '*', NOW());

-- 3. Point the user at the role. Replace the email with the real account.
UPDATE users
   SET role_id = 'ops-admin'
 WHERE email = 'admin@example.com'
   AND role_id IS NULL;

-- 4. Confirm exactly one row was promoted before committing.
SELECT id, username, email, role_id FROM users WHERE role_id = 'ops-admin';

COMMIT;
```

Then verify over HTTP — the gate should stop returning 403:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://your-firecrow-host/api/v1/mfa/admin/compliance
```

Expected: `200`. A `403` means step 2 or 3 did not take effect.

## Guardrails

| Concern | How it is handled |
|---|---|
| Repeated bootstrap | Every statement is `ON CONFLICT`/`WHERE role_id IS NULL` guarded. `resource_pattern` may legitimately repeat, because no unique constraint exists on `role_permissions` (deferred to a later phase) — check `SELECT` before re-running. |
| Accidental privilege creation | Nothing runs automatically. There is no env var, no CLI, no startup hook. |
| Over-promoting | Step 3 matches on a single email **and** requires `role_id IS NULL`, so it cannot silently demote or re-point an existing administrator. |
| Wrong permission string | Only the 20 strings in `ADMIN_PERMISSIONS` grant anything. A typo is inert rather than over-privileged — but it also grants nothing, so verify with the curl above. |
| `resource_pattern` | Inert. Nothing reads it for authorization. `'*'` is conventional, not enforced. |

## Additional administrators

Once at least one administrator exists, do **not** re-run the above. Use the
application:

```bash
# as an existing admin
POST /api/v1/iam/permissions      {"role_id":"ops-admin","permission":"sso:manage","resource_pattern":"*"}
```

Note that `users.role_id` still has no application write path, so promoting a
*second* user also requires direct SQL:

```sql
UPDATE users SET role_id = 'ops-admin' WHERE email = 'second-admin@example.com';
```

**Known gap:** there is no self-service or admin-facing role assignment. That is
Phase 5B-2 work and requires an explicit decision, because it is the point at
which privilege assignment becomes reachable from the application.

## Related

* `documentation/SCHEMA_RECONCILIATION.md` — the schema/model matrix
* The `roles` migration: `backend/migrations/20260901000100_roles_skeleton.sql`
* Regression coverage: `backend/tests/iam_authorization.rs`