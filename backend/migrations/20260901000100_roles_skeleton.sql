-- Phase 5B-1: introduce the roles skeleton and repair the role_permissions FK.
--
-- Problem: `role_permissions.role_id` (a role identifier) was declared with a
-- foreign key onto `iam_policies(id)` (a policy-document identifier). The schema
-- therefore asserted "a role id must equal a policy-document id", which is
-- semantically incoherent. `iam_policies` is retained, intact and separate.
--
-- Scope, per the approved decisions:
--   * `ADMIN_PERMISSIONS`, `AdminUser` and its SQL query are NOT touched.
--     `role_permissions.role_id` values are preserved byte-for-byte, so the
--     authorization join `u.role_id = rp.role_id` is unaffected.
--   * Role names are synthetic (`role-<role_id>`). `iam_policies.name` is NOT
--     used and NOT interpreted as a role name.
--   * No system/canonical roles are created. Roles exist only for role_id values
--     that `role_permissions` already references.
--   * No uniqueness constraint is added to `role_permissions` (deferred).
--   * `users.role_id` is deliberately left without a foreign key: production
--     values have not yet been inspected, and adding an FK that fails against
--     existing data would be an unacceptable rollout hazard.
--
-- Ordering is load-bearing: the replacement FK is created while the incorrect
-- one is still in place, so the table is never left unconstrained, and the old
-- FK is dropped only after the new one exists.

CREATE TABLE IF NOT EXISTS roles (
    id          VARCHAR(128) PRIMARY KEY,
    -- Wider than id: a 128-char role_id yields a 133-char generated name.
    name        VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    created_at  TIMESTAMP    NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE roles IS
  'Role identity. Rows are created only for role_id values already referenced by '
  'role_permissions. Not derived from iam_policies, which remains a separate '
  'policy-document table.';

-- ---------------------------------------------------------------------------
-- Fail loudly if role_permissions violates this migration's assumptions.
-- Repairing unexpected data silently would change authorization meaning.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    bad_blank   BIGINT;
    bad_long    BIGINT;
    bad_name    BIGINT;
BEGIN
    -- role_id must be present: a blank id would produce a role named 'role-'.
    IF EXISTS (SELECT 1 FROM role_permissions WHERE role_id IS NULL OR btrim(role_id) = '') THEN
        RAISE EXCEPTION
            'role_permissions contains a NULL or blank role_id; cannot create a role for it';
    END IF;

    -- The generated name must fit roles.name VARCHAR(255).
    IF EXISTS (SELECT 1 FROM role_permissions WHERE length('role-' || role_id) > 255) THEN
        RAISE EXCEPTION
            'a role_permissions.role_id generates a name longer than roles.name allows (255)';
    END IF;

    -- Generated names must be unique across distinct role_ids. The 'role-' prefix
    -- is injective, so this can only fail if `roles` already holds a conflicting
    -- row that this migration must not overwrite.
    SELECT count(*) INTO bad_name FROM (
        SELECT 'role-' || role_id AS generated
        FROM role_permissions
        GROUP BY 1
        HAVING count(*) > 1
    ) d;
    IF bad_name > 0 THEN
        RAISE EXCEPTION 'generated role names would collide (% groups)', bad_name;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Backfill: one role per DISTINCT referenced role_id, id preserved exactly.
--
-- ON CONFLICT (id) DO NOTHING is genuinely safe here: a conflict on the
-- primary key means the role already exists, which is the desired end state. A
-- conflict on the UNIQUE name constraint would abort the migration, which is
-- correct: it means operator-authored data would be overwritten.
-- ---------------------------------------------------------------------------
INSERT INTO roles (id, name, description)
SELECT DISTINCT
       rp.role_id,
       'role-' || rp.role_id,
       'Backfilled from role_permissions.role_id. Name is synthetic and is not '
       'derived from iam_policies.'
FROM role_permissions rp
ON CONFLICT (id) DO NOTHING;

-- Verify the backfill achieved exact set equality with the referenced role ids.
-- A shortfall here would cause the FK below to fail, so assert it explicitly to
-- produce a clearer error.
DO $$
DECLARE
    missing BIGINT;
BEGIN
    SELECT count(*) INTO missing
    FROM (SELECT DISTINCT role_id FROM role_permissions) req
    WHERE NOT EXISTS (SELECT 1 FROM roles r WHERE r.id = req.role_id);
    IF missing > 0 THEN
        RAISE EXCEPTION
            'backfill incomplete: % referenced role_id(s) have no roles row', missing;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- FK transition. Both constraints hold simultaneously; the incorrect one is
-- removed only after this statement succeeds.
-- ---------------------------------------------------------------------------
ALTER TABLE role_permissions
    DROP CONSTRAINT IF EXISTS fk_role_permissions_roles_role_id;

ALTER TABLE role_permissions
    ADD CONSTRAINT fk_role_permissions_roles_role_id
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE;

-- Remove the incorrect policy FK (named fk_role_permissions_role_id by
-- 20260814000001) now that the correct one exists, then adopt its name so the
-- final state carries exactly one FK under the canonical name.
ALTER TABLE role_permissions
    DROP CONSTRAINT IF EXISTS fk_role_permissions_role_id;

ALTER TABLE role_permissions
    RENAME CONSTRAINT fk_role_permissions_roles_role_id TO fk_role_permissions_role_id;

-- Post-condition: exactly one FK on role_permissions.role_id, and it points at
-- roles. Asserted rather than assumed, so a partially-applied state is loud.
DO $$
DECLARE
    fk_count    BIGINT;
    points_at   TEXT;
BEGIN
    SELECT count(*), COALESCE(max(confrelid::regclass::text), '')
      INTO fk_count, points_at
    FROM pg_constraint
    WHERE conrelid = 'role_permissions'::regclass
      AND contype = 'f'
      AND pg_get_constraintdef(oid) LIKE '%role_id%';

    IF fk_count <> 1 THEN
        RAISE EXCEPTION
            'expected exactly 1 foreign key on role_permissions.role_id, found %', fk_count;
    END IF;
    IF points_at <> 'roles' THEN
        RAISE EXCEPTION
            'role_permissions.role_id still references % instead of roles', points_at;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Indexes. The authorization join `u.role_id = rp.role_id` had no supporting
-- index on either side, so it was a sequential scan on every admin request.
--
-- Deliberately NOT added here: any UNIQUE constraint on role_permissions
-- (deferred pending a review of resource_pattern semantics).
--
-- Deliberately NOT added here: the users.role_id foreign key, pending
-- verification of production role_id values.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions (role_id);
CREATE INDEX IF NOT EXISTS idx_users_role_id            ON users (role_id);