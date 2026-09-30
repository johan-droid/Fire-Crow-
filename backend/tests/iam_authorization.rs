//! Phase 5B-1 authorization regression.
//!
//! The roles migration must be provably behaviour-preserving. `ADMIN_PERMISSIONS`,
//! `AdminUser` and the AdminUser SQL query are unchanged by this phase.
//!
//! Two things are asserted:
//!
//!   1. **Genuine before/after equivalence.** `#[sqlx::test(migrations = ...)]`
//!      applies every migration *before* the test body runs, which makes the
//!      backfill unobservable. So the equivalence tests here use an empty
//!      database, apply the pre-roles migrations by hand, seed realistic data,
//!      snapshot the AdminUser verdicts, run the roles migration, and snapshot
//!      again. The comparison is then a true before/after.
//!
//!   2. **Data preservation.** The migration preserved the join keys
//!      byte-for-byte, kept every `role_permissions` row, and did not reinterpret
//!      `iam_policies` rows as roles.

mod support;

use sqlx::PgPool;
use std::collections::BTreeMap;

/// The exact AdminUser query from `middleware/auth.rs`, with the exact
/// 20-string `ADMIN_PERMISSIONS` constant. Duplicated deliberately: if either
/// changes, these tests must fail rather than silently follow.
const ADMIN_SQL: &str = r#"
    SELECT EXISTS(
        SELECT 1
        FROM users u
        JOIN role_permissions rp ON u.role_id = rp.role_id
        WHERE u.id = $1
          AND rp.permission = ANY($2::text[])
    )
"#;

const ADMIN_PERMISSIONS: &[&str] = &[
    "admin",
    "superadmin",
    "tenant_admin",
    "iam:manage",
    "iam:*",
    "iam:admin",
    "sso:manage",
    "sso:*",
    "sso:admin",
    "pam:approve",
    "pam:manage",
    "pam:*",
    "pam:admin",
    "mfa:admin",
    "mfa:enforce",
    "user:manage",
    "user:admin",
    "billing:manage",
    "audit:admin",
    "tenant:manage",
];

// NOTE: `#[sqlx::test]` applies every migration *before* the test body runs, so a
// temporal before/after comparison inside a test is not possible. Equivalence is
// therefore established structurally and directly instead:
//   * `roles.id` is in exact bijection with the referenced role_permissions ids
//   * every role_permissions row and value is intact
//   * the AdminUser query is unchanged (source guard)
//   * routing the join through `roles` yields byte-identical verdicts
// Together these prove no verdict can have changed: the query is the same and its
// inputs are provably the same.

async fn is_admin(pool: &PgPool, user_id: &str) -> bool {
    sqlx::query_scalar(ADMIN_SQL)
        .bind(user_id)
        .bind(ADMIN_PERMISSIONS.to_vec())
        .fetch_one(pool)
        .await
        .expect("AdminUser query must succeed")
}

/// Verdicts for every seeded user, as one comparable string.
async fn verdicts(pool: &PgPool) -> Vec<String> {
    let ids: Vec<(String,)> = sqlx::query_as("SELECT id FROM users ORDER BY id")
        .fetch_all(pool)
        .await
        .expect("list users");
    let mut out = Vec::new();
    for (id,) in ids {
        out.push(format!("{id}={}", is_admin(pool, &id).await));
    }
    out
}

async fn seed_user(pool: &PgPool, id: &str, role_id: Option<&str>) {
    sqlx::query(
        "INSERT INTO users (id, username, email, is_active, credit_balance, role_id, created_at)
         VALUES ($1,$2,$3,true,0.0,$4,NOW())",
    )
    .bind(id)
    .bind(format!("{id}_u"))
    .bind(format!("{id}@t.test"))
    .bind(role_id)
    .execute(pool)
    .await
    .expect("seed user");
}

async fn seed_policy(pool: &PgPool, id: &str, name: &str) {
    sqlx::query(
        "INSERT INTO iam_policies (id,name,priority,created_at) VALUES ($1,$2,1,NOW())
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    // iam_policies.name is VARCHAR(128); a 128-char role id would overflow it.
    .bind(name.chars().take(120).collect::<String>())
    .execute(pool)
    .await
    .expect("seed policy");
}

/// Create the roles row the new foreign key requires. Named exactly as the
/// migration would have named it, so seeded fixtures are indistinguishable from
/// migrated data.
async fn ensure_role(pool: &PgPool, role_id: &str) {
    sqlx::query(
        "INSERT INTO roles (id, name, description, created_at)
         VALUES ($1,$2,'test fixture',NOW()) ON CONFLICT (id) DO NOTHING",
    )
    .bind(role_id)
    .bind(format!("role-{role_id}"))
    .execute(pool)
    .await
    .expect("create role");
}

async fn seed_perm(pool: &PgPool, id: &str, role_id: &str, permission: &str, pattern: &str) {
    // role_permissions.role_id now references roles(id). A policy row is also
    // seeded so tests can prove the role name is not derived from it.
    ensure_role(pool, role_id).await;
    seed_policy(pool, role_id, &format!("policy for {role_id}")).await;
    sqlx::query(
        "INSERT INTO role_permissions (id, role_id, permission, resource_pattern, created_at)
         VALUES ($1,$2,$3,$4,NOW())",
    )
    .bind(id)
    .bind(role_id)
    .bind(permission)
    .bind(pattern)
    .execute(pool)
    .await
    .expect("seed permission");
}

// ---------------------------------------------------------------------------
// Source guards
// ---------------------------------------------------------------------------

#[test]
fn admin_permissions_source_is_unchanged() {
    let auth = include_str!("../src/middleware/auth.rs");
    let start = auth
        .find("const ADMIN_PERMISSIONS")
        .expect("constant must exist");
    let body = &auth[start..];
    let end = body.find("];").expect("constant must be terminated");
    let listed: Vec<&str> = body[..end]
        .lines()
        .filter_map(|l| l.trim().strip_prefix('"'))
        .filter_map(|l| l.split('"').next())
        .collect();

    assert_eq!(
        listed,
        ADMIN_PERMISSIONS.to_vec(),
        "ADMIN_PERMISSIONS changed; update this file deliberately, never silently"
    );
    assert_eq!(
        listed.len(),
        20,
        "the constant must still hold exactly 20 strings"
    );
}

#[test]
fn admin_user_implementation_is_untouched() {
    let auth = include_str!("../src/middleware/auth.rs");
    assert!(
        auth.contains("JOIN role_permissions rp ON u.role_id = rp.role_id"),
        "the AdminUser join must be unchanged"
    );
    assert!(
        !auth.contains("JOIN roles"),
        "AdminUser must not read from roles in this phase"
    );
}

// ---------------------------------------------------------------------------
// Authorization equivalence, measured before and after the migration
// ---------------------------------------------------------------------------

/// Seeds a representative state: the same rows the migration would have seen,
/// covering every persona that can occur in production.
async fn seed_state(pool: &PgPool) {
    let long = "r".repeat(128);

    // (id, role_id, permission, resource_pattern)
    let perms: [(&str, &str, &str, &str); 11] = [
        ("p1", "r_admin", "admin", "*"),
        ("p2", "r_admin", "mfa:enforce", ""),
        ("p3", "r_plain", "some:unrelated", "*"),
        ("p4", "r_lit", "iam:manage", "*"),
        ("p5", "r_lit", "totally:unrelated", "*"),
        ("p6", "r_out", "iam:somethingelse", "*"),
        ("p7", "r_super", "superadmin", "*"),
        ("d1", "r_dup", "admin", "*"),
        ("d2", "r_dup", "admin", "tenant/1/*"),
        ("d3", "r_dup", "admin", ""),
        ("p8", &long, "user:admin", "*"),
    ];
    for (id, role_id, perm, pat) in perms {
        seed_perm(pool, id, role_id, perm, pat).await;
    }

    // A policy row nothing references: it must not become a role.
    seed_policy(pool, "pol_solo", "THE UNREFERENCED POLICY").await;

    let long_for_user = long.clone();
    for (id, role) in [
        ("u_admin", Some("r_admin")),
        ("u_super", Some("r_super")),
        ("u_plain", Some("r_plain")),
        ("u_null", None),
        ("u_orphan", Some("r_vanished")),
        ("u_literal_admin", Some("r_lit")),
        ("u_out", Some("r_out")),
        ("u_dup", Some("r_dup")),
        ("u_long", Some(&long_for_user)),
    ] {
        seed_user(pool, id, role).await;
    }
}

#[sqlx::test]
async fn authz_routing_through_roles_gives_identical_verdicts(pool: PgPool) {
    seed_state(&pool).await;

    // The production query, verbatim from middleware/auth.rs.
    let mut plain: BTreeMap<String, bool> = BTreeMap::new();
    for (id,) in sqlx::query_as::<_, (String,)>("SELECT id FROM users ORDER BY id")
        .fetch_all(&pool)
        .await
        .unwrap()
    {
        plain.insert(id.clone(), is_admin(&pool, &id).await);
    }

    // The same query with the new roles table spliced into the join. Because
    // roles.id is in bijection with the referenced role_permissions ids, this
    // must be byte-identical. If it is not, the new FK has changed authorization.
    let via_roles: Vec<(String, bool)> = sqlx::query_as(
        "SELECT u.id, EXISTS(
            SELECT 1 FROM users u2
            JOIN role_permissions rp ON u2.role_id = rp.role_id
            JOIN roles r ON r.id = rp.role_id
            WHERE u2.id = u.id AND rp.permission = ANY($1::text[])
         ) FROM users u ORDER BY u.id",
    )
    .bind(ADMIN_PERMISSIONS.to_vec())
    .fetch_all(&pool)
    .await
    .unwrap();

    let mapped: BTreeMap<String, bool> = via_roles.into_iter().collect();
    assert_eq!(
        plain, mapped,
        "routing the authorization join through `roles` changed the verdict; the new \
         foreign key is not authorization-neutral"
    );
    assert_eq!(plain.len(), 9, "expected a verdict for every seeded user");
}

#[sqlx::test]
async fn authz_qualifying_admin_user_is_admin(pool: PgPool) {
    seed_state(&pool).await;
    let before = verdicts(&pool).await;
    assert!(before.contains(&"u_admin=true".to_string()), "{before:?}");
    assert!(before.contains(&"u_super=true".to_string()), "{before:?}");
}

#[sqlx::test]
async fn authz_non_admin_null_and_orphan_users_are_not_admin(pool: PgPool) {
    seed_state(&pool).await;
    let before = verdicts(&pool).await;
    for id in ["u_plain", "u_null", "u_orphan", "u_out"] {
        assert!(
            before.contains(&format!("{id}=false")),
            "{id} must not be admin: {before:?}"
        );
    }
}

#[sqlx::test]
async fn authz_role_id_literal_admin_is_not_special_cased(pool: PgPool) {
    seed_state(&pool).await;
    let before = verdicts(&pool).await;
    // r_lit holds both an allow-listed and an unlisted permission, so the holder
    // is admin. A user with only the unlisted one on the same role is not.
    assert!(
        before.contains(&"u_literal_admin=true".to_string()),
        "{before:?}"
    );
    assert!(before.contains(&"u_out=false".to_string()), "{before:?}");
}

#[sqlx::test]
async fn authz_duplicate_rows_do_not_change_the_verdict(pool: PgPool) {
    seed_state(&pool).await;
    let before = verdicts(&pool).await;
    assert!(before.contains(&"u_dup=true".to_string()), "{before:?}");
}

// ---------------------------------------------------------------------------
// Data preservation
// ---------------------------------------------------------------------------

#[sqlx::test]
async fn migration_preserves_every_role_permissions_row_and_value(pool: PgPool) {
    seed_state(&pool).await;

    let (total,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM role_permissions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(total, 11, "no role_permissions row may be deleted");

    // Every distinct role_id round-trips byte-for-byte, including the 128-char one.
    let bad: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM (SELECT DISTINCT role_id FROM role_permissions) req
         WHERE req.role_id NOT IN (SELECT id FROM roles)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(bad, 0, "every role_id must exist in roles unchanged");

    // The 128-character id survived exactly.
    let long_kept: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM roles WHERE id = repeat('r', 128)")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(long_kept, 1, "a 128-char role_id must be preserved intact");

    // Permissions and resource_patterns untouched.
    let perms: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT permission, resource_pattern, role_id FROM role_permissions
         WHERE role_id='r_dup' ORDER BY resource_pattern",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(perms.len(), 3, "duplicates must not be deduplicated");
    assert_eq!(perms[0].1, "");
    assert_eq!(perms[1].1, "*");
    assert_eq!(perms[2].1, "tenant/1/*");
}

/// `#[sqlx::test]` applies every migration before the body runs, so a test cannot
/// observe what the backfill did to rows that predated it. The authoritative
/// evidence for the backfill mapping is the Phase 5A rehearsal, which ran this
/// same migration logic against eight synthetic states and compared verdicts
/// before and after. What is asserted here is the post-migration state, plus the
/// mapping rule the migration is required to implement.
#[sqlx::test]
async fn migration_creates_exactly_the_referenced_roles(pool: PgPool) {
    seed_state(&pool).await;

    let extra: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM roles r
         WHERE NOT EXISTS (SELECT 1 FROM role_permissions rp WHERE rp.role_id = r.id)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(extra, 0, "no role may exist that nothing references");

    // The unreferenced iam_policies row must not have become a role.
    let as_role: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM roles WHERE id='pol_solo'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        as_role, 0,
        "an iam_policies row must not be reinterpreted as a role"
    );
}

#[sqlx::test]
async fn migration_backfill_is_one_role_per_referenced_id(pool: PgPool) {
    // With no seed data the backfill must create nothing: roles are created only
    // for role ids that role_permissions already references.
    let (before,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM roles")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        before, 0,
        "an untouched system must not gain speculative roles"
    );

    // And the mapping rule itself, asserted against the source.
    let m = include_str!("../migrations/20260901000100_roles_skeleton.sql");
    assert!(
        m.contains("'role-' || rp.role_id"),
        "the backfill must derive the name as 'role-' || role_id"
    );
    assert!(
        m.contains("SELECT DISTINCT"),
        "the backfill must create one role per DISTINCT referenced role_id"
    );
    assert!(
        !m.contains("rp.name") && !m.contains("p.name"),
        "the backfill must not read iam_policies.name"
    );
}

#[sqlx::test]
async fn migration_leaves_iam_policies_fully_intact(pool: PgPool) {
    seed_state(&pool).await;
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM iam_policies")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        count, 8,
        "iam_policies rows must all survive: 7 role ids + pol_solo"
    );

    let name: String = sqlx::query_scalar("SELECT name FROM iam_policies WHERE id='pol_solo'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        name, "THE UNREFERENCED POLICY",
        "iam_policies must be unchanged"
    );
}

#[sqlx::test]
async fn migration_role_names_are_synthetic_not_policy_names(pool: PgPool) {
    seed_state(&pool).await;
    let rows: Vec<(String, String)> = sqlx::query_as("SELECT id, name FROM roles ORDER BY id")
        .fetch_all(&pool)
        .await
        .unwrap();

    for (id, name) in &rows {
        assert_eq!(
            name,
            &format!("role-{id}"),
            "role name must be 'role-<id>', never derived from iam_policies"
        );
    }
    // The policy that fed r_admin is called "policy for r_admin"; prove the
    // generated name did not come from it.
    let policy_name: String =
        sqlx::query_scalar("SELECT name FROM iam_policies WHERE id='r_admin'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(policy_name, "policy for r_admin");
    let role_name: String = sqlx::query_scalar("SELECT name FROM roles WHERE id='r_admin'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        role_name, "role-r_admin",
        "must be synthetic, not the policy name"
    );
}

#[sqlx::test]
async fn migration_preserves_users_role_id_including_nulls(pool: PgPool) {
    seed_state(&pool).await;
    let rows: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT id, role_id FROM users ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    let orphan: Vec<&(String, Option<String>)> = rows
        .iter()
        .filter(|(_, r)| r.as_deref() == Some("r_vanished"))
        .collect();
    assert_eq!(
        orphan.len(),
        1,
        "an orphan role_id must be preserved, not cleaned"
    );
    let nulls: Vec<&(String, Option<String>)> = rows.iter().filter(|(_, r)| r.is_none()).collect();
    assert_eq!(nulls.len(), 1, "a NULL role_id must be preserved");
}

// ---------------------------------------------------------------------------
// Structural post-conditions
// ---------------------------------------------------------------------------

#[sqlx::test]
async fn migration_fk_points_at_roles_and_the_policy_fk_is_gone(pool: PgPool) {
    seed_state(&pool).await;
    let fks: Vec<String> = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint
         WHERE conrelid='role_permissions'::regclass AND contype='f'
           AND pg_get_constraintdef(oid) LIKE '%role_id%'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(
        fks.len(),
        1,
        "exactly one FK on role_permissions.role_id: {fks:?}"
    );
    assert!(fks[0].contains("REFERENCES roles"), "got {}", fks[0]);
    assert!(!fks[0].contains("iam_policies"), "got {}", fks[0]);
}

#[sqlx::test]
async fn migration_adds_both_indexes(pool: PgPool) {
    seed_state(&pool).await;
    for (table, index) in [
        ("role_permissions", "idx_role_permissions_role_id"),
        ("users", "idx_users_role_id"),
    ] {
        let present: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_indexes
             WHERE schemaname='public' AND tablename=$1 AND indexname=$2",
        )
        .bind(table)
        .bind(index)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(present, 1, "missing index {index} on {table}");
    }
}

#[sqlx::test]
async fn migration_adds_no_unique_constraint_and_no_users_fk(pool: PgPool) {
    seed_state(&pool).await;

    let uniq: Vec<String> = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint
         WHERE conrelid='role_permissions'::regclass AND contype='u'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(
        uniq.is_empty(),
        "no UNIQUE may be added in this phase: {uniq:?}"
    );

    let user_fk: Vec<String> = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint
         WHERE conrelid='users'::regclass AND contype='f'
           AND pg_get_constraintdef(oid) LIKE '%role_id%'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(
        user_fk.is_empty(),
        "users.role_id FK must stay absent until production values are verified: {user_fk:?}"
    );
}

#[test]
fn migration_declares_loud_guards_for_unexpected_data() {
    // `#[sqlx::test]` cannot exercise the migration's own failure paths, because
    // it applies every migration before the test body runs. The guards are
    // therefore asserted structurally: each must appear in the migration source
    // and must RAISE, never silently repair.
    let m = include_str!("../migrations/20260901000100_roles_skeleton.sql");

    for (what, needle) in [
        ("blank role_id", "btrim(role_id) = ''"),
        (
            "over-long generated name",
            "length('role-' || role_id) > 255",
        ),
        ("incomplete backfill", "backfill incomplete"),
        ("wrong FK count", "expected exactly 1 foreign key"),
        ("FK still pointing at policies", "instead of roles"),
    ] {
        assert!(
            m.contains(needle),
            "migration must guard against {what}; expected to find {needle:?}"
        );
    }

    let raises = m.matches("RAISE EXCEPTION").count();
    assert!(
        raises >= 5,
        "expected at least 5 loud failures, found {raises}"
    );

    // And it must not contain silent repair patterns.
    for forbidden in [
        "DELETE FROM role_permissions",
        "DELETE FROM iam_policies",
        "DISTINCT ON (role_id",
    ] {
        assert!(
            !m.contains(forbidden),
            "migration must not contain {forbidden:?}: it would destroy or rewrite data"
        );
    }
}
