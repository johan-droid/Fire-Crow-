//! FC-AUTHZ-01/03 containment regressions: platform-admin gating of the
//! SSO/IAM configuration reads, the dashboard aggregate, the permission-grant
//! path, account deactivation, and tenant authority separation.
//!
//! Every assertion that can inspect response contents does: a status code alone
//! cannot distinguish "filtered" from "empty because the fixture vanished".

mod support;

use axum_test::TestServer;
use sqlx::PgPool;

async fn seed_provider(pool: &PgPool) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO sso_providers (id, name, provider_type, issuer_url, client_id, client_secret, domains, created_at)
         VALUES ($1, 'Acme Okta', 'oidc', 'https://acme.okta.com', 'cid-1', 'ENC[c2VjcmV0]', 'acme.com', NOW())",
    )
    .bind(&id)
    .execute(pool)
    .await
    .expect("seed provider");
    id
}

async fn seed_policy_row(pool: &PgPool) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO iam_policies (id, name, effect, actions, resources, priority, created_at)
         VALUES ($1, 'deny-legacy', 'Deny', 'delete', 'prod-*', 1, NOW())",
    )
    .bind(&id)
    .execute(pool)
    .await
    .expect("seed policy");
    id
}

async fn ensure_role(pool: &PgPool, role_id: &str) {
    sqlx::query(
        "INSERT INTO roles (id, name, description, created_at)
         VALUES ($1, $2, 'fixture', NOW()) ON CONFLICT (id) DO NOTHING",
    )
    .bind(role_id)
    .bind(format!("role-{role_id}"))
    .execute(pool)
    .await
    .expect("create role");
}

async fn grant_tenant_admin(pool: &PgPool, user_id: &str) {
    let role_id = format!("role-{}", uuid::Uuid::new_v4());
    ensure_role(pool, &role_id).await;
    sqlx::query(
        "INSERT INTO role_permissions (id, role_id, permission, resource_pattern, created_at)
         VALUES ($1, $2, 'tenant_admin', '*', NOW())",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&role_id)
    .execute(pool)
    .await
    .expect("seed tenant_admin");
    sqlx::query("UPDATE users SET role_id = $1 WHERE id = $2")
        .bind(&role_id)
        .bind(user_id)
        .execute(pool)
        .await
        .expect("attach role");
}

// ---------------------------------------------------------------------------
// FC-AUTHZ-01: read containment
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn sso_and_iam_reads_require_platform_admin(pool: PgPool) {
    let app: TestServer = support::test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "plain").await;
    let provider_id = seed_provider(&pool).await;
    seed_policy_row(&pool).await;

    for path in [
        "/api/v1/sso/providers".to_string(),
        "/api/v1/iam/policies".to_string(),
        format!("/api/v1/sso/providers/{provider_id}"),
    ] {
        let res = app
            .get(&path)
            .add_header("authorization", user.auth_header())
            .await;
        assert_eq!(
            res.status_code(),
            403,
            "{path} must be admin-only: {}",
            res.text()
        );
        assert!(
            !res.text().contains("acme.okta.com"),
            "{path} must not leak provider configuration to a non-admin"
        );
    }

    let anon = app.get("/api/v1/sso/providers").await;
    assert_eq!(anon.status_code(), 401);

    support::grant_admin(&pool, &user).await;
    let res = app
        .get("/api/v1/sso/providers")
        .add_header("authorization", user.auth_header())
        .await;
    assert_eq!(res.status_code(), 200, "body: {}", res.text());
    let body: serde_json::Value = res.json();
    let arr = body.as_array().expect("array response preserved");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"], "Acme Okta");
    assert_eq!(arr[0]["client_secret_set"], true);
    assert!(
        arr[0].get("client_secret").is_none(),
        "secret must stay redacted even for admins"
    );

    let res = app
        .get(&format!("/api/v1/sso/providers/{provider_id}"))
        .add_header("authorization", user.auth_header())
        .await;
    assert_eq!(res.status_code(), 200);

    let res = app
        .get("/api/v1/iam/policies")
        .add_header("authorization", user.auth_header())
        .await;
    assert_eq!(res.status_code(), 200, "body: {}", res.text());
    let body: serde_json::Value = res.json();
    assert_eq!(body[0]["effect"], "Deny");
}

#[sqlx::test(migrations = "./migrations")]
async fn dashboard_restricts_global_sections_without_touching_user_sections(pool: PgPool) {
    let app: TestServer = support::test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "dashuser").await;
    let job_id = support::seed_job(&pool, &user.id, "completed").await;
    seed_provider(&pool).await;
    seed_policy_row(&pool).await;

    // Non-admin: user-specific sections intact, global sections empty.
    let res = app
        .get("/api/v1/dashboard/summary")
        .add_header("authorization", user.auth_header())
        .await;
    assert_eq!(res.status_code(), 200, "body: {}", res.text());
    let whole = res.text();
    let body: serde_json::Value = serde_json::from_str(&whole).expect("json");
    let jobs = body["jobs"].as_array().expect("jobs array");
    assert_eq!(jobs.len(), 1, "the caller's own job must be present");
    assert_eq!(jobs[0]["id"], job_id);
    assert!(
        body["sso_providers"].as_array().unwrap().is_empty(),
        "SSO providers must be empty for a non-admin"
    );
    assert!(
        body["iam_policies"].as_array().unwrap().is_empty(),
        "IAM policies must be empty for a non-admin"
    );
    assert!(
        body.get("mfa_status").is_some(),
        "mfa_status contract preserved"
    );
    assert!(
        body.get("generated_at").is_some(),
        "generated_at contract preserved"
    );
    assert!(
        !whole.contains("acme.okta.com"),
        "no global config may leak"
    );

    // Admin: the same call populates the global sections.
    support::grant_admin(&pool, &user).await;
    let res = app
        .get("/api/v1/dashboard/summary")
        .add_header("authorization", user.auth_header())
        .await;
    assert_eq!(res.status_code(), 200);
    let body: serde_json::Value = res.json();
    assert_eq!(body["sso_providers"].as_array().unwrap().len(), 1);
    assert_eq!(body["iam_policies"].as_array().unwrap().len(), 1);
    assert_eq!(body["jobs"].as_array().unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// FC-AUTHZ-03: permission granting cannot mint arbitrary privilege
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn permission_granting_rejects_unknown_strings_roles_and_non_admins(pool: PgPool) {
    let app: TestServer = support::test_app(pool.clone()).await;
    let admin = support::seed_user(&pool, "grantor").await;
    support::grant_admin(&pool, &admin).await;
    let role_id = format!("role-{}", uuid::Uuid::new_v4());
    ensure_role(&pool, &role_id).await;

    // A platform admin may grant an allowlisted permission to an existing role.
    let res = app
        .post("/api/v1/iam/permissions")
        .add_header("authorization", admin.auth_header())
        .json(&serde_json::json!({"role_id": role_id, "permission": "tenant_admin"}))
        .await;
    assert_eq!(res.status_code(), 200, "body: {}", res.text());

    // Arbitrary strings are refused, not stored.
    let res = app
        .post("/api/v1/iam/permissions")
        .add_header("authorization", admin.auth_header())
        .json(&serde_json::json!({"role_id": role_id, "permission": "root:everything"}))
        .await;
    assert_eq!(res.status_code(), 400, "body: {}", res.text());

    // Nonexistent roles are 404, not silently orphaned.
    let res = app
        .post("/api/v1/iam/permissions")
        .add_header("authorization", admin.auth_header())
        .json(&serde_json::json!({"role_id": "no-such-role", "permission": "tenant_admin"}))
        .await;
    assert_eq!(res.status_code(), 404, "body: {}", res.text());

    // A tenant administrator cannot reach the grant endpoint at all.
    let tenant_admin = support::seed_user(&pool, "tadmin").await;
    grant_tenant_admin(&pool, &tenant_admin.id).await;
    let res = app
        .post("/api/v1/iam/permissions")
        .add_header("authorization", tenant_admin.auth_header())
        .json(&serde_json::json!({"role_id": role_id, "permission": "platform:admin"}))
        .await;
    assert_eq!(
        res.status_code(),
        403,
        "tenant admin must not grant: {}",
        res.text()
    );
}

// ---------------------------------------------------------------------------
// Account lifecycle: deactivation invalidates authorization immediately
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn deactivated_user_is_rejected_despite_valid_token(pool: PgPool) {
    let app: TestServer = support::test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "byebye").await;
    let header = user.auth_header();

    let res = app
        .get("/api/v1/dashboard/summary")
        .add_header("authorization", header.clone())
        .await;
    assert_eq!(
        res.status_code(),
        200,
        "active user works before deactivation"
    );

    support::deactivate_user(&pool, &user.id).await;

    let res = app
        .get("/api/v1/dashboard/summary")
        .add_header("authorization", header)
        .await;
    assert_eq!(
        res.status_code(),
        401,
        "a deactivated account must be refused before token expiry: {}",
        res.text()
    );
}

// ---------------------------------------------------------------------------
// Tenant authority separation
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn tenant_admin_of_one_tenant_cannot_manage_another(pool: PgPool) {
    let app: TestServer = support::test_app(pool.clone()).await;
    let (tenant_a, admin_a) = support::seed_tenant_with_user(&pool, "acme").await;
    let (tenant_b, _admin_b) = support::seed_tenant_with_user(&pool, "globex").await;
    grant_tenant_admin(&pool, &admin_a.id).await;

    // Own tenant: allowed.
    let res = app
        .put(&format!("/api/v1/tenant/{tenant_a}"))
        .add_header("authorization", admin_a.auth_header())
        .json(&serde_json::json!({"name": "Acme Renamed"}))
        .await;
    assert_eq!(
        res.status_code(),
        200,
        "own-tenant update must succeed: {}",
        res.text()
    );
    assert_eq!(res.json::<serde_json::Value>()["name"], "Acme Renamed");

    // Other tenant: refused, even though the caller is an administrator.
    let name_before: String = sqlx::query_scalar("SELECT name FROM tenants WHERE id = $1")
        .bind(&tenant_b)
        .fetch_one(&pool)
        .await
        .unwrap();
    let res = app
        .put(&format!("/api/v1/tenant/{tenant_b}"))
        .add_header("authorization", admin_a.auth_header())
        .json(&serde_json::json!({"name": "Hijacked"}))
        .await;
    assert_eq!(
        res.status_code(),
        403,
        "cross-tenant update must be refused: {}",
        res.text()
    );
    let name: String = sqlx::query_scalar("SELECT name FROM tenants WHERE id = $1")
        .bind(&tenant_b)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(name, name_before, "tenant B must be untouched");

    // Deactivation of a tenant blocks its own administrator too, and its
    // members can no longer list it.
    sqlx::query("UPDATE tenants SET is_active = false WHERE id = $1")
        .bind(&tenant_a)
        .execute(&pool)
        .await
        .unwrap();
    let res = app
        .put(&format!("/api/v1/tenant/{tenant_a}"))
        .add_header("authorization", admin_a.auth_header())
        .json(&serde_json::json!({"name": "Should Fail"}))
        .await;
    assert_eq!(
        res.status_code(),
        403,
        "inactive tenant must be refused: {}",
        res.text()
    );

    let res = app
        .get("/api/v1/tenant")
        .add_header("authorization", admin_a.auth_header())
        .await;
    assert_eq!(
        res.status_code(),
        403,
        "member listing of inactive tenant must be refused"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn tenant_context_is_database_fresh_not_jwt_cached(pool: PgPool) {
    let app: TestServer = support::test_app(pool.clone()).await;
    let (tenant_a, user) = support::seed_tenant_with_user(&pool, "fresh").await;
    let header = user.auth_header(); // minted while the user belonged to tenant A

    let res = app
        .get("/api/v1/tenant")
        .add_header("authorization", header.clone())
        .await;
    assert_eq!(res.status_code(), 200);
    let body: serde_json::Value = res.json();
    assert_eq!(body[0]["id"], tenant_a, "JWT-era tenant must be visible");

    // Move the user to another tenant directly in the database. The still-valid
    // JWT claims tenant A; the request must follow the database, not the claim.
    let (moved, _other_user) = support::seed_tenant_with_user(&pool, "moved").await;
    sqlx::query("UPDATE users SET tenant_id = $1 WHERE id = $2")
        .bind(&moved)
        .bind(&user.id)
        .execute(&pool)
        .await
        .unwrap();

    let res = app
        .get("/api/v1/tenant")
        .add_header("authorization", header)
        .await;
    assert_eq!(res.status_code(), 200);
    let body: serde_json::Value = res.json();
    let ids: Vec<String> = body
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["id"].as_str().map(String::from))
        .collect();
    assert!(
        !ids.contains(&tenant_a),
        "stale JWT tenant claim must not surface tenant A after the move: {ids:?}"
    );
    assert_eq!(
        ids,
        vec![moved],
        "the database-current tenant must be visible"
    );
}
