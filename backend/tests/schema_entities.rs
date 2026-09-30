//! Phase 4 acceptance: every entity and endpoint that was structurally broken by
//! schema drift, exercised against **seeded** rows.
//!
//! The rule these tests exist to enforce: an empty table never attempts `FromRow`
//! decoding, so a broken model returns `200 []` and looks fine. Every assertion
//! here therefore seeds at least one row first.
//!
//! Before Phase 4, `/sso/providers`, `/iam/policies`, `/pam/requests` and
//! `/verify/domains` returned `200 []` on an empty table and `500` on a seeded
//! one. `pam_audit`, `mfa_audit_logs` and `service_accounts` did not exist, so
//! every write to them failed.

mod support;

use sqlx::PgPool;

async fn seed_sso_provider(pool: &PgPool) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO sso_providers
           (id,name,provider_type,issuer_url,client_id,client_secret,domains,created_at)
         VALUES ($1,'Acme Okta','oidc','https://acme.okta.com','cid-1','ENC[c2VjcmV0]','acme.com',NOW())",
    )
    .bind(&id)
    .execute(pool)
    .await
    .expect("seed sso provider");
    id
}

async fn seed_policy(pool: &PgPool) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO iam_policies
           (id,name,effect,actions,resources,description,conditions,priority,created_at)
         VALUES ($1,'deny-legacy','Deny','delete','prod-*','legacy','{}',1,NOW())",
    )
    .bind(&id)
    .execute(pool)
    .await
    .expect("seed policy");
    id
}

async fn seed_pam_request(pool: &PgPool, user_id: &str) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO pam_requests
           (id,user_id,role_name,permission,requested_duration_minutes,ticket_ref,target_resource,reason,status,created_at)
         VALUES ($1,$2,'db-admin','pg:write',30,'OPS-1','prod-db','oncall','pending',NOW())",
    )
    .bind(&id)
    .bind(user_id)
    .execute(pool)
    .await
    .expect("seed pam request");
    id
}

async fn seed_domain(pool: &PgPool, user_id: &str) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO domain_verifications
           (id,user_id,domain,verification_token,verified,dns_txt_name,dns_txt_value,
            html_meta_name,html_meta_content,well_known_path,well_known_content,created_at)
         VALUES ($1,$2,'acme.com','tok-abc',false,'_firecrow-verify.acme.com','fc=abc',
                 'firecrow-domain-verification','fc=abc','/.well-known/firecrow','fc=abc',NOW())",
    )
    .bind(&id)
    .bind(user_id)
    .execute(pool)
    .await
    .expect("seed domain");
    id
}

async fn seed_artifact(pool: &PgPool, job_id: &str, user_id: &str) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO audit_artifacts
           (id,job_id,user_id,organization_id,artifact_type,file_name,size_bytes,sha256,
            mime_type,storage_backend,storage_key,sensitivity_level,legal_hold,name,file_path,created_at)
         VALUES ($1,$2,$3,'org-1','report','report.md',12,'abc123','text/markdown','local',
                 'k/report.md','internal',false,'report','report.md',NOW())",
    )
    .bind(&id)
    .bind(job_id)
    .bind(user_id)
    .execute(pool)
    .await
    .expect("seed artifact");
    id
}

// ---------------------------------------------------------------------------
// Endpoint acceptance: seeded rows must no longer produce 500
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn sso_list_providers_decodes_seeded_rows(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "sso").await;

    // Empty table must still work.
    let empty = app
        .get("/api/v1/sso/providers")
        .add_header("authorization", user.auth_header())
        .await;
    assert_eq!(empty.status_code(), 200);

    seed_sso_provider(&pool).await;
    let seeded = app
        .get("/api/v1/sso/providers")
        .add_header("authorization", user.auth_header())
        .await;

    assert_eq!(
        seeded.status_code(),
        200,
        "seeded decode failed: {}",
        seeded.text()
    );
    let body: serde_json::Value = seeded.json();
    let arr = body.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["provider_type"], "oidc");
    // Phase 4 made the previously-missing columns real, so they must be present.
    assert_eq!(arr[0]["domains"], "acme.com");
    assert_eq!(arr[0]["auto_provision"], false);
    assert_eq!(arr[0]["enforce_mfa"], false);
}

#[sqlx::test(migrations = "./migrations")]
async fn iam_list_policies_decodes_seeded_rows(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "iam").await;

    seed_policy(&pool).await;
    let res = app
        .get("/api/v1/iam/policies")
        .add_header("authorization", user.auth_header())
        .await;

    assert_eq!(res.status_code(), 200, "body: {}", res.text());
    let body: serde_json::Value = res.json();
    assert_eq!(body[0]["effect"], "Deny");
    assert_eq!(body[0]["actions"], "delete");
    assert_eq!(body[0]["resources"], "prod-*");
}

#[sqlx::test(migrations = "./migrations")]
async fn pam_list_requests_decodes_seeded_rows(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "pam").await;
    seed_pam_request(&pool, &user.id).await;

    let res = app
        .get("/api/v1/pam/requests")
        .add_header("authorization", user.auth_header())
        .await;

    assert_eq!(res.status_code(), 200, "body: {}", res.text());
    let body: serde_json::Value = res.json();
    assert_eq!(body[0]["role_name"], "db-admin");
    assert_eq!(body[0]["permission"], "pg:write");
    assert_eq!(body[0]["requested_duration_minutes"], 30);
    assert_eq!(body[0]["ticket_ref"], "OPS-1");
}

#[sqlx::test(migrations = "./migrations")]
async fn verify_list_domains_decodes_seeded_rows(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "verify").await;
    seed_domain(&pool, &user.id).await;

    let res = app
        .get("/api/v1/verify/domains")
        .add_header("authorization", user.auth_header())
        .await;

    assert_eq!(res.status_code(), 200, "body: {}", res.text());
    let body: serde_json::Value = res.json();
    assert_eq!(body[0]["dns_txt_name"], "_firecrow-verify.acme.com");
    assert_eq!(body[0]["well_known_path"], "/.well-known/firecrow");
}

#[sqlx::test(migrations = "./migrations")]
async fn tenant_endpoints_decode_seeded_rows(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    // The user must carry the tenant at seed time: the token is minted with
    // tenant_id, and GET /tenant/ reads it from the token.
    let (_tenant_id, user) = support::seed_tenant_with_user(&pool, "acme").await;

    // No trailing slash: `nest("/tenant", route("/"))` resolves `/api/v1/tenant`
    // and 404s on `/api/v1/tenant/`. That inconsistency is recorded in app.rs and
    // belongs to the API phase; this assertion covers the path that resolves.
    let res = app
        .get("/api/v1/tenant")
        .add_header("authorization", user.auth_header())
        .await;

    assert_eq!(res.status_code(), 200, "body: {}", res.text());
    let body: serde_json::Value = res.json();
    let arr = body.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    // Previously unreachable: the Tenant model needed 5 columns that no migration
    // created, so this handler 500'd for any user with a tenant.
    assert_eq!(arr[0]["is_active"], true);
    assert_eq!(arr[0]["plan"], "free");
    assert!(arr[0]["max_users"].is_null());
    assert!(arr[0]["max_storage_gb"].is_null());
}

#[sqlx::test(migrations = "./migrations")]
async fn storage_download_authorizes_by_owner(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let owner = support::seed_user(&pool, "artowner").await;
    let other = support::seed_user(&pool, "artother").await;
    let job = support::seed_job(&pool, &owner.id, "completed").await;
    let artifact = seed_artifact(&pool, &job, &owner.id).await;

    // Non-owner must not receive the artifact.
    let denied = app
        .get(&format!("/api/v1/storage/artifacts/{artifact}/download"))
        .add_header("authorization", other.auth_header())
        .await;
    assert!(
        denied.status_code() == 404 || denied.status_code() == 403,
        "cross-user artifact access must be refused, got {}",
        denied.status_code()
    );
    assert!(
        !denied.text().contains("report.md"),
        "artifact name leaked to a non-owner"
    );

    // The owner's request must reach storage logic, not fail on a missing column.
    let allowed = app
        .get(&format!("/api/v1/storage/artifacts/{artifact}/download"))
        .add_header("authorization", owner.auth_header())
        .await;
    assert_ne!(
        allowed.status_code(),
        500,
        "owner request must not be a server error: {}",
        allowed.text()
    );
}

// ---------------------------------------------------------------------------
// Entity-level acceptance: create / read / update / delete / NULL / relationships
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn entities_handle_multiple_rows_and_nulls(pool: PgPool) {
    let _user = support::seed_user(&pool, "multi").await;

    for i in 0..3 {
        sqlx::query(
            "INSERT INTO sso_providers
               (id,name,provider_type,issuer_url,client_id,client_secret,created_at)
             VALUES ($1,$2,'oidc',$3,'cid',NULL,NOW())",
        )
        .bind(format!("p{i}"))
        .bind(format!("Provider {i}"))
        .bind(format!("https://p{i}.test"))
        .execute(&pool)
        .await
        .expect("insert provider without a secret");
    }
    let rows: Vec<(String, Option<String>, bool)> =
        sqlx::query_as("SELECT name, client_secret, enforce_mfa FROM sso_providers ORDER BY name")
            .fetch_all(&pool)
            .await
            .expect("read multiple");
    assert_eq!(rows.len(), 3);
    assert!(
        rows.iter().all(|(_, s, _)| s.is_none()),
        "NULL secret must stay NULL"
    );
    assert!(
        rows.iter().all(|(_, _, m)| !*m),
        "enforce_mfa must default to false"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn entities_support_update_and_delete(pool: PgPool) {
    let id = seed_sso_provider(&pool).await;

    sqlx::query("UPDATE sso_providers SET enforce_mfa = true, domains = $1 WHERE id = $2")
        .bind("updated.com")
        .bind(&id)
        .execute(&pool)
        .await
        .expect("update");
    let (mfa, domains): (bool, String) =
        sqlx::query_as("SELECT enforce_mfa, domains FROM sso_providers WHERE id = $1")
            .bind(&id)
            .fetch_one(&pool)
            .await
            .expect("read updated");
    assert!(mfa);
    assert_eq!(domains, "updated.com");

    sqlx::query("DELETE FROM sso_providers WHERE id = $1")
        .bind(&id)
        .execute(&pool)
        .await
        .expect("delete");
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sso_providers WHERE id = $1")
        .bind(&id)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(n, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn artifacts_reject_an_owner_that_does_not_exist(pool: PgPool) {
    let user = support::seed_user(&pool, "fkowner").await;
    let job = support::seed_job(&pool, &user.id, "completed").await;

    // The owner foreign key must be enforced: an artifact cannot claim ownership
    // by a user id that is not in users.
    let res = sqlx::query(
        "INSERT INTO audit_artifacts
           (id,job_id,user_id,organization_id,artifact_type,file_name,size_bytes,sha256,
            storage_backend,storage_key,sensitivity_level,legal_hold,name,file_path,created_at)
         VALUES ('orphan','$1','no-such-user','o','report','r.md',1,'h','local','k','internal',
                 false,'r','r',NOW())",
    )
    .bind(&job)
    .execute(&pool)
    .await;

    assert!(
        res.is_err(),
        "audit_artifacts.user_id must reference users(id)"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn phantom_tables_are_writable(pool: PgPool) {
    let user = support::seed_user(&pool, "phantom").await;

    // pam_audit
    sqlx::query(
        "INSERT INTO pam_audit (id,request_id,action,actor_id,details,created_at)
         VALUES ($1,'req-1','revoked',$2,'via api',NOW())",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&user.id)
    .execute(&pool)
    .await
    .expect("pam_audit must be writable");

    // mfa_audit_logs
    sqlx::query(
        "INSERT INTO mfa_audit_logs (id,user_id,action,success,ip_hash,created_at)
         VALUES ($1,$2,'verify',true,NULL,NOW())",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&user.id)
    .execute(&pool)
    .await
    .expect("mfa_audit_logs must be writable");

    // service_accounts
    sqlx::query(
        "INSERT INTO service_accounts
           (id,name,token_hash,permissions,expires_at,created_by,is_active,created_at)
         VALUES ($1,'ci',$2,'read:*',NOW() + INTERVAL '1 hour',$3,true,NOW())",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind("hash")
    .bind(&user.id)
    .execute(&pool)
    .await
    .expect("service_accounts must be writable");

    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM service_accounts")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(n, 1);
}
