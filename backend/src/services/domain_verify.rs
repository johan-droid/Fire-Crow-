use crate::error::{AppError, Result};
use crate::models::DomainVerification;
use chrono::Utc;
use rand::Rng;

pub struct DomainVerifyService;
impl DomainVerifyService {
    pub async fn initiate(pool: &sqlx::PgPool, user_id: &str, domain: &str) -> Result<DomainVerification> {
        let id = uuid::Uuid::new_v4().to_string();
        let verification_token: String = rand::thread_rng().sample_iter(&rand::distributions::Alphanumeric).take(32).map(char::from).collect();
        sqlx::query_as::<_, DomainVerification>(
            r#"INSERT INTO domain_verifications (id, user_id, domain, verification_token, verified, created_at, dns_txt_name, dns_txt_value, html_meta_name, html_meta_content, well_known_path, well_known_content)
               VALUES ($1,$2,$3,$4,false,$5,$6,$7,$8,$9,$10,$11) RETURNING *"#
        )
        .bind(id.clone()).bind(user_id).bind(domain).bind(verification_token.clone()).bind(Utc::now().naive_utc())
        .bind(format!("_firecrow-verify.{}", domain)).bind(format!("firecrow-verify={}", &verification_token[..16]))
        .bind(format!("firecrow-verify-{}", &id[..8])).bind(verification_token.clone())
        .bind(format!("/.well-known/firecrow/{}", &id[..8])).bind(verification_token)
        .fetch_one(pool).await.map_err(AppError::Database)
    }
    pub async fn list(pool: &sqlx::PgPool, user_id: &str) -> Result<Vec<DomainVerification>> {
        sqlx::query_as::<_, DomainVerification>("SELECT * FROM domain_verifications WHERE user_id = $1 ORDER BY created_at DESC")
            .bind(user_id)
            .fetch_all(pool).await.map_err(AppError::Database)
    }
    pub async fn check(pool: &sqlx::PgPool, id: &str, _method: &str) -> Result<DomainVerification> {
        sqlx::query_as::<_, DomainVerification>("SELECT * FROM domain_verifications WHERE id = $1")
            .bind(id)
            .fetch_optional(pool).await.map_err(AppError::Database)?.ok_or_else(|| AppError::NotFound("Domain verification not found".into()))
    }
    pub async fn delete(pool: &sqlx::PgPool, id: &str, user_id: &str) -> Result<bool> {
        let r = sqlx::query("DELETE FROM domain_verifications WHERE id = $1 AND user_id = $2")
            .bind(id).bind(user_id)
            .execute(pool).await.map_err(AppError::Database)?;
        Ok(r.rows_affected() > 0)
    }
}
