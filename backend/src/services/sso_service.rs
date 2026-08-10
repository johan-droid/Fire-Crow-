use crate::error::{AppError, Result};
use crate::models::SsoProvider;
use chrono::Utc;

pub struct SsoService;

impl SsoService {
    pub async fn list_providers(pool: &sqlx::PgPool) -> Result<Vec<SsoProvider>> {
        sqlx::query_as::<_, SsoProvider>("SELECT * FROM sso_providers ORDER BY name")
            .fetch_all(pool).await.map_err(AppError::Database)
    }

    pub async fn create_provider(pool: &sqlx::PgPool, provider: SsoProvider) -> Result<SsoProvider> {
        sqlx::query_as::<_, SsoProvider>(
            r#"INSERT INTO sso_providers (id, name, provider_type, issuer_url, client_id, client_secret, authorization_url, token_url, userinfo_url, jwks_url, certificate, attribute_mapping, domains, enforce_mfa, auto_provision, default_role_id, created_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) RETURNING *"#
        )
        .bind(provider.id).bind(provider.name).bind(provider.provider_type).bind(provider.issuer_url).bind(provider.client_id).bind(provider.client_secret)
        .bind(provider.authorization_url).bind(provider.token_url).bind(provider.userinfo_url).bind(provider.jwks_url).bind(provider.certificate)
        .bind(provider.attribute_mapping).bind(provider.domains).bind(provider.enforce_mfa).bind(provider.auto_provision).bind(provider.default_role_id).bind(Utc::now().naive_utc())
        .fetch_one(pool).await.map_err(AppError::Database)
    }

    pub async fn get_provider(pool: &sqlx::PgPool, provider_id: &str) -> Result<Option<SsoProvider>> {
        sqlx::query_as::<_, SsoProvider>("SELECT * FROM sso_providers WHERE id = $1")
            .bind(provider_id)
            .fetch_optional(pool).await.map_err(AppError::Database)
    }

    pub async fn update_provider(pool: &sqlx::PgPool, provider_id: &str, updates: &SsoProviderUpdate) -> Result<Option<SsoProvider>> {
        sqlx::query(
            r#"UPDATE sso_providers SET name=COALESCE($1,name), issuer_url=COALESCE($2,issuer_url), client_id=COALESCE($3,client_id),
               client_secret=COALESCE($4,client_secret), authorization_url=COALESCE($5,authorization_url), token_url=COALESCE($6,token_url),
               userinfo_url=COALESCE($7,userinfo_url), jwks_url=COALESCE($8,jwks_url), certificate=COALESCE($9,certificate),
               attribute_mapping=COALESCE($10,attribute_mapping), domains=COALESCE($11,domains),
               enforce_mfa=COALESCE($12,enforce_mfa), auto_provision=COALESCE($13,auto_provision), default_role_id=COALESCE($14,default_role_id)
               WHERE id=$15"#
        )
        .bind(updates.name.as_ref()).bind(updates.issuer_url.as_ref()).bind(updates.client_id.as_ref()).bind(updates.client_secret.as_ref())
        .bind(updates.authorization_url.as_ref()).bind(updates.token_url.as_ref()).bind(updates.userinfo_url.as_ref()).bind(updates.jwks_url.as_ref())
        .bind(updates.certificate.as_ref()).bind(updates.attribute_mapping.as_ref()).bind(updates.domains.as_ref())
        .bind(updates.enforce_mfa).bind(updates.auto_provision).bind(updates.default_role_id.as_ref()).bind(provider_id)
        .execute(pool).await.map_err(AppError::Database)?;
        Self::get_provider(pool, provider_id).await
    }

    pub async fn delete_provider(pool: &sqlx::PgPool, provider_id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM sso_providers WHERE id = $1")
            .bind(provider_id)
            .execute(pool).await.map_err(AppError::Database)?;
        Ok(result.rows_affected() > 0)
    }
}

#[derive(Debug, Clone, Default)]
pub struct SsoProviderUpdate {
    pub name: Option<String>,
    pub issuer_url: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub authorization_url: Option<String>,
    pub token_url: Option<String>,
    pub userinfo_url: Option<String>,
    pub jwks_url: Option<String>,
    pub certificate: Option<String>,
    pub attribute_mapping: Option<String>,
    pub domains: Option<String>,
    pub enforce_mfa: Option<bool>,
    pub auto_provision: Option<bool>,
    pub default_role_id: Option<String>,
}
