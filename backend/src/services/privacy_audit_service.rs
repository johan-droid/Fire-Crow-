use crate::error::{AppError, Result};
use crate::models::{CreatePrivacyAuditRequest, PrivacyAuditLog};
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub struct PrivacyAuditService;

impl PrivacyAuditService {
    /// Hashes IP address and user-agent string to generate privacy-shielded anonymized audit hashes
    pub fn anonymize_ip(ip: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(format!("SALT_FIRE_CROW_PRIVACY_{}", ip).as_bytes());
        format!("anon_ip_{}", hex::encode(&hasher.finalize()[..8]))
    }

    pub async fn record_event(
        pool: &sqlx::PgPool,
        user_id: &str,
        raw_ip: &str,
        user_agent: Option<&str>,
        req: CreatePrivacyAuditRequest,
    ) -> Result<PrivacyAuditLog> {
        let id = Uuid::new_v4().to_string();
        let anon_ip = Self::anonymize_ip(raw_ip);
        let ua_hash = user_agent.map(|ua| {
            let mut hasher = Sha256::new();
            hasher.update(ua.as_bytes());
            hex::encode(&hasher.finalize()[..8])
        });
        let is_brand_visible = req.is_brand_visible.unwrap_or(false);

        sqlx::query_as::<_, PrivacyAuditLog>(
            "INSERT INTO privacy_audit_logs (id, user_id, tenant_id, event_type, anonymized_ip, user_agent_hash, details_json, is_brand_visible, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             RETURNING *"
        )
        .bind(&id)
        .bind(user_id)
        .bind(&req.tenant_id)
        .bind(&req.event_type)
        .bind(&anon_ip)
        .bind(&ua_hash)
        .bind(&req.details_json)
        .bind(is_brand_visible)
        .bind(Utc::now().naive_utc())
        .fetch_one(pool)
        .await
        .map_err(AppError::Database)
    }

    pub async fn list_user_logs(pool: &sqlx::PgPool, user_id: &str) -> Result<Vec<PrivacyAuditLog>> {
        sqlx::query_as::<_, PrivacyAuditLog>(
            "SELECT * FROM privacy_audit_logs WHERE user_id = $1 ORDER BY created_at DESC LIMIT 100"
        )
        .bind(user_id)
        .fetch_all(pool)
        .await
        .map_err(AppError::Database)
    }
}
