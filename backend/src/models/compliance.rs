use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub tenant_id: String,
    pub dpo_contact: Option<String>,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Membership {
    pub id: String,
    pub user_id: String,
    pub organization_id: String,
    pub role: String,
    pub joined_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DataProcessingRecord {
    pub id: String,
    pub organization_id: String,
    pub processing_purpose: String,
    pub data_categories: String,
    pub retention_days: i32,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RetentionPolicy {
    pub id: String,
    pub name: String,
    pub data_type: String,
    pub retention_days: i32,
    pub action_on_expire: String,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ArtifactObject {
    pub id: String,
    pub job_id: String,
    pub organization_id: String,
    pub artifact_type: String,
    pub file_name: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub mime_type: Option<String>,
    pub storage_backend: String,
    pub storage_key: String,
    pub sensitivity_level: String,
    pub legal_hold: bool,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ComplianceEvent {
    pub id: String,
    pub user_id: Option<String>,
    pub tenant_id: String,
    pub event_type: String,
    pub details_json: Option<String>,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PrivacyRequest {
    pub id: String,
    pub user_id: String,
    pub request_type: String,
    pub status: String,
    pub processed_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuthorizationAttestation {
    pub id: String,
    pub job_id: String,
    pub user_id: String,
    pub attestation_token: String,
    pub authorized_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SecretRedactionEvent {
    pub id: String,
    pub job_id: String,
    pub secret_type: String,
    pub redacted_count: i32,
    pub created_at: NaiveDateTime,
}
