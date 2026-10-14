//! Storage service with support for Local disk storage and Cloudflare R2 (S3-compatible).

use crate::error::{AppError, Result};
use axum::async_trait;
use mime_guess::MimeGuess;

use aws_credential_types::Credentials;
use aws_sdk_s3::config::{Builder as ConfigBuilder, Region};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client as S3Client;

#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn upload(&self, data: Vec<u8>, key: &str, content_type: &str) -> Result<String>;
    async fn download(&self, key: &str) -> Result<Vec<u8>>;
    async fn delete(&self, key: &str) -> Result<()>;
    async fn presigned_url(&self, key: &str, expires_secs: i64) -> Result<String>;
}

pub struct S3StorageBackend {
    client: S3Client,
    bucket: String,
    endpoint: Option<String>,
}

impl S3StorageBackend {
    pub async fn new(
        endpoint: Option<String>,
        access_key: &str,
        secret_key: &str,
        bucket: &str,
        region: &str,
    ) -> Result<Self> {
        let reg_str = if region.is_empty() {
            "auto".to_string()
        } else {
            region.to_string()
        };
        let credentials = Credentials::new(access_key, secret_key, None, None, "r2_provider");
        let mut builder = ConfigBuilder::new()
            .credentials_provider(credentials)
            .region(Region::new(reg_str))
            .force_path_style(true);

        if let Some(ep) = &endpoint {
            if !ep.is_empty() {
                builder = builder.endpoint_url(ep);
            }
        }

        let config = builder.build();
        let client = S3Client::from_conf(config);

        Ok(Self {
            client,
            bucket: bucket.into(),
            endpoint,
        })
    }
}

#[async_trait]
impl StorageBackend for S3StorageBackend {
    async fn upload(&self, data: Vec<u8>, key: &str, content_type: &str) -> Result<String> {
        if key.contains("..") || key.starts_with('/') {
            return Err(AppError::Forbidden("Invalid key".into()));
        }
        tracing::info!(
            "Cloudflare R2 / S3 uploading object: bucket={}, key={}, size={}",
            self.bucket,
            key,
            data.len()
        );
        let body = ByteStream::from(data);
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(body)
            .content_type(content_type)
            .send()
            .await
            .map_err(|e| AppError::StorageError(format!("Cloudflare R2 upload error: {}", e)))?;

        Ok(key.to_string())
    }

    async fn download(&self, key: &str) -> Result<Vec<u8>> {
        if key.contains("..") || key.starts_with('/') {
            return Err(AppError::Forbidden("Invalid key".into()));
        }
        tracing::info!(
            "Cloudflare R2 / S3 downloading object: bucket={}, key={}",
            self.bucket,
            key
        );
        let output = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| {
                use aws_sdk_s3::error::SdkError;
                match &e {
                    SdkError::ServiceError(ctx) => classify_get_object_error(ctx.err()),
                    _ => AppError::StorageError(format!("Cloudflare R2 download error: {e}")),
                }
            })?;

        let data = output.body.collect().await.map_err(|e| {
            AppError::StorageError(format!("Failed reading R2 response body: {}", e))
        })?;

        Ok(data.into_bytes().to_vec())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        if key.contains("..") || key.starts_with('/') {
            return Err(AppError::Forbidden("Invalid key".into()));
        }
        tracing::info!(
            "Cloudflare R2 / S3 deleting object: bucket={}, key={}",
            self.bucket,
            key
        );
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| AppError::StorageError(format!("Cloudflare R2 delete error: {}", e)))?;
        Ok(())
    }

    async fn presigned_url(&self, key: &str, expires_secs: i64) -> Result<String> {
        if key.contains("..") || key.starts_with('/') {
            return Err(AppError::Forbidden("Invalid key".into()));
        }
        let expires = aws_sdk_s3::presigning::PresigningConfig::expires_in(
            std::time::Duration::from_secs(expires_secs as u64),
        )
        .map_err(|e| AppError::StorageError(format!("Invalid expiration: {}", e)))?;
        let presigned = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .presigned(expires)
            .await
            .map_err(|e| AppError::StorageError(format!("Presigning failed: {}", e)))?;
        Ok(presigned.uri().to_string())
    }
}

pub struct LocalStorageBackend {
    base_dir: std::path::PathBuf,
}

impl LocalStorageBackend {
    pub fn new(base_dir: impl AsRef<std::path::Path>) -> Self {
        let base = base_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&base).ok();
        Self { base_dir: base }
    }
}

#[async_trait]
impl StorageBackend for LocalStorageBackend {
    async fn upload(&self, data: Vec<u8>, key: &str, _content_type: &str) -> Result<String> {
        if key.contains("..") || key.starts_with('/') {
            return Err(AppError::Forbidden("Invalid key".into()));
        }
        let path = self.base_dir.join(key);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&path, data).map_err(|e| AppError::StorageError(format!("{e}")))?;
        Ok(key.to_string())
    }

    async fn download(&self, key: &str) -> Result<Vec<u8>> {
        if key.contains("..") || key.starts_with('/') {
            return Err(AppError::Forbidden("Invalid key".into()));
        }
        std::fs::read(self.base_dir.join(key)).map_err(|e| {
            // A DB row whose backing object is gone (retention sweep, manual
            // deletion, half-completed upload) is a missing resource, not a
            // server fault: 404 lets the client distinguish "no such artifact"
            // from a storage outage.
            if e.kind() == std::io::ErrorKind::NotFound {
                AppError::NotFound("Stored object not found".into())
            } else {
                AppError::StorageError(format!("{e}"))
            }
        })
    }

    async fn delete(&self, key: &str) -> Result<()> {
        if key.contains("..") || key.starts_with('/') {
            return Err(AppError::Forbidden("Invalid key".into()));
        }
        std::fs::remove_file(self.base_dir.join(key))
            .map_err(|e| AppError::StorageError(format!("{e}")))
    }

    async fn presigned_url(&self, key: &str, _expires_secs: i64) -> Result<String> {
        if key.contains("..") || key.starts_with('/') {
            return Err(AppError::Forbidden("Invalid key".into()));
        }
        Ok(format!("file:///{}", self.base_dir.join(key).display()))
    }
}

pub struct StorageService {
    pub s3_backend: Option<S3StorageBackend>,
    pub local_backend: LocalStorageBackend,
    bucket: String,
}

impl StorageService {
    pub async fn new(
        endpoint: Option<String>,
        access_key: &str,
        secret_key: &str,
        bucket: &str,
        local_dir: impl AsRef<std::path::Path>,
        region: &str,
    ) -> Self {
        let s3_backend = if endpoint.is_some() && !access_key.is_empty() {
            S3StorageBackend::new(endpoint, access_key, secret_key, bucket, region)
                .await
                .ok()
        } else {
            None
        };
        Self {
            s3_backend,
            local_backend: LocalStorageBackend::new(local_dir),
            bucket: bucket.into(),
        }
    }

    pub async fn upload_artifact(
        &self,
        data: Vec<u8>,
        artifact_type: &str,
        file_name: &str,
        job_id: &str,
    ) -> Result<(String, String)> {
        use sha2::{Digest, Sha256};
        if job_id.trim().is_empty()
            || job_id.contains('/')
            || job_id.contains('\\')
            || job_id.contains("..")
            || artifact_type.trim().is_empty()
            || artifact_type.contains('/')
            || artifact_type.contains('\\')
            || artifact_type.contains("..")
            || file_name.trim().is_empty()
            || file_name.contains('/')
            || file_name.contains('\\')
            || file_name.contains("..")
        {
            return Err(AppError::BadRequest("Invalid artifact path segment".into()));
        }
        let key = format!("artifacts/{}/{}/{}", job_id.trim(), artifact_type.trim(), file_name.trim());
        let sha256 = format!("{:x}", Sha256::digest(&data));
        let content_type = MimeGuess::from_path(file_name)
            .first_or_octet_stream()
            .to_string();
        if let Some(s3) = &self.s3_backend {
            s3.upload(data, &key, &content_type).await?;
        } else {
            self.local_backend.upload(data, &key, &content_type).await?;
        }
        Ok((key, sha256))
    }

    pub async fn download_artifact(&self, key: &str) -> Result<Vec<u8>> {
        if let Some(s3) = &self.s3_backend {
            s3.download(key).await
        } else {
            self.local_backend.download(key).await
        }
    }
}

/// Classify a GetObject service error: only a confirmed missing key is a 404.
/// Access denials, missing buckets (unmodeled here), archived-object state,
/// throttling, and transport failures stay 5xx, so a permissions or
/// infrastructure problem is never misreported as "no such artifact".
/// Mirrors the local backend's `NotFound` mapping for the same condition.
fn classify_get_object_error(err: &aws_sdk_s3::operation::get_object::GetObjectError) -> AppError {
    if err.is_no_such_key() {
        AppError::NotFound("Stored object not found".into())
    } else {
        AppError::StorageError(format!("Cloudflare R2 download error: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_s3_key_maps_to_not_found_without_masking_other_failures() {
        use aws_sdk_s3::operation::get_object::GetObjectError;
        use aws_sdk_s3::types::error::NoSuchKey;

        let missing = GetObjectError::NoSuchKey(
            NoSuchKey::builder()
                .message("The specified key does not exist.")
                .build(),
        );
        assert!(
            matches!(classify_get_object_error(&missing), AppError::NotFound(_)),
            "a confirmed missing key must be a 404 like the local backend"
        );

        // Anything else — archived state, unmodeled service errors — stays a
        // 5xx so outages and permission problems are never reported as
        // "no such artifact".
        let archived = GetObjectError::unhandled("InvalidObjectState");
        assert!(
            matches!(
                classify_get_object_error(&archived),
                AppError::StorageError(_)
            ),
            "non-key failures must stay server errors"
        );
    }
}
