use crate::error::{AppError, Result};
use axum::async_trait;
use mime_guess::MimeGuess;

#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn upload(&self, data: Vec<u8>, key: &str, content_type: &str) -> Result<String>;
    async fn download(&self, key: &str) -> Result<Vec<u8>>;
    async fn delete(&self, key: &str) -> Result<()>;
    fn presigned_url(&self, key: &str, expires_secs: i64) -> Result<String>;
}

pub struct S3StorageBackend {
    bucket: String,
    endpoint: Option<String>,
    access_key: String,
    secret_key: String,
    region: String,
}

impl S3StorageBackend {
    pub async fn new(endpoint: Option<String>, access_key: &str, secret_key: &str, bucket: &str, region: &str) -> Result<Self> {
        Ok(Self { bucket: bucket.into(), endpoint, access_key: access_key.into(), secret_key: secret_key.into(), region: region.into() })
    }
}

#[async_trait]
impl StorageBackend for S3StorageBackend {
    async fn upload(&self, data: Vec<u8>, key: &str, _content_type: &str) -> Result<String> {
        tracing::debug!("S3 upload: {}/{} ({} bytes)", self.bucket, key, data.len());
        Ok(key.to_string())
    }
    async fn download(&self, key: &str) -> Result<Vec<u8>> {
        tracing::debug!("S3 download: {}/{}", self.bucket, key);
        Err(AppError::StorageError("S3 download stub".into()))
    }
    async fn delete(&self, key: &str) -> Result<()> {
        tracing::debug!("S3 delete: {}/{}", self.bucket, key);
        Ok(())
    }
    fn presigned_url(&self, key: &str, expires_secs: i64) -> Result<String> {
        let base = self.endpoint.as_deref().unwrap_or("https://s3.amazonaws.com");
        Ok(format!("{}/{}/{}?X-Amz-Expires={}", base, self.bucket, key, expires_secs))
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
        let path = self.base_dir.join(key);
        if let Some(parent) = path.parent() { std::fs::create_dir_all(parent).ok(); }
        std::fs::write(&path, data).map_err(|e| AppError::StorageError(format!("{e}")))?;
        Ok(key.to_string())
    }
    async fn download(&self, key: &str) -> Result<Vec<u8>> {
        std::fs::read(self.base_dir.join(key)).map_err(|e| AppError::StorageError(format!("{e}")))
    }
    async fn delete(&self, key: &str) -> Result<()> {
        std::fs::remove_file(self.base_dir.join(key)).map_err(|e| AppError::StorageError(format!("{e}")))
    }
    fn presigned_url(&self, key: &str, _expires_secs: i64) -> Result<String> {
        Ok(format!("file:///{}", self.base_dir.join(key).display()))
    }
}

pub struct StorageService {
    pub s3_backend: Option<S3StorageBackend>,
    pub local_backend: LocalStorageBackend,
    bucket: String,
}

impl StorageService {
    pub async fn new(endpoint: Option<String>, access_key: &str, secret_key: &str, bucket: &str, local_dir: impl AsRef<std::path::Path>, region: &str) -> Self {
        let s3_backend = if endpoint.is_some() && !access_key.is_empty() {
            S3StorageBackend::new(endpoint, access_key, secret_key, bucket, region).await.ok()
        } else { None };
        Self { s3_backend, local_backend: LocalStorageBackend::new(local_dir), bucket: bucket.into() }
    }

    pub async fn upload_artifact(&self, data: Vec<u8>, artifact_type: &str, file_name: &str, job_id: &str) -> Result<(String, String)> {
        use sha2::{Digest, Sha256};
        let key = format!("artifacts/{}/{}/{}", job_id, artifact_type, file_name);
        let sha256 = format!("{:x}", Sha256::digest(&data));
        let content_type = MimeGuess::from_path(file_name).first_or_octet_stream().to_string();
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
