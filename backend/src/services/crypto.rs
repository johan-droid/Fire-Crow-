use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::sync::Arc;

/// Authenticated encryption using AES-256-GCM.
///
/// The key is derived from the configured `ENCRYPTION_KEY` (or `SECRET_KEY` as a
/// fallback) using HKDF-SHA256, producing a full 256-bit key with proper domain
/// separation. Ciphertext format: `ENC[<url-safe base64(nonce || ciphertext + tag)>]`
/// with a random 96-bit nonce per message.
pub struct CryptoManager {
    key: [u8; 32],
}

impl CryptoManager {
    pub fn new(secret_or_encryption_key: &str) -> Result<Self> {
        let hk = Hkdf::<Sha256>::new(None, secret_or_encryption_key.as_bytes());
        let mut okm = [0u8; 32];
        hk.expand(b"firecrow-aes-256-gcm-v1", &mut okm)
            .map_err(|e| anyhow::anyhow!("HKDF key expansion failed: {e:?}"))?;
        Ok(Self { key: okm })
    }

    pub fn encrypt_secret(&self, plaintext: &str) -> Result<String> {
        if plaintext.is_empty() { return Ok(plaintext.into()); }
        let cipher = Aes256Gcm::new_from_slice(&self.key).context("invalid AES-256 key")?;
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {e:?}"))?;
        let mut out = nonce.to_vec();
        out.extend(ciphertext);
        Ok(format!("ENC[{}]", URL_SAFE.encode(out)))
    }

    pub fn decrypt_secret(&self, ciphertext: &str) -> Result<String> {
        if !ciphertext.starts_with("ENC[") || !ciphertext.ends_with(']') {
            return Ok(ciphertext.into());
        }
        let inner = &ciphertext[4..ciphertext.len() - 1];
        let data = URL_SAFE.decode(inner).context("Base64 decode failed")?;
        if data.len() < 12 + 16 {
            anyhow::bail!("Ciphertext too short");
        }
        let (nonce_bytes, ct) = data.split_at(12);
        let cipher = Aes256Gcm::new_from_slice(&self.key).context("invalid AES-256 key")?;
        let plaintext_bytes = cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ct)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {e:?}"))?;
        String::from_utf8(plaintext_bytes).context("Decrypted bytes are not valid UTF-8")
    }
}

pub fn crypto_manager(secret_key: &str, encryption_key: &str) -> Result<Arc<CryptoManager>> {
    let key = if encryption_key.is_empty() { secret_key } else { encryption_key };
    Ok(Arc::new(CryptoManager::new(key)?))
}