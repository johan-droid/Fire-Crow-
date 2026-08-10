use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use sha2::{Digest, Sha256};
use std::sync::Arc;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

pub struct CryptoManager {
    key: Vec<u8>,
}

impl CryptoManager {
    pub fn new(secret_or_encryption_key: &str) -> Result<Self> {
        let key_bytes = secret_or_encryption_key.as_bytes();
        let hash = Sha256::digest(key_bytes);
        let fernet_key = URL_SAFE.encode(hash);
        Ok(Self { key: fernet_key.into_bytes() })
    }

    pub fn encrypt_secret(&self, plaintext: &str) -> Result<String> {
        if plaintext.is_empty() { return Ok(plaintext.into()); }
        let iv: [u8; 16] = rand::random();
        let encryptor = Aes128CbcEnc::new((&self.key[..16]).into(), &iv.into());
        let ciphertext = encryptor.encrypt_padded_vec_mut::<Pkcs7>(plaintext.as_bytes());
        let mut result = iv.to_vec();
        result.extend(ciphertext);
        Ok(format!("ENC[{}]", URL_SAFE.encode(result)))
    }

    pub fn decrypt_secret(&self, ciphertext: &str) -> Result<String> {
        if !ciphertext.starts_with("ENC[") || !ciphertext.ends_with(']') {
            return Ok(ciphertext.into());
        }
        let inner = &ciphertext[4..ciphertext.len() - 1];
        let data = URL_SAFE.decode(inner).context("Base64 decode failed")?;
        if data.len() < 16 { anyhow::bail!("Ciphertext too short"); }
        let iv: [u8; 16] = data[..16].try_into().unwrap();
        let decryptor = Aes128CbcDec::new((&self.key[..16]).into(), &iv.into());
        let plaintext_bytes = decryptor.decrypt_padded_vec_mut::<Pkcs7>(&data[16..])
            .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;
        String::from_utf8(plaintext_bytes).context("Decrypted bytes are not valid UTF-8")
    }
}

pub fn crypto_manager(secret_key: &str, encryption_key: &str) -> Result<Arc<CryptoManager>> {
    let key = if encryption_key.is_empty() { secret_key } else { encryption_key };
    Ok(Arc::new(CryptoManager::new(key)?))
}
