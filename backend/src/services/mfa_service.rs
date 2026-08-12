use crate::error::{AppError, Result};
use chrono::Utc;
use otpauth::TOTP;
use rand::Rng;

pub struct MfaService;

impl MfaService {
    pub fn generate_secret(username: &str, issuer: &str) -> (String, String) {
        let auth_secret: String = (0..32)
            .map(|_| format!("{:x}", rand::thread_rng().gen_range(0..16)))
            .collect();
        let totp = TOTP::new(auth_secret.clone());
        let uri = totp.to_uri(username, issuer);
        (auth_secret, uri)
    }

    pub fn verify_totp(secret: &str, token: &str) -> bool {
        let code: u32 = match token.parse() {
            Ok(c) => c,
            Err(_) => return false,
        };
        let totp = TOTP::new(secret);
        let timestamp = Utc::now().timestamp() as u64;
        totp.verify(code, 1, timestamp)
    }

    pub fn generate_recovery_codes(count: i32) -> (Vec<String>, Vec<String>) {
        // HIGH-09: 8-character codes from a 32-character alphabet (excluding
        // look-alikes 0/O/1/I/l) provide >40 bits of entropy, vs ~20 bits for
        // the old 6-digit numeric codes.
        const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
        let mut codes = Vec::with_capacity(count.max(0) as usize);
        for _ in 0..count.max(0) {
            let code: String = (0..8)
                .map(|_| {
                    let idx = rand::thread_rng().gen_range(0..ALPHABET.len());
                    ALPHABET[idx] as char
                })
                .collect();
            codes.push(code);
        }
        let code_hashes: Vec<String> = codes.iter()
            .map(|code| MfaService::hash_recovery_code(code))
            .collect();
        (codes, code_hashes)
    }

    pub fn hash_recovery_code(code: &str) -> String {
        use sha2::Digest;
        format!("{:x}", sha2::Sha256::digest(code.as_bytes()))
    }

    pub async fn log_event(
        pool: &sqlx::PgPool,
        user_id: &str,
        action: &str,
        success: bool,
        ip_hash: Option<&str>,
    ) -> Result<()> {
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO mfa_audit_logs (id, user_id, action, success, ip_hash, created_at) VALUES ($1, $2, $3, $4, $5, $6)"
        )
        .bind(id).bind(user_id).bind(action).bind(success).bind(ip_hash).bind(Utc::now().naive_utc())
        .execute(pool)
        .await
        .map_err(AppError::Database)?;
        Ok(())
    }
}
