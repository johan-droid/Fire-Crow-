use rand::Rng;
use std::sync::Arc;
use tokio::sync::RwLock;

const CSRF_COOKIE_NAME: &str = "firecrow_csrf_token";
const CSRF_HEADER_NAME: &str = "x-csrf-token";

#[derive(Debug, Clone)]
pub struct CsrfStore {
    tokens: Arc<RwLock<Vec<String>>>,
}

impl CsrfStore {
    pub fn new() -> Self { Self { tokens: Arc::new(RwLock::new(Vec::new())) } }
    pub async fn generate_token(&self) -> String {
        let token: String = rand::thread_rng().sample_iter(&rand::distributions::Alphanumeric).take(32).map(char::from).collect();
        let mut tokens = self.tokens.write().await;
        tokens.push(token.clone());
        let len = tokens.len();
        if len > 1000 { tokens.drain(0..len - 1000); }
        token
    }
    pub async fn validate(&self, token: &str) -> bool {
        let tokens = self.tokens.read().await;
        tokens.contains(&token.to_string())
    }
    pub fn set_cookie_header(&self, token: &str, secure: bool) -> String {
        let secure_flag = if secure { "Secure; " } else { "" };
        format!("{}={}; Path=/; HttpOnly=false; {}SameSite=Strict; Max-Age=3600", CSRF_COOKIE_NAME, token, secure_flag)
    }
}
impl Default for CsrfStore { fn default() -> Self { Self::new() } }
