use axum::Router;
use std::sync::Arc;

pub fn router() -> Router<Arc<crate::AppState>> {
    Router::new()
}
