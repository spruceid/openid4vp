use axum::{extract::State, Json};
use serde_json::{json, Value};

use crate::server::AppState;

/// GET /health
///
/// Health check endpoint for monitoring and load balancers.
pub async fn health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "engine": "headless"
    }))
}

/// GET /debug/config
///
/// Debug endpoint showing current configuration.
/// Should be disabled or protected in production.
pub async fn debug_config(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "authorization_endpoint": state.config.authorization_endpoint.to_string(),
        "public_url": state.config.public_url.to_string(),
        "credentials_count": state.engine.credentials_count(),
    }))
}

/// GET /debug/credentials
///
/// Debug endpoint listing available mock credentials.
pub async fn debug_credentials(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "count": state.engine.credentials_count(),
        "formats": ["dc+sd-jwt", "vc+sd-jwt"],
    }))
}
