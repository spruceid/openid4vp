use axum::{
    routing::{get, post},
    Router,
};
use std::time::Duration;
use tower_http::{
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};

use super::handlers::{authorization, health, metadata};
use super::AppState;

pub fn create_router(state: AppState) -> Router {
    // CORS configuration (permissive for testing)
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        // Authorization Endpoint (OID4VP)
        .route("/authorize", get(authorization::authorization_get))
        .route("/authorize", post(authorization::authorization_post))
        // Metadata Endpoints
        .route(
            "/.well-known/openid-configuration",
            get(metadata::wallet_metadata),
        )
        .route("/.well-known/jwks.json", get(metadata::jwks))
        // Health & Debug Endpoints
        .route("/health", get(health::health))
        .route("/debug/config", get(health::debug_config))
        .route("/debug/credentials", get(health::debug_credentials))
        // Root endpoint (useful for quick health check)
        .route("/", get(health::health))
        // Middleware
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .layer(RequestBodyLimitLayer::new(1024 * 1024)) // 1MB max
        // State
        .with_state(state)
}
