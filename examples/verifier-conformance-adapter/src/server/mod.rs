use std::sync::Arc;
use std::time::Duration;

use axum::{
    routing::{get, post},
    Router,
};
use tower_http::{cors::CorsLayer, timeout::TimeoutLayer, trace::TraceLayer};

mod handlers;
mod state;

pub use state::{AppState, OidfConfig};

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Initiate authorization request - triggers the OID4VP flow
        .route("/initiate", post(handlers::initiate_request))
        // Request URI endpoint - wallet fetches the signed JWT here
        .route("/request/:session_id", get(handlers::get_request_object))
        // Response URI endpoint - wallet submits vp_token here
        .route("/response/:session_id", post(handlers::receive_response))
        // Status endpoint - check session status
        .route("/status/:session_id", get(handlers::get_status))
        // Health check
        .route("/health", get(handlers::health))
        .with_state(state)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
}
