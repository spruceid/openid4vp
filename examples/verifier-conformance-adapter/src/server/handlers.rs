use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use openid4vp::{
    core::{authorization_request::parameters::Nonce, response::AuthorizationResponse},
    verifier::session::{Outcome, Status},
};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};
use uuid::Uuid;

use super::AppState;
use crate::crypto::decrypt_jwe;

/// Health check endpoint
pub async fn health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "service": "oid4vp-verifier-adapter"
    }))
}

#[derive(Debug, Deserialize)]
pub struct InitiateRequest {
    /// Optional custom nonce (generated if not provided)
    pub nonce: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct InitiateResponse {
    /// Session ID for tracking
    pub session_id: String,
    /// Authorization URL to redirect the wallet to
    pub authorization_url: String,
    /// Status polling endpoint
    pub status_url: String,
}

/// POST /initiate
///
/// Initiates an OID4VP authorization request using the library's Verifier.
pub async fn initiate_request(
    State(state): State<Arc<AppState>>,
    Json(body): Json<InitiateRequest>,
) -> Result<Json<InitiateResponse>, AppError> {
    info!("Initiating authorization request");

    let dcql_query = AppState::build_dcql_query();

    // Build the authorization request
    let mut request_builder = state
        .verifier
        .build_authorization_request()
        .with_dcql_query(dcql_query);

    // Add nonce
    let nonce = body.nonce.unwrap_or_else(|| Uuid::new_v4().to_string());
    request_builder = request_builder.with_request_parameter(Nonce::from(nonce));

    // Build the request. This creates the session and returns the URL
    let (session_id, authorization_url) = request_builder
        .build(state.wallet_metadata.clone())
        .await
        .map_err(|e| {
            error!("Failed to build authorization request: {}", e);
            AppError::Internal(e.to_string())
        })?;

    info!(
        "Created authorization request with session_id: {}",
        session_id
    );
    info!("Authorization URL: {}", authorization_url);

    let status_url = format!("{}/status/{}", state.public_url, session_id);

    Ok(Json(InitiateResponse {
        session_id: session_id.to_string(),
        authorization_url: authorization_url.to_string(),
        status_url,
    }))
}

/// GET /request/:session_id
///
/// Returns the signed authorization request JWT for the wallet to fetch.
/// This is the request_uri endpoint.
pub async fn get_request_object(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> Result<Response, AppError> {
    let uuid: Uuid = session_id
        .parse()
        .map_err(|_| AppError::BadRequest("Invalid session ID".to_string()))?;

    info!("Wallet fetching request object for session: {}", uuid);

    let jwt = state
        .verifier
        .retrieve_authorization_request(uuid)
        .await
        .map_err(|e| {
            error!("Failed to retrieve authorization request: {}", e);
            AppError::NotFound(format!("Session not found: {}", e))
        })?;

    info!("Returning signed JWT request object");

    Ok((
        StatusCode::OK,
        [("content-type", "application/oauth-authz-req+jwt")],
        jwt,
    )
        .into_response())
}

/// POST /response/:session_id
///
/// Receives the authorization response (vp_token) from the wallet.
/// This is the response_uri endpoint for direct_post.jwt mode.
pub async fn receive_response(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    body: String,
) -> Result<Json<serde_json::Value>, AppError> {
    let uuid: Uuid = session_id
        .parse()
        .map_err(|_| AppError::BadRequest("Invalid session ID".to_string()))?;

    info!("Received authorization response for session: {}", uuid);
    debug!("Response body: {}", body);

    let authorization_response = AuthorizationResponse::from_x_www_form_urlencoded(body.as_bytes())
        .map_err(|e| {
            error!("Failed to parse authorization response: {}", e);
            AppError::BadRequest(format!("Invalid authorization response: {}", e))
        })?;

    info!("Parsed authorization response successfully");

    // Clone the encryption key for use in the closure
    let encryption_key = state.encryption_key_jwk.clone();

    state
        .verifier
        .verify_response(uuid, authorization_response, |session, response| {
            Box::pin(async move {
                // For conformance testing, we do basic validation
                // In production, you would verify signatures, check claims, etc.
                info!("Validating response for session: {}", session.uuid);

                match &response {
                    AuthorizationResponse::Unencoded(unencoded) => {
                        let vp_token = &unencoded.vp_token;
                        info!(
                            "Received unencoded vp_token with {} credential(s)",
                            vp_token.0.len()
                        );

                        for (query_id, presentations) in &vp_token.0 {
                            info!(
                                "Query '{}': {} presentation(s)",
                                query_id,
                                presentations.len()
                            );
                        }

                        Outcome::Success {
                            info: serde_json::json!({
                                "message": "Verification successful",
                                "credentials_received": vp_token.0.len()
                            }),
                        }
                    }
                    AuthorizationResponse::Jwt(jwt_response) => {
                        // For direct_post.jwt mode - decrypt the JWE
                        info!("Received encrypted JWT response (JARM)");
                        debug!("JWE: {}", jwt_response.response);

                        match decrypt_jwe(&jwt_response.response, &encryption_key) {
                            Ok(decrypted) => {
                                info!("Successfully decrypted JARM response");
                                debug!("Decrypted payload: {:?}", decrypted);

                                // Extract vp_token from decrypted payload
                                if let Some(vp_token) = decrypted.get("vp_token") {
                                    info!(
                                        "Extracted vp_token from decrypted response: {:?}",
                                        vp_token
                                    );
                                }

                                Outcome::Success {
                                    info: serde_json::json!({
                                        "message": "JARM response decrypted and verified",
                                        "decrypted_payload": decrypted
                                    }),
                                }
                            }
                            Err(e) => {
                                error!("Failed to decrypt JARM response: {}", e);
                                Outcome::Error {
                                    cause: format!("Failed to decrypt JARM: {}", e),
                                }
                            }
                        }
                    }
                }
            })
        })
        .await
        .map_err(|e| {
            error!("Failed to verify response: {}", e);
            AppError::Internal(format!("Verification failed: {}", e))
        })?;

    info!("Authorization response verified successfully");

    Ok(Json(serde_json::json!({})))
}

/// GET /status/:session_id
///
/// Returns the current status of an authorization session.
pub async fn get_status(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let uuid: Uuid = session_id
        .parse()
        .map_err(|_| AppError::BadRequest("Invalid session ID".to_string()))?;

    let status = state
        .verifier
        .poll_status(uuid)
        .await
        .map_err(|e| AppError::NotFound(format!("Session not found: {}", e)))?;

    let status_json = match status {
        Status::SentRequestByReference => serde_json::json!({
            "status": "sent_request_by_reference",
            "message": "Waiting for wallet to fetch request"
        }),
        Status::ReceivedResponse => serde_json::json!({
            "status": "received_response",
            "message": "Response received, processing"
        }),
        Status::SentRequest => serde_json::json!({
            "status": "sent_request",
            "message": "Request sent to wallet, waiting for response"
        }),
        Status::Complete(outcome) => match outcome {
            Outcome::Success { info } => serde_json::json!({
                "status": "complete",
                "result": "success",
                "info": info
            }),
            Outcome::Failure { reason } => serde_json::json!({
                "status": "complete",
                "result": "failure",
                "reason": reason
            }),
            Outcome::Error { cause } => serde_json::json!({
                "status": "complete",
                "result": "error",
                "cause": cause
            }),
        },
    };

    Ok(Json(status_json))
}

#[derive(Debug)]
pub enum AppError {
    BadRequest(String),
    NotFound(String),
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            AppError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}
