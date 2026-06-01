use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::prelude::*;
use openid4vp::{
    core::{
        authorization_request::parameters::Nonce,
        response::{parameters::VpTokenItem, AuthorizationResponse},
    },
    verifier::session::{Outcome, Session, Status},
};
use serde::{Deserialize, Serialize};
use ssi::claims::jws::{decode_unverified, decode_verify};
use ssi::claims::sd_jwt::{KbJwtPayload, SdAlg, SdJwt};
use ssi::claims::{DateTimeProvider, ValidateClaims};
use ssi::jwk::JWK;
use tracing::{debug, error, info};
use uuid::Uuid;
use x509_cert::{der::Decode, Certificate};

use super::AppState;
use crate::crypto::decrypt_jwe;

/// Health check endpoint
pub async fn health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "service": "verifier-conformance-adapter"
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

    // Clone the encryption key for use in the closure.
    let encryption_key = state.encryption_key_jwk.clone();

    // The validator runs inside `verify_response`, but its `Outcome` is only
    // stored in the session. We capture the rejection reason here so the HTTP
    // handler can return a 4xx, as required by OID4VP 1.0 Section 8.2.
    let rejection: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let rejection_cb = rejection.clone();

    state
        .verifier
        .verify_response(uuid, authorization_response, move |session, response| {
            Box::pin(async move {
                info!("Validating response for session: {}", session.uuid);

                let result = match &response {
                    AuthorizationResponse::Unencoded(unencoded) => {
                        verify_string_presentations(&session, &unencoded.vp_token.0)
                    }
                    AuthorizationResponse::Jwt(jwt_response) => {
                        info!("Received encrypted JWT response (JARM)");
                        match decrypt_jwe(&jwt_response.response, &encryption_key) {
                            Ok(decrypted) => verify_decrypted_vp_token(&session, &decrypted),
                            Err(e) => Err(format!("failed to decrypt JARM response: {e}")),
                        }
                    }
                };

                match result {
                    Ok(count) => Outcome::Success {
                        info: serde_json::json!({
                            "message": "Verification successful",
                            "credentials_verified": count
                        }),
                    },
                    Err(reason) => {
                        error!("Rejecting response: {}", reason);
                        *rejection_cb.lock().unwrap() = Some(reason.clone());
                        Outcome::Failure { reason }
                    }
                }
            })
        })
        .await
        .map_err(|e| {
            error!("Failed to verify response: {}", e);
            AppError::Internal(format!("Verification failed: {}", e))
        })?;

    if let Some(reason) = rejection.lock().unwrap().take() {
        return Err(AppError::BadRequest(reason));
    }

    info!("Authorization response verified successfully");

    Ok(Json(serde_json::json!({})))
}

/// Verify every string presentation in an unencoded `vp_token`.
///
/// Returns the number of verified credentials, or a rejection reason.
fn verify_string_presentations(
    session: &Session,
    vp_token: &std::collections::HashMap<String, Vec<VpTokenItem>>,
) -> Result<usize, String> {
    let (nonce, aud) = request_binding(session);
    let mut count = 0;
    for (query_id, presentations) in vp_token {
        for item in presentations {
            let VpTokenItem::String(sd_jwt) = item else {
                return Err(format!(
                    "query '{query_id}': unsupported presentation format"
                ));
            };
            verify_sd_jwt_vc(sd_jwt, &nonce, &aud)?;
            count += 1;
        }
    }
    Ok(count)
}

/// Verify the string presentations carried in a decrypted (JARM) `vp_token`.
fn verify_decrypted_vp_token(
    session: &Session,
    decrypted: &serde_json::Value,
) -> Result<usize, String> {
    let (nonce, aud) = request_binding(session);
    let vp_token = decrypted
        .get("vp_token")
        .and_then(|v| v.as_object())
        .ok_or("decrypted response has no vp_token object")?;
    let mut count = 0;
    for (query_id, presentations) in vp_token {
        let arr = presentations
            .as_array()
            .ok_or_else(|| format!("query '{query_id}': presentations is not an array"))?;
        for item in arr {
            let sd_jwt = item
                .as_str()
                .ok_or_else(|| format!("query '{query_id}': unsupported presentation format"))?;
            verify_sd_jwt_vc(sd_jwt, &nonce, &aud)?;
            count += 1;
        }
    }
    Ok(count)
}

/// Extract the expected `nonce` and `aud` (client_id) from the request session.
fn request_binding(session: &Session) -> (String, String) {
    let nonce = session.authorization_request_object.nonce().to_string();
    let aud = session
        .authorization_request_object
        .client_id()
        .map(|c| c.0.clone())
        .unwrap_or_default();
    (nonce, aud)
}

/// Minimal SD-JWT VC + Key Binding JWT verification using `ssi`.
///
/// Checks the essentials needed to reject forged or mis-bound presentations:
/// - the credential is a well-formed SD-JWT VC ending in a Key Binding JWT;
/// - the issuer JWT signature is valid against the public key in its `x5c` leaf
///   certificate (this is what the `invalid-credential-signature` test corrupts);
/// - the KB-JWT signature is valid against the holder key in the issuer JWT's
///   `cnf` claim (this is what the `invalid-kb-jwt-signature` test corrupts);
/// - the KB-JWT `nonce` and `aud` match the Authorization Request.
fn verify_sd_jwt_vc(
    presentation: &str,
    expected_nonce: &str,
    expected_aud: &str,
) -> Result<(), String> {
    let sd_jwt = SdJwt::new(presentation).map_err(|e| format!("invalid SD-JWT: {e}"))?;
    let issuer_jwt = sd_jwt.jwt().as_str();

    // Decode the issuer JWT header (for the x5c key) and verify its signature.
    let (header, _) =
        decode_unverified(issuer_jwt).map_err(|e| format!("failed to decode issuer JWT: {e}"))?;
    let issuer_key = issuer_key_from_x5c(&header.x509_certificate_chain)?;
    let (_, payload) = decode_verify(issuer_jwt, &issuer_key)
        .map_err(|e| format!("issuer SD-JWT signature verification failed: {e}"))?;

    // Recover the holder key from the issuer JWT's `cnf.jwk`.
    let claims: serde_json::Value = serde_json::from_slice(&payload)
        .map_err(|e| format!("issuer JWT payload not JSON: {e}"))?;
    let cnf_jwk = claims
        .get("cnf")
        .and_then(|c| c.get("jwk"))
        .ok_or("issuer JWT has no cnf.jwk (holder key)")?;
    let holder_key: JWK =
        serde_json::from_value(cnf_jwk.clone()).map_err(|e| format!("invalid cnf.jwk: {e}"))?;

    // Verify the KB-JWT signature against the holder key, then deserialize the
    // typed KB-JWT payload (ssi `KbJwtPayload`).
    let kb_jwt = sd_jwt.kb().ok_or("Key Binding JWT is missing")?.as_str();
    let (_, kb_payload) = decode_verify(kb_jwt, &holder_key)
        .map_err(|e| format!("Key Binding JWT signature verification failed: {e}"))?;
    let kb: KbJwtPayload = serde_json::from_slice(&kb_payload)
        .map_err(|e| format!("KB-JWT is not a valid Key Binding JWT: {e}"))?;

    // Ensure the KB-JWT binds to this transaction.
    if kb.nonce.0 != expected_nonce {
        return Err("KB-JWT nonce does not match the request".into());
    }
    if kb.aud != expected_aud {
        return Err("KB-JWT aud does not match the client_id".into());
    }

    // Verify the `sd_hash` against the presented SD-JWT using ssi (hashes the
    // SD-JWT up to and including the last '~' before the KB-JWT).
    if !kb.sd_hash.verify(SdAlg::Sha256, sd_jwt) {
        return Err("KB-JWT sd_hash does not match the presented SD-JWT".into());
    }

    // Validate the KB-JWT time claims via its own `ValidateClaims` impl
    // (rejects `iat` in the future, plus `exp`/`nbf` when present).
    kb.validate_claims(&Now, &())
        .map_err(|e| format!("KB-JWT time claims are invalid: {e}"))?;

    // `ssi` only checks that `iat` is not in the future. The maximum age ("iat too
    // far in the past") is verifier policy, so we enforce it here.
    const MAX_AGE_SECS: f64 = 300.0;
    let iat = kb.iat.0.as_seconds();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("system clock error: {e}"))?
        .as_secs() as f64;
    if iat < now - MAX_AGE_SECS {
        return Err("KB-JWT iat is too far in the past".into());
    }

    Ok(())
}

/// Minimal [`DateTimeProvider`] supplying the current time so `ssi` can validate
/// the KB-JWT time claims against "now".
struct Now;

impl DateTimeProvider for Now {
    fn date_time(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }
}

/// Build a P-256 JWK from the leaf certificate of a JWS `x5c` header.
fn issuer_key_from_x5c(x5c: &Option<Vec<String>>) -> Result<JWK, String> {
    let leaf_b64 = x5c
        .as_ref()
        .and_then(|chain| chain.first())
        .ok_or("issuer JWT header has no x5c certificate")?;
    let der = BASE64_STANDARD
        .decode(leaf_b64)
        .map_err(|e| format!("invalid base64 in x5c: {e}"))?;
    let cert =
        Certificate::from_der(&der).map_err(|e| format!("invalid x5c certificate DER: {e}"))?;

    // For an EC key the SPKI subject public key is the SEC1 uncompressed point:
    // 0x04 || X(32) || Y(32).
    let point = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    if point.len() != 65 || point[0] != 0x04 {
        return Err("unsupported issuer key (expected uncompressed P-256 point)".into());
    }

    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": BASE64_URL_SAFE_NO_PAD.encode(&point[1..33]),
        "y": BASE64_URL_SAFE_NO_PAD.encode(&point[33..65]),
    });
    serde_json::from_value(jwk).map_err(|e| format!("failed to build issuer JWK: {e}"))
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
