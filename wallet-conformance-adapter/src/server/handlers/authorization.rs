use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Form, Json,
};
use openid4vp::core::{
    authorization_request::{
        parameters::{ResponseMode, State as RequestState},
        AuthorizationRequest, AuthorizationRequestObject,
    },
    dcql_query::DcqlQuery,
    jwe::{find_encryption_jwk, EncryptionJwkInfo, JweBuilder},
    object::ParsingErrorContext,
    response::{parameters::VpToken, UnencodedAuthorizationResponse},
    util::ReqwestClient,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{debug, error, info, instrument, warn};

use crate::server::AppState;

#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizationParams {
    /// Client ID (with "redirect_uri:" scheme prefix)
    pub client_id: Option<String>,
    /// Request object JWT (by-value delivery)
    pub request: Option<String>,
    /// Request URI (by-reference delivery)
    pub request_uri: Option<String>,
    /// Response type (should be "vp_token")
    pub response_type: Option<String>,
    /// Nonce for replay protection
    pub nonce: Option<String>,
    /// State to echo back
    pub state: Option<String>,
    /// Response mode (direct_post, direct_post.jwt)
    pub response_mode: Option<String>,
    /// Response URI (where to send the response)
    pub response_uri: Option<String>,
    /// DCQL query (for direct encoding, rare)
    pub dcql_query: Option<String>,
}

/// Error response structure
#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    error_description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
}

/// Success response (redirect info)
#[derive(Debug, Serialize)]
struct SuccessResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    redirect_uri: Option<String>,
}

/// GET /authorize
///
/// Authorization endpoint accepting requests via query parameters.
#[instrument(skip(state), fields(client_id = ?params.client_id))]
pub async fn authorization_get(
    State(state): State<AppState>,
    Query(params): Query<AuthorizationParams>,
) -> Response {
    info!("Received authorization request (GET)");
    debug!(?params, "Request parameters");
    process_authorization_request(state, params).await
}

/// POST /authorize
///
/// Authorization endpoint accepting requests via form body.
#[instrument(skip(state), fields(client_id = ?params.client_id))]
pub async fn authorization_post(
    State(state): State<AppState>,
    Form(params): Form<AuthorizationParams>,
) -> Response {
    info!("Received authorization request (POST)");
    debug!(?params, "Request parameters");
    process_authorization_request(state, params).await
}

/// Process the authorization request
async fn process_authorization_request(state: AppState, params: AuthorizationParams) -> Response {
    // 1. Build the URL for the openid4vp library
    let url = match build_request_url(&state, &params) {
        Ok(url) => url,
        Err(e) => {
            error!("Failed to build request URL: {}", e);
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                &e.to_string(),
                params.state.as_deref(),
            );
        }
    };

    debug!(%url, "Constructed authorization request URL");

    // 2. Parse the authorization request using openid4vp library
    let auth_request =
        match AuthorizationRequest::from_url(url.clone(), &state.config.authorization_endpoint) {
            Ok(req) => req,
            Err(e) => {
                error!("Failed to parse authorization request: {}", e);
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    &format!("Failed to parse request: {}", e),
                    params.state.as_deref(),
                );
            }
        };

    // 3. Resolve the request (fetch request_uri if needed, decode JWT)
    let http_client = match ReqwestClient::new() {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to create HTTP client: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &format!("Failed to create HTTP client: {}", e),
                params.state.as_deref(),
            );
        }
    };
    let (request_object, _jwt) = match auth_request.resolve_request(&http_client).await {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to resolve authorization request: {}", e);
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                &format!("Failed to resolve request: {}", e),
                params.state.as_deref(),
            );
        }
    };

    debug!("Authorization request resolved successfully");

    // 4. Extract DCQL query using the dedicated method
    let dcql_query: DcqlQuery = match request_object.dcql_query() {
        Some(Ok(q)) => q,
        Some(Err(e)) => {
            error!("Failed to parse dcql_query: {}", e);
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                &format!("Invalid dcql_query: {}", e),
                params.state.as_deref(),
            );
        }
        None => {
            error!("Missing dcql_query in request");
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Missing required parameter: dcql_query",
                params.state.as_deref(),
            );
        }
    };

    debug!(?dcql_query, "Extracted DCQL query");

    // 5. Process with wallet engine (select credentials)
    let selection = match state.engine.process_request(&request_object).await {
        Ok(sel) => sel,
        Err(e) => {
            error!("Engine processing failed: {}", e);
            return error_response(
                StatusCode::BAD_REQUEST,
                "access_denied",
                &e.to_string(),
                params.state.as_deref(),
            );
        }
    };

    // 6. Security validation: verify response_uri matches client_id for redirect_uri scheme
    // Per OID4VP spec, when client_id_scheme is "redirect_uri", the response_uri MUST equal client_id
    if let Some(client_id) = request_object.client_id() {
        let client_id_str = &client_id.0;
        let response_uri_str = request_object.return_uri().as_str();

        // Check if client_id uses redirect_uri scheme
        if client_id_str.starts_with("redirect_uri:") {
            let expected_response_uri = client_id_str.strip_prefix("redirect_uri:").unwrap();

            if response_uri_str != expected_response_uri {
                error!(
                    %client_id_str,
                    %response_uri_str,
                    %expected_response_uri,
                    "Security violation: response_uri does not match client_id"
                );
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "response_uri must match client_id when using redirect_uri client_id_scheme",
                    params.state.as_deref(),
                );
            }
            debug!("Security check passed: response_uri matches client_id");
        }
    }

    // 7. Extract nonce and audience for VP creation
    let nonce = request_object.nonce().as_str();
    let audience = request_object
        .client_id()
        .map(|c| c.0.as_str())
        .unwrap_or("unknown-verifier");

    // 8. Build vp_token
    let vp_token_map = match state
        .engine
        .build_vp_token(&selection, nonce, audience)
        .await
    {
        Ok(vp) => vp,
        Err(e) => {
            error!("Failed to build vp_token: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &format!("Failed to build presentation: {}", e),
                params.state.as_deref(),
            );
        }
    };

    // 9. Get response mode and URI
    let response_mode = request_object.response_mode();
    let response_uri = request_object.return_uri();

    // Get state from request if present
    let request_state = request_object.state().and_then(|r| r.ok()).map(|s| s.0);
    let state_to_echo = request_state.or(params.state.clone());

    info!(
        ?response_mode,
        %response_uri,
        "Submitting response"
    );

    // 10. Submit response based on response_mode
    match response_mode {
        ResponseMode::DirectPost => {
            submit_direct_post(&state, response_uri, vp_token_map, state_to_echo).await
        }
        ResponseMode::DirectPostJwt => {
            submit_direct_post_jwt(
                &state,
                &request_object,
                response_uri,
                vp_token_map,
                state_to_echo,
            )
            .await
        }
        other => {
            error!(?other, "Unsupported response mode");
            error_response(
                StatusCode::BAD_REQUEST,
                "unsupported_response_mode",
                &format!("Response mode {:?} is not supported", other),
                params.state.as_deref(),
            )
        }
    }
}

/// Build the request URL from parameters
fn build_request_url(state: &AppState, params: &AuthorizationParams) -> anyhow::Result<url::Url> {
    let mut url = state.config.authorization_endpoint.clone();

    {
        let mut query = url.query_pairs_mut();

        if let Some(ref client_id) = params.client_id {
            query.append_pair("client_id", client_id);
        }
        if let Some(ref request) = params.request {
            query.append_pair("request", request);
        }
        if let Some(ref request_uri) = params.request_uri {
            query.append_pair("request_uri", request_uri);
        }
        if let Some(ref response_type) = params.response_type {
            query.append_pair("response_type", response_type);
        }
        if let Some(ref nonce) = params.nonce {
            query.append_pair("nonce", nonce);
        }
        if let Some(ref state_val) = params.state {
            query.append_pair("state", state_val);
        }
        if let Some(ref response_mode) = params.response_mode {
            query.append_pair("response_mode", response_mode);
        }
        if let Some(ref response_uri) = params.response_uri {
            query.append_pair("response_uri", response_uri);
        }
        if let Some(ref dcql) = params.dcql_query {
            query.append_pair("dcql_query", dcql);
        }
    }

    Ok(url)
}

/// Submit response via direct_post
async fn submit_direct_post(
    _state: &AppState,
    response_uri: &url::Url,
    vp_token: VpToken,
    original_state: Option<String>,
) -> Response {
    let auth_response = match original_state {
        Some(ref state_val) => {
            UnencodedAuthorizationResponse::with_state(vp_token, RequestState(state_val.clone()))
        }
        None => UnencodedAuthorizationResponse::new(vp_token),
    };

    let body = match auth_response.into_x_www_form_urlencoded() {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to encode authorization response: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "encoding_error",
                &e.to_string(),
                original_state.as_deref(),
            );
        }
    };

    debug!(%response_uri, body_len = body.len(), "Submitting direct_post response");

    // POST to response_uri
    let client = reqwest::Client::new();
    match client
        .post(response_uri.as_str())
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            info!(?status, "Verifier response received");

            if status.is_success() {
                // Check for redirect_uri in response
                if let Ok(body) = resp.text().await {
                    if let Ok(json) = serde_json::from_str::<Value>(&body) {
                        if let Some(redirect) = json.get("redirect_uri").and_then(|v| v.as_str()) {
                            info!(%redirect, "Verifier returned redirect_uri, following redirect");

                            // Follow the redirect_uri as required by OID4VP spec
                            // This completes the flow for scenarios with redirect
                            let redirect_client = reqwest::Client::new();
                            match redirect_client.get(redirect).send().await {
                                Ok(redirect_resp) => {
                                    let redirect_status = redirect_resp.status();
                                    info!(?redirect_status, "Redirect response received");
                                }
                                Err(e) => {
                                    warn!("Failed to follow redirect_uri: {}", e);
                                }
                            }

                            return Json(SuccessResponse {
                                redirect_uri: Some(redirect.to_string()),
                            })
                            .into_response();
                        }
                    }
                }

                Json(SuccessResponse { redirect_uri: None }).into_response()
            } else {
                let error_body = resp.text().await.unwrap_or_default();
                warn!(?status, error_body, "Verifier returned error");
                error_response(
                    StatusCode::BAD_GATEWAY,
                    "verifier_error",
                    &format!("Verifier returned {}: {}", status, error_body),
                    original_state.as_deref(),
                )
            }
        }
        Err(e) => {
            error!("Failed to submit response: {}", e);
            error_response(
                StatusCode::BAD_GATEWAY,
                "submission_failed",
                &e.to_string(),
                original_state.as_deref(),
            )
        }
    }
}

/// Submit response via direct_post.jwt (encrypted JWE)
async fn submit_direct_post_jwt(
    _state: &AppState,
    request_object: &AuthorizationRequestObject,
    response_uri: &url::Url,
    vp_token: VpToken,
    original_state: Option<String>,
) -> Response {
    // Build the payload to encrypt
    let mut payload = json!({
        "vp_token": vp_token,
    });

    if let Some(ref state_val) = original_state {
        payload["state"] = Value::String(state_val.clone());
    }

    // Get verifier's public key from client_metadata
    let jwk_info = match get_verifier_encryption_key(request_object) {
        Ok(info) => info,
        Err(e) => {
            error!("Failed to get verifier encryption key: {}", e);
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                &format!("Missing encryption key: {}", e),
                original_state.as_deref(),
            );
        }
    };

    // Convert JWK to JSON Value for the builder
    let verifier_jwk: Value = match serde_json::to_value(&jwk_info.jwk) {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to serialize JWK: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "encryption_error",
                &e.to_string(),
                original_state.as_deref(),
            );
        }
    };

    // Build JWE per OID4VP v1.0 §8.3 (alg from JWK, enc default A128GCM)
    let mut builder = JweBuilder::new().payload(payload).alg(&jwk_info.alg);

    if let Some(ref kid) = jwk_info.kid {
        builder = builder.kid(kid);
    }

    let jwe = match builder
        .recipient_key_json(&verifier_jwk)
        .and_then(|b| b.build())
    {
        Ok(jwe) => jwe,
        Err(e) => {
            error!("JWE encryption failed: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "encryption_error",
                &e.to_string(),
                original_state.as_deref(),
            );
        }
    };

    debug!(%response_uri, jwe_len = jwe.len(), "Submitting direct_post.jwt response");

    // Submit as form with `response` parameter
    let body = serde_urlencoded::to_string([("response", &jwe)]).unwrap_or_default();

    let client = reqwest::Client::new();
    match client
        .post(response_uri.as_str())
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            info!(?status, "Verifier response received (JWE)");

            if status.is_success() {
                // Check for redirect_uri in response
                if let Ok(body) = resp.text().await {
                    if let Ok(json) = serde_json::from_str::<Value>(&body) {
                        if let Some(redirect) = json.get("redirect_uri").and_then(|v| v.as_str()) {
                            info!(%redirect, "Verifier returned redirect_uri, following redirect");

                            // Follow the redirect_uri as required by OID4VP spec
                            let redirect_client = reqwest::Client::new();
                            match redirect_client.get(redirect).send().await {
                                Ok(redirect_resp) => {
                                    let redirect_status = redirect_resp.status();
                                    info!(?redirect_status, "Redirect response received");
                                }
                                Err(e) => {
                                    warn!("Failed to follow redirect_uri: {}", e);
                                }
                            }

                            return Json(SuccessResponse {
                                redirect_uri: Some(redirect.to_string()),
                            })
                            .into_response();
                        }
                    }
                }

                Json(SuccessResponse { redirect_uri: None }).into_response()
            } else {
                let error_body = resp.text().await.unwrap_or_default();
                warn!(?status, error_body, "Verifier returned error");
                error_response(
                    StatusCode::BAD_GATEWAY,
                    "verifier_error",
                    &format!("Verifier returned {}: {}", status, error_body),
                    original_state.as_deref(),
                )
            }
        }
        Err(e) => {
            error!("Failed to submit JWE response: {}", e);
            error_response(
                StatusCode::BAD_GATEWAY,
                "submission_failed",
                &e.to_string(),
                original_state.as_deref(),
            )
        }
    }
}

/// Get verifier's encryption key from client_metadata
fn get_verifier_encryption_key(
    request: &AuthorizationRequestObject,
) -> anyhow::Result<EncryptionJwkInfo> {
    let client_metadata = request.client_metadata().parsing_error()?;
    let jwks = client_metadata.jwks().parsing_error()?;
    let keys: Vec<_> = jwks.keys.iter().collect();

    find_encryption_jwk(keys.into_iter())
}

/// Create an error response
fn error_response(
    status: StatusCode,
    error: &str,
    description: &str,
    state: Option<&str>,
) -> Response {
    let body = ErrorResponse {
        error: error.to_string(),
        error_description: description.to_string(),
        state: state.map(String::from),
    };

    (status, Json(body)).into_response()
}
