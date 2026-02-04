use std::{
    fmt::Debug,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::prelude::*;
use clap::Parser;
use openid4vp::{
    core::{
        authorization_request::{
            parameters::{
                ClientId, ClientIdScheme, ClientMetadata, Nonce, ResponseMode, ResponseType,
            },
            AuthorizationRequestObject,
        },
        credential_format::{ClaimFormatDesignation, ClaimFormatMap, ClaimFormatPayload},
        dcql_query::{
            DcqlCredentialClaimsQuery, DcqlCredentialClaimsQueryPath, DcqlCredentialQuery,
            DcqlCredentialSetQuery, DcqlQuery,
        },
        metadata::{
            parameters::wallet::{
                AuthorizationEndpoint, ClientIdPrefixesSupported, VpFormatsSupported,
            },
            WalletMetadata,
        },
        object::UntypedObject,
        response::AuthorizationResponse,
    },
    utils::NonEmptyVec,
    verifier::{
        client::Client,
        session::{MemoryStore, Outcome},
        Verifier,
    },
};
use qrcode::{render::unicode, QrCode};
use serde_json::json;
use tokio::{net::TcpListener, signal};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use url::Url;
use uuid::Uuid;

// ============================================================================
// CLI Arguments
// ============================================================================

#[derive(Parser, Debug)]
#[command(name = "cli-verifier")]
#[command(about = "Minimal CLI Verifier for OID4VP v1.0 protocol testing")]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value = "3000")]
    port: u16,

    /// Public URL where this server is accessible (e.g., https://abc123.ngrok.io)
    #[arg(long)]
    public_url: Url,

    /// Credential types to request (comma-separated): mdl, ldp_vc, jwt_vc, vcdm2_sd_jwt, ldp_or_mdl
    /// Use ldp_or_mdl to accept either ldp_vc OR mso_mdoc (wallet chooses)
    /// Example: --credential mdl,vcdm2_sd_jwt
    #[arg(short, long, default_value = "mdl", value_delimiter = ',')]
    credential: Vec<String>,

    /// Disable QR code display (just show URL)
    #[arg(long, default_value = "false")]
    no_qr: bool,
}

// ============================================================================
// RedirectUriClient - Implementation of Client for redirect_uri scheme
// ============================================================================

/// A Client with the `redirect_uri` Client Identifier Prefix.
///
/// Per OID4VP v1.0 Section 5.9.3, requests using this scheme cannot be signed.
/// The client_id is the redirect URI with the "redirect_uri:" prefix.
///
/// This is the simplest client_id_scheme, requiring no certificates or DIDs.
#[derive(Debug, Clone)]
pub struct RedirectUriClient {
    id: ClientId,
}

impl RedirectUriClient {
    pub fn new(response_uri: Url) -> Self {
        // Per OID4VP v1.0 Section 5.9.3:
        // client_id = "redirect_uri:<response_uri>"
        let prefixed_id = format!("{}:{}", ClientIdScheme::REDIRECT_URI, response_uri);
        Self {
            id: ClientId(prefixed_id),
        }
    }
}

#[async_trait]
impl Client for RedirectUriClient {
    fn id(&self) -> &ClientId {
        &self.id
    }

    fn prefix(&self) -> ClientIdScheme {
        ClientIdScheme(ClientIdScheme::REDIRECT_URI.to_string())
    }

    async fn generate_request_object_jwt(
        &self,
        body: &AuthorizationRequestObject,
    ) -> Result<String> {
        // Per OID4VP v1.0 Section 5.9.3, redirect_uri scheme requests
        // cannot be signed. We create an unsigned JWT (alg: "none").
        let header = json!({
            "alg": "none",
            "typ": "oauth-authz-req+jwt"
        });

        let header_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let body_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(body)?);

        // Unsigned JWT has empty signature
        Ok(format!("{}.{}.", header_b64, body_b64))
    }
}

// ============================================================================
// Application State
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
enum DisplayStatus {
    Initializing,
    WaitingForWallet,
    RequestFetched,
    ResponseReceived,
    Success(serde_json::Value),
    Failed(String),
}

struct AppState {
    verifier: Verifier,
    session_id: Mutex<Option<Uuid>>,
    display_status: Mutex<DisplayStatus>,
    completion_notify: tokio::sync::Notify,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("session_id", &self.session_id)
            .field("display_status", &self.display_status)
            .finish()
    }
}

impl AppState {
    fn update_status(&self, status: DisplayStatus) {
        *self.display_status.lock().unwrap() = status;
    }

    fn get_status(&self) -> DisplayStatus {
        self.display_status.lock().unwrap().clone()
    }

    fn set_session_id(&self, id: Uuid) {
        *self.session_id.lock().unwrap() = Some(id);
    }

    fn notify_complete(&self) {
        self.completion_notify.notify_one();
    }

    async fn wait_for_completion(&self) {
        self.completion_notify.notified().await;
    }
}

// ============================================================================
// HTTP Handlers
// ============================================================================

/// GET /request/{session_id} - Wallet fetches the authorization request JWT
async fn get_request_object(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> Result<Response, AppError> {
    let uuid: Uuid = session_id.parse().context("Invalid session ID")?;

    info!("Wallet fetching request for session {}", uuid);

    let jwt = state
        .verifier
        .retrieve_authorization_request(uuid)
        .await
        .context("Failed to retrieve authorization request")?;

    state.update_status(DisplayStatus::RequestFetched);
    print_status_update(&state.get_status());

    Ok((
        StatusCode::OK,
        [("content-type", "application/oauth-authz-req+jwt")],
        jwt,
    )
        .into_response())
}

/// POST /response/{session_id} - Wallet submits the VP token
async fn receive_response(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    body: String,
) -> Result<Json<serde_json::Value>, AppError> {
    let uuid: Uuid = session_id.parse().context("Invalid session ID")?;

    info!("Received response for session {}", uuid);
    state.update_status(DisplayStatus::ResponseReceived);
    print_status_update(&state.get_status());

    let auth_response = AuthorizationResponse::from_x_www_form_urlencoded(body.as_bytes())
        .context("Failed to parse authorization response")?;

    let state_clone = state.clone();
    state
        .verifier
        .verify_response(uuid, auth_response, move |_session, response| {
            Box::pin(async move {
                match &response {
                    AuthorizationResponse::Unencoded(unencoded) => {
                        let vp_token = &unencoded.vp_token;
                        let credential_ids: Vec<&String> = vp_token.0.keys().collect();

                        let info = json!({
                            "credentials_received": vp_token.0.len(),
                            "credential_query_ids": credential_ids,
                        });

                        state_clone.update_status(DisplayStatus::Success(info.clone()));
                        print_status_update(&state_clone.get_status());
                        state_clone.notify_complete();

                        Outcome::Success { info }
                    }
                    AuthorizationResponse::Jwt(_) => {
                        let reason =
                            "Encrypted responses (direct_post.jwt) not supported in this example"
                                .to_string();
                        state_clone.update_status(DisplayStatus::Failed(reason.clone()));
                        print_status_update(&state_clone.get_status());
                        state_clone.notify_complete();

                        Outcome::Failure { reason }
                    }
                }
            })
        })
        .await
        .context("Failed to verify response")?;

    Ok(Json(json!({})))
}

// ============================================================================
// Error Handling
// ============================================================================

struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        warn!("Request error: {:?}", self.0);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Error: {}", self.0),
        )
            .into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

// ============================================================================
// Router Setup
// ============================================================================

fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/request/:session_id", get(get_request_object))
        .route("/response/:session_id", post(receive_response))
        .with_state(state)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
}

// ============================================================================
// DCQL Query Builder
// ============================================================================

/// Build a credential query for LDP VC
fn build_ldp_vc_credential_query() -> DcqlCredentialQuery {
    DcqlCredentialQuery::new("ldp_vc_0".to_string(), ClaimFormatDesignation::LdpVc)
    // No specific claims - accepts any claims from the credential
}

/// Build a credential query for JWT VC
fn build_jwt_vc_credential_query() -> DcqlCredentialQuery {
    DcqlCredentialQuery::new("jwt_vc_0".to_string(), ClaimFormatDesignation::JwtVcJson)
    // No specific claims - accepts any claims from the credential
}

/// Build a credential query for VCDM2 SD-JWT
///
/// VCDM2SdJwt is a W3C VCDM v2 credential using SD-JWT encoding.
/// This is NOT the same as IETF dc+sd-jwt which has a different payload structure.
/// We use a custom format identifier "vcdm2_sd_jwt" to distinguish it.
fn build_vcdm2_sd_jwt_credential_query() -> DcqlCredentialQuery {
    DcqlCredentialQuery::new(
        "vcdm2_sd_jwt_0".to_string(),
        ClaimFormatDesignation::Other("vcdm2_sd_jwt".to_string()),
    )
    // No specific claims - accepts any claims from the credential
}

/// Build a credential query for mDL
fn build_mdl_credential_query() -> DcqlCredentialQuery {
    let mut credential_query =
        DcqlCredentialQuery::new("mdl_0".to_string(), ClaimFormatDesignation::MsoMDoc);

    // Set meta with doctype_value for mDL
    let mut meta = serde_json::Map::new();
    meta.insert(
        "doctype_value".to_string(),
        serde_json::json!("org.iso.18013.5.1.mDL"),
    );
    credential_query.set_meta(meta);

    // Request specific claims: given_name and family_name
    let namespace = "org.iso.18013.5.1";
    let claims = NonEmptyVec::try_from(vec![
        DcqlCredentialClaimsQuery::new(
            NonEmptyVec::try_from(vec![
                DcqlCredentialClaimsQueryPath::String(namespace.to_string()),
                DcqlCredentialClaimsQueryPath::String("given_name".to_string()),
            ])
            .unwrap(),
        ),
        DcqlCredentialClaimsQuery::new(
            NonEmptyVec::try_from(vec![
                DcqlCredentialClaimsQueryPath::String(namespace.to_string()),
                DcqlCredentialClaimsQueryPath::String("family_name".to_string()),
            ])
            .unwrap(),
        ),
    ])
    .unwrap();
    credential_query.set_claims(Some(claims));

    credential_query
}

/// Build a DCQL query for multiple credential types
///
/// Per OID4VP v1.0 Section 6.2, when credential_sets is present, ALL credentials
/// in the credentials array MUST be covered by at least one credential_set option.
///
/// This function creates separate credential_sets for:
/// - OR types (like ldp_or_mdl): one credential_set with multiple options
/// - Individual types: one credential_set with a single option (required)
fn build_dcql_query_for_types(types: &[String]) -> Result<(DcqlQuery, String)> {
    let mut queries = Vec::new();
    let mut descriptions = Vec::new();
    // Each entry is a credential_set: Vec of options, where each option is Vec of credential IDs
    let mut credential_sets: Vec<Vec<Vec<String>>> = Vec::new();

    for cred_type in types {
        match cred_type.as_str() {
            "mdl" => {
                queries.push(build_mdl_credential_query());
                descriptions.push("mDL");
                // Single credential_set with single option = required
                credential_sets.push(vec![vec!["mdl_0".to_string()]]);
            }
            "ldp_vc" => {
                queries.push(build_ldp_vc_credential_query());
                descriptions.push("LDP VC");
                credential_sets.push(vec![vec!["ldp_vc_0".to_string()]]);
            }
            "jwt_vc" => {
                queries.push(build_jwt_vc_credential_query());
                descriptions.push("JWT VC");
                credential_sets.push(vec![vec!["jwt_vc_0".to_string()]]);
            }
            "vcdm2_sd_jwt" => {
                queries.push(build_vcdm2_sd_jwt_credential_query());
                descriptions.push("VCDM2 SD-JWT");
                credential_sets.push(vec![vec!["vcdm2_sd_jwt_0".to_string()]]);
            }
            "ldp_or_mdl" => {
                // Add both credential queries
                queries.push(build_ldp_vc_credential_query());
                queries.push(build_mdl_credential_query());
                descriptions.push("(LDP VC OR mDL)");
                // One credential_set with two options = OR logic
                credential_sets.push(vec![
                    vec!["ldp_vc_0".to_string()], // Option 1: ldp_vc
                    vec!["mdl_0".to_string()],    // Option 2: mDL
                ]);
            }
            other => {
                anyhow::bail!("Unknown credential type: {}. Available: mdl, ldp_vc, jwt_vc, vcdm2_sd_jwt, ldp_or_mdl", other);
            }
        }
    }

    if queries.is_empty() {
        anyhow::bail!("At least one credential type must be specified");
    }

    let mut dcql_query =
        DcqlQuery::new(NonEmptyVec::try_from(queries).expect("At least one credential query"));

    // Only use credential_sets if we have more than one type OR if any type uses OR logic
    // Per spec, when credential_sets is present, ALL credentials must be covered
    if !credential_sets.is_empty() {
        let sets: Vec<DcqlCredentialSetQuery> = credential_sets
            .into_iter()
            .map(|options| {
                DcqlCredentialSetQuery::new(
                    NonEmptyVec::try_from(options).expect("At least one option"),
                )
            })
            .collect();

        dcql_query.set_credential_sets(Some(
            NonEmptyVec::try_from(sets).expect("At least one credential set"),
        ));
    }

    Ok((dcql_query, descriptions.join(" + ")))
}

// ============================================================================
// Client Metadata (Verifier Metadata for the request)
// ============================================================================

/// Build client metadata with vp_formats_supported.
///
/// Per OID4VP v1.0 Section 5.1, `vp_formats_supported` is REQUIRED in client_metadata
/// when not available to the Wallet via another mechanism. Since we use `redirect_uri`
/// client_id_scheme, the wallet has no other way to obtain this information.
fn build_client_metadata(credential_types: &[String]) -> ClientMetadata {
    let mut vp_formats = ClaimFormatMap::new();

    for cred_type in credential_types {
        match cred_type.as_str() {
            "mdl" => {
                // For mso_mdoc, we accept any algorithm (empty object)
                vp_formats.insert(
                    ClaimFormatDesignation::MsoMDoc,
                    ClaimFormatPayload::Other(serde_json::json!({})),
                );
            }
            "ldp_vc" => {
                // Per OID4VP v1.0 Section B.1.3.2.1:
                // "The Credential Format Identifier is `ldp_vc` to request a W3C Verifiable
                // Credential... or a Verifiable Presentation of such a Credential."
                vp_formats.insert(
                    ClaimFormatDesignation::LdpVc,
                    ClaimFormatPayload::ProofTypeValues(vec![
                        "Ed25519Signature2018".to_string(),
                        "Ed25519Signature2020".to_string(),
                        "JsonWebSignature2020".to_string(),
                        "DataIntegrityProof".to_string(),
                        // ECDSA Data Integrity cryptosuites
                        "ecdsa-rdfc-2019".to_string(),
                        "ecdsa-sd-2023".to_string(),
                        "ecdsa-jcs-2019".to_string(),
                    ]),
                );
            }
            "jwt_vc" => {
                // Per OID4VP v1.0 Section B.1.3.1.1:
                // "The Credential Format Identifier is `jwt_vc_json` to request a W3C Verifiable
                // Credential... or a Verifiable Presentation of such a Credential."
                vp_formats.insert(
                    ClaimFormatDesignation::JwtVcJson,
                    ClaimFormatPayload::AlgValues(vec![
                        "ES256".to_string(),
                        "ES384".to_string(),
                        "ES512".to_string(),
                        "EdDSA".to_string(),
                    ]),
                );
            }
            "vcdm2_sd_jwt" => {
                // VCDM2SdJwt is a custom format (W3C VCDM v2 with SD-JWT encoding)
                // Not a standard OID4VP v1.0 format, so we use Other("vcdm2_sd_jwt")
                vp_formats.insert(
                    ClaimFormatDesignation::Other("vcdm2_sd_jwt".to_string()),
                    ClaimFormatPayload::Other(serde_json::json!({
                        "alg_values": ["ES256", "ES384", "EdDSA"]
                    })),
                );
            }
            "ldp_or_mdl" => {
                // Support both formats - wallet chooses which to present
                vp_formats.insert(
                    ClaimFormatDesignation::MsoMDoc,
                    ClaimFormatPayload::Other(serde_json::json!({})),
                );
                vp_formats.insert(
                    ClaimFormatDesignation::LdpVc,
                    ClaimFormatPayload::ProofTypeValues(vec![
                        "Ed25519Signature2018".to_string(),
                        "Ed25519Signature2020".to_string(),
                        "JsonWebSignature2020".to_string(),
                        "DataIntegrityProof".to_string(),
                        "ecdsa-rdfc-2019".to_string(),
                        "ecdsa-sd-2023".to_string(),
                        "ecdsa-jcs-2019".to_string(),
                    ]),
                );
            }
            _ => {}
        }
    }

    let mut inner = UntypedObject::default();
    inner.insert(VpFormatsSupported(vp_formats));

    ClientMetadata(inner)
}

// ============================================================================
// Wallet Metadata
// ============================================================================

/// Create wallet metadata that supports redirect_uri scheme
fn create_wallet_metadata() -> Result<WalletMetadata> {
    // Use openid4vp:// as the authorization endpoint (standard for mobile wallets)
    let authorization_endpoint: Url = "openid4vp://".parse()?;

    // Support multiple credential formats
    let mut vp_formats = ClaimFormatMap::new();
    vp_formats.insert(
        ClaimFormatDesignation::MsoMDoc,
        ClaimFormatPayload::Other(serde_json::json!({})),
    );
    vp_formats.insert(
        ClaimFormatDesignation::LdpVc,
        ClaimFormatPayload::ProofTypeValues(vec![
            "Ed25519Signature2018".to_string(),
            "Ed25519Signature2020".to_string(),
            "JsonWebSignature2020".to_string(),
        ]),
    );
    vp_formats.insert(
        ClaimFormatDesignation::JwtVcJson,
        ClaimFormatPayload::AlgValues(vec![
            "ES256".to_string(),
            "ES384".to_string(),
            "EdDSA".to_string(),
        ]),
    );
    // VCDM2SdJwt - custom format for W3C VCDM v2 with SD-JWT encoding
    vp_formats.insert(
        ClaimFormatDesignation::Other("vcdm2_sd_jwt".to_string()),
        ClaimFormatPayload::Other(serde_json::json!({
            "alg_values": ["ES256", "ES384", "EdDSA"]
        })),
    );

    let mut metadata = WalletMetadata::new(
        AuthorizationEndpoint(authorization_endpoint),
        VpFormatsSupported(vp_formats),
        None,
    );

    // Support redirect_uri client_id prefix
    metadata.insert(ClientIdPrefixesSupported(vec![ClientIdScheme(
        ClientIdScheme::REDIRECT_URI.to_string(),
    )]));

    Ok(metadata)
}

// ============================================================================
// Display Functions
// ============================================================================

fn print_banner() {
    println!();
    println!("========================================");
    println!("   OID4VP CLI Verifier - Protocol Test");
    println!("========================================");
    println!();
}

fn display_qr_code(url: &str) {
    let code = match QrCode::new(url) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to generate QR code: {}", e);
            return;
        }
    };

    let image = code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .quiet_zone(true)
        .build();

    println!("{}", image);
}

fn print_status_update(status: &DisplayStatus) {
    match status {
        DisplayStatus::Initializing => {
            println!("[*] Initializing...");
        }
        DisplayStatus::WaitingForWallet => {
            println!("[*] Status: WAITING FOR WALLET");
        }
        DisplayStatus::RequestFetched => {
            println!();
            println!("[*] Status: REQUEST FETCHED");
            println!("[*] Wallet retrieved the authorization request");
            println!("[*] Waiting for presentation submission...");
        }
        DisplayStatus::ResponseReceived => {
            println!();
            println!("[*] Status: PROCESSING RESPONSE");
            println!("[*] Verifying presentation...");
        }
        DisplayStatus::Success(info) => {
            println!();
            println!("========================================");
            println!("[+] Status: SUCCESS");
            println!("========================================");
            println!();
            println!("Verification completed successfully!");
            println!();
            println!("{}", serde_json::to_string_pretty(info).unwrap_or_default());
            println!();
        }
        DisplayStatus::Failed(reason) => {
            println!();
            println!("========================================");
            println!("[-] Status: FAILED");
            println!("========================================");
            println!();
            println!("Verification failed: {}", reason);
            println!();
        }
    }
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("cli_verifier=info".parse()?))
        .init();

    let args = Args::parse();

    print_banner();
    println!("[*] Initializing verifier...");
    println!("[*] Public URL: {}", args.public_url);
    println!("[*] Listening on port: {}", args.port);
    println!("[*] Credential types: {}", args.credential.join(", "));
    println!();

    // Build URLs
    let mut response_uri = args.public_url.clone();
    response_uri.set_path("/response");

    let mut request_uri_base = args.public_url.clone();
    request_uri_base.set_path("/request");

    // Create the redirect_uri client
    let client = Arc::new(RedirectUriClient::new(response_uri.clone()));

    // Create session store
    let session_store = Arc::new(MemoryStore::default());

    // Build the verifier
    let verifier = Verifier::builder()
        .with_client(client)
        .with_session_store(session_store)
        .with_submission_endpoint(response_uri)
        .by_reference(request_uri_base)
        .with_default_request_parameter(ResponseType::VpToken)
        .with_default_request_parameter(ResponseMode::DirectPost)
        .build()
        .await
        .context("Failed to build verifier")?;

    // Create wallet metadata
    let wallet_metadata = create_wallet_metadata()?;

    // Create app state
    let state = Arc::new(AppState {
        verifier,
        session_id: Mutex::new(None),
        display_status: Mutex::new(DisplayStatus::Initializing),
        completion_notify: tokio::sync::Notify::new(),
    });

    // Build DCQL query based on credential types
    let (dcql_query, credential_desc) = build_dcql_query_for_types(&args.credential)?;

    // Build client metadata with vp_formats_supported
    // Required per OID4VP v1.0 Section 5.1 when using redirect_uri scheme
    let client_metadata = build_client_metadata(&args.credential);

    // Build authorization request
    let (session_id, auth_url) = state
        .verifier
        .build_authorization_request()
        .with_dcql_query(dcql_query)
        .with_request_parameter(Nonce::from(Uuid::new_v4().to_string()))
        .with_request_parameter(client_metadata)
        .build(wallet_metadata)
        .await
        .context("Failed to build authorization request")?;

    state.set_session_id(session_id);
    state.update_status(DisplayStatus::WaitingForWallet);

    // Display information
    println!("[*] Session ID: {}", session_id);
    println!("[*] Requesting: {}", credential_desc);
    println!();

    if !args.no_qr {
        println!("Scan this QR code with your wallet app:");
        println!();
        display_qr_code(auth_url.as_str());
    }

    println!("Authorization URL:");
    println!("{}", auth_url);
    println!();
    println!("----------------------------------------");
    print_status_update(&state.get_status());

    // Start HTTP server
    let app = create_router(state.clone());
    let addr = format!("0.0.0.0:{}", args.port);
    let listener = TcpListener::bind(&addr)
        .await
        .context("Failed to bind to address")?;

    info!("Server listening on {}", addr);

    // Run server and wait for completion or Ctrl+C
    tokio::select! {
        result = axum::serve(listener, app) => {
            if let Err(e) = result {
                warn!("Server error: {}", e);
            }
        }
        _ = state.wait_for_completion() => {
            println!();
            println!("[*] Verification complete. Shutting down...");
        }
        _ = signal::ctrl_c() => {
            println!();
            println!("[*] Interrupted. Shutting down...");
        }
    }

    Ok(())
}
