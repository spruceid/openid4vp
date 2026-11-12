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
        response::{parameters::VpTokenItem, AuthorizationResponse},
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

    /// W3C VC type the ldp_* DCQL cases ask for
    #[arg(long, default_value = "VehicleRegistrationCredential")]
    vc_type: String,

    /// W3C VC type the jwt_vc_* DCQL cases ask for
    #[arg(long, default_value = "Iso18013DriversLicenseCredential")]
    jwt_vc_type: String,

    /// Serve every DCQL test case at once, with a QR page at the public URL
    #[arg(long, default_value = "false")]
    all: bool,

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
    WaitingForWallet,
    RequestFetched,
    ResponseReceived,
    Success(serde_json::Value),
    Failed(String),
}

#[derive(Debug, Clone)]
struct CaseSession {
    case: String,
    session_id: Uuid,
    auth_url: Url,
    dcql_query: serde_json::Value,
    status: DisplayStatus,
}

struct AppState {
    verifier: Verifier,
    vc_type: String,
    jwt_vc_type: String,
    serve_all: bool,
    sessions: Mutex<Vec<CaseSession>>,
    completion_notify: tokio::sync::Notify,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("sessions", &self.sessions)
            .finish()
    }
}

impl AppState {
    fn update_status(&self, session_id: Uuid, status: DisplayStatus) {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.iter_mut().find(|s| s.session_id == session_id) {
            println!("[{}]", session.case);
            print_status_update(&status);
            session.status = status;
        }
    }

    fn notify_complete(&self) {
        if !self.serve_all {
            self.completion_notify.notify_one();
        }
    }

    async fn start_session(&self, case: &str) -> Result<CaseSession> {
        let types: Vec<String> = case.split('+').map(str::to_owned).collect();
        let (dcql_query, _) = build_dcql_query_for_types(&types, &self.vc_type, &self.jwt_vc_type)?;
        let dcql_query_json = serde_json::to_value(&dcql_query)?;
        let (session_id, auth_url) = self
            .verifier
            .build_authorization_request()
            .with_dcql_query(dcql_query)
            .with_request_parameter(Nonce::from(Uuid::new_v4().to_string()))
            .with_request_parameter(build_client_metadata(&types))
            .build(create_wallet_metadata()?)
            .await
            .context("Failed to build authorization request")?;

        let session = CaseSession {
            case: case.to_owned(),
            session_id,
            auth_url,
            dcql_query: dcql_query_json,
            status: DisplayStatus::WaitingForWallet,
        };
        let mut sessions = self.sessions.lock().unwrap();
        match sessions.iter_mut().find(|s| s.case == case) {
            Some(existing) => *existing = session.clone(),
            None => sessions.push(session.clone()),
        }
        Ok(session)
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

    state.update_status(uuid, DisplayStatus::RequestFetched);

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
    state.update_status(uuid, DisplayStatus::ResponseReceived);

    let form: std::collections::HashMap<String, String> =
        url::form_urlencoded::parse(body.as_bytes()).into_owned().collect();
    if let Some(error) = form.get("error") {
        warn!("Wallet returned error {error} for session {uuid}");
        state.update_status(
            uuid,
            DisplayStatus::Failed(format!(
                "Wallet declined: error={error}, state={}",
                form.get("state").map(String::as_str).unwrap_or("<none>")
            )),
        );
        return Ok(Json(json!({})));
    }

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

                        let presented: serde_json::Map<_, _> = vp_token
                            .0
                            .iter()
                            .map(|(id, items)| {
                                (id.clone(), items.iter().map(decode_vp_token_item).collect())
                            })
                            .collect();

                        let presentations_per_query: serde_json::Map<_, _> = vp_token
                            .0
                            .iter()
                            .map(|(id, items)| (id.clone(), json!(items.len())))
                            .collect();

                        let info = json!({
                            "credentials_received": vp_token.0.len(),
                            "credential_query_ids": credential_ids,
                            "presentations_per_query": presentations_per_query,
                            "presented": presented,
                        });

                        state_clone.update_status(uuid, DisplayStatus::Success(info.clone()));
                        state_clone.notify_complete();

                        Outcome::Success { info }
                    }
                    AuthorizationResponse::Jwt(_) => {
                        let reason =
                            "Encrypted responses (direct_post.jwt) not supported in this example"
                                .to_string();
                        state_clone.update_status(uuid, DisplayStatus::Failed(reason.clone()));
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
// Presentation Decoding
// ============================================================================

fn decode_jwt_payload(jwt: &str) -> Option<serde_json::Value> {
    let payload = jwt.split('.').nth(1)?;
    let bytes = BASE64_URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn decode_jwt(jwt: &str) -> serde_json::Value {
    let Some(mut payload) = decode_jwt_payload(jwt) else {
        return json!({ "undecodable_jwt": jwt });
    };
    if let Some(credentials) = payload
        .pointer_mut("/vp/verifiableCredential")
        .and_then(|vcs| vcs.as_array_mut())
    {
        for credential in credentials {
            if let Some(decoded) = credential.as_str().and_then(decode_jwt_payload) {
                *credential = decoded;
            }
        }
    }
    payload
}

fn decode_sd_jwt(sd_jwt: &str) -> serde_json::Value {
    let parts: Vec<&str> = sd_jwt.split('~').collect();
    let disclosures: Vec<serde_json::Value> = parts[1..parts.len().saturating_sub(1)]
        .iter()
        .filter_map(|disclosure| {
            let bytes = BASE64_URL_SAFE_NO_PAD.decode(disclosure).ok()?;
            serde_json::from_slice(&bytes).ok()
        })
        .collect();
    json!({
        "issuer_jwt": parts.first().map(|jwt| decode_jwt(jwt)),
        "disclosures": disclosures,
        "kb_jwt": parts.last().filter(|last| !last.is_empty()).map(|jwt| decode_jwt(jwt)),
    })
}

fn cbor_to_json(value: &ciborium::Value) -> serde_json::Value {
    use ciborium::Value as Cbor;
    match value {
        Cbor::Text(text) => json!(text),
        Cbor::Bool(b) => json!(b),
        Cbor::Null => serde_json::Value::Null,
        Cbor::Integer(i) => json!(i128::from(*i)),
        Cbor::Float(f) => json!(f),
        Cbor::Bytes(bytes) => json!(format!("<{} bytes>", bytes.len())),
        Cbor::Array(items) => items.iter().map(cbor_to_json).collect(),
        Cbor::Map(entries) => entries
            .iter()
            .map(|(k, v)| {
                let key = k
                    .as_text()
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| cbor_to_json(k).to_string());
                (key, cbor_to_json(v))
            })
            .collect::<serde_json::Map<_, _>>()
            .into(),
        Cbor::Tag(24, inner) => inner
            .as_bytes()
            .and_then(|bytes| ciborium::from_reader::<Cbor, _>(bytes.as_slice()).ok())
            .map(|decoded| cbor_to_json(&decoded))
            .unwrap_or_else(|| cbor_to_json(inner)),
        Cbor::Tag(_, inner) => cbor_to_json(inner),
        _ => json!(format!("{value:?}")),
    }
}

fn decode_mdoc(device_response: &str) -> serde_json::Value {
    let Some(response) = BASE64_URL_SAFE_NO_PAD
        .decode(device_response.trim_end_matches('='))
        .ok()
        .and_then(|bytes| ciborium::from_reader::<ciborium::Value, _>(bytes.as_slice()).ok())
    else {
        return json!({ "undecodable": device_response });
    };
    let response = cbor_to_json(&response);
    let documents: Vec<serde_json::Value> = response["documents"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|document| {
            let namespaces: serde_json::Map<_, _> = document["issuerSigned"]["nameSpaces"]
                .as_object()
                .into_iter()
                .flatten()
                .map(|(namespace, items)| {
                    let elements: serde_json::Map<_, _> = items
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|item| {
                            Some((
                                item["elementIdentifier"].as_str()?.to_owned(),
                                item["elementValue"].clone(),
                            ))
                        })
                        .collect();
                    (namespace.clone(), elements.into())
                })
                .collect();
            json!({ "docType": document["docType"], "nameSpaces": namespaces })
        })
        .collect();
    json!({ "documents": documents })
}

fn decode_vp_token_item(item: &VpTokenItem) -> serde_json::Value {
    match item {
        VpTokenItem::JsonObject(object) => serde_json::Value::Object(object.clone()),
        VpTokenItem::String(text) if text.contains('~') => decode_sd_jwt(text),
        VpTokenItem::String(text) if text.split('.').count() == 3 => decode_jwt(text),
        VpTokenItem::String(text) => decode_mdoc(text),
    }
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

const ALL_CASES: &[(&str, &str)] = &[
    (
        "jwt_vc_claim_values+ldp_claim_values+ldp_insurance_values",
        "CHP request: one DL, one --vc-type and one insurance, picked in the multi-credential sheet.",
    ),
    (
        "ldp_claim_values",
        "Only VCs of --vc-type are offered. One is sent.",
    ),
    (
        "ldp_type_values",
        "Only VCs of --vc-type are offered. One is sent.",
    ),
    (
        "ldp_claim_sets",
        "Only VCs of --vc-type are offered, through the second claim_sets option.",
    ),
    (
        "ldp_multiple",
        "Several VCs of --vc-type can be sent. Count can be above 1.",
    ),
    (
        "ldp_no_match",
        "No credential matches. The wallet errors and nothing is sent.",
    ),
    ("mdl_age_over_18", "The mDL matches if age_over_18 is true."),
    (
        "mdl_no_match",
        "No credential matches. The wallet errors and nothing is sent.",
    ),
    (
        "ldp_claim_sets_first",
        "Only VCs of --vc-type are offered, through the first claim_sets option.",
    ),
    (
        "ldp_claim_sets_no_claims",
        "claim_sets without claims can't be satisfied. Nothing matches.",
    ),
    (
        "ldp_claim_sets_unknown_id",
        "claim_sets names a claim id that doesn't exist. Nothing matches.",
    ),
    (
        "ldp_index_path",
        "Integer path index: type[0] is VerifiableCredential. Any LDP VC matches.",
    ),
    (
        "ldp_path_wrong_type",
        "Path selects a key from an array. Nothing matches.",
    ),
    (
        "ldp_type_values_iri",
        "type_values with the expanded VerifiableCredential IRI. Any LDP VC matches.",
    ),
    (
        "ldp_type_values_no_match",
        "type_values with a type nobody has. Nothing matches.",
    ),
    (
        "ldp_no_holder_binding",
        "require_cryptographic_holder_binding is false. A VC of --vc-type is sent.",
    ),
    (
        "jwt_vc_claim_values",
        "Only JWT VCs of --jwt-vc-type are offered. One is sent.",
    ),
    (
        "jwt_vc_type_values",
        "Only JWT VCs of --jwt-vc-type are offered. One is sent.",
    ),
    (
        "jwt_vc_no_match",
        "No JWT VC matches. The wallet errors and nothing is sent.",
    ),
    (
        "mdl_claim_sets",
        "The mDL matches through the second claim_sets option (given_name).",
    ),
    (
        "mdl_wrong_doctype",
        "doctype_value doesn't match the mDL. Nothing matches.",
    ),
    (
        "mdl_bad_path",
        "An mdoc path with three components is invalid. Nothing matches.",
    ),
    ("mdl", "The mDL with given_name and family_name."),
    ("mdl+jwt_vc", "Both an mDL and a JWT VC are required."),
    ("ldp_or_mdl", "Either an LDP VC or the mDL."),
];

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn status_label(status: &DisplayStatus) -> (&'static str, String) {
    match status {
        DisplayStatus::WaitingForWallet => ("waiting", "Waiting for wallet".to_owned()),
        DisplayStatus::RequestFetched => ("fetched", "Request fetched, no response yet".to_owned()),
        DisplayStatus::ResponseReceived => ("fetched", "Verifying response".to_owned()),
        DisplayStatus::Success(info) => (
            "success",
            serde_json::to_string_pretty(&info["presented"]).unwrap_or_default(),
        ),
        DisplayStatus::Failed(reason) => ("failed", reason.clone()),
    }
}

async fn index_page(State(state): State<Arc<AppState>>) -> axum::response::Html<String> {
    let sessions = state.sessions.lock().unwrap().clone();
    let cards: String = sessions
        .iter()
        .map(|session| {
            let expected = ALL_CASES
                .iter()
                .find(|(case, _)| *case == session.case)
                .map(|(_, expected)| {
                    expected
                        .replace("--jwt-vc-type", &state.jwt_vc_type)
                        .replace("--vc-type", &state.vc_type)
                })
                .unwrap_or_default();
            let qr = QrCode::new(session.auth_url.as_str())
                .map(|code| {
                    code.render::<qrcode::render::svg::Color>()
                        .min_dimensions(220, 220)
                        .build()
                })
                .unwrap_or_default();
            let (class, label) = status_label(&session.status);
            format!(
                r#"<section class="card {class}" data-case="{case}"><h2>{case}</h2><p class="expected">{expected}</p>{qr}
<p><a href="{url}">Open in wallet</a> &middot; <a href="/retry/{case}">New QR</a></p>
<pre class="status">{label}</pre>
<details><summary>DCQL query</summary><pre class="query">{query}</pre></details></section>"#,
                case = html_escape(&session.case),
                expected = html_escape(&expected),
                url = html_escape(session.auth_url.as_str()),
                label = html_escape(&label),
                query = html_escape(
                    &serde_json::to_string_pretty(&session.dcql_query).unwrap_or_default()
                ),
            )
        })
        .collect();

    axum::response::Html(format!(
        r#"<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>DCQL test cases</title>
<script>
const openKey = "open-queries";
const focusKey = "focused-case";
addEventListener("DOMContentLoaded", () => {{
  let open = [];
  try {{ open = JSON.parse(sessionStorage.getItem(openKey) || "[]"); }} catch (e) {{}}
  document.querySelectorAll("details").forEach((d, i) => {{ if (open.includes(i)) d.open = true; }});
  const focused = sessionStorage.getItem(focusKey);
  document.querySelectorAll(".card").forEach((card) => {{
    if (card.dataset.case === focused) setFocus(card);
    card.querySelector("svg")?.addEventListener("click", () =>
      setFocus(card.classList.contains("focus") ? null : card));
  }});
}});
addEventListener("keydown", (e) => {{ if (e.key === "Escape") setFocus(null); }});
function setFocus(card) {{
  document.querySelectorAll(".card.focus").forEach((c) => c.classList.remove("focus"));
  document.body.classList.toggle("focusing", !!card);
  if (card) card.classList.add("focus");
  try {{
    card ? sessionStorage.setItem(focusKey, card.dataset.case) : sessionStorage.removeItem(focusKey);
  }} catch (e) {{}}
}}
setInterval(() => {{
  const open = [...document.querySelectorAll("details")].flatMap((d, i) => d.open ? [i] : []);
  try {{ sessionStorage.setItem(openKey, JSON.stringify(open)); }} catch (e) {{}}
  location.reload();
}}, 3000);
</script>
<style>
body {{ font-family: system-ui, sans-serif; margin: 16px; background: #fafafa; color: #111; }}
main {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 16px; }}
.card {{ background: #fff; border: 2px solid #ddd; border-radius: 8px; padding: 12px; }}
.card h2 {{ font-size: 16px; margin: 0 0 4px; font-family: ui-monospace, monospace; }}
.expected {{ font-size: 13px; color: #555; min-height: 2.6em; }}
.card svg {{ width: 220px; height: 220px; }}
.card svg {{ cursor: zoom-in; }}
body.focusing {{ overflow: hidden; }}
.card.focus {{ position: fixed; inset: 0; z-index: 10; border-radius: 0; overflow: auto; display: flex; flex-direction: column; align-items: center; }}
.card.focus svg {{ width: min(90vw, 70vh); height: min(90vw, 70vh); cursor: zoom-out; }}
.card.focus .status, .card.focus details {{ align-self: stretch; }}
details {{ margin-top: 8px; font-size: 12px; }}
.query {{ font-size: 11px; white-space: pre-wrap; word-break: break-word; margin: 4px 0 0; background: #f4f4f4; padding: 6px; border-radius: 4px; }}
.status {{ font-size: 11px; white-space: pre-wrap; word-break: break-word; margin: 0; max-height: 360px; overflow: auto; }}
.success {{ border-color: #2a9d4b; }} .fetched {{ border-color: #d99a00; }} .failed {{ border-color: #c62828; }}
</style>
<h1>DCQL test cases</h1><p>VC type: {vc_type}. JWT VC type: {jwt_vc_type}. The page refreshes every 3 seconds. Click a QR code to enlarge it, and click it again or press Esc to go back.</p><main>{cards}</main>"#,
        vc_type = html_escape(&state.vc_type),
        jwt_vc_type = html_escape(&state.jwt_vc_type),
    ))
}

async fn retry_case(
    State(state): State<Arc<AppState>>,
    Path(case): Path<String>,
) -> Result<axum::response::Redirect, AppError> {
    state.start_session(&case).await?;
    Ok(axum::response::Redirect::to("/"))
}

fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index_page))
        .route("/retry/:case", get(retry_case))
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

fn credential_query_from_json(query: serde_json::Value) -> DcqlCredentialQuery {
    serde_json::from_value(query).expect("valid DCQL credential query")
}

fn build_ldp_dcql_case(case: &str, vc_type: &str) -> Option<DcqlCredentialQuery> {
    let id = format!("{case}_0");
    let query = match case {
        "ldp_type_values" => json!({
            "id": id,
            "format": "ldp_vc",
            "meta": { "type_values": [["VerifiableCredential", vc_type]] }
        }),
        "ldp_claim_values" => json!({
            "id": id,
            "format": "ldp_vc",
            "claims": [{ "path": ["type", null], "values": [vc_type] }]
        }),
        "ldp_claim_sets" => json!({
            "id": id,
            "format": "ldp_vc",
            "claims": [
                { "id": "missing", "path": ["credentialSubject", "no_such_claim"] },
                { "id": "type", "path": ["type", null], "values": [vc_type] }
            ],
            "claim_sets": [["missing"], ["type"]]
        }),
        "ldp_multiple" => json!({
            "id": id,
            "format": "ldp_vc",
            "multiple": true,
            "claims": [{ "path": ["type", null], "values": [vc_type] }]
        }),
        "ldp_no_match" => json!({
            "id": id,
            "format": "ldp_vc",
            "claims": [{ "path": ["type", null], "values": ["NoSuchCredential"] }]
        }),
        "ldp_insurance_values" => json!({
            "id": id,
            "format": "ldp_vc",
            "claims": [{ "path": ["type", null], "values": ["VehicleInsuranceCredential"] }]
        }),
        "ldp_claim_sets_first" => json!({
            "id": id,
            "format": "ldp_vc",
            "claims": [
                { "id": "type", "path": ["type", null], "values": [vc_type] },
                { "id": "missing", "path": ["credentialSubject", "no_such_claim"] }
            ],
            "claim_sets": [["type"], ["missing"]]
        }),
        "ldp_claim_sets_no_claims" => json!({
            "id": id,
            "format": "ldp_vc",
            "claim_sets": [["type"]]
        }),
        "ldp_claim_sets_unknown_id" => json!({
            "id": id,
            "format": "ldp_vc",
            "claims": [{ "id": "type", "path": ["type", null], "values": [vc_type] }],
            "claim_sets": [["no_such_id"]]
        }),
        "ldp_index_path" => json!({
            "id": id,
            "format": "ldp_vc",
            "claims": [{ "path": ["type", 0], "values": ["VerifiableCredential"] }]
        }),
        "ldp_path_wrong_type" => json!({
            "id": id,
            "format": "ldp_vc",
            "claims": [{ "path": ["type", "not_an_object"] }]
        }),
        "ldp_type_values_iri" => json!({
            "id": id,
            "format": "ldp_vc",
            "meta": {
                "type_values": [["https://www.w3.org/2018/credentials#VerifiableCredential"]]
            }
        }),
        "ldp_type_values_no_match" => json!({
            "id": id,
            "format": "ldp_vc",
            "meta": { "type_values": [["VerifiableCredential", "NoSuchCredential"]] }
        }),
        "ldp_no_holder_binding" => json!({
            "id": id,
            "format": "ldp_vc",
            "require_cryptographic_holder_binding": false,
            "claims": [{ "path": ["type", null], "values": [vc_type] }]
        }),
        _ => return None,
    };
    Some(credential_query_from_json(query))
}

fn build_jwt_dcql_case(case: &str, jwt_vc_type: &str) -> Option<DcqlCredentialQuery> {
    let id = format!("{case}_0");
    let query = match case {
        "jwt_vc_claim_values" => json!({
            "id": id,
            "format": "jwt_vc_json",
            "claims": [{ "path": ["type", null], "values": [jwt_vc_type] }]
        }),
        "jwt_vc_type_values" => json!({
            "id": id,
            "format": "jwt_vc_json",
            "meta": { "type_values": [["VerifiableCredential", jwt_vc_type]] }
        }),
        "jwt_vc_no_match" => json!({
            "id": id,
            "format": "jwt_vc_json",
            "claims": [{ "path": ["type", null], "values": ["NoSuchCredential"] }]
        }),
        _ => return None,
    };
    Some(credential_query_from_json(query))
}

fn build_mdl_dcql_case(case: &str) -> Option<DcqlCredentialQuery> {
    let id = format!("{case}_0");
    let given_name = |values: serde_json::Value| {
        json!({
            "id": id,
            "format": "mso_mdoc",
            "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
            "claims": [{ "path": ["org.iso.18013.5.1", "given_name"], "values": values }]
        })
    };
    let query = match case {
        "mdl_age_over_18" => json!({
            "id": id,
            "format": "mso_mdoc",
            "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
            "claims": [{ "path": ["org.iso.18013.5.1", "age_over_18"], "values": [true] }]
        }),
        "mdl_no_match" => given_name(json!(["__no_such_name__"])),
        "mdl_claim_sets" => json!({
            "id": id,
            "format": "mso_mdoc",
            "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
            "claims": [
                { "id": "given_name", "path": ["org.iso.18013.5.1", "given_name"] },
                { "id": "missing", "path": ["org.iso.18013.5.1", "no_such_element"] }
            ],
            "claim_sets": [["missing"], ["given_name"]]
        }),
        "mdl_wrong_doctype" => json!({
            "id": id,
            "format": "mso_mdoc",
            "meta": { "doctype_value": "org.iso.18013.5.1.NotAnMdl" },
            "claims": [{ "path": ["org.iso.18013.5.1", "given_name"] }]
        }),
        "mdl_bad_path" => json!({
            "id": id,
            "format": "mso_mdoc",
            "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
            "claims": [{ "path": ["org.iso.18013.5.1", "given_name", "extra"] }]
        }),
        _ => return None,
    };
    Some(credential_query_from_json(query))
}

/// Build a DCQL query for multiple credential types
///
/// Per OID4VP v1.0 Section 6.2, when credential_sets is present, ALL credentials
/// in the credentials array MUST be covered by at least one credential_set option.
///
/// This function creates separate credential_sets for:
/// - OR types (like ldp_or_mdl): one credential_set with multiple options
/// - Individual types: one credential_set with a single option (required)
fn build_dcql_query_for_types(
    types: &[String],
    vc_type: &str,
    jwt_vc_type: &str,
) -> Result<(DcqlQuery, String)> {
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
                let Some(query) = build_ldp_dcql_case(other, vc_type)
                    .or_else(|| build_jwt_dcql_case(other, jwt_vc_type))
                    .or_else(|| build_mdl_dcql_case(other))
                else {
                    anyhow::bail!(
                        "Unknown credential type: {}. Available: {}",
                        other,
                        CREDENTIAL_TYPES
                    );
                };
                credential_sets.push(vec![vec![query.id().to_string()]]);
                queries.push(query);
                descriptions.push(other);
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
const CREDENTIAL_TYPES: &str = "mdl, ldp_vc, jwt_vc, vcdm2_sd_jwt, ldp_or_mdl, \
or any case name shown on the --all page";

fn build_client_metadata(credential_types: &[String]) -> ClientMetadata {
    let mut vp_formats = ClaimFormatMap::new();

    for cred_type in credential_types {
        let kind = match cred_type.as_str() {
            "ldp_or_mdl" => "ldp_or_mdl",
            case if case.starts_with("ldp_") => "ldp_vc",
            case if case.starts_with("jwt_vc_") => "jwt_vc",
            case if case.starts_with("mdl_") => "mdl",
            other => other,
        };
        match kind {
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

    let state = Arc::new(AppState {
        verifier,
        vc_type: args.vc_type.clone(),
        jwt_vc_type: args.jwt_vc_type.clone(),
        serve_all: args.all,
        sessions: Mutex::new(Vec::new()),
        completion_notify: tokio::sync::Notify::new(),
    });

    if args.all {
        for (case, _) in ALL_CASES {
            state.start_session(case).await?;
        }
        println!("[*] Serving {} DCQL test cases", ALL_CASES.len());
        println!("[*] Open {} to scan them", args.public_url);
        println!();
    } else {
        let session = state.start_session(&args.credential.join("+")).await?;

        println!("[*] Session ID: {}", session.session_id);
        println!("[*] Requesting: {}", session.case);
        println!();

        if !args.no_qr {
            println!("Scan this QR code with your wallet app:");
            println!();
            display_qr_code(session.auth_url.as_str());
        }

        println!("Authorization URL:");
        println!("{}", session.auth_url);
        println!();
        println!("----------------------------------------");
        print_status_update(&session.status);
    }

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
