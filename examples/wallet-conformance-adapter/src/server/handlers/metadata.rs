use axum::{extract::State, Json};
use openid4vp::core::{
    authorization_request::parameters::{ClientIdScheme, ResponseType},
    credential_format::{ClaimFormatDesignation, ClaimFormatMap, ClaimFormatPayload},
    metadata::{
        parameters::wallet::{
            AuthorizationEncryptionAlgValuesSupported, AuthorizationEncryptionEncValuesSupported,
            AuthorizationEndpoint, ClientIdPrefixesSupported, ResponseTypesSupported,
            VpFormatsSupported,
        },
        WalletMetadata,
    },
    object::UntypedObject,
};
use serde_json::{json, Value};

use crate::server::AppState;

/// GET /.well-known/openid-configuration
///
/// Returns wallet metadata using the openid4vp library's WalletMetadata type.
pub async fn wallet_metadata(State(state): State<AppState>) -> Json<Value> {
    // Build vp_formats_supported - only dc+sd-jwt
    let mut vp_formats = ClaimFormatMap::new();
    vp_formats.insert(
        ClaimFormatDesignation::Other("dc+sd-jwt".to_string()),
        ClaimFormatPayload::Other(json!({
            "alg_values_supported": ["ES256"],
            "kb-jwt_alg_values_supported": ["ES256"]
        })),
    );

    let authorization_endpoint = AuthorizationEndpoint(state.config.authorization_endpoint.clone());
    let vp_formats_supported = VpFormatsSupported(vp_formats);

    let mut metadata = WalletMetadata::new(authorization_endpoint, vp_formats_supported, None);

    metadata.insert(ResponseTypesSupported(vec![ResponseType::VpToken]));
    metadata.insert(ClientIdPrefixesSupported(vec![ClientIdScheme(
        "redirect_uri".to_string(),
    )]));
    metadata.insert(AuthorizationEncryptionAlgValuesSupported(vec![
        "ECDH-ES".to_string()
    ]));
    metadata.insert(AuthorizationEncryptionEncValuesSupported(vec![
        "A256GCM".to_string()
    ]));

    let metadata_object: UntypedObject = metadata.into();
    let mut metadata_json: Value = serde_json::to_value(metadata_object).unwrap_or_default();

    if let Value::Object(ref mut map) = metadata_json {
        map.insert(
            "response_modes_supported".to_string(),
            json!(["direct_post", "direct_post.jwt"]),
        );
    }

    Json(metadata_json)
}

/// GET /.well-known/jwks.json
///
/// Returns the wallet's public keys in JWKS format.
pub async fn jwks(State(state): State<AppState>) -> Json<Value> {
    let keys = state.engine.public_keys();

    Json(json!({
        "keys": keys
    }))
}
